//! ISO/IEC 14443 protocol layer (on top of [`Thm3060`]):
//! - Part 3 Type A: WUPA/REQA, cascaded anticollision + SELECT, HLTA
//! - Part 3 Type B: REQB/WUPB -> ATQB, ATTRIB (incl. the raw, non-ISO-DEP variant)
//! - Part 4 ISO-DEP: RATS/ATS, I-block send/receive (chaining, WTX, R-NAK retransmit), DESELECT
//! - Mifare Classic (auth/read) and Ultralight/NTAG (read) helpers
//!
//! v1 limitation: Type A anticollision doesn't do the bitwise collision-resolution loop; with multiple cards in the field it returns Collision.

use crate::thm3060::{Error, Protocol, Thm3060};

/// Our receive capability: FSDI=8 -> FSD=256 (THM3060 buffer is 512, plenty)
const FSDI: u8 = 8;
const FSD: usize = 256;
/// One frame (INF + PCB + CRC) buffer
const FRAME_MAX: usize = FSD + 4;

/// ISO14443-3A CRC_A (init 0x6363, reflected poly 0x8408), low byte first
pub fn crc_a(data: &[u8]) -> [u8; 2] {
    let mut crc: u16 = 0x6363;
    for &b in data {
        let mut ch = b ^ (crc as u8);
        ch ^= ch << 4;
        crc = (crc >> 8) ^ ((ch as u16) << 8) ^ ((ch as u16) << 3) ^ ((ch as u16) >> 4);
    }
    crc.to_le_bytes()
}

fn fsci_to_fsc(fsci: u8) -> usize {
    const T: [usize; 9] = [16, 24, 32, 40, 48, 64, 96, 128, 256];
    T[(fsci as usize).min(8)]
}

#[derive(Clone, Copy, Debug, defmt::Format)]
pub struct CardA {
    pub atqa: [u8; 2],
    pub uid: [u8; 10],
    pub uid_len: u8,
    pub sak: u8,
}

impl CardA {
    pub fn uid(&self) -> &[u8] {
        &self.uid[..self.uid_len as usize]
    }
    /// SAK bit5: supports ISO14443-4
    pub fn iso_dep(&self) -> bool {
        self.sak & 0x20 != 0
    }
    /// Rough classification by SAK (NXP AN10833)
    pub fn kind(&self) -> CardKind {
        if self.iso_dep() {
            CardKind::IsoDep // includes 0x28/0x38 (Classic emulation + CPU), prefer ISO-DEP
        } else if matches!(self.sak, 0x08 | 0x18 | 0x09 | 0x88 | 0x01) {
            CardKind::MifareClassic
        } else if self.sak == 0x00 {
            CardKind::Ultralight
        } else {
            CardKind::Unknown
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum CardKind {
    MifareClassic,
    Ultralight,
    IsoDep,
    Unknown,
}

#[derive(Clone, Copy, Debug, defmt::Format)]
pub struct CardB {
    pub atqb: [u8; 12],
}

impl CardB {
    pub fn pupi(&self) -> &[u8] {
        &self.atqb[1..5]
    }
    pub fn app_data(&self) -> &[u8] {
        &self.atqb[5..9]
    }
    pub fn prot_info(&self) -> &[u8] {
        &self.atqb[9..12]
    }
    /// Raw Type B card: PUPI all zero, protocol type 0 (not ISO14443-4), ProtInfo 00 80 80
    pub fn is_raw_type_b(&self) -> bool {
        self.pupi() == [0, 0, 0, 0] && self.prot_info() == [0x00, 0x80, 0x80]
    }
}

/// ISO-DEP session parameters
#[derive(Clone, Copy, Debug, defmt::Format)]
pub struct IsoDep {
    /// Max frame size the card can accept (including PCB+CRC)
    pub fsc: usize,
    pub fwi: u8,
    block_num: u8,
    /// Type B: first byte of the ATTRIB answer (MBLI << 4 | CID)
    pub attrib_resp: u8,
}

impl IsoDep {
    pub fn new(fsc: usize, fwi: u8) -> Self {
        IsoDep { fsc, fwi: fwi.min(14), block_num: 0, attrib_resp: 0 }
    }
    /// FWT = 302us * 2^FWI, plus margin
    pub fn fwt_us(&self) -> u32 {
        (302u32 << self.fwi) + 2_000
    }
}

pub struct Reader {
    pub chip: Thm3060,
    /// An auth has been attempted (success = encrypted session, failure = card dropped back to IDLE);
    /// either way the next auth must re-activate the card first
    crypto: bool,
}

impl Reader {
    pub fn new(chip: Thm3060) -> Self {
        Reader { chip, crypto: false }
    }

    /// Type A frame: send, verify and strip CRC_A (when `with_crc`; the extended path keeps CRC in the received data)
    async fn xa(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32, with_crc: bool) -> Result<usize, Error> {
        let n = self.chip.transceive(tx, rx, timeout_us).await?;
        if !with_crc {
            return Ok(n);
        }
        if n < 2 || crc_a(&rx[..n - 2]) != [rx[n - 2], rx[n - 1]] {
            return Err(Error::Crc);
        }
        Ok(n - 2)
    }

    // ================= Type A =================

    /// Find and select one Type A card (field must already be on; caller decides whether to field_reset first).
    /// Matches the original: try WUPA first, fall back to REQA.
    pub async fn activate_a(&mut self) -> Result<CardA, Error> {
        self.chip.mifare_crypto_off();
        self.crypto = false;
        let c = &mut self.chip;
        // Always run the full Type A init (incl. 0x13=0xC0 reset of the extended block): measured, without it a second
        // Mifare auth after re-activation fails (the Crypto1 engine keeps state from the previous session)
        c.select_protocol(Protocol::TypeA); // PSEL=0x50: bit6 = extended mode (rats() clears it)
        c.write_reg(crate::thm3060::reg::CRCSEL, 0x01);
        c.write_reg(crate::thm3060::ext::AFRAME, 0x40);

        let mut buf = [0u8; 16];
        let n = match self.chip.transceive(&[0x52], &mut buf, 1_000).await {
            Ok(n) => n,
            Err(_) => self.chip.transceive(&[0x26], &mut buf, 1_000).await?,
        };
        if n != 2 {
            return Err(Error::Framing);
        }
        let mut card = CardA { atqa: [buf[0], buf[1]], uid: [0; 10], uid_len: 0, sak: 0 };

        for &sel in &[0x93u8, 0x95, 0x97] {
            // Anticollision: SEL 20, no CRC, returns UID0-3 + BCC
            self.chip.set_crc(false, false);
            self.chip.set_aframe(true);
            let n = self.chip.transceive(&[sel, 0x20], &mut buf, 1_000).await?;
            if n != 5 {
                return Err(Error::Framing);
            }
            let part = [buf[0], buf[1], buf[2], buf[3], buf[4]];
            if part[0] ^ part[1] ^ part[2] ^ part[3] != part[4] {
                return Err(Error::Collision); // BCC mismatch, usually several cards
            }
            // SELECT: SEL 70 UID0-3 BCC + CRC, returns SAK + CRC
            self.chip.set_crc(true, true);
            self.chip.set_aframe(false);
            let tx = [sel, 0x70, part[0], part[1], part[2], part[3], part[4]];
            let n = self.xa(&tx, &mut buf, 1_000, true).await?;
            if n != 1 {
                return Err(Error::Framing);
            }
            let sak = buf[0];
            let l = card.uid_len as usize;
            if sak & 0x04 != 0 {
                // UID incomplete: first byte is the cascade tag 0x88, take the next 3 bytes
                card.uid[l..l + 3].copy_from_slice(&part[1..4]);
                card.uid_len += 3;
            } else {
                card.uid[l..l + 4].copy_from_slice(&part[0..4]);
                card.uid_len += 4;
                card.sak = sak;
                return Ok(card);
            }
        }
        Err(Error::Framing)
    }

    /// WUPA only (presence poll): true if any Type A card answered with an ATQA
    pub async fn wupa(&mut self) -> bool {
        if self.chip.protocol() != Protocol::TypeA {
            self.chip.select_protocol(Protocol::TypeA);
        }
        self.chip.write_reg(crate::thm3060::reg::PSEL, 0x50);
        self.chip.write_reg(crate::thm3060::reg::CRCSEL, 0x01);
        self.chip.write_reg(crate::thm3060::ext::AFRAME, 0x40);
        let mut buf = [0u8; 8];
        matches!(self.chip.transceive(&[0x52], &mut buf, 1_000).await, Ok(2))
    }

    /// ISO-DEP presence check (ISO 14443-4 rule 11): send R(NAK); a present card answers with R(ACK)
    pub async fn presence(&mut self, dep: &IsoDep) -> bool {
        let mut rx = [0u8; 8];
        self.block(&[0xB2 | dep.block_num], &mut rx, dep.fwt_us()).await.is_ok()
    }

    /// Mifare command answered by a 4-bit ACK/NAK (WRITE phase 1/2, Ultralight WRITE).
    /// Measured: the THM3060 delivers the 4-bit frame as one byte in the **high** nibble (ACK = 0xA0).
    pub async fn mifare_ack(&mut self, cmd: &[u8], timeout_us: u32) -> Result<bool, Error> {
        let mut buf = [0u8; 8];
        self.chip.set_crc(true, false);
        let r = self.chip.transceive(cmd, &mut buf, timeout_us).await;
        self.chip.set_crc(true, true);
        let n = r?;
        defmt::debug!("mifare ack: {=[u8]:02x}", &buf[..n]);
        Ok(n >= 1 && (buf[0] == 0xA0 || buf[0] == 0x0A))
    }

    /// Forget the Mifare session (the next auth re-activates the card)
    pub fn mifare_reset(&mut self) {
        self.chip.mifare_crypto_off();
        self.crypto = false;
    }

    /// HLTA (card doesn't respond; timeout counts as success)
    pub async fn halt_a(&mut self) {
        let mut buf = [0u8; 4];
        let _ = self.chip.transceive(&[0x50, 0x00], &mut buf, 1_000).await;
        self.chip.mifare_crypto_off();
    }

    /// RATS -> ATS, enter ISO-DEP. Returns session parameters; `ats_out` receives the raw ATS (without CRC).
    pub async fn rats(&mut self, ats_out: &mut [u8]) -> Result<(IsoDep, usize), Error> {
        let mut buf = [0u8; 64];
        // PSEL bit6 (RFU in the manual) looks like the extended-mode switch: with it set, SCON.START doesn't run (measured,
        // SCON stays at 03). The original's CPU-card flow (@0x80127a4) uses PSEL=0x10 (plain Type A) + standard path, so do the same.
        self.chip.write_reg(crate::thm3060::reg::PSEL, 0x10);
        self.chip.set_crc(true, true);
        // FWT during activation ~ 65536/fc = 4.8ms
        // Like the original: RATS and ISO-DEP use the standard path (chip strips CRC), avoiding the extended path's long-frame byte loss
        let n = self.chip.transceive_path(&[0xE0, FSDI << 4], &mut buf, 6_000, true).await?;
        if n == 0 || buf[0] as usize != n {
            return Err(Error::Framing);
        }
        let ats = &buf[..n];
        let (mut fsci, mut fwi) = (2u8, 4u8);
        if n > 1 {
            let t0 = ats[1];
            fsci = t0 & 0x0F;
            let mut i = 2;
            if t0 & 0x10 != 0 {
                i += 1; // TA
            }
            if t0 & 0x20 != 0 && i < n {
                fwi = ats[i] >> 4; // TB: FWI | SFGI
                let sfgi = ats[i] & 0x0F;
                if sfgi > 0 && sfgi < 15 {
                    // SFGT = 302us * 2^SFGI: wait before sending the first frame
                    self.chip.delay_us((302u32 << sfgi) + 100);
                }
            }
        }
        let m = n.min(ats_out.len());
        ats_out[..m].copy_from_slice(&ats[..m]);
        Ok((IsoDep::new(fsci_to_fsc(fsci), fwi), n))
    }

    // ================= Type B =================

    /// REQB (wupb=false) / WUPB, AFI=0 (all), single slot
    pub async fn request_b(&mut self, wupb: bool) -> Result<CardB, Error> {
        if self.chip.protocol() != Protocol::TypeB {
            self.chip.select_protocol(Protocol::TypeB);
        }
        let mut buf = [0u8; 32];
        let n = self.chip.transceive(&[0x05, 0x00, if wupb { 0x08 } else { 0x00 }], &mut buf, 2_000).await?;
        if n < 12 || buf[0] != 0x50 {
            return Err(Error::Framing);
        }
        let mut atqb = [0u8; 12];
        atqb.copy_from_slice(&buf[..12]);
        Ok(CardB { atqb })
    }

    /// ATTRIB: select the card and enter ISO-DEP (Type B). Returns session parameters.
    pub async fn attrib(&mut self, card: &CardB) -> Result<IsoDep, Error> {
        let pi = card.prot_info();
        let fsci = pi[1] >> 4;
        let proto_type = pi[1] & 0x0F;
        let fwi = pi[2] >> 4;
        let p = card.pupi();
        let tx = [0x1D, p[0], p[1], p[2], p[3], 0x00, FSDI, proto_type & 0x0F, 0x00];
        let mut buf = [0u8; 16];
        let mut dep = IsoDep::new(fsci_to_fsc(fsci), fwi);
        let n = self.chip.transceive(&tx, &mut buf, dep.fwt_us()).await?;
        if n < 1 {
            return Err(Error::Framing);
        }
        dep.block_num = 0;
        dep.attrib_resp = buf[0];
        Ok(dep)
    }

    /// Raw Type B link layer: the de-facto ATTRIB the industry uses (1D 00000000 00 08 01 08), card replies 1 byte.
    /// After that the card doesn't speak ISO-DEP: raw frames + CRC_B, the security module drives the rest.
    pub async fn attrib_raw(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 16];
        let n = self.chip.transceive(&[0x1D, 0, 0, 0, 0, 0x00, 0x08, 0x01, 0x08], &mut buf, 80_000).await?;
        if n < 1 {
            return Err(Error::Framing);
        }
        Ok(buf[0])
    }

    /// Send a raw Type B frame (chip adds/checks CRC_B), used to talk to a raw Type B card after ATTRIB
    pub async fn raw_b(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32) -> Result<usize, Error> {
        self.chip.transceive(tx, rx, timeout_us).await
    }

    // ================= ISO-DEP (14443-4) =================

    /// Send one block frame and receive the response block. Both Type A and B use the standard path (chip checks and strips CRC).
    async fn block(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32) -> Result<usize, Error> {
        self.chip.transceive_path(tx, rx, timeout_us, true).await
    }

    /// Send a frame; handle S(WTX) automatically; on transmission error retry up to 2 times with R(NAK)
    async fn block_wtx(&mut self, dep: &IsoDep, tx: &[u8], rx: &mut [u8]) -> Result<usize, Error> {
        let mut timeout = dep.fwt_us();
        let mut r = self.block(tx, rx, timeout).await;
        let mut retries = 0;
        loop {
            match r {
                Ok(n) if n >= 1 && rx[0] & 0xF7 == 0xF2 => {
                    // S(WTX) request: echo WTXM, extend this wait
                    let wtxm = if n >= 2 { rx[1] & 0x3F } else { 1 };
                    timeout = dep.fwt_us().saturating_mul(wtxm.max(1) as u32);
                    let resp = [0xF2, wtxm];
                    r = self.block(&resp, rx, timeout).await;
                }
                Ok(n) => return Ok(n),
                Err(e) => {
                    if retries >= 2 {
                        return Err(e);
                    }
                    retries += 1;
                    let nak = [0xB2 | dep.block_num];
                    r = self.block(&nak, rx, timeout).await;
                }
            }
        }
    }

    /// Send an APDU, receive the response (automatic chaining both ways). Returns the response length (including SW1SW2).
    pub async fn apdu(&mut self, dep: &mut IsoDep, cmd: &[u8], resp: &mut [u8]) -> Result<usize, Error> {
        let mut frame = [0u8; FRAME_MAX];
        let mut rx = [0u8; FRAME_MAX];
        // Max INF per block: FSC - PCB(1) - CRC(2)
        let max_inf = dep.fsc.saturating_sub(3).max(1);

        // ---- Send (with chaining) ----
        let mut off = 0;
        let mut n;
        loop {
            let chunk = (cmd.len() - off).min(max_inf);
            let more = off + chunk < cmd.len();
            frame[0] = 0x02 | dep.block_num | if more { 0x10 } else { 0 };
            frame[1..1 + chunk].copy_from_slice(&cmd[off..off + chunk]);
            n = self.block_wtx(dep, &frame[..1 + chunk], &mut rx).await?;
            off += chunk;
            if !more {
                break;
            }
            // Expect R(ACK) with the same block number
            if n < 1 || rx[0] & 0xF6 != 0xA2 || (rx[0] & 1) != dep.block_num {
                return Err(Error::Framing);
            }
            dep.block_num ^= 1;
        }

        // ---- Receive (with chaining) ----
        let mut out = 0;
        loop {
            if n < 1 || rx[0] & 0xE2 != 0x02 {
                return Err(Error::Framing); // not an I-block
            }
            dep.block_num ^= 1;
            let inf = &rx[1..n];
            if out + inf.len() > resp.len() {
                return Err(Error::BufferTooSmall);
            }
            resp[out..out + inf.len()].copy_from_slice(inf);
            out += inf.len();
            if rx[0] & 0x10 == 0 {
                return Ok(out);
            }
            // Card is chaining: reply R(ACK) for the next block
            let ack = [0xA2 | dep.block_num];
            n = self.block_wtx(dep, &ack, &mut rx).await?;
        }
    }

    /// S(DESELECT)
    pub async fn deselect(&mut self, dep: &IsoDep) {
        let mut rx = [0u8; 8];
        let _ = self.block(&[0xC2], &mut rx, dep.fwt_us()).await;
    }

    // ================= Mifare =================

    /// Mifare Classic authentication. 4-byte UIDs are used as-is; for 7-byte UIDs use UID3..UID6 (NXP AN10927)
    pub async fn mifare_auth(&mut self, card: &CardA, key_b: bool, block: u8, key: &[u8; 6]) -> Result<(), Error> {
        let u = card.uid();
        let uid4 = if u.len() == 4 { [u[0], u[1], u[2], u[3]] } else { [u[3], u[4], u[5], u[6]] };
        // Reader nonce: current SysTick value (constant if SysTick isn't running); nothing security-critical depends on it
        let t = cortex_m::peripheral::SYST::get_current();
        let nr = t.to_le_bytes();
        if self.crypto {
            // Success: in an encrypted session the card only accepts encrypted (nested) AUTH, and the chip's nested-auth
            //   behaviour is unknown. Failure: the card is already back to IDLE.
            // Either way: drop the field, re-activate the same card, then do a plaintext auth.
            self.chip.field_reset(8).await;
            let again = self.activate_a().await?;
            if again.uid() != card.uid() {
                return Err(Error::AuthFailed); // a different card was swapped in
            }
        }
        let r = self.chip.mifare_auth(key_b, block, key, &uid4, &nr).await;
        defmt::trace!("MIFARE auth {=str} blk {=u8} -> {}", if key_b { "B" } else { "A" }, block, r);
        self.crypto = true;
        r
    }

    /// READ (0x30): Mifare Classic (after auth) returns 1 block; Ultralight/NTAG returns 4 pages = 16 bytes
    pub async fn read16(&mut self, addr: u8, out: &mut [u8; 16]) -> Result<(), Error> {
        let mut buf = [0u8; 24];
        let n = self.xa(&[0x30, addr], &mut buf, 5_000, true).await?;
        if n != 16 {
            return Err(Error::Framing);
        }
        out.copy_from_slice(&buf[..16]);
        Ok(())
    }
}
