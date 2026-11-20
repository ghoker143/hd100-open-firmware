//! Contactless slot as PC/SC sees it (structure and PC/SC Part 3 behaviour ported from bp8903-fw's iso14443.rs,
//! the low layers swapped for our THM3060 + [`Reader`]):
//! - power_on: activate the card (Type A first, then Type B), synthesise the PC/SC Part 3 ATR
//! - xfr: CLA=FF pseudo-APDUs handled by the reader (UID, Mifare keys / auth / read / write), the rest goes to the card
//! - poll: presence detection (idle: WUPA/WUPB field pulse; active: ISO-DEP R(NAK) / raw Type B 00 36 / re-select)
//! - P5 security module (idsam.rs), reachable while a card session is open:
//!     FF 70 00 00 Lc CMD PARA [DATA]  run one SAM command (relaying its RF frames); returns the first ≤256 bytes
//!                                     of the raw response frame (AA AA AA 96 69 ..), SW 9000 or 61xx = more left
//!     FF 72 P1 P2 Le                  read the stored response frame from offset P1P2 (Le 00 = 256)
//!   Errors: 6A81 no module, 6401 module timeout, 6581 bad response frame.
//!   `20 01` (find card) resets the field first so the module's REQB finds a card we already activated.
//!   Once the SAM is used, presence polling stops touching the card until the session ends (power off / on),
//!   so it can't disturb the module's own session with the card.

use embassy_time::Duration;

use crate::idsam::{self, IdSam};
use crate::iso14443::{CardA, IsoDep, Reader};
use crate::thm3060::{Error, Protocol};

#[derive(Clone, Copy, Default, defmt::Format)]
pub struct Card {
    pub type_b: bool,
    /// Type B card that doesn't speak ISO-DEP (PUPI 00000000): bare APDU frames after ATTRIB
    pub raw: bool,
    pub uid: [u8; 10],
    pub uid_len: u8,
    pub sak: u8,
    pub iso_dep: bool,
    /// ATS historical bytes; Type B: ATQB app data(4) + protocol info(3) + MBLI<<4 (PC/SC Part 3)
    pub hist: [u8; 15],
    pub hist_len: u8,
}

impl Card {
    pub fn uid(&self) -> &[u8] {
        &self.uid[..self.uid_len as usize]
    }
    pub fn hist(&self) -> &[u8] {
        &self.hist[..self.hist_len as usize]
    }
    fn as_a(&self) -> CardA {
        let mut uid = [0u8; 10];
        uid.copy_from_slice(&self.uid);
        CardA { atqa: [0; 2], uid, uid_len: self.uid_len, sak: self.sak }
    }
}

pub struct Atr {
    pub bytes: [u8; 20],
    pub len: usize,
}

#[derive(Clone, Copy)]
struct Auth {
    key_b: bool,
    block: u8,
}

pub struct Contactless {
    rd: Reader,
    card: Option<Card>,
    dep: Option<IsoDep>,
    present: bool,
    /// PC/SC volatile reader keys (FF 82, key numbers 0 and 1)
    keys: [Option<[u8; 6]>; 2],
    /// Mifare Classic sector currently authenticated, and the key used
    auth: Option<Auth>,
    last_key: [u8; 6],
    sam: Option<IdSam>,
    /// The host is using the SAM in this session: presence polling leaves the card alone
    sam_hold: bool,
}

/// Mifare READ/WRITE answer time
const T_MIFARE_US: u32 = 10_000;
const T_WRITE_US: u32 = 20_000;

fn sector(block: u8) -> u8 {
    if block < 128 { block / 4 } else { 32 + (block - 128) / 16 }
}

fn is_trailer(block: u8) -> bool {
    if block < 128 { block % 4 == 3 } else { block % 16 == 15 }
}

/// Sector trailer bytes 6..8: access bits and complements (MF1S50 8.7.1); a broken trailer locks the sector for good
fn access_bits_ok(t: &[u8]) -> bool {
    let (b6, b7, b8) = (t[6], t[7], t[8]);
    (b7 >> 4) == (!b6 & 0x0F) && (b8 & 0x0F) == (!b6 >> 4) && (b8 >> 4) == (!b7 & 0x0F)
}

fn classic_blocks(sak: u8) -> Option<u16> {
    match sak & 0xDF {
        0x09 => Some(20),
        0x08 => Some(64),
        0x18 => Some(256),
        0x19 => Some(128),
        _ => None,
    }
}

fn sw(out: &mut [u8], at: usize, sw: u16) -> usize {
    out[at..at + 2].copy_from_slice(&sw.to_be_bytes());
    at + 2
}

impl Contactless {
    pub fn new(rd: Reader) -> Self {
        Contactless {
            rd,
            card: None,
            dep: None,
            present: false,
            keys: [None; 2],
            auth: None,
            last_key: [0; 6],
            sam: None,
            sam_hold: false,
        }
    }

    /// Attach the P5 security module (pseudo-APDUs FF 70 / FF 72)
    pub fn with_sam(mut self, sam: IdSam) -> Self {
        self.sam = Some(sam);
        self
    }

    /// Bring up the P5 module link if a module is there (no-op when there is none). True = usable.
    pub async fn sam_ensure(&mut self) -> bool {
        match self.sam.as_mut() {
            Some(sam) => sam.ensure().await,
            None => false,
        }
    }

    /// The activated card, if a session is open
    pub fn card(&self) -> Option<&Card> {
        self.card.as_ref()
    }

    pub fn is_active(&self) -> bool {
        self.card.is_some()
    }

    pub fn card_present(&self) -> bool {
        self.present
    }

    fn drop_card(&mut self) {
        self.card = None;
        self.dep = None;
        self.auth = None;
        self.sam_hold = false;
        self.rd.mifare_reset();
        self.rd.chip.carrier(false);
    }

    /// Field reset, activate one card, return its PC/SC Part 3 ATR.
    pub async fn power_on(&mut self) -> Result<Atr, Error> {
        self.drop_card();
        self.rd.chip.select_protocol(Protocol::TypeA);
        self.rd.chip.field_reset(8).await;
        let r = match self.activate_a().await {
            Err(Error::Timeout) => {
                self.rd.chip.select_protocol(Protocol::TypeB);
                self.rd.chip.field_reset(8).await;
                self.activate_b().await
            }
            r => r,
        };
        match r {
            Ok(card) => {
                self.present = true;
                self.card = Some(card);
                Ok(atr_for(&card))
            }
            Err(e) => {
                self.drop_card();
                Err(e)
            }
        }
    }

    async fn activate_a(&mut self) -> Result<Card, Error> {
        let a = self.rd.activate_a().await?;
        let mut card = Card { uid_len: a.uid_len, sak: a.sak, ..Default::default() };
        card.uid.copy_from_slice(&a.uid);
        if a.iso_dep() {
            let mut ats = [0u8; 32];
            let (dep, n) = self.rd.rats(&mut ats).await?;
            // Historical bytes: after TL, T0 and the TA/TB/TC announced by T0
            if n >= 2 {
                let t0 = ats[1];
                let start = 2 + (t0 & 0x10 != 0) as usize + (t0 & 0x20 != 0) as usize + (t0 & 0x40 != 0) as usize;
                let h = &ats[start.min(n)..n];
                let h = &h[..h.len().min(15)];
                card.hist[..h.len()].copy_from_slice(h);
                card.hist_len = h.len() as u8;
            }
            card.iso_dep = true;
            self.dep = Some(dep);
        }
        defmt::info!("rf: [A] UID {=[u8]:02x} SAK {=u8:02x}", card.uid(), card.sak);
        Ok(card)
    }

    async fn activate_b(&mut self) -> Result<Card, Error> {
        let b = self.rd.request_b(true).await?;
        let mut card = Card { type_b: true, uid_len: 4, ..Default::default() };
        card.uid[..4].copy_from_slice(b.pupi());
        let dep = if b.is_raw_type_b() {
            let r = self.rd.attrib_raw().await?;
            card.raw = true;
            let mut d = IsoDep::new(256, b.prot_info()[2] >> 4);
            d.attrib_resp = r;
            d
        } else {
            self.rd.attrib(&b).await?
        };
        card.iso_dep = true;
        card.hist[..4].copy_from_slice(b.app_data());
        card.hist[4..7].copy_from_slice(b.prot_info());
        card.hist[7] = dep.attrib_resp & 0xF0;
        card.hist_len = 8;
        self.dep = Some(dep);
        defmt::info!("rf: [B] PUPI {=[u8]:02x}{=str}", card.uid(), if card.raw { " (raw)" } else { "" });
        Ok(card)
    }

    pub async fn power_off(&mut self) {
        if let (Some(card), Some(dep)) = (self.card, self.dep) {
            if card.iso_dep && !card.raw {
                self.rd.deselect(&dep).await;
            }
        }
        self.drop_card();
    }

    /// Presence poll (the CCID interrupt-endpoint task calls this periodically).
    pub async fn poll(&mut self) -> bool {
        if self.sam_hold && self.card.is_some() {
            return self.present;
        }
        self.present = match self.card {
            None => {
                self.rd.chip.select_protocol(Protocol::TypeA);
                self.rd.chip.field_reset(5).await;
                let mut seen = self.rd.wupa().await;
                if seen {
                    self.rd.halt_a().await;
                } else {
                    seen = self.rd.request_b(true).await.is_ok();
                }
                self.rd.chip.carrier(false);
                seen
            }
            Some(card) if card.raw => {
                let mut buf = [0u8; 16];
                let mut ok = false;
                for _ in 0..2 {
                    if matches!(self.rd.raw_b(&[0x00, 0x36, 0x00, 0x00, 0x08], &mut buf, 80_000).await, Ok(10)) {
                        ok = true;
                        break;
                    }
                }
                ok
            }
            Some(card) if card.iso_dep => {
                let dep = self.dep.unwrap();
                let mut ok = false;
                for _ in 0..2 {
                    if self.rd.presence(&dep).await {
                        ok = true;
                        break;
                    }
                }
                ok
            }
            Some(card) => {
                // Memory card: re-authenticate if a sector was open (keeps it open for the application), else re-select
                let reauth = match self.auth {
                    Some(a) => self.reauth(&card, a).await,
                    None => false,
                };
                reauth || self.reselect(&card).await
            }
        };
        if !self.present && self.card.is_some() {
            defmt::info!("rf: card left the field");
            self.drop_card();
        }
        self.present
    }

    /// Field drop + re-activate; true if the same card is back (Crypto1 session gone)
    async fn reselect(&mut self, card: &Card) -> bool {
        self.auth = None;
        self.rd.mifare_reset();
        self.rd.chip.field_reset(8).await;
        matches!(self.rd.activate_a().await, Ok(a) if a.uid() == card.uid())
    }

    async fn reauth(&mut self, card: &Card, a: Auth) -> bool {
        let key = self.last_key;
        self.authenticate(card, a.key_b, a.block, &key).await.is_ok()
    }

    async fn authenticate(&mut self, card: &Card, key_b: bool, block: u8, key: &[u8; 6]) -> Result<(), Error> {
        match self.rd.mifare_auth(&card.as_a(), key_b, block, key).await {
            Ok(()) => {
                self.auth = Some(Auth { key_b, block });
                self.last_key = *key;
                Ok(())
            }
            Err(e) => {
                self.auth = None;
                Err(e)
            }
        }
    }

    /// One APDU from the host. CLA=FF is handled here (PC/SC Part 3), everything else goes to the card.
    pub async fn xfr(&mut self, cmd: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let Some(card) = self.card else { return Err(Error::Timeout) };
        if cmd.first() == Some(&0xFF) {
            return Ok(self.pseudo_apdu(&card, cmd, out).await);
        }
        if !card.iso_dep {
            return Ok(sw(out, 0, 0x6E00)); // memory card: CLA not supported
        }
        let r = self.apdu(&card, cmd, out).await;
        if r.is_err() {
            defmt::warn!("rf: APDU exchange failed, dropping the card");
            self.drop_card();
        }
        r
    }

    async fn apdu(&mut self, card: &Card, cmd: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let mut dep = self.dep.ok_or(Error::Timeout)?;
        let r = if card.raw {
            // Raw Type B: bare frame, chip adds/checks CRC_B; one retry
            match self.rd.raw_b(cmd, out, dep.fwt_us()).await {
                Err(_) => self.rd.raw_b(cmd, out, dep.fwt_us()).await,
                r => r,
            }
        } else {
            self.rd.apdu(&mut dep, cmd, out).await
        };
        self.dep = Some(dep);
        r
    }

    /// PC/SC Part 3 pseudo-APDUs (CLA=FF). Always answers with a status word; never drops the card.
    async fn pseudo_apdu(&mut self, card: &Card, cmd: &[u8], out: &mut [u8]) -> usize {
        if cmd.len() < 4 {
            return sw(out, 0, 0x6700);
        }
        let (ins, p1, p2) = (cmd[1], cmd[2], cmd[3]);
        let lc = cmd.get(4).copied().unwrap_or(0) as usize;
        let data = cmd.get(5..5 + lc).unwrap_or(&[]);
        match ins {
            // GET DATA: P1=00 UID, 01 historical bytes
            0xCA => {
                if p2 != 0 {
                    return sw(out, 0, 0x6B00);
                }
                // Raw Type B card (PUPI 00000000): serial from the de facto 00 36 00 00 08, like local readers
                let mut id = [0u8; 10];
                let mut id_len = 0;
                if p1 == 0x00 && card.raw {
                    if let Ok(10) = self.apdu(card, &[0x00, 0x36, 0x00, 0x00, 0x08], &mut id).await {
                        if id[8..10] == [0x90, 0x00] {
                            id_len = 8;
                        }
                    }
                }
                let d: &[u8] = match p1 {
                    0x00 if id_len > 0 => &id[..id_len],
                    0x00 => card.uid(),
                    0x01 if card.iso_dep => card.hist(),
                    _ => return sw(out, 0, 0x6A81),
                };
                let le = cmd.get(4).copied().unwrap_or(0) as usize;
                if le != 0 && le < d.len() {
                    return sw(out, 0, 0x6C00 | d.len() as u16);
                }
                out[..d.len()].copy_from_slice(d);
                sw(out, d.len(), if le > d.len() { 0x6282 } else { 0x9000 })
            }
            // LOAD KEYS: P1 = key structure, P2 = key number
            0x82 => {
                if p1 & 0x80 != 0 {
                    return sw(out, 0, 0x6982);
                }
                if p1 & 0x20 != 0 {
                    return sw(out, 0, 0x6987);
                }
                if p2 as usize >= self.keys.len() {
                    return sw(out, 0, 0x6988);
                }
                if lc != 6 || data.len() != 6 {
                    return sw(out, 0, 0x6989);
                }
                let mut k = [0u8; 6];
                k.copy_from_slice(data);
                self.keys[p2 as usize] = Some(k);
                sw(out, 0, 0x9000)
            }
            // GENERAL AUTHENTICATE (86: 01 00 blk type keynr) / old AUTHENTICATE (88: P2=blk, type, keynr)
            0x86 | 0x88 => {
                let (block, key_type, key_nr) = match ins {
                    0x86 if lc == 5 && data.len() == 5 && data[0] == 0x01 && data[1] == 0x00 => (data[2], data[3], data[4]),
                    0x88 if cmd.len() >= 6 => (p2, cmd[4], cmd[5]),
                    _ => return sw(out, 0, 0x6700),
                };
                if card.iso_dep || card.uid_len < 4 {
                    return sw(out, 0, 0x6981);
                }
                let key_b = match key_type {
                    0x60 | 0x0A => false,
                    0x61 | 0x0B => true,
                    _ => return sw(out, 0, 0x6A81),
                };
                let Some(key) = self.keys.get(key_nr as usize).copied().flatten() else {
                    return sw(out, 0, 0x6983);
                };
                match self.authenticate(card, key_b, block, &key).await {
                    Ok(()) => sw(out, 0, 0x9000),
                    Err(e) => {
                        defmt::info!("rf: auth block {} failed: {}", block, e);
                        sw(out, 0, 0x6300)
                    }
                }
            }
            // READ / UPDATE BINARY on storage cards
            0xB0 | 0xD6 => {
                if card.iso_dep {
                    return sw(out, 0, 0x6981);
                }
                if p1 != 0 {
                    return sw(out, 0, 0x6B00);
                }
                let le = cmd.get(4).copied().unwrap_or(0) as usize;
                self.storage(card, ins, p2, lc, data, le, out).await
            }
            // P5 security module: run a command
            0x70 => {
                if data.len() < 2 || lc != data.len() {
                    return sw(out, 0, 0x6700);
                }
                // Usually there is no module at all: answer at once, leave the card session alone
                let up = match self.sam.as_mut() {
                    Some(sam) => sam.ensure().await,
                    None => false,
                };
                if !up {
                    return sw(out, 0, 0x6A81);
                }
                let (c, p) = (data[0], data[1]);
                self.sam_hold = true;
                if (c, p) == (0x20, 0x01) {
                    idsam::rf_on(&mut self.rd.chip).await;
                } else if self.rd.chip.protocol() != Protocol::TypeB {
                    self.rd.chip.select_protocol(Protocol::TypeB);
                }
                let sam = self.sam.as_mut().unwrap();
                match sam.command(&mut self.rd.chip, c, p, &data[2..], Duration::from_secs(5)).await {
                    Ok(_) => {
                        // 30 xx = read card data: the step the user waits for
                        if c == 0x30 {
                            let ok = idsam::split_response(sam.frame()).is_some_and(|r| r.2 == 0x90);
                            crate::ui::toast(if ok { "ID card read" } else { "ID card error" }, 2000);
                            crate::ui::beep(if ok { 1 } else { 2 });
                        }
                        self.sam_chunk(0, 256, out)
                    }
                    Err(e) => {
                        defmt::warn!("idsam: {=u8:02x} {=u8:02x}: {}", c, p, e);
                        sw(out, 0, if e == idsam::Error::Timeout { 0x6401 } else { 0x6581 })
                    }
                }
            }
            // P5 security module: read the stored response from an offset
            0x72 => {
                if !self.sam.as_ref().is_some_and(|s| s.is_up()) {
                    return sw(out, 0, 0x6A81);
                }
                let le = match cmd.get(4).copied().unwrap_or(0) {
                    0 => 256,
                    n => n as usize,
                };
                self.sam_chunk((p1 as usize) << 8 | p2 as usize, le, out)
            }
            _ => sw(out, 0, 0x6D00),
        }
    }

    async fn storage(&mut self, card: &Card, ins: u8, block: u8, lc: usize, data: &[u8], le: usize, out: &mut [u8]) -> usize {
        let ultralight = card.sak == 0x00;
        if !ultralight {
            if let Some(n) = classic_blocks(card.sak) {
                if block as u16 >= n {
                    return sw(out, 0, 0x6B00);
                }
            }
            if self.auth.map(|a| sector(a.block)) != Some(sector(block)) {
                return sw(out, 0, 0x6982);
            }
        }
        let r: Result<usize, Error> = match ins {
            0xB0 => {
                if le != 0 && le != 16 {
                    return sw(out, 0, 0x6C10);
                }
                let mut b = [0u8; 16];
                self.rd.read16(block, &mut b).await.map(|_| {
                    out[..16].copy_from_slice(&b);
                    16
                })
            }
            _ => {
                // UPDATE BINARY. 4-bit ACK handling on the THM3060 is unverified (see Reader::mifare_ack).
                if ultralight {
                    if lc != 4 || data.len() != 4 {
                        return sw(out, 0, 0x6700);
                    }
                    let c = [0xA2, block, data[0], data[1], data[2], data[3]];
                    match self.rd.mifare_ack(&c, T_WRITE_US).await {
                        Ok(true) => Ok(0),
                        Ok(false) => Err(Error::AuthFailed),
                        Err(e) => Err(e),
                    }
                } else {
                    if lc != 16 || data.len() != 16 {
                        return sw(out, 0, 0x6700);
                    }
                    if is_trailer(block) && !access_bits_ok(data) {
                        defmt::warn!("rf: refused trailer write to block {}: bad access bits", block);
                        return sw(out, 0, 0x6A80);
                    }
                    match self.rd.mifare_ack(&[0xA0, block], T_MIFARE_US).await {
                        Ok(true) => match self.rd.mifare_ack(data, T_WRITE_US).await {
                            Ok(true) => Ok(0),
                            Ok(false) => Err(Error::AuthFailed),
                            Err(e) => Err(e),
                        },
                        Ok(false) => Err(Error::AuthFailed),
                        Err(e) => Err(e),
                    }
                }
            }
        };
        match r {
            Ok(n) => sw(out, n, 0x9000),
            Err(e) => {
                defmt::info!("rf: {=u8:02x} block {} failed: {}", ins, block, e);
                self.reselect(card).await;
                sw(out, 0, if e == Error::AuthFailed { 0x6982 } else { 0x6400 })
            }
        }
    }

    /// Up to `le` bytes of the stored SAM response frame from `off`; SW 61xx while more is left.
    fn sam_chunk(&self, off: usize, le: usize, out: &mut [u8]) -> usize {
        let frame = self.sam.as_ref().map(|s| s.frame()).unwrap_or(&[]);
        if off > frame.len() {
            return sw(out, 0, 0x6B00);
        }
        let n = le.min(frame.len() - off).min(256);
        out[..n].copy_from_slice(&frame[off..off + n]);
        let left = frame.len() - off - n;
        // 61xx: xx = bytes left, 00 = 256 or more
        sw(out, n, if left == 0 { 0x9000 } else if left >= 256 { 0x6100 } else { 0x6100 | left as u16 })
    }
}

/// PC/SC Part 3 3.1.3.2.3: ATR for a contactless card.
fn atr_for(card: &Card) -> Atr {
    let mut a = Atr { bytes: [0; 20], len: 0 };
    let mut push = |b: u8| {
        a.bytes[a.len] = b;
        a.len += 1;
    };
    if card.iso_dep {
        push(0x3B);
        push(0x80 | card.hist_len);
        push(0x80);
        push(0x01);
        for &b in card.hist() {
            push(b);
        }
    } else {
        // Storage card: RID A000000306, SS=03 (14443-A part 3), card name NN
        let nn: u16 = match card.sak {
            0x08 => 0x0001,
            0x18 => 0x0002,
            0x00 => 0x0003,
            0x09 => 0x0026,
            _ => 0x0000,
        };
        for b in [0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03] {
            push(b);
        }
        push((nn >> 8) as u8);
        push(nn as u8);
        for _ in 0..4 {
            push(0);
        }
    }
    let tck = a.bytes[1..a.len].iter().fold(0, |x, &b| x ^ b);
    a.bytes[a.len] = tck;
    a.len += 1;
    a
}
