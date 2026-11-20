//! THM3060 contactless reader IC driver (bit-banged SPI).
//!
//! Wiring (reverse-engineered from the original firmware, verified on board, see docs/hardware.md):
//!   PB1 = SS_N, PC4 = SCLK, PA6 = MOSI, PA5 = MISO, PC5 = RSTN (active low)
//! SPI mode 0, MSB first; command byte bit7 = 1 write / 0 read, low 7 bits = register address; max clock 2.5MHz.
//!
//! Two transceive paths:
//! - Standard path (documented in the manual): SCON.START to start, poll RSTAT.IRQ for completion. Used for Type B.
//! - Extended path (undocumented, as used by the original firmware): write 0x1C=1 to start, poll 0x14 for completion.
//!   The original uses this for all Type A traffic; Mifare Classic Crypto1 also goes through it.
//!   See [`ext`] for the meaning of these registers (inferred from the original firmware, not documented).

use core::ptr::{read_volatile, write_volatile};

use embassy_time::{Duration, Instant, Timer};

/// Documented registers (manual §5.1). Value = read address; OR 0x80 for writes.
pub mod reg {
    pub const DATA: u8 = 0x00;
    pub const PSEL: u8 = 0x01;
    pub const FCONB: u8 = 0x02;
    pub const EGT: u8 = 0x03;
    pub const CRCSEL: u8 = 0x04;
    pub const RSTAT: u8 = 0x05;
    pub const SCON: u8 = 0x06;
    pub const INTCON: u8 = 0x07;
    pub const RSCH: u8 = 0x08;
    pub const RSCL: u8 = 0x09;
    pub const TMRH: u8 = 0x0C;
    pub const TMRL: u8 = 0x0D;
    pub const BPOS: u8 = 0x0E;
    pub const SMOD: u8 = 0x10;
    pub const PWTH: u8 = 0x11;
}

/// Undocumented registers (usage inferred from the original firmware @0x801150c / 0x801184c / 0x801264c).
pub mod ext {
    /// Crypto1 enable: 0 = plaintext, 1 = encrypted (set after successful auth)
    pub const CRYPTO_EN: u8 = 0x12;
    /// Type A frame control: 0x40 = normal (with SCRC/RCRC), 0x46 = anti-collision frame (no CRC);
    /// 0xC0 at init, presumably resets this block
    pub const AFRAME: u8 = 0x13;
    /// Extended completion status: bit4 (0x10) = done; 0x08 = no response (measured); other bits = error. Write 0 to clear.
    pub const ESTAT: u8 = 0x14;
    /// Crypto1 control: 0x08 = load/idle, 0x0C = run auth
    pub const CRYPTO_CTL: u8 = 0x15;
    /// Key/UID input FIFO: write 6 key bytes, then 4 UID bytes
    pub const CRYPTO_FIFO: u8 = 0x16;
    /// 4-byte nonce registers 0x17..0x1A: first the card nonce nt, then the reader nonce nr
    pub const NONCE0: u8 = 0x17;
    /// Write 1 = start the extended send/receive
    pub const START: u8 = 0x1C;
}

/// SCON bits
const SCON_CARRYON: u8 = 0x01;
const SCON_START: u8 = 0x02;
const SCON_PTRCLR: u8 = 0x04;

/// RSTAT bits
pub mod rstat {
    pub const IRQ: u8 = 0x80;
    pub const CERR: u8 = 0x40;
    pub const PERR: u8 = 0x20;
    pub const FERR: u8 = 0x10;
    pub const DATOVER: u8 = 0x08;
    pub const TMROVER: u8 = 0x04;
    pub const CRCERR: u8 = 0x02;
    pub const FEND: u8 = 0x01;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum Protocol {
    TypeA,
    TypeB,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum Error {
    /// Chip didn't respond on SPI / wrong register readback
    NoChip,
    /// Card didn't respond (chip timer TMROVER or software deadline)
    Timeout,
    /// Collision (Type A anticollision / multiple cards)
    Collision,
    Crc,
    Parity,
    Framing,
    Overflow,
    /// Raw nonzero error bits from extended status 0x14 (meaning unknown, kept for analysis)
    Ext(u8),
    /// Received frame longer than the caller's buffer
    BufferTooSmall,
    /// Crypto1 authentication failed
    AuthFailed,
}

const RCC_APB2ENR: u32 = 0x4002_1018;
const GPIOA: u32 = 0x4001_0800;
const GPIOB: u32 = 0x4001_0C00;
const GPIOC: u32 = 0x4001_1000;

type Pin = (u32, u8);
const SS: Pin = (GPIOB, 1);
const SCLK: Pin = (GPIOC, 4);
const MOSI: Pin = (GPIOA, 6);
const MISO: Pin = (GPIOA, 5);
const RSTN: Pin = (GPIOC, 5);

#[inline(always)]
fn rd(a: u32) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
#[inline(always)]
fn wr(a: u32, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn cfg((base, pin): Pin, nib: u32) {
    let reg = if pin < 8 { base } else { base + 4 };
    let sh = ((pin % 8) * 4) as u32;
    // CRL/CRH read-modify-write: P0 interrupts (contact-card error signal) touch other pins of the same
    // register and aren't masked by critical sections (rt.rs), so keep them out with PRIMASK
    cortex_m::interrupt::free(|_| wr(reg, (rd(reg) & !(0xF << sh)) | (nib << sh)));
}
#[inline(always)]
fn set((base, pin): Pin, hi: bool) {
    // BSRR is atomic, safe to share the port with other drivers (USB etc.)
    wr(base + 0x10, if hi { 1 << pin } else { 1 << (pin + 16) });
}
#[inline(always)]
fn get((base, pin): Pin) -> bool {
    (rd(base + 0x08) >> pin) & 1 == 1
}

pub struct Thm3060 {
    cyc_per_us: u32,
    half: u32,
    proto: Protocol,
}

impl Thm3060 {
    /// Configure pins and reset the chip. `sysclk_hz` is used for delays and SPI timing.
    ///
    /// The pins live on GPIOA/B/C, which other drivers share (USB on PA11/12, PC11 etc.), so we don't take
    /// ownership of the ports: outputs go through atomic BSRR writes; CRL is read-modify-written only here at init.
    pub async fn new(sysclk_hz: u32) -> Self {
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 2) | (1 << 3) | (1 << 4));
        set(SS, true);
        set(SCLK, false);
        set(MOSI, true);
        set(RSTN, true);
        for p in [SS, SCLK, MOSI, RSTN] {
            cfg(p, 0x3); // push-pull 50MHz
        }
        set(MISO, true); // ODR=1 -> pull-up
        cfg(MISO, 0x8);
        let mut t = Thm3060 {
            cyc_per_us: (sysclk_hz / 1_000_000).max(1),
            // Half period >= 333ns -> SCLK <= 1.5MHz (limit 2.5MHz, includes margin for GPIO write overhead)
            half: (sysclk_hz / 3_000_000).max(1),
            proto: Protocol::TypeB,
        };
        t.reset().await;
        t
    }

    pub fn delay_us(&self, us: u32) {
        cortex_m::asm::delay(us.saturating_mul(self.cyc_per_us));
    }

    /// Hardware reset: RSTN low 10ms, then wait 10ms after release (matches the original timing).
    pub async fn reset(&mut self) {
        set(RSTN, false);
        Timer::after_millis(10).await;
        set(RSTN, true);
        Timer::after_millis(10).await;
        self.proto = Protocol::TypeB; // PSEL reset value
    }

    /// Same check as the original power-on probe: write FCONB, read it back. Restores the default value.
    pub fn probe(&mut self) -> bool {
        self.write_reg(reg::FCONB, 0x05);
        let ok = self.read_reg(reg::FCONB) == 0x05;
        self.write_reg(reg::FCONB, 0x2A);
        ok
    }

    // ---------------- SPI ----------------

    fn xfer(&self, out: u8) -> u8 {
        let mut inp = 0u8;
        for i in (0..8).rev() {
            set(SCLK, false);
            set(MOSI, (out >> i) & 1 == 1);
            cortex_m::asm::delay(self.half);
            set(SCLK, true);
            if get(MISO) {
                inp |= 1 << i;
            }
            cortex_m::asm::delay(self.half);
        }
        set(SCLK, false);
        inp
    }

    fn frame<R>(&self, f: impl FnOnce(&Self) -> R) -> R {
        set(SS, false);
        self.delay_us(1); // tCSU > 1us
        let r = f(self);
        cortex_m::asm::delay(self.half);
        set(SS, true);
        cortex_m::asm::delay(self.half * 2);
        r
    }

    pub fn read_reg(&self, addr: u8) -> u8 {
        self.frame(|s| {
            s.xfer(addr & 0x7f);
            s.xfer(0)
        })
    }

    pub fn write_reg(&self, addr: u8, v: u8) {
        self.frame(|s| {
            s.xfer(addr | 0x80);
            s.xfer(v);
        })
    }

    fn write_fifo(&self, data: &[u8]) {
        self.frame(|s| {
            s.xfer(0x80 | reg::DATA);
            for &b in data {
                s.xfer(b);
            }
        })
    }

    fn read_fifo(&self, out: &mut [u8]) {
        self.frame(|s| {
            s.xfer(reg::DATA);
            for b in out.iter_mut() {
                *b = s.xfer(0);
            }
        })
    }

    fn rsc(&self) -> usize {
        let l = self.read_reg(reg::RSCL) as usize;
        let h = self.read_reg(reg::RSCH) as usize;
        (h << 8) | l
    }

    // ---------------- RF control ----------------

    pub fn carrier(&mut self, on: bool) {
        self.write_reg(reg::SCON, if on { SCON_CARRYON } else { 0 });
    }

    /// RF field off for `ms` then back on (forces all cards back to IDLE)
    pub async fn field_reset(&mut self, ms: u32) {
        self.carrier(false);
        Timer::after_millis(ms as u64).await;
        self.carrier(true);
        Timer::after_millis(5).await; // let the card power up (ISO14443 requires >= 5ms before the first command)
    }

    pub fn protocol(&self) -> Protocol {
        self.proto
    }

    /// Switch protocol (106kbps). Type A init sequence follows the original @0x801150c.
    pub fn select_protocol(&mut self, p: Protocol) {
        match p {
            Protocol::TypeA => {
                self.write_reg(reg::PSEL, 0x50); // Type A, 106k; bit6 is RFU in the manual but the original sets it
                self.write_reg(reg::CRCSEL, 0x01); // no CRC until SELECT, timer on
                self.write_reg(ext::AFRAME, 0xC0);
                self.write_reg(ext::CRYPTO_EN, 0x00);
                self.write_reg(ext::AFRAME, 0x40);
            }
            Protocol::TypeB => {
                self.write_reg(reg::PSEL, 0x00); // Type B, 106k
                self.write_reg(reg::FCONB, 0x2A); // manual default SOF/EOF
                self.write_reg(reg::EGT, 0x40);
                self.write_reg(reg::CRCSEL, 0xC1); // auto CRC on TX/RX + timer
            }
        }
        self.proto = p;
    }

    /// Set CRC handling (TX auto-append / RX check), timer always on
    pub fn set_crc(&mut self, tx: bool, rx: bool) {
        self.write_reg(reg::CRCSEL, (tx as u8) << 7 | (rx as u8) << 6 | 0x01);
    }

    /// Set the Type A frame mode (extended register 0x13)
    pub fn set_aframe(&mut self, anticollision: bool) {
        self.write_reg(ext::AFRAME, if anticollision { 0x46 } else { 0x42 });
    }

    /// Set the receive timeout, unit 302us (same as ISO14443 FWT: 256*16/fc), so FWI maps directly to 2^FWI.
    pub fn set_timeout_units(&mut self, units: u16) {
        let u = units.max(1);
        self.write_reg(reg::TMRH, (u >> 8) as u8);
        self.write_reg(reg::TMRL, u as u8);
    }

    // ---------------- Transceive ----------------

    /// Send `tx`, receive into `rx`, return the number of bytes received.
    /// Type A goes through the extended path, Type B through the standard path.
    /// Also programs the chip timer (TMR) from `timeout_us`; the software deadline adds a 5ms margin on top.
    ///
    /// Note: per the original firmware, frames received over the Type A extended path **include** the 2-byte CRC_A
    /// (SELECT gets 3 bytes = SAK + CRC; READ gets 18 bytes); the caller has to verify and strip it.
    /// Type B's standard path has the chip check and strip the CRC.
    pub async fn transceive(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32) -> Result<usize, Error> {
        let std = self.proto == Protocol::TypeB;
        self.transceive_path(tx, rx, timeout_us, std).await
    }

    /// Explicitly pick the transceive path. `std = true` uses the standard path (chip checks and strips CRC per CRCSEL).
    ///
    /// Measured: the Type A extended path loses one byte on frames longer than ~32 bytes (bank card PPSE response 57
    /// bytes came back as 56). The original firmware also uses the standard path for RATS / ISO-DEP (@0x8012ca8),
    /// keeping the extended path only for anticollision / SELECT / Mifare. Follow the same split.
    pub async fn transceive_path(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32, std: bool) -> Result<usize, Error> {
        self.set_timeout_units((timeout_us / 302 + 1).min(0xFFFF) as u16);
        let r = if std {
            self.transceive_std(tx, rx, timeout_us).await
        } else {
            self.transceive_ext(tx, rx, timeout_us).await
        };
        match &r {
            Ok(n) => defmt::trace!("{} tx {=[u8]:02x} -> rx {=[u8]:02x}", self.proto, tx, &rx[..*n]),
            Err(e) => defmt::trace!("{} tx {=[u8]:02x} -> {}", self.proto, tx, e),
        }
        r
    }

    fn load(&self, tx: &[u8]) {
        self.write_reg(reg::SCON, SCON_PTRCLR | SCON_CARRYON);
        self.write_reg(reg::SCON, SCON_CARRYON);
        self.write_fifo(tx);
    }

    fn fetch(&self, rx: &mut [u8]) -> Result<usize, Error> {
        let n = self.rsc();
        if n > rx.len() {
            return Err(Error::BufferTooSmall);
        }
        if n > 0 {
            self.read_fifo(&mut rx[..n]);
        }
        Ok(n)
    }

    /// Standard path (manual §11): START, poll RSTAT.IRQ.
    async fn transceive_std(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32) -> Result<usize, Error> {
        self.load(tx);
        self.write_reg(reg::RSTAT, 0);
        self.write_reg(reg::SCON, SCON_START | SCON_CARRYON);
        let st = self.poll(timeout_us, |s| {
            let v = s.read_reg(reg::RSTAT);
            (v & rstat::IRQ != 0).then_some(v)
        })
        .await;
        let r = match st {
            None => {
                defmt::trace!(
                    "std timeout: RSTAT={=u8:02x} ESTAT={=u8:02x} RSC={} SCON={=u8:02x}",
                    self.read_reg(reg::RSTAT),
                    self.read_reg(ext::ESTAT),
                    self.rsc(),
                    self.read_reg(reg::SCON)
                );
                self.write_reg(reg::SCON, SCON_CARRYON); // stop receiving
                Err(Error::Timeout)
            }
            Some(v) if v & rstat::TMROVER != 0 => Err(Error::Timeout),
            Some(v) if v & rstat::CERR != 0 => Err(Error::Collision),
            Some(v) if v & rstat::CRCERR != 0 => Err(Error::Crc),
            Some(v) if v & rstat::PERR != 0 => Err(Error::Parity),
            Some(v) if v & rstat::FERR != 0 => Err(Error::Framing),
            Some(v) if v & rstat::DATOVER != 0 => Err(Error::Overflow),
            Some(_) => self.fetch(rx),
        };
        self.write_reg(reg::RSTAT, 0);
        r
    }

    /// Extended path (original @0x801264c + 0x801242a): write 0x1C=1 to start, poll 0x14.
    async fn transceive_ext(&mut self, tx: &[u8], rx: &mut [u8], timeout_us: u32) -> Result<usize, Error> {
        self.load(tx);
        self.write_reg(ext::ESTAT, 0);
        self.write_reg(ext::START, 1);
        let st = self.poll(timeout_us, |s| {
            let v = s.read_reg(ext::ESTAT);
            (v != 0).then_some(v)
        })
        .await;
        let r = match st {
            None => Err(Error::Timeout),
            Some(v) if v & 0xEF != 0 => Err(self.ext_error(v)),
            Some(_) => self.fetch(rx),
        };
        self.write_reg(ext::ESTAT, 0);
        self.write_reg(reg::RSTAT, 0);
        r
    }

    /// Bits of extended status 0x14 are undocumented; cross-check against RSTAT for a more specific error.
    fn ext_error(&self, v: u8) -> Error {
        let rs = self.read_reg(reg::RSTAT);
        defmt::trace!("ext err: ESTAT={=u8:02x} RSTAT={=u8:02x} RSC={}", v, rs, self.rsc());
        // Measured: with no card in the field ESTAT=0x08 (bit3 = no response / timeout)
        if v == 0x08 || rs & rstat::TMROVER != 0 {
            Error::Timeout
        } else if rs & rstat::CERR != 0 {
            Error::Collision
        } else if rs & rstat::CRCERR != 0 || v & 0x02 != 0 {
            // Measured: ESTAT=0x12 on bad signal (0x10 done | 0x02), same bit position as RSTAT.CRCERR
            Error::Crc
        } else if rs & rstat::PERR != 0 {
            Error::Parity
        } else {
            Error::Ext(v)
        }
    }

    /// Poll until `f` returns Some or the deadline (timeout + 5ms margin) expires. Yields to the executor between polls.
    async fn poll<T>(&self, timeout_us: u32, mut f: impl FnMut(&Self) -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + Duration::from_micros(timeout_us as u64 + 5_000);
        loop {
            if let Some(v) = f(self) {
                return Some(v);
            }
            if Instant::now() > deadline {
                return None;
            }
            Timer::after_micros(50).await;
        }
    }

    // ---------------- Mifare Classic (Crypto1, undocumented feature) ----------------

    /// Mifare Classic three-pass authentication. Flow taken from the original @0x801184c:
    /// 1. Plaintext 60/61 + block, card returns 4-byte nt
    /// 2. 0x15=0x08; nt -> 0x17..0x1A; 6 key bytes + 4 UID bytes -> 0x16; nr -> 0x17..0x1A
    /// 3. 0x15=0x0C to start, poll 0x14; success means (v & 0xEF)==0
    /// 4. 0x15=0x08, 0x12=1 to enable encryption; later frames are encrypted by the chip
    ///
    /// `nr` is the reader nonce (the original just used the 4 bytes at flash address 0, i.e. effectively a constant).
    pub async fn mifare_auth(
        &mut self,
        key_b: bool,
        block: u8,
        key: &[u8; 6],
        uid4: &[u8; 4],
        nr: &[u8; 4],
    ) -> Result<(), Error> {
        self.write_reg(ext::CRYPTO_EN, 0);
        // Measured: without returning 0x15 to 0x00 first, a second auth (after re-activation) always fails
        self.write_reg(ext::CRYPTO_CTL, 0x00);
        // Same as the original: CRCSEL stays 0xC1 (as set at SELECT); in the extended path the chip doesn't strip CRC
        self.set_crc(true, true);
        self.set_timeout_units(17); // ~5ms
        let mut nt = [0u8; 8];
        let n = self.transceive_ext(&[if key_b { 0x61 } else { 0x60 }, block], &mut nt, 5_000).await?;
        if n != 4 {
            return Err(Error::AuthFailed);
        }
        self.write_reg(ext::CRYPTO_CTL, 0x08);
        for i in 0..4 {
            self.write_reg(ext::NONCE0 + i as u8, nt[i]);
        }
        for &b in key.iter().chain(uid4.iter()) {
            self.write_reg(ext::CRYPTO_FIFO, b);
        }
        for i in 0..4 {
            self.write_reg(ext::NONCE0 + i as u8, nr[i]);
        }
        self.write_reg(ext::CRYPTO_CTL, 0x0C);
        let st = self.poll(10_000, |s| {
            let v = s.read_reg(ext::ESTAT);
            (v != 0).then_some(v)
        })
        .await;
        let ok = matches!(st, Some(v) if v & 0xEF == 0);
        self.write_reg(ext::ESTAT, 0);
        self.write_reg(ext::CRYPTO_CTL, 0x08);
        if ok {
            self.write_reg(ext::CRYPTO_EN, 1);
            Ok(())
        } else {
            Err(Error::AuthFailed)
        }
    }

    /// Leave the encrypted session (back to plaintext)
    pub fn mifare_crypto_off(&mut self) {
        self.write_reg(ext::CRYPTO_EN, 0);
    }
}
