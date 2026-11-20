//! Magstripe reader driver: M3-2200L (dual-track F/2F decoder, same as M3-2200G) outputs, captured via EXTI.
//!
//! Wiring (reverse-engineered from the original firmware @0x80107aa / 0x8010832 / 0x800fc2c / 0x8010938):
//!   Track A: /RCP = PC10 (EXTI10, falling edge), /RDT = PA15 (low = bit 1)
//!   Track B: /RCP = PA9  (EXTI9,  falling edge), /RDT = PA8  (low = bit 1)
//!   /CLS    = PA10 (card loading, low = card passing through the head)
//! All inputs use pull-ups. PA15 is JTDI: requires AFIO_MAPR.SWJ_CFG=010 (the keypad driver sets it too).
//!
//! Usage: `MagStripe::new()` once, then call [`on_exti9_5`] / [`on_exti15_10`] from the bin's EXTI9_5 / EXTI15_10
//! interrupt handlers; poll [`MagStripe::poll`] from the main loop — returns the raw bit streams after a swipe ends.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};

const RCC_APB2ENR: u32 = 0x4002_1018;
const AFIO_MAPR: u32 = 0x4001_0004;
const AFIO_EXTICR3: u32 = 0x4001_0010; // EXTI8..11
const EXTI_IMR: u32 = 0x4001_0400;
const EXTI_FTSR: u32 = 0x4001_040C;
const EXTI_PR: u32 = 0x4001_0414;
const GPIOA: u32 = 0x4001_0800;
const GPIOC: u32 = 0x4001_1000;
const NVIC_ISER0: u32 = 0xE000_E100;
const NVIC_ISER1: u32 = 0xE000_E104;
const IRQ_EXTI9_5: u32 = 23;
const IRQ_EXTI15_10: u32 = 40;

/// Max 1024 bits per track (ISO track 1 is 210bpi; an 85mm card is ~700 bits)
pub const MAX_BITS: usize = 1024;

pub struct TrackBuf {
    bits: [AtomicU8; MAX_BITS / 8],
    len: AtomicU16,
}

impl TrackBuf {
    const fn new() -> Self {
        const Z: AtomicU8 = AtomicU8::new(0);
        TrackBuf { bits: [Z; MAX_BITS / 8], len: AtomicU16::new(0) }
    }
    fn push(&self, bit: bool) {
        let n = self.len.load(Ordering::Relaxed) as usize;
        if n >= MAX_BITS {
            return;
        }
        if bit {
            self.bits[n / 8].fetch_or(1 << (n % 8), Ordering::Relaxed);
        }
        self.len.store((n + 1) as u16, Ordering::Release);
    }
    fn clear(&self) {
        for b in self.bits.iter() {
            b.store(0, Ordering::Relaxed);
        }
        self.len.store(0, Ordering::Release);
    }
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire) as usize
    }
    pub fn bit(&self, i: usize) -> bool {
        self.bits[i / 8].load(Ordering::Relaxed) >> (i % 8) & 1 == 1
    }
}

pub static TRACK_A: TrackBuf = TrackBuf::new();
pub static TRACK_B: TrackBuf = TrackBuf::new();
static ACTIVITY: AtomicBool = AtomicBool::new(false);

#[inline(always)]
fn rd(a: u32) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
#[inline(always)]
fn wr(a: u32, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn cfg(base: u32, pin: u8, nib: u32) {
    let reg = if pin < 8 { base } else { base + 4 };
    let sh = ((pin % 8) * 4) as u32;
    // CRL/CRH read-modify-write: P0 interrupts (contact-card error signal) touch other pins of the same
    // register and aren't masked by critical sections (rt.rs), so keep them out with PRIMASK
    cortex_m::interrupt::free(|_| wr(reg, (rd(reg) & !(0xF << sh)) | (nib << sh)));
}
fn pin_low(base: u32, pin: u8) -> bool {
    rd(base + 8) >> pin & 1 == 0
}

/// embassy interrupt binding: `EXTI9_5 => magstripe::Exti9Irq`
pub struct Exti9Irq;
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::EXTI9_5> for Exti9Irq {
    unsafe fn on_interrupt() {
        on_exti9_5();
    }
}

/// embassy interrupt binding: `EXTI15_10 => magstripe::Exti10Irq`
pub struct Exti10Irq;
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::EXTI15_10> for Exti10Irq {
    unsafe fn on_interrupt() {
        on_exti15_10();
    }
}

/// EXTI line 9 currently routed to contact slot 3's I/O (PC9) instead of the track B clock
static LINE9_LENT: AtomicBool = AtomicBool::new(false);

/// Lend EXTI line 9 to contact slot 3 (`true`) or take it back. Track B is deaf meanwhile.
pub fn lend_line9(lend: bool) {
    cortex_m::interrupt::free(|_| {
        LINE9_LENT.store(lend, Ordering::Relaxed);
        let port = if lend { 0x2 } else { 0x0 }; // PC9 / PA9
        wr(AFIO_EXTICR3, (rd(AFIO_EXTICR3) & !(0xF << 4)) | (port << 4));
        wr(EXTI_PR, 1 << 9);
        if !lend {
            // The contact receiver masks the line when it lets go of it
            wr(EXTI_IMR, rd(EXTI_IMR) | (1 << 9));
        }
    });
}

/// Handle pending clock edges right now. For code that spins with interrupts off or inside a long ISR
/// (contact-card characters, P5 module frames): a track clock edge comes every ~150us at a fast swipe.
#[inline(always)]
pub fn service() {
    if rd(EXTI_PR) & ((1 << 9) | (1 << 10)) != 0 {
        on_exti9_5();
        on_exti15_10();
    }
}

/// EXTI9 (track B clock). Call from the EXTI9_5 interrupt.
pub fn on_exti9_5() {
    if rd(EXTI_PR) & (1 << 9) != 0 && !LINE9_LENT.load(Ordering::Relaxed) {
        wr(EXTI_PR, 1 << 9);
        TRACK_B.push(pin_low(GPIOA, 8));
        ACTIVITY.store(true, Ordering::Relaxed);
    }
}

/// EXTI10 (track A clock). Call from the EXTI15_10 interrupt.
pub fn on_exti15_10() {
    if rd(EXTI_PR) & (1 << 10) != 0 {
        wr(EXTI_PR, 1 << 10);
        TRACK_A.push(pin_low(GPIOA, 15));
        ACTIVITY.store(true, Ordering::Relaxed);
    }
}

pub struct MagStripe {
    idle_ticks: u32,
    had_card: bool,
}

/// Result of one swipe (raw bit streams; decode with [`decode`])
pub struct Swipe {
    pub a: &'static TrackBuf,
    pub b: &'static TrackBuf,
}

impl MagStripe {
    pub fn new() -> Self {
        // IOPA/IOPC/AFIO clocks
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 0) | (1 << 2) | (1 << 4));
        // SWJ_CFG=010 frees PA15 (JTDI)
        wr(AFIO_MAPR, (rd(AFIO_MAPR) & !(0x7 << 24)) | (0x2 << 24));
        // Pull-up inputs (CNF=10, ODR=1)
        for (base, pin) in [(GPIOA, 8u8), (GPIOA, 9), (GPIOA, 10), (GPIOA, 15), (GPIOC, 10)] {
            wr(base + 0x10, 1 << pin);
            cfg(base, pin, 0x8);
        }
        // EXTI9 <- PA (0), EXTI10 <- PC (2)
        let cr = rd(AFIO_EXTICR3) & !(0xF << 4 | 0xF << 8);
        wr(AFIO_EXTICR3, cr | (0x0 << 4) | (0x2 << 8));
        TRACK_A.clear();
        TRACK_B.clear();
        wr(EXTI_PR, (1 << 9) | (1 << 10));
        wr(EXTI_FTSR, rd(EXTI_FTSR) | (1 << 9) | (1 << 10));
        wr(EXTI_IMR, rd(EXTI_IMR) | (1 << 9) | (1 << 10));
        wr(NVIC_ISER0, 1 << IRQ_EXTI9_5);
        wr(NVIC_ISER1, 1 << (IRQ_EXTI15_10 - 32));
        MagStripe { idle_ticks: 0, had_card: false }
    }

    /// /CLS level: true = card passing through the head
    pub fn card_present(&self) -> bool {
        pin_low(GPIOA, 10)
    }

    /// Call every ~1ms. Once /CLS goes high and the clock has been quiet for 20 ticks, consider the swipe finished
    /// and return the data. Call [`MagStripe::rearm`] afterwards to clear the buffers.
    pub fn poll(&mut self) -> Option<Swipe> {
        if self.card_present() {
            self.had_card = true;
        }
        if ACTIVITY.swap(false, Ordering::Relaxed) || self.card_present() {
            self.idle_ticks = 0;
            return None;
        }
        self.idle_ticks += 1;
        let have = TRACK_A.len() > 0 || TRACK_B.len() > 0;
        if have && self.idle_ticks >= 20 {
            self.had_card = false;
            return Some(Swipe { a: &TRACK_A, b: &TRACK_B });
        }
        None
    }

    pub fn rearm(&mut self) {
        TRACK_A.clear();
        TRACK_B.clear();
        self.idle_ticks = 0;
    }
}

/// Track encoding
#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum Format {
    /// ISO 7811 track 1: 6 data bits + odd parity, char = v + 0x20, start '%', end '?'
    Alpha7,
    /// ISO 7811 track 2/3: 4 data bits + odd parity, char = v + 0x30, start ';', end '?'
    Bcd5,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum DecodeError {
    NoStart,
    NoEnd,
    Parity,
    Lrc,
    TooLong,
}

/// Decode one track into ASCII (including the start/end sentinels). `reverse` = card swiped backwards (read bits in reverse order).
/// Returns the number of characters written.
pub fn decode(t: &TrackBuf, fmt: Format, reverse: bool, out: &mut [u8]) -> Result<usize, DecodeError> {
    let n = t.len();
    let bit = |i: usize| if reverse { t.bit(n - 1 - i) } else { t.bit(i) };
    let (w, start, end, base) = match fmt {
        Format::Alpha7 => (7usize, 0x05u8, 0x1Fu8, 0x20u8),
        Format::Bcd5 => (5, 0x0B, 0x0F, 0x30),
    };
    let dbits = w - 1;
    let read = |pos: usize| -> (u8, bool) {
        let mut v = 0u8;
        let mut ones = 0;
        for k in 0..w {
            let b = bit(pos + k);
            if b {
                ones += 1;
                if k < dbits {
                    v |= 1 << k;
                }
            }
        }
        (v, ones % 2 == 1)
    };
    // Find the start sentinel (skip leading zeros)
    let mut pos = (0..n.saturating_sub(w)).find(|&p| {
        let (v, ok) = read(p);
        ok && v == start
    }).ok_or(DecodeError::NoStart)?;
    let mut lrc = 0u8;
    let mut k = 0;
    loop {
        if pos + w > n {
            return Err(DecodeError::NoEnd);
        }
        let (v, ok) = read(pos);
        if !ok {
            return Err(DecodeError::Parity);
        }
        if k >= out.len() {
            return Err(DecodeError::TooLong);
        }
        out[k] = v + base;
        k += 1;
        lrc ^= v;
        pos += w;
        if v == end {
            break;
        }
    }
    // LRC character: data bits = XOR of all characters
    if pos + w <= n {
        let (v, _) = read(pos);
        if v != lrc & ((1 << dbits) - 1) {
            return Err(DecodeError::Lrc);
        }
    }
    Ok(k)
}
