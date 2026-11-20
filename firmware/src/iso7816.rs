//! Contact smart cards (ISO 7816-3, T=0) on 5 bit-banged slots.
//!
//! Reverse-engineered from the original firmware: dispatcher @0x800fb0c takes slot codes
//! 0x0C..0x10 and calls 5 copies of the same driver. Slot 1 (code 0x0C, @0x800af74, reset @0x800b4c0,
//! deactivate @0x800b454, rx byte @0x800a500) has its own clock; the other four share one.
//!
//! | Slot | Orig code | I/O  | RST  | CLK                     | EXTI |
//! |------|-----------|------|------|-------------------------|------|
//! | 1    | 0x0C      | PB11 | PB12 | PA7 = TIM3_CH2, 4MHz    | 11   |
//! | 2    | 0x0D      | PC7  | PC6  | PB0 = TIM3_CH3, 4MHz    | 7    |
//! | 3    | 0x0E      | PC9  | PC8  | PB0                     | 9 (borrowed from the magstripe) |
//! | 4    | 0x0F      | PB13 | PB10 | PB0                     | 13   |
//! | 5    | 0x10      | PC12 | PB14 | PB0                     | 12   |
//!
//! - I/O and RST are open-drain (the original: Out_OD 50MHz; I/O switched to pull-up input to receive).
//! - CLK: TIM3 PSC=0 ARR=17 PWM 50% → 72MHz/18 = 4MHz. Clock stop = pin back to push-pull low. Slots 2-5
//!   share PB0, so it only stops once none of them is in use.
//! - No VCC switch: card power is always on. Cold reset = RST low, I/O high, CLK on, ≥400 clk, RST high.
//!
//! Character layer (nothing here blocks the executor for longer than one character):
//! - **Receive** runs in the EXTI interrupt of the slot's I/O line (P0, the highest priority): the start bit's
//!   falling edge enters the ISR, which samples the whole character against the DWT cycle counter, sends the
//!   error signal on a parity error (the card repeats the character) and queues the byte. The task side just
//!   awaits the queue. Slot 3's line 9 is shared with the magstripe track 2 clock: it is borrowed for as long
//!   as slot 3 is in use (a swipe meanwhile loses track 2).
//! - **Transmit** sends one character with interrupts off (~1.1ms at the default 93us etu); between characters
//!   the executor runs.
//! - While spinning with interrupts off or inside the ISR, magstripe clock edges are serviced inline
//!   ([`crate::magstripe::service`]) so a swipe isn't lost to contact-card traffic.
//! - A P5 module command needs the same exclusive real-time access (its I2C frames are received in a P0
//!   ISR too): every operation here runs under [`crate::rt::RT_LOCK`], taken by the caller.

use core::future::poll_fn;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use core::task::Poll;

use embassy_sync::waitqueue::AtomicWaker;
use embassy_time::{with_timeout, Duration, Timer};

const RCC_APB2ENR: u32 = 0x4002_1018;
const RCC_APB1ENR: u32 = 0x4002_101C;
const AFIO_EXTICR2: u32 = 0x4001_000C; // EXTI4..7
const AFIO_EXTICR3: u32 = 0x4001_0010; // EXTI8..11
const AFIO_EXTICR4: u32 = 0x4001_0014; // EXTI12..15
const EXTI_IMR: u32 = 0x4001_0400;
const EXTI_FTSR: u32 = 0x4001_040C;
const EXTI_PR: u32 = 0x4001_0414;
const GPIOA: u32 = 0x4001_0800;
const GPIOB: u32 = 0x4001_0C00;
const GPIOC: u32 = 0x4001_1000;
const TIM3: u32 = 0x4000_0400;
const DEMCR: u32 = 0xE000_EDFC;
const DWT_CTRL: u32 = 0xE000_1000;
const DWT_CYCCNT: u32 = 0xE000_1004;

const OUT_OD: u32 = 0x7; // open-drain output 50MHz
const OUT_PP: u32 = 0x3;
const AF_PP: u32 = 0xB;
const IN_PUPD: u32 = 0x8;

/// Card clock divider from SYSCLK (TIM3 ARR+1).
const CLK_DIV: u32 = 18;
const CYC_PER_US: u32 = crate::board::SYSCLK_HZ / 1_000_000;
/// CPU cycles per etu at the default F=372, D=1 (used for the ATR).
pub const DEFAULT_ETU: u32 = 372 * CLK_DIV;

/// Fi / Di tables (ISO 7816-3 tables 7/8); 0 = RFU.
const FI: [u32; 16] = [372, 372, 558, 744, 1116, 1488, 1860, 0, 0, 512, 768, 1024, 1536, 2048, 0, 0];
const DI: [u32; 16] = [0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0];

/// Fastest etu we trust the bit-banged UART with, in card clocks (16 clk = 288 CPU cycles = 4us).
pub const MIN_ETU_CLOCKS: u32 = 16;

/// Cycles from the start bit's falling edge to the first instruction of the ISR that reads DWT
/// (exception entry + embassy's handler dispatch); measured from the sampling margin, see `on_exti`.
const ISR_LATENCY: u32 = 40;

/// Pick the PPS1 to propose for a card offering `ta1`: the card's Fi with the largest Di that is ≤ the card's
/// and keeps etu ≥ MIN_ETU_CLOCKS. None = default (0x11) is the best option, no PPS needed.
fn choose_fd(ta1: u8) -> Option<u8> {
    let (fi, di) = ((ta1 >> 4) as usize, (ta1 & 0x0F) as usize);
    let (f, dmax) = (FI[fi], DI[di]);
    if f == 0 || dmax == 0 {
        return None;
    }
    let best = (1..16)
        .filter(|&i| DI[i] != 0 && DI[i] <= dmax && f / DI[i] >= MIN_ETU_CLOCKS)
        .max_by_key(|&i| DI[i])?;
    let fd = ((fi as u8) << 4) | best as u8;
    // Fi=372 or 0 with D=1 is the default itself
    if DI[best] == 1 && f == 372 {
        None
    } else {
        Some(fd)
    }
}

type Pin = (u32, u8);

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
    // CRL/CRH are shared with other drivers' pins: never let an interrupt write the same register in between
    cortex_m::interrupt::free(|_| wr(reg, (rd(reg) & !(0xF << sh)) | (nib << sh)));
}
#[inline(always)]
fn set((base, pin): Pin, hi: bool) {
    wr(base + 0x10, if hi { 1 << pin } else { 1 << (pin + 16) });
}
#[inline(always)]
fn get((base, pin): Pin) -> bool {
    rd(base + 0x08) & (1 << pin) != 0
}
#[inline(always)]
fn now() -> u32 {
    rd(DWT_CYCCNT)
}
/// Spin until cycle stamp `t`, keeping the magstripe serviced. Only for short waits (< 1s).
#[inline(always)]
fn wait_until(t: u32) {
    while (now().wrapping_sub(t) as i32) < 0 {
        crate::magstripe::service();
    }
}
/// Like [`wait_until`] but tolerant of stamps far in the past (the DWT counter wraps every ~60s).
fn wait_until_recent(t: u32) {
    let left = t.wrapping_sub(now()) as i32;
    if left > 0 && (left as u32) < CYC_PER_US * 1_000_000 {
        wait_until(t);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum Slot {
    S1,
    S2,
    S3,
    S4,
    S5,
}

impl Slot {
    pub const ALL: [Slot; 5] = [Slot::S1, Slot::S2, Slot::S3, Slot::S4, Slot::S5];

    fn io(self) -> Pin {
        match self {
            Slot::S1 => (GPIOB, 11),
            Slot::S2 => (GPIOC, 7),
            Slot::S3 => (GPIOC, 9),
            Slot::S4 => (GPIOB, 13),
            Slot::S5 => (GPIOC, 12),
        }
    }
    fn rst(self) -> Pin {
        match self {
            Slot::S1 => (GPIOB, 12),
            Slot::S2 => (GPIOC, 6),
            Slot::S3 => (GPIOC, 8),
            Slot::S4 => (GPIOB, 10),
            Slot::S5 => (GPIOB, 14),
        }
    }
    fn clk(self) -> Pin {
        match self {
            Slot::S1 => (GPIOA, 7),
            _ => (GPIOB, 0),
        }
    }
    /// EXTI line of the I/O pin = its pin number
    fn line(self) -> u32 {
        self.io().1 as u32
    }
    fn from_index(i: u8) -> Slot {
        Slot::ALL[(i as usize).min(4)]
    }
    /// Slot number as used by the original firmware's dispatcher.
    pub fn orig_code(self) -> u8 {
        0x0C + self as u8
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum Error {
    /// No start bit within the waiting time
    Timeout,
    /// Parity still wrong after retries, or characters lost
    Parity,
    /// Card kept signalling a parity error on our transmission
    TxRejected,
    /// ATR malformed / too long, or an unexpected procedure byte
    Protocol,
    /// Response doesn't fit the buffer
    Overflow,
}

pub struct Atr {
    pub bytes: [u8; 33],
    pub len: usize,
}

impl Atr {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// ---------------- receiver (EXTI interrupt) ----------------

const RING: usize = 320;
static mut RX_BUF: [u8; RING] = [0; RING];
static RX_HEAD: AtomicUsize = AtomicUsize::new(0); // ISR writes
static RX_TAIL: AtomicUsize = AtomicUsize::new(0); // task writes
/// Slot index being received + 1; 0 = receiver off
static RX_SLOT: AtomicU8 = AtomicU8::new(0);
static RX_ETU: AtomicU32 = AtomicU32::new(DEFAULT_ETU);
/// Bit 0 = convention known (TS seen: check parity from now on), bit 1 = inverse convention
static RX_MODE: AtomicU8 = AtomicU8::new(0);
const MODE_KNOWN: u8 = 1;
const MODE_INVERSE: u8 = 2;
/// Characters lost (queue full or parity retries exhausted) since the receiver was armed
static RX_FAULT: AtomicBool = AtomicBool::new(false);
static RX_ERRS: AtomicU8 = AtomicU8::new(0);
/// Cycle stamp of the last received start bit
static RX_LAST: AtomicU32 = AtomicU32::new(0);
static RX_WAKER: AtomicWaker = AtomicWaker::new();
/// Parity errors signalled since boot (diagnostics)
pub static PARITY_ERRORS: AtomicU32 = AtomicU32::new(0);

/// embassy interrupt binding, on both `EXTI9_5` and `EXTI15_10` (list it first: it is the timing-critical one)
pub struct ExtiIrq;
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::EXTI9_5> for ExtiIrq {
    unsafe fn on_interrupt() {
        on_exti();
    }
}
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::EXTI15_10> for ExtiIrq {
    unsafe fn on_interrupt() {
        on_exti();
    }
}

fn on_exti() {
    let t0 = now().wrapping_sub(ISR_LATENCY);
    let s = RX_SLOT.load(Ordering::Relaxed);
    if s == 0 {
        return;
    }
    let slot = Slot::from_index(s - 1);
    let line = 1 << slot.line();
    if rd(EXTI_PR) & line == 0 {
        return;
    }
    let io = slot.io();
    let etu = RX_ETU.load(Ordering::Relaxed);
    if get(io) {
        // Glitch, not a start bit (it must still be low half an etu in)
        wr(EXTI_PR, line);
        return;
    }
    let mode = RX_MODE.load(Ordering::Relaxed);
    let mut v: u16 = 0;
    for i in 0..9 {
        wait_until(t0.wrapping_add(etu * 3 / 2 + i * etu));
        if get(io) {
            v |= 1 << i;
        }
    }
    let raw = v as u8;
    if mode & MODE_KNOWN == 0 {
        // TS decides the convention: 3B direct, 3F inverse (reads 03 through direct decoding)
        RX_MODE.store(MODE_KNOWN | if raw == 0x03 { MODE_INVERSE } else { 0 }, Ordering::Relaxed);
    }
    // Even parity over data + parity bit (inverse convention: line levels are inverted, 9 inverted bits flip
    // the count's parity, so check odd there). TS itself is not checked.
    let ones = v.count_ones() & 1;
    let ok = mode & MODE_KNOWN == 0 || if mode & MODE_INVERSE != 0 { ones == 1 } else { ones == 0 };
    if !ok && RX_ERRS.load(Ordering::Relaxed) < 3 {
        // Error signal: pull I/O low from 10.5 etu for 1.5 etu; the card repeats the character
        RX_ERRS.fetch_add(1, Ordering::Relaxed);
        PARITY_ERRORS.fetch_add(1, Ordering::Relaxed);
        wait_until(t0.wrapping_add(etu * 21 / 2));
        set(io, false);
        cfg_nolock(io, OUT_OD);
        wait_until(t0.wrapping_add(etu * 12));
        set(io, true);
        cfg_nolock(io, IN_PUPD);
        wr(EXTI_PR, line);
        return;
    }
    if !ok {
        RX_FAULT.store(true, Ordering::Relaxed);
    }
    RX_ERRS.store(0, Ordering::Relaxed);
    RX_LAST.store(t0, Ordering::Relaxed);
    let h = RX_HEAD.load(Ordering::Relaxed);
    let next = (h + 1) % RING;
    if next == RX_TAIL.load(Ordering::Acquire) {
        RX_FAULT.store(true, Ordering::Relaxed);
    } else {
        unsafe { (*core::ptr::addr_of_mut!(RX_BUF))[h] = raw };
        RX_HEAD.store(next, Ordering::Release);
    }
    // Falling edges inside the character (data bits) set PR too: clear it now, after the parity bit was
    // sampled and before the next start bit (≥ 2 etu of stop / guard time away)
    wr(EXTI_PR, line);
    crate::rt::wake_from_p0(crate::rt::WAKE_ICC_RX);
}

/// Wake the task waiting for received characters (from [`crate::rt::WakeIrq`], below P0)
pub fn wake_rx() {
    RX_WAKER.wake();
}

fn rx_pop() -> Option<u8> {
    let t = RX_TAIL.load(Ordering::Relaxed);
    if t == RX_HEAD.load(Ordering::Acquire) {
        return None;
    }
    let b = unsafe { (*core::ptr::addr_of!(RX_BUF))[t] };
    RX_TAIL.store((t + 1) % RING, Ordering::Release);
    Some(b)
}

/// Point the receiver at `slot` (convention unknown until TS) and empty the queue.
fn rx_arm(slot: Slot, etu: u32, mode: u8) {
    let line = 1 << slot.line();
    cortex_m::interrupt::free(|_| wr(EXTI_IMR, rd(EXTI_IMR) & !line));
    if slot == Slot::S3 {
        crate::magstripe::lend_line9(true);
    }
    RX_ETU.store(etu, Ordering::Relaxed);
    RX_MODE.store(mode, Ordering::Relaxed);
    RX_FAULT.store(false, Ordering::Relaxed);
    RX_ERRS.store(0, Ordering::Relaxed);
    RX_TAIL.store(RX_HEAD.load(Ordering::Acquire), Ordering::Release);
    RX_SLOT.store(slot as u8 + 1, Ordering::Release);
    wr(EXTI_PR, line);
    cortex_m::interrupt::free(|_| wr(EXTI_IMR, rd(EXTI_IMR) | line));
}

fn rx_disarm(slot: Slot) {
    if RX_SLOT.load(Ordering::Acquire) != slot as u8 + 1 {
        return;
    }
    let line = 1 << slot.line();
    cortex_m::interrupt::free(|_| wr(EXTI_IMR, rd(EXTI_IMR) & !line));
    RX_SLOT.store(0, Ordering::Release);
    wr(EXTI_PR, line);
    if slot == Slot::S3 {
        crate::magstripe::lend_line9(false);
    }
}

// ---------------- slot-level ----------------

/// Slots whose clock is running (bit = slot index)
static CLOCKED: AtomicU8 = AtomicU8::new(0);

/// One-time setup: clocks, TIM3 4MHz PWM on CH2/CH3, DWT cycle counter, EXTI routing, all slots idle.
pub fn init() {
    wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4)); // AFIO, IOPA/B/C
    wr(RCC_APB1ENR, rd(RCC_APB1ENR) | (1 << 1)); // TIM3

    // TIM3: PSC=0, ARR=17, PWM mode 1 on CH2/CH3 at 50%, outputs enabled. Pins decide if the clock gets out.
    wr(TIM3 + 0x00, 0); // CR1 off while configuring
    wr(TIM3 + 0x28, 0); // PSC
    wr(TIM3 + 0x2C, CLK_DIV - 1); // ARR
    wr(TIM3 + 0x18, (0b110 << 12) | (1 << 11)); // CCMR1: OC2M=PWM1, OC2PE
    wr(TIM3 + 0x1C, (0b110 << 4) | (1 << 3)); // CCMR2: OC3M=PWM1, OC3PE
    wr(TIM3 + 0x38, CLK_DIV / 2); // CCR2
    wr(TIM3 + 0x3C, CLK_DIV / 2); // CCR3
    wr(TIM3 + 0x20, (1 << 4) | (1 << 8)); // CCER: CC2E, CC3E
    wr(TIM3 + 0x14, 1); // EGR: UG, load preloads
    wr(TIM3 + 0x00, 1 << 7 | 1); // CR1: ARPE, CEN

    wr(DEMCR, rd(DEMCR) | (1 << 24)); // TRCENA
    wr(DWT_CTRL, rd(DWT_CTRL) | 1); // CYCCNTENA

    // EXTI routing for the I/O lines (masked until a slot is received from): 7 <- C, 11 <- B, 12 <- C, 13 <- B.
    // Line 9 stays with the magstripe (port A) until slot 3 borrows it.
    cortex_m::interrupt::free(|_| {
        wr(AFIO_EXTICR2, (rd(AFIO_EXTICR2) & !(0xF << 12)) | (0x2 << 12));
        wr(AFIO_EXTICR3, (rd(AFIO_EXTICR3) & !(0xF << 12)) | (0x1 << 12));
        wr(AFIO_EXTICR4, (rd(AFIO_EXTICR4) & !0xFF) | 0x2 | (0x1 << 4));
        wr(EXTI_IMR, rd(EXTI_IMR) & !((1 << 7) | (1 << 11) | (1 << 12) | (1 << 13)));
        wr(EXTI_FTSR, rd(EXTI_FTSR) | (1 << 7) | (1 << 9) | (1 << 11) | (1 << 12) | (1 << 13));
    });

    for s in Slot::ALL {
        deactivate(s);
    }
}

fn clock(slot: Slot, on: bool) {
    let bit = 1u8 << slot as u8;
    let shared = 0b11110u8; // slots 2-5 on PB0
    let c = slot.clk();
    if on {
        CLOCKED.fetch_or(bit, Ordering::Relaxed);
        cfg(c, AF_PP);
    } else {
        let left = CLOCKED.fetch_and(!bit, Ordering::Relaxed) & !bit;
        if slot != Slot::S1 && left & shared != 0 {
            return; // another PSAM slot still needs PB0
        }
        set(c, false);
        cfg(c, OUT_PP);
    }
}

/// Deactivate like the original (@0x800b454): RST low, CLK stopped low (unless shared and in use), I/O low.
pub fn deactivate(slot: Slot) {
    rx_disarm(slot);
    set(slot.rst(), false);
    cfg(slot.rst(), OUT_OD);
    clock(slot, false);
    set(slot.io(), false);
    cfg(slot.io(), OUT_OD);
}

/// One card session on a slot. Dropping it deactivates the slot.
pub struct Card {
    slot: Slot,
    inverse: bool,
    /// Extra guard time (TC1), etu
    extra_gt: u32,
    /// Work waiting time, etu (960 × WI × D; WI from TC2, default 10)
    wwt: u32,
    /// Current etu in CPU cycles
    etu: u32,
    /// Current Fi/Di as a TA1-style byte (high nibble = Fi index, low = Di index); 0x11 = default
    fd: u8,
    /// WI from TC2 (WWT = 960 × WI × D)
    wi: u32,
    /// TA1 as offered in the ATR (0x11 if absent)
    ta1: u8,
    /// No TA2 in the ATR: parameters may be changed by PPS
    negotiable: bool,
    /// Earliest cycle stamp at which we may start sending the next character
    tx_ready: u32,
}

impl Card {
    /// Cold reset and read the ATR, then PPS if worthwhile. On failure the slot is deactivated again.
    pub async fn activate(slot: Slot) -> Result<(Card, Atr), Error> {
        let (mut card, atr) = Self::activate_no_pps(slot).await?;
        if !card.negotiable {
            return Ok((card, atr));
        }
        let Some(fd) = choose_fd(card.ta1) else {
            return Ok((card, atr)); // default parameters are already the best we can do
        };
        match card.pps(fd).await {
            Ok(()) => {
                defmt::debug!("{}: PPS ok, Fi/Di now 0x{=u8:02x}", slot, card.fd);
                Ok((card, atr))
            }
            Err(e) => {
                // ISO 7816-3 §9.3: unsuccessful PPS -> deactivate; start over without PPS at default speed
                defmt::warn!("{}: PPS {=u8:02x} failed ({}), cold reset at default speed", slot, fd, e);
                drop(card);
                Self::activate_no_pps(slot).await
            }
        }
    }

    /// Cold reset + ATR only. Specific mode (TA2) is still honoured; negotiable cards stay at the default.
    pub async fn activate_no_pps(slot: Slot) -> Result<(Card, Atr), Error> {
        let mut card = Card::cold_reset(slot);
        // On error `card` is dropped, which deactivates the slot
        let mut atr = Atr { bytes: [0; 33], len: 0 };
        match card.read_atr(&mut atr).await {
            Ok(()) => {
                // Like the original (end of @0x800b4c0): give the card 10ms before the first command.
                // Without it this JavaCard (specific mode, D=12) misses the first command header.
                Timer::after_millis(10).await;
                rx_disarm(slot); // re-armed per exchange: nothing listens to the line in between
                Ok((card, atr))
            }
            Err(e) => {
                defmt::trace!("{}: ATR failed ({}) after {=[u8]:02x}", slot, e, atr.as_slice());
                Err(e)
            }
        }
    }

    /// RST low, I/O released, CLK on, ≥400 clocks, RST high; receiver armed for the ATR.
    fn cold_reset(slot: Slot) -> Card {
        let card = Card {
            slot,
            inverse: false,
            extra_gt: 0,
            wwt: 9600,
            etu: DEFAULT_ETU,
            fd: 0x11,
            wi: 10,
            ta1: 0x11,
            negotiable: true,
            tx_ready: now(),
        };
        let (io, rst) = (slot.io(), slot.rst());
        set(rst, false);
        cfg(rst, OUT_OD);
        set(io, true);
        cfg(io, IN_PUPD); // ODR=1 -> pull-up
        clock(slot, true);
        wait_until(now().wrapping_add(2 * DEFAULT_ETU)); // ≥400 clocks (original: 105us)
        rx_arm(slot, DEFAULT_ETU, 0);
        set(rst, true);
        card
    }

    /// Current Fi/Di (TA1 encoding, as CCID's bmFindexDindex).
    pub fn fd(&self) -> u8 {
        self.fd
    }

    /// CCID T=0 parameters (abProtocolDataStructure, CCID 6.2.3):
    /// bmFindexDindex, bmTCCKST0 (bit1 = inverse convention), bGuardTimeT0 (TC1), bWaitingIntegerT0 (WI),
    /// bClockStop (0 = not allowed).
    pub fn t0_params(&self) -> [u8; 5] {
        [self.fd, (self.inverse as u8) << 1, self.extra_gt as u8, self.wi as u8, 0]
    }

    /// Current etu in nanoseconds.
    pub fn etu_ns(&self) -> u32 {
        self.etu * 1000 / CYC_PER_US
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    fn set_fd(&mut self, fd: u8) -> Result<(), Error> {
        let (f, d) = (FI[(fd >> 4) as usize], DI[(fd & 0x0F) as usize]);
        if f == 0 || d == 0 || f / d < MIN_ETU_CLOCKS {
            return Err(Error::Protocol);
        }
        self.etu = (f * CLK_DIV + d / 2) / d;
        self.wwt = 960 * self.wi * d;
        self.fd = fd;
        RX_ETU.store(self.etu, Ordering::Relaxed);
        Ok(())
    }

    /// PPS exchange (ISO 7816-3 §9) for T=0 with PPS1 = `fd`. On success the new Fi/Di is in effect.
    async fn pps(&mut self, fd: u8) -> Result<(), Error> {
        rx_arm(self.slot, self.etu, MODE_KNOWN | if self.inverse { MODE_INVERSE } else { 0 });
        let r = self.pps_inner(fd).await;
        rx_disarm(self.slot);
        r
    }

    async fn pps_inner(&mut self, fd: u8) -> Result<(), Error> {
        let req = [0xFF, 0x10, fd, 0xFF ^ 0x10 ^ fd];
        for b in req {
            self.tx(b).await?;
        }
        let ppss = self.rx(9600).await?;
        let pps0 = self.rx(9600).await?;
        // PPSS = FF, same protocol (T=0), and no PPS2/PPS3/RFU bits since we didn't send them
        if ppss != 0xFF || pps0 & 0x0F != 0 || pps0 & 0xE0 != 0 {
            return Err(Error::Protocol);
        }
        let mut pck = ppss ^ pps0;
        let mut new_fd = 0x11; // PPS1 absent in the response = keep default Fi/Di
        if pps0 & 0x10 != 0 {
            new_fd = self.rx(9600).await?;
            pck ^= new_fd;
        }
        pck ^= self.rx(9600).await?;
        if pck != 0 || (new_fd != fd && new_fd != 0x11) {
            return Err(Error::Protocol);
        }
        if new_fd != 0x11 {
            self.set_fd(new_fd)?;
        }
        Ok(())
    }

    async fn read_atr(&mut self, atr: &mut Atr) -> Result<(), Error> {
        // First character within 40000 clocks after RST high (~108 etu); allow some margin
        let ts = self.rx_raw(200).await?;
        self.inverse = match ts {
            0x3B => false,
            0x03 => true, // 0x3F sent in inverse convention, as seen through direct decoding
            _ => return Err(Error::Protocol),
        };
        let push = |atr: &mut Atr, b: u8| -> Result<(), Error> {
            if atr.len >= atr.bytes.len() {
                return Err(Error::Overflow);
            }
            atr.bytes[atr.len] = b;
            atr.len += 1;
            Ok(())
        };
        push(atr, if self.inverse { 0x3F } else { 0x3B })?;

        let t0 = self.rx(9600).await?;
        push(atr, t0)?;
        let hist = (t0 & 0x0F) as usize;
        let mut y = t0 >> 4;
        let mut i = 1; // interface byte group index
        let mut need_tck = false;
        let mut ta1 = 0x11u8; // default Fi=372 Di=1
        let mut ta2 = None;
        let mut wi = 10u32;
        loop {
            let mut td = None;
            for bit in 0..4 {
                if y & (1 << bit) == 0 {
                    continue;
                }
                let b = self.rx(9600).await?;
                push(atr, b)?;
                match (i, bit) {
                    (1, 0) => ta1 = b,
                    (1, 2) => self.extra_gt = if b == 0xFF { 0 } else { b as u32 }, // TC1
                    (2, 0) => ta2 = Some(b),
                    (2, 2) => wi = b.max(1) as u32, // TC2 = WI
                    (_, 3) => td = Some(b),
                    _ => {}
                }
            }
            match td {
                Some(td) => {
                    if td & 0x0F != 0 {
                        need_tck = true;
                    }
                    y = td >> 4;
                    i += 1;
                }
                None => break,
            }
        }
        for _ in 0..hist {
            let b = self.rx(9600).await?;
            push(atr, b)?;
        }
        if need_tck {
            let b = self.rx(9600).await?;
            push(atr, b)?;
            if atr.as_slice()[1..].iter().fold(0, |a, b| a ^ b) != 0 {
                return Err(Error::Protocol);
            }
        }
        self.wi = wi;
        self.wwt = 960 * wi;
        self.ta1 = ta1;
        self.negotiable = ta2.is_none();
        // Specific mode (TA2 present, bit5 = 0): the card uses TA1's Fi/Di right after the ATR.
        // Negotiable mode: default until a PPS says otherwise.
        if let Some(ta2) = ta2 {
            if ta2 & 0x10 != 0 {
                return Err(Error::Protocol); // implicit parameters: can't follow
            }
            self.set_fd(ta1)?; // also fails if the card's speed is beyond what we can bit-bang
        }
        Ok(())
    }

    // ---- character level ----

    fn code(&self, b: u8) -> u8 {
        if self.inverse {
            !b.reverse_bits()
        } else {
            b
        }
    }

    /// Next received character as it came off the line (direct-convention bit order). `wait_etu` = max wait.
    async fn rx_raw(&mut self, wait_etu: u32) -> Result<u8, Error> {
        if RX_FAULT.load(Ordering::Relaxed) {
            return Err(Error::Parity);
        }
        if let Some(b) = rx_pop() {
            return Ok(b);
        }
        // + 2ms: the ISR is still busy with the character when a start bit right at the deadline arrives
        let us = (wait_etu as u64 * self.etu as u64) / CYC_PER_US as u64 + 2_000;
        let got = with_timeout(
            Duration::from_micros(us),
            poll_fn(|cx| {
                RX_WAKER.register(cx.waker());
                match rx_pop() {
                    Some(b) => Poll::Ready(b),
                    None => Poll::Pending,
                }
            }),
        )
        .await;
        match got {
            Ok(b) if !RX_FAULT.load(Ordering::Relaxed) => Ok(b),
            Ok(_) => Err(Error::Parity),
            Err(_) => Err(Error::Timeout),
        }
    }

    async fn rx(&mut self, wait_etu: u32) -> Result<u8, Error> {
        let b = self.rx_raw(wait_etu).await?;
        Ok(self.code(b))
    }

    /// Send one character; retransmit if the card signals a parity error.
    async fn tx(&mut self, b: u8) -> Result<(), Error> {
        let raw = self.code(b);
        let etu = self.etu;
        let io = self.slot.io();
        let line = 1u32 << self.slot.line();
        // ≥16 etu between the leading edges of the card's last character and our next one
        let after_rx = RX_LAST.load(Ordering::Relaxed).wrapping_add(16 * etu);
        for _ in 0..4 {
            let parity_bit = if self.inverse {
                // Line-level bits get inverted, so send odd parity of the raw value
                (raw.count_ones() & 1) ^ 1
            } else {
                raw.count_ones() & 1
            };
            let frame: u16 = ((raw as u16) << 1) | ((parity_bit as u16) << 9) | (1 << 10); // start=0, stop=1
            // Guard times with interrupts on (being late is harmless), then the character with them off
            wait_until_recent(self.tx_ready);
            wait_until_recent(after_rx);
            let err = cortex_m::interrupt::free(|_| {
                let t0 = now();
                // Our own edges must not look like the card's start bits
                wr(EXTI_IMR, rd(EXTI_IMR) & !line);
                set(io, true);
                cfg_nolock(io, OUT_OD);
                for i in 0..11 {
                    wait_until(t0.wrapping_add(i * etu));
                    set(io, frame & (1 << i) != 0);
                }
                // Release; sample for the error signal around 11 etu
                set(io, true);
                cfg_nolock(io, IN_PUPD);
                wait_until(t0.wrapping_add(etu * 11));
                let err = !get(io);
                if err {
                    // Wait out the error signal; retransmit ≥2 etu later
                    wait_until(t0.wrapping_add(etu * 14));
                    self.tx_ready = now();
                } else {
                    // Guard time: ≥12 etu (+N from TC1) between leading edges of our characters
                    self.tx_ready = t0.wrapping_add((12 + self.extra_gt) * etu);
                }
                wr(EXTI_PR, line);
                wr(EXTI_IMR, rd(EXTI_IMR) | line);
                err
            });
            if !err {
                // Let the rest of the firmware run between characters (no upper limit on our side but WT)
                embassy_futures::yield_now().await;
                return Ok(());
            }
            PARITY_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        Err(Error::TxRejected)
    }

    // ---- T=0 ----

    /// Send one T=0 command TPDU (5-byte header + optional data), collect response data + SW1 SW2.
    /// `data` non-empty = outgoing (case 3), otherwise incoming into `resp` (P3 = expected length).
    async fn tpdu(&mut self, hdr: &[u8; 5], data: &[u8], resp: &mut [u8]) -> Result<(usize, u8, u8), Error> {
        let ins = hdr[1];
        let incoming = data.is_empty();
        let mut want = if incoming { if hdr[4] == 0 { 256 } else { hdr[4] as usize } } else { data.len() };
        if incoming && hdr[4] == 0 && resp.is_empty() {
            want = 0; // case 1
        }
        for &b in hdr {
            self.tx(b).await?;
        }
        let (mut sent, mut got) = (0usize, 0usize);
        loop {
            let pb = self.rx(self.wwt).await?;
            match pb {
                0x60 => continue,
                _ if pb == ins || pb == ins ^ 0xFF => {
                    let n = if pb == ins { usize::MAX } else { 1 };
                    if incoming {
                        let n = n.min(want - got);
                        for _ in 0..n {
                            let b = self.rx(self.wwt).await?;
                            if got >= resp.len() {
                                return Err(Error::Overflow);
                            }
                            resp[got] = b;
                            got += 1;
                        }
                    } else {
                        let n = n.min(data.len() - sent);
                        for _ in 0..n {
                            self.tx(data[sent]).await?;
                            sent += 1;
                        }
                    }
                }
                0x61..=0x6F | 0x90..=0x9F => {
                    let sw2 = self.rx(self.wwt).await?;
                    return Ok((got, pb, sw2));
                }
                _ => {
                    defmt::debug!(
                        "T=0: unexpected procedure byte {=u8:02x} (hdr {=[u8]:02x}, sent {=usize}, got {=usize})",
                        pb, &hdr[..], sent, got
                    );
                    return Err(Error::Protocol);
                }
            }
        }
    }

    /// Exchange a short command APDU (cases 1-4) and return the response APDU (data + SW1 SW2) in `resp`.
    /// Handles 61xx (GET RESPONSE) and 6Cxx (resend with correct Le) like a T=0 reader should.
    pub async fn transmit(&mut self, apdu: &[u8], resp: &mut [u8]) -> Result<usize, Error> {
        // A previous exchange may have left garbage or a fault behind (e.g. the card kept talking)
        rx_arm(self.slot, self.etu, MODE_KNOWN | if self.inverse { MODE_INVERSE } else { 0 });
        let r = self.transmit_inner(apdu, resp).await;
        rx_disarm(self.slot);
        r
    }

    async fn transmit_inner(&mut self, apdu: &[u8], resp: &mut [u8]) -> Result<usize, Error> {
        if apdu.len() < 4 || resp.len() < 2 {
            return Err(Error::Protocol);
        }
        let mut hdr = [apdu[0], apdu[1], apdu[2], apdu[3], 0];
        let body = &apdu[4..];
        // Parse case
        let (data, le): (&[u8], Option<usize>) = match body.len() {
            0 => (&[], None),
            1 => (&[], Some(if body[0] == 0 { 256 } else { body[0] as usize })),
            n => {
                let lc = body[0] as usize;
                if n == 1 + lc {
                    (&body[1..], None)
                } else if n == 2 + lc {
                    let l = body[1 + lc];
                    (&body[1..1 + lc], Some(if l == 0 { 256 } else { l as usize }))
                } else {
                    return Err(Error::Protocol);
                }
            }
        };
        let cap = resp.len() - 2;
        let (mut n, mut sw1, mut sw2);
        if !data.is_empty() {
            hdr[4] = data.len() as u8;
            (n, sw1, sw2) = self.tpdu(&hdr, data, &mut []).await?;
        } else {
            hdr[4] = le.map(|l| l as u8).unwrap_or(0);
            let buf_len = if le.is_some() { cap } else { 0 };
            (n, sw1, sw2) = self.tpdu(&hdr, &[], &mut resp[..buf_len]).await?;
            if sw1 == 0x6C {
                // Wrong Le: resend with the length the card asked for
                hdr[4] = sw2;
                (n, sw1, sw2) = self.tpdu(&hdr, &[], &mut resp[..cap]).await?;
            }
        }
        // 61xx: more data available -> GET RESPONSE
        let mut total = n;
        while sw1 == 0x61 {
            let gr = [hdr[0], 0xC0, 0x00, 0x00, sw2];
            let (k, a, b) = self.tpdu(&gr, &[], &mut resp[total..cap]).await?;
            total += k;
            sw1 = a;
            sw2 = b;
            if sw1 == 0x6C {
                let gr = [hdr[0], 0xC0, 0x00, 0x00, sw2];
                let (k, a, b) = self.tpdu(&gr, &[], &mut resp[total..cap]).await?;
                total += k;
                sw1 = a;
                sw2 = b;
            }
        }
        if total + 2 > resp.len() {
            return Err(Error::Overflow);
        }
        resp[total] = sw1;
        resp[total + 1] = sw2;
        Ok(total + 2)
    }
}

/// [`cfg`] for code already inside a critical section
fn cfg_nolock((base, pin): Pin, nib: u32) {
    let reg = if pin < 8 { base } else { base + 4 };
    let sh = ((pin % 8) * 4) as u32;
    wr(reg, (rd(reg) & !(0xF << sh)) | (nib << sh));
}

impl Drop for Card {
    fn drop(&mut self) {
        deactivate(self.slot);
    }
}
