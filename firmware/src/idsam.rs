//! P5 security module (SAM, a black box). Reverse-engineered from the original firmware.
//!
//! The module has two links to the MCU:
//! - **Host side, USART2** (PA2 TX / PA3 RX, 115200 8N1, original @0x8014452): standard SAM frames
//!   `AA AA AA 96 69 | LEN(2, BE) | CMD PARA DATA.. | XOR`. LEN counts CMD through the checksum;
//!   XOR covers LEN..last data byte. Responses: `.. | LEN | SW1 SW2 SW3 DATA.. | XOR`.
//!   Receive state machine is the original USART2 RXNE handler @0x80144a8.
//! - **Card side, bit-banged I2C** (original @0x8013c4c..0x8014352). The module has no RF of its own:
//!   it hands each RF frame to the MCU, which sends it through the THM3060 (Type B, chip adds/checks CRC_B)
//!   and gives the card's answer back.
//!     PB8 = SCL, PB9 = SDA (module has pull-ups; we use open-drain, the original switches push-pull/input)
//!     PB15 = module "I have a frame" (high = request)
//!     PC14 = MCU "I'm sending" (high during an MCU-master write)
//!     PC13 = module reset (low 10ms, then high)
//!   Module → MCU: module is master, MCU acts as slave receiver (ACKs every byte); STOP ends the frame.
//!   MCU → module: MCU is master, writes card answer + one status byte `00` (original @0x801432a/0x8014352).
//!   If the card doesn't answer, the original sends nothing back and the module times out by itself.
//!
//! Timing (measured): the module raises PB15 and starts clocking immediately; reacting 500µs late loses the
//! frame. So the module → MCU receive runs in the EXTI15 interrupt (PB15 rising), enabled only while a command
//! is in flight. PB15 also goes high while the module sends a long UART response (no I2C START then): the ISR
//! gives up after 50µs so USART2 doesn't overrun. The module waits tens of ms for our answer, so the RF
//! exchange and the MCU → module write run in the task.
//!
//! A long command relays ~44 RF frames over ~1s.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use embassy_time::{Duration, Instant};

use crate::thm3060::{Protocol, Thm3060};

fn rd(a: u32) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
fn wr(a: u32, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}

const RCC_APB2ENR: u32 = 0x4002_1018;
const RCC_APB1ENR: u32 = 0x4002_101C;
const AFIO_EXTICR4: u32 = 0x4001_0014;
const EXTI_IMR: u32 = 0x4001_0400;
const EXTI_RTSR: u32 = 0x4001_0408;
const EXTI_PR: u32 = 0x4001_0414;
const GPIOA_CRL: u32 = 0x4001_0800;
const GPIOA_IDR: u32 = 0x4001_0808;
const GPIOA_BSRR: u32 = 0x4001_0810;
const GPIOB_CRH: u32 = 0x4001_0C04;
const GPIOB_IDR: u32 = 0x4001_0C08;
const GPIOB_BSRR: u32 = 0x4001_0C10;
const GPIOC_CRH: u32 = 0x4001_1004;
const GPIOC_BSRR: u32 = 0x4001_1010;
const USART2: u32 = 0x4000_4400;
const USART_SR: u32 = USART2;
const USART_DR: u32 = USART2 + 0x04;
const USART_BRR: u32 = USART2 + 0x08;
const USART_CR1: u32 = USART2 + 0x0C;
const NVIC_ISER1: u32 = 0xE000_E104;
const IRQ_USART2: u32 = 38;
const IRQ_EXTI15_10: u32 = 40;
const DWT_CYCCNT: u32 = 0xE000_1004;
const DWT_CTRL: u32 = 0xE000_1000;
const DEMCR: u32 = 0xE000_EDFC;

const SCL: u32 = 8; // PB8
const SDA: u32 = 9; // PB9
const REQ: u32 = 15; // PB15
const MCU_TX: u32 = 14; // PC14
const MOD_RST: u32 = 13; // PC13
const RXD: u32 = 3; // PA3, module TX

const CYC_PER_US: u32 = crate::board::SYSCLK_HZ / 1_000_000;

fn now() -> u32 {
    rd(DWT_CYCCNT)
}
fn delay_us(us: u32) {
    let t0 = now();
    while now().wrapping_sub(t0) < us * CYC_PER_US {
        crate::magstripe::service();
    }
}
/// Spin until `f()` is true; false on timeout.
#[inline(always)]
fn wait(us: u32, f: impl Fn() -> bool) -> bool {
    let t0 = now();
    loop {
        if f() {
            return true;
        }
        crate::magstripe::service();
        if now().wrapping_sub(t0) >= us * CYC_PER_US {
            return false;
        }
    }
}

#[inline(always)]
fn pin_b(n: u32) -> bool {
    rd(GPIOB_IDR) & (1 << n) != 0
}
/// Atomic set/reset (BSRR): safe against the task / ISR and against other code sharing GPIOB
#[inline(always)]
fn set_b(n: u32, high: bool) {
    wr(GPIOB_BSRR, if high { 1 << n } else { 1 << (n + 16) });
}
#[inline(always)]
fn set_c(n: u32, high: bool) {
    wr(GPIOC_BSRR, if high { 1 << n } else { 1 << (n + 16) });
}
fn cfg_b(n: u32, nib: u32) {
    let sh = (n - 8) * 4;
    // CRL/CRH read-modify-write: P0 interrupts (contact-card error signal) touch other pins of the same
    // register and aren't masked by critical sections (rt.rs), so keep them out with PRIMASK
    cortex_m::interrupt::free(|_| wr(GPIOB_CRH, (rd(GPIOB_CRH) & !(0xF << sh)) | (nib << sh)));
}
fn cfg_c(n: u32, nib: u32) {
    let sh = (n - 8) * 4;
    // CRL/CRH read-modify-write: P0 interrupts (contact-card error signal) touch other pins of the same
    // register and aren't masked by critical sections (rt.rs), so keep them out with PRIMASK
    cortex_m::interrupt::free(|_| wr(GPIOC_CRH, (rd(GPIOC_CRH) & !(0xF << sh)) | (nib << sh)));
}

const OUT_PP: u32 = 0x3;
const OUT_OD: u32 = 0x7;
const IN_PULL: u32 = 0x8;
const IN_FLOAT: u32 = 0x4;

#[inline(always)]
fn scl() -> bool {
    pin_b(SCL)
}
#[inline(always)]
fn sda() -> bool {
    pin_b(SDA)
}

// ---------------- USART2 receive ring (filled by the RXNE interrupt) ----------------

/// 1295-byte answers arrive in ~112ms; the task drains this every executor pass while a command runs
const RING: usize = 1024;
static mut RING_BUF: [u8; RING] = [0; RING];
static HEAD: AtomicUsize = AtomicUsize::new(0); // written by the ISR
static TAIL: AtomicUsize = AtomicUsize::new(0); // written by the reader
static OVERRUNS: AtomicUsize = AtomicUsize::new(0);

/// embassy interrupt binding: `USART2 => idsam::Usart2Irq`
pub struct Usart2Irq;
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::USART2> for Usart2Irq {
    unsafe fn on_interrupt() {
        on_usart2();
    }
}

fn on_usart2() {
    let sr = rd(USART_SR);
    if sr & ((1 << 5) | (1 << 3)) != 0 {
        // RXNE or ORE: reading DR clears both
        let b = rd(USART_DR) as u8;
        if sr & (1 << 3) != 0 {
            OVERRUNS.fetch_add(1, Ordering::Relaxed);
        }
        let h = HEAD.load(Ordering::Relaxed);
        let next = (h + 1) % RING;
        if next != TAIL.load(Ordering::Acquire) {
            unsafe { (*core::ptr::addr_of_mut!(RING_BUF))[h] = b };
            HEAD.store(next, Ordering::Release);
        } else {
            OVERRUNS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn ring_pop() -> Option<u8> {
    let t = TAIL.load(Ordering::Relaxed);
    if t == HEAD.load(Ordering::Acquire) {
        return None;
    }
    let b = unsafe { (*core::ptr::addr_of!(RING_BUF))[t] };
    TAIL.store((t + 1) % RING, Ordering::Release);
    Some(b)
}

fn ring_clear() {
    TAIL.store(HEAD.load(Ordering::Acquire), Ordering::Release);
}

// ---------------- module → MCU frames (received in the EXTI15 interrupt) ----------------

/// Largest RF frame the module hands over (seen ≤ 15 bytes; the card answers are the long ones)
const MAX_RF: usize = 300;
const NO_FRAME: usize = usize::MAX;
static mut RF_BUF: [u8; MAX_RF] = [0; MAX_RF];
/// Length of the frame in RF_BUF, NO_FRAME = empty. ISR fills it, the task empties it.
static RF_LEN: AtomicUsize = AtomicUsize::new(NO_FRAME);
static LINK_ERRORS: AtomicU16 = AtomicU16::new(0);
static NOT_FRAMES: AtomicU16 = AtomicU16::new(0);

/// embassy interrupt binding, shared with the magstripe: `EXTI15_10 => magstripe::Exti10Irq, idsam::Exti15Irq`
pub struct Exti15Irq;
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::EXTI15_10> for Exti15Irq {
    unsafe fn on_interrupt() {
        on_exti15();
    }
}

/// PB15 rising. Call from the EXTI15_10 interrupt.
pub fn on_exti15() {
    if rd(EXTI_PR) & (1 << REQ) == 0 {
        return;
    }
    wr(EXTI_PR, 1 << REQ);
    if RF_LEN.load(Ordering::Acquire) != NO_FRAME {
        return; // previous frame not handled yet (shouldn't happen: the module waits for our answer)
    }
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(RF_BUF) };
    match slave_receive(buf) {
        Ok(n) => RF_LEN.store(n.min(MAX_RF), Ordering::Release),
        Err(LinkError::NoStart) => {
            NOT_FRAMES.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            LINK_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Module → MCU (module is master). Port of @0x8013f2e / 0x8013d42 / 0x8013dfa, lines already released.
fn slave_receive(buf: &mut [u8]) -> Result<usize, LinkError> {
    // START: SDA already low by the time PB15 is up (measured). If it isn't, this is the "busy" level.
    if !wait(50, || !sda()) {
        return Err(LinkError::NoStart);
    }
    if !wait(2_000, || !scl()) {
        return Err(LinkError::NoStart);
    }
    let mut n = 0;
    loop {
        let mut b = 0u8;
        for _ in 0..8 {
            if !wait(5_000, scl) {
                return Err(LinkError::Stall);
            }
            b = (b << 1) | sda() as u8;
            // SCL staying high = STOP (original: ~500 loop iterations ≈ 60µs)
            if !wait(100, || !scl()) {
                return Ok(n);
            }
        }
        // ACK: hold SDA low over the 9th clock
        set_b(SDA, false);
        let ok = wait(100, scl) && wait(100, || !scl());
        set_b(SDA, true);
        if !ok {
            return Err(LinkError::Stall);
        }
        if n < buf.len() {
            buf[n] = b;
        }
        n += 1;
    }
}

/// MCU → module (MCU is master, PC14 high around it). Port of @0x8014254, open-drain.
/// Call with interrupts off (bit timing).
fn master_send(data: &[u8]) -> Result<(), LinkError> {
    set_c(MCU_TX, false);
    set_b(SDA, true);
    set_b(SCL, true);
    set_c(MCU_TX, true);
    delay_us(3);
    // START
    set_b(SDA, false);
    delay_us(4);
    set_b(SCL, false);
    let mut r = Ok(());
    for &byte in data {
        let mut b = byte;
        delay_us(1);
        for _ in 0..8 {
            set_b(SDA, b & 0x80 != 0);
            b <<= 1;
            delay_us(1);
            set_b(SCL, true);
            delay_us(4);
            set_b(SCL, false);
            delay_us(2);
        }
        // ACK: release SDA while SCL is low, clock, module pulls SDA low
        set_b(SDA, true);
        delay_us(1);
        set_b(SCL, true);
        let ack = wait(100, || !sda());
        delay_us(2);
        set_b(SCL, false);
        if !ack {
            r = Err(LinkError::Nak);
            break;
        }
        delay_us(2);
    }
    // STOP (@0x8014010)
    set_b(SDA, false);
    delay_us(3);
    set_b(SCL, true);
    delay_us(4);
    set_b(SDA, true);
    delay_us(4);
    set_c(MCU_TX, false);
    r
}

fn exti15_enable(on: bool) {
    if on {
        wr(EXTI_PR, 1 << REQ);
        wr(EXTI_IMR, rd(EXTI_IMR) | (1 << REQ));
    } else {
        wr(EXTI_IMR, rd(EXTI_IMR) & !(1 << REQ));
        wr(EXTI_PR, 1 << REQ);
    }
}

// ---------------- driver ----------------

pub const HEADER: [u8; 5] = [0xAA, 0xAA, 0xAA, 0x96, 0x69];
/// Largest response frame (longest seen: 2321 bytes).
pub const MAX_FRAME: usize = 2400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Error {
    /// No complete response frame on the UART in time
    Timeout,
    /// Response frame checksum wrong
    Checksum,
    /// Response longer than MAX_FRAME
    Overflow,
}

/// Card-side link errors (not fatal: the module just times out on its side)
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum LinkError {
    NoStart,
    Stall,
    Nak,
}

#[derive(Default, Clone, Copy, defmt::Format)]
pub struct Stats {
    /// RF frames relayed / not answered by the card
    pub relayed: u16,
    pub rf_errors: u16,
    /// Module → MCU receive errors (ISR), MCU → module NAKs, PB15 rises without a frame
    pub link_errors: u16,
    pub naks: u16,
    pub not_frames: u16,
}

pub struct IdSam {
    frame: [u8; MAX_FRAME],
    flen: usize,
    /// Parser position inside the frame being received
    pos: usize,
    relayed: u16,
    rf_errors: u16,
    naks: u16,
    /// Log every relayed RF frame (debug)
    pub trace: bool,
    link: Link,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    /// Pins passive, nothing driven
    Down,
    /// Pins driven and module reset, but it hasn't answered yet
    Reset,
    Up,
}

/// How long [`IdSam::ensure`] keeps asking a freshly reset module
const BOOT_TIMEOUT: Duration = Duration::from_millis(1500);

impl IdSam {
    /// Passive setup only: nothing is driven high yet, see [`ensure`](Self::ensure).
    /// Bind `USART2 => idsam::Usart2Irq` and `EXTI15_10 => .., idsam::Exti15Irq` first.
    ///
    /// Most boards ship without the module, and an unpowered module clamps every pin to ground (driving
    /// PA2 / PC13 high would back-power it), so the link only comes up once the module shows it's alive.
    pub fn new() -> Self {
        // DWT cycle counter for the bit-bang timing
        wr(DEMCR, rd(DEMCR) | (1 << 24));
        wr(DWT_CTRL, rd(DWT_CTRL) | 1);
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | 1 | (1 << 2) | (1 << 3) | (1 << 4)); // AFIO, IOPA/B/C
        wr(RCC_APB1ENR, rd(RCC_APB1ENR) | (1 << 17)); // USART2

        // PA2 (our TX) floating input for now; PA3 (module TX) pull-down input: idle-high only if powered
        wr(GPIOA_BSRR, 1 << (RXD + 16));
        wr(GPIOA_CRL, (rd(GPIOA_CRL) & !(0xFF << 8)) | (0x4 << 8) | (IN_PULL << 12));
        // PC13 / PC14 low (module reset held, "MCU sending" off); SCL / SDA / PB15 floating inputs
        set_c(MCU_TX, false);
        set_c(MOD_RST, false);
        cfg_c(MCU_TX, OUT_PP);
        cfg_c(MOD_RST, OUT_PP);
        cfg_b(SCL, IN_FLOAT);
        cfg_b(SDA, IN_FLOAT);
        cfg_b(REQ, IN_FLOAT);

        IdSam { frame: [0; MAX_FRAME], flen: 0, pos: 0, relayed: 0, rf_errors: 0, naks: 0, trace: false, link: Link::Down }
    }

    /// Link up and the module answered at least once
    pub fn is_up(&self) -> bool {
        self.link == Link::Up
    }

    /// Module powered? Its UART TX idles high; unpowered it is clamped low, absent our pull-down wins.
    fn powered() -> bool {
        rd(GPIOA_IDR) & (1 << RXD) != 0
    }

    /// Bring the link up if it isn't (USART2, I2C pins, reset pulse) and check the module answers.
    /// Cheap when it is already up or when there is no powered module (one pin read).
    pub async fn ensure(&mut self) -> bool {
        if self.link == Link::Up {
            return true;
        }
        if !Self::powered() {
            defmt::info!("idsam: no powered module");
            return false;
        }
        // The module needs a moment after reset: keep asking for the SAM ID for a while the first time,
        // later (powered but silent before) just once, so a dead module costs each FF 70 only ~0.2s.
        let budget = if self.link == Link::Down {
            self.bring_up().await;
            self.link = Link::Reset;
            BOOT_TIMEOUT
        } else {
            Duration::from_millis(200)
        };
        let t0 = Instant::now();
        while t0.elapsed() < budget {
            if self.probe(Duration::from_millis(100)).await {
                defmt::info!("idsam: module up after {=u64} ms", t0.elapsed().as_millis());
                self.link = Link::Up;
                return true;
            }
        }
        defmt::info!("idsam: powered but no answer");
        false
    }

    async fn bring_up(&mut self) {
        // PA2 = AF push-pull 50MHz, PA3 = floating input
        wr(GPIOA_CRL, (rd(GPIOA_CRL) & !(0xFF << 8)) | (0xB << 8) | (0x4 << 12));
        // 115200 @ PCLK1 36MHz: 312.5 -> 19 + 8/16 (115384, +0.16%)
        wr(USART_BRR, (19 << 4) | 8);
        wr(USART_CR1, (1 << 13) | (1 << 5) | (1 << 3) | (1 << 2)); // UE, RXNEIE, TE, RE
        let _ = rd(USART_DR);
        ring_clear();
        wr(NVIC_ISER1, 1 << (IRQ_USART2 - 32));

        // Card side: SCL/SDA open-drain, released (CRH is never touched again: the ISR only uses BSRR);
        // PB15 pull-up input on EXTI15 rising (masked until a command is in flight); PC14 low; PC13 reset pulse.
        set_b(SCL, true);
        set_b(SDA, true);
        cfg_b(SCL, OUT_OD);
        cfg_b(SDA, OUT_OD);
        set_b(REQ, true);
        cfg_b(REQ, IN_PULL);
        wr(AFIO_EXTICR4, (rd(AFIO_EXTICR4) & !(0xF << 12)) | (0x1 << 12)); // EXTI15 <- port B
        wr(EXTI_RTSR, rd(EXTI_RTSR) | (1 << REQ));
        exti15_enable(false);
        wr(NVIC_ISER1, 1 << (IRQ_EXTI15_10 - 32));
        set_c(MOD_RST, false);
        embassy_time::Timer::after_millis(10).await;
        set_c(MOD_RST, true);
    }

    /// `12 FF` (read SAM ID): no RF involved. True if a well-formed answer came back in time.
    async fn probe(&mut self, timeout: Duration) -> bool {
        self.send_command(0x12, 0xFF, &[]);
        exti15_enable(false);
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(r) = self.poll_uart() {
                return r.is_ok();
            }
            if Instant::now() >= deadline {
                return false;
            }
            embassy_time::Timer::after_millis(1).await;
        }
    }

    pub fn stats(&self) -> Stats {
        Stats {
            relayed: self.relayed,
            rf_errors: self.rf_errors,
            link_errors: LINK_ERRORS.load(Ordering::Relaxed),
            naks: self.naks,
            not_frames: NOT_FRAMES.load(Ordering::Relaxed),
        }
    }

    fn uart_send(&self, bytes: &[u8]) {
        for &b in bytes {
            while rd(USART_SR) & (1 << 7) == 0 {} // TXE
            wr(USART_DR, b as u32);
        }
        while rd(USART_SR) & (1 << 6) == 0 {} // TC
    }

    fn start(&mut self) {
        ring_clear();
        self.pos = 0;
        self.flen = 0;
        RF_LEN.store(NO_FRAME, Ordering::Release);
        exti15_enable(true);
    }

    /// Send one SAM command frame (header, length, checksum added here).
    pub fn send_command(&mut self, cmd: u8, para: u8, data: &[u8]) {
        let len = (data.len() + 3) as u16;
        let mut chk = (len >> 8) as u8 ^ len as u8 ^ cmd ^ para;
        for &b in data {
            chk ^= b;
        }
        self.start();
        self.uart_send(&HEADER);
        self.uart_send(&len.to_be_bytes());
        self.uart_send(&[cmd, para]);
        self.uart_send(data);
        self.uart_send(&[chk]);
    }

    /// Send a complete pre-built frame as-is (host passthrough).
    pub fn send_raw(&mut self, frame: &[u8]) {
        self.start();
        self.uart_send(frame);
    }

    /// Feed received UART bytes to the frame parser. Some(result) once a frame is complete.
    fn poll_uart(&mut self) -> Option<Result<usize, Error>> {
        while let Some(b) = ring_pop() {
            let p = self.pos;
            if p < 5 {
                // Header AA AA AA 96 69; resync on mismatch (extra AAs keep us in the AA run)
                self.pos = match (p, b) {
                    (_, _) if b == HEADER[p] => p + 1,
                    (3, 0xAA) => 3,
                    (4, 0xAA) => 1,
                    _ => 0,
                };
                self.frame[..self.pos].copy_from_slice(&HEADER[..self.pos]);
                continue;
            }
            self.frame[p] = b;
            self.pos += 1;
            if self.pos >= 7 {
                let total = u16::from_be_bytes([self.frame[5], self.frame[6]]) as usize + 7;
                if total > MAX_FRAME {
                    self.pos = 0;
                    return Some(Err(Error::Overflow));
                }
                if self.pos == total {
                    self.pos = 0;
                    self.flen = total;
                    let chk = self.frame[5..total - 1].iter().fold(0u8, |a, &x| a ^ x);
                    return Some(if chk == self.frame[total - 1] { Ok(total) } else { Err(Error::Checksum) });
                }
            }
        }
        None
    }

    /// Last complete response frame (header .. checksum)
    pub fn frame(&self) -> &[u8] {
        &self.frame[..self.flen]
    }

    /// Run one command: send it, relay RF frames until the response arrives. Returns the response frame length
    /// (see [`frame`](Self::frame)). The RF chip must already be in Type B with the field on ([`rf_on`]).
    pub async fn transact(&mut self, rf: &mut Thm3060, cmd: u8, para: u8, data: &[u8], timeout: Duration) -> Result<usize, Error> {
        self.send_command(cmd, para, data);
        self.wait_response(rf, timeout).await
    }

    /// [`transact`](Self::transact) under the real-time lock ([`crate::rt`]): the module's frames are received
    /// in a P0 interrupt, which contact-card traffic must not overlap.
    pub async fn command(&mut self, rf: &mut Thm3060, cmd: u8, para: u8, data: &[u8], timeout: Duration) -> Result<usize, Error> {
        let _rt = crate::rt::RT_LOCK.lock().await;
        self.transact(rf, cmd, para, data, timeout).await
    }

    /// Relay RF frames and wait for the response to a command already sent.
    pub async fn wait_response(&mut self, rf: &mut Thm3060, timeout: Duration) -> Result<usize, Error> {
        let deadline = Instant::now() + timeout;
        let r = loop {
            let n = RF_LEN.load(Ordering::Acquire);
            if n != NO_FRAME {
                self.relay(rf, n).await;
                RF_LEN.store(NO_FRAME, Ordering::Release);
            }
            if let Some(r) = self.poll_uart() {
                break r;
            }
            if Instant::now() >= deadline {
                defmt::warn!(
                    "idsam: timeout: pos {=usize}, overruns {=usize}, ring {=usize}/{=usize}, link {=u16}, not frames {=u16}, relayed {=u16}",
                    self.pos, OVERRUNS.load(Ordering::Relaxed), HEAD.load(Ordering::Relaxed), TAIL.load(Ordering::Relaxed),
                    LINK_ERRORS.load(Ordering::Relaxed), NOT_FRAMES.load(Ordering::Relaxed), self.relayed
                );
                break Err(Error::Timeout);
            }
            embassy_futures::yield_now().await;
        };
        exti15_enable(false);
        r
    }

    /// One RF round trip on behalf of the module: its frame (already in RF_BUF) to the card, the answer back.
    async fn relay(&mut self, rf: &mut Thm3060, n: usize) {
        let mut tx = [0u8; MAX_RF];
        let src: &[u8; MAX_RF] = unsafe { &*core::ptr::addr_of!(RF_BUF) };
        tx[..n].copy_from_slice(&src[..n]);
        let tx = &tx[..n];
        let mut rx = [0u8; MAX_RF];
        match rf.transceive(tx, &mut rx[..MAX_RF - 1], 100_000).await {
            Ok(m) => {
                if self.trace {
                    defmt::info!("idsam: rf > {=[u8]:02x}", tx);
                    defmt::info!("idsam: rf < {=usize} bytes", m);
                }
                rx[m] = 0x00; // status byte: OK
                self.relayed += 1;
                if cortex_m::interrupt::free(|_| master_send(&rx[..m + 1])).is_err() {
                    self.naks += 1;
                    defmt::warn!("idsam: module NAKed the card answer");
                }
            }
            Err(e) => {
                // Original: no answer to the module, it times out by itself
                self.rf_errors += 1;
                if self.trace {
                    defmt::info!("idsam: rf > {=[u8]:02x} : {}", tx, e);
                }
            }
        }
    }
}

/// RF chip into the state the original uses for the module (@0x80132e4): Type B, field reset, 5ms settle.
/// The field reset puts a card left ACTIVE by an earlier session back to IDLE, so the module's REQB finds it.
pub async fn rf_on(rf: &mut Thm3060) {
    rf.select_protocol(Protocol::TypeB);
    rf.field_reset(10).await;
}

/// UART overruns since boot (ring full or USART ORE)
pub fn overruns() -> usize {
    OVERRUNS.load(Ordering::Relaxed)
}

/// Parsed response: (SW1, SW2, SW3, data)
pub fn split_response(frame: &[u8]) -> Option<(u8, u8, u8, &[u8])> {
    if frame.len() < 11 {
        return None;
    }
    Some((frame[7], frame[8], frame[9], &frame[10..frame.len() - 1]))
}
