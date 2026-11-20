//! Real-time arbitration and interrupt priorities.
//!
//! Two things need the CPU with exact timing for long stretches, and would corrupt each other:
//! - a contact-card exchange: characters received in the EXTI interrupt of the I/O line (~1ms each at the
//!   default rate) and sent with interrupts off (iso7816.rs);
//! - a P5 module command: its I2C frames are received in the EXTI15 interrupt, and it gives up if our
//!   answer is late (idsam.rs).
//!
//! Both take [`RT_LOCK`] for the whole operation, so they never overlap. Everything else is either short
//! or tolerates being preempted (bit-banged SPI to the THM3060 / LCD is clocked by us).
//!
//! Interrupt priorities (Cortex-M3, lower number = more urgent):
//! | Prio | Interrupts | Why |
//! |------|------------|-----|
//! | P0   | EXTI9_5, EXTI15_10 | contact-card start bits, ID module frames, magstripe clocks: sub-us latency |
//! | P0   | USART2 | ID module UART. Must not be preempted by EXTI15: while the module sends a long UART answer it
//! |      |        | also raises PB15 (no I2C frame), and each of those costs a ~50us EXTI15 visit. At equal priority
//! |      |        | USART2 (IRQ 38) is served before EXTI15_10 (IRQ 40) when both are pending; at P1 it overran (measured). |
//! | P1   | SPI2 (unused peripheral) | software interrupt: wakes tasks on behalf of P0 handlers |
//! | P2   | USB, TIM4 (embassy time) | just wake tasks |
//!
//! **Critical sections never mask P0.** The `critical-section` implementation below raises BASEPRI to P1
//! instead of setting PRIMASK, so the embassy internals (executor queues, time driver, wakers, defmt) can't
//! delay a start bit: at the fastest rates a contact-card bit is 4us. The price: P0 handlers must not use
//! anything guarded by a critical section — no wakers, channels or logging, only atomics. They hand over
//! through [`wake_from_p0`].

use embassy_stm32::interrupt::{self, InterruptExt, Priority};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

pub static RT_LOCK: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

/// BASEPRI value that masks P1 and everything below it (Cortex-M3: 4 priority bits in the top nibble)
const MASK_P1: u8 = 0x10;

struct BasepriCs;
critical_section::set_impl!(BasepriCs);

unsafe impl critical_section::Impl for BasepriCs {
    unsafe fn acquire() -> u32 {
        let old = cortex_m::register::basepri::read();
        cortex_m::register::basepri_max::write(MASK_P1);
        old as u32
    }

    unsafe fn release(old: u32) {
        unsafe { cortex_m::register::basepri::write(old as u8) };
    }
}

/// Wake-ups requested from P0 handlers, run from the SPI2 interrupt (bit = [`crate::iso7816`] receiver, ..)
static P0_WAKES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
pub const WAKE_ICC_RX: u32 = 1 << 0;

/// From a P0 handler: have `what` woken as soon as P0 is done.
#[inline(always)]
pub fn wake_from_p0(what: u32) {
    P0_WAKES.fetch_or(what, core::sync::atomic::Ordering::Relaxed);
    interrupt::SPI2.pend();
}

/// embassy interrupt binding: `SPI2 => rt::WakeIrq`
pub struct WakeIrq;
impl embassy_stm32::interrupt::typelevel::Handler<embassy_stm32::interrupt::typelevel::SPI2> for WakeIrq {
    unsafe fn on_interrupt() {
        let w = P0_WAKES.swap(0, core::sync::atomic::Ordering::Relaxed);
        if w & WAKE_ICC_RX != 0 {
            crate::iso7816::wake_rx();
        }
    }
}

/// Keep the CPU out of sleep (see [`keep_awake`])
static AWAKE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Stop (or allow again) the CPU from sleeping when idle.
///
/// Measured on this board: while the P5 module is running, bursts of I/O (LCD page writes, contact-card
/// probes) separated by CPU sleep make the LCD backlight flicker visibly; the same work with the CPU kept
/// awake doesn't, and neither does a pure CPU burst. Mechanism unknown (supply / ground shared with the
/// module?). Costs ~20mA, so only done when a module is present (most boards have none).
pub fn set_keep_awake(on: bool) {
    AWAKE.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Task: while [`set_keep_awake`] is on, keeps the executor busy so it never reaches WFE.
pub async fn keep_awake() -> ! {
    loop {
        if AWAKE.load(core::sync::atomic::Ordering::Relaxed) {
            embassy_futures::yield_now().await;
        } else {
            embassy_time::Timer::after_millis(50).await;
        }
    }
}

/// Call first thing in `main`, before `embassy_stm32::init` enables any interrupt.
pub fn set_priorities() {
    interrupt::EXTI9_5.set_priority(Priority::P0);
    interrupt::EXTI15_10.set_priority(Priority::P0);
    interrupt::USART2.set_priority(Priority::P0);
    interrupt::SPI2.set_priority(Priority::P1);
    unsafe { interrupt::SPI2.enable() };
    interrupt::USB_LP_CAN1_RX0.set_priority(Priority::P2);
    interrupt::TIM4.set_priority(Priority::P2);
}
