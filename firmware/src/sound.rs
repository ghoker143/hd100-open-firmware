//! Buzzer + voice chip.
//!
//! Reverse-engineered from the original firmware:
//! - **Buzzer: PD2**, push-pull, active high, self-oscillating (active buzzer). The original just drives
//!   it high for N ms (@0x80087e0); boot beep is 50ms (@0x8008830).
//! - **Voice chip: unmarked SOP8 OTP voice IC with pulse-count interface, on the SWD pins.**
//!   PA14 (SWCLK) = RST, PA13 (SWDIO) = DATA. Init @0x80099c0 drives both low; play @0x8009a28:
//!   both low 1ms, RST high 1ms, RST low, then N × (DATA high 1ms, DATA low 1ms) selects clip N.
//!   The original takes N straight from a host command byte, so the firmware itself has no clip table.
//!
//! Because the voice chip lives on PA13/PA14, the original firmware turns SWD off for good. With SWD on,
//! the debug pull-up on SWDIO / pull-down on SWCLK look like "RST low + one DATA edge" to the chip, which
//! is why the board says clip 1 ("请插卡") on power-up even with the original firmware erased.
//!
//! [`Voice::play`] / [`Voice::mute`] take the pins away from SWD (SWJ_CFG=100). Measured on this board: writing
//! SWJ_CFG back to 010 afterwards does **not** bring SWD back, so after the first use the board can only be
//! reflashed through the system bootloader (BOOT0=1). The main firmware therefore leaves the chip alone unless
//! built with `--features mute`.

use core::ptr::{read_volatile, write_volatile};

use embassy_time::Timer;

const RCC_APB2ENR: u32 = 0x4002_1018;
const AFIO_MAPR: u32 = 0x4001_0004;
const GPIOA: u32 = 0x4001_0800;
const GPIOD: u32 = 0x4001_1400;

const PP50: u32 = 0x3;

const VOICE_DATA: u8 = 13; // PA13
const VOICE_RST: u8 = 14; // PA14
const BUZZER: u8 = 2; // PD2

const SWJ_SWD_ONLY: u32 = 0b010;
const SWJ_ALL_OFF: u32 = 0b100;

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
    wr(reg, (rd(reg) & !(0xF << sh)) | (nib << sh));
}
#[inline(always)]
fn set(base: u32, pin: u8, hi: bool) {
    wr(base + 0x10, if hi { 1 << pin } else { 1 << (pin + 16) });
}
/// SWJ_CFG is write-only (reads back undefined), so always write it explicitly; keep the other remap bits.
fn swj(mode: u32) {
    wr(AFIO_MAPR, (rd(AFIO_MAPR) & !(0x7 << 24)) | (mode << 24));
}

pub struct Buzzer;

impl Buzzer {
    pub fn new() -> Self {
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 5)); // IOPD
        set(GPIOD, BUZZER, false);
        cfg(GPIOD, BUZZER, PP50);
        Buzzer
    }

    pub fn set(&mut self, on: bool) {
        set(GPIOD, BUZZER, on);
    }

    /// Beep for `ms` milliseconds (the original uses 50ms).
    pub async fn beep(&mut self, ms: u64) {
        self.set(true);
        Timer::after_millis(ms).await;
        self.set(false);
    }
}

impl Default for Buzzer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Voice {
    /// Hand PA13/PA14 back to SWD after each command (development); false = keep them as GPIO like the original.
    pub keep_swd: bool,
    swd_on: bool,
}

impl Voice {
    /// Doesn't touch the pins yet: SWD stays usable until the first [`Voice::play`].
    pub fn new(keep_swd: bool) -> Self {
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 2) | (1 << 0)); // IOPA + AFIO
        Voice { keep_swd, swd_on: true }
    }

    pub fn swd_enabled(&self) -> bool {
        self.swd_on
    }

    fn take_pins(&mut self) {
        set(GPIOA, VOICE_DATA, false);
        set(GPIOA, VOICE_RST, false);
        cfg(GPIOA, VOICE_DATA, PP50);
        cfg(GPIOA, VOICE_RST, PP50);
        swj(SWJ_ALL_OFF);
        self.swd_on = false;
    }

    /// Try to give PA13/PA14 back to the debugger. **Measured not to work on this board** (SWD stays
    /// dead after SWJ_CFG 100 -> 010).
    pub fn release_swd(&mut self) {
        swj(SWJ_SWD_ONLY);
        // Put the GPIO config back to its reset value (floating input) so nothing fights the SWD logic
        cfg(GPIOA, VOICE_DATA, 0x4);
        cfg(GPIOA, VOICE_RST, 0x4);
        self.swd_on = true;
    }

    /// Shut the chip up for good: PA13/PA14 become GPIO and RST is held high, so the chip sits in reset
    /// (aborts the "请插卡" the SWD pulls queue at power-on, verified silent 2026-11-20).
    ///
    /// **SWD is gone afterwards**: measured on this board, writing SWJ_CFG back to 010 after 100 does not
    /// bring SWD back. Reflash via BOOT0=1.
    pub fn mute(&mut self) {
        self.take_pins();
        self.keep_swd = false;
        set(GPIOA, VOICE_RST, true);
    }

    /// Play clip `n` (1-based pulse count, as in the original). `n = 0` just resets the chip (stops playback).
    pub async fn play(&mut self, n: u8) {
        if self.swd_on {
            self.take_pins();
        }
        set(GPIOA, VOICE_RST, false);
        set(GPIOA, VOICE_DATA, false);
        Timer::after_millis(1).await;
        set(GPIOA, VOICE_RST, true);
        Timer::after_millis(1).await;
        set(GPIOA, VOICE_RST, false);
        for _ in 0..n {
            set(GPIOA, VOICE_DATA, true);
            Timer::after_millis(1).await;
            set(GPIOA, VOICE_DATA, false);
            Timer::after_millis(1).await;
        }
        if self.keep_swd {
            // Let the chip latch the count before the lines float back to the SWD pulls
            Timer::after_millis(20).await;
            self.release_swd();
        }
    }
}
