//! Board-level setup shared by the main firmware and the test programs.

use embassy_stm32::time::Hertz;
use embassy_stm32::Config;

/// System clock: 8MHz HSE x9 = 72MHz (USB gets 72 / 1.5 = 48MHz).
pub const SYSCLK_HZ: u32 = 72_000_000;

/// Clocks + SWJ. SWJ_CFG=010 (SwdOnly): frees PB3/PB4 (keypad) and PA15 (magstripe), keeps SWD.
pub fn config() -> Config {
    use embassy_stm32::rcc::{AHBPrescaler, APBPrescaler, Hse, HseMode, Pll, PllMul, PllPreDiv, PllSource, Sysclk};
    let mut config = Config::default();
    config.rcc.hse = Some(Hse { freq: Hertz(8_000_000), mode: HseMode::Oscillator });
    config.rcc.pll = Some(Pll { src: PllSource::HSE, prediv: PllPreDiv::DIV1, mul: PllMul::MUL9 });
    config.rcc.sys = Sysclk::PLL1_P;
    config.rcc.ahb_pre = AHBPrescaler::DIV1;
    config.rcc.apb1_pre = APBPrescaler::DIV2;
    config.rcc.apb2_pre = APBPrescaler::DIV1;
    config.swj = embassy_stm32::gpio::SwjCfg::SwdOnly;
    config
}
