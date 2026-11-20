//! 128x64 monochrome LCD (ST7565-compatible controller) + GT21L16S2Y font ROM.
//!
//! Wiring and protocol reverse-engineered from the original firmware:
//!   init @0x800a48e, pins @0x800a352 / 0x8009d92, command @0x8009e38, data @0x8009ef2,
//!   set position @0x8009fa8, clear @0x800a2b0, full-frame blit @0x800a2f8,
//!   font ROM read @0x8009d4c, text @0x800a08e.
//!
//! | Signal       | Pin | Notes                                                    |
//! |--------------|-----|----------------------------------------------------------|
//! | LCD /CS      | PA1 | active low                                               |
//! | LCD /RST     | PA0 | active low                                               |
//! | SCK (shared) | PC3 | LCD SCL and font ROM SCLK                                 |
//! | PC0 (shared) | PC0 | LCD SDA (output) / font ROM SO (input, pull-up)          |
//! | PC2 (shared) | PC2 | LCD A0 (0 = command, 1 = data) / font ROM SI             |
//! | Font /CS     | PC1 | GT21L16S2Y chip select, active low                       |
//!
//! Quirks copied from the original firmware:
//! - Commands go out MSB first, display data goes out **LSB first**.
//! - Page `p` is written to controller page `7 - p`, column `x` to controller column `x + 1`
//!   (the controller has 132 columns; the panel shows 1..=128).
//! - Init: E2, 2F, 60 (start line 32), A0, C0, 25, 81 37 (contrast), AF, 23.
//!
//! Combined, these make a page buffer "logical" ([`Lcd::write_page`]): bit k of `data[x]` is the pixel at
//! (x, 8*page + k) with (0,0) top-left, which is also the byte layout the font ROM returns.
//!
//! All pins sit on GPIOA/GPIOC, shared with other drivers (USB PA11/12, PC11; THM3060 PC4/PC5 ...):
//! outputs only go through atomic BSRR, CRL is read-modify-written only for our own pins.

use core::ptr::{read_volatile, write_volatile};

use embassy_time::Timer;

pub const WIDTH: usize = 128;
pub const HEIGHT: usize = 64;
pub const PAGES: usize = HEIGHT / 8;

/// Default contrast (electronic volume) used by the original firmware.
pub const DEFAULT_CONTRAST: u8 = 0x37;

const RCC_APB2ENR: u32 = 0x4002_1018;
const GPIOA: u32 = 0x4001_0800;
const GPIOC: u32 = 0x4001_1000;

type Pin = (u32, u8);
const LCD_RST: Pin = (GPIOA, 0);
const LCD_CS: Pin = (GPIOA, 1);
const SDA_SO: Pin = (GPIOC, 0);
const FONT_CS: Pin = (GPIOC, 1);
const A0_SI: Pin = (GPIOC, 2);
const SCK: Pin = (GPIOC, 3);

const PP50: u32 = 0x3; // push-pull output 50MHz
const IN_PUPD: u32 = 0x8; // with ODR=1 -> pull-up (original: GPIO_Mode_IPU)

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
    wr(base + 0x10, if hi { 1 << pin } else { 1 << (pin + 16) });
}
#[inline(always)]
fn get((base, pin): Pin) -> bool {
    rd(base + 0x08) & (1 << pin) != 0
}
/// Half SCK period. ST7565 needs >=50ns per phase, GT21L is faster; ~110ns at 72MHz.
#[inline(always)]
fn half() {
    cortex_m::asm::delay(8);
}

/// GT21L16S2Y address map (as used by the original firmware).
pub mod font {
    /// 6x12 ASCII 0x20..=0x7E, 12 bytes per glyph
    pub const ASCII_6X12: u32 = 0x66D40;
    /// 12x12 GB2312, 24 bytes per glyph
    pub const GB2312_12X12: u32 = 0x3CF80;

    pub fn ascii_6x12(c: u8) -> Option<u32> {
        (0x20..0x7F).contains(&c).then(|| ASCII_6X12 + (c as u32 - 0x20) * 12)
    }

    /// Level-1/2 hanzi (MSB 0xB0..=0xF7). The original firmware uses offset 376 here, not the
    /// datasheet's 846; 376 is what this ROM was shipped with.
    pub fn gb2312_12x12(msb: u8, lsb: u8) -> Option<u32> {
        if !(0xB0..0xF8).contains(&msb) || !(0xA1..0xFF).contains(&lsb) {
            return None;
        }
        let idx = (msb as u32 - 0xB0) * 94 + (lsb as u32 - 0xA1) + 376;
        Some(GB2312_12X12 + idx * 24)
    }
}

/// Bus-level driver: controller commands, page writes and font ROM reads. The framebuffer and all drawing
/// live in the UI (crate `hd100-ui`, layout as documented above).
pub struct Lcd {
    _private: (),
}

impl Lcd {
    /// Configure pins, hardware-reset the controller and run the original init sequence.
    /// The screen is cleared (including the 4 hidden columns) and switched on.
    pub async fn new() -> Self {
        // IOPA + IOPC
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 2) | (1 << 4));
        set(LCD_CS, true);
        set(FONT_CS, true);
        set(SCK, true);
        for p in [LCD_RST, LCD_CS, FONT_CS, A0_SI, SCK, SDA_SO] {
            cfg(p, PP50);
        }

        set(LCD_RST, false);
        Timer::after_millis(10).await;
        set(LCD_RST, true);
        Timer::after_millis(10).await;

        let mut lcd = Lcd { _private: () };
        lcd.cmd(0xE2); // software reset
        Timer::after_millis(10).await;
        for c in [0x2F, 0x60, 0xA0, 0xC0, 0x25, 0x81, DEFAULT_CONTRAST, 0xAF, 0x23] {
            lcd.cmd(c);
        }
        // Wipe all 132 columns of controller RAM, as the original does
        for page in 0..PAGES as u8 {
            lcd.cmd(0xB0 | page);
            lcd.cmd(0x00);
            lcd.cmd(0x10);
            for _ in 0..132 {
                lcd.data(0);
            }
        }
        lcd
    }

    // ---- bus level ----

    fn shift_out(&mut self, byte: u8, msb_first: bool) {
        cfg(SDA_SO, PP50); // PC0 may have been left as input by a font read
        set(LCD_CS, false);
        half();
        for i in 0..8 {
            let bit = if msb_first { byte & (0x80 >> i) } else { byte & (1 << i) };
            set(SCK, false);
            set(SDA_SO, bit != 0);
            half();
            set(SCK, true);
            half();
        }
        set(LCD_CS, true);
    }

    /// Send one controller command byte (A0 = 0).
    pub fn cmd(&mut self, c: u8) {
        set(A0_SI, false);
        self.shift_out(c, true);
    }

    /// Send one display data byte (A0 = 1), LSB first like the original.
    fn data(&mut self, d: u8) {
        set(A0_SI, true);
        self.shift_out(d, false);
    }

    fn goto(&mut self, page: usize, x: usize) {
        let col = x as u8 + 1;
        self.cmd(0xB0 | (7 - page as u8));
        self.cmd(0x10 | (col >> 4));
        self.cmd(col & 0x0F);
    }

    // ---- controller settings ----

    /// Electronic volume, 0..=63.
    pub fn set_contrast(&mut self, v: u8) {
        self.cmd(0x81);
        self.cmd(v & 0x3F);
    }

    pub fn display_on(&mut self, on: bool) {
        self.cmd(if on { 0xAF } else { 0xAE });
    }

    /// Hardware inverse (A7) / normal (A6).
    pub fn invert(&mut self, inv: bool) {
        self.cmd(if inv { 0xA7 } else { 0xA6 });
    }

    // ---- display RAM ----

    /// Write one 128-column page (`data[x]` bit k = pixel (x, 8 * page + k)) to the panel (~0.4ms).
    pub fn write_page(&mut self, page: usize, data: &[u8; WIDTH]) {
        self.goto(page, 0);
        for &b in data {
            self.data(b);
        }
    }

    // ---- font ROM ----

    /// Read `buf.len()` bytes from the GT21L16S2Y at `addr` (READ 0x03 + 24-bit address).
    pub fn font_read(&mut self, addr: u32, buf: &mut [u8]) {
        set(LCD_CS, true);
        set(SCK, true);
        set(SDA_SO, true); // ODR=1 -> pull-up once switched to input
        cfg(SDA_SO, IN_PUPD);
        set(FONT_CS, false);
        half();
        for b in [0x03, (addr >> 16) as u8, (addr >> 8) as u8, addr as u8] {
            self.font_xfer(b);
        }
        for out in buf.iter_mut() {
            *out = self.font_xfer(0xFF);
        }
        set(FONT_CS, true);
        cfg(SDA_SO, PP50);
    }

    /// One SPI mode-0 byte, MSB first. Like the original: falling edge, sample SO, drive SI, rising edge.
    fn font_xfer(&mut self, out: u8) -> u8 {
        let mut inp = 0u8;
        for i in 0..8 {
            set(SCK, false);
            half();
            inp = (inp << 1) | get(SDA_SO) as u8;
            set(A0_SI, out & (0x80 >> i) != 0);
            half();
            set(SCK, true);
        }
        inp
    }

    /// 6x12 ASCII glyph from the ROM (blank for anything else), layout as [`hd100_ui::Font`] expects.
    pub fn ascii_glyph(&mut self, c: u8) -> [u8; 12] {
        let mut g = [0u8; 12];
        if let Some(a) = font::ascii_6x12(c) {
            self.font_read(a, &mut g);
        }
        g
    }
}
