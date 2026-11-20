//! HD100 LCD status panel: pure drawing, layout and animation scenes. No hardware access, no allocation:
//! the firmware owns the LCD, the font ROM and the clock, and calls [`Ui::render`] with the current state.
//!
//! The look follows the panel hid2pcsc (cardreader/src/backend/huada/panel.rs) draws on the vendor firmware
//! through its character-only display command: same lines, same scenes (boot wave, four-way fly-in,
//! typewriter, idle radar). Owning the framebuffer, we can move things by the pixel instead of by the row.
#![no_std]

pub mod panel;

pub use panel::{Ident, Medium, Panel, Ui, Usb};

pub const WIDTH: i32 = 128;
pub const HEIGHT: i32 = 64;
pub const PAGES: usize = 8;
/// Glyph cell of the font ROM's ASCII 6x12
pub const GW: i32 = 6;
pub const GH: i32 = 12;
/// Characters per text line
pub const COLS: usize = 21;

/// Framebuffer layout used by the LCD driver: bit k of `fb[page][x]` is pixel (x, 8 * page + k).
pub type Frame = [[u8; WIDTH as usize]; PAGES];

/// ASCII 6x12 glyphs as the GT21L16S2Y stores them: bytes 0..6 = columns, rows 0-7 (bit k = row k);
/// bytes 6..12 = the same columns, rows 8-11 in the low nibble. Unknown characters: all zero.
pub trait Font {
    fn glyph(&mut self, c: u8) -> [u8; 12];
}

pub struct Fb<'a>(pub &'a mut Frame);

impl Fb<'_> {
    pub fn clear(&mut self) {
        *self.0 = [[0; WIDTH as usize]; PAGES];
    }

    /// Set / clear one pixel; anything off-screen is ignored.
    #[inline]
    pub fn pixel(&mut self, x: i32, y: i32, on: bool) {
        if !(0..WIDTH).contains(&x) || !(0..HEIGHT).contains(&y) {
            return;
        }
        let b = &mut self.0[(y / 8) as usize][x as usize];
        if on {
            *b |= 1 << (y % 8);
        } else {
            *b &= !(1 << (y % 8));
        }
    }

    pub fn get(&self, x: i32, y: i32) -> bool {
        (0..WIDTH).contains(&x) && (0..HEIGHT).contains(&y) && self.0[(y / 8) as usize][x as usize] >> (y % 8) & 1 != 0
    }

    pub fn fill(&mut self, x: i32, y: i32, w: i32, h: i32, on: bool) {
        for yy in y..y + h {
            for xx in x..x + w {
                self.pixel(xx, yy, on);
            }
        }
    }

    pub fn invert(&mut self, x: i32, y: i32, w: i32, h: i32) {
        for yy in y..y + h {
            for xx in x..x + w {
                let v = self.get(xx, yy);
                self.pixel(xx, yy, !v);
            }
        }
    }

    /// Draw a 6x12 glyph scaled by `scale`, only its set pixels (transparent background).
    pub fn glyph(&mut self, x: i32, y: i32, g: &[u8; 12], scale: i32) {
        for col in 0..GW {
            let bits = g[col as usize] as u16 | ((g[col as usize + 6] & 0x0F) as u16) << 8;
            for row in 0..GH {
                if bits >> row & 1 != 0 {
                    self.fill(x + col * scale, y + row * scale, scale, scale, true);
                }
            }
        }
    }

    /// Text at (x, y), 6 px per character; returns the x after the last one.
    pub fn text(&mut self, font: &mut impl Font, mut x: i32, y: i32, s: &[u8]) -> i32 {
        for &c in s {
            if x >= WIDTH {
                break;
            }
            if x > -GW && c != b' ' {
                let g = font.glyph(c);
                self.glyph(x, y, &g, 1);
            }
            x += GW;
        }
        x
    }

    /// Small 7x7 USB status mark at (x, y): configured = filled plug, suspended = hollow, detached = nothing.
    pub fn usb_mark(&mut self, x: i32, y: i32, state: Usb) {
        // A plug: square head on a stem
        const PLUG: [u8; 7] = [0b0011100, 0b0011100, 0b1111111, 0b1111111, 0b1111111, 0b0011100, 0b0011100];
        match state {
            Usb::Detached => {}
            Usb::Configured => {
                for (col, bits) in PLUG.iter().enumerate() {
                    for row in 0..7 {
                        if bits >> row & 1 != 0 {
                            self.pixel(x + col as i32, y + row, true);
                        }
                    }
                }
            }
            Usb::Suspended => {
                // Outline of the head only
                for i in 0..5 {
                    self.pixel(x + 2, y + 1 + i, true);
                    self.pixel(x + 6, y + 1 + i, true);
                    self.pixel(x + 2 + i, y + 1, true);
                    self.pixel(x + 2 + i, y + 5, true);
                }
            }
        }
    }
}

/// A fixed-width text line (no allocation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Line {
    buf: [u8; COLS],
    len: u8,
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

impl Line {
    pub const fn new() -> Self {
        Line { buf: [b' '; COLS], len: 0 }
    }

    pub fn from(s: &str) -> Self {
        let mut l = Line::new();
        l.push(s);
        l
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append printable ASCII; the rest is dropped, so is anything past the width.
    pub fn push(&mut self, s: &str) -> &mut Self {
        for b in s.bytes() {
            self.push_byte(b);
        }
        self
    }

    pub fn push_byte(&mut self, b: u8) -> &mut Self {
        if (self.len as usize) < COLS && (b.is_ascii_graphic() || b == b' ') {
            self.buf[self.len as usize] = b;
            self.len += 1;
        }
        self
    }

    pub fn push_hex(&mut self, bytes: &[u8]) -> &mut Self {
        const H: &[u8; 16] = b"0123456789ABCDEF";
        for &b in bytes {
            self.push_byte(H[(b >> 4) as usize]);
            self.push_byte(H[(b & 15) as usize]);
        }
        self
    }

    pub fn push_dec(&mut self, mut v: u32) -> &mut Self {
        let mut d = [0u8; 10];
        let mut n = 0;
        loop {
            d[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.push_byte(d[n]);
        }
        self
    }
}
