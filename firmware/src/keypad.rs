//! HD100 15-key keypad driver (polled).
//!
//! Hardware (verified on board, see docs/hardware.md):
//! - The whole keyboard sits on PB3..PB7 (5 lines). Each key bridges two lines through a diode,
//!   so direction matters: 5×4 = 20 positions, 15 of them populated.
//! - Scan: drive one line high (push-pull), set the other 4 to pull-down input, read IDR; high = pressed.
//! - PB3 = JTDO, PB4 = NJTRST: only usable as GPIO after AFIO_MAPR.SWJ_CFG=010 (JTAG off, SWD kept).
//!
//! Usage: call [`Keypad::tick`] every 10ms. Debounce = 2 consecutive identical scans (~20ms).

use core::ptr::{read_volatile, write_volatile};

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum Key {
    F1,
    F2,
    F3,
    D0,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    Cancel,
    Enter,
}

impl Key {
    /// Original firmware key code (matches the original dispatch logic, handy when cross-referencing the reverse engineering)
    #[allow(dead_code)] // reserved for cross-referencing the reverse engineering
    pub fn orig_code(self) -> u8 {
        match self {
            Key::D1 => 0x01,
            Key::D2 => 0x02,
            Key::D3 => 0x03,
            Key::D4 => 0x04,
            Key::D5 => 0x05,
            Key::D6 => 0x06,
            Key::D7 => 0x07,
            Key::D8 => 0x08,
            Key::D9 => 0x09,
            Key::D0 => 0x0a,
            Key::F1 => 0x0b,
            Key::Cancel => 0x0c,
            Key::F2 => 0x0d,
            Key::F3 => 0x0e,
            Key::Enter => 0x0f,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Key::F1 => "F1",
            Key::F2 => "F2",
            Key::F3 => "F3",
            Key::D0 => "0",
            Key::D1 => "1",
            Key::D2 => "2",
            Key::D3 => "3",
            Key::D4 => "4",
            Key::D5 => "5",
            Key::D6 => "6",
            Key::D7 => "7",
            Key::D8 => "8",
            Key::D9 => "9",
            Key::Cancel => "CANCEL",
            Key::Enter => "ENTER",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, defmt::Format)]
pub enum KeyEvent {
    Down(Key),
    Up(Key),
}

const LINES: [u8; 5] = [3, 4, 5, 6, 7];

use Key::*;
/// KEYMAP[driver][sense]; None = diagonal or unpopulated position on this board.
/// Unpopulated: PB6->PB3 (original code also 0x0f), PB6->PB7 (0x10), PB7->PB4/5/6 (0x13/0x12/0x11).
const KEYMAP: [[Option<Key>; 5]; 5] = [
    //   PB3           PB4       PB5       PB6       PB7     <- sense
    [None, Some(D7), Some(D4), Some(D1), Some(F1)], // drive PB3
    [Some(Cancel), None, Some(D5), Some(D2), Some(F2)], // drive PB4
    [Some(D0), Some(D8), None, Some(D3), Some(F3)], // drive PB5
    [None, Some(D9), Some(D6), None, None],         // drive PB6
    [Some(Enter), None, None, None, None],          // drive PB7
];

const RCC_APB2ENR: u32 = 0x4002_1018;
const AFIO_MAPR: u32 = 0x4001_0004;
const GPIOB_CRL: u32 = 0x4001_0C00;
const GPIOB_IDR: u32 = 0x4001_0C08;
const GPIOB_BSRR: u32 = 0x4001_0C10;
const PP50: u32 = 0x3;
const IN_PUPD: u32 = 0x8;

#[inline]
fn rd(a: u32) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
#[inline]
fn wr(a: u32, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}

/// Accesses PB3..PB7 through raw registers (CRL read-modify-write + BSRR). Nothing else may use these pins.
pub struct Keypad {
    settle_cycles: u32,
    stable: u32,
    last: u32,
}

impl Keypad {
    /// `sysclk_hz` is used to size the ~30us settle delay.
    pub fn new(sysclk_hz: u32) -> Self {
        // IOPB + AFIO clocks. Read-modify-write a single register at init, no concurrency.
        wr(RCC_APB2ENR, rd(RCC_APB2ENR) | (1 << 3) | (1 << 0));
        // SWJ_CFG=010: free PB3/PB4/PA15, keep SWD
        wr(AFIO_MAPR, (rd(AFIO_MAPR) & !(0x7 << 24)) | (0x2 << 24));
        let mut kp = Keypad {
            settle_cycles: sysclk_hz / 1_000_000 * 30,
            stable: 0,
            last: 0,
        };
        kp.idle();
        kp
    }

    fn cfg(pin: u8, nib: u32) {
        let sh = pin as u32 * 4;
        // CRL/CRH read-modify-write: P0 interrupts (contact-card error signal) touch other pins of the same
        // register and aren't masked by critical sections (rt.rs), so keep them out with PRIMASK
        cortex_m::interrupt::free(|_| wr(GPIOB_CRL, (rd(GPIOB_CRL) & !(0xF << sh)) | (nib << sh)));
    }
    fn set(pin: u8, hi: bool) {
        wr(GPIOB_BSRR, if hi { 1 << pin } else { 1 << (pin + 16) });
    }

    /// Idle state: all pull-down inputs, no current flowing.
    fn idle(&mut self) {
        for &p in LINES.iter() {
            Self::set(p, false);
            Self::cfg(p, IN_PUPD);
        }
    }

    /// One full scan; bit = d*5+s. Takes about 5 × settle ≈ 150us.
    fn scan(&mut self) -> u32 {
        let mut m = 0u32;
        for (di, &d) in LINES.iter().enumerate() {
            for &p in LINES.iter() {
                if p == d {
                    Self::cfg(p, PP50);
                    Self::set(p, true);
                } else {
                    Self::set(p, false);
                    Self::cfg(p, IN_PUPD);
                }
            }
            cortex_m::asm::delay(self.settle_cycles);
            let idr = rd(GPIOB_IDR);
            for (si, &s) in LINES.iter().enumerate() {
                if si != di && (idr >> s) & 1 == 1 {
                    m |= 1 << (di * 5 + si);
                }
            }
            Self::set(d, false);
        }
        self.idle();
        m
    }

    /// Call every 10ms; emits debounced press/release events through `emit`.
    pub fn tick(&mut self, mut emit: impl FnMut(KeyEvent)) {
        let now = self.scan();
        if now == self.last && now != self.stable {
            let changed = now ^ self.stable;
            for bit in 0..25usize {
                if changed & (1 << bit) == 0 {
                    continue;
                }
                if let Some(k) = KEYMAP[bit / 5][bit % 5] {
                    emit(if now & (1 << bit) != 0 {
                        KeyEvent::Down(k)
                    } else {
                        KeyEvent::Up(k)
                    });
                }
            }
            self.stable = now;
        }
        self.last = now;
    }

    /// Currently held keys (debounced).
    #[allow(dead_code)]
    pub fn held(&self) -> impl Iterator<Item = Key> + '_ {
        (0..25usize)
            .filter(move |b| self.stable & (1 << b) != 0)
            .filter_map(|b| KEYMAP[b / 5][b % 5])
    }
}
