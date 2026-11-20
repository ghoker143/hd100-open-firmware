//! The HID keyboard interface: the one task that writes keyboard reports.
//! - Magstripe, same output as bp8903-fw (src/msr.rs): after a swipe it types `;track2?;track3?` + Enter
//!   (US layout); a track with data that won't decode types `;E?`; a blank card types nothing.
//! - Keypad passthrough: keys pressed outside PIN entry go out as real key down / up (host does autorepeat),
//!   digits as main-row digits (not keypad usages, so NumLock doesn't matter), OK = Enter, Cancel = Backspace;
//!   F1-F3 are kept for the reader's own use. Queued through [`KEYS`]; held keys are re-sent after a swipe
//!   was typed.
//! Only the keyboard report (report ID 1) is kept; bp8903's write commands (vendor reports 2/3) are dropped —
//! the HD100 head can't write.

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{with_timeout, Duration, Timer};

use crate::ccid::Drv;
use crate::keypad::{Key, KeyEvent};
use crate::magstripe::{decode, Format, MagStripe, TrackBuf};

/// Report 1: boot-style keyboard (same layout as bp8903's report 1)
#[rustfmt::skip]
pub const HID_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,  // Keyboard, report 1
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02,              //   modifiers
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01,              //   reserved
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
    0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,  //   6 keys
    0xC0,
];

pub const HID_PACKET: usize = 16;

pub type Hid = embassy_usb::class::hid::HidWriter<'static, Drv, HID_PACKET>;

/// US layout usage (and shift) for the characters a track 2/3 read can hold
fn key(c: u8) -> (u8, u8) {
    const SHIFT: u8 = 0x02;
    match c {
        b'1'..=b'9' => (0, 0x1E + (c - b'1')),
        b'0' => (0, 0x27),
        b';' => (0, 0x33),
        b':' => (SHIFT, 0x33),
        b'=' => (0, 0x2E),
        b'<' => (SHIFT, 0x36),
        b'>' => (SHIFT, 0x37),
        b'?' => (SHIFT, 0x38),
        b'E' => (SHIFT, 0x08),
        _ => (0, 0x28), // Enter
    }
}

/// Keypad events to send to the host
pub static KEYS: Channel<CriticalSectionRawMutex, KeyEvent, 8> = Channel::new();

fn key_usage(k: Key) -> Option<u8> {
    Some(match k {
        Key::D0 => 0x27,
        Key::D1 => 0x1E,
        Key::D2 => 0x1F,
        Key::D3 => 0x20,
        Key::D4 => 0x21,
        Key::D5 => 0x22,
        Key::D6 => 0x23,
        Key::D7 => 0x24,
        Key::D8 => 0x25,
        Key::D9 => 0x26,
        Key::Enter => 0x28,
        Key::Cancel => 0x2A,
        Key::F1 | Key::F2 | Key::F3 => return None,
    })
}

/// Keyboard report with the held keys
fn held_report(held: &[u8; 6]) -> [u8; 9] {
    let mut r = [1, 0, 0, 0, 0, 0, 0, 0, 0];
    r[3..].copy_from_slice(held);
    r
}

async fn send(hid: &mut Hid, report: &[u8]) {
    // Nobody reading (no host driver yet): drop rather than stall the reader
    let _ = with_timeout(Duration::from_millis(100), hid.write(report)).await;
}

async fn type_text(hid: &mut Hid, text: &[u8]) {
    for &c in text {
        let (mods, usage) = key(c);
        send(hid, &[1, mods, 0, usage, 0, 0, 0, 0, 0]).await;
        send(hid, &[1, 0, 0, 0, 0, 0, 0, 0, 0]).await;
    }
}

/// Track 2/3 (5-bit) in either swipe direction; None if it won't decode cleanly
fn clean(t: &TrackBuf, out: &mut [u8]) -> Option<usize> {
    decode(t, Format::Bcd5, false, out).or_else(|_| decode(t, Format::Bcd5, true, out)).ok()
}

/// HD100: channel A = ISO track 3, channel B = ISO track 2 (measured)
pub async fn run(mut mag: MagStripe, mut hid: Hid) -> ! {
    hid.ready().await;
    defmt::info!("msr: ready");
    let mut held = [0u8; 6];
    loop {
        Timer::after_millis(1).await;
        let mut changed = false;
        while let Ok(ev) = KEYS.try_receive() {
            let (k, down) = match ev {
                KeyEvent::Down(k) => (k, true),
                KeyEvent::Up(k) => (k, false),
            };
            let Some(u) = key_usage(k) else { continue };
            if down && !held.contains(&u) {
                if let Some(slot) = held.iter_mut().find(|x| **x == 0) {
                    *slot = u;
                    changed = true;
                }
            } else if !down {
                held.iter_mut().filter(|x| **x == u).for_each(|x| *x = 0);
                changed = true;
            }
        }
        if changed {
            send(&mut hid, &held_report(&held)).await;
        }
        let Some(s) = mag.poll() else { continue };
        let mut text = [0u8; 2 * 110 + 8];
        let mut n = 0;
        let (mut good, mut bad) = (false, false);
        for (name, t) in [(2, s.b), (3, s.a)] {
            let mut buf = [0u8; 110];
            let chars: &[u8] = match clean(t, &mut buf) {
                Some(k) => {
                    defmt::info!("msr: track {} ok, {} chars", name, k);
                    good = true;
                    &buf[..k]
                }
                None if t.len() > 0 => {
                    defmt::info!("msr: track {} unreadable ({} bits)", name, t.len());
                    bad = true;
                    b";E?"
                }
                None => &[],
            };
            text[n..n + chars.len()].copy_from_slice(chars);
            n += chars.len();
        }
        mag.rearm();
        let (msg, beeps) = match (good, bad) {
            (true, false) => ("Swipe OK", 1),
            (_, true) => ("Swipe error", 2),
            (false, false) => ("No magstripe data", 2),
        };
        crate::ui::toast(msg, 2000);
        crate::ui::beep(beeps);
        if n > 0 {
            text[n] = b'\n';
            type_text(&mut hid, &text[..n + 1]).await;
            if held.iter().any(|&u| u != 0) {
                send(&mut hid, &held_report(&held)).await;
            }
        }
    }
}
