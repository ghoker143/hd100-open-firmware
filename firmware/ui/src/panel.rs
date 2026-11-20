//! Status panel: four 12-px text lines on a 16-px pitch (y = 0 / 16 / 32 / 48), 21 characters each.
//!
//! | Line | Content |
//! |------|---------|
//! | 0    | title, USB mark at the right |
//! | 1    | contact slot: `CT` + ATR / `no card` / `card present` |
//! | 2    | contactless: `RF` + UID / a card name / ... |
//! | 3    | hint, idle radar, or a toast (inverted bar) |
//!
//! Scenes (timings as in hid2pcsc's panel.rs): boot wave → converge (lines fly in from four sides) → live.
//! In live, a newly identified card is typed onto its line behind a cursor; the idle hint pulses
//! `Tap a card )))` for 10 minutes, then stays still. The intro always plays out (the first second after
//! power-up always changes state: USB enumeration, the first card probes); the fly-in carries the latest state,
//! and whatever arrived during the intro is shown complete, without the typewriter.

use crate::{Fb, Font, Line, COLS, GH, GW, WIDTH};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Usb {
    #[default]
    Detached,
    Suspended,
    Configured,
}

/// Bytes identifying a card (ATR or UID), shown in hex, truncated to the line.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Ident {
    bytes: [u8; 12],
    len: u8,
}

impl Ident {
    pub fn new(b: &[u8]) -> Self {
        let mut i = Ident::default();
        let n = b.len().min(12);
        i.bytes[..n].copy_from_slice(&b[..n]);
        i.len = n as u8;
        i
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// What one slot holds, as its panel line shows it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Medium {
    #[default]
    Empty,
    /// A card is there; its identity if known (empty = only detected). Kept while the host powers the card
    /// down (pcscd does that to idle cards): to the person at the reader it is still the same card.
    Present(Ident),
    /// A card shown by name instead of bytes (e.g. a Type B card whose PUPI is all zero)
    Named(&'static str),
}

impl Medium {
    fn identified(&self) -> bool {
        match self {
            Medium::Present(id) => id.len > 0,
            Medium::Named(_) => true,
            Medium::Empty => false,
        }
    }
}

/// Everything the panel shows that comes from the rest of the firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Panel {
    pub ct: Medium,
    pub rf: Medium,
    pub usb: Usb,
}

impl Panel {
    pub fn is_idle(&self) -> bool {
        self.ct == Medium::Empty && self.rf == Medium::Empty
    }
}

pub const LINES: usize = 4;
pub const IDLE_HINT: &str = "Insert or tap a card";
const TAP_TEXT: &str = "  Tap a card ";
const SUBTITLE: &str = "open firmware";
const WAVE_WORD: &[u8] = b"HD100";

pub const WAVE_MS: u32 = 2000;
const WAVE_STEP: u32 = 30;
const FLY_V_MS: u32 = 450;
const FLY_H_MS: u32 = 350;
pub const CONVERGE_MS: u32 = FLY_V_MS + FLY_H_MS;
const CONVERGE_STEP: u32 = 25;
pub const TYPE_STEP: u32 = 60;
pub const RADAR_STEP: u32 = 200;
pub const IDLE_ANIMATION_MS: u32 = 600_000;

/// y of panel line `i`
pub fn line_y(i: usize) -> i32 {
    16 * i as i32
}

fn medium_line(tag: &str, m: &Medium) -> Line {
    let mut l = Line::from(tag);
    l.push(" ");
    match m {
        Medium::Empty => l.push("no card"),
        Medium::Present(id) if id.len == 0 => l.push("card present"),
        Medium::Present(id) => l.push_hex(id.as_bytes()),
        Medium::Named(s) => l.push(s),
    };
    l
}

/// The static panel lines for a state (line 3 = the static hint; animation may cover it).
pub fn layout(title: &Line, p: &Panel) -> [Line; LINES] {
    [
        *title,
        medium_line("CT", &p.ct),
        medium_line("RF", &p.rf),
        if p.is_idle() { Line::from(IDLE_HINT) } else { Line::new() },
    ]
}

const SIN64: [i8; 64] = [
    0, 12, 25, 37, 49, 60, 71, 81, 90, 98, 106, 112, 117, 122, 125, 126, 127, 126, 125, 122, 117, 112, 106, 98,
    90, 81, 71, 60, 49, 37, 25, 12, 0, -12, -25, -37, -49, -60, -71, -81, -90, -98, -106, -112, -117, -122, -125,
    -126, -127, -126, -125, -122, -117, -112, -106, -98, -90, -81, -71, -60, -49, -37, -25, -12,
];

/// Ease-out cubic: `from` at t = 0, `to` at t = dur.
fn ease(from: i32, to: i32, t: u32, dur: u32) -> i32 {
    let u = (t.min(dur) as i64 * 1000) / dur as i64; // 0..=1000
    let r = 1000 - u;
    let e = 1000 - r * r * r / 1_000_000; // 0..=1000
    from + ((to - from) as i64 * e / 1000) as i32
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Boot,
    Wave(u32),
    Converge(u32),
    Live,
}

pub struct Ui {
    title: Line,
    phase: Phase,
    /// Lines 1 and 2 as last laid out, to spot a newly identified card
    shown: [Line; LINES],
    /// Start of a typewriter animation per line
    typing: [Option<u32>; LINES],
    idle_since: Option<u32>,
    toast: Option<(Line, u32)>,
}

impl Ui {
    pub fn new(title: Line) -> Self {
        Ui {
            title,
            phase: Phase::Boot,
            shown: [Line::new(); LINES],
            typing: [None; LINES],
            idle_since: None,
            toast: None,
        }
    }

    /// Show `text` as an inverted bar on the bottom line for `ms`.
    pub fn toast(&mut self, now: u32, text: &str, ms: u32) {
        self.toast = Some((Line::from(text), now.wrapping_add(ms)));
    }

    /// Skip the boot scenes (e.g. after a firmware restart the user didn't see happen).
    pub fn skip_intro(&mut self) {
        self.phase = Phase::Live;
    }

    /// Draw the frame for time `now` (ms, wrapping) and state `p` into `fb` (fully redrawn).
    /// Returns how long until the next frame is due; None = nothing moves until the state changes.
    pub fn render(&mut self, now: u32, p: &Panel, fb: &mut Fb, font: &mut impl Font) -> Option<u32> {
        fb.clear();
        if self.phase == Phase::Boot {
            self.phase = Phase::Wave(now);
        }
        let lines = layout(&self.title, p);
        match self.phase {
            Phase::Wave(t0) => {
                let t = now.wrapping_sub(t0);
                if t < WAVE_MS {
                    self.draw_wave(t, fb, font);
                    return Some(WAVE_STEP);
                }
                self.phase = Phase::Converge(now);
                return self.render(now, p, fb, font);
            }
            Phase::Converge(t0) => {
                let t = now.wrapping_sub(t0);
                if t < CONVERGE_MS {
                    self.draw_converge(t, &lines, p.usb, fb, font);
                    return Some(CONVERGE_STEP);
                }
                self.go_live(&lines);
            }
            Phase::Boot | Phase::Live => {}
        }
        self.draw_live(now, &lines, p, fb, font)
    }

    fn go_live(&mut self, lines: &[Line; LINES]) {
        self.phase = Phase::Live;
        self.shown = *lines;
        self.typing = [None; LINES];
    }

    fn draw_wave(&self, t: u32, fb: &mut Fb, font: &mut impl Font) {
        let adv = 2 * GW + 2;
        let x0 = (WIDTH - WAVE_WORD.len() as i32 * adv + 2) / 2;
        for (i, &c) in WAVE_WORD.iter().enumerate() {
            // sin(4t - 0.6i): 64 table steps per turn -> t * 4 / 2pi * 64 = t * 0.0407 per ms
            let idx = ((t as i32 * 41 / 1000) - i as i32 * 6).rem_euclid(64) as usize;
            let y = 12 + 8 * SIN64[idx] as i32 / 127;
            let g = font.glyph(c);
            fb.glyph(x0 + i as i32 * adv, y, &g, 2);
        }
        let sx = (WIDTH - SUBTITLE.len() as i32 * GW) / 2;
        fb.text(font, sx, 50, SUBTITLE.as_bytes());
    }

    /// The contact line drops from the top while the contactless line rises from the bottom; then the title
    /// slides in from the left and the hint from the right. Ends on the exact live panel.
    fn draw_converge(&self, t: u32, lines: &[Line; LINES], usb: Usb, fb: &mut Fb, font: &mut impl Font) {
        let tv = t.min(FLY_V_MS);
        let y1 = ease(-GH, line_y(1), tv, FLY_V_MS);
        let y2 = ease(64, line_y(2), tv, FLY_V_MS);
        fb.text(font, 0, y1, lines[1].as_bytes());
        fb.text(font, 0, y2, lines[2].as_bytes());
        if t >= FLY_V_MS {
            let th = t - FLY_V_MS;
            let w0 = lines[0].len() as i32 * GW;
            fb.text(font, ease(-w0, 0, th, FLY_H_MS), line_y(0), lines[0].as_bytes());
            fb.text(font, ease(WIDTH, 0, th, FLY_H_MS), line_y(3), lines[3].as_bytes());
            fb.usb_mark(WIDTH - 8, 2, usb);
        }
    }

    fn draw_live(&mut self, now: u32, lines: &[Line; LINES], p: &Panel, fb: &mut Fb, font: &mut impl Font) -> Option<u32> {
        let mut next: Option<u32> = None;
        let mut due = |ms: u32| next = Some(next.map_or(ms, |n| n.min(ms)));

        fb.text(font, 0, line_y(0), lines[0].as_bytes());
        fb.usb_mark(WIDTH - 8, 2, p.usb);

        for (i, m) in [(1, &p.ct), (2, &p.rf)] {
            if lines[i] != self.shown[i] {
                self.typing[i] = m.identified().then_some(now);
                self.shown[i] = lines[i];
            }
            let text = lines[i].as_bytes();
            match self.typing[i] {
                Some(t0) => {
                    let k = (now.wrapping_sub(t0) / TYPE_STEP) as usize;
                    if k >= text.len() {
                        self.typing[i] = None;
                        fb.text(font, 0, line_y(i), text);
                    } else {
                        let x = fb.text(font, 0, line_y(i), &text[..k]);
                        if k < COLS {
                            fb.text(font, x, line_y(i), b"_");
                        }
                        due(TYPE_STEP - now.wrapping_sub(t0) % TYPE_STEP);
                    }
                }
                None => {
                    fb.text(font, 0, line_y(i), text);
                }
            }
        }

        // Line 3: toast > radar > static hint
        if p.is_idle() {
            self.idle_since.get_or_insert(now);
        } else {
            self.idle_since = None;
        }
        if let Some((text, until)) = self.toast {
            let left = until.wrapping_sub(now) as i32;
            if left <= 0 {
                self.toast = None;
            } else {
                let x = (WIDTH - text.len() as i32 * GW) / 2;
                fb.text(font, x, line_y(3), text.as_bytes());
                fb.invert(0, line_y(3) - 1, WIDTH, GH + 2);
                due(left as u32);
            }
        }
        if self.toast.is_none() {
            match self.idle_since {
                Some(t0) if now.wrapping_sub(t0) < IDLE_ANIMATION_MS => {
                    let el = now.wrapping_sub(t0);
                    let mut l = Line::from(TAP_TEXT);
                    for _ in 0..(el / RADAR_STEP) % 4 {
                        l.push(")");
                    }
                    fb.text(font, 0, line_y(3), l.as_bytes());
                    due((RADAR_STEP - el % RADAR_STEP).min(IDLE_ANIMATION_MS - el));
                }
                _ => {
                    fb.text(font, 0, line_y(3), lines[3].as_bytes());
                }
            }
        }
        next
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{Frame, PAGES};
    use std::string::String;
    use std::vec::Vec;

    /// Test font: column 0 of each glyph carries the character code in rows 0-7, the rest is blank.
    /// With text on 8-aligned y, `fb[y / 8][x]` reads the character back.
    struct CodeFont;
    impl Font for CodeFont {
        fn glyph(&mut self, c: u8) -> [u8; 12] {
            let mut g = [0u8; 12];
            g[0] = c;
            g
        }
    }

    fn new_fb() -> Frame {
        [[0; WIDTH as usize]; PAGES]
    }

    /// Text on panel line `i` as the test font left it (spaces where nothing was drawn)
    fn read_line(f: &Frame, i: usize) -> String {
        let page = line_y(i) as usize / 8;
        (0..COLS).map(|k| f[page][k * GW as usize]).map(|c| if c == 0 { ' ' } else { c as char }).collect::<String>()
    }

    fn pad(s: &str) -> String {
        std::format!("{s:<21}")
    }

    fn title() -> Line {
        Line::from("HD100 v0.1.0")
    }

    fn atr() -> Medium {
        Medium::Present(Ident::new(&[0x3B, 0xFA, 0x18, 0x00, 0xFF, 0x10, 0x00, 0x00, 0x31, 0xC1, 0x73]))
    }

    /// Run the UI from `t0` to `t1` like the firmware would (frame at each requested time).
    fn play(ui: &mut Ui, f: &mut Frame, p: &Panel, t0: u32, t1: u32) -> u32 {
        let mut t = t0;
        while t < t1 {
            match ui.render(t, p, &mut Fb(f), &mut CodeFont) {
                Some(d) => t += d.max(1),
                None => return t,
            }
        }
        t
    }

    #[test]
    fn lines_are_formatted_and_truncated() {
        let p = Panel { ct: atr(), rf: Medium::Named("tag"), usb: Usb::Configured };
        let l = layout(&title(), &p);
        assert_eq!(std::str::from_utf8(l[1].as_bytes()).unwrap(), "CT 3BFA1800FF10000031");
        assert_eq!(std::str::from_utf8(l[2].as_bytes()).unwrap(), "RF tag");
        assert!(l[3].is_empty());
        let idle = layout(&title(), &Panel::default());
        assert_eq!(std::str::from_utf8(idle[1].as_bytes()).unwrap(), "CT no card");
        assert_eq!(std::str::from_utf8(idle[3].as_bytes()).unwrap(), IDLE_HINT);
        let present = Panel { rf: Medium::Present(Ident::default()), ..Default::default() };
        assert_eq!(std::str::from_utf8(layout(&title(), &present)[2].as_bytes()).unwrap(), "RF card present");
    }

    #[test]
    fn intro_ends_on_the_live_panel() {
        let mut ui = Ui::new(title());
        let mut f = new_fb();
        let p = Panel { usb: Usb::Configured, ..Default::default() };
        let t = play(&mut ui, &mut f, &p, 0, WAVE_MS + CONVERGE_MS + 100);
        assert!(t >= WAVE_MS + CONVERGE_MS);
        // Column 20 of the title line is under the USB mark
        assert_eq!(read_line(&f, 0)[..20], pad("HD100 v0.1.0")[..20]);
        assert_eq!(read_line(&f, 1), pad("CT no card"));
        assert_eq!(read_line(&f, 2), pad("RF no card"));
        // Idle: the radar owns line 3
        assert!(read_line(&f, 3).starts_with("  Tap a card"));
    }

    #[test]
    fn wave_stays_on_screen_and_clear_of_the_subtitle() {
        let mut ui = Ui::new(title());
        for t in (0..WAVE_MS).step_by(10) {
            let mut f = new_fb();
            let mut ui2 = Ui::new(title());
            ui2.render(0, &Panel::default(), &mut Fb(&mut f), &mut CodeFont);
            let mut f = new_fb();
            assert_eq!(ui2.render(t, &Panel::default(), &mut Fb(&mut f), &mut CodeFont), Some(WAVE_STEP));
            // Scaled glyph rows land at y = 12 + 8 sin(..) .. +24: never below the subtitle at 50
            for idx in 0..64 {
                let y = 12 + 8 * SIN64[idx] as i32 / 127;
                assert!(y >= 4 && y + 2 * GH <= 50);
            }
        }
        let _ = ui.render(0, &Panel::default(), &mut Fb(&mut new_fb()), &mut CodeFont);
    }

    #[test]
    fn state_change_during_the_intro_keeps_the_intro_and_lands_complete() {
        let mut ui = Ui::new(title());
        let mut f = new_fb();
        play(&mut ui, &mut f, &Panel::default(), 0, 500);
        let p = Panel { ct: atr(), usb: Usb::Configured, ..Default::default() };
        // Still the wave
        assert_eq!(ui.render(500, &p, &mut Fb(&mut f), &mut CodeFont), Some(WAVE_STEP));
        let t = play(&mut ui, &mut f, &p, 500, WAVE_MS + CONVERGE_MS + 100);
        // No typewriter for a state that arrived during the intro: complete as soon as the intro ends
        assert_eq!(read_line(&f, 1), pad("CT 3BFA1800FF10000031"));
        assert_eq!(ui.render(t, &p, &mut Fb(&mut f), &mut CodeFont), None);
    }

    #[test]
    fn new_card_is_typed_in_then_static() {
        let mut ui = Ui::new(title());
        ui.skip_intro();
        let mut f = new_fb();
        let idle = Panel::default();
        ui.render(0, &idle, &mut Fb(&mut f), &mut CodeFont);
        let p = Panel { rf: Medium::Present(Ident::new(&[0x24, 0x77, 0x95, 0x5F])), ..Default::default() };
        ui.render(1000, &p, &mut Fb(&mut f), &mut CodeFont);
        assert_eq!(read_line(&f, 2), pad("_"));
        ui.render(1000 + 3 * TYPE_STEP, &p, &mut Fb(&mut f), &mut CodeFont);
        assert_eq!(read_line(&f, 2), pad("RF _"));
        let t = play(&mut ui, &mut f, &p, 1000 + 3 * TYPE_STEP, 10_000);
        assert!(t < 1000 + 13 * TYPE_STEP, "settles once typed");
        assert_eq!(read_line(&f, 2), pad("RF 2477955F"));
        // Detected-but-unidentified changes are written in place
        let det = Panel { ct: Medium::Present(Ident::default()), ..p };
        assert_eq!(ui.render(t, &det, &mut Fb(&mut f), &mut CodeFont), None);
        assert_eq!(read_line(&f, 1), pad("CT card present"));
    }

    #[test]
    fn radar_pulses_then_stops_after_ten_minutes() {
        let mut ui = Ui::new(title());
        ui.skip_intro();
        let p = Panel::default();
        let mut seen = Vec::new();
        for k in 0..5 {
            let mut f = new_fb();
            let next = ui.render(k * RADAR_STEP, &p, &mut Fb(&mut f), &mut CodeFont);
            assert_eq!(next, Some(RADAR_STEP));
            seen.push(String::from(read_line(&f, 3).trim_end()));
        }
        assert_eq!(seen[0], "  Tap a card");
        assert_eq!(seen[3], "  Tap a card )))");
        assert_eq!(seen[4], seen[0]);
        let mut f = new_fb();
        assert_eq!(ui.render(IDLE_ANIMATION_MS, &p, &mut Fb(&mut f), &mut CodeFont), None);
        assert_eq!(read_line(&f, 3), pad(IDLE_HINT));
    }

    #[test]
    fn toast_is_an_inverted_bar_that_expires() {
        let mut ui = Ui::new(title());
        ui.skip_intro();
        let p = Panel { ct: atr(), ..Default::default() };
        let mut f = new_fb();
        let t = play(&mut ui, &mut f, &p, 0, 10_000); // let the CT line finish typing
        ui.toast(t, "Swipe OK", 2000);
        let mut f = new_fb();
        assert_eq!(ui.render(t, &p, &mut Fb(&mut f), &mut CodeFont), Some(2000));
        // Background of the bar is lit, the text's own pixels are dark
        let fb = Fb(&mut f);
        assert!(fb.get(0, line_y(3)) && fb.get(WIDTH - 1, line_y(3) + GH));
        let mut f = new_fb();
        assert_eq!(ui.render(t + 2000, &p, &mut Fb(&mut f), &mut CodeFont), None);
        assert!(!Fb(&mut f).get(0, line_y(3)));
    }

    #[test]
    fn usb_mark_follows_state() {
        let mut ui = Ui::new(title());
        ui.skip_intro();
        let lit = |usb| {
            let mut f = new_fb();
            let mut ui = Ui::new(title());
            ui.skip_intro();
            ui.render(IDLE_ANIMATION_MS, &Panel { usb, ..Default::default() }, &mut Fb(&mut f), &mut CodeFont);
            let fb = Fb(&mut f);
            (WIDTH - 8..WIDTH).flat_map(|x| (0..10).map(move |y| (x, y))).filter(|&(x, y)| fb.get(x, y)).count()
        };
        assert_eq!(lit(Usb::Detached), 0);
        assert!(lit(Usb::Suspended) > 0 && lit(Usb::Suspended) < lit(Usb::Configured));
        let _ = ui;
    }
}
