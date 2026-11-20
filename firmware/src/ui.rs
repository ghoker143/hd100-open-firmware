//! Screen and sounds. The UI task is the only owner of the LCD / font ROM bus and draws the status panel of
//! crate `hd100-ui`; the sound task is the only owner of the buzzer. Everything else just reports:
//! - [`update`] changes the panel state (slot contents, USB) and wakes the UI;
//! - [`toast`] shows a short message on the bottom line;
//! - [`beep`] queues beeps.
//! None of these block or fail: if the UI is busy, state updates simply coalesce and extra toasts / beeps
//! are dropped.

use core::cell::Cell;

use embassy_futures::select::select;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use hd100_ui::{Fb, Font, Frame, Line, Panel, Ui, PAGES};

use crate::lcd::Lcd;
use crate::sound::Buzzer;

pub use hd100_ui::{Ident, Medium, Usb};

static STATE: Mutex<CriticalSectionRawMutex, Cell<Panel>> = Mutex::new(Cell::new(Panel {
    ct: Medium::Empty,
    rf: Medium::Empty,
    usb: Usb::Detached,
}));
static CHANGED: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static TOASTS: Channel<CriticalSectionRawMutex, (&'static str, u32), 2> = Channel::new();
static BEEPS: Channel<CriticalSectionRawMutex, u8, 4> = Channel::new();

/// Change the panel state; the screen follows on its next frame.
pub fn update(f: impl FnOnce(&mut Panel)) {
    let changed = STATE.lock(|c| {
        let mut p = c.get();
        let old = p;
        f(&mut p);
        c.set(p);
        p != old
    });
    if changed {
        CHANGED.signal(());
    }
}

pub fn panel() -> Panel {
    STATE.lock(|c| c.get())
}

/// Inverted message on the bottom line for `ms`.
pub fn toast(text: &'static str, ms: u32) {
    if TOASTS.try_send((text, ms)).is_ok() {
        CHANGED.signal(());
    }
}

/// `n` short beeps (1 = OK / card in, 2 = error).
pub fn beep(n: u8) {
    let _ = BEEPS.try_send(n);
}

struct RomFont<'a>(&'a mut Lcd);

impl Font for RomFont<'_> {
    fn glyph(&mut self, c: u8) -> [u8; 12] {
        self.0.ascii_glyph(c)
    }
}

fn page_sum(p: &[u8]) -> u32 {
    // FNV-1a: cheap and good enough to spot a changed page
    p.iter().fold(0x811C_9DC5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193))
}

pub async fn run(mut lcd: Lcd) -> ! {
    let mut title = Line::from("HD100 v");
    title.push(env!("CARGO_PKG_VERSION"));
    let mut ui = Ui::new(title);
    let mut frame: Frame = [[0; 128]; PAGES];
    let mut sums = [0u32; PAGES];
    let mut first = true;
    loop {
        let t = Instant::now();
        let now = t.as_millis() as u32; // the UI works with wrapping ms
        while let Ok((text, ms)) = TOASTS.try_receive() {
            ui.toast(now, text, ms);
        }
        CHANGED.reset();
        let next = ui.render(now, &panel(), &mut Fb(&mut frame), &mut RomFont(&mut lcd));
        for (page, data) in frame.iter().enumerate() {
            let sum = page_sum(data);
            if first || sum != sums[page] {
                lcd.write_page(page, data);
                sums[page] = sum;
                // Bit-banged, ~0.4ms a page: let card traffic in between
                embassy_futures::yield_now().await;
            }
        }
        first = false;
        match next {
            Some(ms) => {
                let _ = select(Timer::at(t + Duration::from_millis(ms as u64)), CHANGED.wait()).await;
            }
            None => CHANGED.wait().await,
        }
    }
}

pub async fn sound() -> ! {
    let mut buzzer = Buzzer::new();
    loop {
        let n = BEEPS.receive().await;
        for i in 0..n {
            if i > 0 {
                Timer::after_millis(80).await;
            }
            buzzer.beep(50).await;
        }
        // A burst (e.g. both slots changing at once) plays as one pattern
        while BEEPS.try_receive().is_ok() {}
        Timer::after_millis(100).await;
    }
}
