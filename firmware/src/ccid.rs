//! Minimal USB CCID class, ported from bp8903-fw (src/ccid.rs).
//! One CCID interface = one slot, both at short APDU level:
//! - contactless (activation and ISO-DEP live in contactless.rs)
//! - contact, front card slot (ATR / PPS / T=0 live in iso7816.rs)
//!
//! Rules carried over from bp8903 (learned from its vendor firmware's failure modes):
//! - Bulk OUT messages are framed by `dwLength`, never by "short packet".
//! - Every IN transfer that ends on a 64-byte boundary is followed by a ZLP.
//! - Interrupt notifications are sent with a timeout and dropped if the host is not polling.

use embassy_stm32::usb::Driver;
use embassy_stm32::peripherals::USB;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use core::pin::pin;

use embassy_futures::select::{select, Either};
use embassy_time::{with_timeout, Duration, Timer};
use embassy_usb::driver::{Endpoint, EndpointError, EndpointIn, EndpointOut};

use crate::contactless::Contactless;
use crate::ui::{self, Ident, Medium};
use crate::iso7816::{self, Card, Error as IccError, Slot as IccSlot};
use crate::thm3060::Error as RfError;

pub type Drv = Driver<'static, USB>;

pub const MAX_PACKET: u16 = 64;
const HDR: usize = 10;
const MAX_DATA: usize = 261;
const MAX_MSG: usize = HDR + MAX_DATA;

/// Contactless interface: T=1 by PC/SC convention, short APDU level, the
/// reader does activation and everything below the APDU.
#[rustfmt::skip]
pub const CONTACTLESS_DESCRIPTOR: [u8; 52] = {
    let clock = 13_560u32.to_le_bytes();
    let rate = 106_000u32.to_le_bytes();
    let max_msg = (MAX_MSG as u32).to_le_bytes();
    [
        0x10, 0x01,             // bcdCCID 1.10
        0x00,                   // bMaxSlotIndex
        0x07,                   // bVoltageSupport: any (ignored)
        0x02, 0x00, 0x00, 0x00, // dwProtocols: T=1
        clock[0], clock[1], clock[2], clock[3], // dwDefaultClock: 13.56 MHz carrier
        clock[0], clock[1], clock[2], clock[3], // dwMaximumClock
        0x00,                   // bNumClockSupported
        rate[0], rate[1], rate[2], rate[3],     // dwDataRate: 106 kbit/s
        rate[0], rate[1], rate[2], rate[3],     // dwMaxDataRate
        0x00,                   // bNumDataRatesSupported
        0xFE, 0x00, 0x00, 0x00, // dwMaxIFSD
        0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
        0x00, 0x00, 0x00, 0x00, // dwMechanical
        // dwFeatures: automatic parameters from ATR, voltage, clock, baud rate,
        // parameter negotiation and PPS; short APDU level exchange.
        0xFA, 0x00, 0x02, 0x00,
        max_msg[0], max_msg[1], max_msg[2], max_msg[3], // dwMaxCCIDMessageLength
        0xFF,                   // bClassGetResponse
        0xFF,                   // bClassEnvelope
        0x00, 0x00,             // wLcdLayout
        0x00,                   // bPINSupport
        0x01,                   // bMaxCCIDBusySlots
    ]
};

/// Contact interface (front card slot): T=0 only, short APDU level. The reader does ATR, PPS,
/// T=0 procedure bytes and 61xx / 6Cxx itself (iso7816.rs), like the contactless slot.
#[rustfmt::skip]
pub const CONTACT_DESCRIPTOR: [u8; 52] = {
    let clock = 4_000u32.to_le_bytes(); // kHz: TIM3, 72 MHz / 18
    let rate = (4_000_000u32 / 372).to_le_bytes();
    let max_rate = (4_000_000u32 / iso7816::MIN_ETU_CLOCKS).to_le_bytes();
    let max_msg = (MAX_MSG as u32).to_le_bytes();
    [
        0x10, 0x01,             // bcdCCID 1.10
        0x00,                   // bMaxSlotIndex
        0x01,                   // bVoltageSupport: card VCC is fixed (not switchable; level not measured yet)
        0x01, 0x00, 0x00, 0x00, // dwProtocols: T=0
        clock[0], clock[1], clock[2], clock[3], // dwDefaultClock (kHz)
        clock[0], clock[1], clock[2], clock[3], // dwMaximumClock
        0x00,                   // bNumClockSupported
        rate[0], rate[1], rate[2], rate[3],     // dwDataRate
        max_rate[0], max_rate[1], max_rate[2], max_rate[3], // dwMaxDataRate: 16 clocks / etu
        0x00,                   // bNumDataRatesSupported
        0x00, 0x00, 0x00, 0x00, // dwMaxIFSD (no T=1)
        0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
        0x00, 0x00, 0x00, 0x00, // dwMechanical
        // dwFeatures: automatic parameters from ATR, voltage, clock, baud rate,
        // parameter negotiation and PPS; short APDU level exchange.
        0xFA, 0x00, 0x02, 0x00,
        max_msg[0], max_msg[1], max_msg[2], max_msg[3], // dwMaxCCIDMessageLength
        0xFF,                   // bClassGetResponse
        0xFF,                   // bClassEnvelope
        0x00, 0x00,             // wLcdLayout
        0x00,                   // bPINSupport
        0x01,                   // bMaxCCIDBusySlots
    ]
};

mod msg {
    pub const SET_PARAMETERS: u8 = 0x61;
    pub const ICC_POWER_ON: u8 = 0x62;
    pub const ICC_POWER_OFF: u8 = 0x63;
    pub const GET_SLOT_STATUS: u8 = 0x65;
    pub const GET_PARAMETERS: u8 = 0x6C;
    pub const XFR_BLOCK: u8 = 0x6F;

    pub const DATA_BLOCK: u8 = 0x80;
    pub const SLOT_STATUS: u8 = 0x81;
    pub const PARAMETERS: u8 = 0x82;

    pub const NOTIFY_SLOT_CHANGE: u8 = 0x50;
}

#[allow(dead_code)]
mod err {
    pub const CMD_NOT_SUPPORTED: u8 = 0x00;
    pub const BAD_SLOT: u8 = 0x05;
    pub const ICC_MUTE: u8 = 0xFE;
    pub const XFR_PARITY_ERROR: u8 = 0xFD;
    pub const XFR_OVERRUN: u8 = 0xFC;
    pub const PROCEDURE_BYTE_CONFLICT: u8 = 0xF4;
    pub const BAD_LENGTH: u8 = 0x01;
    pub const BAD_POWER_SELECT: u8 = 0x07;
    pub const HW_ERROR: u8 = 0xFB;
    pub const BAD_ATR_TS: u8 = 0xF8;
}

const CMD_FAILED: u8 = 0x40;
const TIME_EXTENSION: u8 = 0x80;

pub type SharedContactless = Mutex<NoopRawMutex, Contactless>;

/// One CCID interface (one slot).
#[allow(async_fn_in_trait)]
pub trait Slot {
    /// Presence poll period for the interrupt endpoint.
    const POLL: Duration;
    /// Buzzer feedback on presence changes (50ms beep).
    const BEEP_ON_INSERT: bool;
    const BEEP_ON_REMOVE: bool;
    async fn handle(&self, req: &[u8]) -> Reply;
    async fn present(&self) -> bool;
}

pub struct Reply {
    buf: [u8; MAX_MSG],
    len: usize,
}

impl Reply {
    fn new(kind: u8, req: &[u8], status: u8, error: u8) -> Self {
        let mut buf = [0u8; MAX_MSG];
        buf[0] = kind;
        buf[5] = req[5]; // bSlot
        buf[6] = req[6]; // bSeq
        buf[7] = status;
        buf[8] = error;
        Self { buf, len: HDR }
    }

    fn data(mut self, data: &[u8]) -> Self {
        self.buf[HDR..HDR + data.len()].copy_from_slice(data);
        self.buf[1..5].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.len = HDR + data.len();
        self
    }

    fn failed(kind: u8, req: &[u8], icc: u8, error: u8) -> Self {
        Self::new(kind, req, CMD_FAILED | icc, error)
    }
}

impl Slot for SharedContactless {
    /// Each idle poll pulses the field for ~10 ms.
    const POLL: Duration = Duration::from_millis(250);
    const BEEP_ON_INSERT: bool = true;
    const BEEP_ON_REMOVE: bool = true;

    async fn handle(&self, req: &[u8]) -> Reply {
        handle_contactless(req, self).await
    }

    async fn present(&self) -> bool {
        let mut c = self.lock().await;
        let present = c.poll().await;
        let shown = c.card().map(rf_medium);
        ui::update(|p| {
            p.rf = match (present, shown) {
                (false, _) => Medium::Empty,
                (true, Some(m)) => m,
                // Detected by the idle poll: keep what we know about it, if anything
                (true, None) if p.rf == Medium::Empty => Medium::Present(Ident::default()),
                (true, None) => p.rf,
            }
        });
        present
    }
}

/// How the panel shows an activated contactless card
fn rf_medium(card: &crate::contactless::Card) -> Medium {
    if card.raw {
        Medium::Named("ID card") // PUPI is all zero, nothing worth showing as bytes
    } else {
        Medium::Present(Ident::new(card.uid()))
    }
}

fn cl_status(c: &Contactless) -> u8 {
    if c.is_active() {
        0
    } else if c.card_present() {
        1
    } else {
        2
    }
}

/// T=1 parameters reported for contactless cards (CCID 6.1.7): Fi/Di 11,
/// LRC, BWI 4 / CWI 13, IFSC 254. Informational only.
const CL_T1_PARAMS: [u8; 7] = [0x11, 0x10, 0x00, 0x4D, 0x00, 0xFE, 0x00];

async fn handle_contactless(req: &[u8], cl: &SharedContactless) -> Reply {
    let mut c = cl.lock().await;
    let icc = cl_status(&c);
    if req[5] != 0 {
        return Reply::failed(msg::SLOT_STATUS, req, icc, err::BAD_SLOT);
    }
    match req[0] {
        msg::GET_SLOT_STATUS => Reply::new(msg::SLOT_STATUS, req, icc, 0),
        msg::ICC_POWER_ON => match c.power_on().await {
            Ok(atr) => {
                defmt::info!("rf: ATR {=[u8]:02x}", atr.bytes[..atr.len]);
                if let Some(m) = c.card().map(rf_medium) {
                    ui::update(|p| p.rf = m);
                }
                Reply::new(msg::DATA_BLOCK, req, 0, 0).data(&atr.bytes[..atr.len])
            }
            Err(e) => {
                defmt::warn!("rf: power on: {}", e);
                let code = match e {
                    RfError::NoChip => err::HW_ERROR,
                    _ => err::ICC_MUTE,
                };
                Reply::failed(msg::DATA_BLOCK, req, cl_status(&c), code)
            }
        },
        msg::ICC_POWER_OFF => {
            c.power_off().await;
            Reply::new(msg::SLOT_STATUS, req, cl_status(&c), 0)
        }
        msg::GET_PARAMETERS | msg::SET_PARAMETERS => {
            let mut r = Reply::new(msg::PARAMETERS, req, icc, 0).data(&CL_T1_PARAMS);
            r.buf[9] = 1; // bProtocolNum: T=1
            if req[0] == msg::SET_PARAMETERS && req[7] != 1 {
                r.buf[7] |= CMD_FAILED;
                r.buf[8] = 7; // offset of bProtocolNum
            }
            r
        }
        msg::XFR_BLOCK => {
            let len = u32::from_le_bytes([req[1], req[2], req[3], req[4]]) as usize;
            if !c.is_active() {
                return Reply::failed(msg::DATA_BLOCK, req, icc, err::ICC_MUTE);
            }
            let mut r = Reply::new(msg::DATA_BLOCK, req, 0, 0);
            match c.xfr(&req[HDR..HDR + len], &mut r.buf[HDR..]).await {
                Ok(n) => {
                    r.buf[1..5].copy_from_slice(&(n as u32).to_le_bytes());
                    r.len = HDR + n;
                    r
                }
                Err(e) => {
                    defmt::warn!("rf: xfr: {}", e);
                    let code = match e {
                        RfError::NoChip => err::HW_ERROR,
                        RfError::Overflow | RfError::BufferTooSmall => err::XFR_OVERRUN,
                        RfError::Crc | RfError::Parity | RfError::Framing => err::XFR_PARITY_ERROR,
                        _ => err::ICC_MUTE,
                    };
                    Reply::failed(msg::DATA_BLOCK, req, cl_status(&c), code)
                }
            }
        }
        _ => Reply::failed(msg::SLOT_STATUS, req, icc, err::CMD_NOT_SUPPORTED),
    }
}

/// Front contact slot state. `card` = session opened by the host (IccPowerOn).
pub struct Contact {
    slot: IccSlot,
    card: Option<Card>,
    /// Last presence probe result (only meaningful while there is no session)
    present: bool,
}

impl Contact {
    pub fn new(slot: IccSlot) -> Self {
        iso7816::init();
        Contact { slot, card: None, present: false }
    }

    fn status(&self) -> u8 {
        if self.card.is_some() {
            0
        } else if self.present {
            1
        } else {
            2
        }
    }

    /// No detect switch on this board: probe with a cold reset and wait for TS (≤ ~20ms).
    /// Never touches an open session — that would reset the card under the host's feet.
    /// Skipped while the P5 module is mid-command (it holds the real-time lock).
    async fn probe(&mut self) -> bool {
        if self.card.is_none() {
            if let Ok(_rt) = crate::rt::RT_LOCK.try_lock() {
                // The card is dropped (deactivated) right away; the ATR is what the panel shows
                let r = Card::activate_no_pps(self.slot).await;
                self.present = r.is_ok();
                let m = match r {
                    Ok((_, atr)) => Medium::Present(Ident::new(atr.as_slice())),
                    Err(_) => Medium::Empty,
                };
                ui::update(|p| p.ct = m);
            }
        }
        self.card.is_some() || self.present
    }
}

pub type SharedContact = Mutex<NoopRawMutex, Contact>;

impl Slot for SharedContact {
    /// Each idle probe is a cold reset + ATR wait (~20-30ms with a card, ~20ms without).
    const POLL: Duration = Duration::from_millis(500);
    /// Only "card answered with an ATR" is detectable, so the beep means "inserted correctly".
    const BEEP_ON_INSERT: bool = true;
    const BEEP_ON_REMOVE: bool = false;

    async fn handle(&self, req: &[u8]) -> Reply {
        handle_contact(req, self).await
    }

    async fn present(&self) -> bool {
        self.lock().await.probe().await
    }
}

async fn handle_contact(req: &[u8], contact: &SharedContact) -> Reply {
    let mut c = contact.lock().await;
    let icc = c.status();
    if req[5] != 0 {
        return Reply::failed(msg::SLOT_STATUS, req, icc, err::BAD_SLOT);
    }
    match req[0] {
        msg::GET_SLOT_STATUS => Reply::new(msg::SLOT_STATUS, req, icc, 0),
        msg::ICC_POWER_ON => {
            c.card = None; // power cycle: drop (deactivate) any previous session first
            let _rt = crate::rt::RT_LOCK.lock().await;
            match Card::activate(c.slot).await {
                Ok((card, atr)) => {
                    defmt::info!(
                        "contact: ATR {=[u8]:02x}, Fi/Di 0x{=u8:02x}, etu {=u32}ns",
                        atr.as_slice(),
                        card.fd(),
                        card.etu_ns()
                    );
                    c.card = Some(card);
                    c.present = true;
                    ui::update(|p| p.ct = Medium::Present(Ident::new(atr.as_slice())));
                    Reply::new(msg::DATA_BLOCK, req, 0, 0).data(atr.as_slice())
                }
                Err(e) => {
                    defmt::warn!("contact: power on: {}", e);
                    c.present = !matches!(e, IccError::Timeout);
                    if !c.present {
                        ui::update(|p| p.ct = Medium::Empty);
                    }
                    let code = match e {
                        IccError::Timeout => err::ICC_MUTE,
                        _ => err::BAD_ATR_TS,
                    };
                    Reply::failed(msg::DATA_BLOCK, req, c.status(), code)
                }
            }
        }
        msg::ICC_POWER_OFF => {
            c.card = None;
            Reply::new(msg::SLOT_STATUS, req, c.status(), 0)
        }
        msg::GET_PARAMETERS | msg::SET_PARAMETERS => {
            // Parameters are automatic (ATR / PPS); SetParameters is accepted and ignored.
            let params = c.card.as_ref().map(|k| k.t0_params()).unwrap_or([0x11, 0, 0, 10, 0]);
            let mut r = Reply::new(msg::PARAMETERS, req, icc, 0).data(&params);
            r.buf[9] = 0; // bProtocolNum: T=0
            if req[0] == msg::SET_PARAMETERS && req[7] != 0 {
                r.buf[7] |= CMD_FAILED;
                r.buf[8] = 7; // offset of bProtocolNum: T=1 not supported
            }
            r
        }
        msg::XFR_BLOCK => {
            let len = u32::from_le_bytes([req[1], req[2], req[3], req[4]]) as usize;
            let Some(card) = c.card.as_mut() else {
                return Reply::failed(msg::DATA_BLOCK, req, icc, err::ICC_MUTE);
            };
            let mut r = Reply::new(msg::DATA_BLOCK, req, 0, 0);
            let rt = crate::rt::RT_LOCK.lock().await;
            let res = card.transmit(&req[HDR..HDR + len], &mut r.buf[HDR..]).await;
            drop(rt);
            match res {
                Ok(n) => {
                    r.buf[1..5].copy_from_slice(&(n as u32).to_le_bytes());
                    r.len = HDR + n;
                    r
                }
                Err(e) => {
                    defmt::warn!("contact: xfr: {}", e);
                    let code = match e {
                        IccError::Parity | IccError::TxRejected => err::XFR_PARITY_ERROR,
                        IccError::Overflow => err::XFR_OVERRUN,
                        IccError::Protocol => err::PROCEDURE_BYTE_CONFLICT,
                        IccError::Timeout => err::ICC_MUTE,
                    };
                    if matches!(e, IccError::Timeout) {
                        // Mute card: most likely pulled out. End the session; the next probe decides presence.
                        c.card = None;
                        c.present = false;
                        ui::update(|p| p.ct = Medium::Empty);
                    }
                    Reply::failed(msg::DATA_BLOCK, req, c.status(), code)
                }
            }
        }
        _ => Reply::failed(msg::SLOT_STATUS, req, icc, err::CMD_NOT_SUPPORTED),
    }
}

async fn read_message(
    ep: &mut <Drv as embassy_usb::driver::Driver<'static>>::EndpointOut,
    buf: &mut [u8; MAX_MSG],
) -> Result<usize, EndpointError> {
    let mut len = 0;
    loop {
        let n = ep.read(&mut buf[len..]).await?;
        len += n;
        if len >= HDR {
            let want = HDR + u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if want > MAX_MSG {
                // Too long to hold: discard exactly the rest of it, by length.
                let mut left = want - len;
                while left > 0 {
                    let n = ep.read(&mut buf[..]).await?;
                    if n == 0 {
                        break;
                    }
                    left = left.saturating_sub(n);
                }
                return Ok(0);
            }
            if len >= want {
                return Ok(want);
            }
        } else if n < MAX_PACKET as usize {
            return Ok(0); // runt
        }
    }
}

async fn write_message(
    ep: &mut <Drv as embassy_usb::driver::Driver<'static>>::EndpointIn,
    data: &[u8],
) -> Result<(), EndpointError> {
    for chunk in data.chunks(MAX_PACKET as usize) {
        ep.write(chunk).await?;
    }
    if data.len().is_multiple_of(MAX_PACKET as usize) {
        ep.write(&[]).await?;
    }
    Ok(())
}

pub async fn bulk_loop<S: Slot>(
    mut ep_out: <Drv as embassy_usb::driver::Driver<'static>>::EndpointOut,
    mut ep_in: <Drv as embassy_usb::driver::Driver<'static>>::EndpointIn,
    slot: &S,
) -> ! {
    let mut buf = [0u8; MAX_MSG];
    loop {
        ep_out.wait_enabled().await;
        loop {
            let len = match read_message(&mut ep_out, &mut buf).await {
                Ok(0) => continue,
                Ok(n) => n,
                Err(_) => break,
            };
            let req = &buf[..len];
            let mut work = pin!(slot.handle(req));
            // Long card operations (key generation, T=0 NULL bytes): tell the host
            // we are alive so libccid keeps waiting (CCID 6.2.7, bStatus = 0x80).
            let reply = loop {
                match select(&mut work, Timer::after_secs(1)).await {
                    Either::First(r) => break r,
                    Either::Second(()) => {
                        // Same message type as the final answer (CCID 6.2).
                        let kind = match req[0] {
                            msg::ICC_POWER_ON | msg::XFR_BLOCK => msg::DATA_BLOCK,
                            msg::GET_PARAMETERS | msg::SET_PARAMETERS => msg::PARAMETERS,
                            _ => msg::SLOT_STATUS,
                        };
                        let ext = Reply::new(kind, req, TIME_EXTENSION, 1);
                        // Never let an absent reader of bulk IN stall the card work.
                        let _ = with_timeout(Duration::from_millis(200), write_message(&mut ep_in, &ext.buf[..ext.len])).await;
                    }
                }
            };
            if write_message(&mut ep_in, &reply.buf[..reply.len]).await.is_err() {
                break;
            }
        }
    }
}

/// Polls card presence, reports changes on the interrupt endpoint and beeps per the slot's policy.
pub async fn notify_loop<S: Slot>(
    mut ep_int: <Drv as embassy_usb::driver::Driver<'static>>::EndpointIn,
    slot: &S,
    name: &str,
) -> ! {
    let mut last: Option<bool> = None;
    loop {
        Timer::after(S::POLL).await;
        let present = slot.present().await;
        if last == Some(present) {
            continue;
        }
        defmt::info!("{}: card {}", name, if present { "inserted" } else { "removed" });
        let changed = last.is_some();
        // Card present at boot counts as an insertion; "absent at boot" is not a removal.
        if (present && S::BEEP_ON_INSERT) || (!present && changed && S::BEEP_ON_REMOVE) {
            ui::beep(1);
        }
        last = Some(present);
        let state = present as u8 | (changed as u8) << 1;
        // Host may not be polling; never let that stall presence tracking.
        let _ = with_timeout(Duration::from_millis(50), ep_int.write(&[msg::NOTIFY_SLOT_CHANGE, state])).await;
    }
}
