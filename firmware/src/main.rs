//! HD100 open firmware (STM32F103RBT6), embassy edition. USB stack, CCID and HID ported from bp8903-fw.
//!
//! USB composite device:
//!   interface 0: CCID contactless slot (THM3060, ISO14443 A/B, Mifare via PC/SC pseudo-APDUs,
//!                P5 security module via FF 70 / FF 72 pseudo-APDUs, see contactless.rs)
//!   interface 1: HID keyboard, magstripe swipes typed as `;track2?;track3?` + Enter (same format as bp8903)
//!   interface 2: CCID contact slot (front card slot, ISO 7816 T=0, bit-banged; PSAM slots not exposed yet)
//! Keypad: passed through to the host as keyboard keys (msr_hid.rs). LCD: status panel (ui.rs).

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_futures::join::{join3, join5};
use embassy_stm32::wdg::IndependentWatchdog;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::usb::{self, Driver};
use embassy_stm32::{bind_interrupts, peripherals};
use embassy_sync::mutex::Mutex;
use embassy_time::Timer;
use embassy_usb::types::StringIndex;
use embassy_usb::{Builder, Handler};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use hd100_fw::contactless::Contactless;
use hd100_fw::iso14443::Reader;
use hd100_fw::idsam::{self, IdSam};
use hd100_fw::iso7816;
use hd100_fw::keypad::{KeyEvent, Keypad};
use hd100_fw::magstripe::{self, MagStripe};
use hd100_fw::thm3060::Thm3060;
use hd100_fw::lcd::Lcd;
use hd100_fw::ui::{self, Usb};
use hd100_fw::{board, ccid, msr_hid};

bind_interrupts!(struct Irqs {
    USB_LP_CAN1_RX0 => usb::InterruptHandler<peripherals::USB>;
    // iso7816 first: its start-bit timing is the tightest
    EXTI9_5 => iso7816::ExtiIrq, magstripe::Exti9Irq;
    EXTI15_10 => iso7816::ExtiIrq, magstripe::Exti10Irq, idsam::Exti15Irq;
    USART2 => idsam::Usart2Irq;
    SPI2 => hd100_fw::rt::WakeIrq;
});

/// pid.codes test VID; PID differs from bp8903 (0x0001 app / 0x0002 bootloader). Development only.
const USB_VID: u16 = 0x1209;
const USB_PID: u16 = 0x0003;

/// iInterface string; libccid shows it in the reader name
struct Strings {
    contactless: StringIndex,
    contact: StringIndex,
}

impl Handler for Strings {
    fn configured(&mut self, configured: bool) {
        ui::update(|p| p.usb = if configured { Usb::Configured } else { Usb::Detached });
    }

    fn suspended(&mut self, suspended: bool) {
        ui::update(|p| {
            if suspended {
                p.usb = Usb::Suspended;
            } else if p.usb == Usb::Suspended {
                p.usb = Usb::Configured;
            }
        });
    }

    fn reset(&mut self) {
        ui::update(|p| p.usb = Usb::Detached);
    }

    fn get_string(&mut self, index: StringIndex, _lang_id: u16) -> Option<&str> {
        if index == self.contactless {
            Some("Contactless")
        } else if index == self.contact {
            Some("Contact")
        } else {
            None
        }
    }
}

async fn keypad_task(mut kp: Keypad) -> ! {
    loop {
        Timer::after_millis(10).await;
        kp.tick(|ev| {
            if let KeyEvent::Down(k) = ev {
                defmt::debug!("key down {}", k.name());
            }
            // Passthrough to the host keyboard; a full queue just drops the event
            let _ = msr_hid::KEYS.try_send(ev);
        });
    }
}

/// Own task, not part of the join below: it yields constantly, and a join re-polls all its children each time.
#[embassy_executor::task]
async fn keep_awake_task() -> ! {
    hd100_fw::rt::keep_awake().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Before anything can raise an interrupt: the critical sections only mask P1 and below (rt.rs)
    hd100_fw::rt::set_priorities();
    let p = embassy_stm32::init(board::config());
    // Voice chip is OTP with fixed clips, not useful: `--features mute` holds it in reset first thing (the
    // SWD pulls make it say "请插卡" on power-up). That turns SWD off for good, so it's off by default.
    #[cfg(feature = "mute")]
    hd100_fw::sound::Voice::new(false).mute();
    defmt::info!("HD100 fw start");

    // SysTick free-running: Mifare reader-nonce source (embassy's time driver uses TIM4)
    let mut cp = cortex_m::Peripherals::take().unwrap();
    cp.SYST.set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    cp.SYST.set_reload(0x00FF_FFFF);
    cp.SYST.enable_counter();

    // D+ pull-up is gated by PC11 (active low, measured). Keep it off until the device is built.
    let mut usb_pullup = Output::new(p.PC11, Level::High, Speed::Low);

    let keypad = Keypad::new(board::SYSCLK_HZ);
    let lcd = Lcd::new().await;
    let mag = MagStripe::new();

    let mut chip = Thm3060::new(board::SYSCLK_HZ).await;
    if !chip.probe() {
        defmt::error!("THM3060 probe failed");
    }
    chip.carrier(false);
    let sam = IdSam::new();
    static CONTACTLESS: StaticCell<ccid::SharedContactless> = StaticCell::new();
    let contactless: &'static ccid::SharedContactless =
        CONTACTLESS.init(Mutex::new(Contactless::new(Reader::new(chip)).with_sam(sam)));
    static CONTACT: StaticCell<ccid::SharedContact> = StaticCell::new();
    let contact: &'static ccid::SharedContact = CONTACT.init(Mutex::new(ccid::Contact::new(iso7816::Slot::S1)));

    let driver = Driver::new(p.USB, Irqs, p.PA12, p.PA11);
    let mut usb_config = embassy_usb::Config::new(USB_VID, USB_PID);
    usb_config.manufacturer = Some("hid2pcsc");
    usb_config.product = Some("HD100 open firmware");
    usb_config.serial_number = Some(embassy_stm32::uid::uid_hex());
    usb_config.max_power = 250; // RF field + magstripe, bus powered
    usb_config.max_packet_size_0 = 64;

    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 16]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 128]> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        usb_config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 16]),
        &mut [],
        CONTROL_BUF.init([0; 128]),
    );

    static STRINGS: StaticCell<Strings> = StaticCell::new();
    let strings = STRINGS.init(Strings { contactless: builder.string(), contact: builder.string() });
    let (cl_str, ct_str) = (strings.contactless, strings.contact);
    builder.handler(strings);

    // Interface 0: CCID contactless
    let (cl_out, cl_in, cl_int) = {
        let mut func = builder.function(0x0B, 0x00, 0x00);
        let mut iface = func.interface();
        let mut alt = iface.alt_setting(0x0B, 0x00, 0x00, Some(cl_str));
        alt.descriptor(0x21, &ccid::CONTACTLESS_DESCRIPTOR);
        let ep_out = alt.endpoint_bulk_out(None, ccid::MAX_PACKET);
        let ep_in = alt.endpoint_bulk_in(None, ccid::MAX_PACKET);
        let ep_int = alt.endpoint_interrupt_in(None, 8, 10);
        (ep_out, ep_in, ep_int)
    };

    // Interface 1: magstripe keyboard
    static HID_STATE: StaticCell<embassy_usb::class::hid::State> = StaticCell::new();
    let hid = embassy_usb::class::hid::HidWriter::<_, { msr_hid::HID_PACKET }>::new(
        &mut builder,
        HID_STATE.init(embassy_usb::class::hid::State::new()),
        embassy_usb::class::hid::Config {
            report_descriptor: msr_hid::HID_DESCRIPTOR,
            request_handler: None,
            poll_ms: 1,
            max_packet_size: msr_hid::HID_PACKET as u16,
            hid_subclass: embassy_usb::class::hid::HidSubclass::No,
            hid_boot_protocol: embassy_usb::class::hid::HidBootProtocol::None,
        },
    );

    // Interface 2: CCID contact (front slot)
    let (ct_out, ct_in, ct_int) = {
        let mut func = builder.function(0x0B, 0x00, 0x00);
        let mut iface = func.interface();
        let mut alt = iface.alt_setting(0x0B, 0x00, 0x00, Some(ct_str));
        alt.descriptor(0x21, &ccid::CONTACT_DESCRIPTOR);
        let ep_out = alt.endpoint_bulk_out(None, ccid::MAX_PACKET);
        let ep_in = alt.endpoint_bulk_in(None, ccid::MAX_PACKET);
        let ep_int = alt.endpoint_interrupt_in(None, 8, 10);
        (ep_out, ep_in, ep_int)
    };

    let mut usb = builder.build();
    usb_pullup.set_low(); // present the device to the host
    defmt::info!("USB up (PC11 low)");

    // Watchdog: 2s, fed from the executor (so it bites if any task stops yielding); halted with the core.
    const DBGMCU_CR: *mut u32 = 0xE004_2004 as *mut u32;
    unsafe { DBGMCU_CR.write_volatile(DBGMCU_CR.read_volatile() | (1 << 8)) }; // DBG_IWDG_STOP
    let mut wdg = IndependentWatchdog::new(p.IWDG, 2_000_000);
    wdg.unleash();
    let watchdog = async {
        loop {
            wdg.pet();
            Timer::after_millis(500).await;
        }
    };
    spawner.spawn(keep_awake_task().unwrap());
    // Most boards have no P5 module: find out once in the background, without delaying anything.
    // Not before the boot animation is over: the module starting up under the animation's LCD traffic makes
    // the backlight flicker (measured; see docs/hardware.md). A host command (FF 70) brings it up earlier.
    let sam_probe = async {
        Timer::after_millis(3500).await;
        let up = contactless.lock().await.sam_ensure().await;
        defmt::info!("P5 module: {}", if up { "present" } else { "absent" });
        hd100_fw::rt::set_keep_awake(up); // backlight flicker otherwise, see rt.rs
    };

    join5(
        usb.run(),
        ccid::bulk_loop(cl_out, cl_in, contactless),
        ccid::notify_loop(cl_int, contactless, "rf"),
        msr_hid::run(mag, hid),
        join5(
            keypad_task(keypad),
            ccid::bulk_loop(ct_out, ct_in, contact),
            ccid::notify_loop(ct_int, contact, "contact"),
            watchdog,
            join3(sam_probe, ui::run(lcd), ui::sound()),
        ),
    )
    .await;
}
