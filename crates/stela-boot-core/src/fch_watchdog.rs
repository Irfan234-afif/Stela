//! AMD's FCH watchdog, for an unattended diagnostics run: armed at the
//! start, it resets the PC by itself if the boot never reaches the stop
//! that restarts it, so a check run from another computer always hands the
//! PC back to its own boot order.
//!
//! The registers are Linux's `drivers/watchdog/sp5100_tco.[ch]` for the
//! FCH of Zen processors (`efch_mmio`: SMBus 1022:790b revision 0x51 or
//! later). The power-management block at 0xfed8_0300 enables the timer's
//! decoding (DECODEEN bit 7, which also starts its operation), clears the
//! firmware's disable (DECODEEN3 bits 3:2) and counts in seconds (DECODEEN3
//! bits 1:0); the watchdog's control and count sit at 0xfed8_0b00 in the
//! same ACPI MMIO window, where ISACONTROL bit 1 decodes it. Starting is a
//! write of the run bit and then a distinct one of the trigger, which loads
//! the count; an expiry with the action bit clear resets the PC.
//!
//! The stop that restarts the PC stops the watchdog first, so its reset
//! leaves it off; a restart that did not take arms it again for a short
//! count. The firmware's start, on this PC as on others, sets the disable
//! bits that Linux clears, so a boot after the watchdog's own reset does
//! not run it.

/// The FCH's power-management registers, `EFCH_PM_ACPI_MMIO_PM_ADDR`.
pub const PM: u64 = 0xfed8_0300;
/// The watchdog's control and count in the ACPI MMIO window,
/// `EFCH_PM_ACPI_MMIO_ADDR + EFCH_PM_ACPI_MMIO_WDT_OFFSET`.
pub const WATCHDOG: u64 = 0xfed8_0b00;
/// The bytes from [`PM`] to the end of the watchdog's registers, all in one
/// 64 KiB ACPI MMIO window.
pub const SPAN: u64 = WATCHDOG + 8 - PM;

/// `EFCH_PM_DECODEEN` and its `EFCH_PM_DECODEEN_WDT_TMREN`.
const DECODE_EN: u64 = 0x00;
const TIMER_ENABLE: u8 = 1 << 7;
/// `EFCH_PM_DECODEEN3`: `EFCH_PM_WATCHDOG_DISABLE` and
/// `EFCH_PM_DECODEEN_SECOND_RES`, one-second ticks.
const DECODE_EN3: u64 = 0x03;
const WATCHDOG_DISABLE: u8 = 0b1100;
const SECONDS: u8 = 0b0011;
/// `EFCH_PM_ISACONTROL` and its `EFCH_PM_ISACONTROL_MMIOEN`.
const ISA_CONTROL: u64 = 0x04;
const MMIO_ENABLE: u8 = 1 << 1;

/// `SP5100_WDT_CONTROL` and `SP5100_WDT_COUNT`.
const CONTROL: u64 = 0x00;
const COUNT: u64 = 0x04;
/// `SP5100_WDT_START_STOP_BIT`, `_FIRED`, `_ACTION_RESET` (set: power
/// off; clear: reset), `_DISABLED` and `_TRIGGER_BIT`.
const RUN: u32 = 1 << 0;
const FIRED: u32 = 1 << 1;
const POWER_OFF: u32 = 1 << 2;
const DISABLED: u32 = 1 << 3;
const TRIGGER: u32 = 1 << 7;

/// How long an unattended run may take before the watchdog resets the PC:
/// a Wi-Fi check with its recovery stage takes about four minutes at most.
pub const RUN_SECONDS: u16 = 600;
/// The count a restart that did not take leaves the watchdog.
pub const RESTART_SECONDS: u16 = 30;

/// The FCH's registers at their physical addresses.
pub trait Registers {
    fn read8(&mut self, address: u64) -> u8;
    fn write8(&mut self, address: u64, value: u8);
    fn read32(&mut self, address: u64) -> u32;
    fn write32(&mut self, address: u64, value: u32);
}

/// Why the watchdog was not armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The processor is not one of AMD's Zen families.
    NotZen,
    /// The firmware's page tables do not map the registers.
    Unmapped,
    /// DECODEEN's timer enable did not stay set.
    NoDecode,
    /// ISACONTROL leaves the ACPI MMIO window's watchdog undecoded.
    NoMmio,
    /// The control register still reads disabled, or all ones.
    Disabled(u32),
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotZen => f.write_str("not an AMD Zen processor"),
            Self::Unmapped => f.write_str("the firmware's page tables do not map its registers"),
            Self::NoDecode => f.write_str("its timer enable did not stay set"),
            Self::NoMmio => f.write_str("its registers are not decoded in the ACPI MMIO window"),
            Self::Disabled(control) => write!(f, "it reads disabled (control {control:#010x})"),
        }
    }
}

/// An armed watchdog: whether it had fired before this boot armed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Armed {
    pub seconds: u16,
    pub fired_before: bool,
}

/// `sp5100_tco_setupdevice_mmio`, `sp5100_tco_timer_init` and
/// `tco_timer_start`: decode and enable the timer, count `seconds`, reset
/// at expiry, and start it.
pub fn arm(registers: &mut impl Registers, seconds: u16) -> Result<Armed, Refusal> {
    let decode = registers.read8(PM + DECODE_EN);
    if decode & TIMER_ENABLE == 0 {
        registers.write8(PM + DECODE_EN, decode | TIMER_ENABLE);
        if registers.read8(PM + DECODE_EN) & TIMER_ENABLE == 0 {
            return Err(Refusal::NoDecode);
        }
    }
    if registers.read8(PM + ISA_CONTROL) & MMIO_ENABLE == 0 {
        return Err(Refusal::NoMmio);
    }
    let decode3 = registers.read8(PM + DECODE_EN3);
    registers.write8(PM + DECODE_EN3, decode3 & !WATCHDOG_DISABLE | SECONDS);
    let control = registers.read32(WATCHDOG + CONTROL);
    if control == u32::MAX || control & DISABLED != 0 {
        return Err(Refusal::Disabled(control));
    }
    let fired_before = control & FIRED != 0;
    // Written back, the fired bit clears; the action is a reset.
    let control = control & !(POWER_OFF | TRIGGER);
    registers.write32(WATCHDOG + CONTROL, control);
    registers.write32(WATCHDOG + COUNT, u32::from(seconds));
    // Stopped before the count is loaded, as Linux leaves it, then started.
    let control = control & !(RUN | FIRED);
    registers.write32(WATCHDOG + CONTROL, control);
    start(registers, control);
    Ok(Armed {
        seconds,
        fired_before,
    })
}

/// `tco_timer_start`: the run bit, then the trigger in a distinct write.
fn start(registers: &mut impl Registers, control: u32) {
    registers.write32(WATCHDOG + CONTROL, control | RUN);
    registers.write32(WATCHDOG + CONTROL, control | RUN | TRIGGER);
}

/// `tco_timer_stop`.
pub fn stop(registers: &mut impl Registers) {
    let control = registers.read32(WATCHDOG + CONTROL);
    registers.write32(WATCHDOG + CONTROL, control & !(RUN | TRIGGER | FIRED));
}

/// `tco_timer_set_timeout` and `tco_timer_start` on a watchdog [`arm`]
/// decoded: `seconds` from now.
pub fn rearm(registers: &mut impl Registers, seconds: u16) {
    let control = registers.read32(WATCHDOG + CONTROL) & !(RUN | TRIGGER | FIRED | POWER_OFF);
    registers.write32(WATCHDOG + COUNT, u32::from(seconds));
    start(registers, control);
}

/// The boot log's line for an arming's outcome.
pub fn line(outcome: &Result<Armed, Refusal>) -> alloc::string::String {
    match outcome {
        Ok(armed) => alloc::format!(
            "HOST WATCHDOG FCH armed: the PC resets in {} s unless the stop restarts it first{}\n",
            armed.seconds,
            if armed.fired_before {
                "; it had fired before this boot"
            } else {
                ""
            }
        ),
        Err(refusal) => alloc::format!(
            "HOST WATCHDOG FCH not armed: {refusal}; a hang before the stop needs a power-off\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The FCH as Linux finds it after the firmware's start: the timer
    /// decoded, the watchdog disabled in DECODEEN3, the ACPI MMIO window on.
    struct Fch {
        decode: u8,
        decode3: u8,
        isa: u8,
        control: u32,
        count: u32,
        /// Writes to the watchdog's control, in order.
        controls: Vec<u32>,
        /// DECODEEN's timer enable will not set.
        stuck: bool,
    }

    impl Fch {
        fn new() -> Self {
            Self {
                decode: TIMER_ENABLE,
                decode3: WATCHDOG_DISABLE,
                isa: MMIO_ENABLE,
                control: 0,
                count: 0,
                controls: Vec::new(),
                stuck: false,
            }
        }
    }

    impl Registers for Fch {
        fn read8(&mut self, address: u64) -> u8 {
            match address - PM {
                DECODE_EN => self.decode,
                DECODE_EN3 => self.decode3,
                ISA_CONTROL => self.isa,
                other => panic!("read of PM {other:#x}"),
            }
        }
        fn write8(&mut self, address: u64, value: u8) {
            match address - PM {
                DECODE_EN if !self.stuck => self.decode = value,
                DECODE_EN => {}
                DECODE_EN3 => self.decode3 = value,
                other => panic!("write of PM {other:#x}"),
            }
        }
        fn read32(&mut self, address: u64) -> u32 {
            match address - WATCHDOG {
                CONTROL => {
                    // The firmware's disable shows until DECODEEN3 clears it.
                    let disabled = if self.decode3 & WATCHDOG_DISABLE != 0 {
                        DISABLED
                    } else {
                        0
                    };
                    self.control & !TRIGGER | disabled
                }
                COUNT => self.count,
                other => panic!("read of the watchdog's {other:#x}"),
            }
        }
        fn write32(&mut self, address: u64, value: u32) {
            match address - WATCHDOG {
                CONTROL => {
                    self.controls.push(value);
                    // The fired bit clears where it is written.
                    let fired = self.control & FIRED & !value;
                    self.control = value & !FIRED | fired;
                }
                COUNT => self.count = value,
                other => panic!("write of the watchdog's {other:#x}"),
            }
        }
    }

    #[test]
    fn arming_clears_the_firmwares_disable_counts_seconds_and_starts_with_a_distinct_trigger() {
        let mut fch = Fch::new();
        fch.control = POWER_OFF;
        let armed = arm(&mut fch, RUN_SECONDS).unwrap();
        assert_eq!(
            armed,
            Armed {
                seconds: 600,
                fired_before: false
            }
        );
        assert_eq!(fch.decode3, SECONDS, "enabled, one-second ticks");
        assert_eq!(fch.count, 600);
        // The action set to reset, stopped, then run and trigger apart.
        assert_eq!(fch.controls, [0, 0, RUN, RUN | TRIGGER]);
    }

    #[test]
    fn a_watchdog_that_fired_before_is_named_and_its_flag_cleared() {
        let mut fch = Fch::new();
        fch.control = FIRED;
        let armed = arm(&mut fch, 60).unwrap();
        assert!(armed.fired_before);
        assert_eq!(fch.controls[0] & FIRED, FIRED, "written back to clear");
        assert_eq!(fch.control & FIRED, 0);
        assert!(line(&Ok(armed)).contains("it had fired before this boot"));
    }

    #[test]
    fn the_timer_enable_is_set_where_the_firmware_left_it_off() {
        let mut fch = Fch::new();
        fch.decode = 0;
        arm(&mut fch, 60).unwrap();
        assert_eq!(fch.decode, TIMER_ENABLE);
        let mut fch = Fch::new();
        fch.decode = 0;
        fch.stuck = true;
        assert_eq!(arm(&mut fch, 60), Err(Refusal::NoDecode));
        assert!(fch.controls.is_empty());
    }

    #[test]
    fn an_undecoded_window_or_a_watchdog_still_disabled_is_left_alone() {
        let mut fch = Fch::new();
        fch.isa = 0;
        assert_eq!(arm(&mut fch, 60), Err(Refusal::NoMmio));
        assert!(fch.controls.is_empty());
        let mut fch = Fch::new();
        fch.control = DISABLED;
        assert_eq!(arm(&mut fch, 60), Err(Refusal::Disabled(DISABLED)));
        assert!(fch.controls.is_empty());
        assert!(
            line(&Err(Refusal::Disabled(DISABLED)))
                .contains("not armed: it reads disabled (control 0x00000008)")
        );
    }

    #[test]
    fn a_stop_clears_the_run_bit_and_a_rearm_counts_again_from_its_seconds() {
        let mut fch = Fch::new();
        arm(&mut fch, RUN_SECONDS).unwrap();
        stop(&mut fch);
        assert_eq!(fch.control & RUN, 0);
        rearm(&mut fch, RESTART_SECONDS);
        assert_eq!(fch.count, 30);
        assert_eq!(fch.controls[fch.controls.len() - 2..], [RUN, RUN | TRIGGER]);
    }
}
