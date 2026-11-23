// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
extern crate std;

use super::*;
use crate::wifi::realtek::ax::features::ver_code;
use alloc::{collections::BTreeMap, vec, vec::Vec};

/// One register access, or a delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Read { register: u32, value: u32 },
    Write { register: u32, value: u32 },
    Delay(u64),
}

/// MAC registers, 32 bits each, whose halt control reads `ready` once
/// `after` reads went by.
#[derive(Default)]
struct Model {
    registers: BTreeMap<u32, u32>,
    log: Vec<Access>,
    after: usize,
}

impl Model {
    /// A firmware that halted with `err`, its control set after `after`
    /// polls.
    fn halted(err: u32, after: usize) -> Self {
        let mut model = Self {
            after,
            ..Self::default()
        };
        model.registers.insert(HALT_C2H, err);
        model
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Err(io::Error::Register { register })
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Err(io::Error::Register { register })
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        let mut value = self.registers.get(&register).copied().unwrap_or(0);
        if register == HALT_C2H_CTRL && !self.registers.contains_key(&register) {
            value = u32::from(self.after == 0);
            self.after = self.after.saturating_sub(1);
        }
        self.log.push(Access::Read { register, value });
        Ok(value)
    }
    fn write8(&mut self, register: u32, _: u8) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn write16(&mut self, register: u32, _: u16) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.registers.insert(register, value);
        self.log.push(Access::Write { register, value });
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.log.push(Access::Delay(microseconds));
    }
}

#[test]
fn the_error_is_read_once_the_halt_control_is_set_and_the_control_cleared() {
    let mut io = Model::halted(MAC_AX_ERR_L2_ERR_AH_DMA, 2);
    assert_eq!(err_status(&mut io), Ok(MAC_AX_ERR_L2_ERR_AH_DMA));
    assert_eq!(
        io.log,
        vec![
            Access::Read {
                register: HALT_C2H_CTRL,
                value: 0
            },
            Access::Delay(1_000),
            Access::Read {
                register: HALT_C2H_CTRL,
                value: 0
            },
            Access::Delay(1_000),
            Access::Read {
                register: HALT_C2H_CTRL,
                value: 1
            },
            Access::Read {
                register: HALT_C2H,
                value: MAC_AX_ERR_L2_ERR_AH_DMA
            },
            Access::Write {
                register: HALT_C2H_CTRL,
                value: 0
            },
        ]
    );
}

#[test]
fn a_scenario_names_its_error_and_a_silent_control_times_out() {
    for (err, named) in [
        (0x2000_1234, MAC_AX_ERR_CPU_EXCEPTION),
        (0x3000_0042, MAC_AX_ERR_ASSERTION),
        (0x1000_0007, MAC_AX_ERR_RXI300),
        (MAC_AX_ERR_L1_ERR_DMAC, MAC_AX_ERR_L1_ERR_DMAC),
    ] {
        assert_eq!(err_status(&mut Model::halted(err, 0)), Ok(named));
    }
    // 100 polls a millisecond apart, then rtw89's -ETIMEDOUT.
    let mut io = Model::halted(0, usize::MAX);
    assert_eq!(
        err_status(&mut io),
        Err(io::Error::Timeout {
            register: HALT_C2H_CTRL,
            mask: u32::MAX
        })
    );
    let polls = io
        .log
        .iter()
        .filter(|access| matches!(access, Access::Read { .. }))
        .count();
    assert_eq!(polls, 101);
    assert!(
        !io.log
            .iter()
            .any(|access| matches!(access, Access::Write { .. }))
    );
}

#[test]
fn ser_notify_maps_each_level_and_refuses_what_it_does_not_know() {
    let cases = [
        (MAC_AX_ERR_L1_PREERR_DMAC, Some(Event::L1ResetPrepare)),
        (MAC_AX_ERR_L1_ERR_DMAC, Some(Event::L1Reset)),
        (MAC_AX_ERR_L0_PROMOTE_TO_L1, Some(Event::L1Reset)),
        (
            MAC_AX_ERR_L1_RESET_DISABLE_DMAC_DONE,
            Some(Event::DoRecovery),
        ),
        (MAC_AX_ERR_L1_RESET_RECOVERY_DONE, Some(Event::MacResetDone)),
        (MAC_AX_ERR_L0_ERR_CMAC1, Some(Event::L0Reset)),
        (MAC_AX_ERR_L1_PROMOTE_TO_L2, Some(Event::L2Reset)),
        (MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT, Some(Event::L2Reset)),
        (MAC_AX_ERR_CPU_EXCEPTION, Some(Event::L2Reset)),
        (MAC_AX_GET_ERR_MAX, Some(Event::L2Reset)),
        (MAC_AX_GET_ERR_MAX + 1, None),
        (0x0004, None),
        (0x1fff, None),
    ];
    for (err, event) in cases {
        assert_eq!(Event::of(err), event, "{err:#x}");
    }
    let halted = Halt::Firmware(Ok(MAC_AX_ERR_CPU_EXCEPTION));
    assert_eq!(
        format!("{halted}"),
        "firmware halted (err status 0x3000, SER_EV_L2_RESET)"
    );
    assert_eq!(
        format!("{}", Halt::Watchdog),
        "firmware watchdog fired (err status 0x2599, SER_EV_L2_RESET)"
    );
    let unread = Halt::Firmware(Err(io::Error::Timeout {
        register: HALT_C2H_CTRL,
        mask: u32::MAX,
    }));
    assert!(format!("{unread}").starts_with("firmware halted (err status unread: Timeout"));
}

#[test]
fn three_recoveries_a_minute_are_allowed_and_a_fourth_waits_for_the_first_to_age() {
    let mut recoveries = Recoveries::default();
    assert_eq!(recoveries.allow(0), Some(1));
    assert_eq!(recoveries.allow(10_000_000), Some(2));
    assert_eq!(recoveries.allow(20_000_000), Some(3));
    assert_eq!(recoveries.allow(59_999_999), None);
    // The first is a minute old: one more.
    assert_eq!(recoveries.allow(60_000_000), Some(3));
    assert_eq!(recoveries.total(), 4);
}

#[test]
fn the_crash_trigger_follows_the_firmwares_feature() {
    assert_eq!(
        cpu_exception_type(Features::of(ver_code(0, 29, 29, 18))),
        Some(CPU_EXCEPTION_TYPE_0)
    );
    assert_eq!(
        cpu_exception_type(Features::of(ver_code(0, 29, 128, 0))),
        Some(CPU_EXCEPTION_TYPE_1)
    );
    assert_eq!(
        cpu_exception_type(Features::of(ver_code(0, 29, 28, 0))),
        None
    );
}
