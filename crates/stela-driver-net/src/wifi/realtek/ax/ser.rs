// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! An RTL8852BE's system error recovery (SER), as Stela takes it.
//!
//! Pinned rtw89 (ser.c) recovers a halted firmware in place: its L0 and L1
//! resets are handshakes the firmware drives through the halt registers,
//! and its L2 reset (`ser_l2_reset_st_hdl`) stops the core
//! (`rtw89_core_stop`) and has mac80211 restart the hardware
//! (`ieee80211_restart_hw`), which brings it up through `rtw89_core_start`
//! and replays the interface, the station and its keys. Stela takes every
//! error as L2 and replays nothing: the chip is powered off and brought up
//! cold as the interface came up, and the station joins again from a scan
//! ([`super::hardware::Hardware`]'s recovery). This module holds what that
//! recovery reads and bounds:
//!
//! - [`err_status`] is `rtw89_mac_get_err_status` (mac.c) on an RTL8852B,
//!   which `rtw89_pci_interrupt_threadfn` (pci.c) runs for the halt C2H
//!   cause ([`super::interrupt::Events::halt_c2h`]): the error the firmware
//!   left in `R_AX_HALT_C2H`, once `R_AX_HALT_C2H_CTRL` says it is there,
//!   that control cleared, and the error scenario's CPU exception,
//!   assertion and RXI300 named. The watchdog cause
//!   ([`super::interrupt::Events::wdt`]) reports
//!   [`MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT`] instead ([`Halt::Watchdog`]).
//! - [`Event::of`] is `rtw89_ser_notify`'s map from that error to the
//!   event it sends the SER state machine, kept for the log only.
//! - [`Recoveries`] is the bound on cold re-inits: [`RECOVERIES`] a
//!   minute, after which the chip stays off.
//! - [`trigger_cpu_exception`] is `rtw89_fw_h2c_trigger_cpu_exception`
//!   (fw.c), which halts the firmware on purpose, for diagnostics.
//!
//! What this leaves out, and why: the L0 and L1 handshakes
//! (`rtw89_mac_set_err_status` and the state machine), since every error
//! is taken as L2 here; `rtw89_fw_st_dbg_dump` and `dump_err_status`'s
//! register dumps and `rtw89_mac_suppress_log`, which only log; and
//! `SER_POST_RECOVER_DMAC`, a feature no RTL8852B firmware has, so the
//! control is cleared right after the error is read.
//!
//! An error read proves only what the firmware wrote; nothing here proves
//! that the firmware halted for the reason it names.
use super::{
    features::{Feature, Features},
    h2c::{self, Channel, FWCMD_TYPE_H2C, Function, H2C_CAT_TEST},
    io::{self, Io, Registers},
    pci::ring::Rings,
    registers::{HALT_C2H, HALT_C2H_CTRL},
};
use alloc::vec::Vec;
use core::fmt;

#[cfg(test)]
mod tests;

/// `enum rtw89_mac_error_scenario` and `RTW89_ERROR_SCENARIO`'s shift: the
/// top nibble of a halt C2H's error.
pub const RXI300_ERROR: u32 = 1;
pub const WCPU_CPU_EXCEPTION: u32 = 2;
pub const WCPU_ASSERTION: u32 = 3;
pub const ERROR_SCENARIO_SHIFT: u32 = 28;

/// The members of `enum mac_ax_err_info` that `rtw89_ser_notify` names.
pub const MAC_AX_ERR_L0_ERR_CMAC0: u32 = 0x0001;
pub const MAC_AX_ERR_L0_ERR_CMAC1: u32 = 0x0002;
pub const MAC_AX_ERR_L0_RESET_DONE: u32 = 0x0003;
pub const MAC_AX_ERR_L0_PROMOTE_TO_L1: u32 = 0x0010;
pub const MAC_AX_ERR_L1_PREERR_DMAC: u32 = 0x0999;
pub const MAC_AX_ERR_L1_ERR_DMAC: u32 = 0x1000;
pub const MAC_AX_ERR_L1_RESET_DISABLE_DMAC_DONE: u32 = 0x1001;
pub const MAC_AX_ERR_L1_RESET_RECOVERY_DONE: u32 = 0x1002;
pub const MAC_AX_ERR_L1_PROMOTE_TO_L2: u32 = 0x1010;
pub const MAC_AX_ERR_L2_ERR_AH_DMA: u32 = 0x2000;
pub const MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT: u32 = 0x2599;
pub const MAC_AX_ERR_CPU_EXCEPTION: u32 = 0x3000;
pub const MAC_AX_ERR_ASSERTION: u32 = 0x4000;
pub const MAC_AX_ERR_RXI300: u32 = 0x5000;
/// `MAC_AX_GET_ERR_MAX`, the member after `MAC_AX_ERR_RXI300`.
pub const MAC_AX_GET_ERR_MAX: u32 = MAC_AX_ERR_RXI300 + 1;

/// `rtw89_mac_get_err_status`'s poll of `R_AX_HALT_C2H_CTRL`: every 1 ms,
/// for up to 100 ms.
pub const ERR_STATUS_STEP_US: u64 = 1_000;
pub const ERR_STATUS_TIMEOUT_US: u64 = 100_000;

/// `H2C_CL_FW_STATUS_TEST` and `H2C_FUNC_CPU_EXCEPTION` of `H2C_CAT_TEST`.
pub const H2C_CL_FW_STATUS_TEST: u8 = 0x5;
pub const H2C_FUNC_CPU_EXCEPTION: u8 = 0x1;
/// `H2C_FW_CPU_EXCEPTION_TYPE_0` and `_1`: the word that asks the firmware
/// to crash, by its `CRASH_TRIGGER_TYPE_*` feature.
pub const CPU_EXCEPTION_TYPE_0: u32 = 0x5566;
pub const CPU_EXCEPTION_TYPE_1: u32 = 0x0;

/// How many cold re-inits a minute the chip gets, and the minute.
pub const RECOVERIES: usize = 3;
pub const WINDOW_US: u64 = 60_000_000;

/// `rtw89_mac_get_err_status` on an RTL8852B: the firmware's error once
/// `R_AX_HALT_C2H_CTRL` reads non-zero, that control cleared, an error
/// whose scenario is a CPU exception, an assertion or RXI300 named as one.
/// A control that stays 0 is rtw89's "Polling FW err status fail", whose
/// timeout rtw89 hands `rtw89_ser_notify` as the error.
pub fn err_status<I: Io + ?Sized>(io: &mut I) -> Result<u32, io::Error> {
    io.poll32(
        HALT_C2H_CTRL,
        u32::MAX,
        ERR_STATUS_STEP_US,
        ERR_STATUS_TIMEOUT_US,
        |err| err != 0,
    )?;
    let err = io.read32(HALT_C2H)?;
    // No SER_POST_RECOVER_DMAC on an RTL8852B: cleared now.
    io.write32(HALT_C2H_CTRL, 0)?;
    Ok(match err >> ERROR_SCENARIO_SHIFT {
        WCPU_CPU_EXCEPTION => MAC_AX_ERR_CPU_EXCEPTION,
        WCPU_ASSERTION => MAC_AX_ERR_ASSERTION,
        RXI300_ERROR => MAC_AX_ERR_RXI300,
        _ => err,
    })
}

/// The events `rtw89_ser_notify` sends the SER state machine
/// (`enum ser_evt`'s `SER_EV_*`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    L1ResetPrepare,
    L1Reset,
    DoRecovery,
    MacResetDone,
    L0Reset,
    L2Reset,
}

impl Event {
    /// `rtw89_ser_notify`'s map: `None` where rtw89 "cannot recognize" the
    /// error and recovers nothing.
    pub const fn of(err: u32) -> Option<Self> {
        Some(match err {
            MAC_AX_ERR_L1_PREERR_DMAC => Self::L1ResetPrepare,
            MAC_AX_ERR_L1_ERR_DMAC | MAC_AX_ERR_L0_PROMOTE_TO_L1 => Self::L1Reset,
            MAC_AX_ERR_L1_RESET_DISABLE_DMAC_DONE => Self::DoRecovery,
            MAC_AX_ERR_L1_RESET_RECOVERY_DONE => Self::MacResetDone,
            MAC_AX_ERR_L0_ERR_CMAC0 | MAC_AX_ERR_L0_ERR_CMAC1 | MAC_AX_ERR_L0_RESET_DONE => {
                Self::L0Reset
            }
            MAC_AX_ERR_L1_PROMOTE_TO_L2 | MAC_AX_ERR_L2_ERR_AH_DMA..=MAC_AX_GET_ERR_MAX => {
                Self::L2Reset
            }
            _ => return None,
        })
    }

    /// The event's name in ser.c.
    pub const fn name(self) -> &'static str {
        match self {
            Self::L1ResetPrepare => "SER_EV_L1_RESET_PREPARE",
            Self::L1Reset => "SER_EV_L1_RESET",
            Self::DoRecovery => "SER_EV_DO_RECOVERY",
            Self::MacResetDone => "SER_EV_MAC_RESET_DONE",
            Self::L0Reset => "SER_EV_L0_RESET",
            Self::L2Reset => "SER_EV_L2_RESET",
        }
    }
}

/// Why the firmware went: the cause `rtw89_pci_interrupt_threadfn` hands
/// `rtw89_ser_notify`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Halt {
    /// The halt C2H, with what [`err_status`] read.
    Firmware(Result<u32, io::Error>),
    /// The firmware's watchdog: [`MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT`].
    Watchdog,
}

impl Halt {
    /// The error `rtw89_ser_notify` is handed, where one was read.
    pub fn err(self) -> Option<u32> {
        match self {
            Self::Firmware(err) => err.ok(),
            Self::Watchdog => Some(MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT),
        }
    }
}

/// As the log names it: `firmware halted (err status 0x3000,
/// SER_EV_L2_RESET)`.
impl fmt::Display for Halt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::Firmware(_) => "firmware halted",
            Self::Watchdog => "firmware watchdog fired",
        };
        match (self, self.err()) {
            (_, Some(err)) => {
                let event = Event::of(err).map_or("unrecognized", Event::name);
                write!(f, "{what} (err status {err:#x}, {event})")
            }
            (Self::Firmware(Err(error)), None) => {
                write!(f, "{what} (err status unread: {error:?})")
            }
            _ => f.write_str(what),
        }
    }
}

/// When the last cold re-inits began, the minute's bound on them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Recoveries {
    began: Vec<u64>,
    total: u32,
}

impl Recoveries {
    /// A cold re-init at `now`, in microseconds: its number among the
    /// minute's, 1 to [`RECOVERIES`], or `None` once that many began within
    /// the minute before `now`.
    pub fn allow(&mut self, now: u64) -> Option<usize> {
        self.began
            .retain(|&began| now.saturating_sub(began) < WINDOW_US);
        if self.began.len() >= RECOVERIES {
            return None;
        }
        self.began.push(now);
        self.total += 1;
        Some(self.began.len())
    }

    /// Every cold re-init allowed so far.
    pub const fn total(&self) -> u32 {
        self.total
    }
}

/// The word `rtw89_fw_h2c_trigger_cpu_exception` sends for firmware with
/// `features`, `None` for firmware with neither crash trigger
/// (`-EOPNOTSUPP`).
pub const fn cpu_exception_type(features: Features) -> Option<u32> {
    if features.has(Feature::CrashTriggerType1) {
        Some(CPU_EXCEPTION_TYPE_1)
    } else if features.has(Feature::CrashTriggerType0) {
        Some(CPU_EXCEPTION_TYPE_0)
    } else {
        None
    }
}

/// Why [`trigger_cpu_exception`] sent nothing.
#[derive(Debug)]
pub enum TriggerError {
    /// The firmware has no crash trigger: before 0.29.29.0.
    Unsupported,
    H2c(h2c::Error),
}

/// `rtw89_fw_h2c_trigger_cpu_exception`: the firmware asked to crash, by
/// the word its features name, an `H2C_CAT_TEST` command without acks.
/// The halt C2H it raises is the caller's to take.
pub fn trigger_cpu_exception<I: Io + ?Sized>(
    io: &mut I,
    channel: &mut Channel<'_>,
    rings: &mut Rings,
    features: Features,
) -> Result<(), TriggerError> {
    let word = cpu_exception_type(features).ok_or(TriggerError::Unsupported)?;
    let payload = word.to_le_bytes();
    let function = Function {
        del_type: FWCMD_TYPE_H2C,
        cat: H2C_CAT_TEST,
        class: H2C_CL_FW_STATUS_TEST,
        func: H2C_FUNC_CPU_EXCEPTION,
    };
    let packet = channel.command_for(function, false, false, &payload);
    channel.send(io, rings, &packet).map_err(TriggerError::H2c)
}
