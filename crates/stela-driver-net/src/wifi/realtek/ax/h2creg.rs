// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The register mailbox to an RTL8852B's running firmware, as pinned rtw89
//! reaches it: `rtw89_fw_write_h2c_reg`, `rtw89_fw_read_c2h_reg` and
//! `rtw89_fw_msg_reg` (fw.c), over RTL8852B's `rtw8852b_h2c_regs`,
//! `rtw8852b_c2h_regs`, control registers and UDM1 counters (rtw8852b.c).
//! The H2C packets on CH12 ([`super::h2c`]) are another channel; this one
//! carries four words each way through MAC registers, and the first command
//! rtw89 sends on it is the phycap request ([`super::efuse::setup_phycap`]).
//!
//! An H2C waits, every 1000 us for up to 5000 us, for the firmware to have
//! cleared H2CREG_CTRL, writes the four words, counts itself in UDM1 and
//! triggers. A C2H waits, every 1 us for up to [`C2H_TIMEOUT`] us, for
//! C2HREG_CTRL to read nonzero, reads the four words, clears C2HREG_CTRL and
//! counts itself in UDM1. Polls are counted in steps
//! ([`Registers::poll32`]'s model), and each access is the one rtw89 makes,
//! in its order.
//!
//! What this leaves out, and why:
//! - USB's shorter C2H bound (`RTW89_C2H_TIMEOUT_USB`): the chip is reached
//!   over PCIe.
//! - `lockdep_assert_wiphy`, which makes no access.
//!
//! An exchange that returns proves only that the firmware cleared and set
//! the control registers in turn and left four words behind; what the words
//! mean is the caller's to check.
use super::{
    fwdl::Downloaded,
    io::{self, Io, Registers, field, prep},
    registers::*,
};

/// `RTW89_H2CREG_MAX` and `RTW89_C2HREG_MAX`.
pub const H2CREG_MAX: usize = 4;
pub const C2HREG_MAX: usize = 4;
/// `RTW89_H2CREG_HDR_LEN` and `RTW89_C2HREG_HDR_LEN`: the bytes a header
/// takes of the first word.
pub const H2CREG_HDR_LEN: u32 = 2;
pub const C2HREG_HDR_LEN: u32 = 2;
/// `RTW89_H2CREG_HDR_FUNC_MASK` and `RTW89_H2CREG_HDR_LEN_MASK`.
pub const H2CREG_HDR_FUNC_MASK: u32 = 0x0000_007f;
pub const H2CREG_HDR_LEN_MASK: u32 = 0x0000_0f00;
/// `RTW89_C2HREG_HDR_FUNC_MASK` and `RTW89_C2HREG_HDR_LEN_MASK`.
pub const C2HREG_HDR_FUNC_MASK: u32 = 0x0000_007f;
pub const C2HREG_HDR_LEN_MASK: u32 = 0x0000_0f00;
/// `RTW89_C2H_TIMEOUT`: the PCIe bound, in microseconds, of the C2H poll.
pub const C2H_TIMEOUT: u64 = 1_000_000;
const C2H_STEP_US: u64 = 1;
/// `read_poll_timeout(rtw89_read8, …, 1000, 5000, false, …)`: how long an
/// H2C waits for the firmware to have taken the previous one.
const H2C_STEP_US: u64 = 1000;
const H2C_BOUND_US: u64 = 5000;
/// `rtw8852b_h2c_regs` and `rtw8852b_c2h_regs`.
pub const H2C_REGS: [u32; H2CREG_MAX] = [H2CREG_DATA0, H2CREG_DATA1, H2CREG_DATA2, H2CREG_DATA3];
pub const C2H_REGS: [u32; C2HREG_MAX] = [C2HREG_DATA0, C2HREG_DATA1, C2HREG_DATA2, C2HREG_DATA3];
/// `rtw8852b_chip_info.h2c_counter_reg` and `.c2h_counter_reg`.
const H2C_COUNTER_REG: (u32, u32) = (UDM1 + 1, UDM1_HALMAC_H2C_DEQ_CNT_MASK >> 8);
const C2H_COUNTER_REG: (u32, u32) = (UDM1 + 1, UDM1_HALMAC_C2H_ENQ_CNT_MASK >> 8);

/// `struct rtw89_mac_h2c_info`: a function, its content length in bytes,
/// and the four words, whose first carries the header [`Mailbox::write_h2c`]
/// fills in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H2cReg {
    pub id: u8,
    pub content_len: u8,
    pub regs: [u32; H2CREG_MAX],
}

/// `struct rtw89_mac_c2h_info` as `rtw89_fw_read_c2h_reg` fills it: the
/// function and content length its header names, and the four words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2hReg {
    pub id: u8,
    /// `(LEN << 2) - RTW89_C2HREG_HDR_LEN`, kept in a byte as rtw89 keeps it.
    pub content_len: u8,
    pub regs: [u32; C2HREG_MAX],
}

/// The mailbox's state in `rtwdev->fw`: the H2C and C2H counters, written
/// to UDM1 after each exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mailbox {
    h2c_counter: u8,
    c2h_counter: u8,
}

impl Mailbox {
    /// Both counters as `__rtw89_fw_download` leaves them, at 0, once the
    /// firmware it downloaded runs.
    pub fn after_download(_downloaded: &Downloaded) -> Self {
        Self {
            h2c_counter: 0,
            c2h_counter: 0,
        }
    }

    /// `fw_info->h2c_counter`.
    pub fn h2c_counter(&self) -> u8 {
        self.h2c_counter
    }

    /// `fw_info->c2h_counter`.
    pub fn c2h_counter(&self) -> u8 {
        self.c2h_counter
    }

    /// `rtw89_fw_write_h2c_reg`: once H2CREG_CTRL reads 0, the four words with
    /// the function and the length in words (header included) in the first,
    /// the H2C counter, then the trigger. A firmware that never clears
    /// H2CREG_CTRL is [`io::Error::Timeout`] naming it with mask 0xff.
    pub fn write_h2c<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        info: &H2cReg,
    ) -> Result<(), io::Error> {
        let mut waited = 0;
        loop {
            if io.read8(H2CREG_CTRL)? == 0 {
                break;
            }
            if waited >= H2C_BOUND_US {
                return Err(io::Error::Timeout {
                    register: H2CREG_CTRL,
                    mask: 0xff,
                });
            }
            io.delay_us(H2C_STEP_US);
            waited += H2C_STEP_US;
        }
        // DIV_ROUND_UP(content_len + RTW89_H2CREG_HDR_LEN, sizeof(u32)), kept
        // in a byte.
        let len = (u32::from(info.content_len) + H2CREG_HDR_LEN).div_ceil(4) as u8;
        let mut regs = info.regs;
        regs[0] = (regs[0] & !H2CREG_HDR_FUNC_MASK) | prep(info.id.into(), H2CREG_HDR_FUNC_MASK);
        regs[0] = (regs[0] & !H2CREG_HDR_LEN_MASK) | prep(len.into(), H2CREG_HDR_LEN_MASK);
        for (register, value) in H2C_REGS.into_iter().zip(regs) {
            io.write32(register, value)?;
        }
        self.h2c_counter = self.h2c_counter.wrapping_add(1);
        io.write8_mask(H2C_COUNTER_REG.0, H2C_COUNTER_REG.1, self.h2c_counter)?;
        io.write8(H2CREG_CTRL, H2CREG_TRIGGER)
    }

    /// `rtw89_fw_read_c2h_reg` over PCIe: once C2HREG_CTRL reads nonzero, the
    /// four words, C2HREG_CTRL cleared, then the C2H counter. `timeout_us` is
    /// `info->timeout`: 0 for [`C2H_TIMEOUT`]. A firmware that never answers
    /// is [`io::Error::Timeout`] naming C2HREG_CTRL with mask 0xff.
    pub fn read_c2h<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        timeout_us: u64,
    ) -> Result<C2hReg, io::Error> {
        let bound = if timeout_us == 0 {
            C2H_TIMEOUT
        } else {
            timeout_us
        };
        let mut waited = 0;
        loop {
            if io.read8(C2HREG_CTRL)? != 0 {
                break;
            }
            if waited >= bound {
                return Err(io::Error::Timeout {
                    register: C2HREG_CTRL,
                    mask: 0xff,
                });
            }
            io.delay_us(C2H_STEP_US);
            waited += C2H_STEP_US;
        }
        let mut regs = [0; C2HREG_MAX];
        for (value, register) in regs.iter_mut().zip(C2H_REGS) {
            *value = io.read32(register)?;
        }
        io.write8(C2HREG_CTRL, 0)?;
        let id = field(regs[0], C2HREG_HDR_FUNC_MASK) as u8;
        let content_len =
            (field(regs[0], C2HREG_HDR_LEN_MASK) << 2).wrapping_sub(C2HREG_HDR_LEN) as u8;
        self.c2h_counter = self.c2h_counter.wrapping_add(1);
        io.write8_mask(C2H_COUNTER_REG.0, C2H_COUNTER_REG.1, self.c2h_counter)?;
        Ok(C2hReg {
            id,
            content_len,
            regs,
        })
    }

    /// `rtw89_fw_msg_reg` with both an H2C and a C2H: the H2C, then its
    /// answer, with the default C2H bound.
    pub fn exchange<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        info: &H2cReg,
    ) -> Result<C2hReg, io::Error> {
        self.write_h2c(io, info)?;
        self.read_c2h(io, 0)
    }
}

#[cfg(test)]
mod tests;
