// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! What is RTL8852B's own in pinned rtw89, beside the AX generation's shared
//! layers: its RF calibration tables ([`rfk`]) and the values its power
//! functions and chip info give [`super::power`].
use super::registers::SCOREBOARD;

pub mod rfk;

/// `RTL8852B_RFE_05_SPS_ANA`: what `rtw8852b_pwr_sps_ana` writes to
/// `R_AX_SPS_ANA_ON_CTRL2` on a board of RFE type 5.
pub const RTL8852B_RFE_05_SPS_ANA: u16 = 0x4a82;

/// `rtw8852b_chip_info.btc_sb`: each scoreboard entry's `cfg` register, 0
/// for an entry the chip leaves unset.
pub const BTC_SB_CFG: [u32; 2] = [SCOREBOARD, 0];
