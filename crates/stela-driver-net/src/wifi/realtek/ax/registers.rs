// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The rtw89 register names the AX layers read and write, as pinned
//! rtw89/reg.h, mac.h, phy.h and core.h define them. MAC registers are
//! BAR2 offsets; BB and RF registers are named without `cr_base`, which
//! [`super::io`] adds.

/// `R_AX_SYS_CFG1` and its cut field, `B_AX_CHIP_VER_MASK`.
pub const SYS_CFG1: u32 = 0x00f0;
pub const CHIP_VER_MASK: u32 = 0x0000_f000;

/// `R_AX_WLAN_XTAL_SI_CTRL` and its fields.
pub const WLAN_XTAL_SI_CTRL: u32 = 0x0270;
pub const XTAL_SI_CMD_POLL: u32 = 1 << 31;
pub const XTAL_SI_MODE_MASK: u32 = 0x0300_0000;
pub const XTAL_SI_BITMASK_MASK: u32 = 0x00ff_0000;
pub const XTAL_SI_DATA_MASK: u32 = 0x0000_ff00;
pub const XTAL_SI_ADDR_MASK: u32 = 0x0000_00ff;
/// `XTAL_SI_NORMAL_WRITE` and `XTAL_SI_NORMAL_READ`.
pub const XTAL_SI_NORMAL_WRITE: u32 = 0;
pub const XTAL_SI_NORMAL_READ: u32 = 1;
/// `XTAL_SI_CV` and `XTAL_SI_ACV_MASK`: the analog cut.
pub const XTAL_SI_CV: u8 = 0x41;
pub const XTAL_SI_ACV_MASK: u8 = 0x0f;

/// `R_AX_CMAC_REG_START` to `R_AX_CMAC_REG_END`: the registers whose reads
/// `rtw89_pci_ops_read32_cmac` retries (`ACCESS_CMAC`).
pub const CMAC_REG_START: u32 = 0xc000;
pub const CMAC_REG_END: u32 = 0xffff;
/// `R_AX_CK_EN`, written `B_AX_CMAC_ALLCKEN` before each retry.
pub const CK_EN: u32 = 0xc004;
pub const CMAC_ALLCKEN: u32 = u32::MAX;
/// `MAC_REG_POOL_COUNT`.
pub const MAC_REG_POOL_COUNT: usize = 10;
/// `RTW89_R32_DEAD`: what a register block that is off reads as.
pub const R32_DEAD: u32 = 0xdead_beef;

/// `R_SWSI_DATA_V1` and its fields: an indirect RF write.
pub const SWSI_DATA_V1: u32 = 0x0370;
pub const SWSI_DATA_VAL_V1: u32 = 0x000f_ffff;
pub const SWSI_DATA_ADDR_V1: u32 = 0x0ff0_0000;
pub const SWSI_DATA_PATH_V1: u32 = 0x7000_0000;
pub const SWSI_DATA_BIT_MASK_EN_V1: u32 = 1 << 31;
/// `R_SWSI_BIT_MASK_V1`.
pub const SWSI_BIT_MASK_V1: u32 = 0x0374;
/// `R_SWSI_READ_ADDR_V1` and its fields: an indirect RF read.
pub const SWSI_READ_ADDR_V1: u32 = 0x0378;
pub const SWSI_READ_ADDR_ADDR_V1: u32 = 0x0000_00ff;
pub const SWSI_READ_ADDR_PATH_V1: u32 = 0x0000_0700;
pub const SWSI_READ_ADDR_MASK_V1: u32 = 0x0000_07ff;
/// `R_SWSI_V1` and its status bits.
pub const SWSI_V1: u32 = 0x174c;
pub const SWSI_W_BUSY_V1: u32 = 1 << 24;
pub const SWSI_R_BUSY_V1: u32 = 1 << 25;
pub const SWSI_R_DATA_DONE_V1: u32 = 1 << 26;

/// `RFREG_MASK`: an RF register's 20 bits.
pub const RFREG_MASK: u32 = 0x000f_ffff;
/// `MASKDWORD`.
pub const MASKDWORD: u32 = u32::MAX;
/// `RTW89_RF_ADDR_ADSEL_MASK`: an RF address with this bit set is reached
/// directly through the BB window, otherwise through SWSI.
pub const RF_ADDR_ADSEL: u32 = 1 << 16;
