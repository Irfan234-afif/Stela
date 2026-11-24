// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's IQ calibration, `rtw8852b_iqk` and `_iqk` with their helpers
//! from pinned rtw89/rtw8852b_rfk.c, line by line: with the scheduler
//! stopped and both paths out of TX mode, each path in turn has its BB and
//! RF registers backed up, the LO leakage calibrated (up to three times,
//! with a higher bias each time), then TX and RX IQ by group, or narrowband
//! when [`IqkInfo::is_nbiqk`] says so, before the results are restored and
//! the backups put back. The channel is the caller's: rtw89 reads it from
//! the channel context. The register reads rtw89 makes only for its log
//! lines are made here too. A one-shot whose NCTL report never comes counts
//! as failed, as in rtw89. That the one-shots reported is all a return
//! proves; nothing here judges the IQ the chip measured.
use super::{
    Channel, RF_AB, RF_PATH_NUM, Scheduler, State, kpath, paused, poll, reg::*, rfk_backup_bb_reg,
    rfk_backup_rf_reg, rfk_restore_bb_reg, rfk_restore_rf_reg,
};
use crate::wifi::realtek::ax::{
    io::{Error, Io, Registers, field},
    mac,
    registers::{MASKDWORD, RFREG_MASK},
};

/// `RTW8852B_IQK_VER`.
pub const IQK_VER: u8 = 0x2a;
/// `RTW8852B_IQK_SS`: the paths IQK calibrates.
pub const IQK_SS: usize = 2;
/// `RTW89_IQK_CHS_NR`: the channels whose results rtw89 keeps.
pub const IQK_CHS_NR: usize = 2;
/// `RTW8852B_RXK_GROUP_NR`.
const RXK_GROUP_NR: usize = 4;
/// `RTW89_BAND_2G` and `RTW89_BAND_5G`, as `iqk_band` holds them.
const BAND_2G: u8 = 0;
const BAND_5G: u8 = 1;
/// `RTW89_CHANNEL_WIDTH_80`, as `iqk_bw` holds it.
const CHANNEL_WIDTH_80: u8 = 2;

const A_IDXRXGAIN: [u32; RXK_GROUP_NR] = [0x190, 0x198, 0x350, 0x352];
const A_IDXATTC2: [u32; RXK_GROUP_NR] = [0x0f, 0x0f, 0x3f, 0x7f];
const A_IDXATTC1: [u32; RXK_GROUP_NR] = [0x3, 0x1, 0x0, 0x0];
const G_IDXRXGAIN: [u32; RXK_GROUP_NR] = [0x212, 0x21c, 0x350, 0x360];
const G_IDXATTC2: [u32; RXK_GROUP_NR] = [0x00, 0x00, 0x28, 0x5f];
const G_IDXATTC1: [u32; RXK_GROUP_NR] = [0x3, 0x3, 0x2, 0x1];
const A_POWER_RANGE: [u32; RXK_GROUP_NR] = [0x0, 0x0, 0x0, 0x0];
const A_TRACK_RANGE: [u32; RXK_GROUP_NR] = [0x3, 0x3, 0x6, 0x6];
const A_GAIN_BB: [u32; RXK_GROUP_NR] = [0x08, 0x0e, 0x06, 0x0e];
const A_ITQT: [u32; RXK_GROUP_NR] = [0x12, 0x12, 0x12, 0x1b];
const G_POWER_RANGE: [u32; RXK_GROUP_NR] = [0x0, 0x0, 0x0, 0x0];
const G_TRACK_RANGE: [u32; RXK_GROUP_NR] = [0x4, 0x4, 0x6, 0x6];
const G_GAIN_BB: [u32; RXK_GROUP_NR] = [0x08, 0x0e, 0x06, 0x0e];
const G_ITQT: [u32; RXK_GROUP_NR] = [0x09, 0x12, 0x1b, 0x24];

/// `rtw8852b_set_nondbcc_path01`: `{addr, mask, data}`.
const SET_NONDBCC_PATH01: [(u32, u32, u32); 32] = [
    (0x20fc, 0xffff0000, 0x0303),
    (0x5864, 0x18000000, 0x3),
    (0x7864, 0x18000000, 0x3),
    (0x12b8, 0x40000000, 0x1),
    (0x32b8, 0x40000000, 0x1),
    (0x030c, 0xff000000, 0x13),
    (0x032c, 0xffff0000, 0x0041),
    (0x12b8, 0x10000000, 0x1),
    (0x58c8, 0x01000000, 0x1),
    (0x78c8, 0x01000000, 0x1),
    (0x5864, 0xc0000000, 0x3),
    (0x7864, 0xc0000000, 0x3),
    (0x2008, 0x01ffffff, 0x1ffffff),
    (0x0c1c, 0x00000004, 0x1),
    (0x0700, 0x08000000, 0x1),
    (0x0c70, 0x000003ff, 0x3ff),
    (0x0c60, 0x00000003, 0x3),
    (0x0c6c, 0x00000001, 0x1),
    (0x58ac, 0x08000000, 0x1),
    (0x78ac, 0x08000000, 0x1),
    (0x0c3c, 0x00000200, 0x1),
    (0x2344, 0x80000000, 0x1),
    (0x4490, 0x80000000, 0x1),
    (0x12a0, 0x00007000, 0x7),
    (0x12a0, 0x00008000, 0x1),
    (0x12a0, 0x00070000, 0x3),
    (0x12a0, 0x00080000, 0x1),
    (0x32a0, 0x00070000, 0x3),
    (0x32a0, 0x00080000, 0x1),
    (0x0700, 0x01000000, 0x1),
    (0x0700, 0x06000000, 0x2),
    (0x20fc, 0xffff0000, 0x3333),
];

/// `rtw8852b_restore_nondbcc_path01`: `{addr, mask, data}`.
const RESTORE_NONDBCC_PATH01: [(u32, u32, u32); 18] = [
    (0x20fc, 0xffff0000, 0x0303),
    (0x12b8, 0x40000000, 0x0),
    (0x32b8, 0x40000000, 0x0),
    (0x5864, 0xc0000000, 0x0),
    (0x7864, 0xc0000000, 0x0),
    (0x2008, 0x01ffffff, 0x0000000),
    (0x0c1c, 0x00000004, 0x0),
    (0x0700, 0x08000000, 0x0),
    (0x0c70, 0x0000001f, 0x03),
    (0x0c70, 0x000003e0, 0x03),
    (0x12a0, 0x000ff000, 0x00),
    (0x32a0, 0x000ff000, 0x00),
    (0x0700, 0x07000000, 0x0),
    (0x20fc, 0xffff0000, 0x0000),
    (0x58c8, 0x01000000, 0x0),
    (0x78c8, 0x01000000, 0x0),
    (0x0c3c, 0x00000200, 0x0),
    (0x2344, 0x80000000, 0x0),
];

/// `struct rtw89_iqk_info`, as far as RTL8852B's IQK reads or writes it,
/// by channel table and path. `iqk_channel` and the FFT, SRAM, CFIR and XYM
/// enables, which `_iqk_init` only clears and nothing reads, are left out.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IqkInfo {
    pub lok_cor_fail: [[bool; IQK_SS]; IQK_CHS_NR],
    pub lok_fin_fail: [[bool; IQK_SS]; IQK_CHS_NR],
    pub iqk_tx_fail: [[bool; IQK_SS]; IQK_CHS_NR],
    pub iqk_rx_fail: [[bool; IQK_SS]; IQK_CHS_NR],
    pub iqk_fail_cnt: u32,
    pub is_iqk_init: bool,
    /// `enum rtw89_band` by path.
    pub iqk_band: [u8; IQK_SS],
    pub iqk_ch: [u8; IQK_SS],
    /// `enum rtw89_bandwidth` by path.
    pub iqk_bw: [u8; IQK_SS],
    pub iqk_times: u8,
    pub version: u8,
    pub nb_txcfir: [u32; IQK_SS],
    pub nb_rxcfir: [u32; IQK_SS],
    pub bp_txkresult: [u32; IQK_SS],
    pub bp_rxkresult: [u32; IQK_SS],
    pub bp_iqkenable: [u32; IQK_SS],
    pub is_wb_txiqk: [bool; IQK_SS],
    pub is_wb_rxiqk: [bool; IQK_SS],
    /// Narrowband IQK, which `_iqk_init` clears and nothing in rtw89 sets.
    pub is_nbiqk: bool,
    pub syn1to2: u32,
    pub iqk_mcc_ch: [[u8; IQK_SS]; IQK_CHS_NR],
    pub iqk_table_idx: [u8; IQK_SS],
    pub lok_idac: [[u32; IQK_SS]; IQK_CHS_NR],
    pub lok_vbuf: [[u32; IQK_SS]; IQK_CHS_NR],
}

/// `enum rtw8852b_iqk_type`, the one-shots RTL8852B's IQK runs; rtw89 never
/// asks for `ID_RXAGC` or the others.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ktype {
    FlokCoarse,
    FlokFine,
    Txk,
    Rxk,
    Nbtxk,
    Nbrxk,
    FlokVbuffer,
}

/// `rtw8852b_iqk(rtwdev, RTW89_PHY_0, …)` on `channel`: `_iqk_init` and
/// `_iqk` with the scheduler stopped and both paths out of TX mode, between
/// the coex notifications `BTC_WRFKT_IQK` start and stop, no-ops here. The
/// results go to `state.iqk`, under the MCC table `state.rfk_mcc` names.
/// Returns the scheduler's refusal, which rtw89 ignores.
pub fn iqk<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    state: &mut State,
    channel: Channel,
) -> Result<Option<mac::Cause>, Error> {
    paused(io, scheduler, |io| {
        iqk_init(io, &mut state.iqk)?;
        iqk_all(io, state, channel)
    })
}

/// `_iqk_check_cal`: whether the one-shot failed, as the NCTL report says
/// once 0xbff8 reads 0x55, or for want of one.
fn iqk_check_cal<I: Io + ?Sized>(io: &mut I) -> Result<bool, Error> {
    let mut fail = true;

    let done = poll(io, 1, 8200, |io| {
        Ok(io.phy_read32_mask(0xbff8, MASKBYTE0)? == 0x55)
    })?;

    io.delay_us(200);

    if done {
        fail = io.phy_read32_mask(R_NCTL_RPT, B_NCTL_RPT_FLG)? != 0;
    }
    io.phy_write32_mask(R_NCTL_N1, MASKBYTE0, 0x0)?;

    // "[IQK]S%x, 0x8008 = 0x%x"
    io.phy_read32_mask(R_NCTL_RPT, MASKDWORD)?;

    Ok(fail)
}

/// `_iqk_rxk_setting`.
fn iqk_rxk_setting<I: Io + ?Sized>(io: &mut I, iqk: &IqkInfo, path: u8) -> Result<(), Error> {
    match iqk.iqk_band[usize::from(path)] {
        BAND_2G => {
            io.write_rf(path, RR_MOD, RR_MOD_MASK, 0xc)?;
            io.write_rf(path, RR_RXK, RR_RXK_SEL2G, 0x1)?;
            let tmp = io.read_rf(path, RR_CFGCH, RFREG_MASK)?;
            io.write_rf(path, RR_RSV4, RFREG_MASK, tmp)?;
        }
        BAND_5G => {
            io.write_rf(path, RR_MOD, RR_MOD_MASK, 0xc)?;
            io.write_rf(path, RR_RXK, RR_RXK_SEL5G, 0x1)?;
            let tmp = io.read_rf(path, RR_CFGCH, RFREG_MASK)?;
            io.write_rf(path, RR_RSV4, RFREG_MASK, tmp)?;
        }
        _ => {}
    }
    Ok(())
}

/// `_iqk_one_shot`: whether it failed.
fn iqk_one_shot<I: Io + ?Sized>(
    io: &mut I,
    iqk: &IqkInfo,
    path: u8,
    ktype: Ktype,
) -> Result<bool, Error> {
    let path32 = u32::from(path);
    let bw = u32::from(iqk.iqk_bw[usize::from(path)]);
    let iqk_cmd = match ktype {
        Ktype::FlokCoarse => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
            0x108 | (1 << (4 + path32))
        }
        Ktype::FlokFine => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
            0x208 | (1 << (4 + path32))
        }
        Ktype::FlokVbuffer => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
            0x308 | (1 << (4 + path32))
        }
        Ktype::Txk => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x0)?;
            0x008 | (1 << (path32 + 4)) | (((0x8 + bw) & 0xf) << 8)
        }
        Ktype::Rxk => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
            0x008 | (1 << (path32 + 4)) | (((0xb + bw) & 0xf) << 8)
        }
        Ktype::Nbtxk => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x0)?;
            io.phy_write32_mask(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x011)?;
            0x408 | (1 << (4 + path32))
        }
        Ktype::Nbrxk => {
            io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
            io.phy_write32_mask(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x011)?;
            0x608 | (1 << (4 + path32))
        }
    };

    io.phy_write32_mask(R_NCTL_CFG, MASKDWORD, iqk_cmd + 1)?;
    io.delay_us(1);
    let fail = iqk_check_cal(io)?;
    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x0)?;

    Ok(fail)
}

/// The RX gain of group `gp`, by band, as `_rxk_group_sel` and
/// `_iqk_nbrxk` set it.
fn rx_gain<I: Io + ?Sized>(io: &mut I, iqk: &IqkInfo, path: u8, gp: usize) -> Result<(), Error> {
    match iqk.iqk_band[usize::from(path)] {
        BAND_2G => {
            io.write_rf(path, RR_MOD, RR_MOD_RGM, G_IDXRXGAIN[gp])?;
            io.write_rf(path, RR_RXBB, RR_RXBB_C2G, G_IDXATTC2[gp])?;
            io.write_rf(path, RR_RXBB, RR_RXBB_C1G, G_IDXATTC1[gp])?;
        }
        BAND_5G => {
            io.write_rf(path, RR_MOD, RR_MOD_RGM, A_IDXRXGAIN[gp])?;
            io.write_rf(path, RR_RXA2, RR_RXA2_HATT, A_IDXATTC2[gp])?;
            io.write_rf(path, RR_RXA2, RR_RXA2_CC2, A_IDXATTC1[gp])?;
        }
        _ => {}
    }
    Ok(())
}

/// `_rxk_group_sel`: whether any group failed.
fn rxk_group_sel<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo, path: u8) -> Result<bool, Error> {
    let p = usize::from(path);
    let lut = R_CFIR_LUT + (u32::from(path) << 8);
    let mut kfail = false;

    for gp in 0..RXK_GROUP_NR {
        rx_gain(io, iqk, path, gp)?;

        io.phy_write32_mask(lut, B_CFIR_LUT_SEL, 0x1)?;
        io.phy_write32_mask(lut, B_CFIR_LUT_SET, 0x0)?;
        io.phy_write32_mask(lut, B_CFIR_LUT_GP_V1, gp as u32)?;
        let fail = iqk_one_shot(io, iqk, path, Ktype::Rxk)?;
        io.phy_write32_mask(R_IQKINF, 1 << (16 + gp as u32 + p as u32 * 4), fail.into())?;
        kfail |= fail;
    }
    io.write_rf(path, RR_RXK, RR_RXK_SEL5G, 0x0)?;

    let res = R_IQK_RES + (u32::from(path) << 8);
    if kfail {
        iqk.nb_rxcfir[p] = 0x40000002;
        io.phy_write32_mask(res, B_IQK_RES_RXCFIR, 0x0)?;
        iqk.is_wb_rxiqk[p] = false;
    } else {
        iqk.nb_rxcfir[p] = 0x40000000;
        io.phy_write32_mask(res, B_IQK_RES_RXCFIR, 0x5)?;
        iqk.is_wb_rxiqk[p] = true;
    }

    Ok(kfail)
}

/// `_iqk_nbrxk`: whether group 3's narrowband RXK failed.
fn iqk_nbrxk<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo, path: u8) -> Result<bool, Error> {
    let p = usize::from(path);
    let lut = R_CFIR_LUT + (u32::from(path) << 8);
    const GP: usize = 0x3;
    let mut kfail = false;

    rx_gain(io, iqk, path, GP)?;

    io.phy_write32_mask(lut, B_CFIR_LUT_SEL, 0x1)?;
    io.phy_write32_mask(lut, B_CFIR_LUT_SET, 0x0)?;
    io.phy_write32_mask(lut, B_CFIR_LUT_GP_V1, GP as u32)?;
    io.write_rf(path, RR_RXKPLL, RFREG_MASK, 0x80013)?;
    io.delay_us(1);

    let fail = iqk_one_shot(io, iqk, path, Ktype::Nbrxk)?;
    io.phy_write32_mask(R_IQKINF, 1 << (16 + GP as u32 + p as u32 * 4), fail.into())?;
    kfail |= fail;
    io.write_rf(path, RR_RXK, RR_RXK_SEL5G, 0x0)?;

    iqk.nb_rxcfir[p] = if !kfail {
        io.phy_read32_mask(R_RXIQC + (u32::from(path) << 8), MASKDWORD)? | 0x2
    } else {
        0x40000002
    };

    Ok(kfail)
}

/// `_iqk_rxclk_setting`.
fn iqk_rxclk_setting<I: Io + ?Sized>(io: &mut I, iqk: &IqkInfo, path: u8) -> Result<(), Error> {
    let (val, adc) = if iqk.iqk_bw[usize::from(path)] == CHANNEL_WIDTH_80 {
        (0x2, 0x1)
    } else {
        (0x1, 0x0)
    };
    io.phy_write32_mask(R_P0_NRBW, B_P0_NRBW_DBG, 0x1)?;
    io.phy_write32_mask(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0x1)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x0f)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x03)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_15, 0xa001)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_15, 0xa041)?;
    io.phy_write32_mask(R_P0_RXCK, B_P0_RXCK_VAL, val)?;
    io.phy_write32_mask(R_P0_RXCK, B_P0_RXCK_ON, 0x1)?;
    io.phy_write32_mask(R_P1_RXCK, B_P1_RXCK_VAL, val)?;
    io.phy_write32_mask(R_P1_RXCK, B_P1_RXCK_ON, 0x1)?;
    io.phy_write32_mask(R_UPD_CLK_ADC, B_UPD_CLK_ADC_ON, 0x1)?;
    io.phy_write32_mask(R_UPD_CLK_ADC, B_UPD_CLK_ADC_VAL, adc)
}

/// The TX gain of group `gp`, by band, as `_txk_group_sel` and `_iqk_nbtxk`
/// set it.
fn tx_gain<I: Io + ?Sized>(io: &mut I, iqk: &IqkInfo, path: u8, gp: usize) -> Result<(), Error> {
    let iqp = R_KIP_IQP + (u32::from(path) << 8);
    match iqk.iqk_band[usize::from(path)] {
        BAND_2G => {
            io.write_rf(path, RR_TXIG, RR_TXIG_GR0, G_POWER_RANGE[gp])?;
            io.write_rf(path, RR_TXIG, RR_TXIG_GR1, G_TRACK_RANGE[gp])?;
            io.write_rf(path, RR_TXIG, RR_TXIG_TG, G_GAIN_BB[gp])?;
            io.phy_write32_mask(iqp, MASKDWORD, G_ITQT[gp])?;
        }
        BAND_5G => {
            io.write_rf(path, RR_TXIG, RR_TXIG_GR0, A_POWER_RANGE[gp])?;
            io.write_rf(path, RR_TXIG, RR_TXIG_GR1, A_TRACK_RANGE[gp])?;
            io.write_rf(path, RR_TXIG, RR_TXIG_TG, A_GAIN_BB[gp])?;
            io.phy_write32_mask(iqp, MASKDWORD, A_ITQT[gp])?;
        }
        _ => {}
    }
    Ok(())
}

/// `_txk_group_sel`: whether any group failed.
fn txk_group_sel<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo, path: u8) -> Result<bool, Error> {
    let p = usize::from(path);
    let lut = R_CFIR_LUT + (u32::from(path) << 8);
    let mut kfail = false;

    for gp in 0..RXK_GROUP_NR {
        tx_gain(io, iqk, path, gp)?;

        io.phy_write32_mask(lut, B_CFIR_LUT_SEL, 0x1)?;
        io.phy_write32_mask(lut, B_CFIR_LUT_SET, 0x1)?;
        io.phy_write32_mask(lut, B_CFIR_LUT_G2, 0x0)?;
        io.phy_write32_mask(lut, B_CFIR_LUT_GP, gp as u32)?;
        io.phy_write32_mask(R_NCTL_N1, B_NCTL_N1_CIP, 0x00)?;
        let fail = iqk_one_shot(io, iqk, path, Ktype::Txk)?;
        io.phy_write32_mask(R_IQKINF, 1 << (8 + gp as u32 + p as u32 * 4), fail.into())?;
        kfail |= fail;
    }

    let res = R_IQK_RES + (u32::from(path) << 8);
    if kfail {
        iqk.nb_txcfir[p] = 0x40000002;
        io.phy_write32_mask(res, B_IQK_RES_TXCFIR, 0x0)?;
        iqk.is_wb_txiqk[p] = false;
    } else {
        iqk.nb_txcfir[p] = 0x40000000;
        io.phy_write32_mask(res, B_IQK_RES_TXCFIR, 0x5)?;
        iqk.is_wb_txiqk[p] = true;
    }

    Ok(kfail)
}

/// `_iqk_nbtxk`: whether group 2's narrowband TXK failed.
fn iqk_nbtxk<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo, path: u8) -> Result<bool, Error> {
    let lut = R_CFIR_LUT + (u32::from(path) << 8);
    const GP: usize = 0x2;

    tx_gain(io, iqk, path, GP)?;

    io.phy_write32_mask(lut, B_CFIR_LUT_SEL, 0x1)?;
    io.phy_write32_mask(lut, B_CFIR_LUT_SET, 0x1)?;
    io.phy_write32_mask(lut, B_CFIR_LUT_G2, 0x0)?;
    io.phy_write32_mask(lut, B_CFIR_LUT_GP, GP as u32)?;
    io.phy_write32_mask(R_NCTL_N1, B_NCTL_N1_CIP, 0x00)?;
    let kfail = iqk_one_shot(io, iqk, path, Ktype::Nbtxk)?;

    iqk.nb_txcfir[usize::from(path)] = if !kfail {
        io.phy_read32_mask(R_TXIQC + (u32::from(path) << 8), MASKDWORD)? | 0x2
    } else {
        0x40000002
    };

    Ok(kfail)
}

/// `_lok_res_table`.
fn lok_res_table<I: Io + ?Sized>(
    io: &mut I,
    iqk: &IqkInfo,
    path: u8,
    ibias: u8,
) -> Result<(), Error> {
    io.write_rf(path, RR_LUTWE, RFREG_MASK, 0x2)?;
    if iqk.iqk_band[usize::from(path)] == BAND_2G {
        io.write_rf(path, RR_LUTWA, RFREG_MASK, 0x0)?;
    } else {
        io.write_rf(path, RR_LUTWA, RFREG_MASK, 0x1)?;
    }
    io.write_rf(path, RR_LUTWD0, RFREG_MASK, ibias.into())?;
    io.write_rf(path, RR_LUTWE, RFREG_MASK, 0x0)?;
    io.write_rf(path, RR_TXVBUF, RR_TXVBUF_DACEN, 0x1)?;

    // "[IQK]S%x, 0x7c = %x"
    io.read_rf(path, RR_TXVBUF, RFREG_MASK)?;
    Ok(())
}

/// `_lok_finetune_check`: whether the LO leakage's core or buffer codes sit
/// at their ends. The codes are kept under MCC table `ch`, which rtw89
/// never gives past [`IQK_CHS_NR`]; one past it keeps nothing.
fn lok_finetune_check<I: Io + ?Sized>(
    io: &mut I,
    iqk: &mut IqkInfo,
    ch: u8,
    path: u8,
) -> Result<bool, Error> {
    let p = usize::from(path);
    let tmp = io.read_rf(path, RR_TXMO, RFREG_MASK)?;
    let core_i = field(tmp, RR_TXMO_COI);
    let core_q = field(tmp, RR_TXMO_COQ);

    let is_fail1 = !(0x2..=0x1d).contains(&core_i) || !(0x2..=0x1d).contains(&core_q);

    if let Some(slot) = iqk.lok_idac.get_mut(usize::from(ch)) {
        slot[p] = tmp;
    }

    let tmp = io.read_rf(path, RR_LOKVB, RFREG_MASK)?;
    let vbuff_i = field(tmp, RR_LOKVB_COI);
    let vbuff_q = field(tmp, RR_LOKVB_COQ);

    let is_fail2 = !(0x2..=0x3d).contains(&vbuff_i) || !(0x2..=0x3d).contains(&vbuff_q);

    if let Some(slot) = iqk.lok_vbuf.get_mut(usize::from(ch)) {
        slot[p] = tmp;
    }

    Ok(is_fail1 | is_fail2)
}

/// `_iqk_lok`: whether the fine-tune check failed.
fn iqk_lok<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo, ch: u8, path: u8) -> Result<bool, Error> {
    let p = usize::from(path);
    let iqp = R_KIP_IQP + (u32::from(path) << 8);
    let band = iqk.iqk_band[p];
    let known = band == BAND_2G || band == BAND_5G;

    io.phy_write32_mask(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x021)?;

    match band {
        BAND_2G => {
            io.write_rf(path, RR_TXIG, RR_TXIG_GR0, 0x0)?;
            io.write_rf(path, RR_TXIG, RR_TXIG_GR1, 0x6)?;
        }
        BAND_5G => {
            io.write_rf(path, RR_TXIG, RR_TXIG_GR0, 0x0)?;
            io.write_rf(path, RR_TXIG, RR_TXIG_GR1, 0x4)?;
        }
        _ => {}
    }

    // Both bands' targets are the same from here on.
    if known {
        io.write_rf(path, RR_TXIG, RR_TXIG_TG, 0x0)?;
    }

    io.phy_write32_mask(iqp, MASKDWORD, 0x9)?;
    let tmp = iqk_one_shot(io, iqk, path, Ktype::FlokCoarse)?;
    iqk.lok_cor_fail[0][p] = tmp;

    if known {
        io.write_rf(path, RR_TXIG, RR_TXIG_TG, 0x12)?;
    }

    io.phy_write32_mask(iqp, MASKDWORD, 0x24)?;
    iqk_one_shot(io, iqk, path, Ktype::FlokVbuffer)?;

    if known {
        io.write_rf(path, RR_TXIG, RR_TXIG_TG, 0x0)?;
    }

    io.phy_write32_mask(iqp, MASKDWORD, 0x9)?;
    io.phy_write32_mask(R_IQK_DIF4, B_IQK_DIF4_TXT, 0x021)?;
    let tmp = iqk_one_shot(io, iqk, path, Ktype::FlokFine)?;
    iqk.lok_fin_fail[0][p] = tmp;

    if known {
        io.write_rf(path, RR_TXIG, RR_TXIG_TG, 0x12)?;
    }

    io.phy_write32_mask(iqp, MASKDWORD, 0x24)?;
    iqk_one_shot(io, iqk, path, Ktype::FlokVbuffer)?;

    lok_finetune_check(io, iqk, ch, path)
}

/// `_iqk_txk_setting`.
fn iqk_txk_setting<I: Io + ?Sized>(io: &mut I, iqk: &IqkInfo, path: u8) -> Result<(), Error> {
    match iqk.iqk_band[usize::from(path)] {
        BAND_2G => {
            io.write_rf(path, RR_XALNA2, RR_XALNA2_SW2, 0x00)?;
            io.write_rf(path, RR_TXG1, RR_TXG1_ATT2, 0x0)?;
            io.write_rf(path, RR_TXG1, RR_TXG1_ATT1, 0x0)?;
            io.write_rf(path, RR_TXG2, RR_TXG2_ATT0, 0x1)?;
            io.write_rf(path, RR_TXGA, RR_TXGA_LOK_EXT, 0x0)?;
            io.write_rf(path, RR_LUTWE, RR_LUTWE_LOK, 0x1)?;
            io.write_rf(path, RR_LUTWA, RR_LUTWA_M1, 0x00)?;
            io.write_rf(path, RR_MOD, RR_MOD_IQK, 0x403e)?;
            io.delay_us(1);
        }
        BAND_5G => {
            io.write_rf(path, RR_XGLNA2, RR_XGLNA2_SW, 0x00)?;
            io.write_rf(path, RR_BIASA, RR_BIASA_A, 0x1)?;
            io.write_rf(path, RR_TXGA, RR_TXGA_LOK_EXT, 0x0)?;
            io.write_rf(path, RR_LUTWE, RR_LUTWE_LOK, 0x1)?;
            io.write_rf(path, RR_LUTWA, RR_LUTWA_M1, 0x80)?;
            io.write_rf(path, RR_MOD, RR_MOD_IQK, 0x403e)?;
            io.delay_us(1);
        }
        _ => {}
    }
    Ok(())
}

/// `_iqk_txclk_setting`.
fn iqk_txclk_setting<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    io.phy_write32_mask(R_P0_NRBW, B_P0_NRBW_DBG, 0x1)?;
    io.phy_write32_mask(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0x1)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x1f)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x13)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_15, 0x0001)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_15, 0x0041)
}

/// `_iqk_info_iqk`.
fn iqk_info_iqk<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo, path: u8) -> Result<(), Error> {
    let p = usize::from(path);
    let shift = u32::from(path) * 4;

    let flag = iqk.lok_cor_fail[0][p];
    io.phy_write32_mask(R_IQKINF, B_IQKINF_FCOR << shift, flag.into())?;
    let flag = iqk.lok_fin_fail[0][p];
    io.phy_write32_mask(R_IQKINF, B_IQKINF_FFIN << shift, flag.into())?;
    let flag = iqk.iqk_tx_fail[0][p];
    io.phy_write32_mask(R_IQKINF, B_IQKINF_FTX << shift, flag.into())?;
    let flag = iqk.iqk_rx_fail[0][p];
    io.phy_write32_mask(R_IQKINF, B_IQKINF_F_RX << shift, flag.into())?;

    let offset = u32::from(path) << 8;
    iqk.bp_iqkenable[p] = io.phy_read32_mask(R_IQK_RES + offset, MASKDWORD)?;
    iqk.bp_txkresult[p] = io.phy_read32_mask(R_TXIQC + offset, MASKDWORD)?;
    iqk.bp_rxkresult[p] = io.phy_read32_mask(R_RXIQC + offset, MASKDWORD)?;

    io.phy_write32_mask(R_IQKINF2, B_IQKINF2_KCNT, iqk.iqk_times.into())?;

    if io.phy_read32_mask(R_IQKINF, B_IQKINF_FAIL << shift)? != 0 {
        iqk.iqk_fail_cnt = iqk.iqk_fail_cnt.wrapping_add(1);
    }
    io.phy_write32_mask(R_IQKINF2, B_IQKINF2_FCNT << shift, iqk.iqk_fail_cnt)
}

/// `_iqk_by_path`, which `_iqk_start_iqk` is.
fn iqk_by_path<I: Io + ?Sized>(
    io: &mut I,
    iqk: &mut IqkInfo,
    ch: u8,
    path: u8,
) -> Result<(), Error> {
    let p = usize::from(path);
    const TRY: usize = 3;
    let mut ibias: u8 = 0x1;

    iqk_txclk_setting(io)?;

    // LOK; "[IQK] LOK (%d) fail" is all rtw89 does when every try fails.
    for _ in 0..TRY {
        lok_res_table(io, iqk, path, ibias)?;
        ibias = ibias.wrapping_add(1);
        iqk_txk_setting(io, iqk, path)?;
        if !iqk_lok(io, iqk, ch, path)? {
            break;
        }
    }

    // TXK
    iqk.iqk_tx_fail[0][p] = if iqk.is_nbiqk {
        iqk_nbtxk(io, iqk, path)?
    } else {
        txk_group_sel(io, iqk, path)?
    };

    // RX
    iqk_rxclk_setting(io, iqk, path)?;
    iqk_rxk_setting(io, iqk, path)?;
    iqk.iqk_rx_fail[0][p] = if iqk.is_nbiqk {
        iqk_nbrxk(io, iqk, path)?
    } else {
        rxk_group_sel(io, iqk, path)?
    };

    iqk_info_iqk(io, iqk, path)
}

/// `_iqk_get_ch_info`.
fn iqk_get_ch_info<I: Io + ?Sized>(
    io: &mut I,
    iqk: &mut IqkInfo,
    idx: u8,
    path: u8,
    channel: Channel,
) -> Result<(), Error> {
    let p = usize::from(path);
    // "[IQK]S%x, 0x18= 0x%x, idx = %x"
    io.read_rf(path, RR_CFGCH, RFREG_MASK)?;
    let reg_35c = io.phy_read32_mask(R_CIRST, B_CIRST_SYN)?;

    iqk.iqk_band[p] = channel.band as u8;
    iqk.iqk_bw[p] = channel.width as u8;
    iqk.iqk_ch[p] = channel.number;
    if let Some(slot) = iqk.iqk_mcc_ch.get_mut(usize::from(idx)) {
        slot[p] = channel.number;
    }
    iqk.iqk_table_idx[p] = idx;

    iqk.syn1to2 = if reg_35c == 0x01 { 0x1 } else { 0x0 };

    let shift = u32::from(path) * 16;
    io.phy_write32_mask(R_IQKINF, B_IQKINF_VER, IQK_VER.into())?;
    // 2GHz/5GHz/6GHz = 0/1/2
    io.phy_write32_mask(R_IQKCH, B_IQKCH_BAND << shift, iqk.iqk_band[p].into())?;
    // 20/40/80 = 0/1/2
    io.phy_write32_mask(R_IQKCH, B_IQKCH_BW << shift, iqk.iqk_bw[p].into())?;
    io.phy_write32_mask(R_IQKCH, B_IQKCH_CH << shift, iqk.iqk_ch[p].into())
}

/// `_iqk_restore`.
fn iqk_restore<I: Io + ?Sized>(io: &mut I, iqk: &IqkInfo, path: u8) -> Result<(), Error> {
    let p = usize::from(path);
    let offset = u32::from(path) << 8;
    io.phy_write32_mask(R_TXIQC + offset, MASKDWORD, iqk.nb_txcfir[p])?;
    io.phy_write32_mask(R_RXIQC + offset, MASKDWORD, iqk.nb_rxcfir[p])?;
    io.phy_write32_mask(R_NCTL_CFG, MASKDWORD, 0x00000e19 + (u32::from(path) << 4))?;
    // "%s result =%x" is all rtw89 does with it.
    iqk_check_cal(io)?;

    io.phy_write32_mask(R_NCTL_N1, B_NCTL_N1_CIP, 0x00)?;
    io.phy_write32_mask(R_NCTL_RPT, MASKDWORD, 0x00000000)?;
    io.phy_write32_mask(R_KIP_SYSCFG, MASKDWORD, 0x80000000)?;
    io.phy_write32_mask(R_CFIR_SYS, B_IQK_RES_K, 0x0)?;
    io.phy_write32_mask(R_IQRSN, B_IQRSN_K1, 0x0)?;
    io.phy_write32_mask(R_IQRSN, B_IQRSN_K2, 0x0)?;
    io.write_rf(path, RR_LUTWE, RR_LUTWE_LOK, 0x0)?;
    io.write_rf(path, RR_LUTWE, RR_LUTWE_LOK, 0x0)?;
    io.write_rf(path, RR_MOD, RR_MOD_MASK, 0x3)?;
    io.write_rf(path, RR_RSV1, RR_RSV1_RST, 0x1)?;
    io.write_rf(path, RR_BBDC, RR_BBDC_SEL, 0x1)
}

/// `rtw89_phy_write32_mask` for each `{addr, mask, data}` of `defs`, as
/// `_iqk_macbb_setting` and `_iqk_afebb_restore` write their table when
/// `_kpath` gives both paths; with one path they write nothing.
fn write_defs<I: Io + ?Sized>(io: &mut I, defs: &[(u32, u32, u32)]) -> Result<(), Error> {
    if kpath() != RF_AB {
        return Ok(());
    }
    for &(address, mask, data) in defs {
        io.phy_write32_mask(address, mask, data)?;
    }
    Ok(())
}

/// `_iqk_preset`.
fn iqk_preset<I: Io + ?Sized>(io: &mut I, idx: u8, path: u8) -> Result<(), Error> {
    let offset = u32::from(path) << 8;
    io.phy_write32_mask(R_COEF_SEL + offset, B_COEF_SEL_IQC, idx.into())?;
    io.phy_write32_mask(R_CFIR_LUT + offset, B_CFIR_LUT_G3, idx.into())?;

    io.write_rf(path, RR_RSV1, RR_RSV1_RST, 0x0)?;
    io.write_rf(path, RR_BBDC, RR_BBDC_SEL, 0x0)?;
    io.phy_write32_mask(R_NCTL_RPT, MASKDWORD, 0x00000080)?;
    io.phy_write32_mask(R_KIP_SYSCFG, MASKDWORD, 0x81ff010a)?;

    // "[IQK](1)S%x, 0x8%x54 = 0x%x" and "0x8%x04 = 0x%x"
    io.phy_read32_mask(R_CFIR_LUT + offset, MASKDWORD)?;
    io.phy_read32_mask(R_COEF_SEL + offset, MASKDWORD)?;
    Ok(())
}

/// `_iqk_init`: `R_IQKINF` cleared, and `iqk` reset the first time.
fn iqk_init<I: Io + ?Sized>(io: &mut I, iqk: &mut IqkInfo) -> Result<(), Error> {
    io.phy_write32_mask(R_IQKINF, MASKDWORD, 0x0)?;
    if iqk.is_iqk_init {
        return Ok(());
    }

    iqk.is_iqk_init = true;
    iqk.is_nbiqk = false;
    iqk.iqk_times = 0x0;

    for idx in 0..IQK_CHS_NR {
        for path in 0..IQK_SS {
            iqk.lok_cor_fail[idx][path] = false;
            iqk.lok_fin_fail[idx][path] = false;
            iqk.iqk_tx_fail[idx][path] = false;
            iqk.iqk_rx_fail[idx][path] = false;
            iqk.iqk_mcc_ch[idx][path] = 0x0;
            iqk.iqk_table_idx[path] = 0x0;
        }
    }
    Ok(())
}

/// `_doiqk` on `path`, between the coex notifications `BTC_WRFKT_IQK`
/// one-shot start and stop, no-ops here.
fn doiqk<I: Io + ?Sized>(
    io: &mut I,
    state: &mut State,
    path: u8,
    channel: Channel,
) -> Result<(), Error> {
    let idx = state.rfk_mcc.table_idx;
    let iqk = &mut state.iqk;
    iqk.iqk_times = iqk.iqk_times.wrapping_add(1);
    iqk.version = IQK_VER;

    iqk_get_ch_info(io, iqk, idx, path, channel)?;

    let backup_bb_val = rfk_backup_bb_reg(io)?;
    let backup_rf_val = rfk_backup_rf_reg(io, path)?;
    write_defs(io, &SET_NONDBCC_PATH01)?;
    iqk_preset(io, idx, path)?;
    iqk_by_path(io, iqk, idx, path)?;
    iqk_restore(io, iqk, path)?;
    write_defs(io, &RESTORE_NONDBCC_PATH01)?;
    rfk_restore_bb_reg(io, &backup_bb_val)?;
    rfk_restore_rf_reg(io, &backup_rf_val, path)
}

/// `_iqk`: `_doiqk` on each path `_kpath` gives, A first.
fn iqk_all<I: Io + ?Sized>(io: &mut I, state: &mut State, channel: Channel) -> Result<(), Error> {
    for path in 0..RF_PATH_NUM {
        if kpath() & (1 << path) != 0 {
            doiqk(io, state, path, channel)?;
        }
    }
    Ok(())
}
