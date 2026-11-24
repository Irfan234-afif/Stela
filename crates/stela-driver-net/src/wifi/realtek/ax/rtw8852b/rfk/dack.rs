// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's DAC calibration, `rtw8852b_dack` and `_dac_cal` with their
//! helpers from pinned rtw89/rtw8852b_rfk.c, line by line: the AFE init
//! table, the D-die RCK, the ADC DC calibration of both paths with its
//! results reloaded by hand, then each path's MSBK and DADCK with their
//! results backed up in [`DackInfo`]. The register reads rtw89 makes only
//! for its log lines (`_check_addc`'s averages, `_drck`'s last read) are made
//! here too; `_dack_dump` reads nothing. A timeout rtw89 notes in
//! `rtw89_dack_info` is noted there too and the calibration goes on. That
//! the calibration's polls were answered is all a return proves.
use super::{RF_PATH_A, RF_PATH_B, poll, reg::*, run, run_by_cond, table};
use crate::wifi::realtek::ax::{
    io::{Error, Io, Registers},
    registers::{MASKDWORD, PHYREG_SET, RFREG_MASK},
};

/// `RTW89_DACK_PATH_NR`.
pub const DACK_PATH_NR: usize = 2;
/// `RTW89_DACK_IDX_NR`.
pub const DACK_IDX_NR: usize = 2;
/// `RTW89_DACK_MSBK_NR`.
pub const DACK_MSBK_NR: usize = 16;
/// `ADDC_T_AVG`: the reads `_check_addc` averages.
const ADDC_T_AVG: u32 = 100;

/// `struct rtw89_dack_info`, each array by path, then I or Q.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DackInfo {
    pub dack_done: bool,
    pub msbk_d: [[[u8; DACK_MSBK_NR]; DACK_IDX_NR]; DACK_PATH_NR],
    pub dadck_d: [[u8; DACK_IDX_NR]; DACK_PATH_NR],
    pub addck_d: [[u16; DACK_IDX_NR]; DACK_PATH_NR],
    pub biask_d: [[u16; DACK_IDX_NR]; DACK_PATH_NR],
    pub dack_cnt: u32,
    pub addck_timeout: [bool; DACK_PATH_NR],
    pub dadck_timeout: [bool; DACK_PATH_NR],
    pub msbk_timeout: [bool; DACK_PATH_NR],
}

/// `rtw8852b_dack`: `_dac_cal(rtwdev, false)`, between the coex
/// notifications `BTC_WRFKT_DACK` start and stop, no-ops here.
pub fn dack<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    dac_cal(io, dack)
}

/// `_afe_init`.
fn afe_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    io.write32(PHYREG_SET, 0xf)?;

    run(io, table::AFE_INIT)
}

/// `_drck`.
fn drck<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    io.phy_write32_mask(R_DRCK_V1, B_DRCK_V1_KICK, 0x1)?;

    // "[DACK]DRCK timeout" is all rtw89 does when it times out.
    poll(io, 1, 10000, |io| {
        Ok(io.phy_read32_mask(R_DRCK_RS, B_DRCK_RS_DONE)? != 0)
    })?;

    io.phy_write32_mask(R_DRCK_V1, B_DRCK_V1_KICK, 0x0)?;
    io.phy_write32_mask(R_DRCK_FH, B_DRCK_LAT, 0x1)?;
    io.delay_us(1);
    io.phy_write32_mask(R_DRCK_FH, B_DRCK_LAT, 0x0)?;
    let rck_d = io.phy_read32_mask(R_DRCK_RS, B_DRCK_RS_LPS)?;
    io.phy_write32_mask(R_DRCK_V1, B_DRCK_V1_SEL, 0x0)?;
    io.phy_write32_mask(R_DRCK_V1, B_DRCK_V1_CV, rck_d)?;

    // "[DACK]0xc0cc = 0x%x"
    io.phy_read32_mask(R_DRCK_V1, MASKDWORD)?;
    Ok(())
}

/// `_addck_backup`.
fn addck_backup<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    io.phy_write32_mask(R_ADDCK0, B_ADDCK0, 0x0)?;
    dack.addck_d[0][0] = io.phy_read32_mask(R_ADDCKR0, B_ADDCKR0_A0)? as u16;
    dack.addck_d[0][1] = io.phy_read32_mask(R_ADDCKR0, B_ADDCKR0_A1)? as u16;

    io.phy_write32_mask(R_ADDCK1, B_ADDCK1, 0x0)?;
    dack.addck_d[1][0] = io.phy_read32_mask(R_ADDCKR1, B_ADDCKR1_A0)? as u16;
    dack.addck_d[1][1] = io.phy_read32_mask(R_ADDCKR1, B_ADDCKR1_A1)? as u16;
    Ok(())
}

/// `_addck_reload`.
fn addck_reload<I: Io + ?Sized>(io: &mut I, dack: &DackInfo) -> Result<(), Error> {
    let addck_d = dack.addck_d.map(|path| path.map(u32::from));
    // S0
    io.phy_write32_mask(R_ADDCK0D, B_ADDCK0D_VAL, addck_d[0][0])?;
    io.phy_write32_mask(R_ADDCK0, B_ADDCK0_VAL, addck_d[0][1] >> 6)?;
    io.phy_write32_mask(R_ADDCK0D, B_ADDCK0D_VAL2, addck_d[0][1] & 0x3f)?;
    io.phy_write32_mask(R_ADDCK0, B_ADDCK0_MAN, 0x3)?;

    // S1
    io.phy_write32_mask(R_ADDCK1D, B_ADDCK1D_VAL, addck_d[1][0])?;
    io.phy_write32_mask(R_ADDCK1, B_ADDCK0_VAL, addck_d[1][1] >> 6)?;
    io.phy_write32_mask(R_ADDCK1D, B_ADDCK1D_VAL2, addck_d[1][1] & 0x3f)?;
    io.phy_write32_mask(R_ADDCK1, B_ADDCK1_MAN, 0x3)?;
    Ok(())
}

/// `_dack_backup_s0`.
fn dack_backup_s0<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    io.phy_write32_mask(R_P0_NRBW, B_P0_NRBW_DBG, 0x1)?;

    for i in 0..DACK_MSBK_NR {
        io.phy_write32_mask(R_DCOF0, B_DCOF0_V, i as u32)?;
        dack.msbk_d[0][0][i] = io.phy_read32_mask(R_DACK_S0P2, B_DACK_S0M0)? as u8;
        io.phy_write32_mask(R_DCOF8, B_DCOF8_V, i as u32)?;
        dack.msbk_d[0][1][i] = io.phy_read32_mask(R_DACK_S0P3, B_DACK_S0M1)? as u8;
    }

    dack.biask_d[0][0] = io.phy_read32_mask(R_DACK_BIAS00, B_DACK_BIAS00)? as u16;
    dack.biask_d[0][1] = io.phy_read32_mask(R_DACK_BIAS01, B_DACK_BIAS01)? as u16;

    dack.dadck_d[0][0] = io.phy_read32_mask(R_DACK_DADCK00, B_DACK_DADCK00)? as u8;
    dack.dadck_d[0][1] = io.phy_read32_mask(R_DACK_DADCK01, B_DACK_DADCK01)? as u8;
    Ok(())
}

/// `_dack_backup_s1`.
fn dack_backup_s1<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    io.phy_write32_mask(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0x1)?;

    for i in 0..DACK_MSBK_NR {
        io.phy_write32_mask(R_DACK10, B_DACK10, i as u32)?;
        dack.msbk_d[1][0][i] = io.phy_read32_mask(R_DACK10S, B_DACK10S)? as u8;
        io.phy_write32_mask(R_DACK11, B_DACK11, i as u32)?;
        dack.msbk_d[1][1][i] = io.phy_read32_mask(R_DACK11S, B_DACK11S)? as u8;
    }

    dack.biask_d[1][0] = io.phy_read32_mask(R_DACK_BIAS10, B_DACK_BIAS10)? as u16;
    dack.biask_d[1][1] = io.phy_read32_mask(R_DACK_BIAS11, B_DACK_BIAS11)? as u16;

    dack.dadck_d[1][0] = io.phy_read32_mask(R_DACK_DADCK10, B_DACK_DADCK10)? as u8;
    dack.dadck_d[1][1] = io.phy_read32_mask(R_DACK_DADCK11, B_DACK_DADCK11)? as u8;
    Ok(())
}

/// `_check_addc`: the path's table, then the `ADDC_T_AVG` reads of
/// `R_DBG32_D` whose DC average rtw89 only logs.
fn check_addc<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<(), Error> {
    run_by_cond(
        io,
        path == RF_PATH_A,
        table::CHECK_ADDC_A,
        table::CHECK_ADDC_B,
    )?;

    for _ in 0..ADDC_T_AVG {
        io.phy_read32_mask(R_DBG32_D, MASKDWORD)?;
    }
    Ok(())
}

/// `_addck`.
fn addck<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    // S0
    io.phy_write32_mask(R_ADDCK0, B_ADDCK0_MAN, 0x0)?;
    io.phy_write32_mask(R_PATH1_SAMPL_DLY_T_V1, 0x30, 0x0)?;
    io.phy_write32_mask(R_P0_NRBW, B_P0_NRBW_DBG, 0x1)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_ADCCLK, 0x0)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_FLTRST, 0x0)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_FLTRST, 0x1)?;
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0xf)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_EN, 0x0)?;
    io.phy_write32_mask(R_PATH0_SAMPL_DLY_T_V1, 1 << 1, 0x1)?;
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0x3)?;

    check_addc(io, RF_PATH_A)?;

    io.phy_write32_mask(R_ADDCK0, B_ADDCK0_TRG, 0x1)?;
    io.phy_write32_mask(R_ADDCK0, B_ADDCK0_TRG, 0x0)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ADDCK0, B_ADDCK0, 0x1)?;

    if !poll(io, 1, 10000, |io| {
        Ok(io.phy_read32_mask(R_ADDCKR0, 1 << 0)? != 0)
    })? {
        dack.addck_timeout[0] = true;
    }
    check_addc(io, RF_PATH_A)?;

    io.phy_write32_mask(R_PATH0_SAMPL_DLY_T_V1, 1 << 1, 0x0)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_EN, 0x1)?;
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0xc)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_ADCCLK, 0x1)?;
    io.phy_write32_mask(R_P0_NRBW, B_P0_NRBW_DBG, 0x0)?;

    // S1
    io.phy_write32_mask(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0x1)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_ADCCLK, 0x0)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_FLTRST, 0x0)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_FLTRST, 0x1)?;
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0xf)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_EN, 0x0)?;
    io.phy_write32_mask(R_PATH1_SAMPL_DLY_T_V1, 1 << 1, 0x1)?;
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0x3)?;

    check_addc(io, RF_PATH_B)?;

    io.phy_write32_mask(R_ADDCK1, B_ADDCK1_TRG, 0x1)?;
    io.phy_write32_mask(R_ADDCK1, B_ADDCK1_TRG, 0x0)?;
    io.delay_us(1);
    io.phy_write32_mask(R_ADDCK1, B_ADDCK1, 0x1)?;

    if !poll(io, 1, 10000, |io| {
        Ok(io.phy_read32_mask(R_ADDCKR1, 1 << 0)? != 0)
    })? {
        dack.addck_timeout[1] = true;
    }
    check_addc(io, RF_PATH_B)?;

    io.phy_write32_mask(R_PATH1_SAMPL_DLY_T_V1, 1 << 1, 0x0)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_EN, 0x1)?;
    io.phy_write32_mask(R_ANAPAR_PW15, B_ANAPAR_PW15_H, 0xc)?;
    io.phy_write32_mask(R_ANAPAR, B_ANAPAR_ADCCLK, 0x1)?;
    io.phy_write32_mask(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0x0)?;
    Ok(())
}

/// `_check_dadc`.
fn check_dadc<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<(), Error> {
    run_by_cond(
        io,
        path == RF_PATH_A,
        table::CHECK_DADC_EN_A,
        table::CHECK_DADC_EN_B,
    )?;

    check_addc(io, path)?;

    run_by_cond(
        io,
        path == RF_PATH_A,
        table::CHECK_DADC_DIS_A,
        table::CHECK_DADC_DIS_B,
    )
}

/// `_dack_s0_check_done`: false as soon as one of the part's two done bits
/// reads clear.
fn dack_s0_check_done<I: Io + ?Sized>(io: &mut I, part1: bool) -> Result<bool, Error> {
    if part1 {
        if io.phy_read32_mask(R_DACK_S0P0, B_DACK_S0P0_OK)? == 0
            || io.phy_read32_mask(R_DACK_S0P1, B_DACK_S0P1_OK)? == 0
        {
            return Ok(false);
        }
    } else if io.phy_read32_mask(R_DACK_S0P2, B_DACK_S0P2_OK)? == 0
        || io.phy_read32_mask(R_DACK_S0P3, B_DACK_S0P3_OK)? == 0
    {
        return Ok(false);
    }

    Ok(true)
}

/// `_dack_s0`.
fn dack_s0<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    run(io, table::DACK_S0_1)?;

    if !poll(io, 1, 10000, |io| dack_s0_check_done(io, true))? {
        dack.msbk_timeout[0] = true;
    }

    run(io, table::DACK_S0_2)?;

    if !poll(io, 1, 10000, |io| dack_s0_check_done(io, false))? {
        dack.dadck_timeout[0] = true;
    }

    run(io, table::DACK_S0_3)?;

    dack_backup_s0(io, dack)?;
    io.phy_write32_mask(R_P0_NRBW, B_P0_NRBW_DBG, 0x0)
}

/// `_dack_s1_check_done`: false only when both of the part's done bits read
/// clear.
fn dack_s1_check_done<I: Io + ?Sized>(io: &mut I, part1: bool) -> Result<bool, Error> {
    if part1 {
        if io.phy_read32_mask(R_DACK_S1P0, B_DACK_S1P0_OK)? == 0
            && io.phy_read32_mask(R_DACK_S1P1, B_DACK_S1P1_OK)? == 0
        {
            return Ok(false);
        }
    } else if io.phy_read32_mask(R_DACK10S, B_DACK_S1P2_OK)? == 0
        && io.phy_read32_mask(R_DACK11S, B_DACK_S1P3_OK)? == 0
    {
        return Ok(false);
    }

    Ok(true)
}

/// `_dack_s1`.
fn dack_s1<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    run(io, table::DACK_S1_1)?;

    if !poll(io, 1, 10000, |io| dack_s1_check_done(io, true))? {
        dack.msbk_timeout[1] = true;
    }

    run(io, table::DACK_S1_2)?;

    if !poll(io, 1, 10000, |io| dack_s1_check_done(io, false))? {
        dack.dadck_timeout[1] = true;
    }

    run(io, table::DACK_S1_3)?;

    check_dadc(io, RF_PATH_B)?;
    dack_backup_s1(io, dack)?;
    io.phy_write32_mask(R_P1_DBGMOD, B_P1_DBGMOD_ON, 0x0)
}

/// `_dac_cal(rtwdev, false)`; `_dack_dump` only logs [`DackInfo`].
fn dac_cal<I: Io + ?Sized>(io: &mut I, dack: &mut DackInfo) -> Result<(), Error> {
    dack.dack_done = false;

    let rf0_0 = io.read_rf(RF_PATH_A, RR_MOD, RFREG_MASK)?;
    let rf1_0 = io.read_rf(RF_PATH_B, RR_MOD, RFREG_MASK)?;
    afe_init(io)?;
    drck(io)?;

    io.write_rf(RF_PATH_A, RR_RSV1, RR_RSV1_RST, 0x0)?;
    io.write_rf(RF_PATH_B, RR_RSV1, RR_RSV1_RST, 0x0)?;
    io.write_rf(RF_PATH_A, RR_MOD, RFREG_MASK, 0x337e1)?;
    io.write_rf(RF_PATH_B, RR_MOD, RFREG_MASK, 0x337e1)?;
    addck(io, dack)?;
    addck_backup(io, dack)?;
    addck_reload(io, dack)?;

    io.write_rf(RF_PATH_A, RR_MODOPT, RFREG_MASK, 0x0)?;
    io.write_rf(RF_PATH_B, RR_MODOPT, RFREG_MASK, 0x0)?;
    // _dack
    dack_s0(io, dack)?;
    dack_s1(io, dack)?;
    dack.dack_done = true;

    io.write_rf(RF_PATH_A, RR_MOD, RFREG_MASK, rf0_0)?;
    io.write_rf(RF_PATH_B, RR_MOD, RFREG_MASK, rf1_0)?;
    io.write_rf(RF_PATH_A, RR_RSV1, RR_RSV1_RST, 0x1)?;
    io.write_rf(RF_PATH_B, RR_RSV1, RR_RSV1_RST, 0x1)?;
    dack.dack_cnt = dack.dack_cnt.wrapping_add(1);
    Ok(())
}
