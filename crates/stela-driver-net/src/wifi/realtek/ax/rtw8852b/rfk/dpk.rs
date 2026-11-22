// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's digital predistortion calibration, `rtw8852b_dpk` and `_dpk`
//! with every helper `_dpk_cal_select` reaches from pinned
//! rtw89/rtw8852b_rfk.c, line by line: with the scheduler stopped and both
//! paths out of TX mode, the BB, the KIP results and each path's RF
//! registers are backed up and TSSI tracking paused on a path in TSSI
//! mode; then each path in turn has its KIP powered, its TX AGC set, its RF
//! set for the band, its RX DC offset calibrated, its gain found by the AGC
//! loop (`_dpk_agc`) and, unless the sync failed, its MDPD coefficients
//! learned and the result filled in, before DPD is switched on for the
//! paths that passed and everything is put back. The register reads rtw89
//! makes only for its log lines are made here too.
//!
//! The channel is the caller's; `Channel::number` is `chan->channel`, the
//! center channel. A one-shot whose report never comes is counted in
//! [`DpkInfo::oneshot_timeouts`] and the calibration goes on, as rtw89 logs
//! it and goes on. That the one-shots reported and the AGC loop ended is
//! all a return proves; nothing here judges the predistortion learned.
use super::{
    Band, Bandwidth, Channel, RF_PATH_NUM, Scheduler, State, kpath, paused, pmac::sign_extend32,
    poll, reg::*, rfk_backup_bb_reg, rfk_backup_rf_reg, rfk_restore_bb_reg, rfk_restore_rf_reg,
    run, rx_dck::set_rx_dck, table,
};
use crate::wifi::realtek::ax::{
    io::{Error, Io, Registers},
    mac,
    registers::{CHIP_CAV, MASKDWORD, RFREG_MASK},
};

/// `RTW8852B_DPK_RF_PATH`.
pub const DPK_RF_PATH: usize = 2;
/// `RTW89_DPK_BKUP_NUM`: the results kept per path.
pub const DPK_BKUP_NUM: usize = 2;
/// `RTW8852B_DPK_KIP_REG_NUM`.
const DPK_KIP_REG_NUM: usize = 3;
/// `DPK_TXAGC_LOWER`, `DPK_TXAGC_UPPER` and `DPK_TXAGC_INVAL`.
const DPK_TXAGC_LOWER: u8 = 0x2e;
const DPK_TXAGC_UPPER: u8 = 0x3f;
const DPK_TXAGC_INVAL: u8 = 0xff;
/// `RFREG_MASKRXBB` and `RFREG_MASKMODE`.
const RFREG_MASKRXBB: u32 = 0x003e0;
const RFREG_MASKMODE: u32 = 0xf0000;
/// `DPK_SYNC_TH_DC_I`, `DPK_SYNC_TH_DC_Q` and `DPK_SYNC_TH_CORR`.
const DPK_SYNC_TH_DC_I: u16 = 200;
const DPK_SYNC_TH_DC_Q: u16 = 200;
const DPK_SYNC_TH_CORR: u8 = 170;
/// The KIP results `_dpk_cal_select` backs up per path.
const KIP_REG: [u32; DPK_KIP_REG_NUM] = [0x813c, 0x8124, 0x8120];

/// `enum rtw8852b_dpk_id`, the one-shots RTL8852B's DPK runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum DpkId {
    LbkRxiqk = 0x06,
    Sync = 0x10,
    MdpkIdl = 0x11,
    GainLoss = 0x13,
    DpkRxagc = 0x15,
    KipPreset = 0x16,
    DpkTxagc = 0x19,
}

/// `enum dpk_agc_step`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgcStep {
    SyncDgain,
    GainAdj,
    GainLossIdx,
    GlGtCriterion,
    GlLtCriterion,
    SetTxGain,
}

/// `struct rtw89_dpk_bkup_para`, one kept result: `band` and `bw` hold
/// `enum rtw89_band` and `enum rtw89_bandwidth`. `mdpd_en`, which no
/// RTL8852B code sets, is left out.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DpkBkupPara {
    pub band: u8,
    pub bw: u8,
    pub ch: u8,
    pub path_ok: bool,
    pub txagc_dpk: u8,
    pub ther_dpk: u8,
    pub gs: u8,
    pub pwsf: u16,
}

/// `struct rtw89_dpk_info` past `dpk_gs`, which [`State::dpk_gs`] holds,
/// as far as RTL8852B's DPK reads or writes it; `cur_k_set`,
/// `max_dpk_txagc` and `dpk_order`, which it never touches, are left out.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DpkInfo {
    pub is_dpk_enable: bool,
    pub is_dpk_reload_en: bool,
    pub dc_i: [[u16; DPK_BKUP_NUM]; DPK_RF_PATH],
    pub dc_q: [[u16; DPK_BKUP_NUM]; DPK_RF_PATH],
    pub corr_val: [[u8; DPK_BKUP_NUM]; DPK_RF_PATH],
    pub corr_idx: [[u8; DPK_BKUP_NUM]; DPK_RF_PATH],
    pub cur_idx: [u8; DPK_RF_PATH],
    pub bp: [[DpkBkupPara; DPK_BKUP_NUM]; DPK_RF_PATH],
    /// Stela's, not rtw89's: the one-shot polls (0xbff8 reading 0x55 within
    /// 20 ms, the KIP report reading 0x8000 within 2 ms) that ran past their
    /// bound, which rtw89 only logs.
    pub oneshot_timeouts: u32,
}

/// What DPK reads besides the channel and its state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Inputs {
    /// `rtwdev->fem.epa_2g` and `epa_5g`: an external PA, for which rtw89
    /// skips DPK on that band and switches DPD off. rtw89 sets them only
    /// for an RTL8852A; an RTL8852B leaves both false.
    pub epa_2g: bool,
    pub epa_5g: bool,
    /// `rtwdev->hal.cv`, the chip's cut ([`CHIP_CAV`] and up).
    pub cv: u8,
}

/// `rtw8852b_dpk(rtwdev, RTW89_PHY_0, …)` on `channel`: `_dpk` with the
/// scheduler stopped and both paths out of TX mode, DPK enabled and its
/// reload off, between the coex notifications `BTC_WRFKT_DPK` start and
/// stop, no-ops here. Returns the scheduler's refusal, which rtw89 ignores.
pub fn dpk<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    state: &mut State,
    channel: Channel,
    inputs: Inputs,
) -> Result<Option<mac::Cause>, Error> {
    paused(io, scheduler, |io| {
        state.dpk.is_dpk_enable = true;
        state.dpk.is_dpk_reload_en = false;
        dpk_run(io, state, channel, inputs)
    })
}

/// `_dpk`: DPD forced off on both paths when the band has an external PA,
/// otherwise `_dpk_cal_select`.
fn dpk_run<I: Io + ?Sized>(
    io: &mut I,
    state: &mut State,
    channel: Channel,
    inputs: Inputs,
) -> Result<(), Error> {
    // _dpk_bypass_check
    let bypass = match channel.band {
        Band::Ghz2 => inputs.epa_2g,
        Band::Ghz5 => inputs.epa_5g,
    };
    if bypass {
        // _dpk_force_bypass
        for path in 0..DPK_RF_PATH as u8 {
            if kpath() & (1 << path) != 0 {
                dpk_onoff(io, &state.dpk, path, true)?;
            }
        }
        Ok(())
    } else {
        dpk_cal_select(io, state, channel, inputs)
    }
}

/// `_dpk_one_shot`: the one-shot started, 0xbff8 polled for 0x55 every 1
/// us for 20 ms, the KIP report selected and polled for 0x8000 every 1 us
/// for 2 ms.
fn dpk_one_shot<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    id: DpkId,
) -> Result<(), Error> {
    let dpk_cmd = ((id as u16) << 8) | (0x19 + (u16::from(path) << 4));
    io.phy_write32_mask(R_NCTL_CFG, MASKDWORD, dpk_cmd.into())?;

    if !poll(io, 1, 20000, |io| {
        Ok(io.phy_read32_mask(0xbff8, MASKBYTE0)? == 0x55)
    })? {
        dpk.oneshot_timeouts += 1;
    }

    io.delay_us(1);

    io.phy_write32_mask(R_KIP_RPT1, MASKDWORD, 0x00030000)?;

    if !poll(io, 1, 2000, |io| {
        Ok(io.phy_read32_mask(0x80fc, MASKLWORD)? == 0x8000)
    })? {
        dpk.oneshot_timeouts += 1;
    }

    io.phy_write32_mask(R_NCTL_N1, MASKBYTE0, 0x0)
}

/// `_dpk_order_convert`.
fn dpk_order_convert<I: Io + ?Sized>(io: &mut I) -> Result<u32, Error> {
    let order = io.phy_read32_mask(R_LDL_NORM, B_LDL_NORM_OP)?;
    Ok(0x3 >> order)
}

/// `_dpk_onoff`: DPD of `path`'s current result on when DPK is enabled,
/// `off` is not asked and the result passed.
fn dpk_onoff<I: Io + ?Sized>(io: &mut I, dpk: &DpkInfo, path: u8, off: bool) -> Result<(), Error> {
    let p = usize::from(path);
    let kidx = dpk.cur_idx[p];
    let val = dpk.is_dpk_enable && !off && dpk.bp[p][usize::from(kidx)].path_ok;
    let order = dpk_order_convert(io)?;

    io.phy_write32_mask(
        R_DPD_CH0A + (u32::from(path) << 8) + (u32::from(kidx) << 2),
        MASKBYTE3,
        order << 1 | u32::from(val),
    )
}

/// `_dpk_rx_dck`.
fn dpk_rx_dck<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<(), Error> {
    io.write_rf(path, RR_RXBB2, RR_EN_TIA_IDA, 0x3)?;
    set_rx_dck(io, path)
}

/// `_dpk_information`: the channel the current result of `path` is for.
fn dpk_information(dpk: &mut DpkInfo, path: u8, channel: Channel) {
    let p = usize::from(path);
    let kidx = usize::from(dpk.cur_idx[p]);
    let bp = &mut dpk.bp[p][kidx];
    bp.band = channel.band as u8;
    bp.ch = channel.number;
    bp.bw = channel.width as u8;
}

/// `_dpk_bb_afe_setting`.
fn dpk_bb_afe_setting<I: Io + ?Sized>(io: &mut I, channel: Channel) -> Result<(), Error> {
    run(io, table::DPK_AFE)?;

    if channel.width == Bandwidth::Mhz80 {
        io.phy_write32_mask(R_P0_CFCH_BW1, B_P0_CFCH_EX, 0x1)?;
        io.phy_write32_mask(R_PATH1_BW_SEL_V1, B_PATH1_BW_SEL_EX, 0x1)?;
    }
    Ok(())
}

/// `_dpk_bb_afe_restore`.
fn dpk_bb_afe_restore<I: Io + ?Sized>(io: &mut I, channel: Channel) -> Result<(), Error> {
    run(io, table::DPK_AFE_RESTORE)?;

    if channel.width == Bandwidth::Mhz80 {
        io.phy_write32_mask(R_P0_CFCH_BW1, B_P0_CFCH_EX, 0x0)?;
        io.phy_write32_mask(R_PATH1_BW_SEL_V1, B_PATH1_BW_SEL_EX, 0x0)?;
    }
    Ok(())
}

/// `_dpk_tssi_pause`.
fn dpk_tssi_pause<I: Io + ?Sized>(io: &mut I, path: u8, is_pause: bool) -> Result<(), Error> {
    io.phy_write32_mask(
        R_P0_TSSI_TRK + (u32::from(path) << 13),
        B_P0_TSSI_TRK_EN,
        is_pause.into(),
    )
}

/// `_dpk_kip_restore`.
fn dpk_kip_restore<I: Io + ?Sized>(io: &mut I, path: u8, cv: u8) -> Result<(), Error> {
    run(io, table::DPK_KIP)?;

    if cv > CHIP_CAV {
        io.phy_write32_mask(R_DPD_COM + (u32::from(path) << 8), B_DPD_COM_OF, 0x1)?;
    }
    Ok(())
}

/// `_dpk_lbk_rxiqk`: the loopback RX IQK an 80 MHz channel's AGC runs.
fn dpk_lbk_rxiqk<I: Io + ?Sized>(io: &mut I, dpk: &mut DpkInfo, path: u8) -> Result<(), Error> {
    let offset = u32::from(path) << 8;
    let cur_rxbb = io.read_rf(path, RR_MOD, RFREG_MASKRXBB)? as u8;

    io.phy_write32_mask(R_MDPK_RX_DCK, B_MDPK_RX_DCK_EN, 0x1)?;
    io.phy_write32_mask(R_IQK_RES + offset, B_IQK_RES_RXCFIR, 0x0)?;

    let tmp = io.read_rf(path, RR_CFGCH, RFREG_MASK)?;
    io.write_rf(path, RR_RSV4, RFREG_MASK, tmp)?;
    io.write_rf(path, RR_MOD, RFREG_MASKMODE, 0xd)?;
    io.write_rf(path, RR_RXK, RR_RXK_PLLEN, 0x1)?;

    let att1 = if cur_rxbb >= 0x11 {
        0x13
    } else if cur_rxbb <= 0xa {
        0x00
    } else {
        0x05
    };
    io.write_rf(path, RR_TXIQK, RR_TXIQK_ATT1, att1)?;

    io.write_rf(path, RR_XGLNA2, RR_XGLNA2_SW, 0x0)?;
    io.write_rf(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0)?;
    io.write_rf(path, RR_RXKPLL, RFREG_MASK, 0x80014)?;
    io.delay_us(70);

    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
    io.phy_write32_mask(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x025)?;

    dpk_one_shot(io, dpk, path, DpkId::LbkRxiqk)?;

    // "[DPK] S%d LBK RXIQC = 0x%x"
    io.phy_read32_mask(R_RXIQC, MASKDWORD)?;

    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x0)?;
    io.write_rf(path, RR_RXK, RR_RXK_PLLEN, 0x0)?;
    io.phy_write32_mask(R_MDPK_RX_DCK, B_MDPK_RX_DCK_EN, 0x0)?;
    io.phy_write32_mask(R_KPATH_CFG, B_KPATH_CFG_ED, 0x0)?;
    io.phy_write32_mask(R_LOAD_COEF + offset, B_LOAD_COEF_DI, 0x1)?;
    io.write_rf(path, RR_MOD, RFREG_MASKMODE, 0x5)
}

/// `_dpk_get_thermal`.
fn dpk_get_thermal<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    kidx: u8,
    path: u8,
) -> Result<(), Error> {
    io.write_rf(path, RR_TM, RR_TM_TRI, 0x1)?;
    io.write_rf(path, RR_TM, RR_TM_TRI, 0x0)?;
    io.write_rf(path, RR_TM, RR_TM_TRI, 0x1)?;

    io.delay_us(200);

    dpk.bp[usize::from(path)][usize::from(kidx)].ther_dpk =
        io.read_rf(path, RR_TM, RR_TM_VAL)? as u8;
    Ok(())
}

/// `_dpk_rf_setting`.
fn dpk_rf_setting<I: Io + ?Sized>(
    io: &mut I,
    dpk: &DpkInfo,
    path: u8,
    kidx: u8,
) -> Result<(), Error> {
    let bp = &dpk.bp[usize::from(path)][usize::from(kidx)];

    if bp.band == Band::Ghz2 as u8 {
        io.write_rf(path, RR_MOD, RFREG_MASK, 0x50220)?;
        io.write_rf(path, RR_RXBB, RR_RXBB_FATT, 0xf2)?;
        io.write_rf(path, RR_LUTDBG, RR_LUTDBG_TIA, 0x1)?;
        io.write_rf(path, RR_TIA, RR_TIA_N6, 0x1)?;
    } else {
        io.write_rf(path, RR_MOD, RFREG_MASK, 0x50220)?;
        io.write_rf(path, RR_RXA2, RR_RAA2_SWATT, 0x5)?;
        io.write_rf(path, RR_LUTDBG, RR_LUTDBG_TIA, 0x1)?;
        io.write_rf(path, RR_TIA, RR_TIA_N6, 0x1)?;
        io.write_rf(path, RR_RXA_LNA, RFREG_MASK, 0x920FC)?;
        io.write_rf(path, RR_XALNA2, RFREG_MASK, 0x002C0)?;
        io.write_rf(path, RR_IQGEN, RFREG_MASK, 0x38800)?;
    }

    io.write_rf(path, RR_RCKD, RR_RCKD_BW, 0x1)?;
    io.write_rf(path, RR_BTC, RR_BTC_TXBB, u32::from(bp.bw) + 1)?;
    io.write_rf(path, RR_BTC, RR_BTC_RXBB, 0x0)?;

    // "[DPK] ARF 0x0/0x11/0x1a = 0x%x/ 0x%x/ 0x%x"
    io.read_rf(path, RR_MOD, RFREG_MASK)?;
    io.read_rf(path, RR_TXIG, RFREG_MASK)?;
    io.read_rf(path, RR_BTC, RFREG_MASK)?;
    Ok(())
}

/// `_dpk_bypass_rxcfir`.
fn dpk_bypass_rxcfir<I: Io + ?Sized>(io: &mut I, path: u8, is_bypass: bool) -> Result<(), Error> {
    let register = R_RXIQC + (u32::from(path) << 8);
    if is_bypass {
        io.phy_write32_mask(register, B_RXIQC_BYPASS2, 0x1)?;
        io.phy_write32_mask(register, B_RXIQC_BYPASS, 0x1)?;
    } else {
        io.phy_write32_clr(register, B_RXIQC_BYPASS2)?;
        io.phy_write32_clr(register, B_RXIQC_BYPASS)?;
    }
    // "[DPK] Bypass RXIQC (0x8%d3c = 0x%x)" or "[DPK] restore 0x8%d3c = 0x%x"
    io.phy_read32_mask(register, MASKDWORD)?;
    Ok(())
}

/// `_dpk_tpg_sel`.
fn dpk_tpg_sel<I: Io + ?Sized>(io: &mut I, dpk: &DpkInfo, path: u8, kidx: u8) -> Result<(), Error> {
    let bw = dpk.bp[usize::from(path)][usize::from(kidx)].bw;
    if bw == Bandwidth::Mhz80 as u8 {
        io.phy_write32_clr(R_TPG_MOD, B_TPG_MOD_F)
    } else if bw == Bandwidth::Mhz40 as u8 {
        io.phy_write32_mask(R_TPG_MOD, B_TPG_MOD_F, 0x2)
    } else {
        io.phy_write32_mask(R_TPG_MOD, B_TPG_MOD_F, 0x1)
    }
}

/// `_dpk_table_select`.
fn dpk_table_select<I: Io + ?Sized>(io: &mut I, path: u8, kidx: u8, gain: u8) -> Result<(), Error> {
    let val = 0x80u8
        .wrapping_add(kidx.wrapping_mul(0x20))
        .wrapping_add(gain.wrapping_mul(0x10));
    io.phy_write32_mask(R_DPD_CH0 + (u32::from(path) << 8), MASKBYTE3, val.into())
}

/// `_dpk_sync_check`: whether the sync failed, its DC offset above 200 or
/// its correlation below 170, with the correlation and offsets kept.
fn dpk_sync_check<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    kidx: u8,
) -> Result<bool, Error> {
    let (p, k) = (usize::from(path), usize::from(kidx));
    io.phy_write32_clr(R_KIP_RPT1, B_KIP_RPT1_SEL)?;

    let corr_idx = io.phy_read32_mask(R_RPT_COM, B_PRT_COM_CORI)? as u8;
    let corr_val = io.phy_read32_mask(R_RPT_COM, B_PRT_COM_CORV)? as u8;

    dpk.corr_idx[p][k] = corr_idx;
    dpk.corr_val[p][k] = corr_val;

    io.phy_write32_mask(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x9)?;

    let dc_i = io.phy_read32_mask(R_RPT_COM, B_PRT_COM_DCI)? as u16;
    let dc_q = io.phy_read32_mask(R_RPT_COM, B_PRT_COM_DCQ)? as u16;

    let dc_i = sign_extend32(dc_i.into(), 11).unsigned_abs() as u16;
    let dc_q = sign_extend32(dc_q.into(), 11).unsigned_abs() as u16;

    dpk.dc_i[p][k] = dc_i;
    dpk.dc_q[p][k] = dc_q;

    Ok(dc_i > DPK_SYNC_TH_DC_I || dc_q > DPK_SYNC_TH_DC_Q || corr_val < DPK_SYNC_TH_CORR)
}

/// `_dpk_sync`.
fn dpk_sync<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    kidx: u8,
) -> Result<bool, Error> {
    dpk_one_shot(io, dpk, path, DpkId::Sync)?;
    dpk_sync_check(io, dpk, path, kidx)
}

/// `_dpk_dgain_read`.
fn dpk_dgain_read<I: Io + ?Sized>(io: &mut I) -> Result<u16, Error> {
    io.phy_write32_mask(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x0)?;
    Ok(io.phy_read32_mask(R_RPT_COM, B_PRT_COM_DCI)? as u16)
}

/// `_dpk_dgain_mapping`: the RX BB step for a digital gain.
fn dpk_dgain_mapping(dgain: u16) -> i8 {
    const BND: [u16; 15] = [
        0xbf1, 0xaa5, 0x97d, 0x875, 0x789, 0x6b7, 0x5fc, 0x556, 0x4c1, 0x43d, 0x3c7, 0x35e, 0x2ac,
        0x262, 0x220,
    ];
    if dgain >= BND[0] {
        return 0x6;
    }
    // Between bnd[i - 1] and bnd[i]: 0x6, 0x5, …, down to 0xf9.
    for (i, &bound) in BND.iter().enumerate().skip(1) {
        if dgain >= bound {
            return [6, 5, 4, 3, 2, 1, 0, -1, -2, -3, -4, -5, -6, -7][i - 1];
        }
    }
    -8
}

/// `_dpk_gainloss_read`.
fn dpk_gainloss_read<I: Io + ?Sized>(io: &mut I) -> Result<u8, Error> {
    io.phy_write32_mask(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x6)?;
    io.phy_write32_mask(R_DPK_CFG2, B_DPK_CFG2_ST, 0x1)?;

    Ok(io.phy_read32_mask(R_RPT_COM, B_PRT_COM_GL)? as u8)
}

/// `_dpk_gainloss`.
fn dpk_gainloss<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    kidx: u8,
) -> Result<(), Error> {
    dpk_table_select(io, path, kidx, 1)?;
    dpk_one_shot(io, dpk, path, DpkId::GainLoss)
}

/// `_dpk_kip_preset`.
fn dpk_kip_preset<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    kidx: u8,
) -> Result<(), Error> {
    dpk_tpg_sel(io, dpk, path, kidx)?;
    dpk_one_shot(io, dpk, path, DpkId::KipPreset)
}

/// `_dpk_kip_pwr_clk_on`.
fn dpk_kip_pwr_clk_on<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<(), Error> {
    io.phy_write32_mask(R_NCTL_RPT, MASKDWORD, 0x00000080)?;
    io.phy_write32_mask(R_KIP_SYSCFG, MASKDWORD, 0x807f030a)?;
    io.phy_write32_mask(R_CFIR_SYS + (u32::from(path) << 8), MASKDWORD, 0xce000a08)
}

/// `_dpk_kip_set_txagc`.
fn dpk_kip_set_txagc<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    txagc: u8,
) -> Result<(), Error> {
    io.write_rf(path, RR_TXAGC, RFREG_MASK, txagc.into())?;
    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
    dpk_one_shot(io, dpk, path, DpkId::DpkTxagc)?;
    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x0)
}

/// `_dpk_kip_set_rxagc`.
fn dpk_kip_set_rxagc<I: Io + ?Sized>(io: &mut I, dpk: &mut DpkInfo, path: u8) -> Result<(), Error> {
    let tmp = io.read_rf(path, RR_MOD, RFREG_MASK)?;
    io.phy_write32_mask(R_KIP_MOD, B_KIP_MOD, tmp)?;
    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x1)?;
    dpk_one_shot(io, dpk, path, DpkId::DpkRxagc)?;
    io.phy_write32_mask(R_P0_RFCTM, B_P0_RFCTM_EN, 0x0)?;
    io.phy_write32_mask(R_KIP_RPT1, B_KIP_RPT1_SEL_V1, 0x8)?;

    // "[DPK] set RXBB = 0x%x (RF0x0[9:5] = 0x%x)"
    io.phy_read32_mask(R_RPT_COM, B_PRT_COM_RXBB_V1)?;
    io.read_rf(path, RR_MOD, RFREG_MASKRXBB)?;
    Ok(())
}

/// `_dpk_set_offset`: the TX AGC moved down by `gain_offset`, within
/// 0x2e to 0x3f.
fn dpk_set_offset<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    gain_offset: i8,
) -> Result<u8, Error> {
    let txagc = io.read_rf(path, RR_TXAGC, RFREG_MASK)? as u8;
    let moved = i32::from(txagc) - i32::from(gain_offset);

    let txagc = if moved < DPK_TXAGC_LOWER.into() {
        DPK_TXAGC_LOWER
    } else if moved > DPK_TXAGC_UPPER.into() {
        DPK_TXAGC_UPPER
    } else {
        moved as u8
    };

    dpk_kip_set_txagc(io, dpk, path, txagc)?;
    Ok(txagc)
}

/// `_dpk_pas_read(rtwdev, true)`: whether the first PA sample's power is at
/// least 8/5 of the last's. rtw89 never asks for the dump it makes
/// otherwise.
fn dpk_pas_read<I: Io + ?Sized>(io: &mut I) -> Result<bool, Error> {
    io.phy_write32_mask(R_KIP_RPT1, MASKBYTE2, 0x06)?;
    io.phy_write32_mask(R_DPK_CFG2, B_DPK_CFG2_ST, 0x0)?;
    io.phy_write32_mask(R_DPK_CFG3, MASKBYTE2, 0x08)?;

    let sample = |io: &mut I, index: u32| -> Result<(u32, u32), Error> {
        io.phy_write32_mask(R_DPK_CFG3, MASKBYTE3, index)?;
        let i = io.phy_read32_mask(R_RPT_COM, MASKHWORD)?;
        let i = sign_extend32(i, 11).unsigned_abs();
        let q = io.phy_read32_mask(R_RPT_COM, MASKLWORD)?;
        let q = sign_extend32(q, 11).unsigned_abs();
        Ok((i, q))
    };
    let (val1_i, val1_q) = sample(io, 0x00)?;
    let (val2_i, val2_q) = sample(io, 0x1f)?;

    Ok(val1_i * val1_i + val1_q * val1_q >= (val2_i * val2_i + val2_q * val2_q) * 8 / 5)
}

/// `_dpk_agc`: the TX AGC the loop settles on, or [`DPK_TXAGC_INVAL`] when
/// the sync failed; at most six steps that count and 200 in all.
fn dpk_agc<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    kidx: u8,
    init_txagc: u8,
    loss_only: bool,
    channel: Channel,
) -> Result<u8, Error> {
    let mut step = AgcStep::SyncDgain;
    let mut tmp_txagc = init_txagc;
    let mut tmp_gl_idx: u8 = 0;
    let mut goout = false;
    let mut agc_cnt: u8 = 0;
    let mut limited_rxbb = false;
    let mut dgain: u16 = 0;
    let mut limit: i32 = 200;

    loop {
        match step {
            AgcStep::SyncDgain => {
                if dpk_sync(io, dpk, path, kidx)? {
                    tmp_txagc = DPK_TXAGC_INVAL;
                    goout = true;
                } else {
                    dgain = dpk_dgain_read(io)?;

                    step = if loss_only || limited_rxbb {
                        AgcStep::GainLossIdx
                    } else {
                        AgcStep::GainAdj
                    };
                }
            }
            AgcStep::GainAdj => {
                let rxbb = io.read_rf(path, RR_MOD, RFREG_MASKRXBB)? as u8;
                let offset = dpk_dgain_mapping(dgain);
                let adjusted = i32::from(rxbb) + i32::from(offset);

                let tmp_rxbb = if adjusted > 0x1f {
                    limited_rxbb = true;
                    0x1f
                } else if adjusted < 0 {
                    limited_rxbb = true;
                    0
                } else {
                    adjusted as u8
                };

                io.write_rf(path, RR_MOD, RFREG_MASKRXBB, tmp_rxbb.into())?;
                if offset != 0 || agc_cnt == 0 {
                    if channel.width != Bandwidth::Mhz80 {
                        dpk_bypass_rxcfir(io, path, true)?;
                    } else {
                        dpk_lbk_rxiqk(io, dpk, path)?;
                    }
                }
                step = if !(342..=1922).contains(&dgain) {
                    AgcStep::SyncDgain
                } else {
                    AgcStep::GainLossIdx
                };

                agc_cnt += 1;
            }
            AgcStep::GainLossIdx => {
                dpk_gainloss(io, dpk, path, kidx)?;
                tmp_gl_idx = dpk_gainloss_read(io)?;

                step = if (tmp_gl_idx == 0 && dpk_pas_read(io)?) || tmp_gl_idx >= 7 {
                    AgcStep::GlGtCriterion
                } else if tmp_gl_idx == 0 {
                    AgcStep::GlLtCriterion
                } else {
                    AgcStep::SetTxGain
                };
            }
            AgcStep::GlGtCriterion => {
                if tmp_txagc == 0x2e {
                    goout = true;
                } else {
                    tmp_txagc = dpk_set_offset(io, dpk, path, 0x3)?;
                }
                step = AgcStep::GainLossIdx;
                agc_cnt += 1;
            }
            AgcStep::GlLtCriterion => {
                if tmp_txagc == 0x3f {
                    goout = true;
                } else {
                    tmp_txagc = dpk_set_offset(io, dpk, path, -2)?;
                }
                step = AgcStep::GainLossIdx;
                agc_cnt += 1;
            }
            AgcStep::SetTxGain => {
                tmp_txagc = dpk_set_offset(io, dpk, path, tmp_gl_idx as i8)?;
                goout = true;
                agc_cnt += 1;
            }
        }

        // while (!goout && agc_cnt < 6 && limit-- > 0)
        if goout || agc_cnt >= 6 {
            break;
        }
        let before = limit;
        limit -= 1;
        if before <= 0 {
            break;
        }
    }

    Ok(tmp_txagc)
}

/// `_dpk_set_mdpd_para`.
fn dpk_set_mdpd_para<I: Io + ?Sized>(io: &mut I, order: u8) -> Result<(), Error> {
    match order {
        0 => {
            io.phy_write32_mask(R_LDL_NORM, B_LDL_NORM_OP, order.into())?;
            io.phy_write32_mask(R_LDL_NORM, B_LDL_NORM_PN, 0x3)?;
            io.phy_write32_mask(R_MDPK_SYNC, B_MDPK_SYNC_MAN, 0x1)
        }
        1 | 2 => {
            io.phy_write32_mask(R_LDL_NORM, B_LDL_NORM_OP, order.into())?;
            io.phy_write32_clr(R_LDL_NORM, B_LDL_NORM_PN)?;
            io.phy_write32_clr(R_MDPK_SYNC, B_MDPK_SYNC_MAN)
        }
        // "[DPK] Wrong MDPD order!!(0x%x)"
        _ => Ok(()),
    }
}

/// `_dpk_idl_mpa`.
fn dpk_idl_mpa<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    kidx: u8,
) -> Result<(), Error> {
    let bp = &dpk.bp[usize::from(path)][usize::from(kidx)];
    if bp.bw < Bandwidth::Mhz80 as u8 && bp.band == Band::Ghz5 as u8 {
        dpk_set_mdpd_para(io, 0x2)?;
    } else {
        dpk_set_mdpd_para(io, 0x0)?;
    }

    dpk_one_shot(io, dpk, path, DpkId::MdpkIdl)
}

/// `_dpk_fill_result(rtwdev, RTW89_PHY_0, …)`.
fn dpk_fill_result<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    dpk_gs: u8,
    path: u8,
    kidx: u8,
    gain: u8,
    txagc: u8,
) -> Result<(), Error> {
    const PWSF: u16 = 0x78;
    let offset = u32::from(path) << 8;
    let (gain, kidx_shift) = (u32::from(gain), u32::from(kidx));
    let bp = &mut dpk.bp[usize::from(path)][usize::from(kidx)];

    io.phy_write32_mask(R_COEF_SEL + offset, B_COEF_SEL_MDPD, kidx.into())?;

    bp.txagc_dpk = txagc;
    io.phy_write32_mask(
        R_TXAGC_RFK + offset,
        0x3F << ((gain << 3) + (kidx_shift << 4)),
        txagc.into(),
    )?;

    bp.pwsf = PWSF;
    io.phy_write32_mask(
        R_DPD_BND + offset + (kidx_shift << 2),
        0x1FF << (gain << 4),
        PWSF.into(),
    )?;

    io.phy_write32_mask(R_LOAD_COEF + offset, B_LOAD_COEF_MDPD, 0x1)?;
    io.phy_write32_mask(R_LOAD_COEF + offset, B_LOAD_COEF_MDPD, 0x0)?;

    bp.gs = dpk_gs;
    let dpd = R_DPD_CH0A + offset + (kidx_shift << 2);
    if dpk_gs == 0x7f {
        io.phy_write32_mask(dpd, MASKDWORD, 0x007f7f7f)?;
    } else {
        io.phy_write32_mask(dpd, MASKDWORD, 0x005b5b5b)?;
    }

    let order = dpk_order_convert(io)?;
    io.phy_write32_mask(dpd, B_DPD_ORDER_V1, order)?;
    io.phy_write32_mask(R_DPD_V1 + offset, MASKDWORD, 0x0)?;
    io.phy_write32_mask(R_MDPK_SYNC, B_MDPK_SYNC_SEL, 0x0)
}

/// `_dpk_reload_check`: whether a kept result of `path` is for `channel`'s
/// band and number, made current.
fn dpk_reload_check<I: Io + ?Sized>(
    io: &mut I,
    dpk: &mut DpkInfo,
    path: u8,
    channel: Channel,
) -> Result<bool, Error> {
    let p = usize::from(path);
    let mut is_reload = false;

    for idx in 0..DPK_BKUP_NUM {
        let bp = &dpk.bp[p][idx];
        if channel.band as u8 != bp.band || channel.number != bp.ch {
            continue;
        }

        io.phy_write32_mask(
            R_COEF_SEL + (u32::from(path) << 8),
            B_COEF_SEL_MDPD,
            idx as u32,
        )?;
        dpk.cur_idx[p] = idx as u8;
        is_reload = true;
    }

    Ok(is_reload)
}

/// `_dpk_main(rtwdev, RTW89_PHY_0, path, gain, …)`: whether `path` failed.
fn dpk_main<I: Io + ?Sized>(
    io: &mut I,
    state: &mut State,
    path: u8,
    gain: u8,
    channel: Channel,
) -> Result<bool, Error> {
    let dpk_gs = state.dpk_gs[0];
    let dpk = &mut state.dpk;
    let mut txagc = 0x38;
    let kidx = dpk.cur_idx[usize::from(path)];

    // _rfk_rf_direct_cntrl and _rfk_drf_direct_cntrl, not by BB
    io.write_rf(path, RR_RSV1, RR_RSV1_RST, 0x0)?;
    io.write_rf(path, RR_BBDC, RR_BBDC_SEL, 0x0)?;

    dpk_kip_pwr_clk_on(io, path)?;
    dpk_kip_set_txagc(io, dpk, path, txagc)?;
    dpk_rf_setting(io, dpk, path, kidx)?;
    dpk_rx_dck(io, path)?;

    dpk_kip_preset(io, dpk, path, kidx)?;
    dpk_kip_set_rxagc(io, dpk, path)?;
    dpk_table_select(io, path, kidx, gain)?;

    txagc = dpk_agc(io, dpk, path, kidx, txagc, false, channel)?;

    let is_fail = txagc == DPK_TXAGC_INVAL;
    if !is_fail {
        dpk_get_thermal(io, dpk, kidx, path)?;

        dpk_idl_mpa(io, dpk, path, kidx)?;

        io.write_rf(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX)?;

        dpk_fill_result(io, dpk, dpk_gs, path, kidx, gain, txagc)?;
    }

    dpk.bp[usize::from(path)][usize::from(kidx)].path_ok = !is_fail;

    Ok(is_fail)
}

/// `_dpk_cal_select(rtwdev, false, RTW89_PHY_0, RF_AB, …)`.
fn dpk_cal_select<I: Io + ?Sized>(
    io: &mut I,
    state: &mut State,
    channel: Channel,
    inputs: Inputs,
) -> Result<(), Error> {
    let mut kip_bkup = [[0u32; DPK_KIP_REG_NUM]; DPK_RF_PATH];
    let mut backup_rf_val = [[0u32; 11]; DPK_RF_PATH];

    if state.dpk.is_dpk_reload_en {
        for path in 0..DPK_RF_PATH as u8 {
            let p = usize::from(path);
            let reloaded = dpk_reload_check(io, &mut state.dpk, path, channel)?;
            if !reloaded && state.dpk.bp[p][0].ch != 0 {
                state.dpk.cur_idx[p] = u8::from(state.dpk.cur_idx[p] == 0);
            } else {
                dpk_onoff(io, &state.dpk, path, false)?;
            }
        }
    } else {
        state.dpk.cur_idx = [0; DPK_RF_PATH];
    }

    let backup_bb_val = rfk_backup_bb_reg(io)?;

    for path in 0..DPK_RF_PATH as u8 {
        let p = usize::from(path);
        // _dpk_bkup_kip
        for (value, register) in kip_bkup[p].iter_mut().zip(KIP_REG) {
            *value = io.phy_read32_mask(register + (u32::from(path) << 8), MASKDWORD)?;
        }
        backup_rf_val[p] = rfk_backup_rf_reg(io, path)?;
        dpk_information(&mut state.dpk, path, channel);
        if state.is_tssi_mode[p] {
            dpk_tssi_pause(io, path, true)?;
        }
    }

    dpk_bb_afe_setting(io, channel)?;

    for path in 0..DPK_RF_PATH as u8 {
        let is_fail = dpk_main(io, state, path, 1, channel)?;
        dpk_onoff(io, &state.dpk, path, is_fail)?;
    }

    dpk_bb_afe_restore(io, channel)?;
    rfk_restore_bb_reg(io, &backup_bb_val)?;

    for path in 0..DPK_RF_PATH as u8 {
        let p = usize::from(path);
        dpk_kip_restore(io, path, inputs.cv)?;
        // _dpk_reload_kip
        for (&value, register) in kip_bkup[p].iter().zip(KIP_REG) {
            io.phy_write32_mask(register + (u32::from(path) << 8), MASKDWORD, value)?;
        }
        rfk_restore_rf_reg(io, &backup_rf_val[p], path)?;
        if state.is_tssi_mode[p] {
            dpk_tssi_pause(io, path, false)?;
        }
    }
    Ok(())
}

const _: () = assert!(DPK_RF_PATH == RF_PATH_NUM as usize);
