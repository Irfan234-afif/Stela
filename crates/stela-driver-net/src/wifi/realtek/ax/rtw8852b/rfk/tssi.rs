// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's TX power control by TSSI, `rtw8852b_tssi`,
//! `rtw8852b_tssi_scan` and `rtw8852b_wifi_scan_notify` with every helper
//! they reach from pinned rtw89/rtw8852b_rfk.c, line by line: TSSI off,
//! each path's RF and system settings, its BB TX power tables, DCK, the
//! thermal meter table from the firmware's TX power tracking deltas, the
//! DAC gain and slope tables and the default alignment, then, with the
//! scheduler stopped, the alignment by PMAC packets on the channel
//! (`_tssi_alimentk`), before TSSI is turned on with the efuse's DE. The
//! register reads rtw89 makes only for its log lines are made here too.
//!
//! The channel is the caller's: `Channel::number` is `chan->channel`, the
//! center channel, as everywhere in rtw89's calibrations. That the
//! alignment's CW reports came, or that a report never came within 100
//! looks 30 us apart and the alignment was left undone, as in rtw89, is all
//! a return proves; nothing here measures TX power.
use super::super::channel::{self, CH_2G, CH_5G_BAND_1, CH_5G_BAND_3, CH_5G_BAND_4};
use super::{
    Band, Channel, RF_PATH_A, RF_PATH_NUM, Scheduler, State, paused,
    pmac::{self, RF_A, RF_ABCD, RF_B, RF_PATH_AB, RF_PATH_ABCD, sign_extend32},
    reg::*,
    run, run_by_cond, table,
};
use crate::wifi::realtek::ax::{
    efuse,
    elements::{DELTA_SWINGIDX_SIZE, TxpwrTrk},
    io::{Error, Io, Registers, prep},
    mac,
    registers::MASKDWORD,
};

/// `RTW8852B_TSSI_PATH_NR`.
pub const TSSI_PATH_NR: u8 = 2;
/// `TSSI_ALIMK_MAX`: the alignment bands, 2 GHz and 5 GHz low, mid and
/// high (`enum rtw89_tssi_alimk_band`).
pub const TSSI_ALIMK_MAX: usize = 4;
/// `TSSI_ALIMK_VALUE_NUM`: rtw89 keeps eight words per alignment and uses
/// four.
pub const TSSI_ALIMK_VALUE_NUM: usize = 8;
/// `TSSI_MAX_CH_NUM`: the channels `_tssi_ch_to_idx` numbers.
pub const TSSI_MAX_CH_NUM: usize = 67;
/// `TSSI_ALIMK_2G`, `TSSI_ALIMK_5GL`, `TSSI_ALIMK_5GM`, `TSSI_ALIMK_5GH`.
pub const TSSI_ALIMK_2G: usize = 0;
pub const TSSI_ALIMK_5GL: usize = 1;
pub const TSSI_ALIMK_5GM: usize = 2;
pub const TSSI_ALIMK_5GH: usize = 3;

/// `_TSSI_DE_MASK`.
const TSSI_DE_MASK: u32 = 0x003f_f000;
/// `_tssi_trigger`.
const TSSI_TRIGGER: [u32; TSSI_PATH_NR as usize] = [0x5820, 0x7820];
/// `_tssi_cw_rpt_addr`.
const TSSI_CW_RPT_ADDR: [u32; TSSI_PATH_NR as usize] = [0x1c18, 0x3c18];
/// `_tssi_cw_default_addr`.
const TSSI_CW_DEFAULT_ADDR: [[u32; 4]; TSSI_PATH_NR as usize] = [
    [0x5634, 0x5630, 0x5630, 0x5630],
    [0x7634, 0x7630, 0x7630, 0x7630],
];
/// `_tssi_cw_default_mask`.
const TSSI_CW_DEFAULT_MASK: [u32; 4] = [0x000003ff, 0x3ff00000, 0x000ffc00, 0x000003ff];
/// `_tssi_de_cck_long` and the other DE registers, by path.
const TSSI_DE_CCK_LONG: [u32; 2] = [0x5858, 0x7858];
const TSSI_DE_CCK_SHORT: [u32; 2] = [0x5860, 0x7860];
const TSSI_DE_MCS_20M: [u32; 2] = [0x5838, 0x7838];
const TSSI_DE_MCS_40M: [u32; 2] = [0x5840, 0x7840];
const TSSI_DE_MCS_80M: [u32; 2] = [0x5848, 0x7848];
const TSSI_DE_MCS_80M_80M: [u32; 2] = [0x5850, 0x7850];
const TSSI_DE_MCS_5M: [u32; 2] = [0x5828, 0x7828];
const TSSI_DE_MCS_10M: [u32; 2] = [0x5830, 0x7830];

/// `struct rtw89_tssi_info` past what the efuse gives
/// ([`efuse::Tssi`]): the alignments `_tssi_alimentk` found, by path and
/// band, and the copies it keeps by path and channel index. The extra
/// offsets, tracking checks, base thermal values and the alignment's time
/// account, which no RTL8852B calibration here reads, are left out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TssiInfo {
    pub check_backup_aligmk: [[bool; TSSI_MAX_CH_NUM]; RF_PATH_NUM as usize],
    pub alignment_backup_by_ch:
        [[[u32; TSSI_ALIMK_VALUE_NUM]; TSSI_MAX_CH_NUM]; RF_PATH_NUM as usize],
    pub alignment_value: [[[u32; TSSI_ALIMK_VALUE_NUM]; TSSI_ALIMK_MAX]; RF_PATH_NUM as usize],
    pub alignment_done: [[bool; TSSI_ALIMK_MAX]; RF_PATH_NUM as usize],
}

impl Default for TssiInfo {
    /// Zeroed, as `rtwdev` is allocated.
    fn default() -> Self {
        Self {
            check_backup_aligmk: [[false; TSSI_MAX_CH_NUM]; RF_PATH_NUM as usize],
            alignment_backup_by_ch: [[[0; TSSI_ALIMK_VALUE_NUM]; TSSI_MAX_CH_NUM];
                RF_PATH_NUM as usize],
            alignment_value: [[[0; TSSI_ALIMK_VALUE_NUM]; TSSI_ALIMK_MAX]; RF_PATH_NUM as usize],
            alignment_done: [[false; TSSI_ALIMK_MAX]; RF_PATH_NUM as usize],
        }
    }
}

/// `RTW89_FW_TXPWR_TRK_TYPE_*`: the TX power tracking types the thermal
/// meter table reads.
const TRK_5GB_N: usize = 4;
const TRK_5GB_P: usize = 5;
const TRK_5GA_N: usize = 6;
const TRK_5GA_P: usize = 7;
const TRK_2GB_N: usize = 8;
const TRK_2GB_P: usize = 9;
const TRK_2GA_N: usize = 10;
const TRK_2GA_P: usize = 11;

/// The rows of `rtwdev->fw.elm_info.txpwr_trk` that `_tssi_set_tmeter_tbl`
/// reads, copied out: per path, the thermal deltas up and down for 2 GHz
/// (index 0) and the three 5 GHz subbands (1 to 3).
///
/// rtw89 falls back to `rtw89_8852b_trk_cfg` without the element; an
/// RTL8852B's firmware must carry it
/// ([`RTL8852B_TXPWR_TRK_NEEDED`](crate::wifi::realtek::ax::elements::RTL8852B_TXPWR_TRK_NEEDED)),
/// so that fallback is not taken here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrkDeltas {
    pub up: [[[i8; DELTA_SWINGIDX_SIZE]; 4]; RF_PATH_NUM as usize],
    pub down: [[[i8; DELTA_SWINGIDX_SIZE]; 4]; RF_PATH_NUM as usize],
}

impl TrkDeltas {
    /// The rows of `trk`, or `None` when one of the 2 GHz or 5 GHz types
    /// is missing.
    pub fn from_elements(trk: &TxpwrTrk<'_>) -> Option<Self> {
        let row = |ty: usize, subband: usize| -> Option<[i8; DELTA_SWINGIDX_SIZE]> {
            let mut row = [0; DELTA_SWINGIDX_SIZE];
            for (index, delta) in row.iter_mut().enumerate() {
                *delta = trk.delta(ty, subband, index)?;
            }
            Some(row)
        };
        let mut deltas = Self {
            up: [[[0; DELTA_SWINGIDX_SIZE]; 4]; RF_PATH_NUM as usize],
            down: [[[0; DELTA_SWINGIDX_SIZE]; 4]; RF_PATH_NUM as usize],
        };
        for (path, (up_2g, down_2g, up_5g, down_5g)) in [
            (TRK_2GA_P, TRK_2GA_N, TRK_5GA_P, TRK_5GA_N),
            (TRK_2GB_P, TRK_2GB_N, TRK_5GB_P, TRK_5GB_N),
        ]
        .into_iter()
        .enumerate()
        {
            deltas.up[path][0] = row(up_2g, 0)?;
            deltas.down[path][0] = row(down_2g, 0)?;
            for subband in 0..3 {
                deltas.up[path][1 + subband] = row(up_5g, subband)?;
                deltas.down[path][1 + subband] = row(down_5g, subband)?;
            }
        }
        Some(deltas)
    }
}

/// What TSSI reads besides the channel and its state.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    /// `rtwdev->tssi`'s efuse part: thermal values, DE and trims.
    pub efuse: &'a efuse::Tssi,
    /// The firmware's TX power tracking deltas.
    pub deltas: &'a TrkDeltas,
    /// The RX gain offsets the alignment's RX path reads, as a channel
    /// switch takes them (`rtw8852bx_set_gain_offset`).
    pub gain: &'a channel::Inputs,
}

/// `chan->subband_type` of `channel` (`rtw89_get_subband_type` on its
/// center channel), up to 5 GHz.
pub fn subband(channel: Channel) -> u8 {
    match channel.band {
        Band::Ghz2 => CH_2G,
        Band::Ghz5 => match channel.number {
            100..=144 => CH_5G_BAND_3,
            149..=177 => CH_5G_BAND_4,
            _ => CH_5G_BAND_1,
        },
    }
}

/// The alignment band of `channel` as `_tssi_alimentk` and its kin pick
/// it, by channel number alone.
fn alimk_band(channel: u8) -> usize {
    match channel {
        1..=14 => TSSI_ALIMK_2G,
        36..=64 => TSSI_ALIMK_5GL,
        100..=144 => TSSI_ALIMK_5GM,
        149..=177 => TSSI_ALIMK_5GH,
        _ => TSSI_ALIMK_2G,
    }
}

/// `rtw8852b_tssi(rtwdev, RTW89_PHY_0, hwtx_en, …)` on `channel`, between
/// the coex notifications `BTC_WRFKT_IQK` one-shot start and stop, no-ops
/// here: both paths set up, each aligned with the scheduler stopped when
/// `hwtx_en`, then TSSI on with the efuse's DE. Returns the first of the
/// scheduler's refusals, which rtw89 ignores.
pub fn tssi<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    state: &mut State,
    channel: Channel,
    hwtx_en: bool,
    inputs: &Inputs<'_>,
) -> Result<Option<mac::Cause>, Error> {
    let mut refused = None;

    tssi_disable(io, state)?;

    for path in RF_PATH_A..RF_PATH_NUM {
        tssi_rf_setting(io, path, channel)?;
        tssi_set_sys(io, path, channel)?;
        // _tssi_ini_txpwr_ctrl_bb
        run_by_cond(
            io,
            path == RF_PATH_A,
            table::TSSI_INIT_TXPWR_A,
            table::TSSI_INIT_TXPWR_B,
        )?;
        // _tssi_ini_txpwr_ctrl_bb_he_tb
        run_by_cond(
            io,
            path == RF_PATH_A,
            table::TSSI_INIT_TXPWR_HE_TB_A,
            table::TSSI_INIT_TXPWR_HE_TB_B,
        )?;
        // _tssi_set_dck
        run_by_cond(io, path == RF_PATH_A, table::TSSI_DCK_A, table::TSSI_DCK_B)?;
        tssi_set_tmeter_tbl(io, path, channel, inputs)?;
        // _tssi_set_dac_gain_tbl
        run_by_cond(
            io,
            path == RF_PATH_A,
            table::TSSI_DAC_GAIN_A,
            table::TSSI_DAC_GAIN_B,
        )?;
        tssi_slope_cal_org(io, path, channel)?;
        tssi_alignment_default(io, path, true, channel)?;
        // _tssi_set_tssi_slope
        run_by_cond(
            io,
            path == RF_PATH_A,
            table::TSSI_SLOPE_A,
            table::TSSI_SLOPE_B,
        )?;

        // The stop, _tmac_tx_pause's wait for RX mode, the alignment and
        // the resume.
        let cause = paused(io, scheduler, |io| {
            if hwtx_en {
                tssi_alimentk(io, &mut state.tssi, path, channel, inputs)?;
            }
            Ok(())
        })?;
        refused = refused.or(cause);
    }

    tssi_enable(io, state)?;
    tssi_set_efuse_to_de(io, channel, inputs.efuse)?;
    Ok(refused)
}

/// `rtw8852b_tssi_scan(rtwdev, RTW89_PHY_0, chan)`, which
/// `rtw8852b_rfk_band_changed` runs: both paths set up for `channel`, each
/// with the alignment its band found before or the default one, then TSSI
/// on with the efuse's DE.
pub fn tssi_scan<I: Io + ?Sized>(
    io: &mut I,
    state: &mut State,
    channel: Channel,
    inputs: &Inputs<'_>,
) -> Result<(), Error> {
    let band = alimk_band(channel.number);

    tssi_disable(io, state)?;

    for path in RF_PATH_A..TSSI_PATH_NR {
        tssi_rf_setting(io, path, channel)?;
        tssi_set_sys(io, path, channel)?;
        tssi_set_tmeter_tbl(io, path, channel, inputs)?;

        if state.tssi.alignment_done[usize::from(path)][band] {
            tssi_alimentk_done(io, &state.tssi, path, channel)?;
        } else {
            tssi_alignment_default(io, path, true, channel)?;
        }
    }

    tssi_enable(io, state)?;
    tssi_set_efuse_to_de(io, channel, inputs.efuse)
}

/// `rtw8852b_wifi_scan_notify(rtwdev, scan_start, RTW89_PHY_0, …)`, which
/// is `rtw8852b_tssi_default_txagc`: a scan's start runs [`tssi`] when
/// neither path is in TSSI mode; its end resets both paths' TSSI offset
/// and puts back the alignments found for `channel`'s band. Returns the
/// scheduler's refusal, which rtw89 ignores.
pub fn wifi_scan_notify<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    state: &mut State,
    scan_start: bool,
    channel: Channel,
    inputs: &Inputs<'_>,
) -> Result<Option<mac::Cause>, Error> {
    if scan_start {
        if !state.is_tssi_mode[0] && !state.is_tssi_mode[1] {
            return tssi(io, scheduler, state, channel, true, inputs);
        }
        return Ok(None);
    }

    // "======>%s 1 SCAN_END Set 0x5818[7:0]=0x%x 0x7818[7:0]=0x%x"
    io.phy_read32_mask(R_P0_TSSI_TRK, B_P0_TSSI_OFT)?;
    io.phy_read32_mask(R_P1_TSSI_TRK, B_P1_TSSI_OFT)?;

    io.phy_write32_mask(R_P0_TSSI_TRK, B_P0_TSSI_OFT, 0xc0)?;
    io.phy_write32_mask(R_P1_TSSI_TRK, B_P1_TSSI_OFT, 0xc0)?;
    io.phy_write32_mask(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0x0)?;
    io.phy_write32_mask(R_P0_TSSI_TRK, B_P0_TSSI_OFT_EN, 0x1)?;
    io.phy_write32_mask(R_P1_TSSI_TRK, B_P1_TSSI_OFT_EN, 0x0)?;
    io.phy_write32_mask(R_P1_TSSI_TRK, B_P1_TSSI_OFT_EN, 0x1)?;

    tssi_alimentk_done(io, &state.tssi, RF_PATH_A, channel)?;
    tssi_alimentk_done(io, &state.tssi, super::RF_PATH_B, channel)?;

    // "======>%s 2 SCAN_END Set 0x5818[7:0]=0x%x 0x7818[7:0]=0x%x"
    io.phy_read32_mask(R_P0_TSSI_TRK, B_P0_TSSI_OFT)?;
    io.phy_read32_mask(R_P1_TSSI_TRK, B_P1_TSSI_OFT)?;
    Ok(None)
}

/// `_tssi_rf_setting`.
fn tssi_rf_setting<I: Io + ?Sized>(io: &mut I, path: u8, channel: Channel) -> Result<(), Error> {
    if channel.band == Band::Ghz2 {
        io.write_rf(path, RR_TXPOW, RR_TXPOW_TXG, 0x1)
    } else {
        io.write_rf(path, RR_TXPOW, RR_TXPOW_TXA, 0x1)
    }
}

/// `_tssi_set_sys`.
fn tssi_set_sys<I: Io + ?Sized>(io: &mut I, path: u8, channel: Channel) -> Result<(), Error> {
    run(io, table::TSSI_SYS)?;

    let g2 = channel.band == Band::Ghz2;
    if path == RF_PATH_A {
        run_by_cond(io, g2, table::TSSI_SYS_A_2G, table::TSSI_SYS_A_5G)
    } else {
        run_by_cond(io, g2, table::TSSI_SYS_B_2G, table::TSSI_SYS_B_5G)
    }
}

/// `_tssi_set_tmeter_tbl`: the thermal meter, and the 64 offsets around
/// the efuse's thermal value from the deltas of `channel`'s subband; no
/// offsets when the efuse has no thermal value (0xff).
fn tssi_set_tmeter_tbl<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    channel: Channel,
    inputs: &Inputs<'_>,
) -> Result<(), Error> {
    let row = match subband(channel) {
        CH_5G_BAND_1 => 1,
        CH_5G_BAND_3 => 2,
        CH_5G_BAND_4 => 3,
        _ => 0,
    };
    let p = usize::from(path);
    let thm_up = &inputs.deltas.up[p][row];
    let thm_down = &inputs.deltas.down[p][row];
    let thermal = inputs.efuse.thermal[p];

    let (tmeter, b_dis, b_trk, b_tmeter, rfctm, b_rfctm_val, rfctm_rdy, base) = if path == RF_PATH_A
    {
        (
            R_P0_TMETER,
            B_P0_TMETER_DIS,
            B_P0_TMETER_TRK,
            B_P0_TMETER,
            R_P0_RFCTM,
            B_P0_RFCTM_VAL,
            R_P0_RFCTM_RDY,
            R_P0_TSSI_BASE,
        )
    } else {
        (
            R_P1_TMETER,
            B_P1_TMETER_DIS,
            B_P1_TMETER_TRK,
            B_P1_TMETER,
            R_P1_RFCTM,
            B_P1_RFCTM_VAL,
            R_P1_RFCTM_RDY,
            R_TSSI_THOF,
        )
    };

    io.phy_write32_mask(tmeter, b_dis, 0x0)?;
    io.phy_write32_mask(tmeter, b_trk, 0x1)?;

    if thermal == 0xff {
        io.phy_write32_mask(tmeter, b_tmeter, 32)?;
        io.phy_write32_mask(rfctm, b_rfctm_val, 32)?;

        for i in (0..64).step_by(4) {
            phy_write32(io, base + i, 0x0)?;
        }
    } else {
        io.phy_write32_mask(tmeter, b_tmeter, thermal.into())?;
        io.phy_write32_mask(rfctm, b_rfctm_val, thermal.into())?;

        let mut thm_ofst = [0i8; 64];
        let mut i = 0;
        for slot in &mut thm_ofst[..32] {
            *slot = if i < DELTA_SWINGIDX_SIZE {
                i += 1;
                thm_down[i - 1].wrapping_neg()
            } else {
                thm_down[DELTA_SWINGIDX_SIZE - 1].wrapping_neg()
            };
        }

        let mut i = 1;
        for slot in thm_ofst[32..].iter_mut().rev() {
            *slot = if i < DELTA_SWINGIDX_SIZE {
                i += 1;
                thm_up[i - 1]
            } else {
                thm_up[DELTA_SWINGIDX_SIZE - 1]
            };
        }

        for (i, chunk) in (0u32..).step_by(4).zip(thm_ofst.chunks(4)) {
            // RTW8852B_TSSI_GET_VAL
            let tmp = chunk
                .iter()
                .enumerate()
                .fold(0u32, |value, (k, &v)| value | u32::from(v as u8) << (8 * k));
            phy_write32(io, base + i, tmp)?;
        }
    }
    io.phy_write32_mask(rfctm, rfctm_rdy, 0x1)?;
    io.phy_write32_mask(rfctm, rfctm_rdy, 0x0)
}

/// `rtw89_phy_write32`: the BB register written whole, without a read.
fn phy_write32<I: Io + ?Sized>(io: &mut I, register: u32, value: u32) -> Result<(), Error> {
    io.write32(crate::wifi::realtek::ax::io::CR_BASE + register, value)
}

/// `_tssi_slope_cal_org`.
fn tssi_slope_cal_org<I: Io + ?Sized>(io: &mut I, path: u8, channel: Channel) -> Result<(), Error> {
    let g2 = channel.band == Band::Ghz2;
    if path == RF_PATH_A {
        run_by_cond(io, g2, table::TSSI_SLOPE_A_2G, table::TSSI_SLOPE_A_5G)
    } else {
        run_by_cond(io, g2, table::TSSI_SLOPE_B_2G, table::TSSI_SLOPE_B_5G)
    }
}

/// `_tssi_alignment_default`: path A picks by band then channel, path B by
/// channel alone; a 5 GHz channel outside the ranges writes nothing.
fn tssi_alignment_default<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    all: bool,
    channel: Channel,
) -> Result<(), Error> {
    let ch = channel.number;
    let pick = |all_tbl, part_tbl| Some(if all { all_tbl } else { part_tbl });
    let tbl = if path == RF_PATH_A {
        if channel.band == Band::Ghz2 {
            pick(table::TSSI_ALIGN_A_2G_ALL, table::TSSI_ALIGN_A_2G_PART)
        } else {
            match ch {
                36..=64 => pick(table::TSSI_ALIGN_A_5G1_ALL, table::TSSI_ALIGN_A_5G1_PART),
                100..=144 => pick(table::TSSI_ALIGN_A_5G2_ALL, table::TSSI_ALIGN_A_5G2_PART),
                149..=177 => pick(table::TSSI_ALIGN_A_5G3_ALL, table::TSSI_ALIGN_A_5G3_PART),
                _ => None,
            }
        }
    } else {
        match ch {
            1..=14 => pick(table::TSSI_ALIGN_B_2G_ALL, table::TSSI_ALIGN_B_2G_PART),
            36..=64 => pick(table::TSSI_ALIGN_B_5G1_ALL, table::TSSI_ALIGN_B_5G1_PART),
            100..=144 => pick(table::TSSI_ALIGN_B_5G2_ALL, table::TSSI_ALIGN_B_5G2_PART),
            149..=177 => pick(table::TSSI_ALIGN_B_5G3_ALL, table::TSSI_ALIGN_B_5G3_PART),
            _ => None,
        }
    };

    match tbl {
        Some(tbl) => run(io, tbl),
        None => Ok(()),
    }
}

/// `_tssi_enable`: tracking on, the moving average and TSSI on, and both
/// paths in TSSI mode.
fn tssi_enable<I: Io + ?Sized>(io: &mut I, state: &mut State) -> Result<(), Error> {
    for i in 0..RF_PATH_NUM {
        // _tssi_set_tssi_track
        if i == RF_PATH_A {
            io.phy_write32_mask(R_P0_TSSIC, B_P0_TSSIC_BYPASS, 0x0)?;
        } else {
            io.phy_write32_mask(R_P1_TSSIC, B_P1_TSSIC_BYPASS, 0x0)?;
        }
        // _tssi_set_txagc_offset_mv_avg
        if i == RF_PATH_A {
            io.phy_write32_mask(R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_MIX, 0x010)?;
        } else {
            io.phy_write32_mask(R_P1_TSSI_MV_AVG, B_P1_RFCTM_DEL, 0x010)?;
        }

        let (mv_avg, mv_clr, avg, en, trk, rfc, oft, oft_en) = if i == RF_PATH_A {
            (
                R_P0_TSSI_MV_AVG,
                B_P0_TSSI_MV_CLR,
                R_P0_TSSI_AVG,
                B_P0_TSSI_EN,
                R_P0_TSSI_TRK,
                B_P0_TSSI_RFC,
                B_P0_TSSI_OFT,
                B_P0_TSSI_OFT_EN,
            )
        } else {
            (
                R_P1_TSSI_MV_AVG,
                B_P1_TSSI_MV_CLR,
                R_P1_TSSI_AVG,
                B_P1_TSSI_EN,
                R_P1_TSSI_TRK,
                B_P1_TSSI_RFC,
                B_P1_TSSI_OFT,
                B_P1_TSSI_OFT_EN,
            )
        };
        io.phy_write32_mask(mv_avg, mv_clr, 0x0)?;
        io.phy_write32_mask(avg, en, 0x0)?;
        io.phy_write32_mask(avg, en, 0x1)?;
        io.write_rf(i, RR_TXGA_V1, RR_TXGA_V1_TRK_EN, 0x1)?;
        io.phy_write32_mask(trk, rfc, 0x3)?;

        io.phy_write32_mask(trk, oft, 0xc0)?;
        io.phy_write32_mask(trk, oft_en, 0x0)?;
        io.phy_write32_mask(trk, oft_en, 0x1)?;

        state.is_tssi_mode[usize::from(i)] = true;
    }
    Ok(())
}

/// `_tssi_disable`: TSSI off on both paths, neither in TSSI mode.
fn tssi_disable<I: Io + ?Sized>(io: &mut I, state: &mut State) -> Result<(), Error> {
    io.phy_write32_mask(R_P0_TSSI_AVG, B_P0_TSSI_EN, 0x0)?;
    io.phy_write32_mask(R_P0_TSSI_TRK, B_P0_TSSI_RFC, 0x1)?;
    io.phy_write32_mask(R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_CLR, 0x1)?;
    io.phy_write32_mask(R_P1_TSSI_AVG, B_P1_TSSI_EN, 0x0)?;
    io.phy_write32_mask(R_P1_TSSI_TRK, B_P1_TSSI_RFC, 0x1)?;
    io.phy_write32_mask(R_P1_TSSI_MV_AVG, B_P1_TSSI_MV_CLR, 0x1)?;

    state.is_tssi_mode = [false; RF_PATH_NUM as usize];
    Ok(())
}

/// `_tssi_get_cck_group`.
fn tssi_get_cck_group(ch: u8) -> usize {
    match ch {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        12..=13 => 4,
        14 => 5,
        _ => 0,
    }
}

/// A group of `_tssi_get_ofdm_group` or `_tssi_get_trim_group`: one
/// group, or the average of this one and the next (`TSSI_EXTRA_GROUP`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Group {
    One(usize),
    Extra(usize),
}

/// `_tssi_get_ofdm_group`.
fn tssi_get_ofdm_group(ch: u8) -> Group {
    use Group::{Extra, One};
    match ch {
        1..=2 => One(0),
        3..=5 => One(1),
        6..=8 => One(2),
        9..=11 => One(3),
        12..=14 => One(4),
        36..=40 => One(5),
        41..=43 => Extra(5),
        44..=48 => One(6),
        49..=51 => Extra(6),
        52..=56 => One(7),
        57..=59 => Extra(7),
        60..=64 => One(8),
        100..=104 => One(9),
        105..=107 => Extra(9),
        108..=112 => One(10),
        113..=115 => Extra(10),
        116..=120 => One(11),
        121..=123 => Extra(11),
        124..=128 => One(12),
        129..=131 => Extra(12),
        132..=136 => One(13),
        137..=139 => Extra(13),
        140..=144 => One(14),
        149..=153 => One(15),
        154..=156 => Extra(15),
        157..=161 => One(16),
        162..=164 => Extra(16),
        165..=169 => One(17),
        170..=172 => Extra(17),
        173..=177 => One(18),
        _ => One(0),
    }
}

/// `_tssi_get_trim_group`: never an extra group.
fn tssi_get_trim_group(ch: u8) -> Group {
    Group::One(match ch {
        1..=8 => 0,
        9..=14 => 1,
        36..=48 => 2,
        52..=64 => 3,
        100..=112 => 4,
        116..=128 => 5,
        132..=144 => 6,
        149..=177 => 7,
        _ => 0,
    })
}

/// The DE of `group` in `values`: `(de_1st + de_2nd) / 2` for an extra
/// group, rounded toward zero as C divides.
fn group_de(values: &[i8], group: Group) -> i8 {
    match group {
        Group::One(index) => values[index],
        Group::Extra(index) => {
            ((i32::from(values[index]) + i32::from(values[index + 1])) / 2) as i8
        }
    }
}

/// `_tssi_get_ofdm_de`.
fn tssi_get_ofdm_de(efuse: &efuse::Tssi, path: usize, ch: u8) -> i8 {
    group_de(&efuse.tssi_mcs[path], tssi_get_ofdm_group(ch))
}

/// `_tssi_get_ofdm_trim_de`.
fn tssi_get_ofdm_trim_de(efuse: &efuse::Tssi, path: usize, ch: u8) -> i8 {
    group_de(&efuse.tssi_trim[path], tssi_get_trim_group(ch))
}

/// `_tssi_set_efuse_to_de`: each path's CCK and MCS DE, with its trim.
fn tssi_set_efuse_to_de<I: Io + ?Sized>(
    io: &mut I,
    channel: Channel,
    efuse: &efuse::Tssi,
) -> Result<(), Error> {
    let ch = channel.number;
    for i in 0..usize::from(RF_PATH_NUM) {
        let gidx = tssi_get_cck_group(ch);
        let trim_de = tssi_get_ofdm_trim_de(efuse, i, ch);
        let val = (i32::from(efuse.tssi_cck[i][gidx]) + i32::from(trim_de)) as u32;

        io.phy_write32_mask(TSSI_DE_CCK_LONG[i], TSSI_DE_MASK, val)?;
        io.phy_write32_mask(TSSI_DE_CCK_SHORT[i], TSSI_DE_MASK, val)?;

        // "[TSSI] Set TSSI CCK DE 0x%x[21:12]=0x%x"
        io.phy_read32_mask(TSSI_DE_CCK_LONG[i], TSSI_DE_MASK)?;

        let ofdm_de = tssi_get_ofdm_de(efuse, i, ch);
        let trim_de = tssi_get_ofdm_trim_de(efuse, i, ch);
        let val = (i32::from(ofdm_de) + i32::from(trim_de)) as u32;

        for register in [
            TSSI_DE_MCS_20M,
            TSSI_DE_MCS_40M,
            TSSI_DE_MCS_80M,
            TSSI_DE_MCS_80M_80M,
            TSSI_DE_MCS_5M,
            TSSI_DE_MCS_10M,
        ] {
            io.phy_write32_mask(register[i], TSSI_DE_MASK, val)?;
        }

        // "[TSSI] Set TSSI MCS DE 0x%x[21:12]=0x%x"
        io.phy_read32_mask(TSSI_DE_MCS_20M[i], TSSI_DE_MASK)?;
    }
    Ok(())
}

/// `_tssi_alimentk_dump_result`: the reads of rtw89's log line.
fn tssi_alimentk_dump_result<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<(), Error> {
    let offset = u32::from(path) << 13;
    for register in [
        R_TSSI_PA_K1,
        R_TSSI_PA_K2,
        R_P0_TSSI_ALIM1,
        R_P0_TSSI_ALIM3,
        R_TSSI_PA_K5,
        R_P0_TSSI_ALIM2,
        R_P0_TSSI_ALIM4,
        R_TSSI_PA_K8,
    ] {
        io.phy_read32_mask(register + offset, MASKDWORD)?;
    }
    Ok(())
}

/// The four alignment registers of `path`, in rtw89's order: ALIM1, ALIM3,
/// ALIM2 and ALIM4.
fn alim_registers(path: u8) -> [u32; 4] {
    let offset = u32::from(path) << 13;
    [
        R_P0_TSSI_ALIM1 + offset,
        R_P0_TSSI_ALIM3 + offset,
        R_P0_TSSI_ALIM2 + offset,
        R_P0_TSSI_ALIM4 + offset,
    ]
}

/// `_tssi_alimentk_done`: the alignment found for `channel`'s band, when
/// there is one.
fn tssi_alimentk_done<I: Io + ?Sized>(
    io: &mut I,
    tssi: &TssiInfo,
    path: u8,
    channel: Channel,
) -> Result<(), Error> {
    let band = alimk_band(channel.number);
    let p = usize::from(path);

    if tssi.alignment_done[p][band] {
        for (register, value) in alim_registers(path)
            .into_iter()
            .zip(tssi.alignment_value[p][band])
        {
            io.phy_write32_mask(register, MASKDWORD, value)?;
        }
    }

    tssi_alimentk_dump_result(io, path)
}

/// `_tssi_hw_tx(rtwdev, RTW89_PHY_0, path, cnt, period, pwr_dbm, enable,
/// chan)`.
#[allow(clippy::too_many_arguments)]
fn tssi_hw_tx<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    cnt: u16,
    period: u16,
    pwr_dbm: i16,
    enable: bool,
    channel: Channel,
    gain: &channel::Inputs,
) -> Result<(), Error> {
    let rx_path = match path {
        RF_PATH_A => RF_A,
        super::RF_PATH_B => RF_B,
        RF_PATH_AB => super::RF_AB,
        _ => RF_ABCD,
    };

    if enable {
        pmac::set_plcp_tx(io)?;
        pmac::cfg_tx_path(io, path)?;
        pmac::ctrl_rx_path(io, rx_path, channel, gain)?;
        pmac::set_power(io, pwr_dbm)?;
    }

    pmac::set_pmac_pkt_tx(io, enable, cnt, period, channel)
}

/// `_tssi_ch_to_idx`.
fn tssi_ch_to_idx(channel: u8) -> usize {
    usize::from(match channel {
        1..=14 => channel - 1,
        36..=64 => (channel - 36) / 2 + 14,
        100..=144 => ((channel - 100) / 2) + 15 + 14,
        149..=177 => ((channel - 149) / 2) + 38 + 14,
        _ => 0,
    })
}

/// `_tssi_get_cw_report`: for each power, TSSI triggered and 100 PMAC
/// packets sent until the CW report is ready, looked at up to 100 times 30
/// us apart. Whether every report came.
fn tssi_get_cw_report<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    power: &[i16; 4],
    tssi_cw_rpt: &mut [u32; TSSI_PATH_NR as usize],
    channel: Channel,
    gain: &channel::Inputs,
) -> Result<bool, Error> {
    const RETRY: u32 = 100;
    let p = usize::from(path);

    for j in 0..usize::from(TSSI_PATH_NR) {
        io.phy_write32_mask(TSSI_TRIGGER[p], B_P0_TSSI_EN, 0x0)?;
        io.phy_write32_mask(TSSI_TRIGGER[p], B_P0_TSSI_EN, 0x1)?;

        // The HW TX counter, which rtw89 only logs.
        io.phy_read32_mask(R_TX_COUNTER, MASKLWORD)?;

        // "[TSSI PA K] 0x%x = 0x%08x   path=%d"
        io.phy_read32_mask(TSSI_TRIGGER[p], MASKDWORD)?;

        let tx_path = if j == 0 { path } else { RF_PATH_ABCD };
        tssi_hw_tx(io, tx_path, 100, 5000, power[j], true, channel, gain)?;

        io.phy_read32_mask(R_TX_COUNTER, MASKLWORD)?;

        let mut k = 0;
        while k < RETRY {
            if io.phy_read32_mask(TSSI_CW_RPT_ADDR[p], B_TSSI_CWRPT_RDY)? != 0 {
                break;
            }

            io.delay_us(30);

            io.phy_read32_mask(R_TX_COUNTER, MASKLWORD)?;
            k += 1;
        }

        if k >= RETRY {
            tssi_hw_tx(io, path, 100, 5000, power[j], false, channel, gain)?;
            return Ok(false);
        }

        tssi_cw_rpt[j] = io.phy_read32_mask(TSSI_CW_RPT_ADDR[p], B_TSSI_CWRPT)?;

        tssi_hw_tx(io, path, 100, 5000, power[j], false, channel, gain)?;

        io.phy_read32_mask(R_TX_COUNTER, MASKLWORD)?;
    }

    Ok(true)
}

/// `_tssi_alimentk`: the alignment kept for `channel` put back, or found
/// from two CW reports with the BB backed up around them and kept by band
/// and channel.
fn tssi_alimentk<I: Io + ?Sized>(
    io: &mut I,
    tssi: &mut TssiInfo,
    path: u8,
    channel: Channel,
    inputs: &Inputs<'_>,
) -> Result<(), Error> {
    const BB_REG: [u32; 8] = [
        0x5820, 0x7820, 0x4978, 0x58e4, 0x78e4, 0x49c0, 0x0d18, 0x0d80,
    ];
    const POWER_2G: [i16; 4] = [48, 20, 4, 4];
    const POWER_5G: [i16; 4] = [48, 20, 4, 4];
    let p = usize::from(path);
    let ch_idx = tssi_ch_to_idx(channel.number);

    if tssi.check_backup_aligmk[p][ch_idx] {
        for (register, value) in alim_registers(path)
            .into_iter()
            .zip(tssi.alignment_backup_by_ch[p][ch_idx])
        {
            io.phy_write32_mask(register, MASKDWORD, value)?;
        }

        tssi_alimentk_dump_result(io, path)?;
        return Ok(());
    }

    let power = if channel.band == Band::Ghz2 {
        &POWER_2G
    } else {
        &POWER_5G
    };
    let band = alimk_band(channel.number);

    let tssi_bak = pmac::backup_tssi(io)?;
    // _tssi_backup_bb_registers
    let mut bb_reg_backup = [0; BB_REG.len()];
    for (value, register) in bb_reg_backup.iter_mut().zip(BB_REG) {
        *value = io.phy_read32_mask(register, MASKDWORD)?;
    }

    io.phy_write32_mask(R_P0_TSSI_AVG, B_P0_TSSI_AVG, 0x8)?;
    io.phy_write32_mask(R_P1_TSSI_AVG, B_P1_TSSI_AVG, 0x8)?;
    io.phy_write32_mask(R_P0_TSSI_MV_AVG, B_P0_TSSI_MV_AVG, 0x2)?;
    io.phy_write32_mask(R_P1_TSSI_MV_AVG, B_P1_TSSI_MV_AVG, 0x2)?;

    let mut tssi_cw_rpt = [0u32; TSSI_PATH_NR as usize];
    if tssi_get_cw_report(io, path, power, &mut tssi_cw_rpt, channel, inputs.gain)? {
        let default = |io: &mut I, k: usize| -> Result<i32, Error> {
            let tmp = io.phy_read32_mask(TSSI_CW_DEFAULT_ADDR[p][k], TSSI_CW_DEFAULT_MASK[k])?;
            Ok(sign_extend32(tmp, 8))
        };

        let tssi_cw_default = default(io, 1)?;
        let tssi_alim_offset_1 = tssi_cw_rpt[0]
            .wrapping_sub(((i32::from(power[0]) - i32::from(power[1])) * 2) as u32)
            .wrapping_sub(tssi_cw_rpt[1])
            .wrapping_add(tssi_cw_default as u32) as i32;
        let aliment_diff = tssi_alim_offset_1.wrapping_sub(tssi_cw_default);

        let tssi_cw_default = default(io, 2)?;
        let tssi_alim_offset_2 = tssi_cw_default.wrapping_add(aliment_diff);

        let tssi_cw_default = default(io, 3)?;
        let tssi_alim_offset_3 = tssi_cw_default.wrapping_add(aliment_diff);

        let tmp = prep(tssi_alim_offset_1 as u32, B_P1_TSSI_ALIM11)
            | prep(tssi_alim_offset_2 as u32, B_P1_TSSI_ALIM12)
            | prep(tssi_alim_offset_3 as u32, B_P1_TSSI_ALIM13);

        if path == RF_PATH_A {
            io.phy_write32_mask(R_P0_TSSI_ALIM1, B_P0_TSSI_ALIM1, tmp)?;
            io.phy_write32_mask(R_P0_TSSI_ALIM2, B_P0_TSSI_ALIM2, tmp)?;

            // "[TSSI PA K] tssi_alim_offset = 0x%x   0x%x   0x%x   0x%x"
            io.phy_read32_mask(R_P0_TSSI_ALIM3, B_P0_TSSI_ALIM31)?;
            io.phy_read32_mask(R_P0_TSSI_ALIM1, B_P0_TSSI_ALIM11)?;
            io.phy_read32_mask(R_P0_TSSI_ALIM1, B_P0_TSSI_ALIM12)?;
            io.phy_read32_mask(R_P0_TSSI_ALIM1, B_P0_TSSI_ALIM13)?;
        } else {
            io.phy_write32_mask(R_P1_TSSI_ALIM1, B_P1_TSSI_ALIM1, tmp)?;
            io.phy_write32_mask(R_P1_TSSI_ALIM2, B_P1_TSSI_ALIM2, tmp)?;

            io.phy_read32_mask(R_P1_TSSI_ALIM3, B_P1_TSSI_ALIM31)?;
            io.phy_read32_mask(R_P1_TSSI_ALIM1, B_P1_TSSI_ALIM11)?;
            io.phy_read32_mask(R_P1_TSSI_ALIM1, B_P1_TSSI_ALIM12)?;
            io.phy_read32_mask(R_P1_TSSI_ALIM1, B_P1_TSSI_ALIM13)?;
        }

        tssi.alignment_done[p][band] = true;
        for (k, register) in alim_registers(path).into_iter().enumerate() {
            tssi.alignment_value[p][band][k] = io.phy_read32_mask(register, MASKDWORD)?;
        }

        tssi.check_backup_aligmk[p][ch_idx] = true;
        for (k, register) in alim_registers(path).into_iter().enumerate() {
            tssi.alignment_backup_by_ch[p][ch_idx][k] = io.phy_read32_mask(register, MASKDWORD)?;
        }
    }

    // out: _tssi_reload_bb_registers
    for (register, value) in BB_REG.into_iter().zip(bb_reg_backup) {
        io.phy_write32_mask(register, MASKDWORD, value)?;
    }
    pmac::restore_tssi(io, &tssi_bak)?;
    pmac::tx_mode_switch(io, 0)
}
