// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! What an RTL8852B's radio tracks every two seconds once it runs, as
//! pinned rtw89's `rtw89_track_work` does it (phy.c, rtw8852b.c), from
//! the init `rtw89_phy_dm_init` gives each part:
//!
//! - [`EnvMonitor`]: the environment monitor's IFS-CLM and EDCCA-CLM
//!   counters, `rtw89_phy_env_monitor_init` and
//!   `rtw89_phy_env_monitor_track` with every CCX helper they reach: the
//!   last 1900 ms window's false alarms read and turned into ratios and
//!   permils, then the next window armed;
//! - [`physts_parsing_init`]: `rtw89_physts_parsing_init`, the PHY status
//!   IE bitmaps per packet type, which give IE01 (and with it the CFO
//!   [`Cfo::parse`] needs) to CCK and trigger-based packets;
//! - [`Dig`]: dynamic initial gain, `rtw89_phy_dig_init` and
//!   `rtw89_phy_dig`, with the suspend and resume rtw89 runs around station
//!   changes and scans: the false-alarm permils move the gain index the
//!   link's RSSI starts from, which sets the OFDM and CCK packet detection
//!   floors;
//! - [`Cfo`]: carrier frequency offset tracking, `rtw89_phy_cfo_init`,
//!   `rtw89_phy_cfo_track`, `rtw89_phy_cfo_track_work` and
//!   `rtw89_phy_cfo_parse`: the CFO the PPDU statuses report
//!   ([`super::rxdesc::PhyPpdu::cfo`]) averaged, the crystal cap moved
//!   through XTAL SI toward it and the rest compensated digitally;
//! - [`Ewma`]: the kernel's `DECLARE_EWMA`, with the averages rtw89 keeps
//!   by it: a station's RSSI ([`RssiAverage`], what `rtw89_core_rx_stats`
//!   adds each A1-matched PPDU's `rssi_avg` to), whose lowest is DIG's
//!   [`Link::rssi_min`], and each path's thermal meter ([`Thermal`],
//!   `rtw89_phy_stat_init` and `rtw89_phy_stat_thermal_update` with
//!   RTL8852B's `__rtw8852bx_get_thermal`), which DPK tracking reads.
//!
//! [`Dynamic`] holds them as `rtwdev` does. [`Dynamic::init`] runs what
//! `rtw89_phy_dm_init` runs of them, in its order: the environment monitor,
//! the PHY status bitmaps, DIG, CFO; the caller runs it where rtw89 runs
//! `rtw89_phy_dm_init`, after the BB and RF tables and before the NCTL
//! table and the RF calibrations, with [`Thermal::init`] (its
//! `rtw89_phy_stat_init`) first. Every two seconds, unless scanning
//! (`rtw89_track_work` returns before them then), the caller runs, in
//! `rtw89_track_work`'s order: [`Thermal::update`] (where
//! `rtw89_phy_stat_track` starts), [`Dynamic::env_monitor_track`],
//! [`Dynamic::dig`], the chip's RF tracking
//! ([`super::rtw8852b::rfk::track`] with [`Thermal::read`]), then
//! [`Dynamic::cfo_track`].
//! What rtw89 takes from mac80211 and its own
//! bookkeeping is the caller's and is passed in: the associated stations
//! and their lowest RSSI average ([`Link`]), the channel, and the traffic
//! statistics `rtw89_traffic_stats_track` keeps ([`Traffic`]). When
//! [`Dynamic::cfo_track`] returns a delay, rtw89 queues
//! `rtw89_phy_cfo_track_work` that many milliseconds later; the caller
//! runs [`Dynamic::cfo_track_work`] then, and again after each delay it
//! returns.
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included, on PHY 0 with DBCC off. An XTAL
//! SI request the chip never answers is counted
//! ([`Cfo::xtal_timeouts`]) and the step goes on, as rtw89 warns and goes
//! on with the value it read left 0; any other access the [`Io`] refuses
//! ends the step with its error.
//!
//! What this leaves out, and why:
//! - DIG's gain-code half (`rtw89_phy_dig_update_gain_para`,
//!   `rtw89_phy_dig_config_igi`, `rtw89_phy_dig_set_igi_cr` and the LNA,
//!   TIA and RXB indices): `rtw89_core_setup_phycap` sets
//!   `hal.support_igi` for an RTL8852A up to cut CBV alone, so on an
//!   RTL8852B they return before touching anything.
//! - The fixed PD thresholds `hal.disabled_dm_bitmap` selects: only
//!   debugfs sets `RTW89_DM_DIG_PD`.
//! - MCC (`rtw89_phy_dig_mcc`) and MLO: Stela runs one channel context and
//!   one link.
//! - NHM: RTL8852B's `support_noise` is false, so `rtw89_phy_nhm_*` return
//!   at once; the CCX trigger never selects NHM.
//! - The manual CCX control and the IFS-CLM applications other than init
//!   and background: only debugfs reaches them.
//! - CFO's packet- and entry-based multi-station averages:
//!   `rtw89_phy_cfo_init` sets the throughput-based mode and nothing
//!   changes it; its per-station tolerance is never set, so it is 0.
//! - Monitor mode's extra IE bitmaps are kept, behind the `monitor` flag
//!   [`physts_parsing_init`] takes.
//!
//! That a step returns proves its reads were answered, not that the gain
//! or the crystal suits the air.
use super::{
    io::{Error, Io, Registers},
    registers::{CHIP_CAV, DCFO_OPT, MASKDWORD, PWR_UL_CTRL2},
    rtw8852b::rfk::{
        Band, Bandwidth, Channel, RF_PATH_NUM,
        reg::{RR_TM, RR_TM_TRI, RR_TM_VAL},
    },
};

#[cfg(test)]
mod tests;

/// BB `R_CCX` and its fields.
pub const CCX: u32 = 0x0c00;
pub const CCX_EDCCA_OPT_MSK: u32 = 0x0000_0070;
pub const MEASUREMENT_TRIG_MSK: u32 = 1 << 2;
pub const CCX_TRIG_OPT_MSK: u32 = 1 << 1;
pub const CCX_EN_MSK: u32 = 1 << 0;
/// BB `R_IFS_COUNTER` and its fields.
pub const IFS_COUNTER: u32 = 0x0c28;
pub const IFS_CLM_PERIOD_MSK: u32 = 0xffff_0000;
pub const IFS_CLM_COUNTER_UNIT_MSK: u32 = 0x0000_c000;
pub const IFS_COUNTER_CLR_MSK: u32 = 1 << 13;
pub const IFS_COLLECT_EN: u32 = 1 << 12;
/// BB `R_IFS_T1` to `R_IFS_T4`, whose fields are the same for each.
pub const IFS_T: [u32; IFS_CLM_NUM] = [0x0c2c, 0x0c30, 0x0c34, 0x0c38];
pub const IFS_T_TH_HIGH_MSK: u32 = 0xffff_0000;
pub const IFS_T_EN_MSK: u32 = 1 << 15;
pub const IFS_T_TH_LOW_MSK: u32 = 0x0000_7fff;
/// BB IFS-CLM reports: `R_IFS_CLM_TX_CNT`, `R_IFS_CLM_CCA`, `R_IFS_CLM_FA`,
/// `R_IFS_HIS`, `R_IFS_AVG_L` and `_H`, `R_IFS_CCA_L` and `_H`, `R_IFSCNT`.
pub const IFS_CLM_TX_CNT: u32 = 0x1acc;
pub const IFS_CLM_EDCCA_EXCLUDE_CCA_FA_MSK: u32 = 0xffff_0000;
pub const IFS_CLM_TX_CNT_MSK: u32 = 0x0000_ffff;
pub const IFS_CLM_CCA: u32 = 0x1ad0;
pub const IFS_CLM_OFDMCCA_EXCLUDE_FA_MSK: u32 = 0xffff_0000;
pub const IFS_CLM_CCKCCA_EXCLUDE_FA_MSK: u32 = 0x0000_ffff;
pub const IFS_CLM_FA: u32 = 0x1ad4;
pub const IFS_CLM_OFDM_FA_MSK: u32 = 0xffff_0000;
pub const IFS_CLM_CCK_FA_MSK: u32 = 0x0000_ffff;
pub const IFS_HIS: u32 = 0x1ad8;
/// `B_IFS_T1_HIS_MSK` to `B_IFS_T4_HIS_MSK`.
pub const IFS_HIS_MSK: [u32; IFS_CLM_NUM] = [0x0000_00ff, 0x0000_ff00, 0x00ff_0000, 0xff00_0000];
pub const IFS_AVG_L: u32 = 0x1adc;
pub const IFS_AVG_H: u32 = 0x1ae0;
pub const IFS_CCA_L: u32 = 0x1ae4;
pub const IFS_CCA_H: u32 = 0x1ae8;
/// The low and high halves of the average and CCA reports: T1 and T3 low,
/// T2 and T4 high.
pub const IFS_LOW_MSK: u32 = 0x0000_ffff;
pub const IFS_HIGH_MSK: u32 = 0xffff_0000;
pub const IFSCNT: u32 = 0x1aec;
pub const IFSCNT_DONE_MSK: u32 = 1 << 16;
pub const IFSCNT_TOTAL_CNT_MSK: u32 = 0x0000_ffff;
/// BB `R_CLM_EDCCA_RDY` and `R_CLM_EDCCA_RESULT`, one register.
pub const CLM_EDCCA: u32 = 0x1ac8;
pub const CLM_EDCCA_RDY: u32 = 1 << 16;
pub const CLM_EDCCA_RESULT: u32 = 0x0000_ffff;
/// BB `R_PLCP_HISTOGRAM` with `B_STS_DIS_TRIG_BY_FAIL` and `_BY_BRK`.
pub const PLCP_HISTOGRAM: u32 = 0x0738;
pub const STS_DIS_TRIG_BY_FAIL: u32 = 1 << 3;
pub const STS_DIS_TRIG_BY_BRK: u32 = 1 << 2;
/// BB `R_PHY_STS_BITMAP_ADDR_START` (`R_PHY_STS_BITMAP_SEARCH_FAIL`).
pub const PHY_STS_BITMAP_ADDR_START: u32 = 0x073c;
/// BB `R_DCFO_WEIGHT`, `R_DCFO_OPT`'s `B_DCFO_OPT_EN`, `R_DCFO` and
/// RTL8852B's `dcfo_comp`, `R_DCFO_COMP_S0`.
pub const DCFO_WEIGHT: u32 = 0x4490;
pub const DCFO_WEIGHT_MSK: u32 = 0x0f00_0000;
pub const DCFO_OPT_EN: u32 = 1 << 29;
pub const DCFO: u32 = 0x4264;
pub const DCFO_MSK: u32 = 0x0000_00ff;
pub const DCFO_COMP_S0: u32 = 0x448c;
pub const DCFO_COMP_S0_MSK: u32 = 0x0000_0fff;
/// MAC `R_AX_PWR_UL_CTRL2`'s `B_AX_PWR_UL_CFO_MASK`.
pub const PWR_UL_CFO_MASK: u32 = 0x0000_0007;
/// RTL8852B's `dig_regs`: `R_SEG0R_PD_V1`, `R_BMODE_PDTH_EN_V1`,
/// `R_BMODE_PDTH_V1` and the four PAGC/UGC follow enables.
pub const SEG0R_PD_V1: u32 = 0x4860;
pub const SEG0R_PD_LOWER_BOUND_MSK: u32 = 0x0000_07c0;
pub const SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1: u32 = 1 << 30;
pub const BMODE_PDTH_EN_V1: u32 = 0x4b74;
pub const BMODE_PDTH_LIMIT_EN_MSK_V1: u32 = 1 << 30;
pub const BMODE_PDTH_V1: u32 = 0x4b64;
pub const BMODE_PDTH_LOWER_BOUND_MSK_V1: u32 = 0xff00_0000;
/// `p0_p20_pagcugc_en`, `p0_s20_pagcugc_en`, `p1_p20_pagcugc_en` and
/// `p1_s20_pagcugc_en`, in that order, each with its bit 5.
pub const PAGCUGC_EN: [u32; 4] = [0x46e8, 0x46ec, 0x47a8, 0x47ac];
pub const PAGCUGC_EN_MSK: u32 = 1 << 5;
/// `XTAL_SI_XTAL_SC_XI` and `XTAL_SI_XTAL_SC_XO`, with `XTAL_SC_XI_MASK`
/// and `XTAL_SC_XO_MASK`; `B_AX_XTAL_SC_MASK`.
pub const XTAL_SI_XTAL_SC_XI: u8 = 0x04;
pub const XTAL_SI_XTAL_SC_XO: u8 = 0x05;
pub const XTAL_SC_MASK: u8 = 0xff;
pub const AX_XTAL_SC_MASK: u8 = 0x7f;

/// `RTW89_IFS_CLM_NUM`.
pub const IFS_CLM_NUM: usize = 4;
/// `CFO_TRACK_MAX_USER`.
pub const CFO_TRACK_MAX_USER: usize = 64;

/// What `rtw89_track_work` reads of mac80211's stations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Link {
    /// `rtwdev->total_sta_assoc`: the associated stations (for a client,
    /// 1 once associated, its AP).
    pub stations: u8,
    /// `ch_info.rssi_min`: the lowest station [`RssiAverage`] reading,
    /// in rtw89's RSSI units (twice dBm plus 110, `RSSI_FACTOR` 1); read
    /// only while `stations` is not 0.
    pub rssi_min: u8,
}

impl Link {
    /// `rtwdev->total_sta_assoc > 0`.
    pub const fn linked(self) -> bool {
        self.stations > 0
    }
}

/// What CFO tracking reads of `rtwdev->stats`, which
/// `rtw89_traffic_stats_track` keeps: the TX and RX throughput averages in
/// Mbps, and the trigger frames counted in the last period.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Traffic {
    pub tx_throughput: u32,
    pub rx_throughput: u32,
    pub rx_tf_periodic: u32,
}

/// The kernel's `DECLARE_EWMA(name, PRECISION, WEIGHT_RCP)`: an
/// exponentially weighted moving average kept with `PRECISION` fraction
/// bits, each new value weighing `1 / WEIGHT_RCP` (a power of two).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ewma<const PRECISION: u32, const WEIGHT_RCP: u64> {
    internal: u64,
}

impl<const PRECISION: u32, const WEIGHT_RCP: u64> Ewma<PRECISION, WEIGHT_RCP> {
    /// `ewma_<name>_init`.
    pub const fn new() -> Self {
        Self { internal: 0 }
    }

    /// `ewma_<name>_add`: the first value is taken whole.
    pub fn add(&mut self, value: u64) {
        let weight = WEIGHT_RCP.ilog2();
        let internal = self.internal;
        self.internal = if internal != 0 {
            ((internal << weight).wrapping_sub(internal)).wrapping_add(value << PRECISION) >> weight
        } else {
            value << PRECISION
        };
    }

    /// `ewma_<name>_read`.
    pub const fn read(&self) -> u64 {
        self.internal >> PRECISION
    }
}

/// `DECLARE_EWMA(rssi, 10, 16)`: a station's `avg_rssi`.
pub type RssiAverage = Ewma<10, 16>;
/// `DECLARE_EWMA(thermal, 4, 4)`: `phystat.avg_thermal`.
pub type ThermalAverage = Ewma<4, 4>;

/// `__rtw8852bx_get_thermal`: path `path`'s thermal meter, from the TSSI
/// tracking's report in TSSI mode, otherwise triggered through RF `RR_TM`
/// (set, cleared, set) and read 200 us later.
pub fn get_thermal<I: Io + ?Sized>(io: &mut I, path: u8, tssi_mode: bool) -> Result<u8, Error> {
    if tssi_mode {
        let address = 0x1c10 + (u32::from(path) << 13);
        return io.phy_read32_mask(address, 0x3f00_0000).map(|v| v as u8);
    }
    io.write_rf(path, RR_TM, RR_TM_TRI, 0x1)?;
    io.write_rf(path, RR_TM, RR_TM_TRI, 0x0)?;
    io.write_rf(path, RR_TM, RR_TM_TRI, 0x1)?;
    // fsleep(200)
    io.delay_us(200);
    io.read_rf(path, RR_TM, RR_TM_VAL).map(|v| v as u8)
}

/// `rtwdev->phystat`'s thermal part: each path's averaged thermal meter
/// and the highest reading of the last update.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Thermal {
    pub avg_thermal: [ThermalAverage; RF_PATH_NUM as usize],
    pub last_thermal_max: u8,
}

impl Thermal {
    /// `rtw89_phy_stat_init`'s thermal part: the averages cleared, then a
    /// first reading. `tssi_mode` is `rtwdev->is_tssi_mode` per path.
    pub fn init<I: Io + ?Sized>(io: &mut I, tssi_mode: [bool; 2]) -> Result<Self, Error> {
        let mut thermal = Self::default();
        thermal.update(io, tssi_mode)?;
        Ok(thermal)
    }

    /// `rtw89_phy_stat_thermal_update`: each path read, a reading of 0 left
    /// out of its average.
    pub fn update<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        tssi_mode: [bool; 2],
    ) -> Result<(), Error> {
        let mut th_max = 0;
        for path in 0..RF_PATH_NUM {
            let p = usize::from(path);
            let th = get_thermal(io, path, tssi_mode[p])?;
            if th != 0 {
                self.avg_thermal[p].add(th.into());
            }
            th_max = th_max.max(th);
        }
        self.last_thermal_max = th_max;
        Ok(())
    }

    /// `ewma_thermal_read` of each path, as the `u8` DPK tracking keeps.
    pub fn read(&self) -> [u8; 2] {
        self.avg_thermal.map(|average| average.read() as u8)
    }
}

/// `enum rtw89_ifs_clm_application`, the two rtw89 reaches outside
/// debugfs.
const IFS_CLM_INIT: u8 = 0;
const IFS_CLM_BACKGROUND: u8 = 1;
/// `RTW89_RAC_RELEASE` and `RTW89_RAC_LV_1`.
const RAC_RELEASE: u8 = 0;
const RAC_LV_1: u8 = 1;
/// `RTW89_CCX_32_US`.
const CCX_32_US: u8 = 3;
/// `CCX_US_BASE_RATIO`'s log2.
const CCX_US_BASE_SHIFT: u32 = 2;
/// `CCX_MAX_PERIOD`, `CCX_MAX_PERIOD_UNIT` and `MS_TO_4US_RATIO`.
const CCX_MAX_PERIOD: u16 = 2097;
const CCX_MAX_PERIOD_UNIT: u32 = 32;
const MS_TO_4US_RATIO: u32 = 250;
/// `ENV_MNTR_FAIL_DWORD` and `ENV_MNTR_IFSCLM_HIS_MAX`.
const ENV_MNTR_FAIL_DWORD: u32 = 0xffff_ffff;
const ENV_MNTR_IFSCLM_HIS_MAX: u16 = 127;
/// `PERMIL` and `PERCENT`.
const PERMIL: u16 = 1000;
const PERCENT: u16 = 100;
/// `IFS_CLM_TH0_UPPER` and `IFS_CLM_TH_MUL`.
const IFS_CLM_TH0_UPPER: u32 = 64;
const IFS_CLM_TH_MUL: u32 = 4;
/// `RTW89_PHY_ENV_MON_IFS_CLM` and `RTW89_PHY_ENV_MON_EDCCA_CLM`.
pub const ENV_MON_IFS_CLM: u8 = 1 << 3;
pub const ENV_MON_EDCCA_CLM: u8 = 1 << 4;
/// The window `__rtw89_phy_env_monitor_track` arms, in ms.
const ENV_MONITOR_TIME: u16 = 1900;

/// `struct rtw89_env_monitor_info` as far as IFS-CLM and EDCCA-CLM use it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnvMonitor {
    /// `RTW89_PHY_ENV_MON_*` bits: the reports the last track read.
    pub ccx_watchdog_result: u8,
    pub ccx_ongoing: bool,
    pub ccx_rac_lv: u8,
    pub ifs_clm_mntr_time: u16,
    pub ifs_clm_app: u8,
    pub ccx_period: u16,
    pub ccx_unit_idx: u8,
    pub ifs_clm_th_l: [u16; IFS_CLM_NUM],
    pub ifs_clm_th_h: [u16; IFS_CLM_NUM],
    pub ifs_clm_tx: u16,
    pub ifs_clm_edcca_excl_cca: u16,
    pub ifs_clm_ofdmfa: u16,
    pub ifs_clm_ofdmcca_excl_fa: u16,
    pub ifs_clm_cckfa: u16,
    pub ifs_clm_cckcca_excl_fa: u16,
    pub ifs_clm_total_ifs: u16,
    pub ifs_clm_his: [u16; IFS_CLM_NUM],
    pub ifs_clm_avg: [u16; IFS_CLM_NUM],
    pub ifs_clm_cca: [u16; IFS_CLM_NUM],
    pub ifs_clm_tx_ratio: u8,
    pub ifs_clm_edcca_excl_cca_ratio: u8,
    pub ifs_clm_cck_fa_ratio: u8,
    pub ifs_clm_ofdm_fa_ratio: u8,
    pub ifs_clm_cck_cca_excl_fa_ratio: u8,
    pub ifs_clm_ofdm_cca_excl_fa_ratio: u8,
    pub ifs_clm_cck_fa_permil: u16,
    pub ifs_clm_ofdm_fa_permil: u16,
    pub ifs_clm_ifs_avg: [u32; IFS_CLM_NUM],
    pub ifs_clm_cca_avg: [u32; IFS_CLM_NUM],
    pub edcca_clm_ratio: u8,
}

impl EnvMonitor {
    /// `rtw89_phy_ccx_us_to_idx`.
    fn us_to_idx(&self, time_us: u32) -> u16 {
        (time_us >> (CCX_US_BASE_SHIFT + u32::from(self.ccx_unit_idx))) as u16
    }

    /// `rtw89_phy_ccx_idx_to_us`.
    fn idx_to_us(&self, idx: u16) -> u32 {
        u32::from(idx) << (CCX_US_BASE_SHIFT + u32::from(self.ccx_unit_idx))
    }

    /// `rtw89_phy_ccx_get_report`: `report` over the window, in `score`ths,
    /// rounded and kept below `score`.
    fn report(&self, report: u16, score: u16) -> u16 {
        let numer = u32::from(report) * u32::from(score) + u32::from(self.ccx_period >> 1);
        let ret = if self.ccx_period != 0 {
            (numer / u32::from(self.ccx_period)) as u16
        } else {
            0
        };
        if ret >= score { score - 1 } else { ret }
    }

    /// `rtw89_phy_ccx_top_setting_init`.
    fn top_setting_init<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.ccx_ongoing = false;
        self.ccx_rac_lv = RAC_RELEASE;
        self.ccx_period = 0;
        self.ccx_unit_idx = CCX_32_US;
        io.phy_write32_mask(CCX, CCX_EN_MSK, 1)?;
        io.phy_write32_mask(CCX, CCX_TRIG_OPT_MSK, 1)?;
        io.phy_write32_mask(CCX, MEASUREMENT_TRIG_MSK, 1)?;
        // RTW89_CCX_EDCCA_BW20_0
        io.phy_write32_mask(CCX, CCX_EDCCA_OPT_MSK, 0)
    }

    /// `rtw89_phy_ccx_racing_release`.
    fn racing_release(&mut self) {
        self.ccx_ongoing = false;
        self.ccx_rac_lv = RAC_RELEASE;
        self.ifs_clm_app = IFS_CLM_BACKGROUND;
    }

    /// `rtw89_phy_ifs_clm_th_update_check` for `app`, init or background:
    /// whether the thresholds were recomputed.
    fn th_update_check(&mut self, app: u8) -> bool {
        if self.ifs_clm_app == app {
            return false;
        }
        let mut th_h_us = [0u32; IFS_CLM_NUM];
        self.ifs_clm_th_l[0] = 0;
        th_h_us[0] = IFS_CLM_TH0_UPPER;
        self.ifs_clm_th_h[0] = self.us_to_idx(IFS_CLM_TH0_UPPER);
        for i in 1..IFS_CLM_NUM {
            self.ifs_clm_th_l[i] = self.ifs_clm_th_h[i - 1].wrapping_add(1);
            th_h_us[i] = th_h_us[i - 1].wrapping_mul(IFS_CLM_TH_MUL);
            self.ifs_clm_th_h[i] = self.us_to_idx(th_h_us[i]);
        }
        true
    }

    /// `rtw89_phy_ifs_clm_set_th_reg`.
    fn set_th_reg<I: Io + ?Sized>(&self, io: &mut I) -> Result<(), Error> {
        for (&register, &low) in IFS_T.iter().zip(&self.ifs_clm_th_l) {
            io.phy_write32_mask(register, IFS_T_TH_LOW_MSK, u32::from(low))?;
        }
        for (&register, &high) in IFS_T.iter().zip(&self.ifs_clm_th_h) {
            io.phy_write32_mask(register, IFS_T_TH_HIGH_MSK, u32::from(high))?;
        }
        Ok(())
    }

    /// `rtw89_phy_ifs_clm_setting_init`.
    fn ifs_clm_setting_init<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.ifs_clm_app = IFS_CLM_BACKGROUND;
        self.ifs_clm_mntr_time = 0;
        if self.th_update_check(IFS_CLM_INIT) {
            self.set_th_reg(io)?;
        }
        io.phy_write32_mask(IFS_COUNTER, IFS_COLLECT_EN, 1)?;
        for register in IFS_T {
            io.phy_write32_mask(register, IFS_T_EN_MSK, 1)?;
        }
        Ok(())
    }

    /// `rtw89_phy_ccx_racing_ctrl`: whether `level` won the CCX.
    fn racing_ctrl(&mut self, level: u8) -> bool {
        let mut won = true;
        if self.ccx_ongoing {
            if level <= self.ccx_rac_lv {
                won = false;
            } else {
                self.ccx_ongoing = false;
            }
        }
        if won {
            self.ccx_rac_lv = level;
        }
        won
    }

    /// `rtw89_phy_ccx_trigger` without NHM, which RTL8852B lacks.
    fn trigger<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        io.phy_write32_mask(IFS_COUNTER, IFS_COUNTER_CLR_MSK, 0)?;
        io.phy_write32_mask(CCX, MEASUREMENT_TRIG_MSK, 0)?;
        io.phy_write32_mask(IFS_COUNTER, IFS_COUNTER_CLR_MSK, 1)?;
        io.phy_write32_mask(CCX, MEASUREMENT_TRIG_MSK, 1)?;
        self.ccx_ongoing = true;
        Ok(())
    }

    /// `rtw89_phy_ifs_clm_get_utility`.
    fn get_utility(&mut self) {
        self.ifs_clm_tx_ratio = self.report(self.ifs_clm_tx, PERCENT) as u8;
        self.ifs_clm_edcca_excl_cca_ratio = self.report(self.ifs_clm_edcca_excl_cca, PERCENT) as u8;
        self.ifs_clm_cck_fa_ratio = self.report(self.ifs_clm_cckfa, PERCENT) as u8;
        self.ifs_clm_ofdm_fa_ratio = self.report(self.ifs_clm_ofdmfa, PERCENT) as u8;
        self.ifs_clm_cck_cca_excl_fa_ratio =
            self.report(self.ifs_clm_cckcca_excl_fa, PERCENT) as u8;
        self.ifs_clm_ofdm_cca_excl_fa_ratio =
            self.report(self.ifs_clm_ofdmcca_excl_fa, PERCENT) as u8;
        self.ifs_clm_cck_fa_permil = self.report(self.ifs_clm_cckfa, PERMIL);
        self.ifs_clm_ofdm_fa_permil = self.report(self.ifs_clm_ofdmfa, PERMIL);
        for i in 0..IFS_CLM_NUM {
            let his = self.ifs_clm_his[i];
            self.ifs_clm_ifs_avg[i] = if his > ENV_MNTR_IFSCLM_HIS_MAX {
                ENV_MNTR_FAIL_DWORD
            } else {
                self.idx_to_us(self.ifs_clm_avg[i])
            };
            let res = self
                .idx_to_us(self.ifs_clm_cca[i])
                .wrapping_add(u32::from(his >> 1));
            self.ifs_clm_cca_avg[i] = if his != 0 { res / u32::from(his) } else { 0 };
        }
    }

    /// `rtw89_phy_ifs_clm_get_result`: whether the window's report was
    /// ready.
    fn ifs_clm_get_result<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<bool, Error> {
        if io.phy_read32_mask(IFSCNT, IFSCNT_DONE_MSK)? == 0 {
            return Ok(false);
        }
        let mut read = |register, mask| io.phy_read32_mask(register, mask).map(|v| v as u16);
        self.ifs_clm_tx = read(IFS_CLM_TX_CNT, IFS_CLM_TX_CNT_MSK)?;
        self.ifs_clm_edcca_excl_cca = read(IFS_CLM_TX_CNT, IFS_CLM_EDCCA_EXCLUDE_CCA_FA_MSK)?;
        self.ifs_clm_cckcca_excl_fa = read(IFS_CLM_CCA, IFS_CLM_CCKCCA_EXCLUDE_FA_MSK)?;
        self.ifs_clm_ofdmcca_excl_fa = read(IFS_CLM_CCA, IFS_CLM_OFDMCCA_EXCLUDE_FA_MSK)?;
        self.ifs_clm_cckfa = read(IFS_CLM_FA, IFS_CLM_CCK_FA_MSK)?;
        self.ifs_clm_ofdmfa = read(IFS_CLM_FA, IFS_CLM_OFDM_FA_MSK)?;
        for (his, mask) in self.ifs_clm_his.iter_mut().zip(IFS_HIS_MSK) {
            *his = read(IFS_HIS, mask)?;
        }
        let halves = [
            (IFS_AVG_L, IFS_LOW_MSK),
            (IFS_AVG_L, IFS_HIGH_MSK),
            (IFS_AVG_H, IFS_LOW_MSK),
            (IFS_AVG_H, IFS_HIGH_MSK),
        ];
        for (avg, (register, mask)) in self.ifs_clm_avg.iter_mut().zip(halves) {
            *avg = read(register, mask)?;
        }
        let halves = [
            (IFS_CCA_L, IFS_LOW_MSK),
            (IFS_CCA_L, IFS_HIGH_MSK),
            (IFS_CCA_H, IFS_LOW_MSK),
            (IFS_CCA_H, IFS_HIGH_MSK),
        ];
        for (cca, (register, mask)) in self.ifs_clm_cca.iter_mut().zip(halves) {
            *cca = read(register, mask)?;
        }
        self.ifs_clm_total_ifs = read(IFSCNT, IFSCNT_TOTAL_CNT_MSK)?;
        self.get_utility();
        Ok(true)
    }

    /// `rtw89_phy_edcca_clm_get_result`.
    fn edcca_clm_get_result<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<bool, Error> {
        if io.phy_read32_mask(CLM_EDCCA, CLM_EDCCA_RDY)? == 0 {
            return Ok(false);
        }
        let count = io.phy_read32_mask(CLM_EDCCA, CLM_EDCCA_RESULT)?;
        self.edcca_clm_ratio = self.report(count as u16, PERCENT) as u8;
        Ok(true)
    }

    /// `rtw89_phy_ifs_clm_set` for the background window
    /// `__rtw89_phy_env_monitor_track` asks: whether it was set.
    fn ifs_clm_set<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<bool, Error> {
        if !self.racing_ctrl(RAC_LV_1) {
            return Ok(false);
        }
        if ENV_MONITOR_TIME != self.ifs_clm_mntr_time {
            let (period, unit_idx) = ms_to_period_unit(ENV_MONITOR_TIME);
            io.phy_write32_mask(IFS_COUNTER, IFS_CLM_PERIOD_MSK, period)?;
            io.phy_write32_mask(IFS_COUNTER, IFS_CLM_COUNTER_UNIT_MSK, unit_idx)?;
            self.ifs_clm_mntr_time = ENV_MONITOR_TIME;
            self.ccx_period = period as u16;
            self.ccx_unit_idx = unit_idx as u8;
        }
        if self.th_update_check(IFS_CLM_BACKGROUND) {
            self.ifs_clm_app = IFS_CLM_BACKGROUND;
            self.set_th_reg(io)?;
        }
        Ok(true)
    }

    /// `__rtw89_phy_env_monitor_init`.
    pub fn init<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.top_setting_init(io)?;
        self.ifs_clm_setting_init(io)
    }

    /// `__rtw89_phy_env_monitor_track`: the last window's reports read,
    /// then the next armed.
    pub fn track<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.ccx_watchdog_result = 0;
        if self.ifs_clm_get_result(io)? {
            self.ccx_watchdog_result |= ENV_MON_IFS_CLM;
        }
        if self.edcca_clm_get_result(io)? {
            self.ccx_watchdog_result |= ENV_MON_EDCCA_CLM;
        }
        self.racing_release();
        let mut chk_result = 0;
        if self.ifs_clm_set(io)? {
            chk_result |= ENV_MON_IFS_CLM;
        }
        if chk_result != 0 {
            self.trigger(io)?;
        }
        Ok(())
    }
}

/// `rtw89_phy_ccx_ms_to_period_unit`: the window's period and unit index.
fn ms_to_period_unit(time_ms: u16) -> (u32, u32) {
    let time_ms = time_ms.min(CCX_MAX_PERIOD);
    let quotient = (CCX_MAX_PERIOD_UNIT * u32::from(time_ms) / u32::from(CCX_MAX_PERIOD)) as u8;
    let idx = match quotient {
        0..4 => 0,
        4..8 => 1,
        8..16 => 2,
        _ => 3,
    };
    ((u32::from(time_ms) * MS_TO_4US_RATIO) >> idx, idx)
}

/// `enum rtw89_phy_status_bitmap`: the packet types with an IE bitmap.
const PHYSTS_BITMAP_NUM: u8 = 17;
const RSVD_9: u8 = 9;
const HE_MU: u8 = 6;
const VHT_MU: u8 = 7;
const TRIG_BASE_PPDU: u8 = 10;
const CCK_PKT: u8 = 11;
const HT_PKT: u8 = 13;
const VHT_PKT: u8 = 14;
const HE_PKT: u8 = 15;
const EHT_PKT: u8 = 16;
/// `enum rtw89_phy_status_ie_type`, the IEs the bitmaps name.
const IE01_CMN_OFDM: u32 = 1;
const IE04_CMN_EXT_PATH_A: u32 = 4;
const IE07_CMN_EXT_PATH_D: u32 = 7;
const IE09_FTR_0: u32 = 9;
const IE10_FTR_PLCP_EXT: u32 = 10;
const IE13_DL_MU_DEF: u32 = 13;
const IE20_DBG_OFDM_FD_USER_SEG_0: u32 = 20;

/// `rtw89_physts_ie_page_valid` on an AX chip: the bitmap's index, past
/// the reserved one, or `None`.
fn ie_page(page: u8) -> Option<u8> {
    match page {
        RSVD_9 | EHT_PKT.. => None,
        10..EHT_PKT => Some(page - 1),
        _ => Some(page),
    }
}

/// `rtw89_physts_parsing_init` with DBCC off: each packet type's PHY status
/// IE bitmap read and rewritten with the IEs rtw89 adds or drops, after
/// the reports of failed and broken PPDUs are turned off. `monitor` is
/// `IEEE80211_CONF_MONITOR`, which adds IE09 (and IE10 to MU) for
/// rtw89's radiotap.
pub fn physts_parsing_init<I: Io + ?Sized>(io: &mut I, monitor: bool) -> Result<(), Error> {
    let (mu_ies, su_ies) = if monitor {
        // physt_gen 0 is below 2: IE10 too.
        (1 << IE09_FTR_0 | 1 << IE10_FTR_PLCP_EXT, 1 << IE09_FTR_0)
    } else {
        (0, 0)
    };
    // rtw89_physts_enable_fail_report(false); rtw89_physts_enable_hdr_2
    // does nothing on an AX chip.
    io.phy_write32_set(PLCP_HISTOGRAM, STS_DIS_TRIG_BY_FAIL)?;
    io.phy_write32_set(PLCP_HISTOGRAM, STS_DIS_TRIG_BY_BRK)?;
    for i in 0..PHYSTS_BITMAP_NUM {
        let Some(page) = ie_page(i) else {
            continue;
        };
        let address = PHY_STS_BITMAP_ADDR_START + (u32::from(page) << 2);
        let mut val = io.phy_read32_mask(address, MASKDWORD)?;
        if i == HE_MU || i == VHT_MU {
            val |= 1 << IE13_DL_MU_DEF;
            val |= mu_ies;
        } else if i == TRIG_BASE_PPDU {
            val |= 1 << IE13_DL_MU_DEF | 1 << IE01_CMN_OFDM;
        } else if i >= CCK_PKT {
            val &= !genmask(IE07_CMN_EXT_PATH_D, IE04_CMN_EXT_PATH_A);
            if i == CCK_PKT {
                val |= 1 << IE01_CMN_OFDM;
            } else if i >= HT_PKT {
                val |= 1 << IE20_DBG_OFDM_FD_USER_SEG_0;
            }
        }
        if i == HE_PKT || i == VHT_PKT {
            val |= su_ies;
        }
        io.phy_write32_mask(address, MASKDWORD, val)?;
    }
    Ok(())
}

const fn genmask(high: u32, low: u32) -> u32 {
    (!0u32 >> (31 - high)) & (!0u32 << low)
}

/// `rssi_nolink`, `igi_rssi_th`, `fa_th_2g`, `fa_th_5g` and `fa_th_nolink`.
const RSSI_NOLINK: u8 = 22;
pub const IGI_RSSI_TH: [u8; 5] = [68, 84, 90, 98, 104];
pub const FA_TH_2G: [u16; 4] = [22, 44, 66, 88];
pub const FA_TH_5G: [u16; 4] = [4, 8, 12, 16];
pub const FA_TH_NOLINK: [u16; 4] = [196, 352, 440, 528];
/// `pd_low_th_offset`, `dynamic_igi_min`, `igi_max_performance_mode` and
/// `dynamic_pd_threshold_max`.
const PD_LOW_TH_OFFSET: u8 = 16;
const DYNAMIC_IGI_MIN: u8 = 0x20;
const IGI_MAX_PERFORMANCE_MODE: u8 = 0x5a;
const DYNAMIC_PD_THRESHOLD_MAX: u8 = 0;
/// `IGI_OFFSET_MAX`, `IGI_OFFSET_MUL`, `IGI_RSSI_MIN` and `ABS_IGI_MIN`.
const IGI_OFFSET_MAX: u8 = 25;
const IGI_OFFSET_MUL: i32 = 2;
const IGI_RSSI_MIN: i32 = 10;
const ABS_IGI_MIN: u8 = 0xc;
/// `IGI_RSSI_MAX`, `PD_TH_MAX_RSSI`, `PD_TH_MIN_RSSI`, `CCKPD_TH_MIN_RSSI`,
/// `PD_TH_SB_FLTR_CMP_VAL` and the bandwidths' `PD_TH_BW*_CMP_VAL`.
const IGI_RSSI_MAX: i32 = 110;
const PD_TH_MAX_RSSI: u8 = 70;
const PD_TH_MIN_RSSI: u8 = 8;
const CCKPD_TH_MIN_RSSI: i8 = -18;
const PD_TH_SB_FLTR_CMP_VAL: u8 = 7;
/// `RTW89_DIAG_BB_PD_MAX_PERIOD`.
const DIAG_BB_PD_MAX_PERIOD: u8 = 5;

/// `enum rtw89_dig_noisy_level`.
pub const DIG_NOISY_LEVEL0: i8 = -1;
pub const DIG_NOISY_LEVEL_MAX: i8 = 3;

/// `struct rtw89_dig_info` but its gain-code half, which an RTL8852B never
/// reaches, and `bb->diag`'s PD bit and count, which DIG sets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dig {
    /// `enum rtw89_dig_noisy_level`: -1 to 3.
    pub noisy_lv: i8,
    pub igi_rssi_th: [u8; 5],
    pub fa_th: [u16; 4],
    pub igi_rssi: u8,
    pub igi_fa_rssi: u8,
    pub fa_rssi_ofst: u8,
    pub dyn_igi_max: u8,
    pub dyn_igi_min: u8,
    pub dyn_pd_th_en: bool,
    pub dyn_pd_th_max: u8,
    pub dyn_pd_max_cnt: u8,
    pub pd_low_th_ofst: u8,
    pub bak_dig: u32,
    pub is_linked_pre: bool,
    pub bypass_dig: bool,
    pub pause_dig: bool,
    /// `diag_bb_bitmap`'s `RTW89_DIAG_BB_PD`: the PD floor stuck at its
    /// top with the air at its noisiest for five tracks while linked.
    pub diag_pd: bool,
    /// `diag_bb_cnt[RTW89_DIAG_BB_PD]`.
    pub diag_pd_cnt: u32,
}

impl Dig {
    /// `rtw89_phy_dig_update_rssi_info`.
    fn update_rssi_info(&mut self, link: Link) {
        self.igi_rssi = if link.linked() {
            link.rssi_min >> 1
        } else {
            RSSI_NOLINK
        };
    }

    /// `rtw89_phy_dig_update_para`: the false-alarm thresholds for the band
    /// and the link.
    fn update_para(&mut self, linked: bool, band: Band) {
        self.fa_th = match (band, linked) {
            (Band::Ghz2, true) => FA_TH_2G,
            (Band::Ghz5, true) => FA_TH_5G,
            (_, false) => FA_TH_NOLINK,
        };
        self.dyn_pd_th_en = true;
        self.igi_rssi_th = IGI_RSSI_TH;
    }

    /// `rtw89_phy_dig_para_reset` but the gain codes.
    fn para_reset(&mut self) {
        self.dyn_igi_max = IGI_MAX_PERFORMANCE_MODE;
        self.dyn_igi_min = DYNAMIC_IGI_MIN;
        self.dyn_pd_th_max = DYNAMIC_PD_THRESHOLD_MAX;
        self.dyn_pd_max_cnt = 0;
        self.pd_low_th_ofst = PD_LOW_TH_OFFSET;
        self.is_linked_pre = false;
    }

    /// `rtw89_phy_dig_igi_offset_by_env`: the noise level the false-alarm
    /// permils give, and the offset it moves.
    fn igi_offset_by_env(&mut self, env: &EnvMonitor) {
        let fa_ratio = env
            .ifs_clm_cck_fa_permil
            .wrapping_add(env.ifs_clm_ofdm_fa_permil);
        let noisy_lv = if fa_ratio < self.fa_th[0] {
            DIG_NOISY_LEVEL0
        } else if fa_ratio < self.fa_th[1] {
            0
        } else if fa_ratio < self.fa_th[2] {
            1
        } else if fa_ratio < self.fa_th[3] {
            2
        } else {
            DIG_NOISY_LEVEL_MAX
        };
        let mut igi_offset = self.fa_rssi_ofst;
        if noisy_lv == DIG_NOISY_LEVEL0 && igi_offset < 2 {
            igi_offset = 0;
        } else {
            igi_offset = (i32::from(igi_offset) + i32::from(noisy_lv) * IGI_OFFSET_MUL) as u8;
        }
        self.fa_rssi_ofst = igi_offset.min(IGI_OFFSET_MAX);
        self.noisy_lv = noisy_lv;
    }

    /// `rtw89_phy_dig_cal_under_region` on an AX chip.
    fn under_region(&self, width: Bandwidth) -> u8 {
        self.pd_low_th_ofst
            .wrapping_add(PD_TH_SB_FLTR_CMP_VAL)
            .wrapping_add(match width {
                Bandwidth::Mhz20 => 0,
                Bandwidth::Mhz40 => 3,
                Bandwidth::Mhz80 => 6,
            })
    }

    /// `__rtw89_phy_dig_dyn_pd_th`: the OFDM PD floor for `rssi`.
    fn dyn_pd_th_value(&mut self, rssi: u8, enable: bool, width: Bandwidth) -> u32 {
        let under_region = self.under_region(width);
        self.dyn_pd_th_max = self.igi_rssi;
        let final_rssi = rssi.min(self.igi_rssi);
        let low = PD_TH_MIN_RSSI.wrapping_add(under_region);
        let high = PD_TH_MAX_RSSI.wrapping_add(under_region);
        let ofdm_cca_th = final_rssi.max(low).min(high);
        if enable {
            ((i32::from(ofdm_cca_th) - i32::from(under_region) - i32::from(PD_TH_MIN_RSSI)) >> 1)
                as u32
        } else {
            0
        }
    }

    /// `rtw89_phy_dig_dyn_pd_th` with no fixed thresholds: the OFDM floor,
    /// then the CCK one where the cut has CCK PD.
    fn dyn_pd_th<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        rssi: u8,
        enable: bool,
        width: Bandwidth,
        cckpd: bool,
    ) -> Result<(), Error> {
        let pd_val = self.dyn_pd_th_value(rssi, enable, width);
        self.bak_dig = pd_val;
        io.phy_write32_mask(SEG0R_PD_V1, SEG0R_PD_LOWER_BOUND_MSK, pd_val)?;
        io.phy_write32_mask(
            SEG0R_PD_V1,
            SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1,
            u32::from(enable),
        )?;
        if !cckpd {
            return Ok(());
        }
        let final_rssi = rssi.min(self.igi_rssi);
        let under_region = self.under_region(width);
        let cck_cca_th =
            ((i32::from(final_rssi) - i32::from(under_region)) as i8).max(CCKPD_TH_MIN_RSSI);
        let pd_val = (i32::from(cck_cca_th) - IGI_RSSI_MAX) as u32;
        io.phy_write32_mask(
            BMODE_PDTH_EN_V1,
            BMODE_PDTH_LIMIT_EN_MSK_V1,
            u32::from(enable),
        )?;
        io.phy_write32_mask(BMODE_PDTH_V1, BMODE_PDTH_LOWER_BOUND_MSK_V1, pd_val)
    }

    /// `rtw89_phy_dig_diag`.
    fn diag(&mut self, linked: bool) {
        self.diag_pd = false;
        if self.dyn_igi_max != self.igi_fa_rssi || self.noisy_lv < DIG_NOISY_LEVEL_MAX {
            self.dyn_pd_max_cnt = 0;
            return;
        }
        self.dyn_pd_max_cnt = self.dyn_pd_max_cnt.wrapping_add(1);
        if self.dyn_pd_max_cnt < DIAG_BB_PD_MAX_PERIOD || !linked {
            return;
        }
        self.diag_pd = true;
        self.diag_pd_cnt = self.diag_pd_cnt.wrapping_add(1);
    }

    /// `rtw89_phy_cal_igi_fa_rssi`.
    fn cal_igi_fa_rssi(&mut self, env: &EnvMonitor, linked: bool) {
        self.igi_offset_by_env(env);
        let igi_min = (i32::from(self.igi_rssi) - IGI_RSSI_MIN).max(0) as u8;
        self.dyn_igi_max = (i32::from(igi_min) + i32::from(IGI_OFFSET_MAX))
            .min(i32::from(IGI_MAX_PERFORMANCE_MODE)) as u8;
        self.dyn_igi_min = igi_min.max(ABS_IGI_MIN);
        if self.dyn_igi_max >= self.dyn_igi_min {
            let rssi = self.igi_fa_rssi.wrapping_add(self.fa_rssi_ofst);
            self.igi_fa_rssi = rssi.max(self.dyn_igi_min).min(self.dyn_igi_max);
        } else {
            self.igi_fa_rssi = self.dyn_igi_max;
        }
        self.diag(linked);
    }
}

/// `rtw89_phy_dig_sdagc_follow_pagc_config` on an AX chip.
fn sdagc_follow_pagc_config<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), Error> {
    for register in PAGCUGC_EN {
        io.phy_write32_mask(register, PAGCUGC_EN_MSK, u32::from(enable))?;
    }
    Ok(())
}

/// `enum rtw89_phy_cfo_status`.
pub const DCFO_STATE_NORMAL: u8 = 0;
pub const DCFO_STATE_ENHANCE: u8 = 1;
pub const DCFO_STATE_HOLD: u8 = 2;
/// `CFO_TRK_ENABLE_TH`, `CFO_TRK_STOP_TH_4` to `_1` and `CFO_TRK_STOP_TH`,
/// in rtw89's quarter-kHz CFO units.
const CFO_TRK_ENABLE_TH: i32 = 2 << 2;
const CFO_TRK_STOP_TH_4: i32 = 30 << 2;
const CFO_TRK_STOP_TH_3: i32 = 20 << 2;
const CFO_TRK_STOP_TH_2: i32 = 10 << 2;
const CFO_TRK_STOP_TH_1: i32 = 3 << 2;
const CFO_TRK_STOP_TH: i32 = 2 << 2;
/// `CFO_SW_COMP_FINE_TUNE`, `CFO_PERIOD_CNT`, `CFO_BOUND`, `CFO_TP_UPPER`,
/// `CFO_TP_LOWER`, `CFO_COMP_PERIOD` and `CFO_TF_CNT_TH`.
const CFO_SW_COMP_FINE_TUNE: i32 = 2 << 2;
const CFO_PERIOD_CNT: u8 = 15;
const CFO_BOUND: i32 = 64;
const CFO_TP_UPPER: u32 = 100;
const CFO_TP_LOWER: u32 = 50;
const CFO_COMP_PERIOD: u16 = 250;
const CFO_TF_CNT_TH: u32 = 300;
/// RTL8852B's `dcfo_comp_sft`.
const DCFO_COMP_SFT: u32 = 10;

/// `struct rtw89_cfo_tracking_info` as far as an RTL8852B reaches it:
/// `cfo_ul_ofdma_acc_mode` stays `RTW89_CFO_UL_OFDMA_ACC_ENABLE`,
/// `rtw89_multi_cfo_mode` the throughput-based mode and
/// `sta_cfo_tolerance` 0, and `apply_compensation` and `residual_cfo_acc`,
/// which nothing reads, are left out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cfo {
    pub cfo_timer_ms: u16,
    pub cfo_trig_by_timer_en: bool,
    /// `DCFO_STATE_*`.
    pub phy_cfo_status: u8,
    pub phy_cfo_trk_cnt: u8,
    pub is_adjust: bool,
    pub crystal_cap: u8,
    pub crystal_cap_default: u8,
    pub def_x_cap: u8,
    pub x_cap_ofst: i8,
    pub cfo_tail: [i32; CFO_TRACK_MAX_USER],
    pub cfo_cnt: [u16; CFO_TRACK_MAX_USER],
    pub cfo_avg_pre: i32,
    pub cfo_avg: [i32; CFO_TRACK_MAX_USER],
    pub pre_cfo_avg: [i32; CFO_TRACK_MAX_USER],
    pub dcfo_avg: i32,
    pub dcfo_avg_pre: i32,
    pub packet_count: u32,
    pub packet_count_pre: u32,
    pub divergence_lock_en: bool,
    pub x_cap_lb: u8,
    pub x_cap_ub: u8,
    pub lock_cnt: u8,
    /// Stela's own: XTAL SI requests the chip never answered, which rtw89
    /// warns of and goes on from.
    pub xtal_timeouts: u32,
}

impl Default for Cfo {
    fn default() -> Self {
        Self {
            cfo_timer_ms: 0,
            cfo_trig_by_timer_en: false,
            phy_cfo_status: DCFO_STATE_NORMAL,
            phy_cfo_trk_cnt: 0,
            is_adjust: false,
            crystal_cap: 0,
            crystal_cap_default: 0,
            def_x_cap: 0,
            x_cap_ofst: 0,
            cfo_tail: [0; CFO_TRACK_MAX_USER],
            cfo_cnt: [0; CFO_TRACK_MAX_USER],
            cfo_avg_pre: 0,
            cfo_avg: [0; CFO_TRACK_MAX_USER],
            pre_cfo_avg: [0; CFO_TRACK_MAX_USER],
            dcfo_avg: 0,
            dcfo_avg_pre: 0,
            packet_count: 0,
            packet_count_pre: 0,
            divergence_lock_en: false,
            x_cap_lb: 0,
            x_cap_ub: 0,
            lock_cnt: 0,
            xtal_timeouts: 0,
        }
    }
}

/// `phy_div`: 0 for a zero divisor.
const fn phy_div(a: i32, b: i32) -> i32 {
    if b != 0 { a.wrapping_div(b) } else { 0 }
}

impl Cfo {
    /// `rtw89_mac_write_xtal_si`, a timeout counted.
    fn write_xtal<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        offset: u8,
        value: u8,
    ) -> Result<(), Error> {
        match io.write_xtal_si(offset, value, XTAL_SC_MASK) {
            Err(Error::Timeout { .. }) => {
                self.xtal_timeouts = self.xtal_timeouts.wrapping_add(1);
                Ok(())
            }
            other => other,
        }
    }

    /// `rtw89_mac_read_xtal_si`, a timeout counted and read as 0, the
    /// value rtw89 leaves unset.
    fn read_xtal<I: Io + ?Sized>(&mut self, io: &mut I, offset: u8) -> Result<u8, Error> {
        match io.read_xtal_si(offset) {
            Err(Error::Timeout { .. }) => {
                self.xtal_timeouts = self.xtal_timeouts.wrapping_add(1);
                Ok(0)
            }
            other => other,
        }
    }

    /// `rtw89_phy_cfo_set_crystal_cap` for an RTL8852B: SC_XO and SC_XI
    /// through XTAL SI, then both read back.
    fn set_crystal_cap<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        crystal_cap: u8,
        force: bool,
    ) -> Result<(), Error> {
        if !force && self.crystal_cap == crystal_cap {
            return Ok(());
        }
        self.write_xtal(io, XTAL_SI_XTAL_SC_XO, crystal_cap)?;
        self.write_xtal(io, XTAL_SI_XTAL_SC_XI, crystal_cap)?;
        let _sc_xo = self.read_xtal(io, XTAL_SI_XTAL_SC_XO)?;
        let sc_xi = self.read_xtal(io, XTAL_SI_XTAL_SC_XI)?;
        self.crystal_cap = sc_xi;
        self.x_cap_ofst = (i32::from(self.crystal_cap) - i32::from(self.def_x_cap)) as i8;
        Ok(())
    }

    /// `rtw89_phy_cfo_reset`: a step back toward the default cap.
    fn reset<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.def_x_cap = self.crystal_cap_default & AX_XTAL_SC_MASK;
        self.is_adjust = false;
        if self.crystal_cap == self.def_x_cap {
            return Ok(());
        }
        let cap = if self.crystal_cap > self.def_x_cap {
            self.crystal_cap.wrapping_sub(1)
        } else {
            self.crystal_cap.wrapping_add(1)
        };
        self.set_crystal_cap(io, cap, false)
    }

    /// `rtw89_phy_cfo_init`, from the efuse's crystal cap (`xtal_k`).
    pub fn init<I: Io + ?Sized>(&mut self, io: &mut I, xtal_cap: u8) -> Result<(), Error> {
        self.crystal_cap_default = xtal_cap & AX_XTAL_SC_MASK;
        self.crystal_cap = self.crystal_cap_default;
        self.def_x_cap = self.crystal_cap;
        self.x_cap_ub = (i32::from(self.def_x_cap) + CFO_BOUND).min(0x7f) as u8;
        self.x_cap_lb = (i32::from(self.def_x_cap) - CFO_BOUND).max(0x1) as u8;
        self.is_adjust = false;
        self.divergence_lock_en = false;
        self.x_cap_ofst = 0;
        self.lock_cnt = 0;
        self.set_crystal_cap(io, self.crystal_cap_default, true)?;
        // rtw89_dcfo_comp_init with RTL8852B's cfo_hw_comp.
        io.phy_write32_mask(DCFO_OPT, DCFO_OPT_EN, 1)?;
        io.phy_write32_mask(DCFO_WEIGHT, DCFO_WEIGHT_MSK, 8)?;
        io.write32_mask(PWR_UL_CTRL2, PWR_UL_CFO_MASK, 0x6)?;
        self.cfo_timer_ms = 2000;
        self.cfo_trig_by_timer_en = false;
        self.phy_cfo_trk_cnt = 0;
        self.phy_cfo_status = DCFO_STATE_NORMAL;
        Ok(())
    }

    /// `rtw89_phy_cfo_parse`: one PPDU's CFO for the MAC ID it came from;
    /// false for a MAC ID past `CFO_TRACK_MAX_USER`, which rtw89 warns of.
    pub fn parse(&mut self, cfo: i16, mac_id: u8) -> bool {
        let Some(tail) = self.cfo_tail.get_mut(usize::from(mac_id)) else {
            return false;
        };
        *tail = tail.wrapping_add(i32::from(cfo));
        let count = &mut self.cfo_cnt[usize::from(mac_id)];
        *count = count.wrapping_add(1);
        self.packet_count = self.packet_count.wrapping_add(1);
        true
    }

    /// `rtw89_dcfo_comp` with RTL8852B's `dcfo_comp`.
    fn dcfo_comp<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        linked: bool,
        curr_cfo: i32,
    ) -> Result<(), Error> {
        if !linked || curr_cfo == 0 {
            return Ok(());
        }
        let dcfo_comp_val = io.phy_read32_mask(DCFO, DCFO_MSK)? as i32;
        let sign = if curr_cfo > 0 { 1 } else { -1 };
        let cfo_avg_312 = (curr_cfo / 625).wrapping_add(sign * dcfo_comp_val);
        io.phy_write32_mask(DCFO_COMP_S0, DCFO_COMP_S0_MSK, cfo_avg_312 as u32)
    }

    /// `rtw89_phy_cfo_crystal_cap_adjust`.
    fn crystal_cap_adjust<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        curr_cfo: i32,
    ) -> Result<(), Error> {
        let cfo_abs = curr_cfo.wrapping_abs();
        if curr_cfo == 0 {
            return Ok(());
        }
        if !self.is_adjust {
            if cfo_abs > CFO_TRK_ENABLE_TH {
                self.is_adjust = true;
            }
        } else if cfo_abs <= CFO_TRK_STOP_TH {
            self.is_adjust = false;
        }
        if !self.is_adjust {
            return Ok(());
        }
        let sign = if curr_cfo > 0 { 1 } else { -1 };
        let step = if cfo_abs > CFO_TRK_STOP_TH_4 || cfo_abs > CFO_TRK_STOP_TH_3 {
            3
        } else if cfo_abs > CFO_TRK_STOP_TH_2 || cfo_abs > CFO_TRK_STOP_TH_1 {
            1
        } else {
            return Ok(());
        };
        let crystal_cap = (i32::from(self.crystal_cap) + step * sign).clamp(0, 127);
        self.set_crystal_cap(io, crystal_cap as u8, false)
    }

    /// `rtw89_phy_average_cfo_calc`: one station's average CFO.
    fn average_cfo_calc(&mut self, stations: u8) -> i32 {
        let mut cfo_khz_all = 0i32;
        let mut cfo_cnt_all = 0i32;
        let mut cfo_all_avg = 0;
        if stations != 1 {
            return 0;
        }
        for i in 0..CFO_TRACK_MAX_USER {
            if self.cfo_cnt[i] == 0 {
                continue;
            }
            cfo_khz_all = cfo_khz_all.wrapping_add(self.cfo_tail[i]);
            cfo_cnt_all = cfo_cnt_all.wrapping_add(i32::from(self.cfo_cnt[i]));
            cfo_all_avg = phy_div(cfo_khz_all, cfo_cnt_all);
            self.pre_cfo_avg[i] = self.cfo_avg[i];
            self.dcfo_avg = phy_div(cfo_khz_all.wrapping_shl(DCFO_COMP_SFT), cfo_cnt_all);
        }
        cfo_all_avg
    }

    /// `rtw89_phy_multi_sta_cfo_calc` in the throughput-based mode, with no
    /// per-station throughput (rtw89 has none yet) and tolerance 0.
    fn multi_sta_cfo_calc(&mut self, stations: u8, rx_throughput: u32) -> i32 {
        let cfo_tol = 0i32;
        let mut cfo_khz_all = 0i32;
        let mut max_cfo_lb = i32::MIN;
        let mut min_cfo_ub = i32::MAX;
        let mut sta_cnt = 0u8;
        for i in 0..CFO_TRACK_MAX_USER {
            sta_cnt = sta_cnt.wrapping_add(1);
            self.cfo_avg[i] = if self.cfo_cnt[i] != 0 {
                phy_div(self.cfo_tail[i], i32::from(self.cfo_cnt[i]))
            } else {
                self.pre_cfo_avg[i]
            };
            max_cfo_lb = self.cfo_avg[i].wrapping_sub(cfo_tol).max(max_cfo_lb);
            min_cfo_ub = self.cfo_avg[i].wrapping_add(cfo_tol).min(min_cfo_ub);
            cfo_khz_all = cfo_khz_all.wrapping_add(self.cfo_avg[i]);
            if sta_cnt >= stations {
                break;
            }
        }
        // cfo_khz_all_tp_wgt stays 0.
        let cfo_avg = phy_div(0, rx_throughput as i32);
        let target_cfo = if max_cfo_lb <= min_cfo_ub {
            cfo_avg.max(max_cfo_lb).min(min_cfo_ub)
        } else {
            phy_div(cfo_khz_all, i32::from(sta_cnt))
        };
        self.pre_cfo_avg = self.cfo_avg;
        target_cfo
    }

    /// `rtw89_phy_cfo_statistics_reset`.
    fn statistics_reset(&mut self) {
        self.cfo_tail = [0; CFO_TRACK_MAX_USER];
        self.cfo_cnt = [0; CFO_TRACK_MAX_USER];
        self.packet_count = 0;
        self.packet_count_pre = 0;
        self.cfo_avg_pre = 0;
    }

    /// `rtw89_phy_cfo_dm`: the CFO gathered since the last run applied to
    /// the crystal cap and the digital compensation.
    fn dm<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        traffic: Traffic,
    ) -> Result<(), Error> {
        let pre_x_cap = self.crystal_cap;
        self.dcfo_avg = 0;
        if link.stations == 0 {
            return self.reset(io);
        }
        if self.packet_count == 0 || self.packet_count == self.packet_count_pre {
            return Ok(());
        }
        let new_cfo = if link.stations == 1 {
            self.average_cfo_calc(link.stations)
        } else {
            self.multi_sta_cfo_calc(link.stations, traffic.rx_throughput)
        };
        if self.divergence_lock_en {
            self.lock_cnt = self.lock_cnt.wrapping_add(1);
            if self.lock_cnt > CFO_PERIOD_CNT {
                self.divergence_lock_en = false;
                self.lock_cnt = 0;
            } else {
                self.reset(io)?;
            }
            return Ok(());
        }
        if self.crystal_cap >= self.x_cap_ub || self.crystal_cap <= self.x_cap_lb {
            self.divergence_lock_en = true;
            return self.reset(io);
        }
        self.crystal_cap_adjust(io, new_cfo)?;
        self.cfo_avg_pre = new_cfo;
        self.dcfo_avg_pre = self.dcfo_avg;
        if self.crystal_cap != pre_x_cap {
            let fine = CFO_SW_COMP_FINE_TUNE << DCFO_COMP_SFT;
            self.dcfo_avg = if self.dcfo_avg > 0 {
                self.dcfo_avg.wrapping_sub(fine)
            } else {
                self.dcfo_avg.wrapping_add(fine)
            };
        }
        self.dcfo_comp(io, link.linked(), self.dcfo_avg)?;
        self.statistics_reset();
        Ok(())
    }

    /// `rtw89_phy_cfo_track`: the state the TX throughput and trigger
    /// frames give, then the CFO applied unless the 250 ms timer applies
    /// it. The delay, in ms, after which rtw89 queues
    /// `rtw89_phy_cfo_track_work`, when it does.
    pub fn track<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        traffic: Traffic,
    ) -> Result<Option<u16>, Error> {
        let ofdma_acc_en = traffic.rx_tf_periodic > CFO_TF_CNT_TH;
        let mut queued = None;
        match self.phy_cfo_status {
            DCFO_STATE_NORMAL => {
                if traffic.tx_throughput >= CFO_TP_UPPER {
                    self.phy_cfo_status = DCFO_STATE_ENHANCE;
                    self.cfo_trig_by_timer_en = true;
                    self.cfo_timer_ms = CFO_COMP_PERIOD;
                    queued = Some(self.cfo_timer_ms);
                }
            }
            DCFO_STATE_ENHANCE => {
                if traffic.tx_throughput <= CFO_TP_LOWER {
                    self.phy_cfo_status = DCFO_STATE_NORMAL;
                } else if ofdma_acc_en && self.phy_cfo_trk_cnt >= CFO_PERIOD_CNT {
                    self.phy_cfo_status = DCFO_STATE_HOLD;
                } else {
                    self.phy_cfo_trk_cnt = self.phy_cfo_trk_cnt.wrapping_add(1);
                }
                if self.phy_cfo_status == DCFO_STATE_NORMAL {
                    self.phy_cfo_trk_cnt = 0;
                    self.cfo_trig_by_timer_en = false;
                }
            }
            DCFO_STATE_HOLD => {
                if traffic.tx_throughput <= CFO_TP_LOWER {
                    self.phy_cfo_status = DCFO_STATE_NORMAL;
                    self.phy_cfo_trk_cnt = 0;
                    self.cfo_trig_by_timer_en = false;
                } else {
                    self.phy_cfo_trk_cnt = self.phy_cfo_trk_cnt.wrapping_add(1);
                }
            }
            _ => {
                self.phy_cfo_status = DCFO_STATE_NORMAL;
                self.phy_cfo_trk_cnt = 0;
            }
        }
        if self.cfo_trig_by_timer_en {
            return Ok(queued);
        }
        self.dm(io, link, traffic)?;
        Ok(queued)
    }

    /// `rtw89_phy_cfo_track_work`: nothing once the timer is off;
    /// otherwise `leave_ps` (`rtw89_leave_ps_mode`), the CFO applied, and
    /// the delay after which the work runs again.
    pub fn track_work<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        traffic: Traffic,
        leave_ps: impl FnOnce(&mut I) -> Result<(), Error>,
    ) -> Result<Option<u16>, Error> {
        if !self.cfo_trig_by_timer_en {
            return Ok(None);
        }
        leave_ps(io)?;
        self.dm(io, link, traffic)?;
        Ok(Some(self.cfo_timer_ms))
    }
}

/// What rtw89 keeps in `rtwdev->bbs[RTW89_PHY_0]` and `rtwdev` for the
/// tracking here, with `hal.support_cckpd`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dynamic {
    pub env: EnvMonitor,
    pub dig: Dig,
    pub cfo: Cfo,
    /// `hal.support_cckpd`: an RTL8852B past cut CAV.
    pub cckpd: bool,
}

impl Dynamic {
    /// What `rtw89_phy_dm_init` runs of the tracking, in its order:
    /// `rtw89_phy_env_monitor_init`, `rtw89_physts_parsing_init`,
    /// `rtw89_phy_dig_init` and `rtw89_phy_cfo_init`, for the chip's cut
    /// `cv`, the efuse's crystal cap and the channel tuned, with no station
    /// associated.
    pub fn init<I: Io + ?Sized>(
        io: &mut I,
        cv: u8,
        xtal_cap: u8,
        channel: Channel,
        monitor: bool,
    ) -> Result<Self, Error> {
        let mut dynamic = Self {
            cckpd: cv > CHIP_CAV,
            ..Self::default()
        };
        dynamic.env.init(io)?;
        physts_parsing_init(io, monitor)?;
        dynamic.dig_reset(io, channel)?;
        dynamic.cfo.init(io, xtal_cap)?;
        Ok(dynamic)
    }

    /// `rtw89_phy_dm_reinit`, which `rtw89_leave_ips` runs: the environment
    /// monitor and the PHY status bitmaps again.
    pub fn reinit<I: Io + ?Sized>(&mut self, io: &mut I, monitor: bool) -> Result<(), Error> {
        self.env.init(io)?;
        physts_parsing_init(io, monitor)
    }

    /// `rtw89_phy_dig_reset`, which `__rtw89_phy_dig_init` runs after the
    /// gain parameters an RTL8852B does not read.
    fn dig_reset<I: Io + ?Sized>(&mut self, io: &mut I, channel: Channel) -> Result<(), Error> {
        let dig = &mut self.dig;
        dig.bypass_dig = false;
        dig.para_reset();
        dig.dyn_pd_th(io, RSSI_NOLINK, false, channel.width, self.cckpd)?;
        sdagc_follow_pagc_config(io, false)?;
        dig.update_para(false, channel.band);
        Ok(())
    }

    /// `rtw89_phy_env_monitor_track`.
    pub fn env_monitor_track<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.env.track(io)
    }

    /// `rtw89_phy_dig`: the PD floors for the link's RSSI and the last
    /// window's false alarms, on the channel tuned.
    pub fn dig<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        channel: Channel,
    ) -> Result<(), Error> {
        let dig = &mut self.dig;
        let linked = link.linked();
        if dig.bypass_dig {
            dig.bypass_dig = false;
            return Ok(());
        }
        dig.update_rssi_info(link);
        if dig.pause_dig {
            return Ok(());
        }
        if dig.is_linked_pre != linked {
            // First connected, or first disconnected.
            dig.update_para(linked, channel.band);
            dig.igi_fa_rssi = dig.igi_rssi;
        }
        dig.is_linked_pre = linked;
        dig.cal_igi_fa_rssi(&self.env, linked);
        let rssi = dig.igi_fa_rssi;
        let enable = dig.dyn_pd_th_en;
        dig.dyn_pd_th(io, rssi, enable, channel.width, self.cckpd)?;
        let follow = dig.dyn_pd_th_en && dig.igi_fa_rssi > dig.dyn_pd_th_max;
        sdagc_follow_pagc_config(io, follow)
    }

    /// `rtw89_phy_dig_ctrl`, for `rtw89_phy_dig_suspend` (`pause`) and
    /// `rtw89_phy_dig_resume`.
    fn dig_ctrl<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        pause: bool,
        restore: bool,
        linked: bool,
    ) -> Result<(), Error> {
        let dig = &mut self.dig;
        if dig.pause_dig == pause {
            return Ok(());
        }
        let (en_dig, pd_val) = if pause {
            (false, 0)
        } else {
            (linked, if restore { dig.bak_dig } else { 0 })
        };
        io.phy_write32_mask(SEG0R_PD_V1, SEG0R_PD_LOWER_BOUND_MSK, pd_val)?;
        io.phy_write32_mask(
            SEG0R_PD_V1,
            SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1,
            u32::from(en_dig),
        )?;
        dig.pause_dig = pause;
        Ok(())
    }

    /// `rtw89_phy_dig_suspend`, which rtw89 runs when a station is added
    /// to a client interface, at a hardware scan's start and on a
    /// remain-on-channel: the OFDM PD floor at 0.
    pub fn dig_suspend<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        self.dig_ctrl(io, true, false, false)
    }

    /// `rtw89_phy_dig_resume`: the floor back, the one DIG last set when
    /// `restore` (after a scan or a remain-on-channel), 0 otherwise (once
    /// associated).
    pub fn dig_resume<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        restore: bool,
    ) -> Result<(), Error> {
        self.dig_ctrl(io, false, restore, link.linked())
    }

    /// What `rtw89_core_scan_complete` does for DIG: the next track is
    /// skipped (`bypass_dig`).
    pub fn scan_complete(&mut self) {
        self.dig.bypass_dig = true;
    }

    /// `rtw89_phy_cfo_track`.
    pub fn cfo_track<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        traffic: Traffic,
    ) -> Result<Option<u16>, Error> {
        self.cfo.track(io, link, traffic)
    }

    /// `rtw89_phy_cfo_track_work`.
    pub fn cfo_track_work<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        link: Link,
        traffic: Traffic,
        leave_ps: impl FnOnce(&mut I) -> Result<(), Error>,
    ) -> Result<Option<u16>, Error> {
        self.cfo.track_work(io, link, traffic, leave_ps)
    }

    /// `rtw89_phy_cfo_parse`, for each A1-matched PPDU status that carried
    /// a CFO ([`super::rxdesc::PhyPpdu::cfo`]).
    pub fn cfo_parse(&mut self, cfo: i16, mac_id: u8) -> bool {
        self.cfo.parse(cfo, mac_id)
    }
}
