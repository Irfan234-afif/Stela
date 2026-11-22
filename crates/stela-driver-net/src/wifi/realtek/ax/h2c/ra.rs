// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! Rate adaptation and the Block Ack CAM of an RTL8852B, as pinned rtw89
//! builds them (phy.c, fw.c, core.c):
//!
//! - [`Ra::assoc`]: `rtw89_phy_ra_assoc`, with `rtw89_phy_ra_sta_update`
//!   ([`RaInfo::sta_update`]) and its mask helpers (`get_mcs_ra_mask`,
//!   `get_he_ra_mask`, [`ra_mask_rssi`], [`ra_mask_recover`],
//!   `rtw89_phy_ra_gi_ltf`), from what it reads of the peer's
//!   `ieee80211_link_sta` ([`LinkSta`], which [`LinkSta::from_negotiated`]
//!   takes from the station's negotiation) and of its own link ([`Link`]).
//!   [`Ra::update`] is `rtw89_phy_ra_update_sta_link`. [`Ra::payload`] and
//!   [`Ra::send`] are `rtw89_fw_h2c_ra` on an AX chip: `struct rtw89_h2c_ra`,
//!   sent as OUTSRC class RA, function MACIDCFG, asking no ack;
//! - [`RaReport::parse`]: `__rtw89_phy_c2h_ra_rpt_iter` of a report
//!   [`super::super::c2h::C2h::ra_report`] read, into `rate_info` terms and
//!   the bit rate ([`bit_rate::rate_info`]), `hw_rate`,
//!   `might_fallback_legacy`, and through [`max_amsdu_len`] the A-MSDU the
//!   rate may carry (`get_max_amsdu_len`, `max_agg_wait`);
//! - [`BaCam`]: `rtw89_core_acquire_sta_ba_entry` and
//!   `rtw89_core_release_sta_ba_entry` over the RTL8852B's two static
//!   entries, and [`BaCam::send`], `rtw89_fw_h2c_ba_cam` as an RX Block Ack
//!   session starts or stops (`IEEE80211_AMPDU_RX_START`/`_STOP`), in its
//!   `RTW89_BACAM_V0` form.
//!
//! What this leaves out, and why:
//! - `cfg80211_bitrate_mask` (`use_cfg_mask`, `rtw89_phy_ra_mask_cfg`) and
//!   the vif's rate pattern: nothing in Stela sets a bitrate mask, so the
//!   mask stays all ones and the pattern off, as rtw89 leaves them.
//! - EHT, the BE chips' `rtw89_h2c_ra_v1` and the RA report's `format_v1`
//!   bits: an RTL8852B is an AX chip with neither.
//! - `RTW89_FW_FEATURE_OLD_HT_RA_FORMAT`: rtw89 sets it for RTL8852A
//!   firmware alone, so an HT report's rate is `RTW89_RA_RATE_MASK_HT_MCS`.
//! - `rtw89_fw_h2c_init_ba_cam_users` and `rtw89_fw_h2c_init_dynamic_ba_cam_v0_ext`:
//!   rtw89 sends them for `RTW89_BACAM_V1` and `RTW89_BACAM_V0_EXT` chips
//!   only (`rtw89_mac_feat_init`, `rtw89_fw_h2c_init_ba_cam`); an RTL8852B is
//!   `RTW89_BACAM_V0`, whose dynamic entries the hardware makes itself.
//! - `ieee80211_sta_recalc_aggregates`: what the station does with
//!   [`RaReport::max_amsdu_len`] is the caller's.
//!
//! A command built proves what rtw89 would have sent, nothing about what
//! the firmware's rate adaptation then picks.
use super::{Error, phy::Outsrc};
use crate::wifi::{
    Band,
    realtek::{
        ax::{
            c2h::RaRpt,
            io::{Io, prep},
            mac::Commands,
        },
        bit_rate::{self, HeGi, Rate},
    },
    station::phy::{Mode, Negotiated, Width},
};

/// `H2C_CL_OUTSRC_RA` and `H2C_FUNC_OUTSRC_RA_MACIDCFG`.
pub const H2C_CL_OUTSRC_RA: u8 = 0x1;
pub const H2C_FUNC_OUTSRC_RA_MACIDCFG: u8 = 0x0;
/// `H2C_CL_BA_CAM` and `H2C_FUNC_MAC_BA_CAM`.
pub const H2C_CL_BA_CAM: u8 = 0xc;
pub const H2C_FUNC_MAC_BA_CAM: u8 = 0x0;

/// `sizeof(struct rtw89_h2c_ra)` and `sizeof(struct rtw89_h2c_ba_cam)`.
pub const RA_LEN: usize = 16;
pub const BA_CAM_LEN: usize = 8;

/// `RTW89_H2C_RA_W0_*`.
pub const RA_W0_MODE: u32 = 0x0000_003e;
pub const RA_W0_BW_CAP: u32 = 0x0000_00c0;
pub const RA_W0_MACID: u32 = 0x0000_ff00;
pub const RA_W0_DCM: u32 = 1 << 16;
pub const RA_W0_ER: u32 = 1 << 17;
pub const RA_W0_INIT_RATE_LV: u32 = 0x000c_0000;
pub const RA_W0_UPD_ALL: u32 = 1 << 20;
pub const RA_W0_SGI: u32 = 1 << 21;
pub const RA_W0_LDPC: u32 = 1 << 22;
pub const RA_W0_STBC: u32 = 1 << 23;
pub const RA_W0_SS_NUM: u32 = 0x0700_0000;
pub const RA_W0_GILTF: u32 = 0x3800_0000;
pub const RA_W0_UPD_BW_NSS_MASK: u32 = 1 << 30;
pub const RA_W0_UPD_MASK: u32 = 1 << 31;
/// `RTW89_H2C_RA_W2_RAMASK_HI32` (bits 30:0, so the mask's bit 63 is never
/// sent) and `RTW89_H2C_RA_W2_BFEE_CSI_CTL`.
pub const RA_W2_RAMASK_HI32: u32 = 0x7fff_ffff;
pub const RA_W2_BFEE_CSI_CTL: u32 = 1 << 31;
/// `RTW89_H2C_RA_W3_*`.
pub const RA_W3_BAND_NUM: u32 = 0x0000_00ff;
pub const RA_W3_RA_CSI_RATE_EN: u32 = 1 << 8;
pub const RA_W3_FIXED_CSI_RATE_EN: u32 = 1 << 9;
pub const RA_W3_CR_TBL_SEL: u32 = 1 << 10;
pub const RA_W3_FIX_GILTF_EN: u32 = 1 << 11;
pub const RA_W3_FIX_GILTF: u32 = 0x0000_7000;
pub const RA_W3_FIXED_CSI_MCS_SS_IDX: u32 = 0x00ff_0000;
pub const RA_W3_FIXED_CSI_MODE: u32 = 0x0300_0000;
pub const RA_W3_FIXED_CSI_GI_LTF: u32 = 0x1c00_0000;
pub const RA_W3_FIXED_CSI_BW: u32 = 0xe000_0000;
/// `RTW89_H2C_BA_CAM_W0_*`; `W1` is the V0_EXT and V1 chips'.
pub const BA_CAM_W0_VALID: u32 = 1 << 0;
pub const BA_CAM_W0_INIT_REQ: u32 = 1 << 1;
pub const BA_CAM_W0_ENTRY_IDX: u32 = 0x0000_000c;
pub const BA_CAM_W0_TID: u32 = 0x0000_00f0;
pub const BA_CAM_W0_MACID: u32 = 0x0000_ff00;
pub const BA_CAM_W0_BMAP_SIZE: u32 = 0x000f_0000;
pub const BA_CAM_W0_SSN: u32 = 0xfff0_0000;

/// `enum rtw89_ra_mode`.
pub const RA_MODE_CCK: u8 = 1 << 0;
pub const RA_MODE_OFDM: u8 = 1 << 1;
pub const RA_MODE_HT: u8 = 1 << 2;
pub const RA_MODE_VHT: u8 = 1 << 3;
pub const RA_MODE_HE: u8 = 1 << 4;
/// `enum rtw89_ra_report_mode`.
pub const RA_RPT_MODE_LEGACY: u8 = 0;
pub const RA_RPT_MODE_HT: u8 = 1;
pub const RA_RPT_MODE_VHT: u8 = 2;
pub const RA_RPT_MODE_HE: u8 = 3;
/// `enum rtw89_gi_ltf`.
pub const GILTF_LGI_4XHE32: u8 = 0;
pub const GILTF_SGI_4XHE08: u8 = 1;
pub const GILTF_2XHE16: u8 = 2;
pub const GILTF_2XHE08: u8 = 3;
pub const GILTF_1XHE16: u8 = 4;
pub const GILTF_1XHE08: u8 = 5;
/// `enum rtw89_bandwidth`.
pub const CHANNEL_WIDTH_20: u8 = 0;
pub const CHANNEL_WIDTH_40: u8 = 1;
pub const CHANNEL_WIDTH_80: u8 = 2;
pub const CHANNEL_WIDTH_160: u8 = 3;
/// `RSSI_FACTOR`: rtw89's RSSI is in half dB above -110 dBm.
pub const RSSI_FACTOR: u8 = 1;
/// `enum ieee80211_rate_control_changed`'s bits `rtw89_phy_ra_update_sta_link`
/// reads.
pub const RC_BW_CHANGED: u32 = 1 << 0;
pub const RC_SUPP_RATES_CHANGED: u32 = 1 << 2;
pub const RC_NSS_CHANGED: u32 = 1 << 3;
/// `rtw8852b_chip_info.max_amsdu_limit`.
pub const MAX_AMSDU_LIMIT: u16 = 5000;
/// `rtw8852b_chip_info.bacam_num`: the static BA CAM entries.
pub const BACAM_NUM: usize = 2;

/// `GENMASK_ULL(high, low)`.
const fn genmask(high: u32, low: u32) -> u64 {
    (u64::MAX >> (63 - high)) & (u64::MAX << low)
}

/// phy.h's `RA_MASK_*`: CCK in bits 0..3, OFDM in 4..11, then 12 bits per
/// stream from bit 12 on.
pub const RA_MASK_CCK_RATES: u64 = genmask(3, 0);
pub const RA_MASK_OFDM_RATES: u64 = genmask(11, 4);
pub const RA_MASK_SUBCCK_RATES: u64 = 0x5;
pub const RA_MASK_SUBOFDM_RATES: u64 = 0x10;
/// `rtw89_ra_mask_ht_rates`, `rtw89_ra_mask_vht_rates` and
/// `rtw89_ra_mask_he_rates`.
pub const RA_MASK_HT_RATES: [u64; 4] = [
    genmask(19, 12),
    genmask(31, 24),
    genmask(43, 36),
    genmask(55, 48),
];
pub const RA_MASK_VHT_RATES: [u64; 4] = [
    genmask(21, 12),
    genmask(33, 24),
    genmask(45, 36),
    genmask(57, 48),
];
pub const RA_MASK_HE_RATES: [u64; 4] = [
    genmask(23, 12),
    genmask(35, 24),
    genmask(47, 36),
    genmask(59, 48),
];

/// The capability bits rtw89's RA reads: `IEEE80211_HT_CAP_*`,
/// `IEEE80211_VHT_CAP_*` and `IEEE80211_HE_PHY_CAP*_*`.
const HT_CAP_LDPC_CODING: u16 = 0x0001;
const HT_CAP_SGI_20: u16 = 0x0020;
const HT_CAP_SGI_40: u16 = 0x0040;
const HT_CAP_RX_STBC: u16 = 0x0300;
const VHT_CAP_RXLDPC: u32 = 0x0000_0010;
const VHT_CAP_SHORT_GI_80: u32 = 0x0000_0020;
const VHT_CAP_SHORT_GI_160: u32 = 0x0000_0040;
const VHT_CAP_RXSTBC_MASK: u32 = 0x0000_0700;
const VHT_CAP_SU_BEAMFORMER_CAPABLE: u32 = 0x0000_0800;
const VHT_CAP_MU_BEAMFORMER_CAPABLE: u32 = 0x0008_0000;
const HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G: u8 = 0x10;
const HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD: u8 = 0x20;
const HE_PHY_CAP2_STBC_RX_UNDER_80MHZ: u8 = 0x08;
const HE_PHY_CAP3_DCM_MAX_CONST_RX_16_QAM: u8 = 0x18;
const HE_PHY_CAP3_SU_BEAMFORMER: u8 = 0x80;
const HE_PHY_CAP4_MU_BEAMFORMER: u8 = 0x02;
/// `IEEE80211_HE_OPERATION_ER_SU_DISABLE`, of the HE Operation parameters.
pub const HE_OPERATION_ER_SU_DISABLE: u32 = 0x0001_0000;

/// The HT capabilities mac80211 keeps for the peer (`link_sta->ht_cap`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HtCap {
    pub cap: u16,
    /// `mcs.rx_mask[0..4]`: what the peer receives, bounded by what this
    /// station sends.
    pub rx_mask: [u8; 4],
}

/// `link_sta->vht_cap`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VhtCap {
    pub cap: u32,
    pub rx_mcs_map: u16,
}

/// `link_sta->he_cap`: the PHY capabilities and the receive maps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeCap {
    pub phy: [u8; 11],
    pub rx_mcs_80: u16,
    pub rx_mcs_160: u16,
    pub rx_mcs_80p80: u16,
}

/// `enum ieee80211_sta_rx_bandwidth`, the peer's current width.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StaBandwidth {
    #[default]
    Mhz20,
    Mhz40,
    Mhz80,
    Mhz160,
}

/// What `rtw89_phy_ra_sta_update` reads of the peer's
/// `ieee80211_link_sta`. A capability the peer lacks (or the link does not
/// use) is `None`, as mac80211 leaves it zeroed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkSta {
    /// `supp_rates[band]`: bits over the band's `rtw89_bitrates`, CCK first
    /// on 2.4 GHz, 6 Mbps first elsewhere.
    pub supp_rates: u32,
    pub ht: Option<HtCap>,
    pub vht: Option<VhtCap>,
    pub he: Option<HeCap>,
    pub bandwidth: StaBandwidth,
    /// The streams the peer receives, at least one.
    pub rx_nss: u8,
}

impl LinkSta {
    /// The `ieee80211_link_sta` mac80211 would keep after `negotiated`: HT
    /// from an HT link up, VHT from a VHT link up and HE on an HE link, with
    /// the peer's receive sets as they bound this station's transmissions.
    /// A map the peer did not send reads 0, as mac80211 zeroes it.
    pub fn from_negotiated(negotiated: &Negotiated) -> Self {
        let mode = negotiated.mode;
        let ht = negotiated
            .ht
            .as_ref()
            .filter(|_| mode >= Mode::Ht)
            .map(|ht| HtCap {
                cap: ht.capability,
                rx_mask: [
                    ht.peer_rx_mcs[0],
                    ht.peer_rx_mcs[1],
                    ht.peer_rx_mcs[2],
                    ht.peer_rx_mcs[3],
                ],
            });
        let vht = negotiated
            .vht
            .as_ref()
            .filter(|_| mode >= Mode::Vht)
            .map(|vht| VhtCap {
                cap: vht.capability,
                rx_mcs_map: vht.mcs.rx,
            });
        let he = negotiated
            .he
            .as_ref()
            .filter(|_| mode >= Mode::He)
            .map(|he| HeCap {
                phy: he.phy,
                rx_mcs_80: he.mcs_80.rx,
                rx_mcs_160: he.mcs_160.map_or(0, |maps| maps.rx),
                rx_mcs_80p80: he.mcs_80p80.map_or(0, |maps| maps.rx),
            });
        Self {
            supp_rates: u32::from(negotiated.legacy.supported),
            ht,
            vht,
            he,
            bandwidth: match negotiated.width {
                Width::Mhz20 => StaBandwidth::Mhz20,
                Width::Mhz40 => StaBandwidth::Mhz40,
                Width::Mhz80 => StaBandwidth::Mhz80,
                Width::Mhz160 | Width::Mhz80P80 | Width::Mhz320 => StaBandwidth::Mhz160,
            },
            rx_nss: negotiated.tx_nss.max(1),
        }
    }
}

/// What rtw89 keeps of its own side of the link for the RA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Link {
    /// The channel's band (`chan->band_type`).
    pub band: Band,
    /// `rtwsta_link->mac_id`.
    pub mac_id: u8,
    /// `rtwsta_link->er_cap`, as [`can_er`] sets it at association.
    pub er_cap: bool,
    /// `ewma_rssi_read(&rtwsta_link->avg_rssi)`: the received RSSI in half
    /// dB above -110 dBm, as the PPDU status carries it.
    pub rssi: u8,
    /// `hal->tx_nss`.
    pub tx_nss: u8,
}

/// `rtw89_sta_link_can_er` on an RTL8852B: the BSS uses HE and its HE
/// Operation does not disable ER SU.
pub const fn can_er(he_support: bool, he_oper_params: u32) -> bool {
    he_support && he_oper_params & HE_OPERATION_ER_SU_DISABLE == 0
}

/// `rtw89_sta_has_beamformer_cap`: the peer beamforms over VHT or HE.
pub fn has_beamformer_cap(sta: &LinkSta) -> bool {
    let vht = sta.vht.map_or(0, |vht| vht.cap);
    let phy = sta.he.map_or([0; 11], |he| he.phy);
    vht & (VHT_CAP_MU_BEAMFORMER_CAPABLE | VHT_CAP_SU_BEAMFORMER_CAPABLE) != 0
        || phy[3] & HE_PHY_CAP3_SU_BEAMFORMER != 0
        || phy[4] & HE_PHY_CAP4_MU_BEAMFORMER != 0
}

/// `get_mcs_ra_mask`: per stream from bit 12, 12 bits apart, MCS 0 up to
/// `highest`, `highest - gap` or `highest - 2 * gap` as the 2-bit entry
/// says; nothing for 3.
fn mcs_ra_mask(mut map: u16, highest: u8, gap: u8) -> u64 {
    let mut mask = 0;
    for nss in [12, 24, 36, 48] {
        let top = match map & 3 {
            2 => Some(highest),
            1 => Some(highest - gap),
            0 => Some(highest - gap * 2),
            _ => None,
        };
        if let Some(top) = top {
            mask |= genmask(u32::from(top), 0) << nss;
        }
        map >>= 2;
    }
    mask
}

/// `get_he_ra_mask`: MCS 11, 9 or 7 per stream, from the 160 or 80+80 map
/// at 160 MHz and the 80 map otherwise.
fn he_ra_mask(he: &HeCap, bandwidth: StaBandwidth) -> u64 {
    let map = match bandwidth {
        StaBandwidth::Mhz160
            if he.phy[0] & HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G != 0 =>
        {
            he.rx_mcs_80p80
        }
        StaBandwidth::Mhz160 => he.rx_mcs_160,
        _ => he.rx_mcs_80,
    };
    mcs_ra_mask(map, 11, 2)
}

/// `rtw89_phy_ra_mask_rssi`: the rates a weak link keeps, by RSSI level
/// against `{30, 44, 48, 52, 56, 60, 100}` dB above -110 dBm, each raised by
/// `RA_FLOOR_UP_GAP` (3) from `ratr_state` on. An RSSI past every level is
/// level 0, all rates, as rtw89 leaves it.
pub fn ra_mask_rssi(rssi: u8, ratr_state: u8) -> u64 {
    let rssi = rssi >> 1;
    let mut level = 0;
    for (i, threshold) in [30u8, 44, 48, 52, 56, 60, 100].into_iter().enumerate() {
        let threshold = if i >= usize::from(ratr_state) {
            threshold + 3
        } else {
            threshold
        };
        if rssi < threshold {
            level = i;
            break;
        }
    }
    match level {
        0 => u64::MAX,
        1 => 0xffff_ffff_ffff_fff0,
        2 => 0xffff_ffff_ffff_efe0,
        3 => 0xffff_ffff_ffff_cfc0,
        4 => 0xffff_ffff_ffff_8f80,
        _ => 0xffff_ffff_ffff_0f00,
    }
}

/// `rtw89_phy_ra_mask_recover`: the HT and up rates of `backup` when the
/// mask kept none, then its legacy rates when it kept nothing at all.
pub fn ra_mask_recover(mut mask: u64, backup: u64) -> u64 {
    let legacy = RA_MASK_CCK_RATES | RA_MASK_OFDM_RATES;
    if mask & !legacy == 0 {
        mask |= backup & !legacy;
    }
    if mask == 0 {
        mask |= backup & legacy;
    }
    mask
}

/// `struct rtw89_ra_info` as far as an AX chip's H2C carries it, each field
/// as narrow as its bitfield.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RaInfo {
    /// `enum rtw89_ra_mode` bits.
    pub mode_ctrl: u8,
    /// `enum rtw89_bandwidth`.
    pub bw_cap: u8,
    pub macid: u8,
    pub dcm_cap: bool,
    pub er_cap: bool,
    pub init_rate_lv: u8,
    pub upd_all: bool,
    pub en_sgi: bool,
    pub ldpc_cap: bool,
    pub stbc_cap: bool,
    pub ss_num: u8,
    /// Never set by rtw89: 0.
    pub giltf: u8,
    pub upd_bw_nss_mask: bool,
    pub upd_mask: bool,
    pub ra_mask: u64,
    pub band_num: u8,
    pub ra_csi_rate_en: bool,
    pub fixed_csi_rate_en: bool,
    pub cr_tbl_sel: bool,
    pub fix_giltf_en: bool,
    pub fix_giltf: u8,
    pub csi_mcs_ss_idx: u8,
    pub csi_mode: u8,
    pub csi_gi_ltf: u8,
    pub csi_bw: u8,
}

impl RaInfo {
    /// `rtw89_phy_ra_sta_update` with no bitrate mask or rate pattern, on
    /// PHY 0: the mask from the peer's capabilities, its band's legacy rates
    /// and this chip's streams, cut by the RSSI and recovered; mode, width,
    /// guard interval, LDPC, STBC, DCM and streams; the CSI fields when
    /// `csi` (the peer beamforms).
    pub fn sta_update(sta: &LinkSta, link: &Link, csi: bool) -> Self {
        let mut mode = 0;
        let mut csi_mode = RA_RPT_MODE_LEGACY;
        let mut mask = 0;
        let mut high = &RA_MASK_HT_RATES;
        let (mut stbc, mut ldpc) = (false, false);
        let (mut fix_giltf_en, mut fix_giltf) = (false, 0);
        if let Some(he) = &sta.he {
            mode |= RA_MODE_HE;
            csi_mode = RA_RPT_MODE_HE;
            mask |= he_ra_mask(he, sta.bandwidth);
            high = &RA_MASK_HE_RATES;
            stbc = he.phy[2] & HE_PHY_CAP2_STBC_RX_UNDER_80MHZ != 0;
            ldpc = he.phy[1] & HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD != 0;
            // rtw89_phy_ra_gi_ltf on an RTL8852B, no bitrate mask.
            (fix_giltf_en, fix_giltf) = (true, GILTF_2XHE08);
        } else if let Some(vht) = &sta.vht {
            mode |= RA_MODE_VHT;
            csi_mode = RA_RPT_MODE_VHT;
            // MCS 9 (not at 20 MHz), 8, 7.
            mask |= if sta.bandwidth == StaBandwidth::Mhz20 {
                mcs_ra_mask(vht.rx_mcs_map, 8, 1)
            } else {
                mcs_ra_mask(vht.rx_mcs_map, 9, 1)
            };
            high = &RA_MASK_VHT_RATES;
            stbc = vht.cap & VHT_CAP_RXSTBC_MASK != 0;
            ldpc = vht.cap & VHT_CAP_RXLDPC != 0;
        } else if let Some(ht) = &sta.ht {
            mode |= RA_MODE_HT;
            csi_mode = RA_RPT_MODE_HT;
            mask |= (u64::from(ht.rx_mask[3]) << 48)
                | (u64::from(ht.rx_mask[2]) << 36)
                | (u64::from(ht.rx_mask[1]) << 24)
                | (u64::from(ht.rx_mask[0]) << 12);
            stbc = ht.cap & HT_CAP_RX_STBC != 0;
            ldpc = ht.cap & HT_CAP_LDPC_CODING != 0;
        }
        match link.band {
            Band::Ghz2 => {
                mask |= u64::from(sta.supp_rates);
                if sta.supp_rates & 0xf != 0 {
                    mode |= RA_MODE_CCK;
                }
                if sta.supp_rates & 0xff0 != 0 {
                    mode |= RA_MODE_OFDM;
                }
            }
            Band::Ghz5 | Band::Ghz6 => {
                mask |= u64::from(sta.supp_rates) << 4;
                mode |= RA_MODE_OFDM;
            }
        }
        let backup = mask;
        if mode >= RA_MODE_HT {
            let mut allowed = high
                .iter()
                .take(usize::from(link.tx_nss))
                .fold(0, |allowed, rates| allowed | rates);
            if mode & RA_MODE_OFDM != 0 {
                allowed |= RA_MASK_SUBOFDM_RATES;
            }
            if mode & RA_MODE_CCK != 0 {
                allowed |= RA_MASK_SUBCCK_RATES;
            }
            mask &= allowed;
        } else if mode & RA_MODE_OFDM != 0 {
            mask &= RA_MASK_OFDM_RATES | RA_MASK_SUBCCK_RATES;
        }
        if mode != RA_MODE_CCK {
            mask &= ra_mask_rssi(link.rssi, 0);
        }
        let mask = ra_mask_recover(mask, backup);
        let ht_cap = sta.ht.map_or(0, |ht| ht.cap);
        let vht_cap = sta.vht.map_or(0, |vht| vht.cap);
        let (bw_mode, sgi) = match sta.bandwidth {
            StaBandwidth::Mhz160 => (
                CHANNEL_WIDTH_160,
                sta.vht.is_some() && vht_cap & VHT_CAP_SHORT_GI_160 != 0,
            ),
            StaBandwidth::Mhz80 => (
                CHANNEL_WIDTH_80,
                sta.vht.is_some() && vht_cap & VHT_CAP_SHORT_GI_80 != 0,
            ),
            StaBandwidth::Mhz40 => (
                CHANNEL_WIDTH_40,
                sta.ht.is_some() && ht_cap & HT_CAP_SGI_40 != 0,
            ),
            StaBandwidth::Mhz20 => (
                CHANNEL_WIDTH_20,
                sta.ht.is_some() && ht_cap & HT_CAP_SGI_20 != 0,
            ),
        };
        let phy = sta.he.map_or([0; 11], |he| he.phy);
        let mut info = Self {
            mode_ctrl: mode & 0x3f,
            bw_cap: bw_mode,
            macid: link.mac_id,
            dcm_cap: phy[3] & HE_PHY_CAP3_DCM_MAX_CONST_RX_16_QAM != 0,
            er_cap: link.er_cap,
            ss_num: sta.rx_nss.min(link.tx_nss).wrapping_sub(1) & 7,
            en_sgi: sgi,
            ldpc_cap: ldpc,
            stbc_cap: stbc,
            ra_mask: mask,
            fix_giltf_en,
            fix_giltf,
            ..Self::default()
        };
        if csi {
            info.fixed_csi_rate_en = false;
            info.ra_csi_rate_en = true;
            info.cr_tbl_sel = false;
            // rtwvif_link->phy_idx: RTW89_PHY_0.
            info.band_num = 0;
            info.csi_bw = bw_mode;
            info.csi_gi_ltf = GILTF_LGI_4XHE32;
            info.csi_mcs_ss_idx = 5;
            info.csi_mode = csi_mode;
        }
        info
    }
}

/// An RA command: the info and whether `rtw89_fw_h2c_ra` sends its CSI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ra {
    pub info: RaInfo,
    pub csi: bool,
}

impl Ra {
    /// `rtw89_phy_ra_assoc`: [`RaInfo::sta_update`] with the CSI fields when
    /// the peer beamforms, the initial rate level by RSSI (1 above 40 dB over
    /// -110 dBm, 2 above 20, 3 above 1, else 0) and `upd_all`.
    pub fn assoc(sta: &LinkSta, link: &Link) -> Self {
        let csi = has_beamformer_cap(sta);
        let mut info = RaInfo::sta_update(sta, link, csi);
        let rssi = link.rssi >> RSSI_FACTOR;
        info.init_rate_lv = match rssi {
            41.. => 1,
            21..=40 => 2,
            2..=20 => 3,
            _ => 0,
        };
        info.upd_all = true;
        Self { info, csi }
    }

    /// `rtw89_phy_ra_update_sta_link`: [`RaInfo::sta_update`] without CSI,
    /// asking the firmware to take the mask when `changed` names the
    /// supported rates and the width and streams when it names either.
    pub fn update(sta: &LinkSta, link: &Link, changed: u32) -> Self {
        let mut info = RaInfo::sta_update(sta, link, false);
        if changed & RC_SUPP_RATES_CHANGED != 0 {
            info.upd_mask = true;
        }
        if changed & (RC_BW_CHANGED | RC_NSS_CHANGED) != 0 {
            info.upd_bw_nss_mask = true;
        }
        Self { info, csi: false }
    }

    /// `struct rtw89_h2c_ra` as `rtw89_fw_h2c_ra` fills it on an AX chip.
    pub fn payload(&self) -> [u8; RA_LEN] {
        let ra = &self.info;
        let bit = |set: bool, mask: u32| if set { mask } else { 0 };
        let w0 = prep(u32::from(ra.mode_ctrl), RA_W0_MODE)
            | prep(u32::from(ra.bw_cap), RA_W0_BW_CAP)
            | prep(u32::from(ra.macid), RA_W0_MACID)
            | bit(ra.dcm_cap, RA_W0_DCM)
            | bit(ra.er_cap, RA_W0_ER)
            | prep(u32::from(ra.init_rate_lv), RA_W0_INIT_RATE_LV)
            | bit(ra.upd_all, RA_W0_UPD_ALL)
            | bit(ra.en_sgi, RA_W0_SGI)
            | bit(ra.ldpc_cap, RA_W0_LDPC)
            | bit(ra.stbc_cap, RA_W0_STBC)
            | prep(u32::from(ra.ss_num), RA_W0_SS_NUM)
            | prep(u32::from(ra.giltf), RA_W0_GILTF)
            | bit(ra.upd_bw_nss_mask, RA_W0_UPD_BW_NSS_MASK)
            | bit(ra.upd_mask, RA_W0_UPD_MASK);
        let w1 = ra.ra_mask as u32;
        let mut w2 = prep((ra.ra_mask >> 32) as u32, RA_W2_RAMASK_HI32);
        let mut w3 = bit(ra.fix_giltf_en, RA_W3_FIX_GILTF_EN)
            | prep(u32::from(ra.fix_giltf), RA_W3_FIX_GILTF);
        if self.csi {
            w2 |= RA_W2_BFEE_CSI_CTL;
            w3 |= prep(u32::from(ra.band_num), RA_W3_BAND_NUM)
                | bit(ra.cr_tbl_sel, RA_W3_CR_TBL_SEL)
                | bit(ra.fixed_csi_rate_en, RA_W3_FIXED_CSI_RATE_EN)
                | bit(ra.ra_csi_rate_en, RA_W3_RA_CSI_RATE_EN)
                | prep(u32::from(ra.csi_mcs_ss_idx), RA_W3_FIXED_CSI_MCS_SS_IDX)
                | prep(u32::from(ra.csi_mode), RA_W3_FIXED_CSI_MODE)
                | prep(u32::from(ra.csi_gi_ltf), RA_W3_FIXED_CSI_GI_LTF)
                | prep(u32::from(ra.csi_bw), RA_W3_FIXED_CSI_BW);
        }
        let mut bytes = [0; RA_LEN];
        for (chunk, word) in bytes
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip([w0, w1, w2, w3])
        {
            *chunk = word.to_le_bytes();
        }
        bytes
    }

    /// `rtw89_fw_h2c_ra`: the payload as OUTSRC class RA, function
    /// MACIDCFG, with neither ack asked.
    pub fn send<I: Io + ?Sized, C: Outsrc<I> + ?Sized>(
        &self,
        io: &mut I,
        commands: &mut C,
    ) -> Result<(), Error> {
        commands.send_outsrc(
            io,
            H2C_CL_OUTSRC_RA,
            H2C_FUNC_OUTSRC_RA_MACIDCFG,
            false,
            false,
            &self.payload(),
        )
    }
}

/// `get_max_amsdu_len` on an RTL8852B: no aggregation under 55 Mbps or on a
/// rate that may fall back to legacy, then 1200, 2600 and 3500 bytes under
/// 180, 400 and 700 Mbps, and [`MAX_AMSDU_LIMIT`] past that.
pub const fn max_amsdu_len(bit_rate: u32, might_fallback_legacy: bool) -> u16 {
    if bit_rate < 550 || might_fallback_legacy {
        1
    } else if bit_rate < 1800 {
        1200
    } else if bit_rate < 4000 {
        2600
    } else if bit_rate < 7000 {
        3500
    } else {
        MAX_AMSDU_LIMIT
    }
}

/// `rtwsta_link->max_agg_wait` for the peer's `max_rc_amsdu_len`.
pub const fn max_agg_wait(max_rc_amsdu_len: u16) -> i32 {
    max_rc_amsdu_len as i32 / 1500 - 1
}

/// `struct rtw89_ra_report` as `__rtw89_phy_c2h_ra_rpt_iter` fills it on an
/// AX chip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RaReport {
    pub rate: Rate,
    /// `rtw89_hw_to_rate_info_bw`'s width: 0 for 20 MHz up to 3 for 160.
    pub width: u8,
    /// `cfg80211_calculate_bitrate`, in 100 kbps ([`bit_rate::rate_info`]).
    pub bit_rate: u32,
    /// The mode in bits 8:7 and the rate in 6:0 (`RTW89_HW_RATE_MASK_*`).
    pub hw_rate: u16,
    pub retry_ratio: u8,
    /// The MCS (for HT, within its stream) is 2 or below, or the rate is
    /// legacy.
    pub might_fallback_legacy: bool,
}

/// `rtw89_bitrates`, in 100 kbps.
pub const BITRATES: [u16; 12] = [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540];

impl RaReport {
    /// `__rtw89_phy_c2h_ra_rpt_iter` for a report already matched to the
    /// peer's MAC ID: `None` where rtw89 returns early, a legacy rate past
    /// `rtw89_bitrates`, which leaves the last report standing.
    pub fn parse(rpt: &RaRpt) -> Option<Self> {
        let mut rate = rpt.rate;
        let mut mcs = 0;
        let nss = ((rate >> 4) & 7) + 1;
        let info = match rpt.mode {
            RA_RPT_MODE_LEGACY => Rate::Legacy(*BITRATES.get(usize::from(rate))?),
            RA_RPT_MODE_HT => {
                rate &= 0x1f;
                mcs = rate & 7;
                Rate::Ht {
                    mcs: rate,
                    short_gi: rpt.giltf != 0,
                }
            }
            RA_RPT_MODE_VHT => {
                mcs = rate & 0xf;
                Rate::Vht {
                    mcs,
                    nss,
                    short_gi: rpt.giltf != 0,
                }
            }
            _ => {
                mcs = rate & 0xf;
                Rate::He {
                    mcs,
                    nss,
                    gi: match rpt.giltf {
                        GILTF_2XHE08 | GILTF_1XHE08 => HeGi::Us0_8,
                        GILTF_2XHE16 | GILTF_1XHE16 => HeGi::Us1_6,
                        _ => HeGi::Us3_2,
                    },
                }
            }
        };
        let width = rpt.bw & 3;
        Some(Self {
            rate: info,
            width,
            bit_rate: bit_rate::rate_info(info, width),
            hw_rate: ((u16::from(rpt.mode) << 7) & 0x180) | (u16::from(rate) & 0x7f),
            retry_ratio: rpt.retry_ratio,
            might_fallback_legacy: mcs <= 2,
        })
    }

    /// [`max_amsdu_len`] at this report's rate.
    pub const fn max_amsdu_len(&self) -> u16 {
        max_amsdu_len(self.bit_rate, self.might_fallback_legacy)
    }
}

/// What `struct ieee80211_ampdu_params` gives `rtw89_fw_h2c_ba_cam`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ampdu {
    pub tid: u8,
    pub ssn: u16,
    pub buf_size: u16,
}

/// One static entry: its TID and where it stands in the station's
/// `ba_cam_list`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    tid: u8,
    order: u32,
}

/// `cam_info->ba_cam_map` and `ba_cam_entry` over the RTL8852B's
/// [`BACAM_NUM`] static entries, every one the station's.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BaCam {
    entries: [Option<Entry>; BACAM_NUM],
    next: u32,
}

impl BaCam {
    /// The TID each entry holds, `None` where its bit is clear.
    pub fn tids(&self) -> [Option<u8>; BACAM_NUM] {
        self.entries.map(|entry| entry.map(|entry| entry.tid))
    }

    /// `rtw89_core_acquire_sta_ba_entry`: the first free entry, or, when
    /// none is, the first whose TID is neither 0 nor 5 if `tid` is one of
    /// them; the entry goes to the tail of the station's list. `None` is
    /// `-ENOSPC`.
    pub fn acquire(&mut self, tid: u8) -> Option<u8> {
        let index = match self.entries.iter().position(Option::is_none) {
            Some(index) => index,
            None if tid == 0 || tid == 5 => self
                .entries
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.tid != 0 && entry.tid != 5))?,
            None => return None,
        };
        self.entries[index] = Some(Entry {
            tid,
            order: self.next,
        });
        self.next = self.next.wrapping_add(1);
        Some(index as u8)
    }

    /// `rtw89_core_release_sta_ba_entry`: the first entry in the station's
    /// list holding `tid`, freed. `None` is `-ENOENT`.
    pub fn release(&mut self, tid: u8) -> Option<u8> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.filter(|entry| entry.tid == tid).map(|e| (index, e)))
            .min_by_key(|(_, entry)| entry.order.wrapping_sub(self.next))?
            .0;
        self.entries[index] = None;
        Some(index as u8)
    }

    /// `rtw89_fw_h2c_ba_cam` on an `RTW89_BACAM_V0` chip up to the send: an
    /// entry acquired (`valid`) or released for `params.tid`, and the
    /// payload naming it, with the TID, a 256-bit bitmap past 64 frames,
    /// INIT_REQ and the SSN when `valid`. `None` where no entry was had,
    /// which rtw89 lets pass: the hardware makes dynamic entries itself.
    pub fn h2c(&mut self, mac_id: u8, valid: bool, params: &Ampdu) -> Option<[u8; BA_CAM_LEN]> {
        let entry = if valid {
            self.acquire(params.tid)?
        } else {
            self.release(params.tid)?
        };
        let mut w0 =
            prep(u32::from(mac_id), BA_CAM_W0_MACID) | prep(u32::from(entry), BA_CAM_W0_ENTRY_IDX);
        if valid {
            w0 |= BA_CAM_W0_VALID
                | prep(u32::from(params.tid), BA_CAM_W0_TID)
                | prep(
                    if params.buf_size > 64 { 4 } else { 0 },
                    BA_CAM_W0_BMAP_SIZE,
                )
                | BA_CAM_W0_INIT_REQ
                | prep(u32::from(params.ssn), BA_CAM_W0_SSN);
        }
        let mut bytes = [0; BA_CAM_LEN];
        bytes[..4].copy_from_slice(&w0.to_le_bytes());
        Some(bytes)
    }

    /// `rtw89_fw_h2c_ba_cam`: [`Self::h2c`], sent as MAC class BA_CAM asking
    /// DONE_ACK alone. Returns the entry, or `None` when no H2C was sent.
    pub fn send<I: Io + ?Sized, C: Commands<I> + ?Sized>(
        &mut self,
        io: &mut I,
        commands: &mut C,
        mac_id: u8,
        valid: bool,
        params: &Ampdu,
    ) -> Result<Option<[u8; BA_CAM_LEN]>, Error> {
        let Some(payload) = self.h2c(mac_id, valid, params) else {
            return Ok(None);
        };
        commands.send(
            io,
            H2C_CL_BA_CAM,
            H2C_FUNC_MAC_BA_CAM,
            false,
            true,
            &payload,
        )?;
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests;
