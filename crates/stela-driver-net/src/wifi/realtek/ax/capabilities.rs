// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! What an RTL8852B station advertises and where it may tune, as pinned
//! rtw89 builds them for mac80211 (core.c):
//!
//! - [`ht_cap`], [`vht_cap`] and [`he_cap`]: `rtw89_init_ht_cap`,
//!   `rtw89_init_vht_cap` and `rtw89_init_he_cap` for a station on an
//!   RTL8852B (20, 40 and 80 MHz, no 160; `max_vht_mpdu_cap` 11454), from
//!   its streams and cut ([`Chip`]). A CAV cut gives no NG16 feedback
//!   (`no_ng16`).
//! - [`capability_elements`]: the HT Capabilities, Extended Capabilities,
//!   VHT Capabilities (5 GHz only, as rtw89 gives the 2.4 GHz band no VHT)
//!   and HE Capabilities elements mac80211 sends from them in a probe or an
//!   association request (`ieee80211_ie_build_ht_cap`, `ieee80211_add_vht_ie`,
//!   `ieee80211_put_he_cap`), in that order, with spatial multiplexing power
//!   save disabled as `ieee80211_add_ht_ie` writes it for `IEEE80211_SMPS_OFF`
//!   and mac80211's `ext_capa` for rtw89's flags: extended channel switching
//!   (`WIPHY_FLAG_HAS_CHANNEL_SWITCH`), Multiple BSSID (`SUPPORTS_MULTI_BSSID`)
//!   and operating mode notification, which is also `rtw89_ext_capa_sta`.
//!   [`rate_elements`] are `rtw89_bitrates` of the band, [`WMM_INFO`]
//!   mac80211's WMM information element without U-APSD, and
//!   [`advertisement_elements`] the three as the RTL8822C's advertisement
//!   composes them. [`he_source_maps`] are the HE MCS words of rtw89's
//!   `iftype_data` at 80, 160 and 80+80 MHz, the last two zero as
//!   `devm_kcalloc` left them.
//! - [`CHANNELS_2GHZ`] and [`CHANNELS_5GHZ`]: `rtw89_channels_2ghz` and
//!   `rtw89_channels_5ghz`, with [`channel_flags`] for the one channel rtw89
//!   marks (165, `IEEE80211_CHAN_NO_HT40MINUS`). The last three 5 GHz
//!   channels are UNII-4, which `rtw89_regd_setup_unii4` keeps only where
//!   the country allows ([`super::regd`]).
//!
//! What this leaves out, and why:
//! - The AP interface type's HE bits and the 6 GHz band (`he_6ghz_capa`,
//!   `rtw89_channels_6ghz`): an RTL8852B is a 2.4 and 5 GHz station here.
//! - mac80211's trims against the AP in `ieee80211_add_vht_ie` (no
//!   beamformee bits toward an AP that does not beamform) and against a
//!   narrower connection: the station's elements are fixed per band, as the
//!   other Realtek station's are. A width the AP does not offer is the
//!   negotiation's to drop.
//! - EHT: `rtw89_init_eht_cap` returns at once for an AX chip.
//!
//! Advertising beamformee capability promises that the station answers an
//! AP's sounding; rtw89 sets that up at association (`rtw89_mac_bf_assoc`),
//! which this does not do.
use super::{efuse::Hal, registers::CHIP_CAV};
use crate::wifi::{Band, Channel, regulatory::channel::NO_HT40MINUS, station::phy::McsMaps};
use alloc::vec::Vec;

/// `rtw89_init_ht_cap`'s `IEEE80211_HT_CAP_*`.
pub const HT_CAP_LDPC_CODING: u16 = 0x0001;
pub const HT_CAP_SUP_WIDTH_20_40: u16 = 0x0002;
pub const HT_CAP_SGI_20: u16 = 0x0020;
pub const HT_CAP_SGI_40: u16 = 0x0040;
pub const HT_CAP_TX_STBC: u16 = 0x0080;
pub const HT_CAP_RX_STBC_SHIFT: u16 = 8;
pub const HT_CAP_MAX_AMSDU: u16 = 0x0800;
pub const HT_CAP_DSSSCCK40: u16 = 0x1000;
/// `IEEE80211_HT_CAP_SM_PS` and `WLAN_HT_CAP_SM_PS_DISABLED` at its shift.
pub const HT_CAP_SM_PS: u16 = 0x000c;
pub const HT_CAP_SM_PS_DISABLED: u16 = 3 << 2;
/// `IEEE80211_HT_MAX_AMPDU_64K`, `IEEE80211_HT_MPDU_DENSITY_NONE` and
/// `IEEE80211_HT_MCS_TX_DEFINED`.
pub const HT_MAX_AMPDU_64K: u8 = 3;
pub const HT_MPDU_DENSITY_NONE: u8 = 0;
pub const HT_MCS_TX_DEFINED: u8 = 0x01;
/// `rtw89_init_vht_cap`'s `IEEE80211_VHT_CAP_*`.
pub const VHT_CAP_MAX_MPDU_LENGTH_11454: u32 = 0x0000_0002;
pub const VHT_CAP_RXLDPC: u32 = 0x0000_0010;
pub const VHT_CAP_SHORT_GI_80: u32 = 0x0000_0020;
pub const VHT_CAP_TXSTBC: u32 = 0x0000_0080;
pub const VHT_CAP_RXSTBC_1: u32 = 0x0000_0100;
pub const VHT_CAP_SU_BEAMFORMEE_CAPABLE: u32 = 0x0000_1000;
pub const VHT_CAP_BEAMFORMEE_STS_SHIFT: u32 = 13;
pub const VHT_CAP_MU_BEAMFORMEE_CAPABLE: u32 = 0x0010_0000;
pub const VHT_CAP_HTC_VHT: u32 = 0x0040_0000;
pub const VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK: u32 = 7 << 23;
/// `IEEE80211_VHT_MCS_SUPPORT_0_9`, `IEEE80211_HE_MCS_SUPPORT_0_11` and
/// either's `_NOT_SUPPORTED`.
pub const VHT_MCS_SUPPORT_0_9: u16 = 2;
pub const HE_MCS_SUPPORT_0_11: u16 = 2;
pub const MCS_NOT_SUPPORTED: u16 = 3;

/// The streams and cut `rtw89_init_*_cap` read: `hal->tx_nss`,
/// `hal->rx_nss` and `hal->cv`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chip {
    /// One or two.
    pub tx_nss: u8,
    pub rx_nss: u8,
    pub cv: u8,
}

impl Chip {
    /// What the efuse step left in `struct rtw89_hal`, and the cut.
    pub const fn from_hal(hal: &Hal, cv: u8) -> Self {
        Self {
            tx_nss: hal.tx_nss,
            rx_nss: hal.rx_nss,
            cv,
        }
    }

    /// `rtw89_init_ht_cap`'s and `rtw89_init_vht_cap`'s index into their
    /// per-stream tables, which rtw89 takes unchecked: one to four streams.
    const fn index(nss: u8) -> usize {
        (if nss == 0 {
            1
        } else if nss > 4 {
            4
        } else {
            nss
        }) as usize
            - 1
    }
}

/// `struct ieee80211_sta_ht_cap` as `rtw89_init_ht_cap` fills it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HtCap {
    pub cap: u16,
    pub ampdu_factor: u8,
    pub ampdu_density: u8,
    pub rx_mask: [u8; 10],
    pub rx_highest: u16,
    pub tx_params: u8,
}

/// `struct ieee80211_sta_vht_cap` as `rtw89_init_vht_cap` fills it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VhtCap {
    pub cap: u32,
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}

/// `struct ieee80211_sta_he_cap` as `rtw89_init_he_cap` fills it for a
/// station: the capability bytes and the MCS words at 80, 160 and 80+80
/// MHz, receive then transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeCap {
    pub mac: [u8; 6],
    pub phy: [u8; 11],
    pub mcs: [McsMaps; 3],
}

/// `rtw89_init_ht_cap`: SGI at 20 and 40 MHz, 7935-byte A-MSDUs, TX STBC
/// and one RX STBC stream, LDPC, 20/40 MHz with DSSS/CCK at 40; 64 KB
/// A-MPDUs without spacing; MCS 0-7 per receive stream and MCS 32.
pub const fn ht_cap(chip: &Chip) -> HtCap {
    const HIGHEST: [u16; 4] = [150, 300, 450, 600];
    let mut rx_mask = [0; 10];
    let mut i = 0;
    while i < chip.rx_nss as usize && i < 4 {
        rx_mask[i] = 0xff;
        i += 1;
    }
    rx_mask[4] = 0x01;
    HtCap {
        cap: HT_CAP_SGI_20
            | HT_CAP_MAX_AMSDU
            | HT_CAP_TX_STBC
            | (1 << HT_CAP_RX_STBC_SHIFT)
            | HT_CAP_LDPC_CODING
            | HT_CAP_SUP_WIDTH_20_40
            | HT_CAP_DSSSCCK40
            | HT_CAP_SGI_40,
        ampdu_factor: HT_MAX_AMPDU_64K,
        ampdu_density: HT_MPDU_DENSITY_NONE,
        rx_mask,
        rx_highest: HIGHEST[Chip::index(chip.rx_nss)],
        tx_params: HT_MCS_TX_DEFINED,
    }
}

/// The 2-bit-per-stream map of `streams` streams at `value`, the rest
/// unsupported.
const fn streams_map(streams: u8, value: u16) -> u16 {
    let mut map = 0;
    let mut i = 0;
    while i < 8 {
        map |= (if i < streams {
            value
        } else {
            MCS_NOT_SUPPORTED
        }) << (i * 2);
        i += 1;
    }
    map
}

/// `rtw89_init_vht_cap` on a chip without 160 MHz: 11454-byte MPDUs, SGI at
/// 80 MHz, one RX STBC stream, HTC-VHT, the largest A-MPDU, TX STBC, RX LDPC,
/// SU and MU beamformee with four STS; MCS 0-9 per stream each way, at
/// `highest_bw80`'s rates. `SUPPORTS_VHT_EXT_NSS_BW` is set only for 160 MHz
/// chips, so the TX highest carries no extended NSS bit.
pub const fn vht_cap(chip: &Chip) -> VhtCap {
    const HIGHEST_BW80: [u16; 4] = [433, 867, 1300, 1733];
    let sts_cap: u32 = 3;
    VhtCap {
        cap: VHT_CAP_MAX_MPDU_LENGTH_11454
            | VHT_CAP_SHORT_GI_80
            | VHT_CAP_RXSTBC_1
            | VHT_CAP_HTC_VHT
            | VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK
            | VHT_CAP_TXSTBC
            | VHT_CAP_RXLDPC
            | VHT_CAP_MU_BEAMFORMEE_CAPABLE
            | VHT_CAP_SU_BEAMFORMEE_CAPABLE
            | sts_cap << VHT_CAP_BEAMFORMEE_STS_SHIFT,
        rx_mcs_map: streams_map(chip.rx_nss, VHT_MCS_SUPPORT_0_9),
        rx_highest: HIGHEST_BW80[Chip::index(chip.rx_nss)],
        tx_mcs_map: streams_map(chip.tx_nss, VHT_MCS_SUPPORT_0_9),
        tx_highest: HIGHEST_BW80[Chip::index(chip.tx_nss)],
    }
}

/// `rtw89_init_he_cap` for `NL80211_IFTYPE_STATION` on `band` (2.4 or 5
/// GHz) of an RTL8852B: HTC-HE, 16 us trigger padding, all-ack, BSR, the
/// A-MPDU exponent extension 2, OPS, A-MSDU in A-MPDU, HT/VHT trigger
/// frames; 40 MHz on 2.4 GHz or 40/80 MHz on 5 GHz, class A, LDPC, 0.8 us
/// HE-LTF and GI, NDP with 4x LTF at 3.2 us, STBC under 80 MHz, Doppler TX,
/// DCM at 16-QAM both ways on two TX streams, SU beamformee with four STS,
/// NG16 feedback unless the cut is CAV, the codebooks, triggered SU
/// feedback, partial bandwidth ER, power boost, 4x LTF at 0.8 us, Nc 1,
/// ER SU at 0.8 us, DCM on a 996-tone RU, more than 16 SIG-B symbols,
/// 1024-QAM under a 242-tone RU both ways, full-bandwidth SU over MU with
/// either SIG-B, 16 us nominal padding; MCS 0-11 on each receive stream,
/// both ways.
pub const fn he_cap(chip: &Chip, band: Band) -> HeCap {
    let no_ng16 = chip.cv == CHIP_CAV;
    let map = streams_map(chip.rx_nss, HE_MCS_SUPPORT_0_11);
    HeCap {
        mac: [0x01, 0x08, 0x02 | 0x08, 0x10, 0x20 | 0x40, 0x80],
        phy: [
            match band {
                Band::Ghz2 => 0x02,
                _ => 0x04,
            },
            0x10 | 0x20 | 0x40,
            0x02 | 0x04 | 0x08 | 0x10,
            0x18 | 0x03 | 0x04,
            0x01 | 0x0c,
            if no_ng16 { 0 } else { 0x40 | 0x80 },
            0x01 | 0x02 | 0x04 | 0x20,
            0x02 | 0x04 | 0x08,
            0x01 | 0x10 | 0x80,
            0x01 | 0x08 | 0x10 | 0x20 | (2 << 6) | 0x04,
            0,
        ],
        mcs: [
            McsMaps { rx: map, tx: map },
            McsMaps { rx: 0, tx: 0 },
            McsMaps { rx: 0, tx: 0 },
        ],
    }
}

/// The HE MCS words of rtw89's `iftype_data` at 80, 160 and 80+80 MHz: what
/// [`crate::wifi::station::phy::Capabilities::with_local_he_source_maps`]
/// takes.
pub const fn he_source_maps(chip: &Chip) -> [McsMaps; 3] {
    he_cap(chip, Band::Ghz5).mcs
}

/// mac80211's `ext_capa` for rtw89: extended channel switching, Multiple
/// BSSID and operating mode notification.
pub const EXTENDED_CAPABILITIES: [u8; 8] = [0x04, 0, 0x40, 0, 0, 0, 0, 0x40];
/// `ieee80211_add_wmm_info_ie` without U-APSD.
pub const WMM_INFO: [u8; 9] = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];

fn element(elements: &mut Vec<u8>, id: u8, body: &[u8]) {
    elements.extend_from_slice(&[id, body.len() as u8]);
    elements.extend_from_slice(body);
}

/// The capability elements mac80211 builds from rtw89's capabilities for
/// `band`: HT Capabilities with SM power save disabled, Extended
/// Capabilities, VHT Capabilities on 5 GHz, and HE Capabilities with the
/// 80 MHz MCS maps alone, as a chip without 160 MHz has.
pub fn capability_elements(chip: &Chip, band: Band) -> Vec<u8> {
    let mut elements = Vec::new();
    let ht = ht_cap(chip);
    let mut body = Vec::with_capacity(26);
    let cap = (ht.cap & !HT_CAP_SM_PS) | HT_CAP_SM_PS_DISABLED;
    body.extend_from_slice(&cap.to_le_bytes());
    body.push(ht.ampdu_factor | (ht.ampdu_density << 2));
    body.extend_from_slice(&ht.rx_mask);
    body.extend_from_slice(&ht.rx_highest.to_le_bytes());
    body.extend_from_slice(&[ht.tx_params, 0, 0, 0]);
    // Extended HT capabilities, TX beamforming and antenna selection.
    body.extend_from_slice(&[0; 7]);
    element(&mut elements, 45, &body);
    element(&mut elements, 127, &EXTENDED_CAPABILITIES);
    if band == Band::Ghz5 {
        let vht = vht_cap(chip);
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&vht.cap.to_le_bytes());
        for half in [
            vht.rx_mcs_map,
            vht.rx_highest,
            vht.tx_mcs_map,
            vht.tx_highest,
        ] {
            body.extend_from_slice(&half.to_le_bytes());
        }
        element(&mut elements, 191, &body);
    }
    let he = he_cap(chip, band);
    let mut body = alloc::vec![35];
    body.extend_from_slice(&he.mac);
    body.extend_from_slice(&he.phy);
    body.extend_from_slice(&he.mcs[0].rx.to_le_bytes());
    body.extend_from_slice(&he.mcs[0].tx.to_le_bytes());
    element(&mut elements, 255, &body);
    elements
}

/// `rtw89_bitrates` of `band` as Supported Rates, and on 2.4 GHz Extended
/// Supported Rates, in units of 500 kbps.
pub fn rate_elements(band: Band) -> &'static [u8] {
    match band {
        Band::Ghz2 => &[1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108],
        _ => &[1, 8, 12, 18, 24, 36, 48, 72, 96, 108],
    }
}

/// What the station offers on `band`: [`rate_elements`],
/// [`capability_elements`] and [`WMM_INFO`].
pub fn advertisement_elements(chip: &Chip, band: Band) -> Vec<u8> {
    let mut elements = rate_elements(band).to_vec();
    elements.extend(capability_elements(chip, band));
    elements.extend_from_slice(&WMM_INFO);
    elements
}

const fn channel(band: Band, frequency_mhz: u16, number: u16) -> Channel {
    Channel {
        band,
        number,
        frequency_mhz,
    }
}

/// `rtw89_channels_2ghz`.
pub const CHANNELS_2GHZ: [Channel; 14] = [
    channel(Band::Ghz2, 2412, 1),
    channel(Band::Ghz2, 2417, 2),
    channel(Band::Ghz2, 2422, 3),
    channel(Band::Ghz2, 2427, 4),
    channel(Band::Ghz2, 2432, 5),
    channel(Band::Ghz2, 2437, 6),
    channel(Band::Ghz2, 2442, 7),
    channel(Band::Ghz2, 2447, 8),
    channel(Band::Ghz2, 2452, 9),
    channel(Band::Ghz2, 2457, 10),
    channel(Band::Ghz2, 2462, 11),
    channel(Band::Ghz2, 2467, 12),
    channel(Band::Ghz2, 2472, 13),
    channel(Band::Ghz2, 2484, 14),
];

/// `rtw89_channels_5ghz`, UNII-4's 169, 173 and 177 last.
pub const CHANNELS_5GHZ: [Channel; 28] = [
    channel(Band::Ghz5, 5180, 36),
    channel(Band::Ghz5, 5200, 40),
    channel(Band::Ghz5, 5220, 44),
    channel(Band::Ghz5, 5240, 48),
    channel(Band::Ghz5, 5260, 52),
    channel(Band::Ghz5, 5280, 56),
    channel(Band::Ghz5, 5300, 60),
    channel(Band::Ghz5, 5320, 64),
    channel(Band::Ghz5, 5500, 100),
    channel(Band::Ghz5, 5520, 104),
    channel(Band::Ghz5, 5540, 108),
    channel(Band::Ghz5, 5560, 112),
    channel(Band::Ghz5, 5580, 116),
    channel(Band::Ghz5, 5600, 120),
    channel(Band::Ghz5, 5620, 124),
    channel(Band::Ghz5, 5640, 128),
    channel(Band::Ghz5, 5660, 132),
    channel(Band::Ghz5, 5680, 136),
    channel(Band::Ghz5, 5700, 140),
    channel(Band::Ghz5, 5720, 144),
    channel(Band::Ghz5, 5745, 149),
    channel(Band::Ghz5, 5765, 153),
    channel(Band::Ghz5, 5785, 157),
    channel(Band::Ghz5, 5805, 161),
    channel(Band::Ghz5, 5825, 165),
    channel(Band::Ghz5, 5845, 169),
    channel(Band::Ghz5, 5865, 173),
    channel(Band::Ghz5, 5885, 177),
];

/// `RTW89_5GHZ_UNII4_START_INDEX`: where UNII-4 starts in [`CHANNELS_5GHZ`].
pub const UNII4_START_INDEX: usize = 25;

/// The flags `RTW89_DEF_CHAN` gives a channel, which a country's rules add
/// to: `IEEE80211_CHAN_NO_HT40MINUS` on channel 165
/// (`RTW89_DEF_CHAN_5G_NO_HT40MINUS`), none elsewhere.
pub const fn channel_flags(channel: &Channel) -> u32 {
    if matches!(channel.band, Band::Ghz5) && channel.number == 165 {
        NO_HT40MINUS
    } else {
        0
    }
}

#[cfg(test)]
mod tests;
