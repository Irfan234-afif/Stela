// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
//! What the rate firmware reports is worth: `cfg80211_calculate_bitrate` of
//! `rtw_fw_ra_report_iter`'s `rate_info`, in units of 100 kbps, and the
//! A-MSDU `get_max_amsdu_len` lets it carry.
//!
//! [`rate_info`] is the same for the `rate_info` rtw89's
//! `__rtw89_phy_c2h_ra_rpt_iter` fills from an RTL8852B's report, HE
//! included. An HE rate is not cfg80211's formula: it is derived from IEEE
//! 802.11ax-2021 (27.5, the HE-MCS tables): data subcarriers of the
//! full-width SU PPDU (234, 468, 980 and 1960 for 20, 40, 80 and 160 MHz),
//! bits per subcarrier and coding rate of the MCS, the streams, over a
//! symbol of 12.8 us and the guard interval, cut to 100 kbps as cfg80211
//! cuts its own. cfg80211 rounds its per-width constants, so the two can
//! differ by one unit at some rates; the products' numbers (1201 Mbps at
//! HE80, two streams, MCS 11, 0.8 us) are both's.

/// `rtw_ratetable`, of `DESC_RATE1M` up to `DESC_RATE54M`.
const LEGACY: [u32; 12] = [10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540];
/// `DESC_RATEMCS0`, `DESC_RATEVHT1SS_MCS0`, and how far one VHT stream count
/// lies from the next.
const MCS0: u8 = 0x0c;
const VHT_MCS0: u8 = 0x2c;
const VHT_MCS_COUNT: u8 = 10;
const VHT_STREAMS: u8 = 4;
/// `cfg80211_calculate_bitrate_vht`'s table, of 20, 40 and 80 MHz.
const VHT: [[u32; VHT_MCS_COUNT as usize]; 3] = [
    [
        6_500_000, 13_000_000, 19_500_000, 26_000_000, 39_000_000, 52_000_000, 58_500_000,
        65_000_000, 78_000_000, 86_700_000,
    ],
    [
        13_500_000,
        27_000_000,
        40_500_000,
        54_000_000,
        81_000_000,
        108_000_000,
        121_500_000,
        135_000_000,
        162_000_000,
        180_000_000,
    ],
    [
        29_300_000,
        58_500_000,
        87_800_000,
        117_000_000,
        175_500_000,
        234_000_000,
        263_300_000,
        292_500_000,
        351_000_000,
        390_000_000,
    ],
];

/// The rounding both of cfg80211's formulas end on, past the short guard
/// interval's tenth.
fn in_units(bits: u32, short_gi: bool) -> u32 {
    let bits = if short_gi { (bits / 9) * 10 } else { bits };
    (bits + 50_000) / 100_000
}

/// `cfg80211_calculate_bitrate_ht`.
fn ht(mcs: u8, short_gi: bool, width: u8) -> u32 {
    let modulation = u32::from(mcs & 7);
    let streams = u32::from(mcs >> 3) + 1;
    let base = if width == 1 { 13_500_000 } else { 6_500_000 };
    let factor = match modulation {
        0..4 => modulation + 1,
        4 => modulation + 2,
        _ => modulation + 3,
    };
    in_units(base * factor * streams, short_gi)
}

/// A rate as firmware names it, sent `width` wide as `rtw_fw_ra_report_iter`
/// reads it: 0 for 20 MHz, 1 for 40 and 2 for 80. Zero for no such rate.
pub fn bit_rate(rate: u8, short_gi: bool, width: u8) -> u32 {
    if let Some(&legacy) = LEGACY.get(usize::from(rate)) {
        return legacy;
    }
    if rate < VHT_MCS0 {
        return ht(rate - MCS0, short_gi, width);
    }
    let index = rate - VHT_MCS0;
    let (streams, mcs) = (index / VHT_MCS_COUNT, index % VHT_MCS_COUNT);
    match VHT.get(usize::from(width)) {
        Some(rates) if streams < VHT_STREAMS => {
            in_units(rates[usize::from(mcs)] * (u32::from(streams) + 1), short_gi)
        }
        _ => 0,
    }
}

/// The guard interval of an HE rate, `enum nl80211_he_gi`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeGi {
    Us0_8,
    Us1_6,
    Us3_2,
}

/// A rate as rtw89 leaves it in `rate_info` from a firmware report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rate {
    /// `rate_info.legacy`: `rtw89_bitrates`' bitrate, in 100 kbps.
    Legacy(u16),
    /// `RATE_INFO_FLAGS_MCS`: HT MCS 0 to 31, streams in its upper bits.
    Ht { mcs: u8, short_gi: bool },
    /// `RATE_INFO_FLAGS_VHT_MCS`.
    Vht { mcs: u8, nss: u8, short_gi: bool },
    /// `RATE_INFO_FLAGS_HE_MCS`.
    He { mcs: u8, nss: u8, gi: HeGi },
}

/// HE-MCS 0 to 11: bits per subcarrier and the coding rate, numerator and
/// denominator (IEEE 802.11ax-2021, 27.5).
const HE_MCS: [(u32, u32, u32); 12] = [
    (1, 1, 2),
    (2, 1, 2),
    (2, 3, 4),
    (4, 1, 2),
    (4, 3, 4),
    (6, 2, 3),
    (6, 3, 4),
    (6, 5, 6),
    (8, 3, 4),
    (8, 5, 6),
    (10, 3, 4),
    (10, 5, 6),
];
/// The data subcarriers of a full-width HE SU PPDU at 20, 40, 80 and 160
/// MHz: a 242-, 484-, 996- and 2x996-tone RU.
const HE_DATA_SUBCARRIERS: [u32; 4] = [234, 468, 980, 1960];

/// An HE SU rate `width` wide (0 for 20 MHz up to 3 for 160), in 100 kbps:
/// subcarriers times bits times coding rate times streams per symbol,
/// 12.8 us and the guard interval long, cut as cfg80211 cuts. Zero for an
/// MCS above 11, no stream or more than eight, or a width beyond 160 MHz.
pub fn he(mcs: u8, nss: u8, gi: HeGi, width: u8) -> u32 {
    let (Some(&(bits, numerator, denominator)), Some(&subcarriers)) = (
        HE_MCS.get(usize::from(mcs)),
        HE_DATA_SUBCARRIERS.get(usize::from(width)),
    ) else {
        return 0;
    };
    if !(1..=8).contains(&nss) {
        return 0;
    }
    // The symbol, in units of 100 ns.
    let symbol: u32 = match gi {
        HeGi::Us0_8 => 136,
        HeGi::Us1_6 => 144,
        HeGi::Us3_2 => 160,
    };
    // Bits per symbol over the symbol in us is Mbps: ten units of 100 kbps.
    subcarriers * bits * numerator * u32::from(nss) * 100 / (denominator * symbol)
}

/// `cfg80211_calculate_bitrate_vht` for 20, 40 and 80 MHz and MCS 0 to 9,
/// which is all an RTL8852B sends; zero otherwise.
fn vht(mcs: u8, nss: u8, short_gi: bool, width: u8) -> u32 {
    match (
        VHT.get(usize::from(width))
            .and_then(|rates| rates.get(usize::from(mcs))),
        nss,
    ) {
        (Some(&rate), 1..=8) => in_units(rate * u32::from(nss), short_gi),
        _ => 0,
    }
}

/// `cfg80211_calculate_bitrate` of the `rate_info` rtw89 builds for `rate`
/// sent `width` wide (`rtw89_hw_to_rate_info_bw`: 0 for 20 MHz, 1 for 40,
/// 2 for 80, 3 for 160), in 100 kbps.
pub fn rate_info(rate: Rate, width: u8) -> u32 {
    match rate {
        Rate::Legacy(bitrate) => u32::from(bitrate),
        Rate::Ht { mcs, short_gi } if mcs < 32 => ht(mcs, short_gi, width),
        Rate::Ht { .. } => 0,
        Rate::Vht { mcs, nss, short_gi } => vht(mcs, nss, short_gi, width),
        Rate::He { mcs, nss, gi } => he(mcs, nss, gi, width),
    }
}

/// `get_max_amsdu_len`: the bytes an A-MSDU may take at `bit_rate`, where 1
/// lets no two frames join and 0 sets no limit.
pub fn max_amsdu(bit_rate: u32) -> u16 {
    match bit_rate {
        0..550 => 1,
        550..1800 => 1200,
        1800..4000 => 2600,
        4000..7000 => 3500,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_rates_come_from_the_table() {
        assert_eq!(bit_rate(0, false, 0), 10);
        assert_eq!(
            bit_rate(2, true, 1),
            55,
            "no guard interval or width applies"
        );
        assert_eq!(bit_rate(11, false, 0), 540);
    }

    #[test]
    fn ht_rates_follow_modulation_streams_width_and_guard() {
        assert_eq!(bit_rate(MCS0, false, 0), 65);
        assert_eq!(bit_rate(MCS0 + 7, false, 0), 650);
        assert_eq!(bit_rate(MCS0 + 7, true, 0), 722);
        assert_eq!(bit_rate(MCS0 + 15, false, 1), 2700);
        assert_eq!(bit_rate(MCS0 + 15, true, 1), 3000);
    }

    #[test]
    fn vht_rates_multiply_by_stream() {
        assert_eq!(bit_rate(VHT_MCS0, false, 0), 65);
        assert_eq!(bit_rate(VHT_MCS0 + 9, false, 2), 3900);
        assert_eq!(bit_rate(VHT_MCS0 + 19, false, 2), 7800);
        assert_eq!(bit_rate(VHT_MCS0 + 19, true, 2), 8667);
        assert_eq!(bit_rate(VHT_MCS0, false, 3), 0, "a width cfg80211 warns of");
    }

    #[test]
    fn he_rates_match_the_tx20e_product_numbers() {
        // 1201 and 574 Mbps: HE80 and HE40, two streams, MCS 11, 0.8 us.
        let he80 = rate_info(
            Rate::He {
                mcs: 11,
                nss: 2,
                gi: HeGi::Us0_8,
            },
            2,
        );
        let he40 = he(11, 2, HeGi::Us0_8, 1);
        assert_eq!(he80, 12009);
        assert_eq!(he40, 5735);
        assert_eq!((he80 + 5) / 10, 1201);
        assert_eq!((he40 + 5) / 10, 574);
    }

    #[test]
    fn he_rates_follow_mcs_streams_width_and_guard() {
        // cfg80211's values at these points, which IEEE's formula meets.
        assert_eq!(he(0, 1, HeGi::Us0_8, 2), 360);
        assert_eq!(he(0, 1, HeGi::Us3_2, 0), 73);
        assert_eq!(he(7, 1, HeGi::Us0_8, 0), 860);
        assert_eq!(he(11, 1, HeGi::Us1_6, 2), 5671);
        assert_eq!(he(11, 2, HeGi::Us3_2, 3), 20416);
        assert_eq!(he(12, 1, HeGi::Us0_8, 0), 0, "4096-QAM is EHT's");
        assert_eq!(he(0, 0, HeGi::Us0_8, 0), 0);
        assert_eq!(he(0, 9, HeGi::Us0_8, 0), 0);
        assert_eq!(he(0, 1, HeGi::Us0_8, 4), 0);
    }

    #[test]
    fn rtw89_rate_info_reuses_the_ht_and_vht_formulas() {
        assert_eq!(rate_info(Rate::Legacy(540), 2), 540);
        let ht = |mcs, short_gi, width| rate_info(Rate::Ht { mcs, short_gi }, width);
        assert_eq!(ht(15, true, 1), 3000);
        assert_eq!(ht(32, false, 1), 0);
        let vht = |mcs, nss, short_gi, width| rate_info(Rate::Vht { mcs, nss, short_gi }, width);
        assert_eq!(vht(9, 2, false, 2), 7800);
        assert_eq!(vht(9, 2, true, 2), 8667);
        assert_eq!(vht(8, 1, false, 0), 780);
        assert_eq!(vht(10, 1, false, 2), 0, "no RTL8852B rate");
        assert_eq!(vht(0, 1, false, 3), 0, "no RTL8852B width");
    }

    #[test]
    fn each_rate_tier_bounds_an_amsdu() {
        assert_eq!(max_amsdu(0), 1);
        assert_eq!(max_amsdu(549), 1);
        assert_eq!(max_amsdu(550), 1200);
        assert_eq!(max_amsdu(1800), 2600);
        assert_eq!(max_amsdu(4000), 3500);
        assert_eq!(max_amsdu(7000), 0);
    }
}
