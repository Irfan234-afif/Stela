// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
extern crate std;
use super::*;
use crate::wifi::{
    realtek::ax::{
        h2c::ra::{
            CHANNEL_WIDTH_80, Link, LinkSta, RA_MASK_HE_RATES, RA_MODE_HE, RA_MODE_OFDM, Ra,
        },
        regd::UNII4_CHANNELS,
        registers::CHIP_CBV,
    },
    station::phy::{Capabilities, Mode, Negotiated, Role, Width},
};

/// The user's TX20E: two streams each way, cut B.
const TX20E: Chip = Chip {
    tx_nss: 2,
    rx_nss: 2,
    cv: CHIP_CBV,
};

#[test]
fn a_two_stream_80mhz_station_advertises_rtw89s_capabilities() {
    let ht = ht_cap(&TX20E);
    assert_eq!(ht.cap, 0x19e3);
    assert_eq!((ht.ampdu_factor, ht.ampdu_density), (3, 0));
    assert_eq!(ht.rx_mask, [0xff, 0xff, 0, 0, 1, 0, 0, 0, 0, 0]);
    assert_eq!((ht.rx_highest, ht.tx_params), (300, 1));
    assert_eq!(
        vht_cap(&TX20E),
        VhtCap {
            cap: 0x03d0_71b2,
            rx_mcs_map: 0xfffa,
            rx_highest: 867,
            tx_mcs_map: 0xfffa,
            tx_highest: 867,
        }
    );
    let he = he_cap(&TX20E, Band::Ghz5);
    assert_eq!(he.mac, [0x01, 0x08, 0x0a, 0x10, 0x60, 0x80]);
    assert_eq!(
        he.phy,
        [
            0x04, 0x70, 0x1e, 0x1f, 0x0d, 0xc0, 0x27, 0x0e, 0x91, 0xbd, 0x00
        ]
    );
    assert_eq!(he_cap(&TX20E, Band::Ghz2).phy[0], 0x02);
    assert_eq!(
        he_cap(
            &Chip {
                cv: CHIP_CAV,
                ..TX20E
            },
            Band::Ghz5
        )
        .phy[5],
        0,
        "no NG16 on a CAV cut"
    );
    assert_eq!(
        he_source_maps(&TX20E),
        [
            McsMaps {
                rx: 0xfffa,
                tx: 0xfffa
            },
            McsMaps { rx: 0, tx: 0 },
            McsMaps { rx: 0, tx: 0 }
        ]
    );
}

#[test]
fn the_elements_are_mac80211s_ht_ext_vht_and_he() {
    let elements = capability_elements(&TX20E, Band::Ghz5);
    let mut expected = alloc::vec![45, 26, 0xef, 0x19, 0x03, 0xff, 0xff, 0, 0, 1, 0, 0, 0, 0, 0];
    expected.extend_from_slice(&[0x2c, 0x01, 0x01, 0, 0, 0]);
    expected.extend_from_slice(&[0; 7]);
    expected.extend_from_slice(&[127, 8, 0x04, 0, 0x40, 0, 0, 0, 0, 0x40]);
    expected.extend_from_slice(&[191, 12, 0xb2, 0x71, 0xd0, 0x03, 0xfa, 0xff, 0x63, 0x03]);
    expected.extend_from_slice(&[0xfa, 0xff, 0x63, 0x03]);
    expected.extend_from_slice(&[255, 22, 35, 0x01, 0x08, 0x0a, 0x10, 0x60, 0x80]);
    expected.extend_from_slice(&[
        0x04, 0x70, 0x1e, 0x1f, 0x0d, 0xc0, 0x27, 0x0e, 0x91, 0xbd, 0,
    ]);
    expected.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
    assert_eq!(elements, expected);
    let two = capability_elements(&TX20E, Band::Ghz2);
    assert!(!two.windows(2).any(|w| w == [191, 12]), "no VHT on 2.4 GHz");
    assert_eq!(two.len(), expected.len() - 14);
}

#[test]
fn the_elements_reparse_and_carry_the_he_source_maps() {
    for band in [Band::Ghz2, Band::Ghz5] {
        let elements = advertisement_elements(&TX20E, band);
        let parsed = Capabilities::parse(band, Role::Station, &elements).unwrap();
        let ht = parsed.ht().unwrap();
        assert_eq!(ht.capability, 0x19ef);
        assert_eq!((ht.ampdu_exponent, ht.mpdu_spacing), (3, 0));
        assert_eq!(ht.rx_mcs[..5], [0xff, 0xff, 0, 0, 1]);
        assert_eq!(parsed.vht().is_some(), band == Band::Ghz5);
        if let Some(vht) = parsed.vht() {
            assert_eq!(vht.capability, 0x03d0_71b2);
            assert_eq!((vht.mcs.rx, vht.mcs.tx), (0xfffa, 0xfffa));
        }
        let he = parsed.he().unwrap();
        assert_eq!(he.phy, he_cap(&TX20E, band).phy);
        assert_eq!((he.mcs_80.rx_nss(), he.mcs_80.tx_nss()), (2, 2));
        assert_eq!((he.mcs_160, he.mcs_80p80), (None, None));
        let complete = parsed
            .clone()
            .with_local_he_source_maps(he_source_maps(&TX20E))
            .unwrap();
        assert_eq!(
            complete.local_he_source_maps(),
            Some(&he_source_maps(&TX20E))
        );
        let one = he_source_maps(&Chip { rx_nss: 1, ..TX20E });
        assert!(parsed.with_local_he_source_maps(one).is_err());
    }
}

#[test]
fn negotiating_with_an_he80_ap_feeds_rtw89s_rate_adaptation() {
    let band = Band::Ghz5;
    let local = Capabilities::parse(band, Role::Station, &advertisement_elements(&TX20E, band))
        .unwrap()
        .with_local_he_source_maps(he_source_maps(&TX20E))
        .unwrap();
    // An AP offering what this station does, with WMM parameters.
    let mut ap = rate_elements(band).to_vec();
    ap.extend(capability_elements(&TX20E, band));
    ap.extend([221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x80, 0]);
    for category in 0..4 {
        ap.extend([(category << 5) | 3, 0xa4, 0, 0]);
    }
    let ap = Capabilities::parse(band, Role::AccessPoint, &ap).unwrap();
    let negotiated = Negotiated::between(&local, &ap, Mode::He, Width::Mhz80).unwrap();
    let sta = LinkSta::from_negotiated(&negotiated);
    assert_eq!((sta.rx_nss, sta.supp_rates), (2, 0xff));
    let ra = Ra::assoc(
        &sta,
        &Link {
            band,
            mac_id: 0,
            er_cap: false,
            rssi: 120,
            tx_nss: TX20E.tx_nss,
        },
    );
    assert_eq!(ra.info.mode_ctrl, RA_MODE_HE | RA_MODE_OFDM);
    assert_eq!((ra.info.bw_cap, ra.info.ss_num), (CHANNEL_WIDTH_80, 1));
    assert_eq!(
        ra.info.ra_mask & RA_MASK_HE_RATES[1],
        RA_MASK_HE_RATES[1],
        "HE MCS 0-11 on the second stream"
    );
    assert!(!ra.csi, "this station's own capabilities beamform nothing");
}

#[test]
fn rtw89s_channels_are_14_and_28_with_165_kept_from_ht40_minus() {
    assert_eq!(CHANNELS_2GHZ[13].frequency_mhz, 2484);
    assert!(
        CHANNELS_2GHZ[..13]
            .iter()
            .all(|channel| channel.frequency_mhz == 2407 + 5 * channel.number)
    );
    assert!(
        CHANNELS_5GHZ
            .iter()
            .all(|channel| channel.frequency_mhz == 5000 + 5 * channel.number)
    );
    let unii4: alloc::vec::Vec<u8> = CHANNELS_5GHZ[UNII4_START_INDEX..]
        .iter()
        .map(|channel| channel.number as u8)
        .collect();
    assert_eq!(unii4, UNII4_CHANNELS);
    let marked: alloc::vec::Vec<u16> = CHANNELS_2GHZ
        .iter()
        .chain(&CHANNELS_5GHZ)
        .filter(|channel| channel_flags(channel) != 0)
        .map(|channel| channel.number)
        .collect();
    assert_eq!(marked, [165]);
    assert_eq!(channel_flags(&CHANNELS_5GHZ[24]), NO_HT40MINUS);
}

/// The 64 bytes the oracle keeps of `rtw89_init_ht_cap`, `rtw89_init_vht_cap`
/// and `rtw89_init_he_cap`.
fn blob(chip: &Chip, band: Band) -> [u8; 64] {
    let (ht, vht, he) = (ht_cap(chip), vht_cap(chip), he_cap(chip, band));
    let mut bytes = [0; 64];
    bytes[0..2].copy_from_slice(&ht.cap.to_le_bytes());
    bytes[2] = ht.ampdu_factor;
    bytes[3] = ht.ampdu_density;
    bytes[4..14].copy_from_slice(&ht.rx_mask);
    bytes[14..16].copy_from_slice(&ht.rx_highest.to_le_bytes());
    bytes[16] = ht.tx_params;
    bytes[20..24].copy_from_slice(&vht.cap.to_le_bytes());
    for (index, half) in [
        vht.rx_mcs_map,
        vht.rx_highest,
        vht.tx_mcs_map,
        vht.tx_highest,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[24 + 2 * index..26 + 2 * index].copy_from_slice(&half.to_le_bytes());
    }
    bytes[32..38].copy_from_slice(&he.mac);
    bytes[38..49].copy_from_slice(&he.phy);
    for (index, maps) in he.mcs.iter().enumerate() {
        bytes[49 + 4 * index..51 + 4 * index].copy_from_slice(&maps.rx.to_le_bytes());
        bytes[51 + 4 * index..53 + 4 * index].copy_from_slice(&maps.tx.to_le_bytes());
    }
    // HT, VHT and HE supported; no 6 GHz capabilities.
    bytes[61] = 7;
    bytes
}

#[test]
#[ignore = "oracle: STELA_RTW89_RA_ORACLE"]
fn capabilities_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_RA_ORACLE").unwrap());
    let bytes = std::fs::read(directory.join("capabilities.bin")).unwrap();
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let count = word(0) as usize;
    assert_eq!(bytes.len(), 4 + count * 80);
    for case in 0..count {
        let at = 4 + case * 80;
        let chip = Chip {
            rx_nss: word(at) as u8,
            tx_nss: word(at + 4) as u8,
            cv: word(at + 8) as u8,
        };
        let band = if word(at + 12) == 0 {
            Band::Ghz2
        } else {
            Band::Ghz5
        };
        assert_eq!(
            blob(&chip, band)[..],
            bytes[at + 16..at + 80],
            "case {case}: {chip:?} on {band:?}"
        );
    }
}
