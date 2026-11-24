extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    c2h::RX_TYPE_C2H,
    pci::ring::RxBdInfo,
    rxdesc::{
        NL80211_BAND_5GHZ, RX_TYPE_CTRL, RX_TYPE_DATA, RX_TYPE_MGNT,
        tests::{Rxd, beacon, ppdu_status},
    },
};
use alloc::vec;

const DARAYA: [u8; 6] = [0x90, 0xd2, 0x0b, 0xdf, 0xbd, 0xed];
const OTHER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

#[test]
fn a_beacon_names_its_bssid_ssid_and_the_channel_its_elements_give() {
    let frame = Frame::parse(&beacon(DARAYA, b"DARAYA", Some(36)));
    assert!(frame.is_beacon() && !frame.is_probe_resp());
    assert_eq!(frame.ftype(), Some(0));
    assert_eq!(frame.bssid, Some(DARAYA));
    assert_eq!(frame.ssid.as_deref(), Some(&b"DARAYA"[..]));
    assert_eq!(frame.channel, Some(36));

    // Without a DS parameter set, the HT operation's primary channel.
    let mut ht = beacon(DARAYA, b"x", None);
    let fcs = ht.split_off(ht.len() - FCS_LEN);
    ht.extend_from_slice(&[EID_HT_OPERATION, 22, 40]);
    ht.extend_from_slice(&[0; 21]);
    ht.extend_from_slice(&fcs);
    assert_eq!(Frame::parse(&ht).channel, Some(40));

    // A probe response is read as a beacon is, but counted apart.
    let mut probe = beacon(OTHER, b"", Some(6));
    probe[0] = 0x50;
    let frame = Frame::parse(&probe);
    assert!(frame.is_probe_resp() && !frame.is_beacon());
    assert_eq!(frame.ssid.as_deref(), Some(&b""[..]));

    // Data and runts name no BSSID.
    let data = Frame::parse(&[0x08, 0x02, 0, 0, 1, 2, 3]);
    assert_eq!((data.ftype(), data.bssid), (Some(2), None));
    assert_eq!(Frame::parse(&[0x80]), Frame::default());
}

#[test]
fn the_ies_channel_follows_cfg80211s_walk() {
    // A DS set of two bytes is not one; the HT operation is next.
    let mut ies = vec![EID_DS_PARAMS, 2, 1, 1, EID_HT_OPERATION, 22, 149];
    ies.extend_from_slice(&[0; 21]);
    assert_eq!(ies_channel_number(&ies), Some(149));
    // An HT operation too short is not one.
    assert_eq!(ies_channel_number(&[EID_HT_OPERATION, 3, 1, 2, 3]), None);
    // The walk stops at an element that runs past the end.
    assert_eq!(
        ies_channel_number(&[0, 40, 1, 2, EID_DS_PARAMS, 1, 6]),
        None
    );
    assert_eq!(find_elem(&[0, 0, 3, 1, 11], EID_DS_PARAMS), Some(&[11][..]));
    assert_eq!(find_elem(&[3], EID_DS_PARAMS), None);
}

/// Feed `buffers` through a tally, as RXQ would hand them over.
fn tally(buffers: &[(RxBdInfo, Vec<u8>)]) -> Heard {
    let mut sorter = Sorter::<Frame>::new(5180, NL80211_BAND_5GHZ);
    let mut heard = Heard::default();
    for (info, data) in buffers {
        heard.buffer(&mut sorter, Received { info: *info, data });
    }
    heard.finish(&mut sorter);
    heard
}

#[test]
fn a_listen_tallies_every_bssid_with_its_best_signal_and_every_packet_by_kind() {
    let daraya = Rxd::frame(RX_TYPE_MGNT, 1);
    let other = Rxd::frame(RX_TYPE_MGNT, 2);
    let corrupt = Rxd {
        crc32_err: true,
        ..Rxd::frame(RX_TYPE_MGNT, 3)
    };
    let buffers = [
        daraya.buffer(&beacon(DARAYA, b"DARAYA", Some(36))),
        Rxd::ppdu_of(&daraya).buffer(&ppdu_status([110, 104], 100, 120, 0x20)),
        other.buffer(&beacon(OTHER, b"next door", Some(36))),
        // A weaker status for the neighbour's beacon.
        Rxd::ppdu_of(&other).buffer(&ppdu_status([90, 80], 100, 100, 0x20)),
        Rxd::frame(RX_TYPE_MGNT, 4).buffer(&beacon(DARAYA, b"DARAYA", Some(36))),
        Rxd::ppdu_of(&Rxd::frame(RX_TYPE_MGNT, 4)).buffer(&ppdu_status([60, 60], 100, 100, 0x20)),
        corrupt.buffer(&beacon(OTHER, b"corrupt", Some(36))),
        Rxd::frame(RX_TYPE_CTRL, 5).buffer(&[0xd4, 0, 0, 0]),
        Rxd::frame(RX_TYPE_DATA, 6).buffer(&[0x88, 0x02, 0, 0, 0, 0]),
        Rxd {
            pkt_type: RX_TYPE_C2H,
            long: false,
            ..Rxd::default()
        }
        .buffer(&[0; 8]),
    ];
    let mut segment = buffers[0].clone();
    segment.0.ls = false;
    let mut all = buffers.to_vec();
    all.push(segment);
    let heard = tally(&all);

    let counts = heard.counts;
    assert_eq!(counts.buffers, 11);
    assert_eq!(counts.segmented, 1);
    assert_eq!(counts.wifi, 6);
    assert_eq!((counts.mgmt, counts.ctrl, counts.data), (4, 1, 1));
    // The corrupt one is not a beacon heard.
    assert_eq!(counts.beacons, 3);
    assert_eq!(counts.crc32_err, 1);
    assert_eq!((counts.ppdu, counts.ppdu_valid, counts.matched), (3, 3, 3));
    assert_eq!(counts.c2h, 1);

    assert_eq!(heard.bss.len(), 2);
    let daraya = &heard.bss[0];
    assert_eq!(daraya.bssid, DARAYA);
    assert_eq!(daraya.ssid, b"DARAYA");
    assert_eq!(daraya.beacons, 2);
    // -45 dBm from the first status; the third gives (60 >> 1) - 110.
    assert_eq!(daraya.best, Some(-45));
    assert_eq!(daraya.channel, Some(36));
    assert_eq!(daraya.freq, 5180);
    // Both statuses A1-matched; the header alone gives (110 >> 1) - 110.
    assert_eq!((daraya.a1, daraya.header_best), (2, Some(-55)));
    assert_eq!(heard.bss[1].best, Some(-65));
    assert_eq!(heard.strongest().unwrap().bssid, DARAYA);
    assert_eq!(heard.beacons(), 3);
}

#[test]
fn a_beacon_without_a_status_counts_without_a_signal() {
    let frame = Rxd::frame(RX_TYPE_MGNT, 1);
    let heard = tally(&[frame.buffer(&beacon(DARAYA, b"DARAYA", None))]);
    assert_eq!(heard.beacons(), 1);
    assert_eq!(heard.bss[0].best, None);
    assert_eq!(heard.bss[0].channel, None);
    assert_eq!(heard.counts.matched, 0);
    // A BSSID with a signal is the strongest over one heard more often
    // without.
    let mut heard = heard;
    heard.bss.push(Bss {
        bssid: OTHER,
        ssid: Vec::new(),
        beacons: 1,
        best: Some(-90),
        a1: 0,
        header_best: None,
        channel: None,
        freq: 5180,
    });
    heard.bss[0].beacons = 9;
    assert_eq!(heard.strongest().unwrap().bssid, OTHER);
}

#[test]
fn a_beacon_whose_status_is_not_a1_matched_keeps_the_headers_signal_beside_rtw89s() {
    let frame = Rxd {
        a1_match: false,
        ..Rxd::frame(RX_TYPE_MGNT, 1)
    };
    let heard = tally(&[
        frame.buffer(&beacon(DARAYA, b"DARAYA", Some(36))),
        Rxd::ppdu_of(&frame).buffer(&ppdu_status([110, 104], 100, 120, 0x20)),
    ]);
    let bss = &heard.bss[0];
    assert_eq!(heard.counts.matched, 1);
    // rtw89 takes no FD average: path A's 110 less the average 100, read
    // as (10 >> 1) - 110.
    assert_eq!(bss.best, Some(-105));
    assert_eq!((bss.a1, bss.header_best), (0, Some(-55)));
}
