extern crate std;

use super::*;
use alloc::{vec, vec::Vec};

/// An AX RX descriptor's fields, for building packets as the chip writes
/// them.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Rxd {
    pub pkt_type: u8,
    pub long: bool,
    pub mac_info_valid: bool,
    pub drv_info: u8,
    pub ppdu_cnt: u8,
    pub rate: u16,
    pub gi: u8,
    pub bw: u8,
    pub frame_type: u8,
    pub a1_match: bool,
    pub crc32_err: bool,
    pub mac_id: u8,
}

impl Rxd {
    /// A frame's descriptor: long, of `frame_type`, legacy OFDM 6M.
    pub(crate) fn frame(frame_type: u8, ppdu_cnt: u8) -> Self {
        Self {
            pkt_type: RX_TYPE_WIFI,
            long: true,
            ppdu_cnt,
            rate: HW_RATE_OFDM6,
            frame_type,
            a1_match: true,
            ..Self::default()
        }
    }

    /// The PPDU status of `frame`'s PPDU: short, with MAC info.
    pub(crate) fn ppdu_of(frame: &Self) -> Self {
        Self {
            pkt_type: RX_TYPE_PPDU_STAT,
            long: false,
            mac_info_valid: true,
            ppdu_cnt: frame.ppdu_cnt,
            rate: frame.rate,
            gi: frame.gi,
            bw: frame.bw,
            a1_match: frame.a1_match,
            ..Self::default()
        }
    }

    /// The descriptor's words.
    pub(crate) fn words(&self, pkt_size: usize) -> Vec<u32> {
        let mut words = vec![
            pkt_size as u32
                | u32::from(self.mac_info_valid) << 23
                | u32::from(self.pkt_type) << 24
                | u32::from(self.drv_info) << 28
                | u32::from(self.long) << 31,
            u32::from(self.ppdu_cnt) << 4
                | u32::from(self.rate) << 16
                | u32::from(self.gi) << 25
                | u32::from(self.bw) << 30,
            0x1234_5678,
            u32::from(self.a1_match) | u32::from(self.crc32_err) << 9,
        ];
        if self.long {
            words.extend([
                u32::from(self.frame_type),
                u32::from(self.mac_id) << 16,
                0,
                0,
            ]);
        }
        words
    }

    /// What follows the `rxbd_info` dword: the descriptor, the driver info
    /// and `payload`.
    pub(crate) fn packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = self
            .words(payload.len())
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        out.resize(out.len() + 8 * usize::from(self.drv_info), 0xdd);
        out.extend_from_slice(payload);
        out
    }

    /// [`Self::packet`] behind its `rxbd_info` dword, as one whole buffer.
    pub(crate) fn buffer(&self, payload: &[u8]) -> (RxBdInfo, Vec<u8>) {
        let packet = self.packet(payload);
        let info = RxBdInfo {
            fs: true,
            ls: true,
            len: (4 + packet.len()) as u16,
            tag: 0,
        };
        let mut data = info.encode().to_le_bytes().to_vec();
        data.extend_from_slice(&packet);
        (info, data)
    }
}

/// A beacon from `bssid` for `ssid`, with a DS parameter set naming
/// `channel` when given, and its FCS.
pub(crate) fn beacon(bssid: [u8; 6], ssid: &[u8], channel: Option<u8>) -> Vec<u8> {
    let mut frame = vec![0x80, 0x00, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x10, 0x00]);
    frame.extend_from_slice(&[0; 8]);
    frame.extend_from_slice(&100u16.to_le_bytes());
    frame.extend_from_slice(&0x0431u16.to_le_bytes());
    frame.push(0);
    frame.push(ssid.len() as u8);
    frame.extend_from_slice(ssid);
    frame.extend_from_slice(&[1, 4, 0x8c, 0x12, 0x98, 0x24]);
    if let Some(channel) = channel {
        frame.extend_from_slice(&[3, 1, channel]);
    }
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    frame
}

/// A PPDU status: MAC info of one user whose MAC ID is valid and who sent a
/// beacon, padded to 8 bytes, then a PHY status of LEGACY_OFDM_PKT with
/// paths A and B at `rssi`, `rssi_avg` in the header and one IE01 whose FD
/// average is `rpl` and channel index `chan_idx`.
pub(crate) fn ppdu_status(rssi: [u8; 2], rssi_avg: u8, rpl: u8, chan_idx: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let w0 = 1u32;
    let w1 = 0u32;
    out.extend_from_slice(&w0.to_le_bytes());
    out.extend_from_slice(&w1.to_le_bytes());
    out.extend_from_slice(&(RXINFO_USER_MAC_ID_VALID | RXINFO_USER_BCN).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    let len = (PHY_STS_HDR_LEN + 32) as u32;
    let hdr0 = 12 | PHY_STS_HDR_W0_VALID | (len >> 3) << 8 | u32::from(rssi_avg) << 24;
    out.extend_from_slice(&hdr0.to_le_bytes());
    out.extend_from_slice(&[rssi[0], rssi[1], 0, 0]);
    let ie0 = u32::from(PHYSTS_IE01_CMN_OFDM) | u32::from(rpl) << 8 | u32::from(chan_idx) << 16;
    out.extend_from_slice(&ie0.to_le_bytes());
    out.extend_from_slice(&[0; 28]);
    out
}

#[test]
fn query_reads_every_field_rtw89_reads_of_a_short_and_a_long_descriptor() {
    let mut words = [0u32; 8];
    words[0] = 0x123 | 0x5 << 28 | 1 << 23 | 0xa << 24 | 1 << 31 | 1 << 22 | 0x3 << 14;
    words[1] = 0x7 | 0x5 << 4 | 1 << 7 | 0x42 << 8 | 0x1ab << 16 | 0x5 << 25 | 0x2 << 30;
    words[2] = 0xcafe_f00d;
    words[3] = RXD_A1_MATCH | RXD_SW_DEC | RXD_HW_DEC | RXD_AMPDU | RXD_CRC32_ERR | RXD_ICV_ERR;
    words[4] = 0x2;
    words[5] = 0x11 | 0x22 << 8 | 0x33 << 16 | 0x4 << 24 | RXD_ADDR_CAM_VLD;
    words[7] = 0x9 << 17;
    let mut data = vec![0xee; 4];
    data.extend(words.iter().flat_map(|word| word.to_le_bytes()));
    let desc = RxDescInfo::query(&data, 4).unwrap();
    assert_eq!(
        desc,
        RxDescInfo {
            pkt_size: 0x123,
            drv_info_size: 5,
            long_rxdesc: true,
            pkt_type: 0xa,
            mac_info_valid: true,
            bw: 2,
            data_rate: 0x1ab,
            gi_ltf: 5,
            user_id: 0x42,
            sr_en: true,
            ppdu_cnt: 5,
            ppdu_type: 7,
            free_run_cnt: 0xcafe_f00d,
            icv_err: true,
            crc32_err: true,
            hw_dec: true,
            sw_dec: true,
            addr1_match: true,
            ampdu: true,
            shift: 0,
            bb_sel: false,
            offset: 4 + 40,
            rxd_len: 32,
            ready: true,
            frame_type: 2,
            addr_cam_valid: true,
            addr_cam_id: 0x22,
            sec_cam_id: 0x11,
            mac_id: 0x33,
            rx_pl_id: 4,
            sec_type: 9,
        }
    );
    // The short descriptor leaves the long one's fields at 0, and needs
    // its 16 bytes alone.
    words[0] &= !RXD_LONG_RXD;
    let mut short = vec![0; 4];
    short.extend(words[..4].iter().flat_map(|word| word.to_le_bytes()));
    let desc = RxDescInfo::query(&short, 4).unwrap();
    assert_eq!((desc.rxd_len, desc.frame_type, desc.mac_id), (16, 0, 0));
    assert_eq!(
        RxDescInfo::query(&short[..19], 4),
        Err(Error::Truncated {
            needed: 20,
            written: 19
        })
    );
    words[0] |= RXD_LONG_RXD;
    let mut long = vec![0; 4];
    long.extend(words[..4].iter().flat_map(|word| word.to_le_bytes()));
    assert_eq!(
        RxDescInfo::query(&long, 4),
        Err(Error::Truncated {
            needed: 36,
            written: 20
        })
    );
}

#[test]
fn a_buffer_splits_into_its_descriptor_and_the_bytes_behind_its_driver_info() {
    let rxd = Rxd {
        drv_info: 2,
        ..Rxd::frame(RX_TYPE_MGNT, 1)
    };
    let (info, mut data) = rxd.buffer(b"frame");
    // Bytes the chip wrote past `len` are not the packet's.
    data.extend_from_slice(b"stale");
    let packet = split(info, &data).unwrap();
    assert_eq!(packet.data, b"frame");
    assert_eq!(packet.desc.offset, 4 + 16);
    assert_eq!(packet.desc.packet_offset(), 4 + 16 + 32);

    let segment = RxBdInfo { ls: false, ..info };
    assert_eq!(
        split(segment, &data),
        Err(Error::Segmented {
            fs: true,
            ls: false
        })
    );
    let short = RxBdInfo { len: 30, ..info };
    assert!(matches!(split(short, &data), Err(Error::Truncated { .. })));
}

#[test]
fn a_ppdu_status_gives_each_paths_rssi_corrected_by_ie01s_fd_average() {
    let frame = Rxd::frame(RX_TYPE_MGNT, 3);
    let status = ppdu_status([110, 104], 100, 120, 0x20);
    let desc = RxDescInfo {
        mac_info_valid: true,
        addr1_match: true,
        data_rate: HW_RATE_OFDM6,
        ppdu_cnt: 3,
        pkt_type: RX_TYPE_PPDU_STAT,
        ..RxDescInfo::default()
    };
    let (phy, error) = PhyPpdu::process(&desc, &status);
    assert_eq!(error, None);
    assert!(phy.valid && phy.has_bcn && !phy.has_data && phy.to_self);
    assert_eq!((phy.ie, phy.chan_idx, phy.rpl_avg), (12, 0x20, 120));
    // __rtw8852bx_convert_rpl_to_rssi: each path moved by rpl - rssi_avg.
    assert_eq!(phy.rssi, [130, 124, 0, 0]);
    assert_eq!(phy.rssi_avg, 120);

    let mut rx = RxStatus::update(
        &RxDescInfo::query(&frame.buffer(&[0; 24]).1, 4).unwrap(),
        5210,
        NL80211_BAND_5GHZ,
    );
    assert!(ppdu_match(3, &desc, &rx));
    rx.query_ppdu(&phy);
    assert_eq!(rx.signal, -45);
    assert_eq!(rx.chain_signal, [-45, -48]);
    assert_eq!(rx.chains, 0b11);
    // IE01's channel index 0x20: base 36, offset 0.
    assert_eq!((rx.freq, rx.band), (5180, NL80211_BAND_5GHZ));

    // A report not A1-matched takes no FD average: the header's RSSI less
    // its own average, as rtw89 leaves it.
    let other = RxDescInfo {
        addr1_match: false,
        ..desc
    };
    let (phy, _) = PhyPpdu::process(&other, &status);
    assert_eq!(phy.rpl_avg, 0);
    assert_eq!(phy.rssi[..2], [10, 4]);
    // The header's own RSSI stays for the report.
    assert_eq!(phy.hdr_rssi, Some([110, 104]));
    // A header that is not valid gives none.
    let mut invalid = status.clone();
    // The header's first byte, behind the MAC info and its one user.
    invalid[16] &= !(PHY_STS_HDR_W0_VALID as u8);
    assert_eq!(PhyPpdu::process(&desc, &invalid).0.hdr_rssi, None);
}

#[test]
fn a_ppdu_status_that_falls_short_says_where() {
    let desc = RxDescInfo {
        mac_info_valid: true,
        addr1_match: true,
        data_rate: HW_RATE_OFDM6,
        ..RxDescInfo::default()
    };
    let good = ppdu_status([110, 104], 100, 120, 0);
    // Five users is past RTL8852B's four.
    let mut users = good.clone();
    users[0] = 5;
    assert_eq!(
        PhyPpdu::process(&desc, &users).1,
        Some(PpduError::UserNumber(5))
    );
    // The PHY status header's valid bit.
    let mut invalid = good.clone();
    invalid[16] &= !(PHY_STS_HDR_W0_VALID as u8);
    assert_eq!(
        PhyPpdu::process(&desc, &invalid).1,
        Some(PpduError::Invalid)
    );
    // A length the report does not have.
    let mut long = good.clone();
    long.extend_from_slice(&[0; 8]);
    assert_eq!(
        PhyPpdu::process(&desc, &long).1,
        Some(PpduError::LengthMismatch {
            header: 40,
            report: 48
        })
    );
    // An IE map below CCK_PKT is bypassed, the header's RSSI kept.
    let mut bypassed = good.clone();
    bypassed[16] = (bypassed[16] & !0x1f) | 3;
    let (phy, error) = PhyPpdu::process(&desc, &bypassed);
    assert_eq!(error, Some(PpduError::Bypassed(3)));
    assert_eq!(phy.rssi[..2], [110, 104]);
    assert!(!phy.valid);
    // An IE of length 0 (type 23).
    let mut zero = good;
    zero[24] = 23;
    assert_eq!(
        PhyPpdu::process(&desc, &zero).1,
        Some(PpduError::ParseFailed)
    );
}

#[test]
fn the_sorter_holds_frames_for_their_ppdu_status_and_flushes_them_when_the_count_moves() {
    let mut sorter = Sorter::<u32>::new(5180, NL80211_BAND_5GHZ);
    let mut delivered = Vec::new();
    let mut take = |rxd: Rxd, payload: &[u8], id: u32, delivered: &mut Vec<Delivered<u32>>| {
        let (info, data) = rxd.buffer(payload);
        let packet = split(info, &data).unwrap();
        sorter.receive(&packet, |_| id, |frame| delivered.push(frame))
    };
    let beacon = Rxd::frame(RX_TYPE_MGNT, 3);
    // A management frame of a long descriptor waits for its status.
    assert_eq!(
        take(beacon, &[0; 24], 1, &mut delivered),
        Sorted::Wifi { held: true }
    );
    // Another of a different rate in the same PPDU count waits too.
    let other = Rxd {
        rate: 0x5,
        ..beacon
    };
    assert_eq!(
        take(other, &[0; 24], 2, &mut delivered),
        Sorted::Wifi { held: true }
    );
    // A control frame goes at once, without a status.
    let ack = Rxd::frame(RX_TYPE_CTRL, 3);
    assert_eq!(
        take(ack, &[0; 10], 3, &mut delivered),
        Sorted::Wifi { held: false }
    );
    assert_eq!(delivered.len(), 1);
    // The status delivers both, matching the one of its rate alone.
    let status = ppdu_status([110, 104], 100, 120, 0);
    assert_eq!(
        take(Rxd::ppdu_of(&beacon), &status, 0, &mut delivered),
        Sorted::PpduStatus {
            error: None,
            delivered: 2,
            matched: 1
        }
    );
    assert_eq!(delivered[1].frame, 1);
    assert_eq!(delivered[1].status.signal, -45);
    assert!(delivered[1].ppdu.is_some());
    assert_eq!(delivered[2].frame, 2);
    assert_eq!(delivered[2].status.signal, 0);
    assert_eq!(delivered[2].ppdu, None);

    // A frame of the next count flushes a held one without a status.
    take(Rxd::frame(RX_TYPE_DATA, 4), &[0; 24], 4, &mut delivered);
    take(Rxd::frame(RX_TYPE_DATA, 5), &[0; 24], 5, &mut delivered);
    assert_eq!(delivered.last().unwrap().frame, 4);
    assert_eq!(delivered.last().unwrap().ppdu, None);
    // C2H and other types are told apart.
    let c2h = Rxd {
        pkt_type: RX_TYPE_C2H,
        long: false,
        ..Rxd::default()
    };
    assert_eq!(take(c2h, &[0; 8], 0, &mut delivered), Sorted::C2h);
    let other = Rxd {
        pkt_type: 7,
        long: false,
        ..Rxd::default()
    };
    assert_eq!(
        take(other, &[0; 8], 0, &mut delivered),
        Sorted::Unhandled(7)
    );
    assert_eq!(sorter.held(), 1);
}

#[test]
fn a_ppdu_status_before_any_frame_delivers_nothing() {
    let mut sorter = Sorter::<()>::new(2437, NL80211_BAND_2GHZ);
    let (info, data) =
        Rxd::ppdu_of(&Rxd::frame(RX_TYPE_MGNT, 0)).buffer(&ppdu_status([1, 2], 3, 4, 0));
    let packet = split(info, &data).unwrap();
    let sorted = sorter.receive(&packet, |_| (), |_| panic!("nothing is held"));
    assert_eq!(
        sorted,
        Sorted::PpduStatus {
            error: None,
            delivered: 0,
            matched: 0
        }
    );
}

#[test]
fn channel_indices_and_frequencies_follow_rtw89_and_cfg80211() {
    assert_eq!(decode_chan_idx(0x06), (6, NL80211_BAND_2GHZ));
    assert_eq!(decode_chan_idx(0x2c), (60, NL80211_BAND_5GHZ));
    assert_eq!(decode_chan_idx(0x58), (165, NL80211_BAND_5GHZ));
    assert_eq!(decode_chan_idx(0x71), (3, NL80211_BAND_6GHZ));
    // A reserved base adds to 0xff, as rtw89's u8 does.
    assert_eq!(decode_chan_idx(0x12), (3, NL80211_BAND_5GHZ));
    assert_eq!(channel_to_frequency(14, NL80211_BAND_2GHZ), 2484);
    assert_eq!(channel_to_frequency(15, NL80211_BAND_2GHZ), 0);
    assert_eq!(channel_to_frequency(36, NL80211_BAND_5GHZ), 5180);
    assert_eq!(channel_to_frequency(184, NL80211_BAND_5GHZ), 4920);
    assert_eq!(channel_to_frequency(2, NL80211_BAND_6GHZ), 5935);
    assert_eq!(channel_to_frequency(0, NL80211_BAND_5GHZ), 0);
    assert_eq!(rssi_raw_to_dbm(0), -110);
    assert_eq!(rssi_raw_to_dbm(255), 17);
    assert_eq!(he_gi(6, true), HE_GI_3_2);
    assert_eq!(he_gi(6, false), GI_UNKNOWN);
    assert_eq!(rate_idx(0x1ab), 0xb);
    assert_eq!(rate_idx(0x095), 0x15);
}

/// `rtw89_core_query_rxdesc`'s fields, in the order the C oracle writes them.
fn desc_words(desc: &RxDescInfo) -> Vec<u32> {
    let d = desc;
    vec![
        d.pkt_size.into(),
        d.drv_info_size.into(),
        d.long_rxdesc.into(),
        d.pkt_type.into(),
        d.mac_info_valid.into(),
        d.bw.into(),
        d.data_rate.into(),
        d.gi_ltf.into(),
        d.user_id.into(),
        d.sr_en.into(),
        d.ppdu_cnt.into(),
        d.ppdu_type.into(),
        d.free_run_cnt,
        d.icv_err.into(),
        d.crc32_err.into(),
        d.hw_dec.into(),
        d.sw_dec.into(),
        d.addr1_match.into(),
        d.ampdu.into(),
        d.shift.into(),
        d.bb_sel.into(),
        d.offset.into(),
        d.rxd_len.into(),
        d.ready.into(),
        d.frame_type.into(),
        d.addr_cam_valid.into(),
        d.addr_cam_id.into(),
        d.sec_cam_id.into(),
        d.mac_id.into(),
        d.rx_pl_id.into(),
        d.sec_type.into(),
    ]
}

/// One oracle case's input, replayed: the words the C oracle wrote for it.
fn replay(input: &[u8]) -> Vec<u32> {
    let word = |at: usize| u32::from_le_bytes(input[at..at + 4].try_into().unwrap());
    let (buf_len, frame_len) = (word(0) as usize, word(4) as usize);
    let current = input[8];
    let buf = &input[12..12 + buf_len];
    let frame_at = 12 + buf_len.next_multiple_of(4);
    let frame = &input[frame_at..frame_at + frame_len];
    let desc = RxDescInfo::query(buf, 4).unwrap();
    let mut out = desc_words(&desc);
    if desc.pkt_type != RX_TYPE_PPDU_STAT {
        return out;
    }
    let rx_len = (u32::from_le_bytes(buf[..4].try_into().unwrap()) & 0x3fff) as usize;
    let (phy, error) = PhyPpdu::process(&desc, &buf[desc.packet_offset()..rx_len]);
    out.push(match error {
        None => 0,
        Some(PpduError::UserNumber(_) | PpduError::MacInfoLength) => 1,
        Some(PpduError::Invalid | PpduError::LengthMismatch { .. } | PpduError::Truncated) => 2,
        Some(PpduError::Bypassed(_) | PpduError::ParseFailed) => 3,
    });
    out.push(phy.rssi_avg.into());
    out.extend(phy.rssi.map(u32::from));
    out.extend(
        [phy.mac_id, phy.chan_idx, phy.phy_idx, phy.ie]
            .map(u32::from)
            .into_iter()
            .chain([phy.rate.into()])
            .chain([phy.rpl_avg, phy.rx_path_en].map(u32::from)),
    );
    out.extend([u32::from(phy.ofdm_has)]);
    out.extend([phy.avg_snr, phy.evm_max, phy.evm_min].map(u32::from));
    out.extend(
        [
            phy.has_data,
            phy.has_bcn,
            phy.su,
            phy.ldpc,
            phy.stbc,
            phy.bf,
            phy.to_self,
            phy.valid,
            phy.hdr_2_en,
            phy.ie09,
        ]
        .map(u32::from),
    );
    let mut status = RxStatus::default();
    status.query_ppdu(&phy);
    out.extend([
        i32::from(status.signal) as u32,
        status.chains.into(),
        i32::from(status.chain_signal[0]) as u32,
        i32::from(status.chain_signal[1]) as u32,
        status.freq,
        status.band.into(),
    ]);
    if frame.is_empty() {
        return out;
    }
    let frame_desc = RxDescInfo::query(frame, 4).unwrap();
    let rx = RxStatus::update(&frame_desc, 0, NL80211_BAND_2GHZ);
    out.extend([rx.rate_idx, rx.he_gi, rx.bw].map(u32::from));
    out.push(ppdu_match(current, &desc, &rx).into());
    out
}

#[test]
#[ignore = "oracle: STELA_RTW89_TRX_ORACLE"]
fn rxdesc_matches_unchanged_c() {
    use super::super::pci::tests::segment;
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_TRX_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trx_trace.bin")).unwrap();
    let (mut offset, mut cases, mut ppdu, mut valid, mut matched) = (0, 0, 0, 0, 0);
    while offset < trace.len() {
        let input = segment(&trace, &mut offset);
        let expected: Vec<u32> = segment(&trace, &mut offset)
            .chunks(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();
        let actual = replay(input);
        if expected != actual {
            let first = expected
                .iter()
                .zip(&actual)
                .position(|(e, a)| e != a)
                .unwrap_or(expected.len().min(actual.len()));
            panic!(
                "case {cases}: word {first} of {}/{}: C {:x?}, Rust {:x?}",
                expected.len(),
                actual.len(),
                expected.get(first),
                actual.get(first)
            );
        }
        if expected.len() > 31 {
            ppdu += 1;
            valid += usize::from(expected[31] == 0);
        }
        if expected.len() > 31 + 33 {
            matched += usize::from(expected[31 + 33 + 3] == 1);
        }
        cases += 1;
    }
    assert_eq!(offset, trace.len());
    // Every kind the generator makes, each reached.
    assert_eq!((cases, ppdu), (617, 417));
    assert!(
        valid > 40 && matched > 20,
        "{valid} parsed, {matched} matched"
    );
}
