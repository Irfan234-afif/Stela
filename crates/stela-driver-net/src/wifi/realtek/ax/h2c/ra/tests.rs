// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
extern crate std;
use super::*;
use crate::wifi::realtek::ax::{
    c2h::C2h,
    h2c::{Function, Sequence, phy::outsrc},
    io,
};
use alloc::vec::Vec;

/// No register is touched on the way to `rtw89_h2c_tx`.
struct NoIo;

// SAFETY: a stand-in of this test alone; it reaches no hardware and refuses
// every access.
unsafe impl Io for NoIo {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Err(io::Error::Register { register })
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Err(io::Error::Register { register })
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Err(io::Error::Register { register })
    }
    fn write8(&mut self, register: u32, _: u8) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn write16(&mut self, register: u32, _: u16) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn write32(&mut self, register: u32, _: u32) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn delay_us(&mut self, _: u64) {}
}

/// The C oracle's `rtw89_h2c_tx`: each H2C as `rtw89_h2c_pkt_set_hdr` built
/// it, header and payload.
#[derive(Default)]
struct Recorder {
    sequence: Sequence,
    sent: Vec<Vec<u8>>,
}

impl Recorder {
    fn keep(&mut self, function: Function, rack: bool, dack: bool, payload: &[u8]) {
        let header = self
            .sequence
            .set_hdr(function, rack, dack, payload.len() as u32);
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(payload);
        self.sent.push(bytes);
    }
}

impl<I: Io + ?Sized> Outsrc<I> for Recorder {
    fn send_outsrc(
        &mut self,
        _: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), Error> {
        self.keep(outsrc(class, func), rack, dack, payload);
        Ok(())
    }
}

impl<I: Io + ?Sized> Commands<I> for Recorder {
    fn send(
        &mut self,
        _: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), Error> {
        self.keep(Function::mac(class, func), rack, dack, payload);
        Ok(())
    }
}

/// An HE 2SS 80 MHz AP of the user's kind: HT and VHT with SGI, LDPC and
/// one STBC stream, a VHT and HE SU beamformer with DCM.
fn he_ap() -> LinkSta {
    LinkSta {
        supp_rates: 0xff,
        ht: Some(HtCap {
            cap: 0x0161,
            rx_mask: [0xff, 0xff, 0, 0],
        }),
        vht: Some(VhtCap {
            cap: 0x0130 | 0x800,
            rx_mcs_map: 0xfffa,
        }),
        he: Some(HeCap {
            phy: [0x04, 0x20, 0x08, 0x98, 0, 0, 0x20, 0, 0, 0, 0],
            rx_mcs_80: 0xfffa,
            rx_mcs_160: 0,
            rx_mcs_80p80: 0,
        }),
        bandwidth: StaBandwidth::Mhz80,
        rx_nss: 2,
    }
}

/// -50 dBm, on 5 GHz, MAC ID 0, two TX streams.
const LINK: Link = Link {
    band: Band::Ghz5,
    mac_id: 0,
    er_cap: false,
    rssi: 120,
    tx_nss: 2,
};

#[test]
fn an_he80_two_stream_ap_gets_rtw89s_ra_command() {
    let ra = Ra::assoc(&he_ap(), &LINK);
    assert!(ra.csi, "the AP beamforms");
    let info = ra.info;
    assert_eq!(info.mode_ctrl, RA_MODE_HE | RA_MODE_OFDM);
    assert_eq!(info.bw_cap, CHANNEL_WIDTH_80);
    assert_eq!(info.ss_num, 1);
    // HE 1SS MCS 4-11 and 2SS MCS 0-11: the RSSI level drops 6 Mbps and
    // HE 1SS MCS 0-3; the OFDM rates are not among an HE peer's.
    assert_eq!(info.ra_mask, 0xf_ffff_0000);
    assert!(info.en_sgi && info.ldpc_cap && info.stbc_cap && info.dcm_cap);
    assert_eq!((info.fix_giltf_en, info.fix_giltf), (true, GILTF_2XHE08));
    assert_eq!((info.init_rate_lv, info.upd_all), (1, true));
    let words: Vec<u32> = ra
        .payload()
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    assert_eq!(words, [0x01f5_00a4, 0xffff_0000, 0x8000_000f, 0x4305_3900]);

    let mut recorder = Recorder::default();
    ra.send(&mut NoIo, &mut recorder).unwrap();
    let header = &recorder.sent[0][..8];
    // OUTSRC, class RA, function MACIDCFG, 24 bytes, REC_ACK at sequence 0.
    assert_eq!(header, [0x06, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00]);
}

#[test]
fn an_update_asks_what_changed_without_csi() {
    let ra = Ra::update(&he_ap(), &LINK, RC_BW_CHANGED | RC_SUPP_RATES_CHANGED);
    assert!(!ra.csi);
    assert!(ra.info.upd_mask && ra.info.upd_bw_nss_mask && !ra.info.upd_all);
    assert_eq!(ra.info.init_rate_lv, 0);
    assert_eq!(ra.info.csi_mode, 0);
    assert_eq!(ra.payload()[8..12], 0xfu32.to_le_bytes(), "no BFEE_CSI_CTL");
}

#[test]
fn rssi_levels_and_recovery_follow_rtw89() {
    // Under 33 dB over -110 dBm keeps all; 103 and up keeps all too.
    assert_eq!(ra_mask_rssi(64, 0), u64::MAX);
    assert_eq!(ra_mask_rssi(66, 0), 0xffff_ffff_ffff_fff0);
    assert_eq!(ra_mask_rssi(200, 0), 0xffff_ffff_ffff_0f00);
    assert_eq!(ra_mask_rssi(206, 0), u64::MAX);
    assert_eq!(ra_mask_recover(0x0f00, 0xf0ff0), 0xf0f00);
    assert_eq!(ra_mask_recover(0, 0xff0), 0xff0);
    assert!(can_er(true, 0) && !can_er(true, HE_OPERATION_ER_SU_DISABLE) && !can_er(false, 0));
}

#[test]
fn the_ba_cam_fills_replaces_for_tid_0_and_5_and_misses() {
    let mut cam = BaCam::default();
    let mut recorder = Recorder::default();
    let mut session = |cam: &mut BaCam, valid, tid, ssn| {
        let params = Ampdu {
            tid,
            ssn,
            buf_size: 64,
        };
        cam.send(&mut NoIo, &mut recorder, 3, valid, &params)
            .unwrap()
    };
    assert!(session(&mut cam, true, 1, 10).is_some());
    assert!(session(&mut cam, true, 2, 20).is_some());
    assert_eq!(
        session(&mut cam, true, 3, 30),
        None,
        "full, and not TID 0 or 5"
    );
    let replaced = session(&mut cam, true, 0, 0x123).unwrap();
    // MAC ID 3, entry 0, valid, INIT_REQ, TID 0, SSN 0x123.
    assert_eq!(replaced[..4], 0x1230_0303u32.to_le_bytes());
    assert_eq!(cam.tids(), [Some(0), Some(2)]);
    assert_eq!(session(&mut cam, false, 1, 0), None, "TID 1 lost its entry");
    let released = session(&mut cam, false, 2, 0).unwrap();
    assert_eq!(released, [0x04, 0x03, 0, 0, 0, 0, 0, 0]);
    assert_eq!(cam.tids(), [Some(0), None]);
    // DONE_ACK alone asked, REC_ACK at sequence 0.
    assert_eq!(recorder.sent[0][4..8], [0x10, 0xc0, 0, 0]);
}

#[test]
fn an_he_report_reads_as_rtw89_fills_rate_info() {
    let mut c2h = [0u8; 16];
    c2h[0] = 2 | (1 << 2);
    c2h[4] = 16;
    c2h[12..16].copy_from_slice(&(0x1bu32 | (3 << 8) | (3 << 10) | (2 << 13)).to_le_bytes());
    let rpt = C2h::parse(&c2h).unwrap().ra_report().unwrap().unwrap();
    let report = RaReport::parse(&rpt).unwrap();
    assert_eq!(
        report.rate,
        Rate::He {
            mcs: 11,
            nss: 2,
            gi: HeGi::Us0_8
        }
    );
    assert_eq!(report.bit_rate, 12009);
    assert_eq!(report.hw_rate, 0x19b);
    assert!(!report.might_fallback_legacy);
    assert_eq!(report.max_amsdu_len(), MAX_AMSDU_LIMIT);
    assert_eq!(max_agg_wait(report.max_amsdu_len()), 2);
    assert_eq!(max_agg_wait(1), -1);
    assert!(
        C2h::parse(&c2h[..12])
            .unwrap()
            .ra_report()
            .is_none_or(|r| r.is_err())
    );
}

/// Little-endian words and bytes in order.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> &'a [u8] {
        let bytes = &self.bytes[self.at..self.at + length];
        self.at += length;
        bytes
    }
    fn word(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn words<const N: usize>(&mut self) -> [u32; N] {
        core::array::from_fn(|_| self.word())
    }
}

/// The peer and link a trace's 22 input words describe.
fn ra_case(w: &[u32; 22]) -> (LinkSta, Link, u32) {
    let phy: Vec<u8> = w[15..18].iter().flat_map(|w| w.to_le_bytes()).collect();
    let sta = LinkSta {
        supp_rates: w[7],
        ht: (w[8] != 0).then(|| HtCap {
            cap: w[9] as u16,
            rx_mask: w[10].to_le_bytes(),
        }),
        vht: (w[11] != 0).then(|| VhtCap {
            cap: w[12],
            rx_mcs_map: w[13] as u16,
        }),
        he: (w[14] != 0).then(|| HeCap {
            phy: phy[..11].try_into().unwrap(),
            rx_mcs_80: w[18] as u16,
            rx_mcs_160: w[19] as u16,
            rx_mcs_80p80: w[20] as u16,
        }),
        bandwidth: [
            StaBandwidth::Mhz20,
            StaBandwidth::Mhz40,
            StaBandwidth::Mhz80,
            StaBandwidth::Mhz160,
        ][w[1] as usize],
        rx_nss: w[6] as u8,
    };
    let link = Link {
        band: if w[0] == 0 { Band::Ghz2 } else { Band::Ghz5 },
        mac_id: w[4] as u8,
        er_cap: w[3] != 0,
        rssi: w[2] as u8,
        tx_nss: w[5] as u8,
    };
    (sta, link, w[21])
}

#[test]
#[ignore = "oracle: STELA_RTW89_RA_ORACLE"]
fn ra_ba_cam_and_report_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_RA_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut reader = Reader {
        bytes: &trace,
        at: 0,
    };
    let mut recorder = Recorder::default();

    let count = reader.word();
    for case in 0..count {
        let (sta, link, changed) = ra_case(&reader.words::<22>());
        Ra::assoc(&sta, &link)
            .send(&mut NoIo, &mut recorder)
            .unwrap();
        Ra::update(&sta, &link, changed)
            .send(&mut NoIo, &mut recorder)
            .unwrap();
        let update = recorder.sent.pop().unwrap();
        let assoc = recorder.sent.pop().unwrap();
        assert_eq!(assoc, reader.take(24), "RA case {case}: assoc, {sta:x?}");
        assert_eq!(update, reader.take(24), "RA case {case}: update, {sta:x?}");
    }

    let mut cam = BaCam::default();
    let count = reader.word();
    for op in 0..count {
        let [mac_id, valid, tid, ssn, buf_size] = reader.words::<5>();
        let [ret, sent, state] = reader.words::<3>();
        let expected = reader.take(16);
        let params = Ampdu {
            tid: tid as u8,
            ssn: ssn as u16,
            buf_size: buf_size as u16,
        };
        let payload = cam
            .send(&mut NoIo, &mut recorder, mac_id as u8, valid != 0, &params)
            .unwrap();
        assert_eq!(ret, 0);
        assert_eq!(payload.is_some(), sent != 0, "BA operation {op}");
        let tids = cam.tids();
        let ours = tids
            .iter()
            .enumerate()
            .fold(0, |state, (index, tid)| match tid {
                Some(tid) => state | (1 << index) | (u32::from(*tid) << (8 + 8 * index)),
                None => state | (0xff << (8 + 8 * index)),
            });
        assert_eq!(ours, state, "BA operation {op}: entries");
        let actual = if payload.is_some() {
            recorder.sent.pop().unwrap()
        } else {
            alloc::vec![0; 16]
        };
        assert_eq!(actual, expected, "BA operation {op}");
    }

    let count = reader.word();
    for case in 0..count {
        let [mac_id, w2, w3, stub, initial] = reader.words::<5>();
        let expected = reader.words::<13>();
        let mut c2h = [0u8; 16];
        c2h[0] = 2 | (1 << 2);
        c2h[4] = 16;
        c2h[8..12].copy_from_slice(&w2.to_le_bytes());
        c2h[12..16].copy_from_slice(&w3.to_le_bytes());
        let rpt = C2h::parse(&c2h).unwrap().ra_report().unwrap().unwrap();
        let report = (rpt.mac_id == mac_id as u8)
            .then(|| RaReport::parse(&rpt))
            .flatten();
        let actual = report.map_or([0; 13], |report| {
            let (kind, short_gi, mcs, nss, gi, legacy) = match report.rate {
                Rate::Legacy(bitrate) => (0, false, 0, 0, 0, bitrate),
                Rate::Ht { mcs, short_gi } => (1, short_gi, mcs, 0, 0, 0),
                Rate::Vht { mcs, nss, short_gi } => (2, short_gi, mcs, nss, 0, 0),
                Rate::He { mcs, nss, gi } => (3, false, mcs, nss, gi as u32, 0),
            };
            let amsdu = max_amsdu_len(stub, report.might_fallback_legacy);
            [
                1,
                kind | u32::from(short_gi) << 8,
                mcs.into(),
                nss.into(),
                gi,
                report.width.into(),
                legacy.into(),
                report.hw_rate.into(),
                report.might_fallback_legacy.into(),
                report.retry_ratio.into(),
                amsdu.into(),
                u32::from(u32::from(amsdu) != initial),
                max_agg_wait(amsdu) as u32,
            ]
        });
        assert_eq!(actual, expected, "report {case}: {rpt:x?}");
    }
    assert_eq!(reader.at, trace.len());
}
