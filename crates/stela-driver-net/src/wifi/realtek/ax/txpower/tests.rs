extern crate std;

use super::super::{
    elements::{Board, Elements, Id},
    io::{CR_BASE, Error as IoError, Io},
    pci::tests::segment,
    regd::{self, ETSI, FCC, Regulation, WW},
    rtw8852b::txpower::{bb_cal_txpwr_ref, set_txpwr, set_txpwr_ctrl, set_txpwr_ref},
};
use super::*;
use crate::wifi::{realtek::firmware::Rtw89, regulatory::database::tests::country_of};
use alloc::{vec, vec::Vec};

/// BAR2 as the C oracle's harness holds it: byte `i` starts as
/// `i * 37 + 11`; reads and writes of any width are logged as the oracle
/// logs them, reads tagged by width and writes by 4 plus width.
pub(crate) struct Model {
    memory: Vec<u8>,
    pub(crate) log: Vec<u8>,
}

impl Model {
    pub(crate) fn new() -> Self {
        Self {
            memory: (0..0x2_0000usize).map(|at| (at * 37 + 11) as u8).collect(),
            log: Vec::new(),
        }
    }
    fn record(&mut self, tag: u32, register: u32, value: u32) {
        for word in [tag, register, value] {
            self.log.extend_from_slice(&word.to_le_bytes());
        }
    }
    fn get(&mut self, register: u32, width: u32) -> Result<u32, IoError> {
        let at = register as usize;
        let bytes = self
            .memory
            .get(at..at + width as usize)
            .ok_or(IoError::Register { register })?;
        let mut word = [0; 4];
        word[..bytes.len()].copy_from_slice(bytes);
        let value = u32::from_le_bytes(word);
        self.record(width, register, value);
        Ok(value)
    }
    fn set(&mut self, register: u32, width: u32, value: u32) -> Result<(), IoError> {
        let at = register as usize;
        let bytes = self
            .memory
            .get_mut(at..at + width as usize)
            .ok_or(IoError::Register { register })?;
        bytes.copy_from_slice(&value.to_le_bytes()[..width as usize]);
        self.record(4 + width, register, value);
        Ok(())
    }
}

// SAFETY: a test's own memory; nothing else reaches it, and delays take no
// time because nothing waits on them.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, IoError> {
        self.get(register, 1).map(|v| v as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, IoError> {
        self.get(register, 2).map(|v| v as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, IoError> {
        self.get(register, 4)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), IoError> {
        self.set(register, 1, value.into())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), IoError> {
        self.set(register, 2, value.into())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), IoError> {
        self.set(register, 4, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.record(9, 0, microseconds as u32);
    }
}

/// A `struct rtw89_fw_element_hdr` and its body, padded to the next
/// element's 16-byte boundary.
fn element(id: Id, fixed: [u8; 8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(id as u32).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&[1, 2, 3, 4]);
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&fixed);
    out.extend_from_slice(body);
    out.resize(out.len().next_multiple_of(16), 0);
    out
}

fn regs(n: u32) -> Vec<u8> {
    (0..n)
        .flat_map(|i| [0x4000 + 4 * i, i].into_iter().flat_map(u32::to_le_bytes))
        .collect()
}

/// A TX power element of RFE type `rfe`, its entries `ent_sz` bytes each.
fn txpwr(id: Id, rfe: u8, ent_sz: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    let n = (entries.len() as u32).to_le_bytes();
    let body: Vec<u8> = entries.iter().flatten().copied().collect();
    element(id, [0, 0, rfe, ent_sz, n[0], n[1], n[2], n[3]], &body)
}

fn byrate(band: u8, nss: u8, rs: u8, shf: u8, len: u8, data: u32, bw: u8) -> Vec<u8> {
    let mut e = vec![band, nss, rs, shf, len];
    e.extend_from_slice(&data.to_le_bytes());
    e.extend_from_slice(&[bw, 0]);
    e
}

/// Firmware elements an RTL8852B accepts: the register tables, a tracking
/// table, and TX power tables of RFE 0 and RFE 3 whose values differ by
/// `rfe * 4`. The limits name ETSI at channels 1 and 36 and the worldwide
/// regulation at channel 6.
fn firmware() -> Vec<u8> {
    let mut file = vec![0; 16];
    file.extend(element(Id::BbReg, [0; 8], &regs(2)));
    file.extend(element(Id::RadioA, [0; 8], &regs(2)));
    file.extend(element(Id::RadioB, [1, 0, 0, 0, 0, 0, 0, 0], &regs(2)));
    file.extend(element(Id::RfNctl, [0; 8], &regs(2)));
    file.extend(element(
        Id::TxpwrTrk,
        [0xf0, 0xff, 0, 0, 0, 0, 0, 0],
        &[0; 600],
    ));
    for rfe in [0u8, 3] {
        let up = rfe * 4;
        let rows = vec![
            // CCK at 10 dBm, OFDM at 12 dBm, then 2.4 GHz MCS of 2 SS.
            byrate(0, 0, RS_CCK, 0, 4, u32::from_le_bytes([40 + up; 4]), 0),
            byrate(0, 0, RS_OFDM, 0, 4, u32::from_le_bytes([48 + up; 4]), 0),
            byrate(0, 1, RS_MCS, 4, 4, 0x2c2a_2826, 0),
            byrate(1, 0, RS_OFFSET, 0, 4, 0x0100_ff02, 0),
            // An unknown section and a bandwidth past the table: skipped.
            byrate(0, 0, 9, 0, 4, 0x7f7f_7f7f, 0),
            byrate(0, 0, RS_CCK, 0, 4, 0x7f7f_7f7f, 5),
        ];
        let mut long = byrate(1, 0, RS_OFDM, 4, 4, u32::from_le_bytes([36 + up; 4]), 0);
        long.push(0);
        let mut bad = byrate(1, 0, RS_OFDM, 0, 4, 0x7f7f_7f7f, 0);
        bad.push(1);
        let mut byrate_rows: Vec<Vec<u8>> = rows
            .into_iter()
            .map(|mut row| {
                row.push(0);
                row
            })
            .collect();
        // An entry longer than rtw89's struct is taken only when its excess
        // is zero.
        byrate_rows.push(long);
        byrate_rows.push(bad);
        file.extend(txpwr(Id::TxpwrByrate, rfe, 12, &byrate_rows));
        let lmt = |bw: u8, nt: u8, rs: u8, bf: u8, regd: u8, ch: u8, v: i8| {
            vec![bw, nt, rs, bf, regd, ch, v as u8]
        };
        file.extend(txpwr(
            Id::TxpwrLmt2ghz,
            rfe,
            7,
            &[
                lmt(0, 0, RS_OFDM, 0, ETSI, 0, 60 + up as i8),
                lmt(0, 1, RS_OFDM, 0, ETSI, 0, 50),
                lmt(0, 0, RS_OFDM, 0, WW, 5, 44),
                lmt(0, 0, RS_OFDM, 0, ETSI, 12, 127),
                lmt(0, 0, RS_OFDM, 1, ETSI, 12, -128),
                // Past the 2.4 GHz widths: skipped.
                lmt(2, 0, RS_OFDM, 0, ETSI, 0, 1),
            ],
        ));
        file.extend(txpwr(
            Id::TxpwrLmt5ghz,
            rfe,
            7,
            &[
                lmt(0, 0, RS_OFDM, 0, ETSI, 0, 56),
                lmt(2, 0, RS_MCS, 0, FCC, 3, 70),
            ],
        ));
        let ru = |ru: u8, nt: u8, regd: u8, ch: u8, v: i8| vec![ru, nt, regd, ch, v as u8];
        file.extend(txpwr(
            Id::TxpwrLmtRu2ghz,
            rfe,
            5,
            &[ru(RU26, 0, ETSI, 0, 30)],
        ));
        file.extend(txpwr(
            Id::TxpwrLmtRu5ghz,
            rfe,
            5,
            &[ru(RU106, 1, WW, 0, 20)],
        ));
        file.extend(txpwr(
            Id::TxShapeLmt,
            rfe,
            5,
            &[vec![0, RS_CCK, ETSI, 1 + rfe, 0]],
        ));
        file.extend(txpwr(Id::TxShapeLmtRu, rfe, 4, &[vec![0, ETSI, 2, 0]]));
    }
    file.extend([0; 16]);
    file
}

fn tables(file: &[u8], rfe: u8) -> Tables {
    let elements = Elements::parse(&file[16..], 16, Board::rtl8852b(rfe, 1), |_, _| {}).unwrap();
    Tables::load(elements.rfe_data.as_ref()).unwrap()
}

fn id() -> Regulation {
    Regulation::new(&regd::RTW89_REGD_MAP, [0xff; 2], *b"ID")
}

fn power<'a>(tables: &'a Tables, regulation: &'a Regulation) -> Power<'a> {
    Power {
        tables,
        regulation,
        cap: Cap::NONE,
    }
}

const fn ofdm(idx: u8) -> RateDesc {
    RateDesc {
        nss: 0,
        rs: RS_OFDM,
        ofdma: 0,
        idx,
    }
}

#[test]
fn a_board_without_its_own_tables_takes_rfe_0s() {
    let file = firmware();
    let (rfe0, rfe1, rfe3) = (tables(&file, 0), tables(&file, 1), tables(&file, 3));
    assert_eq!(rfe1, rfe0);
    assert_ne!(rfe3, rfe0);
    let regulation = id();
    // CCK at 40 quarter dB, read in half dB, on 5 GHz too.
    assert_eq!(
        power(&rfe1, &regulation).read_byrate(Band::Ghz5, 0, &RateDesc::default()),
        20
    );
    assert_eq!(
        power(&rfe3, &regulation).read_byrate(Band::Ghz2, 0, &RateDesc::default()),
        26
    );
    let mcs = RateDesc {
        nss: 1,
        rs: RS_MCS,
        ofdma: 0,
        idx: 5,
    };
    assert_eq!(
        power(&rfe1, &regulation).read_byrate(Band::Ghz2, 0, &mcs),
        0x28 >> 1
    );
}

#[test]
fn entries_are_checked_and_copied_as_rtw89_copies_them() {
    let file = firmware();
    let tables = tables(&file, 1);
    let regulation = id();
    let power = power(&tables, &regulation);
    // The zero-padded long entry is taken, the one with a set excess byte
    // and the unknown section are not.
    assert_eq!(power.read_byrate(Band::Ghz5, 0, &ofdm(4)), 18);
    assert_eq!(power.read_byrate(Band::Ghz5, 0, &ofdm(0)), 0);
    assert_eq!(tables.byr(0, 0).unwrap().trap, 0);
    // A width past the by-rate table and past the 2.4 GHz limits: nothing.
    assert!(tables.byr(0, 5).is_none());
    let at = LimitAt {
        bw: 2,
        ntx: 0,
        rs: RS_OFDM,
        bf: 0,
        regd: ETSI,
        ch_idx: 0,
    };
    assert_eq!(tables.lmt(Band::Ghz2, at), 0);
    // Offsets: 2, -1, 0, 1 quarter dB read in half dB.
    let offset = |idx| RateDesc {
        nss: 0,
        rs: RS_OFFSET,
        ofdma: 0,
        idx,
    };
    let read: Vec<i8> = (0..4)
        .map(|idx| power.read_byrate(Band::Ghz5, 0, &offset(idx)))
        .collect();
    assert_eq!(read, [1, -1, 0, 0]);
}

#[test]
fn a_limit_falls_back_to_worldwide_and_is_held_to_mac_range() {
    let file = firmware();
    let tables = tables(&file, 1);
    let regulation = id();
    let power = power(&tables, &regulation);
    let limit = |ntx, bf, ch| power.read_limit(Band::Ghz2, 0, ntx, RS_OFDM, bf, ch);
    // ETSI's own at channel 1, per NTX.
    assert_eq!(limit(0, 0, 1), 30);
    assert_eq!(limit(1, 0, 1), 25);
    // None for ETSI at channel 6: the worldwide one.
    assert_eq!(limit(0, 0, 6), 22);
    // Neither: 0.
    assert_eq!(limit(0, 0, 11), 0);
    // 127 quarter dB is 63 half dB; -128 is -64.
    assert_eq!(limit(0, 0, 13), 63);
    assert_eq!(limit(0, 1, 13), -64);
    // 5 GHz widths reach 80 MHz, 2.4 GHz's stop at 40.
    assert_eq!(power.read_limit(Band::Ghz2, 2, 0, RS_OFDM, 0, 1), 0);
    let us = Regulation::new(&regd::RTW89_REGD_MAP, [0xff; 2], *b"US");
    let us_power = Power {
        regulation: &us,
        ..power
    };
    assert_eq!(us_power.read_limit(Band::Ghz5, 2, 0, RS_MCS, 0, 42), 35);
    // RU limits fall back alike.
    assert_eq!(power.read_limit_ru(Band::Ghz2, RU26, 0, 1), 15);
    assert_eq!(power.read_limit_ru(Band::Ghz5, RU106, 1, 36), 10);
    assert_eq!(power.read_limit_ru(Band::Ghz5, RU106, 0, 36), 0);
}

#[test]
fn the_pages_take_their_subchannels_and_the_lower_of_the_40_mhz_halves() {
    let file = firmware();
    let tables = tables(&file, 1);
    let regulation = id();
    let power = power(&tables, &regulation);
    let chan = Chan::new(Band::Ghz2, 3, 1, Width::Mhz40).unwrap();
    let page = power.fill_limit(&chan, 0);
    // OFDM reads the primary channel.
    assert_eq!(page[4..6], [30, 0]);
    let chan = Chan::new(Band::Ghz5, 42, 36, Width::Mhz80).unwrap();
    let us = Regulation::new(&regd::RTW89_REGD_MAP, [0xff; 2], *b"US");
    let page = Power {
        regulation: &us,
        ..power
    }
    .fill_limit(&chan, 0);
    assert_eq!(page[30], 35);
    let ru = power.fill_limit_ru(&Chan::new(Band::Ghz2, 3, 1, Width::Mhz40).unwrap(), 0);
    assert_eq!(ru[..2], [15, 0]);
}

#[test]
fn the_eirp_cap_bounds_each_limit_per_ntx() {
    assert_eq!(Cap::eirp(2000).mac, [28, 21]);
    assert_eq!(Cap::eirp(3000).mac, [48, 41]);
    // Floored, never rounded up past the EIRP: 19.99 dBm less 6 dBi.
    assert_eq!(Cap::eirp(1999).mac, [27, 21]);
    assert_eq!(Cap::eirp(i32::MIN).mac, [-64, -64]);
    assert_eq!(Cap::eirp(i32::MAX).mac, [63, 63]);
    let file = firmware();
    let tables = tables(&file, 1);
    let regulation = id();
    let capped = Power {
        cap: Cap::eirp(2000),
        ..power(&tables, &regulation)
    };
    // 30 under a cap of 28 at 1TX; 25 under 21 at 2TX; a worldwide 22
    // under 28 stays.
    assert_eq!(capped.read_limit(Band::Ghz2, 0, 0, RS_OFDM, 0, 1), 28);
    assert_eq!(capped.read_limit(Band::Ghz2, 0, 1, RS_OFDM, 0, 1), 21);
    assert_eq!(capped.read_limit(Band::Ghz2, 0, 0, RS_OFDM, 0, 6), 22);
    assert_eq!(capped.read_limit_ru(Band::Ghz2, RU26, 0, 1), 15);
    let low = Power {
        cap: Cap::eirp(700),
        ..capped
    };
    assert_eq!(low.read_limit_ru(Band::Ghz2, RU26, 0, 1), 2);
    // The rule holding the whole channel decides; none, no transmission.
    let country = country_of(&[
        (2_400_000, 2_483_500, 40_000, 2000, 0),
        (5_150_000, 5_250_000, 80_000, 2300, 0),
    ]);
    let ch1 = Chan::new(Band::Ghz2, 1, 1, Width::Mhz20).unwrap();
    assert_eq!(Cap::country(&country, &ch1), Some(Cap::eirp(2000)));
    let ch42 = Chan::new(Band::Ghz5, 42, 36, Width::Mhz80).unwrap();
    assert_eq!(Cap::country(&country, &ch42), Some(Cap::eirp(2300)));
    let ch149 = Chan::new(Band::Ghz5, 149, 149, Width::Mhz20).unwrap();
    assert_eq!(Cap::country(&country, &ch149), None);
}

#[test]
fn missing_tables_are_refused_naming_them() {
    assert_eq!(Tables::load(None), Err(Error::Missing(TxpwrSlot::Byrate)));
    let file = firmware();
    let mut elements = Elements::parse(&file[16..], 16, Board::rtl8852b(1, 1), |_, _| {}).unwrap();
    let rfe = elements.rfe_data.as_mut().unwrap();
    rfe.confs[TxpwrSlot::TxShapeLmtRu as usize] = None;
    assert_eq!(
        Tables::load(Some(&*rfe)),
        Err(Error::Missing(TxpwrSlot::TxShapeLmtRu))
    );
}

#[test]
fn channels_are_those_rtw89_tunes() {
    let ok = |band, ch, pri, width| Chan::new(band, ch, pri, width).is_ok();
    assert!(ok(Band::Ghz2, 1, 1, Width::Mhz20));
    assert!(ok(Band::Ghz2, 14, 14, Width::Mhz20));
    assert!(ok(Band::Ghz2, 11, 13, Width::Mhz40));
    assert!(!ok(Band::Ghz2, 12, 14, Width::Mhz40));
    assert!(!ok(Band::Ghz2, 7, 7, Width::Mhz80));
    assert!(!ok(Band::Ghz2, 3, 3, Width::Mhz40));
    assert!(ok(Band::Ghz5, 42, 48, Width::Mhz80));
    assert!(!ok(Band::Ghz5, 46, 44, Width::Mhz80));
    assert!(ok(Band::Ghz5, 155, 161, Width::Mhz80));
    assert!(ok(Band::Ghz5, 171, 177, Width::Mhz80));
    assert!(ok(Band::Ghz5, 142, 144, Width::Mhz40));
    assert!(!ok(Band::Ghz5, 144, 144, Width::Mhz40));
    assert!(!ok(Band::Ghz5, 152, 152, Width::Mhz20));
    assert!(!ok(Band::Ghz5, 68, 68, Width::Mhz20));
    let chan = Chan::new(Band::Ghz5, 106, 100, Width::Mhz80).unwrap();
    assert_eq!(chan.subchannels().collect::<Vec<_>>(), [100, 104, 108, 112]);
    assert_eq!(chan.freq_mhz(), 5530);
    assert_eq!(channel_freq_mhz(Band::Ghz2, 14), 2484);
}

#[test]
fn the_reference_is_rtw89s_codewords() {
    // 0 dB: TSSI offset 172, power codeword 312, reference 0.
    assert_eq!(bb_cal_txpwr_ref(0, 0), (172 << 18) | (312 << 9));
    // 3 dB less: RF codeword 36, BB 0.
    assert_eq!(bb_cal_txpwr_ref(0, 24), ((172 - 24) << 18) | (288 << 9));
    // Far less: the RF codeword stays at 15, the TSSI offset wraps.
    assert_eq!(bb_cal_txpwr_ref(0, 300) & DPD_PWR_CW_FIELD, 15 << 12);
}

const DPD_PWR_CW_FIELD: u32 = 0x3f << 12;

#[test]
fn set_txpwr_writes_every_page_then_the_reference() {
    let file = firmware();
    let tables = tables(&file, 1);
    let regulation = id();
    let power = power(&tables, &regulation);
    let mut io = Model::new();
    let chan = Chan::new(Band::Ghz2, 6, 6, Width::Mhz20).unwrap();
    set_txpwr(&mut io, &power, &chan).unwrap();
    let writes: Vec<u32> = io
        .log
        .as_chunks::<12>()
        .0
        .iter()
        .filter(|record| record[0] == 8)
        .map(|record| u32::from_le_bytes(record[4..8].try_into().unwrap()))
        .collect();
    // 11 by-rate words, the offsets, 8 DFIR words and the shape, 20 limit
    // words, 12 RU limit words, then the reference.
    assert_eq!(writes.len(), 11 + 1 + 9 + 20 + 12 + 5);
    assert_eq!(
        writes[..11],
        (0..11).map(|i| PWR_BY_RATE + 4 * i).collect::<Vec<_>>()
    );
    assert_eq!(writes[11], PWR_RATE_OFST_CTRL);
    assert_eq!(writes[12], CR_BASE + 0x2300);
    assert_eq!(
        writes[21..41],
        (0..20).map(|i| PWR_LMT + 4 * i).collect::<Vec<_>>()
    );
    assert_eq!(writes[53], PWR_RATE_CTRL);
    assert_eq!(
        writes[54..],
        [
            CR_BASE + 0x5804,
            CR_BASE + 0x7804,
            CR_BASE + 0x5808,
            CR_BASE + 0x7808
        ]
    );
    let mut ctrl = Model::new();
    set_txpwr_ctrl(&mut ctrl).unwrap();
    let mut reference = Model::new();
    set_txpwr_ref(&mut reference, 0).unwrap();
    assert_eq!(ctrl.log, reference.log);
}

/// `[a, b]` as rtw89 packs an alpha2 into the trace's word.
fn alpha2(word: u32) -> [u8; 2] {
    [word as u8, (word >> 8) as u8]
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_IMAGES, STELA_RTW89_TXPWR_ORACLE"]
fn txpower_writes_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_TXPWR_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let images = std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap());
    let pinned = std::fs::read(images.join("rtw89/rtw8852b_fw-2.bin")).unwrap();
    let firmware = Rtw89::parse(&pinned, 1).unwrap();
    let recognized =
        |rfe: u32| Elements::recognize(&firmware, Board::rtl8852b(rfe as u8, 1)).unwrap();
    let words =
        |values: &[u32]| -> Vec<u8> { values.iter().flat_map(|v| v.to_le_bytes()).collect() };
    let (mut offset, mut counts) = (0, [0usize; 6]);
    while offset < trace.len() {
        let got = segment(&trace, &mut offset);
        let word =
            |index: usize| u32::from_le_bytes(got[index * 4..index * 4 + 4].try_into().unwrap());
        let kind = word(0);
        let expected = match kind {
            1 => {
                let elements = recognized(1);
                let map = if word(1) == 0 {
                    regd::map(&elements)
                } else {
                    &regd::RTW89_REGD_MAP
                };
                let r = Regulation::new(map, alpha2(word(2)), alpha2(word(3)));
                let regd = r.regd();
                let unii4 = if r.unii4() { 0 } else { 0b111 };
                words(&[
                    1,
                    word(1),
                    word(2),
                    word(3),
                    u32::from(u16::from_le_bytes(regd.alpha2)),
                    regd.txpwr_regd[0].into(),
                    regd.txpwr_regd[1].into(),
                    regd.txpwr_regd[2].into(),
                    regd.func_bitmap.into(),
                    r.txpwr_regd(Band::Ghz2).into(),
                    r.txpwr_regd(Band::Ghz5).into(),
                    r.programmed.into(),
                    r.is_ww().into(),
                    unii4,
                    map.len() as u32,
                ])
            }
            2 => {
                let rfe = word(1);
                let elements = recognized(rfe);
                let data = elements.rfe_data.as_ref();
                let has_da = [
                    TxpwrSlot::DaLmt2ghz,
                    TxpwrSlot::DaLmtRu2ghz,
                    TxpwrSlot::DaLmt5ghz,
                    TxpwrSlot::DaLmtRu5ghz,
                ]
                .iter()
                .all(|&slot| data.and_then(|d| d.conf(slot)).is_some());
                let mut expected = words(&[2, rfe, has_da.into()]);
                for slot in TxpwrSlot::ALL {
                    let conf = data.and_then(|d| d.conf(slot));
                    expected.extend(words(&[conf.map_or(u32::MAX, |c| c.rfe_type.into())]));
                }
                expected.extend(Tables::load(data).unwrap().bytes());
                expected
            }
            3 => {
                let elements = recognized(word(1));
                let tables = Tables::load(elements.rfe_data.as_ref()).unwrap();
                let map = if word(2) == 0 {
                    regd::map(&elements)
                } else {
                    &regd::RTW89_REGD_MAP
                };
                let regulation = Regulation::new(map, [0xff; 2], alpha2(word(3)));
                let band = if word(4) == 0 { Band::Ghz2 } else { Band::Ghz5 };
                let width = [Width::Mhz20, Width::Mhz40, Width::Mhz80][word(7) as usize];
                let chan = Chan::new(band, word(5) as u8, word(6) as u8, width).unwrap();
                let power = Power {
                    tables: &tables,
                    regulation: &regulation,
                    cap: Cap {
                        mac: [word(8) as i8, word(9) as i8],
                    },
                };
                let mut io = Model::new();
                set_txpwr(&mut io, &power, &chan).unwrap();
                let mut expected = got[..40].to_vec();
                expected.extend(io.log);
                expected
            }
            4 => {
                let mut io = Model::new();
                set_txpwr_ref(&mut io, word(1) as i16).unwrap();
                let mut expected = words(&[4, word(1)]);
                expected.extend(io.log);
                expected
            }
            5 => {
                let mut io = Model::new();
                set_txpwr_ctrl(&mut io).unwrap();
                let mut expected = words(&[5]);
                expected.extend(io.log);
                expected
            }
            _ => panic!("segment kind {kind}"),
        };
        assert!(
            got == expected.as_slice(),
            "case {}: kind {kind}, header {:?}",
            counts.iter().sum::<usize>(),
            got.as_chunks::<4>()
                .0
                .iter()
                .take(10)
                .map(|w| u32::from_le_bytes(*w))
                .collect::<Vec<_>>()
        );
        counts[kind as usize] += 1;
    }
    assert_eq!(offset, trace.len());
    assert_eq!(counts, ORACLE_COUNTS);
}

/// Segments the oracle writes, by kind: regulations, tables, `set_txpwr`
/// channels, references at an offset, `set_txpwr_ctrl`.
const ORACLE_COUNTS: [usize; 6] = [0, 48, 2, 72, 9, 1];
