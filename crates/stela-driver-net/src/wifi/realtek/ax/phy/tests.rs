extern crate std;

use super::*;
use crate::wifi::realtek::{
    ax::{
        elements::RTL8852B_AID,
        h2c::{
            self, Channel, HEADER_LEN, Header, Sequence,
            phy::{H2C_CL_OUTSRC_RF_REG_A, H2C_CL_OUTSRC_RF_REG_B, RF_PAGE_SIZE, outsrc},
        },
        pci::tests::{Domain, Placement, Source, segment},
    },
    firmware::Rtw89,
};
use alloc::{vec, vec::Vec};

/// One record as the C oracle's harness makes it: tag and two values.
/// Reads are tagged by width, writes by 4 plus width, delays 9.
type Rec = (u32, u32, u32);

fn encode(log: &[Rec]) -> Vec<u8> {
    log.iter()
        .flat_map(|&(tag, a, b)| [tag, a, b])
        .flat_map(u32::to_le_bytes)
        .collect()
}

/// How the model's chip misbehaves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Faults {
    /// XTAL SI keeps its poll bit.
    xtal_stuck: bool,
    /// The NCTL report reads 0.
    nctl_stuck: bool,
    /// SWSI reads busy (the C oracle has no such case).
    swsi_busy: bool,
}

const BAR: usize = 0x2_0000;

/// The C oracle's register model: BAR2 as little-endian bytes, byte i
/// holding i * 37 + 11, behaving per aligned word. SWSI reads neither busy
/// bit (unless faulted); the NCTL report reads as written (0 when stuck);
/// WLAN_XTAL_SI_CTRL written with its poll bit answers a read with the XTAL
/// SI register in its data field or applies a write under its mask, then
/// clears the poll bit, unless stuck. XTAL SI register i starts at
/// i * 29 + 0x47.
struct Model {
    memory: Vec<u8>,
    xtal: [u8; 256],
    faults: Faults,
    log: Vec<Rec>,
}

impl Model {
    fn new(faults: Faults) -> Self {
        Self {
            memory: (0..BAR).map(|i| (i * 37 + 11) as u8).collect(),
            xtal: core::array::from_fn(|i| (i * 29 + 0x47) as u8),
            faults,
            log: Vec::new(),
        }
    }

    fn get(&self, register: u32, width: u32) -> u32 {
        (0..width).fold(0, |v, i| {
            v | u32::from(self.memory[(register + i) as usize]) << (8 * i)
        })
    }

    fn set(&mut self, register: u32, width: u32, value: u32) {
        for i in 0..width {
            self.memory[(register + i) as usize] = (value >> (8 * i)) as u8;
        }
    }

    fn check(register: u32, width: u32) {
        assert!(
            register as usize + width as usize <= BAR && register.is_multiple_of(width),
            "access {register:#x}/{width}"
        );
    }

    fn view(&self, word: u32) -> u32 {
        let value = self.get(word, 4);
        if word == CR_BASE + SWSI_V1 {
            return if self.faults.swsi_busy {
                value | SWSI_W_BUSY_V1
            } else {
                value & !(SWSI_W_BUSY_V1 | SWSI_R_BUSY_V1)
            };
        }
        if word == CR_BASE + NCTL_RPT && self.faults.nctl_stuck {
            return 0;
        }
        value
    }

    fn read(&mut self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        let mut value = self.view(register & !3) >> ((register & 3) * 8);
        if width < 4 {
            value &= (1 << (8 * width)) - 1;
        }
        self.log.push((width, register, value));
        value
    }

    fn write(&mut self, register: u32, width: u32, value: u32) {
        Self::check(register, width);
        self.log.push((4 + width, register, value));
        self.set(register, width, value);
        let word = register & !3;
        let mut s = self.get(word, 4);
        if word == WLAN_XTAL_SI_CTRL && s & XTAL_SI_CMD_POLL != 0 && !self.faults.xtal_stuck {
            let offset = io::field(s, XTAL_SI_ADDR_MASK) as usize;
            match io::field(s, XTAL_SI_MODE_MASK) {
                XTAL_SI_NORMAL_READ => {
                    s = (s & !XTAL_SI_DATA_MASK)
                        | io::prep(self.xtal[offset].into(), XTAL_SI_DATA_MASK);
                }
                XTAL_SI_NORMAL_WRITE => {
                    let mask = io::field(s, XTAL_SI_BITMASK_MASK) as u8;
                    let data = io::field(s, XTAL_SI_DATA_MASK) as u8;
                    self.xtal[offset] = (self.xtal[offset] & !mask) | (data & mask);
                }
                _ => {}
            }
            self.set(word, 4, s & !XTAL_SI_CMD_POLL);
        }
    }

    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push((tag, a, b));
    }

    fn writes(&self, register: u32) -> Vec<u32> {
        self.log
            .iter()
            .filter(|&&(tag, at, _)| tag == 8 && at == register)
            .map(|&(_, _, value)| value)
            .collect()
    }

    fn reads(&self, register: u32) -> usize {
        self.log
            .iter()
            .filter(|&&(tag, at, _)| tag == 4 && at == register)
            .count()
    }

    fn delays(&self) -> Vec<u32> {
        self.log
            .iter()
            .filter(|&&(tag, ..)| tag == 9)
            .map(|&(.., us)| us)
            .collect()
    }
}

// SAFETY: a model; delays are counted, not waited.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.read(register, 1) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.read(register, 2) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(self.read(register, 4))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.write(register, 1, value.into());
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.write(register, 2, value.into());
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.write(register, 4, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.log.push((9, 0, microseconds as u32));
    }
}

/// The C oracle's `rtw89_h2c_tx` stand-in: the H2C `rtw89_h2c_pkt_set_hdr`
/// built, recorded with its length and the sequence after it (40) and as
/// little-endian words (41), then taken, or refused with `-ENOSPC` at call
/// `refuse_at`.
struct Recorder {
    sequence: Sequence,
    refuse_at: Option<usize>,
    calls: usize,
    sent: Vec<(Header, Vec<u8>)>,
}

impl Recorder {
    fn new(seq: u8, refuse_at: Option<usize>) -> Self {
        Self {
            sequence: Sequence(seq),
            refuse_at,
            calls: 0,
            sent: Vec::new(),
        }
    }
}

impl Outsrc<Model> for Recorder {
    fn send_outsrc(
        &mut self,
        io: &mut Model,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error> {
        let header = self
            .sequence
            .set_hdr(outsrc(class, func), rack, dack, payload.len() as u32);
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(payload);
        io.mark(40, bytes.len() as u32, self.sequence.0.into());
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            io.mark(41, index as u32, u32::from_le_bytes(word));
        }
        let call = self.calls;
        self.calls += 1;
        if self.refuse_at == Some(call) {
            return Err(h2c::Error::NoResource);
        }
        self.sent.push((header, payload.to_vec()));
        Ok(())
    }
}

/// A `struct rtw89_fw_element_hdr` of AID 0 and its body.
fn element(id: u32, fixed: [u8; 8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&[1, 2, 3, 4]);
    out.extend_from_slice(&RTL8852B_AID.to_le_bytes());
    out.extend_from_slice(&[0; 10]);
    out.extend_from_slice(&fixed);
    out.extend_from_slice(body);
    out
}

fn regs(pairs: &[(u32, u32)]) -> Vec<u8> {
    pairs
        .iter()
        .flat_map(|&(addr, data)| [addr, data])
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn txpwr(id: Id, ent_sz: u8, num: u32) -> Vec<u8> {
    let n = num.to_le_bytes();
    let body = vec![0x11; num as usize * usize::from(ent_sz)];
    element(id as u32, [0, 0, 0, ent_sz, n[0], n[1], n[2], n[3]], &body)
}

/// Synthetic BB, BB gain, radio and NCTL tables, which [`Self::tables`]
/// puts in elements with every other element RTL8852B needs.
struct Synthetic {
    bb: Vec<(u32, u32)>,
    gain: Vec<(u32, u32)>,
    radio: [Vec<(u32, u32)>; 2],
    nctl: Vec<(u32, u32)>,
}

impl Default for Synthetic {
    fn default() -> Self {
        Self {
            bb: vec![(0x4000, 1)],
            gain: vec![(0x0000_0000, 0x0403_0201)],
            radio: [vec![(0x10018, 0x10d24)], vec![(0x10018, 0x10d25)]],
            nctl: vec![(0x8100, 2)],
        }
    }
}

impl Synthetic {
    /// The tables as [`Elements::parse`] recognizes them.
    fn tables(&self) -> Tables<'static> {
        let pieces = [
            element(Id::BbReg as u32, [0; 8], &regs(&self.bb)),
            element(Id::BbGain as u32, [0; 8], &regs(&self.gain)),
            element(Id::RadioA as u32, [0; 8], &regs(&self.radio[0])),
            element(
                Id::RadioB as u32,
                [1, 0, 0, 0, 0, 0, 0, 0],
                &regs(&self.radio[1]),
            ),
            element(Id::RfNctl as u32, [0; 8], &regs(&self.nctl)),
            element(
                Id::TxpwrTrk as u32,
                [0xf0, 0xff, 0, 0, 0, 0, 0, 0],
                &[0x22; 20 * 30],
            ),
            txpwr(Id::TxpwrByrate, 9, 2),
            txpwr(Id::TxpwrLmt2ghz, 7, 3),
            txpwr(Id::TxpwrLmt5ghz, 7, 3),
            txpwr(Id::TxpwrLmtRu2ghz, 5, 2),
            txpwr(Id::TxpwrLmtRu5ghz, 5, 2),
            txpwr(Id::TxShapeLmt, 4, 2),
            txpwr(Id::TxShapeLmtRu, 3, 2),
        ];
        let mut file = Vec::new();
        for piece in pieces {
            file.resize(file.len().next_multiple_of(16), 0);
            file.extend_from_slice(&piece);
        }
        let file: &'static [u8] = Vec::leak(file);
        let elements = Elements::parse(file, 16, Board::rtl8852b(0, 1), |_, _| {}).unwrap();
        Tables::from_elements(&elements).unwrap()
    }
}

fn board(rfe: u8, cv: u8) -> Board {
    Board::rtl8852b(rfe, cv)
}

#[test]
fn headline_selection_picks_rtw89s_package_for_each_cut_and_rfe() {
    // The pinned 0.29.29.18 radio tables' headlines.
    let pinned = Synthetic {
        radio: [
            [
                0xf001_0000,
                0xf002_0000,
                0xf001_0001,
                0xf002_0001,
                0xf003_0001,
                0xf029_0001,
                0xf02b_0001,
            ]
            .into_iter()
            .map(|addr| (addr, 0))
            .chain([(0x10018, 1)])
            .collect(),
            vec![(0x10018, 1)],
        ],
        ..Synthetic::default()
    };
    let tables = pinned.tables();
    let pick = |rfe, cv| sel_headline(&tables.radio[0], rfe, cv);
    let at = |index| Some(Headline { size: 7, index });
    // RFE 1: cuts 0 and 1 by RFE and cut; cut 2 takes RFE 1's highest.
    assert_eq!(pick(1, 0), at(0));
    assert_eq!(pick(1, 1), at(2));
    assert_eq!(pick(1, 2), at(2));
    assert_eq!(pick(2, 2), at(3));
    // RFE 0 has no package, and none is for any RFE.
    assert_eq!(pick(0, 1), None);
    // No headline: the whole table.
    assert_eq!(
        sel_headline(&tables.radio[1], 0, 0),
        Some(Headline { size: 0, index: 0 })
    );

    // RFE with any cut, then any RFE's highest cut, the last one listed.
    let wild = Synthetic {
        nctl: [
            0xf001_0001,
            0xf005_00ff,
            0xf0ff_0003,
            0xf0ff_0001,
            0xf0ff_0003,
        ]
        .into_iter()
        .map(|addr| (addr, 0))
        .collect(),
        ..Synthetic::default()
    };
    let tables = wild.tables();
    let pick = |rfe, cv| sel_headline(&tables.nctl, rfe, cv);
    let at = |index| Some(Headline { size: 5, index });
    assert_eq!(pick(5, 7), at(1));
    assert_eq!(pick(4, 0), at(4));
    assert_eq!(pick(1, 1), at(0));
    assert_eq!(pick(1, 9), at(0));
}

#[test]
fn branches_keep_the_lines_of_the_package_picked_for_each_cut() {
    // Packages for RFE 1 at cuts 0 and 1, whose branches write 0xa0, 0xa1
    // or (unmatched) 0xee to 0x8100, then 1 to 0x8104 whatever matched.
    let tables = Synthetic {
        nctl: vec![
            (0xf001_0000, 0),
            (0xf001_0001, 0),
            (0x8001_0000, 0),
            (0x4000_0000, 0),
            (0x8100, 0xa0),
            (0x9001_0001, 0),
            (0x4000_0000, 0),
            (0x8100, 0xa1),
            (0xa000_0000, 0),
            (0x8100, 0xee),
            (0xb000_0000, 0),
            (0x8104, 1),
        ],
        ..Synthetic::default()
    }
    .tables();
    for (cv, written) in [(0, 0xa0), (1, 0xa1), (2, 0xa1)] {
        let mut io = Model::new(Faults::default());
        let mut warnings = Vec::new();
        init_rf_nctl(&mut io, &tables, board(1, cv), &mut warnings).unwrap();
        assert_eq!(io.writes(CR_BASE + 0x8100), [written], "cut {cv}");
        assert_eq!(io.writes(CR_BASE + 0x8104), [1], "cut {cv}");
        assert_eq!(warnings, []);
    }
    // No package for RFE 0: nothing from the table, and a warning.
    let mut io = Model::new(Faults::default());
    let mut warnings = Vec::new();
    init_rf_nctl(&mut io, &tables, board(0, 1), &mut warnings).unwrap();
    assert!(io.writes(CR_BASE + 0x8100).is_empty());
    assert!(io.writes(CR_BASE + 0x8104).is_empty());
    let invalid = Warning::InvalidPackage {
        table: Table::Nctl,
        rfe: 0,
        cv: 1,
    };
    assert_eq!(warnings, [invalid]);

    // An ELSE before any branch matched stops the table there.
    let tables = Synthetic {
        nctl: vec![
            (0xf0ff_0002, 0),
            (0x8001_0000, 0),
            (0x4000_0000, 0),
            (0x8100, 0xa0),
            (0xa000_0000, 0x77),
            (0x8100, 0xee),
            (0xb000_0000, 0),
            (0x8104, 1),
        ],
        ..Synthetic::default()
    }
    .tables();
    let mut io = Model::new(Faults::default());
    let mut warnings = Vec::new();
    init_rf_nctl(&mut io, &tables, board(1, 0), &mut warnings).unwrap();
    assert!(io.writes(CR_BASE + 0x8100).is_empty());
    assert!(io.writes(CR_BASE + 0x8104).is_empty());
    let failed = Warning::FailedToLoad {
        table: Table::Nctl,
        addr: 0xa000_0000,
        data: 0x77,
    };
    assert_eq!(warnings, [failed]);
}

#[test]
fn delay_addresses_wait_in_the_bb_tables_and_only_0xfe_in_the_radio_tables() {
    let delays = [0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9].map(|addr| (addr, 0x1234));
    let tables = Synthetic {
        nctl: delays
            .into_iter()
            .chain([(0x8100, BYPASS_CR_DATA), (0x8104, 5)])
            .collect(),
        radio: [vec![(0xfe, 0), (0xfd, 0x12345), (0x05, 1)], vec![]],
        ..Synthetic::default()
    }
    .tables();
    let mut io = Model::new(Faults::default());
    let mut warnings = Vec::new();
    // The NCTL preinit's own delay first: 1 us before its one poll read.
    init_rf_nctl(&mut io, &tables, board(0, 0), &mut warnings).unwrap();
    assert_eq!(io.delays(), [1, 50_000, 5_000, 1_000, 50, 5, 1]);
    assert!(io.writes(CR_BASE + 0x8100).is_empty());
    assert_eq!(io.writes(CR_BASE + 0x8104), [5]);

    let mut io = Model::new(Faults::default());
    let mut recorder = Recorder::new(0, None);
    init_rf_reg(&mut io, &mut recorder, &tables, board(0, 0), &mut warnings).unwrap();
    // 0xfe waits; 0xfd and 0x05 go out through SWSI without a delay, and
    // below 0x100 nothing is mirrored.
    assert_eq!(io.delays(), [50_000]);
    assert_eq!(
        io.writes(CR_BASE + SWSI_DATA_V1),
        [
            io::prep(0xfd, SWSI_DATA_ADDR_V1) | 0x12345,
            io::prep(0x05, SWSI_DATA_ADDR_V1) | 1
        ]
    );
    assert!(recorder.sent.is_empty());
    assert_eq!(warnings, []);
}

#[test]
fn rf_reg_pages_hold_500_words_each_and_stop_after_three() {
    let writes = |n: u32, salt: u32| -> Vec<(u32, u32)> {
        (0..n)
            .map(|i| (0x10000 | (i % 0xff), (i * 7 + salt) & 0xfffff))
            .collect()
    };
    let tables = Synthetic {
        radio: [writes(1234, 1), writes(1600, 2)],
        ..Synthetic::default()
    }
    .tables();
    let mut io = Model::new(Faults::default());
    let mut recorder = Recorder::new(2, None);
    let mut warnings = Vec::new();
    init_rf_reg(&mut io, &mut recorder, &tables, board(0, 0), &mut warnings).unwrap();
    let pages: Vec<(u8, u8, usize)> = recorder
        .sent
        .iter()
        .map(|(header, payload)| {
            let function = header.function();
            assert_eq!(function.cat, h2c::H2C_CAT_OUTSRC);
            assert_eq!(usize::from(header.total_len()), HEADER_LEN + payload.len());
            assert!(!header.done_ack());
            assert_eq!(header.rec_ack(), header.seq().is_multiple_of(4));
            (function.class, function.func, payload.len() / 4)
        })
        .collect();
    let (a, b) = (H2C_CL_OUTSRC_RF_REG_A, H2C_CL_OUTSRC_RF_REG_B);
    assert_eq!(
        pages,
        [
            (a, 0, 500),
            (a, 1, 500),
            (a, 2, 234),
            (b, 0, 500),
            (b, 1, 500),
            (b, 2, 500)
        ]
    );
    // Each word is addr << 20 | data, the address's ADSEL bit shifted out.
    let (addr, data) = writes(1234, 1)[RF_PAGE_SIZE];
    assert_eq!(recorder.sent[1].1[..4], ((addr << 20) | data).to_le_bytes());
    // Path B's writes past the 1500th are not mirrored, and the index
    // stays where the pages end.
    let overflow = Warning::RfOverflow {
        path: 1,
        index: 1500,
    };
    assert_eq!(warnings, [overflow; 100]);

    // A refused page stops its path's later pages, not the next path's.
    let mut io = Model::new(Faults::default());
    let mut recorder = Recorder::new(0, Some(1));
    let mut warnings = Vec::new();
    init_rf_reg(&mut io, &mut recorder, &tables, board(0, 0), &mut warnings).unwrap();
    assert_eq!(recorder.calls, 5);
    assert_eq!(
        warnings[0],
        Warning::RfH2c {
            path: 0,
            error: RfRegError::Page {
                page: 1,
                error: h2c::Error::NoResource
            }
        }
    );
}

#[test]
fn the_nctl_poll_timeout_names_its_register() {
    let tables = Synthetic::default().tables();
    let mut io = Model::new(Faults {
        nctl_stuck: true,
        ..Faults::default()
    });
    let mut warnings = Vec::new();
    init_rf_nctl(&mut io, &tables, board(0, 0), &mut warnings).unwrap();
    let timeout = io::Error::Timeout {
        register: 0x1_8080,
        mask: MASKDWORD,
    };
    assert_eq!(warnings, [Warning::NctlPoll(timeout)]);
    assert_eq!(
        std::format!("{timeout:?}"),
        "Timeout { register: 0x18080, mask: 0xffffffff }"
    );
    // A read every 10 us for 1000 us and one past it, each after writing
    // the report and waiting 1 us; then the table still loads.
    assert_eq!(io.reads(CR_BASE + NCTL_RPT), 101);
    assert_eq!(io.writes(CR_BASE + NCTL_RPT).len(), 101);
    assert_eq!(io.writes(CR_BASE + 0x8100), [2]);
}

#[test]
fn a_busy_swsi_drops_the_write_but_still_mirrors_it() {
    let tables = Synthetic {
        radio: [vec![(0x1ee, 0x12345), (0x18, 1)], vec![]],
        ..Synthetic::default()
    }
    .tables();
    let mut io = Model::new(Faults {
        swsi_busy: true,
        ..Faults::default()
    });
    let mut recorder = Recorder::new(0, None);
    let mut warnings = Vec::new();
    init_rf_reg(&mut io, &mut recorder, &tables, board(0, 0), &mut warnings).unwrap();
    assert!(io.writes(CR_BASE + SWSI_DATA_V1).is_empty());
    assert_eq!(
        warnings,
        [
            Warning::SwsiBusy {
                path: 0,
                addr: 0x1ee
            },
            Warning::SwsiBusy {
                path: 0,
                addr: 0x18
            }
        ]
    );
    assert_eq!(recorder.sent.len(), 1);
    assert_eq!(
        recorder.sent[0].1,
        ((0x1ee << 20) | 0x12345u32).to_le_bytes()
    );
}

#[test]
fn bb_gain_lines_fill_rtw89s_gain_tables() {
    let gain = |cfg: u32, band: u32, path: u32, kind: u32, data| {
        (cfg << 24 | band << 16 | path << 8 | kind, data)
    };
    let tables = Synthetic {
        gain: vec![
            gain(0, 1, 1, 0, 0x8102_7f04),
            gain(0, 1, 1, 1, 0x0007_0605),
            gain(0, 1, 1, 2, 0x0000_fe03),
            gain(1, 2, 0, 0x00, 0xffff_ff9c),
            gain(1, 2, 0, 0x31, 0x0403_0201),
            gain(1, 2, 0, 0x3d, 0x0000_0605),
            gain(1, 2, 0, 0x25, 0x0000_0099),
            gain(3, 0, 1, 3, 0x0d0c_0b0a),
            gain(0, 8, 0, 0, 0x7f7f_7f7f),
            gain(0, 0, 2, 0, 0x7f7f_7f7f),
            gain(4, 0, 0, 0, 1),
            gain(1, 0, 0, 0x40, 2),
            (0xfb, 3),
        ],
        ..Synthetic::default()
    }
    .tables();
    let mut io = Model::new(Faults::default());
    let mut warnings = Vec::new();
    let got = init_bb_reg(&mut io, &tables, board(1, 1), &mut warnings).unwrap();
    assert_eq!(got.lna_gain[1][1], [4, 0x7f, 2, -127, 5, 6, 7]);
    assert_eq!(got.tia_gain[1][1], [3, -2]);
    assert_eq!(got.rpl_ofst_20[2][0], -100);
    assert_eq!(got.rpl_ofst_160[2][0][1..5], [1, 2, 3, 4]);
    assert_eq!(got.rpl_ofst_160[2][0][13..15], [5, 6]);
    // 80 MHz from sub-channel 5 is no slot rtw89 fills.
    assert_eq!(got.rpl_ofst_80[2][0], [0; BB_RXSC_NUM_80]);
    assert_eq!(got.tia_lna_op1db[0][1][4..8], [10, 11, 12, 13]);
    // Band 8, path 2 and eFEM lines below RFE 50 are skipped silently.
    assert_eq!(got.lna_gain[0][0], [0; LNA_GAIN_NUM]);
    assert_eq!(
        warnings,
        [
            Warning::BbRplOfstBw {
                addr: 0x0100_0040,
                data: 2
            },
            Warning::BbGainFlowCtrl { addr: 0xfb }
        ]
    );
}

#[test]
fn an_xtal_si_that_never_answers_stops_the_reset_naming_its_register() {
    let mut io = Model::new(Faults {
        xtal_stuck: true,
        ..Faults::default()
    });
    let error = reset_bb_rf(&mut io).unwrap_err();
    assert_eq!(
        error,
        Error {
            step: Step::ResetBbRf,
            cause: io::Error::Timeout {
                register: WLAN_XTAL_SI_CTRL,
                mask: XTAL_SI_CMD_POLL
            }
        }
    );
}

#[test]
fn the_reset_clears_both_rf_enables_then_turns_the_bb_back_on() {
    let mut io = Model::new(Faults::default());
    reset_bb_rf(&mut io).unwrap();
    // Disabled from the starting registers, then enabled as 0xc7.
    let (s0, s1) = ((0x80 * 29 + 0x47) as u8, (0x81 * 29 + 0x47) as u8);
    let written: Vec<u32> = io
        .writes(WLAN_XTAL_SI_CTRL)
        .into_iter()
        .filter(|request| io::field(*request, XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_WRITE)
        .map(|request| io::field(request, XTAL_SI_DATA_MASK))
        .collect();
    assert_eq!(
        written,
        [
            u32::from(s0 & !XTAL_SI_RF00S_EN),
            u32::from(s1 & !XTAL_SI_RF10S_EN),
            0xc7,
            0xc7
        ]
    );
    assert_eq!((io.xtal[0x80], io.xtal[0x81]), (0xc7, 0xc7));
}

#[test]
fn a_load_without_a_table_is_refused_naming_the_element() {
    let mut elements = Elements::default();
    assert_eq!(Tables::from_elements(&elements), Err(Id::BbReg));
    let tables = Synthetic::default().tables();
    elements.bb_tbl = Some(tables.bb);
    assert_eq!(Tables::from_elements(&elements), Err(Id::BbGain));
    elements.bb_gain = Some(tables.bb_gain);
    elements.rf_radio[0] = Some(tables.radio[0]);
    assert_eq!(Tables::from_elements(&elements), Err(Id::RadioB));
    elements.rf_radio[1] = Some(tables.radio[1]);
    assert_eq!(Tables::from_elements(&elements), Err(Id::RfNctl));
    elements.rf_nctl = Some(tables.nctl);
    assert_eq!(Tables::from_elements(&elements), Ok(tables));
}

#[test]
fn load_runs_the_reset_the_bb_tables_and_the_radio_tables_in_order() {
    let tables = Synthetic::default().tables();
    let mut io = Model::new(Faults::default());
    let mut recorder = Recorder::new(0, None);
    let loaded = load(&mut io, &mut recorder, &tables, board(1, 1)).unwrap();
    assert_eq!(loaded.warnings, []);
    assert_eq!(loaded.bb_gain.lna_gain[0][0][..4], [1, 2, 3, 4]);
    let at = |register: u32| {
        io.log
            .iter()
            .position(|&(tag, at, _)| tag == 8 && at == register)
            .unwrap()
    };
    assert!(at(WLRF_CTRL) < at(CR_BASE + 0x4000));
    assert!(at(CR_BASE + 0x4000) < at(PWR_UL_CTRL2));
    assert!(at(PWR_UL_CTRL2) < at(CR_BASE + RSTB_ASYNC));
    assert!(at(CR_BASE + RSTB_ASYNC) < at(CR_BASE + io::RF_BASE[1] + (0x18 << 2)));
    assert_eq!(recorder.sent.len(), 2);
    // The UL TB 2T offset: 0 - 3 dB in five bits.
    assert_eq!(io.writes(PWR_UL_TB_2T)[0] & PWR_UL_TB_2T_MASK, 0x1d);
}

#[test]
fn outsrc_commands_take_the_channel_s_next_sequence() {
    let source = Source;
    let domain = Domain::new(Placement::Oracle);
    let mut channel = Channel::new(&source, domain);
    let packet = channel.outsrc(H2C_CL_OUTSRC_RF_REG_B, 2, false, false, &[1, 2, 3, 4]);
    let header = packet.header.unwrap();
    assert_eq!(header.function(), outsrc(H2C_CL_OUTSRC_RF_REG_B, 2));
    assert_eq!(
        (header.seq(), header.rec_ack(), header.total_len()),
        (0, true, 12)
    );
    assert_eq!(channel.sequence(), Sequence(1));
    assert!(!packet.fwdl);
}

/// One oracle case: the image (0 pinned, 1 syn-phy), RFE type, cut, the
/// model's faults, the H2C call refused and the first sequence number.
#[derive(Clone, Copy, Debug)]
struct Case {
    image: u8,
    rfe: u8,
    cv: u8,
    faults: Faults,
    refuse_at: Option<usize>,
    seq0: u8,
}

fn oracle_cases() -> Vec<Case> {
    let case = |image, rfe, cv, xtal_stuck, nctl_stuck, refuse_at, seq0| Case {
        image,
        rfe,
        cv,
        faults: Faults {
            xtal_stuck,
            nctl_stuck,
            swsi_busy: false,
        },
        refuse_at,
        seq0,
    };
    let mut cases = Vec::new();
    for cv in 0..3 {
        for rfe in 0..3 {
            cases.push(case(0, rfe, cv, false, false, None, cv));
        }
    }
    cases.extend([
        case(1, 3, 1, false, false, None, 3),
        case(1, 7, 0, false, false, None, 0),
        case(1, 1, 0, false, false, None, 1),
        case(1, 55, 1, false, false, None, 2),
        case(1, 3, 1, false, true, None, 0),
        case(1, 3, 1, false, false, Some(1), 0),
        case(1, 3, 1, true, false, None, 0),
    ]);
    cases
}

/// The oracle's WARNINGS indices a warning logs, in order.
fn logged(warning: &Warning) -> &'static [u32] {
    match warning {
        Warning::InvalidPackage { .. } => &[0],
        Warning::FailedToLoad { .. } => &[1],
        Warning::BbGainFlowCtrl { .. } => &[2],
        Warning::BbGainCfgType { .. } => &[3],
        Warning::BbGainErrorType { .. } => &[4],
        Warning::BbRplOfstBw { .. } => &[5],
        Warning::BbGainBypassType { .. } => &[6],
        Warning::BbGainOp1dbType { .. } => &[7],
        Warning::SwsiBusy { .. } => &[8],
        Warning::UnsupportedRfPath { .. } => &[9],
        Warning::RfOverflow { .. } => &[10],
        Warning::RfH2c {
            error: RfRegError::TooLong { .. },
            ..
        } => &[11, 13],
        Warning::RfH2c {
            error: RfRegError::Page { .. },
            ..
        } => &[12, 13],
        Warning::NctlPoll(_) => &[14],
        Warning::AfeClass { .. } => &[15],
        Warning::AfeWriteCat { .. } => &[16],
        Warning::AfePoll { .. } => &[17],
    }
}

fn flush(io: &mut Model, warnings: &mut Vec<Warning>) {
    for warning in warnings.drain(..) {
        for &index in logged(&warning) {
            io.mark(70, index, 0);
        }
    }
}

/// `rtwdev->bb_gain.ax`'s bytes, in its declaration's order.
fn gain_bytes(gain: &BbGain) -> Vec<u8> {
    let mut out: Vec<i8> = Vec::new();
    out.extend(gain.lna_gain.as_flattened().as_flattened());
    out.extend(gain.tia_gain.as_flattened().as_flattened());
    out.extend(gain.lna_gain_bypass.as_flattened().as_flattened());
    out.extend(gain.lna_op1db.as_flattened().as_flattened());
    out.extend(gain.tia_lna_op1db.as_flattened().as_flattened());
    out.extend(gain.rpl_ofst_20.as_flattened());
    out.extend(gain.rpl_ofst_40.as_flattened().as_flattened());
    out.extend(gain.rpl_ofst_80.as_flattened().as_flattened());
    out.extend(gain.rpl_ofst_160.as_flattened().as_flattened());
    out.into_iter().map(|byte| byte as u8).collect()
}

/// One case as the Rust side runs it: the trace segment it gives.
fn replay(case: &Case, pinned: &[u8], synthetic: &[u8]) -> Vec<u8> {
    let image = if case.image == 0 { pinned } else { synthetic };
    let firmware = Rtw89::parse(image, 1).unwrap();
    let board = board(case.rfe, case.cv);
    let elements = Elements::recognize(&firmware, board).unwrap();
    let tables = Tables::from_elements(&elements).unwrap();
    let mut io = Model::new(case.faults);
    let mut recorder = Recorder::new(case.seq0, case.refuse_at);
    let mut warnings = Vec::new();
    io.mark(50, 0, 0);
    init_bb_afe(&mut io, tables.afe.as_ref(), &mut warnings).unwrap();
    flush(&mut io, &mut warnings);
    io.mark(50, 1, 0);
    let reset = reset_bb_rf(&mut io);
    let ret: i32 = match reset {
        Ok(()) => 0,
        Err(Error {
            step: Step::ResetBbRf,
            cause: io::Error::Timeout { .. },
        }) => {
            // rtw89 warns which XTAL SI request went unanswered.
            let request = io.writes(WLAN_XTAL_SI_CTRL).pop().unwrap();
            let read = io::field(request, XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_READ;
            io.mark(70, if read { 18 } else { 19 }, 0);
            -110
        }
        Err(error) => panic!("the model refuses no access: {error:?}"),
    };
    io.mark(11, 0, ret as u32);
    if reset.is_ok() {
        io.mark(50, 2, 0);
        let gain = init_bb_reg(&mut io, &tables, board, &mut warnings).unwrap();
        flush(&mut io, &mut warnings);
        // rtw89_chip_bb_postinit: NULL for an RTL8852B.
        io.mark(50, 3, 0);
        io.mark(50, 4, 0);
        init_rf_reg(&mut io, &mut recorder, &tables, board, &mut warnings).unwrap();
        flush(&mut io, &mut warnings);
        io.mark(50, 5, 0);
        init_rf_nctl(&mut io, &tables, board, &mut warnings).unwrap();
        flush(&mut io, &mut warnings);
        for (index, word) in gain_bytes(&gain).chunks(4).enumerate() {
            let mut bytes = [0; 4];
            bytes[..word.len()].copy_from_slice(word);
            io.mark(60, index as u32, u32::from_le_bytes(bytes));
        }
    }
    io.mark(24, recorder.sequence.0.into(), 0);
    encode(&io.log)
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_IMAGES, STELA_RTW89_PHY_ORACLE"]
fn bb_and_rf_loads_match_unchanged_c_for_each_cut_and_rfe() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_PHY_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let synthetic = std::fs::read(directory.join("syn-phy.bin")).unwrap();
    let images = std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap());
    let pinned = std::fs::read(images.join("rtw89/rtw8852b_fw-2.bin")).unwrap();
    let cases = oracle_cases();
    assert_eq!(cases.len(), 16);
    let mut offset = 0;
    for case in cases {
        let got = segment(&trace, &mut offset);
        let expected = replay(&case, &pinned, &synthetic);
        if got != expected.as_slice() {
            let first = got
                .chunks(12)
                .zip(expected.chunks(12))
                .position(|(c, rust)| c != rust);
            let record = |bytes: &[u8]| {
                first.and_then(|at| bytes.chunks(12).nth(at)).map(|r| {
                    r.chunks(4)
                        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
                        .collect::<Vec<_>>()
                })
            };
            panic!(
                "{case:?}: {} bytes from C, {} from Rust; first difference at record \
                 {first:?}: C {:x?}, Rust {:x?}",
                got.len(),
                expected.len(),
                record(got),
                record(&expected)
            );
        }
    }
    assert_eq!(offset, trace.len());
}
