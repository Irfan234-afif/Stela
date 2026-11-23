extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    efuse,
    elements::TxpwrTrk,
    io::{CR_BASE, RF_BASE, field, prep},
    registers::{
        CHIP_CAV, CHIP_CBV, PHYREG_SET, RFREG_MASK, SWSI_BIT_MASK_V1, SWSI_DATA_ADDR_V1,
        SWSI_DATA_BIT_MASK_EN_V1, SWSI_DATA_PATH_V1, SWSI_DATA_V1, SWSI_DATA_VAL_V1,
        SWSI_R_BUSY_V1, SWSI_R_DATA_DONE_V1, SWSI_READ_ADDR_ADDR_V1, SWSI_READ_ADDR_PATH_V1,
        SWSI_READ_ADDR_V1, SWSI_V1, SWSI_W_BUSY_V1,
    },
};
use alloc::{vec, vec::Vec};

const MEMORY: usize = 0x2_0000;
const CR: u32 = CR_BASE;

/// What the model's BAR2 and RF registers hold before the first access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fill {
    /// BAR2 byte `i` holds `i * 37 + 11`; RF register `a` of path `p` holds
    /// `a * 0x9e37 + p * 0x3c1 + 0x1234`, cut to 20 bits.
    Pattern,
    Ones,
    Zeros,
}

/// The polls the model's chip never answers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Faults {
    /// RF RR_RCKS bit 3 stays clear.
    rck_stuck: bool,
    /// R_DRCK_RS's done bit stays clear.
    drck_stuck: bool,
    /// R_ADDCKR0 and R_ADDCKR1 bit 0 stay clear.
    addck_stuck: bool,
    /// S0's MSBK and DADCK done bits stay clear.
    s0_stuck: bool,
    /// S1's MSBK and DADCK done bits stay clear.
    s1_stuck: bool,
    /// RF RR_MOD reads mode 2 (TX).
    rx_stuck: bool,
    /// RF RR_TXMO's LO leakage core I code reads 0x1f, out of range;
    /// otherwise 0x10.
    lok_fail: bool,
    /// The NCTL one-shots, by bit from the first, whose report reads
    /// B_NCTL_RPT_FLG.
    nctl_fail: u64,
    /// The NCTL one-shot, counted from 1, whose 0xbff8 never reads 0x55.
    nctl_stuck: u32,
    /// R_RPT_COM's low word stays clear while R_KIP_RPT1 selects the DPK
    /// one-shot's report (3); otherwise it reads 0x8000.
    kip_stuck: bool,
    /// The TSSI CW reports' ready bits stay clear.
    cwrpt_stuck: bool,
    /// The words R_RPT_COM reads in turn, cycling, while another report is
    /// selected; memory when empty.
    rpt: &'static [u32],
}

/// The C oracle's register model: BAR2 as little-endian bytes behaving per
/// aligned word, and each RF path's registers as 20-bit words behind SWSI.
///
/// SWSI never reads busy; a read request leaves R_SWSI_V1 holding the done
/// bit and the RF word, and a data write stores the RF word, under
/// R_SWSI_BIT_MASK_V1 when the write says so. The polls read done unless
/// [`Faults`] keeps them clear, and RR_MOD reads mode 2 when it says so.
/// Everything else reads as filled or written. Every access is logged as
/// the oracle records it: reads tagged by width, writes by 4 plus width,
/// delays 9, the scheduler stub 12 and 13.
struct Model {
    memory: Vec<u8>,
    rf: [[u32; 256]; 2],
    faults: Faults,
    log: Vec<[u32; 3]>,
    /// A register the model refuses.
    refuse: Option<u32>,
    /// The NCTL one-shots started: writes to R_NCTL_CFG.
    oneshots: u32,
    /// The reads of [`Faults::rpt`] so far.
    rpt_reads: usize,
}

impl Model {
    fn new(fill: Fill, faults: Faults) -> Self {
        let memory = (0..MEMORY)
            .map(|i| match fill {
                Fill::Pattern => (i as u32).wrapping_mul(37).wrapping_add(11) as u8,
                Fill::Ones => 0xff,
                Fill::Zeros => 0,
            })
            .collect();
        let mut rf = [[0; 256]; 2];
        for (p, path) in rf.iter_mut().enumerate() {
            for (a, register) in path.iter_mut().enumerate() {
                *register = match fill {
                    Fill::Pattern => (a as u32 * 0x9e37 + p as u32 * 0x3c1 + 0x1234) & RFREG_MASK,
                    Fill::Ones => RFREG_MASK,
                    Fill::Zeros => 0,
                };
            }
        }
        Self {
            memory,
            rf,
            faults,
            log: Vec::new(),
            refuse: None,
            oneshots: 0,
            rpt_reads: 0,
        }
    }
    fn get(&self, register: u32, width: u32) -> u32 {
        (0..width).fold(0, |value, i| {
            value | u32::from(self.memory[(register + i) as usize]) << (8 * i)
        })
    }
    fn set(&mut self, register: u32, width: u32, value: u32) {
        for i in 0..width {
            self.memory[(register + i) as usize] = (value >> (8 * i)) as u8;
        }
    }
    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push([tag, a, b]);
    }
    fn rf_view(&self, path: usize, address: usize) -> u32 {
        let value = self.rf[path][address];
        match address as u32 {
            RR_RCKS => forced(value, 1 << 3, self.faults.rck_stuck),
            RR_MOD if self.faults.rx_stuck => (value & !RR_MOD_MASK) | prep(2, RR_MOD_MASK),
            RR_TXMO => {
                let core_i = if self.faults.lok_fail { 0x1f } else { 0x10 };
                (value & !(RR_TXMO_COI | RR_TXMO_COQ))
                    | prep(core_i, RR_TXMO_COI)
                    | prep(0x0f, RR_TXMO_COQ)
            }
            RR_LOKVB => {
                (value & !(RR_LOKVB_COI | RR_LOKVB_COQ))
                    | prep(0x20, RR_LOKVB_COI)
                    | prep(0x1f, RR_LOKVB_COQ)
            }
            _ => value,
        }
    }
    fn view(&self, word: u32) -> u32 {
        let value = self.get(word, 4);
        if word < CR {
            return value;
        }
        let f = self.faults;
        match word - CR {
            SWSI_V1 => value & !(SWSI_W_BUSY_V1 | SWSI_R_BUSY_V1),
            R_DRCK_RS => forced(value, B_DRCK_RS_DONE, f.drck_stuck),
            R_ADDCKR0 | R_ADDCKR1 => forced(value, 1 << 0, f.addck_stuck),
            R_DACK_S0P0 | R_DACK_S0P1 => forced(value, B_DACK_S0P0_OK, f.s0_stuck),
            R_DACK_S0P2 | R_DACK_S0P3 => forced(value, B_DACK_S0P2_OK, f.s0_stuck),
            R_DACK_S1P0 | R_DACK_S1P1 => forced(value, B_DACK_S1P0_OK, f.s1_stuck),
            R_DACK10S | R_DACK11S => forced(value, B_DACK_S1P2_OK, f.s1_stuck),
            0xbff8 => {
                let stuck = self.oneshots != 0 && self.oneshots == f.nctl_stuck;
                (value & !0xff) | if stuck { 0 } else { 0x55 }
            }
            R_NCTL_RPT => {
                let fail = (1..=64).contains(&self.oneshots)
                    && (f.nctl_fail >> (self.oneshots - 1)) & 1 != 0;
                forced(value, B_NCTL_RPT_FLG, !fail)
            }
            0x1c18 | 0x3c18 => forced(value, B_TSSI_CWRPT_RDY, f.cwrpt_stuck),
            _ => value,
        }
    }
    fn check(&self, register: u32, width: u32) -> Result<(), Error> {
        assert!(register as usize + width as usize <= MEMORY && register.is_multiple_of(width));
        if self.refuse == Some(register) {
            return Err(Error::Register { register });
        }
        Ok(())
    }
    fn read(&mut self, register: u32, width: u32) -> Result<u32, Error> {
        self.check(register, width)?;
        let word = register & !3;
        let viewed = if word == CR + R_RPT_COM {
            self.rpt_view(word)
        } else {
            self.view(word)
        };
        let mut value = viewed >> ((register & 3) * 8);
        if width < 4 {
            value &= (1 << (8 * width)) - 1;
        }
        self.mark(width, register, value);
        Ok(value)
    }
    fn write(&mut self, register: u32, width: u32, value: u32) -> Result<(), Error> {
        self.check(register, width)?;
        self.mark(4 + width, register, value);
        self.set(register, width, value);
        let word = register & !3;
        let stored = self.get(word, 4);
        if word == CR + SWSI_READ_ADDR_V1 {
            let path = field(stored, SWSI_READ_ADDR_PATH_V1) as usize;
            let address = field(stored, SWSI_READ_ADDR_ADDR_V1) as usize;
            let data = SWSI_R_DATA_DONE_V1 | self.rf_view(path, address);
            self.set(CR + SWSI_V1, 4, data);
        }
        if word == CR + R_NCTL_CFG {
            self.oneshots += 1;
        }
        if word == CR + SWSI_DATA_V1 {
            let path = field(stored, SWSI_DATA_PATH_V1) as usize;
            let address = field(stored, SWSI_DATA_ADDR_V1) as usize;
            let data = field(stored, SWSI_DATA_VAL_V1);
            let mask = self.get(CR + SWSI_BIT_MASK_V1, 4) & RFREG_MASK;
            let rf = &mut self.rf[path][address];
            if stored & SWSI_DATA_BIT_MASK_EN_V1 != 0 {
                *rf = (*rf & !mask) | (data & mask);
            } else {
                *rf = data;
            }
        }
        Ok(())
    }
    /// What R_RPT_COM reads as: the DPK one-shot's done word while report 3
    /// is selected, else the next scripted word, else memory.
    fn rpt_view(&mut self, word: u32) -> u32 {
        let value = self.get(word, 4);
        if field(self.get(CR + R_KIP_RPT1, 4), B_KIP_RPT1_SEL) == 3 {
            return (value & 0xffff_0000) | if self.faults.kip_stuck { 0 } else { 0x8000 };
        }
        let rpt = self.faults.rpt;
        if rpt.is_empty() {
            return value;
        }
        let scripted = rpt[self.rpt_reads % rpt.len()];
        self.rpt_reads += 1;
        scripted
    }
    /// Reads logged of `register`.
    fn reads(&self, register: u32) -> usize {
        self.log
            .iter()
            .filter(|[tag, r, _]| *tag <= 4 && *r == register)
            .count()
    }
    /// Values written to `register`, in order.
    fn writes(&self, register: u32) -> Vec<u32> {
        self.log
            .iter()
            .filter(|[tag, r, _]| (5..=8).contains(tag) && *r == register)
            .map(|[_, _, value]| *value)
            .collect()
    }
    fn encode(&self) -> Vec<u8> {
        let mut trace = Vec::new();
        for record in &self.log {
            push(&mut trace, record[0], record[1], record[2]);
        }
        trace
    }
}

fn forced(value: u32, bits: u32, stuck: bool) -> u32 {
    if stuck { value & !bits } else { value | bits }
}

fn push(trace: &mut Vec<u8>, tag: u32, a: u32, b: u32) {
    for word in [tag, a, b] {
        trace.extend_from_slice(&word.to_le_bytes());
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        self.read(register, 1).map(|value| value as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        self.read(register, 2).map(|value| value as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        self.read(register, 4)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        self.write(register, 1, value.into())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        self.write(register, 2, value.into())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.write(register, 4, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.mark(9, 0, microseconds as u32);
    }
}

/// The oracle's scheduler stubs: a stop gives 0xa5c3. Either may refuse.
#[derive(Default)]
struct Stub {
    refuse_stop: Option<mac::Cause>,
    refuse_resume: Option<mac::Cause>,
}

impl Scheduler<Model> for Stub {
    fn stop(&mut self, io: &mut Model) -> Result<u16, mac::Cause> {
        io.mark(12, 0, 0);
        self.refuse_stop.map_or(Ok(0xa5c3), Err)
    }
    fn resume(&mut self, io: &mut Model, tx_en: u16) -> Result<(), mac::Cause> {
        io.mark(13, tx_en.into(), 0);
        self.refuse_resume.map_or(Ok(()), Err)
    }
}

/// The state records the oracle makes after each case.
fn push_state(trace: &mut Vec<u8>, state: &State) {
    let k = &state.dack;
    let flags = u32::from(k.dack_done)
        | u32::from(k.addck_timeout[0]) << 1
        | u32::from(k.addck_timeout[1]) << 2
        | u32::from(k.dadck_timeout[0]) << 3
        | u32::from(k.dadck_timeout[1]) << 4
        | u32::from(k.msbk_timeout[0]) << 5
        | u32::from(k.msbk_timeout[1]) << 6;
    push(trace, 14, flags, k.dack_cnt);
    for p in 0..dack::DACK_PATH_NR {
        for i in 0..dack::DACK_IDX_NR {
            push(
                trace,
                15,
                (p as u32) << 8 | i as u32 | u32::from(k.dadck_d[p][i]) << 16,
                u32::from(k.addck_d[p][i]) | u32::from(k.biask_d[p][i]) << 16,
            );
            for (w, bytes) in k.msbk_d[p][i].chunks(4).enumerate() {
                push(
                    trace,
                    16,
                    (p as u32) << 16 | (i as u32) << 8 | w as u32,
                    u32::from_le_bytes(bytes.try_into().unwrap()),
                );
            }
        }
    }
    push(
        trace,
        17,
        u32::from(state.dpk_gs[0]) | u32::from(state.dpk_gs[1]) << 8,
        u32::from(state.rfk_mcc.table_idx)
            | u32::from(state.is_tssi_mode[0]) << 8
            | u32::from(state.is_tssi_mode[1]) << 9,
    );
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Init,
    /// `rtw8852b_rx_dck` alone, both paths' TSSI mode as given.
    RxDck(bool),
}

#[derive(Clone, Copy, Debug)]
struct Case {
    kind: Kind,
    fill: Fill,
    dpd_bf: Option<u32>,
    faults: Faults,
}

const fn init_case(fill: Fill, faults: Faults) -> Case {
    Case {
        kind: Kind::Init,
        fill,
        dpd_bf: None,
        faults,
    }
}

const NONE: Faults = Faults {
    rck_stuck: false,
    drck_stuck: false,
    addck_stuck: false,
    s0_stuck: false,
    s1_stuck: false,
    rx_stuck: false,
    lok_fail: false,
    nctl_fail: 0,
    nctl_stuck: 0,
    kip_stuck: false,
    cwrpt_stuck: false,
    rpt: &[],
};

/// The oracle's cases, in its order.
fn init_cases() -> Vec<Case> {
    let pattern = |faults| init_case(Fill::Pattern, faults);
    vec![
        Case {
            dpd_bf: Some(0),
            ..pattern(NONE)
        },
        Case {
            dpd_bf: Some(0x0001_f07f),
            ..pattern(NONE)
        },
        init_case(Fill::Ones, NONE),
        init_case(Fill::Zeros, NONE),
        pattern(Faults {
            rck_stuck: true,
            ..NONE
        }),
        pattern(Faults {
            drck_stuck: true,
            ..NONE
        }),
        pattern(Faults {
            addck_stuck: true,
            ..NONE
        }),
        pattern(Faults {
            s0_stuck: true,
            ..NONE
        }),
        pattern(Faults {
            s1_stuck: true,
            ..NONE
        }),
        pattern(Faults {
            rx_stuck: true,
            ..NONE
        }),
        Case {
            kind: Kind::RxDck(true),
            ..pattern(NONE)
        },
    ]
}

/// One case as the Rust side runs it: its model and the state it left.
fn run_case(case: &Case) -> (Model, State) {
    let mut io = Model::new(case.fill, case.faults);
    if let Some(value) = case.dpd_bf {
        io.set(CR + R_DPD_BF, 4, value);
    }
    let mut state = State::default();
    let refused = match case.kind {
        Kind::Init => init(&mut io, &mut Stub::default(), &mut state),
        Kind::RxDck(tssi) => {
            state.is_tssi_mode = [tssi; 2];
            rx_dck::rx_dck(&mut io, &mut Stub::default(), state.is_tssi_mode)
        }
    };
    assert_eq!(refused, Ok(None));
    (io, state)
}

fn replay(case: &Case) -> Vec<u8> {
    let (io, state) = run_case(case);
    let mut trace = io.encode();
    push_state(&mut trace, &state);
    trace
}

/// The next length-prefixed segment of the oracle's trace.
fn segment<'a>(trace: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length = u32::from_le_bytes(trace[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let segment = &trace[*offset..*offset + length];
    *offset += length;
    segment
}

#[test]
#[ignore = "oracle: STELA_RTW89_RFK_ORACLE"]
fn rfk_init_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_RFK_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("rfk_trace.bin")).unwrap();
    let mut offset = 0;
    let cases = init_cases();
    assert_eq!(cases.len(), 11);
    for case in cases {
        assert_eq!(segment(&trace, &mut offset), replay(&case), "{case:?}");
    }
    assert_eq!(offset, trace.len());
}

#[test]
fn rfk_init_runs_dpk_init_rck_dack_then_rx_dck_with_the_scheduler_stopped() {
    let (io, state) = run_case(&init_cases()[0]);
    // DPK init's read comes first, then RCK's trigger, DACK's AFE init and
    // RX DCK between the scheduler's stop and resume.
    let position =
        |predicate: &dyn Fn(&[u32; 3]) -> bool| io.log.iter().position(predicate).unwrap();
    let dpd = position(&|r| r[0] == 4 && r[1] == CR + R_DPD_BF);
    let afe = position(&|r| r[0] == 8 && r[1] == PHYREG_SET);
    let stop = position(&|r| r[0] == 12);
    let resume = position(&|r| r[0] == 13);
    assert!(dpd < afe && afe < stop && stop < resume);
    assert_eq!(io.log[resume], [13, 0xa5c3, 0]);
    assert_eq!(state.dpk_gs, [0x5b, 0]);
    assert!(state.dack.dack_done);
    assert_eq!(state.dack.dack_cnt, 1);
    assert_eq!(state.dack.addck_timeout, [false; 2]);
    assert_eq!(state.dack.msbk_timeout, [false; 2]);
    assert_eq!(state.dack.dadck_timeout, [false; 2]);
    // RX DCK's 1 ms wait, once per path.
    assert_eq!(io.log.iter().filter(|r| **r == [9, 0, 1000]).count(), 2);
}

#[test]
fn dpk_init_moves_the_backoff_to_the_bb_from_44_on() {
    for (ofdm, scale, gs) in [(31, 12, 0x5b), (31, 13, 0x7f), (0, 44, 0x7f), (0, 0, 0x5b)] {
        let mut io = Model::new(Fill::Zeros, NONE);
        io.set(
            CR + R_DPD_BF,
            4,
            prep(ofdm, B_DPD_BF_OFDM) | prep(scale, B_DPD_BF_SCA),
        );
        let mut state = State::default();
        dpk_init(&mut io, &mut state).unwrap();
        assert_eq!(state.dpk_gs, [gs, 0]);
        for path in 0..2 {
            let written = io.writes(CR + R_DPD_CH0A + (path << 8));
            if gs == 0x7f {
                assert_eq!(written, [0x007f_7f7f]);
            } else {
                assert!(written.is_empty());
            }
        }
    }
}

#[test]
fn a_poll_that_never_answers_is_noted_after_its_bound_and_the_calibration_goes_on() {
    // RCK: every 2 us for 30 us, 16 looks per path, then the code it read
    // is written back anyway.
    let mut io = Model::new(
        Fill::Pattern,
        Faults {
            rck_stuck: true,
            ..NONE
        },
    );
    assert_eq!(rck::rck(&mut io).unwrap(), [true, true]);
    assert_eq!(rf_reads(&io, RR_RCKS), 2 * 16);
    let mut io = Model::new(Fill::Pattern, NONE);
    assert_eq!(rck::rck(&mut io).unwrap(), [false, false]);

    // The D-die RCK and ADDCK: every 1 us for 10 ms, 10001 looks.
    let (io, state) = run_case(&init_case(
        Fill::Pattern,
        Faults {
            drck_stuck: true,
            addck_stuck: true,
            ..NONE
        },
    ));
    // Each poll's looks, then the reads of the code it reports.
    assert_eq!(io.reads(CR + R_DRCK_RS), 10001 + 1);
    assert_eq!(io.reads(CR + R_ADDCKR0), 10001 + 2);
    assert_eq!(io.reads(CR + R_ADDCKR1), 10001 + 2);
    assert_eq!(state.dack.addck_timeout, [true, true]);
    assert!(state.dack.dack_done);

    // S0 reads its second done bit only when the first is set; S1 reads
    // both until either is set.
    let (io, state) = run_case(&init_case(
        Fill::Pattern,
        Faults {
            s0_stuck: true,
            s1_stuck: true,
            ..NONE
        },
    ));
    assert_eq!(io.reads(CR + R_DACK_S0P0), 10001);
    assert_eq!(io.reads(CR + R_DACK_S0P1), 0);
    assert_eq!(io.reads(CR + R_DACK_S1P0), 10001);
    assert_eq!(io.reads(CR + R_DACK_S1P1), 10001);
    assert_eq!(state.dack.msbk_timeout, [true, true]);
    assert_eq!(state.dack.dadck_timeout, [true, true]);
    assert!(state.dack.dack_done);
}

#[test]
fn rx_dck_waits_out_tx_mode_and_tracks_tssi_only_in_tssi_mode() {
    let mut io = Model::new(
        Fill::Pattern,
        Faults {
            rx_stuck: true,
            ..NONE
        },
    );
    assert_eq!(wait_rx_mode(&mut io, kpath()).unwrap(), 0b11);
    // Every 2 us for 5 ms: 2501 looks per path.
    assert_eq!(rf_reads(&io, RR_MOD), 2 * 2501);
    let mut io = Model::new(Fill::Pattern, NONE);
    assert_eq!(wait_rx_mode(&mut io, kpath()).unwrap(), 0);

    for tssi in [false, true] {
        let mut io = Model::new(Fill::Pattern, NONE);
        let refused = rx_dck::rx_dck(&mut io, &mut Stub::default(), [tssi; 2]).unwrap();
        assert_eq!(refused, None);
        for path in 0..2 {
            let enables: Vec<_> = io
                .writes(CR + R_P0_TSSI_TRK + (path << 13))
                .into_iter()
                .map(|value| field(value, B_P0_TSSI_TRK_EN))
                .collect();
            assert_eq!(enables, if tssi { vec![1, 0] } else { vec![] });
            // Fine tune and RF 0x05 are back as they were.
            let original = Model::new(Fill::Pattern, NONE).rf[path as usize];
            assert_eq!(
                io.rf[path as usize][RR_RSV1 as usize],
                original[RR_RSV1 as usize]
            );
            assert_eq!(
                io.rf[path as usize][RR_DCK as usize] & RR_DCK_FINE,
                original[RR_DCK as usize] & RR_DCK_FINE
            );
        }
    }
}

#[test]
fn a_scheduler_refusal_is_reported_and_a_failed_stop_is_not_resumed() {
    let cause = mac::Cause::CmacOff { value: 0 };
    let mut io = Model::new(Fill::Pattern, NONE);
    let mut stub = Stub {
        refuse_stop: Some(cause),
        ..Stub::default()
    };
    assert_eq!(
        rx_dck::rx_dck(&mut io, &mut stub, [false; 2]),
        Ok(Some(cause))
    );
    assert!(io.log.iter().any(|r| r[0] == 12));
    assert!(!io.log.iter().any(|r| r[0] == 13));
    // The calibration still ran.
    assert_eq!(io.log.iter().filter(|r| **r == [9, 0, 1000]).count(), 2);

    let mut io = Model::new(Fill::Pattern, NONE);
    let mut stub = Stub {
        refuse_resume: Some(cause),
        ..Stub::default()
    };
    assert_eq!(
        rx_dck::rx_dck(&mut io, &mut stub, [false; 2]),
        Ok(Some(cause))
    );
    assert!(io.log.contains(&[13, 0xa5c3, 0]));
}

#[test]
fn a_refused_access_ends_the_calibration() {
    let mut io = Model::new(Fill::Pattern, NONE);
    io.refuse = Some(CR + R_ADDCKR1);
    let mut state = State::default();
    assert_eq!(
        init(&mut io, &mut Stub::default(), &mut state),
        Err(Error::Register {
            register: CR + R_ADDCKR1
        })
    );
    assert!(!state.dack.dack_done);
    assert!(!io.log.iter().any(|r| r[0] == 12));
}

/// SWSI read requests for RF register `address`, either path.
fn rf_reads(io: &Model, address: u32) -> usize {
    io.writes(CR + SWSI_READ_ADDR_V1)
        .into_iter()
        .filter(|request| field(*request, SWSI_READ_ADDR_ADDR_V1) == address)
        .count()
}

/// The IQK records the oracle makes after the state's.
fn push_iqk(trace: &mut Vec<u8>, q: &iqk::IqkInfo) {
    push(
        trace,
        20,
        q.iqk_fail_cnt,
        u32::from(q.is_iqk_init)
            | u32::from(q.is_nbiqk) << 1
            | u32::from(q.iqk_times) << 8
            | u32::from(q.version) << 16,
    );
    for p in 0..iqk::IQK_SS {
        push(
            trace,
            21,
            p as u32
                | u32::from(q.iqk_band[p]) << 8
                | u32::from(q.iqk_bw[p]) << 16
                | u32::from(q.iqk_ch[p]) << 24,
            u32::from(q.lok_cor_fail[0][p])
                | u32::from(q.lok_fin_fail[0][p]) << 1
                | u32::from(q.iqk_tx_fail[0][p]) << 2
                | u32::from(q.iqk_rx_fail[0][p]) << 3
                | u32::from(q.is_wb_txiqk[p]) << 4
                | u32::from(q.is_wb_rxiqk[p]) << 5
                | u32::from(q.iqk_table_idx[p]) << 8,
        );
        push(trace, 22, q.nb_txcfir[p], q.nb_rxcfir[p]);
        push(trace, 23, q.bp_txkresult[p], q.bp_rxkresult[p]);
        push(trace, 24, q.bp_iqkenable[p], q.syn1to2);
    }
    for i in 0..iqk::IQK_CHS_NR {
        for p in 0..iqk::IQK_SS {
            push(
                trace,
                25,
                (i as u32) << 8 | p as u32 | u32::from(q.iqk_mcc_ch[i][p]) << 16,
                q.lok_idac[i][p],
            );
            push(trace, 26, (i as u32) << 8 | p as u32, q.lok_vbuf[i][p]);
        }
    }
}

const fn channel(band: Band, width: Bandwidth, number: u8) -> Channel {
    Channel {
        band,
        width,
        number,
    }
}

const G1: Channel = channel(Band::Ghz2, Bandwidth::Mhz20, 1);
const G6: Channel = channel(Band::Ghz2, Bandwidth::Mhz40, 6);
const A36: Channel = channel(Band::Ghz5, Bandwidth::Mhz20, 36);
const A149: Channel = channel(Band::Ghz5, Bandwidth::Mhz40, 149);
const A36_80: Channel = channel(Band::Ghz5, Bandwidth::Mhz80, 36);
const A149_80: Channel = channel(Band::Ghz5, Bandwidth::Mhz80, 149);

#[derive(Clone, Copy, Debug)]
struct IqkCase {
    channel: Channel,
    /// A second IQK on the same state.
    then: Option<Channel>,
    table_idx: u8,
    faults: Faults,
    /// `is_iqk_init` and `is_nbiqk` set beforehand.
    nbiqk: bool,
}

const fn iqk_case(channel: Channel) -> IqkCase {
    IqkCase {
        channel,
        then: None,
        table_idx: 0,
        faults: NONE,
        nbiqk: false,
    }
}

/// The oracle's IQK cases, in its order.
fn iqk_cases() -> Vec<IqkCase> {
    vec![
        iqk_case(G1),
        iqk_case(G6),
        iqk_case(A36),
        iqk_case(A149),
        iqk_case(A36_80),
        iqk_case(A149_80),
        IqkCase {
            faults: Faults {
                lok_fail: true,
                ..NONE
            },
            ..iqk_case(A36_80)
        },
        IqkCase {
            faults: Faults {
                nctl_fail: 1 << 0 | 1 << 5 | 1 << 10 | 1 << 12 | 1 << (13 + 6),
                ..NONE
            },
            ..iqk_case(G1)
        },
        IqkCase {
            faults: Faults {
                nctl_stuck: 7,
                ..NONE
            },
            ..iqk_case(G6)
        },
        IqkCase {
            table_idx: 1,
            ..iqk_case(A36)
        },
        IqkCase {
            then: Some(A149_80),
            ..iqk_case(G1)
        },
        IqkCase {
            nbiqk: true,
            ..iqk_case(A149)
        },
        IqkCase {
            nbiqk: true,
            faults: Faults {
                nctl_fail: u64::MAX,
                ..NONE
            },
            ..iqk_case(A149)
        },
    ]
}

fn run_iqk(case: &IqkCase) -> (Model, State) {
    let mut io = Model::new(Fill::Pattern, case.faults);
    let mut state = State::default();
    state.rfk_mcc.table_idx = case.table_idx;
    if case.nbiqk {
        state.iqk.is_iqk_init = true;
        state.iqk.is_nbiqk = true;
    }
    for channel in [Some(case.channel), case.then].into_iter().flatten() {
        let refused = iqk::iqk(&mut io, &mut Stub::default(), &mut state, channel);
        assert_eq!(refused, Ok(None));
    }
    (io, state)
}

fn replay_iqk(case: &IqkCase) -> Vec<u8> {
    let (io, state) = run_iqk(case);
    let mut trace = io.encode();
    push_state(&mut trace, &state);
    push_iqk(&mut trace, &state.iqk);
    trace
}

#[test]
#[ignore = "oracle: STELA_RTW89_RFK_ORACLE"]
fn iqk_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_RFK_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("iqk_trace.bin")).unwrap();
    let mut offset = 0;
    let cases = iqk_cases();
    assert_eq!(cases.len(), 13);
    for case in cases {
        assert_eq!(segment(&trace, &mut offset), replay_iqk(&case), "{case:?}");
    }
    assert_eq!(offset, trace.len());
}

#[test]
fn iqk_calibrates_both_paths_on_the_channel_it_is_given() {
    let (io, state) = run_iqk(&iqk_case(A149_80));
    let q = &state.iqk;
    assert!(q.is_iqk_init);
    assert_eq!(q.version, iqk::IQK_VER);
    // One run per path.
    assert_eq!(q.iqk_times, 2);
    assert_eq!(q.iqk_band, [1, 1]);
    assert_eq!(q.iqk_bw, [2, 2]);
    assert_eq!(q.iqk_ch, [149, 149]);
    assert_eq!(q.iqk_mcc_ch[0], [149, 149]);
    assert_eq!(q.is_wb_txiqk, [true, true]);
    assert_eq!(q.is_wb_rxiqk, [true, true]);
    assert_eq!(q.nb_txcfir, [0x4000_0000; 2]);
    assert_eq!(q.nb_rxcfir, [0x4000_0000; 2]);
    assert_eq!(q.iqk_fail_cnt, 0);
    // Four LOK, four TXK and four RXK one-shots and the restore's, per path.
    assert_eq!(io.oneshots, 2 * 13);
    // The scheduler is stopped once, around both paths.
    let marks: Vec<_> = io
        .log
        .iter()
        .filter(|r| r[0] == 12 || r[0] == 13)
        .copied()
        .collect();
    assert_eq!(marks, [[12, 0, 0], [13, 0xa5c3, 0]]);
    // Band 5 GHz, 80 MHz and channel 149 for each path in R_IQKCH.
    let iqkch = io.get(CR + R_IQKCH, 4);
    for shift in [0, 16] {
        assert_eq!(field(iqkch, B_IQKCH_BAND << shift), 1);
        assert_eq!(field(iqkch, B_IQKCH_BW << shift), 2);
        assert_eq!(field(iqkch, B_IQKCH_CH << shift), 149);
    }
}

#[test]
fn iqk_puts_back_the_bb_and_rf_registers_it_backed_up() {
    let original = Model::new(Fill::Pattern, NONE);
    let (io, _) = run_iqk(&iqk_case(G6));
    for register in BACKUP_BB_REGS {
        assert_eq!(io.get(CR + register, 4), original.get(CR + register, 4));
    }
    for (path, base) in RF_BASE.into_iter().enumerate() {
        for address in BACKUP_RF_REGS {
            if address & 0x1_0000 != 0 {
                let direct = CR + base + ((address & 0xff) << 2);
                assert_eq!(
                    io.get(direct, 4) & RFREG_MASK,
                    original.get(direct, 4) & RFREG_MASK
                );
            } else {
                let address = address as usize;
                assert_eq!(io.rf[path][address], original.rf[path][address]);
            }
        }
    }
}

#[test]
fn a_lok_code_out_of_range_is_tried_three_times_with_a_higher_bias() {
    let (io, state) = run_iqk(&iqk_cases()[6]);
    assert_eq!(io.oneshots, 2 * (3 * 4 + 4 + 4 + 1));
    for path in 0..2 {
        assert_eq!(io.rf[path][RR_LUTWD0 as usize], 3);
        assert_eq!(field(state.iqk.lok_idac[0][path], RR_TXMO_COI), 0x1f);
    }
    // rtw89 only logs that LOK failed; TXK and RXK still pass.
    assert_eq!(state.iqk.iqk_tx_fail[0], [false, false]);
    assert_eq!(state.iqk.iqk_rx_fail[0], [false, false]);
}

#[test]
fn a_failed_or_silent_one_shot_fails_its_calibration() {
    let (_, state) = run_iqk(&iqk_cases()[7]);
    let q = &state.iqk;
    // Path A: LOK coarse, TXK group 1, RXK group 2 and the restore; path B:
    // TXK group 2.
    assert_eq!(q.lok_cor_fail[0], [true, false]);
    assert_eq!(q.iqk_tx_fail[0], [true, true]);
    assert_eq!(q.iqk_rx_fail[0], [true, false]);
    assert_eq!(q.is_wb_txiqk, [false, false]);
    assert_eq!(q.nb_txcfir, [0x4000_0002; 2]);
    assert_eq!(q.nb_rxcfir, [0x4000_0002, 0x4000_0000]);
    assert_eq!(q.iqk_fail_cnt, 2);

    // A report that never comes: 0xbff8 every 1 us for 8.2 ms, 8201 looks,
    // and the group counts as failed.
    let (io, state) = run_iqk(&iqk_cases()[8]);
    assert_eq!(io.reads(CR + 0xbff8), 8201 + (2 * 13 - 1));
    assert_eq!(state.iqk.iqk_tx_fail[0], [true, false]);
}

#[test]
fn iqk_init_resets_once_and_every_run_counts() {
    let (_, state) = run_iqk(&iqk_cases()[10]);
    assert_eq!(state.iqk.iqk_times, 4);
    assert_eq!(state.iqk.iqk_ch, [149, 149]);

    // Results go under the MCC table the state names; one rtw89 never
    // gives keeps none.
    let (_, state) = run_iqk(&iqk_cases()[9]);
    assert_eq!(state.iqk.iqk_mcc_ch, [[0, 0], [36, 36]]);
    assert_eq!(state.iqk.lok_idac[0], [0, 0]);
    assert_ne!(state.iqk.lok_idac[1], [0, 0]);
    assert_eq!(state.iqk.iqk_table_idx, [1, 1]);
    let (_, state) = run_iqk(&IqkCase {
        table_idx: 2,
        ..iqk_case(A36)
    });
    assert_eq!(state.iqk.iqk_mcc_ch, [[0, 0]; 2]);
    assert_eq!(state.iqk.lok_idac, [[0, 0]; 2]);
}

/// The TSSI, DPK and MCC records the oracle makes after the IQK's.
fn push_tssi_dpk(trace: &mut Vec<u8>, state: &State) {
    let m = &state.rfk_mcc;
    push(
        trace,
        40,
        u32::from(m.ch[0]) | u32::from(m.ch[1]) << 8 | u32::from(m.ch[2]) << 16,
        u32::from(m.band[0]) | u32::from(m.band[1]) << 8 | u32::from(m.band[2]) << 16,
    );
    let d = &state.dpk;
    push(
        trace,
        43,
        u32::from(d.is_dpk_enable)
            | u32::from(d.is_dpk_reload_en) << 1
            | u32::from(d.cur_idx[0]) << 8
            | u32::from(d.cur_idx[1]) << 16,
        0,
    );
    for p in 0..dpk::DPK_RF_PATH {
        for k in 0..dpk::DPK_BKUP_NUM {
            let b = &d.bp[p][k];
            push(
                trace,
                41,
                (p as u32) << 8
                    | k as u32
                    | u32::from(b.band) << 16
                    | u32::from(b.bw) << 20
                    | u32::from(b.ch) << 24,
                u32::from(b.path_ok)
                    | u32::from(b.txagc_dpk) << 8
                    | u32::from(b.ther_dpk) << 16
                    | u32::from(b.gs) << 24,
            );
            push(
                trace,
                42,
                u32::from(b.pwsf)
                    | u32::from(d.corr_val[p][k]) << 16
                    | u32::from(d.corr_idx[p][k]) << 24,
                u32::from(d.dc_i[p][k]) | u32::from(d.dc_q[p][k]) << 16,
            );
        }
    }
    let t = &state.tssi;
    for p in 0..2 {
        for b in 0..tssi::TSSI_ALIMK_MAX {
            for v in 0..4 {
                push(
                    trace,
                    44,
                    (p << 16 | b << 8 | v) as u32 | u32::from(t.alignment_done[p][b]) << 24,
                    t.alignment_value[p][b][v],
                );
            }
        }
        for c in 0..tssi::TSSI_MAX_CH_NUM {
            if t.check_backup_aligmk[p][c] {
                for v in 0..4 {
                    push(
                        trace,
                        45,
                        (p << 16 | c << 8 | v) as u32,
                        t.alignment_backup_by_ch[p][c][v],
                    );
                }
            }
        }
    }
}

/// The oracle's H2C stub: `rtw89_h2c_pkt_set_hdr`'s arguments (30) and
/// each payload word (31).
struct Fw;

impl crate::wifi::realtek::ax::coex::Commands<Model> for Fw {
    fn send(
        &mut self,
        io: &mut Model,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error> {
        io.mark(
            30,
            u32::from(h2c::H2C_CAT_OUTSRC) | u32::from(class) << 8 | u32::from(func) << 16,
            u32::from(h2c::FWCMD_TYPE_H2C)
                | u32::from(rack) << 8
                | u32::from(dack) << 9
                | (payload.len() as u32) << 16,
        );
        for (i, word) in payload.chunks(4).enumerate() {
            io.mark(31, i as u32, u32::from_le_bytes(word.try_into().unwrap()));
        }
        Ok(())
    }
}

/// The oracle's TX power tracking element: 20 rows, bitmap 0xfff0.
fn trk_contents() -> Vec<u8> {
    (0..20)
        .flat_map(|r: i32| (0..30).map(move |i| ((r * 13 + i * 7) % 61 - 30) as i8 as u8))
        .collect()
}

fn trk_delta_rows() -> [Option<usize>; 16] {
    let mut delta = [None; 16];
    for (ty, row) in delta.iter_mut().enumerate().skip(4) {
        *row = Some(if ty < 8 { (ty - 4) * 3 } else { ty + 4 });
    }
    delta
}

fn trk_deltas() -> tssi::TrkDeltas {
    let contents = trk_contents();
    let trk = TxpwrTrk {
        contents: &contents,
        offset: 0,
        delta: trk_delta_rows(),
    };
    tssi::TrkDeltas::from_elements(&trk).unwrap()
}

/// The oracle's efuse TSSI values.
fn efuse_tssi(thermal_ff: bool) -> efuse::Tssi {
    let mut t = efuse::Tssi::default();
    for p in 0..2 {
        t.thermal[p] = if thermal_ff { 0xff } else { 0x20 + p as u8 };
        for (g, trim) in t.tssi_trim[p].iter_mut().enumerate() {
            *trim = (((p * 7 + g * 3) % 9) as i32 - 4) as i8;
        }
        for (g, cck) in t.tssi_cck[p].iter_mut().enumerate() {
            *cck = (0x10 + p * 3 + g) as i8;
        }
        for (g, mcs) in t.tssi_mcs[p].iter_mut().enumerate() {
            *mcs = (((p * 5 + g * 11) % 31) as i32 - 15) as i8;
        }
    }
    t
}

/// The oracle's RX gain offsets: none, or valid and patterned.
fn gain_inputs(valid: bool) -> super::super::channel::Inputs {
    let mut inputs = super::super::channel::Inputs::default();
    if valid {
        let e = &mut inputs.efuse_gain;
        e.offset_valid = true;
        e.comp_valid = true;
        for p in 0..2 {
            for (k, offset) in e.offset[p].iter_mut().enumerate() {
                *offset = (((p * 3 + k * 5) % 13) as i32 - 6) as i8;
            }
            for (s, comp) in e.comp[p].iter_mut().enumerate() {
                *comp = (((p * 7 + s * 2) % 11) as i32 - 5) as i8;
            }
        }
        inputs.offset_base = 3;
        inputs.rssi_base = -2;
    }
    inputs
}

const A42_80: Channel = channel(Band::Ghz5, Bandwidth::Mhz80, 42);
const A100: Channel = channel(Band::Ghz5, Bandwidth::Mhz20, 100);

/// The oracle's R_RPT_COM scripts: the RX BB, sync correlation index and
/// value, DC I and Q, digital gain and gain loss reads of one path, then
/// the PA samples where there are any.
const RPT_OK: [u32; 7] = [
    0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b, 0x05000000, 0x00000030,
];
const RPT_SYNC_FAIL: [u32; 7] = [
    0x00000005, 0x00000012, 0x00006400, 0x000a0000, 0x0000000b, 0x05000000, 0x00000030,
];
const RPT_DGAIN_LOW: [u32; 7] = [
    0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b, 0x01000000, 0x00000030,
];
const RPT_GL_HIGH: [u32; 7] = [
    0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b, 0x05000000, 0x00000090,
];
const RPT_GL_PAS: [u32; 11] = [
    0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b, 0x05000000, 0x00000000, 0x04000400,
    0x04000400, 0x00100010, 0x00100010,
];
const RPT_GL_LT: [u32; 11] = [
    0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b, 0x05000000, 0x00000000, 0x04000400,
    0x04000400, 0x04000400, 0x04000400,
];

#[derive(Clone, Copy, Debug)]
enum Op {
    Tssi,
    Dpk,
    Channel,
    BandChanged,
    ScanStart,
    ScanEnd,
}

#[derive(Clone, Copy, Debug)]
struct TssiDpkCase {
    ops: &'static [(Op, Channel)],
    thermal_ff: bool,
    cwrpt_stuck: bool,
    kip_stuck: bool,
    gain: bool,
    tssi_mode: bool,
    epa_5g: bool,
    gs7f: bool,
    cav: bool,
    mcc1: bool,
    nctl_stuck: u32,
    rpt: &'static [u32],
}

const fn tcase(ops: &'static [(Op, Channel)]) -> TssiDpkCase {
    TssiDpkCase {
        ops,
        thermal_ff: false,
        cwrpt_stuck: false,
        kip_stuck: false,
        gain: false,
        tssi_mode: false,
        epa_5g: false,
        gs7f: false,
        cav: false,
        mcc1: false,
        nctl_stuck: 0,
        rpt: &[],
    }
}

const fn scripted(ops: &'static [(Op, Channel)], rpt: &'static [u32]) -> TssiDpkCase {
    TssiDpkCase { rpt, ..tcase(ops) }
}

/// The oracle's TSSI and DPK cases, in its order.
fn tssi_dpk_cases() -> Vec<TssiDpkCase> {
    use Op::*;
    vec![
        tcase(&[(Tssi, G1)]),
        tcase(&[(Tssi, G6)]),
        tcase(&[(Tssi, A36)]),
        tcase(&[(Tssi, A149)]),
        tcase(&[(Tssi, A36_80)]),
        tcase(&[(Tssi, A149_80)]),
        tcase(&[(Tssi, A42_80)]),
        tcase(&[(Tssi, A100)]),
        TssiDpkCase {
            thermal_ff: true,
            ..tcase(&[(Tssi, A36)])
        },
        TssiDpkCase {
            cwrpt_stuck: true,
            ..tcase(&[(Tssi, G1)])
        },
        TssiDpkCase {
            gain: true,
            ..tcase(&[(Tssi, G6)])
        },
        tcase(&[(Tssi, G1), (Tssi, G1)]),
        scripted(&[(Dpk, G1)], &RPT_OK),
        scripted(&[(Dpk, G6)], &RPT_OK),
        scripted(&[(Dpk, A36)], &RPT_OK),
        scripted(&[(Dpk, A149)], &RPT_OK),
        scripted(&[(Dpk, A36_80)], &RPT_OK),
        scripted(&[(Dpk, A149_80)], &RPT_OK),
        scripted(&[(Dpk, G1)], &RPT_SYNC_FAIL),
        scripted(&[(Dpk, A36)], &RPT_DGAIN_LOW),
        scripted(&[(Dpk, A36_80)], &RPT_DGAIN_LOW),
        scripted(&[(Dpk, G6)], &RPT_GL_HIGH),
        scripted(&[(Dpk, A149)], &RPT_GL_PAS),
        scripted(&[(Dpk, A149)], &RPT_GL_LT),
        TssiDpkCase {
            tssi_mode: true,
            ..scripted(&[(Dpk, G1)], &RPT_OK)
        },
        TssiDpkCase {
            epa_5g: true,
            ..scripted(&[(Dpk, A36)], &RPT_OK)
        },
        TssiDpkCase {
            epa_5g: true,
            ..scripted(&[(Dpk, G1)], &RPT_OK)
        },
        TssiDpkCase {
            gs7f: true,
            cav: true,
            ..scripted(&[(Dpk, A36)], &RPT_OK)
        },
        TssiDpkCase {
            kip_stuck: true,
            nctl_stuck: 3,
            ..scripted(&[(Dpk, G6)], &RPT_OK)
        },
        tcase(&[(Dpk, G1)]),
        scripted(&[(Channel, G1)], &RPT_OK),
        scripted(&[(Channel, A149_80)], &RPT_OK),
        scripted(&[(Channel, G6), (Channel, A36)], &RPT_OK),
        TssiDpkCase {
            mcc1: true,
            ..scripted(&[(Channel, A36)], &RPT_OK)
        },
        tcase(&[(BandChanged, A36)]),
        tcase(&[(Tssi, A36), (BandChanged, A36)]),
        tcase(&[(ScanStart, G1)]),
        tcase(&[(Tssi, G1), (ScanStart, G1), (ScanEnd, G1)]),
    ]
}

/// One TSSI or DPK case as the Rust side runs it.
fn run_tssi_dpk(case: &TssiDpkCase) -> (Model, State) {
    let mut io = Model::new(
        Fill::Pattern,
        Faults {
            cwrpt_stuck: case.cwrpt_stuck,
            kip_stuck: case.kip_stuck,
            nctl_stuck: case.nctl_stuck,
            rpt: case.rpt,
            ..NONE
        },
    );
    let mut state = State::default();
    state.dpk_gs[0] = if case.gs7f { 0x7f } else { 0x5b };
    let efuse = efuse_tssi(case.thermal_ff);
    let deltas = trk_deltas();
    let gain = gain_inputs(case.gain);
    let tssi_inputs = tssi::Inputs {
        efuse: &efuse,
        deltas: &deltas,
        gain: &gain,
    };
    let dpk_inputs = dpk::Inputs {
        epa_2g: false,
        epa_5g: case.epa_5g,
        cv: if case.cav { CHIP_CAV } else { CHIP_CBV },
    };
    if case.tssi_mode {
        state.is_tssi_mode = [true; 2];
    }
    if case.mcc1 {
        let (_, first) = case.ops[0];
        state.rfk_mcc.ch[1] = first.number;
        state.rfk_mcc.band[1] = first.band as u8;
    }
    for &(op, channel) in case.ops {
        let mut stub = Stub::default();
        match op {
            Op::Tssi => assert_eq!(
                tssi::tssi(&mut io, &mut stub, &mut state, channel, true, &tssi_inputs),
                Ok(None)
            ),
            Op::Dpk => assert_eq!(
                dpk::dpk(&mut io, &mut stub, &mut state, channel, dpk_inputs),
                Ok(None)
            ),
            Op::Channel => {
                let inputs = ChannelInputs {
                    tssi: tssi_inputs,
                    dpk: dpk_inputs,
                };
                let done =
                    super::channel(&mut io, &mut stub, &mut Fw, &mut state, channel, &inputs);
                assert_eq!(
                    done,
                    Ok(Calibrated {
                        rx_dck: None,
                        iqk: None,
                        tssi: None,
                        dpk: None,
                        ntfy_mcc: Ok(()),
                    })
                );
            }
            Op::BandChanged => band_changed(&mut io, &mut state, channel, &tssi_inputs).unwrap(),
            Op::ScanStart | Op::ScanEnd => assert_eq!(
                scan(
                    &mut io,
                    &mut stub,
                    &mut state,
                    matches!(op, Op::ScanStart),
                    channel,
                    &tssi_inputs
                ),
                Ok(None)
            ),
        }
    }
    (io, state)
}

fn replay_tssi_dpk(case: &TssiDpkCase) -> Vec<u8> {
    let (io, state) = run_tssi_dpk(case);
    let mut trace = io.encode();
    push_state(&mut trace, &state);
    push_iqk(&mut trace, &state.iqk);
    push_tssi_dpk(&mut trace, &state);
    trace
}

#[test]
#[ignore = "oracle: STELA_RTW89_RFK_ORACLE"]
fn tssi_dpk_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_RFK_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("tssi_dpk_trace.bin")).unwrap();
    let mut offset = 0;
    let cases = tssi_dpk_cases();
    assert_eq!(cases.len(), 38);
    for (index, case) in cases.iter().enumerate() {
        let expected = segment(&trace, &mut offset);
        let replayed = replay_tssi_dpk(case);
        if expected != replayed {
            let first = expected
                .chunks(12)
                .zip(replayed.chunks(12))
                .position(|(a, b)| a != b);
            panic!(
                "case {index} {case:?}: {} bytes against {}, first record apart {first:?}",
                expected.len(),
                replayed.len()
            );
        }
    }
    assert_eq!(offset, trace.len());
}

/// Writes logged of `register` and the reads among them, as `(tag, value)`.
fn accesses(io: &Model, register: u32) -> Vec<(u32, u32)> {
    io.log
        .iter()
        .filter(|[tag, r, _]| *tag <= 8 && *r == register)
        .map(|[tag, _, value]| (*tag, *value))
        .collect()
}

#[test]
fn tssi_aligns_each_path_then_turns_both_to_tssi_mode() {
    let (io, state) = run_tssi_dpk(&tcase(&[(Op::Tssi, G1)]));
    assert_eq!(state.is_tssi_mode, [true, true]);
    for p in 0..2 {
        assert!(state.tssi.alignment_done[p][tssi::TSSI_ALIMK_2G]);
        assert!(!state.tssi.alignment_done[p][tssi::TSSI_ALIMK_5GL]);
        // Channel 1 is index 0.
        assert!(state.tssi.check_backup_aligmk[p][0]);
        assert_eq!(
            state.tssi.alignment_backup_by_ch[p][0][..4],
            state.tssi.alignment_value[p][0][..4]
        );
    }
    // The scheduler is stopped around each path's alignment.
    let marks: Vec<_> = io.log.iter().filter(|r| r[0] == 12 || r[0] == 13).collect();
    assert_eq!(marks.len(), 4);
    // TSSI goes off first and on last.
    let en = |io: &Model| -> Vec<u32> {
        accesses(io, CR + R_P0_TSSI_AVG)
            .into_iter()
            .filter(|(tag, _)| *tag == 8)
            .map(|(_, value)| field(value, B_P0_TSSI_EN))
            .collect()
    };
    let enables = en(&io);
    assert_eq!(enables.first(), Some(&0));
    assert_eq!(enables.last(), Some(&1));
}

#[test]
fn a_cw_report_that_never_comes_leaves_the_alignment_undone_after_100_looks() {
    let case = TssiDpkCase {
        cwrpt_stuck: true,
        ..tcase(&[(Op::Tssi, G1)])
    };
    let (io, state) = run_tssi_dpk(&case);
    assert_eq!(io.reads(CR + 0x1c18), 100);
    assert_eq!(io.reads(CR + 0x3c18), 100);
    assert_eq!(io.log.iter().filter(|r| **r == [9, 0, 30]).count(), 200);
    assert_eq!(
        state.tssi.alignment_done,
        [[false; tssi::TSSI_ALIMK_MAX]; 2]
    );
    assert!(!state.tssi.check_backup_aligmk[0].contains(&true));
    // TSSI is still turned on.
    assert_eq!(state.is_tssi_mode, [true, true]);

    // A second TSSI on the channel puts back the alignment it kept,
    // without sending a packet.
    let (once, _) = run_tssi_dpk(&tcase(&[(Op::Tssi, G1)]));
    let (twice, _) = run_tssi_dpk(&tcase(&[(Op::Tssi, G1), (Op::Tssi, G1)]));
    assert_eq!(twice.reads(CR + 0x1c18), once.reads(CR + 0x1c18));
}

#[test]
fn tssi_writes_the_thermal_offsets_around_the_efuse_value_or_none() {
    let (io, _) = run_tssi_dpk(&tcase(&[(Op::Tssi, A36)]));
    let deltas = trk_deltas();
    // Path A on 5 GHz band 1: offsets 0..31 are the down deltas negated,
    // 63 down to 32 the up deltas from index 1.
    let first = io.get(CR + R_P0_TSSI_BASE, 4).to_le_bytes();
    let down = deltas.down[0][1];
    for (k, byte) in first.iter().enumerate() {
        assert_eq!(*byte as i8, down[k].wrapping_neg());
    }
    let last = io.get(CR + R_P0_TSSI_BASE + 60, 4).to_le_bytes();
    let up = deltas.up[0][1];
    assert_eq!(last[3] as i8, up[1]);
    assert_eq!(last[0] as i8, up[4]);
    assert_eq!(field(io.get(CR + R_P0_TMETER, 4), B_P0_TMETER), 0x20);

    let (io, _) = run_tssi_dpk(&TssiDpkCase {
        thermal_ff: true,
        ..tcase(&[(Op::Tssi, A36)])
    });
    for i in (0..64).step_by(4) {
        assert_eq!(io.get(CR + R_P0_TSSI_BASE + i, 4), 0);
        assert_eq!(io.get(CR + R_TSSI_THOF + i, 4), 0);
    }
    assert_eq!(field(io.get(CR + R_P1_TMETER, 4), B_P1_TMETER), 32);
}

#[test]
fn trk_deltas_need_every_2ghz_and_5ghz_type() {
    let contents = trk_contents();
    let mut delta = trk_delta_rows();
    let trk = TxpwrTrk {
        contents: &contents,
        offset: 0,
        delta,
    };
    let deltas = tssi::TrkDeltas::from_elements(&trk).unwrap();
    // 2GA_P is type 11 at row 15; 5GB_N subband 2 is type 4's third row.
    assert_eq!(deltas.up[0][0][3], contents[15 * 30 + 3] as i8);
    assert_eq!(deltas.down[1][3][0], contents[2 * 30] as i8);
    delta[9] = None;
    let trk = TxpwrTrk {
        contents: &contents,
        offset: 0,
        delta,
    };
    assert_eq!(tssi::TrkDeltas::from_elements(&trk), None);
}

#[test]
fn dpk_passes_both_paths_and_switches_dpd_on() {
    let (io, state) = run_tssi_dpk(&scripted(&[(Op::Dpk, G1)], &RPT_OK));
    for p in 0..2 {
        let bp = &state.dpk.bp[p][0];
        assert!(bp.path_ok, "path {p}");
        // The loop's gain loss 3 takes the TX AGC from 0x38 to 0x35.
        assert_eq!(bp.txagc_dpk, 0x35);
        assert_eq!(bp.pwsf, 0x78);
        assert_eq!(bp.gs, 0x5b);
        assert_eq!((bp.band, bp.bw, bp.ch), (0, 0, 1));
        assert_eq!(state.dpk.corr_val[p][0], 200);
        assert_eq!((state.dpk.dc_i[p][0], state.dpk.dc_q[p][0]), (10, 11));
        // DPD's enable is the last byte-3 write of the path's DPD register.
        let dpd: Vec<_> = accesses(&io, CR + R_DPD_CH0A + ((p as u32) << 8))
            .into_iter()
            .filter(|(tag, _)| *tag == 8)
            .collect();
        assert_eq!(dpd.last().map(|(_, value)| value >> 24 & 1), Some(1));
    }
    assert!(state.dpk.is_dpk_enable);
    assert_eq!(state.dpk.oneshot_timeouts, 0);
    // The scheduler is stopped once, around both paths.
    let marks: Vec<_> = io.log.iter().filter(|r| r[0] == 12 || r[0] == 13).collect();
    assert_eq!(marks.len(), 2);
}

#[test]
fn a_failed_sync_fails_its_path_and_leaves_dpd_off() {
    let (io, state) = run_tssi_dpk(&scripted(&[(Op::Dpk, G1)], &RPT_SYNC_FAIL));
    let bp = &state.dpk.bp[0][0];
    assert!(!bp.path_ok);
    assert_eq!(bp.txagc_dpk, 0);
    assert_eq!(state.dpk.corr_val[0][0], 100);
    let dpd: Vec<_> = accesses(&io, CR + R_DPD_CH0A)
        .into_iter()
        .filter(|(tag, _)| *tag == 8)
        .collect();
    assert_eq!(dpd.last().map(|(_, value)| value >> 24 & 1), Some(0));
}

#[test]
fn a_dpk_one_shot_that_never_reports_is_counted_and_dpk_goes_on() {
    let case = TssiDpkCase {
        kip_stuck: true,
        nctl_stuck: 3,
        ..scripted(&[(Op::Dpk, G6)], &RPT_OK)
    };
    let (io, state) = run_tssi_dpk(&case);
    // One-shot 3's 0xbff8: every 1 us for 20 ms, 20001 looks.
    assert!(io.reads(CR + 0xbff8) > 20001);
    // Every one-shot's KIP report: 2001 looks each.
    let oneshots = io.oneshots;
    assert_eq!(state.dpk.oneshot_timeouts, oneshots + 1);
    // The 1 us waits: one-shot 3's 20000, each one-shot's 2000 and the one
    // between its polls, and the 1 us after each direct RF write: the TX AGC
    // twice and RR_BBDC once per path, and RR_BBDC's restore per path.
    assert_eq!(
        io.log.iter().filter(|r| **r == [9, 0, 1]).count() as u32,
        20000 + oneshots * 2001 + 2 * 4
    );
}

#[test]
fn an_external_pa_skips_dpk_and_forces_dpd_off() {
    let (io, state) = run_tssi_dpk(&TssiDpkCase {
        epa_5g: true,
        ..scripted(&[(Op::Dpk, A36)], &RPT_OK)
    });
    assert_eq!(io.oneshots, 0);
    assert_eq!(state.dpk.bp[0][0].ch, 0);
    for p in 0..2u32 {
        let dpd = accesses(&io, CR + R_DPD_CH0A + (p << 8));
        assert_eq!(
            dpd.last().map(|(tag, value)| (*tag, value >> 24 & 1)),
            Some((8, 0))
        );
    }
    // 2 GHz has no external PA.
    let (io, _) = run_tssi_dpk(&TssiDpkCase {
        epa_5g: true,
        ..scripted(&[(Op::Dpk, G1)], &RPT_OK)
    });
    assert!(io.oneshots > 0);
}

#[test]
fn rfk_channel_runs_rx_dck_iqk_tssi_and_dpk_then_tells_the_firmware() {
    let (io, state) = run_tssi_dpk(&scripted(&[(Op::Channel, G1)], &RPT_OK));
    // RX DCK, IQK, TSSI's two paths and DPK each stop the scheduler.
    let stops = io.log.iter().filter(|r| r[0] == 12).count();
    assert_eq!(stops, 5);
    // RF_NTFY_MCC goes last: OUTSRC, class 0xa, function 2, no ack, 20
    // bytes, channel 1 in table 0.
    let h2c: Vec<_> = io.log.iter().filter(|r| r[0] == 30 || r[0] == 31).collect();
    assert_eq!(h2c[0], &[30, 2 | 0xa << 8 | 2 << 16, 20 << 16]);
    let words: Vec<_> = h2c[1..].iter().map(|r| r[2]).collect();
    assert_eq!(words, [1, 1, 0, 0, 1]);
    assert_eq!(io.log.last().unwrap()[0], 31);
    assert_eq!(state.rfk_mcc.table_idx, 0);
    assert_eq!(state.rfk_mcc.ch, [1, 0, 0]);
    assert_eq!(state.is_tssi_mode, [true, true]);
    assert!(state.dpk.bp[0][0].path_ok && state.dpk.bp[1][0].path_ok);
    assert_eq!(state.iqk.iqk_ch, [1, 1]);
}

#[test]
fn the_mcc_table_holding_the_channel_is_taken_else_the_first() {
    let mut mcc = RfkMcc::default();
    ntfy::mcc_get_ch_info(&mut mcc, G6);
    assert_eq!((mcc.table_idx, mcc.ch, mcc.band), (0, [6, 0, 0], [0, 0, 0]));
    ntfy::mcc_get_ch_info(&mut mcc, A36);
    assert_eq!(
        (mcc.table_idx, mcc.ch, mcc.band),
        (0, [36, 0, 0], [1, 0, 0])
    );
    mcc.ch[1] = 149;
    mcc.band[1] = 1;
    ntfy::mcc_get_ch_info(&mut mcc, A149);
    assert_eq!((mcc.table_idx, mcc.ch), (1, [36, 149, 0]));
    // The same number on another band is another channel.
    mcc.ch[1] = 1;
    ntfy::mcc_get_ch_info(&mut mcc, G1);
    assert_eq!((mcc.table_idx, mcc.ch, mcc.band), (0, [1, 1, 0], [0, 1, 0]));
    let payload = ntfy::rf_get_mccch(&RfkMcc {
        ch: [36, 149, 0],
        band: [1, 1, 0],
        table_idx: 1,
    });
    assert_eq!(
        payload,
        [
            36, 0, 0, 0, 36, 0, 0, 0, 149, 0, 0, 0, 149, 0, 0, 0, 149, 0, 0, 0
        ]
    );
}

#[test]
fn a_scan_start_in_tssi_mode_and_a_refused_access_are_left_alone() {
    let efuse = efuse_tssi(false);
    let deltas = trk_deltas();
    let gain = gain_inputs(false);
    let inputs = tssi::Inputs {
        efuse: &efuse,
        deltas: &deltas,
        gain: &gain,
    };
    let mut io = Model::new(Fill::Pattern, NONE);
    let mut state = State {
        is_tssi_mode: [true, false],
        ..State::default()
    };
    assert_eq!(
        scan(&mut io, &mut Stub::default(), &mut state, true, G1, &inputs),
        Ok(None)
    );
    assert!(io.log.is_empty());

    let mut io = Model::new(Fill::Pattern, NONE);
    io.refuse = Some(CR + R_P1_TSSI_AVG);
    let mut state = State::default();
    assert_eq!(
        tssi::tssi(&mut io, &mut Stub::default(), &mut state, G1, true, &inputs),
        Err(Error::Register {
            register: CR + R_P1_TSSI_AVG
        })
    );
    assert!(!io.log.iter().any(|r| r[0] == 12));
}

/// The DPK tracking oracle's records, from a segment.
fn track_records(segment: &[u8]) -> Vec<[u32; 3]> {
    segment
        .chunks(12)
        .map(|r| {
            core::array::from_fn(|i| u32::from_le_bytes(r[4 * i..4 * i + 4].try_into().unwrap()))
        })
        .collect()
}

/// One DPK tracking case as the Rust side runs it, from the inputs the C
/// segment records: the modes and tables in use (58), each result (59),
/// and per period (60) its BAR2 words (63) and RR_TM words (65).
fn replay_dpk_track(c: &[[u32; 3]]) -> Vec<u8> {
    use crate::wifi::realtek::ax::dynamic::Thermal;

    let mut io = Model::new(Fill::Pattern, NONE);
    let mut state = State::default();
    let [tag, modes, zero] = c[0];
    assert_eq!(tag, 58);
    io.mark(58, modes, zero);
    state.is_tssi_mode = [modes & 1 != 0, modes & 2 != 0];
    state.dpk.cur_idx = [(modes >> 8) as u8, (modes >> 16) as u8];
    for &[tag, a, b] in &c[1..5] {
        assert_eq!(tag, 59);
        let bp = &mut state.dpk.bp[(a >> 8 & 0xff) as usize][(a & 0xff) as usize];
        bp.band = (a >> 16) as u8;
        bp.ch = (a >> 24) as u8;
        bp.ther_dpk = b as u8;
        bp.pwsf = (b >> 16) as u16;
        io.mark(59, a, b);
    }
    let mut thermal = Thermal::default();
    let mut at = 5;
    while at < c.len() {
        if c[at][0] != 60 {
            at += 1;
            continue;
        }
        let n = c[at][1];
        io.mark(60, n, 0);
        at += 1;
        while c[at][0] == 63 {
            let [_, register, value] = c[at];
            io.set(CR + register, 4, value);
            io.mark(63, register, value);
            at += 1;
        }
        while c[at][0] == 65 {
            let [_, path, value] = c[at];
            io.rf[path as usize][RR_TM as usize] = value;
            io.mark(65, path, value);
            at += 1;
        }
        io.mark(50, 1, n);
        thermal.update(&mut io, state.is_tssi_mode).unwrap();
        let [a, b] = thermal.read();
        io.mark(
            66,
            u32::from(a) | u32::from(b) << 8 | u32::from(thermal.last_thermal_max) << 16,
            0,
        );
        io.mark(50, 2, n);
        track(&mut io, &state, thermal.read()).unwrap();
    }
    io.encode()
}

#[test]
#[ignore = "oracle: STELA_RTW89_RFK_ORACLE"]
fn dpk_track_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_RFK_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("dpk_track_trace.bin")).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < trace.len() {
        let expected = segment(&trace, &mut offset);
        let replayed = replay_dpk_track(&track_records(expected));
        if expected != replayed.as_slice() {
            let first = expected
                .chunks(12)
                .zip(replayed.chunks(12))
                .position(|(a, b)| a != b);
            let record = |bytes: &[u8]| {
                first
                    .and_then(|at| bytes.chunks(12).nth(at))
                    .map(track_records)
            };
            panic!(
                "case {cases}: {} bytes against {}, first record apart {first:?}: C {:x?}, \
                 Rust {:x?}",
                expected.len(),
                replayed.len(),
                record(expected),
                record(&replayed)
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 5);
}

/// A state whose results in use (table 0) were learned at thermal 0x20 with
/// pwsf 0x100 on `band`, and a model whose TX AGC reads `txagc_rf` on both
/// paths, tracking enabled.
fn track_setup(band: Band, tssi: bool, txagc_rf: u32) -> (Model, State) {
    let mut io = Model::new(Fill::Zeros, NONE);
    let mut state = State {
        is_tssi_mode: [tssi; 2],
        ..State::default()
    };
    for path in 0..2 {
        state.dpk.bp[path][0] = dpk::DpkBkupPara {
            band: band as u8,
            ch: 36,
            ther_dpk: 0x20,
            pwsf: 0x100,
            ..dpk::DpkBkupPara::default()
        };
        io.set(CR + R_TXAGC_BB + ((path as u32) << 13), 4, txagc_rf);
    }
    (io, state)
}

fn bnd(io: &Model, path: u32, kidx: u32) -> (u32, u32) {
    let word = io.get(CR + R_DPD_BND + (path << 8) + (kidx << 2), 4);
    (field(word, B_DPD_BND_0), field(word, B_DPD_BND_1))
}

#[test]
fn dpk_track_moves_pwsf_by_the_thermal_drift_per_band() {
    // 2 GHz: 1.5 per step, 4 steps cooler than learned: +6.
    let (mut io, state) = track_setup(Band::Ghz2, false, 0x12);
    track(&mut io, &state, [0x1c, 0x1c]).unwrap();
    assert_eq!(bnd(&io, 0, 0), (0x106, 0x106));
    assert_eq!(bnd(&io, 1, 0), (0x106, 0x106));
    // 5 GHz: 2.5 per step, 3 steps hotter: -7 (truncated toward 0).
    let (mut io, state) = track_setup(Band::Ghz5, false, 0x12);
    track(&mut io, &state, [0x23, 0x20]).unwrap();
    assert_eq!(bnd(&io, 0, 0), (0x0f9, 0x0f9));
    assert_eq!(bnd(&io, 1, 0), (0x100, 0x100));
    // No reading yet: no drift.
    let (mut io, state) = track_setup(Band::Ghz5, false, 0x12);
    track(&mut io, &state, [0, 0]).unwrap();
    assert_eq!(bnd(&io, 0, 0), (0x100, 0x100));
}

#[test]
fn dpk_track_writes_nothing_with_tracking_disabled_or_no_tx_agc() {
    let (mut io, state) = track_setup(Band::Ghz2, false, 0);
    track(&mut io, &state, [0x10, 0x10]).unwrap();
    assert!(!io.log.iter().any(|r| r[0] == 8));
    let (mut io, state) = track_setup(Band::Ghz2, false, 0x12);
    io.set(CR + R_DPK_TRK, 4, B_DPK_TRK_DIS);
    track(&mut io, &state, [0x10, 0x10]).unwrap();
    assert!(!io.log.iter().any(|r| r[0] == 8));
}

#[test]
fn dpk_track_in_tssi_mode_adds_the_agc_offset_and_the_bb_agc_against_its_target() {
    // Offset byte -3, BB byte 0x10 against target 2, drift +6 (2 GHz).
    let word = 0xfd10_0012u32;
    let (mut io, state) = track_setup(Band::Ghz2, true, word);
    io.set(CR + R_TXAGC_TP, 4, 2);
    io.set(CR + R_TXAGC_TP + (1 << 13), 4, 2);
    track(&mut io, &state, [0x1c, 0x1c]).unwrap();
    // R_P0_TXDPD 0: 0x100 + 2 - 0x10 + (-3 + 6).
    assert_eq!(bnd(&io, 0, 0), (0x0f5, 0x0f5));
    // The HW offset mode zeroes the offset; R_P0_TXDPD set leaves the BB
    // AGC out.
    let (mut io, state) = track_setup(Band::Ghz2, true, word);
    io.set(CR + R_DPD_COM, 4, B_DPD_COM_OF);
    io.set(CR + R_P0_TXDPD, 4, 0x1000_0000);
    track(&mut io, &state, [0x1c, 0x1c]).unwrap();
    assert_eq!(bnd(&io, 0, 0).0, 0x106);
}

#[test]
fn the_thermal_average_leaves_out_a_zero_reading_and_reads_tssi_reports_in_tssi_mode() {
    use crate::wifi::realtek::ax::dynamic::Thermal;

    let mut io = Model::new(Fill::Zeros, NONE);
    io.rf[0][RR_TM as usize] = 0x20 << 1;
    io.rf[1][RR_TM as usize] = 0;
    let mut thermal = Thermal::init(&mut io, [false, false]).unwrap();
    assert_eq!(
        (thermal.read(), thermal.last_thermal_max),
        ([0x20, 0], 0x20)
    );
    // Triggered through RR_TM_TRI, then read 200 us later.
    assert!(io.log.contains(&[9, 0, 200]));
    io.set(CR + 0x1c10, 4, 0x2c << 24);
    io.set(CR + 0x3c10, 4, 0x18 << 24);
    thermal.update(&mut io, [true, true]).unwrap();
    // (0x20 * 3 + 0x2c) / 4 on path A; path B's first reading taken whole.
    assert_eq!(thermal.read(), [0x23, 0x18]);
    assert_eq!(thermal.last_thermal_max, 0x2c);
}
