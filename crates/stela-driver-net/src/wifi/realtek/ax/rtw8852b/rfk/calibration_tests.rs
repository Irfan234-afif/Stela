extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    io::{CR_BASE, RF_BASE, field, prep},
    registers::{
        PHYREG_SET, RFREG_MASK, SWSI_BIT_MASK_V1, SWSI_DATA_ADDR_V1, SWSI_DATA_BIT_MASK_EN_V1,
        SWSI_DATA_PATH_V1, SWSI_DATA_V1, SWSI_DATA_VAL_V1, SWSI_R_BUSY_V1, SWSI_R_DATA_DONE_V1,
        SWSI_READ_ADDR_ADDR_V1, SWSI_READ_ADDR_PATH_V1, SWSI_READ_ADDR_V1, SWSI_V1, SWSI_W_BUSY_V1,
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
        let mut value = self.view(register & !3) >> ((register & 3) * 8);
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
