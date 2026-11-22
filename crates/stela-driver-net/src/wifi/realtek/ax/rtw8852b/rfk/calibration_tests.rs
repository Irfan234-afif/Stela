extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    io::{CR_BASE, field, prep},
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
