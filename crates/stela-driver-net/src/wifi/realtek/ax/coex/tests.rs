extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    h2c::{HEADER_LEN, Header, Sequence},
    io::CR_BASE,
};
use alloc::{vec, vec::Vec};

/// One access, or one of the C oracle's harness records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Read {
        width: u32,
        register: u32,
        value: u32,
    },
    Write {
        width: u32,
        register: u32,
        value: u32,
    },
    Delay(u64),
    /// A record the harness makes itself: an H2C's bytes.
    Mark {
        tag: u32,
        a: u32,
        b: u32,
    },
}

/// The C oracle's records: tag and two values, each a little-endian u32.
/// Reads are tagged by width, writes by 4 plus width, delays 9.
fn push(trace: &mut Vec<u8>, tag: u32, a: u32, b: u32) {
    for word in [tag, a, b] {
        trace.extend_from_slice(&word.to_le_bytes());
    }
}

fn encode(log: &[Access]) -> Vec<u8> {
    let mut trace = Vec::new();
    for access in log {
        match *access {
            Access::Read {
                width,
                register,
                value,
            } => push(&mut trace, width, register, value),
            Access::Write {
                width,
                register,
                value,
            } => push(&mut trace, 4 + width, register, value),
            Access::Delay(microseconds) => push(&mut trace, 9, 0, microseconds as u32),
            Access::Mark { tag, a, b } => push(&mut trace, tag, a, b),
        }
    }
    trace
}

/// What the model's spaces hold before the first access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fill {
    /// MAC byte `i` holds `i * 37 + 11`, LTE byte `i` holds `i * 53 + 7`.
    Pattern,
    Ones,
    Zeros,
}

const MEMORY: usize = 0x2_0000;
const LTE: usize = 0x100;
/// The LTE access's ready bit in its word.
const LTE_READY: u32 = (LTE_CTRL_READY as u32) << 24;
const SWSI_BUSY: u32 = SWSI_W_BUSY_V1 | SWSI_R_BUSY_V1;

/// The register model the C oracle's harness uses: MAC and BB space as
/// little-endian bytes, behaving per aligned word, and the LTE space.
///
/// LTE_CTRL reads its ready bit set unless the LTE is stuck; a write of
/// `LTE_CTRL_WRITE | offset` stores LTE_WDATA in the LTE space at offset,
/// one of `LTE_CTRL_READ | offset` puts it in LTE_RDATA. BB SWSI_V1 reads
/// its busy bits clear. CMAC_FUNC_EN reads `RTW89_R32_DEAD` when dead.
struct Model {
    memory: Vec<u8>,
    lte: Vec<u8>,
    log: Vec<Access>,
    lte_stuck: bool,
    cmac_dead: bool,
}

impl Model {
    /// The model as the oracle starts each case: CMAC0 enabled, as the MAC
    /// init left it.
    fn new(fill: Fill) -> Self {
        let (memory, lte) = match fill {
            Fill::Pattern => (
                (0..MEMORY).map(|at| (at * 37 + 11) as u8).collect(),
                (0..LTE).map(|at| (at * 53 + 7) as u8).collect(),
            ),
            Fill::Ones => (vec![0xff; MEMORY], vec![0xff; LTE]),
            Fill::Zeros => (vec![0; MEMORY], vec![0; LTE]),
        };
        let mut model = Self {
            memory,
            lte,
            log: Vec::new(),
            lte_stuck: false,
            cmac_dead: false,
        };
        let cmac = model.get(CMAC_FUNC_EN, 4);
        model.set(CMAC_FUNC_EN, 4, cmac | CMAC_EN);
        model
    }
    fn get(&self, register: u32, width: u32) -> u32 {
        get(&self.memory, register, width)
    }
    fn set(&mut self, register: u32, width: u32, value: u32) {
        set(&mut self.memory, register, width, value);
    }
    fn lte_word(&self, offset: u32) -> u32 {
        get(&self.lte, offset, 4)
    }
    fn view(&self, word: u32) -> u32 {
        let value = self.get(word, 4);
        match word {
            LTE_CTRL if self.lte_stuck => value & !LTE_READY,
            LTE_CTRL => value | LTE_READY,
            CMAC_FUNC_EN if self.cmac_dead => R32_DEAD,
            word if word == CR_BASE + SWSI_V1 => value & !SWSI_BUSY,
            _ => value,
        }
    }
    fn check(register: u32, width: u32) {
        assert!(
            register as usize + width as usize <= MEMORY,
            "{register:#x}"
        );
        assert!(register.is_multiple_of(width), "{register:#x}/{width}");
    }
    fn read(&mut self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        let mut value = self.view(register & !3) >> ((register & 3) * 8);
        if width < 4 {
            value &= (1 << (8 * width)) - 1;
        }
        self.log.push(Access::Read {
            width,
            register,
            value,
        });
        value
    }
    fn write(&mut self, register: u32, width: u32, value: u32) {
        Self::check(register, width);
        self.log.push(Access::Write {
            width,
            register,
            value,
        });
        self.set(register, width, value);
        if register == LTE_CTRL && width == 4 {
            let offset = value & 0xffff;
            assert!((offset as usize) + 4 <= LTE && offset.is_multiple_of(4));
            match value & 0xffff_0000 {
                LTE_CTRL_WRITE => {
                    let data = self.get(LTE_WDATA, 4);
                    set(&mut self.lte, offset, 4, data);
                }
                LTE_CTRL_READ => {
                    let data = self.lte_word(offset);
                    self.set(LTE_RDATA, 4, data);
                }
                command => panic!("LTE command {command:#x}"),
            }
        }
    }
    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push(Access::Mark { tag, a, b });
    }
    /// The values written to `register`, `width` bytes wide, in order.
    fn writes(&self, register: u32, width: u32) -> Vec<u32> {
        self.log
            .iter()
            .filter_map(|access| match *access {
                Access::Write {
                    width: w,
                    register: at,
                    value,
                } if at == register && w == width => Some(value),
                _ => None,
            })
            .collect()
    }
}

fn get(bytes: &[u8], register: u32, width: u32) -> u32 {
    let at = register as usize;
    let mut word = [0; 4];
    word[..width as usize].copy_from_slice(&bytes[at..at + width as usize]);
    u32::from_le_bytes(word)
}

fn set(bytes: &mut [u8], register: u32, width: u32, value: u32) {
    let at = register as usize;
    bytes[at..at + width as usize].copy_from_slice(&value.to_le_bytes()[..width as usize]);
}

// SAFETY: a register file of this test alone; it reaches no hardware.
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
        self.log.push(Access::Delay(microseconds));
    }
}

/// The C oracle's `rtw89_h2c_tx` stand-in: the H2C `rtw89_h2c_pkt_set_hdr`
/// built, recorded with its length and the sequence after it (tag 40) and
/// as little-endian words (tag 41), then taken, or refused with `-ENOSPC`.
struct Recorder {
    sequence: Sequence,
    refuse: bool,
    sent: u32,
    failed: u32,
    /// Every H2C: its header and payload.
    commands: Vec<(Header, Vec<u8>)>,
}

impl Recorder {
    fn new(sequence: u8, refuse: bool) -> Self {
        Self {
            sequence: Sequence(sequence),
            refuse,
            sent: 0,
            failed: 0,
            commands: Vec::new(),
        }
    }
}

impl Commands<Model> for Recorder {
    fn send(
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
        self.commands.push((header, payload.to_vec()));
        if self.refuse {
            self.failed += 1;
            Err(h2c::Error::NoResource)
        } else {
            self.sent += 1;
            Ok(())
        }
    }
}

/// The user's card: RFE 1, cut B.
const RFE: u8 = 1;
const CUT_B: u8 = 1;
/// WL's scoreboard after the init: active, on, BT log.
const SCBD: u32 = BTC_WSCB_ACTIVE | BTC_WSCB_ON | BTC_WSCB_BTLOG;

fn run(io: &mut Model, recorder: &mut Recorder, rfe: u8, cv: u8) -> Init {
    init_wl_only(io, recorder, rfe, cv).unwrap()
}

#[test]
fn rfe_types_pick_shared_or_dedicated_antennas() {
    for (rfe, num, kind, bt0_pos) in [
        (0, 2, BTC_ANT_SHARED, BTC_BT_BTG),
        (1, 2, BTC_ANT_SHARED, BTC_BT_BTG),
        (2, 3, BTC_ANT_DEDICATED, BTC_BT_ALONE),
        (3, 2, BTC_ANT_SHARED, BTC_BT_BTG),
        (4, 3, BTC_ANT_DEDICATED, BTC_BT_ALONE),
    ] {
        let module = set_rfe(rfe, 2);
        assert_eq!(
            module,
            Module {
                ant: Ant {
                    kind,
                    num,
                    isolation: DEFAULT_ANISO,
                    ..Ant::default()
                },
                rfe_type: rfe,
                kt_ver: 2,
                bt0_pos,
                ..Module::default()
            },
            "rfe {rfe}"
        );
    }
}

#[test]
fn wl_only_init_grants_wlan_the_antennas_and_the_pta() {
    let mut io = Model::new(Fill::Zeros);
    let mut recorder = Recorder::new(0, false);
    let init = run(&mut io, &mut recorder, RFE, CUT_B);
    // The init ends with the wait rtw89 gives BT's firmware.
    assert_eq!(io.log.last(), Some(&Access::Delay(1000)));
    assert_eq!(init.coex_init, Ok(()));
    assert_eq!(init.gnt, Ok(()));
    assert_eq!(init.plt, Ok(()));
    assert!(!init.pta_owner);
    assert_eq!((init.h2c_failed, init.h2c_error), (0, None));
    // Both paths: WL granted and BT refused by software, read back through
    // the LTE access.
    let gnt = 0x7700_7700;
    assert_eq!(gnt_value(&[GNT_WL_ONLY; 2]), gnt);
    assert_eq!(io.lte_word(LTE_SW_CFG_1), gnt);
    assert_eq!(read_gnt(&mut io), Ok(gnt));
    // WLAN owns the PTA, and band 0's polluter table follows WL's grant.
    assert_eq!(
        io.get(SYS_SDIO_CTRL, 4) & LTE_MUX_CTRL_PATH,
        LTE_MUX_CTRL_PATH
    );
    assert_eq!(io.writes(BT_PLT, 2), [0x111]);
    // The scoreboard: toggle, the firmware's TP major notice, WL's bits.
    assert_eq!(init.coex.scbd, SCBD);
    assert_eq!(io.writes(SCOREBOARD, 4), [0x8100_4003]);
    // The PTA in RTK mode, its sample rate and inner direction.
    assert_eq!(io.get(GPIO_MUXCFG, 2), 0x0220);
    assert_eq!(io.get(TDMA_MODE, 1), 1);
    assert_eq!(io.get(BT_COEX_CFG_5, 1), 5);
    assert_eq!(io.get(BTC_BREAK_TABLE, 4), BTC_BREAK_PARAM);
    assert_eq!(io.get(CSR_MODE, 4), 0x0001_000c);
    // TDMA off, bound to hardware band 0; the OFF slot's table changed.
    assert_eq!(init.coex.tdma_now.bind, TDMA_BIND_HWB0);
    assert_eq!(init.coex.slots_now[CXST_OFF].cxtbl, CXTBL_OFF_BT);
}

#[test]
fn h2cs_carry_the_bytes_rtw89_sends() {
    let mut io = Model::new(Fill::Zeros);
    let mut recorder = Recorder::new(0, false);
    let init = run(&mut io, &mut recorder, RFE, CUT_B);
    let commands = &recorder.commands;
    let funcs: Vec<(u8, bool, bool)> = commands
        .iter()
        .map(|(header, _)| (header.function().func, header.rec_ack(), header.done_ack()))
        .collect();
    // REC_ACK on every fourth sequence number, as rtw89 asks on an AX chip.
    assert_eq!(
        funcs,
        [
            (SET_DRV_INFO, true, false),
            (SET_DRV_INFO, false, false),
            (SET_SLOT_TABLE, false, true),
            (SET_MREG_TABLE, false, true),
            (SET_MREG_TABLE, true, true),
            (SET_SLOT_TABLE, false, true),
            (SET_DRV_INFO, false, false),
            (SET_DRV_INFO, false, false),
            (SET_CX_POLICY, true, true),
        ]
    );
    for (header, _) in commands {
        let function = header.function();
        assert_eq!((function.cat, function.class), (H2C_CAT_OUTSRC, BTFC_SET));
    }
    let cxinit = [0, 12, 0, 2, 10, 0, 1, 1, 0x02, 0, 6, 0x03, 0, 0];
    assert_eq!(commands[0].1, cxinit);
    assert_eq!(commands[6].1, cxinit);
    assert_eq!(commands[1].1, [6, 4, 0, 0, 0, 0]);
    assert_eq!(commands[7].1, [6, 4, 0, 0, 0, 0]);
    let slots = &commands[2].1;
    assert_eq!(slots.len(), 2 + 8 * CXST_MAX);
    assert_eq!(slots[..10], [1, 18, 100, 0, 0x55, 0x55, 0x55, 0x55, 0, 0]);
    assert_eq!(commands[5].1, *slots);
    let monreg = &commands[3].1;
    assert_eq!(monreg.len(), 2 + 8 * 16);
    assert_eq!(monreg[..10], [2, 16, 0, 0, 4, 0, 0x24, 0xda, 0, 0]);
    assert_eq!(monreg[monreg.len() - 8..], [1, 0, 4, 0, 0x94, 0x46, 0, 0]);
    assert_eq!(commands[4].1, *monreg);
    // The TDMA, version 3: off, bound to hardware band 0; then the OFF
    // slot, version 1: 100 ms, cxtbl[2], mixed.
    let tdma = [CXPOLICY_TDMA, 12, 3, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let slot = [CXPOLICY_SLOT, 10, 1, 0];
    let off = [100, 0, 0x55, 0x55, 0x55, 0xe5, 0, 0];
    assert_eq!(commands[8].1, [&tdma[..], &slot, &off].concat());
    assert_eq!(recorder.sequence, Sequence(9));
    assert_eq!(init.coex.tdma_now, init.coex.tdma);
    assert_eq!(init.coex.slots_now, init.coex.slots);
    // H2C payloads stay within what a header's 14-bit length carries.
    assert!(
        commands
            .iter()
            .all(|(_, payload)| payload.len() + HEADER_LEN < 1 << 14)
    );
}

#[test]
fn the_pta_init_comes_first_as_rtw89_orders_it() {
    let mut io = Model::new(Fill::Zeros);
    let mut recorder = Recorder::new(0, false);
    run(&mut io, &mut recorder, RFE, CUT_B);
    let read = |width, register, value| Access::Read {
        width,
        register,
        value,
    };
    let write = |width, register, value| Access::Write {
        width,
        register,
        value,
    };
    assert_eq!(
        io.log[..28],
        [
            read(1, GPIO_MUXCFG, 0),
            write(1, GPIO_MUXCFG, 0x20),
            read(1, BTC_FUNC_EN, 0),
            write(1, BTC_FUNC_EN, 0x02),
            read(1, BT_COEX_CFG_2 + 1, 0),
            write(1, BT_COEX_CFG_2 + 1, 0x01),
            read(1, CSR_MODE, 0),
            write(1, CSR_MODE, 0x0c),
            read(1, CSR_MODE + 2, 0),
            write(1, CSR_MODE + 2, 0x01),
            read(1, TRXPTCL_RESP_0 + 3, 0),
            write(1, TRXPTCL_RESP_0 + 3, 0),
            read(2, CCA_CFG_0, 0),
            write(2, CCA_CFG_0, 0x20),
            read(1, LTE_CTRL + 3, 0x20),
            write(4, LTE_CTRL, 0x800f_003c),
            read(4, LTE_RDATA, 0),
            read(1, LTE_CTRL + 3, 0xa0),
            write(4, LTE_WDATA, 0),
            write(4, LTE_CTRL, 0xc00f_003c),
            read(1, GPIO_MUXCFG, 0x20),
            write(1, GPIO_MUXCFG, 0x20),
            read(1, TDMA_MODE, 0),
            write(1, TDMA_MODE, 1),
            read(1, BT_COEX_CFG_5, 0),
            write(1, BT_COEX_CFG_5, 5),
            read(1, GPIO_MUXCFG + 1, 0),
            write(1, GPIO_MUXCFG + 1, 0x02),
        ]
    );
}

#[test]
fn a_dedicated_antenna_takes_its_own_trx_masks() {
    let masks = |rfe| {
        let mut io = Model::new(Fill::Zeros);
        let mut recorder = Recorder::new(0, false);
        run(&mut io, &mut recorder, rfe, CUT_B);
        io.writes(CR_BASE + SWSI_DATA_V1, 4)
            .into_iter()
            .filter(|value| field(*value, SWSI_DATA_ADDR_V1) == RR_LUTWD0)
            .map(|value| {
                (
                    field(value, SWSI_DATA_PATH_V1),
                    field(value, SWSI_DATA_VAL_V1),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(masks(1), [(0, 0x5ff), (1, 0x5ff), (0, 0x5ff), (1, 0x55f)]);
    assert_eq!(masks(2), [(0, 0x5df), (1, 0x5df), (0, 0x5ff), (1, 0x5ff)]);
}

#[test]
fn an_lte_that_never_readies_stops_the_pta_init_but_not_the_grants() {
    let mut io = Model::new(Fill::Zeros);
    io.lte_stuck = true;
    let mut recorder = Recorder::new(0, false);
    let init = run(&mut io, &mut recorder, RFE, CUT_B);
    assert_eq!(init.coex_init, Err(lte_timeout()));
    assert_eq!(init.gnt, Err(lte_timeout()));
    // The read polled 1001 times, every 50 us, then rtw89 stopped before
    // writing LTE_SW_CFG_2 back or the RTK mode.
    assert_eq!(io.writes(LTE_CTRL, 4), [0x800f_003c, 0xc00f_0038]);
    assert_eq!(io.writes(GPIO_MUXCFG, 1), [0x20]);
    assert!(io.writes(TDMA_MODE, 1).is_empty());
    // The grants were written anyway, as were the rest.
    assert_eq!(io.lte_word(LTE_SW_CFG_1), 0x7700_7700);
    assert_eq!(read_gnt(&mut io), Err(lte_timeout()));
    assert_eq!(io.writes(SCOREBOARD, 4), [0x8100_4003]);
}

#[test]
fn cmac_off_skips_the_polluter_table_alone() {
    let mut io = Model::new(Fill::Zeros);
    io.cmac_dead = true;
    let mut recorder = Recorder::new(0, false);
    let init = run(&mut io, &mut recorder, RFE, CUT_B);
    assert_eq!(init.plt, Err(R32_DEAD));
    assert!(io.writes(BT_PLT, 2).is_empty());
    assert_eq!(recorder.sent, 9);
    assert_eq!(io.writes(SCOREBOARD, 4), [0x8100_4003]);
}

#[test]
fn refused_h2cs_are_counted_and_the_policy_still_counts_as_taken() {
    let mut io = Model::new(Fill::Zeros);
    let mut recorder = Recorder::new(0xfe, true);
    let init = run(&mut io, &mut recorder, RFE, CUT_B);
    assert_eq!(init.h2c_failed, 9);
    assert_eq!(init.h2c_error, Some(h2c::Error::NoResource));
    assert_eq!(init.coex.tdma_now, init.coex.tdma);
    assert_eq!(recorder.sequence, Sequence(7));
    assert_eq!(io.lte_word(LTE_SW_CFG_1), 0x7700_7700);
}

#[test]
fn bt_owning_the_pta_is_warned_about_and_taken_back() {
    let mut io = Model::new(Fill::Zeros);
    io.set(SYS_SDIO_CTRL, 4, LTE_MUX_CTRL_PATH);
    let mut recorder = Recorder::new(0, false);
    let init = run(&mut io, &mut recorder, RFE, CUT_B);
    assert!(init.pta_owner);
}

/// One oracle case: the fill, RFE type, cut, faults, and the first H2C's
/// sequence number.
#[derive(Clone, Copy, Debug)]
struct Case {
    fill: Fill,
    rfe: u8,
    cv: u8,
    lte_stuck: bool,
    cmac_dead: bool,
    refuse: bool,
    sequence: u8,
}

const fn case(fill: Fill, rfe: u8, cv: u8) -> Case {
    Case {
        fill,
        rfe,
        cv,
        lte_stuck: false,
        cmac_dead: false,
        refuse: false,
        sequence: 0,
    }
}

/// The oracle's cases, in its order.
fn oracle_cases() -> [Case; 7] {
    [
        case(Fill::Zeros, 1, 1),
        case(Fill::Pattern, 1, 1),
        case(Fill::Ones, 2, 2),
        case(Fill::Zeros, 0, 0),
        Case {
            lte_stuck: true,
            ..case(Fill::Zeros, 1, 1)
        },
        Case {
            cmac_dead: true,
            ..case(Fill::Zeros, 1, 1)
        },
        Case {
            refuse: true,
            sequence: 0xfe,
            ..case(Fill::Pattern, 1, 1)
        },
    ]
}

/// One case as the Rust side runs it: the trace segment it gives.
fn replay(case: &Case) -> Vec<u8> {
    let mut io = Model::new(case.fill);
    io.lte_stuck = case.lte_stuck;
    io.cmac_dead = case.cmac_dead;
    let mut recorder = Recorder::new(case.sequence, case.refuse);
    let init = run(&mut io, &mut recorder, case.rfe, case.cv);
    let mut trace = encode(&io.log);
    let module = &init.coex.module;
    let ant = &module.ant;
    push(
        &mut trace,
        50,
        u32::from(module.rfe_type)
            | u32::from(module.kt_ver) << 8
            | u32::from(module.bt_solo) << 16
            | u32::from(module.bt0_pos) << 24,
        u32::from(module.bt0_sw_type)
            | u32::from(module.wa_type) << 8
            | u32::from(module.kt_ver_adie) << 16,
    );
    push(
        &mut trace,
        51,
        u32::from(ant.kind)
            | u32::from(ant.num) << 8
            | u32::from(ant.isolation) << 16
            | u32::from(ant.diversity) << 24,
        u32::from(ant.single_pos) | u32::from(ant.btg_pos) << 8 | u32::from(ant.stream_cnt) << 16,
    );
    push(&mut trace, 52, init.pta_owner.into(), init.coex.scbd);
    push(&mut trace, 53, ant.kind.into(), ant.btg_pos.into());
    push(
        &mut trace,
        54,
        io.lte_word(LTE_SW_CFG_1),
        io.lte_word(LTE_SW_CFG_2),
    );
    push(&mut trace, 55, recorder.sent, recorder.failed);
    push(&mut trace, 24, recorder.sequence.0.into(), 0);
    assert_eq!(init.h2c_failed, recorder.failed);
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
#[ignore = "oracle: STELA_RTW89_COEX_ORACLE"]
fn coex_init_and_grant_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_COEX_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;
    for case in oracle_cases() {
        let expected = segment(&trace, &mut offset);
        let actual = replay(&case);
        if expected != actual {
            let records = |bytes: &[u8]| -> Vec<[u32; 3]> {
                bytes
                    .chunks(12)
                    .map(|record| {
                        let word =
                            |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().unwrap());
                        [word(0), word(4), word(8)]
                    })
                    .collect()
            };
            let (expected, actual) = (records(expected), records(&actual));
            let first = expected
                .iter()
                .zip(&actual)
                .position(|(e, a)| e != a)
                .unwrap_or(expected.len().min(actual.len()));
            panic!(
                "{case:?}: record {first} of {}/{}: C {:x?}, Rust {:x?}",
                expected.len(),
                actual.len(),
                expected.get(first),
                actual.get(first)
            );
        }
    }
    assert_eq!(offset, trace.len());
}
