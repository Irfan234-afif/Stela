extern crate std;

use super::*;
use crate::wifi::realtek::ax::io::{RF_BASE, field};
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
    /// A record the harness makes itself: a seam's marker.
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

const MEMORY: usize = 0x2_0000;

/// What byte `at` of BAR2 holds before the first access.
fn pattern_byte(at: usize) -> u8 {
    (at * 37 + 11) as u8
}
/// What RF word `address` of `path` holds before the first access.
fn rf_pattern(path: u32, address: u32) -> u32 {
    (address * 0x9e3 + path * 0x4f1b + 0x1a2b3) & RFREG_MASK
}

/// How the model's chip misbehaves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Faults {
    /// S0's RR_SYNFB reads its lock bit clear.
    unlocked: bool,
    /// S0's RR_LPF reads its busy bit set.
    lpf_stuck: bool,
    /// CMAC_FUNC_EN lacks CMAC_EN.
    cmac_off: bool,
    /// R_CHBW_MOD_V1's B_ANT_RX_SEG0, when not as the pattern has it.
    rx_path: Option<u32>,
    /// A register whose every access the interface refuses.
    refuse: Option<u32>,
}

/// The C oracle's register model: BAR2 as bytes, byte i holding
/// `i * 37 + 11` and CMAC_FUNC_EN holding CMAC_EN; the RF registers SWSI
/// reaches as two files of 256 words. A write to R_SWSI_READ_ADDR_V1
/// latches the request; R_SWSI_V1 reads B_SWSI_R_DATA_DONE_V1 with the
/// requested word, never busy; a write to R_SWSI_DATA_V1 writes the word,
/// under R_SWSI_BIT_MASK_V1 when its mask bit is set. S0's RR_LPF reads its
/// busy bit clear and RR_SYNFB its lock bit set, unless the faults say
/// otherwise. The direct RF window is plain memory.
struct Model {
    memory: Vec<u8>,
    rf: [[u32; 256]; 2],
    request: u32,
    faults: Faults,
    log: Vec<Access>,
}

impl Model {
    fn new(faults: Faults) -> Self {
        let mut model = Self {
            memory: (0..MEMORY).map(pattern_byte).collect(),
            rf: [[0; 256]; 2],
            request: 0,
            faults,
            log: Vec::new(),
        };
        for path in 0..2 {
            for address in 0..256 {
                model.rf[path][address] = rf_pattern(path as u32, address as u32);
            }
        }
        let cmac = model.get(CMAC_FUNC_EN, 4);
        let cmac = if faults.cmac_off {
            cmac & !CMAC_EN
        } else {
            cmac | CMAC_EN
        };
        model.set(CMAC_FUNC_EN, 4, cmac);
        if let Some(rx_path) = faults.rx_path {
            let at = CR_BASE + R_CHBW_MOD_V1;
            let value = (model.get(at, 4) & !B_ANT_RX_SEG0) | rx_path;
            model.set(at, 4, value);
        }
        model
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
    fn check(&self, register: u32, width: u32) -> Result<(), io::Error> {
        assert!(register as usize + width as usize <= MEMORY && register.is_multiple_of(width));
        if self.faults.refuse == Some(register) {
            return Err(io::Error::Register { register });
        }
        Ok(())
    }
    fn rf_value(&self, path: u32, address: u32) -> u32 {
        let mut value = self.rf[path as usize][address as usize];
        if path == 0 && address == RR_LPF {
            value = if self.faults.lpf_stuck {
                value | RR_LPF_BUSY
            } else {
                value & !RR_LPF_BUSY
            };
        }
        if path == 0 && address == RR_SYNFB {
            value = if self.faults.unlocked {
                value & !RR_SYNFB_LK
            } else {
                value | RR_SYNFB_LK
            };
        }
        value
    }
    fn read(&mut self, register: u32, width: u32) -> Result<u32, io::Error> {
        self.check(register, width)?;
        let value = if register == CR_BASE + SWSI_V1 {
            let path = field(self.request, SWSI_READ_ADDR_PATH_V1);
            assert!(width == 4 && path < 2);
            SWSI_R_DATA_DONE_V1 | self.rf_value(path, field(self.request, SWSI_READ_ADDR_ADDR_V1))
        } else {
            self.get(register, width)
        };
        self.log.push(Access::Read {
            width,
            register,
            value,
        });
        Ok(value)
    }
    fn write(&mut self, register: u32, width: u32, value: u32) -> Result<(), io::Error> {
        self.check(register, width)?;
        self.log.push(Access::Write {
            width,
            register,
            value,
        });
        self.set(register, width, value);
        if register == CR_BASE + SWSI_READ_ADDR_V1 {
            assert_eq!(width, 4);
            self.request = value;
        }
        if register == CR_BASE + SWSI_DATA_V1 {
            let path = field(value, SWSI_DATA_PATH_V1) as usize;
            let address = field(value, SWSI_DATA_ADDR_V1) as usize;
            let data = field(value, SWSI_DATA_VAL_V1);
            assert!(width == 4 && path < 2);
            let mask = if value & SWSI_DATA_BIT_MASK_EN_V1 != 0 {
                self.get(CR_BASE + SWSI_BIT_MASK_V1, 4) & RFREG_MASK
            } else {
                RFREG_MASK
            };
            let word = &mut self.rf[path][address];
            *word = (*word & !mask) | (data & mask);
        }
        Ok(())
    }
    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push(Access::Mark { tag, a, b });
    }
    /// The direct window's word for RF `address` of `path`.
    fn direct(&self, path: usize, address: u32) -> u32 {
        self.get(CR_BASE + RF_BASE[path] + ((address & 0xff) << 2), 4)
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.read(register, 1)? as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.read(register, 2)? as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        self.read(register, 4)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.write(register, 1, value.into())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.write(register, 2, value.into())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.write(register, 4, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.log.push(Access::Delay(microseconds));
    }
}

/// The oracle's input kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// A programmed card after its BB table loads.
    Card,
    /// rtw89's state before efuse and tables: every input zero.
    Blank,
    /// The card's, with `antenna_rx` [`RF_B`] and a monitor interface up.
    RfBMonitor,
}

fn pattern(a: usize, b: usize, c: usize, k: usize) -> i8 {
    (((a * 31 + b * 17 + c * 7 + k * 3) % 41) as i32 - 20) as i8
}

fn inputs(kind: Kind) -> Inputs {
    let mut inputs = Inputs::default();
    if kind == Kind::Blank {
        return inputs;
    }
    let gain = &mut inputs.bb_gain;
    for band in 0..BB_GAIN_BAND_2G_5G {
        for path in 0..BB_PATH_NUM {
            for i in 0..LNA_GAIN_NUM {
                gain.lna_gain[band][path][i] = pattern(band, path, i, 1);
            }
            for i in 0..TIA_GAIN_NUM {
                gain.tia_gain[band][path][i] = pattern(band, path, i, 2);
            }
            gain.rpl_ofst_20[band][path] = pattern(band, path, 0, 3);
            for i in 0..BB_RXSC_NUM_40 {
                gain.rpl_ofst_40[band][path][i] = pattern(band, path, i, 4);
            }
            for i in 0..BB_RXSC_NUM_80 {
                gain.rpl_ofst_80[band][path][i] = pattern(band, path, i, 5);
            }
        }
    }
    let efuse = &mut inputs.efuse_gain;
    efuse.offset_valid = true;
    efuse.comp_valid = true;
    for path in 0..2 {
        for i in 0..5 {
            efuse.offset[path][i] = ((path * 5 + i * 3) % 15) as i8 - 7;
            efuse.comp[path][i] = ((path * 3 + i * 5) % 15) as i8 - 7;
        }
    }
    inputs.offset_base = -37;
    inputs.rssi_base = 21;
    if kind == Kind::RfBMonitor {
        inputs.antenna_rx = RF_B;
        inputs.monitor = true;
    }
    inputs
}

fn width(mhz: u32) -> Width {
    match mhz {
        20 => Width::Mhz20,
        40 => Width::Mhz40,
        80 => Width::Mhz80,
        _ => unreachable!(),
    }
}

fn channel(center: u8, primary: u8, mhz: u32) -> Channel {
    Channel::new(center, primary, width(mhz)).unwrap()
}

/// One of the oracle's cases: its inputs, its faults, and the channels it
/// switches to in order.
#[derive(Clone, Debug)]
struct Case {
    kind: Kind,
    faults: Faults,
    steps: Vec<(u8, u8, u32)>,
}

/// The oracle script's `CASES`, in its order.
fn oracle_cases() -> Vec<Case> {
    const SINGLE: [(u8, u8, u32); 25] = [
        (1, 1, 20),
        (3, 1, 40),
        (6, 6, 20),
        (8, 6, 40),
        (4, 6, 40),
        (13, 13, 20),
        (11, 13, 40),
        (14, 14, 20),
        (36, 36, 20),
        (38, 36, 40),
        (42, 36, 80),
        (42, 40, 80),
        (42, 44, 80),
        (100, 100, 20),
        (102, 100, 40),
        (106, 100, 80),
        (149, 149, 20),
        (151, 149, 40),
        (155, 149, 80),
        (165, 165, 20),
        (167, 165, 40),
        (171, 165, 80),
        (177, 177, 20),
        (175, 177, 40),
        (171, 177, 80),
    ];
    let case = |kind, faults, steps: &[(u8, u8, u32)]| Case {
        kind,
        faults,
        steps: steps.to_vec(),
    };
    let none = Faults::default();
    let mut cases: Vec<Case> = SINGLE
        .iter()
        .map(|&step| case(Kind::Card, none, &[step]))
        .collect();
    cases.extend([
        case(Kind::Blank, none, &[(1, 1, 20)]),
        case(Kind::Blank, none, &[(42, 36, 80)]),
        case(Kind::RfBMonitor, none, &[(6, 6, 20)]),
        case(Kind::RfBMonitor, none, &[(155, 149, 80)]),
        case(
            Kind::Card,
            Faults {
                unlocked: true,
                ..none
            },
            &[(36, 36, 20)],
        ),
        case(
            Kind::Card,
            Faults {
                lpf_stuck: true,
                ..none
            },
            &[(1, 1, 20)],
        ),
        case(
            Kind::Card,
            Faults {
                rx_path: Some(1),
                ..none
            },
            &[(38, 36, 40)],
        ),
        case(
            Kind::Card,
            Faults {
                rx_path: Some(2),
                ..none
            },
            &[(3, 1, 40)],
        ),
        case(
            Kind::Card,
            Faults {
                cmac_off: true,
                ..none
            },
            &[(6, 6, 20)],
        ),
        case(Kind::Card, none, &[(1, 1, 20), (6, 6, 20)]),
        case(Kind::Card, none, &[(1, 1, 20), (42, 36, 80), (42, 36, 80)]),
    ]);
    cases
}

/// `enum rtw89_band`'s value.
fn band_value(band: Band) -> u32 {
    match band {
        Band::Ghz2 => 0,
        Band::Ghz5 => 1,
    }
}

/// One case as the Rust side runs it: the trace segment it gives, with the
/// seams' markers where the C harness's stubs make them.
fn replay(case: &Case) -> (Model, Vec<Switched>) {
    let mut io = Model::new(case.faults);
    let inputs = inputs(case.kind);
    let mut previous = None;
    let mut switched = Vec::new();
    for &(center, primary, mhz) in &case.steps {
        let chan = channel(center, primary, mhz);
        let result = switch(&mut io, None, &chan, &inputs, previous, |io, chan| {
            io.mark(12, chan.center().into(), chan.primary().into());
            Ok(())
        })
        .unwrap();
        if result.band_notice {
            io.mark(13, 0, band_value(chan.band()));
            io.mark(14, 0, band_value(chan.band()));
        }
        previous = Some(chan.band());
        switched.push(result);
    }
    (io, switched)
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
#[ignore = "oracle: STELA_RTW89_CHANNEL_ORACLE"]
fn channel_switch_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_CHANNEL_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;
    let cases = oracle_cases();
    assert_eq!(cases.len(), 36);
    for case in cases {
        let expected = segment(&trace, &mut offset);
        let (io, _) = replay(&case);
        let actual = encode(&io.log);
        if actual != expected {
            let first = actual
                .chunks(12)
                .zip(expected.chunks(12))
                .position(|(a, b)| a != b)
                .unwrap_or(actual.len().min(expected.len()) / 12);
            panic!(
                "{case:?}: record {first} of {} (C {}) differs: Rust {:?}, C {:?}",
                actual.len() / 12,
                expected.len() / 12,
                actual.chunks(12).nth(first),
                expected.chunks(12).nth(first),
            );
        }
    }
    assert_eq!(offset, trace.len());
}

#[test]
fn channels_follow_rtw89_chan_create_and_the_channel_plan() {
    // (center, primary, width): subband, pri_ch_idx, freq, txsc20, txsc40,
    // chan_idx.
    let derived = [
        ((1, 1, 20), (CH_2G, SC_DONT_CARE, 2412, 0, 0, 0x01)),
        ((3, 1, 40), (CH_2G, SC_20_LOWER, 2422, 2, 0, 0x01)),
        ((11, 13, 40), (CH_2G, SC_20_UPPER, 2462, 1, 0, 0x0d)),
        ((14, 14, 20), (CH_2G, SC_DONT_CARE, 2484, 0, 0, 0x0e)),
        (
            (42, 36, 80),
            (CH_5G_BAND_1, SC_20_LOWEST, 5210, 4, 10, 0x20),
        ),
        ((42, 40, 80), (CH_5G_BAND_1, SC_20_LOWER, 5210, 2, 10, 0x22)),
        ((42, 44, 80), (CH_5G_BAND_1, SC_20_UPPER, 5210, 1, 9, 0x24)),
        (
            (106, 100, 80),
            (CH_5G_BAND_3, SC_20_LOWEST, 5530, 4, 10, 0x30),
        ),
        (
            (138, 144, 80),
            (CH_5G_BAND_3, SC_20_UPMOST, 5690, 3, 9, 0x46),
        ),
        (
            (151, 149, 40),
            (CH_5G_BAND_4, SC_20_LOWER, 5755, 2, 0, 0x50),
        ),
        (
            (171, 177, 80),
            (CH_5G_BAND_4, SC_20_UPMOST, 5855, 3, 9, 0x5e),
        ),
        (
            (165, 165, 20),
            (CH_5G_BAND_4, SC_DONT_CARE, 5825, 0, 0, 0x58),
        ),
    ];
    for ((center, primary, mhz), (subband, pri, freq, txsc20, txsc40, idx)) in derived {
        let chan = channel(center, primary, mhz);
        assert_eq!(chan.subband(), subband, "{chan:?}");
        assert_eq!(chan.pri_ch_idx(), pri, "{chan:?}");
        assert_eq!(chan.freq(), freq, "{chan:?}");
        assert_eq!(chan.txsc(Width::Mhz20), txsc20, "{chan:?}");
        assert_eq!(chan.txsc(Width::Mhz40), txsc40, "{chan:?}");
        assert_eq!(chan.chan_idx(), idx, "{chan:?}");
    }
    assert_eq!(channel(8, 6, 40).band(), Band::Ghz2);
    assert_eq!(channel(175, 177, 40).band(), Band::Ghz5);

    let refused = [
        // No 80 MHz at 2.4 GHz, no 40 MHz on channel 14, none past 13.
        (6, 6, 80),
        (7, 6, 80),
        (12, 14, 40),
        (14, 14, 40),
        (15, 13, 40),
        (1, 1, 40),
        (2, 1, 40),
        // Centers off the plan, primaries outside the channel.
        (37, 37, 20),
        (40, 36, 40),
        (38, 40, 20),
        (46, 40, 40),
        (50, 48, 80),
        (42, 52, 80),
        (42, 38, 80),
        (171, 181, 80),
        (181, 181, 20),
        (0, 0, 20),
        (144, 144, 80),
        // 6 GHz's and other bands' numbers.
        (15, 15, 20),
        (32, 32, 20),
        (68, 68, 20),
        (96, 96, 20),
        (184, 184, 20),
    ];
    for (center, primary, mhz) in refused {
        assert_eq!(
            Channel::new(center, primary, width(mhz)),
            Err(Invalid {
                center,
                primary,
                width: width(mhz),
            }),
        );
    }
}

/// A shadow of the model's memory that builds an expected access list.
struct Shadow {
    memory: Vec<u8>,
    log: Vec<Access>,
}

impl Shadow {
    fn new() -> Self {
        let model = Model::new(Faults::default());
        Self {
            memory: model.memory,
            log: Vec::new(),
        }
    }
    fn get(&self, register: u32, width: u32) -> u32 {
        (0..width).fold(0, |value, i| {
            value | u32::from(self.memory[(register + i) as usize]) << (8 * i)
        })
    }
    fn r(&mut self, width: u32, register: u32) -> u32 {
        let value = self.get(register, width);
        self.log.push(Access::Read {
            width,
            register,
            value,
        });
        value
    }
    fn w(&mut self, width: u32, register: u32, value: u32) {
        for i in 0..width {
            self.memory[(register + i) as usize] = (value >> (8 * i)) as u8;
        }
        self.log.push(Access::Write {
            width,
            register,
            value,
        });
    }
    fn rmw(&mut self, width: u32, register: u32, clear: u32, set: u32) {
        let value = self.r(width, register);
        self.w(width, register, (value & !clear) | set);
    }
    fn bb(&mut self, register: u32, mask: u32, data: u32) {
        self.rmw(4, CR_BASE + register, mask, prep(data, mask));
    }
}

#[test]
fn set_channel_mac_writes_the_rf_mode_subcarriers_and_band_checks() {
    for (center, primary, mhz, rfmod, sub_carrier) in [
        (42, 36, 80, 2, 4 | 10 << 4),
        (42, 44, 80, 2, 1 | 9 << 4),
        (3, 1, 40, 1, 2),
        (167, 169, 40, 1, 1),
        (6, 6, 20, 0, 0),
        (149, 149, 20, 0, 0),
    ] {
        let chan = channel(center, primary, mhz);
        let mut io = Model::new(Faults::default());
        set_channel_mac(&mut io, &chan).unwrap();
        let mut expected = Shadow::new();
        expected.rmw(1, WMAC_RFMOD, WMAC_RFMOD_MASK, rfmod);
        expected.w(4, TX_SUB_CARRIER_VALUE, sub_carrier);
        let checks = CHECK_CCK_EN | RTS_LIMIT_IN_OFDM6;
        if center > 14 {
            expected.rmw(1, TXRATE_CHK, BAND_MODE, 0);
            expected.rmw(1, TXRATE_CHK, 0, checks);
        } else {
            expected.rmw(1, TXRATE_CHK, 0, BAND_MODE);
            expected.rmw(1, TXRATE_CHK, checks, 0);
        }
        assert_eq!(io.log, expected.log, "{chan:?}");
    }
}

#[test]
fn the_help_stops_tx_holds_the_bb_and_puts_both_back() {
    for chan in [channel(1, 1, 20), channel(42, 36, 80)] {
        let mut io = Model::new(Faults::default());
        let help = enter(&mut io, None, &chan).unwrap();
        let done = done(&mut io, None, &chan, &help).unwrap();
        assert_eq!(done, Done::default());

        let mut expected = Shadow::new();
        let tx_en = expected.r(2, CTN_TXEN);
        assert_eq!(
            help,
            Help {
                tx_en: tx_en as u16,
                stop_sch_tx: None,
                ppdu_status: None,
            }
        );
        // rtw89_mac_stop_sch_tx(ALL): CMAC checked, every enable cleared.
        expected.r(4, CMAC_FUNC_EN);
        expected.rmw(2, CTN_TXEN, 0xffff, 0);
        // PPDU status off.
        expected.r(4, CMAC_FUNC_EN);
        expected.rmw(4, PPDU_STAT, PPDU_STAT_RPT_EN, 0);
        for (bbrst, trk) in [
            (R_P0_TXPW_RSTB, R_P0_TSSI_TRK),
            (R_P1_TXPW_RSTB, R_P1_TSSI_TRK),
        ] {
            expected.bb(bbrst, B_P0_TXPW_RSTB_MANON, 1);
            expected.bb(trk, B_P0_TSSI_TRK_EN, 1);
        }
        expected.bb(R_ADC_FIFO, B_ADC_FIFO_RST, 0xf);
        expected.log.push(Access::Delay(40));
        expected.bb(R_RXCCA, B_RXCCA_DIS, 1);
        expected.bb(R_PD_CTRL, B_PD_HIT_DIS, 1);
        expected.bb(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 7);
        expected.bb(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 7);
        expected.log.push(Access::Delay(1));
        expected.bb(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 0);
        // The exit: PPDU status on, ADC and TSSI released, BB out of reset,
        // TX enables back.
        expected.r(4, CMAC_FUNC_EN);
        expected.w(
            4,
            PPDU_STAT,
            PPDU_STAT_RPT_EN | APP_MAC_INFO_RPT | APP_PLCP_HDR_RPT | PPDU_STAT_RPT_CRC32,
        );
        expected.rmw(4, HW_RPT_FWD, FWD_PPDU_STAT_MASK, PRPT_DEST_HOST);
        expected.bb(R_ADC_FIFO, B_ADC_FIFO_RST, 0);
        for (bbrst, trk) in [
            (R_P0_TXPW_RSTB, R_P0_TSSI_TRK),
            (R_P1_TXPW_RSTB, R_P1_TSSI_TRK),
        ] {
            expected.bb(bbrst, B_P0_TXPW_RSTB_MANON, 0);
            expected.bb(trk, B_P0_TSSI_TRK_EN, 0);
        }
        expected.bb(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 0);
        expected.bb(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 0);
        expected.bb(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1);
        if chan.band() == Band::Ghz2 {
            expected.bb(R_RXCCA, B_RXCCA_DIS, 0);
        }
        expected.bb(R_PD_CTRL, B_PD_HIT_DIS, 0);
        expected.r(4, CMAC_FUNC_EN);
        expected.rmw(2, CTN_TXEN, 0xffff, tx_en);
        assert_eq!(io.log, expected.log, "{chan:?}");
    }
}

#[test]
fn rf_0x18_holds_the_channel_band_and_width_on_both_paths() {
    for (center, primary, mhz, band5, bw, lb) in [
        (1, 1, 20, false, CFGCH_BW_20M, 0x1b),
        (11, 13, 40, false, CFGCH_BW_40M, 0x13),
        (42, 36, 80, true, CFGCH_BW_80M, 0xb),
        (175, 177, 40, true, CFGCH_BW_40M, 0x13),
    ] {
        let chan = channel(center, primary, mhz);
        let mut io = Model::new(Faults::default());
        let tuned = set_channel(&mut io, &chan, &inputs(Kind::Card)).unwrap();
        assert_eq!(tuned, Tuned::default());
        let kept = !(RR_CFGCH_BAND1
            | RR_CFGCH_BAND0
            | RR_CFGCH_CH
            | RR_CFGCH_BW
            | RR_CFGCH_POW_LCK
            | RR_CFGCH_TRX_AH
            | RR_CFGCH_BCN);
        let set = u32::from(center)
            | prep(bw, RR_CFGCH_BW)
            | RR_CFGCH_BW2
            | if band5 {
                prep(CFGCH_BAND1_5G, RR_CFGCH_BAND1) | prep(CFGCH_BAND0_5G, RR_CFGCH_BAND0)
            } else {
                0
            };
        for path in 0..2 {
            let swsi = rf_pattern(path as u32, RR_CFGCH);
            assert_eq!(
                io.rf[path][RR_CFGCH as usize],
                (swsi & kept) | set,
                "{chan:?}"
            );
            let direct = Model::new(Faults::default()).direct(path, RR_CFGCH_V1);
            assert_eq!(
                io.direct(path, RR_CFGCH_V1),
                (direct & !RFREG_MASK) | (direct & kept & RFREG_MASK) | set,
                "{chan:?}"
            );
            assert_eq!(
                field(io.rf[path][RR_LUTWD0 as usize], RR_LUTWD0_LB),
                lb,
                "{chan:?}"
            );
            // The LUT write enable is left off, the LCK state bin on.
            assert_eq!(io.rf[path][RR_LUTWE2 as usize] & RR_LUTWE2_RTXBW, 0);
            assert_eq!(io.rf[path][RR_LCKST as usize] & RR_LCKST_BIN, 1);
        }
        // S0's LDO is put back as it read.
        assert_eq!(io.rf[0][RR_LDO as usize], rf_pattern(0, RR_LDO));
    }
}

#[test]
fn an_lpf_that_stays_busy_is_counted_and_skips_the_lock_check() {
    let chan = channel(36, 36, 20);
    let mut io = Model::new(Faults {
        lpf_stuck: true,
        ..Faults::default()
    });
    let tuned = set_channel(&mut io, &chan, &inputs(Kind::Card)).unwrap();
    assert_eq!(tuned.lck_timeouts, 1);
    // 1001 polls of RR_LPF, one past the bound, and none of RR_SYNFB.
    let requested = |address: u32| {
        io.log
            .iter()
            .filter(|access| {
                matches!(access, Access::Write { register, value, .. }
                    if *register == CR_BASE + SWSI_READ_ADDR_V1
                        && field(*value, SWSI_READ_ADDR_ADDR_V1) == address)
            })
            .count()
    };
    assert_eq!(requested(RR_LPF), 1001);
    assert_eq!(requested(RR_SYNFB), 0);

    // Unlocked, each recovery runs, and each rewrite of RF 0x18 polls again.
    let mut io = Model::new(Faults {
        unlocked: true,
        ..Faults::default()
    });
    let tuned = set_channel(&mut io, &chan, &inputs(Kind::Card)).unwrap();
    assert_eq!(tuned.lck_timeouts, 0);
    let requested = |address: u32| {
        io.log
            .iter()
            .filter(|access| {
                matches!(access, Access::Write { register, value, .. }
                    if *register == CR_BASE + SWSI_READ_ADDR_V1
                        && field(*value, SWSI_READ_ADDR_ADDR_V1) == address)
            })
            .count()
    };
    assert_eq!(requested(RR_LPF), 3);
    // Three lock checks and the last debug line's read.
    assert_eq!(requested(RR_SYNFB), 4);
}

#[test]
fn a_cmac_that_reads_off_is_reported_and_the_switch_carries_on_like_rtw89() {
    let chan = channel(6, 6, 20);
    let mut io = Model::new(Faults {
        cmac_off: true,
        ..Faults::default()
    });
    let value = io.get(CMAC_FUNC_EN, 4);
    let switched = switch(
        &mut io,
        None,
        &chan,
        &inputs(Kind::Card),
        Some(Band::Ghz2),
        |_, _| Ok(()),
    )
    .unwrap();
    let off = Some(Cause::CmacOff { value });
    assert_eq!(switched.help.stop_sch_tx, off);
    assert_eq!(switched.help.ppdu_status, off);
    assert_eq!(
        switched.done,
        Done {
            ppdu_status: off,
            resume_sch_tx: off,
        }
    );
    assert!(!switched.band_notice);
    // Neither CTN_TXEN nor PPDU_STAT is written.
    assert!(!io.log.iter().any(|access| matches!(access,
        Access::Write { register, .. } if *register == CTN_TXEN || *register == PPDU_STAT)));
}

#[test]
fn an_access_the_interface_refuses_ends_the_switch() {
    let chan = channel(42, 36, 80);
    for register in [
        CTN_TXEN,
        CMAC_FUNC_EN,
        CR_BASE + R_MAC_PIN_SEL,
        CR_BASE + SWSI_V1,
    ] {
        let mut io = Model::new(Faults {
            refuse: Some(register),
            ..Faults::default()
        });
        let mut powered = false;
        let result = switch(&mut io, None, &chan, &inputs(Kind::Card), None, |_, _| {
            powered = true;
            Ok(())
        });
        assert_eq!(result, Err(io::Error::Register { register }));
        assert!(!powered);
    }
    // TX power's own failure ends it before the help exits.
    let mut io = Model::new(Faults::default());
    let failure = io::Error::Register { register: 0x1234 };
    let result = switch(&mut io, None, &chan, &inputs(Kind::Card), None, |_, _| {
        Err(failure)
    });
    assert_eq!(result, Err(failure));
    assert!(!io.log.iter().any(|access| matches!(access,
        Access::Write { register, .. } if *register == HW_RPT_FWD)));
}

#[test]
fn the_band_notice_is_owed_on_the_first_switch_and_each_band_change() {
    let case = Case {
        kind: Kind::Card,
        faults: Faults::default(),
        steps: vec![
            (1, 1, 20),
            (6, 6, 20),
            (42, 36, 80),
            (155, 149, 80),
            (3, 1, 40),
        ],
    };
    let (io, switched) = replay(&case);
    let notices: Vec<bool> = switched.iter().map(|s| s.band_notice).collect();
    assert_eq!(notices, [true, false, true, false, true]);
    // TX power is set once per switch, between the channel and the exit.
    let marks = io
        .log
        .iter()
        .filter(|access| matches!(access, Access::Mark { tag: 12, .. }))
        .count();
    assert_eq!(marks, 5);
}

#[test]
fn a_primary_and_width_name_the_plans_block_and_convert_for_rfk_and_tx_power() {
    // 36/80 is the user's AP's channel: center 42, as rfk and TX power read it.
    let ap = Channel::for_primary(36, Width::Mhz80).unwrap();
    assert_eq!((ap.center(), ap.primary(), ap.width_mhz()), (42, 36, 80));
    assert_eq!(ap.primary_freq(), 5180);
    assert_eq!(
        ap.rfk(),
        rfk::Channel {
            band: rfk::Band::Ghz5,
            width: rfk::Bandwidth::Mhz80,
            number: 42,
        }
    );
    assert_eq!(
        ap.txpower(),
        txpower::Chan {
            band: txpower::Band::Ghz5,
            channel: 42,
            primary: 36,
            width: txpower::Width::Mhz80,
        }
    );
    // Each primary of the block names the same center.
    for primary in [36, 40, 44, 48] {
        assert_eq!(
            Channel::for_primary(primary, Width::Mhz80)
                .unwrap()
                .center(),
            42
        );
    }
    assert_eq!(
        Channel::for_primary(149, Width::Mhz40).unwrap().center(),
        151
    );
    assert_eq!(
        Channel::for_primary(153, Width::Mhz40).unwrap().center(),
        151
    );
    // At 2.4 GHz HT40+ where it fits, else HT40-.
    let low = Channel::for_primary(1, Width::Mhz40).unwrap();
    assert_eq!((low.center(), low.primary_freq()), (3, 2412));
    assert_eq!(
        low.rfk(),
        rfk::Channel {
            band: rfk::Band::Ghz2,
            width: rfk::Bandwidth::Mhz40,
            number: 3,
        }
    );
    assert_eq!(Channel::for_primary(11, Width::Mhz40).unwrap().center(), 9);
    let six = Channel::for_primary(6, Width::Mhz20).unwrap();
    assert_eq!(
        six.txpower(),
        txpower::Chan {
            band: txpower::Band::Ghz2,
            channel: 6,
            primary: 6,
            width: txpower::Width::Mhz20,
        }
    );
    // UNII-4's block holds 165.
    assert_eq!(
        Channel::for_primary(165, Width::Mhz80).unwrap().center(),
        171
    );
    // No block holds them.
    assert!(Channel::for_primary(6, Width::Mhz80).is_err());
    assert!(Channel::for_primary(14, Width::Mhz40).is_err());
    assert!(Channel::for_primary(37, Width::Mhz20).is_err());
}
