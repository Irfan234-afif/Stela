extern crate std;

use super::*;
use crate::{
    firmware::Catalog,
    wifi::realtek::{
        ax::{
            bootstrap::{
                self, Claim,
                tests::{ACV, CUT, DEVICE, board, catalog, container},
            },
            c2h::RX_TYPE_C2H,
            elements::tests as elm,
            io::CR_BASE,
            model::Chip as Model,
            pci::tests::{Access, Domain, Placement, Source},
            rxdesc::{
                RX_TYPE_MGNT,
                tests::{Rxd, beacon, ppdu_status},
            },
        },
        identity::tests::observed,
    },
};
use alloc::{sync::Arc, vec::Vec};
use core::cell::Cell;

const DARAYA: [u8; 6] = [0x90, 0xd2, 0x0b, 0xdf, 0xbd, 0xed];

/// The synthetic container with every element stage 2 needs behind its
/// suits: RTL8852B's needed elements for RFE 0 and a BB gain table.
fn firmware() -> Catalog {
    let mut file = container();
    let mut pieces = elm::required();
    pieces.push(elm::plain(Id::BbGain, &elm::regs(3, 9)));
    for piece in pieces {
        file.resize(file.len().next_multiple_of(16), 0);
        file.extend_from_slice(&piece);
    }
    catalog(file)
}

/// The clock the stages run on: one tick per microsecond, virtual.
const CLOCK: Clock = Clock {
    ticks_per_microsecond: 1,
};

fn plan() -> Plan<'static> {
    Plan {
        channel: Plan::default_channel(),
        alpha2: Some(*b"ID"),
        country: None,
        listen_us: 20_000,
        clock: CLOCK,
    }
}

/// Records each stage's beginning with the log's length then, tells the
/// faulty interface which stage runs, and queues the user's AP's beacon
/// with its PPDU status as the listen begins.
struct Recorder<'c> {
    chip: &'c Model,
    stage: &'c Cell<Option<Stage>>,
    begun: Vec<(Stage, usize)>,
    ended: Option<Option<Stage>>,
}

impl Observer for Recorder<'_> {
    fn begin(&mut self, stage: Stage) {
        self.begun.push((stage, self.chip.log().len()));
        self.stage.set(Some(stage));
        if stage == Stage::Listen {
            let frame = Rxd::frame(RX_TYPE_MGNT, 2);
            // A C2H (a DONE_ACK of the MAC info class) before them.
            let c2h = Rxd {
                pkt_type: RX_TYPE_C2H,
                ..Rxd::default()
            };
            self.chip.queue_rx([
                c2h.packet(&[0x01, 0x01, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0]),
                frame.packet(&beacon(DARAYA, b"DARAYA", Some(36))),
                Rxd::ppdu_of(&frame).packet(&ppdu_status([110, 104], 100, 120, 0x20)),
            ]);
        }
    }
    fn end(&mut self, stopped: Option<Stage>) {
        self.ended = Some(stopped);
        self.stage.set(None);
    }
}

/// The model, every access refused while the stage it was given runs.
struct Faulty<'c> {
    chip: &'c Model,
    stage: &'c Cell<Option<Stage>>,
    target: Option<Stage>,
}

impl Faulty<'_> {
    fn check(&self, register: u32) -> Result<(), io::Error> {
        match self.target {
            Some(target) if self.stage.get() == Some(target) => {
                Err(io::Error::Register { register })
            }
            _ => Ok(()),
        }
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Faulty<'_> {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        self.check(register)?;
        let mut chip = self.chip;
        Io::read8(&mut chip, register)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        self.check(register)?;
        let mut chip = self.chip;
        Io::read16(&mut chip, register)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        self.check(register)?;
        let mut chip = self.chip;
        Io::read32(&mut chip, register)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.check(register)?;
        let mut chip = self.chip;
        Io::write8(&mut chip, register, value)
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.check(register)?;
        let mut chip = self.chip;
        Io::write16(&mut chip, register, value)
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.check(register)?;
        let mut chip = self.chip;
        Io::write32(&mut chip, register, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        let mut chip = self.chip;
        Io::delay_us(&mut chip, microseconds);
    }
}

/// What a run of stage 1, its power-off and stage 2 left.
struct Run {
    outcome: Outcome,
    begun: Vec<(Stage, usize)>,
    ended: Option<Option<Stage>>,
}

/// Stage 1 on `chip`, its power-off, then stage 2 with every access
/// refused during `fault`.
fn run_on(chip: &Model, domain: &Arc<Domain>, catalog: &Catalog, fault: Option<Stage>) -> Run {
    let _clock = crate::test_clock::virtualize();
    let mut config = chip;
    let claim = Claim {
        io: chip,
        source: &Source,
        domain: domain.clone(),
        observed: observed(DEVICE, CUT),
    };
    // SAFETY: the model, its DMA domain and these pages belong to this test
    // alone; no device reaches them.
    let mut stage1 = unsafe { bootstrap::bring_up(claim, &mut config, catalog, &mut ()) }
        .unwrap_or_else(|failure| panic!("{failure}"));
    stage1.power_off().unwrap();
    assert!(!chip.on());
    let stage = Cell::new(None);
    let mut faulty = Faulty {
        chip,
        stage: &stage,
        target: fault,
    };
    let mut recorder = Recorder {
        chip,
        stage: &stage,
        begun: Vec::new(),
        ended: None,
    };
    let held = Held {
        io: &mut faulty,
        rings: &mut stage1.rings,
        channel: &mut stage1.channel,
    };
    // SAFETY: as above; stage 1's power-off stopped the model's DMA.
    let outcome = unsafe {
        run(
            held,
            &mut config,
            &stage1.report,
            catalog,
            &plan(),
            &mut recorder,
        )
    };
    let Recorder { begun, ended, .. } = recorder;
    Run {
        outcome,
        begun,
        ended,
    }
}

/// The writes in `log[range]`, as (width, register, value).
fn writes(log: &[Access], range: core::ops::Range<usize>) -> Vec<(u32, u32, u32)> {
    log[range]
        .iter()
        .filter_map(|access| match *access {
            Access::Write {
                width,
                register,
                value,
            } => Some((width, register, value)),
            _ => None,
        })
        .collect()
}

#[test]
fn stage_2_takes_rtw89s_interface_start_in_order_and_hears_the_beacon_queued_for_it() {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let catalog = firmware();
    let Run {
        outcome,
        begun,
        ended,
    } = run_on(&chip, &domain, &catalog, None);
    if let Some((stage, error)) = &outcome.stopped {
        panic!("stage 2 stopped at {stage}: {error}");
    }
    assert_eq!(ended, Some(None));
    let stages: Vec<Stage> = begun.iter().map(|&(stage, _)| stage).collect();
    assert_eq!(stages, Stage::ALL);
    assert!(!chip.on());
    assert_eq!(outcome.power_off, Some(Ok(())));

    let log = chip.log();
    let window = |stage: Stage| {
        let at = stage.index();
        let start = begun[at].1;
        let end = begun.get(at + 1).map_or(log.len(), |&(_, end)| end);
        start..end
    };
    let wrote = |stage: Stage, register: u32| {
        writes(&log, window(stage))
            .into_iter()
            .filter(move |&(_, at, _)| at == register)
            .map(|(_, _, value)| value)
            .collect::<Vec<_>>()
    };
    // The tables are parsed without an access.
    assert!(window(Stage::Tables).is_empty());
    // rtw89_mac_pwr_on, then the partial init and a second download.
    assert!(
        wrote(Stage::PowerOn, SYS_PW_CTRL)
            .iter()
            .any(|value| value & APFN_ONMAC != 0)
    );
    assert!(!wrote(Stage::DmacPreInit, DMAC_FUNC_EN).is_empty());
    assert!(
        wrote(Stage::PciePreInit, TXBD_RWPTR_CLR1)
            .iter()
            .any(|value| value & CLR_CH12_IDX != 0)
    );
    assert!(!wrote(Stage::Download, CH12_TXBD_IDX).is_empty());
    assert_eq!(chip.attempts().len(), 2);
    // The MAC init enables CMAC0, the BB table loads, coex grants WL.
    assert!(!wrote(Stage::MacInit, CMAC_FUNC_EN).is_empty());
    assert!(!wrote(Stage::BbRf, CR_BASE + 0x4100).is_empty());
    assert!(wrote(Stage::Coex, LTE_CTRL).contains(&(LTE_CTRL_WRITE | LTE_SW_CFG_1)));
    // bb_sethw zeroes the MAC ID power limits.
    assert_eq!(wrote(Stage::DmInit, PWR_MACID_LMT_TABLE0), [0]);
    assert_eq!(wrote(Stage::DmInit, PWR_MACID_LMT_TABLE127), [0]);
    // The PPDU status, the RTS thresholds and the scan's RX filter.
    assert_eq!(
        wrote(Stage::Start, PPDU_STAT),
        [PPDU_STAT_RPT_EN | APP_MAC_INFO_RPT | APP_PLCP_HDR_RPT | PPDU_STAT_RPT_CRC32]
    );
    assert_eq!(wrote(Stage::Start, AGG_LEN_HT_0).len(), 2);
    let filter = wrote(Stage::Start, RX_FLTR_OPT);
    assert_eq!(filter.len(), 1);
    assert_eq!(
        filter[0] & RX_FLTR_CFG_MASK,
        SCAN_RX_FLTR & RX_FLTR_CFG_MASK
    );
    assert_eq!(
        filter[0] & (A_BCN_CHK_EN | A_BC | A_A1_MATCH | A_UC_CAM_MATCH | A_BC_CAM_MATCH),
        0
    );
    assert_eq!(Some(filter[0]), outcome.report.rx_filter);
    // The switch sets the bandwidth, then the calibrations run.
    assert!(!wrote(Stage::Channel, CR_BASE + R_CHBW_MOD_V1).is_empty());
    assert!(!writes(&log, window(Stage::Calibrate)).is_empty());
    assert!(log[window(Stage::Listen)].iter().any(|access| matches!(
        access,
        Access::Read {
            register: RXQ_RXBD_IDX,
            ..
        }
    )));

    let report = &outcome.report;
    assert!(report.mac.is_some() && report.coex.is_some() && report.calibrated.is_some());
    let switched = report.switched.unwrap();
    assert!(switched.band_notice);
    let regulated = report.regulated.unwrap();
    assert_eq!(regulated.cap, Cap::NONE);
    assert!(!regulated.country_cap);
    // The listen heard the beacon, with the signal its status gave.
    let heard = outcome.heard().unwrap();
    assert_eq!(heard.beacons(), 1);
    let bss = heard.strongest().unwrap();
    assert_eq!(bss.bssid, DARAYA);
    assert_eq!(bss.ssid, b"DARAYA");
    assert_eq!(bss.best, Some(-45));
    assert_eq!(bss.channel, Some(36));
    assert_eq!(heard.counts.ppdu_valid, 1);
    assert_eq!((heard.counts.c2h, heard.counts.buffers), (1, 3));
    assert!(heard.listened_us.unwrap() >= 20_000);
    assert_eq!(chip.rx_queued(), 0);
    // The key registers were read before the power-off.
    assert_eq!(report.registers.len(), KEY_REGISTERS.len());
    let gnt = report
        .registers
        .iter()
        .find(|read| read.space == Space::Gnt)
        .unwrap();
    assert_eq!(gnt.value, Ok(coex::gnt_value(&[coex::GNT_WL_ONLY; 2])));
    let fltr = report
        .registers
        .iter()
        .find(|read| read.address == RX_FLTR_OPT && read.space == Space::Mac)
        .unwrap();
    assert_eq!(fltr.value, Ok(filter[0]));
}

#[test]
fn a_failure_at_each_stage_powers_the_chip_off_and_names_the_stage() {
    let catalog = firmware();
    for &target in &Stage::ALL[1..] {
        let domain = Domain::new(Placement::Oracle);
        let chip = Model::new(&board(1), ACV, domain.clone());
        chip.logging(false);
        let Run { outcome, ended, .. } = run_on(&chip, &domain, &catalog, Some(target));
        let (stage, error) = outcome.stopped.as_ref().unwrap();
        assert_eq!(*stage, target, "{error}");
        assert_eq!(ended, Some(Some(target)));
        assert!(!chip.on(), "{target}");
        if target == Stage::PowerOn {
            // rtw89_mac_pwr_on powered it off between its attempts; nothing
            // is left to power off.
            assert!(matches!(error, Error::PowerOn(_)), "{error}");
            assert_eq!(outcome.power_off, None);
            assert!(outcome.report.registers.is_empty());
        } else {
            assert_eq!(outcome.power_off, Some(Ok(())), "{target}");
            assert_eq!(outcome.report.registers.len(), KEY_REGISTERS.len());
        }
        match outcome.heard() {
            // The listen keeps what it heard before its read was refused.
            Some(heard) => assert!(target == Stage::Listen && heard.counts.buffers == 0),
            None => assert_ne!(target, Stage::Listen),
        }
    }
}

#[test]
fn firmware_without_elements_stops_before_the_power_on() {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let catalog = catalog(container());
    let Run { outcome, begun, .. } = run_on(&chip, &domain, &catalog, None);
    assert!(matches!(
        outcome.stopped,
        Some((Stage::Tables, Error::Elements(_)))
    ));
    assert_eq!(begun.len(), 1);
    assert_eq!(outcome.power_off, None);
    assert!(!chip.on());
}

#[test]
fn the_scan_filter_drops_the_address_checks_and_keeps_the_rest() {
    assert_eq!(SCAN_RX_FLTR, DEFAULT_AX_RX_FLTR & !0xb6);
    let mut log = Vec::new();
    let mut io = Recording(&mut log, 0xffff_ffff);
    assert_eq!(
        set_rx_fltr(&mut io, SCAN_RX_FLTR).unwrap(),
        RX_MPDU_MAX_LEN_MASK | (SCAN_RX_FLTR & RX_FLTR_CFG_MASK)
    );
    assert_eq!(log, [(4, RX_FLTR_OPT, false), (4, RX_FLTR_OPT, true)]);
    // rtw89's default RTS thresholds: 88 us >> 5 and 4080 bytes >> 4.
    assert_eq!((RTS_TIME_TH, RTS_LEN_TH), (2, 255));
}

/// Every access as (width, register, write), each read answering `.1`.
struct Recording<'a>(&'a mut Vec<(u32, u32, bool)>, u32);

// SAFETY: a log of this test alone; it reaches no hardware.
unsafe impl Io for Recording<'_> {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        self.0.push((1, register, false));
        Ok(self.1 as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        self.0.push((2, register, false));
        Ok(self.1 as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        self.0.push((4, register, false));
        Ok(self.1)
    }
    fn write8(&mut self, register: u32, _: u8) -> Result<(), io::Error> {
        self.0.push((1, register, true));
        Ok(())
    }
    fn write16(&mut self, register: u32, _: u16) -> Result<(), io::Error> {
        self.0.push((2, register, true));
        Ok(())
    }
    fn write32(&mut self, register: u32, _: u32) -> Result<(), io::Error> {
        self.0.push((4, register, true));
        Ok(())
    }
    fn delay_us(&mut self, _: u64) {}
}
