extern crate std;

use super::*;
use crate::{
    firmware::Catalog,
    wifi::realtek::{
        ax::{
            bootstrap::tests::{ACV, CUT, DEVICE, board, catalog, container, container_of},
            fwdl::FWDL_CHECKSUM_FAIL,
            model::Chip as Model,
            pci::tests::{Access, Domain, Placement, Source, r32},
        },
        identity::tests::observed,
    },
};
use alloc::vec;

/// What the boot read of the synthetic chip before power-on, at `cut`.
fn unpowered(cut: u8) -> Unpowered {
    Unpowered {
        observed: observed(DEVICE, cut),
        bar2_bytes: 0x10_0000,
        msi: true,
    }
}

/// [`run`] over `chip`, whose DMA reaches `domain`, with `catalog`'s image.
fn run_on<'c>(
    chip: &'c Model,
    domain: &Arc<Domain>,
    catalog: &'c Catalog,
) -> (Outcome, Kept<'c, &'c Model>) {
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let inputs = Inputs {
        firmware: catalog,
        pages: &Source,
        clock,
    };
    let plan = radio::Plan {
        channel: radio::Plan::default_channel(),
        alpha2: None,
        country: None,
        listen_us: radio::LISTEN_US,
        clock,
    };
    let mut config = chip;
    // SAFETY: the model, its DMA domain and these pages belong to this test
    // alone; no device reaches them.
    unsafe {
        run(
            chip,
            &mut config,
            domain.clone(),
            observed(DEVICE, CUT),
            Found::Off,
            &inputs,
            &plan,
        )
    }
}

/// Timings that put the download at 100 ms and the efuse 12 ms later.
fn fixed() -> Timings {
    let mut timings = Timings::default();
    timings.begun[position(Stage::Download)] = Some(100_000);
    timings.begun[position(Stage::Efuse)] = Some(112_345);
    timings.ended = Some(130_000);
    timings
}

#[test]
fn a_dead_read_a_cav_or_no_image_leaves_the_chip_off() {
    // The image linux-firmware ships: suits for cuts 1 and 2 alone.
    let shipped = catalog(container_of(&[
        (1, 5, 0, [0, 29, 29, 18]),
        (2, 5, 0, [0, 29, 29, 18]),
    ]));
    assert!(admit(&unpowered(1), &shipped).is_ok());
    assert!(admit(&unpowered(2), &shipped).is_ok());

    let cav = admit(&unpowered(0), &shipped).unwrap_err();
    assert!(matches!(
        cav,
        Refusal::Firmware(StageError::Format(ParseError::NoCompatibleFirmware {
            cut: 0
        }))
    ));
    assert_eq!(cav.stage(), Stage::Firmware);
    assert_eq!(
        cav.to_string(),
        "the firmware image holds no suit for cut 0 (CAV), so rtw89 would have nothing to download"
    );

    for word in [u32::MAX, 0xdead_beef] {
        let mut dead = unpowered(1);
        dead.observed.sys_cfg1 = word;
        let refusal = admit(&dead, &shipped).unwrap_err();
        assert!(matches!(refusal, Refusal::NoAnswer(at) if at == word));
        assert_eq!(refusal.stage(), Stage::Identity);
    }

    let empty = Catalog::from_handoff(vec![]).unwrap();
    let missing = admit(&unpowered(1), &empty).unwrap_err();
    assert!(missing.to_string().ends_with("not supplied"), "{missing}");

    // The account names what was left off, and the check where.
    let outcome = Outcome::Refused(cav);
    assert_eq!(
        outcome.lines(),
        [
            "left off before power-on: the firmware image holds no suit for cut 0 (CAV), so rtw89 would have nothing to download"
        ]
    );
    let summary = outcome.summary();
    assert_eq!((summary.firmware, summary.efuse), (None, None));
    assert_eq!(summary.stopped.unwrap().0, Stage::Firmware);
    assert!(
        outcome
            .no_station()
            .unwrap()
            .0
            .starts_with("RTL8852B left off before power-on")
    );
}

#[test]
fn a_chip_that_reaches_the_efuse_is_powered_off_and_reported() {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let catalog = catalog(container());
    let (mut outcome, kept) = run_on(&chip, &domain, &catalog);
    assert!(!chip.on());
    assert!(kept.rings.is_some() && kept.channel.is_some());
    let Outcome::Reached {
        power_off,
        timings,
        radio,
        ..
    } = &mut outcome
    else {
        panic!("{outcome:?}")
    };
    assert_eq!(*power_off, Ok(()));
    // The synthetic container carries no elements: stage 2 stops before
    // it powers the chip on again.
    let stage2 = radio.as_mut().unwrap();
    assert!(matches!(
        stage2.stopped,
        Some((radio::Stage::Tables, radio::Error::Elements(_)))
    ));
    assert_eq!(stage2.power_off, None);
    stage2.timings = radio::Timings::default();
    // Every stage began in order on the clock.
    let begun: Vec<u64> = timings.begun.iter().map(|at| at.unwrap()).collect();
    assert!(begun.windows(2).all(|pair| pair[0] <= pair[1]));
    *timings = fixed();

    assert_eq!(
        outcome.lines(),
        [
            "chip: cut 1 (CBV), ACV 2; found off; powered on at the first attempt",
            "firmware: 0.29.29.18 type 5 from the cut 1 image (commit 0x1234567a): 6 H2C packets at the \
             first attempt, FREERTOS_DONE 12 ms after the download began; secure boot off",
            "efuse: MAC 02:00:00:..:..:01 (unicast), RFE 1, crystal cap 0x3c, autoloaded; the firmware's \
             phycap: 2 TX and 2 RX streams, over the register mailbox (1 H2C, 1 C2H)",
            "powered off after stage 1, as rtw89's probe ends",
            "stage 2 for channel 36 (80 MHz) stopped at tables: firmware elements 0x00076f34 are \
             unrecognized: BB_REG RADIO_A RADIO_B RF_NCTL TXPWR_BYRATE TXPWR_LMT_2GHZ \
             TXPWR_LMT_5GHZ TXPWR_LMT_RU_2GHZ TXPWR_LMT_RU_5GHZ TX_SHAPE_LMT TX_SHAPE_LMT_RU \
             TXPWR_TRK",
            "stage 2 RX before listening: buffers=0 wifi=0 mgmt=0 ctrl=0 data=0 ext=0 runt=0 \
             beacons=0 probe_resp=0 matched_ppdu=0 crc32_err=0 icv_err=0 c2h=0 ppdu=0 \
             ppdu_valid=0 other=0 segmented=0 truncated=0",
            "stage 2 never powered it on",
        ]
    );
    let summary_radio = outcome.summary().radio;
    assert_eq!(
        outcome.summary(),
        Summary {
            firmware: Some(FirmwareRan {
                version: [0, 29, 29, 18],
                kind: 5,
                image_cut: 1,
                packets: 6,
                retries: 0,
                freertos_done_us: Some(12_345),
                secure_boot: false,
            }),
            efuse: Some(EfuseRead {
                mac: [0x02, 0, 0, 0, 0, 0x01],
                unicast: true,
                rfe: 1,
                xtal: 0x3c,
                acv: Some(ACV),
                valid: true,
                mailbox: (1, 1),
            }),
            stopped: None,
            radio: summary_radio.clone(),
        }
    );
    let radio = summary_radio.unwrap();
    assert_eq!((radio.primary, radio.center, radio.width), (36, 42, 80));
    assert_eq!(radio.heard, None);
    assert_eq!(radio.stopped.unwrap().0, radio::Stage::Tables);
    assert!(
        outcome
            .no_station()
            .unwrap()
            .0
            .starts_with("RTL8852B stage 2 stopped at tables: firmware elements"),
        "{:?}",
        outcome.no_station()
    );
}

#[test]
fn a_download_that_never_finishes_is_logged_attempt_by_attempt_with_its_registers() {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone()).statuses(&[FWDL_CHECKSUM_FAIL]);
    // Each attempt polls the status for 400 ms; no log is read here.
    chip.logging(false);
    let catalog = catalog(container());
    let (outcome, kept) = run_on(&chip, &domain, &catalog);
    assert!(!chip.on());
    assert!(kept.rings.is_some() && kept.channel.is_some());
    let Outcome::Stopped {
        stage,
        registers,
        power_off,
        ..
    } = &outcome
    else {
        panic!("{outcome:?}")
    };
    assert_eq!(*stage, Stage::Download);
    assert_eq!(*power_off, Some(Ok(())));
    // Past the power-on, the DMA's and the firmware's registers are read
    // too, before the power-off.
    let names: Vec<&str> = registers.iter().map(|read| read.name).collect();
    assert_eq!(
        names,
        [
            "SYS_PW_CTRL",
            "IC_PWR_STATE",
            "PLATFORM_ENABLE",
            "WCPU_FW_CTRL",
            "HCI_FUNC_EN",
            "DMAC_FUNC_EN",
            "PCIE_DMA_STOP1",
            "CH12_TXBD_IDX",
            "BOOT_DBG",
        ]
    );
    let wcpu = registers[3].value.unwrap();
    assert_eq!(
        io::field(wcpu, WCPU_FWDL_STS_MASK),
        u32::from(FWDL_CHECKSUM_FAIL)
    );
    // The WL MAC still read as on.
    assert_eq!(registers[1].value, Ok(0x100));

    let lines = outcome.lines();
    assert!(
        lines[0].starts_with("stopped at firmware download after ")
            && lines[0].ends_with(": every one of the 5 attempts failed"),
        "{}",
        lines[0]
    );
    for (index, line) in lines[1..6].iter().enumerate() {
        assert!(
            line.starts_with(&format!(
                "attempt {}: ChecksumFail; WCPU_FW_CTRL 0x",
                index + 1
            )),
            "{line}"
        );
        assert!(line.contains("program counter 0x0 x15"), "{line}");
    }
    assert!(
        lines[6].starts_with(
            "reached first: found off; cut 1 (CBV), ACV 2; powered on at the first attempt; secure boot off; \
             firmware 0.29.29.18 type 5 from the cut 1 image, 6 H2C packets to send"
        ),
        "{}",
        lines[6]
    );
    assert!(
        lines[7].starts_with("registers before the power-off: SYS_PW_CTRL=0x")
            && lines[7].contains(" IC_PWR_STATE=0x00000100 ")
            && lines[7].contains(" BOOT_DBG=0x"),
        "{}",
        lines[7]
    );
    assert_eq!(lines[8], "powered off");
    assert_eq!(lines.len(), 9);

    let summary = outcome.summary();
    assert_eq!((summary.firmware, summary.efuse), (None, None));
    let (stage, why) = summary.stopped.unwrap();
    assert_eq!(stage, Stage::Download);
    assert_eq!(
        why,
        "every one of the 5 attempts failed: ChecksumFail, ChecksumFail, ChecksumFail, \
         ChecksumFail, ChecksumFail"
    );
    assert_eq!(
        outcome.no_station().unwrap().0,
        format!("RTL8852B stage 1 stopped at firmware download: {why}; powered off")
    );
}

#[test]
fn an_efuse_step_that_fails_keeps_the_firmware_stage_for_the_check() {
    let domain = Domain::new(Placement::Oracle);
    let mut case = board(1);
    case.c2h = None;
    let chip = Model::new(&case, ACV, domain.clone());
    // The mailbox is polled for a second; no log is read here.
    chip.logging(false);
    let catalog = catalog(container());
    let (outcome, _kept) = run_on(&chip, &domain, &catalog);
    assert!(!chip.on());
    let summary = outcome.summary();
    let firmware = summary.firmware.unwrap();
    assert_eq!((firmware.version, firmware.packets), ([0, 29, 29, 18], 6));
    assert_eq!(summary.efuse, None);
    let (stage, why) = summary.stopped.unwrap();
    assert_eq!(stage, Stage::Efuse);
    assert!(
        why.contains("C2HREG_CTRL") || why.contains("0x8164"),
        "{why}"
    );
    let lines = outcome.lines();
    assert!(
        lines[0].starts_with("stopped at efuse after ") && lines[0].contains("register: 0x8164"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains("firmware 0.29.29.18 type 5 from the cut 1 image (commit 0x1234567a): 6 H2C packets at the first attempt, FREERTOS_DONE"),
        "{}",
        lines[1]
    );
}

#[test]
fn a_chip_left_on_is_powered_off_before_bus_mastering_and_a_cold_one_only_read() {
    let domain = Domain::new(Placement::Oracle);
    let cold = Model::new(&board(1), ACV, domain.clone());
    let mut io = &cold;
    assert_eq!(quiesce(&mut io, CUT).unwrap(), Found::Off);
    assert_eq!(cold.log(), [r32(IC_PWR_STATE, 0)]);

    let warm = Model::new(&board(1), ACV, domain).left_on();
    let mut io = &warm;
    assert_eq!(quiesce(&mut io, CUT).unwrap(), Found::PoweredOff);
    assert!(!warm.on());
    let log = warm.log();
    assert_eq!(log[0], r32(IC_PWR_STATE, 0x100));
    assert_eq!(*log.last().unwrap(), r32(IC_PWR_STATE, 0));
    // Between them, rtw89_mac_pwr_off: the OFF MAC request among its writes.
    assert!(log.iter().any(|access| matches!(
        access,
        Access::Write { register: SYS_PW_CTRL, value, .. } if value & APFM_OFFMAC != 0
    )));
    assert_eq!(
        Found::PoweredOff.to_string(),
        "found on, as a previous boot can leave it, and powered off before bus mastering"
    );
    assert_eq!(Refusal::Quiesce(None).stage(), Stage::PowerOn);
}

#[test]
fn a_stage_lasts_until_the_next_one_begins_or_stage_1_ends() {
    let timings = fixed();
    assert_eq!(timings.took(Stage::Download), Some(12_345));
    assert_eq!(timings.took(Stage::Efuse), Some(130_000 - 112_345));
    assert_eq!(timings.took(Stage::PowerOn), None);
    // A clock that did not count gives no times.
    assert_eq!(Timings::default().took(Stage::Download), None);
    assert_eq!(millis(999), "999 us");
    assert_eq!(millis(12_345), "12 ms");
    assert_eq!(runs(&[1, 1, 2, 3, 3, 3]), "0x1 x2 0x2 0x3 x3");
    assert_eq!(
        Masked(&[0x00, 0xe0, 0x4c, 0x12, 0x34, 0x56]).to_string(),
        "00:e0:4c:..:..:56"
    );
}

#[test]
fn a_listen_that_heard_the_ap_is_logged_with_the_plans_headline_and_each_bssid() {
    let mut heard = Heard {
        listened_us: Some(2_000_431),
        ..Heard::default()
    };
    let counts = &mut heard.counts;
    (counts.buffers, counts.wifi, counts.mgmt, counts.beacons) = (7, 3, 3, 3);
    (counts.matched, counts.ppdu, counts.ppdu_valid, counts.c2h) = (3, 3, 3, 1);
    heard.bss.push(Bss {
        bssid: [0x90, 0xd2, 0x0b, 0xdf, 0xbd, 0xed],
        ssid: b"DARAYA".to_vec(),
        beacons: 3,
        best: Some(-41),
        a1: 3,
        header_best: Some(-43),
        channel: Some(36),
        freq: 5180,
    });
    let report = radio::Report {
        heard: Some(heard),
        registers: vec![
            radio::Read {
                name: "RX_FLTR_OPT",
                space: radio::Space::Mac,
                address: RX_FLTR_OPT,
                value: Ok(0x0300_4408),
            },
            radio::Read {
                name: "RF A 0x18",
                space: radio::Space::Rf(0),
                address: 0x18,
                value: Ok(0x1012a),
            },
        ],
        ..radio::Report::default()
    };
    let outcome = radio::Outcome {
        channel: radio::Plan::default_channel(),
        report: Box::new(report),
        stopped: None,
        timings: radio::Timings::default(),
        power_off: Some(Ok(())),
    };
    assert_eq!(
        radio_lines(&outcome),
        [
            "rtw89: RTL8852B tuned to channel 36 (80 MHz), heard 3 beacons in 2 s, strongest -41 \
             dBm from 90:d2:0b:..:..:ed; no station yet",
            "stage 2 RX before listening: buffers=0 wifi=0 mgmt=0 ctrl=0 data=0 ext=0 runt=0 \
             beacons=0 probe_resp=0 matched_ppdu=0 crc32_err=0 icv_err=0 c2h=0 ppdu=0 \
             ppdu_valid=0 other=0 segmented=0 truncated=0",
            "stage 2 RX while listening: buffers=7 wifi=3 mgmt=3 ctrl=0 data=0 ext=0 runt=0 \
             beacons=3 probe_resp=0 matched_ppdu=3 crc32_err=0 icv_err=0 c2h=1 ppdu=3 \
             ppdu_valid=3 other=0 segmented=0 truncated=0",
            "stage 2 heard 90:d2:0b:..:..:ed ssid \"DARAYA\": 3 beacons, best -41 dBm (3 with an \
             A1-matched PPDU status; the PHY status header alone -43 dBm), elements name channel \
             36, received at 5180 MHz",
            "stage 2 registers: RX_FLTR_OPT=0x3004408 RF A 0x18=0x1012a",
            "powered off after stage 2, so the next system finds it cold; no station driver here \
             yet",
        ]
    );
}
