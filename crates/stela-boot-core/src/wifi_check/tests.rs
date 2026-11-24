use super::*;
use alloc::vec;
use stela_drivers::net::{
    Mac as Address,
    wifi::{
        Band, Channel,
        connection::keeper::{Chosen, Standing},
        realtek::ax::{
            attach::{EfuseRead, FirmwareRan},
            bootstrap::Stage as Step,
            listen::{Bss, Heard as Listened},
            radio::Stage as Step2,
        },
    },
};

const AT: &str = "0000:03:00.0";
/// The user's AP: DARAYA on channel 36, its BSSID 90:d2:0b:df:bd:ed.
const DARAYA: [u8; 6] = [0x90, 0xd2, 0x0b, 0xdf, 0xbd, 0xed];
const CHANNEL_36: Channel = Channel {
    band: Band::Ghz5,
    number: 36,
    frequency_mhz: 5180,
};

fn firmware() -> FirmwareRan {
    FirmwareRan {
        version: [0, 29, 29, 18],
        kind: 5,
        image_cut: 1,
        packets: 165,
        retries: 0,
        freertos_done_us: Some(48_200),
        secure_boot: false,
    }
}

fn efuse() -> EfuseRead {
    EfuseRead {
        mac: [0x00, 0xe0, 0x4c, 0x12, 0x34, 0x56],
        unicast: true,
        rfe: 1,
        xtal: 0x3c,
        acv: Some(2),
        valid: true,
        mailbox: (1, 1),
    }
}

fn daraya(beacons: u32) -> Bss {
    Bss {
        bssid: DARAYA,
        ssid: b"DARAYA".to_vec(),
        beacons,
        best: Some(-48),
        a1: beacons,
        header_best: Some(-50),
        channel: Some(36),
        freq: 5180,
    }
}

fn listened(bss: Vec<Bss>) -> Listened {
    let mut heard = Listened {
        listened_us: Some(2_000_100),
        ..Listened::default()
    };
    heard.counts.buffers = 40;
    heard.counts.wifi = 30;
    heard.counts.mgmt = 20;
    heard.counts.data = 10;
    heard.counts.beacons = bss.iter().map(|bss| bss.beacons).sum();
    heard.counts.ppdu = 10;
    heard.counts.ppdu_valid = 9;
    heard.counts.matched = 18;
    heard.bss = bss;
    heard
}

fn radio(heard: Option<Listened>, stopped: Option<(Step2, String)>) -> RadioRan {
    let mut before = Listened::default();
    before.counts.buffers = 3;
    before.counts.c2h = 3;
    RadioRan {
        primary: 36,
        center: 42,
        width: 80,
        heard,
        before,
        stopped,
        warnings: Vec::new(),
        power_off: Some(Ok(())),
    }
}

fn reached() -> Summary {
    Summary {
        firmware: Some(firmware()),
        efuse: Some(efuse()),
        stopped: None,
        radio: Some(radio(Some(listened(vec![daraya(17)])), None)),
        station: Some(StationRan::Up { vector: true }),
    }
}

fn cut(cut: u8, stage1: Option<&Summary>) -> Reached<'_> {
    Reached::Cut {
        sys_cfg1: u32::from(cut) << 12 | 0x0f00,
        cut,
        name: ["CAV", "CBV", "CCV"].get(usize::from(cut)).copied(),
        stage1,
    }
}

/// The association the station made with DARAYA under WPA2-PSK.
fn associated() -> Association {
    Association {
        ssid: b"DARAYA".to_vec(),
        bssid: Address(DARAYA),
        aid: 3,
        akm: Akm::Psk,
        pairwise: Cipher::Ccmp128,
        group: Cipher::Ccmp128,
        channel: CHANNEL_36,
        width: Width::Mhz80,
    }
}

const STATE: &str = "connection at connected; 1 scans, the last heard 2 BSSes and found the \
                     network on channel 36 (5180 MHz) at -48 dBm; tx sent=12 acked=11 \
                     retry_limit=1 dropped=0 channel=36/80 calibrations=1 msi";

fn lease() -> Lease {
    Lease {
        address: Ipv4Addr::new(192, 168, 1, 23),
        prefix: 24,
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
    }
}

/// The RTL8852BE station, tried by the host's network, as `lease` and
/// `associated` say.
fn station<'a>(
    lease: Result<Option<Lease>, &'a str>,
    associated: Option<&'a Association>,
    progress: Option<&'a Progress>,
) -> Tried<'a> {
    Tried {
        driver: DRIVER,
        location: AT,
        wireless: true,
        lease,
        associated,
        progress,
        state: Some(STATE),
        dhcp: None,
    }
}

/// The wired adapter at 0000:04:00.0, its lease got.
fn ethernet<'a>() -> Tried<'a> {
    Tried {
        driver: "realtek",
        location: "0000:04:00.0",
        wireless: false,
        lease: Ok(Some(lease())),
        associated: None,
        progress: None,
        state: None,
        dhcp: None,
    }
}

#[test]
fn stages_are_ordered_and_named_as_the_log_prints_them() {
    let stages = [
        Stage::Cut,
        Stage::Firmware,
        Stage::Efuse,
        Stage::Radio,
        Stage::Station,
        Stage::Lease,
        Stage::Ser,
    ];
    assert!(stages.windows(2).all(|pair| pair[0] < pair[1]));
    let names: Vec<_> = stages.iter().map(|stage| stage.name()).collect();
    assert_eq!(
        names,
        [
            "cut", "firmware", "efuse", "radio", "station", "lease", "ser"
        ]
    );
    assert_eq!(DRIVEN, Stage::Lease);
}

#[test]
fn a_station_that_got_a_lease_passes_with_each_stage_in_its_words() {
    let summary = reached();
    let associated = associated();
    let tried = [station(Ok(Some(lease())), Some(&associated), None)];
    let network = Network {
        tried: &tried,
        check: Some(Ok(())),
        recovery: None,
    };
    let report = report([(AT, cut(1, Some(&summary)))], &network);
    assert_eq!(report.verdict, Verdict::Passed);
    assert_eq!(
        report.lines,
        [
            "WIFI CHECK 0000:03:00.0 stage=cut cut=1 (CBV) sys_cfg1=0x00001f00",
            "WIFI CHECK 0000:03:00.0 stage=firmware version=0.29.29.18 type=5 image=cv1 \
             freertos_done=48 ms packets=165 retries=0 secure_boot=off",
            "WIFI CHECK 0000:03:00.0 stage=efuse mac=00:e0:4c:..:..:56 unicast rfe=1 xtal=0x3c \
             acv=2 autoload=yes mailbox=1/1",
            "WIFI CHECK 0000:03:00.0 rx before listening buffers=3 wifi=0 mgmt=0 ctrl=0 data=0 \
             beacons=0 probe_resp=0 matched_ppdu=0 crc32_err=0 icv_err=0 c2h=3 ppdu=0 \
             ppdu_valid=0 other=0 dropped=0",
            "WIFI CHECK 0000:03:00.0 stage=radio channel=36 width=80 beacons=17 \
             strongest=90:d2:0b:..:..:ed rssi=-48",
            "WIFI CHECK 0000:03:00.0 bss=90:d2:0b:..:..:ed ssid=\"DARAYA\" beacons=17 rssi=-48 \
             a1=17 hdr_rssi=-50 ch=36 freq=5180",
            "WIFI CHECK 0000:03:00.0 rx while listening buffers=40 wifi=30 mgmt=20 ctrl=0 \
             data=10 beacons=17 probe_resp=0 matched_ppdu=18 crc32_err=0 icv_err=0 c2h=0 \
             ppdu=10 ppdu_valid=9 other=0 dropped=0",
            &format!(
                "WIFI CHECK 0000:03:00.0 stage=station ssid={} bssid=90:d2:0b:..:..:ed aid=3 \
                 cipher=CCMP-128 group=CCMP-128 akm=WPA-PSK channel=36 width=80",
                Name("DARAYA")
            ),
            &format!("WIFI CHECK 0000:03:00.0 state {STATE}"),
            "WIFI CHECK 0000:03:00.0 stage=lease address=192.168.1.23/24 router=192.168.1.1",
            "WIFI CHECK reached lease; restarting",
        ]
    );
    // The network's name stays out of the log.
    assert!(
        report
            .lines
            .iter()
            .all(|line| !line.contains("ssid=DARAYA"))
    );
}

#[test]
fn the_listen_is_a_diagnostic_the_station_decides() {
    let associated = associated();
    let tried = [station(Ok(Some(lease())), Some(&associated), None)];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    // The listen ran and heard frames, but no beacon.
    let silent = Summary {
        radio: Some(radio(Some(listened(Vec::new())), None)),
        ..reached()
    };
    let checked = report([(AT, cut(1, Some(&silent)))], &network);
    assert_eq!(checked.verdict, Verdict::Passed);
    assert!(
        checked.lines[4].ends_with("beacons=0 strongest=none"),
        "{}",
        checked.lines[4]
    );

    // Stage 2 stopped at the channel; the station came up after it.
    let stopped = Summary {
        radio: Some(radio(
            None,
            Some((
                Step2::Channel,
                String::from("Timeout { register: 0x1174c, mask: 0x4000000 }"),
            )),
        )),
        ..reached()
    };
    let checked = report([(AT, cut(1, Some(&stopped)))], &network);
    assert_eq!(
        checked.lines[4],
        "WIFI CHECK 0000:03:00.0 stopped before stage=radio: channel: Timeout { register: \
         0x1174c, mask: 0x4000000 }"
    );
    assert!(checked.lines[5].contains(" stage=station "));
    assert_eq!(checked.verdict, Verdict::Passed);
}

#[test]
fn a_station_that_did_not_start_or_associate_names_where_it_stopped() {
    // The station did not start: no regulatory database.
    let down = Summary {
        station: Some(StationRan::Down(String::from(
            "started no station: no regulatory database",
        ))),
        ..reached()
    };
    let checked = report([(AT, cut(1, Some(&down)))], &Network::default());
    assert_eq!(
        checked.lines.last().unwrap(),
        "WIFI CHECK 0000:03:00.0 stopped before stage=station: started no station: no \
         regulatory database"
    );
    assert_eq!(
        checked.verdict,
        Verdict::Failed(String::from(
            "1 of 1 RTL8852B stopped before stage=station: started no station: no regulatory \
             database"
        ))
    );

    // The scan never found the network.
    let summary = reached();
    let missed = Progress {
        standing: Standing::Waiting,
        scans: 3,
        heard: 12,
        chosen: None,
        failures: 3,
        failed: Some((
            Standing::Scanning,
            String::from("the network was not among the BSSes heard"),
        )),
    };
    let tried = [station(
        Err("not connected to the Wi-Fi network."),
        None,
        Some(&missed),
    )];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    let why = "connection at waiting to scan; 3 scans, the last heard 12 BSSes and did not find \
               the network; 3 attempts failed, the last at scan: the network was not among the \
               BSSes heard";
    assert_eq!(
        &checked.lines[checked.lines.len() - 2..],
        [
            format!("WIFI CHECK 0000:03:00.0 state {STATE}"),
            format!("WIFI CHECK 0000:03:00.0 stopped before stage=station: {why}"),
        ]
    );
    assert_eq!(
        checked.verdict,
        Verdict::Failed(format!(
            "1 of 1 RTL8852B stopped before stage=station: {why}"
        ))
    );

    // Found on channel 36, then the AP's message 3 never came.
    let handshake = Progress {
        standing: Standing::Handshake(Some(3)),
        scans: 1,
        heard: 2,
        chosen: Some(Chosen {
            bssid: Address(DARAYA),
            channel: CHANNEL_36,
            signal_dbm: Some(-48),
        }),
        failures: 0,
        failed: None,
    };
    let tried = [station(
        Err("not connected to the Wi-Fi network."),
        None,
        Some(&handshake),
    )];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    assert_eq!(
        checked.verdict,
        Verdict::Failed(String::from(
            "1 of 1 RTL8852B stopped before stage=station: connection at 4-way handshake, \
             waiting for EAPOL message 3 of 4; 1 scans, the last heard 2 BSSes and found the \
             network on channel 36 (5180 MHz) at -48 dBm"
        ))
    );

    // The AP refused the association.
    let refused = Progress {
        failures: 1,
        failed: Some((
            Standing::Associating,
            String::from("rtw89: authentication or association failed"),
        )),
        standing: Standing::Leaving,
        ..handshake.clone()
    };
    let tried = [station(Err("no link"), None, Some(&refused))];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    assert!(
        matches!(&checked.verdict, Verdict::Failed(why)
            if why.ends_with("1 attempts failed, the last at association: rtw89: authentication \
                              or association failed")),
        "{:?}",
        checked.verdict
    );
}

#[test]
fn a_lease_that_did_not_come_names_dhcp_and_one_over_ethernet_says_to_unplug_it() {
    let summary = reached();
    let associated = associated();
    // Associated, then no DHCP server answered.
    let mut tried = station(
        Err(
            "no address (DHCP: no DHCPv4 lease or usable IPv6 router advertisement within 60 seconds)",
        ),
        Some(&associated),
        None,
    );
    tried.dhcp = Some("4 DISCOVER sent, 0 OFFER");
    let tried = [tried];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    let lines = &checked.lines[checked.lines.len() - 4..];
    assert!(lines[0].contains(" stage=station "), "{}", lines[0]);
    assert_eq!(
        lines[2],
        "WIFI CHECK 0000:03:00.0 dhcp 4 DISCOVER sent, 0 OFFER"
    );
    assert!(
        lines[3]
            .starts_with("WIFI CHECK 0000:03:00.0 stopped before stage=lease: DHCP: no address"),
        "{}",
        lines[3]
    );
    assert!(matches!(&checked.verdict, Verdict::Failed(why)
        if why.starts_with("1 of 1 RTL8852B stopped before stage=lease: DHCP: ")));

    // IPv6 alone gave an address.
    let tried = [station(Ok(None), Some(&associated), None)];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    assert_eq!(
        checked.verdict,
        Verdict::Failed(String::from(
            "1 of 1 RTL8852B stopped before stage=lease: no DHCPv4 lease came: only IPv6 gave an \
             address"
        ))
    );

    // The cable's adapter got the lease first; the station was never tried.
    let tried = [ethernet()];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    assert_eq!(
        checked.lines.last().unwrap(),
        "WIFI CHECK 0000:03:00.0 stopped before stage=station: the host network took realtek \
         at 0000:04:00.0 first and never tried the station"
    );
    assert_eq!(
        checked.verdict,
        Verdict::Failed(String::from(
            "the lease came over realtek at 0000:04:00.0, not Wi-Fi: unplug the Ethernet cable"
        ))
    );

    // The station leased, and the POST over it failed.
    let tried = [station(Ok(Some(lease())), Some(&associated), None)];
    let network = Network {
        tried: &tried,
        check: Some(Err("DNS: no answer")),
        recovery: None,
    };
    let checked = report([(AT, cut(1, Some(&summary)))], &network);
    assert_eq!(
        checked.verdict,
        Verdict::Failed(String::from(
            "the network check over Wi-Fi failed: DNS: no answer"
        ))
    );
    assert!(checked.lines.last().unwrap().contains(" stage=lease "));
}

#[test]
fn a_chip_that_stopped_names_the_stage_it_did_not_reach_and_why() {
    // The download gave up: no firmware stage.
    let download = Summary {
        firmware: None,
        efuse: None,
        stopped: Some((
            Step::Download,
            String::from("every one of the 5 attempts failed: ChecksumFail x5"),
        )),
        radio: None,
        station: None,
    };
    let failed = report([(AT, cut(1, Some(&download)))], &Network::default());
    let why = "firmware download: every one of the 5 attempts failed: ChecksumFail x5";
    assert_eq!(
        failed.lines[1],
        format!("WIFI CHECK 0000:03:00.0 stopped before stage=firmware: {why}")
    );
    assert_eq!(failed.lines.len(), 2);
    assert_eq!(
        failed.verdict,
        Verdict::Failed(format!(
            "1 of 1 RTL8852B stopped before stage=firmware: {why}"
        ))
    );

    // The firmware ran and the mailbox did not answer.
    let efuse = Summary {
        firmware: Some(firmware()),
        efuse: None,
        stopped: Some((Step::Efuse, String::from("Efuse(Io(Timeout { .. }))"))),
        radio: None,
        station: None,
    };
    let passed = reached();
    let associated = associated();
    let mut tried = station(Ok(Some(lease())), Some(&associated), None);
    tried.location = "0000:04:00.0";
    let tried = [tried];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let mixed = report(
        [
            (AT, cut(1, Some(&efuse))),
            ("0000:04:00.0", cut(2, Some(&passed))),
        ],
        &network,
    );
    assert!(mixed.lines[1].contains("stage=firmware version=0.29.29.18"));
    assert_eq!(
        mixed.lines[2],
        "WIFI CHECK 0000:03:00.0 stopped before stage=efuse: efuse: Efuse(Io(Timeout { .. }))"
    );
    assert!(matches!(&mixed.verdict, Verdict::Failed(why) if why.starts_with("1 of 2")));

    // Stage 1 that never ran.
    let unrun = report([(AT, cut(1, None))], &Network::default());
    assert_eq!(
        unrun.lines[1],
        "WIFI CHECK 0000:03:00.0 stopped before stage=firmware: stage 1 did not run"
    );
    assert!(matches!(unrun.verdict, Verdict::Failed(_)));
}

#[test]
fn cut_zero_a_failed_read_and_no_function_fail_naming_why() {
    let refused = Summary {
        firmware: None,
        efuse: None,
        radio: None,
        station: None,
        stopped: Some((
            Step::Firmware,
            String::from(
                "left off before power-on: the firmware image holds no suit for cut 0 (CAV)",
            ),
        )),
    };
    let cav = report([(AT, cut(0, Some(&refused)))], &Network::default());
    assert!(matches!(&cav.verdict, Verdict::Failed(why) if why.contains("cut 0 (CAV)")));
    assert!(cav.lines[0].ends_with("linux-firmware has no RTL8852B image for this cut"));
    assert!(cav.lines[1].contains("left off before power-on"));
    assert_eq!(cav.lines.len(), 2);

    let passed = reached();
    let unread = report(
        [
            (AT, Reached::NotRead("the function did not answer")),
            ("0000:04:00.0", cut(2, Some(&passed))),
        ],
        &Network::default(),
    );
    assert_eq!(
        unread.lines[0],
        "WIFI CHECK 0000:03:00.0 stopped before stage=cut: the function did not answer"
    );
    assert_eq!(
        unread.verdict,
        Verdict::Failed(String::from("1 of 2 RTL8852B stopped before stage=cut"))
    );

    let none = report(
        core::iter::empty::<(&str, Reached<'_>)>(),
        &Network::default(),
    );
    assert!(none.lines.is_empty());
    assert!(matches!(&none.verdict, Verdict::Failed(why) if why.contains("--wifi network")));
}

#[test]
fn a_cut_past_rtw89s_names_and_an_unmeasured_download_still_pass() {
    let mut summary = reached();
    if let Some(firmware) = summary.firmware.as_mut() {
        firmware.freertos_done_us = None;
    }
    if let Some(efuse) = summary.efuse.as_mut() {
        efuse.acv = None;
    }
    let associated = associated();
    let tried = [station(Ok(Some(lease())), Some(&associated), None)];
    let network = Network {
        tried: &tried,
        check: None,
        recovery: None,
    };
    let report = report(
        [(
            AT,
            Reached::Cut {
                sys_cfg1: 0x6000,
                cut: 6,
                name: None,
                stage1: Some(&summary),
            },
        )],
        &network,
    );
    assert_eq!(report.verdict, Verdict::Passed);
    assert_eq!(
        report.lines[0],
        "WIFI CHECK 0000:03:00.0 stage=cut cut=6 (past rtw89's CHIP_CFV) sys_cfg1=0x00006000"
    );
    assert!(report.lines[1].contains("freertos_done=unmeasured"));
    assert!(report.lines[2].contains(" acv=unread "));
}

/// What `rtw89` says as its firmware halts and the chip comes up cold.
const HALTED: &str =
    "rtw89: firmware halted (err status 0x3000, SER_EV_L2_RESET), cold re-init 1/3";

/// The recovery stage that ran to its end: the halt, the carrier lost and
/// back, a new lease and one cold re-init.
fn recovery<'a>() -> Recovery<'a> {
    Recovery {
        halted: Some(HALTED),
        took_ms: [Some(12), Some(13), Some(4_210), Some(5_034)],
        lease: Some(Lease {
            address: Ipv4Addr::new(192, 168, 1, 24),
            ..lease()
        }),
        recoveries: Some(1),
        stopped: None,
    }
}

#[test]
fn the_recovery_stage_after_the_lease_crashes_rejoins_and_leases_again() {
    let summary = reached();
    let associated = associated();
    let tried = [station(Ok(Some(lease())), Some(&associated), None)];
    let network = Network {
        tried: &tried,
        check: Some(Ok(())),
        recovery: Some(recovery()),
    };
    let report = report([(AT, cut(1, Some(&summary)))], &network);
    assert_eq!(report.verdict, Verdict::Passed);
    let tail = &report.lines[report.lines.len() - 5..];
    assert_eq!(
        tail,
        [
            "WIFI CHECK 0000:03:00.0 stage=lease address=192.168.1.23/24 router=192.168.1.1",
            &format!("WIFI CHECK 0000:03:00.0 stage=ser halted after 12 ms: {HALTED}"),
            "WIFI CHECK 0000:03:00.0 stage=ser carrier down after 13 ms, back after 4210 ms",
            "WIFI CHECK 0000:03:00.0 stage=ser lease address=192.168.1.24/24 router=192.168.1.1 \
             after 5034 ms recoveries=1",
            "WIFI CHECK reached ser; restarting",
        ]
    );
}

#[test]
fn a_recovery_that_stopped_names_its_step_and_one_that_counted_otherwise_fails() {
    let summary = reached();
    let associated = associated();
    let tried = [station(Ok(Some(lease())), Some(&associated), None)];
    let checked = |recovery: Recovery<'_>| {
        let network = Network {
            tried: &tried,
            check: None,
            recovery: Some(recovery),
        };
        report([(AT, cut(1, Some(&summary)))], &network)
    };

    // The firmware never reported its halt.
    let silent = checked(Recovery {
        halted: None,
        took_ms: [None; 4],
        lease: None,
        recoveries: Some(0),
        stopped: Some((RecoveryStep::Halt, "no halt came within 5 s of the trigger")),
    });
    assert_eq!(
        silent.lines.last().unwrap(),
        "WIFI CHECK 0000:03:00.0 stopped before stage=ser: halt: no halt came within 5 s of the \
         trigger"
    );
    assert_eq!(
        silent.verdict,
        Verdict::Failed(String::from(
            "1 of 1 RTL8852B stopped before stage=ser: halt: no halt came within 5 s of the \
             trigger"
        ))
    );

    // It halted and came up cold, but never joined again.
    let alone = checked(Recovery {
        took_ms: [Some(12), Some(13), None, None],
        lease: None,
        stopped: Some((RecoveryStep::Rejoin, "no carrier within 50 s")),
        ..recovery()
    });
    let lines = &alone.lines[alone.lines.len() - 3..];
    assert!(lines[0].contains(" stage=ser halted after 12 ms: "));
    assert_eq!(
        lines[1],
        "WIFI CHECK 0000:03:00.0 stage=ser carrier down after 13 ms, back after unmeasured"
    );
    assert_eq!(
        lines[2],
        "WIFI CHECK 0000:03:00.0 stopped before stage=ser: rejoin: no carrier within 50 s"
    );

    // Every step ran, but the chip was brought up cold twice.
    let twice = checked(Recovery {
        recoveries: Some(2),
        ..recovery()
    });
    assert_eq!(
        twice.verdict,
        Verdict::Failed(String::from(
            "1 of 1 RTL8852B stopped before stage=ser: the station counted 2 cold re-inits where \
             one ran"
        ))
    );
    assert!(!twice.lines.iter().any(|line| line.contains("reached")));
}
