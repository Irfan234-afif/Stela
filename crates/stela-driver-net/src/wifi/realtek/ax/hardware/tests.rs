// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The RTL8852B under the generic Realtek station, on the whole-chip model
//! ([`super::super::model`]) brought up through stage 1 and stage 2, with
//! the model's AP, the user's: WPA2-PSK (or WPA3-SAE with PMF required) and
//! CCMP on 5 GHz channel 36 at 80 MHz, HT, VHT and HE.
extern crate std;

use super::*;
use crate::{
    Clock, Link, LinkError,
    firmware::Catalog,
    wifi::{
        connection::{keeper::Radio, security::Security},
        intel::policy::tests::regdb,
        network::{Network, Secret},
        realtek::{
            ax::{
                bootstrap::tests::{ACV, CUT, DEVICE, board, catalog, container},
                c2h::RaRpt,
                elements::{Id, tests as elm},
                h2c::{H2C_CAT_MAC, H2C_CAT_OUTSRC, H2C_CAT_TEST},
                io::{CR_BASE, field},
                mac::port::NET_TYPE_INFRA,
                model::{AID, Ap, Chip as Model, Command, Protection, Sent, Shared},
                pci::{
                    release::{TX_DONE, TX_RETRY_LIMIT},
                    tests::{Access, Domain, Placement, Source},
                },
                registers::{HALT_C2H_CTRL, SWSI_DATA_ADDR_V1, SWSI_DATA_V1, WLAN_XTAL_SI_CTRL},
                rtw8852b::rfk::{
                    ntfy::{H2C_CL_OUTSRC_RF_FW_NOTIFY, H2C_FUNC_OUTSRC_RF_GET_MCCCH},
                    reg::{B_P0_TSSI_OFT, R_P0_TSSI_TRK, R_TXAGC_BB, RR_TM},
                },
                txwd::*,
            },
            ccmp,
            identity::tests::observed,
            station::{Realtek, Wifi},
        },
        security::PacketNumber,
        station::Phase,
        supplicant::tests::Authenticator,
    },
};
use alloc::{rc::Rc, vec};
use core::sync::atomic::{AtomicU8, Ordering};
use stela_driver_base::entropy::{Entropy, EntropyError};
use zeroize::Zeroizing;

const CLOCK: Clock = Clock {
    ticks_per_microsecond: 1,
};
const AP: [u8; 6] = [0x02, 0xd2, 0x0b, 0x10, 0x20, 0x30];
const SSID: &[u8] = b"test";
/// The country's 2.4 GHz and UNII-1 rules, 20 dBm each, active scans
/// allowed.
const RULES: [(u32, u32, u8, u16); 2] = [
    (2_402_000, 2_472_000, 0, 2000),
    (5_170_000, 5_250_000, 0, 2000),
];

/// Each read one byte over the last, from 0x5a.
#[derive(Default)]
struct FixedEntropy(AtomicU8);

impl Entropy for FixedEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(0x5a + self.0.fetch_add(1, Ordering::Relaxed));
        Ok(())
    }
}

/// The synthetic container with every element stage 2 needs behind its
/// suits, as the radio's tests build it.
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

/// A cold chip of RFE type 1 whose DMA reaches a packed domain, logging
/// nothing, and the hardware brought up on it.
fn hardware() -> (Hardware<Shared>, Rc<Model>) {
    core::mem::forget(crate::test_clock::virtualize());
    let domain = Domain::new(Placement::Packed);
    let chip = Rc::new(Model::new(&board(1), ACV, domain.clone()));
    chip.logging(false);
    let claim = Claim {
        io: Shared(chip.clone()),
        source: &Source,
        domain,
        observed: observed(DEVICE, CUT),
    };
    let mut config = &*chip;
    let settings = Settings {
        alpha2: Some(*b"ID"),
        vector: false,
    };
    // SAFETY: the model, its DMA domain and these pages belong to this test
    // alone; no device reaches them.
    let mut hardware = unsafe { Hardware::new(claim, &mut config, &firmware(), &settings) }
        .unwrap_or_else(|stopped| panic!("{stopped}"));
    let restart = Restart {
        config: Box::new(Shared(chip.clone())),
        firmware: Box::leak(Box::new(firmware())),
    };
    // SAFETY: the configuration space is the model's, which the hardware's
    // register interface reaches, of this test alone.
    unsafe { hardware.restartable(restart) };
    (hardware, chip)
}

/// The station on the hardware, kept connected to the AP's network, and
/// the AP.
struct Bench {
    wifi: Wifi<Hardware<Shared>>,
    chip: Rc<Model>,
    ap: Ap,
    local: Mac,
}

fn bench(protection: Protection) -> Bench {
    let (hardware, chip) = hardware();
    let local = hardware.address();
    let ap = Ap::new(AP, local.0, SSID, protection);
    let database = regdb(&[(*b"ID", &RULES)]);
    let country = database.select(*b"ID").unwrap();
    let secret = match protection {
        Protection::Wpa2Psk => Secret::Psk(Zeroizing::new([0; 32])),
        Protection::Wpa3Sae => Secret::parse(&ap.password).unwrap(),
    };
    let network = Network {
        ssid: SSID.to_vec(),
        secret,
        country: None,
    };
    let radio = Realtek::new(hardware, local, country, CLOCK).unwrap();
    Bench {
        wifi: radio.keep(network, Arc::new(FixedEntropy::default())),
        chip,
        ap,
        local,
    }
}

impl Bench {
    /// Serve the air until `done`, five milliseconds passing each round.
    fn run(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        for _ in 0..4000 {
            self.wifi.carrier();
            self.ap.serve(&self.chip);
            if done(self) {
                return true;
            }
            crate::test_clock::advance(CLOCK, 5_000);
        }
        false
    }

    fn associated(&mut self) -> bool {
        self.run(|bench| bench.wifi.radio().station().phase() == Phase::Associated)
    }

    fn sent(&self) -> Vec<Sent> {
        self.chip.sent_from(0)
    }

    /// The EAPOL payloads the station sent from its `from`th frame on.
    fn answers(&self, from: usize) -> Vec<Vec<u8>> {
        self.chip
            .sent_from(from)
            .iter()
            .filter_map(|sent| eapol_payload(&sent.frame).map(<[u8]>::to_vec))
            .collect()
    }

    /// A frame from the AP, as the chip hands it over.
    fn hear(&mut self, frame: &[u8], decrypted: bool) {
        self.ap.hear(&self.chip, frame, decrypted);
    }

    /// An IPv4 frame from the station to the AP under `tos`.
    fn ip(&self, tos: u8) -> Vec<u8> {
        let mut ethernet = vec![0; 14];
        ethernet[..6].copy_from_slice(&AP);
        ethernet[6..12].copy_from_slice(&self.local.0);
        ethernet[12..14].copy_from_slice(&[8, 0]);
        ethernet.extend([0x45, tos]);
        ethernet.extend([0; 44]);
        ethernet
    }
}

/// What the station sent past `frame`'s header, IV and LLC when it is
/// EAPOL.
fn eapol_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame[0] & 0x0c != 8 {
        return None;
    }
    let header = if frame[0] & 0x80 != 0 { 26 } else { 24 };
    let header = header + if frame[1] & 0x40 != 0 { 8 } else { 0 };
    (frame.get(header + 6..header + 8)? == [0x88, 0x8e]).then(|| &frame[header + 8..])
}

/// A QoS data frame from the AP to `receiver`, with `key` its index and
/// packet number.
fn data(
    receiver: [u8; 6],
    sequence: u16,
    kind: [u8; 2],
    body: &[u8],
    key: Option<(u8, u8)>,
) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = if key.is_some() { 0x42 } else { 0x02 };
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    if let Some((index, number)) = key {
        frame.extend([number, 0, 0, 0x20 | index << 6, 0, 0, 0, 0]);
    }
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend(kind);
    frame.extend(body);
    if key.is_some() {
        frame.extend([0; 8]);
    }
    frame
}

impl Bench {
    /// The station associated with the AP and through its 4-way handshake
    /// with a new authenticator, the port open; the GTK is 0x50.., and under
    /// PMF the IGTK 0x77... The authenticator, for the group handshakes
    /// that follow.
    fn join(&mut self) -> Authenticator {
        assert!(self.associated(), "no association");
        let from = self.chip.sent_count();
        let local = self.local;
        let protection = self.ap.protection;
        let rsn = self.ap.rsn();
        let security = Security::select(&rsn, true).unwrap();
        let pmk = match protection {
            Protection::Wpa2Psk => Zeroizing::new([0; 32]),
            Protection::Wpa3Sae => self.ap.pmk().expect("SAE accepted"),
        };
        let mut ap =
            Authenticator::between(security.suites(), pmk, Mac(AP), local, security.element());
        let frame = data(local.0, 0, [0x88, 0x8e], &ap.message_1(), None);
        self.hear(&frame, false);
        assert!(self.run(|bench| !bench.answers(from).is_empty()));
        ap.message_2(&self.answers(from)[0]);
        let mut igtk = Vec::new();
        if protection == Protection::Wpa3Sae {
            igtk = vec![0xdd, 4 + 8 + 16, 0x00, 0x0f, 0xac, 9, 4, 0];
            igtk.extend_from_slice(&[0; 6]);
            igtk.extend_from_slice(&[0x77; 16]);
        }
        let frame = data(
            local.0,
            1,
            [0x88, 0x8e],
            &ap.message_3_with(&rsn, &igtk),
            None,
        );
        self.hear(&frame, false);
        assert!(self.run(|bench| bench.answers(from).len() > 1));
        assert!(self.run(|bench| bench.wifi.carrier()), "no carrier");
        ap.signed_reply(&self.answers(from)[1], 0x308);
        ap
    }

    /// Serve the air until the link reports the firmware's loss, and what
    /// it said.
    fn lost(&mut self) -> String {
        for _ in 0..4000 {
            self.ap.serve(&self.chip);
            if let Err(LinkError::Adapter(why)) = self.wifi.receive()
                && why.contains("firmware")
            {
                return why;
            }
            crate::test_clock::advance(CLOCK, 5_000);
        }
        panic!("no firmware loss reported");
    }
}

/// The bench joined to the AP through its handshake, the port open; the
/// GTK is 0x50.., and under PMF the IGTK 0x77...
fn connected(protection: Protection) -> Bench {
    let mut bench = bench(protection);
    bench.join();
    bench
}

/// What the station holds for the network, as each frame's first payload
/// byte.
fn delivered(wifi: &mut Wifi<Hardware<Shared>>) -> Vec<u8> {
    let mut values = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        values.push(ethernet[14]);
    }
    values
}

/// The security CAM H2C (`H2C_FUNC_MAC_SEC_UPD`) of `commands`.
fn sec_cam(commands: &[Command]) -> Vec<&Command> {
    commands
        .iter()
        .filter(|command| {
            (command.cat, command.class, command.func)
                == (
                    H2C_CAT_MAC,
                    cam::H2C_CL_MAC_SEC_CAM,
                    cam::H2C_FUNC_MAC_SEC_UPD,
                )
        })
        .collect()
}

/// The PTK as its security CAM H2C carries it, and its entry.
fn ptk(commands: &[Command]) -> ([u8; 16], u8) {
    let key = sec_cam(commands)
        .into_iter()
        .find(|key| key.payload[8] != 0x50)
        .unwrap();
    (key.payload[8..24].try_into().unwrap(), key.payload[0])
}

/// A field of a TXWD body or info dword.
fn get(dword: u32, mask: u32) -> u32 {
    (dword & mask) >> mask.trailing_zeros()
}

/// The data frames the station sent on best effort's ring.
fn best_effort(bench: &Bench) -> Vec<Sent> {
    bench
        .sent()
        .into_iter()
        .filter(|sent| sent.txch == 0 && sent.frame[0] == 0x88)
        .collect()
}

/// The Block Ack actions of `kind` the station sent.
fn actions(bench: &Bench, kind: u8) -> Vec<Vec<u8>> {
    bench
        .sent()
        .into_iter()
        .filter(|sent| sent.frame[0] == 0xd0 && sent.frame[24..26] == [3, kind])
        .map(|sent| sent.frame[26..].to_vec())
        .collect()
}

#[test]
fn a_scan_hops_the_channels_in_software_and_joins_the_ap_at_80_mhz() {
    let mut bench = bench(Protection::Wpa2Psk);
    assert!(bench.associated());
    // Probes left on the 2.4 GHz channels and on the AP's.
    assert!(bench.ap.probed.contains(&1) && bench.ap.probed.contains(&11));
    assert!(bench.ap.probed.contains(&36));
    // The association stands on 36/80: its center, 42.
    assert_eq!(bench.chip.tuned(), Some(42));
}

#[test]
fn a_beacon_heard_off_its_channel_is_placed_by_its_elements() {
    let mut bench = bench(Protection::Wpa2Psk);
    bench.ap.heard_on = vec![40, 44, 48];
    assert!(bench.associated());
    // Its beacons on 40, 44 and 48 named 36: the station approached there,
    // where the AP answers, and nothing it sent the AP went unheard.
    assert_eq!(bench.chip.tuned(), Some(42));
    let to_ap = bench
        .sent()
        .into_iter()
        .zip(&bench.ap.statuses)
        .filter(|(sent, _)| sent.frame[4] & 1 == 0)
        .all(|(_, &status)| status == TX_DONE);
    assert!(to_ap);
}

#[test]
fn wpa2_psk_with_ccmp_joins_the_users_ap_and_keys_the_security_cam() {
    let bench = connected(Protection::Wpa2Psk);
    let commands = bench.chip.commands();
    let keys = sec_cam(&commands);
    assert_eq!(keys.len(), 2);
    for key in &keys {
        // CCMP-128, 20 bytes long.
        assert_eq!(key.payload[4] & 0xf, cam::SEC_KEY_TYPE_CCMP128);
        assert_eq!(key.payload[2], cam::SEC_CAM_LEN);
    }
    // The PTK and the GTK, each in its own entry.
    let gtk: Vec<u8> = (0x50..0x60).collect();
    assert!(keys.iter().any(|key| key.payload[8..24] == gtk[..]));
    assert_ne!(keys[0].payload[0], keys[1].payload[0]);
    // The address CAM after them holds both: pairwise in slot 0, the group
    // key in slot 2.
    let last = commands
        .iter()
        .rev()
        .find(|command| command.class == cam::H2C_CL_MAC_ADDR_CAM_UPDATE)
        .unwrap();
    let w10 = u32::from_le_bytes(last.payload[40..44].try_into().unwrap());
    assert_eq!(w10 & cam::ADDR_CAM_W10_SEC_ENT_VALID, 0b101);
}

#[test]
fn wpa3_sae_with_pmf_required_joins_and_keeps_the_igtk_in_the_host() {
    let bench = connected(Protection::Wpa3Sae);
    // SAE's commit and confirm left on the management ring.
    let sae = bench
        .sent()
        .into_iter()
        .filter(|sent| sent.frame[0] == 0xb0 && sent.frame[24..26] == [3, 0])
        .inspect(|sent| assert_eq!(sent.txch, 8))
        .count();
    assert_eq!(sae, 2);
    // The PTK and GTK reach the CAM; the IGTK does not.
    assert_eq!(sec_cam(&bench.chip.commands()).len(), 2);
}

/// An SA Query request at packet number `number`, sealed under `key`, as
/// the chip leaves a unicast management frame: undecrypted.
fn sa_query(key: &[u8; 16], local: Mac, number: u8) -> Vec<u8> {
    let mut header = vec![0xd0, 0x40, 0, 0];
    header.extend_from_slice(&local.0);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0, 0]);
    let iv = [number, 0, 0, 0x20, 0, 0, 0, 0];
    let pn = PacketNumber::new(number.into()).unwrap();
    ccmp::seal(key, &header, &iv, pn, &[8, 0, 1, 2])
}

#[test]
fn protected_management_frames_are_sealed_in_software() {
    let mut bench = connected(Protection::Wpa3Sae);
    let (key, _) = ptk(&bench.chip.commands());
    let before = bench.chip.sent_count();
    let request = sa_query(&key, bench.local, 5);
    bench.hear(&request, false);
    let answered = |bench: &mut Bench| {
        bench
            .chip
            .sent_from(before)
            .iter()
            .any(|sent| sent.frame[0] == 0xd0)
    };
    assert!(bench.run(answered));
    let response = bench
        .chip
        .sent_from(before)
        .into_iter()
        .find(|sent| sent.frame[0] == 0xd0)
        .unwrap();
    // Protected, on B0MGQ, the hardware asked for no encryption: the host
    // sealed it, and it opens under the PTK with the request's ID.
    assert_ne!(response.frame[1] & 0x40, 0);
    assert_eq!(response.qsel(), QSEL_B0_MGMT);
    assert_eq!(response.info.unwrap()[2] & INFO2_SEC_HW_ENC, 0);
    let pn = PacketNumber::new(u64::from(response.frame[24])).unwrap();
    let opened = ccmp::open(&key, &response.frame, pn).unwrap();
    assert_eq!(opened[32..36], [8, 1, 1, 2]);
}

#[test]
fn received_data_decrypted_by_the_chip_passes_its_replay_and_integrity_checks() {
    let mut bench = connected(Protection::Wpa2Psk);
    let local = bench.local.0;
    let body = [0x45; 46];
    let frame = |sequence, key| data(local, sequence, [8, 0], &body, Some(key));
    bench.hear(&frame(10, (0, 1)), true);
    bench.wifi.carrier();
    assert_eq!(delivered(&mut bench.wifi), [0x45]);
    // Replayed, then failing the hardware's ICV.
    bench.hear(&frame(10, (0, 1)), true);
    bench.ap.hear_failed(&bench.chip, &frame(11, (0, 2)));
    bench.wifi.carrier();
    assert_eq!(delivered(&mut bench.wifi), []);
}

#[test]
fn an_a_msdu_gives_up_each_of_its_frames() {
    let mut bench = connected(Protection::Wpa2Psk);
    let local = bench.local.0;
    let mut frame = data(local, 20, [8, 0], &[], Some((0, 1)));
    frame.truncate(34);
    frame[24] = 0x80;
    for value in [0x31, 0x32] {
        let padding = (4 - frame[34..].len() % 4) % 4;
        frame.extend(vec![0; padding]);
        frame.extend(local);
        frame.extend(AP);
        frame.extend(54u16.to_be_bytes());
        frame.extend([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
        frame.extend([value; 46]);
    }
    frame.extend([0; 8]);
    bench.hear(&frame, true);
    bench.wifi.carrier();
    assert_eq!(delivered(&mut bench.wifi), [0x31, 0x32]);
}

#[test]
fn an_ra_report_sets_the_a_msdu_its_rate_may_carry() {
    let (hardware, _) = hardware();
    // HE at 80 MHz, two streams, MCS 11, 0.8 us: 1200.9 Mb/s.
    let rpt = RaRpt {
        mac_id: MAC_ID,
        rate: 0x1b,
        mode: 3,
        giltf: ra::GILTF_2XHE08,
        bw: 2,
        ..RaRpt::default()
    };
    let rate = RaReport::parse(&rpt).unwrap();
    assert_eq!(rate.bit_rate, 12009);
    assert_eq!(
        hardware.reported(&Report::Rate(rate), Width::Mhz80),
        Some(Reported::Amsdu(ra::MAX_AMSDU_LIMIT))
    );
}

#[test]
fn a_block_ack_agreement_orders_what_it_holds() {
    let mut bench = connected(Protection::Wpa2Psk);
    // ADDBA request: dialog 7, TID 0, immediate, 64 frames, starting at 100.
    let parameters = 2u16 | 64 << 6;
    let mut body = vec![3, 0, 7];
    body.extend(parameters.to_le_bytes());
    body.extend([0, 0]);
    body.extend((100u16 << 4).to_le_bytes());
    let before = bench.chip.sent_count();
    let request = bench.ap.management(0xd0, &body);
    bench.hear(&request, false);
    assert!(bench.run(|bench| bench.chip.sent_count() > before));
    let answer = bench.chip.sent_from(before)[0].frame.clone();
    assert_eq!(answer[24..27], [3, 1, 7]);
    assert_eq!(answer[27..29], [0, 0]);
    let local = bench.local.0;
    let frame = |sequence: u16, number: u8, value| {
        data(local, sequence, [8, 0], &[value; 46], Some((0, number)))
    };
    bench.hear(&frame(101, 2, 0x21), true);
    bench.wifi.carrier();
    assert_eq!(delivered(&mut bench.wifi), []);
    bench.hear(&frame(100, 1, 0x20), true);
    bench.wifi.carrier();
    assert_eq!(delivered(&mut bench.wifi), [0x20, 0x21]);
}

#[test]
fn traffic_opens_an_agreement_and_what_follows_leaves_as_an_a_mpdu() {
    let mut bench = connected(Protection::Wpa2Psk);
    let ethernet = bench.ip(0);
    bench.wifi.transmit(&ethernet).unwrap();
    assert!(bench.run(|bench| !actions(bench, 0).is_empty()));
    let dialog = actions(&bench, 0)[0][0];
    let first = best_effort(&bench);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].body[3] & BODY3_AGG_EN, 0);
    // The AP accepts: TID 0, immediate, 64 frames.
    let mut body = vec![3, 1, dialog, 0, 0];
    body.extend((3u16 | 64 << 6).to_le_bytes());
    body.extend([0, 0]);
    let response = bench.ap.management(0xd0, &body);
    bench.hear(&response, false);
    bench.wifi.carrier();
    bench.wifi.transmit(&ethernet).unwrap();
    assert!(bench.run(|bench| best_effort(bench).len() == 2));
    let second = &best_effort(&bench)[1];
    let info = second.info.unwrap();
    // The AP's HT A-MPDU parameters 0x17: 64K, 4 us spacing.
    assert_ne!(second.body[3] & BODY3_AGG_EN, 0);
    assert_eq!(get(info[1], INFO1_MAX_AGGNUM), 31);
    assert_eq!(get(info[2], INFO2_AMPDU_DENSITY), 5);
}

/// What a management descriptor of `sent` holds that every one does, and
/// its rate.
fn management_rate(sent: &Sent) -> u32 {
    assert_eq!(sent.txch, 8);
    assert_eq!(sent.qsel(), QSEL_B0_MGMT);
    assert_eq!(get(sent.body[0], BODY0_CHANNEL_DMA), 8);
    assert_eq!(get(sent.body[0], BODY0_HW_SSN_SEL), 1);
    assert_eq!(get(sent.body[0], BODY0_HW_SSN_MODE), 1);
    assert_ne!(sent.body[0] & BODY0_WD_PAGE, 0);
    assert_eq!(
        get(sent.body[2], BODY2_TXPKT_SIZE) as usize,
        sent.frame.len()
    );
    let info = sent.info.expect("WD info");
    assert_ne!(info[0] & INFO0_USE_RATE, 0);
    assert_ne!(info[0] & INFO0_DISDATAFB, 0);
    assert_eq!(info[2] & INFO2_SEC_HW_ENC, 0);
    get(info[0], INFO0_DATA_RATE)
}

#[test]
fn each_frame_kind_leaves_with_the_descriptor_rtw89_fills() {
    let mut bench = connected(Protection::Wpa2Psk);
    let ethernet = bench.ip(0);
    bench.wifi.transmit(&ethernet).unwrap();
    assert!(bench.run(|bench| !best_effort(bench).is_empty()));
    let sent = bench.sent();
    // Probes at CCK 1M on 2.4 GHz and OFDM 6M on 5 GHz; the exchange with
    // the AP at OFDM 6M.
    let probes: Vec<u32> = sent
        .iter()
        .filter(|sent| sent.frame[0] == 0x40)
        .map(management_rate)
        .collect();
    assert!(probes.contains(&u32::from(HW_RATE_CCK1)));
    assert!(probes.contains(&u32::from(HW_RATE_OFDM6)));
    for kind in [0xb0, 0x00] {
        let frame = sent.iter().find(|sent| sent.frame[0] == kind).unwrap();
        assert_eq!(management_rate(frame), u32::from(HW_RATE_OFDM6));
    }
    // EAPOL: voice's ring, kept out of aggregation, in the clear.
    let eapol = sent
        .iter()
        .find(|sent| eapol_payload(&sent.frame).is_some())
        .unwrap();
    assert_eq!(eapol.txch, 3);
    assert_eq!(eapol.qsel(), QSEL_VO_0);
    assert_ne!(eapol.body[3] & BODY3_BK, 0);
    assert_eq!(eapol.info.unwrap()[2] & INFO2_SEC_HW_ENC, 0);
    // Data: best effort, under the PTK's security CAM entry, the header's
    // length in its LLC field, its own sequence number, no fixed rate.
    let (_, entry) = ptk(&bench.chip.commands());
    let data = &best_effort(&bench)[0];
    let info = data.info.unwrap();
    assert_eq!(data.qsel(), QSEL_BE_0);
    assert_eq!(get(data.body[0], BODY0_HDR_LLC_LEN), 13);
    assert_eq!(get(data.body[0], BODY0_HW_SSN_SEL), 0);
    assert_eq!(
        get(data.body[3], BODY3_SW_SEQ),
        u32::from(u16::from_le_bytes([data.frame[22], data.frame[23]]) >> 4)
    );
    assert_ne!(info[2] & INFO2_SEC_HW_ENC, 0);
    assert_eq!(
        get(info[2], INFO2_SEC_TYPE),
        u32::from(cam::SEC_KEY_TYPE_CCMP128)
    );
    assert_eq!(get(info[2], INFO2_SEC_CAM_IDX), u32::from(entry));
    assert_eq!(info[0] & INFO0_USE_RATE, 0);
    assert_eq!(
        get(info[1], INFO1_DATA_RTY_LOWEST_RATE),
        u32::from(HW_RATE_OFDM6)
    );
    // The host made the IV.
    assert_ne!(data.frame[1] & 0x40, 0);
    assert_eq!(data.frame[26 + 3] & 0x20, 0x20);
}

#[test]
fn a_lost_authentication_is_released_unacknowledged_and_goes_again() {
    let mut bench = bench(Protection::Wpa2Psk);
    bench.ap.losses = 1;
    assert!(bench.associated());
    let tries = bench
        .sent()
        .iter()
        .filter(|sent| sent.frame[0] == 0xb0)
        .count();
    assert_eq!(tries, 2);
    assert!(bench.ap.statuses.contains(&TX_RETRY_LIMIT));
}

/// A 20 MHz channel definition of `number` at `frequency_mhz`, or of
/// `width` around `center`.
fn definition(number: u16, frequency_mhz: u16, width: Width, center: u32) -> ChannelDefinition {
    ChannelDefinition {
        control: crate::wifi::Channel {
            band: if number <= 14 { Band::Ghz2 } else { Band::Ghz5 },
            number,
            frequency_mhz,
        },
        width,
        center1_mhz: center,
        center2_mhz: None,
        punctured: 0,
    }
}

#[test]
fn release_reports_name_the_stations_numbers() {
    let (mut hardware, chip) = hardware();
    hardware
        .tune(&definition(36, 5180, Width::Mhz20, 5180), false, 2000)
        .unwrap();
    let mut frame = vec![0xb0, 0, 0, 0];
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&hardware.address().0);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    let management = |report| Management {
        mpdu: &frame,
        band: Band::Ghz5,
        basic: None,
        report,
    };
    for report in [Some(8), None, Some(12)] {
        let descriptor = hardware.management(&management(report));
        assert!(
            hardware
                .transmit(Queue::Management, &descriptor, &frame)
                .unwrap()
        );
    }
    let sent = chip.sent_from(0);
    assert_eq!(
        sent.iter().map(|sent| sent.seq).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    chip.release(&sent[0], TX_DONE);
    chip.release(&sent[1], TX_DONE);
    chip.release(&sent[2], TX_RETRY_LIMIT);
    let mut reports = Vec::new();
    hardware
        .receive(&mut |incoming| {
            if let Incoming::Report(report) = incoming {
                reports.push(report);
            }
        })
        .unwrap();
    let reported: Vec<_> = reports
        .iter()
        .map(|report| hardware.reported(report, Width::Mhz20))
        .collect();
    assert_eq!(
        reported,
        [
            Some(Reported::Transmitted {
                number: 8,
                acknowledged: true
            }),
            Some(Reported::Transmitted {
                number: 12,
                acknowledged: false
            }),
        ]
    );
    // The pages were released: B0MGQ's free pages hold all but none.
    let descriptor = hardware.management(&management(Some(16)));
    assert!(
        hardware
            .transmit(Queue::Management, &descriptor, &frame)
            .unwrap()
    );
    assert_eq!(chip.sent_count(), 4);
}

#[test]
fn the_association_sends_rtw89s_h2c_in_its_order() {
    let (_, chip) = hardware();
    let up = chip.commands();
    // rtw89_mac_vif_init, behind stage 2's: the MAC ID unpaused, the role,
    // the join info, the address CAM, the default CMAC table.
    let tail: Vec<_> = up[up.len() - 5..]
        .iter()
        .map(|command| (command.class, command.func))
        .collect();
    assert_eq!(
        tail,
        [
            (H2C_CL_MAC_FW_OFLD, sta::H2C_FUNC_MAC_MACID_PAUSE),
            (sta::H2C_CL_MAC_MEDIA_RPT, sta::H2C_FUNC_MAC_FWROLE_MAINTAIN),
            (sta::H2C_CL_MAC_MEDIA_RPT, sta::H2C_FUNC_MAC_JOININFO),
            (
                cam::H2C_CL_MAC_ADDR_CAM_UPDATE,
                cam::H2C_FUNC_MAC_ADDR_CAM_UPD
            ),
            (sta::H2C_CL_MAC_FR_EXCHG, sta::H2C_FUNC_MAC_CCTLINFO_UD),
        ]
    );

    let mut bench = bench(Protection::Wpa2Psk);
    let start = bench.chip.commands().len();
    assert!(bench.associated());
    let commands = bench.chip.commands()[start..].to_vec();
    let kinds: Vec<_> = commands
        .iter()
        .map(|command| (command.cat, command.class, command.func))
        .collect();
    let at = |kind: (u8, u8, u8), from: usize| {
        kinds[from..]
            .iter()
            .position(|&each| each == kind)
            .map(|index| from + index)
            .unwrap_or_else(|| panic!("{kind:?} after {from} in {kinds:?}"))
    };
    let addr = (
        H2C_CAT_MAC,
        cam::H2C_CL_MAC_ADDR_CAM_UPDATE,
        cam::H2C_FUNC_MAC_ADDR_CAM_UPD,
    );
    let edca = (H2C_CAT_MAC, H2C_CL_MAC_FW_OFLD, H2C_FUNC_USR_EDCA);
    let cmac = (
        H2C_CAT_MAC,
        sta::H2C_CL_MAC_FR_EXCHG,
        sta::H2C_FUNC_MAC_CCTLINFO_UD,
    );
    let join = (
        H2C_CAT_MAC,
        sta::H2C_CL_MAC_MEDIA_RPT,
        sta::H2C_FUNC_MAC_JOININFO,
    );
    let ra = (
        H2C_CAT_OUTSRC,
        ra::H2C_CL_OUTSRC_RA,
        ra::H2C_FUNC_OUTSRC_RA_MACIDCFG,
    );
    // The scan's start and end, then the BSSID, each an address CAM.
    let scan = at(addr, 0);
    let bssid = at(addr, at(addr, scan + 1) + 1);
    assert_eq!(commands[bssid].payload[22..28], AP);
    // The four access categories in mac80211's order, then
    // rtw89_core_sta_link_assoc's CMAC table, join info and address CAM,
    // then rtw89_phy_ra_assoc's RA.
    let first_edca = at(edca, bssid);
    let acs: Vec<u8> = commands[first_edca..first_edca + 4]
        .iter()
        .map(|command| command.payload[0] >> 5 & 3)
        .collect();
    assert_eq!(acs, [3, 2, 0, 1]);
    let assoc = at(cmac, first_edca + 4);
    assert_eq!(
        [at(join, assoc), at(addr, assoc), at(ra, assoc)],
        [assoc + 1, assoc + 2, assoc + 3]
    );
    // The join info is the association's: not a disconnection (OP is
    // `dis_conn`), infrastructure.
    let w0 = u32::from_le_bytes(commands[assoc + 1].payload[..4].try_into().unwrap());
    assert_eq!(w0 & sta::JOININFO_W0_OP, 0);
    assert_eq!(
        get(w0, sta::JOININFO_W0_NET_TYPE),
        u32::from(NET_TYPE_INFRA)
    );
    // The address CAM names the AID and the AP.
    let addr_cam = &commands[assoc + 2].payload;
    let w9 = u32::from_le_bytes(addr_cam[36..40].try_into().unwrap());
    assert_eq!(w9 & cam::ADDR_CAM_W9_AID12, u32::from(AID));
    assert_eq!(addr_cam[22..24], AP[..2]);
    // The RA: 80 MHz on two streams.
    let ra = u32::from_le_bytes(commands[assoc + 3].payload[..4].try_into().unwrap());
    assert_eq!(get(ra, ra::RA_W0_BW_CAP), 2);
    assert_eq!(get(ra, ra::RA_W0_SS_NUM), 1);
}

#[test]
fn a_scan_notifies_tssi_and_calibrates_only_outside_it() {
    let (mut hardware, chip) = hardware();
    let notices = |chip: &Model| {
        chip.commands()
            .iter()
            .filter(|command| {
                (command.cat, command.class, command.func)
                    == (
                        H2C_CAT_OUTSRC,
                        H2C_CL_OUTSRC_RF_FW_NOTIFY,
                        H2C_FUNC_OUTSRC_RF_GET_MCCCH,
                    )
            })
            .count()
    };
    let calibrated = notices(&chip);
    hardware.scanning(true).unwrap();
    for (number, frequency) in [(1, 2412), (6, 2437), (36, 5180), (40, 5200)] {
        let hop = definition(number, frequency, Width::Mhz20, frequency.into());
        hardware.tune(&hop, true, 2000).unwrap();
        hardware.prepare_transmit().unwrap();
        assert_eq!(chip.tuned(), Some(number as u8));
    }
    // No calibration on a scan's hop.
    assert_eq!(hardware.calibrations(), 0);
    assert_eq!(notices(&chip), calibrated);
    // The scan's end: rtw8852b_wifi_scan_notify's TSSI offsets.
    hardware.scanning(false).unwrap();
    let mut io = Shared(chip.clone());
    let trk = Io::read32(&mut io, CR_BASE + R_P0_TSSI_TRK).unwrap();
    assert_eq!(trk & B_P0_TSSI_OFT, 0xc0);
    // The AP's channel tuned outside a scan is calibrated before its first
    // frame, once.
    hardware
        .tune(&definition(36, 5180, Width::Mhz80, 5210), false, 2000)
        .unwrap();
    assert_eq!(chip.tuned(), Some(42));
    hardware.prepare_transmit().unwrap();
    hardware.prepare_transmit().unwrap();
    assert_eq!(hardware.calibrations(), 1);
    assert_eq!(notices(&chip), calibrated + 1);
}

#[test]
fn the_advertisement_leaves_out_the_beamformee_bits_and_tkip_is_refused() {
    let (mut hardware, _) = hardware();
    let (elements, maps) = hardware.advertisement(Band::Ghz5);
    let vht = elements.windows(2).position(|w| w == [191, 12]).unwrap();
    let cap = u32::from_le_bytes(elements[vht + 2..vht + 6].try_into().unwrap());
    assert_eq!(cap & VHT_BEAMFORMEE, 0);
    assert_ne!(cap & capabilities::VHT_CAP_RXLDPC, 0);
    let he = elements
        .windows(3)
        .position(|w| w[0] == 255 && w[2] == 35)
        .unwrap();
    assert_eq!(elements[he + 3 + 6 + 4] & HE_PHY_CAP4_BEAMFORMEE, 0);
    assert_eq!(maps[0].rx, 0xfffa);
    let key = KeyEntry {
        entry: 1,
        index: 1,
        cipher: Cipher::Tkip,
        group: true,
        peer: Mac::BROADCAST,
        material: &[0; 16],
    };
    assert!(hardware.write_key(&key).is_err());
}

/// The voice data frames the station sent.
fn voice(bench: &Bench) -> Vec<Sent> {
    bench
        .sent()
        .into_iter()
        .filter(|sent| sent.txch == 3 && sent.frame[0] == 0x88)
        .collect()
}

#[test]
fn data_waiting_together_on_five_ghz_leaves_as_one_amsdu() {
    let mut bench = connected(Protection::Wpa2Psk);
    let before = voice(&bench).len();
    let ethernet = bench.ip(0xc0);
    // The voice ring's 255 free BDs take as many frames; the next two wait
    // for room, together.
    bench.chip.stall(true);
    for _ in 0..257 {
        bench.wifi.transmit(&ethernet).unwrap();
        bench.wifi.carrier();
    }
    bench.chip.stall(false);
    assert!(bench.run(|bench| voice(bench).len() > before + 255));
    for _ in 0..4 {
        bench.wifi.carrier();
    }
    let frames = voice(&bench);
    assert_eq!(frames.len(), before + 256);
    assert!(
        frames[before..before + 255]
            .iter()
            .all(|sent| sent.frame[24] & 0x80 == 0)
    );
    let joined = &frames[before + 255];
    assert_eq!(joined.frame[24] & 0x80, 0x80);
    assert_eq!(joined.frame[26 + 3] & 0x20, 0x20, "under the head's IV");
    assert_eq!(
        get(joined.body[2], BODY2_TXPKT_SIZE) as usize,
        joined.frame.len()
    );
    assert_ne!(joined.info.unwrap()[2] & INFO2_SEC_HW_ENC, 0);
}

/// The first access in `log` that `found` names.
fn first(log: &[Access], what: &str, found: impl Fn(&Access) -> bool) -> usize {
    log.iter()
        .position(found)
        .unwrap_or_else(|| panic!("no {what} in {} accesses", log.len()))
}

#[test]
fn the_watchdog_tracks_in_rtw89s_order_and_leaves_a_scan_alone() {
    let (mut hardware, chip) = hardware();
    hardware
        .tune(&definition(36, 5180, Width::Mhz80, 5210), false, 2000)
        .unwrap();
    // No station added: DIG runs. A crystal off its default, which CFO tracking without an AP steps
    // back toward it.
    let cfo = &mut hardware.running.dynamic.cfo;
    let default = cfo.crystal_cap_default;
    cfo.crystal_cap = default + 2;
    chip.logging(true);
    hardware.watchdog(true, false).unwrap();
    assert_eq!(chip.log(), [], "a scan's watchdog tracks nothing");
    hardware.watchdog(false, false).unwrap();
    let log = chip.log();
    let read = |at: u32| move |access: &Access| matches!(*access, Access::Read { register, .. } if register == at);
    let wrote = |at: u32| move |access: &Access| matches!(*access, Access::Write { register, .. } if register == at);
    // The thermal meters: TSSI's report, or RF RR_TM triggered.
    let thermal = first(&log, "thermal reading", |access| {
        read(CR_BASE + 0x1c10)(access)
            || matches!(*access, Access::Write { register, value, .. }
                if register == CR_BASE + SWSI_DATA_V1 && field(value, SWSI_DATA_ADDR_V1) == RR_TM)
    });
    let monitor = first(&log, "IFS-CLM report", read(CR_BASE + dynamic::IFSCNT));
    let dig = first(&log, "PD floor", wrote(CR_BASE + dynamic::SEG0R_PD_V1));
    let dpk = first(&log, "DPK track", read(CR_BASE + R_TXAGC_BB));
    let cfo = first(&log, "crystal cap", wrote(WLAN_XTAL_SI_CTRL));
    assert!(
        thermal < monitor && monitor < dig && dig < dpk && dpk < cfo,
        "{thermal} {monitor} {dig} {dpk} {cfo}"
    );
    assert_eq!(hardware.running.dynamic.cfo.crystal_cap, default + 1);
}

#[test]
fn the_association_resumes_dig_and_feeds_it_the_aps_rssi() {
    let mut bench = connected(Protection::Wpa2Psk);
    let hardware = bench.wifi.radio_mut().device_mut();
    // Suspended as the AP's channel was calibrated, resumed at the
    // association; the AP's frames, A1-matched to its MAC ID, are its
    // average at the rssi_avg __rtw8852bx_convert_rpl_to_rssi gives their
    // PPDU statuses: IE01's FD average, 120.
    assert!(!hardware.running.dynamic.dig.pause_dig);
    assert_eq!(
        hardware.dm_link(),
        dynamic::Link {
            stations: 1,
            rssi_min: 120
        }
    );
    // A scan suspends DIG; its end resumes it and skips the next DIG.
    hardware.scanning(true).unwrap();
    assert!(hardware.running.dynamic.dig.pause_dig);
    hardware.scanning(false).unwrap();
    let dig = hardware.running.dynamic.dig;
    assert!(!dig.pause_dig && dig.bypass_dig);
    hardware.watchdog(false, false).unwrap();
    assert!(!hardware.running.dynamic.dig.bypass_dig);
}

#[test]
fn a_busy_link_runs_cfo_tracking_on_its_timer() {
    let (mut hardware, _) = hardware();
    let start = 10_000_000;
    hardware.coexist(start).unwrap();
    // More than CFO_TP_UPPER's 100 Mbps sent: the enhanced state, its
    // timer started.
    hardware.traffic.tx_tp.add(400);
    hardware.watchdog(false, false).unwrap();
    let period = u64::from(hardware.running.dynamic.cfo.cfo_timer_ms) * 1000;
    assert_eq!(period, 250_000);
    assert_eq!(hardware.cfo_due, Some(start + period));
    hardware.coexist(start + period - 1).unwrap();
    assert_eq!(hardware.cfo_due, Some(start + period));
    hardware.coexist(start + period).unwrap();
    assert_eq!(hardware.cfo_due, Some(start + 2 * period));
    // Quiet: the watchdogs bring the average under CFO_TP_LOWER, and the
    // next work stops the timer.
    while hardware.traffic.dynamic().tx_throughput > 50 {
        hardware.watchdog(false, false).unwrap();
    }
    hardware.watchdog(false, false).unwrap();
    hardware.coexist(start + 2 * period).unwrap();
    assert_eq!(hardware.cfo_due, None);
}

#[test]
fn a_firmware_halt_mid_traffic_brings_the_chip_up_cold_and_rejoins() {
    let mut bench = connected(Protection::Wpa2Psk);
    let downloads = bench.chip.attempts().len();
    let ethernet = bench.ip(0);
    bench.wifi.transmit(&ethernet).unwrap();
    assert!(bench.run(|bench| !best_effort(bench).is_empty()));
    // The firmware halts on a CPU exception, with a frame left on the ring.
    bench.chip.halt(0x2000_0abc);
    bench.wifi.transmit(&ethernet).unwrap();
    let sent = best_effort(&bench).len();
    assert_eq!(
        bench.lost(),
        "rtw89: firmware halted (err status 0x3000, SER_EV_L2_RESET), cold re-init 1/3"
    );
    // Powered off and brought up cold: the image downloaded again, the
    // halt's control cleared, the port closed.
    assert_eq!(bench.chip.attempts().len(), downloads + 1);
    assert!(bench.chip.on());
    let mut io = Shared(bench.chip.clone());
    assert_eq!(Io::read32(&mut io, HALT_C2H_CTRL).unwrap(), 0);
    assert!(!bench.wifi.carrier());
    assert_eq!(bench.wifi.radio().device().recoveries(), 1);
    // The station joins again from a scan, and its traffic flows.
    bench.join();
    bench.wifi.transmit(&ethernet).unwrap();
    assert!(bench.run(|bench| best_effort(bench).len() > sent));
}

#[test]
fn a_fourth_firmware_halt_within_a_minute_leaves_the_chip_off() {
    let mut bench = connected(Protection::Wpa2Psk);
    for count in 1..=3 {
        bench.chip.halt(ser::MAC_AX_ERR_L2_ERR_AH_DMA);
        let why = bench.lost();
        assert!(why.ends_with(&format!(", cold re-init {count}/3")), "{why}");
    }
    let downloads = bench.chip.attempts().len();
    bench.chip.halt(ser::MAC_AX_ERR_L2_ERR_AH_DMA);
    assert_eq!(
        bench.lost(),
        "rtw89: firmware halted (err status 0x2000, SER_EV_L2_RESET), past 3 cold re-inits \
         within a minute; the RTL8852B stays powered off"
    );
    // Off for good: no download, no carrier, and the link says why.
    assert!(!bench.chip.on());
    assert!(!bench.run(|bench| bench.wifi.carrier()));
    assert_eq!(bench.chip.attempts().len(), downloads);
    assert_eq!(bench.wifi.radio().device().recoveries(), 3);
    assert!(matches!(
        bench.wifi.receive(),
        Err(LinkError::Adapter(why)) if why.contains("stays powered off")
    ));
}

#[test]
fn the_crash_trigger_asks_for_a_cpu_exception_whose_halt_is_recovered() {
    let (mut hardware, chip) = hardware();
    hardware.trigger_cpu_exception().unwrap();
    let last = chip.commands().pop().unwrap();
    assert_eq!(
        (last.cat, last.class, last.func),
        (
            H2C_CAT_TEST,
            ser::H2C_CL_FW_STATUS_TEST,
            ser::H2C_FUNC_CPU_EXCEPTION
        )
    );
    // Firmware 0.29.29.18: CRASH_TRIGGER_TYPE_0.
    assert_eq!(last.payload, ser::CPU_EXCEPTION_TYPE_0.to_le_bytes());
    // The firmware's answer, its halt, is found by the next look and
    // recovered.
    chip.halt(0x2000_0001);
    hardware.receive(&mut |_| {}).unwrap();
    let why = hardware.recover().unwrap();
    assert!(why.ends_with("cold re-init 1/3"), "{why}");
    assert!(chip.on());
    assert_eq!(hardware.recover(), None);
}
