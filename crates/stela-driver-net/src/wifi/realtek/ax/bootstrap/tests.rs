extern crate std;

use super::*;
use crate::{
    firmware::{Catalog, ErrorKind, Provenance, Resource},
    wifi::realtek::{
        ax::{
            efuse::{
                Hal,
                tests::{Case, PHYCAP_OK, encode_blocks, program_phycap, synthetic_logical},
            },
            features::ver_code,
            fwdl::{
                DOWNLOAD_ATTEMPTS, FWDL_CHECKSUM_FAIL, MAX_BASE_HEADER, packets,
                tests::{SYN_A, synthetic},
                tweak_header,
            },
            h2c::{H2C_DESC_SIZE, HEADER_LEN, Sequence},
            model::Chip as Model,
            pci::tests::{Access, Domain, Placement, Source, r32, w16},
            registers::*,
            rtw8852b::{RTL8852B_RFE_05_SPS_ANA, efuse::RFE_TYPE},
        },
        firmware::AxImage,
        identity::tests::observed,
    },
};
use alloc::{format, string::ToString, vec, vec::Vec};
use sha2::{Digest, Sha256};

pub(crate) const CUT: u8 = CHIP_CBV;
pub(crate) const ACV: u8 = 0x2;
pub(crate) const DEVICE: u16 = 0xb852;

/// The synthetic container's suits: cut, type, MP and version. For a CBV
/// rtw89 picks the CE suit of cut 1: not the MP one, not the normal one,
/// and not cut 2's.
const SUITS: [(u8, u8, u8, [u8; 4]); 5] = [
    (0, 5, 0, [0, 29, 29, 10]),
    (1, 1, 0, [0, 29, 29, 17]),
    (1, 5, 0, [0, 29, 29, 18]),
    (1, 5, 1, [0, 29, 29, 99]),
    (2, 5, 0, [0, 29, 30, 0]),
];
const PICKED: usize = 2;

/// [`container_of`] the synthetic suits.
pub(crate) fn container() -> Vec<u8> {
    container_of(&SUITS)
}

/// A container as `rtw89_mfw_recognize` reads it: the header, an entry per
/// suit (cut, type, MP, then the offset and size), and each suit the
/// download's synthetic image A with its own version and commit.
pub(crate) fn container_of(suits: &[(u8, u8, u8, [u8; 4])]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = suits
        .iter()
        .enumerate()
        .map(|(index, &(.., version))| {
            let mut image = synthetic(index as u8, &SYN_A, 16);
            image[4..8].copy_from_slice(&version);
            image
        })
        .collect();
    let mut bytes = vec![0; 16 + 16 * suits.len()];
    bytes[0] = 0xff;
    bytes[1] = suits.len() as u8;
    let mut offset = bytes.len();
    for (index, (&(cut, kind, mp, _), image)) in suits.iter().zip(&images).enumerate() {
        let at = 16 + 16 * index;
        bytes[at..at + 3].copy_from_slice(&[cut, kind, mp]);
        bytes[at + 4..at + 8].copy_from_slice(&(offset as u32).to_le_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&(image.len() as u32).to_le_bytes());
        offset += image.len();
    }
    for image in images {
        bytes.extend_from_slice(&image);
    }
    bytes
}

/// A USB holding `bytes` as the RTL8852B's image, bound to the chip.
pub(crate) fn catalog(bytes: Vec<u8>) -> Catalog {
    let profile = Profile::select(observed(DEVICE, CUT)).unwrap();
    let expected_sha256 = Sha256::digest(&bytes).into();
    Catalog::from_handoff(vec![Resource {
        name: profile.firmware_name(),
        target: profile.chip_target(),
        provenance: Provenance {
            source: "synthetic-test",
            revision: "1",
            member: profile.firmware_name(),
            license: "MIT",
        },
        expected_length: bytes.len(),
        expected_sha256,
        bytes,
    }])
    .unwrap()
}

/// The efuse step's synthetic board (MAC 02:00:00:00:00:01, crystal cap
/// 0x3c, power calibration programmed) with RFE type `rfe`, whose firmware
/// answers the phycap request with [`PHYCAP_OK`].
pub(crate) fn board(rfe: u8) -> Case {
    let mut case = Case::blank(CUT);
    let mut logical = synthetic_logical();
    logical[RFE_TYPE] = rfe;
    case.ddv[..4].copy_from_slice(&[0x00, 0x11, 0x22, 0x33]);
    encode_blocks(&mut case.ddv, 4, &logical);
    program_phycap(&mut case.ddv, 0xaa);
    case
}

/// An observer that records each stage as it begins with the log's length
/// then, keeps the log off from `quiet` on, and, when a stage fails, turns
/// the log back on and reads `probe`.
struct Recorder<'c> {
    chip: &'c Model,
    quiet: Option<Stage>,
    probe: Option<u32>,
    begun: Vec<(Stage, usize)>,
    /// The stage that failed, the log's length then, and what `probe` read.
    failed: Option<(Stage, usize, Option<u32>)>,
}

impl<'c> Recorder<'c> {
    fn new(chip: &'c Model) -> Self {
        Self {
            chip,
            quiet: None,
            probe: None,
            begun: Vec::new(),
            failed: None,
        }
    }
    fn stages(&self) -> Vec<Stage> {
        self.begun.iter().map(|&(stage, _)| stage).collect()
    }
    /// The log's length when `stage` began.
    fn mark(&self, stage: Stage) -> usize {
        self.begun.iter().find(|&&(at, _)| at == stage).unwrap().1
    }
}

impl Observer for Recorder<'_> {
    fn begin(&mut self, stage: Stage) {
        self.begun.push((stage, self.chip.log().len()));
        if self.quiet == Some(stage) {
            self.chip.logging(false);
        }
    }
    fn failed(&mut self, stage: Stage, _error: &Error, io: &mut dyn Io) {
        self.chip.logging(true);
        let at = self.chip.log().len();
        let read = self.probe.map(|register| io.read32(register).unwrap());
        self.failed = Some((stage, at, read));
    }
}

type Outcome<'c> = Result<Stage1<'static, &'c Model>, Failure<'static, &'c Model>>;

/// [`bring_up`] over `chip`, whose DMA reaches `domain`.
#[expect(
    clippy::result_large_err,
    reason = "bring_up's failure, handed back whole"
)]
fn bring<'c>(
    chip: &'c Model,
    domain: &Arc<Domain>,
    firmware: &dyn Provider,
    observed: Observed,
    observer: &mut dyn Observer,
) -> Outcome<'c> {
    let mut config = chip;
    let claim = Claim {
        io: chip,
        source: &Source,
        domain: domain.clone(),
        observed,
    };
    // SAFETY: the model, its DMA domain and these pages belong to this test
    // alone; no device reaches them.
    unsafe { bring_up(claim, &mut config, firmware, observer) }
}

/// A cold chip of `case`'s, brought up without trouble: its report.
fn cold_report(case: &Case, catalog: &Catalog) -> Report {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(case, ACV, domain.clone());
    let stage1 = bring(&chip, &domain, catalog, observed(DEVICE, CUT), &mut ()).unwrap();
    stage1.report
}

/// The log of a twin of `case`'s chip after `rtw89_read_chip_ver`,
/// `rtw89_mac_pwr_on` and `rtw89_mac_pwr_off`, with nothing between.
fn power_cycle(case: &Case) -> Vec<Access> {
    let chip = Model::new(case, ACV, Domain::new(Placement::Oracle));
    let mut io = &chip;
    io.chip_version().unwrap();
    power::power_on(&mut io, &power::Inputs::first(CUT)).unwrap();
    power::power_off(&mut io, &power::Inputs::first(CUT)).unwrap();
    chip.log()
}

fn writes_offmac(access: &Access) -> bool {
    matches!(
        access,
        Access::Write { register: SYS_PW_CTRL, value, .. } if value & APFM_OFFMAC != 0
    )
}

#[test]
fn stage_1_reaches_running_firmware_and_a_read_efuse_in_one_power_cycle() {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let bytes = container();
    let catalog = catalog(bytes.clone());
    let mut recorder = Recorder::new(&chip);
    let mut stage1 = bring(
        &chip,
        &domain,
        &catalog,
        observed(DEVICE, CUT),
        &mut recorder,
    )
    .unwrap();
    assert_eq!(recorder.stages(), Stage::ALL);
    assert_eq!(recorder.failed, None);

    let report = &stage1.report;
    assert_eq!(report.profile.observed(), observed(DEVICE, CUT));
    assert_eq!(
        report.version,
        ChipVersion {
            cut: CUT,
            acv: Some(ACV)
        }
    );
    // A cold chip powers on at the first attempt; its secure-boot bytes are
    // blank.
    assert_eq!(report.powered.first_failure, None);
    assert_eq!(report.powered.secure_efuse, Some(Ok([0xff, 0xff])));
    assert_eq!(report.secure, FwSecure::recognize(Ok([0xff, 0xff])));
    assert!(!report.secure.secure_boot);

    let parsed = Rtw89::parse(&bytes, CUT).unwrap();
    assert_eq!(parsed.selected, PICKED);
    assert_eq!(
        report.firmware,
        Firmware {
            version: [0, 29, 29, 18],
            commit_id: 0x1234_5678 ^ PICKED as u32,
            kind: 5,
            cut: 1,
            packets: packets(&parsed.image),
        }
    );
    assert_eq!(report.firmware.to_string(), "0.29.29.18");
    assert_eq!(report.features, Features::of(ver_code(0, 29, 29, 18)));
    assert_eq!(report.downloaded.packets, report.firmware.packets);
    assert_eq!(report.downloaded.retried, [None; DOWNLOAD_ATTEMPTS - 1]);

    assert_eq!(report.info.efuse.addr, [0x02, 0, 0, 0, 0, 0x01]);
    assert!(report.info.efuse.unicast());
    assert!(report.info.efuse.valid);
    assert_eq!(report.info.efuse.rfe_type, 1);
    assert_eq!(report.info.efuse.xtal_cap, 0x3c);
    assert_eq!(
        report.info.hal,
        Hal {
            tx_nss: 2,
            rx_nss: 2,
            antenna_tx: 0,
            antenna_rx: 0,
            tx_path_diversity: false,
            no_eht: true,
            support_cckpd: true,
            phycap: PHYCAP_OK,
        }
    );
    assert_eq!(
        (stage1.mailbox.h2c_counter(), stage1.mailbox.c2h_counter()),
        (1, 1)
    );
    assert_eq!(stage1.channel.sequence(), Sequence(0));

    // The chip read the picked suit and nothing else: the header with its
    // part size set to 2020, then every section's bytes, part by part.
    let attempts = chip.attempts();
    assert_eq!(attempts.len(), 1);
    let frames = &attempts[0];
    assert_eq!(frames.len(), report.firmware.packets);
    let mut header = [0; MAX_BASE_HEADER];
    let length = tweak_header(&parsed.image, &mut header);
    assert_eq!(frames[0][H2C_DESC_SIZE + HEADER_LEN..], header[..length]);
    let sent: Vec<u8> = frames[1..]
        .iter()
        .flat_map(|frame| frame[H2C_DESC_SIZE..].iter().copied())
        .collect();
    let sections: Vec<u8> = parsed
        .image
        .sections
        .iter()
        .flat_map(|section| section.data.iter().copied())
        .collect();
    assert_eq!(sent, sections);

    // Stage 1 leaves the firmware running for the steps after it; the
    // power-off that closes rtw89_chip_info_setup is the caller's.
    assert!(chip.on());
    let before = chip.log().len();
    assert_eq!(stage1.power_off(), Ok(()));
    assert!(!chip.on());
    let off = &chip.log()[before..];
    assert!(off.iter().any(writes_offmac));
    // RFE 1 takes the power-off's ordinary branch: no SPS_ANA write.
    assert!(!off.iter().any(|access| matches!(
        access,
        Access::Write {
            register: SPS_ANA_ON_CTRL2,
            ..
        }
    )));
}

/// `rtw89_chip_info_setup`'s steps, called one by one on `chip` as each
/// slice's own tests call them: the log's length after each.
fn steps(chip: &Model, domain: &Arc<Domain>, image: &AxImage<'_>) -> Vec<usize> {
    let (mut io, mut config) = (chip, chip);
    let mut rings = Rings::new(&Source, domain.clone()).unwrap();
    let mut channel = Channel::new(&Source, domain.clone());
    let mut marks = Vec::new();
    let version = io.chip_version().unwrap();
    marks.push(chip.log().len());
    let powered = power::power_on(&mut io, &power::Inputs::first(version.cut)).unwrap();
    marks.push(chip.log().len());
    dle::partial_init_before_hci(&mut io).unwrap();
    marks.push(chip.log().len());
    // SAFETY: the model and these rings belong to this test alone; no
    // device reaches them.
    unsafe { pci::mac_pre_init(&mut io, &mut config, &mut rings) }.unwrap();
    marks.push(chip.log().len());
    let secure = FwSecure::recognize(powered.secure_efuse.unwrap());
    let downloaded = fwdl::download(&mut io, &mut rings, &mut channel, image, &secure).unwrap();
    marks.push(chip.log().len());
    let mut mailbox = Mailbox::after_download(&downloaded);
    efuse::info_setup(&mut io, version.cut, &mut mailbox).unwrap();
    marks.push(chip.log().len());
    marks
}

#[test]
fn stage_1_makes_its_steps_accesses_in_rtw89s_order_and_none_between_them() {
    let bytes = container();
    let catalog = catalog(bytes.clone());
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let mut recorder = Recorder::new(&chip);
    bring(
        &chip,
        &domain,
        &catalog,
        observed(DEVICE, CUT),
        &mut recorder,
    )
    .unwrap();

    let twin_domain = Domain::new(Placement::Oracle);
    let twin = Model::new(&board(1), ACV, twin_domain.clone());
    let parsed = Rtw89::parse(&bytes, CUT).unwrap();
    let marks = steps(&twin, &twin_domain, &parsed.image);

    let log = chip.log();
    let reference = twin.log();
    assert_eq!(log.len(), reference.len());
    for (at, (seen, want)) in log.iter().zip(&reference).enumerate() {
        assert_eq!(seen, want, "access {at}");
    }
    // Each stage began where its step's first access is; the identity, the
    // rings, the secure-boot decision and the firmware make none.
    let begun: Vec<usize> = recorder.begun.iter().map(|&(_, at)| at).collect();
    assert_eq!(
        begun,
        [
            0, 0, 0, marks[0], marks[1], marks[1], marks[1], marks[2], marks[3], marks[4]
        ]
    );
    assert_eq!(log.len(), marks[5]);
    // The efuse step ends with the HCI pre-deinit.
    assert!(matches!(
        log.last(),
        Some(Access::Write {
            register: HCI_OPT_CTRL,
            ..
        })
    ));
}

#[test]
fn a_chip_a_previous_boot_left_on_is_powered_off_and_on_again() {
    let domain = Domain::new(Placement::Oracle);
    let case = board(1);
    let chip = Model::new(&case, ACV, domain.clone()).left_on();
    let catalog = catalog(container());
    let mut recorder = Recorder::new(&chip);
    let stage1 = bring(
        &chip,
        &domain,
        &catalog,
        observed(DEVICE, CUT),
        &mut recorder,
    )
    .unwrap();
    assert_eq!(
        stage1.report.powered.first_failure,
        Some(power::Error::AlreadyOn)
    );
    assert!(chip.on());
    // Past the power-on, it is a cold chip's stage 1.
    let mut report = stage1.report.clone();
    report.powered.first_failure = None;
    assert_eq!(report, cold_report(&case, &catalog));

    // rtw89_mac_pwr_on's retry: IC_PWR_STATE reads the WL MAC as on, the
    // chip is powered off, and IC_PWR_STATE reads it off before the
    // power-on proper.
    let log = chip.log();
    let power_on = &log[recorder.mark(Stage::PowerOn)..recorder.mark(Stage::SecureBoot)];
    let states: Vec<Access> = power_on
        .iter()
        .copied()
        .filter(|access| {
            matches!(
                access,
                Access::Read {
                    register: IC_PWR_STATE,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(states, [r32(IC_PWR_STATE, 0x100), r32(IC_PWR_STATE, 0)]);
    assert_eq!(power_on[0], states[0]);
    let offmac = power_on.iter().position(writes_offmac).unwrap();
    let second = power_on.iter().position(|access| *access == states[1]);
    assert!(second.is_some_and(|second| offmac < second));
}

#[test]
fn a_chip_rtw89_would_boot_securely_is_refused_before_its_dma_is_set_up() {
    let domain = Domain::new(Placement::Oracle);
    let mut case = board(1);
    // RTL8852B's own non-COB device type, which the MSS v1 recognizer takes.
    case.ddv[0x5ec..0x5ee].copy_from_slice(&[0xff, 0x6e]);
    let chip = Model::new(&case, ACV, domain.clone());
    let catalog = catalog(container());
    let mut recorder = Recorder::new(&chip);
    let failure = bring(
        &chip,
        &domain,
        &catalog,
        observed(DEVICE, CUT),
        &mut recorder,
    )
    .unwrap_err();
    assert_eq!(failure.stage, Stage::SecureBoot);
    let Error::SecureBoot(secure) = failure.error else {
        panic!("{failure:?}")
    };
    assert!(secure.secure_boot && secure.can_mss_v1);
    assert_eq!(failure.progress.secure, Some(secure));
    assert_eq!(failure.progress.firmware, None);
    assert_eq!(failure.power_off, Some(Ok(())));
    assert_eq!(
        recorder.failed.map(|(stage, ..)| stage),
        Some(Stage::SecureBoot)
    );
    assert!(!chip.on());
    assert!(chip.attempts().is_empty());

    // Nothing between the power-on and the power-off: no DMAC, PCIe or WCPU
    // access, so no ring address was written and the rings, never the
    // chip's, are freed with the failure.
    assert_eq!(chip.log(), power_cycle(&case));
    assert_eq!(failure.rings.as_ref().map(Rings::fwcmd), Some((0, 0)));
    assert!(domain.live() > 0);
    drop(failure);
    assert_eq!(domain.live(), 0);
}

#[test]
fn no_freertos_done_after_five_attempts_powers_the_chip_off_and_keeps_its_rings() {
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone()).statuses(&[FWDL_CHECKSUM_FAIL]);
    let catalog = catalog(container());
    let mut recorder = Recorder::new(&chip);
    // Each attempt polls the status for 400 ms: keep that out of the log.
    recorder.quiet = Some(Stage::Download);
    recorder.probe = Some(WCPU_FW_CTRL);
    let failure = bring(
        &chip,
        &domain,
        &catalog,
        observed(DEVICE, CUT),
        &mut recorder,
    )
    .unwrap_err();
    assert_eq!(failure.stage, Stage::Download);
    let Error::Download(download) = &failure.error else {
        panic!("{failure:?}")
    };
    let fwdl::Failure::Attempts(attempts) = &**download else {
        panic!("{failure:?}")
    };
    for attempt in attempts {
        assert_eq!(attempt.error, fwdl::Error::ChecksumFail);
        let dump = attempt.dump.unwrap().unwrap();
        assert_eq!(
            io::field(dump.wcpu_fw_ctrl, WCPU_FWDL_STS_MASK),
            u32::from(FWDL_CHECKSUM_FAIL)
        );
    }
    // Every attempt sent the whole suit.
    let sent = chip.attempts();
    assert_eq!(sent.len(), DOWNLOAD_ATTEMPTS);
    let packets = failure.progress.firmware.unwrap().packets;
    assert!(sent.iter().all(|frames| frames.len() == packets));
    assert_eq!(failure.progress.downloaded, None);

    // The observer read the chip as the failure left it, then rtw89's out:
    // label powered it off.
    let (stage, at, read) = recorder.failed.unwrap();
    assert_eq!(stage, Stage::Download);
    let read = read.unwrap();
    assert_eq!(
        io::field(read, WCPU_FWDL_STS_MASK),
        u32::from(FWDL_CHECKSUM_FAIL)
    );
    let log = chip.log();
    assert_eq!(log[at], r32(WCPU_FW_CTRL, read));
    assert!(log[at + 1..].iter().any(writes_offmac));
    assert_eq!(failure.power_off, Some(Ok(())));
    assert!(!chip.on());
    assert_eq!(
        failure.to_string(),
        format!("firmware download: {}; powered off", failure.error)
    );

    // The rings and the channel are kept; dropping them unmaps nothing the
    // chip was given.
    assert!(failure.rings.is_some() && failure.channel.is_some());
    let (live, unmaps) = (domain.live(), domain.unmaps());
    drop(failure);
    assert_eq!((domain.live(), domain.unmaps()), (live, unmaps));
}

#[test]
fn an_efuse_step_that_times_out_powers_off_with_the_rfe_type_it_read() {
    let domain = Domain::new(Placement::Oracle);
    let mut case = board(5);
    // The firmware takes the phycap request and never answers it.
    case.c2h = None;
    let chip = Model::new(&case, ACV, domain.clone());
    let catalog = catalog(container());
    let mut recorder = Recorder::new(&chip);
    // C2HREG_CTRL is polled for a second: keep that out of the log.
    recorder.quiet = Some(Stage::Efuse);
    let failure = bring(
        &chip,
        &domain,
        &catalog,
        observed(DEVICE, CUT),
        &mut recorder,
    )
    .unwrap_err();
    assert_eq!(failure.stage, Stage::Efuse);
    assert!(matches!(
        failure.error,
        Error::Efuse(efuse::Error::Io(io::Error::Timeout {
            register: C2HREG_CTRL,
            mask: 0xff
        }))
    ));
    assert!(failure.progress.downloaded.is_some());
    assert_eq!(failure.power_off, Some(Ok(())));
    assert!(!chip.on());
    assert!(failure.rings.is_some());

    // The map was read before the mailbox failed, so the power-off is RFE
    // 5's: SPS_ANA first, as rtw8852b_pwr_sps_ana writes it.
    let (_, at, _) = recorder.failed.unwrap();
    assert_eq!(
        chip.log()[at],
        w16(SPS_ANA_ON_CTRL2, RTL8852B_RFE_05_SPS_ANA.into())
    );
}

#[test]
fn another_chip_or_a_changed_cut_is_refused_before_the_power_on() {
    let catalog = catalog(container());

    // An RTL8822C: nothing is read, allocated or powered.
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let failure = bring(&chip, &domain, &catalog, observed(0xc822, CUT), &mut ()).unwrap_err();
    assert_eq!(failure.stage, Stage::Identity);
    assert!(matches!(
        failure.error,
        Error::NotRtl8852b(super::Chip::Rtl8822C)
    ));
    assert!(chip.log().is_empty());
    assert_eq!(domain.live(), 0);
    assert!(failure.rings.is_none() && failure.channel.is_none());
    assert_eq!(failure.power_off, None);

    // SYS_CFG1 names cut 1 where the boot read cut 2, whose firmware
    // binding was chosen for another chip.
    let domain = Domain::new(Placement::Oracle);
    let chip = Model::new(&board(1), ACV, domain.clone());
    let mut recorder = Recorder::new(&chip);
    let failure = bring(&chip, &domain, &catalog, observed(DEVICE, 2), &mut recorder).unwrap_err();
    assert_eq!(failure.stage, Stage::ChipVersion);
    assert!(matches!(
        failure.error,
        Error::CutChanged {
            observed: 2,
            read: CUT
        }
    ));
    assert_eq!(
        failure.progress.version,
        Some(ChipVersion {
            cut: CUT,
            acv: Some(ACV)
        })
    );
    assert_eq!(failure.power_off, None);
    assert!(!chip.on());
    assert_eq!(recorder.stages(), Stage::ALL[..3]);
    // SYS_CFG1, then the analog cut through XTAL SI, and nothing else.
    let log = chip.log();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0], r32(SYS_CFG1, u32::from(CUT) << 12));
}

#[test]
fn missing_firmware_powers_the_chip_off_again() {
    let domain = Domain::new(Placement::Oracle);
    let case = board(1);
    let chip = Model::new(&case, ACV, domain.clone());
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let failure = bring(&chip, &domain, &empty, observed(DEVICE, CUT), &mut ()).unwrap_err();
    assert_eq!(failure.stage, Stage::Firmware);
    assert!(matches!(
        failure.error,
        Error::Firmware(StageError::Resource(crate::firmware::Error {
            kind: ErrorKind::Missing,
            ..
        }))
    ));
    assert_eq!(failure.power_off, Some(Ok(())));
    assert!(!chip.on());
    assert_eq!(chip.log(), power_cycle(&case));
}
