// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! Stage 1 of an RTL8852BE's bring-up: one claimed function taken from its
//! registers to running firmware and a read efuse in one power cycle, in the
//! order pinned rtw89's probe takes it. [`bring_up`] composes the first
//! slices, each a [`Stage`]:
//!
//! 1. `rtw89_pci_setup_resource` (pci.c), which `rtw89_pci_probe` runs before
//!    `rtw89_chip_info_setup`: `rtw89_pci_alloc_trx_rings` ([`Rings::new`],
//!    every ring below 4 GiB) and `rtw89_pci_h2c_init` ([`Channel::new`]).
//!    Then `rtw89_chip_info_setup` (core.c):
//! 2. `rtw89_read_chip_ver` ([`Registers::chip_version`]): SYS_CFG1's cut and
//!    the analog cut through XTAL SI. The cut must be the one the boot read
//!    before ([`Observed::sys_cfg1`]), which picked the firmware binding.
//! 3. `rtw89_mac_pwr_on` ([`power::power_on`]), with rtw89's state at its
//!    first power-on ([`power::Inputs::first`]): a chip a previous boot left
//!    on fails the first attempt and is powered off and on again. That first
//!    power-on reads the two secure-boot efuse bytes; a chip rtw89 would boot
//!    securely ([`FwSecure::recognize`]) is refused right after it, before
//!    any DMA is set up, where rtw89 goes on to boot it securely.
//! 4. `rtw89_wait_firmware_completion` and `rtw89_fw_recognize`: the image
//!    loaded from the provider and its normal suit picked for the cut, CE
//!    first ([`Profile::stage`]), and the features its version brings
//!    ([`Features::of_image`]).
//! 5. `rtw89_chip_efuse_info_setup`, whose `rtw89_mac_partial_init(rtwdev,
//!    false, false)` is the DMAC pre-init ([`dle::partial_init_before_hci`]),
//!    the PCIe pre-init ([`pci::mac_pre_init`]) and the firmware download
//!    ([`fwdl::download`]), and whose efuse and phycap reads and HCI
//!    pre-deinit ([`efuse::info_setup_into`]) follow over the register
//!    mailbox the download opened ([`Mailbox::after_download`]).
//!
//! The composition makes no access of its own: between the steps rtw89
//! makes none either. `rtw89_wait_firmware_completion` and
//! `rtw89_fw_recognize` only parse, `rtw89_mac_fwdl_preconfig` is NULL in
//! `rtw89_mac_gen_ax`, and nothing runs between `rtw89_mac_pwr_on` and
//! `rtw89_mac_partial_init`. After the efuse, `rtw89_chip_info_setup` runs
//! `rtw89_fw_recognize_elements`, `rtw89_chip_board_info_setup`,
//! `rtw89_chip_data_setup` and `rtw89_core_setup_rfe_parms`, none of which
//! makes an access on an RTL8852B: the elements and RFE tables are parsed
//! from the image, and `fem_setup` and `data_setup` are NULL in
//! `rtw8852b_chip_ops`, so the board info setup does nothing. Those tables
//! are a later step's.
//!
//! A failure keeps what the device may still reach: the register interface
//! with its owner, the rings and the channel whose command buffers they
//! hold ([`Failure`]). Like `rtw89_chip_info_setup`'s `out:` label, a
//! failure after the power-on powers the chip off ([`power::power_off`]), with
//! the RFE type the efuse gave by then; a failure before it, the power-on's
//! included, does not. An [`Observer`] sees each stage begin, and a failure
//! with the chip still as the failure left it.
//!
//! What this leaves out, and why:
//! - `rtw89_chip_info_setup`'s closing `rtw89_mac_pwr_off` on success:
//!   [`Stage1`] keeps the firmware running for the steps after it.
//!   [`Stage1::power_off`] is that power-off, for a caller that stops here.
//!   `__rtw89_leave_ps_mode`, which the power-off reaches while firmware is
//!   ready, makes no access: the chip never entered a low-power mode.
//! - `rtw89_fw_validate_ver_required`, which needs a chip variant: an
//!   RTL8852BE has none, so no firmware version is too old for it. The
//!   WOWLAN suit `rtw89_fw_recognize` also looks for is never downloaded.
//! - `rtw89_pci_basic_cfg`, which `rtw89_pci_probe` runs after
//!   `rtw89_chip_info_setup`: Stela leaves ASPM, CLKREQ and L1SS as the
//!   platform left them ([`pci`]).
//!
//! A stage 1 that returns proves what its steps prove: the polled bits
//! answered, the firmware reported FREERTOS_DONE, every efuse byte was
//! answered and the firmware answered the phycap request. It proves nothing
//! about the radio, that the efuse was programmed, or that the firmware
//! accepts the commands of the steps after it.
use super::{
    super::{
        firmware::{Layout, Rtw89},
        identity::{Chip, IdentityError, Observed, Profile, StageError},
    },
    dle::{self, PreInit},
    efuse::{self, Efuse, Info},
    features::Features,
    fwdl::{self, Downloaded, FwSecure},
    h2c::Channel,
    h2creg::Mailbox,
    io::{self, ChipVersion, Io, Registers},
    pci::{
        self,
        ring::{self, Rings},
    },
    power::{self, PoweredOn},
};
use crate::{
    bus::{
        dma::{mapping::DmaDomain, memory::PageSource},
        pci::ConfigSpace,
    },
    firmware::Provider,
};
use alloc::{boxed::Box, sync::Arc};
use core::fmt;

/// How far stage 1 got: each step of [`bring_up`], in its order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Stage {
    /// The PCI identity and SYS_CFG1 the boot read name an RTL8852B
    /// ([`Profile::select`]). No access.
    Identity,
    /// `rtw89_pci_alloc_trx_rings` and `rtw89_pci_h2c_init`. No access.
    Rings,
    /// `rtw89_read_chip_ver`.
    ChipVersion,
    /// `rtw89_mac_pwr_on`.
    PowerOn,
    /// The secure-boot decision the first power-on's efuse bytes give. No
    /// access.
    SecureBoot,
    /// `rtw89_wait_firmware_completion` and `rtw89_fw_recognize`. No access.
    Firmware,
    /// `rtw89_mac_partial_init` up to `hci.ops->mac_pre_init`.
    DmacPreInit,
    /// `rtw89_pci_ops_mac_pre_init_ax`.
    PciePreInit,
    /// `rtw89_fw_download`.
    Download,
    /// The rest of `rtw89_chip_efuse_info_setup`: efuse, phycap and the
    /// HCI pre-deinit.
    Efuse,
}

impl Stage {
    /// Every stage, in [`bring_up`]'s order.
    pub const ALL: [Self; 10] = [
        Self::Identity,
        Self::Rings,
        Self::ChipVersion,
        Self::PowerOn,
        Self::SecureBoot,
        Self::Firmware,
        Self::DmacPreInit,
        Self::PciePreInit,
        Self::Download,
        Self::Efuse,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Rings => "rings",
            Self::ChipVersion => "chip version",
            Self::PowerOn => "power on",
            Self::SecureBoot => "secure boot",
            Self::Firmware => "firmware",
            Self::DmacPreInit => "dmac pre-init",
            Self::PciePreInit => "pcie pre-init",
            Self::Download => "firmware download",
            Self::Efuse => "efuse",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why stage 1 stopped. Each step's own error says which register, poll or
/// attempt failed.
#[derive(Debug)]
pub enum Error {
    /// [`Profile::select`] refused the observed function.
    Identity(IdentityError),
    /// The observed function is another chip.
    NotRtl8852b(Chip),
    /// A ring could not be allocated, mapped or placed below 4 GiB.
    Rings(ring::Error),
    /// `rtw89_read_chip_ver`'s SYS_CFG1 read was refused.
    ChipVersion(io::Error),
    /// SYS_CFG1 names another cut than the one the boot observed, and so
    /// another firmware binding.
    CutChanged {
        observed: u8,
        read: u8,
    },
    PowerOn(power::Error),
    /// rtw89 would boot this chip securely, which this path does not do.
    SecureBoot(FwSecure),
    /// No image was loaded, or none of its suits suits the cut.
    Firmware(StageError),
    DmacPreInit(dle::Error),
    PciePreInit(pci::Error),
    /// Every attempt's error and the registers read after it, boxed: the
    /// largest of these by far.
    Download(Box<fwdl::Failure>),
    Efuse(efuse::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => write!(f, "{error:?}"),
            Self::NotRtl8852b(chip) => write!(f, "{chip:?} is not an RTL8852B"),
            Self::Rings(error) => write!(f, "{error:?}"),
            Self::ChipVersion(error) => write!(f, "{error:?}"),
            Self::CutChanged { observed, read } => {
                write!(
                    f,
                    "SYS_CFG1 reads cut {read}, where the boot read cut {observed}"
                )
            }
            Self::PowerOn(error) => write!(f, "{error:?}"),
            Self::SecureBoot(secure) => write!(f, "secure boot is on: {secure:?}"),
            Self::Firmware(error) => write!(f, "{error:?}"),
            Self::DmacPreInit(error) => write!(f, "{error:?}"),
            Self::PciePreInit(error) => write!(f, "{error:?}"),
            Self::Download(error) => write!(f, "{error:?}"),
            Self::Efuse(error) => write!(f, "{error:?}"),
        }
    }
}

/// The downloaded suit, as `rtw89_fw_update_ver` and
/// `rtw89_fw_recognize` know it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Firmware {
    /// The header's major, minor, sub-version and sub-index
    /// (`FW_HDR_W1_*`), as rtw89's "Firmware version" line prints them.
    pub version: [u8; 4],
    /// `FW_HDR_W2_COMMITID`.
    pub commit_id: u32,
    /// The suit's `enum rtw89_fw_type`: `RTW89_FW_NORMAL_CE` (5), which
    /// RTL8852B tries first, or `RTW89_FW_NORMAL` (1), which a single
    /// legacy image is.
    pub kind: u8,
    /// The suit's cut (`cv`): the highest that does not pass the chip's.
    pub cut: u8,
    /// The H2C packets a download of it sends: the header and every part
    /// ([`fwdl::packets`]).
    pub packets: usize,
}

impl Firmware {
    /// What `firmware`'s picked suit names.
    pub fn of(firmware: &Rtw89<'_>) -> Self {
        let (kind, cut) = firmware
            .entries
            .get(firmware.selected)
            .map_or((0, 0), |entry| (entry.kind, entry.cut));
        Self {
            version: firmware.image.version,
            commit_id: firmware.image.commit_id,
            kind,
            cut,
            packets: fwdl::packets(&firmware.image),
        }
    }
}

impl fmt::Display for Firmware {
    /// The version, as rtw89 prints it: `0.29.29.18`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, sub, index] = self.version;
        write!(f, "{major}.{minor}.{sub}.{index}")
    }
}

/// What stage 1 learned before it stopped: each field is filled as its
/// stage completes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    pub version: Option<ChipVersion>,
    pub powered: Option<PoweredOn>,
    pub secure: Option<FwSecure>,
    pub firmware: Option<Firmware>,
    pub features: Option<Features>,
    pub downloaded: Option<Downloaded>,
}

/// What a stage 1 that ran to the end learned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub profile: Profile,
    /// The cut and analog cut `rtw89_read_chip_ver` read.
    pub version: ChipVersion,
    /// [`PoweredOn::first_failure`] says why a first attempt failed, as for
    /// a chip a previous boot left on.
    pub powered: PoweredOn,
    pub secure: FwSecure,
    pub firmware: Firmware,
    pub features: Features,
    /// The DLE and flow-control parameters the DMAC pre-init left.
    pub pre_init: PreInit,
    /// The packets the download sent and why earlier attempts failed.
    pub downloaded: Downloaded,
    /// The efuse, phycap and the firmware's NSS and antennas.
    pub info: Info,
}

/// An RTL8852BE whose firmware runs and whose efuse is read, with the
/// state the steps after stage 1 continue from.
pub struct Stage1<'s, I> {
    pub report: Report,
    /// The register interface, which keeps the claim.
    pub io: I,
    /// Every ring, programmed; the chip may reach them while its DMA runs.
    pub rings: Rings,
    /// The H2C channel on CH12, its sequence back at 0 after the download.
    pub channel: Channel<'s>,
    /// The register mailbox, past the phycap exchange.
    pub mailbox: Mailbox,
}

impl<I: Io> Stage1<'_, I> {
    /// The `rtw89_mac_pwr_off` that closes `rtw89_chip_info_setup`, for a
    /// caller that goes no further: the firmware stops and the chip is left
    /// powered off, with this stage's cut and efuse. rtw89 ignores the
    /// result. Nothing here stops the DMA first, as in rtw89: keep
    /// [`Self::rings`] afterwards, or drop them, which keeps their memory
    /// for good.
    pub fn power_off(&mut self) -> Result<(), power::Error> {
        power::power_off(
            &mut self.io,
            &power_inputs(self.report.version.cut, &self.report.info.efuse),
        )
    }
}

impl<I> fmt::Debug for Stage1<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stage1")
            .field("report", &self.report)
            .field("mailbox", &self.mailbox)
            .finish_non_exhaustive()
    }
}

/// Why stage 1 stopped, with everything the device may still reach.
pub struct Failure<'s, I> {
    pub stage: Stage,
    pub error: Error,
    pub progress: Progress,
    /// What powering the chip off gave, or `None` when the failure came
    /// before the chip was powered on, where rtw89 powers nothing off.
    pub power_off: Option<Result<(), power::Error>>,
    /// The register interface, which keeps the claim.
    pub io: I,
    /// The rings, once allocated. From the PCIe pre-init on the chip may
    /// reach them; dropping them keeps their memory for good.
    pub rings: Option<Rings>,
    /// The H2C channel, once the rings are allocated.
    pub channel: Option<Channel<'s>>,
}

impl<I> fmt::Debug for Failure<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failure")
            .field("stage", &self.stage)
            .field("error", &self.error)
            .field("progress", &self.progress)
            .field("power_off", &self.power_off)
            .finish_non_exhaustive()
    }
}

impl<I> fmt::Display for Failure<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.error)?;
        match &self.power_off {
            None => Ok(()),
            Some(Ok(())) => f.write_str("; powered off"),
            Some(Err(error)) => write!(f, "; powering off failed: {error:?}"),
        }
    }
}

/// What a caller sees of stage 1 as it runs, as for a log. Both methods do
/// nothing by default.
pub trait Observer {
    /// `stage` begins.
    fn begin(&mut self, _stage: Stage) {}
    /// `stage` failed with `error`. The chip is as the failure left it, not
    /// yet powered off, and `io` reaches it, so its registers can be read
    /// for the log.
    fn failed(&mut self, _stage: Stage, _error: &Error, _io: &mut dyn Io) {}
}

impl Observer for () {}

/// The claimed function and the services stage 1 borrows.
pub struct Claim<'s, I> {
    /// BAR2's registers ([`super::io::NativeIo`] in the boot), which keep
    /// the claim and the mapping.
    pub io: I,
    /// Coherent write-back RAM for the rings and command buffers.
    pub source: &'s dyn PageSource,
    /// The function's DMA domain.
    pub domain: Arc<dyn DmaDomain>,
    /// What the boot read of the function before any driver powered it.
    pub observed: Observed,
}

/// `rtw89_chip_info_setup` on a PCIe RTL8852B up to its efuse, with
/// `rtw89_pci_setup_resource`'s rings before it, and the firmware left
/// running. `config` is the function's configuration space and `firmware`
/// gives its image.
///
/// # Safety
/// `claim.io` reaches the exclusive uncached BAR2 of the RTL8852B function
/// `claim.observed` describes, and `config` that function's configuration
/// space, with memory decoding and bus mastering on and its DMA and
/// interrupts quiet; no other worker resets or programs the function
/// meanwhile. `claim.domain` isolates that requester, and `claim.source` is
/// coherent write-back RAM. From the PCIe pre-init on, the chip may read
/// every ring and command buffer and write every RX buffer whenever its DMA
/// runs: the caller keeps what [`Stage1`] or [`Failure`] hands back for as
/// long as that may happen.
#[expect(
    clippy::result_large_err,
    reason = "a failure hands back the owners the device may still reach and what stage 1 learned"
)]
pub unsafe fn bring_up<'s, I: Io, C: ConfigSpace + ?Sized>(
    claim: Claim<'s, I>,
    config: &mut C,
    firmware: &dyn Provider,
    observer: &mut dyn Observer,
) -> Result<Stage1<'s, I>, Failure<'s, I>> {
    let Claim {
        io,
        source,
        domain,
        observed,
    } = claim;
    observer.begin(Stage::Identity);
    let profile = match identify(observed) {
        Ok(profile) => profile,
        Err(error) => return Err(unpowered(observer, Stage::Identity, error, io)),
    };
    observer.begin(Stage::Rings);
    let rings = match Rings::new(source, domain.clone()) {
        Ok(rings) => rings,
        Err(error) => return Err(unpowered(observer, Stage::Rings, Error::Rings(error), io)),
    };
    let mut held = Held {
        io,
        rings,
        channel: Channel::new(source, domain),
        stage: Stage::Rings,
        progress: Progress::default(),
        powered: None,
        info: Info::probe(),
    };
    // SAFETY: the caller's contract, for the same function, rings and
    // channel.
    match unsafe { chip_info_setup(&mut held, config, profile, firmware, observer) } {
        Ok(done) => {
            let Held {
                io,
                rings,
                channel,
                info,
                ..
            } = held;
            Ok(Stage1 {
                report: Report {
                    profile,
                    version: done.version,
                    powered: done.powered,
                    secure: done.secure,
                    firmware: done.firmware,
                    features: done.features,
                    pre_init: done.pre_init,
                    downloaded: done.downloaded,
                    info,
                },
                io,
                rings,
                channel,
                mailbox: done.mailbox,
            })
        }
        Err(error) => Err(held.fail(observer, error)),
    }
}

/// What the function's state holds while stage 1 runs, and a failure keeps.
struct Held<'s, I> {
    io: I,
    rings: Rings,
    channel: Channel<'s>,
    /// The stage that began last.
    stage: Stage,
    progress: Progress,
    /// The cut the power-on was given, once it succeeded.
    powered: Option<u8>,
    /// `rtwdev->efuse` and the rest the efuse step fills.
    info: Info,
}

impl<'s, I: Io> Held<'s, I> {
    /// `rtw89_chip_info_setup`'s `out:` label after `error` in the stage
    /// that began last: the observer, then the power-off once the chip was
    /// powered on.
    fn fail(mut self, observer: &mut dyn Observer, error: Error) -> Failure<'s, I> {
        let stage = self.stage;
        observer.failed(stage, &error, &mut self.io);
        let power_off = self
            .powered
            .map(|cut| power::power_off(&mut self.io, &power_inputs(cut, &self.info.efuse)));
        Failure {
            stage,
            error,
            progress: self.progress,
            power_off,
            io: self.io,
            rings: Some(self.rings),
            channel: Some(self.channel),
        }
    }
}

/// What a successful [`chip_info_setup`] read, besides the efuse.
struct Done {
    version: ChipVersion,
    powered: PoweredOn,
    secure: FwSecure,
    firmware: Firmware,
    features: Features,
    pre_init: PreInit,
    downloaded: Downloaded,
    mailbox: Mailbox,
}

/// A failure before any ring exists or the chip was powered on.
fn unpowered<'s, I: Io>(
    observer: &mut dyn Observer,
    stage: Stage,
    error: Error,
    mut io: I,
) -> Failure<'s, I> {
    observer.failed(stage, &error, &mut io);
    Failure {
        stage,
        error,
        progress: Progress::default(),
        power_off: None,
        io,
        rings: None,
        channel: None,
    }
}

/// The RTL8852B the boot observed.
fn identify(observed: Observed) -> Result<Profile, Error> {
    let profile = Profile::select(observed).map_err(Error::Identity)?;
    match profile.chip() {
        Chip::Rtl8852B => Ok(profile),
        chip => Err(Error::NotRtl8852b(chip)),
    }
}

/// What `rtw89_mac_pwr_off` reads of rtw89's state at
/// `rtw89_chip_info_setup`'s `out:` label: the cut, and what the efuse step
/// had read by then, which is nothing before it. Probe is not done.
fn power_inputs(cut: u8, efuse: &Efuse) -> power::Inputs {
    power::Inputs {
        cut,
        rfe_type: efuse.rfe_type,
        efuse_valid: efuse.valid,
        power_k_valid: efuse.power_k_valid,
        probe_done: false,
    }
}

/// `rtw89_chip_info_setup` from `rtw89_read_chip_ver` through
/// `rtw89_chip_efuse_info_setup`, recording in `held` what each stage learns.
///
/// # Safety
/// [`bring_up`]'s contract, for `held`'s interface, rings and channel.
unsafe fn chip_info_setup<I: Io, C: ConfigSpace + ?Sized>(
    held: &mut Held<'_, I>,
    config: &mut C,
    profile: Profile,
    firmware: &dyn Provider,
    observer: &mut dyn Observer,
) -> Result<Done, Error> {
    let Held {
        io,
        rings,
        channel,
        stage,
        progress,
        powered,
        info,
    } = held;
    let mut begin = |next: Stage| {
        *stage = next;
        observer.begin(next);
    };

    begin(Stage::ChipVersion);
    let version = io.chip_version().map_err(Error::ChipVersion)?;
    progress.version = Some(version);
    if version.cut != profile.cut() {
        return Err(Error::CutChanged {
            observed: profile.cut(),
            read: version.cut,
        });
    }

    begin(Stage::PowerOn);
    let powered_on =
        power::power_on(io, &power::Inputs::first(version.cut)).map_err(Error::PowerOn)?;
    *powered = Some(version.cut);
    progress.powered = Some(powered_on);

    begin(Stage::SecureBoot);
    // The first power-on always reads the bytes; without them rtw89 keeps
    // secure boot off.
    let secure = powered_on
        .secure_efuse
        .map_or_else(FwSecure::default, FwSecure::recognize);
    progress.secure = Some(secure);
    if secure.secure_boot {
        return Err(Error::SecureBoot(secure));
    }

    begin(Stage::Firmware);
    let staged = profile.stage(firmware).map_err(Error::Firmware)?;
    let Layout::Rtw89(suit) = &staged.layout else {
        return Err(Error::NotRtl8852b(profile.chip()));
    };
    let summary = Firmware::of(suit);
    progress.firmware = Some(summary);
    let features = Features::of_image(&suit.image);
    progress.features = Some(features);

    begin(Stage::DmacPreInit);
    let pre_init = dle::partial_init_before_hci(io).map_err(Error::DmacPreInit)?;

    begin(Stage::PciePreInit);
    // SAFETY: the caller's contract: `io` and `config` reach the one
    // function whose DMA domain `rings` was allocated in, and the caller
    // keeps `rings` while the chip may reach them.
    unsafe { pci::mac_pre_init(io, config, rings) }.map_err(Error::PciePreInit)?;

    begin(Stage::Download);
    let downloaded = fwdl::download(io, rings, channel, &suit.image, &secure)
        .map_err(|failure| Error::Download(Box::new(failure)))?;
    progress.downloaded = Some(downloaded);
    let mut mailbox = Mailbox::after_download(&downloaded);

    begin(Stage::Efuse);
    efuse::info_setup_into(io, version.cut, &mut mailbox, info).map_err(Error::Efuse)?;

    Ok(Done {
        version,
        powered: powered_on,
        secure,
        firmware: summary,
        features,
        pre_init,
        downloaded,
        mailbox,
    })
}

#[cfg(test)]
pub(super) mod tests;
