// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! One RTL8852BE a boot given a `--wifi` network finds, taken from its
//! registers to a kept station: stage 1 ([`bootstrap`]) and the power-off
//! that closes `rtw89_chip_info_setup` at probe, then the interface coming
//! up as rtw89 brings it up ([`Hardware::start`]) under the softMAC station
//! ([`Realtek`]) that the connection keeper keeps joined to the network.
//! For the Wi-Fi check, a listen comes between them: stage 2 ([`radio`])
//! tunes one channel, listens for a while, and powers the chip off again,
//! and the station's start powers it on afresh.
//!
//! [`admit`] decides before any access whether the chip may be powered on:
//! the read before power-on answered, and the image holds a suit for the
//! cut. linux-firmware's RTL8852B container holds suits for cuts 1 and 2,
//! and rtw89 takes the newest suit whose cut is not above the chip's, so a
//! CAV has none and is never powered on. [`quiesce`] is the stop a cold
//! requester's preparation needs before it allows bus mastering: the WL
//! MAC, which holds the DMAC and the PCIe DMA, off, as a chip a previous boot
//! left on is made by the power-off `rtw89_mac_pwr_on`'s retry makes, here
//! before the claim rather than in the power-on. [`run`] is stage 1, timing each
//! stage and, when one fails, reading the registers that say where the chip
//! stood ([`Read`]) before rtw89's power-off; once stage 1 reached the
//! efuse, it is the power-off that closes `rtw89_chip_info_setup`, and the
//! listen, when asked, and the station follow on the chip that power-off
//! left cold. The station transmits, so it starts only with the network's
//! regulation ([`Join`]); without it the chip stays off.
//!
//! What the boot learned is an [`Outcome`]: [`Outcome::lines`] for its log,
//! [`Outcome::summary`] for the Wi-Fi check, [`Outcome::unattached`] for the
//! probe's account of a chip that runs no station. What the device may
//! still reach afterwards is [`Kept`], for the rest of the boot: the
//! station, or the register interface with its owner, the rings and the
//! H2C channel.
//!
//! What an outcome proves is what each stage proves ([`bootstrap`],
//! [`radio`], [`Hardware::start`]): the firmware reported FREERTOS_DONE,
//! every efuse byte was answered, the listen counted what RXQ held, and the
//! station's interface came up; a beacon with a BSSID proves the radio
//! receives, and only the keeper's association proves it transmits.
use super::{
    super::{
        firmware::ParseError,
        identity::{self, Chip, IdentityError, Observed, Profile, StageError, Unpowered},
        station::{Realtek, Wifi},
    },
    bootstrap::{self, Claim, Failure, Firmware, Observer, Progress, Report, Stage, Stage1},
    fwdl::{self, Attempt, Downloaded, FwSecure},
    h2c::Channel,
    h2creg::Mailbox,
    hardware::{self, Hardware, Settings},
    io::{self, Io, Registers},
    listen::{Bss, Counts, Heard},
    pci::ring::Rings,
    power, radio,
    registers::*,
};
use crate::{
    Clock, Mac,
    bus::{
        dma::{mapping::DmaDomain, memory::PageSource},
        pci::ConfigSpace,
    },
    firmware::Provider,
    wifi::{network::Network, regulatory::database::Country},
};
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt;
use stela_driver_base::entropy::Entropy;

/// Why the chip was left as it was, before stage 1 began.
#[derive(Debug)]
pub enum Refusal {
    /// SYS_CFG1 read as all ones or `RTW89_R32_DEAD`: the function did not
    /// answer, so it has no cut.
    NoAnswer(u32),
    /// [`Profile::select`] refused the function, or it is no RTL8852B.
    Identity(IdentityError),
    /// The image is missing, or holds no suit for the cut.
    Firmware(StageError),
    /// BAR2 or the clock cannot carry the register interface
    /// ([`super::io::NativeIo::new`]).
    Window(io::Error),
    /// The WL MAC read on and stayed on after the power-off ([`quiesce`]),
    /// or reading it or powering it off failed: its DMA may still run, so
    /// bus mastering was never allowed.
    Quiesce(Option<power::Error>),
}

impl Refusal {
    /// The stage it stands for.
    pub fn stage(&self) -> Stage {
        match self {
            Self::Firmware(_) => Stage::Firmware,
            Self::Quiesce(_) => Stage::PowerOn,
            Self::NoAnswer(_) | Self::Identity(_) | Self::Window(_) => Stage::Identity,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAnswer(word) => write!(
                f,
                "SYS_CFG1 read {word:#010x}: the function did not answer, so it has no cut"
            ),
            Self::Identity(error) => write!(f, "rtw89 takes no such function: {error:?}"),
            Self::Firmware(StageError::Format(ParseError::NoCompatibleFirmware { cut })) => {
                write!(
                    f,
                    "the firmware image holds no suit for {}, so rtw89 would have nothing to download",
                    cut_name(*cut)
                )
            }
            Self::Firmware(StageError::Resource(error)) => error.fmt(f),
            Self::Firmware(StageError::Format(error)) => {
                write!(f, "the firmware image cannot be read: {error:?}")
            }
            Self::Window(error) => write!(f, "BAR2 cannot carry the registers: {error:?}"),
            Self::Quiesce(None) => f.write_str(
                "its WL MAC read on and stayed on after the power-off, so its DMA may still run \
                 and bus mastering stays off",
            ),
            Self::Quiesce(Some(error)) => write!(
                f,
                "reading or powering off its WL MAC failed ({error:?}), so its DMA may still run \
                 and bus mastering stays off"
            ),
        }
    }
}

/// Whether stage 1 may power on the chip `unpowered` describes, decided
/// without any access: the read before power-on answered, the function is an
/// RTL8852B, and `firmware` gives an image with a suit for its cut.
pub fn admit(unpowered: &Unpowered, firmware: &dyn Provider) -> Result<(), Refusal> {
    if unpowered.cut().is_none() {
        return Err(Refusal::NoAnswer(unpowered.observed.sys_cfg1));
    }
    let profile = Profile::select(unpowered.observed).map_err(Refusal::Identity)?;
    if profile.chip() != Chip::Rtl8852B {
        return Err(Refusal::Identity(IdentityError::UnsupportedPci));
    }
    profile
        .stage(firmware)
        .map(|_| ())
        .map_err(Refusal::Firmware)
}

/// How [`quiesce`] found the chip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Found {
    /// The WL MAC read off.
    Off,
    /// The WL MAC read on, as a previous boot can leave it, and was powered
    /// off.
    PoweredOff,
}

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "found off",
            Self::PoweredOff => {
                "found on, as a previous boot can leave it, and powered off before bus mastering"
            }
        })
    }
}

/// Whether IC_PWR_STATE reads the WL MAC as on, as
/// `rtw89_mac_reset_pwr_state_ax` reads it.
fn mac_on<I: Io + ?Sized>(io: &mut I) -> Result<bool, io::Error> {
    // rtw89 keeps the field in a u8.
    let state = io.read32_mask(IC_PWR_STATE, WLMAC_PWR_STE_MASK)? as u8;
    Ok(u32::from(state) == MAC_AX_MAC_ON)
}

/// Stop a chip of cut `cut` before its requester is allowed bus mastering:
/// a WL MAC that reads off holds no running DMAC or PCIe DMA; one that reads
/// on is powered off as `rtw89_mac_pwr_off` powers it off, with rtw89's
/// state at its first power-on, and must then read off. Register accesses
/// alone, with bus mastering off.
pub fn quiesce<I: Io + ?Sized>(io: &mut I, cut: u8) -> Result<Found, Refusal> {
    let read =
        |io: &mut I| mac_on(io).map_err(|error| Refusal::Quiesce(Some(power::Error::Io(error))));
    if !read(io)? {
        return Ok(Found::Off);
    }
    power::power_off(io, &power::Inputs::first(cut))
        .map_err(|error| Refusal::Quiesce(Some(error)))?;
    if read(io)? {
        return Err(Refusal::Quiesce(None));
    }
    Ok(Found::PoweredOff)
}

/// What the attach borrows of the machine.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    pub firmware: &'a dyn Provider,
    /// The rings' and frames' memory, which the station keeps for the boot.
    pub pages: &'static dyn PageSource,
    /// The clock the stages are timed by, and the station runs on.
    pub clock: Clock,
}

/// What the station takes beside the chip.
pub struct Join {
    /// The network the keeper joins.
    pub network: Network,
    /// regulatory.db's rules for the network's country, or the world's
    /// (`00`) when it names none, which the station's channels and TX
    /// power follow.
    pub country: Country,
    /// The source of each handshake's SNonce.
    pub entropy: Arc<dyn Entropy>,
    /// An MSI the caller routed raises the function's causes.
    pub vector: bool,
}

/// When each stage began, from stage 1's start.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timings {
    /// Microseconds to each stage's beginning, in [`Stage::ALL`]'s order:
    /// `None` for a stage not begun, or a clock that does not count.
    pub begun: [Option<u64>; Stage::ALL.len()],
    /// Microseconds to stage 1's end: its return, or its failure.
    pub ended: Option<u64>,
}

impl Timings {
    /// How long `stage` took: from its beginning to the next stage's, or
    /// to the end.
    pub fn took(&self, stage: Stage) -> Option<u64> {
        let index = position(stage);
        let start = self.begun[index]?;
        let end = self.begun[index + 1..]
            .iter()
            .find_map(|at| *at)
            .or(self.ended)?;
        end.checked_sub(start)
    }
}

fn position(stage: Stage) -> usize {
    Stage::ALL
        .iter()
        .position(|&each| each == stage)
        .unwrap_or_default()
}

/// A register read for the log when a stage failed, before the power-off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Read {
    pub name: &'static str,
    pub register: u32,
    pub value: Result<u32, io::Error>,
}

/// Read whenever a stage fails: the power sequencer's and the WCPU's
/// state, in the block that stays on.
const ALWAYS_ON: [(&str, u32); 4] = [
    ("SYS_PW_CTRL", SYS_PW_CTRL),
    ("IC_PWR_STATE", IC_PWR_STATE),
    ("PLATFORM_ENABLE", PLATFORM_ENABLE),
    ("WCPU_FW_CTRL", WCPU_FW_CTRL),
];

/// Read as well once the chip was powered on: the HCI's and DMAC's
/// enables, the PCIe DMA's stop bits, CH12's host and hardware indices and
/// the firmware's boot step.
const POWERED: [(&str, u32); 5] = [
    ("HCI_FUNC_EN", HCI_FUNC_EN),
    ("DMAC_FUNC_EN", DMAC_FUNC_EN),
    ("PCIE_DMA_STOP1", PCIE_DMA_STOP1),
    ("CH12_TXBD_IDX", CH12_TXBD_IDX),
    ("BOOT_DBG", BOOT_DBG),
];

/// Times each stage and, when one fails, reads [`ALWAYS_ON`], and
/// [`POWERED`] past the power-on.
struct Watch {
    clock: Clock,
    start: Option<u64>,
    timings: Timings,
    registers: Vec<Read>,
}

impl Watch {
    fn new(clock: Clock) -> Self {
        Self {
            clock,
            start: clock.try_start().ok(),
            timings: Timings::default(),
            registers: Vec::new(),
        }
    }

    fn now(&self) -> Option<u64> {
        self.start
            .and_then(|start| self.clock.try_elapsed_us(start).ok())
    }
}

impl Observer for Watch {
    fn begin(&mut self, stage: Stage) {
        self.timings.begun[position(stage)] = self.now();
    }

    fn failed(&mut self, stage: Stage, _error: &bootstrap::Error, io: &mut dyn Io) {
        self.timings.ended = self.now();
        let powered: &[(&str, u32)] = if stage > Stage::PowerOn {
            &POWERED
        } else {
            &[]
        };
        self.registers = ALWAYS_ON
            .iter()
            .chain(powered)
            .map(|&(name, register)| Read {
                name,
                register,
                value: io.read32(register),
            })
            .collect();
    }
}

/// What the boot learned of one RTL8852BE.
#[derive(Debug)]
pub enum Outcome {
    /// Stage 1 did not begin: the chip was left as it was, or as a failed
    /// [`quiesce`] left it, with bus mastering off.
    Refused(Refusal),
    /// Stage 1 reached the efuse, then the chip was powered off; the listen
    /// and the station followed.
    Reached {
        found: Found,
        report: Box<Report>,
        /// The register mailbox's counters, past the phycap exchange.
        mailbox: Mailbox,
        timings: Timings,
        power_off: Result<(), power::Error>,
        /// Stage 2's listen, when the boot asked for one and stage 1's
        /// power-off left the chip cold.
        radio: Option<Box<radio::Outcome>>,
        /// The station's start.
        station: Started,
    },
    /// Stage 1 stopped at `stage`, and the chip was powered off where
    /// rtw89 powers it off.
    Stopped {
        found: Found,
        stage: Stage,
        error: bootstrap::Error,
        /// What stage 1 learned first, boxed: the largest part by far.
        progress: Box<Progress>,
        /// The registers read before the power-off.
        registers: Vec<Read>,
        timings: Timings,
        /// `None` when the failure came before the chip was powered on.
        power_off: Option<Result<(), power::Error>>,
    },
}

/// How the station's start went, once stage 1 reached the efuse.
#[derive(Debug)]
pub enum Started {
    /// The interface came up ([`Hardware::start`]) and the keeper keeps the
    /// station joined to the network; `vector` when an MSI signals it.
    Up { vector: bool },
    /// No start was tried, and why: no regulation or entropy for it, an
    /// address no station takes, or a power-off before it that failed. The
    /// chip stays as that power-off left it.
    NotTried(String),
    /// The interface's coming up stopped, or the station refused it.
    Stopped {
        error: String,
        /// What the bring-up learned before it stopped.
        report: Box<radio::Report>,
        /// The closing power-off, `None` when the chip was never powered on.
        power_off: Option<Result<(), power::Error>>,
    },
}

/// What the device may still reach after the attach, for the rest of the
/// boot.
#[expect(
    clippy::large_enum_variant,
    reason = "made once per attach and moved straight to its keeper"
)]
pub enum Kept<I: Io> {
    /// The station, which holds the register interface with its owner, the
    /// rings and the channel.
    Station(Box<Wifi<Hardware<I>>>),
    /// The register interface with its owner, and the rings and channel
    /// once allocated.
    Owners {
        io: I,
        rings: Option<Rings>,
        channel: Option<Channel<'static>>,
    },
    /// Nothing: the station refused the hardware it was given, which went
    /// with it, its rings' memory kept for good as a dropped ring's is.
    Released,
}

/// Stage 1, then the power-off that closes `rtw89_chip_info_setup`, then
/// stage 2's listen when `plan` asks for one ([`radio::run`]), then the
/// station's start for `join` ([`Hardware::start`], [`Realtek::keep`]), for a
/// chip [`admit`] admitted and [`quiesce`] found as `found`.
///
/// # Safety
/// [`bootstrap::bring_up`]'s contract holds for `io`, `config`, `domain`,
/// `observed` and `inputs.pages`, `join.vector` says the function raises a
/// routed MSI, and the caller keeps what [`Kept`] holds for the rest of the
/// boot: the chip may reach its rings until then.
#[expect(
    clippy::too_many_arguments,
    reason = "the claim's parts, the listen's plan and the station's network"
)]
pub unsafe fn run<I: Io, C: ConfigSpace + ?Sized>(
    io: I,
    config: &mut C,
    domain: Arc<dyn DmaDomain>,
    observed: Observed,
    found: Found,
    inputs: &Inputs<'_>,
    plan: Option<&radio::Plan<'_>>,
    join: Result<Join, String>,
) -> (Outcome, Kept<I>) {
    let mut watch = Watch::new(inputs.clock);
    let claim = Claim {
        io,
        source: inputs.pages,
        domain: domain.clone(),
        observed,
    };
    // SAFETY: forwarded from the caller.
    match unsafe { bootstrap::bring_up(claim, config, inputs.firmware, &mut watch) } {
        Ok(mut stage1) => {
            watch.timings.ended = watch.now();
            let power_off = stage1.power_off();
            let radio = match (&power_off, plan) {
                (Ok(()), Some(plan)) => {
                    let Stage1 {
                        report,
                        io,
                        rings,
                        channel,
                        ..
                    } = &mut stage1;
                    let held = radio::Held { io, rings, channel };
                    // SAFETY: forwarded from the caller, for the function
                    // stage 1 brought up, its rings and channel, its DMA
                    // stopped by the power-off; `rings` stays kept below.
                    Some(Box::new(unsafe {
                        radio::run(held, config, report, inputs.firmware, plan, &mut ())
                    }))
                }
                _ => None,
            };
            let report = Box::new(stage1.report.clone());
            let mailbox = stage1.mailbox;
            // The station starts on a chip the last power-off left cold.
            let cold = match (&power_off, radio.as_deref().map(|radio| &radio.power_off)) {
                (Err(error), _) => Err(format!("powering it off after stage 1 failed ({error:?})")),
                (Ok(()), Some(Some(Err(error)))) => Err(format!(
                    "powering it off after stage 2's listen failed ({error:?})"
                )),
                (Ok(()), _) => Ok(()),
            };
            let address = Mac(report.info.efuse.addr);
            let ready = cold.and(join).and_then(|join| {
                if address.is_multicast() || address.0 == [0; 6] {
                    Err(format!(
                        "the efuse's address {} is no station's",
                        Masked(&address.0)
                    ))
                } else {
                    Ok(join)
                }
            });
            let (station, kept) = match ready {
                Err(why) => {
                    let Stage1 {
                        io, rings, channel, ..
                    } = stage1;
                    let kept = Kept::Owners {
                        io,
                        rings: Some(rings),
                        channel: Some(channel),
                    };
                    (Started::NotTried(why), kept)
                }
                // SAFETY: forwarded from the caller: the function stage 1
                // brought up, its rings and channel, its DMA stopped by the
                // last power-off; `pages` and `domain` are the claim's.
                Ok(join) => unsafe { start(stage1, config, domain, inputs, join) },
            };
            let outcome = Outcome::Reached {
                found,
                report,
                mailbox,
                timings: watch.timings,
                power_off,
                radio,
                station,
            };
            (outcome, kept)
        }
        Err(failure) => {
            let Failure {
                stage,
                error,
                progress,
                power_off,
                io,
                rings,
                channel,
            } = failure;
            let outcome = Outcome::Stopped {
                found,
                stage,
                error,
                progress: Box::new(progress),
                registers: watch.registers,
                timings: watch.timings,
                power_off,
            };
            (outcome, Kept::Owners { io, rings, channel })
        }
    }
}

/// The station on the chip stage 1 brought up and a power-off left cold:
/// the interface coming up ([`Hardware::start`]), then the softMAC station
/// the keeper keeps joined to `join.network`.
///
/// # Safety
/// [`Hardware::start`]'s contract holds for `stage1`, `config`, `domain`
/// and `inputs.pages`, and `join.vector` says the function raises a routed
/// MSI.
unsafe fn start<I: Io, C: ConfigSpace + ?Sized>(
    stage1: Stage1<'static, I>,
    config: &mut C,
    domain: Arc<dyn DmaDomain>,
    inputs: &Inputs<'_>,
    join: Join,
) -> (Started, Kept<I>) {
    let settings = Settings {
        alpha2: join.network.country,
        vector: join.vector,
    };
    // SAFETY: forwarded from the caller.
    let hardware = match unsafe {
        Hardware::start(
            stage1,
            inputs.pages,
            domain,
            config,
            inputs.firmware,
            &settings,
        )
    } {
        Ok(hardware) => hardware,
        Err(failure) => {
            let hardware::Failure {
                error,
                report,
                power_off,
                io,
                rings,
                channel,
            } = *failure;
            let started = Started::Stopped {
                error: error.to_string(),
                report,
                power_off,
            };
            let kept = Kept::Owners {
                io,
                rings: Some(rings),
                channel: Some(channel),
            };
            return (started, kept);
        }
    };
    let address = hardware.address();
    let vector = hardware.vector();
    // The address was checked as `Station::new` and `Scanner::new` check
    // it, so the station takes the hardware.
    match Realtek::new(hardware, address, join.country, inputs.clock) {
        Ok(radio) => (
            Started::Up { vector },
            Kept::Station(Box::new(radio.keep(join.network, join.entropy))),
        ),
        Err(error) => (
            Started::Stopped {
                error: format!("station: {error}"),
                report: Box::default(),
                power_off: None,
            },
            Kept::Released,
        ),
    }
}

/// What the Wi-Fi check reports of one RTL8852BE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    /// The firmware stage, once the download ended with FREERTOS_DONE.
    pub firmware: Option<FirmwareRan>,
    /// The efuse stage, once it completed.
    pub efuse: Option<EfuseRead>,
    /// The stage stage 1 stopped at, or was refused before, and why.
    pub stopped: Option<(Stage, String)>,
    /// Stage 2's listen, once it ran.
    pub radio: Option<RadioRan>,
    /// The station's start, once stage 1 reached the efuse.
    pub station: Option<StationRan>,
}

/// How the station's start went, for the Wi-Fi check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StationRan {
    /// The interface came up and the keeper joins the network; `vector`
    /// when an MSI signals it.
    Up { vector: bool },
    /// No station runs, and why.
    Down(String),
}

/// What stage 2 gave the Wi-Fi check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadioRan {
    /// The primary channel, the center and the width in MHz.
    pub primary: u8,
    pub center: u8,
    pub width: u16,
    /// What the listen heard, once it ran.
    pub heard: Option<Heard>,
    /// What RXQ held before the listen.
    pub before: Heard,
    /// The stage stage 2 stopped at, and why.
    pub stopped: Option<(radio::Stage, String)>,
    /// What rtw89 only logs or ignores, one line each.
    pub warnings: Vec<String>,
    /// The closing power-off; `None` when the chip was never powered on.
    pub power_off: Option<Result<(), power::Error>>,
}

impl RadioRan {
    fn of(outcome: &radio::Outcome) -> Self {
        let channel = outcome.channel;
        Self {
            primary: channel.primary(),
            center: channel.center(),
            width: channel.width_mhz(),
            heard: outcome.report.heard.clone(),
            before: outcome.report.before.clone(),
            stopped: outcome
                .stopped
                .as_ref()
                .map(|(stage, error)| (*stage, error.to_string())),
            warnings: outcome.report.warnings(),
            power_off: outcome.power_off,
        }
    }
}

/// The firmware that ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareRan {
    /// Major, minor, sub-version and sub-index.
    pub version: [u8; 4],
    /// `enum rtw89_fw_type`.
    pub kind: u8,
    /// The cut of the suit downloaded.
    pub image_cut: u8,
    /// The H2C packets of the attempt that ran: the header and every part.
    pub packets: usize,
    /// The attempts that failed before it.
    pub retries: usize,
    /// From the download's start to FREERTOS_DONE, every attempt included.
    pub freertos_done_us: Option<u64>,
    pub secure_boot: bool,
}

/// What the efuse read gave.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EfuseRead {
    pub mac: [u8; 6],
    pub unicast: bool,
    pub rfe: u8,
    /// The crystal cap.
    pub xtal: u8,
    /// The analog cut `rtw89_read_chip_ver` read.
    pub acv: Option<u8>,
    /// The efuse autoloaded.
    pub valid: bool,
    /// The register mailbox's H2C and C2H counters: the phycap exchange.
    pub mailbox: (u8, u8),
}

/// Why the function runs no station, for the probe's account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unattached(pub String);

impl fmt::Display for Unattached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Started {
    /// Why no station runs, or `None` when one does.
    fn down(&self) -> Option<String> {
        match self {
            Self::Up { .. } => None,
            Self::NotTried(why) => Some(format!("started no station: {why}")),
            Self::Stopped {
                error, power_off, ..
            } => Some(format!(
                "station's start stopped at {error}; {}",
                powered_off(power_off.as_ref())
            )),
        }
    }
}

impl Outcome {
    /// The firmware stage, the efuse stage, where stage 1 stopped, the
    /// listen and the station's start.
    pub fn summary(&self) -> Summary {
        match self {
            Self::Refused(refusal) => Summary {
                firmware: None,
                efuse: None,
                stopped: Some((
                    refusal.stage(),
                    format!("left off before power-on: {refusal}"),
                )),
                radio: None,
                station: None,
            },
            Self::Reached {
                report,
                mailbox,
                timings,
                radio,
                station,
                ..
            } => Summary {
                firmware: Some(ran(
                    report.firmware,
                    &report.downloaded,
                    &report.secure,
                    timings,
                )),
                efuse: Some(EfuseRead {
                    mac: report.info.efuse.addr,
                    unicast: report.info.efuse.unicast(),
                    rfe: report.info.efuse.rfe_type,
                    xtal: report.info.efuse.xtal_cap,
                    acv: report.version.acv,
                    valid: report.info.efuse.valid,
                    mailbox: (mailbox.h2c_counter(), mailbox.c2h_counter()),
                }),
                stopped: None,
                radio: radio.as_deref().map(RadioRan::of),
                station: Some(match station {
                    Started::Up { vector } => StationRan::Up { vector: *vector },
                    down => StationRan::Down(down.down().unwrap_or_default()),
                }),
            },
            Self::Stopped {
                stage,
                error,
                progress,
                timings,
                ..
            } => Summary {
                firmware: match (progress.firmware, progress.downloaded, progress.secure) {
                    (Some(firmware), Some(downloaded), Some(secure)) => {
                        Some(ran(firmware, &downloaded, &secure, timings))
                    }
                    _ => None,
                },
                efuse: None,
                stopped: Some((*stage, short(error))),
                radio: None,
                station: None,
            },
        }
    }

    /// Why the function runs no station, or `None` when its station's
    /// interface came up and the keeper keeps it.
    pub fn unattached(&self) -> Option<Unattached> {
        let why = match self {
            Self::Refused(refusal) => format!("RTL8852B left off before power-on: {refusal}"),
            Self::Reached { station, .. } => format!("RTL8852B {}", station.down()?),
            Self::Stopped {
                stage,
                error,
                power_off,
                ..
            } => format!(
                "RTL8852B stage 1 stopped at {stage}: {}; {}",
                short(error),
                powered_off(power_off.as_ref())
            ),
        };
        Some(Unattached(why))
    }

    /// The log's lines, each without its newline, the PCI location for the
    /// caller to put in front.
    pub fn lines(&self) -> Vec<String> {
        match self {
            Self::Refused(refusal) => alloc::vec![format!("left off before power-on: {refusal}")],
            Self::Reached {
                found,
                report,
                mailbox,
                timings,
                power_off,
                radio,
                station,
            } => {
                let efuse = &report.info.efuse;
                let hal = &report.info.hal;
                let mut lines = alloc::vec![
                    format!(
                        "chip: {}, {}; {found}; {}",
                        cut_name(report.version.cut),
                        acv_name(report.version.acv),
                        powered_on(&report.powered)
                    ),
                    format!(
                        "firmware: {}; secure boot {}",
                        firmware_ran(
                            &report.firmware,
                            &report.downloaded,
                            timings.took(Stage::Download)
                        ),
                        on_off(report.secure.secure_boot)
                    ),
                    format!(
                        "efuse: MAC {} ({}), RFE {}, crystal cap {:#04x}, {}; the firmware's phycap: \
                         {} TX and {} RX streams, over the register mailbox ({} H2C, {} C2H)",
                        Masked(&efuse.addr),
                        if efuse.unicast() {
                            "unicast"
                        } else {
                            "not unicast"
                        },
                        efuse.rfe_type,
                        efuse.xtal_cap,
                        if efuse.valid {
                            "autoloaded"
                        } else {
                            "not autoloaded"
                        },
                        hal.tx_nss,
                        hal.rx_nss,
                        mailbox.h2c_counter(),
                        mailbox.c2h_counter()
                    ),
                    match power_off {
                        Ok(()) => String::from("powered off after stage 1, as rtw89's probe ends"),
                        Err(error) => format!(
                            "powering off after stage 1 failed: {error:?}; its rings and claim stay \
                             kept, and neither the listen nor the station runs"
                        ),
                    },
                ];
                if let Some(radio) = radio {
                    lines.extend(radio_lines(radio));
                }
                lines.extend(station_lines(station));
                lines
            }
            Self::Stopped {
                found,
                stage,
                error,
                progress,
                registers,
                timings,
                power_off,
            } => {
                let mut lines = Vec::new();
                let took = timings
                    .took(*stage)
                    .map_or(String::new(), |us| format!(" after {}", millis(us)));
                match download_attempts(error) {
                    Some(attempts) => {
                        lines.push(format!(
                            "stopped at {stage}{took}: every one of the {} attempts failed",
                            attempts.len()
                        ));
                        for (index, attempt) in attempts.iter().enumerate() {
                            lines.push(format!("attempt {}: {}", index + 1, attempt_line(attempt)));
                        }
                    }
                    None => lines.push(format!("stopped at {stage}{took}: {error}")),
                }
                let mut first = alloc::vec![found.to_string()];
                first.extend(reached(progress, timings));
                lines.push(format!("reached first: {}", first.join("; ")));
                if !registers.is_empty() {
                    let values: Vec<String> = registers
                        .iter()
                        .map(|read| match read.value {
                            Ok(value) => format!("{}={value:#010x}", read.name),
                            Err(error) => format!("{} not read ({error:?})", read.name),
                        })
                        .collect();
                    lines.push(format!(
                        "registers before the power-off: {}",
                        values.join(" ")
                    ));
                }
                lines.push(powered_off(power_off.as_ref()));
                lines
            }
        }
    }
}

/// The station's lines: its interface up, or why none came up, with what
/// the bring-up learned and logged when it stopped.
fn station_lines(station: &Started) -> Vec<String> {
    match station {
        Started::Up { vector } => alloc::vec![format!(
            "station: the interface came up, {}; the keeper joins the network",
            if *vector {
                "its causes signalled by MSI"
            } else {
                "polled"
            }
        )],
        Started::NotTried(why) => {
            alloc::vec![format!("station: none started: {why}; the chip stays off")]
        }
        Started::Stopped {
            error,
            report,
            power_off,
        } => {
            let mut lines = alloc::vec![format!("station: the start stopped at {error}")];
            for warning in report.warnings() {
                lines.push(format!("station warning: {warning}"));
            }
            for chunk in report.registers.chunks(8) {
                lines.push(format!("station registers: {}", registers(chunk)));
            }
            lines.push(format!("station: {}", powered_off(power_off.as_ref())));
            lines
        }
    }
}

/// Key registers as `NAME=value`, or why one was not read.
fn registers(reads: &[radio::Read]) -> String {
    let values: Vec<String> = reads
        .iter()
        .map(|read| match read.value {
            Ok(value) => format!("{}={value:#x}", read.name),
            Err(error) => format!("{} not read ({error:?})", read.name),
        })
        .collect();
    values.join(" ")
}

/// Stage 2's lines: the plan's headline, the regulation, each stage's
/// time, what rtw89 only logged, what RXQ held before and during the listen,
/// each BSSID heard, the key registers and the power-off.
fn radio_lines(radio: &radio::Outcome) -> Vec<String> {
    let channel = radio.channel;
    let report = &radio.report;
    let mut lines = Vec::new();
    let tuned = format!(
        "channel {} ({} MHz)",
        channel.primary(),
        channel.width_mhz()
    );
    match (&radio.stopped, report.heard.as_ref()) {
        (None, Some(heard)) => lines.push(headline(&tuned, heard)),
        (Some((stage, error)), _) => {
            let took = radio
                .timings
                .took(*stage)
                .map_or(String::new(), |us| format!(" after {}", millis(us)));
            lines.push(format!(
                "stage 2 for {tuned} stopped at {stage}{took}: {error}"
            ));
        }
        (None, None) => lines.push(format!("stage 2 for {tuned} heard nothing")),
    }
    if let Some(regulated) = &report.regulated {
        let [a, b] = regulated.alpha2;
        lines.push(format!(
            "stage 2 regulation: {}{} ({}), TX power bound {}/{} in 1/2 dB for 1/2 TX ({})",
            a as char,
            b as char,
            if regulated.programmed {
                "the efuse's"
            } else {
                "the stack's"
            },
            regulated.cap.mac[0],
            regulated.cap.mac[1],
            if regulated.country_cap {
                "regulatory.db's EIRP"
            } else {
                "rtw89's maximum, no regulatory.db country"
            }
        ));
    }
    let took: Vec<String> = radio::Stage::ALL
        .iter()
        .filter_map(|&stage| {
            radio
                .timings
                .took(stage)
                .map(|us| format!("{stage} {}", millis(us)))
        })
        .collect();
    if !took.is_empty() {
        lines.push(format!("stage 2 timings: {}", took.join(", ")));
    }
    let mut steps = Vec::new();
    if let Some(downloaded) = &report.downloaded {
        steps.push(format!(
            "firmware downloaded again in {} H2C packets",
            downloaded.packets
        ));
    }
    if let Some((offset_base, rssi_base)) = report.bases {
        steps.push(format!(
            "RPL bias offset_base {offset_base}, rssi_base {rssi_base}"
        ));
    }
    if let Some(filter) = report.rx_filter {
        steps.push(format!("RX_FLTR_OPT {filter:#010x}"));
    }
    if let Some(switched) = &report.switched {
        steps.push(format!(
            "tuned with TX enables {:#06x} restored{}",
            switched.help.tx_en,
            if switched.band_notice {
                ", TSSI scan for the new band"
            } else {
                ""
            }
        ));
    }
    if !steps.is_empty() {
        lines.push(format!("stage 2: {}", steps.join("; ")));
    }
    for warning in report.warnings() {
        lines.push(format!("stage 2 warning: {warning}"));
    }
    lines.push(format!(
        "stage 2 RX before listening: {}",
        counts(&report.before.counts)
    ));
    if let Some(heard) = &report.heard {
        lines.push(format!(
            "stage 2 RX while listening: {}",
            counts(&heard.counts)
        ));
        for bss in &heard.bss {
            lines.push(format!("stage 2 heard {}", bss_line(bss)));
        }
        if heard.more_bss > 0 {
            lines.push(format!(
                "stage 2 heard {} more BSSIDs, not kept",
                heard.more_bss
            ));
        }
    }
    for chunk in report.registers.chunks(8) {
        lines.push(format!("stage 2 registers: {}", registers(chunk)));
    }
    lines.push(radio_powered_off(radio.power_off.as_ref()));
    lines
}

/// The plan's line for a listen that ran.
fn headline(tuned: &str, heard: &Heard) -> String {
    let seconds = heard
        .listened_us
        .map_or(String::from("the listen"), |us| match us / 1_000_000 {
            0 => format!("{} ms", us / 1000),
            s => format!("{s} s"),
        });
    let strongest = match heard.strongest() {
        Some(Bss {
            best: Some(signal),
            bssid,
            ..
        }) => format!(", strongest {signal} dBm from {}", Masked(bssid)),
        Some(Bss { bssid, .. }) => format!(", strongest from {} (no signal)", Masked(bssid)),
        None => String::new(),
    };
    format!(
        "rtw89: RTL8852B tuned to {tuned}, heard {} beacons in {seconds}{strongest}",
        heard.beacons()
    )
}

/// One BSSID heard.
fn bss_line(bss: &Bss) -> String {
    let dbm = |signal: Option<i8>| {
        signal.map_or(String::from("no signal"), |signal| format!("{signal} dBm"))
    };
    format!(
        "{} ssid \"{}\": {} beacons, best {} ({} with an A1-matched PPDU status; the PHY status \
         header alone {}), elements name channel {}, received at {} MHz",
        Masked(&bss.bssid),
        Ssid(&bss.ssid),
        bss.beacons,
        dbm(bss.best),
        bss.a1,
        dbm(bss.header_best),
        bss.channel
            .map_or(String::from("none"), |channel| format!("{channel}")),
        bss.freq
    )
}

/// Every packet heard, by kind.
fn counts(counts: &Counts) -> String {
    format!(
        "buffers={} wifi={} mgmt={} ctrl={} data={} ext={} runt={} beacons={} probe_resp={} \
         matched_ppdu={} crc32_err={} icv_err={} c2h={} ppdu={} ppdu_valid={} other={} \
         segmented={} truncated={}",
        counts.buffers,
        counts.wifi,
        counts.mgmt,
        counts.ctrl,
        counts.data,
        counts.extension,
        counts.runt,
        counts.beacons,
        counts.probe_resps,
        counts.matched,
        counts.crc32_err,
        counts.icv_err,
        counts.c2h,
        counts.ppdu,
        counts.ppdu_valid,
        counts.other,
        counts.segmented,
        counts.truncated
    )
}

/// How stage 2's power-off went.
fn radio_powered_off(power_off: Option<&Result<(), power::Error>>) -> String {
    match power_off {
        Some(Ok(())) => {
            String::from("powered off after stage 2's listen, so the station starts on a cold chip")
        }
        Some(Err(error)) => format!("powering off after stage 2 failed: {error:?}"),
        None => String::from("stage 2 never powered it on"),
    }
}

/// An SSID as text: printable ASCII but `"` and a backslash, the rest as `\xNN`.
pub struct Ssid<'a>(pub &'a [u8]);

impl fmt::Display for Ssid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in self.0 {
            if (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\' {
                write!(f, "{}", byte as char)?;
            } else {
                write!(f, "\\x{byte:02x}")?;
            }
        }
        Ok(())
    }
}

/// The firmware stage of a download that ended with FREERTOS_DONE.
fn ran(
    firmware: Firmware,
    downloaded: &Downloaded,
    secure: &FwSecure,
    timings: &Timings,
) -> FirmwareRan {
    FirmwareRan {
        version: firmware.version,
        kind: firmware.kind,
        image_cut: firmware.cut,
        packets: downloaded.packets,
        retries: downloaded.retried.iter().flatten().count(),
        freertos_done_us: timings.took(Stage::Download),
        secure_boot: secure.secure_boot,
    }
}

/// The attempts of a download that failed every one.
fn download_attempts(error: &bootstrap::Error) -> Option<&[Attempt]> {
    match error {
        bootstrap::Error::Download(failure) => match &**failure {
            fwdl::Failure::Attempts(attempts) => Some(attempts),
            _ => None,
        },
        _ => None,
    }
}

/// `error` on one line: a failed download's attempts by their errors alone.
fn short(error: &bootstrap::Error) -> String {
    match download_attempts(error) {
        Some(attempts) => {
            let errors: Vec<String> = attempts
                .iter()
                .map(|attempt| format!("{:?}", attempt.error))
                .collect();
            format!(
                "every one of the {} attempts failed: {}",
                attempts.len(),
                errors.join(", ")
            )
        }
        None => error.to_string(),
    }
}

/// One failed attempt, with the registers `rtw89_fw_dl_fail_dump` read.
fn attempt_line(attempt: &Attempt) -> String {
    let dump = match attempt.dump {
        None => String::from("no registers read, as rtw89 reads none then"),
        Some(Err(error)) => format!("its registers not read ({error:?})"),
        Some(Ok(dump)) => format!(
            "WCPU_FW_CTRL {:#010x}, BOOT_DBG {:#010x}, program counter {}",
            dump.wcpu_fw_ctrl,
            dump.boot_dbg,
            runs(&dump.pc)
        ),
    };
    format!("{:?}; {dump}", attempt.error)
}

/// `values` in hex, a repeated value once with its count.
fn runs(values: &[u32]) -> String {
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(&value) = values.get(index) {
        let count = values[index..]
            .iter()
            .take_while(|&&each| each == value)
            .count();
        out.push(if count > 1 {
            format!("{value:#x} x{count}")
        } else {
            format!("{value:#x}")
        });
        index += count;
    }
    out.join(" ")
}

/// What a stopped stage 1 learned first.
fn reached(progress: &Progress, timings: &Timings) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(version) = progress.version {
        parts.push(format!(
            "{}, {}",
            cut_name(version.cut),
            acv_name(version.acv)
        ));
    }
    if let Some(powered) = &progress.powered {
        parts.push(powered_on(powered));
    }
    if let Some(secure) = progress.secure {
        parts.push(format!("secure boot {}", on_off(secure.secure_boot)));
    }
    match (progress.firmware, progress.downloaded) {
        (Some(firmware), Some(downloaded)) => parts.push(format!(
            "firmware {}",
            firmware_ran(&firmware, &downloaded, timings.took(Stage::Download))
        )),
        (Some(firmware), None) => parts.push(format!(
            "firmware {firmware} type {} from the cut {} image, {} H2C packets to send",
            firmware.kind, firmware.cut, firmware.packets
        )),
        _ => {}
    }
    parts
}

/// The firmware that ran: version, type, suit, packets, retries and the
/// time to FREERTOS_DONE.
fn firmware_ran(firmware: &Firmware, downloaded: &Downloaded, took: Option<u64>) -> String {
    let failed: Vec<String> = downloaded
        .retried
        .iter()
        .flatten()
        .map(|attempt| format!("{:?}", attempt.error))
        .collect();
    let retried = if failed.is_empty() {
        String::from("at the first attempt")
    } else {
        format!(
            "at attempt {} after {} failed ({})",
            failed.len() + 1,
            failed.len(),
            failed.join(", ")
        )
    };
    let done = took.map_or(String::from("FREERTOS_DONE"), |us| {
        format!("FREERTOS_DONE {} after the download began", millis(us))
    });
    format!(
        "{firmware} type {} from the cut {} image (commit {:#010x}): {} H2C packets {retried}, {done}",
        firmware.kind, firmware.cut, firmware.commit_id, downloaded.packets
    )
}

/// How the power-on went.
fn powered_on(powered: &power::PoweredOn) -> String {
    match powered.first_failure {
        None => String::from("powered on at the first attempt"),
        Some(power::Error::AlreadyOn) => String::from(
            "powered on at the second attempt: the first found it on, as a previous boot can leave it",
        ),
        Some(error) => format!(
            "powered on at the second attempt, after the first failed ({error:?}) and it was powered off"
        ),
    }
}

/// How the power-off went after a stage that stopped.
fn powered_off(power_off: Option<&Result<(), power::Error>>) -> String {
    match power_off {
        Some(Ok(())) => String::from("powered off"),
        Some(Err(error)) => format!("powering off failed: {error:?}"),
        None => String::from(
            "not powered off: the failure came before the power-on, which rtw89 leaves as it is",
        ),
    }
}

/// A cut by number and rtw89's name.
fn cut_name(cut: u8) -> String {
    match identity::rtw89_cut_name(cut) {
        Some(name) => format!("cut {cut} ({name})"),
        None => format!("cut {cut} (past rtw89's CHIP_CFV)"),
    }
}

fn acv_name(acv: Option<u8>) -> String {
    acv.map_or(String::from("ACV unread (XTAL SI did not answer)"), |acv| {
        format!("ACV {acv}")
    })
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// Microseconds as whole milliseconds, or microseconds under one.
fn millis(us: u64) -> String {
    if us < 1000 {
        format!("{us} us")
    } else {
        format!("{} ms", us / 1000)
    }
}

/// A MAC address as `aa:bb:cc:..:..:ff`, as `stela_contracts::masked::Mac`
/// prints one: the vendor's half and the last byte.
pub struct Masked<'a>(pub &'a [u8; 6]);

impl fmt::Display for Masked<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, _, _, last] = *self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:..:..:{last:02x}")
    }
}

#[cfg(test)]
mod tests;
