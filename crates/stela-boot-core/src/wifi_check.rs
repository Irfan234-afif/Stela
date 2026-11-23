//! The Wi-Fi check (`--wifi-check`): how far a boot brought each RTL8852B
//! function the probe found, as lines for the boot log, and the verdict.
//!
//! The check runs once the host's devices have started and the host's
//! network has tried its adapters, and before the guest's storage is
//! opened. Its stages follow the driver's bring-up: the cut read before
//! power-on, firmware running, efuse read, the radio receiving, a station
//! associated and a DHCP lease. An image checks the stages its driver
//! reaches; [`DRIVEN`] is the last of them. This image's driver runs stage
//! 1 (`ax::attach`): it powers the chip on, downloads its firmware until it
//! reports FREERTOS_DONE, reads its efuse, and powers it off again; then
//! stage 2 (`ax::radio`): it powers the chip on again as rtw89's interface
//! start does, tunes one channel, listens for beacons, and powers it off;
//! then the station: the interface comes up again (`ax::hardware`), the
//! connection keeper scans, authenticates, associates and runs the 4-way
//! handshake, and the host's network gets a DHCP lease over it.
//!
//! The radio stage is a diagnostic: its lines show what RXQ held by kind
//! and each BSSID heard, so a silent radio can be told from a deaf one, but
//! the station and the lease decide the verdict. A station that did not
//! associate names where its connection stood ([`Progress`]): the scan and
//! whether it found the network and on which channel, the authentication,
//! the association, or the 4-way handshake's EAPOL message it waited for;
//! one that associated without a lease names the DHCP exchange. Its state
//! line carries the frames its rings sent and how RPQ released them, so a
//! TX path the air never acknowledged shows. A lease that came over
//! another adapter fails the check: the RTL8852B was never tried.
//!
//! A cut of 0 (CAV) fails the check: linux-firmware's RTL8852B container
//! holds images for cuts 1 and 2, and rtw89 takes the newest image whose cut
//! is not above the chip's, so CAV silicon has none and stage 1 leaves it
//! off.
//!
//! No H2C rtw89 sends at probe asks for REC_ACK: the firmware header asks
//! for none, the parts carry no header, and the phycap request goes over
//! the register mailbox. The firmware stage therefore counts the packets
//! the firmware took before it reported FREERTOS_DONE, and the efuse stage
//! the mailbox's exchanges.
use alloc::{format, string::String, vec::Vec};
use core::{fmt, net::Ipv4Addr};
use stela_contracts::masked::{Mac, Name};
use stela_drivers::net::wifi::{
    connection::keeper::{Association, Progress},
    realtek::ax::{
        attach::{RadioRan, Ssid, StationRan, Summary},
        listen::Counts,
    },
    security::Cipher,
    station::phy::Width,
    supplicant::Akm,
};

/// A stage of the Wi-Fi check, in the order a driver reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Stage {
    /// SYS_CFG1 read before power-on.
    Cut,
    /// The firmware downloaded and reporting FREERTOS_DONE.
    Firmware,
    /// The efuse and the firmware's phycap read.
    Efuse,
    /// Stage 2 tuned a channel and listened on it.
    Radio,
    /// The station associated and its 4-way handshake opened its port.
    Station,
    /// DHCP leased the host's network an IPv4 address over the station.
    Lease,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Cut => "cut",
            Self::Firmware => "firmware",
            Self::Efuse => "efuse",
            Self::Radio => "radio",
            Self::Station => "station",
            Self::Lease => "lease",
        }
    }
}

/// The last stage this image's driver reaches.
pub const DRIVEN: Stage = Stage::Lease;

/// The name the network's log gives an RTL8852BE station's adapter.
pub const DRIVER: &str = "rtw89_8852be";

/// What the boot learned of one RTL8852B function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reached<'a> {
    /// The read before power-on did not happen or read nothing, and why.
    NotRead(&'a str),
    /// SYS_CFG1 as read before power-on, the cut in it and rtw89's name
    /// for that cut, then what the attach reached, when it ran.
    Cut {
        sys_cfg1: u32,
        cut: u8,
        name: Option<&'static str>,
        stage1: Option<&'a Summary>,
    },
}

/// An IPv4 lease: the address, its prefix and the router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
}

/// One adapter the host's network tried, in the order it tried them.
#[derive(Clone, Copy, Debug)]
pub struct Tried<'a> {
    /// The adapter's driver and PCI location, as the network's log names
    /// them ([`DRIVER`] for an RTL8852BE station).
    pub driver: &'a str,
    pub location: &'a str,
    pub wireless: bool,
    /// The IPv4 lease, `None` for an address IPv6 alone gave; or why the
    /// adapter got no address.
    pub lease: Result<Option<Lease>, &'a str>,
    /// The association of an RTL8852BE station whose port opened.
    pub associated: Option<&'a Association>,
    /// Where an RTL8852BE station's connection stood.
    pub progress: Option<&'a Progress>,
    /// The adapter's own state line: for an RTL8852BE station, its
    /// connection, the last join's failure, and the frames its rings sent
    /// and how they were released.
    pub state: Option<&'a str>,
    /// The DHCP exchange's summary, for an adapter that got no address.
    pub dhcp: Option<&'a str>,
}

/// What the host's network did, for the station and lease stages.
#[derive(Clone, Copy, Debug, Default)]
pub struct Network<'a> {
    /// Each adapter it tried, in order: those that got no address, then
    /// the one that got the lease, when one did.
    pub tried: &'a [Tried<'a>],
    /// The `--network-check` POST over the lease's adapter, when the boot
    /// asked for one: `Err` says why it failed.
    pub check: Option<Result<(), &'a str>>,
}

/// The check's outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Every function reached [`DRIVEN`].
    Passed,
    /// Why the check failed.
    Failed(String),
}

/// The check's lines, each without its newline, and its verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub lines: Vec<String>,
    pub verdict: Verdict,
}

/// Where one function stopped, when it did not reach [`DRIVEN`].
#[derive(Clone, Debug)]
struct Short {
    /// The stage it did not reach.
    before: Stage,
    why: String,
    /// It stopped on the host's network: it was tried and got no lease, or
    /// was never tried.
    network: bool,
}

/// Report on `functions`, each named by its PCI location, and on what the
/// host's `network` did with their stations.
pub fn report<'a, L: fmt::Display>(
    functions: impl IntoIterator<Item = (L, Reached<'a>)>,
    network: &Network<'_>,
) -> Report {
    let mut lines = Vec::new();
    let mut found = 0usize;
    let mut unread = 0usize;
    let mut cav = 0usize;
    let mut shorts = Vec::new();
    let mut leased = 0usize;
    for (location, reached) in functions {
        found += 1;
        match reached {
            Reached::NotRead(why) => {
                unread += 1;
                lines.push(format!(
                    "WIFI CHECK {location} stopped before stage={}: {why}",
                    Stage::Cut.name()
                ));
            }
            Reached::Cut {
                sys_cfg1,
                cut,
                name,
                stage1,
            } => {
                let name = name.unwrap_or("past rtw89's CHIP_CFV");
                let mut line = format!(
                    "WIFI CHECK {location} stage={} cut={cut} ({name}) sys_cfg1={sys_cfg1:#010x}",
                    Stage::Cut.name()
                );
                if cut == 0 {
                    cav += 1;
                    line.push_str(": linux-firmware has no RTL8852B image for this cut");
                }
                lines.push(line);
                let summary = match stage_1(&location, stage1, &mut lines) {
                    Ok(summary) => summary,
                    Err(short) => {
                        shorts.push(short);
                        continue;
                    }
                };
                // The listen is a diagnostic: the station decides.
                radio(&location, summary.radio.as_ref(), &mut lines);
                let at = format!("{location}");
                match station(
                    &location,
                    &at,
                    summary.station.as_ref(),
                    network,
                    &mut lines,
                ) {
                    Ok(()) => leased += 1,
                    Err(short) => shorts.push(short),
                }
            }
        }
    }
    let elsewhere = network
        .tried
        .iter()
        .find(|tried| tried.lease.is_ok() && tried.driver != DRIVER);
    let first = |network: bool| shorts.iter().find(|short| short.network == network);
    let verdict = if found == 0 {
        Verdict::Failed(String::from(
            "no RTL8852B was read; the probe reads one only given a --wifi network whose key file the boot read",
        ))
    } else if unread > 0 {
        Verdict::Failed(format!(
            "{unread} of {found} RTL8852B stopped before stage={}",
            Stage::Cut.name()
        ))
    } else if cav > 0 {
        Verdict::Failed(format!(
            "{cav} of {found} RTL8852B is cut 0 (CAV), which no linux-firmware image runs"
        ))
    } else if let Some(short) = first(false) {
        Verdict::Failed(format!(
            "{} of {found} RTL8852B stopped before stage={}: {}",
            shorts.len(),
            short.before.name(),
            short.why
        ))
    } else if let (Some(tried), 0) = (elsewhere, leased) {
        Verdict::Failed(match tried.wireless {
            false => format!(
                "the lease came over {} at {}, not Wi-Fi: unplug the Ethernet cable",
                tried.driver, tried.location
            ),
            true => format!(
                "the lease came over {} at {}, not the RTL8852B",
                tried.driver, tried.location
            ),
        })
    } else if let Some(short) = first(true) {
        Verdict::Failed(format!(
            "{} of {found} RTL8852B stopped before stage={}: {}",
            shorts.len(),
            short.before.name(),
            short.why
        ))
    } else if let Some(Err(why)) = network.check {
        Verdict::Failed(format!("the network check over Wi-Fi failed: {why}"))
    } else {
        // A diagnostics-only stage past the lease, such as a firmware
        // recovery the check triggers, goes here, before the verdict.
        lines.push(format!("WIFI CHECK reached {}; restarting", DRIVEN.name()));
        Verdict::Passed
    };
    Report { lines, verdict }
}

/// The station and lease stages' lines for the function at `location`
/// (`at` as the network's log names it): its association and lease, or
/// where it stopped, with its state line.
fn station(
    location: &dyn fmt::Display,
    at: &str,
    started: Option<&StationRan>,
    network: &Network<'_>,
    lines: &mut Vec<String>,
) -> Result<(), Short> {
    let stop = |lines: &mut Vec<String>, before: Stage, why: String, network: bool| {
        Err(stopped(location, lines, before, why, network))
    };
    match started {
        None => return stop(lines, Stage::Station, String::from("no station ran"), false),
        Some(StationRan::Down(why)) => return stop(lines, Stage::Station, why.clone(), false),
        Some(StationRan::Up { .. }) => {}
    }
    let Some(tried) = network.tried.iter().find(|tried| tried.location == at) else {
        let why = match network.tried.iter().find(|tried| tried.lease.is_ok()) {
            Some(leased) => format!(
                "the host network took {} at {} first and never tried the station",
                leased.driver, leased.location
            ),
            None => String::from("the host network never tried the station"),
        };
        return stop(lines, Stage::Station, why, true);
    };
    if let Some(associated) = tried.associated {
        lines.push(association(location, associated));
    }
    if let Some(state) = tried.state {
        lines.push(format!("WIFI CHECK {location} state {state}"));
    }
    match (tried.lease, tried.associated) {
        (Ok(Some(lease)), _) => {
            let router = lease
                .router
                .map_or(String::from("none"), |router| format!("{router}"));
            lines.push(format!(
                "WIFI CHECK {location} stage={} address={}/{} router={router}",
                Stage::Lease.name(),
                lease.address,
                lease.prefix
            ));
            Ok(())
        }
        (Ok(None), _) => stop(
            lines,
            Stage::Lease,
            String::from("no DHCPv4 lease came: only IPv6 gave an address"),
            true,
        ),
        (Err(why), Some(_)) => {
            if let Some(dhcp) = tried.dhcp {
                lines.push(format!("WIFI CHECK {location} dhcp {dhcp}"));
            }
            stop(lines, Stage::Lease, format!("DHCP: {why}"), true)
        }
        (Err(why), None) => {
            let why = match tried.progress {
                Some(progress) => format!("{progress}"),
                None => String::from(why),
            };
            stop(lines, Stage::Station, why, true)
        }
    }
}

/// The line for a function that stopped before `before`, and where it
/// stopped.
fn stopped(
    location: &dyn fmt::Display,
    lines: &mut Vec<String>,
    before: Stage,
    why: String,
    network: bool,
) -> Short {
    lines.push(format!(
        "WIFI CHECK {location} stopped before stage={}: {why}",
        before.name()
    ));
    Short {
        before,
        why,
        network,
    }
}

/// The station stage's line: the network by its masked name, the AP, the
/// AID it gave, the suites and the channel.
fn association(location: &dyn fmt::Display, associated: &Association) -> String {
    let ssid = String::from_utf8_lossy(&associated.ssid);
    format!(
        "WIFI CHECK {location} stage={} ssid={} bssid={} aid={} cipher={} group={} akm={} \
         channel={} width={}",
        Stage::Station.name(),
        Name(&ssid),
        Mac(&associated.bssid.0),
        associated.aid,
        cipher(associated.pairwise),
        cipher(associated.group),
        akm(associated.akm),
        associated.channel.number,
        width(associated.width)
    )
}

/// A cipher suite as the 802.11 standard names it.
fn cipher(cipher: Cipher) -> &'static str {
    match cipher {
        Cipher::Ccmp128 => "CCMP-128",
        Cipher::Ccmp256 => "CCMP-256",
        Cipher::Gcmp128 => "GCMP-128",
        Cipher::Gcmp256 => "GCMP-256",
        Cipher::Tkip => "TKIP",
        Cipher::Wep40 => "WEP-40",
        Cipher::Wep104 => "WEP-104",
    }
}

/// An AKM as wpa_supplicant's `key_mgmt` names it.
fn akm(akm: Akm) -> &'static str {
    match akm {
        Akm::Psk => "WPA-PSK",
        Akm::PskSha256 => "WPA-PSK-SHA256",
        Akm::Sae => "SAE",
    }
}

/// A channel width in MHz.
fn width(width: Width) -> &'static str {
    match width {
        Width::Mhz20 => "20",
        Width::Mhz40 => "40",
        Width::Mhz80 => "80",
        Width::Mhz160 => "160",
        Width::Mhz80P80 => "80+80",
        Width::Mhz320 => "320",
    }
}

/// The radio stage's lines: the plan's `stage=radio` line once the listen
/// ran, each BSSID heard, what RXQ held by kind, or where stage 2 stopped.
fn radio(location: &dyn fmt::Display, radio: Option<&RadioRan>, lines: &mut Vec<String>) {
    let Some(radio) = radio else {
        lines.push(format!(
            "WIFI CHECK {location} stopped before stage={}: stage 2 did not run",
            Stage::Radio.name()
        ));
        return;
    };
    lines.push(format!(
        "WIFI CHECK {location} rx before listening {}",
        counts(&radio.before.counts)
    ));
    let heard = match (&radio.stopped, &radio.heard) {
        (None, Some(heard)) => heard,
        (Some((stage, why)), _) => {
            lines.push(format!(
                "WIFI CHECK {location} stopped before stage={}: {stage}: {why}",
                Stage::Radio.name()
            ));
            return;
        }
        (None, None) => {
            lines.push(format!(
                "WIFI CHECK {location} stopped before stage={}: stage 2 said nothing more",
                Stage::Radio.name()
            ));
            return;
        }
    };
    let dbm =
        |signal: Option<i8>| signal.map_or(String::from("none"), |signal| format!("{signal}"));
    let strongest = match heard.strongest() {
        Some(bss) => format!("strongest={} rssi={}", Mac(&bss.bssid), dbm(bss.best)),
        None => String::from("strongest=none"),
    };
    lines.push(format!(
        "WIFI CHECK {location} stage={} channel={} width={} beacons={} {strongest}",
        Stage::Radio.name(),
        radio.primary,
        radio.width,
        heard.beacons()
    ));
    for bss in &heard.bss {
        lines.push(format!(
            "WIFI CHECK {location} bss={} ssid=\"{}\" beacons={} rssi={} a1={} hdr_rssi={} ch={} \
             freq={}",
            Mac(&bss.bssid),
            Ssid(&bss.ssid),
            bss.beacons,
            dbm(bss.best),
            bss.a1,
            dbm(bss.header_best),
            bss.channel
                .map_or(String::from("none"), |channel| format!("{channel}")),
            bss.freq
        ));
    }
    lines.push(format!(
        "WIFI CHECK {location} rx while listening {}",
        counts(&heard.counts)
    ));
}

/// What RXQ held, by kind.
fn counts(counts: &Counts) -> String {
    format!(
        "buffers={} wifi={} mgmt={} ctrl={} data={} beacons={} probe_resp={} matched_ppdu={} \
         crc32_err={} icv_err={} c2h={} ppdu={} ppdu_valid={} other={} dropped={}",
        counts.buffers,
        counts.wifi,
        counts.mgmt,
        counts.ctrl,
        counts.data,
        counts.beacons,
        counts.probe_resps,
        counts.matched,
        counts.crc32_err,
        counts.icv_err,
        counts.c2h,
        counts.ppdu,
        counts.ppdu_valid,
        counts.other,
        counts.segmented + counts.truncated + counts.runt
    )
}

/// The lines of stage 1's firmware and efuse stages, and of where it
/// stopped: the summary once it reached the efuse.
fn stage_1<'s>(
    location: &dyn fmt::Display,
    stage1: Option<&'s Summary>,
    lines: &mut Vec<String>,
) -> Result<&'s Summary, Short> {
    let stop = |lines: &mut Vec<String>, before: Stage, why: String| {
        Err(stopped(location, lines, before, why, false))
    };
    let Some(summary) = stage1 else {
        return stop(lines, Stage::Firmware, String::from("stage 1 did not run"));
    };
    if let Some(firmware) = &summary.firmware {
        let [major, minor, sub, index] = firmware.version;
        let done = firmware
            .freertos_done_us
            .map_or(String::from("unmeasured"), |us| format!("{} ms", us / 1000));
        lines.push(format!(
            "WIFI CHECK {location} stage={} version={major}.{minor}.{sub}.{index} type={} \
             image=cv{} freertos_done={done} packets={} retries={} secure_boot={}",
            Stage::Firmware.name(),
            firmware.kind,
            firmware.image_cut,
            firmware.packets,
            firmware.retries,
            if firmware.secure_boot { "on" } else { "off" },
        ));
    }
    if let Some(efuse) = &summary.efuse {
        let acv = efuse
            .acv
            .map_or(String::from("unread"), |acv| format!("{acv}"));
        lines.push(format!(
            "WIFI CHECK {location} stage={} mac={} {} rfe={} xtal={:#04x} acv={acv} \
             autoload={} mailbox={}/{}",
            Stage::Efuse.name(),
            Mac(&efuse.mac),
            if efuse.unicast {
                "unicast"
            } else {
                "multicast"
            },
            efuse.rfe,
            efuse.xtal,
            if efuse.valid { "yes" } else { "no" },
            efuse.mailbox.0,
            efuse.mailbox.1,
        ));
    }
    let next = if summary.firmware.is_some() {
        Stage::Efuse
    } else {
        Stage::Firmware
    };
    match &summary.stopped {
        Some((stage, why)) => stop(lines, next, format!("{stage}: {why}")),
        None if summary.efuse.is_none() => {
            stop(lines, next, String::from("stage 1 said nothing more"))
        }
        None => Ok(summary),
    }
}

#[cfg(test)]
mod tests;
