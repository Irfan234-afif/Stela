//! The Wi-Fi check (`--wifi-check`): how far a boot brought each RTL8852B
//! function the probe found, as lines for the boot log, and the verdict.
//!
//! The check runs once the host's devices have started and before the
//! guest's storage is opened. Its stages follow the driver's bring-up: the
//! cut read before power-on, firmware running, efuse read, the radio
//! receiving, a station associated and a DHCP lease. An image checks the
//! stages its driver reaches; [`DRIVEN`] is the last of them. This image's
//! driver runs stage 1 (`ax::attach`): it powers the chip on, downloads its
//! firmware until it reports FREERTOS_DONE, reads its efuse, and powers it
//! off again.
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
use core::fmt;
use stela_contracts::masked::Mac;
use stela_drivers::net::wifi::realtek::ax::attach::Summary;

/// A stage of the Wi-Fi check, in the order a driver reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Stage {
    /// SYS_CFG1 read before power-on.
    Cut,
    /// The firmware downloaded and reporting FREERTOS_DONE.
    Firmware,
    /// The efuse and the firmware's phycap read.
    Efuse,
    Radio,
    Station,
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
pub const DRIVEN: Stage = Stage::Efuse;

/// What the boot learned of one RTL8852B function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reached<'a> {
    /// The read before power-on did not happen or read nothing, and why.
    NotRead(&'a str),
    /// SYS_CFG1 as read before power-on, the cut in it and rtw89's name
    /// for that cut, then what stage 1 reached, when it ran.
    Cut {
        sys_cfg1: u32,
        cut: u8,
        name: Option<&'static str>,
        stage1: Option<&'a Summary>,
    },
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

/// Report on `functions`, each named by its PCI location.
pub fn report<'a, L: fmt::Display>(
    functions: impl IntoIterator<Item = (L, Reached<'a>)>,
) -> Report {
    let mut lines = Vec::new();
    let mut found = 0usize;
    let mut unread = 0usize;
    let mut cav = 0usize;
    let mut stopped = 0usize;
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
                if !stage_1(&location, stage1, &mut lines) {
                    stopped += 1;
                }
            }
        }
    }
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
    } else if stopped > 0 {
        Verdict::Failed(format!(
            "{stopped} of {found} RTL8852B did not reach {}, the last stage this image drives",
            DRIVEN.name()
        ))
    } else {
        lines.push(format!(
            "WIFI CHECK passed: every RTL8852B reached {}, the last stage this image drives",
            DRIVEN.name()
        ));
        Verdict::Passed
    };
    Report { lines, verdict }
}

/// The lines of stage 1's firmware and efuse stages, and of where it
/// stopped: whether it reached [`DRIVEN`].
fn stage_1(location: &dyn fmt::Display, stage1: Option<&Summary>, lines: &mut Vec<String>) -> bool {
    let Some(summary) = stage1 else {
        lines.push(format!(
            "WIFI CHECK {location} stopped before stage={}: stage 1 did not run",
            Stage::Firmware.name()
        ));
        return false;
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
        Some((stage, why)) => {
            lines.push(format!(
                "WIFI CHECK {location} stopped before stage={}: {stage}: {why}",
                next.name()
            ));
            false
        }
        None if summary.efuse.is_none() => {
            lines.push(format!(
                "WIFI CHECK {location} stopped before stage={}: stage 1 said nothing more",
                next.name()
            ));
            false
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::net::wifi::realtek::ax::{
        attach::{EfuseRead, FirmwareRan},
        bootstrap::Stage as Step,
    };

    const AT: &str = "0000:03:00.0";

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

    fn reached() -> Summary {
        Summary {
            firmware: Some(firmware()),
            efuse: Some(efuse()),
            stopped: None,
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

    #[test]
    fn stages_are_ordered_and_named_as_the_log_prints_them() {
        let stages = [
            Stage::Cut,
            Stage::Firmware,
            Stage::Efuse,
            Stage::Radio,
            Stage::Station,
            Stage::Lease,
        ];
        assert!(stages.windows(2).all(|pair| pair[0] < pair[1]));
        let names: Vec<_> = stages.iter().map(|stage| stage.name()).collect();
        assert_eq!(
            names,
            ["cut", "firmware", "efuse", "radio", "station", "lease"]
        );
        assert_eq!(DRIVEN, Stage::Efuse);
    }

    #[test]
    fn a_chip_that_reached_the_efuse_passes_with_each_stage_in_its_words() {
        let summary = reached();
        let report = report([(AT, cut(1, Some(&summary)))]);
        assert_eq!(report.verdict, Verdict::Passed);
        assert_eq!(
            report.lines,
            [
                "WIFI CHECK 0000:03:00.0 stage=cut cut=1 (CBV) sys_cfg1=0x00001f00",
                "WIFI CHECK 0000:03:00.0 stage=firmware version=0.29.29.18 type=5 image=cv1 \
                 freertos_done=48 ms packets=165 retries=0 secure_boot=off",
                "WIFI CHECK 0000:03:00.0 stage=efuse mac=00:e0:4c:..:..:56 unicast rfe=1 xtal=0x3c \
                 acv=2 autoload=yes mailbox=1/1",
                "WIFI CHECK passed: every RTL8852B reached efuse, the last stage this image drives",
            ]
        );
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
        };
        let failed = report([(AT, cut(1, Some(&download)))]);
        assert_eq!(
            failed.lines[1],
            "WIFI CHECK 0000:03:00.0 stopped before stage=firmware: firmware download: \
             every one of the 5 attempts failed: ChecksumFail x5"
        );
        assert_eq!(failed.lines.len(), 2);
        assert_eq!(
            failed.verdict,
            Verdict::Failed(String::from(
                "1 of 1 RTL8852B did not reach efuse, the last stage this image drives"
            ))
        );

        // The firmware ran and the mailbox did not answer.
        let efuse = Summary {
            firmware: Some(firmware()),
            efuse: None,
            stopped: Some((Step::Efuse, String::from("Efuse(Io(Timeout { .. }))"))),
        };
        let passed = reached();
        let mixed = report([
            (AT, cut(1, Some(&efuse))),
            ("0000:04:00.0", cut(2, Some(&passed))),
        ]);
        assert!(mixed.lines[1].contains("stage=firmware version=0.29.29.18"));
        assert_eq!(
            mixed.lines[2],
            "WIFI CHECK 0000:03:00.0 stopped before stage=efuse: efuse: Efuse(Io(Timeout { .. }))"
        );
        assert!(matches!(&mixed.verdict, Verdict::Failed(why) if why.starts_with("1 of 2")));

        // Stage 1 that never ran.
        let unrun = report([(AT, cut(1, None))]);
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
            stopped: Some((
                Step::Firmware,
                String::from(
                    "left off before power-on: the firmware image holds no suit for cut 0 (CAV)",
                ),
            )),
        };
        let cav = report([(AT, cut(0, Some(&refused)))]);
        assert!(matches!(&cav.verdict, Verdict::Failed(why) if why.contains("cut 0 (CAV)")));
        assert!(cav.lines[0].ends_with("linux-firmware has no RTL8852B image for this cut"));
        assert!(cav.lines[1].contains("left off before power-on"));
        assert_eq!(cav.lines.len(), 2);

        let passed = reached();
        let unread = report([
            (AT, Reached::NotRead("the function did not answer")),
            ("0000:04:00.0", cut(2, Some(&passed))),
        ]);
        assert_eq!(
            unread.lines[0],
            "WIFI CHECK 0000:03:00.0 stopped before stage=cut: the function did not answer"
        );
        assert_eq!(
            unread.verdict,
            Verdict::Failed(String::from("1 of 2 RTL8852B stopped before stage=cut"))
        );

        let none = report(core::iter::empty::<(&str, Reached<'_>)>());
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
        let report = report([(
            AT,
            Reached::Cut {
                sys_cfg1: 0x6000,
                cut: 6,
                name: None,
                stage1: Some(&summary),
            },
        )]);
        assert_eq!(report.verdict, Verdict::Passed);
        assert_eq!(
            report.lines[0],
            "WIFI CHECK 0000:03:00.0 stage=cut cut=6 (past rtw89's CHIP_CFV) sys_cfg1=0x00006000"
        );
        assert!(report.lines[1].contains("freertos_done=unmeasured"));
        assert!(report.lines[2].contains(" acv=unread "));
    }
}
