//! The Wi-Fi check (`--wifi-check`): how far a boot brought each RTL8852B
//! function the probe found, as lines for the boot log, and the verdict.
//!
//! The check runs once the host's devices have started and before the
//! guest's storage is opened. Its stages follow the driver's bring-up: the
//! cut read before power-on, firmware running, efuse read, the radio
//! receiving, a station associated and a DHCP lease. An image checks the
//! stages its driver reaches; [`DRIVEN`] is the last of them.
//!
//! A cut of 0 (CAV) fails the check: linux-firmware's RTL8852B container
//! holds images for cuts 1 and 2, and rtw89 takes the newest image whose cut
//! is not above the chip's, so CAV silicon has none.
use alloc::{format, string::String, vec::Vec};
use core::fmt;

/// A stage of the Wi-Fi check, in the order a driver reaches them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Stage {
    /// SYS_CFG1 read before power-on.
    Cut,
    Firmware,
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
pub const DRIVEN: Stage = Stage::Cut;

/// What the boot learned of one RTL8852B function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reached<'a> {
    /// The read before power-on did not happen or read nothing, and why.
    NotRead(&'a str),
    /// SYS_CFG1 as read before power-on, the cut in it and rtw89's name
    /// for that cut.
    Cut {
        sys_cfg1: u32,
        cut: u8,
        name: Option<&'static str>,
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
    let mut stopped = 0usize;
    let mut cav = 0usize;
    for (location, reached) in functions {
        found += 1;
        match reached {
            Reached::NotRead(why) => {
                stopped += 1;
                lines.push(format!(
                    "WIFI CHECK {location} stopped before stage={}: {why}",
                    Stage::Cut.name()
                ));
            }
            Reached::Cut {
                sys_cfg1,
                cut,
                name,
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
            }
        }
    }
    let verdict = if found == 0 {
        Verdict::Failed(String::from(
            "no RTL8852B was read; the probe reads one only given a --wifi network whose key file the boot read",
        ))
    } else if stopped > 0 {
        Verdict::Failed(format!(
            "{stopped} of {found} RTL8852B stopped before stage={}",
            Stage::Cut.name()
        ))
    } else if cav > 0 {
        Verdict::Failed(format!(
            "{cav} of {found} RTL8852B is cut 0 (CAV), which no linux-firmware image runs"
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

#[cfg(test)]
mod tests {
    use super::*;

    const AT: &str = "0000:03:00.0";

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
        assert_eq!(DRIVEN, Stage::Cut);
    }

    #[test]
    fn a_cut_this_image_drives_passes_with_its_word() {
        let report = report([(
            AT,
            Reached::Cut {
                sys_cfg1: 0x0000_1f00,
                cut: 1,
                name: Some("CBV"),
            },
        )]);
        assert_eq!(report.verdict, Verdict::Passed);
        assert_eq!(
            report.lines,
            [
                "WIFI CHECK 0000:03:00.0 stage=cut cut=1 (CBV) sys_cfg1=0x00001f00",
                "WIFI CHECK passed: every RTL8852B reached cut, the last stage this image drives",
            ]
        );
    }

    #[test]
    fn cut_zero_a_failed_read_and_no_function_fail_naming_why() {
        let cav = report([(
            AT,
            Reached::Cut {
                sys_cfg1: 0,
                cut: 0,
                name: Some("CAV"),
            },
        )]);
        assert!(matches!(&cav.verdict, Verdict::Failed(why) if why.contains("cut 0 (CAV)")));
        assert!(cav.lines[0].ends_with("linux-firmware has no RTL8852B image for this cut"));
        assert_eq!(cav.lines.len(), 1);

        let unread = report([
            (AT, Reached::NotRead("the function did not answer")),
            (
                "0000:04:00.0",
                Reached::Cut {
                    sys_cfg1: 0x2000,
                    cut: 2,
                    name: Some("CCV"),
                },
            ),
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
    fn a_cut_past_rtw89s_names_still_passes_under_its_number() {
        let report = report([(
            AT,
            Reached::Cut {
                sys_cfg1: 0x6000,
                cut: 6,
                name: None,
            },
        )]);
        assert_eq!(report.verdict, Verdict::Passed);
        assert_eq!(
            report.lines[0],
            "WIFI CHECK 0000:03:00.0 stage=cut cut=6 (past rtw89's CHIP_CFV) sys_cfg1=0x00006000"
        );
    }
}
