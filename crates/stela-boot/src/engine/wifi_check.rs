//! The Wi-Fi check (`--wifi-check`), once the host's devices have started:
//! a line for each stage every RTL8852B reached in the probe
//! (`stela_boot_core::wifi_check`), then the verdict, and the boot stops
//! before the guest's storage is opened. The options that select the check
//! also restart the PC at the stop (`stop::restart_at_stop`), so the log is
//! stored and the PC returns to its own boot order.
use crate::output;
use alloc::vec::Vec;
use stela_boot_core::wifi_check::{self, Reached, Verdict};
use stela_drivers::{net::wifi::realtek::identity, probe::Rtl8852b};

/// Report `chips` and stop: passed when every function reached the stage
/// this image drives, failed naming why otherwise.
pub(super) fn check(chips: &[Rtl8852b]) -> ! {
    let summaries: Vec<_> = chips
        .iter()
        .map(|chip| chip.outcome.as_ref().map(|outcome| outcome.summary()))
        .collect();
    let report = wifi_check::report(chips.iter().zip(&summaries).map(|(chip, summary)| {
        let reached = match &chip.identity {
            Err(why) => Reached::NotRead(why),
            Ok(read) => match read.cut() {
                Some(cut) => Reached::Cut {
                    sys_cfg1: read.observed.sys_cfg1,
                    cut,
                    name: identity::rtw89_cut_name(cut),
                    stage1: summary.as_ref(),
                },
                None => Reached::NotRead("the function did not answer the read of SYS_CFG1"),
            },
        };
        (chip.address, reached)
    }));
    for line in &report.lines {
        output::arguments(format_args!("{line}\n"));
    }
    match report.verdict {
        Verdict::Passed => output::terminate(0x10),
        Verdict::Failed(why) => output::fatal(format_args!("the Wi-Fi check failed: {why}")),
    }
}
