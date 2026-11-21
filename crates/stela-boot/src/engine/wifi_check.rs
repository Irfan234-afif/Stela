//! The Wi-Fi check (`--wifi-check`), once the host's devices have started:
//! a line for each RTL8852B the probe read (`stela_boot_core::wifi_check`),
//! then the verdict, and the boot stops before the guest's storage is
//! opened. The options that select the check also restart the PC at the
//! stop (`stop::restart_at_stop`), so the log is stored and the PC returns
//! to its own boot order.
use crate::output;
use alloc::{format, string::String, vec::Vec};
use stela_boot_core::wifi_check::{self, Reached, Verdict};
use stela_drivers::{bus::pci::Address, net::wifi::realtek::identity};

/// What the probe read of each RTL8852B before power-on, or why it did not.
pub(super) type Identities = Vec<(
    Address,
    core::result::Result<identity::Unpowered, stela_drivers::probe::Error>,
)>;

/// Report `identities` and stop: passed when every function reached the
/// stage this image drives, failed naming why otherwise.
pub(super) fn check(identities: &Identities) -> ! {
    let failures: Vec<String> = identities
        .iter()
        .map(|(_, read)| match read {
            Ok(_) => String::new(),
            Err(error) => format!("{error}"),
        })
        .collect();
    let report = wifi_check::report(identities.iter().zip(&failures).map(
        |((address, read), failure)| {
            let reached = match read {
                Err(_) => Reached::NotRead(failure),
                Ok(read) => match read.cut() {
                    Some(cut) => Reached::Cut {
                        sys_cfg1: read.observed.sys_cfg1,
                        cut,
                        name: identity::rtw89_cut_name(cut),
                    },
                    None => Reached::NotRead("the function did not answer the read of SYS_CFG1"),
                },
            };
            (address, reached)
        },
    ));
    for line in &report.lines {
        output::arguments(format_args!("{line}\n"));
    }
    match report.verdict {
        Verdict::Passed => output::terminate(0x10),
        Verdict::Failed(why) => output::fatal(format_args!("the Wi-Fi check failed: {why}")),
    }
}
