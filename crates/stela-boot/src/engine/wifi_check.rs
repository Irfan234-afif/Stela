//! The Wi-Fi check (`--wifi-check`), once the host's devices have started
//! and the host's network has tried its adapters: a line for each stage
//! every RTL8852B reached, stage 1's cut, firmware and efuse, stage 2's
//! radio with what its listen heard, the station's association and the
//! lease the host's network got over it (`stela_boot_core::wifi_check`),
//! then the verdict, and the boot stops before the guest's storage is
//! opened. With `--network-check`, the check's POST goes over the station
//! once the lease came over it. With `--wifi-check-ser`, a recovery stage
//! follows the lease: the station's firmware is asked to crash, and the
//! chip must come up cold, rejoin and lease again
//! (`network::HostNetwork::recover_station`). The options that select the
//! check also restart the PC at the stop (`stop::restart_at_stop`), so the
//! log is stored and the PC returns to its own boot order.
use super::network::{Shared, Tried};
use crate::{Result, output};
use alloc::{string::ToString, vec::Vec};
use stela_boot_core::wifi_check::{self, Network, Reached, Recovery, Verdict};
use stela_drivers::{net::wifi::realtek::identity, probe::Rtl8852b};

/// Report `chips` and what the host's network did with their stations,
/// `tried` the adapters it got no address over, POSTing to `url` over the
/// station that got the lease and, with `ser`, crashing its firmware and
/// checking its recovery, and stop: passed when every function reached
/// the last stage asked for, failed naming why otherwise.
pub(super) fn check(
    chips: &[Rtl8852b],
    network: &Option<Result<Shared>>,
    tried: &[Tried],
    url: Option<&str>,
    ser: bool,
) -> ! {
    let summaries: Vec<_> = chips
        .iter()
        .map(|chip| chip.outcome.as_ref().map(|outcome| outcome.summary()))
        .collect();
    // The adapter that got the address, read last: its station has run
    // since the lease, and a POST over it follows.
    let leased = match network {
        Some(Ok(shared)) => Some(shared.0.borrow_mut().tried()),
        _ => None,
    };
    let posted = match (url, network, &leased) {
        (Some(url), Some(Ok(shared)), Some(leased)) if leased.driver == wifi_check::DRIVER => {
            Some(super::network::check(shared, url).map_err(|error| error.to_string()))
        }
        _ => None,
    };
    // The recovery stage runs on a station that holds an IPv4 lease.
    let recovered = match (ser, network, &leased) {
        (true, Some(Ok(shared)), Some(leased))
            if leased.driver == wifi_check::DRIVER && matches!(leased.lease, Ok(Some(_))) =>
        {
            Some(shared.0.borrow_mut().recover_station())
        }
        _ => None,
    };
    let tried: Vec<_> = tried
        .iter()
        .chain(&leased)
        .map(|tried| wifi_check::Tried {
            driver: tried.driver,
            location: &tried.location,
            wireless: tried.wireless,
            lease: tried.lease.as_ref().copied().map_err(|why| why.as_str()),
            associated: tried.associated.as_ref(),
            progress: tried.progress.as_ref(),
            state: tried.state.as_deref(),
            dhcp: tried.dhcp.as_deref(),
        })
        .collect();
    let network = Network {
        tried: &tried,
        check: posted
            .as_ref()
            .map(|posted| posted.as_ref().map(|_| ()).map_err(|why| why.as_str())),
        recovery: recovered.as_ref().map(|recovered| Recovery {
            halted: recovered.halted.as_deref(),
            took_ms: recovered.took_ms,
            lease: recovered.lease,
            recoveries: recovered.recoveries,
            stopped: recovered
                .stopped
                .as_ref()
                .map(|(step, why)| (*step, why.as_str())),
        }),
    };
    let report = wifi_check::report(
        chips.iter().zip(&summaries).map(|(chip, summary)| {
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
        }),
        &network,
    );
    for line in &report.lines {
        output::arguments(format_args!("{line}\n"));
    }
    match report.verdict {
        Verdict::Passed => output::terminate(0x10),
        Verdict::Failed(why) => output::fatal(format_args!("the Wi-Fi check failed: {why}")),
    }
}
