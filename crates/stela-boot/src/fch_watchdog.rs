//! The FCH watchdog of an unattended run (`stela_boot_core::fch_watchdog`)
//! at its registers' physical addresses: the firmware's page tables reach
//! them before its exit, and the loader's root, which maps the firmware's
//! runtime regions by identity, after it. The engine's roots do not: its
//! stop reaches them in the loader's root, as it calls the firmware's
//! services (`stop_record`), where the first hardware run's stop faulted
//! on them and the PC waited for the watchdog's own reset.
use crate::output;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use stela_boot_core::fch_watchdog::{self as fch, Registers};

/// Whether this image may touch an armed watchdog.
static ARMED: AtomicBool = AtomicBool::new(false);
/// The loader's root the engine reaches the registers in; zero in the
/// loader, whose tables reach them.
static ROOT: AtomicU64 = AtomicU64::new(0);

/// Run `access` where the registers are mapped.
fn mapped<T>(access: impl FnOnce(&mut Mmio) -> T) -> T {
    match ROOT.load(Ordering::Acquire) {
        0 => access(&mut Mmio),
        // SAFETY: the loader's live root the handoff named, which maps the
        // FCH's runtime region by identity (`hand_over`); only a stop calls
        // this in the engine, and a stop resumes nothing.
        root => unsafe { crate::engine::in_loader_root_at_stop(root, || access(&mut Mmio)) },
    }
}

struct Mmio;

impl Registers for Mmio {
    fn read8(&mut self, address: u64) -> u8 {
        // SAFETY: an FCH register in the ACPI MMIO window, identity mapped
        // uncached wherever `ARMED` or `arm` lets this run.
        unsafe { (address as *const u8).read_volatile() }
    }
    fn write8(&mut self, address: u64, value: u8) {
        // SAFETY: as `read8`.
        unsafe { (address as *mut u8).write_volatile(value) }
    }
    fn read32(&mut self, address: u64) -> u32 {
        // SAFETY: as `read8`; the register is 32 bits wide and aligned.
        unsafe { (address as *const u32).read_volatile() }
    }
    fn write32(&mut self, address: u64, value: u32) {
        // SAFETY: as `read32`.
        unsafe { (address as *mut u32).write_volatile(value) }
    }
}

/// For a run that restarts the PC at its stop (`--wifi-check`,
/// `--restart-at-stop`), named in `options`: the stop restarts from here
/// on, and the watchdog resets the PC if the boot hangs before any stop.
/// Called before the firmware's exit, while its page tables are active.
pub(crate) fn arm_unattended(options: &[u8]) {
    let Some(system) = core::str::from_utf8(options)
        .ok()
        .and_then(|text| stela_boot_core::options::System::parse(text).ok())
    else {
        return;
    };
    if !(system.wifi_check || system.restart_at_stop) {
        return;
    }
    crate::stop::restart_at_stop();
    let outcome = arm();
    output::arguments(format_args!("{}", fch::line(&outcome)));
}

fn arm() -> Result<fch::Armed, fch::Refusal> {
    use core::arch::x86_64::__cpuid;
    use stela_boot_core::{host_identity, reset_reason};
    let leaf0 = __cpuid(0);
    let vendor = host_identity::vendor([leaf0.ebx, leaf0.edx, leaf0.ecx]);
    let (family, _, _) = host_identity::signature_parts(__cpuid(1).eax);
    if !reset_reason::applies(&vendor, family) {
        return Err(fch::Refusal::NotZen);
    }
    if !crate::firmware::identity_mapped(fch::PM)
        || !crate::firmware::identity_mapped(fch::PM + fch::SPAN - 1)
    {
        return Err(fch::Refusal::Unmapped);
    }
    let armed = fch::arm(&mut Mmio, fch::RUN_SECONDS)?;
    ARMED.store(true, Ordering::Release);
    Ok(armed)
}

/// What the engine is told: whether the watchdog runs, its registers
/// `reached` in the loader's root through a firmware runtime region. One
/// the engine could not reach is stopped here, so that no reset leaves it
/// running.
pub(crate) fn hand_over(reached: bool) -> bool {
    if !ARMED.load(Ordering::Acquire) {
        return false;
    }
    if !reached {
        fch::stop(&mut Mmio);
        ARMED.store(false, Ordering::Release);
        output::arguments(format_args!(
            "HOST WATCHDOG FCH stopped: no runtime region maps its registers for the engine\n"
        ));
        return false;
    }
    true
}

/// The engine's image takes the loader's word for a running watchdog,
/// whose registers it reaches in the loader's `root`.
pub(crate) fn adopt(armed: bool, root: u64) {
    ROOT.store(root, Ordering::Release);
    ARMED.store(armed && root != 0, Ordering::Release);
}

/// Stop the watchdog before a restart; whether one was running.
pub(crate) fn stop() -> bool {
    if !ARMED.load(Ordering::Acquire) {
        return false;
    }
    mapped(|registers| fch::stop(registers));
    true
}

/// Count `seconds` again on a watchdog [`stop`] stopped: a restart that did
/// not take.
pub(crate) fn rearm(seconds: u16) {
    if ARMED.load(Ordering::Acquire) {
        mapped(|registers| fch::rearm(registers, seconds));
    }
}
