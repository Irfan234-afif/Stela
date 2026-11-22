// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's RF calibration tables ([`table`]) and `rtw89_rfk_parser`, which
//! runs one: each entry is a register write `_rfk_handler` dispatches, from
//! pinned rtw89/phy.h and phy.c. Running a table proves nothing about the
//! calibration it belongs to.
//!
//! The calibrations rtw8852b.c's `rtw8852b_rfk_init` runs once the BB and RF
//! tables are loaded, from pinned rtw89/rtw8852b_rfk.c line by line: DPK
//! init ([`dpk_init`]), RCK ([`rck`]), DACK ([`dack`]) and RX DCK
//! ([`rx_dck`]), composed by [`init`]; and what rtw8852b.c's
//! `rtw8852b_rfk_channel` runs on the channel it joins, composed by
//! [`channel()`]: the MCC table ([`ntfy::mcc_get_ch_info`]), RX DCK, the IQ
//! calibration ([`iqk`]), TSSI ([`tssi`]) and DPK ([`dpk`]), then the
//! RF_NTFY_MCC H2C ([`ntfy`]). What rtw89 keeps between them in
//! `rtwdev` is [`State`], which the caller carries from one calibration to
//! the next. rtw89 runs each with PHY 0 and DBCC off, where `_kpath` gives
//! both paths; so do these. The coex notifications rtw89 sends around a
//! calibration (`rtw89_btc_ntfy_wl_rfk`) are no-ops here: Stela gives the
//! antennas to Wi-Fi alone. A timeout rtw89 only logs or notes is noted
//! here too and the calibration goes on; an access the chip refuses ends
//! it, where rtw89 would read `INV_RF_DATA` from an SWSI that stayed busy
//! and go on. A calibration that returns proves that its polls were
//! answered, not that the radio is calibrated.
use crate::wifi::realtek::ax::{
    coex::Commands,
    h2c,
    h2creg::Mailbox,
    io::{Error, Io, Registers},
    mac::{self, SchTxSel},
    registers::{MASKDWORD, RFREG_MASK},
};
use reg::*;

pub mod dack;
pub mod dpk;
pub mod iqk;
pub mod ntfy;
pub mod pmac;
pub mod rck;
pub mod reg;
pub mod rx_dck;
pub mod table;
pub mod tssi;

/// `RF_PATH_NUM_8852B`.
pub const RF_PATH_NUM: u8 = 2;
/// `RF_PATH_A`.
pub const RF_PATH_A: u8 = 0;
/// `RF_PATH_B`.
pub const RF_PATH_B: u8 = 1;
/// `RF_AB`: both paths, as `enum rtw89_rf_path_bit` has them.
pub const RF_AB: u8 = 0b11;
/// `RTW89_PHY_NUM`.
pub const PHY_NUM: usize = 2;

/// `_kpath(rtwdev, RTW89_PHY_0)` with `rtwdev->dbcc_en` false: both paths.
pub const fn kpath() -> u8 {
    RF_AB
}

/// What rtw89 keeps in `rtwdev` across RTL8852B's calibrations, as far as
/// the ones here read or write it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct State {
    /// `rtwdev->dack`.
    pub dack: dack::DackInfo,
    /// `rtwdev->dpk.dpk_gs`, per PHY.
    pub dpk_gs: [u8; PHY_NUM],
    /// `rtwdev->rfk_mcc.data[0]`.
    pub rfk_mcc: RfkMcc,
    /// `rtwdev->is_tssi_mode` for paths A and B.
    pub is_tssi_mode: [bool; RF_PATH_NUM as usize],
    /// `rtwdev->iqk`.
    pub iqk: iqk::IqkInfo,
    /// `rtwdev->dpk` but its `dpk_gs`.
    pub dpk: dpk::DpkInfo,
    /// `rtwdev->tssi` but what the efuse gives.
    pub tssi: tssi::TssiInfo,
}

/// `RTW89_RFK_CHS_NR`.
pub const RFK_CHS_NR: usize = 3;

/// `struct rtw89_rfk_mcc_info_data`, as far as an RTL8852B reads it: the
/// channel and band each MCC table was calibrated on, and the table
/// [`ntfy::mcc_get_ch_info`] chose for the channel. `bw` and `rf18`, which
/// RTL8852B leaves alone, are left out.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RfkMcc {
    /// `ch`: 0 for a table never used.
    pub ch: [u8; RFK_CHS_NR],
    /// `band`: `enum rtw89_band`.
    pub band: [u8; RFK_CHS_NR],
    /// `table_idx`: 0 or 1.
    pub table_idx: u8,
}

/// `enum rtw89_band`, as far as an RTL8852B has it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Band {
    /// `RTW89_BAND_2G`.
    Ghz2 = 0,
    /// `RTW89_BAND_5G`.
    Ghz5 = 1,
}

/// `enum rtw89_bandwidth`, as far as an RTL8852B uses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Bandwidth {
    /// `RTW89_CHANNEL_WIDTH_20`.
    Mhz20 = 0,
    /// `RTW89_CHANNEL_WIDTH_40`.
    Mhz40 = 1,
    /// `RTW89_CHANNEL_WIDTH_80`.
    Mhz80 = 2,
}

/// What the calibrations read of `struct rtw89_chan`, the channel context's
/// channel: its band, width and number. The number is `chan->channel`, the
/// center channel (42 for an 80 MHz channel from 36 to 48).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel {
    pub band: Band,
    pub width: Bandwidth,
    pub number: u8,
}

/// `rtw8852b_backup_bb_regs`.
const BACKUP_BB_REGS: [u32; 3] = [0x2344, 0x5800, 0x7800];
/// `rtw8852b_backup_rf_regs`.
const BACKUP_RF_REGS: [u32; 11] = [
    0xde, 0xdf, 0x8b, 0x90, 0x97, 0x85, 0x1e, 0x0, 0x2, 0x5, 0x10005,
];

/// `_rfk_backup_bb_reg`.
pub(crate) fn rfk_backup_bb_reg<I: Io + ?Sized>(
    io: &mut I,
) -> Result<[u32; BACKUP_BB_REGS.len()], Error> {
    let mut values = [0; BACKUP_BB_REGS.len()];
    for (value, register) in values.iter_mut().zip(BACKUP_BB_REGS) {
        *value = io.phy_read32_mask(register, MASKDWORD)?;
    }
    Ok(values)
}

/// `_rfk_backup_rf_reg`.
pub(crate) fn rfk_backup_rf_reg<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
) -> Result<[u32; BACKUP_RF_REGS.len()], Error> {
    let mut values = [0; BACKUP_RF_REGS.len()];
    for (value, address) in values.iter_mut().zip(BACKUP_RF_REGS) {
        *value = io.read_rf(path, address, RFREG_MASK)?;
    }
    Ok(values)
}

/// `_rfk_restore_bb_reg`.
pub(crate) fn rfk_restore_bb_reg<I: Io + ?Sized>(
    io: &mut I,
    values: &[u32; BACKUP_BB_REGS.len()],
) -> Result<(), Error> {
    for (&value, register) in values.iter().zip(BACKUP_BB_REGS) {
        io.phy_write32_mask(register, MASKDWORD, value)?;
    }
    Ok(())
}

/// `_rfk_restore_rf_reg`.
pub(crate) fn rfk_restore_rf_reg<I: Io + ?Sized>(
    io: &mut I,
    values: &[u32; BACKUP_RF_REGS.len()],
    path: u8,
) -> Result<(), Error> {
    for (&value, address) in values.iter().zip(BACKUP_RF_REGS) {
        io.write_rf(path, address, RFREG_MASK, value)?;
    }
    Ok(())
}

/// `rtw89_chip_stop_sch_tx` and `rtw89_chip_resume_sch_tx` on PHY 0, which
/// rtw8852b_rx_dck and rtw8852b_iqk put around their work.
pub trait Scheduler<I: Io + ?Sized> {
    /// `rtw89_chip_stop_sch_tx(rtwdev, RTW89_PHY_0, &tx_en,
    /// RTW89_SCH_TX_SEL_ALL)`: the enables to resume.
    fn stop(&mut self, io: &mut I) -> Result<u16, mac::Cause>;
    /// `rtw89_chip_resume_sch_tx(rtwdev, RTW89_PHY_0, tx_en)`.
    fn resume(&mut self, io: &mut I, tx_en: u16) -> Result<(), mac::Cause>;
}

/// `rtw8852b_chip_ops`' scheduler: `rtw89_mac_stop_sch_tx` and
/// `rtw89_mac_resume_sch_tx`, through `firmware`, the running firmware's
/// mailbox, when there is one.
pub struct MacScheduler<'a> {
    pub firmware: Option<&'a mut Mailbox>,
}

impl<I: Io + ?Sized> Scheduler<I> for MacScheduler<'_> {
    fn stop(&mut self, io: &mut I) -> Result<u16, mac::Cause> {
        mac::stop_sch_tx(io, self.firmware.as_deref_mut(), SchTxSel::All)
    }
    fn resume(&mut self, io: &mut I, tx_en: u16) -> Result<(), mac::Cause> {
        mac::resume_sch_tx(io, self.firmware.as_deref_mut(), tx_en)
    }
}

/// `work` between a stop and a resume of the scheduler, as rtw8852b_rx_dck
/// and rtw8852b_iqk run it, with `_wait_rx_mode` first. rtw89 ignores what
/// the scheduler returns; so does this, and returns the first refusal for
/// the caller to log. A stop that failed is not resumed, where rtw89 resumes
/// with the enables it read before failing. A refused access ends `work`
/// with the scheduler left stopped.
fn paused<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    work: impl FnOnce(&mut I) -> Result<(), Error>,
) -> Result<Option<mac::Cause>, Error> {
    let stopped = scheduler.stop(io);
    wait_rx_mode(io, kpath())?;
    work(io)?;
    Ok(match stopped {
        Ok(tx_en) => scheduler.resume(io, tx_en).err(),
        Err(cause) => Some(cause),
    })
}

/// `read_poll_timeout_atomic(…, step_us, bound_us, false, …)` over a
/// condition that may read more than once, counted in steps as
/// [`Registers::poll32`] counts: `ready` every step until it holds, and once
/// past the bound. Whether it held.
pub(crate) fn poll<I: Io + ?Sized>(
    io: &mut I,
    step_us: u64,
    bound_us: u64,
    mut ready: impl FnMut(&mut I) -> Result<bool, Error>,
) -> Result<bool, Error> {
    let mut waited = 0;
    loop {
        if ready(io)? {
            return Ok(true);
        }
        if waited >= bound_us {
            return Ok(false);
        }
        io.delay_us(step_us);
        waited += step_us;
    }
}

/// `_wait_rx_mode`: for each path in `kpath`, its RF mode every 2 us for up
/// to 5 ms until it is not 2. Returns the paths whose mode stayed 2, which
/// rtw89 only logs.
pub fn wait_rx_mode<I: Io + ?Sized>(io: &mut I, kpath: u8) -> Result<u8, Error> {
    let mut stuck = 0;
    for path in 0..RF_PATH_NUM {
        if kpath & (1 << path) == 0 {
            continue;
        }
        if !poll(io, 2, 5000, |io| {
            Ok(io.read_rf(path, RR_MOD, RR_MOD_MASK)? != 2)
        })? {
            stuck |= 1 << path;
        }
    }
    Ok(stuck)
}

/// `rtw8852b_dpk_init`, which is `_set_dpd_backoff(rtwdev, RTW89_PHY_0)`:
/// a DPD backoff and TX scale that add up to 44 or more move the backoff to
/// the BB, with each path's DPD set to 0 dB and `dpk_gs` 0x7f; otherwise
/// `dpk_gs` is 0x5b.
pub fn dpk_init<I: Io + ?Sized>(io: &mut I, state: &mut State) -> Result<(), Error> {
    const PHY: u32 = 0;
    let kpath = kpath();
    let ofdm_bkof = io.phy_read32_mask(R_DPD_BF + (PHY << 13), B_DPD_BF_OFDM)? as u8;
    let tx_scale = io.phy_read32_mask(R_DPD_BF + (PHY << 13), B_DPD_BF_SCA)? as u8;
    if u32::from(ofdm_bkof) + u32::from(tx_scale) >= 44 {
        state.dpk_gs[PHY as usize] = 0x7f;
        for path in 0..RF_PATH_NUM {
            if kpath & (1 << path) == 0 {
                continue;
            }
            io.phy_write32_mask(R_DPD_CH0A + (u32::from(path) << 8), B_DPD_CFG, 0x7f7f7f)?;
        }
    } else {
        state.dpk_gs[PHY as usize] = 0x5b;
    }
    Ok(())
}

/// `rtw8852b_rfk_init`: neither path in TSSI mode, the MCC table cleared,
/// then DPK init, RCK, DACK and RX DCK on PHY 0, in that order. Returns the
/// scheduler's refusal around RX DCK, which rtw89 ignores.
pub fn init<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    state: &mut State,
) -> Result<Option<mac::Cause>, Error> {
    state.is_tssi_mode = [false; RF_PATH_NUM as usize];
    state.rfk_mcc = RfkMcc::default();
    dpk_init(io, state)?;
    rck::rck(io)?;
    dack::dack(io, &mut state.dack)?;
    rx_dck::rx_dck(io, scheduler, state.is_tssi_mode)
}

/// What [`channel()`] reads besides the channel and its state.
#[derive(Clone, Copy, Debug)]
pub struct ChannelInputs<'a> {
    pub tssi: tssi::Inputs<'a>,
    pub dpk: dpk::Inputs,
}

/// What rtw89 ignores of [`channel()`]: each calibration's scheduler
/// refusal and what sending RF_NTFY_MCC returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Calibrated {
    pub rx_dck: Option<mac::Cause>,
    pub iqk: Option<mac::Cause>,
    pub tssi: Option<mac::Cause>,
    pub dpk: Option<mac::Cause>,
    pub ntfy_mcc: Result<(), h2c::Error>,
}

/// `rtw8852b_rfk_channel` on PHY 0 after a switch to `channel`: the MCC
/// table chosen, then RX DCK, IQK, TSSI with its alignment and DPK, each
/// with the scheduler stopped around it, and RF_NTFY_MCC to `commands`. The
/// coex notifications around them (`rtw89_btc_ntfy_conn_rfk` and
/// `rtw89_btc_ntfy_preserve_bt_time`) are no-ops here. A refused access
/// ends it; the refusals and the H2C's result rtw89 ignores are returned.
pub fn channel<I, S, C>(
    io: &mut I,
    scheduler: &mut S,
    commands: &mut C,
    state: &mut State,
    channel: Channel,
    inputs: &ChannelInputs<'_>,
) -> Result<Calibrated, Error>
where
    I: Io + ?Sized,
    S: Scheduler<I> + ?Sized,
    C: Commands<I> + ?Sized,
{
    ntfy::mcc_get_ch_info(&mut state.rfk_mcc, channel);

    let rx_dck = rx_dck::rx_dck(io, scheduler, state.is_tssi_mode)?;
    let iqk = iqk::iqk(io, scheduler, state, channel)?;
    let tssi = tssi::tssi(io, scheduler, state, channel, true, &inputs.tssi)?;
    let dpk = dpk::dpk(io, scheduler, state, channel, inputs.dpk)?;

    let ntfy_mcc = ntfy::rf_ntfy_mcc(io, commands, &state.rfk_mcc);
    Ok(Calibrated {
        rx_dck,
        iqk,
        tssi,
        dpk,
        ntfy_mcc,
    })
}

/// `rtw8852b_rfk_band_changed`: [`tssi::tssi_scan`] on `channel`, which a
/// switch to another band runs before the switch is done.
pub fn band_changed<I: Io + ?Sized>(
    io: &mut I,
    state: &mut State,
    channel: Channel,
    inputs: &tssi::Inputs<'_>,
) -> Result<(), Error> {
    tssi::tssi_scan(io, state, channel, inputs)
}

/// `rtw8852b_rfk_scan`: [`tssi::wifi_scan_notify`] as a scan starts
/// (`start`) or ends on `channel`.
pub fn scan<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    state: &mut State,
    start: bool,
    channel: Channel,
    inputs: &tssi::Inputs<'_>,
) -> Result<Option<mac::Cause>, Error> {
    tssi::wifi_scan_notify(io, scheduler, state, start, channel, inputs)
}

/// `rtw89_rfk_parser_by_cond`: `if_true` when `condition` holds, otherwise
/// `if_false`.
pub fn run_by_cond<I: Io + ?Sized>(
    io: &mut I,
    condition: bool,
    if_true: &[Entry],
    if_false: &[Entry],
) -> Result<(), Error> {
    run(io, if condition { if_true } else { if_false })
}

/// One `struct rtw89_reg5_def`, by its `RTW89_DECL_RFK_*` flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry {
    /// `RTW89_DECL_RFK_WRF`: `rtw89_write_rf`.
    RfWrite {
        path: u8,
        address: u32,
        mask: u32,
        data: u32,
    },
    /// `RTW89_DECL_RFK_WM`: `rtw89_phy_write32_mask`.
    Mask { address: u32, mask: u32, data: u32 },
    /// `RTW89_DECL_RFK_WS`: `rtw89_phy_write32_set`.
    Set { address: u32, bits: u32 },
    /// `RTW89_DECL_RFK_WC`: `rtw89_phy_write32_clr`.
    Clear { address: u32, bits: u32 },
    /// `RTW89_DECL_RFK_DELAY`: `udelay`.
    Delay { microseconds: u32 },
}

/// `rtw89_rfk_parser`: every entry of `table`, in order. The first access
/// the chip refuses ends it.
pub fn run<I: Io + ?Sized>(io: &mut I, table: &[Entry]) -> Result<(), Error> {
    for entry in table {
        match *entry {
            Entry::RfWrite {
                path,
                address,
                mask,
                data,
            } => io.write_rf(path, address, mask, data)?,
            Entry::Mask {
                address,
                mask,
                data,
            } => io.phy_write32_mask(address, mask, data)?,
            Entry::Set { address, bits } => io.phy_write32_set(address, bits)?,
            Entry::Clear { address, bits } => io.phy_write32_clr(address, bits)?,
            Entry::Delay { microseconds } => io.delay_us(u64::from(microseconds)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod calibration_tests;
