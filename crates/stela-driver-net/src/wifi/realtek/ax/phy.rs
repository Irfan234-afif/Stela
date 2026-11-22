// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! An RTL8852B's BB and RF register tables loaded as pinned rtw89 loads them
//! once its MAC is up (phy.c, rtw8852b.c, rtw8852b_common.c), from the
//! tables its firmware's elements carry ([`super::elements`]):
//!
//! - [`init_bb_afe`], `rtw89_phy_init_bb_afe`: the AFE power sequence of
//!   a firmware AFE element, which `rtw89_core_start` runs before
//!   `rtw89_mac_init`; without the element it does nothing, and the pinned
//!   0.29.29.18 image has none;
//! - [`reset_bb_rf`], `rtw89_chip_reset_bb_rf`: RTL8852B's
//!   `__rtw8852bx_mac_disable_bb_rf`, then its `__rtw8852bx_mac_enable_bb_rf`
//!   ([`super::mac`]'s);
//! - [`init_bb_reg`], `rtw89_phy_init_bb_reg`: the BB table through
//!   `rtw89_phy_config_bb_reg`, RTL8852B's `init_txpwr_unit`
//!   (`__rtw8852bx_init_txpwr_unit` with `__rtw8852bx_set_txpwr_ul_tb_offset`
//!   at 0 dB), the BB gain table through `rtw89_phy_config_bb_gain_ax`,
//!   which writes no register and fills [`BbGain`] (`rtwdev->bb_gain.ax`),
//!   then `rtw8852b_bb_reset` with `__rtw8852bx_bb_reset_all`;
//! - [`init_rf_reg`], `rtw89_phy_init_rf_reg(rtwdev, false)`: each path's
//!   radio table through `rtw89_phy_config_rf_reg_v1`, whose writes from
//!   0x100 up are mirrored to the firmware in RF_REG pages
//!   ([`super::h2c::phy::RfRegInfo`]) once the path's table is in;
//! - [`init_rf_nctl`], `rtw89_phy_init_rf_nctl`: `rtw89_phy_preinit_rf_nctl_ax`
//!   (the IQK/DPK clocks and resets with RTL8852B's second `R_IOQ_IQK_DPK`
//!   bit, then the NCTL poll), then the NCTL table through
//!   `rtw89_phy_config_bb_reg`; RTL8852B has no `nctl_post_table`.
//!
//! [`load`] runs the middle three as `rtw89_core_start` does, between
//! `rtw89_mac_init` with the BTC power-on notice and the BTC init: the BB and
//! RF reset, the BB tables, `rtw89_chip_bb_postinit` (NULL for RTL8852B) and
//! the radio tables. [`init_rf_nctl`] runs later, from `rtw89_phy_dm_init`.
//!
//! Every table goes through `rtw89_phy_init_reg`: [`sel_headline`]
//! (`rtw89_phy_sel_headline`) picks the table's package for the efuse's RFE
//! type and the chip's cut, by RFE and cut, then RFE with any cut, then RFE
//! with the highest cut listed, then any RFE with the highest cut; the
//! branches (IF, ELIF, ELSE, END, CHECK) after the headlines then keep the
//! lines of the package picked. A table with no package for the board loads
//! nothing ([`Warning::InvalidPackage`]), and an ELSE reached before any
//! branch matched stops the table there ([`Warning::FailedToLoad`]); rtw89
//! logs both and goes on, and so does this module, reporting them.
//!
//! Delays are asked of the [`Io`]: in the BB and NCTL tables addresses 0xfe
//! to 0xf9 wait 50 ms, 5 ms, 1 ms, 50 us, 5 us and 1 us; in the radio tables
//! only 0xfe is a delay (50 ms), and 0xf9 to 0xfd are RF registers like the
//! rest. Data `BYPASS_CR_DATA` in a BB or NCTL table skips its line. Each step
//! makes the reads and writes its rtw89 counterpart makes, in the same order,
//! read-modify-write included, with rtw89's raw PCIe I/O: no packing, and
//! `rtw89_phy_write32` a plain write at [`io::CR_BASE`] plus the address.
//! What rtw89 only logs is a [`Warning`], in rtw89's order; a register
//! access the [`Io`] refuses, or an XTAL SI timeout in the reset (which
//! rtw89 returns from `rtw89_core_start`), is an [`Error`].
//!
//! The seams, and what is left out:
//! - The BTC calls around these steps (`rtw89_btc_ntfy_poweron`,
//!   `rtw89_btc_ntfy_init`) are coex's (3.9); what `rtw89_phy_dm_init` runs
//!   before the NCTL (statistics, `bb_sethw`, DIG, CFO, EDCCA and the rest,
//!   with `rfk_hw_init` NULL for RTL8852B) is the channel's and the dynamic
//!   mechanisms' (3.4, 3.10), and what it runs after (`rtw89_chip_rfk_init`,
//!   TX power control, power trim, the TX/RX path) is the RF calibrations'
//!   and TX power's (3.5, 3.6). [`BbGain`] is what the channel set (3.4)
//!   reads for its gain error and RPL offsets.
//! - DBCC: an RTL8852B runs with `dbcc_en` false, so no table is loaded for
//!   PHY 1, and the AFE's BB1 writes go to PHY 0's registers as rtw89's
//!   `rtw89_phy_write32_idx` sends them.
//! - rtw89's compiled-in tables (`rtw8852b_table.c`), which it uses when the
//!   firmware has no element: Stela carries none, so [`Tables::from_elements`]
//!   refuses firmware without a BB, BB gain, radio A and B or NCTL table,
//!   naming the element. The BB gain element is not among RTL8852B's needed
//!   elements, but the pinned image has it.
//! - USB's firmware command offload and SDIO, and every other chip.
//!
//! A load that returns proves that every write rtw89 makes was made and each
//! RF_REG page's BD written; it proves nothing about the radio, nor that the
//! firmware took the pages, nor that an RF write through SWSI reached the
//! RF (SWSI reports no completion for writes).
use super::{
    elements::{Board, Element, Elements, Id, PhyTable, Reg2},
    h2c::phy::{Outsrc, RfRegError, RfRegInfo},
    io::{self, CR_BASE, Io, Registers},
    mac,
    registers::*,
};
use alloc::vec::Vec;

/// `rtw8852b_chip_info.rf_path_num`.
pub const RF_PATH_NUM: usize = 2;
/// `BYPASS_CR_DATA`: a BB line with this data is skipped.
pub const BYPASS_CR_DATA: u32 = 0xbabe_cafe;
/// `PHY_HEADLINE_VALID`: a headline's top nibble.
pub const PHY_HEADLINE_VALID: u32 = 0xf;
/// The branch lines' top nibbles: `PHY_COND_BRANCH_IF`, `_ELIF`, `_ELSE`,
/// `_END` and `PHY_COND_CHECK`.
pub const PHY_COND_BRANCH_IF: u32 = 0x8;
pub const PHY_COND_BRANCH_ELIF: u32 = 0x9;
pub const PHY_COND_BRANCH_ELSE: u32 = 0xa;
pub const PHY_COND_BRANCH_END: u32 = 0xb;
pub const PHY_COND_CHECK: u32 = 0x4;
/// `PHY_COND_DONT_CARE`: a headline's RFE or cut that matches any.
pub const PHY_COND_DONT_CARE: u8 = 0xff;
/// `RTW89_BB_GAIN_BAND_NR`, `RF_PATH_MAX`, `LNA_GAIN_NUM`, `TIA_GAIN_NUM`
/// and `RTW89_BB_RXSC_NUM_40`, `_80` and `_160`: [`BbGain`]'s dimensions.
pub const BB_GAIN_BAND_NR: usize = 8;
pub const RF_PATH_MAX: usize = 4;
pub const LNA_GAIN_NUM: usize = 7;
pub const TIA_GAIN_NUM: usize = 2;
pub const BB_RXSC_NUM_40: usize = 9;
pub const BB_RXSC_NUM_80: usize = 13;
pub const BB_RXSC_NUM_160: usize = 15;

/// rtw89_phy_nctl_poll's bound and step: `read_poll_timeout(…, 10, 1000,
/// false, …)`.
const NCTL_POLL_STEP_US: u64 = 10;
const NCTL_POLL_BOUND_US: u64 = 1000;
/// The NCTL report `rtw89_phy_nctl_poll` writes and reads, and the value it
/// waits for.
const NCTL_READY: u32 = 0x4;
/// `rtw89_phy_init_bb_afe`'s polls: 11 reads, each failed one followed by
/// `fsleep(1)`.
const AFE_POLLS: usize = 11;
/// `struct rtw89_phy_afe_info`: six little-endian words.
const AFE_INFO_LEN: usize = 24;

/// The table a warning is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Table {
    Bb,
    BbGain,
    /// The radio table loaded for this path of `rtw89_phy_init_rf_reg`'s
    /// loop.
    Radio(u8),
    Nctl,
}

/// What rtw89 logs and goes on from, in the order it logs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Warning {
    /// "invalid PHY package: %d/%d": no headline matched the RFE type and
    /// cut; nothing was loaded from the table.
    InvalidPackage { table: Table, rfe: u8, cv: u8 },
    /// "failed to load CR %x/%x": an ELSE line reached before any branch
    /// matched; the table's lines from there on were not loaded.
    FailedToLoad { table: Table, addr: u32, data: u32 },
    /// "bb gain table with flow ctrl": a delay address in the gain table.
    BbGainFlowCtrl { addr: u32 },
    /// "bb gain {..} with unknown cfg type": `cfg_type` 4 on an RFE type of
    /// 50 or more, or above 4.
    BbGainCfgType { addr: u32, data: u32 },
    /// "bb gain error {..} with unknown type".
    BbGainErrorType { addr: u32, data: u32 },
    /// "bb rpl ofst {..} with unknown bw".
    BbRplOfstBw { addr: u32, data: u32 },
    /// "bb gain bypass {..} with unknown type".
    BbGainBypassType { addr: u32, data: u32 },
    /// "bb gain op1db {..} with unknown type".
    BbGainOp1dbType { addr: u32, data: u32 },
    /// "write rf busy swsi": SWSI stayed busy for 30 us and the RF write
    /// was dropped; rtw89 still mirrors it to the firmware.
    SwsiBusy { path: u8, addr: u32 },
    /// "unsupported rf path (%d)": a radio table whose path the chip lacks.
    UnsupportedRfPath { path: u8 },
    /// "RF parameters exceed size": a write past the last RF_REG page,
    /// which is not mirrored.
    RfOverflow { path: u8, index: u16 },
    /// "rf path %d reg h2c config failed", after the H2C's own error.
    RfH2c { path: u8, error: RfRegError },
    /// "failed to poll nctl block": the NCTL report did not read
    /// `0x4` within 1000 us; the timeout names the register.
    NctlPoll(io::Error),
    /// "unexpected AFE class %u": a sequence entry for a path rtw89 does not
    /// handle, skipped.
    AfeClass { class: u32 },
    /// "unexpected AFE writing action %u": a write of an unknown category.
    AfeWriteCat { cat: u32 },
    /// "failed to poll AFE cat=%u addr=0x%x mask=0x%x".
    AfePoll { cat: u32, addr: u32, mask: u32 },
}

/// The rtw89 step that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// `rtw89_phy_init_bb_afe`.
    Afe,
    /// `rtw89_chip_reset_bb_rf`.
    ResetBbRf,
    /// The BB table of `rtw89_phy_init_bb_reg`.
    BbReg,
    /// `rtw89_chip_init_txpwr_unit`.
    TxpwrUnit,
    /// `rtw89_phy_bb_reset`.
    BbReset,
    /// The radio table of this path.
    RfReg(u8),
    /// `rtw89_phy_preinit_rf_nctl`.
    NctlPreinit,
    /// The NCTL table.
    Nctl,
}

/// A register access the interface refused, or the reset's XTAL SI timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub step: Step,
    pub cause: io::Error,
}

fn at(step: Step) -> impl FnOnce(io::Error) -> Error {
    move |cause| Error { step, cause }
}

/// The tables rtw89 loads, as the firmware's elements give them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tables<'a> {
    pub bb: PhyTable<'a>,
    pub bb_gain: PhyTable<'a>,
    /// `elm_info->rf_radio[0..rf_path_num]`.
    pub radio: [PhyTable<'a>; RF_PATH_NUM],
    pub nctl: PhyTable<'a>,
    pub afe: Option<Element<'a>>,
}

impl<'a> Tables<'a> {
    /// The tables of `elements`, or the id of the first one missing, in
    /// rtw89's loading order: BB, BB gain, radio A, radio B, NCTL.
    pub fn from_elements(elements: &Elements<'a>) -> Result<Self, Id> {
        Ok(Self {
            bb: elements.bb_tbl.ok_or(Id::BbReg)?,
            bb_gain: elements.bb_gain.ok_or(Id::BbGain)?,
            radio: [
                elements.rf_radio[0].ok_or(Id::RadioA)?,
                elements.rf_radio[1].ok_or(Id::RadioB)?,
            ],
            nctl: elements.rf_nctl.ok_or(Id::RfNctl)?,
            afe: elements.afe,
        })
    }
}

/// `struct rtw89_phy_bb_gain_info`, as the BB gain table leaves it from
/// zero: per gain band and path, the LNA and TIA gains, the bypass gains,
/// the OP1dB points and the RPL offsets per bandwidth and sub-channel.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BbGain {
    pub lna_gain: [[[i8; LNA_GAIN_NUM]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub tia_gain: [[[i8; TIA_GAIN_NUM]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub lna_gain_bypass: [[[i8; LNA_GAIN_NUM]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub lna_op1db: [[[i8; LNA_GAIN_NUM]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    /// TIA0 with LNA0 to LNA6, then TIA1 with LNA6.
    pub tia_lna_op1db: [[[i8; LNA_GAIN_NUM + 1]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub rpl_ofst_20: [[i8; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub rpl_ofst_40: [[[i8; BB_RXSC_NUM_40]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub rpl_ofst_80: [[[i8; BB_RXSC_NUM_80]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
    pub rpl_ofst_160: [[[i8; BB_RXSC_NUM_160]; RF_PATH_MAX]; BB_GAIN_BAND_NR],
}

/// What [`load`] leaves: the gain table's values and what rtw89 logged.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Load {
    pub bb_gain: BbGain,
    pub warnings: Vec<Warning>,
}

/// Where a table's package starts: `headline_size` lines of headlines,
/// and the one picked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Headline {
    pub size: usize,
    pub index: usize,
}

const fn headline(addr: u32) -> u32 {
    addr >> 28
}

const fn target(addr: u32) -> u32 {
    addr & 0x0fff_ffff
}

const fn compare(rfe: u8, cv: u8) -> u32 {
    (rfe as u32) << 16 | cv as u32
}

const fn cond_rfe(addr: u32) -> u8 {
    (addr >> 16) as u8
}

const fn cond_cv(addr: u32) -> u8 {
    addr as u8
}

/// `rtw89_phy_sel_headline`: the headlines are the leading lines whose top
/// nibble is `PHY_HEADLINE_VALID`. With none, the whole table loads. Else
/// the first headline for this RFE type and cut, else the first for this
/// RFE type and any cut, else the last of the highest cut for this RFE
/// type, else the last of the highest cut for any RFE type; `None` when
/// even that finds none.
pub fn sel_headline(table: &PhyTable<'_>, rfe: u8, cv: u8) -> Option<Headline> {
    let size = table
        .regs()
        .take_while(|reg| headline(reg.addr) == PHY_HEADLINE_VALID)
        .count();
    if size == 0 {
        return Some(Headline { size, index: 0 });
    }
    let heads = || table.regs().take(size);
    for wanted in [compare(rfe, cv), compare(rfe, PHY_COND_DONT_CARE)] {
        if let Some(index) = heads().position(|reg| target(reg.addr) == wanted) {
            return Some(Headline { size, index });
        }
    }
    // Cases 3 and 4 share rtw89's cv_max, which case 3 leaves at 0 when it
    // finds nothing.
    for wanted_rfe in [rfe, PHY_COND_DONT_CARE] {
        let mut cv_max = 0;
        let mut picked = None;
        for (index, reg) in heads().enumerate() {
            if cond_rfe(reg.addr) == wanted_rfe && cond_cv(reg.addr) >= cv_max {
                cv_max = cond_cv(reg.addr);
                picked = Some(index);
            }
        }
        if let Some(index) = picked {
            return Some(Headline { size, index });
        }
    }
    None
}

/// `rtw89_phy_init_reg`: the lines of the package picked for `board`, each
/// given to `config`.
fn init_reg<I: Io + ?Sized>(
    io: &mut I,
    table: &PhyTable<'_>,
    which: Table,
    board: Board,
    warnings: &mut Vec<Warning>,
    mut config: impl FnMut(&mut I, Reg2, &mut Vec<Warning>) -> Result<(), io::Error>,
) -> Result<(), io::Error> {
    let (rfe, cv) = (board.rfe_type, board.cv);
    let Some(picked) = sel_headline(table, rfe, cv) else {
        warnings.push(Warning::InvalidPackage {
            table: which,
            rfe,
            cv,
        });
        return Ok(());
    };
    // An empty table has no line to take the target of, and none to load.
    let cfg_target = table.reg(picked.index).map_or(0, |reg| target(reg.addr));
    let (mut branch, mut matched, mut found) = (0, true, false);
    for reg in table.regs().skip(picked.size) {
        match headline(reg.addr) {
            PHY_COND_BRANCH_IF | PHY_COND_BRANCH_ELIF => branch = target(reg.addr),
            PHY_COND_BRANCH_ELSE => {
                matched = false;
                if !found {
                    warnings.push(Warning::FailedToLoad {
                        table: which,
                        addr: reg.addr,
                        data: reg.data,
                    });
                    return Ok(());
                }
            }
            PHY_COND_BRANCH_END => {
                matched = true;
                found = false;
            }
            PHY_COND_CHECK => {
                if found {
                    matched = false;
                } else {
                    matched = branch == cfg_target;
                    found = matched;
                }
            }
            _ if matched => config(io, reg, warnings)?,
            _ => {}
        }
    }
    Ok(())
}

/// `rtw89_phy_write32` over rtw89's raw PCIe I/O.
fn phy_write32<I: Io + ?Sized>(io: &mut I, register: u32, value: u32) -> Result<(), io::Error> {
    let at = register
        .checked_add(CR_BASE)
        .ok_or(io::Error::Register { register })?;
    io.write32(at, value)
}

/// `rtw89_phy_config_bb_reg` for PHY 0: a delay, a skipped line, or the
/// write.
fn config_bb_reg<I: Io + ?Sized>(io: &mut I, reg: Reg2) -> Result<(), io::Error> {
    match reg.addr {
        0xfe => io.delay_us(50_000),
        0xfd => io.delay_us(5_000),
        0xfc => io.delay_us(1_000),
        0xfb => io.delay_us(50),
        0xfa => io.delay_us(5),
        0xf9 => io.delay_us(1),
        _ if reg.data == BYPASS_CR_DATA => {}
        addr => phy_write32(io, addr, reg.data)?,
    }
    Ok(())
}

/// `rtw89_phy_config_rf_reg_v1`: 0xfe waits 50 ms; any other line is
/// written to the RF through `rtw89_phy_write_rf_v1`, and from 0x100 up
/// mirrored for the firmware, whether the write went through or not.
fn config_rf_reg_v1<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    reg: Reg2,
    info: &mut RfRegInfo,
    warnings: &mut Vec<Warning>,
) -> Result<(), io::Error> {
    if reg.addr == 0xfe {
        io.delay_us(50_000);
        return Ok(());
    }
    match io.write_rf(path, reg.addr, RFREG_MASK, reg.data) {
        Ok(()) => {}
        Err(io::Error::Timeout { .. }) => warnings.push(Warning::SwsiBusy {
            path,
            addr: reg.addr,
        }),
        Err(io::Error::RfPath(path)) => warnings.push(Warning::UnsupportedRfPath { path }),
        Err(error) => return Err(error),
    }
    if reg.addr < 0x100 {
        return Ok(());
    }
    if let Err(index) = info.store(reg.addr, reg.data) {
        warnings.push(Warning::RfOverflow { path, index });
    }
    Ok(())
}

/// `rtw89_phy_config_bb_gain_ax`: the line's address is `union
/// rtw89_phy_bb_gain_arg`, little-endian bytes type (or the RPL offset's
/// sub-channel start in the low nibble and bandwidth in the high), path,
/// gain band and configuration type.
fn config_bb_gain(gain: &mut BbGain, reg: Reg2, rfe_type: u8, warnings: &mut Vec<Warning>) {
    let [kind, path, band, cfg_type] = reg.addr.to_le_bytes();
    let (addr, data) = (reg.addr, reg.data);
    if usize::from(band) >= BB_GAIN_BAND_NR || usize::from(path) >= RF_PATH_NUM {
        return;
    }
    if (0xf9..=0xfe).contains(&addr) {
        warnings.push(Warning::BbGainFlowCtrl { addr });
        return;
    }
    let (band, path) = (usize::from(band), usize::from(path));
    let bytes = data.to_le_bytes().map(|byte| byte as i8);
    let fill = |out: &mut [i8], count: usize| out[..count].copy_from_slice(&bytes[..count]);
    match cfg_type {
        // rtw89_phy_cfg_bb_gain_error
        0 => match kind {
            0 => fill(&mut gain.lna_gain[band][path][0..], 4),
            1 => fill(&mut gain.lna_gain[band][path][4..], 3),
            2 => fill(&mut gain.tia_gain[band][path][0..], 2),
            _ => warnings.push(Warning::BbGainErrorType { addr, data }),
        },
        // rtw89_phy_cfg_bb_rpl_ofst
        1 => {
            let (rxsc_start, bw) = (usize::from(kind & 0xf), kind >> 4);
            let span = match (bw, rxsc_start) {
                (0, _) => {
                    gain.rpl_ofst_20[band][path] = bytes[0];
                    None
                }
                (1, 0 | 1) => Some((&mut gain.rpl_ofst_40[band][path][..], rxsc_start, 2)),
                (2, 0 | 1) => Some((&mut gain.rpl_ofst_80[band][path][..], rxsc_start, 4)),
                (2, 9) => Some((&mut gain.rpl_ofst_80[band][path][..], rxsc_start, 2)),
                (3, 0 | 1 | 5 | 9) => Some((&mut gain.rpl_ofst_160[band][path][..], rxsc_start, 4)),
                (3, 13) => Some((&mut gain.rpl_ofst_160[band][path][..], rxsc_start, 2)),
                (1..=3, _) => None,
                _ => {
                    warnings.push(Warning::BbRplOfstBw { addr, data });
                    None
                }
            };
            match span {
                // The full bandwidth's offset, RTW89_BB_RXSC_START_IDX_FULL.
                Some((out, 0, _)) => out[0] = bytes[0],
                Some((out, start, count)) => fill(&mut out[start..], count),
                None => {}
            }
        }
        // rtw89_phy_cfg_bb_gain_bypass
        2 => match kind {
            0 => fill(&mut gain.lna_gain_bypass[band][path][0..], 4),
            1 => fill(&mut gain.lna_gain_bypass[band][path][4..], 3),
            _ => warnings.push(Warning::BbGainBypassType { addr, data }),
        },
        // rtw89_phy_cfg_bb_gain_op1db
        3 => match kind {
            0 => fill(&mut gain.lna_op1db[band][path][0..], 4),
            1 => fill(&mut gain.lna_op1db[band][path][4..], 3),
            2 => fill(&mut gain.tia_lna_op1db[band][path][0..], 4),
            3 => fill(&mut gain.tia_lna_op1db[band][path][4..], 4),
            _ => warnings.push(Warning::BbGainOp1dbType { addr, data }),
        },
        // Used only by RFE types from 50 up, with an eFEM.
        4 if rfe_type < 50 => {}
        _ => warnings.push(Warning::BbGainCfgType { addr, data }),
    }
}

/// `rtw89_phy_init_bb_afe`: each entry of the AFE element's sequence, in
/// order. Paths 0 and 1 and the common class are run, others skipped with
/// a warning; writes go to MAC or AFE-digital registers directly and to BB
/// registers behind [`CR_BASE`]; a poll reads the masked register up to 11
/// times, 1 us apart, until it reads the value; a delay waits `addr`
/// microseconds; an unknown action does nothing. Without an element it
/// does nothing.
pub fn init_bb_afe<I: Io + ?Sized>(
    io: &mut I,
    afe: Option<&Element<'_>>,
    warnings: &mut Vec<Warning>,
) -> Result<(), Error> {
    let Some(afe) = afe else {
        return Ok(());
    };
    let count = afe.size as usize / AFE_INFO_LEN;
    // The entries rtw89 reads past the file's end are not run.
    let (infos, _) = afe.body.as_chunks::<AFE_INFO_LEN>();
    for info in infos.iter().take(count) {
        let word = |index: usize| {
            u32::from_le_bytes([
                info[4 * index],
                info[4 * index + 1],
                info[4 * index + 2],
                info[4 * index + 3],
            ])
        };
        let (action, cat, class) = (word(0), word(1), word(2));
        let (addr, mask, val) = (word(3), word(4), word(5));
        // RTW89_FW_AFE_CLASS_P0, _P1 and _CMN.
        if !matches!(class, 0 | 1 | 5) {
            warnings.push(Warning::AfeClass { class });
            continue;
        }
        match action {
            // RTW89_FW_AFE_ACTION_WRITE: CAT_MAC, _MAC1, _AFEDIG, _AFEDIG1
            // directly; CAT_BB and _BB1 through rtw89_phy_write32_idx.
            0 => match cat {
                2..=5 => io.write32_mask(addr, mask, val),
                0 | 1 => io.phy_write32_mask(addr, mask, val),
                _ => {
                    warnings.push(Warning::AfeWriteCat { cat });
                    Ok(())
                }
            }
            .map_err(at(Step::Afe))?,
            // RTW89_FW_AFE_ACTION_POLL
            2 => {
                let mut done = false;
                for _ in 0..AFE_POLLS {
                    if io.read32_mask(addr, mask).map_err(at(Step::Afe))? == val {
                        done = true;
                        break;
                    }
                    io.delay_us(1);
                }
                if !done {
                    warnings.push(Warning::AfePoll { cat, addr, mask });
                }
            }
            // RTW89_FW_AFE_ACTION_DELAY
            1 => io.delay_us(addr.into()),
            _ => {}
        }
    }
    Ok(())
}

/// `rtw89_chip_reset_bb_rf` for an RTL8852B: `__rtw8852bx_mac_disable_bb_rf`
/// (the AFE digital clock and the BB resets off, both RF paths' XTAL SI
/// enables cleared by read-modify-write), then
/// `__rtw8852bx_mac_enable_bb_rf`.
pub fn reset_bb_rf<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    disable_bb_rf(io)
        .and_then(|()| mac::enable_bb_rf(io))
        .map_err(at(Step::ResetBbRf))
}

fn disable_bb_rf<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_clr(WLRF_CTRL, AFC_AFEDIG)?;
    io.write8_clr(SYS_FUNC_EN, (FEN_BBRSTB | FEN_BB_GLB_RSTN) as u8)?;
    let s0 = io.read_xtal_si(XTAL_SI_WL_RFC_S0)? & !XTAL_SI_RF00S_EN;
    io.write_xtal_si(XTAL_SI_WL_RFC_S0, s0, FULL_BIT_MASK)?;
    let s1 = io.read_xtal_si(XTAL_SI_WL_RFC_S1)? & !XTAL_SI_RF10S_EN;
    io.write_xtal_si(XTAL_SI_WL_RFC_S1, s1, FULL_BIT_MASK)
}

/// `rtw89_phy_init_bb_reg` for an RTL8852B without DBCC: the BB table, the
/// TX power unit, the BB gain table and the BB reset. The gain values are
/// returned as rtw89 leaves them in a device it allocated zeroed.
pub fn init_bb_reg<I: Io + ?Sized>(
    io: &mut I,
    tables: &Tables<'_>,
    board: Board,
    warnings: &mut Vec<Warning>,
) -> Result<BbGain, Error> {
    // rtw89_io_pack: PCIe's raw I/O packs nothing.
    init_reg(io, &tables.bb, Table::Bb, board, warnings, |io, reg, _| {
        config_bb_reg(io, reg)
    })
    .map_err(at(Step::BbReg))?;
    init_txpwr_unit(io).map_err(at(Step::TxpwrUnit))?;
    let mut gain = BbGain::default();
    init_reg(
        io,
        &tables.bb_gain,
        Table::BbGain,
        board,
        warnings,
        |_, reg, warnings| {
            config_bb_gain(&mut gain, reg, board.rfe_type, warnings);
            Ok(())
        },
    )
    .map_err(at(Step::BbReg))?;
    bb_reset(io).map_err(at(Step::BbReset))?;
    Ok(gain)
}

/// `__rtw8852bx_init_txpwr_unit` for PHY 0, whose registers
/// `rtw89_mac_get_txpwr_cr_ax` accepts, then
/// `__rtw8852bx_set_txpwr_ul_tb_offset(rtwdev, 0, RTW89_MAC_0)`: the 2T
/// offset is 0 - 3 dB, cut to its five bits.
fn init_txpwr_unit<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32(PWR_UL_CTRL2, 0x0776_3333)?;
    io.write32(PWR_COEXT_CTRL, 0x01eb_f000)?;
    io.write32(PWR_UL_CTRL0, 0x0002_f8ff)?;
    let pw_ofst: i8 = 0;
    io.write32_set(PWR_UL_TB_CTRL, PWR_UL_TB_CTRL_EN)?;
    io.write32_mask(PWR_UL_TB_1T, PWR_UL_TB_1T_MASK, pw_ofst as u32)?;
    let pw_ofst = (pw_ofst - 3).max(-16);
    io.write32_mask(PWR_UL_TB_2T, PWR_UL_TB_2T_MASK, pw_ofst as u32)
}

/// `rtw8852b_bb_reset` for PHY 0: TX power reset and TSSI tracking held,
/// `__rtw8852bx_bb_reset_all`, then released.
fn bb_reset<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.phy_write32_set(P0_TXPW_RSTB, P0_TXPW_RSTB_MANON)?;
    io.phy_write32_set(P0_TSSI_TRK, P0_TSSI_TRK_EN)?;
    io.phy_write32_set(P1_TXPW_RSTB, P1_TXPW_RSTB_MANON)?;
    io.phy_write32_set(P1_TSSI_TRK, P1_TSSI_TRK_EN)?;
    // __rtw8852bx_bb_reset_all, through rtw89_phy_write32_idx for PHY 0.
    io.phy_write32_mask(S0_HW_SI_DIS, S0_HW_SI_DIS_W_R_TRIG, 0x7)?;
    io.phy_write32_mask(S1_HW_SI_DIS, S1_HW_SI_DIS_W_R_TRIG, 0x7)?;
    io.delay_us(1);
    io.phy_write32_mask(RSTB_ASYNC, RSTB_ASYNC_ALL, 1)?;
    io.phy_write32_mask(RSTB_ASYNC, RSTB_ASYNC_ALL, 0)?;
    io.phy_write32_mask(S0_HW_SI_DIS, S0_HW_SI_DIS_W_R_TRIG, 0x0)?;
    io.phy_write32_mask(S1_HW_SI_DIS, S1_HW_SI_DIS_W_R_TRIG, 0x0)?;
    io.phy_write32_mask(RSTB_ASYNC, RSTB_ASYNC_ALL, 1)?;
    io.phy_write32_clr(P0_TXPW_RSTB, P0_TXPW_RSTB_MANON)?;
    io.phy_write32_clr(P0_TSSI_TRK, P0_TSSI_TRK_EN)?;
    io.phy_write32_clr(P1_TXPW_RSTB, P1_TXPW_RSTB_MANON)?;
    io.phy_write32_clr(P1_TSSI_TRK, P1_TSSI_TRK_EN)
}

/// `rtw89_phy_init_rf_reg(rtwdev, false)` for an RTL8852B: for paths A
/// and B, the radio table through `rtw89_phy_config_rf_reg_v1`, then the
/// writes it mirrored sent in RF_REG pages to `commands`. A path whose
/// pages fail is a warning, and the next path still loads.
pub fn init_rf_reg<I: Io + ?Sized, C: Outsrc<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    tables: &Tables<'_>,
    board: Board,
    warnings: &mut Vec<Warning>,
) -> Result<(), Error> {
    let mut info = RfRegInfo::default();
    for (path, table) in tables.radio.iter().enumerate() {
        let rf_path = table.rf_path;
        info.rf_path = rf_path;
        // rtw89_io_pack and rtw89_io_unpack: nothing on PCIe.
        init_reg(
            io,
            table,
            Table::Radio(path as u8),
            board,
            warnings,
            |io, reg, warnings| config_rf_reg_v1(io, rf_path, reg, &mut info, warnings),
        )
        .map_err(at(Step::RfReg(path as u8)))?;
        if let Err(error) = info.send(io, commands) {
            warnings.push(Warning::RfH2c {
                path: rf_path,
                error,
            });
        }
    }
    Ok(())
}

/// `rtw89_phy_preinit_rf_nctl_ax` for an RTL8852B, then the NCTL table
/// through `rtw89_phy_config_bb_reg`. A poll that times out is a warning,
/// and the table still loads.
pub fn init_rf_nctl<I: Io + ?Sized>(
    io: &mut I,
    tables: &Tables<'_>,
    board: Board,
    warnings: &mut Vec<Warning>,
) -> Result<(), Error> {
    preinit_rf_nctl(io, warnings).map_err(at(Step::NctlPreinit))?;
    init_reg(
        io,
        &tables.nctl,
        Table::Nctl,
        board,
        warnings,
        |io, reg, _| config_bb_reg(io, reg),
    )
    .map_err(at(Step::Nctl))
}

/// `rtw89_phy_preinit_rf_nctl_ax`: the IQK/DPK clock and reset, then
/// `read_poll_timeout(rtw89_phy_nctl_poll, val, val == 0x4, 10, 1000,
/// false, …)`, each try writing 0x4 to the report, waiting 1 us and reading
/// it back.
fn preinit_rf_nctl<I: Io + ?Sized>(
    io: &mut I,
    warnings: &mut Vec<Warning>,
) -> Result<(), io::Error> {
    io.phy_write32_set(IOQ_IQK_DPK, 0x3)?;
    io.phy_write32_set(GNT_BT_WGT_EN, 0x1)?;
    io.phy_write32_set(P0_PATH_RST, 0x0800_0000)?;
    io.phy_write32_set(P1_PATH_RST, 0x0800_0000)?;
    io.phy_write32_set(IOQ_IQK_DPK, 0x2)?;
    phy_write32(io, NCTL_CFG, 0x8)?;
    let mut waited = 0;
    loop {
        phy_write32(io, NCTL_RPT, NCTL_READY)?;
        io.delay_us(1);
        if io.phy_read32(NCTL_RPT)? == NCTL_READY {
            return Ok(());
        }
        if waited >= NCTL_POLL_BOUND_US {
            warnings.push(Warning::NctlPoll(io::Error::Timeout {
                register: CR_BASE + NCTL_RPT,
                mask: MASKDWORD,
            }));
            return Ok(());
        }
        io.delay_us(NCTL_POLL_STEP_US);
        waited += NCTL_POLL_STEP_US;
    }
}

/// The BB and RF part of `rtw89_core_start` for an RTL8852B, after
/// `rtw89_mac_init` and the BTC power-on notice: [`reset_bb_rf`],
/// [`init_bb_reg`], `rtw89_chip_bb_postinit` (NULL for an RTL8852B) and
/// [`init_rf_reg`], whose RF_REG pages go to `commands`.
pub fn load<I: Io + ?Sized, C: Outsrc<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    tables: &Tables<'_>,
    board: Board,
) -> Result<Load, Error> {
    let mut warnings = Vec::new();
    reset_bb_rf(io)?;
    let bb_gain = init_bb_reg(io, tables, board, &mut warnings)?;
    init_rf_reg(io, commands, tables, board, &mut warnings)?;
    Ok(Load { bb_gain, warnings })
}

#[cfg(test)]
mod tests;
