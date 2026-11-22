// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! A PCIe RTL8852B's DMAC before its firmware arrives, as pinned rtw89 sets
//! it at probe. `rtw89_chip_info_setup` (core.c) powers the chip on
//! ([`super::power`]); `rtw89_chip_efuse_info_setup` then calls
//! `rtw89_mac_partial_init(rtwdev, false, false)` (mac.c), whose head this
//! is:
//!
//! 1. `rtw89_mac_ctrl_hci_dma_trx(rtwdev, true)` (mac.h);
//! 2. `rtw89_mac_dmac_pre_init`: the AX generation's `hci_func_en` and
//!    `dmac_func_pre_en`, `rtw89_mac_dle_init(rtwdev, RTW89_QTA_DLFW,
//!    rtwdev->mac.qta_mode)`, then `rtw89_mac_hfc_init(rtwdev, true, false,
//!    true)`.
//!
//! [`partial_init_before_hci`] stops where `rtw89_mac_partial_init` calls
//! `rtwdev->hci.ops->mac_pre_init` (`rtw89_pci_ops_mac_pre_init_ax`), which
//! is the PCIe pre-init's. After that `rtw89_mac_fwdl_preconfig` makes no
//! access on an AX chip (`fwdl_preconfig` is NULL in `rtw89_mac_gen_ax`)
//! and `rtw89_fw_download` follows. The C oracle runs the unchanged
//! `rtw89_mac_partial_init` with both stubbed, so it shows the seam too.
//!
//! The DLE memory, its quotas and the HCI flow-control parameters are data
//! named as rtw89 names them: [`mac_size`] holds the `rtw89_mac_size`
//! members RTL8852B's PCIe tables name, and [`super::rtw8852b`] the tables.
//! The DLFW quota takes its WCPU minimum from the SCC entry, and the last
//! entry `get_dle_mem_cfg` reads, SCC's, is the one `rtwdev->mac.dle_info`
//! keeps, so the flow control's parameters are the SCC entry's
//! ([`DleInfo`]).
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included. `chk_dle_rdy_ax` reads every
//! 1 us for up to 2000 us counted in steps ([`Registers::poll32`]).
//!
//! What this leaves out, and why:
//! - `rtw89_chip_bb_preinit`, which `rtw89_mac_partial_init` calls only
//!   with `include_bb` or `bb_preinit`: both are false at an RTL8852B's
//!   probe (`bbmcu_nr` is 0, and only RTL8922D preinits its BB there) and in
//!   `rtw89_mac_init`.
//! - Other chips' branches (RTL8852C's HAXI setup and `tx_rpt` quota,
//!   RTL8851B's and RTL8852BT's AXIDMA clock), USB and SDIO tables, and the
//!   BE generation: the chip is a PCIe RTL8852B.
//! - `rtw89_mac_get_dle_rsvd_qt_cfg`: only BE's preload reaches it.
//!   RTL8852B's DLE entries leave `rsvd_qt`, `rsvd0_size`, `rsvd1_size` and
//!   `dle_input` NULL, so those are not carried either, and
//!   `dle_used_size` adds no reserved size.
//! - The part of `rtw89_mac_hfc_init` that sets channel and public pages:
//!   the pre-init asks for H2C flow control alone (`en` false, `h2c_en`
//!   true), which returns before it. The full MAC init is where it runs.
//!
//! Like rtw89, this sets HCI_TXDMA_EN and HCI_RXDMA_EN before the PCIe
//! pre-init stops each DMA channel and resets its rings, so that pre-init
//! has to follow at once. The pre-init proves only that DMAC_FUNC_EN read
//! back MAC_FUNC_EN and DMAC_FUNC_EN and that the DLE's ready bits answered.
//! It proves nothing about the buffers the quotas describe, whether the chip
//! fetches anything meanwhile, or whether the firmware download will succeed.
use super::{
    io::{self, Io, Registers, prep},
    registers::*,
    rtw8852b,
};

/// `RTW89_DMA_CH_NUM`: the HCI DMA channels, ACH0 to FWCMDQ (`RTW89_DMA_H2C`).
pub const DMA_CH_NUM: usize = 13;
/// The modes `enum rtw89_qta_mode` names, INVALID included: the length of
/// a chip's quota tables.
pub const QTA_NUM: usize = 5;
/// `INVALID_QT_WCPU`: no extension quota for the WCPU's WDE minimum.
const INVALID_QT_WCPU: u16 = u16::MAX;
/// `chk_dle_rdy_ax`'s `read_poll_timeout(…, 1, 2000, …)`.
const DLE_POLL_STEP_US: u64 = 1;
const DLE_POLL_BOUND_US: u64 = 2000;

/// `enum rtw89_qta_mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum QtaMode {
    Scc = 0,
    Dbcc = 1,
    Dlfw = 2,
    Wow = 3,
    Invalid = 4,
}

/// `rtwdev->mac.qta_mode` as `rtw89_core_init` sets it for an AX chip: the
/// mode the DLFW quota takes its WCPU minimum from.
pub const QTA_MODE: QtaMode = QtaMode::Scc;

/// `enum rtw89_hcifc_mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HcifcMode {
    Poh = 0,
    Stf = 1,
    Sdio = 2,
}

/// `grp_0` and `grp_1`: a channel's public page group.
pub const GRP_0: u8 = 0;
pub const GRP_1: u8 = 1;

/// `struct rtw89_hfc_ch_cfg`: one DMA channel's page bounds and group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfcChCfg {
    pub min: u16,
    pub max: u16,
    pub grp: u8,
}

impl HfcChCfg {
    /// rtw89's positional initializer, `{min, max, grp}`.
    pub const fn new(min: u16, max: u16, grp: u8) -> Self {
        Self { min, max, grp }
    }
}

/// `struct rtw89_hfc_pub_cfg`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfcPubCfg {
    pub grp0: u16,
    pub grp1: u16,
    pub pub_max: u16,
    pub wp_thrd: u16,
}

/// `struct rtw89_hfc_prec_cfg`, without the `*_full_page` members only BE
/// chips after RTL8922D set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfcPrecCfg {
    pub ch011_prec: u16,
    pub h2c_prec: u16,
    pub wp_ch07_prec: u16,
    pub wp_ch811_prec: u16,
    pub ch011_full_cond: u8,
    pub h2c_full_cond: u8,
    pub wp_ch07_full_cond: u8,
    pub wp_ch811_full_cond: u8,
}

impl HfcPrecCfg {
    /// rtw89's positional initializer, in member order.
    pub const fn new(prec: [u16; 4], full_cond: [u8; 4]) -> Self {
        Self {
            ch011_prec: prec[0],
            h2c_prec: prec[1],
            wp_ch07_prec: prec[2],
            wp_ch811_prec: prec[3],
            ch011_full_cond: full_cond[0],
            h2c_full_cond: full_cond[1],
            wp_ch07_full_cond: full_cond[2],
            wp_ch811_full_cond: full_cond[3],
        }
    }
}

/// `struct rtw89_hfc_param_ini`; `None` stands for a NULL member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfcParamIni {
    pub ch_cfg: Option<&'static [HfcChCfg; DMA_CH_NUM]>,
    pub pub_cfg: Option<&'static HfcPubCfg>,
    pub prec_cfg: Option<&'static HfcPrecCfg>,
    pub mode: HcifcMode,
}

impl HfcParamIni {
    /// An entry rtw89 leaves zeroed, or writes as `{NULL}`.
    pub const NULL: Self = Self {
        ch_cfg: None,
        pub_cfg: None,
        prec_cfg: None,
        mode: HcifcMode::Poh,
    };
}

/// `struct rtw89_dle_size`, without BE's `srt_ofst`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DleSize {
    pub pge_size: u16,
    pub lnk_pge_num: u16,
    pub unlnk_pge_num: u16,
}

impl DleSize {
    /// rtw89's positional initializer, `{pge_size, lnk_pge_num, unlnk_pge_num}`.
    pub const fn new(pge_size: u16, lnk_pge_num: u16, unlnk_pge_num: u16) -> Self {
        Self {
            pge_size,
            lnk_pge_num,
            unlnk_pge_num,
        }
    }
}

/// `struct rtw89_wde_quota`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WdeQuota {
    pub hif: u16,
    pub wcpu: u16,
    pub pkt_in: u16,
    pub cpu_io: u16,
}

impl WdeQuota {
    /// rtw89's positional initializer, in member order.
    pub const fn new([hif, wcpu, pkt_in, cpu_io]: [u16; 4]) -> Self {
        Self {
            hif,
            wcpu,
            pkt_in,
            cpu_io,
        }
    }
}

/// `struct rtw89_ple_quota`, without BE's `h2d` and `snrpt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PleQuota {
    pub cma0_tx: u16,
    pub cma1_tx: u16,
    pub c2h: u16,
    pub h2c: u16,
    pub wcpu: u16,
    pub mpdu_proc: u16,
    pub cma0_dma: u16,
    pub cma1_dma: u16,
    pub bb_rpt: u16,
    pub wd_rel: u16,
    pub cpu_io: u16,
    pub tx_rpt: u16,
}

impl PleQuota {
    /// rtw89's positional initializer, in member order; an initializer of
    /// eleven values leaves `tx_rpt` 0.
    pub const fn new(
        [
            cma0_tx,
            cma1_tx,
            c2h,
            h2c,
            wcpu,
            mpdu_proc,
            cma0_dma,
            cma1_dma,
            bb_rpt,
            wd_rel,
            cpu_io,
            tx_rpt,
        ]: [u16; 12],
    ) -> Self {
        Self {
            cma0_tx,
            cma1_tx,
            c2h,
            h2c,
            wcpu,
            mpdu_proc,
            cma0_dma,
            cma1_dma,
            bb_rpt,
            wd_rel,
            cpu_io,
            tx_rpt,
        }
    }
}

/// `struct rtw89_dle_mem` as AX chips fill it: the BE members after
/// `ple_max_qt` are NULL there and not carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DleMem {
    pub mode: QtaMode,
    pub wde_size: &'static DleSize,
    pub ple_size: &'static DleSize,
    pub wde_min_qt: &'static WdeQuota,
    pub wde_max_qt: &'static WdeQuota,
    pub ple_min_qt: &'static PleQuota,
    pub ple_max_qt: &'static PleQuota,
}

/// What the DLE and HFC code reads from `rtw89_chip_info` for one chip
/// reached over one HCI: `qta_def`'s tables for `hci.dle_type`, indexed by
/// mode, and the chip's FIFO sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipQuota {
    /// `qta_def.hfc_param_ini[hci.dle_type]`.
    pub hfc_param_ini: &'static [HfcParamIni; QTA_NUM],
    /// `qta_def.dle_mem[hci.dle_type]`; `None` stands for an entry whose
    /// sizes and quotas are NULL.
    pub dle_mem: &'static [Option<DleMem>; QTA_NUM],
    /// `fifo_size`.
    pub fifo_size: u32,
    /// `dle_scc_rsvd_size`.
    pub dle_scc_rsvd_size: u32,
}

/// The `rtw89_mac_size` members (mac.c) RTL8852B's PCIe tables name, with
/// rtw89's comments.
pub mod mac_size {
    use super::{DleSize, HfcPrecCfg, PleQuota, WdeQuota};
    use crate::wifi::realtek::ax::registers::{PLE_PG_128, WDE_PG_64};

    pub const HFC_PRECCFG_PCIE: HfcPrecCfg = HfcPrecCfg::new([2, 40, 0, 0], [1, 0, 0, 0]);
    /// 8852B PCIE SCC
    pub const WDE_SIZE7: DleSize = DleSize::new(WDE_PG_64, 510, 2);
    /// DLFW
    pub const WDE_SIZE9: DleSize = DleSize::new(WDE_PG_64, 0, 1024);
    /// PCIE 64
    pub const PLE_SIZE6: DleSize = DleSize::new(PLE_PG_128, 496, 16);
    /// DLFW
    pub const PLE_SIZE8: DleSize = DleSize::new(PLE_PG_128, 64, 960);
    /// DLFW
    pub const WDE_QT4: WdeQuota = WdeQuota::new([0, 0, 0, 0]);
    /// 8852B PCIE SCC
    pub const WDE_QT7: WdeQuota = WdeQuota::new([446, 48, 0, 16]);
    /// DLFW
    pub const PLE_QT13: PleQuota = PleQuota::new([0, 0, 16, 48, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// PCIE 64
    pub const PLE_QT18: PleQuota = PleQuota::new([147, 0, 16, 20, 17, 13, 89, 0, 32, 14, 8, 0]);
    /// PCIE 64
    pub const PLE_QT58: PleQuota = PleQuota::new([147, 0, 16, 20, 157, 13, 229, 0, 172, 14, 24, 0]);
    /// 8852B PCIE WOW
    pub const PLE_QT_52B_WOW: PleQuota =
        PleQuota::new([147, 0, 16, 20, 157, 13, 133, 0, 172, 14, 24, 0]);
}

/// `struct rtw89_dle_info` as `get_dle_mem_cfg` leaves it on an AX chip,
/// whose `rsvd_qt` and `dle_input` are NULL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DleInfo {
    pub qta_mode: QtaMode,
    pub ple_pg_size: u16,
    pub ple_free_pg: u16,
    pub c0_rx_qta: u16,
    pub c1_rx_qta: u16,
}

impl DleInfo {
    /// What `get_dle_mem_cfg` records of the entry it returns.
    fn of(cfg: &DleMem) -> Self {
        Self {
            qta_mode: cfg.mode,
            ple_pg_size: cfg.ple_size.pge_size,
            ple_free_pg: cfg.ple_size.lnk_pge_num,
            c0_rx_qta: cfg.ple_min_qt.cma0_dma,
            c1_rx_qta: cfg.ple_min_qt.cma1_dma,
        }
    }
}

/// `struct rtw89_hfc_param`, without `ch_info` and `pub_info`, which
/// `hfc_reset_param` zeroes and only the full flow control reads back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfcParam {
    pub en: bool,
    pub h2c_en: bool,
    pub mode: HcifcMode,
    pub ch_cfg: Option<&'static [HfcChCfg; DMA_CH_NUM]>,
    pub pub_cfg: HfcPubCfg,
    pub prec_cfg: HfcPrecCfg,
}

impl HfcParam {
    /// rtw89's zeroed `hfc_param` before the first `hfc_reset_param`.
    pub const ZERO: Self = Self {
        en: false,
        h2c_en: false,
        mode: HcifcMode::Poh,
        ch_cfg: None,
        pub_cfg: HfcPubCfg {
            grp0: 0,
            grp1: 0,
            pub_max: 0,
            wp_thrd: 0,
        },
        prec_cfg: HfcPrecCfg::new([0; 4], [0; 4]),
    };
}

/// What a successful DMAC pre-init leaves in rtw89's `rtwdev->mac`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreInit {
    pub dle_info: DleInfo,
    pub hfc_param: HfcParam,
}

/// Why the DMAC pre-init failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An access the interface refused, or a poll that timed out:
    /// [`io::Error::Timeout`] names the register and the bits it waited on.
    Io(io::Error),
    /// `rtw89_mac_check_mac_en_ax`'s `-EFAULT`: DMAC_FUNC_EN read `value`,
    /// which is `RTW89_R32_EA` or `RTW89_R32_DEAD` or lacks MAC_FUNC_EN or
    /// DMAC_FUNC_EN.
    DmacOff { value: u32 },
    /// `get_dle_mem_cfg`'s NULL: the chip has no DLE entry for the mode.
    NoDleMem(QtaMode),
    /// `rtw89_mac_dle_init`'s "wd/dle mem cfg": the entry's WDE and PLE
    /// pages do not fill the FIFO the chip leaves that mode.
    DleSize { used: u32, expected: u32 },
    /// `dle_mix_cfg_ax`'s `-EINVAL` for 256-byte WDE pages.
    WdePageSize(u16),
    /// `dle_mix_cfg_ax`'s `-EINVAL` for PLE pages of neither 128 nor 256
    /// bytes.
    PlePageSize(u16),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// `rtw89_mac_partial_init(rtwdev, false, false)` on a PCIe RTL8852B up to
/// `hci.ops->mac_pre_init`: the HCI DMA enables, then [`dmac_pre_init`].
/// The PCIe pre-init comes next, then the firmware download; nothing in
/// between makes an access.
pub fn partial_init_before_hci<I: Io + ?Sized>(io: &mut I) -> Result<PreInit, Error> {
    partial_init_before_hci_with(io, &rtw8852b::PCIE_QUOTA)
}

fn partial_init_before_hci_with<I: Io + ?Sized>(
    io: &mut I,
    quota: &ChipQuota,
) -> Result<PreInit, Error> {
    ctrl_hci_dma_trx(io, true)?;
    dmac_pre_init_with(io, quota)
}

/// `rtw89_mac_ctrl_hci_dma_trx`: HCI_TXDMA_EN and HCI_RXDMA_EN in
/// `rtw8852b_chip_info.hci_func_en_addr`, set or cleared.
pub fn ctrl_hci_dma_trx<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    let bits = HCI_TXDMA_EN | HCI_RXDMA_EN;
    if enable {
        io.write32_set(HCI_FUNC_EN, bits)
    } else {
        io.write32_clr(HCI_FUNC_EN, bits)
    }
}

/// `rtw89_mac_dmac_pre_init` on a PCIe RTL8852B at its first probe: the DMAC
/// functions and clocks the download needs, the DLFW quota, and H2C flow
/// control alone.
pub fn dmac_pre_init<I: Io + ?Sized>(io: &mut I) -> Result<PreInit, Error> {
    dmac_pre_init_with(io, &rtw8852b::PCIE_QUOTA)
}

fn dmac_pre_init_with<I: Io + ?Sized>(io: &mut I, quota: &ChipQuota) -> Result<PreInit, Error> {
    hci_func_en(io)?;
    dmac_func_pre_en(io)?;
    let dle_info = dle_init_with(io, quota, QtaMode::Dlfw, QTA_MODE)?;
    let hfc_param = hfc_init_h2c(io, quota, &dle_info, HfcParam::ZERO)?;
    Ok(PreInit {
        dle_info,
        hfc_param,
    })
}

/// `rtw89_mac_dle_init` on a PCIe RTL8852B: `ext_mode` is read only for
/// [`QtaMode::Dlfw`], whose WCPU minimum it gives. What it returns is what
/// `rtwdev->mac.dle_info` keeps: the entry `get_dle_mem_cfg` read last,
/// `ext_mode`'s for DLFW.
pub fn dle_init<I: Io + ?Sized>(
    io: &mut I,
    mode: QtaMode,
    ext_mode: QtaMode,
) -> Result<DleInfo, Error> {
    dle_init_with(io, &rtw8852b::PCIE_QUOTA, mode, ext_mode)
}

fn dle_init_with<I: Io + ?Sized>(
    io: &mut I,
    quota: &ChipQuota,
    mode: QtaMode,
    ext_mode: QtaMode,
) -> Result<DleInfo, Error> {
    check_mac_en(io)?;

    let Some(cfg) = get_dle_mem_cfg(quota, mode) else {
        return Err(dle_init_failed(io, Error::NoDleMem(mode)));
    };
    let mut info = DleInfo::of(cfg);
    let mut ext_wde_min_qt_wcpu = INVALID_QT_WCPU;
    if mode == QtaMode::Dlfw {
        let Some(ext_cfg) = get_dle_mem_cfg(quota, ext_mode) else {
            return Err(dle_init_failed(io, Error::NoDleMem(ext_mode)));
        };
        info = DleInfo::of(ext_cfg);
        ext_wde_min_qt_wcpu = ext_cfg.wde_min_qt.wcpu;
    }

    let used = dle_used_size(cfg);
    let expected = dle_expected_used_size(quota, mode);
    if used != expected {
        return Err(dle_init_failed(io, Error::DleSize { used, expected }));
    }

    dle_func_en(io, false)?;
    dle_clk_en(io, true)?;

    match dle_mix_cfg(io, cfg) {
        Ok(()) => {}
        Err(Error::Io(error)) => return Err(Error::Io(error)),
        Err(error) => return Err(dle_init_failed(io, error)),
    }
    // dle_quota_cfg
    wde_quota_cfg(io, cfg.wde_min_qt, cfg.wde_max_qt, ext_wde_min_qt_wcpu)?;
    ple_quota_cfg(io, cfg.ple_min_qt, cfg.ple_max_qt)?;

    dle_func_en(io, true)?;

    // A ready bit that never answers returns without the error path.
    chk_dle_rdy(io, true)?;
    chk_dle_rdy(io, false)?;
    Ok(info)
}

/// `rtw89_mac_dle_init`'s `error:` path: the DLE disabled, then both INI
/// statuses read for the log, before `error` is returned.
fn dle_init_failed<I: Io + ?Sized>(io: &mut I, error: Error) -> Error {
    let logged = dle_func_en(io, false)
        .and_then(|()| io.read32(WDE_INI_STATUS))
        .and_then(|_| io.read32(PLE_INI_STATUS));
    match logged {
        Ok(_) => error,
        Err(refused) => Error::Io(refused),
    }
}

/// `rtw89_mac_check_mac_en_ax(rtwdev, RTW89_MAC_0, RTW89_DMAC_SEL)`.
fn check_mac_en<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    let value = io.read32(DMAC_FUNC_EN)?;
    let bits = MAC_FUNC_EN | DMAC_FUNC_EN_BIT;
    if value == R32_EA || value == R32_DEAD || value & bits != bits {
        return Err(Error::DmacOff { value });
    }
    Ok(())
}

/// `rtw89_mac_hci_func_en_ax` for a chip other than RTL8852C.
fn hci_func_en<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32(
        DMAC_FUNC_EN,
        MAC_FUNC_EN | DMAC_FUNC_EN_BIT | DISPATCHER_EN | PKT_BUF_EN,
    )
}

/// `rtw89_mac_dmac_func_pre_en_ax` for an RTL8852B: the dispatcher's clock
/// alone, and none of RTL8852C's HAXI setup.
fn dmac_func_pre_en<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32(DMAC_CLK_EN, DISPATCHER_CLK_EN)
}

/// `get_dle_mem_cfg`: the chip's entry for `mode`, when it names that mode.
fn get_dle_mem_cfg(quota: &ChipQuota, mode: QtaMode) -> Option<&'static DleMem> {
    let table: &'static [Option<DleMem>; QTA_NUM] = quota.dle_mem;
    table[mode as usize].as_ref().filter(|cfg| cfg.mode == mode)
}

/// `dle_used_size`: the bytes the entry's WDE and PLE pages take.
fn dle_used_size(cfg: &DleMem) -> u32 {
    let bytes = |size: &DleSize| {
        u32::from(size.pge_size)
            .wrapping_mul(u32::from(size.lnk_pge_num) + u32::from(size.unlnk_pge_num))
    };
    bytes(cfg.wde_size).wrapping_add(bytes(cfg.ple_size))
}

/// `dle_expected_used_size` over PCIe: the FIFO, less what SCC reserves.
fn dle_expected_used_size(quota: &ChipQuota, mode: QtaMode) -> u32 {
    if mode == QtaMode::Scc {
        quota.fifo_size.wrapping_sub(quota.dle_scc_rsvd_size)
    } else {
        quota.fifo_size
    }
}

/// `dle_func_en_ax`.
fn dle_func_en<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    let bits = DLE_WDE_EN | DLE_PLE_EN;
    if enable {
        io.write32_set(DMAC_FUNC_EN, bits)
    } else {
        io.write32_clr(DMAC_FUNC_EN, bits)
    }
}

/// `dle_clk_en_ax` for a chip other than RTL8851B.
fn dle_clk_en<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    let bits = DLE_WDE_CLK_EN | DLE_PLE_CLK_EN;
    if enable {
        io.write32_set(DMAC_CLK_EN, bits)
    } else {
        io.write32_clr(DMAC_CLK_EN, bits)
    }
}

/// `u32_replace_bits`.
const fn replace_bits(value: u32, field: u32, mask: u32) -> u32 {
    (value & !mask) | prep(field, mask)
}

/// `dle_mix_cfg_ax`: each engine's page size and free pages, and the PLE's
/// start past the WDE's pages.
fn dle_mix_cfg<I: Io + ?Sized>(io: &mut I, cfg: &DleMem) -> Result<(), Error> {
    let mut value = io.read32(WDE_PKTBUF_CFG)?;
    let size = cfg.wde_size;
    let select = match size.pge_size {
        WDE_PG_128 => S_AX_WDE_PAGE_SEL_128,
        WDE_PG_256 => return Err(Error::WdePageSize(size.pge_size)),
        // 64 bytes, and rtw89's default case.
        _ => S_AX_WDE_PAGE_SEL_64,
    };
    value = replace_bits(value, select, WDE_PAGE_SEL_MASK);
    value = replace_bits(value, 0, WDE_START_BOUND_MASK);
    value = replace_bits(value, size.lnk_pge_num.into(), WDE_FREE_PAGE_NUM_MASK);
    io.write32(WDE_PKTBUF_CFG, value)?;

    let mut value = io.read32(PLE_PKTBUF_CFG)?;
    // rtw89 keeps the bound in a u8.
    let bound = ((u64::from(size.lnk_pge_num) + u64::from(size.unlnk_pge_num))
        * u64::from(size.pge_size)
        / u64::from(DLE_BOUND_UNIT)) as u8;
    let size = cfg.ple_size;
    let select = match size.pge_size {
        PLE_PG_128 => S_AX_PLE_PAGE_SEL_128,
        PLE_PG_256 => S_AX_PLE_PAGE_SEL_256,
        // 64 bytes, and rtw89's default case.
        _ => return Err(Error::PlePageSize(size.pge_size)),
    };
    value = replace_bits(value, select, PLE_PAGE_SEL_MASK);
    value = replace_bits(value, bound.into(), PLE_START_BOUND_MASK);
    value = replace_bits(value, size.lnk_pge_num.into(), PLE_FREE_PAGE_NUM_MASK);
    io.write32(PLE_PKTBUF_CFG, value)?;
    Ok(())
}

/// `wde_quota_cfg_ax`: `SET_QUOTA` for the HIF, WCPU, packet-in and CPU IO
/// quotas, the WCPU minimum from the extension when there is one.
fn wde_quota_cfg<I: Io + ?Sized>(
    io: &mut I,
    min: &WdeQuota,
    max: &WdeQuota,
    ext_wde_min_qt_wcpu: u16,
) -> Result<(), io::Error> {
    let min_qt_wcpu = if ext_wde_min_qt_wcpu != INVALID_QT_WCPU {
        ext_wde_min_qt_wcpu
    } else {
        min.wcpu
    };
    for (register, min, max) in [
        (WDE_QTA0_CFG, min.hif, max.hif),
        (WDE_QTA1_CFG, min_qt_wcpu, max.wcpu),
        (WDE_QTA3_CFG, min.pkt_in, max.pkt_in),
        (WDE_QTA4_CFG, min.cpu_io, max.cpu_io),
    ] {
        io.write32(
            register,
            prep(min.into(), WDE_MIN_SIZE_MASK) | prep(max.into(), WDE_MAX_SIZE_MASK),
        )?;
    }
    Ok(())
}

/// `ple_quota_cfg_ax` for a chip other than RTL8852C: `SET_QUOTA` for QTA0
/// to QTA10.
fn ple_quota_cfg<I: Io + ?Sized>(
    io: &mut I,
    min: &PleQuota,
    max: &PleQuota,
) -> Result<(), io::Error> {
    for (register, min, max) in [
        (PLE_QTA0_CFG, min.cma0_tx, max.cma0_tx),
        (PLE_QTA1_CFG, min.cma1_tx, max.cma1_tx),
        (PLE_QTA2_CFG, min.c2h, max.c2h),
        (PLE_QTA3_CFG, min.h2c, max.h2c),
        (PLE_QTA4_CFG, min.wcpu, max.wcpu),
        (PLE_QTA5_CFG, min.mpdu_proc, max.mpdu_proc),
        (PLE_QTA6_CFG, min.cma0_dma, max.cma0_dma),
        (PLE_QTA7_CFG, min.cma1_dma, max.cma1_dma),
        (PLE_QTA8_CFG, min.bb_rpt, max.bb_rpt),
        (PLE_QTA9_CFG, min.wd_rel, max.wd_rel),
        (PLE_QTA10_CFG, min.cpu_io, max.cpu_io),
    ] {
        io.write32(
            register,
            prep(min.into(), PLE_MIN_SIZE_MASK) | prep(max.into(), PLE_MAX_SIZE_MASK),
        )?;
    }
    Ok(())
}

/// `chk_dle_rdy_ax`: the WDE's or the PLE's two ready bits, every 1 us for
/// up to 2000 us.
fn chk_dle_rdy<I: Io + ?Sized>(io: &mut I, wde_or_ple: bool) -> Result<(), io::Error> {
    let (register, mask) = if wde_or_ple {
        (WDE_INI_STATUS, WDE_MGN_INI_RDY)
    } else {
        (PLE_INI_STATUS, PLE_MGN_INI_RDY)
    };
    io.poll32(
        register,
        mask,
        DLE_POLL_STEP_US,
        DLE_POLL_BOUND_US,
        |value| value & mask == mask,
    )
    .map(|_| ())
}

/// `rtw89_mac_hfc_init(rtwdev, true, false, true)`: reset the parameters
/// from the chip's entry for `dle_info.qta_mode`, then H2C flow control
/// alone, which returns before any channel or public page is set.
fn hfc_init_h2c<I: Io + ?Sized>(
    io: &mut I,
    quota: &ChipQuota,
    dle_info: &DleInfo,
    mut param: HfcParam,
) -> Result<HfcParam, Error> {
    hfc_reset_param(&mut param, quota, dle_info.qta_mode);
    check_mac_en(io)?;
    hfc_func_en(io, &mut param, false, false)?;
    hfc_h2c_cfg(io, &param)?;
    hfc_func_en(io, &mut param, false, true)?;
    Ok(param)
}

/// `hfc_reset_param`: what the entry names replaces the parameters; a NULL
/// member leaves them as they were.
fn hfc_reset_param(param: &mut HfcParam, quota: &ChipQuota, qta_mode: QtaMode) {
    let ini = &quota.hfc_param_ini[qta_mode as usize];
    param.en = false;
    if let Some(pub_cfg) = ini.pub_cfg {
        param.pub_cfg = *pub_cfg;
    }
    if let Some(prec_cfg) = ini.prec_cfg {
        param.prec_cfg = *prec_cfg;
    }
    if let Some(ch_cfg) = ini.ch_cfg {
        param.ch_cfg = Some(ch_cfg);
    }
    param.mode = ini.mode;
}

/// `hfc_func_en_ax` on `rtw8852b_page_regs.hci_fc_ctrl`.
fn hfc_func_en<I: Io + ?Sized>(
    io: &mut I,
    param: &mut HfcParam,
    en: bool,
    h2c_en: bool,
) -> Result<(), io::Error> {
    let mut value = io.read32(HCI_FC_CTRL)?;
    param.en = en;
    param.h2c_en = h2c_en;
    value = if en {
        value | HCI_FC_EN
    } else {
        value & !HCI_FC_EN
    };
    value = if h2c_en {
        value | HCI_FC_CH12_EN
    } else {
        value & !HCI_FC_CH12_EN
    };
    io.write32(HCI_FC_CTRL, value)
}

/// `hfc_h2c_cfg_ax`: the H2C channel's pre-cost, then its full condition.
fn hfc_h2c_cfg<I: Io + ?Sized>(io: &mut I, param: &HfcParam) -> Result<(), io::Error> {
    let prec_cfg = &param.prec_cfg;
    io.write32(
        CH_PAGE_CTRL,
        prep(prec_cfg.h2c_prec.into(), PREC_PAGE_CH12_MASK),
    )?;
    io.write32_mask(
        HCI_FC_CTRL,
        HCI_FC_CH12_FULL_COND_MASK,
        prec_cfg.h2c_full_cond.into(),
    )
}

#[cfg(test)]
mod tests;
