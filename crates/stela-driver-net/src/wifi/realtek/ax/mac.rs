// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
// Copyright(c) 2024 Realtek Corporation
//! A PCIe RTL8852B's full MAC init once its firmware runs, as pinned rtw89
//! runs it when the interface comes up: `rtw89_mac_init` (mac.c), which
//! `rtw89_core_start` (core.c) calls after `rtw89_mac_preinit`, from the
//! point where its `rtw89_mac_partial_init` has returned. That partial init
//! is stage 1's ([`super::bootstrap`]): the HCI DMA enables and DMAC
//! pre-init ([`super::dle::partial_init_before_hci`]), the PCIe pre-init
//! ([`super::pci::mac_pre_init`]) and the firmware download
//! ([`super::fwdl::download`]). [`init`] is the rest, in rtw89's order:
//!
//! 1. `rtw89_chip_enable_bb_rf`, RTL8852B's `__rtw8852bx_mac_enable_bb_rf`
//!    (rtw8852b_common.c): the BB out of reset, the AFE digital clock
//!    toggled, both RF paths' XTAL SI controls written and the PHY register
//!    cycle set;
//! 2. `sys_init_ax`: `dmac_func_en_ax`, `cmac_func_en_ax(rtwdev, 0, true)`
//!    and `chip_func_en_ax`;
//! 3. `trx_init_ax`: `dmac_init_ax` (the SCC DLE quota through
//!    [`dle::dle_init`], the full HCI flow control through [`dle::hfc_init`]
//!    with every channel's and the public pages, the STA scheduler, the
//!    MPDU processor and the security engine), `cmac_init_ax` for CMAC0
//!    (scheduler, address CAM, RX filters, CCA, NAV, spatial reuse, TMAC,
//!    TRX protocol, RMAC, common, protocol and CMAC DMA), the DMAC's and
//!    CMAC0's error interrupt masks (`enable_imr_ax`, `err_imr_ctrl_ax`)
//!    and the release report (`set_host_rpr_ax`);
//! 4. `rtw89_mac_feat_init`, which makes no access with RTL8852B's
//!    `RTW89_BACAM_V0`;
//! 5. `hci.ops->mac_post_init`, `rtw89_pci_ops_mac_post_init_ax`
//!    ([`pci::mac_post_init`]), without the LTR setup;
//! 6. `rtw89_fw_send_all_early_h2c`, which sends nothing: only debugfs adds
//!    early H2Cs;
//! 7. `rtw89_fw_h2c_set_ofld_cfg` (fw.c): one H2C on CH12 ([`Commands`],
//!    [`Fwcmd`]), whose result rtw89 ignores.
//!
//! RTL8852B's own branches are taken where rtw89 takes them for it: SIFS
//! (`WMAC_SPEC_SIFS_OFDM_52B` in `trxptcl_init_ax`), the security engine's
//! TX partial mode cleared (`sec_eng_init_ax`), the response checks'
//! NAV and CCA bits cleared (`_patch_dis_resp_chk`), and every
//! `rtw89_is_rtl885xb` branch: no preload or SS2F path, the scheduler's TSF
//! advance on port reset, the response rates, the VHT A-MPDU length, the
//! CMAC DMA's full modes off, no CMAC1 error mask. Only band 0 is set up,
//! as rtw89 sets up an RTL8852B: its SCC quota gives CMAC1 no DMA pages, so
//! `rtw89_mac_is_qta_dbcc` is false and neither `dbcc_enable_ax` nor CMAC1's
//! interrupts run.
//!
//! [`stop_sch_tx`] and [`resume_sch_tx`] are `rtw89_mac_stop_sch_tx` and
//! `rtw89_mac_resume_sch_tx` (RTL8852B's `stop_sch_tx` and `resume_sch_tx`)
//! on band 0, for the steps after this one: with the firmware running they
//! ask it through the register mailbox, as rtw89 does once
//! `RTW89_FLAG_FW_RDY` is set.
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included. Polls follow `read_poll_timeout`
//! counted in steps ([`Registers::poll32`]): XTAL SI every 50 us for
//! 50000 us, the STA scheduler and the address CAM every 1 us for 2000 us,
//! the BA CAM reset every 1 us for 1000 us.
//!
//! The seams, and what is left out:
//! - The partial init before [`init`]. rtw89 runs it inside
//!   `rtw89_mac_init`, after powering the chip on afresh in
//!   `rtw89_mac_preinit` (whose `mac_func_en` is NULL on an AX chip), so it
//!   downloads the firmware once more; stage 1 has run it already and left
//!   the firmware running, and stage 2 (3.10) continues from there. Stage 1
//!   also ran the efuse step's HCI pre-deinit, which clears HCI_OPT_CTRL's
//!   wake bit that the PCIe pre-init set and rtw89's fresh partial init
//!   would set again; that is stage 2's to decide, not this module's. The C
//!   oracle runs the whole unchanged `rtw89_mac_init`, and its replay runs
//!   [`super::dle::partial_init_before_hci`] then [`init`], with the PCIe
//!   pre-init and the download stubbed between them.
//! - `rtw89_mac_init`'s `fail:` label, `rtw89_mac_pwr_off`: a failure here
//!   returns with the chip as the failure left it, and the caller powers it
//!   off ([`super::bootstrap::Stage1::power_off`]).
//! - `rtw89_chip_bb_preinit` and `rtw89_phy_init_bb_afe`, which
//!   `rtw89_core_start` runs before `rtw89_mac_init`: RTL8852B's
//!   `bb_preinit` is NULL, and the AFE sequence runs only from a firmware
//!   AFE element (`elm_info.afe`), which is not among RTL8852B's needed
//!   elements; whether the pinned image carries one is the element parser's
//!   (3.2) to show.
//! - Everything `rtw89_core_start` runs after `rtw89_mac_init`, each a later
//!   step's: the BTC power-on notice and coex (3.9), the BB and RF reset and
//!   table loads (3.3), the channel (3.4), TX power (3.5), the RF
//!   calibrations (3.6-3.8), and the HCI start with interrupts and RX
//!   (3.10).
//! - `rtw89_pci_ltr_set`, which `rtw89_pci_ops_mac_post_init_ax` calls
//!   first: Stela leaves LTR, like ASPM and L1SS, as the platform left it
//!   ([`pci`]).
//! - Other chips' branches (RTL8852A, RTL8852C, RTL8851B's and RTL8852BT's
//!   own), USB and SDIO, and the BE generation.
//!
//! An init that returns proves that every bit rtw89 waits on answered (but
//! the BA CAM reset, which rtw89 only warns about and [`Init`] reports),
//! that DMAC_FUNC_EN and CMAC_FUNC_EN read enabled at each check, that the
//! flow control's public pages added up when read back, and that the
//! offload-config H2C's BD was written, when [`Init::ofld_cfg`] says so. It
//! proves nothing about the radio, that the firmware accepted the H2C (its
//! REC_ACK and DONE_ACK come back on RXQ, which nothing reads yet), or that
//! the chip will receive.
use super::{
    dle::{self, DleInfo, HfcInfo, HfcParam, QtaMode},
    h2c::{self, Channel},
    h2creg::{H2CREG_HDR_LEN, H2cReg, Mailbox},
    io::{self, Io, Registers, prep},
    pci::{self, ring::Rings},
    registers::*,
};

/// `H2C_CL_MAC_FW_OFLD` and `H2C_FUNC_OFLD_CFG`.
pub const H2C_CL_MAC_FW_OFLD: u8 = 0x9;
pub const H2C_FUNC_OFLD_CFG: u8 = 0x14;
/// `rtw89_fw_h2c_set_ofld_cfg`'s payload, `H2C_OFLD_CFG_LEN` bytes.
pub const OFLD_CFG: [u8; 8] = [0x09, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00];

/// `RTW89_FWCMD_H2CREG_FUNC_SCH_TX_EN` and
/// `RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT`.
pub const H2CREG_FUNC_SCH_TX_EN: u8 = 5;
pub const C2HREG_FUNC_TX_PAUSE_RPT: u8 = 4;
/// `RTW89_H2CREG_SCH_TX_EN_W0_EN`, `RTW89_H2CREG_SCH_TX_EN_W1_MASK` and
/// `RTW89_H2CREG_SCH_TX_EN_W1_BAND`.
pub const H2CREG_SCH_TX_EN_W0_EN: u32 = 0xffff_0000;
pub const H2CREG_SCH_TX_EN_W1_MASK: u32 = 0x0000_ffff;
pub const H2CREG_SCH_TX_EN_W1_BAND: u32 = 1 << 16;
/// `sizeof(struct rtw89_h2creg_sch_tx_en)`: two words.
const H2CREG_SCH_TX_EN_LEN: u32 = 8;

/// `TRXCFG_WAIT_CNT`: the STA scheduler's and the address CAM's poll bound
/// in microseconds, read every 1 us.
const TRXCFG_WAIT_CNT: u64 = 2000;
/// `rst_bacam`'s `read_poll_timeout_atomic(…, 1, 1000, …)`.
const BACAM_RST_BOUND_US: u64 = 1000;
/// `rmac_init_ax`'s `PLD_RLS_MAX_PG`, `RX_MAX_LEN_UNIT` and
/// `RX_SPEC_MAX_LEN`, and its RX deadlock protection timeouts
/// `TRXCFG_RMAC_DATA_TO` and `TRXCFG_RMAC_CCA_TO`.
const PLD_RLS_MAX_PG: u32 = 127;
const RX_MAX_LEN_UNIT: u32 = 512;
const RX_SPEC_MAX_LEN: u32 = 11454 + RX_MAX_LEN_UNIT;
const TRXCFG_RMAC_DATA_TO: u16 = 15;
const TRXCFG_RMAC_CCA_TO: u16 = 32;
/// `ptcl_init_ax`'s A-MPDU VHT length for an RTL885xB.
const AMPDU_MAX_LEN_VHT: u32 = 0x3ff80;
/// `addr_cam_init_ax`'s CAM range.
const ADDR_CAM_RANGE: u32 = 0x7f;
/// `__rtw8852bx_mac_enable_bb_rf`'s value for both RF paths' XTAL SI control.
const WL_RFC_ON: u8 = 0xc7;
/// `RTW89_RPR_MODE_POH`: release reports over PCIe.
const RPR_MODE_POH: u32 = 0;
/// `set_host_rpr_ax`'s release report aggregation number and timeout.
const RLSRPT0_AGGNUM: u32 = 30;
const RLSRPT0_TO: u32 = 255;

/// The rtw89 step that failed, as its error line names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// `rtw89_chip_enable_bb_rf`.
    EnableBbRf,
    /// `mac->sys_init`.
    SysInit,
    /// `[ERR]DLE init`.
    DleInit,
    /// `[ERR]HCI FC init`.
    HfcInit,
    /// `[ERR]STA SCH init`.
    StaSchInit,
    /// `[ERR]MPDU Proc init`.
    MpduProcInit,
    /// `[ERR]Security Engine init`.
    SecEngInit,
    /// `[ERR]CMAC%d SCH init`.
    SchedulerInit,
    /// `[ERR]CMAC%d ADDR_CAM reset`.
    AddrCamInit,
    /// `[ERR]CMAC%d RX filter init`.
    RxFltrInit,
    /// `[ERR]CMAC%d CCA CTRL init`.
    CcaCtrlInit,
    /// `[ERR]CMAC%d NAV CTRL init`.
    NavCtrlInit,
    /// `[ERR]CMAC%d Spatial Reuse init`.
    SpatialReuseInit,
    /// `[ERR]CMAC%d TMAC init`.
    TmacInit,
    /// `[ERR]CMAC%d TRXPTCL init`.
    TrxptclInit,
    /// `[ERR]CMAC%d RMAC init`.
    RmacInit,
    /// `[ERR]CMAC%d Com init`.
    CmacComInit,
    /// `[ERR]CMAC%d PTCL init`.
    PtclInit,
    /// `[ERR]CMAC%d DMA init`.
    CmacDmaInit,
    /// `[ERR] enable DMAC IMR`.
    DmacImr,
    /// `[ERR] to enable CMAC0 IMR`.
    CmacImr,
    /// `err_imr_ctrl_ax`.
    ErrImr,
    /// `[ERR] set host rpr`.
    HostRpr,
    /// `hci.ops->mac_post_init`.
    PostInit,
}

/// Why a step failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause {
    /// An access the interface refused, or a poll that timed out:
    /// [`io::Error::Timeout`] names the register and the bits it waited on.
    Io(io::Error),
    /// `rtw89_mac_check_mac_en_ax`'s `-EFAULT` for the DMAC: DMAC_FUNC_EN
    /// read `value`, which is `RTW89_R32_EA` or `RTW89_R32_DEAD` or lacks
    /// MAC_FUNC_EN or DMAC_FUNC_EN.
    DmacOff { value: u32 },
    /// `rtw89_mac_check_mac_en_ax`'s `-EFAULT` for CMAC0: CMAC_FUNC_EN read
    /// `value`, which is `RTW89_R32_EA` or `RTW89_R32_DEAD` or lacks CMAC_EN.
    CmacOff { value: u32 },
    /// The DLE quota or the flow control refused its tables or the pages
    /// the chip reported.
    Dle(dle::Error),
    /// `rtw89_hw_sch_tx_en_h2c`'s `-EINVAL`: the firmware answered the
    /// scheduler request with function `id`, not
    /// `RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT`.
    TxPauseReport { id: u8 },
}

impl From<io::Error> for Cause {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<dle::Error> for Cause {
    fn from(error: dle::Error) -> Self {
        match error {
            dle::Error::Io(error) => Self::Io(error),
            dle::Error::DmacOff { value } => Self::DmacOff { value },
            error => Self::Dle(error),
        }
    }
}

/// Why the MAC init failed: the step, and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub step: Step,
    pub cause: Cause,
}

/// A failure in `step`.
fn at<E: Into<Cause>>(step: Step) -> impl FnOnce(E) -> Error {
    move |error| Error {
        step,
        cause: error.into(),
    }
}

/// What a successful MAC init leaves in rtw89's `rtwdev->mac`, and what
/// rtw89 only warns about or ignores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Init {
    /// `dle_info` as the SCC DLE init left it.
    pub dle_info: DleInfo,
    /// `hfc_param` as the full flow control read it back.
    pub hfc_param: HfcParam,
    /// `hfc_param.ch_info` and `.pub_info` as the flow control read them.
    pub hfc_info: HfcInfo,
    /// The timeout of `rst_bacam`'s poll, when the BA CAM's reset field did
    /// not clear: rtw89 warns "failed to reset BA CAM" and goes on.
    pub ba_cam_reset: Option<io::Error>,
    /// What `rtw89_fw_h2c_set_ofld_cfg` returned, which `rtw89_mac_init`
    /// ignores.
    pub ofld_cfg: Result<(), h2c::Error>,
}

/// Where the MAC init's H2C goes: `rtw89_h2c_pkt_set_hdr` with
/// `FWCMD_TYPE_H2C` and `H2C_CAT_MAC`, which takes the next sequence number
/// whatever follows, then `rtw89_h2c_tx`.
pub trait Commands<I: Io + ?Sized> {
    fn send(
        &mut self,
        io: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error>;
}

/// An RTL8852BE's H2C channel on its CH12 ring, as stage 1 leaves them
/// ([`super::bootstrap::Stage1`]).
pub struct Fwcmd<'a, 's> {
    pub channel: &'a mut Channel<'s>,
    pub rings: &'a mut Rings,
}

impl<I: Io + ?Sized> Commands<I> for Fwcmd<'_, '_> {
    /// [`Channel::command`], then [`Channel::send`].
    fn send(
        &mut self,
        io: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error> {
        let packet = self.channel.command(class, func, rack, dack, payload);
        self.channel.send(io, self.rings, &packet)
    }
}

/// `rtw89_mac_init` on a PCIe RTL8852B after its `rtw89_mac_partial_init`:
/// the BB and RF enables, the system and TRX init, the PCIe post-init and
/// the offload-config H2C, which goes to `commands`.
///
/// The chip is as stage 1 left it: powered on, its DMAC pre-initialized,
/// its PCIe DMA programmed and its firmware running. From the PCIe
/// post-init on, the chip may fetch from every TX ring once its host index
/// moves; nothing here moves one but CH12's.
pub fn init<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
) -> Result<Init, Error> {
    enable_bb_rf(io).map_err(at(Step::EnableBbRf))?;
    sys_init(io).map_err(at(Step::SysInit))?;
    let (dle_info, hfc_param, hfc_info) = dmac_init(io)?;
    let ba_cam_reset = cmac_init(io, &dle_info)?;
    // rtw89_mac_is_qta_dbcc: the SCC quota gives CMAC1 no DMA pages.
    enable_imr_dmac(io).map_err(at(Step::DmacImr))?;
    enable_imr_cmac(io).map_err(at(Step::CmacImr))?;
    err_imr_ctrl(io, true).map_err(at(Step::ErrImr))?;
    set_host_rpr(io).map_err(at(Step::HostRpr))?;
    // trx_init_ax's last step is RTL8852C's alone.
    // rtw89_mac_feat_init: RTL8852B's BA CAM is RTW89_BACAM_V0.
    pci::mac_post_init(io).map_err(at(Step::PostInit))?;
    // rtw89_fw_send_all_early_h2c: the early H2C list is empty.
    let ofld_cfg = set_ofld_cfg(io, commands);
    Ok(Init {
        dle_info,
        hfc_param,
        hfc_info,
        ba_cam_reset,
        ofld_cfg,
    })
}

/// `rtw89_fw_h2c_set_ofld_cfg`: [`OFLD_CFG`] as `H2C_FUNC_OFLD_CFG` of
/// `H2C_CL_MAC_FW_OFLD`, asking DONE_ACK and, unless its sequence number
/// does, no REC_ACK.
pub fn set_ofld_cfg<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
) -> Result<(), h2c::Error> {
    commands.send(
        io,
        H2C_CL_MAC_FW_OFLD,
        H2C_FUNC_OFLD_CFG,
        false,
        true,
        &OFLD_CFG,
    )
}

/// `__rtw8852bx_mac_enable_bb_rf` for an RTL8852B.
pub(super) fn enable_bb_rf<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write8_set(SYS_FUNC_EN, (FEN_BBRSTB | FEN_BB_GLB_RSTN) as u8)?;
    io.write32_mask(SPS_DIG_ON_CTRL0, REG_ZCDC_H_MASK, 0x1)?;
    io.write32_set(WLRF_CTRL, AFC_AFEDIG)?;
    io.write32_clr(WLRF_CTRL, AFC_AFEDIG)?;
    io.write32_set(WLRF_CTRL, AFC_AFEDIG)?;
    // The LDO voltage select is RTL8852BT's alone.
    io.write_xtal_si(XTAL_SI_WL_RFC_S0, WL_RFC_ON, FULL_BIT_MASK)?;
    io.write_xtal_si(XTAL_SI_WL_RFC_S1, WL_RFC_ON, FULL_BIT_MASK)?;
    io.write8(PHYREG_SET, PHYREG_SET_XYN_CYCLE)
}

/// `sys_init_ax` for an RTL8852B: `dmac_func_en_ax`, `cmac_func_en_ax` for
/// CMAC0, then `chip_func_en_ax`.
fn sys_init<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    // dmac_func_en_ax, without RTL8852C's H_AXIDMA and RTL8852BT's AXIDMA
    // clock.
    io.write32(
        DMAC_FUNC_EN,
        MAC_FUNC_EN
            | DMAC_FUNC_EN_BIT
            | MAC_SEC_EN
            | DISPATCHER_EN
            | DLE_CPUIO_EN
            | PKT_IN_EN
            | DMAC_TBL_EN
            | PKT_BUF_EN
            | STA_SCH_EN
            | TXPKT_CTRL_EN
            | WD_RLS_EN
            | MPDU_PROC_EN
            | DMAC_CRPRT,
    )?;
    io.write32(
        DMAC_CLK_EN,
        MAC_SEC_CLK_EN
            | DISPATCHER_CLK_EN
            | DLE_CPUIO_CLK_EN
            | PKT_IN_CLK_EN
            | STA_SCH_CLK_EN
            | TXPKT_CTRL_CLK_EN
            | WD_RLS_CLK_EN
            | BBRPT_CLK_EN,
    )?;
    // cmac_func_en_ax(rtwdev, RTW89_MAC_0, true)
    io.write32_set(
        CK_EN,
        CMAC_CKEN
            | PHYINTF_CKEN
            | CMAC_DMA_CKEN
            | PTCLTOP_CKEN
            | SCHEDULER_CKEN
            | TMAC_CKEN
            | RMAC_CKEN,
    )?;
    io.write32_set(
        CMAC_FUNC_EN,
        CMAC_EN
            | CMAC_TXEN
            | CMAC_RXEN
            | PHYINTF_EN
            | CMAC_DMA_EN
            | PTCLTOP_EN
            | SCHEDULER_EN
            | TMAC_EN
            | RMAC_EN
            | CMAC_CRPRT,
    )?;
    // chip_func_en_ax, as for every RTL885xB.
    io.write32_set(SPS_DIG_ON_CTRL0, OCP_L1_MASK)
}

/// `rtw89_mac_check_mac_en(rtwdev, RTW89_MAC_0, RTW89_DMAC_SEL)`.
fn check_dmac<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    Ok(dle::check_mac_en(io)?)
}

/// `rtw89_mac_check_mac_en(rtwdev, RTW89_MAC_0, RTW89_CMAC_SEL)`.
fn check_cmac<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    let value = io.read32(CMAC_FUNC_EN)?;
    if value == R32_EA || value == R32_DEAD || value & CMAC_EN != CMAC_EN {
        return Err(Cause::CmacOff { value });
    }
    Ok(())
}

/// `read_poll_timeout(rtw89_read16, …, step_us, bound_us, false, …)`: the
/// value that satisfied `ready`.
fn poll16<I: Io + ?Sized>(
    io: &mut I,
    register: u32,
    mask: u32,
    step_us: u64,
    bound_us: u64,
    ready: impl Fn(u16) -> bool,
) -> Result<u16, io::Error> {
    let mut waited = 0;
    loop {
        let value = io.read16(register)?;
        if ready(value) {
            return Ok(value);
        }
        if waited >= bound_us {
            return Err(io::Error::Timeout { register, mask });
        }
        io.delay_us(step_us);
        waited += step_us;
    }
}

/// `dmac_init_ax(rtwdev, 0)` on a PCIe RTL8852B: what `rtwdev->mac` then
/// holds of the DLE and the flow control.
fn dmac_init<I: Io + ?Sized>(io: &mut I) -> Result<(DleInfo, HfcParam, HfcInfo), Error> {
    let dle_info = dle::dle_init(io, dle::QTA_MODE, QtaMode::Invalid).map_err(at(Step::DleInit))?;
    // rtw89_mac_preload_init: no preload on an RTL885xB.
    // hfc_reset_param replaces every member the pre-init left, the SCC
    // entry naming each, and hfc_func_en sets h2c_en, so the full flow
    // control starts from nothing the pre-init chose.
    let mut hfc_param = HfcParam::ZERO;
    let mut hfc_info = HfcInfo::default();
    dle::hfc_init(
        io,
        &dle_info,
        &mut hfc_param,
        &mut hfc_info,
        true,
        true,
        true,
    )
    .map_err(at(Step::HfcInit))?;
    sta_sch_init(io).map_err(at(Step::StaSchInit))?;
    mpdu_proc_init(io).map_err(at(Step::MpduProcInit))?;
    sec_eng_init(io).map_err(at(Step::SecEngInit))?;
    Ok((dle_info, hfc_param, hfc_info))
}

/// `sta_sch_init_ax`: the STA scheduler enabled, its init awaited, then its
/// warm-init flag set and the non-empty SS2F info cleared. The SS2F path
/// patch is not for an RTL885xB.
fn sta_sch_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_dmac(io)?;
    let value = io.read8(SS_CTRL)? | SS_EN;
    io.write8(SS_CTRL, value)?;
    io.poll32(SS_CTRL, SS_INIT_DONE_1, 1, TRXCFG_WAIT_CNT, |value| {
        value & SS_INIT_DONE_1 != 0
    })?;
    io.write32_set(SS_CTRL, SS_WARM_INIT_FLG)?;
    io.write32_clr(SS_CTRL, SS_NONEMPTY_SS2FINFO_EN)?;
    Ok(())
}

/// `mpdu_proc_init_ax`.
fn mpdu_proc_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_dmac(io)?;
    io.write32(ACTION_FWD0, TRXCFG_MPDU_PROC_ACT_FRWD)?;
    io.write32(TF_FWD, TRXCFG_MPDU_PROC_TF_FRWD)?;
    io.write32_set(MPDU_PROC, APPEND_FCS | A_ICV_ERR)?;
    io.write32(CUT_AMSDU_CTRL, TRXCFG_MPDU_PROC_CUT_CTRL)?;
    Ok(())
}

/// `sec_eng_init_ax` for an RTL8852B: the engine's clocks, TX encryption and
/// RX, multicast and broadcast decryption on, TX partial mode off (8852B's
/// branch), then ICV and MIC appended.
fn sec_eng_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_dmac(io)?;
    let mut value = io.read32(SEC_ENG_CTRL)?;
    // init clock
    value |= CLK_EN_CGCMP | CLK_EN_WAPI | CLK_EN_WEP_TKIP;
    // init TX encryption
    value |= SEC_TX_ENC | SEC_RX_DEC;
    value |= MC_DEC | BC_DEC;
    value &= !TX_PARTIAL_MODE;
    io.write32(SEC_ENG_CTRL, value)?;
    // init MIC ICV append
    let value = io.read32(SEC_MPDU_PROC)? | APPEND_ICV | APPEND_MIC;
    io.write32(SEC_MPDU_PROC, value)?;
    Ok(())
}

/// `cmac_init_ax(rtwdev, 0)`: what `rst_bacam`'s poll timed out with, if it
/// did.
fn cmac_init<I: Io + ?Sized>(io: &mut I, dle_info: &DleInfo) -> Result<Option<io::Error>, Error> {
    scheduler_init(io).map_err(at(Step::SchedulerInit))?;
    addr_cam_init(io).map_err(at(Step::AddrCamInit))?;
    rx_fltr_init(io).map_err(at(Step::RxFltrInit))?;
    cca_ctrl_init(io).map_err(at(Step::CcaCtrlInit))?;
    nav_ctrl_init(io).map_err(at(Step::NavCtrlInit))?;
    spatial_reuse_init(io).map_err(at(Step::SpatialReuseInit))?;
    tmac_init(io).map_err(at(Step::TmacInit))?;
    trxptcl_init(io).map_err(at(Step::TrxptclInit))?;
    let ba_cam_reset = rmac_init(io, dle_info).map_err(at(Step::RmacInit))?;
    cmac_com_init(io).map_err(at(Step::CmacComInit))?;
    ptcl_init(io).map_err(at(Step::PtclInit))?;
    cmac_dma_init(io).map_err(at(Step::CmacDmaInit))?;
    Ok(ba_cam_reset)
}

/// `scheduler_init_ax` for CMAC0 of an RTL8852B.
fn scheduler_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    io.write32_mask(PREBKF_CFG_1, SIFS_MACTXEN_T1_MASK, SIFS_MACTXEN_T1)?;
    // RTL885xB
    io.write32_set(SCH_EXT_CTRL, PORT_RST_TSF_ADV)?;
    io.write32_clr(CCA_CFG_0, BTCCA_EN)?;
    io.write32_mask(PREBKF_CFG_0, PREBKF_TIME_MASK, SCH_PREBKF_24US)?;
    Ok(())
}

/// `addr_cam_init_ax` for CMAC0: the CAM's range, clear and enable set,
/// then its clear bit awaited 16 bits at a time.
fn addr_cam_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    let value = io.read32(ADDR_CAM_CTRL)?
        | prep(ADDR_CAM_RANGE, ADDR_CAM_RANGE_MASK)
        | ADDR_CAM_CLR
        | ADDR_CAM_EN;
    io.write32(ADDR_CAM_CTRL, value)?;
    poll16(
        io,
        ADDR_CAM_CTRL,
        ADDR_CAM_CLR,
        1,
        TRXCFG_WAIT_CNT,
        |value| u32::from(value) & ADDR_CAM_CLR == 0,
    )?;
    Ok(())
}

/// `rx_fltr_init_ax` for CMAC0: every management, control and data frame to
/// the host, the MAC filter rtw89's `hal.rx_fltr` holds when the interface
/// first comes up (`DEFAULT_AX_RX_FLTR`), and the PLCP header checks.
fn rx_fltr_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    // rtw89_mac_typ_fltr_opt_ax for RTW89_MGNT, RTW89_CTRL, RTW89_DATA.
    for register in [MGNT_FLTR, CTRL_FLTR, DATA_FLTR] {
        io.write32(register, RX_FLTR_FRAME_TO_HOST)?;
    }
    let plcp_ftlr = CCK_CRC_CHK
        | CCK_SIG_CHK
        | LSIG_PARITY_CHK_EN
        | SIGA_CRC_CHK
        | VHT_SU_SIGB_CRC_CHK
        | VHT_MU_SIGB_CRC_CHK
        | HE_SIGB_CRC_CHK;
    io.write32(RX_FLTR_OPT, DEFAULT_AX_RX_FLTR)?;
    io.write16(PLCP_HDR_FLTR, plcp_ftlr as u16)?;
    Ok(())
}

/// `cca_ctrl_init_ax` for CMAC0, then RTL8852B's `_patch_dis_resp_chk`.
fn cca_ctrl_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    let mut value = io.read32(CCA_CONTROL)?;
    value |= TB_CHK_BASIC_NAV
        | TB_CHK_BTCCA
        | TB_CHK_EDCCA
        | TB_CHK_CCA_P20
        | SIFS_CHK_BTCCA
        | SIFS_CHK_CCA_P20
        | CTN_CHK_INTRA_NAV
        | CTN_CHK_BASIC_NAV
        | CTN_CHK_BTCCA
        | CTN_CHK_EDCCA
        | CTN_CHK_CCA_S80
        | CTN_CHK_CCA_S40
        | CTN_CHK_CCA_S20
        | CTN_CHK_CCA_P20;
    value &= !(TB_CHK_TX_NAV
        | TB_CHK_CCA_S80
        | TB_CHK_CCA_S40
        | TB_CHK_CCA_S20
        | SIFS_CHK_CCA_S80
        | SIFS_CHK_CCA_S40
        | SIFS_CHK_CCA_S20
        | CTN_CHK_TXNAV
        | SIFS_CHK_EDCCA);
    io.write32(CCA_CONTROL, value)?;
    patch_dis_resp_chk(io)?;
    Ok(())
}

/// `_patch_dis_resp_chk` for an RTL8852B: the response checks' NAV and CCA
/// bits cleared, where later chips set them.
fn patch_dis_resp_chk<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    let rsp_chk_nav = RSP_CHK_TXNAV | RSP_CHK_INTRA_NAV | RSP_CHK_BASIC_NAV;
    let rsp_chk_cca = RSP_CHK_SEC_CCA_80
        | RSP_CHK_SEC_CCA_40
        | RSP_CHK_SEC_CCA_20
        | RSP_CHK_BTCCA
        | RSP_CHK_EDCCA
        | RSP_CHK_CCA;
    let value = io.read32(RSP_CHK_SIG)? & !rsp_chk_nav;
    io.write32(RSP_CHK_SIG, value)?;
    let value = io.read32(TRXPTCL_RESP_0)? & !rsp_chk_cca;
    io.write32(TRXPTCL_RESP_0, value)
}

/// `nav_ctrl_init_ax`, which checks no CMAC.
fn nav_ctrl_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    io.write32_set(
        WMAC_NAV_CTL,
        WMAC_PLCP_UP_NAV_EN | WMAC_TF_UP_NAV_EN | WMAC_NAV_UPPER_EN,
    )?;
    io.write32_mask(WMAC_NAV_CTL, WMAC_NAV_UPPER_MASK, NAV_25MS)?;
    Ok(())
}

/// `spatial_reuse_init_ax` for CMAC0.
fn spatial_reuse_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    io.write8_clr(RX_SR_CTRL, SR_EN)?;
    io.write8_set(BSSID_SRC_CTRL, PLCP_SRC_EN)?;
    Ok(())
}

/// `tmac_init_ax` for CMAC0.
fn tmac_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    io.write32_clr(MAC_LOOPBACK, MACLBK_EN)?;
    io.write32_mask(TCR0, TCR_UDF_THSD_MASK, TCR_UDF_THSD)?;
    io.write32_mask(
        TXD_FIFO_CTRL,
        TXDFIFO_HIGH_MCS_THRE_MASK,
        TXDFIFO_HIGH_MCS_THRE,
    )?;
    io.write32_mask(
        TXD_FIFO_CTRL,
        TXDFIFO_LOW_MCS_THRE_MASK,
        TXDFIFO_LOW_MCS_THRE,
    )?;
    Ok(())
}

/// `trxptcl_init_ax` for CMAC0 of an RTL8852B: the CCK SIFS and 8852B's
/// OFDM SIFS, the RX trigger's FCS check, and `rtw8852b_rrsr_cfgs`'
/// reference rate and RSC.
fn trxptcl_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    let mut value = io.read32(TRXPTCL_RESP_0)?;
    value &= !WMAC_SPEC_SIFS_CCK_MASK;
    value |= prep(WMAC_SPEC_SIFS_CCK, WMAC_SPEC_SIFS_CCK_MASK);
    value &= !WMAC_SPEC_SIFS_OFDM_MASK;
    value |= prep(WMAC_SPEC_SIFS_OFDM_52B, WMAC_SPEC_SIFS_OFDM_MASK);
    io.write32(TRXPTCL_RESP_0, value)?;
    io.write32_set(RXTRIG_TEST_USER_2, RXTRIG_FCSCHK_EN)?;
    // rtw8852b_rrsr_cfgs: ref_rate 0, rsc 2.
    io.write32_mask(TRXPTCL_RRSR_CTL_0, WMAC_RESP_REF_RATE_SEL, 0)?;
    io.write32_mask(TRXPTCL_RRSR_CTL_0, WMAC_RESP_RSC_MASK, 2)?;
    Ok(())
}

/// `rst_bacam`: the reset field set to reset every BA CAM entry, then
/// awaited clear. A timeout is returned, not raised: rtw89 only warns.
fn rst_bacam<I: Io + ?Sized>(io: &mut I) -> Result<Option<io::Error>, io::Error> {
    io.write32_mask(RESPBA_CAM_CTRL, BACAM_RST_MASK, S_AX_BACAM_RST_ALL)?;
    match io.poll32(
        RESPBA_CAM_CTRL,
        BACAM_RST_MASK,
        1,
        BACAM_RST_BOUND_US,
        |value| value & BACAM_RST_MASK == 0,
    ) {
        Ok(_) => Ok(None),
        Err(timeout @ io::Error::Timeout { .. }) => Ok(Some(timeout)),
        Err(refused) => Err(refused),
    }
}

/// `rmac_init_ax` for CMAC0 of an RTL8852B: the BA CAM reset, SSN
/// selection, RX deadlock timers, channel enable, the maximum MPDU length
/// the SCC quota's CMAC0 RX pages allow, and no VHT SU SIG-B CRC check.
fn rmac_init<I: Io + ?Sized>(io: &mut I, dle_info: &DleInfo) -> Result<Option<io::Error>, Cause> {
    check_cmac(io)?;
    let ba_cam_reset = rst_bacam(io)?;
    io.write8_set(RESPBA_CAM_CTRL, SSN_SEL)?;

    let mut value = io.read16(DLK_PROTECT_CTL)?;
    value = (value & !(RX_DLK_DATA_TIME_MASK as u16))
        | prep(TRXCFG_RMAC_DATA_TO.into(), RX_DLK_DATA_TIME_MASK) as u16;
    value = (value & !(RX_DLK_CCA_TIME_MASK as u16))
        | prep(TRXCFG_RMAC_CCA_TO.into(), RX_DLK_CCA_TIME_MASK) as u16;
    io.write16(DLK_PROTECT_CTL, value)?;

    io.write8_mask(RCR, CH_EN_MASK, 0x1)?;

    let rx_qta = u32::from(dle_info.c0_rx_qta).min(PLD_RLS_MAX_PG);
    let rx_max_len =
        (rx_qta * u32::from(dle_info.ple_pg_size)).min(RX_SPEC_MAX_LEN) / RX_MAX_LEN_UNIT;
    io.write32_mask(RX_FLTR_OPT, RX_MPDU_MAX_LEN_MASK, rx_max_len)?;

    io.write8_clr(PLCP_HDR_FLTR, VHT_SU_SIGB_CRC_CHK as u8)?;
    Ok(ba_cam_reset)
}

/// `cmac_com_init_ax` for CMAC0 of an RTL8852B: no TX sub-carrier, and OFDM
/// and CCK response rates.
fn cmac_com_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    let mut value = io.read32(TX_SUB_CARRIER_VALUE)?;
    value &= !(TXSC_20M_MASK | TXSC_40M_MASK | TXSC_80M_MASK);
    io.write32(TX_SUB_CARRIER_VALUE, value)?;
    // RTL885xB
    io.write32_mask(PTCL_RRSR1, RRSR_RATE_EN_MASK, RRSR_OFDM_CCK_EN)?;
    Ok(())
}

/// `ptcl_init_ax` for CMAC0 of a PCIe RTL8852B.
fn ptcl_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    let mut value = io.read32(SIFS_SETTING)?;
    value = (value & !HW_CTS2SELF_PKT_LEN_TH_MASK)
        | prep(S_AX_CTS2S_TH_1K, HW_CTS2SELF_PKT_LEN_TH_MASK);
    value = (value & !HW_CTS2SELF_PKT_LEN_TH_TWW_MASK)
        | prep(S_AX_CTS2S_TH_SEC_256B, HW_CTS2SELF_PKT_LEN_TH_TWW_MASK);
    value |= HW_CTS2SELF_EN;
    io.write32(SIFS_SETTING, value)?;

    let mut value = io.read32(PTCL_FSM_MON)?;
    value = (value & !PTCL_TX_ARB_TO_THR_MASK) | prep(S_AX_PTCL_TO_2MS, PTCL_TX_ARB_TO_THR_MASK);
    value &= !PTCL_TX_ARB_TO_MODE;
    io.write32(PTCL_FSM_MON, value)?;

    // RTW89_MAC_0
    io.write8_set(
        PTCL_COMMON_SETTING_0,
        (CMAC_TX_MODE_0 | CMAC_TX_MODE_1) as u8,
    )?;
    io.write8_clr(
        PTCL_COMMON_SETTING_0,
        (PTCL_TRIGGER_SS_EN_0 | PTCL_TRIGGER_SS_EN_1 | PTCL_TRIGGER_SS_EN_UL) as u8,
    )?;
    io.write8_mask(PTCLRPT_FULL_HDL, SPE_RPT_PATH_MASK, FWD_TO_WLCPU as u8)?;
    // RTL885xB
    io.write32_mask(AGG_LEN_VHT_0, AMPDU_MAX_LEN_VHT_MASK, AMPDU_MAX_LEN_VHT)?;
    Ok(())
}

/// `cmac_dma_init_ax` for CMAC0 of an RTL885xB: the RU pointers' full modes
/// off.
fn cmac_dma_init<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    io.write8_clr(RXDMA_CTRL_0, RX_FULL_MODE)?;
    Ok(())
}

/// `rtw89_write32_clr` then `rtw89_write32_set` on one interrupt mask, as
/// every `rtw89_*_imr_enable` does.
fn imr<I: Io + ?Sized>(io: &mut I, register: u32, clr: u32, set: u32) -> Result<(), io::Error> {
    io.write32_clr(register, clr)?;
    io.write32_set(register, set)
}

/// `enable_imr_ax(rtwdev, RTW89_MAC_0, RTW89_DMAC_SEL)` with
/// `rtw8852b_imr_info`.
fn enable_imr_dmac<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_dmac(io)?;
    // rtw89_wdrls_imr_enable
    imr(io, WDRLS_ERR_IMR, WDRLS_IMR_EN_CLR, WDRLS_IMR_SET)?;
    // rtw89_wsec_imr_enable
    io.write32_set(SEC_DEBUG, IMR_ERROR)?;
    // rtw89_mpdu_trx_imr_enable, whose set masks are 0 on an RTL8852B.
    imr(
        io,
        MPDU_TX_ERR_IMR,
        TX_GET_ERRPKTID_INT_EN
            | TX_NXT_ERRPKTID_INT_EN
            | TX_MPDU_SIZE_ZERO_INT_EN
            | TX_OFFSET_ERR_INT_EN
            | TX_HDR3_SIZE_ERR_INT_EN,
        0,
    )?;
    imr(
        io,
        MPDU_RX_ERR_IMR,
        GETPKTID_ERR_INT_EN | MHDRLEN_ERR_INT_EN | RPT_ERR_INT_EN,
        0,
    )?;
    // rtw89_sta_sch_imr_enable
    imr(
        io,
        STA_SCHEDULER_ERR_IMR,
        SEARCH_HANG_TIMEOUT_INT_EN | RPT_HANG_TIMEOUT_INT_EN | PLE_B_PKTID_ERR_INT_EN,
        STA_SCHEDULER_IMR_SET,
    )?;
    // rtw89_txpktctl_imr_enable
    imr(
        io,
        TXPKTCTL_ERR_IMR_ISR,
        TXPKTCTL_IMR_B0_CLR,
        TXPKTCTL_IMR_B0_SET,
    )?;
    imr(
        io,
        TXPKTCTL_ERR_IMR_ISR_B1,
        TXPKTCTL_IMR_B1_CLR,
        TXPKTCTL_IMR_B1_SET,
    )?;
    // rtw89_wde_imr_enable, rtw89_ple_imr_enable
    imr(io, WDE_ERR_IMR, WDE_IMR_CLR, WDE_IMR_SET)?;
    imr(io, PLE_ERR_IMR, PLE_IMR_CLR, PLE_IMR_SET)?;
    // rtw89_pktin_imr_enable
    io.write32_set(PKTIN_ERR_IMR, PKTIN_GETPKTID_ERR_INT_EN)?;
    // rtw89_dispatcher_imr_enable; the other dispatcher's set mask is 0.
    imr(
        io,
        HOST_DISPATCHER_ERR_IMR,
        HOST_DISP_IMR_CLR,
        HOST_DISP_IMR_SET,
    )?;
    imr(
        io,
        CPU_DISPATCHER_ERR_IMR,
        CPU_DISP_IMR_CLR,
        CPU_DISP_IMR_SET,
    )?;
    imr(io, OTHER_DISPATCHER_ERR_IMR, OTHER_DISP_IMR_CLR, 0)?;
    // rtw89_cpuio_imr_enable
    imr(io, CPUIO_ERR_IMR, CPUIO_IMR_CLR, CPUIO_IMR_SET)?;
    // rtw89_bbrpt_imr_enable; the channel info error set mask is 0.
    io.write32_set(BBRPT_COM_ERR_IMR_ISR, BBRPT_COM_NULL_PLPKTID_ERR_INT_EN)?;
    imr(io, BBRPT_CHINFO_ERR_IMR_ISR, BBRPT_CHINFO_IMR_CLR, 0)?;
    io.write32_set(BBRPT_DFS_ERR_IMR_ISR, BBRPT_DFS_TO_ERR_INT_EN)?;
    io.write32_set(LA_ERRFLAG, LA_IMR_DATA_LOSS_ERR)?;
    Ok(())
}

/// `enable_imr_ax(rtwdev, RTW89_MAC_0, RTW89_CMAC_SEL)` with
/// `rtw8852b_imr_info`.
fn enable_imr_cmac<I: Io + ?Sized>(io: &mut I) -> Result<(), Cause> {
    check_cmac(io)?;
    // rtw89_scheduler_imr_enable
    imr(
        io,
        SCHEDULE_ERR_IMR,
        SORT_NON_IDLE_ERR_INT_EN | FSM_TIMEOUT_ERR_INT_EN,
        FSM_TIMEOUT_ERR_INT_EN,
    )?;
    // rtw89_ptcl_imr_enable
    imr(io, PTCL_IMR0, PTCL_IMR_CLR_ALL, PTCL_IMR_SET)?;
    // rtw89_cdma_imr_enable; the second mask is RTL8852C's alone.
    imr(io, DLE_CTRL, DLE_IMR_CLR, DLE_IMR_SET)?;
    // rtw89_phy_intf_imr_enable, whose masks are 0 on an RTL8852B.
    imr(io, PHYINFO_ERR_IMR, 0, 0)?;
    // rtw89_rmac_imr_enable, rtw89_tmac_imr_enable
    imr(io, RMAC_ERR_ISR, RMAC_IMR_CLR, RMAC_IMR_SET)?;
    imr(io, TMAC_ERR_IMR_ISR, TMAC_IMR_CLR, TMAC_IMR_SET)?;
    Ok(())
}

/// `err_imr_ctrl_ax` for an RTL885xB, which has no CMAC1 error mask.
fn err_imr_ctrl<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    io.write32(DMAC_ERR_IMR, if enable { DMAC_ERR_IMR_EN } else { 0 })?;
    io.write32(CMAC_ERR_IMR, if enable { CMAC0_ERR_IMR_EN } else { 0 })
}

/// `set_host_rpr_ax` over PCIe: WD release in POH mode with every release
/// report filter on, 30 reports aggregated or 255 time units at most.
fn set_host_rpr<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_mask(WDRLS_CFG, WDRLS_MODE_MASK, RPR_MODE_POH)?;
    io.write32_set(RLSRPT0_CFG0, RLSRPT0_FLTR_MAP_MASK)?;
    io.write32_mask(RLSRPT0_CFG1, RLSRPT0_AGGNUM_MASK, RLSRPT0_AGGNUM)?;
    io.write32_mask(RLSRPT0_CFG1, RLSRPT0_TO_MASK, RLSRPT0_TO)
}

/// `enum rtw89_sch_tx_sel`: which queues [`stop_sch_tx`] stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchTxSel {
    All,
    Hiq,
    Mg0,
    Macid,
}

/// `rtw89_mac_stop_sch_tx(rtwdev, RTW89_MAC_0, &tx_en, sel)`: CTN_TXEN read
/// for what to resume later, then the queues `sel` names stopped. With
/// `firmware`, the mailbox of a running firmware (`RTW89_FLAG_FW_RDY`), the
/// firmware stops them; otherwise CTN_TXEN is written. Returns the enables
/// read first, the `tx_en` [`resume_sch_tx`] takes.
pub fn stop_sch_tx<I: Io + ?Sized>(
    io: &mut I,
    firmware: Option<&mut Mailbox>,
    sel: SchTxSel,
) -> Result<u16, Cause> {
    let tx_en = io.read16(CTN_TXEN)?;
    let mask = match sel {
        SchTxSel::All | SchTxSel::Macid => CTN_TXEN_ALL_MASK,
        SchTxSel::Hiq => CTN_TXEN_HGQ,
        SchTxSel::Mg0 => CTN_TXEN_MGQ,
    };
    set_hw_sch_tx_en(io, firmware, 0, mask as u16)?;
    Ok(tx_en)
}

/// `rtw89_mac_resume_sch_tx(rtwdev, RTW89_MAC_0, tx_en)`: every queue's
/// enable put back as `tx_en` has it, through the firmware when it runs.
pub fn resume_sch_tx<I: Io + ?Sized>(
    io: &mut I,
    firmware: Option<&mut Mailbox>,
    tx_en: u16,
) -> Result<(), Cause> {
    set_hw_sch_tx_en(io, firmware, tx_en, CTN_TXEN_ALL_MASK as u16)
}

/// `rtw89_set_hw_sch_tx_en` for band 0.
fn set_hw_sch_tx_en<I: Io + ?Sized>(
    io: &mut I,
    firmware: Option<&mut Mailbox>,
    tx_en: u16,
    tx_en_mask: u16,
) -> Result<(), Cause> {
    check_cmac(io)?;
    if let Some(mailbox) = firmware {
        return hw_sch_tx_en_h2c(io, mailbox, 0, tx_en, tx_en_mask);
    }
    let value = io.read16(CTN_TXEN)?;
    io.write16(CTN_TXEN, (value & !tx_en_mask) | (tx_en & tx_en_mask))?;
    Ok(())
}

/// `rtw89_hw_sch_tx_en_h2c`: `RTW89_FWCMD_H2CREG_FUNC_SCH_TX_EN` with the
/// enables, their mask and the band, answered by
/// `RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT`.
fn hw_sch_tx_en_h2c<I: Io + ?Sized>(
    io: &mut I,
    mailbox: &mut Mailbox,
    band: u8,
    tx_en: u16,
    tx_en_mask: u16,
) -> Result<(), Cause> {
    let mut regs = [0; 4];
    regs[0] = prep(tx_en.into(), H2CREG_SCH_TX_EN_W0_EN);
    regs[1] = prep(tx_en_mask.into(), H2CREG_SCH_TX_EN_W1_MASK)
        | prep(band.into(), H2CREG_SCH_TX_EN_W1_BAND);
    let info = H2cReg {
        id: H2CREG_FUNC_SCH_TX_EN,
        content_len: (H2CREG_SCH_TX_EN_LEN - H2CREG_HDR_LEN) as u8,
        regs,
    };
    let c2h = mailbox.exchange(io, &info)?;
    if c2h.id != C2HREG_FUNC_TX_PAUSE_RPT {
        return Err(Cause::TxPauseReport { id: c2h.id });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
