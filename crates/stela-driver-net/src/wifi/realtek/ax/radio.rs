// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
// Copyright(c) 2024 Realtek Corporation
//! Stage 2 of an RTL8852BE's bring-up: the chip stage 1 left powered off
//! ([`super::bootstrap::Stage1::power_off`], the power-off that closes
//! rtw89's probe) brought up again as pinned rtw89 brings it up when its
//! interface comes up, tuned to one channel, and listened to. [`run`]
//! composes the slices, each a [`Stage`], in `rtw89_core_start`'s order
//! (core.c):
//!
//! 1. [`Stage::Tables`], no access: the image staged again and its elements
//!    recognized for the board (`rtw89_fw_recognize_elements`, done at probe
//!    in rtw89; [`super::elements`]), the BB, RF and NCTL tables
//!    ([`phy::Tables`]), the TX power tables ([`txpower::Tables::load`]),
//!    the TX power tracking deltas TSSI reads ([`TrkDeltas`]), and the
//!    regulation ([`Regulation::new`], with `--wifi-country` as the stack's
//!    alpha2) with regulatory.db's bound ([`Cap::country`]).
//! 2. [`Stage::PowerOn`]: `rtw89_mac_preinit`, which is `rtw89_mac_pwr_on`
//!    once probe is done ([`power::power_on`]; `mac_func_en` is NULL on an
//!    AX chip), `rtw89_chip_bb_preinit` (NULL for an RTL8852B), then
//!    `rtw89_phy_init_bb_afe` ([`phy::init_bb_afe`]), which
//!    `rtw89_core_start` runs before `rtw89_mac_init` and which does nothing
//!    without an AFE element (the RTL8852B image has none).
//! 3. `rtw89_mac_init`'s `rtw89_mac_partial_init(rtwdev, false, false)`, as
//!    stage 1 ran it ([`super::bootstrap`]): [`Stage::DmacPreInit`]
//!    ([`dle::partial_init_before_hci`]), [`Stage::PciePreInit`]
//!    ([`pci::mac_pre_init`], which sets HCI_OPT_CTRL's wake bit stage 1's
//!    HCI pre-deinit cleared), [`Stage::Download`] ([`fwdl::download`]).
//! 4. [`Stage::MacInit`]: the rest of `rtw89_mac_init` ([`mac::init`]).
//!    `rtw89_btc_ntfy_poweron` only counts.
//! 5. [`Stage::BbRf`]: `rtw89_chip_reset_bb_rf`, `rtw89_phy_init_bb_reg`,
//!    `rtw89_chip_bb_postinit` (NULL) and `rtw89_phy_init_rf_reg`
//!    ([`phy::load`]).
//! 6. [`Stage::Coex`]: `rtw89_btc_ntfy_init`, as the plan's WL-only init
//!    ([`coex::init_wl_only`]), where rtw89 passes `BTC_MODE_NORMAL`.
//! 7. [`Stage::DmInit`]: the subset of `rtw89_phy_dm_init` (phy.c) that
//!    writes the radio's state: `rtw89_chip_bb_sethw`
//!    (`__rtw8852bx_bb_sethw`, [`bb_sethw`]: the sounding bits, the MAC ID
//!    power limits and the RPL bias the channel switch reads),
//!    `rtw89_chip_rfk_hw_init` (NULL), `rtw89_phy_init_rf_nctl`
//!    ([`phy::init_rf_nctl`]), `rtw89_chip_rfk_init` ([`rfk::init`]) and
//!    `rtw89_chip_set_txpwr_ctrl` ([`rtw8852b_txpower::set_txpwr_ctrl`]).
//! 8. [`Stage::Start`]: `rtw89_mac_cfg_ppdu_status_bands(rtwdev, true)`
//!    ([`channel::cfg_ppdu_status`]) and `rtw89_mac_update_rts_threshold`
//!    ([`update_rts_threshold`]); `set_edcca_mode` and `cfg_phy_rpt` are NULL
//!    on an AX chip. `rtw89_hci_start` starts NAPI and writes the interrupt
//!    masks: Stela polls RXQ instead and writes no mask, so its start
//!    is the first drain of RXQ. Then the RX filter
//!    `rtw89_hw_scan_start` (fw.c) writes while it scans
//!    ([`set_rx_fltr`], [`SCAN_RX_FLTR`]).
//! 9. [`Stage::Channel`]: `rtw89_set_channel`'s `__rtw89_set_channel`
//!    ([`channel::switch`], with [`rtw8852b_txpower::set_txpwr`] for its TX
//!    power), then, the PHY having had no channel, `rtw89_chip_rfk_band_changed`
//!    ([`rfk::band_changed`], `rtw8852b_tssi_scan`).
//! 10. [`Stage::Calibrate`]: `rtw8852b_rfk_channel` ([`rfk::channel`]: RX
//!     DCK, IQK, TSSI, DPK, RF_NTFY_MCC), which rtw89 runs when a station
//!     associates; RXQ drained again.
//! 11. [`Stage::Listen`]: RXQ polled ([`listen::listen`]).
//!
//! Then the key registers are read ([`Read`]) and the chip is powered off
//! (`rtw89_mac_pwr_off`, as `rtw89_core_stop` ends), so the next system
//! finds it cold. A stage that fails reads the same registers and powers
//! the chip off, once it was powered on.
//!
//! Steps 2 to the start of 8 are [`power_up`], and what step 1 reads for TX
//! power is [`TxPower`]: the station's hardware ([`super::hardware`]) brings
//! the interface up through them too, then tunes as its station asks.
//!
//! What this leaves out, and why:
//! - The rest of `rtw89_phy_dm_init`: the statistics, diagnostics, CCX and
//!   NHM monitors, the PHY status IE bitmaps (`rtw89_physts_parsing_init`),
//!   DIG, CFO, EDCCA, channel info, UL TB, antenna diversity, the RFE GPIO,
//!   `rtw89_chip_power_trim` and `rtw89_chip_cfg_txrx_path`. They tune
//!   dynamic mechanisms, TX power trims and the TX/RX path from the BB
//!   tables' defaults; the PHY status header that carries the RSSI comes
//!   whatever IEs the bitmaps select.
//! - What `rtw89_core_start` runs after `rtw89_hci_start`: the track works,
//!   `rtw89_chip_rfk_init_late` (NULL for an RTL8852B), the BTC radio state,
//!   the firmware log and BA CAM H2Cs, and TAS.
//! - `rtw89_btc_ntfy_switch_band`, which follows the first channel: coex
//!   runs WL-only.
//! - An interface: rtw89's `add_interface` gives the chip a port, address
//!   and BSSID CAM entries and a role, none of which a passive listen needs
//!   here. With no address CAM entry, the RX filter's CAM checks
//!   (`B_AX_A_UC_CAM_MATCH`, `B_AX_A_BC_CAM_MATCH`) are cleared too, as
//!   rtw89 clears them for `FIF_PROBE_REQ`, on top of what its scan clears.
//! - Monitor mode: not needed to hear beacons.
//!
//! A stage 2 that listened proves that each step's polls answered and that
//! the chip wrote what [`listen::Heard`] counts; a beacon with a BSSID
//! proves the radio receives on the channel.
use super::{
    super::{
        firmware::{Layout, Rtw89},
        identity::{Chip, StageError},
    },
    bootstrap::Report as Stage1,
    coex,
    dle::{self, PreInit},
    efuse::Info,
    elements::{self, Board, Elements, Id},
    fwdl::{self, Downloaded},
    h2c::Channel as H2c,
    h2creg::Mailbox,
    io::{self, Io, Registers},
    listen::{self, Frame, Heard},
    mac::{self, Cause, Fwcmd},
    pci::{
        self,
        ring::{self, Rings},
    },
    phy::{self, Tables},
    power::{self, PoweredOn},
    regd::{self, Regulation},
    registers::*,
    rtw8852b::{
        channel::{self, BbGain, Channel, Switched, Width},
        rfk::{
            self, Calibrated, ChannelInputs, MacScheduler, State, dpk,
            tssi::{self, TrkDeltas},
        },
        txpower as rtw8852b_txpower,
    },
    rxdesc::{NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, Sorter},
    txpower::{self, Cap, Power},
};
use crate::{
    Clock, bus::pci::ConfigSpace, firmware::Provider, wifi::regulatory::database::Country,
};
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt;

/// `R_P0_EN_SOUND_WO_NDP`, `R_P1_EN_SOUND_WO_NDP` and their bit, which
/// `__rtw8852bx_bb_sethw` clears.
pub const R_P0_EN_SOUND_WO_NDP: u32 = 0x0d7c;
pub const R_P1_EN_SOUND_WO_NDP: u32 = 0x2d7c;
pub const B_EN_SOUND_WO_NDP: u32 = 1 << 1;
/// `R_AX_PWR_MACID_LMT_TABLE0` and `…127`.
pub const PWR_MACID_LMT_TABLE0: u32 = 0xd36c;
pub const PWR_MACID_LMT_TABLE127: u32 = 0xd568;
/// `R_AX_AGG_LEN_HT_0`, `B_AX_RTS_TXTIME_TH_MASK` and
/// `B_AX_RTS_LEN_TH_MASK`.
pub const AGG_LEN_HT_0: u32 = 0xc614;
pub const RTS_TXTIME_TH_MASK: u32 = 0xff00;
pub const RTS_LEN_TH_MASK: u32 = 0x00ff;
/// `__rtw89_mac_update_rts_threshold` with the default RTS threshold
/// (`(u32)-1`): `MAC_AX_TIME_TH_DEF >> MAC_AX_TIME_TH_SH` and
/// `MAC_AX_LEN_TH_DEF >> MAC_AX_LEN_TH_SH`, each at most 255.
pub const RTS_TIME_TH: u16 = 88 >> 5;
pub const RTS_LEN_TH: u16 = 4080 >> 4;
/// `R_AX_RX_FLTR_OPT`'s address checks (`B_AX_A_*`).
pub const A_A1_MATCH: u32 = 1 << 1;
pub const A_BC: u32 = 1 << 2;
pub const A_UC_CAM_MATCH: u32 = 1 << 4;
pub const A_BC_CAM_MATCH: u32 = 1 << 5;
pub const A_BCN_CHK_EN: u32 = 1 << 7;
/// `B_AX_RX_FLTR_CFG_MASK`: every bit but the MPDU length.
pub const RX_FLTR_CFG_MASK: u32 = !RX_MPDU_MAX_LEN_MASK;
/// The filter this listens with: `rtwdev->hal.rx_fltr` (`DEFAULT_AX_RX_FLTR`
/// as `rx_fltr_init_ax` left it) without the beacon, broadcast and A1 checks,
/// as `rtw89_hw_scan_start` writes it, and without the address CAM checks,
/// as `FIF_PROBE_REQ` clears them, since no interface holds a CAM entry.
pub const SCAN_RX_FLTR: u32 =
    DEFAULT_AX_RX_FLTR & !(A_BCN_CHK_EN | A_BC | A_A1_MATCH | A_UC_CAM_MATCH | A_BC_CAM_MATCH);
/// How long [`run`] listens by default: the plan's 2 s.
pub const LISTEN_US: u64 = 2_000_000;
/// The most RXQ buffers one drain takes: every RX BD four times.
pub const DRAIN_LIMIT: u32 = 4 * ring::RXBD_NUM_MAX;

/// How far stage 2 got: each step of [`run`], in its order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Stage {
    Tables,
    PowerOn,
    DmacPreInit,
    PciePreInit,
    Download,
    MacInit,
    BbRf,
    Coex,
    DmInit,
    Start,
    Channel,
    Calibrate,
    Listen,
}

impl Stage {
    /// Every stage, in [`run`]'s order.
    pub const ALL: [Self; 13] = [
        Self::Tables,
        Self::PowerOn,
        Self::DmacPreInit,
        Self::PciePreInit,
        Self::Download,
        Self::MacInit,
        Self::BbRf,
        Self::Coex,
        Self::DmInit,
        Self::Start,
        Self::Channel,
        Self::Calibrate,
        Self::Listen,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Tables => "tables",
            Self::PowerOn => "power on",
            Self::DmacPreInit => "dmac pre-init",
            Self::PciePreInit => "pcie pre-init",
            Self::Download => "firmware download",
            Self::MacInit => "mac init",
            Self::BbRf => "bb and rf tables",
            Self::Coex => "coex",
            Self::DmInit => "dm init",
            Self::Start => "hci start",
            Self::Channel => "channel",
            Self::Calibrate => "rf calibration",
            Self::Listen => "listen",
        }
    }

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|&each| each == self)
            .unwrap_or_default()
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why stage 2 stopped.
#[derive(Debug)]
pub enum Error {
    /// The image is gone, or holds no suit for the cut.
    Firmware(StageError),
    NotRtl8852b(Chip),
    /// The firmware's elements were refused.
    Elements(elements::Error),
    /// A BB, RF or NCTL table is missing.
    PhyTable(Id),
    TxpwrTables(txpower::Error),
    /// The firmware has no TX power tracking table for both bands, which
    /// TSSI reads.
    TxpwrTrk,
    /// The regulation disables a channel the channel spans (UNII-4 outside
    /// the US).
    NotPermitted,
    /// regulatory.db's country has no rule for the channel, and the RF
    /// calibrations transmit.
    NoRule {
        alpha2: [u8; 2],
    },
    PowerOn(power::Error),
    DmacPreInit(dle::Error),
    PciePreInit(pci::Error),
    Download(Box<fwdl::Failure>),
    Mac(mac::Error),
    Phy(phy::Error),
    /// A register access the interface refused, or a poll whose timeout
    /// rtw89 returns.
    Io(io::Error),
    /// The CMAC read off for the PPDU status, or its access was refused.
    PpduStatus(Cause),
    Rings(ring::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Firmware(error) => write!(f, "{error:?}"),
            Self::NotRtl8852b(chip) => write!(f, "{chip:?} is not an RTL8852B"),
            Self::Elements(error) => write!(f, "{error}"),
            Self::PhyTable(id) => write!(f, "the firmware has no {} element", id.name()),
            Self::TxpwrTables(error) => write!(f, "{error:?}"),
            Self::TxpwrTrk => f.write_str(
                "the firmware's TX power tracking table lacks a 2.4 or 5 GHz type TSSI reads",
            ),
            Self::NotPermitted => f.write_str("the regulation disables this channel (UNII-4)"),
            Self::NoRule { alpha2 } => write!(
                f,
                "regulatory.db gives {}{} no rule for this channel, and the RF calibrations transmit",
                alpha2[0] as char, alpha2[1] as char
            ),
            Self::PowerOn(error) => write!(f, "{error:?}"),
            Self::DmacPreInit(error) => write!(f, "{error:?}"),
            Self::PciePreInit(error) => write!(f, "{error:?}"),
            Self::Download(error) => write!(f, "{error:?}"),
            Self::Mac(error) => write!(f, "{error:?}"),
            Self::Phy(error) => write!(f, "{error:?}"),
            Self::Io(error) => write!(f, "{error:?}"),
            Self::PpduStatus(cause) => write!(f, "{cause:?}"),
            Self::Rings(error) => write!(f, "{error:?}"),
        }
    }
}

/// Where a key register is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Space {
    /// MAC space, read 32 bits wide.
    Mac,
    /// BB space behind [`io::CR_BASE`].
    Bb,
    /// An RF register of this path, all 20 bits.
    Rf(u8),
    /// The coex software grants through the LTE access
    /// ([`coex::read_gnt`]).
    Gnt,
}

/// A key register read for the log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Read {
    pub name: &'static str,
    pub space: Space,
    pub address: u32,
    pub value: Result<u32, io::Error>,
}

/// The key registers read after the listen, or after a failure: the power
/// and firmware state, the HCI and DMAC/CMAC enables, the RX path's ring
/// indices and filters, the PPDU status, TX power and coex registers, the BB
/// reset, channel, bandwidth and TSSI registers, and RF 0x00, 0x05 and 0x18
/// of both paths.
pub const KEY_REGISTERS: [(&str, Space, u32); 64] = [
    ("SYS_ISO_CTRL", Space::Mac, SYS_ISO_CTRL),
    ("SYS_PW_CTRL", Space::Mac, SYS_PW_CTRL),
    ("SYS_SDIO_CTRL", Space::Mac, SYS_SDIO_CTRL),
    ("HCI_OPT_CTRL", Space::Mac, HCI_OPT_CTRL),
    ("SCOREBOARD", Space::Mac, SCOREBOARD),
    ("IC_PWR_STATE", Space::Mac, IC_PWR_STATE),
    ("PLATFORM_ENABLE", Space::Mac, PLATFORM_ENABLE),
    ("WLRF_CTRL", Space::Mac, WLRF_CTRL),
    ("WCPU_FW_CTRL", Space::Mac, WCPU_FW_CTRL),
    ("BOOT_DBG", Space::Mac, BOOT_DBG),
    ("HCI_FUNC_EN", Space::Mac, HCI_FUNC_EN),
    ("PCIE_INIT_CFG1", Space::Mac, PCIE_INIT_CFG1),
    ("PCIE_DMA_STOP1", Space::Mac, PCIE_DMA_STOP1),
    ("PCIE_DMA_BUSY1", Space::Mac, PCIE_DMA_BUSY1),
    ("RXQ_RXBD_IDX", Space::Mac, RXQ_RXBD_IDX),
    ("RPQ_RXBD_IDX", Space::Mac, RPQ_RXBD_IDX),
    ("CH12_TXBD_IDX", Space::Mac, CH12_TXBD_IDX),
    ("DMAC_FUNC_EN", Space::Mac, DMAC_FUNC_EN),
    ("DMAC_CLK_EN", Space::Mac, DMAC_CLK_EN),
    ("MPDU_PROC", Space::Mac, MPDU_PROC),
    ("SEC_ENG_CTRL", Space::Mac, SEC_ENG_CTRL),
    ("HW_RPT_FWD", Space::Mac, HW_RPT_FWD),
    ("CMAC_FUNC_EN", Space::Mac, CMAC_FUNC_EN),
    ("CK_EN", Space::Mac, CK_EN),
    ("CTN_TXEN", Space::Mac, CTN_TXEN),
    ("PTCL_COMMON_SETTING_0", Space::Mac, PTCL_COMMON_SETTING_0),
    ("AGG_LEN_HT_0", Space::Mac, AGG_LEN_HT_0),
    ("DLE_CTRL", Space::Mac, DLE_CTRL),
    ("RSP_CHK_SIG", Space::Mac, RSP_CHK_SIG),
    ("TRXPTCL_RESP_0", Space::Mac, TRXPTCL_RESP_0),
    ("PLCP_HDR_FLTR", Space::Mac, PLCP_HDR_FLTR),
    ("RX_FLTR_OPT", Space::Mac, RX_FLTR_OPT),
    ("CTRL_FLTR", Space::Mac, CTRL_FLTR),
    ("MGNT_FLTR", Space::Mac, MGNT_FLTR),
    ("DATA_FLTR", Space::Mac, DATA_FLTR),
    ("PPDU_STAT", Space::Mac, PPDU_STAT),
    ("PWR_RATE_CTRL", Space::Mac, PWR_RATE_CTRL),
    ("WL_PRI_MSK", Space::Mac, WL_PRI_MSK),
    ("BTC_BT_COEX_MSK_TABLE", Space::Mac, BTC_BT_COEX_MSK_TABLE),
    ("LTE_SW_CFG_1 (GNT)", Space::Gnt, LTE_SW_CFG_1),
    ("RSTB_ASYNC", Space::Bb, R_RSTB_ASYNC),
    ("UPD_CLK_ADC", Space::Bb, R_UPD_CLK_ADC),
    ("MAC_PIN_SEL", Space::Bb, R_MAC_PIN_SEL),
    ("PD_CTRL", Space::Bb, R_PD_CTRL),
    ("GNT_BT_WGT_EN", Space::Bb, R_GNT_BT_WGT_EN),
    ("S0_HW_SI_DIS", Space::Bb, R_S0_HW_SI_DIS),
    ("S1_HW_SI_DIS", Space::Bb, R_S1_HW_SI_DIS),
    ("P0_RFMODE_ORI_RX", Space::Bb, R_P0_RFMODE_ORI_RX),
    ("P1_RFMODE_ORI_RX", Space::Bb, R_P1_RFMODE_ORI_RX),
    ("ADC_FIFO", Space::Bb, R_ADC_FIFO),
    ("FC0_BW_V1", Space::Bb, R_FC0_BW_V1),
    ("CHBW_MOD_V1", Space::Bb, R_CHBW_MOD_V1),
    ("PATH0_BAND_SEL_V1", Space::Bb, R_PATH0_BAND_SEL_V1),
    ("PATH1_BAND_SEL_V1", Space::Bb, R_PATH1_BAND_SEL_V1),
    ("P0_RPL1", Space::Bb, R_P0_RPL1),
    ("P1_RPL1", Space::Bb, R_P1_RPL1),
    ("P0_TSSI_TRK", Space::Bb, R_P0_TSSI_TRK),
    ("P1_TSSI_TRK", Space::Bb, R_P1_TSSI_TRK),
    ("RF A 0x00", Space::Rf(0), 0x00),
    ("RF A 0x05", Space::Rf(0), 0x05),
    ("RF A 0x18", Space::Rf(0), 0x18),
    ("RF B 0x00", Space::Rf(1), 0x00),
    ("RF B 0x05", Space::Rf(1), 0x05),
    ("RF B 0x18", Space::Rf(1), 0x18),
];

/// Read [`KEY_REGISTERS`].
pub fn read_key_registers<I: Io + ?Sized>(io: &mut I) -> Vec<Read> {
    KEY_REGISTERS
        .iter()
        .map(|&(name, space, address)| Read {
            name,
            space,
            address,
            value: match space {
                Space::Mac => io.read32(address),
                Space::Bb => io.phy_read32(address),
                Space::Rf(path) => io.read_rf(path, address, RFREG_MASK),
                Space::Gnt => coex::read_gnt(io),
            },
        })
        .collect()
}

/// What stage 2 listens on and under which regulation.
#[derive(Clone, Copy)]
pub struct Plan<'a> {
    pub channel: Channel,
    /// The stack's country (`--wifi-country`), `None` for `"00"`.
    pub alpha2: Option<[u8; 2]>,
    /// That country as regulatory.db gives it, when the database loaded and
    /// has it.
    pub country: Option<&'a Country>,
    pub listen_us: u64,
    /// The clock the stages and the listen are timed by.
    pub clock: Clock,
}

impl Plan<'_> {
    /// Channel 36 at 80 MHz (center 42), the user's AP's.
    pub fn default_channel() -> Channel {
        Channel::new(42, 36, Width::Mhz80).expect("36/80 is a channel")
    }
}

/// The regulation the TX power was read under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Regulated {
    /// `regulatory->regd`'s alpha2.
    pub alpha2: [u8; 2],
    /// The efuse named the country.
    pub programmed: bool,
    /// regulatory.db's bound on each limit, per NTX, in MAC units.
    pub cap: Cap,
    /// Whether the bound is regulatory.db's for the country, not rtw89's
    /// SAR-less maximum.
    pub country_cap: bool,
}

/// What stage 2 learned, each part as its stage completed.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub regulated: Option<Regulated>,
    pub powered: Option<PoweredOn>,
    pub pre_init: Option<PreInit>,
    pub downloaded: Option<Downloaded>,
    pub mac: Option<mac::Init>,
    /// What rtw89 logged of the AFE, the BB and RF tables and the NCTL.
    pub phy_warnings: Vec<phy::Warning>,
    pub coex: Option<coex::Init>,
    /// `efuse_gain->offset_base` and `rssi_base` for PHY 0.
    pub bases: Option<(i8, i8)>,
    /// The scheduler's refusal around RFK init's RX DCK.
    pub rfk_init: Option<Option<Cause>>,
    /// `rtw89_mac_cfg_ppdu_status_bands`' failure, which rtw89 ignores.
    pub ppdu_status: Option<Cause>,
    /// RX_FLTR_OPT as written.
    pub rx_filter: Option<u32>,
    pub switched: Option<Switched>,
    pub calibrated: Option<Calibrated>,
    /// The calibrations' state after the last one that ran.
    pub rfk: Option<Box<State>>,
    /// What RXQ held before the listen: the H2C acks and what the radio
    /// received while it was tuned and calibrated.
    pub before: Heard,
    /// What the listen heard.
    pub heard: Option<Heard>,
    /// The key registers, read before the power-off.
    pub registers: Vec<Read>,
}

impl Report {
    /// Each thing rtw89 only logs or ignores that went wrong, in stage
    /// order: phy, mac, coex, RF calibration and channel warnings.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(mac) = &self.mac {
            if let Some(error) = mac.ba_cam_reset {
                out.push(format!("mac: failed to reset BA CAM ({error:?})"));
            }
            if let Err(error) = mac.ofld_cfg {
                out.push(format!("mac: offload-config H2C not sent ({error:?})"));
            }
        }
        for warning in &self.phy_warnings {
            out.push(format!("phy: {warning:?}"));
        }
        if let Some(coex) = &self.coex {
            if let Err(error) = coex.coex_init {
                out.push(format!("coex: PTA init stopped ({error:?})"));
            }
            if coex.pta_owner {
                out.push(String::from("coex: PTA owner warning (BT owned the PTA)"));
            }
            if let Err(error) = coex.gnt {
                out.push(format!(
                    "coex: grants written past an unready LTE ({error:?})"
                ));
            }
            if let Err(value) = coex.plt {
                out.push(format!(
                    "coex: polluter table not written, CMAC_FUNC_EN {value:#010x}"
                ));
            }
            if coex.h2c_failed > 0 {
                out.push(format!(
                    "coex: {} H2C refused, first {:?}",
                    coex.h2c_failed, coex.h2c_error
                ));
            }
        }
        if let Some(Some(cause)) = self.rfk_init {
            out.push(format!("rfk init: scheduler around RX DCK {cause:?}"));
        }
        if let Some(cause) = self.ppdu_status {
            out.push(format!("start: PPDU status not enabled ({cause:?})"));
        }
        if let Some(switched) = &self.switched {
            if let Some(cause) = switched.help.stop_sch_tx {
                out.push(format!("channel: stopping TX {cause:?}"));
            }
            if let Some(cause) = switched.help.ppdu_status {
                out.push(format!("channel: PPDU status off {cause:?}"));
            }
            if let Some(cause) = switched.done.ppdu_status {
                out.push(format!("channel: PPDU status on {cause:?}"));
            }
            if let Some(cause) = switched.done.resume_sch_tx {
                out.push(format!("channel: resuming TX {cause:?}"));
            }
            if switched.tuned.lck_timeouts > 0 {
                out.push(format!(
                    "channel: [LCK]LCK timeout x{}",
                    switched.tuned.lck_timeouts
                ));
            }
        }
        if let Some(calibrated) = &self.calibrated {
            for (name, cause) in [
                ("RX DCK", calibrated.rx_dck),
                ("IQK", calibrated.iqk),
                ("TSSI", calibrated.tssi),
                ("DPK", calibrated.dpk),
            ] {
                if let Some(cause) = cause {
                    out.push(format!("rfk: scheduler around {name} {cause:?}"));
                }
            }
            if let Err(error) = calibrated.ntfy_mcc {
                out.push(format!("rfk: RF_NTFY_MCC not sent ({error:?})"));
            }
        }
        if let Some(state) = &self.rfk {
            let dack = &state.dack;
            for path in 0..dack.addck_timeout.len() {
                for (name, timeout) in [
                    ("ADDCK", dack.addck_timeout[path]),
                    ("DADCK", dack.dadck_timeout[path]),
                    ("MSBK", dack.msbk_timeout[path]),
                ] {
                    if timeout {
                        out.push(format!("rfk: DACK S{path} {name} timeout"));
                    }
                }
            }
            let iqk = &state.iqk;
            if iqk.iqk_fail_cnt > 0 {
                out.push(format!(
                    "rfk: IQK failed {} times (LOK {:?}/{:?}, TX {:?}, RX {:?})",
                    iqk.iqk_fail_cnt,
                    iqk.lok_cor_fail[0],
                    iqk.lok_fin_fail[0],
                    iqk.iqk_tx_fail[0],
                    iqk.iqk_rx_fail[0]
                ));
            }
            if state.dpk.oneshot_timeouts > 0 {
                out.push(format!(
                    "rfk: DPK one-shot timeout x{}",
                    state.dpk.oneshot_timeouts
                ));
            }
        }
        out
    }
}

/// When each stage began, from stage 2's start.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timings {
    /// Microseconds to each stage's beginning, in [`Stage::ALL`]'s order.
    pub begun: [Option<u64>; Stage::ALL.len()],
    /// Microseconds to stage 2's end.
    pub ended: Option<u64>,
}

impl Timings {
    /// How long `stage` took: to the next stage's beginning, or to the end.
    pub fn took(&self, stage: Stage) -> Option<u64> {
        let index = stage.index();
        let start = self.begun[index]?;
        let end = self.begun[index + 1..]
            .iter()
            .find_map(|at| *at)
            .or(self.ended)?;
        end.checked_sub(start)
    }
}

/// What a caller sees of stage 2 as it runs, as for a log or a test. Does
/// nothing by default.
pub trait Observer {
    /// `stage` begins.
    fn begin(&mut self, _stage: Stage) {}
    /// The stages ended, at `stopped` when one failed; the key registers
    /// and the power-off follow.
    fn end(&mut self, _stopped: Option<Stage>) {}
}

impl Observer for () {}

/// How stage 2 ended.
#[derive(Debug)]
pub struct Outcome {
    pub channel: Channel,
    pub report: Box<Report>,
    /// The stage that failed and why; `None` when the listen ran.
    pub stopped: Option<(Stage, Error)>,
    pub timings: Timings,
    /// The closing power-off, `None` when the chip was never powered on.
    pub power_off: Option<Result<(), power::Error>>,
}

impl Outcome {
    /// What the listen heard, when it ran.
    pub fn heard(&self) -> Option<&Heard> {
        self.report.heard.as_ref()
    }
}

/// The owners stage 1 handed back, which stage 2 reuses.
pub struct Held<'h, 's, I> {
    pub io: &'h mut I,
    pub rings: &'h mut Rings,
    pub channel: &'h mut H2c<'s>,
}

/// Stage 2 on the chip stage 1 (`stage1`) brought up and powered off again:
/// [`Stage::ALL`] in order, then the key registers and the power-off. A
/// failure reads the registers and powers the chip off once it was powered
/// on.
///
/// # Safety
/// [`super::bootstrap::bring_up`]'s contract holds for `held` and `config`,
/// as stage 1 had them: the same function, its rings and channel, its DMA
/// stopped by stage 1's power-off. The caller keeps `held.rings` while the
/// chip may reach them, which it may from the PCIe pre-init on, after this
/// returns too when the power-off failed.
pub unsafe fn run<I: Io, C: ConfigSpace + ?Sized>(
    held: Held<'_, '_, I>,
    config: &mut C,
    stage1: &Stage1,
    firmware: &dyn Provider,
    plan: &Plan<'_>,
    observer: &mut dyn Observer,
) -> Outcome {
    let Held { io, rings, channel } = held;
    let start = plan.clock.try_start().ok();
    let now = |clock: Clock| start.and_then(|start| clock.try_elapsed_us(start).ok());
    let mut report = Report::default();
    let mut timings = Timings::default();
    let mut stage = Stage::Tables;
    let mut powered = false;
    let result = {
        let mut begin = |next: Stage| {
            stage = next;
            timings.begun[next.index()] = now(plan.clock);
            observer.begin(next);
        };
        // SAFETY: the caller's contract.
        unsafe {
            bring_up(
                io,
                rings,
                channel,
                config,
                stage1,
                firmware,
                plan,
                &mut report,
                &mut powered,
                &mut begin,
            )
        }
    };
    timings.ended = now(plan.clock);
    let stopped = result.err().map(|error| (stage, error));
    observer.end(stopped.as_ref().map(|&(stage, _)| stage));
    let power_off = powered.then(|| {
        report.registers = read_key_registers(io);
        power::power_off(io, &power_inputs(stage1))
    });
    Outcome {
        channel: plan.channel,
        report: Box::new(report),
        stopped,
        timings,
        power_off,
    }
}

/// `rtw89_mac_pwr_on` and `rtw89_mac_pwr_off`'s inputs once probe is done:
/// the cut and what the efuse gave.
pub fn power_inputs(stage1: &Stage1) -> power::Inputs {
    let efuse = &stage1.info.efuse;
    power::Inputs {
        cut: stage1.version.cut,
        rfe_type: efuse.rfe_type,
        efuse_valid: efuse.valid,
        power_k_valid: efuse.power_k_valid,
        probe_done: true,
    }
}

/// The TX power reads every channel switch makes, owned: what
/// [`Stage::Tables`] reads of the firmware's elements for TX power
/// ([`txpower::Tables::load`]), TSSI's tracking deltas ([`TrkDeltas`]) and
/// the regulation ([`Regulation::new`]).
pub struct TxPower {
    pub tables: txpower::Tables,
    pub deltas: TrkDeltas,
    pub regulation: Regulation,
}

impl TxPower {
    /// The TX power tables of `elements`, the tracking deltas, and the
    /// regulation of the efuse's country and the stack's `alpha2`
    /// (`--wifi-country`, `"00"` when none).
    pub fn load(elements: &Elements<'_>, info: &Info, alpha2: [u8; 2]) -> Result<Self, Error> {
        let tables =
            txpower::Tables::load(elements.rfe_data.as_ref()).map_err(Error::TxpwrTables)?;
        let deltas = elements
            .txpwr_trk
            .as_ref()
            .and_then(TrkDeltas::from_elements)
            .ok_or(Error::TxpwrTrk)?;
        let regulation = Regulation::new(regd::map(elements), info.efuse.country_code, alpha2);
        Ok(Self {
            tables,
            deltas,
            regulation,
        })
    }
}

/// What [`power_up`] leaves for the channel switches and calibrations
/// that follow it.
pub struct Running {
    /// The register mailbox the download opened, through which the
    /// scheduler's TX is stopped and resumed.
    pub mailbox: Mailbox,
    /// The RF calibrations' state after RFK init.
    pub state: Box<State>,
    /// What a channel switch reads besides the channel: the BB gain table's
    /// values, the efuse gains, the RPL biases and the RX antennas.
    pub inputs: channel::Inputs,
}

/// [`run`]'s stages, each begun through `begin`, what each learns put in
/// `report`, `powered` set once the power-on succeeded.
///
/// # Safety
/// [`run`]'s contract.
#[expect(
    clippy::too_many_arguments,
    reason = "the stage-1 owners and stage 2's inputs"
)]
unsafe fn bring_up<I: Io, C: ConfigSpace + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    h2c: &mut H2c<'_>,
    config: &mut C,
    stage1: &Stage1,
    firmware: &dyn Provider,
    plan: &Plan<'_>,
    report: &mut Report,
    powered: &mut bool,
    begin: &mut dyn FnMut(Stage),
) -> Result<(), Error> {
    let cut = stage1.version.cut;
    let info = &stage1.info;
    let board = Board::rtl8852b(info.efuse.rfe_type, cut);
    let chan = plan.channel;

    begin(Stage::Tables);
    let staged = stage1.profile.stage(firmware).map_err(Error::Firmware)?;
    let Layout::Rtw89(suit) = &staged.layout else {
        return Err(Error::NotRtl8852b(stage1.profile.chip()));
    };
    let elements = Elements::recognize(suit, board).map_err(Error::Elements)?;
    let tables = Tables::from_elements(&elements).map_err(Error::PhyTable)?;
    let power = TxPower::load(&elements, info, plan.alpha2.unwrap_or(*b"00"))?;
    let txchan = chan.txpower();
    if !power.regulation.permits(&txchan) {
        return Err(Error::NotPermitted);
    }
    let (cap, country_cap) = match plan.country {
        Some(country) => (
            Cap::country(country, &txchan).ok_or(Error::NoRule {
                alpha2: country.alpha2(),
            })?,
            true,
        ),
        None => (Cap::NONE, false),
    };
    report.regulated = Some(Regulated {
        alpha2: power.regulation.regd().alpha2,
        programmed: power.regulation.programmed,
        cap,
        country_cap,
    });

    // SAFETY: the caller's contract.
    let Running {
        mut mailbox,
        mut state,
        inputs,
    } = unsafe {
        power_up(
            io, rings, h2c, config, stage1, suit, &tables, report, powered, begin,
        )
    }?;
    // rtw89_hci_start: Stela polls RXQ from here on.
    let band = match chan.band() {
        channel::Band::Ghz2 => NL80211_BAND_2GHZ,
        channel::Band::Ghz5 => NL80211_BAND_5GHZ,
    };
    let mut sorter = Sorter::<Frame>::new(chan.primary_freq(), band);
    listen::drain(io, rings, &mut sorter, &mut report.before, DRAIN_LIMIT).map_err(Error::Rings)?;
    report.rx_filter = Some(set_rx_fltr(io, SCAN_RX_FLTR).map_err(Error::Io)?);

    begin(Stage::Channel);
    let txpwr = Power {
        tables: &power.tables,
        regulation: &power.regulation,
        cap,
    };
    let switched = channel::switch(io, Some(&mut mailbox), &chan, &inputs, None, |io, _| {
        rtw8852b_txpower::set_txpwr(io, &txpwr, &txchan)
    })
    .map_err(Error::Io)?;
    report.switched = Some(switched);
    let tssi = tssi::Inputs {
        efuse: &info.tssi,
        deltas: &power.deltas,
        gain: &inputs,
    };
    if switched.band_notice {
        // rtw89_btc_ntfy_switch_band: coex runs WL-only.
        let changed = rfk::band_changed(io, &mut state, chan.rfk(), &tssi);
        report.rfk = Some(state.clone());
        changed.map_err(Error::Io)?;
    }

    begin(Stage::Calibrate);
    let calibrated = rfk::channel(
        io,
        &mut MacScheduler {
            firmware: Some(&mut mailbox),
        },
        &mut Fwcmd {
            channel: h2c,
            rings,
        },
        &mut state,
        chan.rfk(),
        &ChannelInputs {
            tssi,
            dpk: dpk::Inputs {
                epa_2g: false,
                epa_5g: false,
                cv: cut,
            },
        },
    );
    report.rfk = Some(state.clone());
    report.calibrated = Some(calibrated.map_err(Error::Io)?);
    listen::drain(io, rings, &mut sorter, &mut report.before, DRAIN_LIMIT).map_err(Error::Rings)?;
    report.before.finish(&mut sorter);

    begin(Stage::Listen);
    let mut heard = Heard::default();
    let listened = listen::listen(
        io,
        rings,
        plan.clock,
        plan.listen_us,
        &mut sorter,
        &mut heard,
    );
    report.heard = Some(heard);
    listened.map_err(Error::Rings)
}

/// [`Stage::PowerOn`] to the start of [`Stage::Start`] on the chip stage 1
/// (`stage1`) left powered off, with the image `suit` and the BB, RF and
/// NCTL `tables` [`Stage::Tables`] read: the power-on and AFE, the partial
/// init with its download, the MAC init, the BB and RF tables, coex
/// WL-only, the DM init with RFK init, and the start's PPDU status and RTS
/// threshold, each stage begun through `begin`, what each learns put in
/// `report`, `powered` set once the power-on succeeded. What stays of the
/// start, the first drain of RXQ and the RX filter, is the caller's, as is
/// every channel.
///
/// # Safety
/// [`run`]'s contract, for `io`, `rings`, `h2c` and `config`.
#[expect(
    clippy::too_many_arguments,
    reason = "the stage-1 owners and the tables the bring-up loads"
)]
pub unsafe fn power_up<I: Io, C: ConfigSpace + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    h2c: &mut H2c<'_>,
    config: &mut C,
    stage1: &Stage1,
    suit: &Rtw89<'_>,
    tables: &Tables<'_>,
    report: &mut Report,
    powered: &mut bool,
    begin: &mut dyn FnMut(Stage),
) -> Result<Running, Error> {
    let cut = stage1.version.cut;
    let info = &stage1.info;
    let rfe = info.efuse.rfe_type;
    let board = Board::rtl8852b(rfe, cut);

    begin(Stage::PowerOn);
    let inputs = power_inputs(stage1);
    report.powered = Some(power::power_on(io, &inputs).map_err(Error::PowerOn)?);
    *powered = true;
    phy::init_bb_afe(io, tables.afe.as_ref(), &mut report.phy_warnings).map_err(Error::Phy)?;

    begin(Stage::DmacPreInit);
    report.pre_init = Some(dle::partial_init_before_hci(io).map_err(Error::DmacPreInit)?);

    begin(Stage::PciePreInit);
    // SAFETY: the caller's contract: `io` and `config` reach the function
    // whose DMA domain `rings` was allocated in, its DMA stopped by the
    // power-off, and the caller keeps `rings`.
    unsafe { pci::mac_pre_init(io, config, rings) }.map_err(Error::PciePreInit)?;

    begin(Stage::Download);
    let downloaded = fwdl::download(io, rings, h2c, &suit.image, &stage1.secure)
        .map_err(|failure| Error::Download(Box::new(failure)))?;
    report.downloaded = Some(downloaded);
    let mut mailbox = Mailbox::after_download(&downloaded);

    begin(Stage::MacInit);
    report.mac = Some(
        mac::init(
            io,
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
        )
        .map_err(Error::Mac)?,
    );

    begin(Stage::BbRf);
    let load = phy::load(
        io,
        &mut Fwcmd {
            channel: h2c,
            rings,
        },
        tables,
        board,
    )
    .map_err(Error::Phy)?;
    report.phy_warnings.extend_from_slice(&load.warnings);

    begin(Stage::Coex);
    report.coex = Some(
        coex::init_wl_only(
            io,
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
            rfe,
            cut,
        )
        .map_err(Error::Io)?,
    );

    begin(Stage::DmInit);
    let (offset_base, rssi_base) = bb_sethw(io).map_err(Error::Io)?;
    report.bases = Some((offset_base, rssi_base));
    phy::init_rf_nctl(io, tables, board, &mut report.phy_warnings).map_err(Error::Phy)?;
    let mut state = Box::<State>::default();
    let refused = rfk::init(
        io,
        &mut MacScheduler {
            firmware: Some(&mut mailbox),
        },
        &mut state,
    );
    report.rfk = Some(state.clone());
    report.rfk_init = Some(refused.map_err(Error::Io)?);
    rtw8852b_txpower::set_txpwr_ctrl(io).map_err(Error::Io)?;

    begin(Stage::Start);
    report.ppdu_status = ignored(channel::cfg_ppdu_status(io, true)).map_err(Error::PpduStatus)?;
    update_rts_threshold(io).map_err(Error::Io)?;
    Ok(Running {
        mailbox,
        state,
        inputs: channel::Inputs {
            bb_gain: BbGain::from_table(&load.bb_gain),
            efuse_gain: info.efuse_gain,
            offset_base,
            rssi_base,
            antenna_rx: info.hal.antenna_rx,
            monitor: false,
        },
    })
}

/// A result rtw89 ignores: kept, unless the interface refused an access.
fn ignored(result: Result<(), Cause>) -> Result<Option<Cause>, Cause> {
    match result {
        Ok(()) => Ok(None),
        Err(Cause::Io(error)) if !matches!(error, io::Error::Timeout { .. }) => {
            Err(Cause::Io(error))
        }
        Err(cause) => Ok(Some(cause)),
    }
}

/// `__rtw8852bx_bb_sethw`: sounding without NDP off on both paths,
/// `rtw8852bx_bb_macid_ctrl_init`'s MAC ID power limits zeroed through
/// `rtw89_mac_txpwr_write32`, then the RPL bias of R_P0_RPL1 and R_P1_RPL1,
/// read after the BB table loaded: `efuse_gain->offset_base[RTW89_PHY_0]`
/// and `rssi_base[RTW89_PHY_0]`.
pub fn bb_sethw<I: Io + ?Sized>(io: &mut I) -> Result<(i8, i8), io::Error> {
    io.phy_write32_clr(R_P0_EN_SOUND_WO_NDP, B_EN_SOUND_WO_NDP)?;
    io.phy_write32_clr(R_P1_EN_SOUND_WO_NDP, B_EN_SOUND_WO_NDP)?;
    let mut addr = PWR_MACID_LMT_TABLE0;
    while addr <= PWR_MACID_LMT_TABLE127 {
        txpower::mac_txpwr_write32(io, addr, 0)?;
        addr += 4;
    }
    let offset_base = io.phy_read32_mask(R_P0_RPL1, B_P0_RPL1_BIAS_MASK)? as i8;
    let rssi_base = io.phy_read32_mask(R_P1_RPL1, B_P0_RPL1_BIAS_MASK)? as i8;
    Ok((offset_base, rssi_base))
}

/// `rtw89_mac_update_rts_threshold` on band 0 with mac80211's default RTS
/// threshold: the time and length thresholds in `R_AX_AGG_LEN_HT_0`.
pub fn update_rts_threshold<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write16_mask(AGG_LEN_HT_0, RTS_TXTIME_TH_MASK, RTS_TIME_TH.min(255))?;
    io.write16_mask(AGG_LEN_HT_0, RTS_LEN_TH_MASK, RTS_LEN_TH.min(255))
}

/// `rtw89_mac_set_rx_fltr(rtwdev, RTW89_MAC_0, rx_fltr)`: every bit of
/// R_AX_RX_FLTR_OPT but the MPDU length taken from `rx_fltr`. Returns what
/// was written.
pub fn set_rx_fltr<I: Io + ?Sized>(io: &mut I, rx_fltr: u32) -> Result<u32, io::Error> {
    let value = io.read32(RX_FLTR_OPT)?;
    let value = (value & !RX_FLTR_CFG_MASK) | (rx_fltr & RX_FLTR_CFG_MASK);
    io.write32(RX_FLTR_OPT, value)?;
    Ok(value)
}

#[cfg(test)]
mod tests;
