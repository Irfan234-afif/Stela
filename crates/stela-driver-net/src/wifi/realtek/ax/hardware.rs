// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! An RTL8852BE beneath its [`Realtek`] station: what pinned rtw89's
//! `mac80211.c`, `core.c` and `pci.c` do for mac80211 on a station
//! interface, over the slices of the steps before it. Each operation takes
//! the radio's only worker, so nothing here locks.
//!
//! [`Hardware::new`] is stage 1 ([`bootstrap::bring_up`]) and the power-off
//! that closes rtw89's probe; [`Hardware::start`] is what follows as the
//! interface comes up: stage 2's bring-up up to `rtw89_hci_start`
//! ([`radio::power_up`]), the WD pages of the data rings, the first drain
//! of RXQ and the interrupts on (`rtw89_pci_ops_start`), then
//! `rtw89_ops_add_interface`'s station link ([`sta::vif_init`]) and
//! mac80211's first `configure_filter`. No channel is tuned until the
//! station tunes one.
//!
//! Then each [`Device`] operation is rtw89's half of the mac80211 operation
//! it names:
//!
//! - [`Device::tune`] is `__rtw89_set_channel` ([`channel::switch`], with
//!   `rtw8852b_set_txpwr` under the channel's EIRP), and
//!   `rtw89_chip_rfk_band_changed` when PHY 0 had no channel or its band
//!   changed. A channel tuned outside a scan needs its RF calibration
//!   ([`rfk::channel`], `rtw8852b_rfk_channel`), which
//!   [`Device::prepare_transmit`] runs before the first frame, as
//!   `rtw89_core_sta_link_add` runs it before mac80211 authenticates: a
//!   scan's hops are never calibrated.
//! - [`Device::scanning`] is `rtw89_core_scan_start` and
//!   `rtw89_core_scan_complete` (core.c) for mac80211's software scan:
//!   `rtw8852b_rfk_scan`'s TSSI notification on the channel tuned and the
//!   address CAM with the scan's address, which is the station's own.
//! - [`Device::transmit`] is `rtw89_core_tx_write` and the kick:
//!   `rtw89_pci_check_and_reclaim_tx_resource`, the frame mapped behind a
//!   WD page ([`Rings::tx_write`]) and its ring kicked. [`Device::management`],
//!   [`Device::data`] and [`Device::null`] fill the descriptor as
//!   `rtw89_core_tx_update_desc_info` and its mgmt and data helpers do: a
//!   management frame and a nullfunc on B0MGQ with the hardware's sequence
//!   number at the BSS's lowest basic rate; data on its TID's AC ring with
//!   the WD info, the pairwise key's security CAM entry, and the A-MPDU
//!   fields of an agreement in force, an EAPOL frame kept out of it.
//! - [`Device::receive`] is one look of `rtw89_pci_interrupt_threadfn` and
//!   `rtw89_pci_napi_poll` ([`Interrupts::look`]): RPQ's release reports
//!   free the frames and, where the station numbered one, report it
//!   ([`Report::Released`]); RXQ's buffers go through `rtw89_core_rx`
//!   ([`Sorter`]): frames, their FCS cut as `RX_INCLUDES_FCS` has mac80211
//!   cut it, signal from their PPDU status, and the firmware's RA reports
//!   for the peer ([`Report::Rate`]).
//! - [`Device::set_port`] is `BSS_CHANGED_BSSID` ([`sta::bssid_changed`]);
//!   [`Device::joined`] is `rtw89_station_mode_sta_assoc`
//!   ([`sta::sta_assoc`]), `rtw89_phy_ra_assoc` ([`Ra::assoc`]) and
//!   `__rtw89_ops_bss_link_assoc`'s port update ([`sta::bss_assoc`]);
//!   [`Device::left`] is `rtw89_core_sta_link_disconnect` and the BSSID
//!   cleared; [`Device::refresh_rates`] is `rtw89_phy_ra_update_sta_link`.
//! - [`Device::write_key`] and [`Device::clear_key`] are
//!   `rtw89_cam_sec_key_add` and `rtw89_cam_sec_key_del` ([`cam`]).
//! - [`Device::filter_beacons`] is `rtw89_ops_configure_filter`
//!   (mac80211.c) for `FIF_BCN_PRBRESP_PROMISC`; [`Device::set_edca`] is
//!   `__rtw89_conf_tx`'s EDCA H2C (`rtw89_fw_h2c_set_edca`) for each access
//!   category in mac80211's order.
//! - [`Device::watchdog`] is the subset of `rtw89_track_work` that runs
//!   here: the traffic statistics (`rtw89_traffic_stats_track`) and, outside
//!   a scan, `rtw89_phy_ra_update`; DIG, CFO and DPK tracking are a later
//!   step's, at [`Hardware::track`].
//!
//! What this leaves out, and why:
//! - `rtw89_mac_bf_assoc`, beamformee CSI: the advertisement's VHT and HE
//!   beamformee bits are masked, so no AP sounds the station.
//! - The HE QoS +HTC BSR rtw89 adds to data (`rtw89_core_tx_update_he_qos_htc`):
//!   the station builds the MPDU, which carries none.
//! - The BA CAM's static entries (`rtw89_fw_h2c_ba_cam`): the station gets
//!   no hook as an RX agreement starts, and an RTL8852B's
//!   `RTW89_BACAM_V0` makes dynamic entries itself, as rtw89 lets it when
//!   the static ones run out.
//! - MU EDCA, power save (LPS), the beacon tracking and filter offloads,
//!   coex beyond WL-only, and hardware scan: the station hops channels
//!   in software.
//!
//! What a station on it proves is what its frames prove: each was read by
//! the chip's DMA and released by a report, and what the AP answered came
//! back through RXQ. Nothing here proves that a frame reached the air.
//!
//! [`Realtek`]: super::super::station::Realtek
use super::{
    super::{
        firmware::Layout,
        station::{
            self, Data, Device, Incoming, KeyEntry, Management, PAIRWISE_CAM, Queue, Received,
            Reported, Watched,
        },
    },
    bootstrap::{self, Claim, Report as Stage1, Stage1 as Started},
    c2h::C2h,
    cam::{self, Cipher as CamCipher, Key},
    capabilities::{self, Chip},
    elements::{Board, Elements},
    h2c::{
        Channel as H2c,
        ra::{
            self, LinkSta, RC_BW_CHANGED, RC_NSS_CHANGED, RC_SUPP_RATES_CHANGED, Ra, RaReport,
            StaBandwidth,
        },
        station::{self as sta, Bss, HeCap, Link, Peer, UpdMode},
    },
    interrupt::Interrupts,
    io::{Io, NativeIo, prep},
    listen::FCS_LEN,
    mac::{Commands, Fwcmd, H2C_CL_MAC_FW_OFLD},
    pci::{
        release::{Completion, TxStatus},
        ring::{self, Buffer, Rings, RxChannel, TxChannel},
    },
    phy::Tables,
    power,
    radio::{self, A_A1_MATCH, A_BC, A_BC_CAM_MATCH, A_BCN_CHK_EN, A_UC_CAM_MATCH, Running},
    registers::DEFAULT_AX_RX_FLTR,
    rtw8852b::{
        channel::{self, Channel},
        rfk::{self, ChannelInputs, MacScheduler, dpk, tssi},
        txpower as rtw8852b_txpower,
    },
    rxdesc::{self, Delivered, Sorted, Sorter},
    txpower::{Cap, Power},
    txwd::{self, DescInfo},
};
use crate::{
    Mac,
    bus::{
        dma::{
            mapping::{Direction, DmaDomain},
            memory::PageSource,
        },
        pci::ConfigSpace,
    },
    firmware::Provider,
    wifi::{
        Band,
        security::Cipher,
        station::{
            AssociationContext,
            operations::ChannelDefinition,
            phy::{AccessCategory, McsMaps, Mode, Width},
        },
    },
};
use alloc::{boxed::Box, collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use core::fmt;

/// The station link's MAC ID and port: the first an interface takes
/// (`rtw89_acquire_mac_id`, `rtw89_core_acquire_bit_map` over the ports).
pub const MAC_ID: u8 = 0;
pub const PORT: u8 = 0;
/// `IEEE80211_MAX_MPDU_LEN_VHT_11454`, the `max_vht_mpdu_cap` rtw89 gives
/// an RTL8852B: the longest MPDU, an A-MSDU's subframes and all.
pub const MAX_FRAME: usize = 11454;
/// `RTW89_HW_RATE_CCK1` and `RTW89_HW_RATE_OFDM6`.
pub const HW_RATE_CCK1: u16 = 0x0;
pub const HW_RATE_OFDM6: u16 = 0x4;
/// `H2C_FUNC_USR_EDCA` of `H2C_CL_MAC_FW_OFLD`, and `H2C_EDCA_LEN`.
pub const H2C_FUNC_USR_EDCA: u8 = 0xf;
pub const H2C_EDCA_LEN: usize = 12;
/// `FW_EDCA_PARAM_*`.
pub const EDCA_PARAM_TXOPLMT: u32 = 0x07ff_0000;
pub const EDCA_PARAM_CWMAX: u32 = 0x0000_f000;
pub const EDCA_PARAM_CWMIN: u32 = 0x0000_0f00;
pub const EDCA_PARAM_AIFS: u32 = 0x0000_00ff;
/// The ACIs of mac80211's access categories in its order (VO, VI, BE, BK):
/// `ac_to_fw_idx`, which is the ACI.
pub const CONF_TX_ORDER: [usize; 4] = [3, 2, 0, 1];
/// `rtw89_init_vht_cap`'s beamformee bits: SU, MU and the STS.
const VHT_BEAMFORMEE: u32 = capabilities::VHT_CAP_SU_BEAMFORMEE_CAPABLE
    | capabilities::VHT_CAP_MU_BEAMFORMEE_CAPABLE
    | 7 << capabilities::VHT_CAP_BEAMFORMEE_STS_SHIFT;
/// `IEEE80211_HE_PHY_CAP4_SU_BEAMFORMEE` and
/// `IEEE80211_HE_PHY_CAP4_BEAMFORMEE_MAX_STS_UNDER_80MHZ_MASK`.
const HE_PHY_CAP4_BEAMFORMEE: u8 = 0x01 | 0x1c;
/// The looks one [`Device::receive`] takes while a poll spends its budget.
const LOOKS: usize = 4;
/// The most RXQ buffers the start's drain takes: every RX BD four times.
const DRAIN_LIMIT: u32 = radio::DRAIN_LIMIT;
/// `RTW89_TFC_*` traffic levels.
const TFC_MID: u8 = 3;
/// What the station goes without, named once each.
const NO_POWER_SAVE: &str = "rtw89's leisure power save on an RTL8852B";

fn failed<E: fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{step}: {error:?}")
}

/// The channel number of a frequency in MHz.
fn number(frequency: u32) -> u8 {
    match frequency {
        2484 => 14,
        f if f < 5000 => ((f.saturating_sub(2407)) / 5) as u8,
        f => ((f - 5000) / 5) as u8,
    }
}

/// `definition` as rtw89's `struct rtw89_chan`.
fn chan_of(definition: &ChannelDefinition) -> Result<Channel, String> {
    let width = match definition.width {
        Width::Mhz20 => channel::Width::Mhz20,
        Width::Mhz40 => channel::Width::Mhz40,
        Width::Mhz80 => channel::Width::Mhz80,
        width => return Err(format!("{width:?} on an RTL8852B")),
    };
    let primary = u8::try_from(definition.control.number).map_err(failed("channel"))?;
    Channel::new(number(definition.center1_mhz), primary, width).map_err(failed("channel"))
}

/// `ieee80211_hdrlen`'s length of the MAC header `frame` starts with.
fn header_length(frame: &[u8]) -> usize {
    let control = u16::from_le_bytes([frame[0], frame[1]]);
    let mut length = 24;
    if control & 0x0c == 0x08 {
        if control & 0x0300 == 0x0300 {
            length += 6;
        }
        if control & 0x80 != 0 {
            length += 2;
            if control & 0x8000 != 0 {
                length += 4;
            }
        }
    }
    length
}

/// Whether the data frame `frame` carries EAPOL, behind its host-made IV
/// when protected: rtw89's `PACKET_EAPOL` (`IEEE80211_TX_CTRL_PORT_CTRL_PROTO`).
fn eapol(frame: &[u8]) -> bool {
    let mut at = header_length(frame);
    if frame[1] & 0x40 != 0 {
        at += 8;
    }
    frame.get(at + 6..at + 8) == Some(&[0x88, 0x8e])
}

/// The station's TX descriptor: rtw89's `rtw89_tx_desc_info`, the TID it
/// was queued under and the TX report number its release names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub info: DescInfo,
    pub tid: u8,
    pub report: Option<u8>,
}

impl station::Descriptor for Descriptor {
    fn tid(&self) -> u8 {
        self.tid
    }
    fn aggregated(&self) -> bool {
        self.info.agg_en
    }
    fn stop_aggregating(&mut self) {
        self.info.agg_en = false;
        self.info.ampdu_density = 0;
        self.info.ampdu_num = 0;
    }
    fn protected(&self) -> bool {
        self.info.sec_en
    }
    fn resize(&mut self, size: usize) {
        self.info.pkt_size = size as u16;
    }
}

/// What an RTL8852B gives the host beside frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Report {
    /// RPQ released the frame whose TX report was to name `number`, with
    /// `status` (`rtw89_pci_tx_status`).
    Released { number: u8, status: TxStatus },
    /// The firmware's RA report for the peer (`rtw89_phy_c2h_ra_rpt`).
    Rate(RaReport),
}

/// What the station's bring-up takes beside the chip.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// The stack's country (`--wifi-country`), `None` for `"00"`.
    pub alpha2: Option<[u8; 2]>,
    /// An MSI the caller routed raises the function's causes.
    pub vector: bool,
}

/// Why the station's bring-up stopped.
#[derive(Debug)]
pub enum Error {
    /// The power-off that closes the probe, before stage 2.
    ProbePowerOff(power::Error),
    /// A stage of stage 2.
    Radio(radio::Stage, radio::Error),
    /// A step of the interface's coming up, after stage 2's start.
    Interface(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProbePowerOff(error) => write!(f, "probe power-off: {error:?}"),
            Self::Radio(stage, error) => write!(f, "{stage}: {error}"),
            Self::Interface(error) => write!(f, "interface: {error}"),
        }
    }
}

/// Why [`Hardware::start`] stopped, with everything the device may still
/// reach: the register interface with its owner, the rings and the
/// channel whose buffers they hold.
pub struct Failure<I> {
    pub error: Error,
    /// What stage 2 learned before it stopped.
    pub report: Box<radio::Report>,
    /// The closing power-off, `None` when the chip was never powered on.
    pub power_off: Option<Result<(), power::Error>>,
    pub io: I,
    pub rings: Rings,
    pub channel: H2c<'static>,
}

impl<I> fmt::Debug for Failure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failure")
            .field("error", &self.error)
            .field("power_off", &self.power_off)
            .finish_non_exhaustive()
    }
}

impl<I> fmt::Display for Failure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        match &self.power_off {
            None => Ok(()),
            Some(Ok(())) => f.write_str("; powered off"),
            Some(Err(error)) => write!(f, "; powering off failed: {error:?}"),
        }
    }
}

/// Why [`Hardware::new`] stopped.
pub enum Stopped<I> {
    /// Stage 1, with what it hands back.
    Stage1(Box<bootstrap::Failure<'static, I>>),
    /// The probe's power-off, stage 2 or the interface.
    Start(Box<Failure<I>>),
}

impl<I> fmt::Debug for Stopped<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stage1(failure) => write!(f, "Stage1({failure:?})"),
            Self::Start(failure) => write!(f, "Start({failure:?})"),
        }
    }
}

impl<I> fmt::Display for Stopped<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stage1(failure) => write!(f, "stage 1: {failure}"),
            Self::Start(failure) => write!(f, "{failure}"),
        }
    }
}

/// `DECLARE_EWMA(name, precision, weight_rcp)`: Linux's moving average.
#[derive(Clone, Copy, Debug, Default)]
struct Ewma {
    internal: u64,
}

impl Ewma {
    /// `ewma_*_add` with `precision` fractional bits and a weight of one
    /// over 2^`shift`.
    fn add(&mut self, value: u64, precision: u32, shift: u32) {
        self.internal = if self.internal == 0 {
            value << precision
        } else {
            (((self.internal << shift) - self.internal) + (value << precision)) >> shift
        };
    }

    fn read(&self, precision: u32) -> u64 {
        self.internal >> precision
    }
}

/// `rtwdev->stats` as `rtw89_traffic_stats_calc` keeps them over the
/// watchdog's two seconds: unicast data bytes and frames each way.
#[derive(Clone, Copy, Debug, Default)]
struct Traffic {
    tx_unicast: u64,
    rx_unicast: u64,
    tx_cnt: u64,
    rx_cnt: u64,
    /// `DECLARE_EWMA(tp, 10, 2)`.
    tx_tp: Ewma,
    rx_tp: Ewma,
}

/// `rtw89_get_traffic_level` over `RTW89_TFC_INTERVAL_2SEC`.
fn traffic_level(throughput: u64, cnt: u64) -> u8 {
    match throughput {
        _ if cnt < 100 => 0,
        51.. => 4,
        11.. => TFC_MID,
        3.. => 2,
        _ => 1,
    }
}

impl Traffic {
    /// `rtw89_traffic_stats_calc`: the throughputs averaged, then both
    /// levels; whether either is too busy for power save
    /// (`RTW89_TFC_MID` and up, as `rtw89_enter_lps_track` reads them).
    fn track(&mut self) -> bool {
        // rtw89_bytes_to_mbps over two seconds.
        self.tx_tp.add(self.tx_unicast >> 18, 10, 1);
        self.rx_tp.add(self.rx_unicast >> 18, 10, 1);
        let tx = traffic_level(self.tx_tp.read(10), self.tx_cnt);
        let rx = traffic_level(self.rx_tp.read(10), self.rx_cnt);
        self.tx_unicast = 0;
        self.rx_unicast = 0;
        self.tx_cnt = 0;
        self.rx_cnt = 0;
        tx >= TFC_MID || rx >= TFC_MID
    }
}

/// The peer's rate adaptation inputs as rtw89 keeps them after
/// `rtw89_phy_ra_assoc`.
#[derive(Clone, Copy, Debug)]
struct Rated {
    sta: LinkSta,
    band: Band,
    er_cap: bool,
    stbc: bool,
    ldpc: bool,
}

/// What one RXQ buffer gave `rtw89_core_rx`.
enum Arrived {
    Frame(Delivered<Vec<u8>>),
    C2h(Vec<u8>),
}

/// `rtw89_pci_rxbd_deliver_skbs` and `rtw89_core_rx` for one RXQ buffer:
/// a frame, sorted by its PPDU status, or a C2H. A buffer that is not one
/// whole packet is dropped, as rtw89 drops it.
fn sort(sorter: &mut Sorter<Vec<u8>>, received: ring::Received<'_>, out: &mut Vec<Arrived>) {
    let Ok(packet) = rxdesc::split(received.info, received.data) else {
        return;
    };
    let sorted = sorter.receive(&packet, <[u8]>::to_vec, |frame| {
        out.push(Arrived::Frame(frame));
    });
    if sorted == Sorted::C2h {
        out.push(Arrived::C2h(packet.data.to_vec()));
    }
}

/// The HE capabilities' PPE thresholds of the AP in `elements` (its
/// association response's): what `__get_sta_he_pkt_padding` reads of
/// `he_cap.ppe_thres`, all zeros when it sent none.
fn ppe_thresholds(elements: &[u8]) -> [u8; sta::HE_PPE_THRES_MAX_LEN] {
    let mut out = [0; sta::HE_PPE_THRES_MAX_LEN];
    let mut rest = elements;
    while let [id, length, tail @ ..] = rest {
        let Some((body, next)) = tail.split_at_checked(usize::from(*length)) else {
            break;
        };
        rest = next;
        // WLAN_EID_EXT_HE_CAPABILITY: the MAC and PHY capabilities, the
        // 80 MHz maps, 160's and 80+80's where the PHY names them.
        if *id != 255 || body.first() != Some(&35) || body.len() < 1 + 6 + 11 + 4 {
            continue;
        }
        let phy = &body[7..18];
        let mut at = 18 + 4;
        if phy[0] & 0x08 != 0 {
            at += 4;
        }
        if phy[0] & 0x10 != 0 {
            at += 4;
        }
        if let Some(ppe) = body.get(at..) {
            let n = ppe.len().min(out.len());
            out[..n].copy_from_slice(&ppe[..n]);
        }
        break;
    }
    out
}

/// The hardware an attached RTL8852B station runs on.
pub struct Hardware<I = NativeIo> {
    io: I,
    rings: Rings,
    h2c: H2c<'static>,
    pages: &'static dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    /// What stage 1 learned: the cut, the efuse, the firmware's streams.
    stage1: Box<Stage1>,
    /// What stage 2 learned.
    report: Box<radio::Report>,
    running: Running,
    power: radio::TxPower,
    interrupts: Interrupts,
    sorter: Sorter<Vec<u8>>,
    /// Frames the transmit path's reclaim released, reported at the next
    /// receive.
    completions: Vec<Completion>,
    /// The station's TX report number of each frame on a WD page, by its
    /// ring and sequence.
    reports: BTreeMap<(u8, u16), u8>,
    cams: cam::Info,
    link: Link,
    peer: Option<Peer>,
    rated: Option<Rated>,
    /// The security CAM entry of each of the station's logical entries.
    keys: [Option<u8>; PAIRWISE_CAM as usize + 1],
    /// The channel tuned, and its band (`chan_rcd`'s previous band).
    chan: Option<Channel>,
    band: Option<channel::Band>,
    /// `rtwdev->scanning`.
    scanning: bool,
    /// A channel tuned outside a scan waits for its RF calibration.
    calibrate: bool,
    /// `rtwdev->hal.rx_fltr`, and whether mac80211 asked for every BSS's
    /// beacons (`FIF_BCN_PRBRESP_PROMISC`).
    rx_fltr: u32,
    promiscuous: bool,
    /// `rtwsta_link->avg_rssi`: `DECLARE_EWMA(rssi, 10, 16)`.
    rssi: Ewma,
    traffic: Traffic,
    calibrations: u32,
    vector: bool,
    limitations: Vec<&'static str>,
}

impl<I: Io> Hardware<I> {
    /// Stage 1 ([`bootstrap::bring_up`]) on the claimed function, the
    /// power-off that closes rtw89's probe, then [`Self::start`].
    ///
    /// # Safety
    /// [`bootstrap::bring_up`]'s contract holds for `claim` and `config`,
    /// and the caller keeps what a [`Stopped`] hands back for the rest of
    /// the boot, or the [`Hardware`] for as long as the chip may reach its
    /// rings.
    pub unsafe fn new<C: ConfigSpace + ?Sized>(
        claim: Claim<'static, I>,
        config: &mut C,
        firmware: &dyn Provider,
        settings: &Settings,
    ) -> Result<Self, Stopped<I>> {
        let (pages, domain) = (claim.source, claim.domain.clone());
        // SAFETY: forwarded from the caller.
        let mut stage1 = unsafe { bootstrap::bring_up(claim, config, firmware, &mut ()) }
            .map_err(|failure| Stopped::Stage1(Box::new(failure)))?;
        if let Err(error) = stage1.power_off() {
            let Started {
                io, rings, channel, ..
            } = stage1;
            return Err(Stopped::Start(Box::new(Failure {
                error: Error::ProbePowerOff(error),
                report: Box::default(),
                power_off: None,
                io,
                rings,
                channel,
            })));
        }
        // SAFETY: forwarded from the caller; stage 1's power-off stopped the
        // chip's DMA.
        unsafe { Self::start(stage1, pages, domain, config, firmware, settings) }
            .map_err(Stopped::Start)
    }

    /// The interface coming up on the chip stage 1 brought up and its
    /// power-off left cold: stage 2's bring-up to `rtw89_hci_start`
    /// ([`radio::power_up`]), the data rings' WD pages from `pages` mapped
    /// into `domain`, the first drain of RXQ, the interrupts, the station
    /// link and the RX filter. A failure powers the chip off once it was
    /// powered on, as [`radio::run`] does.
    ///
    /// # Safety
    /// [`radio::run`]'s contract holds for `stage1` and `config`: the
    /// function stage 1 brought up, its rings and channel, its DMA stopped
    /// by [`Started::power_off`]; `pages` and `domain` are the claim's. The
    /// caller keeps what a [`Failure`] hands back, or the [`Hardware`], for
    /// as long as the chip may reach the rings.
    pub unsafe fn start<C: ConfigSpace + ?Sized>(
        stage1: Started<'static, I>,
        pages: &'static dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        config: &mut C,
        firmware: &dyn Provider,
        settings: &Settings,
    ) -> Result<Self, Box<Failure<I>>> {
        let Started {
            report: stage1,
            mut io,
            mut rings,
            mut channel,
            ..
        } = stage1;
        let mut report = Box::<radio::Report>::default();
        let mut powered = false;
        let mut stage = radio::Stage::Tables;
        // SAFETY: forwarded from the caller.
        let brought = unsafe {
            bring_up(
                &mut io,
                &mut rings,
                &mut channel,
                config,
                &stage1,
                firmware,
                settings,
                &mut report,
                &mut powered,
                &mut stage,
            )
        };
        let (power, running) = match brought {
            Ok(brought) => brought,
            Err(error) => {
                let power_off = powered.then(|| {
                    report.registers = radio::read_key_registers(&mut io);
                    power::power_off(&mut io, &radio::power_inputs(&stage1))
                });
                return Err(Box::new(Failure {
                    error: Error::Radio(stage, error),
                    report,
                    power_off,
                    io,
                    rings,
                    channel,
                }));
            }
        };
        let mut hardware = Self {
            io,
            rings,
            h2c: channel,
            pages,
            domain,
            report,
            running,
            power,
            interrupts: Interrupts::new(settings.vector),
            sorter: Sorter::new(0, rxdesc::NL80211_BAND_2GHZ),
            completions: Vec::new(),
            reports: BTreeMap::new(),
            cams: cam::Info::default(),
            link: Link::station(MAC_ID, PORT, stage1.info.efuse.addr, stage1.info.hal.tx_nss),
            peer: None,
            rated: None,
            keys: [None; PAIRWISE_CAM as usize + 1],
            chan: None,
            band: None,
            scanning: false,
            calibrate: false,
            rx_fltr: DEFAULT_AX_RX_FLTR,
            promiscuous: false,
            rssi: Ewma::default(),
            traffic: Traffic::default(),
            calibrations: 0,
            vector: settings.vector,
            limitations: Vec::new(),
            stage1: Box::new(stage1),
        };
        if let Err(error) = hardware.interface_up() {
            let power_off =
                power::power_off(&mut hardware.io, &radio::power_inputs(&hardware.stage1));
            let Self {
                io,
                rings,
                h2c,
                report,
                ..
            } = hardware;
            return Err(Box::new(Failure {
                error: Error::Interface(error),
                report,
                power_off: Some(power_off),
                io,
                rings,
                channel: h2c,
            }));
        }
        Ok(hardware)
    }

    /// The rest of `rtw89_core_start` and `rtw89_ops_add_interface`: the WD
    /// pages (`rtw89_pci_alloc_tx_wd_ring`, at probe in rtw89), RXQ drained
    /// of the H2C acks, the interrupts on (`rtw89_pci_ops_start`), the
    /// station link (`rtw89_mac_vif_init`), and mac80211's first
    /// `configure_filter` with no flag set.
    fn interface_up(&mut self) -> Result<(), String> {
        self.rings
            .alloc_tx_wd(self.pages, self.domain.clone())
            .map_err(failed("WD pages"))?;
        let mut taken = 0;
        while taken < DRAIN_LIMIT {
            let got = self
                .rings
                .deliver(&mut self.io, RxChannel::Rxq, 64, |_| {})
                .map_err(failed("drain"))?;
            if got == 0 {
                break;
            }
            taken += got;
        }
        self.interrupts
            .enable(&mut self.io)
            .map_err(failed("interrupts"))?;
        let Self {
            io,
            rings,
            h2c,
            cams,
            link,
            ..
        } = self;
        sta::vif_init(
            io,
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
            cams,
            link,
        )
        .map_err(failed("interface"))?;
        self.configure_filter()
    }

    /// The station's address, the efuse's.
    pub fn address(&self) -> Mac {
        Mac(self.stage1.info.efuse.addr)
    }

    /// What stage 1 learned.
    pub fn stage1(&self) -> &Stage1 {
        &self.stage1
    }

    /// What stage 2 learned as it brought the radio up.
    pub fn report(&self) -> &radio::Report {
        &self.report
    }

    /// How many RF calibrations ran since the radio came up.
    pub fn calibrations(&self) -> u32 {
        self.calibrations
    }

    /// `rtw89_core_stop`'s end for a caller that stops the station: the
    /// interrupts off and the chip powered off (`rtw89_mac_pwr_off`). The
    /// rings stay held: the DMA may have read them until now.
    pub fn power_off(&mut self) -> Result<(), String> {
        self.interrupts
            .disable(&mut self.io)
            .map_err(failed("interrupts"))?;
        power::power_off(&mut self.io, &radio::power_inputs(&self.stage1))
            .map_err(failed("power off"))
    }

    /// `rtw89_ops_configure_filter` for the flags a station's mac80211 sets:
    /// `FIF_BCN_PRBRESP_PROMISC` while it asks for every BSS's beacons, no
    /// `FIF_PROBE_REQ`, `FIF_OTHER_BSS`, `FIF_ALLMULTI` or `FIF_FCSFAIL`;
    /// while scanning the beacon, broadcast and A1 checks stay off.
    fn configure_filter(&mut self) -> Result<(), String> {
        let checks = A_BCN_CHK_EN | A_BC | A_A1_MATCH;
        if self.promiscuous {
            self.rx_fltr &= !checks;
        } else {
            self.rx_fltr |= checks;
        }
        self.rx_fltr |= A_BC_CAM_MATCH | A_UC_CAM_MATCH;
        let mut rx_fltr = self.rx_fltr;
        if self.scanning {
            rx_fltr &= !checks;
        }
        radio::set_rx_fltr(&mut self.io, rx_fltr)
            .map(|_| ())
            .map_err(failed("RX filter"))
    }

    /// The seam where the radio's tracking runs in `rtw89_track_work`, after
    /// the traffic statistics and outside a scan, before the RA update, in
    /// rtw89's order: the environment monitor and DIG (`rtw89_phy_dig`),
    /// the chip's RF tracking (`rtw89_core_rfk_track`, `rtw8852b_dpk_track`),
    /// then CFO tracking (`rtw89_phy_cfo_track`). Their steps are ported
    /// apart (`ax/dynamic.rs` and `rtw8852b/rfk/dpk.rs`), and nothing runs
    /// here until they are wired in; [`Hardware::scanning`]'s end is where
    /// rtw89 sets DIG's bypass, and [`Traffic`] holds the statistics they
    /// read.
    fn track(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// What rtw89 keeps of its own side of the link for the RA.
    fn ra_link(&self, rated: &Rated) -> ra::Link {
        ra::Link {
            band: rated.band,
            mac_id: self.link.mac_id,
            er_cap: rated.er_cap,
            rssi: self.rssi.read(10) as u8,
            tx_nss: self.stage1.info.hal.tx_nss,
        }
    }

    /// `rtw89_fw_h2c_ra` of `ra`.
    fn send_ra(&mut self, ra: &Ra) -> Result<(), String> {
        let Self { io, rings, h2c, .. } = self;
        ra.send(
            io,
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
        )
        .map_err(failed("RA"))
    }

    /// The peer `context` names on a link `width` wide, as mac80211 keeps
    /// its `ieee80211_link_sta`.
    fn rated(&self, context: &AssociationContext, width: Width) -> Rated {
        let negotiated = context.negotiated();
        let mut sta = LinkSta::from_negotiated(negotiated);
        sta.bandwidth = match width {
            Width::Mhz20 => StaBandwidth::Mhz20,
            Width::Mhz40 => StaBandwidth::Mhz40,
            Width::Mhz80 => StaBandwidth::Mhz80,
            _ => StaBandwidth::Mhz160,
        };
        let he_support = negotiated.he.is_some() && negotiated.mode >= Mode::He;
        let parameters = context
            .operations()
            .he
            .as_ref()
            .map_or(0, |he| he.parameters);
        let band = context.channel().band;
        let er_cap = ra::can_er(he_support, parameters);
        let link = ra::Link {
            band,
            mac_id: self.link.mac_id,
            er_cap,
            rssi: self.rssi.read(10) as u8,
            tx_nss: self.stage1.info.hal.tx_nss,
        };
        let info = ra::RaInfo::sta_update(&sta, &link, false);
        Rated {
            sta,
            band,
            er_cap,
            stbc: info.stbc_cap,
            ldpc: info.ldpc_cap,
        }
    }
}

/// [`Hardware::start`]'s stage 2 up to `rtw89_hci_start`: the tables read
/// from the image staged again, then [`radio::power_up`], each stage
/// recorded in `stage` as it begins.
///
/// # Safety
/// [`Hardware::start`]'s contract.
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
    settings: &Settings,
    report: &mut radio::Report,
    powered: &mut bool,
    stage: &mut radio::Stage,
) -> Result<(radio::TxPower, Running), radio::Error> {
    let board = Board::rtl8852b(stage1.info.efuse.rfe_type, stage1.version.cut);
    *stage = radio::Stage::Tables;
    let staged = stage1
        .profile
        .stage(firmware)
        .map_err(radio::Error::Firmware)?;
    let Layout::Rtw89(suit) = &staged.layout else {
        return Err(radio::Error::NotRtl8852b(stage1.profile.chip()));
    };
    let elements = Elements::recognize(suit, board).map_err(radio::Error::Elements)?;
    let tables = Tables::from_elements(&elements).map_err(radio::Error::PhyTable)?;
    let power = radio::TxPower::load(&elements, &stage1.info, settings.alpha2.unwrap_or(*b"00"))?;
    report.regulated = Some(radio::Regulated {
        alpha2: power.regulation.regd().alpha2,
        programmed: power.regulation.programmed,
        cap: Cap::NONE,
        country_cap: false,
    });
    // SAFETY: the caller's contract.
    let running = unsafe {
        radio::power_up(
            io,
            rings,
            h2c,
            config,
            stage1,
            suit,
            &tables,
            report,
            powered,
            &mut |next| *stage = next,
        )
    }?;
    Ok((power, running))
}

impl<I: Io> Device for Hardware<I> {
    type Descriptor = Descriptor;
    type Report = Report;
    const MAX_FRAME: usize = MAX_FRAME;
    const DRIVER: &'static str = "rtw89";
    const CHIP: &'static str = "RTL8852B";
    const CHANNELS_5GHZ: &'static [u16] = &CHANNELS_5GHZ;
    /// RTL8852B's `hw_tkip_crypto` is false: rtw89 refuses TKIP keys.
    const TKIP_GROUP: bool = false;

    /// `rtw89_init_ht_cap`, `rtw89_init_vht_cap` and `rtw89_init_he_cap` as
    /// mac80211 sends them, without the beamformee bits
    /// `rtw89_mac_bf_assoc` would serve.
    fn advertisement(&self, band: Band) -> (Vec<u8>, [McsMaps; 3]) {
        let chip = Chip::from_hal(&self.stage1.info.hal, self.stage1.version.cut);
        let mut elements = capabilities::capability_elements(&chip, band);
        let mut at = 0;
        while at + 2 <= elements.len() {
            let (id, length) = (elements[at], usize::from(elements[at + 1]));
            let body = at + 2;
            if id == 191 && length >= 4 {
                let mut cap = u32::from_le_bytes(elements[body..body + 4].try_into().unwrap());
                cap &= !VHT_BEAMFORMEE;
                elements[body..body + 4].copy_from_slice(&cap.to_le_bytes());
            }
            if id == 255 && length >= 1 + 6 + 11 && elements[body] == 35 {
                elements[body + 1 + 6 + 4] &= !HE_PHY_CAP4_BEAMFORMEE;
            }
            at = body + length;
        }
        (elements, capabilities::he_source_maps(&chip))
    }

    /// `rtw89_core_tx_update_mgmt_info`: B0MGQ, the hardware's sequence
    /// number, a fixed rate without fallback at the lowest basic rate
    /// (`rtw89_core_get_mgmt_rate`), and no hardware encryption, as
    /// `hw_mgmt_tx_encrypt` is false.
    fn management(&self, frame: &Management<'_>) -> Descriptor {
        let lowest = if frame.band == Band::Ghz2 {
            HW_RATE_CCK1
        } else {
            HW_RATE_OFDM6
        };
        let rate = frame
            .basic
            .filter(|&basic| basic != 0)
            .map_or(lowest, |basic| lowest + basic.trailing_zeros() as u16);
        Descriptor {
            info: self.management_info(frame.mpdu, rate),
            tid: 0,
            report: frame.report,
        }
    }

    /// `rtw89_core_tx_update_data_info`, `rtw89_core_tx_update_sec_key`,
    /// `rtw89_core_tx_update_ampdu_info` and `rtw89_core_tx_update_llc_hdr`.
    fn data(&self, frame: &Data<'_>) -> Descriptor {
        let mpdu = frame.mpdu;
        let negotiated = frame.context.negotiated();
        let tid = frame.tid.unwrap_or(0);
        let qsel = txwd::qsel(tid);
        let lowest = if frame.context.channel().band == Band::Ghz2 {
            HW_RATE_CCK1
        } else {
            HW_RATE_OFDM6
        };
        let supported = negotiated.legacy.supported;
        let rated = self.rated;
        let mut info = DescInfo {
            pkt_size: mpdu.len() as u16,
            mac_id: self.link.mac_id,
            qsel,
            ch_dma: txwd::ch_dma(qsel),
            tid_indicate: txwd::tid_indicate(tid),
            is_bmc: mpdu[4] & 1 != 0,
            en_wd_info: true,
            wd_page: true,
            seq: u16::from_le_bytes([mpdu[22], mpdu[23]]) >> 4,
            port: 0,
            stbc: rated.is_some_and(|rated| rated.stbc),
            ldpc: rated.is_some_and(|rated| rated.ldpc),
            data_retry_lowest_rate: if supported == 0 {
                lowest
            } else {
                lowest + supported.trailing_zeros() as u16
            },
            hdr_llc_len: (header_length(mpdu) >> 1) as u8,
            ..DescInfo::default()
        };
        if frame.protected
            && let Some(sec_cam_idx) = self.keys[usize::from(PAIRWISE_CAM)]
        {
            info.sec_en = true;
            info.sec_type = cam::SEC_KEY_TYPE_CCMP128;
            info.sec_cam_idx = sec_cam_idx;
        }
        if eapol(mpdu) {
            info.bk = true;
        } else if frame.aggregate
            && let Some(ht) = &negotiated.ht
        {
            info.agg_en = true;
            info.ampdu_density = ht.peer_mpdu_spacing;
            info.ampdu_num = ((4u16 << ht.peer_ampdu_base_exponent.min(3)) - 1) as u8;
        }
        Descriptor {
            info,
            tid,
            report: None,
        }
    }

    /// A nullfunc is management to rtw89 (`ieee80211_is_any_nullfunc`):
    /// B0MGQ, the hardware's sequence number, the lowest basic rate.
    fn null(&self, frame: &Data<'_>, report: u8) -> Descriptor {
        let context = frame.context;
        let lowest = if context.channel().band == Band::Ghz2 {
            HW_RATE_CCK1
        } else {
            HW_RATE_OFDM6
        };
        let basic = context.negotiated().legacy.basic;
        let rate = if basic == 0 {
            lowest
        } else {
            lowest + basic.trailing_zeros() as u16
        };
        Descriptor {
            info: self.management_info(frame.mpdu, rate),
            tid: 7,
            report: Some(report),
        }
    }

    /// `rtw89_pci_tx_status`'s ACK, and `rtw89_phy_c2h_ra_rpt`'s
    /// `max_rc_amsdu_len`; the report names its own width.
    fn reported(&self, report: &Report, _width: Width) -> Option<Reported> {
        match *report {
            Report::Released { number, status } => Some(Reported::Transmitted {
                number,
                acknowledged: status.acked(),
            }),
            Report::Rate(rate) => Some(Reported::Amsdu(rate.max_amsdu_len())),
        }
    }

    /// `rtw89_station_mode_sta_assoc` for the AP `context` names: the
    /// link's BSS, the peer, `rtw89_core_sta_link_assoc`'s CMAC table,
    /// join info and address CAM, `rtw89_phy_ra_assoc`'s RA, then
    /// `__rtw89_ops_bss_link_assoc`'s port update with the AID and the
    /// beacons' interval and DTIM period.
    fn joined(
        &mut self,
        _local: Mac,
        context: &AssociationContext,
        width: Width,
    ) -> Result<(), String> {
        let negotiated = context.negotiated();
        let he_support = negotiated.he.is_some() && negotiated.mode >= Mode::He;
        let he_operation = context.operations().he.as_ref();
        let band = context.channel().band;
        self.link.bss = Bss {
            aid: context.response().aid,
            beacon_int: context.beacon().beacon_interval,
            dtim_period: context.dtim_period(),
            bss_color: he_operation.map_or(0, |he| he.color()),
            he_support,
            two_ghz: band == Band::Ghz2,
        };
        let peer = Peer {
            addr: context.bssid().0,
            rx_nss: negotiated.tx_nss.max(1),
            he: negotiated
                .he
                .as_ref()
                .filter(|_| he_support)
                .map(|he| HeCap {
                    phy_cap_info: he.phy,
                    ppe_thres: ppe_thresholds(&context.response().elements),
                }),
        };
        let rated = self.rated(context, width);
        {
            let Self {
                io,
                rings,
                h2c,
                link,
                ..
            } = self;
            sta::sta_assoc(
                io,
                &mut Fwcmd {
                    channel: h2c,
                    rings,
                },
                link,
                &peer,
            )
            .map_err(failed("association"))?;
        }
        self.peer = Some(peer);
        let ra = Ra::assoc(&rated.sta, &self.ra_link(&rated));
        self.send_ra(&ra)?;
        self.rated = Some(rated);
        sta::bss_assoc(&mut self.io, &self.link).map_err(failed("port"))
    }

    /// `rtw89_core_sta_link_disconnect`, then `BSS_CHANGED_BSSID` to none.
    fn left(&mut self) -> Result<(), String> {
        let peer = self.peer.take();
        self.rated = None;
        self.rssi = Ewma::default();
        let Self {
            io,
            rings,
            h2c,
            link,
            ..
        } = self;
        let mut commands = Fwcmd {
            channel: h2c,
            rings,
        };
        if let Some(peer) = peer {
            sta::sta_disconnect(io, &mut commands, link, &peer).map_err(failed("disconnect"))?;
        }
        link.bss = Bss::default();
        sta::bssid_changed(io, &mut commands, link, [0; 6]).map_err(failed("BSSID"))
    }

    /// `rtw89_phy_ra_update_sta_link` of a peer whose width or streams
    /// changed, or whose mask starts over.
    fn refresh_rates(
        &mut self,
        context: &AssociationContext,
        width: Width,
        _level: u8,
        reset: bool,
    ) -> Result<(), String> {
        let rated = self.rated(context, width);
        let changed = self.rated.is_none_or(|old| old.sta != rated.sta);
        self.rated = Some(rated);
        if !(changed || reset) {
            return Ok(());
        }
        let ra = Ra::update(
            &rated.sta,
            &self.ra_link(&rated),
            RC_SUPP_RATES_CHANGED | RC_BW_CHANGED | RC_NSS_CHANGED,
        );
        self.send_ra(&ra)
    }

    /// `__rtw89_set_channel` under `eirp_mbm`, and the band's notices.
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String> {
        let chan = chan_of(definition)?;
        let txchan = chan.txpower();
        if !self.power.regulation.permits(&txchan) {
            return Err(format!(
                "the regulation disables channel {} (UNII-4)",
                chan.primary()
            ));
        }
        let Self {
            io,
            running,
            power,
            stage1,
            band,
            ..
        } = self;
        let Running {
            mailbox,
            state,
            inputs,
        } = running;
        let txpwr = Power {
            tables: &power.tables,
            regulation: &power.regulation,
            cap: Cap::eirp(eirp_mbm),
        };
        let switched = channel::switch(io, Some(mailbox), &chan, inputs, *band, |io, _| {
            rtw8852b_txpower::set_txpwr(io, &txpwr, &txchan)
        })
        .map_err(failed("channel"))?;
        *band = Some(chan.band());
        if switched.band_notice {
            // rtw89_btc_ntfy_switch_band: coex runs WL-only.
            let tssi = tssi::Inputs {
                efuse: &stage1.info.tssi,
                deltas: &power.deltas,
                gain: inputs,
            };
            rfk::band_changed(io, state, chan.rfk(), &tssi).map_err(failed("band change"))?;
        }
        self.chan = Some(chan);
        self.calibrate |= !scanning;
        Ok(())
    }

    /// `rtw8852b_rfk_channel` on a channel tuned outside a scan, before its
    /// first frame.
    fn prepare_transmit(&mut self) -> Result<(), String> {
        if !core::mem::take(&mut self.calibrate) {
            return Ok(());
        }
        let Some(chan) = self.chan else {
            return Ok(());
        };
        let Self {
            io,
            rings,
            h2c,
            running,
            power,
            stage1,
            ..
        } = self;
        let Running {
            mailbox,
            state,
            inputs,
        } = running;
        let tssi = tssi::Inputs {
            efuse: &stage1.info.tssi,
            deltas: &power.deltas,
            gain: inputs,
        };
        rfk::channel(
            io,
            &mut MacScheduler {
                firmware: Some(mailbox),
            },
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
            state,
            chan.rfk(),
            &ChannelInputs {
                tssi,
                dpk: dpk::Inputs {
                    epa_2g: false,
                    epa_5g: false,
                    cv: stage1.version.cut,
                },
            },
        )
        .map_err(failed("calibration"))?;
        self.calibrations += 1;
        Ok(())
    }

    /// `rtw89_core_tx_write` and its kick: room on the ring
    /// (`rtw89_pci_check_and_reclaim_tx_resource`), the frame behind a WD
    /// page, the ring kicked.
    fn transmit(
        &mut self,
        _queue: Queue,
        descriptor: &Descriptor,
        mpdu: &[u8],
    ) -> Result<bool, String> {
        let length = u16::try_from(mpdu.len())
            .ok()
            .filter(|&length| usize::from(length) <= MAX_FRAME && length > 0)
            .ok_or_else(|| format!("a frame of {} bytes", mpdu.len()))?;
        let mut info = descriptor.info;
        info.pkt_size = length;
        let txch = TxChannel::ALL
            .get(usize::from(info.ch_dma))
            .copied()
            .ok_or_else(|| format!("DMA channel {}", info.ch_dma))?;
        let Self {
            io,
            rings,
            completions,
            pages,
            domain,
            reports,
            traffic,
            ..
        } = self;
        let room = rings
            .check_and_reclaim_tx_resource(io, txch, |completion| completions.push(completion))
            .map_err(failed("transmit reclaim"))?;
        if room == 0 {
            return Ok(false);
        }
        let buffer = Buffer::new(*pages, domain.clone(), mpdu.len(), Direction::ToDevice)
            .map_err(failed("transmit buffer"))?;
        buffer.write(0, mpdu).map_err(failed("transmit buffer"))?;
        let seq = match rings.tx_write(&info, buffer, length) {
            Ok(seq) => seq,
            Err(ring::Error::NoTxBd | ring::Error::NoTxWd) => return Ok(false),
            Err(error) => return Err(format!("transmit: {error:?}")),
        };
        let key = (txch as u8, seq);
        match descriptor.report {
            Some(number) => {
                reports.insert(key, number);
            }
            None => {
                reports.remove(&key);
            }
        }
        rings
            .tx_kick_off(io, txch)
            .map_err(failed("transmit kick"))?;
        if mpdu[0] & 0x0c == 0x08 && !info.is_bmc {
            traffic.tx_unicast += u64::from(length);
            traffic.tx_cnt += 1;
        }
        Ok(true)
    }

    /// One look ([`Interrupts::look`]): RPQ's releases, then RXQ's frames
    /// and C2H through `rtw89_core_rx`.
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming<Report>)) -> Result<(), String> {
        let mut completions = core::mem::take(&mut self.completions);
        let mut arrived = Vec::new();
        {
            let Self {
                io,
                rings,
                interrupts,
                sorter,
                ..
            } = self;
            let lengths = [
                rings.rx_ring(RxChannel::Rxq).len,
                rings.rx_ring(RxChannel::Rpq).len,
            ];
            for _ in 0..LOOKS {
                let look = interrupts
                    .look(io, lengths, |io, rxch, budget| match rxch {
                        RxChannel::Rpq => {
                            rings.poll_rpq(io, |completion| completions.push(completion))
                        }
                        RxChannel::Rxq => rings.deliver(io, RxChannel::Rxq, budget, |received| {
                            sort(sorter, received, &mut arrived)
                        }),
                    })
                    .map_err(failed("receive"))?;
                if !look.more {
                    break;
                }
            }
        }
        for completion in completions {
            if let Some(number) = self
                .reports
                .remove(&(completion.txch as u8, completion.seq))
            {
                sink(Incoming::Report(Report::Released {
                    number,
                    status: completion.status,
                }));
            }
        }
        for item in arrived {
            match item {
                Arrived::Frame(frame) => {
                    if let Some(received) = self.frame(frame) {
                        sink(Incoming::Frame(received));
                    }
                }
                Arrived::C2h(bytes) => {
                    if let Some(report) = self.c2h(&bytes) {
                        sink(Incoming::Report(report));
                    }
                }
            }
        }
        Ok(())
    }

    /// `BSS_CHANGED_BSSID` when the BSSID changes; a linked port is
    /// `__rtw89_ops_bss_link_assoc`'s update, which [`Device::joined`]
    /// makes.
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String> {
        if bssid.0 != self.link.bssid {
            let Self {
                io,
                rings,
                h2c,
                link,
                ..
            } = self;
            sta::bssid_changed(
                io,
                &mut Fwcmd {
                    channel: h2c,
                    rings,
                },
                link,
                bssid.0,
            )
            .map_err(failed("BSSID"))?;
        }
        if linked {
            self.link.bss.aid = aid;
            sta::bss_assoc(&mut self.io, &self.link).map_err(failed("port"))?;
        }
        Ok(())
    }

    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String> {
        self.promiscuous = !own_only;
        self.configure_filter()
    }

    /// `__rtw89_conf_tx`'s `____rtw89_conf_tx_edca` for each access
    /// category, in mac80211's order: `rtw89_aifsn_to_aifs` and
    /// `rtw89_fw_h2c_set_edca`.
    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String> {
        let slot = if short_slot { 9 } else { 20 };
        let sifs = match self.chan.map(|chan| chan.band()) {
            Some(channel::Band::Ghz2) => 10,
            _ => 16,
        };
        let Self {
            io,
            rings,
            h2c,
            link,
            ..
        } = self;
        let mut commands = Fwcmd {
            channel: h2c,
            rings,
        };
        for aci in CONF_TX_ORDER {
            let category = &edca[aci];
            let aifs = u32::from(category.aifsn) * slot + sifs;
            let value = prep(category.txop_32us.into(), EDCA_PARAM_TXOPLMT)
                | prep(category.ecw_max.into(), EDCA_PARAM_CWMAX)
                | prep(category.ecw_min.into(), EDCA_PARAM_CWMIN)
                | prep(aifs & 0xff, EDCA_PARAM_AIFS);
            let mut payload = [0; H2C_EDCA_LEN];
            let w0 = u32::from(link.mac_idx & 1) << 3 | (aci as u32 & 3) << 5;
            payload[..4].copy_from_slice(&w0.to_le_bytes());
            payload[4..8].copy_from_slice(&value.to_le_bytes());
            commands
                .send(
                    io,
                    H2C_CL_MAC_FW_OFLD,
                    H2C_FUNC_USR_EDCA,
                    false,
                    true,
                    &payload,
                )
                .map_err(failed("EDCA"))?;
        }
        Ok(())
    }

    /// `rtw89_cam_sec_key_add`: a CCMP-128 key in the security CAM and the
    /// link's address CAM entry; a key replacing one under the same entry
    /// goes in first, then the old one leaves.
    fn write_key(&mut self, key: &KeyEntry<'_>) -> Result<(), String> {
        let entry = usize::from(key.entry);
        if entry >= self.keys.len() {
            return Err(format!("key entry {entry}"));
        }
        let cipher = match key.cipher {
            Cipher::Ccmp128 => CamCipher::Ccmp128,
            Cipher::Tkip => CamCipher::Tkip,
            _ => CamCipher::Other,
        };
        let pairwise = !key.group;
        let peer = self.peer.unwrap_or(Peer {
            addr: key.peer.0,
            rx_nss: 1,
            he: None,
        });
        let Self {
            io,
            rings,
            h2c,
            cams,
            link,
            keys,
            ..
        } = self;
        let mut commands = Fwcmd {
            channel: h2c,
            rings,
        };
        let index = cam::write_key(
            io,
            &mut commands,
            cams,
            link,
            pairwise.then_some(&peer),
            &Key {
                cipher,
                pairwise,
                keyidx: key.index,
                material: key.material,
            },
        )
        .map_err(failed("key"))?;
        if let Some(old) = keys[entry].replace(index) {
            cam::clear_key(
                io,
                &mut commands,
                cams,
                link,
                pairwise.then_some(&peer),
                old,
            )
            .map_err(failed("key"))?;
        }
        Ok(())
    }

    /// `rtw89_cam_sec_key_del` with the firmware told.
    fn clear_key(&mut self, entry: u8) -> Result<(), String> {
        let Some(index) = self.keys.get_mut(usize::from(entry)).and_then(Option::take) else {
            return Ok(());
        };
        let pairwise = entry == PAIRWISE_CAM;
        let peer = self.peer;
        let Self {
            io,
            rings,
            h2c,
            cams,
            link,
            ..
        } = self;
        cam::clear_key(
            io,
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
            cams,
            link,
            peer.as_ref().filter(|_| pairwise),
            index,
        )
        .map_err(failed("key"))
    }

    fn set_power_save(&mut self, on: bool) -> Result<(), String> {
        if on && !self.limitations.contains(&NO_POWER_SAVE) {
            self.limitations.push(NO_POWER_SAVE);
        }
        Ok(())
    }

    /// `rtw89_track_work`'s subset: the traffic statistics, then outside a
    /// scan [`Hardware::track`] and `rtw89_phy_ra_update`.
    fn watchdog(&mut self, scanning: bool, _stbc: bool) -> Result<Watched, String> {
        let busy = self.traffic.track();
        if scanning {
            return Ok(Watched { level: 0, busy });
        }
        self.track()?;
        if let Some(rated) = self.rated {
            let ra = Ra::update(&rated.sta, &self.ra_link(&rated), RC_SUPP_RATES_CHANGED);
            self.send_ra(&ra)?;
        }
        Ok(Watched { level: 0, busy })
    }

    /// `rtw89_core_scan_start` and `rtw89_core_scan_complete` of a software
    /// scan.
    fn scanning(&mut self, scanning: bool) -> Result<(), String> {
        self.scanning = scanning;
        let address = scanning.then_some(self.link.mac_addr);
        if !scanning {
            self.send_addr_cam(address)?;
        }
        if let Some(chan) = self.chan {
            let Self {
                io,
                running,
                power,
                stage1,
                ..
            } = self;
            let Running {
                mailbox,
                state,
                inputs,
            } = running;
            let tssi = tssi::Inputs {
                efuse: &stage1.info.tssi,
                deltas: &power.deltas,
                gain: inputs,
            };
            rfk::scan(
                io,
                &mut MacScheduler {
                    firmware: Some(mailbox),
                },
                state,
                scanning,
                chan.rfk(),
                &tssi,
            )
            .map_err(failed("scan notice"))?;
        }
        if scanning {
            self.send_addr_cam(address)?;
        }
        Ok(())
    }

    fn signals(&self) -> bool {
        self.vector
    }

    fn limitation(&mut self) -> Option<&'static str> {
        self.limitations.pop()
    }
}

impl<I: Io> Hardware<I> {
    /// `rtw89_core_tx_update_mgmt_info` over `rtw89_core_tx_update_desc_info`
    /// for `mpdu` at `rate`.
    fn management_info(&self, mpdu: &[u8], rate: u16) -> DescInfo {
        DescInfo {
            pkt_size: mpdu.len() as u16,
            mac_id: self.link.mac_id,
            qsel: txwd::QSEL_B0_MGMT,
            ch_dma: txwd::ch_dma(txwd::QSEL_B0_MGMT),
            is_bmc: mpdu[4] & 1 != 0,
            en_wd_info: true,
            wd_page: true,
            use_rate: true,
            dis_data_fb: true,
            data_rate: rate,
            seq: u16::from_le_bytes([mpdu[22], mpdu[23]]) >> 4,
            hw_ssn_sel: txwd::MGMT_HW_SSN_SEL,
            hw_seq_mode: txwd::MGMT_HW_SEQ_MODE,
            port: 0,
            ..DescInfo::default()
        }
    }

    /// `rtw89_fw_h2c_cam` of the link with `scan_mac_addr` as its address,
    /// as a scan starts and ends.
    fn send_addr_cam(&mut self, scan_mac_addr: Option<[u8; 6]>) -> Result<(), String> {
        let Self {
            io,
            rings,
            h2c,
            link,
            ..
        } = self;
        cam::send_addr_cam(
            io,
            &mut Fwcmd {
                channel: h2c,
                rings,
            },
            link,
            None,
            scan_mac_addr,
            UpdMode::InfoChange,
        )
        .map_err(failed("address CAM"))
    }

    /// `rtw89_core_rx_to_mac80211` of one frame: a frame that failed its CRC
    /// is dropped, the FCS cut, the signal its PPDU status gave. The peer's
    /// average RSSI and the traffic statistics count it.
    fn frame(&mut self, frame: Delivered<Vec<u8>>) -> Option<Received> {
        let Delivered {
            status,
            desc,
            ppdu,
            frame: bytes,
        } = frame;
        if desc.crc32_err {
            return None;
        }
        let length = bytes.len().checked_sub(FCS_LEN).filter(|&n| n >= 10)?;
        if let (Some(ppdu), Some(peer)) = (ppdu, &self.peer)
            && ppdu.to_self
            && bytes[10..16] == peer.addr
        {
            self.rssi.add(ppdu.rssi_avg.into(), 10, 4);
        }
        if bytes[0] & 0x0c == 0x08 && bytes[4..10] == self.link.mac_addr {
            self.traffic.rx_unicast += length as u64;
            self.traffic.rx_cnt += 1;
        }
        Some(Received {
            bytes: bytes[..length].to_vec(),
            tsf: desc.free_run_cnt,
            decrypted: status.decrypted,
            icv_error: desc.icv_err,
            signal_dbm: (status.signal != 0).then_some(status.signal),
        })
    }

    /// `rtw89_fw_c2h_cmd_handle` of what the station acts on: the RA report
    /// of the peer's MAC ID once associated.
    fn c2h(&self, bytes: &[u8]) -> Option<Report> {
        let c2h = C2h::parse(bytes).ok()?;
        let rpt = c2h.ra_report()?.ok()?;
        if rpt.mac_id != self.link.mac_id || self.peer.is_none() {
            return None;
        }
        RaReport::parse(&rpt).map(Report::Rate)
    }
}

/// `rtw89_channels_5ghz`'s numbers.
const CHANNELS_5GHZ: [u16; capabilities::CHANNELS_5GHZ.len()] = {
    let mut out = [0; capabilities::CHANNELS_5GHZ.len()];
    let mut index = 0;
    while index < out.len() {
        out[index] = capabilities::CHANNELS_5GHZ[index].number;
        index += 1;
    }
    out
};

#[cfg(test)]
mod tests;
