// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! A Realtek softMAC chip as the connection keeper's radio. rtw88 and rtw89
//! leave the MAC to mac80211, so what firmware does on other NICs happens here:
//! a scan hops the channels as `ieee80211_scan_work` does, frames carry a
//! host-made IV as `IEEE80211_KEY_FLAG_GENERATE_IV` asks, `Reorder` holds a
//! Block Ack agreement's frames, robust management frames are sealed in
//! software as `IEEE80211_KEY_FLAG_SW_MGMT_TX` asks, and the frames of a TKIP
//! group key the chip refuses are decrypted in software, as mac80211 falls
//! back to when `set_key` returns `-EOPNOTSUPP`. [`Device`] is the hardware
//! beneath it, which names its own descriptor, reports and association
//! commands; rtw88's are in [`super::rtw88`].
use super::ccmp;
use crate::wifi::security::{
    aggregate::{OrderedGroup, Shape},
    michael,
};
use crate::wifi::station::fragments::Fragments;
use crate::{
    Clock, Link, LinkError, Mac,
    wifi::{
        Band, Channel, RadioStatus, RawRate, Timestamp,
        connection::keeper::{self, Advertisement, Keeper, Peer, Radio, Stage},
        frame::Mpdu,
        mediatek::reorder::Reorder,
        network::Network,
        regulatory::{
            channel::{DISABLED, NO_IR},
            database::Country,
        },
        scan::{self, Outcome, Retirement, Scanner, result::Bss},
        security::{
            self, Cipher, InstallOutcome, Integrity, KeyIdentity, KeyScope, KeySlot, PacketNumber,
            ReplaySeed, SecurityStatus,
            management::{self as protection, BipKey, ManagementCipher},
            tx::TransmitSeed,
        },
        station::{
            Action, AssociationContext, Completion, Join, NativeBssObservation, Phase as Peering,
            RegulatoryPolicy, Station, Ticket,
            ba::{self, tx},
            data::{self, Ingress, Protection, Qos, SequenceOwner, TxClass, amsdu},
            external,
            multi_link::Affiliation,
            operations::ChannelDefinition,
            phy::{AccessCategory, Capabilities, McsMaps, Role, Width},
            wire::six_ghz::Selection,
        },
    },
};
use alloc::{boxed::Box, collections::VecDeque, format, string::String, sync::Arc, vec::Vec};
use core::fmt;
use stela_driver_base::entropy::Entropy;
use zeroize::Zeroizing;

/// `IEEE80211_CHANNEL_TIME` and `IEEE80211_PASSIVE_CHANNEL_TIME`.
const ACTIVE_DWELL_US: u64 = 30_000;
const PASSIVE_DWELL_US: u64 = 111_000;
/// How long an interrupt-driven station may sleep past its timers, which are
/// reorder releases, retries and the keeper's own.
const TIMER_TICK_US: u64 = 100_000;
/// `RTW_WATCH_DOG_DELAY_TIME`.
const WATCHDOG_US: u64 = 2_000_000;
/// `IEEE80211_SCAN_RESULT_EXPIRE`.
const BSS_EXPIRY_US: u64 = 30_000_000;
/// `RTW_SEC_DEFAULT_KEY_NUM`: group keys sit at their index, pairwise ones after.
/// A [`KeyEntry`]'s entry is this logical number, which each chip maps.
pub const PAIRWISE_CAM: u8 = 4;
/// `WLAN_HT_SMPS_CONTROL_DISABLED` and `WLAN_HT_SMPS_CONTROL_STATIC`.
const SMPS_DISABLED: u8 = 0;
const SMPS_STATIC: u8 = 1;
/// `IEEE80211_MIN_AMPDU_BUF`'s window, which `HT_RX_REORDER_BUF_TIMEOUT` serves.
const RECEIVE_WINDOW: u16 = 64;
/// mac80211's `max_tx_aggregation_subframes`, which rtw88 leaves alone.
const TRANSMIT_WINDOW: u16 = 64;
/// A reorder clock of microseconds, `HT_RX_REORDER_BUF_TIMEOUT` of 100 ms.
const REORDER_TICKS_PER_SECOND: u32 = 1_000_000;
/// The frames a TID waits with while its queue is full.
const MAX_HELD: usize = 256;
/// A CCMP header, the IV a frame carries behind its MAC header.
const IV_BYTES: usize = 8;
/// `IEEE80211_TKIP_ICV_LEN`, and where a TKIP key keeps the Michael key for
/// what it receives, `NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY`.
const ICV_BYTES: usize = 4;
const RECEIVE_MICHAEL_KEY: usize = 24;
/// `ieee80211_add_wmm_info_ie`, without U-APSD.
const WMM_ELEMENT: [u8; 9] = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];
/// `WLAN_CATEGORY_BACK`.
const BLOCK_ACK_CATEGORY: u8 = 3;

/// One received frame, as `rtw_rx_query_rx_desc` reads it.
#[derive(Clone, Debug)]
pub struct Received {
    /// The MPDU, its FCS removed. `BIT_APP_MIC` keeps a decrypted frame's IV and
    /// MIC, as mac80211 expects of `RX_FLAG_DECRYPTED` alone.
    pub bytes: Vec<u8>,
    pub tsf: u32,
    pub decrypted: bool,
    pub icv_error: bool,
    pub signal_dbm: Option<i8>,
}

/// What the device gave the host: a frame, or one of its own `R` reports.
#[derive(Clone, Debug)]
pub enum Incoming<R> {
    Frame(Received),
    Report(R),
}

/// What a device's report tells the station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reported {
    /// The frame whose TX report was to name `number` went, acknowledged or
    /// not.
    Transmitted { number: u8, acknowledged: bool },
    /// Firmware moved the peer's rate: `max_rc_amsdu_len`, the longest A-MSDU
    /// that rate suits.
    Amsdu(u16),
}

/// The access category a frame waits under, or management. Each chip maps it
/// to its own rings, as `rtw_tx_ac_to_hwq` and `rtw89_core_get_ch_dma` do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Queue {
    Background,
    BestEffort,
    Video,
    Voice,
    Management,
}

/// A key for the hardware's key table: `ieee80211_key_conf` as `set_key`
/// hands it down. `entry` is logical, a group key's index or [`PAIRWISE_CAM`].
pub struct KeyEntry<'a> {
    pub entry: u8,
    pub index: u8,
    pub cipher: Cipher,
    pub group: bool,
    pub peer: Mac,
    /// The temporal key, without a TKIP key's Michael halves.
    pub material: &'a [u8; 16],
}

/// A management frame for the rings: what `rtw_tx_mgmt_pkt_info_update` and
/// `rtw89_core_tx_update_mgmt_info` fill a descriptor from.
pub struct Management<'a> {
    /// The MPDU, its MAC header first.
    pub mpdu: &'a [u8],
    /// The band it leaves on.
    pub band: Band,
    /// The BSS's basic rates once associated, the lowest of which carries it.
    pub basic: Option<u16>,
    /// The number the device's TX report is to name the frame by.
    pub report: Option<u8>,
}

/// A data or null frame to the associated AP: what
/// `rtw_tx_data_pkt_info_update` and `rtw89_core_tx_update_data_info` fill a
/// descriptor from.
pub struct Data<'a> {
    /// The MPDU, its MAC header first and numbered by the host.
    pub mpdu: &'a [u8],
    pub context: &'a AssociationContext,
    /// The width the link runs at.
    pub width: Width,
    /// The TID of a QoS frame.
    pub tid: Option<u8>,
    /// The hardware seals it under the pairwise key, behind the host's IV.
    pub protected: bool,
    /// Its TID's transmit agreement is in force, so it may join an A-MPDU.
    pub aggregate: bool,
}

/// What the station reads and changes of a descriptor it holds.
pub trait Descriptor: Clone {
    /// The TID it was queued under, which a frame outside QoS shares with
    /// TID 0.
    fn tid(&self) -> u8;
    /// Whether it may join an A-MPDU.
    fn aggregated(&self) -> bool;
    /// Its TID's transmit agreement ended, so it leaves alone.
    fn stop_aggregating(&mut self);
    /// Whether the hardware seals it behind the host's IV.
    fn protected(&self) -> bool;
    /// Its frame grew to `size` bytes, a subframe joined to its A-MSDU.
    fn resize(&mut self, size: usize);
}

/// What a radio's station needs of the hardware beneath it. Each operation is
/// the hardware half of the mac80211 operation it names; the descriptor, the
/// reports and the association commands are each chip's own.
pub trait Device {
    /// What goes ahead of a frame in the rings: rtw88's `rtw_tx_pkt_info`.
    type Descriptor: Descriptor;
    /// One report firmware gives the host: rtw88's C2H.
    type Report;
    /// The longest MPDU, an A-MSDU's subframes and all, the rings take.
    const MAX_FRAME: usize;
    /// The driver the keeper's reports name, its `Radio::NAME`.
    const DRIVER: &'static str;
    /// The chip an error names.
    const CHIP: &'static str;
    /// The 5 GHz channels the driver registers with mac80211.
    const CHANNELS_5GHZ: &'static [u16];
    /// Whether the key table takes a TKIP group key, rtw89's `hw_tkip_crypto`:
    /// rtw88's takes its temporal half and decrypts, Michael left to the host.
    /// A chip without it refuses the key in `set_key`, `-EOPNOTSUPP`, and the
    /// host keeps it and decrypts the AP's group traffic itself, as mac80211
    /// does ([`security::tkip`]).
    const HARDWARE_TKIP: bool;

    /// The capability elements a probe and an association request carry on
    /// `band` behind the rates, HT's, VHT's, HE's and the extended
    /// capabilities among them, and the HE MCS maps the station's own HE
    /// capabilities come from.
    fn advertisement(&self, band: Band) -> (Vec<u8>, [McsMaps; 3]);
    /// The descriptor of a management frame, at the BSS's lowest basic rate.
    fn management(&self, frame: &Management<'_>) -> Self::Descriptor;
    /// The descriptor of a data frame to the AP.
    fn data(&self, frame: &Data<'_>) -> Self::Descriptor;
    /// The descriptor of `ieee80211_send_nullfunc`'s null to the AP, which the
    /// device numbers and whose TX report is to name `report`.
    fn null(&self, frame: &Data<'_>, report: u8) -> Self::Descriptor;
    /// What `report` tells the station, for a peer on a link `width` wide.
    fn reported(&self, report: &Self::Report, width: Width) -> Option<Reported>;
    /// `sta_state`'s association and `bss_info_changed` of it, for `local`
    /// joined to `context`'s AP on a link `width` wide: all the hardware
    /// learns of the peer, its port linked to the BSS as its AID and its
    /// beacons' interval and DTIM period among it.
    fn joined(
        &mut self,
        local: Mac,
        context: &AssociationContext,
        width: Width,
    ) -> Result<(), String>;
    /// `sta_state`'s disassociation: firmware told the peer left, ahead of the
    /// port's reset.
    fn left(&mut self) -> Result<(), String>;
    /// Firmware's rate adaptation told of the peer on a link `width` wide at
    /// the watchdog's `level`; `reset` starts its mask and level over.
    fn refresh_rates(
        &mut self,
        context: &AssociationContext,
        width: Width,
        level: u8,
        reset: bool,
    ) -> Result<(), String>;

    /// `config`'s channel. While `scanning`, no calibration follows.
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String>;
    /// `mgd_prepare_tx`: calibrate for the channel a frame will leave on.
    fn prepare_transmit(&mut self) -> Result<(), String>;
    /// `tx` of `mpdu` behind `descriptor` and the kick. False asks to try
    /// again.
    fn transmit(
        &mut self,
        queue: Queue,
        descriptor: &Self::Descriptor,
        mpdu: &[u8],
    ) -> Result<bool, String>;
    /// What arrived since the last look.
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming<Self::Report>)) -> Result<(), String>;
    /// The port's BSSID, AID and link state.
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String>;
    /// `configure_filter`: keep only the BSS's own beacons, or all.
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String>;
    /// `conf_tx` of every access category.
    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String>;
    /// `set_key`'s `SET_KEY`.
    fn write_key(&mut self, key: &KeyEntry<'_>) -> Result<(), String>;
    /// `set_key`'s `DISABLE_KEY` of a logical entry.
    fn clear_key(&mut self, entry: u8) -> Result<(), String>;
    /// Entering and leaving power save, which each stand for being there.
    fn set_power_save(&mut self, _on: bool) -> Result<(), String> {
        Ok(())
    }
    /// The next change to one stream or back to two.
    fn stream_change(&mut self) -> Option<bool> {
        None
    }
    /// A look at the hardware's timers at `now`, once each service: the
    /// Bluetooth arbiter's, or the radio tracking's.
    fn coexist(&mut self, _now: u64) -> Result<(), String> {
        Ok(())
    }
    /// The watchdog's traffic accounts, and unless `scanning` its work on the
    /// air, for a peer that takes STBC or not.
    fn watchdog(&mut self, _scanning: bool, _stbc: bool) -> Result<Watched, String> {
        Ok(Watched::default())
    }
    /// `sw_scan_start` and `sw_scan_complete`.
    fn scanning(&mut self, _scanning: bool) -> Result<(), String> {
        Ok(())
    }
    /// Whether an interrupt wakes the core that looks for frames.
    fn signals(&self) -> bool {
        false
    }
    /// What the hardware does not do yet, each named once or more.
    fn limitation(&mut self) -> Option<&'static str> {
        None
    }
    /// The hardware's own state line, with no address in it, such as what
    /// its rings took and released ([`Link::diagnostic`]).
    fn diagnostic(&mut self) -> Option<String> {
        None
    }
    /// The firmware's loss since the last look, once the hardware dealt
    /// with it: what it says of the loss and of the chip, which it brought
    /// up cold or powered off for good. The peer, its keys and its
    /// agreements went with the firmware. `None` while the firmware runs,
    /// and always for rtw88's chips, whose firmware Stela never sees go.
    fn recover(&mut self) -> Option<String> {
        None
    }
}

#[derive(Debug)]
pub enum Error {
    Hardware(String),
    /// The firmware went: what the hardware said of it.
    Lost(String),
    Station(crate::wifi::station::Error),
    BlockAck(ba::Error),
    Data(data::Error),
    Key(security::Error),
    Scan(scan::Error),
    Refused(&'static str),
    Unsupported(&'static str),
    /// What `chip` does not do.
    Lacks {
        what: &'static str,
        chip: &'static str,
    },
    /// Frames must drain before this can go on.
    Pending,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lacks { what, chip } => write!(f, "Unsupported(\"{what} on an {chip}\")"),
            Self::Lost(why) => f.write_str(why),
            error => write!(f, "{error:?}"),
        }
    }
}

/// The keeper's handle on the IGTK the host holds.
pub struct ManagementKey;

/// A BSS and when it was last heard, a `cfg80211_internal_bss`.
struct Heard {
    observation: Arc<NativeBssObservation>,
    at: u64,
}

/// A scan's walk over its channels, `ieee80211_scan_work`.
struct Hop {
    ticket: scan::Ticket,
    channels: Vec<Channel>,
    next: usize,
    leaves_at: u64,
}

/// What a run of the watchdog found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Watched {
    /// The peer's `rssi_level`.
    pub level: u8,
    /// Too many frames for power save.
    pub busy: bool,
}

/// One key the station holds, in the CAM or, a TKIP key the chip refused,
/// in the host alone.
struct Key {
    slot: KeySlot,
    pairwise: bool,
    index: u8,
    entry: u8,
    /// Whether the CAM took it, mac80211's `KEY_FLAG_UPLOADED_TO_HARDWARE`.
    hardware: bool,
    material: Zeroizing<Vec<u8>>,
}

/// What the AP's TKIP group traffic came to: frames the host decrypted, as
/// the chip left them, ICVs that failed there, and Michael failures, each
/// reported to the AP. A station's diagnostic names them once any is
/// counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TkipCounts {
    decrypted: u32,
    icv_failures: u32,
    michael_failures: u32,
}

/// What became of the protected data frames the chip handed over, unicast
/// (`[0]`) and group-addressed (`[1]`) apart: each heard, and those dropped
/// under a key the station does not hold or has not installed, or for an
/// ICV error the chip found. A station's diagnostic names them once any is
/// counted, so that a run that heard no group traffic tells an AP that sent
/// none from frames dropped on the way in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProtectedCounts {
    heard: [u32; 2],
    unkeyed: [u32; 2],
    icv: [u32; 2],
}

impl core::fmt::Display for ProtectedCounts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (at, kind) in ["unicast", "group"].into_iter().enumerate() {
            if at > 0 {
                f.write_str(" ")?;
            }
            write!(
                f,
                "protected {kind} heard={} unkeyed={} icv={}",
                self.heard[at], self.unkeyed[at], self.icv[at]
            )?;
        }
        Ok(())
    }
}

/// The channels the country admits, which the real check gates at each frame.
struct Admitted<'a>(&'a [(Channel, u32)]);

impl RegulatoryPolicy for Admitted<'_> {
    fn allow_management_tx(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|(known, _)| *known == channel)
    }
    fn allow_data_tx(&mut self, channel: Channel) -> bool {
        self.allow_management_tx(channel)
    }
}

impl scan::Policy for Admitted<'_> {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        self.0.iter().any(|(known, _)| *known == channel)
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        true
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.0
            .iter()
            .map(|(channel, _)| *channel)
            .find(|channel| channel.band == band && channel.number == number)
    }
}

fn management(local: Mac, ap: Mac, subtype: u16, protected: bool, body: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    let control = subtype | if protected { 0x4000 } else { 0 };
    bytes[..2].copy_from_slice(&control.to_le_bytes());
    bytes[4..10].copy_from_slice(&ap.0);
    bytes[10..16].copy_from_slice(&local.0);
    bytes[16..22].copy_from_slice(&ap.0);
    bytes.extend_from_slice(body);
    bytes
}

/// The rates of rtw88's `rtw_band_2ghz` and `rtw_band_5ghz`, which rtw89's
/// `rtw89_sband_2ghz` and `rtw89_sband_5ghz` share.
fn rate_elements(band: Band) -> &'static [u8] {
    match band {
        Band::Ghz2 => &[1, 8, 2, 4, 11, 22, 12, 18, 24, 36, 50, 4, 48, 72, 96, 108],
        _ => &[1, 8, 12, 18, 24, 36, 48, 72, 96, 108],
    }
}

/// `ieee80211_probereq_get`: the elements of a scan's probe on `band`, the
/// device's `capabilities` behind its rates.
fn probe_request(
    local: Mac,
    ssid: &[u8],
    band: Band,
    capabilities: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut bytes = alloc::vec![0; 24];
    bytes[..2].copy_from_slice(&0x40u16.to_le_bytes());
    bytes[4..10].fill(0xff);
    bytes[10..16].copy_from_slice(&local.0);
    bytes[16..22].fill(0xff);
    bytes.extend_from_slice(&[0, ssid.len() as u8]);
    bytes.extend_from_slice(ssid);
    bytes.extend_from_slice(rate_elements(band));
    bytes.extend_from_slice(capabilities);
    bytes.extend_from_slice(extra);
    bytes
}

/// What `ieee80211_crypto_tkip_decrypt` and `ieee80211_rx_h_michael_mic_verify`
/// make of a TKIP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Michael {
    Intact,
    /// A frame this key already took, or no TKIP frame at all: dropped, with
    /// no verdict on Michael.
    Dropped,
    Failed,
}

/// Check `frame`, decrypted with `IV` and trailer in place, under `key`.
/// Michael covers an MSDU, so fragments never reach here.
fn check_michael(frame: &mut Mpdu, key: &Key) -> Michael {
    let header = *frame.header();
    let bytes = frame.bytes();
    let body = header.length + IV_BYTES;
    let Some(end) = bytes.len().checked_sub(ICV_BYTES + michael::MIC_BYTES) else {
        return Michael::Dropped;
    };
    let Some(Ok((number, _))) = bytes
        .get(header.length..)
        .map(PacketNumber::from_tkip_header)
    else {
        return Michael::Dropped;
    };
    if end < body {
        return Michael::Dropped;
    }
    let source = bytes[16..22].try_into().unwrap_or([0; 6]);
    let stored = bytes[end..end + michael::MIC_BYTES].to_vec();
    let mut mic_key = [0; michael::MIC_BYTES];
    mic_key.copy_from_slice(&key.material[RECEIVE_MICHAEL_KEY..]);
    let priority = header.tid.unwrap_or(0);
    let computed = michael::michael(
        &mic_key,
        &header.receiver.0,
        &source,
        priority,
        &bytes[body..end],
    );
    frame.security.pn = Some(number);
    if key.slot.replays(frame) {
        Michael::Dropped
    } else if computed == stored[..] {
        Michael::Intact
    } else {
        Michael::Failed
    }
}

/// `si->stbc_en`.
pub(super) fn peer_stbc(context: &AssociationContext) -> bool {
    let negotiated = context.negotiated();
    match (&negotiated.vht, &negotiated.ht) {
        (Some(vht), _) => vht.capability & 0x700 != 0,
        (_, Some(ht)) => ht.capability & 0x300 != 0,
        _ => false,
    }
}

/// The 20 MHz definition around `channel`, which a scan and a join stand on.
fn twenty(channel: Channel) -> ChannelDefinition {
    ChannelDefinition {
        control: channel,
        width: Width::Mhz20,
        center1_mhz: u32::from(channel.frequency_mhz),
        center2_mhz: None,
        punctured: 0,
    }
}

/// A Realtek softMAC chip kept connected to one network.
pub type Wifi<D> = Keeper<Realtek<D>>;

/// A Realtek softMAC chip's association state.
pub struct Realtek<D: Device> {
    device: D,
    address: Mac,
    clock: Clock,
    country: Country,
    channels: Vec<(Channel, u32)>,
    station: Station,
    scanner: Scanner,
    hop: Option<Hop>,
    /// A scan finished and waits for the keeper.
    scanned: Option<scan::Ticket>,
    observed: Vec<Heard>,
    outbox: VecDeque<(Option<Ticket>, Vec<u8>)>,
    events: VecDeque<keeper::Event>,
    /// What beacons said of the AP since association.
    following: Option<follow::Following>,
    received: VecDeque<Vec<u8>>,
    /// Data frames waiting for room, each with its queue and descriptor.
    held: VecDeque<(Queue, D::Descriptor, Vec<u8>)>,
    /// Data kept from a TID whose transmit agreement is changing, as
    /// `ieee80211_agg_stop_txq` keeps it in the TXQ.
    parked: VecDeque<(u8, Vec<u8>, TxClass)>,
    /// What transmit agreements have yet to do, in turn.
    changes: VecDeque<tx::Action>,
    /// Each TID's agreement in force, `RTW_TXQ_AMPDU`.
    aggregating: [Option<Arc<tx::Session>>; 8],
    /// The TIDs an agreement cannot start on, `RTW_TXQ_BLOCK_BA`.
    unaggregated: [bool; 8],
    /// The TIDs whose agreement carries no A-MSDU, `IEEE80211_TXQ_NO_AMSDU`.
    no_amsdu: [bool; 8],
    /// `agg.max_rc_amsdu_len`, which starts unset.
    rate_amsdu: u16,
    /// The frame last held is plain data, which others may join.
    tail_joins: bool,
    admitted: Option<(Ticket, Arc<AssociationContext>)>,
    context: Option<Arc<AssociationContext>>,
    keys: Vec<Key>,
    next_slot: u16,
    /// The join's management cipher, and the IGTK the host checks frames under.
    management_cipher: Option<ManagementCipher>,
    integrity: Option<BipKey>,
    /// The channel the radio stands on.
    tuned: Option<Channel>,
    /// The frames each TID's Block Ack agreement holds in order.
    agreements: [Option<Reorder<Mpdu>>; 8],
    fragments: Fragments,
    /// The next TX report number, `tx_report.sn`.
    report: u8,
    /// A report's number, which the management frame it names may await.
    reporting: Option<u8>,
    port_open: bool,
    watchdog_at: u64,
    /// `rtwdev->watch_dog_cnt`.
    watchdogs: u32,
    departing: Option<Ticket>,
    left: bool,
    reported: Vec<&'static str>,
    /// Why the station's last peer went: the AP's status or reason, a
    /// frame never acknowledged, or one that never left.
    departed: Option<crate::wifi::station::Failure>,
    tkip: TkipCounts,
    protected: ProtectedCounts,
}

impl<D: Device> Realtek<D> {
    /// `device`, running at `address` under `country`, as a keeper's radio.
    pub fn new(device: D, address: Mac, country: Country, clock: Clock) -> Result<Self, Error> {
        let channels = channels(&country, D::CHANNELS_5GHZ);
        let watchdog_at = clock.now_us() + WATCHDOG_US;
        Ok(Self {
            device,
            address,
            clock,
            country,
            channels,
            station: Station::new(address).map_err(Error::Station)?,
            scanner: Scanner::new(address).map_err(Error::Scan)?,
            hop: None,
            scanned: None,
            observed: Vec::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            following: None,
            received: VecDeque::new(),
            held: VecDeque::new(),
            parked: VecDeque::new(),
            changes: VecDeque::new(),
            aggregating: Default::default(),
            unaggregated: [false; 8],
            no_amsdu: [false; 8],
            rate_amsdu: 0,
            tail_joins: false,
            admitted: None,
            context: None,
            keys: Vec::new(),
            next_slot: 0,
            management_cipher: None,
            integrity: None,
            tuned: None,
            agreements: Default::default(),
            fragments: Fragments::default(),
            report: 0,
            reporting: None,
            port_open: false,
            watchdog_at,
            watchdogs: 0,
            departing: None,
            left: false,
            reported: Vec::new(),
            departed: None,
            tkip: TkipCounts::default(),
            protected: ProtectedCounts::default(),
        })
    }

    /// Keep `self` connected to `network`; `entropy` gives each handshake's
    /// SNonce.
    pub fn keep(self, network: Network, entropy: Arc<dyn Entropy>) -> Wifi<D> {
        let clock = self.clock;
        Keeper::keep(self, network, entropy, clock)
    }

    /// The device, for its models and diagnostics.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// The device, for its models and diagnostics, such as a firmware crash
    /// asked for on purpose.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    fn hardware<T>(result: Result<T, String>) -> Result<T, Error> {
        result.map_err(Error::Hardware)
    }

    /// `chan->max_reg_power` of the channel at `frequency_mhz`.
    fn eirp_mbm(&self, frequency_mhz: u16) -> i32 {
        self.regulated_power_dbm(frequency_mhz) * 100
    }

    fn unsupported(&mut self, operation: &'static str) {
        if !self.reported.contains(&operation) {
            self.reported.push(operation);
            self.events.push_back(keeper::Event::Unsupported(operation));
        }
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::Transmit { ticket, bytes, .. } => {
                self.outbox.push_back((Some(ticket), bytes));
            }
            Action::Configure {
                ticket,
                context: Some(context),
                ..
            } => self.admitted = Some((ticket, context)),
            // Every join here is a modern one, which carries its context.
            Action::Configure { .. } => {
                self.admitted = None;
                if let Ok(Action::Remove { ticket, failure }) = self.station.disconnect() {
                    self.depart(ticket, failure);
                }
            }
            Action::Remove { ticket, failure } => self.depart(ticket, failure),
        }
    }

    fn depart(&mut self, ticket: Ticket, failure: Option<crate::wifi::station::Failure>) {
        if failure.is_some() {
            self.departed = failure;
        }
        if let Some(failure) = failure
            && self.station.external_authentication().is_some()
        {
            self.events
                .push_back(keeper::Event::SaeEnded(format!("{failure:?}")));
        }
        self.departing = Some(ticket);
        self.left = true;
        self.port_open = false;
        self.admitted = None;
        self.outbox.clear();
        self.held.clear();
        self.parked.clear();
        self.end_aggregation();
    }

    /// `ieee80211_sta_tear_down_BA_sessions`, with no frame left to send.
    fn end_aggregation(&mut self) {
        for tid in 0..8 {
            if let Ok(action) = self.station.stop_tx_block_ack(tid, false) {
                self.changes.push_back(action);
            }
        }
        if self.change_agreements().is_err() {
            self.unsupported("a transmit agreement that would not end");
        }
    }

    /// `rtw_sta_remove` and `rtw_ops_bss_info_changed` of the disassociation.
    fn clear(&mut self) -> Result<(), Error> {
        // mac80211 disables only the keys it uploaded.
        for key in core::mem::take(&mut self.keys) {
            if key.hardware {
                Self::hardware(self.device.clear_key(key.entry))?;
            }
        }
        self.power_save(false)?;
        for agreement in &mut self.agreements {
            *agreement = None;
        }
        self.fragments.clear();
        self.changes.clear();
        self.aggregating = Default::default();
        self.unaggregated = [false; 8];
        Self::hardware(self.device.left())?;
        Self::hardware(self.device.set_port(Mac([0; 6]), 0, false))?;
        Self::hardware(self.device.filter_beacons(false))?;
        self.context = None;
        self.following = None;
        self.integrity = None;
        self.management_cipher = None;
        self.departing = None;
        self.left = false;
        self.reporting = None;
        Ok(())
    }

    /// The firmware went, and the device says `why` and what came of it:
    /// the hardware's half of the association goes as [`Self::clear`] has
    /// it go, whatever the device refuses, and the station's half starts
    /// over, for the keeper to join again from a scan once told
    /// ([`keeper::Event::FirmwareLost`]). Nothing is replayed, as
    /// `ieee80211_restart_hw` would replay it: the chip came up cold.
    fn lost(&mut self, why: String) -> Result<(), Error> {
        // A device that stays off refuses these; `why` says so.
        let _ = self.clear();
        self.station = Station::new(self.address).map_err(Error::Station)?;
        self.scanner = Scanner::new(self.address).map_err(Error::Scan)?;
        self.hop = None;
        self.scanned = None;
        self.observed.clear();
        self.outbox.clear();
        self.held.clear();
        self.parked.clear();
        self.changes.clear();
        self.aggregating = Default::default();
        self.unaggregated = [false; 8];
        self.no_amsdu = [false; 8];
        self.rate_amsdu = 0;
        self.tail_joins = false;
        self.admitted = None;
        self.context = None;
        self.following = None;
        self.keys.clear();
        self.management_cipher = None;
        self.integrity = None;
        self.tuned = None;
        self.agreements = Default::default();
        self.fragments.clear();
        self.reporting = None;
        self.port_open = false;
        self.departing = None;
        self.left = false;
        // What the lost association's frames would have the keeper do goes
        // with it: an EAPOL or SAE frame the halt's look still delivered.
        self.events
            .retain(|event| matches!(event, keeper::Event::Unsupported(_)));
        self.events.push_back(keeper::Event::FirmwareLost);
        Err(Error::Lost(why))
    }

    fn observed(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.observed
            .get(handle)
            .map(|heard| heard.observation.clone())
            .ok_or(Error::Refused("the BSS is gone"))
    }

    /// `ieee80211_prep_channel` for the exchange ahead of an association.
    fn approach(&mut self, bss: &Bss) -> Result<(), Error> {
        Self::hardware(self.device.filter_beacons(true))?;
        let eirp_mbm = self.eirp_mbm(bss.channel.frequency_mhz);
        Self::hardware(self.device.tune(&twenty(bss.channel), false, eirp_mbm))?;
        self.tuned = Some(bss.channel);
        Self::hardware(self.device.set_port(bss.bssid, 0, false))?;
        Self::hardware(self.device.prepare_transmit())
    }

    fn walk(&mut self, now: u64) -> Result<(), Error> {
        let Some(hop) = &self.hop else {
            return Ok(());
        };
        if now < hop.leaves_at {
            return Ok(());
        }
        let ticket = hop.ticket;
        let Some(channel) = hop.channels.get(hop.next).copied() else {
            self.hop = None;
            Self::hardware(self.device.scanning(false))?;
            self.scanner
                .completed(ticket, Outcome::Completed)
                .map_err(Error::Scan)?;
            self.scanned = Some(ticket);
            return Ok(());
        };
        let request = self.scanner.request().ok_or(Error::Refused("scan"))?;
        let active = request.active() && self.probes(channel);
        let probes: Vec<Vec<u8>> = if active {
            let extra = request.extra_elements();
            let (capabilities, _) = self.device.advertisement(channel.band);
            let probe = |ssid: &Vec<u8>| {
                probe_request(self.address, ssid, channel.band, &capabilities, extra)
            };
            request.ssids().iter().map(probe).collect()
        } else {
            Vec::new()
        };
        if let Some(hop) = &mut self.hop {
            hop.next += 1;
            hop.leaves_at = now
                + if active {
                    ACTIVE_DWELL_US
                } else {
                    PASSIVE_DWELL_US
                };
        }
        let eirp_mbm = self.eirp_mbm(channel.frequency_mhz);
        Self::hardware(self.device.tune(&twenty(channel), true, eirp_mbm))?;
        self.tuned = Some(channel);
        for probe in probes {
            let packet = self.management_packet(channel.band, &probe, None, None);
            Self::hardware(self.device.transmit(Queue::Management, &packet, &probe))?;
        }
        Ok(())
    }

    /// `rtw_watch_dog_work`.
    fn watchdog(&mut self, now: u64) -> Result<(), Error> {
        if now < self.watchdog_at {
            return Ok(());
        }
        self.watchdog_at = now + WATCHDOG_US;
        let scanning = self.hop.is_some();
        let stbc = self.context.as_deref().is_some_and(peer_stbc);
        if !scanning {
            self.power_save(false)?;
        }
        let Watched { level, busy } = Self::hardware(self.device.watchdog(scanning, stbc))?;
        if scanning {
            return Ok(());
        }
        // `rtw_phy_ra_info_update`.
        if self.watchdogs & 3 == 0
            && let Some(context) = &self.context
        {
            let width = self.width(context);
            Self::hardware(self.device.refresh_rates(context, width, level, false))?;
        }
        self.watchdogs = self.watchdogs.wrapping_add(1);
        // `rtw_recalc_lps`, with `ieee80211_powersave_allowed`.
        let allowed = self.port_open
            && self
                .following
                .as_ref()
                .is_some_and(follow::Following::may_sleep);
        if allowed && !busy {
            self.power_save(true)?;
        }
        Ok(())
    }

    /// `ieee80211_request_smps` of each change the radio made.
    fn announce_streams(&mut self) -> Result<(), Error> {
        while let Some(single) = self.device.stream_change() {
            if let Some(context) = &self.context
                && context.negotiated().ht.is_some()
            {
                let control = if single { SMPS_STATIC } else { SMPS_DISABLED };
                let frame = self
                    .station
                    .spatial_power_save(context, control)
                    .map_err(Error::Station)?;
                self.outbox.push_back((None, frame));
            }
        }
        Ok(())
    }

    /// `rtw_enter_lps` and `rtw_leave_lps`.
    fn power_save(&mut self, on: bool) -> Result<(), Error> {
        Self::hardware(self.device.set_power_save(on))
    }

    /// The width the link to `context` runs at.
    fn width(&self, context: &AssociationContext) -> Width {
        self.following
            .as_ref()
            .map_or(context.negotiated().width, follow::Following::width)
    }

    /// The AP asked for silence, `ieee80211_vif_block_queues_csa`.
    fn silent(&self) -> bool {
        self.following
            .as_ref()
            .is_some_and(follow::Following::silent)
    }

    /// The device's descriptor of the management frame `bytes`, at the BSS's
    /// lowest basic rate.
    fn management_packet(
        &self,
        band: Band,
        bytes: &[u8],
        report: Option<u8>,
        basic: Option<u16>,
    ) -> D::Descriptor {
        self.device.management(&Management {
            mpdu: bytes,
            band,
            basic,
            report,
        })
    }

    fn send_management(&mut self) -> Result<(), Error> {
        while let Some((ticket, bytes)) = self.outbox.front().cloned() {
            if self.silent() {
                return Ok(());
            }
            let band = self.tuned.map_or(Band::Ghz2, |channel| channel.band);
            let basic = self.context.as_ref().map(|c| c.negotiated().legacy.basic);
            let report = ticket.is_some().then_some(self.report);
            let bytes = if bytes[1] & 0x40 != 0 {
                self.seal(&bytes)?
            } else {
                bytes
            };
            let packet = self.management_packet(band, &bytes, report, basic);
            if !Self::hardware(self.device.transmit(Queue::Management, &packet, &bytes))? {
                return Ok(());
            }
            self.outbox.pop_front();
            if let Some(ticket) = ticket {
                self.reporting = report;
                self.report = self.report.wrapping_add(4);
                self.station.submitted(ticket).map_err(Error::Station)?;
            }
        }
        Ok(())
    }

    /// `IEEE80211_KEY_FLAG_SW_MGMT_TX`: mac80211 seals a robust management frame
    /// itself, under the pairwise key.
    fn seal(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self
            .keys
            .iter_mut()
            .find(|key| key.pairwise)
            .ok_or(Error::Refused("no pairwise key"))?;
        let identity = key.slot.installed().ok_or(Error::Refused("no key"))?;
        let nonce = key
            .slot
            .reserve_host_tx_nonce(identity)
            .map_err(Error::Key)?;
        let pn = nonce.packet_number();
        let header = nonce.into_header();
        let material: &[u8; 16] = key.material[..]
            .try_into()
            .map_err(|_| Error::Unsupported("a management key longer than CCMP-128's"))?;
        Ok(ccmp::seal(
            material,
            &bytes[..24],
            &header,
            pn,
            &bytes[24..],
        ))
    }

    fn send_data(&mut self) -> Result<(), Error> {
        while !self.silent()
            && let Some((queue, packet, mpdu)) = self.held.front()
        {
            if !Self::hardware(self.device.transmit(*queue, packet, mpdu))? {
                return Ok(());
            }
            let session = self.aggregating[usize::from(packet.tid())]
                .clone()
                .filter(|_| packet.aggregated());
            self.held.pop_front();
            if let Some(session) = session {
                let now = self.clock.now_us();
                // SAFETY: this frame just went to the rings under `session`.
                // A stop under way has revoked it, and that refusal is right.
                let _ = unsafe { self.station.tx_block_ack_published(&session, now) };
            }
        }
        Ok(())
    }

    /// `rtw_txq_check_agg` and `rtw_txq_ba_iter` of data just queued on `tid`.
    fn start_aggregation(&mut self, tid: u8) {
        let index = usize::from(tid);
        if self.aggregating[index].is_some() || self.unaggregated[index] {
            return;
        }
        let now = self.clock.now_us();
        // A PMF association's ADDBA goes under the pairwise key.
        let started = if !self.station.requires_protected_management() {
            self.station.begin_tx_block_ack(tid, 0, now)
        } else if self.keys.iter().any(|key| key.pairwise) {
            self.station.begin_authenticated_tx_block_ack(tid, 0, now)
        } else {
            return;
        };
        match started {
            Ok(action) => self.changes.push_back(action),
            // `ieee80211_start_tx_ba_session`'s -EINVAL ends the attempts; its
            // other refusals leave the next frame to ask again.
            Err(ba::Error::Unsupported | ba::Error::InvalidLimits) => {
                self.unaggregated[index] = true;
            }
            Err(_) => {}
        }
    }

    /// mac80211's aggregation work over `rtw_ops_ampdu_action`, in which
    /// firmware holds no agreement: only a descriptor asks it to aggregate.
    fn change_agreements(&mut self) -> Result<(), Error> {
        while let Some(action) = self.changes.pop_front() {
            let now = self.clock.now_us();
            let next = match action {
                tx::Action::Prepare { ticket, session } => {
                    let tid = session.tid();
                    // mac80211 numbers a frame as it leaves the TXQ, so nothing
                    // it stopped has a number. What this numbered goes first.
                    if self.held.iter().any(|(_, packet, _)| packet.tid() == tid) {
                        self.changes
                            .push_front(tx::Action::Prepare { ticket, session });
                        return Ok(());
                    }
                    let sequence = self
                        .context
                        .as_ref()
                        .and_then(|context| self.station.next_qos_sequence(context, tid).ok());
                    // SAFETY: new data of this TID waits in `parked`, none of
                    // it is held, and `sequence` is the station's own counter.
                    unsafe {
                        self.station.complete_tx_block_ack_prepare(
                            ticket,
                            Completion::Accepted,
                            sequence,
                            now,
                        )
                    }
                }
                tx::Action::Transmit {
                    ticket,
                    session,
                    bytes,
                } => {
                    let result = if self.left
                        || self
                            .station
                            .validate_tx_block_ack_transmit(ticket, &session, &bytes)
                            .is_err()
                    {
                        Completion::RejectedAndIdle
                    } else if self.silent() || !self.send_agreement_frame(&bytes)? {
                        self.changes.push_front(tx::Action::Transmit {
                            ticket,
                            session,
                            bytes,
                        });
                        return Ok(());
                    } else {
                        Completion::Accepted
                    };
                    // SAFETY: the frame reached the rings, or never will.
                    unsafe {
                        self.station
                            .complete_tx_block_ack_transmit(ticket, result, now)
                    }
                }
                tx::Action::Program {
                    ticket,
                    session,
                    agreement,
                } => {
                    if agreement.is_none() {
                        let tid = session.tid();
                        self.aggregating[usize::from(tid)] = None;
                        for (_, packet, _) in &mut self.held {
                            if packet.tid() == tid {
                                packet.stop_aggregating();
                            }
                        }
                    }
                    // SAFETY: firmware holds nothing to change. As under
                    // `IEEE80211_AMPDU_TX_STOP_CONT`, a frame in a ring goes
                    // out as its descriptor says and later ones go singly.
                    unsafe {
                        self.station
                            .complete_tx_block_ack_program(ticket, Completion::Accepted)
                    }
                }
                tx::Action::Operational { session, agreement } => {
                    let tid = usize::from(session.tid());
                    self.no_amsdu[tid] |= !agreement.amsdu_in_ampdu();
                    self.aggregating[tid] = Some(session);
                    continue;
                }
                tx::Action::ResumeLegacy { .. } | tx::Action::None => continue,
            }
            .map_err(Error::BlockAck)?;
            self.changes.push_front(next);
        }
        Ok(())
    }

    /// `bytes` on the management queue, sealed under PMF. False when no room.
    fn send_agreement_frame(&mut self, bytes: &[u8]) -> Result<bool, Error> {
        let context = self.context.clone().ok_or(Error::Refused("no context"))?;
        let frame = if context.pmf().is_some() {
            let mut robust = bytes.to_vec();
            robust[1] |= 0x40;
            self.seal(&robust)?
        } else {
            bytes.to_vec()
        };
        let basic = Some(context.negotiated().legacy.basic);
        let packet = self.management_packet(context.channel().band, &frame, None, basic);
        Self::hardware(self.device.transmit(Queue::Management, &packet, &frame))
    }

    /// `ieee80211_agg_start_txq` of each TID no longer changing.
    fn release_parked(&mut self) -> Result<(), Error> {
        let mut at = 0;
        while at < self.parked.len() && self.held.len() < MAX_HELD {
            let (tid, ..) = self.parked[at];
            if self.station.tx_block_ack_blocks_data(tid) {
                at += 1;
                continue;
            }
            let Some((_, ethernet, class)) = self.parked.remove(at) else {
                break;
            };
            match self.send(&ethernet, class) {
                // mac80211 drops a frame the link can no longer take.
                Err(Error::Data(_)) => self.unsupported("a data frame its link refused once held"),
                result => result?,
            }
        }
        Ok(())
    }

    /// `rtw_ops_tx` of `ethernet`.
    fn send(&mut self, ethernet: &[u8], class: TxClass) -> Result<(), Error> {
        let epoch = self
            .station
            .association_epoch()
            .ok_or(Error::Refused("no association"))?;
        let context = self.context.clone().ok_or(Error::Refused("no context"))?;
        let tid = data::data_tid(&context, None, None, ethernet);
        if let Some(tid) = tid
            && self.station.tx_block_ack_blocks_data(tid)
        {
            if self.parked.len() >= MAX_HELD {
                self.parked.pop_front();
            }
            self.parked.push_back((tid, ethernet.to_vec(), class));
            return Ok(());
        }
        let joining = tid.filter(|&tid| self.tail_has_room(&context, tid, ethernet.len(), class));
        let mut policy = Admitted(&self.channels);
        let mut keys: Vec<&mut KeySlot> = self.keys.iter_mut().map(|key| &mut key.slot).collect();
        if let Some(tid) = joining {
            let plan = self
                .station
                .prepare_qos_subframe_refs(
                    epoch,
                    ethernet,
                    class,
                    Qos {
                        context: &context,
                        tid,
                    },
                    &mut keys,
                    &mut policy,
                )
                .map_err(Error::Data)?;
            if let Some((_, packet, mpdu)) = self.held.back_mut() {
                let iv = if packet.protected() { IV_BYTES } else { 0 };
                amsdu::append(mpdu, plan.plaintext_mpdu(), iv);
                packet.resize(mpdu.len());
            }
            return Ok(());
        }
        let plan = match tid {
            Some(tid) => self.station.prepare_qos_msdu_refs(
                epoch,
                ethernet,
                class,
                Qos {
                    context: &context,
                    tid,
                },
                &mut keys,
                &mut policy,
            ),
            None => self.station.prepare_msdu_refs(
                epoch,
                ethernet,
                class,
                SequenceOwner::Host,
                &mut keys,
                &mut policy,
            ),
        }
        .map_err(Error::Data)?;
        let (_, _, mpdu, protection, _, _) = plan.into_parts();
        let protected = match protection {
            Protection::None => false,
            Protection::HostIv { .. } => true,
            Protection::Firmware { .. } => return Err(Error::Refused("a firmware key")),
        };
        let queue = tid.map_or(Queue::BestEffort, tid_queue);
        let packet = self.device.data(&Data {
            mpdu: &mpdu,
            context: &context,
            width: self.width(&context),
            tid,
            protected,
            aggregate: tid.is_some_and(|tid| self.aggregating[usize::from(tid)].is_some()),
        });
        if self.held.len() >= MAX_HELD {
            self.held.pop_front();
        }
        self.held.push_back((queue, packet, mpdu));
        self.tail_joins = tid.is_some() && class == TxClass::Data;
        if let Some(tid) = tid
            && class == TxClass::Data
            && queue != Queue::Voice
        {
            self.start_aggregation(tid);
        }
        Ok(())
    }

    /// `ieee80211_amsdu_aggregate`: whether `size` more bytes of data on `tid`
    /// may join the frame waiting last, while one waits. `SUPPORTS_AMSDU_IN_AMPDU`
    /// holds, and `rtw_ops_can_aggregate_in_amsdu` keeps 2.4 GHz out of it.
    /// `max_amsdu_subframes` cannot bind here: its least is 8, and no frame
    /// this long holds so many.
    fn tail_has_room(
        &self,
        context: &AssociationContext,
        tid: u8,
        size: usize,
        class: TxClass,
    ) -> bool {
        let peer = usize::from(context.negotiated().max_tx_amsdu);
        let limit = match self.rate_amsdu {
            0 => peer,
            rate => peer.min(rate.into()),
        };
        class == TxClass::Data
            && self.tail_joins
            && context.channel().band != Band::Ghz2
            && !self.no_amsdu[usize::from(tid)]
            && self.held.back().is_some_and(|(_, packet, mpdu)| {
                packet.tid() == tid
                    && mpdu.len() + size + amsdu::SUBFRAME_OVERHEAD <= limit.min(D::MAX_FRAME)
            })
    }

    fn take_incoming(&mut self, now: u64) -> Result<(), Error> {
        let mut incoming = Vec::new();
        Self::hardware(self.device.receive(&mut |item| incoming.push(item)))?;
        while let Some(limitation) = self.device.limitation() {
            self.unsupported(limitation);
        }
        for item in incoming {
            match item {
                Incoming::Report(report) => {
                    // The width set up for the peer, which a report may leave
                    // out.
                    let width = self
                        .context
                        .as_deref()
                        .map_or(Width::Mhz20, |context| self.width(context));
                    match self.device.reported(&report, width) {
                        Some(Reported::Transmitted {
                            number,
                            acknowledged,
                        }) => {
                            if self.reporting == Some(number) {
                                self.reporting = None;
                                self.station
                                    .management_status(acknowledged, now)
                                    .map_err(Error::Station)?;
                            }
                            if let Some(following) = &mut self.following {
                                following.reported(number, acknowledged, now);
                            }
                        }
                        Some(Reported::Amsdu(limit)) => self.rate_amsdu = limit,
                        None => {}
                    }
                }
                Incoming::Frame(frame) => {
                    if let Some(mpdu) = self.mpdu(frame)
                        && let Err(error) = self.frame(mpdu, now)
                    {
                        match error {
                            // mac80211 drops a frame the station cannot use;
                            // the exchange it answers retries or times out.
                            Error::Station(_) => {
                                self.unsupported("a management frame the station refuses");
                            }
                            error => return Err(error),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The frame `received` holds, on the channel the radio stands on.
    fn mpdu(&mut self, received: Received) -> Option<Mpdu> {
        let channel = self.tuned?;
        let radio = RadioStatus {
            band: channel.band,
            channel: channel.number,
            frequency_mhz: channel.frequency_mhz,
            signal_dbm: received.signal_dbm,
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 0,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: Some(Timestamp::Low32(received.tsf)),
        };
        let security = SecurityStatus {
            decrypted: received.decrypted,
            integrity: if received.decrypted {
                Integrity::Verified
            } else {
                Integrity::Unknown
            },
            icv_error: received.icv_error,
            ..SecurityStatus::default()
        };
        Mpdu::new(received.bytes, radio, security).ok()
    }

    fn frame(&mut self, mut frame: Mpdu, now: u64) -> Result<(), Error> {
        let header = *frame.header();
        if let (Some(following), Some(context)) = (&mut self.following, &self.context)
            && header.transmitter == Some(context.bssid())
            && !header.receiver.is_multicast()
        {
            following.heard(now);
        }
        // A beacon or probe response heard during a scan.
        if let Some(hop) = &self.hop
            && matches!(header.control & 0xfc, 0x80 | 0x50)
        {
            let ticket = hop.ticket;
            let mut policy = Admitted(&self.channels);
            if let Ok(bss) = self.scanner.observe(ticket, &frame, &mut policy) {
                self.hear(bss, now);
            }
            return Ok(());
        }
        if header.control & 12 == 0 {
            return self.management_frame(frame, now);
        }
        if header.control & 12 != 8 || !header.data_present() {
            return Ok(());
        }
        if header.protected() {
            let multicast = header.receiver.is_multicast();
            let kind = usize::from(multicast);
            let counts = &mut self.protected;
            counts.heard[kind] = counts.heard[kind].saturating_add(1);
            let index = frame.bytes().get(header.length + 3).map(|byte| byte >> 6);
            let held = self
                .keys
                .iter()
                .position(|key| key.pairwise != multicast && Some(key.index) == index);
            let installed = held.and_then(|held| Some((held, self.keys[held].slot.installed()?)));
            let Some((held, key)) = installed else {
                counts.unkeyed[kind] = counts.unkeyed[kind].saturating_add(1);
                return Ok(());
            };
            if frame.security.icv_error {
                counts.icv[kind] = counts.icv[kind].saturating_add(1);
                return Ok(());
            }
            let tkip = self.keys[held].material.len() == Cipher::Tkip.key_length();
            // A key the chip never took leaves its frames as they came.
            let software = tkip && !self.keys[held].hardware && !frame.security.decrypted;
            if tkip && (frame.security.decrypted || software) {
                if header.fragmented() {
                    self.unsupported("a fragmented TKIP frame");
                    return Ok(());
                }
                if software {
                    let Some(decrypted) = self.decrypt_tkip(&mut frame, held) else {
                        return Ok(());
                    };
                    frame = decrypted;
                }
                match check_michael(&mut frame, &self.keys[held]) {
                    Michael::Intact => {}
                    Michael::Dropped => return Ok(()),
                    Michael::Failed => {
                        self.tkip.michael_failures = self.tkip.michael_failures.saturating_add(1);
                        let pairwise = !multicast;
                        self.events
                            .push_back(keeper::Event::MichaelFailure { pairwise });
                        return Ok(());
                    }
                }
            }
            frame.security.key = Some(key);
        }
        if header.fragmented() {
            self.reassemble(&frame, now);
            return Ok(());
        }
        self.order(frame, now);
        Ok(())
    }

    /// `ieee80211_crypto_tkip_decrypt` of a data frame the chip left under a
    /// TKIP key it refused: decrypted under the key's temporal half as the AP
    /// sent it, the IV and ICV kept, and marked decrypted as a chip marks
    /// what it decrypted (`RX_FLAG_DECRYPTED` alone), so the Michael and
    /// replay checks follow as for rtw88's. `None` drops a frame from
    /// another transmitter, as mac80211 drops one with no station, or one
    /// `ieee80211_tkip_decrypt_data` refuses, its replay check first and a
    /// failed ICV counted, with no verdict on its Michael.
    fn decrypt_tkip(&mut self, frame: &mut Mpdu, held: usize) -> Option<Mpdu> {
        let header = *frame.header();
        let transmitter = header
            .transmitter
            .filter(|&transmitter| Some(transmitter) == self.station.pairwise_peer())?;
        let (number, _) =
            PacketNumber::from_tkip_header(frame.bytes().get(header.length..)?).ok()?;
        frame.security.pn = Some(number);
        if self.keys[held].slot.replays(frame) {
            return None;
        }
        let temporal = self.keys[held].material.first_chunk::<16>()?;
        let mut bytes = frame.bytes().to_vec();
        let body = bytes.get_mut(header.length..)?;
        match security::tkip::decrypt(temporal, &transmitter.0, body) {
            Ok(()) => {}
            Err(security::tkip::Failure::Icv) => {
                self.tkip.icv_failures = self.tkip.icv_failures.saturating_add(1);
                return None;
            }
            Err(_) => return None,
        }
        let security = SecurityStatus {
            decrypted: true,
            integrity: Integrity::Verified,
            ..frame.security
        };
        let decrypted = Mpdu::new(bytes, frame.radio.clone(), security).ok()?;
        self.tkip.decrypted = self.tkip.decrypted.saturating_add(1);
        Some(decrypted)
    }

    /// `ieee80211_sta_manage_reorder_buf` for a frame under an agreement.
    /// `frame`, one fragment; the station has the MSDU with the last of them.
    fn reassemble(&mut self, frame: &Mpdu, now: u64) {
        let key = frame.security.key;
        let slot = self
            .keys
            .iter_mut()
            .map(|key| &mut key.slot)
            .find(|slot| key.is_some() && slot.installed() == key);
        if let Some(whole) = self.fragments.add(frame, slot, now) {
            self.deliver(whole);
        }
    }

    fn order(&mut self, frame: Mpdu, now: u64) {
        let header = frame.header();
        let agreement = header
            .tid
            .filter(|_| !header.receiver.is_multicast())
            .and_then(|tid| self.agreements.get_mut(usize::from(tid)))
            .and_then(Option::as_mut);
        let (Some(agreement), Some(sequence)) = (agreement, header.sequence) else {
            self.deliver(frame);
            return;
        };
        let mut ready = Vec::new();
        if let Err(rejected) =
            agreement.push(sequence, now as u32, frame, |frame| ready.push(frame))
        {
            ready.push(rejected.frame);
        }
        for frame in ready {
            self.deliver(frame);
        }
    }

    /// `frame`, its turn come, to the station. mac80211 drops what its replay
    /// and port checks refuse.
    fn deliver(&mut self, frame: Mpdu) {
        let ingress = if frame.header().amsdu {
            let Some(context) = self.context.clone() else {
                return;
            };
            let key = frame.security.key;
            // SAFETY: an A-MSDU is one record here, in the order the reorder
            // buffer released it, and `clear` drops what is held for an older
            // association.
            let group =
                unsafe { OrderedGroup::new(context, alloc::vec![frame], Shape::WholeMpdu, ()) };
            let slot = self
                .keys
                .iter_mut()
                .map(|key| &mut key.slot)
                .find(|slot| key.is_some() && slot.installed() == key);
            let Ok(received) = self.station.receive_ordered_group(&group, slot) else {
                return;
            };
            let keys: Vec<&KeySlot> = self.keys.iter().map(|key| &key.slot).collect();
            match self.station.receive_group_refs(&received, &keys) {
                Ok(ingress) => ingress,
                Err(_) => return,
            }
        } else {
            let Some(epoch) = self.station.association_epoch() else {
                return;
            };
            let mut keys: Vec<&mut KeySlot> =
                self.keys.iter_mut().map(|key| &mut key.slot).collect();
            match self.station.receive_msdu_refs(epoch, &frame, &mut keys) {
                Ok(ingress) => alloc::vec![ingress],
                Err(_) => return,
            }
        };
        for ingress in ingress {
            match ingress {
                Ingress::Data(ethernet) => self.received.push_back(ethernet),
                Ingress::ControlPort { ethernet, .. } => {
                    self.events.push_back(keeper::Event::Eapol(ethernet));
                }
            }
        }
    }

    fn hear(&mut self, mut bss: Bss, now: u64) {
        let known = self
            .observed
            .iter_mut()
            .find(|heard| heard.observation.bss().bssid == bss.bssid);
        match known {
            Some(heard) => {
                bss.keep_name_of(heard.observation.bss());
                heard.observation = Arc::new(NativeBssObservation { bss });
                heard.at = now;
            }
            None => self.observed.push(Heard {
                observation: Arc::new(NativeBssObservation { bss }),
                at: now,
            }),
        }
    }

    fn management_frame(&mut self, frame: Mpdu, now: u64) -> Result<(), Error> {
        let header = *frame.header();
        // What is heard outside a scan matters only of the associated AP.
        match header.control & 0xfc {
            0x80 => return self.beacon_heard(&frame, now),
            0x50 => return Ok(()),
            _ => {}
        }
        let mut policy = Admitted(&self.channels);
        if header.protected() {
            return self.protected_management(frame, now);
        }
        if self.station.phase() == Peering::ExternalAuthenticating {
            let session = self
                .station
                .external_authentication()
                .ok_or(Error::Refused("exchange"))?
                .clone();
            if let Some(received) = self
                .station
                .receive_external_authentication(&session, frame, now)
                .map_err(Error::Station)?
            {
                self.events
                    .push_back(keeper::Event::Sae(Box::new(received)));
            }
            return Ok(());
        }
        let Some(epoch) = self.station.association_epoch() else {
            return Ok(());
        };
        // `ieee80211_drop_unencrypted_mgmt`: only Public's is not robust.
        if header.control & 0xfc == 0xd0
            && let Some(body) = frame.bytes().get(header.length..)
            && (body.first() == Some(&4)
                || matches!(body.first(), Some(0 | 9))
                    && !self.station.requires_protected_management())
        {
            self.switch_action(body, now);
            return Ok(());
        }
        if header.control & 0xfc == 0xd0
            && frame.bytes().get(header.length) == Some(&BLOCK_ACK_CATEGORY)
        {
            if let Ok(action) = self.station.receive_block_ack(epoch, &frame, now) {
                self.block_ack(action);
            }
            return Ok(());
        }
        // A robust frame to everyone carries its IGTK's MIC: rtw88 leaves
        // BIP to mac80211.
        if header.receiver.is_multicast() && protection::robust(&frame) {
            let Some(integrity) = &mut self.integrity else {
                return Ok(());
            };
            let Ok(authenticated) = integrity.authenticate(&frame) else {
                return Ok(());
            };
            if matches!(header.control & 0xfc, 0xa0 | 0xc0) {
                let body = authenticated.body();
                let action = self
                    .station
                    .receive_protected_departure(epoch, &frame, body)
                    .map_err(Error::Station)?;
                self.events.push_back(keeper::Event::ConnectionLost);
                self.act(action);
            }
            return Ok(());
        }
        // A PMF association takes a departure only under its keys.
        if self.station.requires_protected_management()
            && matches!(header.control & 0xfc, 0xa0 | 0xc0)
            && !self.keys.is_empty()
        {
            return Ok(());
        }
        let action = self
            .station
            .receive(epoch, &frame, now, &mut policy)
            .map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    fn protected_management(&mut self, mut frame: Mpdu, now: u64) -> Result<(), Error> {
        let local = self.address;
        let Some(epoch) = self.station.association_epoch() else {
            return Ok(());
        };
        let header = *frame.header();
        let Some(key) = self.keys.iter_mut().find(|key| key.pairwise) else {
            return Ok(());
        };
        // mac80211 decrypts in software what hardware did not.
        if !frame.security.decrypted {
            let number = frame
                .bytes()
                .get(header.length..)
                .and_then(|iv| PacketNumber::from_header(iv).ok());
            let material: Option<&[u8; 16]> = key.material[..].try_into().ok();
            let (Some((number, _)), Some(material)) = (number, material) else {
                return Ok(());
            };
            let Some(opened) = ccmp::open(material, frame.bytes(), number) else {
                return Ok(());
            };
            let security = SecurityStatus {
                decrypted: true,
                integrity: Integrity::Verified,
                ..SecurityStatus::default()
            };
            let Ok(clear) = Mpdu::new(opened, frame.radio.clone(), security) else {
                return Ok(());
            };
            frame = clear;
        }
        frame.security.key = key.slot.installed();
        // Under packet numbers `ieee80211_crypto_ccmp_decrypt` keeps apart
        // from data's.
        let Ok(authenticated) = key.slot.authorize_unicast_management(&frame, local) else {
            return Ok(());
        };
        let body = authenticated.body();
        match header.control & 0xfc {
            0xa0 | 0xc0 => {
                let action = self
                    .station
                    .receive_protected_departure(epoch, &frame, body)
                    .map_err(Error::Station)?;
                self.events.push_back(keeper::Event::ConnectionLost);
                self.act(action);
            }
            0xd0 if body.first() == Some(&BLOCK_ACK_CATEGORY) => {
                let Some(context) = self.context.clone() else {
                    return Ok(());
                };
                if let Ok(action) = self
                    .station
                    .receive_authenticated_block_ack(&context, &frame, body, now)
                {
                    self.block_ack(action);
                }
            }
            0xd0 if matches!(body.first(), Some(0 | 9)) => self.switch_action(body, now),
            0xd0 if body.len() >= 4 && body[..2] == [8, 0] => {
                let response = [8, 1, body[2], body[3]];
                let Some(ap) = header.transmitter else {
                    return Ok(());
                };
                self.outbox
                    .push_back((None, management(self.address, ap, 0xd0, true, &response)));
            }
            _ => {}
        }
        Ok(())
    }

    fn block_ack(&mut self, action: ba::Action) {
        match action {
            ba::Action::Program {
                ticket,
                session,
                enable,
            } => {
                let tid = usize::from(session.tid());
                let completion = if enable {
                    match Reorder::new(
                        session.tid(),
                        session.start_sequence(),
                        session.window().min(RECEIVE_WINDOW),
                        REORDER_TICKS_PER_SECOND,
                    ) {
                        Ok(reorder) => {
                            self.agreements[tid] = Some(reorder);
                            Completion::Accepted
                        }
                        Err(_) => {
                            self.unsupported("a Block Ack window the host cannot hold");
                            Completion::RejectedAndIdle
                        }
                    }
                } else {
                    self.close_agreement(tid);
                    Completion::Accepted
                };
                // SAFETY: the host alone holds an agreement's state, which now
                // matches this ticket.
                let completed = unsafe { self.station.complete_rx_block_ack(ticket, completion) };
                if let Ok(action) = completed {
                    self.block_ack(action);
                }
            }
            ba::Action::Transmit {
                context, mut bytes, ..
            } => {
                // Block Ack action frames are robust.
                if context.pmf().is_some() {
                    bytes[1] |= 0x40;
                }
                self.outbox.push_back((None, bytes));
            }
            ba::Action::Bar {
                session,
                start_sequence,
            } => {
                let tid = usize::from(session.tid());
                let mut ready = Vec::new();
                if let Some(agreement) = &mut self.agreements[tid] {
                    let _ = agreement.bar(start_sequence, |frame| ready.push(frame));
                }
                for frame in ready {
                    self.deliver(frame);
                }
            }
            ba::Action::Tx(action) => self.changes.push_back(action),
            ba::Action::None => {}
        }
    }

    /// `ieee80211_free_tid_rx`: what the agreement still held goes with it.
    fn close_agreement(&mut self, tid: usize) {
        if let Some(mut agreement) = self.agreements[tid].take() {
            agreement.stop();
        }
    }

    /// `sta_rx_agg_reorder_timer_cb`, releasing what waited too long.
    fn release_expired(&mut self, now: u64) {
        let mut ready = Vec::new();
        for agreement in self.agreements.iter_mut().flatten() {
            let _ = agreement.poll(now as u32, |frame| ready.push(frame));
        }
        for frame in ready {
            self.deliver(frame);
        }
    }

    fn operate(&mut self) -> Result<(), Error> {
        let now = self.clock.now_us();
        self.take_incoming(now)?;
        if let Some(why) = self.device.recover() {
            return self.lost(why);
        }
        Self::hardware(self.device.coexist(now))?;
        self.announce_streams()?;
        self.watchdog(now)?;
        self.walk(now)?;
        self.release_expired(now);
        let mut policy = Admitted(&self.channels);
        if !self.left
            && let Some(action) = self
                .station
                .poll(now, &mut policy)
                .map_err(Error::Station)?
        {
            self.act(action);
        }
        if !self.left && self.station.phase() == Peering::ExternalAuthenticating {
            let mut policy = Admitted(&self.channels);
            if let Some(bytes) = self
                .station
                .external_retransmission(now, &mut policy)
                .map_err(Error::Station)?
            {
                self.outbox.push_back((None, bytes));
            }
        }
        while !self.left
            && self
                .station
                .next_tx_block_ack_deadline()
                .is_some_and(|deadline| deadline <= now)
        {
            match self.station.poll_tx_block_ack(now) {
                Ok(tx::Action::None) => break,
                Ok(action) => self.changes.push_back(action),
                Err(error) => return Err(Error::BlockAck(error)),
            }
        }
        self.follow(now)?;
        self.send_management()?;
        self.send_data()?;
        self.change_agreements()?;
        self.release_parked()?;
        self.send_data()
    }
}

/// The channels mac80211 registers, 5 GHz's those of `channels_5ghz`, as
/// `country` leaves them.
fn channels(country: &Country, channels_5ghz: &[u16]) -> Vec<(Channel, u32)> {
    let mut out = Vec::new();
    let mut band = |band: Band, numbers: &[u16], frequency: fn(u16) -> u16| {
        let centers: Vec<u16> = numbers.iter().map(|&number| frequency(number)).collect();
        for (&number, regulated) in numbers
            .iter()
            .zip(country.band(&centers).unwrap_or_default())
        {
            if regulated.flags & DISABLED == 0 {
                out.push((
                    Channel {
                        band,
                        number,
                        frequency_mhz: frequency(number),
                    },
                    regulated.flags,
                ));
            }
        }
    };
    band(
        Band::Ghz2,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        |number| {
            if number == 14 {
                2484
            } else {
                2407 + 5 * number
            }
        },
    );
    band(Band::Ghz5, channels_5ghz, |number| 5000 + 5 * number);
    out
}

const SUPPORTED_2GHZ: [u8; 2] = [1, 14];
const SUPPORTED_5GHZ: [u8; 4] = [36, 28, 149, 9];

/// `ieee802_1d_to_ac`: a TID's access category.
fn tid_queue(tid: u8) -> Queue {
    match tid {
        1 | 2 => Queue::Background,
        4 | 5 => Queue::Video,
        6 | 7 => Queue::Voice,
        _ => Queue::BestEffort,
    }
}

impl<D: Device> Link for Realtek<D> {
    fn mac(&self) -> Mac {
        self.address
    }
    fn carrier(&mut self) -> bool {
        self.port_open
    }
    /// A station signals once its port is open. Until then the handshake
    /// polls, as Intel's does.
    fn signals(&self) -> bool {
        self.port_open && self.device.signals()
    }
    fn due_us(&self) -> Option<u64> {
        self.signals()
            .then(|| self.clock.now_us().saturating_add(TIMER_TICK_US))
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        if !self.port_open {
            return Err(LinkError::NoCarrier);
        }
        self.send(frame, TxClass::Data)
            .map_err(|error| LinkError::Adapter(format!("{error}")))
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(self.received.pop_front())
    }
    /// Why the last peer went, when one did, then the hardware's own state.
    fn diagnostic(&mut self) -> Option<String> {
        let departed = self.departed.map(|failure| match failure {
            crate::wifi::station::Failure::PeerRejected(status) => {
                format!("the AP refused the last join with status {status}")
            }
            crate::wifi::station::Failure::PeerDeparture(reason) => {
                format!("the AP ended the last association with reason {reason}")
            }
            crate::wifi::station::Failure::Timeout => {
                String::from("the AP did not answer the last join in time")
            }
            crate::wifi::station::Failure::Transmit => {
                String::from("a frame of the last join never left")
            }
            crate::wifi::station::Failure::MultiLink => {
                String::from("the AP MLD's answer broke the last join's multi-link setup")
            }
        });
        let tkip = self.tkip;
        let tkip = (tkip != TkipCounts::default()).then(|| {
            format!(
                "tkip group decrypted={} icv-failures={} michael-failures={}",
                tkip.decrypted, tkip.icv_failures, tkip.michael_failures
            )
        });
        let protected = self.protected;
        let protected = (protected != ProtectedCounts::default()).then(|| format!("{protected}"));
        let parts: Vec<String> = [departed, protected, tkip, self.device.diagnostic()]
            .into_iter()
            .flatten()
            .collect();
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

impl<D: Device> Radio for Realtek<D> {
    type Handle = usize;
    type Profile = ();
    type Management = Arc<ManagementKey>;
    type Error = Error;

    const NAME: &'static str = D::DRIVER;
    /// rtw88 and rtw89 leave `max_listen_interval` at mac80211's default.
    const LISTEN_INTERVAL: u16 = 5;
    /// A TKIP group key is the CAM's or, where the chip refuses it, the
    /// host's.
    const TKIP_GROUP: bool = true;

    fn deferred(error: &Error) -> bool {
        matches!(error, Error::Pending)
    }

    fn service(&mut self) -> Result<(), Error> {
        self.operate()
    }

    fn take_event(&mut self) -> Option<keeper::Event> {
        self.events.pop_front()
    }

    fn stage(&self) -> Stage {
        if self.left {
            Stage::NeedsDrain
        } else if self.scanned.is_some() {
            Stage::Scanned
        } else if self.admitted.is_some() {
            Stage::Admitted
        } else if self.hop.is_none() && self.station.phase() == Peering::Idle {
            Stage::Idle
        } else {
            Stage::Busy
        }
    }

    fn station(&self) -> &Station {
        &self.station
    }

    fn channels(&self, band: Band) -> Vec<(Channel, u32)> {
        self.channels
            .iter()
            .filter(|(channel, _)| channel.band == band)
            .copied()
            .collect()
    }

    fn probes(&self, channel: Channel) -> bool {
        self.channels
            .iter()
            .any(|&(known, flags)| known == channel && flags & NO_IR == 0)
    }

    fn supported_channels(&self, band: Band) -> &'static [u8] {
        match band {
            Band::Ghz2 => &SUPPORTED_2GHZ,
            Band::Ghz5 => &SUPPORTED_5GHZ,
            Band::Ghz6 => &[],
        }
    }

    fn regulated_power_dbm(&self, frequency_mhz: u16) -> i32 {
        self.country.channel(frequency_mhz).max_reg_dbm
    }

    fn advertisement(&self, band: Band) -> Result<Advertisement, Error> {
        let (capability_elements, he_source_maps) = self.device.advertisement(band);
        let mut elements = rate_elements(band).to_vec();
        elements.extend_from_slice(&capability_elements);
        elements.extend_from_slice(&WMM_ELEMENT);
        let capabilities = Capabilities::parse(band, Role::Station, &elements)
            .map_err(|_| Error::Refused("advertisement"))?;
        Ok(Advertisement {
            capabilities,
            elements,
            he_source_maps,
            multi_link: Some(false),
        })
    }

    fn profile(&self, _: Peer) -> Result<(), Error> {
        Ok(())
    }

    fn begin_scan(&mut self, request: scan::Request, budget_us: u64) -> Result<(), Error> {
        let now = self.clock.now_us();
        self.power_save(false)?;
        self.observed
            .retain(|heard| now.saturating_sub(heard.at) < BSS_EXPIRY_US);
        let channels = request.channels().to_vec();
        let mut policy = Admitted(&self.channels);
        let ticket = self
            .scanner
            .begin(request, now, budget_us, &mut policy)
            .map_err(Error::Scan)?;
        self.scanner
            .validate_submission(ticket, now, &mut policy)
            .map_err(Error::Scan)?;
        self.scanner.submitted(ticket).map_err(Error::Scan)?;
        Self::hardware(self.device.filter_beacons(false))?;
        Self::hardware(self.device.scanning(true))?;
        self.hop = Some(Hop {
            ticket,
            channels,
            next: 0,
            leaves_at: now,
        });
        Ok(())
    }

    unsafe fn retire_scan(&mut self) -> Result<(), Error> {
        let ticket = self.scanned.take().ok_or(Error::Refused("scan"))?;
        self.scanner
            .retire(ticket, Retirement::Confirmed)
            .map_err(Error::Scan)?;
        Ok(())
    }

    fn six_ghz_scan(
        &self,
        _: &scan::Request,
        _: scan::six_ghz::Options,
    ) -> Result<Option<scan::Request>, Error> {
        Ok(None)
    }

    fn bss(&self) -> Vec<(usize, &Bss)> {
        self.observed
            .iter()
            .enumerate()
            .map(|(handle, heard)| (handle, heard.observation.bss()))
            .collect()
    }

    fn observation(&self, handle: usize) -> Result<Arc<NativeBssObservation>, Error> {
        self.observed(handle)
    }

    fn join(&mut self, handle: usize, join: Join, _: ()) -> Result<(), Error> {
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        self.approach(&bss)?;
        let now = self.clock.now_us();
        self.management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let mut policy = Admitted(&self.channels);
        let action = if join.request.pmf().is_some() {
            self.station
                .begin_modern_pmf(join, observed, now, &mut policy)
        } else {
            self.station
                .begin_modern(join, observed.bss().clone(), now, &mut policy)
        }
        .map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    fn begin_external_authentication(
        &mut self,
        handle: usize,
        _: (),
        multi_link: Option<Affiliation>,
        budget_us: u64,
    ) -> Result<Arc<external::Session>, Error> {
        let observed = self.observed(handle)?;
        let bss = observed.bss().clone();
        self.approach(&bss)?;
        let now = self.clock.now_us();
        let mut policy = Admitted(&self.channels);
        self.station
            .begin_external_authentication(
                external::Peer {
                    bssid: bss.bssid,
                    channel: bss.channel,
                    ssid: bss.ssid.clone().unwrap_or_default(),
                    multi_link,
                },
                now,
                budget_us,
                &mut policy,
            )
            .map_err(Error::Station)
    }

    fn begin_six_ghz_external_authentication(
        &mut self,
        _: usize,
        _: Selection,
        _: (),
        _: Option<Affiliation>,
        _: u64,
    ) -> Result<Arc<external::Session>, Error> {
        Err(Error::Lacks {
            what: "6 GHz",
            chip: D::CHIP,
        })
    }

    fn transmit_external_authentication(
        &mut self,
        session: &external::Session,
        frame: external::Frame<'_>,
    ) -> Result<(), Error> {
        let now = self.clock.now_us();
        let mut policy = Admitted(&self.channels);
        let bytes = self
            .station
            .external_authentication_transmit(session, frame, now, &mut policy)
            .map_err(Error::Station)?;
        self.outbox.push_back((None, bytes));
        Ok(())
    }

    fn associate_external(
        &mut self,
        session: &external::Session,
        handle: usize,
        join: Join,
    ) -> Result<(), Error> {
        let observed = self.observed(handle)?;
        let now = self.clock.now_us();
        self.management_cipher = join.request.pmf().map(|pmf| pmf.management());
        let mut policy = Admitted(&self.channels);
        let action = self
            .station
            .associate_external_pmf(session, join, observed, now, &mut policy)
            .map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    /// `sta_state`'s association, then `bss_info_changed` of it.
    fn configure(&mut self) -> Result<(), Error> {
        let (ticket, context) = self
            .admitted
            .take()
            .ok_or(Error::Refused("configuration"))?;
        let eirp_mbm = self.eirp_mbm(context.channel().frequency_mhz);
        Self::hardware(self.device.tune(&context.definition(), false, eirp_mbm))?;
        self.tuned = Some(context.channel());
        Self::hardware(self.device.prepare_transmit())?;
        let slot = follow::short_slot(context.channel().band, context.beacon().capabilities);
        if let Some(wmm) = &context.negotiated().wmm {
            Self::hardware(self.device.set_edca(&wmm.access_categories, slot))?;
        }
        let following = follow::Following::new(&context, self.clock.now_us());
        let width = following.width();
        self.following = Some(following);
        Self::hardware(self.device.joined(self.address, &context, width))?;
        self.no_amsdu = [false; 8];
        self.rate_amsdu = 0;
        self.context = Some(context.clone());
        self.station
            .complete_configuration(ticket, Completion::Accepted, self.clock.now_us())
            .map_err(Error::Station)?;
        if context.negotiated().ht.is_some() {
            self.station
                .configure_rx_block_ack(RECEIVE_WINDOW, true)
                .map_err(|_| Error::Refused("Block Ack limits"))?;
            self.station
                .configure_tx_block_ack(TRANSMIT_WINDOW)
                .map_err(|_| Error::Refused("Block Ack limits"))?;
        }
        Ok(())
    }

    fn send_control(&mut self, ethernet: &[u8], key: Option<KeyIdentity>) -> Result<(), Error> {
        let class = key.map_or(TxClass::ControlPortPlaintext, TxClass::ControlPortProtected);
        self.send(ethernet, class)
    }

    /// `set_key`: the key table takes CCMP-128 alone of what a station uses,
    /// and a TKIP group key where the chip takes TKIP. One that refuses it,
    /// as `rtw89_cam_sec_key_add` does without `hw_tkip_crypto`, leaves the
    /// TKIP group key to the host, which decrypts under it as mac80211 does
    /// and tells the chip nothing.
    fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        receive: ReplaySeed,
    ) -> Result<KeyIdentity, Error> {
        // rtw88 takes a TKIP key's temporal half and leaves Michael to
        // mac80211.
        let cipher = if material.len() == Cipher::Ccmp128.key_length() {
            Cipher::Ccmp128
        } else if !pairwise && material.len() == Cipher::Tkip.key_length() {
            Cipher::Tkip
        } else {
            return Err(Error::Lacks {
                what: "a key other than CCMP-128 or a TKIP group key",
                chip: D::CHIP,
            });
        };
        let hardware = cipher != Cipher::Tkip || D::HARDWARE_TKIP;
        let temporal = material
            .first_chunk::<16>()
            .ok_or(Error::Refused("key material"))?;
        let peer = self
            .station
            .pairwise_peer()
            .ok_or(Error::Refused("no peer"))?;
        let scope = if pairwise {
            KeyScope::Pairwise(peer)
        } else {
            KeyScope::Group(peer)
        };
        let transmit = if pairwise {
            TransmitSeed::host(PacketNumber::new(0).ok_or(Error::Refused("packet number"))?)
        } else {
            TransmitSeed::RECEIVE_ONLY
        };
        // SAFETY: the counter gives each key of the adapter its own slot.
        let mut slot = unsafe { KeySlot::new(self.next_slot) }.map_err(Error::Key)?;
        self.next_slot = self.next_slot.wrapping_add(1);
        let ticket = slot
            .begin_install(index, cipher, material, receive, scope, transmit)
            .map_err(Error::Key)?;
        let identity = ticket.identity();
        let entry = if pairwise { PAIRWISE_CAM } else { index };
        let replaced = self
            .keys
            .iter()
            .position(|key| key.pairwise == pairwise && key.index == index);
        if hardware {
            Self::hardware(self.device.write_key(&KeyEntry {
                entry,
                index,
                cipher,
                group: !pairwise,
                peer: if pairwise { peer } else { Mac::BROADCAST },
                material: temporal,
            }))?;
        } else if let Some(old) = replaced.filter(|&old| self.keys[old].hardware) {
            // `ieee80211_key_replace`: the key the CAM held at this index
            // leaves it.
            Self::hardware(self.device.clear_key(self.keys[old].entry))?;
        }
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .map_err(Error::Key)?;
        if let Some(old) = replaced {
            self.keys.remove(old);
        }
        self.keys.push(Key {
            slot,
            pairwise,
            index,
            entry,
            hardware,
            material: Zeroizing::new(material.to_vec()),
        });
        // A group key installed while the port is open is a group
        // handshake's rekey, which the keeper installs only once its message
        // 1 was authenticated: the port is authorized again with it, so the
        // AP's frames under the new GTK pass, as mac80211 takes them under
        // the group key it was last given.
        if !pairwise && self.port_open {
            let epoch = self
                .station
                .association_epoch()
                .ok_or(Error::Refused("no association"))?;
            self.authorize_port(epoch)?;
        }
        Ok(identity)
    }

    fn install_link_key(&mut self, _: u8, _: u8, _: &[u8], _: ReplaySeed) -> Result<(), Error> {
        Err(Error::Lacks {
            what: "MLO",
            chip: D::CHIP,
        })
    }

    /// The IGTK stays in the host, where mac80211 runs BIP for rtw88.
    unsafe fn install_management_key(
        &mut self,
        _: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        let cipher = self
            .management_cipher
            .ok_or(Error::Refused("no management cipher"))?;
        let gtk = self
            .keys
            .iter()
            .rev()
            .find(|key| !key.pairwise)
            .and_then(|key| key.slot.installed())
            .ok_or(Error::Pending)?;
        self.integrity = Some(
            BipKey::new(gtk, cipher, index, material, receive)
                .map_err(|_| Error::Refused("the IGTK"))?,
        );
        Ok(Arc::new(ManagementKey))
    }

    unsafe fn rotate_management_key(
        &mut self,
        _: &Arc<ManagementKey>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<ManagementKey>, Error> {
        // SAFETY: forwarded from the keeper.
        unsafe { self.install_management_key(0, index, material, receive) }
    }

    fn authorize_port(&mut self, epoch: u64) -> Result<(), Error> {
        let context = self.context.clone().ok_or(Error::Refused("no context"))?;
        let ptk = self
            .keys
            .iter()
            .find(|key| key.pairwise)
            .ok_or(Error::Refused("no pairwise key"))?;
        let gtk = self
            .keys
            .iter()
            .rev()
            .find(|key| !key.pairwise)
            .ok_or(Error::Refused("no group key"))?;
        let links = [(&ptk.slot, &gtk.slot)];
        if self.station.requires_protected_management() {
            self.station
                .authorize_protected_port(&context, epoch, &links)
        } else {
            self.station.authorize_port(epoch, &links)
        }
        .map_err(Error::Station)?;
        self.port_open = true;
        Ok(())
    }

    fn deauthenticate(&mut self, reason: u16) -> Result<(), Error> {
        if self.left || self.station.phase() == Peering::Idle {
            return Ok(());
        }
        if let Ok((local, ap)) = self.station.addresses() {
            let protected = self.station.protected_port_authorized();
            let bytes = management(local, ap, 0xc0, protected, &reason.to_le_bytes());
            self.outbox.push_back((None, bytes));
            self.send_management()?;
        }
        let action = self.station.disconnect().map_err(Error::Station)?;
        self.act(action);
        Ok(())
    }

    unsafe fn retire_peer(&mut self) -> Result<(), Error> {
        if let Some(ticket) = self.departing {
            self.station
                .complete_removal(ticket, Completion::Accepted)
                .map_err(Error::Station)?;
        }
        self.clear()
    }
}

mod follow;
#[cfg(test)]
mod tests;
