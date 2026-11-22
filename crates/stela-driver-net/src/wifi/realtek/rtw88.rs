// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! rtw88's half of the softMAC station, from pinned rtw88 `main.c`, `tx.c`,
//! `fw.c` and `mac80211.c`: the descriptor each frame leaves behind, the C2H
//! reports the station acts on, and the mailbox commands that tell firmware of
//! an association. Any [`Rtw88`] chip is a station [`Device`] by them.
use super::{
    bit_rate,
    commands::{self, RateInfo, Report},
    descriptor::{
        Aggregate, Packet, QSEL_MANAGEMENT, RATE_1M, RATE_6M, RATE_ID_B, RATE_ID_G, SECURITY_CCMP,
    },
    dynamic,
    station::{self, Data, Device, KeyEntry, Management, Queue, Reported, Watched, peer_stbc},
    templates::{self, Templates},
    transmit,
};
use crate::{
    Mac,
    wifi::{
        Band,
        security::Cipher,
        station::{
            AssociationContext,
            operations::ChannelDefinition,
            phy::{AccessCategory, Width},
        },
    },
};
use alloc::{format, string::String};

/// rtw88's sole station shares its interface's MAC ID, the first it acquires.
pub const MAC_ID: u8 = 0;
/// `rtw_ops_add_interface`'s first port.
pub const PORT: u8 = 0;
/// `RTW_CAM_TKIP` and `RTW_CAM_AES`.
pub const CAM_TKIP: u8 = 2;
pub const CAM_AES: u8 = 4;

/// What an rtw88 chip gives the host.
pub type Incoming = station::Incoming<Report>;

/// The key `rtw_sec_write_cam` writes to a CAM entry.
pub struct CamKey<'a> {
    pub entry: u8,
    pub index: u8,
    pub kind: u8,
    pub group: bool,
    pub peer: Mac,
    pub material: &'a [u8; 16],
}

/// What an rtw88 chip does beneath the station. Each operation is the hardware
/// half of the mac80211 or rtw88 operation it names.
pub trait Rtw88 {
    /// `rtw_set_channel`. While `scanning`, no calibration follows.
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String>;
    /// `rtw_chip_prepare_tx`: calibrate for the channel a frame will leave on.
    fn prepare_transmit(&mut self) -> Result<(), String>;
    /// `rtw_pci_tx_write_data` and its kick. False asks to try again.
    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String>;
    /// `rtw_pci_rx_napi`: what arrived since the last look.
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String>;
    /// One H2C mailbox command.
    fn command(&mut self, command: (u32, u32)) -> Result<(), String>;
    /// `rtw_vif_port_config` of the BSSID, AID and link state.
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String>;
    /// `rtw_ops_configure_filter`: keep only the BSS's own beacons, or all.
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String>;
    /// `__rtw_conf_tx` of every access category.
    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String>;
    fn write_key(&mut self, key: &CamKey<'_>) -> Result<(), String>;
    fn clear_key(&mut self, entry: u8) -> Result<(), String>;
    /// `rtw_fw_download_rsvd_page` and `rtw_send_rsvd_page_h2c`.
    fn set_templates(&mut self, _templates: &Templates) -> Result<(), String> {
        Ok(())
    }
    /// `rtw_enter_lps` and `rtw_leave_lps`, which each stand for being there.
    fn set_power_save(&mut self, _on: bool) -> Result<(), String> {
        Ok(())
    }
    /// The beacons' interval and DTIM period.
    fn set_beacon(&mut self, _interval_tu: u16, _dtim_period: u8) -> Result<(), String> {
        Ok(())
    }
    /// `rtw_vif_smps_iter`: the next change to one stream or back to two.
    fn stream_change(&mut self) -> Option<bool> {
        None
    }
    /// A look at the Bluetooth arbiter's timers, at `now`.
    fn coexist(&mut self, _now: u64) -> Result<(), String> {
        Ok(())
    }
    /// `rtw_watch_dog_work`'s traffic accounts, and unless `scanning` its work
    /// on the air, for a peer that takes STBC or not.
    fn watchdog(&mut self, _scanning: bool, _stbc: bool) -> Result<Watched, String> {
        Ok(Watched::default())
    }
    /// `rtw_core_scan_start` and `rtw_core_scan_complete`'s gain.
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
}

/// `enum rtw_bandwidth`.
fn width_code(width: Width) -> u8 {
    match width {
        Width::Mhz80 => 2,
        Width::Mhz40 => 1,
        _ => 0,
    }
}

/// `rtw_update_sta_info`'s rate ID and what it tells firmware of the peer, on
/// a link `width` wide.
pub(super) fn rate_info(
    context: &AssociationContext,
    width: Width,
    initial: bool,
    level: u8,
) -> RateInfo {
    let negotiated = context.negotiated();
    let band = context.channel().band;
    let ht = negotiated.ht.as_ref();
    let vht = negotiated.vht.as_ref();
    let legacy = u64::from(negotiated.legacy.supported);
    let streams = if ht.is_some_and(|ht| ht.peer_rx_mcs[1] != 0) || vht.is_some() {
        2
    } else {
        1
    };
    // CCK in bits 0..4, OFDM in 4..12, then HT's or VHT's rates.
    let mut mask = if band == Band::Ghz2 {
        legacy
    } else {
        legacy << 4
    };
    if let Some(vht) = vht {
        mask |= vht_mask(vht.mcs.rx);
    } else if let Some(ht) = ht {
        mask |= (u64::from(ht.peer_rx_mcs[1]) << 20) | (u64::from(ht.peer_rx_mcs[0]) << 12);
    }
    let cck_only = band == Band::Ghz2 && vht.is_none() && ht.is_none() && legacy <= 0xf;
    let mask = dynamic::rates_at_level(mask, level, cck_only);
    let width = width_code(width);
    // `get_rate_id`.
    let rate_id = match (band, vht.is_some(), ht.is_some(), streams, width) {
        (Band::Ghz2, true, _, 2, _) => 12,
        (Band::Ghz2, true, _, _, _) => 11,
        (_, true, _, 2, _) => 9,
        (_, true, _, _, _) => 10,
        (Band::Ghz2, _, true, 2, 1) => 0,
        (Band::Ghz2, _, true, 1, 1) => 1,
        (Band::Ghz2, _, true, 2, _) => 2,
        (Band::Ghz2, _, true, _, _) => 3,
        (_, _, true, 2, _) => 4,
        (_, _, true, _, _) => 5,
        (Band::Ghz2, ..) if legacy <= 0xf => RATE_ID_B,
        (Band::Ghz2, ..) => 6,
        _ => RATE_ID_G,
    };
    RateInfo {
        mac_id: MAC_ID,
        rate_id,
        initial_level: u8::from(initial),
        short_gi: match width {
            2 => vht.is_some_and(|vht| vht.capability & (1 << 5) != 0),
            1 => ht.is_some_and(|ht| ht.capability & (1 << 6) != 0),
            _ => ht.is_some_and(|ht| ht.capability & (1 << 5) != 0),
        },
        width,
        ldpc: vht.map_or(ht.is_some_and(|ht| ht.capability & 1 != 0), |vht| {
            vht.capability & (1 << 4) != 0
        }),
        no_update: !initial,
        vht: if vht.is_some() { 2 } else { 0 },
        mask: mask as u32,
    }
}

/// `get_vht_ra_mask`, of the two streams firmware's 32-bit mask reaches.
fn vht_mask(map: u16) -> u64 {
    let stream = |map: u16| match map & 3 {
        0 => 0x0ff,
        1 => 0x1ff,
        2 => 0x3ff,
        _ => 0,
    };
    (stream(map) << 12) | (stream(map >> 2) << 22)
}

/// `get_highest_vht_tx_rate` and `get_highest_ht_tx_rate`: the rate firmware's
/// rate adaptation starts a frame's descriptor from.
fn highest_rate(context: &AssociationContext) -> u8 {
    let negotiated = context.negotiated();
    if let Some(vht) = &negotiated.vht {
        match (vht.mcs.tx >> 2) & 3 {
            0 => 0x3d,
            1 => 0x3e,
            _ => 0x3f,
        }
    } else if let Some(ht) = &negotiated.ht {
        if ht.peer_rx_mcs[1] != 0 { 0x1b } else { 0x13 }
    } else if negotiated.legacy.supported <= 0xf {
        3
    } else {
        0x0b
    }
}

impl<T: Rtw88> Device for T {
    type Descriptor = Packet;
    type Report = Report;
    const MAX_FRAME: usize = transmit::MAX_FRAME;

    /// `rtw_tx_mgmt_pkt_info_update`.
    fn management(&self, frame: &Management<'_>) -> Packet {
        let (rate_id, lowest) = if frame.band == Band::Ghz2 {
            (RATE_ID_B, RATE_1M)
        } else {
            (RATE_ID_G, RATE_6M)
        };
        let rate = frame
            .basic
            .filter(|&basic| basic != 0)
            .map_or(lowest, |basic| lowest + basic.trailing_zeros() as u8);
        Packet {
            size: frame.mpdu.len() as u16,
            multicast: frame.mpdu[4] & 1 != 0,
            mac_id: MAC_ID,
            queue: QSEL_MANAGEMENT,
            rate_id,
            report: frame.report,
            fixed_rate: true,
            rate,
            device_sequence: true,
            ..Packet::default()
        }
    }

    /// `rtw_tx_data_pkt_info_update`, with a CCMP frame's key type.
    fn data(&self, frame: &Data<'_>) -> Packet {
        let (mpdu, context) = (frame.mpdu, frame.context);
        let info = rate_info(context, frame.width, false, 0);
        let aggregate = context
            .negotiated()
            .ht
            .as_ref()
            .filter(|_| frame.aggregate)
            .map(|ht| {
                Aggregate::from_ht(ht.peer_ampdu_base_exponent | (ht.peer_mpdu_spacing << 2))
            });
        Packet {
            size: mpdu.len() as u16,
            multicast: mpdu[4] & 1 != 0,
            mac_id: MAC_ID,
            queue: frame.tid.unwrap_or(0),
            rate_id: info.rate_id,
            security: if frame.protected { SECURITY_CCMP } else { 0 },
            rate: highest_rate(context),
            width: info.width,
            ldpc: info.ldpc,
            stbc: u8::from(peer_stbc(context)),
            aggregate,
            // `rtw_tx_pkt_info_update`: mac80211 numbers a data frame.
            sequence: u16::from_le_bytes([mpdu[22], mpdu[23]]) >> 4,
            ..Packet::default()
        }
    }

    /// A null on the voice TID, which the device numbers.
    fn null(&self, frame: &Data<'_>, report: u8) -> Packet {
        let context = frame.context;
        let info = rate_info(context, frame.width, false, 0);
        Packet {
            size: frame.mpdu.len() as u16,
            mac_id: MAC_ID,
            queue: 7,
            rate_id: info.rate_id,
            rate: highest_rate(context),
            width: info.width,
            ldpc: info.ldpc,
            stbc: u8::from(peer_stbc(context)),
            report: Some(report),
            device_sequence: true,
            ..Packet::default()
        }
    }

    /// `rtw_tx_report_handle`, and `rtw_fw_ra_report_iter`'s
    /// `max_rc_amsdu_len` on `width` when firmware does not name one.
    fn reported(&self, report: &Report, width: Width) -> Option<Reported> {
        match *report {
            Report::Transmitted {
                number,
                acknowledged,
            } => Some(Reported::Transmitted {
                number,
                acknowledged,
            }),
            Report::Rate {
                mac_id: MAC_ID,
                rate,
                short_gi,
                width: reported,
            } => {
                let width = reported.unwrap_or_else(|| width_code(width));
                let rate = bit_rate::bit_rate(rate, short_gi, width);
                Some(Reported::Amsdu(bit_rate::max_amsdu(rate)))
            }
            _ => None,
        }
    }

    /// `rtw_sta_add`'s `rtw_update_sta_info` and media status, then
    /// `rtw_ops_bss_info_changed`'s port, beacon, reserved pages and default
    /// port.
    fn joined(
        &mut self,
        local: Mac,
        context: &AssociationContext,
        width: Width,
    ) -> Result<(), String> {
        let info = rate_info(context, width, true, 0);
        self.command(commands::ra_info(info))?;
        self.command(commands::media_status(MAC_ID, true))?;
        let aid = context.response().aid & 0x7ff;
        Rtw88::set_port(self, context.bssid(), aid, true)?;
        let interval = context.beacon().beacon_interval;
        self.set_beacon(interval, context.dtim_period())?;
        let wmm = context.negotiated().wmm.is_some();
        let band = context.channel().band;
        let pages = templates::build(local, context.bssid(), aid, wmm, band);
        self.set_templates(&pages)?;
        self.command(commands::default_port(PORT, MAC_ID))
    }

    /// `rtw_sta_remove`'s media status.
    fn left(&mut self) -> Result<(), String> {
        self.command(commands::media_status(MAC_ID, false))
    }

    /// `rtw_update_sta_info`, whose `reset_ra_mask` is `reset`.
    fn refresh_rates(
        &mut self,
        context: &AssociationContext,
        width: Width,
        level: u8,
        reset: bool,
    ) -> Result<(), String> {
        let info = rate_info(context, width, reset, level);
        self.command(commands::ra_info(info))
    }

    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String> {
        Rtw88::tune(self, definition, scanning, eirp_mbm)
    }

    fn prepare_transmit(&mut self) -> Result<(), String> {
        Rtw88::prepare_transmit(self)
    }

    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String> {
        Rtw88::transmit(self, queue, packet, mpdu)
    }

    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String> {
        Rtw88::receive(self, sink)
    }

    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String> {
        Rtw88::set_port(self, bssid, aid, linked)
    }

    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String> {
        Rtw88::filter_beacons(self, own_only)
    }

    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String> {
        Rtw88::set_edca(self, edca, short_slot)
    }

    /// `rtw_ops_set_key`'s CAM type of the key's cipher.
    fn write_key(&mut self, key: &KeyEntry<'_>) -> Result<(), String> {
        let kind = match key.cipher {
            Cipher::Ccmp128 => CAM_AES,
            Cipher::Tkip => CAM_TKIP,
            cipher => return Err(format!("{cipher:?} in rtw88's CAM")),
        };
        Rtw88::write_key(
            self,
            &CamKey {
                entry: key.entry,
                index: key.index,
                kind,
                group: key.group,
                peer: key.peer,
                material: key.material,
            },
        )
    }

    fn clear_key(&mut self, entry: u8) -> Result<(), String> {
        Rtw88::clear_key(self, entry)
    }

    fn set_power_save(&mut self, on: bool) -> Result<(), String> {
        Rtw88::set_power_save(self, on)
    }

    fn stream_change(&mut self) -> Option<bool> {
        Rtw88::stream_change(self)
    }

    fn coexist(&mut self, now: u64) -> Result<(), String> {
        Rtw88::coexist(self, now)
    }

    fn watchdog(&mut self, scanning: bool, stbc: bool) -> Result<Watched, String> {
        Rtw88::watchdog(self, scanning, stbc)
    }

    fn scanning(&mut self, scanning: bool) -> Result<(), String> {
        Rtw88::scanning(self, scanning)
    }

    fn signals(&self) -> bool {
        Rtw88::signals(self)
    }

    fn limitation(&mut self) -> Option<&'static str> {
        Rtw88::limitation(self)
    }
}
