// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! Listening on a tuned RTL8852BE: RXQ polled for a while, each buffer read
//! as rtw89 reads it ([`super::rxdesc`]), and what was heard tallied for the
//! Wi-Fi check: every BSSID whose beacons arrived, with its SSID, its
//! count, its best signal and the channel its elements name, and a count of
//! every packet by kind, so that a listen that heard no beacon can be told
//! apart from one that heard nothing at all.
//!
//! From rtw89 and cfg80211:
//! - [`Frame::parse`]'s channel is `rtw89_core_update_rx_freq_from_ie`
//!   (core.c) as it runs while rtw89 scans, on a beacon or probe response:
//!   `cfg80211_get_ies_channel_number` (net/wireless/scan.c) over the
//!   elements behind the fixed fields, the DS parameter set's one byte
//!   first, else the HT operation's primary channel. The pinned reference
//!   tree holds rtw89 alone, so this is written from cfg80211's documented
//!   behavior and checked by tests here, not by a C oracle. Like rtw89, it
//!   walks the frame with its FCS ([`FCS_LEN`]): rtw89 sets
//!   `RX_INCLUDES_FCS`.
//! - The polling is `rtw89_pci_poll_rxq_dma` on RXQ without NAPI's budget
//!   accounting or interrupts: Stela polls ([`Rings::deliver`]).
//!
//! Stela's own: the SSID element and BSSID read for the tally, without the
//! FCS, and the tally itself, with, beside the signal rtw89 reports, how
//! many of a BSSID's beacons had an A1-matched PPDU status and the best
//! signal of the PHY status header alone ([`Bss::header_best`]): rtw89
//! corrects the header's RSSI by IE01's FD average, which it reads of an
//! A1-matched status only, so a beacon whose status is not A1-matched
//! reports the header's RSSI less its own average. Nothing here transmits;
//! a beacon heard proves the radio receives on the channel, its BSSID that
//! the frame was read whole, its signal what the chip's PHY status said.
use super::{
    io::Io,
    pci::ring::{self, Received, Rings, RxChannel},
    rxdesc::{Delivered, Error, Sorted, Sorter, rssi_raw_to_dbm, split},
};
use crate::Clock;
use alloc::vec::Vec;

/// `FCS_LEN`.
pub const FCS_LEN: usize = 4;
/// `offsetof(struct ieee80211_mgmt, u.beacon.variable)`: the header, the
/// timestamp, the interval and the capabilities.
pub const BEACON_FIXED: usize = 36;
/// `WLAN_EID_SSID`, `WLAN_EID_DS_PARAMS` and `WLAN_EID_HT_OPERATION`.
pub const EID_SSID: u8 = 0;
pub const EID_DS_PARAMS: u8 = 3;
pub const EID_HT_OPERATION: u8 = 61;
/// `sizeof(struct ieee80211_ht_operation)`.
pub const HT_OPERATION_LEN: usize = 22;
/// The frame control's type and subtype bits and the two subtypes read.
pub const FCTL_FTYPE: u16 = 0x000c;
pub const FCTL_STYPE: u16 = 0x00f0;
pub const STYPE_PROBE_RESP: u16 = 0x0050;
pub const STYPE_BEACON: u16 = 0x0080;
/// The most BSSIDs the tally keeps; later ones are counted, not kept.
pub const MAX_BSS: usize = 64;
/// How many buffers one poll takes at most, as NAPI's budget would.
pub const BUDGET: u32 = 64;

/// What the tally keeps of a frame.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Frame {
    /// The frame control field, or `None` for a frame shorter than it.
    pub fc: Option<u16>,
    /// A beacon's or probe response's BSSID (address 3).
    pub bssid: Option<[u8; 6]>,
    /// Its SSID element, at most 32 bytes.
    pub ssid: Option<Vec<u8>>,
    /// The channel its elements name, as rtw89 reads it while scanning.
    pub channel: Option<u8>,
}

impl Frame {
    /// The kind of frame: management 0, control 1, data 2, extension 3.
    pub fn ftype(&self) -> Option<u8> {
        self.fc.map(|fc| ((fc & FCTL_FTYPE) >> 2) as u8)
    }

    pub fn is_beacon(&self) -> bool {
        self.fc
            .is_some_and(|fc| fc & (FCTL_FTYPE | FCTL_STYPE) == STYPE_BEACON)
    }

    pub fn is_probe_resp(&self) -> bool {
        self.fc
            .is_some_and(|fc| fc & (FCTL_FTYPE | FCTL_STYPE) == STYPE_PROBE_RESP)
    }

    /// The frame `data` as the chip wrote it, its FCS included.
    pub fn parse(data: &[u8]) -> Self {
        let mut frame = Self::default();
        if data.len() < 2 {
            return frame;
        }
        frame.fc = Some(u16::from_le_bytes([data[0], data[1]]));
        if !(frame.is_beacon() || frame.is_probe_resp()) || data.len() <= BEACON_FIXED {
            return frame;
        }
        let mut bssid = [0; 6];
        bssid.copy_from_slice(&data[16..22]);
        frame.bssid = Some(bssid);
        // rtw89_core_update_rx_freq_from_ie: the elements with the FCS.
        frame.channel = ies_channel_number(&data[BEACON_FIXED..]);
        let body = &data[BEACON_FIXED..data.len().saturating_sub(FCS_LEN).max(BEACON_FIXED)];
        frame.ssid = find_elem(body, EID_SSID).map(|ssid| ssid[..ssid.len().min(32)].to_vec());
        frame
    }
}

/// `cfg80211_find_elem`: the first element `id` whose data lies within
/// `ies`, the walk ending at the first element that does not.
pub fn find_elem(ies: &[u8], id: u8) -> Option<&[u8]> {
    let mut pos = 0;
    while ies.len() - pos >= 2 {
        let len = usize::from(ies[pos + 1]);
        if ies.len() - pos < 2 + len {
            return None;
        }
        if ies[pos] == id {
            return Some(&ies[pos + 2..pos + 2 + len]);
        }
        pos += 2 + len;
    }
    None
}

/// `cfg80211_get_ies_channel_number(ie, ielen, NL80211_BAND_2GHZ)`: a DS
/// parameter set of one byte, else an HT operation's primary channel.
pub fn ies_channel_number(ies: &[u8]) -> Option<u8> {
    if let Some(ds) = find_elem(ies, EID_DS_PARAMS)
        && ds.len() == 1
    {
        return Some(ds[0]);
    }
    find_elem(ies, EID_HT_OPERATION)
        .filter(|ht| ht.len() >= HT_OPERATION_LEN)
        .map(|ht| ht[0])
}

/// Every packet heard, by kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// RXQ buffers taken.
    pub buffers: u32,
    /// Buffers not read: a segment, or fewer bytes than the descriptor.
    pub segmented: u32,
    pub truncated: u32,
    /// Frames (`RTW89_CORE_RX_TYPE_WIFI`) delivered, by frame control type.
    pub wifi: u32,
    pub mgmt: u32,
    pub ctrl: u32,
    pub data: u32,
    pub extension: u32,
    /// Frames too short for a frame control field.
    pub runt: u32,
    pub beacons: u32,
    pub probe_resps: u32,
    /// Frames the descriptor marks with a CRC32 or ICV error.
    pub crc32_err: u32,
    pub icv_err: u32,
    /// Frames delivered with a PPDU status that matched them.
    pub matched: u32,
    pub c2h: u32,
    /// PPDU statuses, and those whose PHY status parsed.
    pub ppdu: u32,
    pub ppdu_valid: u32,
    /// Packets of another type, which rtw89 drops.
    pub other: u32,
}

/// One BSSID whose beacons were heard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bss {
    pub bssid: [u8; 6],
    /// The SSID of its last beacon.
    pub ssid: Vec<u8>,
    pub beacons: u32,
    /// The best signal among its beacons that had one, in dBm.
    pub best: Option<i8>,
    /// Its beacons delivered with an A1-matched PPDU status, whose signal
    /// took IE01's FD average.
    pub a1: u32,
    /// The best of its beacons' PHY status headers' signal, the stronger of
    /// paths A and B as `RTW89_RSSI_RAW_TO_DBM` reads them before the RPL
    /// correction, in dBm.
    pub header_best: Option<i8>,
    /// The channel its last beacon's elements named.
    pub channel: Option<u8>,
    /// The frequency its last beacon was received at, as rtw89 reports it.
    pub freq: u32,
}

/// What a listen heard.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Heard {
    pub counts: Counts,
    /// In the order first heard.
    pub bss: Vec<Bss>,
    /// BSSIDs past [`MAX_BSS`], counted, not kept.
    pub more_bss: u32,
    /// How long the listen ran, when the clock counted.
    pub listened_us: Option<u64>,
}

impl Heard {
    /// The BSSID heard with the best signal, else the one heard most.
    pub fn strongest(&self) -> Option<&Bss> {
        self.bss.iter().max_by(|a, b| {
            (a.best.is_some(), a.best, a.beacons).cmp(&(b.best.is_some(), b.best, b.beacons))
        })
    }

    /// Every beacon heard.
    pub fn beacons(&self) -> u32 {
        self.counts.beacons
    }

    /// Tally one delivered frame.
    fn frame(&mut self, delivered: Delivered<Frame>) {
        let Delivered {
            status,
            desc,
            ppdu,
            frame,
        } = delivered;
        let counts = &mut self.counts;
        counts.wifi += 1;
        counts.crc32_err += u32::from(desc.crc32_err);
        counts.icv_err += u32::from(desc.icv_err);
        counts.matched += u32::from(ppdu.is_some());
        match frame.ftype() {
            Some(0) => counts.mgmt += 1,
            Some(1) => counts.ctrl += 1,
            Some(2) => counts.data += 1,
            Some(_) => counts.extension += 1,
            None => counts.runt += 1,
        }
        if frame.is_probe_resp() {
            counts.probe_resps += 1;
        }
        // A beacon the chip found corrupt names no BSSID worth keeping.
        if !frame.is_beacon() || status.failed_fcs_crc {
            return;
        }
        counts.beacons += 1;
        let Some(bssid) = frame.bssid else {
            return;
        };
        let signal = (status.signal != 0).then_some(status.signal);
        let index = match self.bss.iter().position(|bss| bss.bssid == bssid) {
            Some(index) => index,
            None if self.bss.len() >= MAX_BSS => {
                self.more_bss += 1;
                return;
            }
            None => {
                self.bss.push(Bss {
                    bssid,
                    ssid: Vec::new(),
                    beacons: 0,
                    best: None,
                    a1: 0,
                    header_best: None,
                    channel: None,
                    freq: status.freq,
                });
                self.bss.len() - 1
            }
        };
        let bss = &mut self.bss[index];
        bss.beacons += 1;
        if let Some(ssid) = frame.ssid {
            bss.ssid = ssid;
        }
        if frame.channel.is_some() {
            bss.channel = frame.channel;
        }
        bss.freq = status.freq;
        if let Some(signal) = signal {
            bss.best = Some(bss.best.map_or(signal, |best| best.max(signal)));
        }
        if let Some(ppdu) = ppdu {
            bss.a1 += u32::from(ppdu.to_self);
            if let Some([a, b]) = ppdu.hdr_rssi {
                let header = rssi_raw_to_dbm(a.max(b));
                bss.header_best = Some(bss.header_best.map_or(header, |best| best.max(header)));
            }
        }
    }

    /// Tally one RXQ buffer, through `sorter`.
    pub fn buffer(&mut self, sorter: &mut Sorter<Frame>, received: Received<'_>) {
        self.counts.buffers += 1;
        let packet = match split(received.info, received.data) {
            Ok(packet) => packet,
            Err(Error::Segmented { .. }) => {
                self.counts.segmented += 1;
                return;
            }
            Err(Error::Truncated { .. }) => {
                self.counts.truncated += 1;
                return;
            }
        };
        let mut delivered = Vec::new();
        let sorted = sorter.receive(&packet, Frame::parse, |frame| delivered.push(frame));
        match sorted {
            Sorted::Wifi { .. } => {}
            Sorted::C2h => self.counts.c2h += 1,
            Sorted::PpduStatus { error, .. } => {
                self.counts.ppdu += 1;
                self.counts.ppdu_valid += u32::from(error.is_none());
            }
            Sorted::Unhandled(_) => self.counts.other += 1,
        }
        for frame in delivered {
            self.frame(frame);
        }
    }

    /// The frames still held go on without a PPDU status.
    pub fn finish(&mut self, sorter: &mut Sorter<Frame>) {
        let mut delivered = Vec::new();
        sorter.flush(&mut |frame| delivered.push(frame));
        for frame in delivered {
            self.frame(frame);
        }
    }
}

/// Take every filled RXQ buffer until none is left, tallying each into
/// `heard`, at most `limit` buffers. Returns how many were taken.
pub fn drain<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    sorter: &mut Sorter<Frame>,
    heard: &mut Heard,
    limit: u32,
) -> Result<u32, ring::Error> {
    let mut taken = 0;
    while taken < limit {
        let got = rings.deliver(io, RxChannel::Rxq, BUDGET.min(limit - taken), |received| {
            heard.buffer(sorter, received)
        })?;
        if got == 0 {
            break;
        }
        taken += got;
    }
    Ok(taken)
}

/// Poll RXQ for `duration_us` by `clock`, tallying every buffer into
/// `heard`; held frames go on at the end. A clock that does not count ends
/// the listen after one pass that finds RXQ empty.
pub fn listen<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    clock: Clock,
    duration_us: u64,
    sorter: &mut Sorter<Frame>,
    heard: &mut Heard,
) -> Result<(), ring::Error> {
    let start = clock.try_start().ok();
    loop {
        let got = rings.deliver(io, RxChannel::Rxq, BUDGET, |received| {
            heard.buffer(sorter, received)
        })?;
        let elapsed = start.and_then(|start| clock.try_elapsed_us(start).ok());
        match elapsed {
            Some(elapsed) if elapsed >= duration_us => {
                heard.listened_us = Some(elapsed);
                break;
            }
            Some(_) => {}
            None if got == 0 => break,
            None => {}
        }
    }
    heard.finish(sorter);
    Ok(())
}

#[cfg(test)]
mod tests;
