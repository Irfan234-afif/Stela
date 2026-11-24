// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2020 Realtek Corporation
//! How an RTL8852BE gives a sent frame back, as pinned rtw89 takes it
//! (pci.c, pci.h): the WD pages of one data channel and the release reports
//! (RPP) the chip writes to RPQ.
//!
//! - [`WdRing`]: `struct rtw89_pci_tx_wd_ring` with the ring's
//!   `busy_pages` list and the frame each page holds (`txwd->queue`), kept
//!   as rtw89 keeps them: `rtw89_pci_alloc_tx_wd_ring`'s 512 pages in order,
//!   `rtw89_pci_dequeue_txwd` and `rtw89_pci_enqueue_txwd`, the busy list
//!   `rtw89_pci_txbd_submit` appends to, `rtw89_pci_reclaim_txbd` once the
//!   hardware index has moved, `rtw89_pci_release_txwd_skb` for the page a
//!   report names, and `rtw89_pci_release_tx_ring` (`rtw89_pci_release_busy_txwd`
//!   and `rtw89_pci_release_pending_txwd_skb`), with the counters
//!   `rtw89_pci_txwd_submit` and `rtw89_pci_tx_status` keep ([`TxStats`]).
//!   A page goes back to the free list only once both its BD was read and
//!   its report came, in either order, so pages are reused and a frame is
//!   released by the WD page sequence number its report names, not in ring
//!   order.
//! - [`RppInfo::parse`]: `rtw89_pci_parse_rpp`, RTL8852BE's `parse_rpp`, with
//!   `rtw89_core_get_ch_dma` ([`super::super::txwd::ch_dma`]) for the ring,
//!   and [`RppInfo::target`], the checks `rtw89_pci_release_rpp` makes before
//!   it releases a page.
//! - [`reports`]: the walk `rtw89_pci_release_tx_skbs` makes over one RPQ
//!   buffer: the RX descriptor behind the `rtw89_pci_rxbd_info` dword, then
//!   one four-byte report after another up to the length the chip wrote.
//!
//! [`super::ring::Rings`] drives these over its DMA memory: submission,
//! `rtw89_pci_release_tx` over RPQ and `rtw89_pci_check_and_reclaim_tx_resource`.
//!
//! What this leaves out, and why: what `rtw89_pci_tx_status` and
//! `rtw89_core_tx_wait_complete` tell mac80211 (`ieee80211_tx_status_ni`,
//! the ACK and no-ACK flags, a waiting H2C's completion): a released frame
//! is handed back as a [`Completion`] with its [`TxStatus`] and the station
//! decides. rtw89's warnings (a report for a ring the chip lacks, a sequence
//! past the pages, an invalid status, a busy page whose BD the hardware has
//! not read) change nothing there and change nothing here. Low power mode,
//! which only softens one warning, is never entered. The v1 report format
//! of other chips.
//!
//! A report proves only that the chip's MAC let the frame go with the status
//! it names; nothing here shows the frame was on the air or acknowledged
//! beyond that status.
use super::super::{
    io::field,
    pci::ring::{RxBdInfo, TXWD_NUM_MAX, TXWD_PAGE_SIZE, TxChannel},
    rxdesc::{self, RxDescInfo},
    txwd,
};
use crate::bus::dma::memory::MemoryError;
use alloc::{collections::VecDeque, vec::Vec};

/// `sizeof(struct rtw89_pci_rpp_fmt)`: `rtw8852b_pci_info.rpp_fmt_size`.
pub const RPP_SIZE: usize = 4;
/// The `struct rtw89_pci_rpp_fmt` fields: `RTW89_PCI_RPP_*`.
pub const RPP_POLLUTED: u32 = 1 << 31;
pub const RPP_SEQ: u32 = 0x7fff_0000;
pub const RPP_TX_STATUS: u32 = 0x0000_e000;
pub const RPP_QSEL: u32 = 0x0000_1f00;
pub const RPP_MACID: u32 = 0x0000_00ff;
/// `RTW89_TX_DONE`, `RTW89_TX_RETRY_LIMIT`, `RTW89_TX_LIFE_TIME` and
/// `RTW89_TX_MACID_DROP`.
pub const TX_DONE: u8 = 0;
pub const TX_RETRY_LIMIT: u8 = 1;
pub const TX_LIFE_TIME: u8 = 2;
pub const TX_MACID_DROP: u8 = 3;

/// How the chip let a frame go, as a report's three status bits name it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxStatus {
    /// `RTW89_TX_DONE`: sent, and acknowledged where an ACK was due.
    Done,
    /// `RTW89_TX_RETRY_LIMIT`: no ACK within the retries.
    RetryLimit,
    /// `RTW89_TX_LIFE_TIME`: dropped when its lifetime ran out.
    LifeTime,
    /// `RTW89_TX_MACID_DROP`: dropped for its MAC ID, or released by a ring
    /// reset (`rtw89_pci_release_pending_txwd_skb`).
    MacidDrop,
    /// A value rtw89 warns of as an invalid TX status.
    Invalid(u8),
}

impl TxStatus {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            TX_DONE => Self::Done,
            TX_RETRY_LIMIT => Self::RetryLimit,
            TX_LIFE_TIME => Self::LifeTime,
            TX_MACID_DROP => Self::MacidDrop,
            other => Self::Invalid(other),
        }
    }

    pub const fn raw(self) -> u8 {
        match self {
            Self::Done => TX_DONE,
            Self::RetryLimit => TX_RETRY_LIMIT,
            Self::LifeTime => TX_LIFE_TIME,
            Self::MacidDrop => TX_MACID_DROP,
            Self::Invalid(raw) => raw,
        }
    }

    /// What `rtw89_pci_tx_status` reports to mac80211 as
    /// `IEEE80211_TX_STAT_ACK`.
    pub const fn acked(self) -> bool {
        matches!(self, Self::Done)
    }
}

/// `struct rtw89_pci_rpp_info`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RppInfo {
    pub seq: u16,
    pub qsel: u8,
    pub tx_status: u8,
    /// `enum rtw89_tx_channel`.
    pub txch: u8,
}

impl RppInfo {
    /// `rtw89_pci_parse_rpp`: the sequence, queue and status fields, and the
    /// queue's ring (`rtw89_chip_get_ch_dma`).
    pub const fn parse(dword: u32) -> Self {
        let qsel = field(dword, RPP_QSEL) as u8;
        Self {
            seq: field(dword, RPP_SEQ) as u16,
            qsel,
            tx_status: field(dword, RPP_TX_STATUS) as u8,
            txch: txwd::ch_dma(qsel),
        }
    }

    /// `rtw89_pci_release_rpp`'s checks: the ring and WD page the report
    /// names, or `None` where rtw89 warns and drops it (a ring past
    /// `RTW89_TXCH_NUM` or one `tx_dma_ch_mask` takes from the chip, a
    /// sequence past `RTW89_PCI_TXWD_NUM_MAX`).
    pub fn target(&self) -> Option<(TxChannel, u16)> {
        let txch = TxChannel::ALL.get(usize::from(self.txch)).copied()?;
        if !txch.present() || usize::from(self.seq) >= TXWD_NUM_MAX {
            return None;
        }
        Some((txch, self.seq))
    }

    pub const fn status(&self) -> TxStatus {
        TxStatus::from_raw(self.tx_status)
    }
}

/// The counters of one ring's `struct rtw89_pci_tx_ring`: frames submitted
/// (`rtw89_pci_txwd_submit`) and released by status (`rtw89_pci_tx_status`).
/// An invalid status counts nowhere, as in rtw89.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxStats {
    pub tx_cnt: u64,
    pub tx_acked: u64,
    pub tx_retry_lmt: u64,
    pub tx_life_time: u64,
    pub tx_mac_id_drop: u64,
}

impl TxStats {
    fn count(&mut self, status: TxStatus) {
        let counter = match status {
            TxStatus::Done => &mut self.tx_acked,
            TxStatus::RetryLimit => &mut self.tx_retry_lmt,
            TxStatus::LifeTime => &mut self.tx_life_time,
            TxStatus::MacidDrop => &mut self.tx_mac_id_drop,
            TxStatus::Invalid(_) => return,
        };
        *counter += 1;
    }
}

/// One frame the chip gave back: its ring, the sequence number of the WD
/// page that carried it (what [`super::ring::Rings::tx_write`] returned),
/// and the status its report named.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub txch: TxChannel,
    pub seq: u16,
    pub status: TxStatus,
}

/// The reports of one RPQ buffer, as `rtw89_pci_release_tx_skbs` walks
/// them: four bytes at a time from behind the RX descriptor, while a whole
/// report fits in what the chip wrote.
#[derive(Clone, Debug)]
pub struct Reports<'a> {
    data: &'a [u8],
    offset: usize,
    end: usize,
}

impl Iterator for Reports<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.offset + RPP_SIZE > self.end {
            return None;
        }
        let at = self.offset;
        self.offset += RPP_SIZE;
        Some(u32::from_le_bytes([
            self.data[at],
            self.data[at + 1],
            self.data[at + 2],
            self.data[at + 3],
        ]))
    }
}

/// `rtw89_pci_release_tx_skbs` over one RPQ buffer whose info is `info`:
/// a buffer that is not its packet's first and last segment is refused
/// ("cannot process RP frame not set FS/LS"), the descriptor is read at
/// `sizeof(struct rtw89_pci_rxbd_info)` of `buffer` (the whole buffer, as
/// rtw89 reads it from `skb->data`), and the reports run from behind it to
/// `info.len`. Where `info.len` claims more than `buffer` holds, the walk
/// stops at the buffer's end, where rtw89 would read past it.
pub fn reports(info: RxBdInfo, buffer: &[u8]) -> Result<Reports<'_>, rxdesc::Error> {
    if !(info.fs && info.ls) {
        return Err(rxdesc::Error::Segmented {
            fs: info.fs,
            ls: info.ls,
        });
    }
    let desc = RxDescInfo::query(buffer, super::super::c2h::RXBD_INFO_SIZE)?;
    Ok(Reports {
        data: buffer,
        offset: desc.packet_offset(),
        end: usize::from(info.len).min(buffer.len()),
    })
}

/// Which of rtw89's lists a WD page is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum List {
    /// `wd_ring->free_pages`.
    Free,
    /// `tx_ring->busy_pages`: its BD not yet read by the hardware.
    Busy,
    /// Neither (`list_empty(&txwd->list)`): its BD read, its report due.
    Idle,
}

struct Page<F> {
    list: List,
    /// `txwd->queue`: the frame the page carries, until its report.
    frame: Option<F>,
}

/// One data channel's WD pages, as rtw89 lists them, each with the frame
/// it carries (`F`, a DMA buffer in [`super::ring::Rings`]).
pub struct WdRing<F> {
    /// The device address of page 0; page `seq` is `TXWD_PAGE_SIZE` bytes
    /// on per sequence number.
    dma: u64,
    pages: Vec<Page<F>>,
    free: VecDeque<u16>,
    busy: VecDeque<u16>,
    stats: TxStats,
}

impl<F> WdRing<F> {
    /// `rtw89_pci_alloc_tx_wd_ring`'s bookkeeping: 512 pages from `dma` on,
    /// each enqueued free in sequence order.
    pub fn new(dma: u64) -> Result<Self, MemoryError> {
        let mut pages = Vec::new();
        let mut free = VecDeque::new();
        let mut busy = VecDeque::new();
        pages
            .try_reserve_exact(TXWD_NUM_MAX)
            .map_err(|_| MemoryError::OutOfMemory)?;
        free.try_reserve_exact(TXWD_NUM_MAX)
            .map_err(|_| MemoryError::OutOfMemory)?;
        busy.try_reserve_exact(TXWD_NUM_MAX)
            .map_err(|_| MemoryError::OutOfMemory)?;
        for seq in 0..TXWD_NUM_MAX as u16 {
            pages.push(Page {
                list: List::Free,
                frame: None,
            });
            free.push_back(seq);
        }
        Ok(Self {
            dma,
            pages,
            free,
            busy,
            stats: TxStats::default(),
        })
    }

    /// `txwd->paddr` of page `seq`.
    pub fn page_dma(&self, seq: u16) -> u64 {
        self.dma + u64::from(seq) * TXWD_PAGE_SIZE as u64
    }

    /// `wd_ring->curr_num`: the free pages.
    pub fn curr_num(&self) -> u32 {
        self.free.len() as u32
    }

    /// The pages on the busy list, oldest first.
    pub fn busy(&self) -> impl Iterator<Item = u16> + '_ {
        self.busy.iter().copied()
    }

    /// The page `rtw89_pci_dequeue_txwd` would take next.
    pub fn peek(&self) -> Option<u16> {
        self.free.front().copied()
    }

    /// Whether page `seq` still holds a frame awaiting its report.
    pub fn holds(&self, seq: u16) -> bool {
        self.pages
            .get(usize::from(seq))
            .is_some_and(|page| page.frame.is_some())
    }

    pub fn stats(&self) -> TxStats {
        self.stats
    }

    /// `rtw89_pci_txbd_submit`'s page work once `rtw89_pci_txwd_submit` has
    /// filled it: the next free page dequeued, `frame` queued on it,
    /// `tx_cnt` counted and the page added to the busy list. Hands `frame`
    /// back when no page is free ("no available TXWD").
    pub fn submit(&mut self, frame: F) -> Result<u16, F> {
        let Some(seq) = self.free.pop_front() else {
            return Err(frame);
        };
        let page = &mut self.pages[usize::from(seq)];
        page.frame = Some(frame);
        self.stats.tx_cnt += 1;
        page.list = List::Busy;
        self.busy.push_back(seq);
        Ok(seq)
    }

    /// `rtw89_pci_enqueue_txwd`; zeroing the page is the memory owner's.
    fn enqueue(&mut self, seq: u16) {
        self.pages[usize::from(seq)].list = List::Free;
        self.free.push_back(seq);
    }

    /// `rtw89_pci_reclaim_txbd` once `rtw89_pci_txbd_recalc` found `cnt` BDs
    /// read: that many pages leave the busy list, oldest first, and each
    /// whose frame its report already released goes back free. More BDs
    /// than busy pages stops at the last ("No busy txwd pages available").
    pub fn reclaim(&mut self, cnt: u32) {
        for _ in 0..cnt {
            let Some(seq) = self.busy.pop_front() else {
                break;
            };
            let page = &mut self.pages[usize::from(seq)];
            page.list = List::Idle;
            // this skb has been freed by RPP
            if page.frame.is_none() {
                self.enqueue(seq);
            }
        }
    }

    /// `rtw89_pci_release_txwd_skb` for page `seq` with `status`: a page
    /// still on a list first reclaims the BDs the hardware read, `recalc`
    /// counting them (`rtw89_pci_txbd_recalc`); then its frame, if any, is
    /// released and counted, and the page goes back free unless it is
    /// still on a list (a report before its BD was read, which rtw89 warns
    /// of, or a report for a free page). Returns the released frame.
    pub fn release<E>(
        &mut self,
        seq: u16,
        status: TxStatus,
        recalc: impl FnOnce() -> Result<u32, E>,
    ) -> Result<Option<F>, E> {
        let Some(page) = self.pages.get(usize::from(seq)) else {
            return Ok(None);
        };
        if page.list != List::Idle {
            let cnt = recalc()?;
            self.reclaim(cnt);
        }
        let page = &mut self.pages[usize::from(seq)];
        let frame = page.frame.take();
        let list = page.list;
        if frame.is_some() {
            self.stats.count(status);
        }
        if list == List::Idle {
            self.enqueue(seq);
        }
        Ok(frame)
    }

    /// `rtw89_pci_release_tx_ring`: every busy page leaves the busy list
    /// (`rtw89_pci_release_busy_txwd`), then every page on no list is
    /// released with `RTW89_TX_MACID_DROP` and goes back free
    /// (`rtw89_pci_release_pending_txwd_skb`), in sequence order; `released`
    /// takes each frame with its page's sequence.
    pub fn release_ring(&mut self, mut released: impl FnMut(u16, F)) {
        for _ in 0..self.pages.len() {
            let Some(seq) = self.busy.pop_front() else {
                break;
            };
            self.pages[usize::from(seq)].list = List::Idle;
        }
        for seq in 0..self.pages.len() as u16 {
            if self.pages[usize::from(seq)].list != List::Idle {
                continue;
            }
            let frame = self.pages[usize::from(seq)].frame.take();
            if let Some(frame) = frame {
                self.stats.count(TxStatus::MacidDrop);
                released(seq, frame);
            }
            self.enqueue(seq);
        }
    }

    /// Every frame still held, for a final release.
    pub fn frames_mut(&mut self) -> impl Iterator<Item = &mut F> {
        self.pages.iter_mut().filter_map(|page| page.frame.as_mut())
    }
}

#[cfg(test)]
mod tests;
