// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2020 Realtek Corporation
//! An RTL8852BE's PCIe buffer descriptor rings as pinned rtw89 lays them out
//! (pci.h) and keeps them (pci.c):
//!
//! - the BDs: `struct rtw89_pci_tx_bd_32` ([`TxBd`]), `struct
//!   rtw89_pci_rx_bd_32` ([`RxBd`]) and the `struct rtw89_pci_rxbd_info`
//!   dword the chip writes at the head of each RX buffer ([`RxBdInfo`]),
//!   encoded and decoded as pure functions;
//! - the index arithmetic: `rtw89_pci_dma_recalc` with `rtw89_pci_txbd_recalc`
//!   and `rtw89_pci_rxbd_recalc`, `rtw89_pci_get_avail_txbd_num`,
//!   `rtw89_pci_tx_bd_ring_update` and `rtw89_pci_rxbd_increase`;
//! - the RX tag check of `rtw89_pci_rxbd_deliver_skbs`:
//!   `rtw89_pci_validate_rx_tag` inside
//!   `rtw89_pci_sync_skb_for_device_and_validate_rx_info`'s retries;
//! - the firmware command queue, `h2c_queue` and `h2c_release_queue`, which
//!   `rtw89_pci_release_fwcmd` empties ([`FwCmdQueue`]);
//! - [`Rings`]: the part of `rtw89_pci_alloc_trx_rings` this step needs, and
//!   `rtw89_pci_ops_reset` with `rtw89_pci_reset_trx_rings`, which the PCIe
//!   pre-init ([`super::mac_pre_init`]) calls;
//! - the data path: `rtw89_pci_alloc_tx_wd_ring` ([`Rings::alloc_tx_wd`]),
//!   `rtw89_pci_ops_tx_write` with `rtw89_pci_txbd_submit`,
//!   `rtw89_pci_txwd_submit` and RTL885xB's `rtw89_pci_fill_txaddr_info`
//!   ([`Rings::tx_write`], over [`txbd_submit`], [`txwd_page`] and
//!   [`AddrInfo`]), `rtw89_pci_ops_tx_kick_off` ([`Rings::tx_kick_off`]),
//!   and the release: `rtw89_pci_poll_rpq_dma`'s ring work with
//!   `rtw89_pci_release_tx`, `rtw89_pci_release_tx_skbs` and
//!   `rtw89_pci_release_rpp` ([`Rings::poll_rpq`]), `rtw89_pci_reclaim_txbd`
//!   ([`Rings::reclaim_txbd`]) and `rtw89_pci_check_and_reclaim_tx_resource`
//!   ([`Rings::check_and_reclaim_tx_resource`]), over the WD pages and
//!   reports of [`super::release`].
//!
//! [`Rings::new`] allocates what rtw89 allocates for the rings, laid out as
//! rtw89 lays it out, so the addresses and sizes the pre-init programs are
//! rtw89's: one BD pool for the seven TX channels an RTL8852BE has
//! (`tx_dma_ch_mask` leaves out ACH4 to ACH7, CH10 and CH11), 256 BDs each,
//! one BD pool for RXQ and RPQ, 256 BDs each, and an 11498-byte buffer behind
//! every RX BD. Every allocation goes through
//! [`allocate_32bit`](crate::wifi::allocation::allocate_32bit), and an IOVA
//! that reaches above 4 GiB is refused: rtw89 gives RTL8852B a 32-bit DMA
//! mask behind a bridge `rtw89_pci_is_dac_compatible_bridge` does not name,
//! such as this AMD host's.
//!
//! What this leaves out, and why:
//! - When the WD pages are allocated: rtw89 allocates them with the rings at
//!   probe, Stela when the data path starts ([`Rings::alloc_tx_wd`]), after
//!   every RX buffer, so the allocations the pre-init programs stay where
//!   they were. Their BD rings are allocated and programmed with the others
//!   and stay stopped until the full MAC init enables them.
//! - `rtw89_pci_txwd_submit`'s mapping: a frame comes mapped ([`Buffer`]),
//!   so the page rtw89 puts back on a failed mapping is never taken. The WD
//!   page is written whole at submission, which leaves the bytes rtw89's
//!   zeroing at enqueue and its writes leave.
//! - `hci.paused`, its kick map and the no-I/O resource check: Stela never
//!   pauses the interface. Low power mode, never entered.
//! - Hardware indices outside a ring, where rtw89 would go on: refused
//!   ([`Error::Index`]) before anything moves, as for the command ring.
//! - An RPQ buffer the release cannot walk (a stale tag, or not FS and LS)
//!   is synced back for the device before the rest are skipped, where rtw89
//!   skips the sync for the latter.
//! - RX reassembly across segments (`fs`/`ls`), RX descriptor parsing and
//!   `diliver_skb`/`diliver_desc`: [`Rings::deliver`] hands each filled
//!   buffer, with its decoded info, to the caller.
//! - `rx_ring_eq_is_full`, `group_bd_addr` and `wp_sel_addr`, which
//!   `rtw8852b_pci_info` leaves false or 0, and every 36-bit DMA path.
//!
//! Handing a buffer to the device and reading the hardware's index prove
//! only DMA ownership: nothing here shows a command was accepted, a frame
//! sent, or that a received buffer holds a valid frame.
use super::super::{
    io::{self, Io, field, prep},
    registers::*,
};
use super::{
    super::txwd::DescInfo,
    release::{self, Completion, RppInfo, WdRing},
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping},
    memory::{CpuMapping, MemoryError, PageSource},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    ops::Range,
    sync::atomic::{Ordering, fence},
};

/// `RTW89_PCI_TXBD_NUM_MAX`: the BDs of every TX ring.
pub const TXBD_NUM_MAX: u32 = 256;
/// `RTW89_PCI_RXBD_NUM_MAX`: the BDs of every RX ring.
pub const RXBD_NUM_MAX: u32 = 256;
/// `RTW89_PCI_RX_BUF_SIZE`: 11454 bytes, 40 for `rtw89_rxdesc_long_v2` and
/// 4 for `rtw89_pci_rxbd_info`.
pub const RX_BUF_SIZE: usize = 11454 + 40 + 4;
/// `RTW89_PCI_MULTITAG`: the read command buffers `rtw89_pci_release_fwcmd`
/// keeps mapped.
pub const MULTITAG: usize = 8;
/// `RTW89_RX_TAG_MAX`: the RX tag's 13 bits.
pub const RX_TAG_MAX: u16 = 0x1fff;
/// `rtw89_pci_sync_skb_for_device_and_validate_rx_info`'s `rx_tag_retry`.
const RX_TAG_RETRY: u32 = 1000;
/// `rtw8852b_pci_info.check_rx_tag`.
pub const CHECK_RX_TAG: bool = false;

/// `enum rtw89_tx_channel`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum TxChannel {
    Ach0 = 0,
    Ach1 = 1,
    Ach2 = 2,
    Ach3 = 3,
    Ach4 = 4,
    Ach5 = 5,
    Ach6 = 6,
    Ach7 = 7,
    /// Management, band 0.
    Ch8 = 8,
    /// High, band 0.
    Ch9 = 9,
    /// Management, band 1.
    Ch10 = 10,
    /// High, band 1.
    Ch11 = 11,
    /// Firmware commands.
    Ch12 = 12,
}

/// `RTW89_TXCH_NUM`.
pub const TXCH_NUM: usize = 13;

/// `rtw8852b_pci_info.tx_dma_ch_mask`: the TX channels an RTL8852BE lacks.
pub const TX_DMA_CH_MASK: u32 = 1 << TxChannel::Ach4 as u32
    | 1 << TxChannel::Ach5 as u32
    | 1 << TxChannel::Ach6 as u32
    | 1 << TxChannel::Ach7 as u32
    | 1 << TxChannel::Ch10 as u32
    | 1 << TxChannel::Ch11 as u32;

impl TxChannel {
    /// Every channel, in rtw89's loop order.
    pub const ALL: [Self; TXCH_NUM] = [
        Self::Ach0,
        Self::Ach1,
        Self::Ach2,
        Self::Ach3,
        Self::Ach4,
        Self::Ach5,
        Self::Ach6,
        Self::Ach7,
        Self::Ch8,
        Self::Ch9,
        Self::Ch10,
        Self::Ch11,
        Self::Ch12,
    ];

    /// Whether `tx_dma_ch_mask` leaves the channel to the chip.
    pub const fn present(self) -> bool {
        TX_DMA_CH_MASK & (1 << self as u32) == 0
    }
}

/// `enum rtw89_rx_channel`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum RxChannel {
    /// Received frames and C2H.
    Rxq = 0,
    /// TX release reports.
    Rpq = 1,
}

/// `RTW89_RXCH_NUM`.
pub const RXCH_NUM: usize = 2;

impl RxChannel {
    pub const ALL: [Self; RXCH_NUM] = [Self::Rxq, Self::Rpq];
}

/// `struct rtw89_pci_ch_dma_addr`: the registers that name one ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChDmaAddr {
    pub num: u32,
    pub idx: u32,
    pub bdram: u32,
    pub desa_l: u32,
    pub desa_h: u32,
}

const fn tx_addr(num: u32, idx: u32, bdram: u32, desa_l: u32, desa_h: u32) -> ChDmaAddr {
    ChDmaAddr {
        num,
        idx,
        bdram,
        desa_l,
        desa_h,
    }
}

/// `rtw89_pci_ch_dma_addr_set.tx` (`rtw8852b_pci_info.dma_addr_set`):
/// `DEF_TXCHADDRS` for every channel, `DEF_TXCHADDRS_TYPE1` for CH10 and CH11.
pub const DMA_ADDR_SET_TX: [ChDmaAddr; TXCH_NUM] = [
    tx_addr(
        ACH0_TXBD_NUM,
        ACH0_TXBD_IDX,
        ACH0_BDRAM_CTRL,
        ACH0_TXBD_DESA_L,
        ACH0_TXBD_DESA_H,
    ),
    tx_addr(
        ACH1_TXBD_NUM,
        ACH1_TXBD_IDX,
        ACH1_BDRAM_CTRL,
        ACH1_TXBD_DESA_L,
        ACH1_TXBD_DESA_H,
    ),
    tx_addr(
        ACH2_TXBD_NUM,
        ACH2_TXBD_IDX,
        ACH2_BDRAM_CTRL,
        ACH2_TXBD_DESA_L,
        ACH2_TXBD_DESA_H,
    ),
    tx_addr(
        ACH3_TXBD_NUM,
        ACH3_TXBD_IDX,
        ACH3_BDRAM_CTRL,
        ACH3_TXBD_DESA_L,
        ACH3_TXBD_DESA_H,
    ),
    tx_addr(
        ACH4_TXBD_NUM,
        ACH4_TXBD_IDX,
        ACH4_BDRAM_CTRL,
        ACH4_TXBD_DESA_L,
        ACH4_TXBD_DESA_H,
    ),
    tx_addr(
        ACH5_TXBD_NUM,
        ACH5_TXBD_IDX,
        ACH5_BDRAM_CTRL,
        ACH5_TXBD_DESA_L,
        ACH5_TXBD_DESA_H,
    ),
    tx_addr(
        ACH6_TXBD_NUM,
        ACH6_TXBD_IDX,
        ACH6_BDRAM_CTRL,
        ACH6_TXBD_DESA_L,
        ACH6_TXBD_DESA_H,
    ),
    tx_addr(
        ACH7_TXBD_NUM,
        ACH7_TXBD_IDX,
        ACH7_BDRAM_CTRL,
        ACH7_TXBD_DESA_L,
        ACH7_TXBD_DESA_H,
    ),
    tx_addr(
        CH8_TXBD_NUM,
        CH8_TXBD_IDX,
        CH8_BDRAM_CTRL,
        CH8_TXBD_DESA_L,
        CH8_TXBD_DESA_H,
    ),
    tx_addr(
        CH9_TXBD_NUM,
        CH9_TXBD_IDX,
        CH9_BDRAM_CTRL,
        CH9_TXBD_DESA_L,
        CH9_TXBD_DESA_H,
    ),
    tx_addr(
        CH10_TXBD_NUM,
        CH10_TXBD_IDX,
        CH10_BDRAM_CTRL,
        CH10_TXBD_DESA_L,
        CH10_TXBD_DESA_H,
    ),
    tx_addr(
        CH11_TXBD_NUM,
        CH11_TXBD_IDX,
        CH11_BDRAM_CTRL,
        CH11_TXBD_DESA_L,
        CH11_TXBD_DESA_H,
    ),
    tx_addr(
        CH12_TXBD_NUM,
        CH12_TXBD_IDX,
        CH12_BDRAM_CTRL,
        CH12_TXBD_DESA_L,
        CH12_TXBD_DESA_H,
    ),
];

/// `rtw89_pci_ch_dma_addr_set.rx`: `DEF_RXCHADDRS(AX, …)`, which names no
/// BD RAM.
pub const DMA_ADDR_SET_RX: [ChDmaAddr; RXCH_NUM] = [
    tx_addr(
        RXQ_RXBD_NUM,
        RXQ_RXBD_IDX,
        0,
        RXQ_RXBD_DESA_L,
        RXQ_RXBD_DESA_H,
    ),
    tx_addr(
        RPQ_RXBD_NUM,
        RPQ_RXBD_IDX,
        0,
        RPQ_RXBD_DESA_L,
        RPQ_RXBD_DESA_H,
    ),
];

/// `struct rtw89_pci_bd_ram`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BdRam {
    pub start_idx: u8,
    pub max_num: u8,
    pub min_num: u8,
}

const fn bd_ram(start_idx: u8, max_num: u8, min_num: u8) -> BdRam {
    BdRam {
        start_idx,
        max_num,
        min_num,
    }
}

/// `rtw89_bd_ram_table_single` (`rtw8852b_pci_info.bd_ram_table`); the
/// channels it does not name are zero.
pub const BD_RAM_TABLE_SINGLE: [BdRam; TXCH_NUM] = [
    bd_ram(0, 5, 2),
    bd_ram(5, 5, 2),
    bd_ram(10, 5, 2),
    bd_ram(15, 5, 2),
    bd_ram(0, 0, 0),
    bd_ram(0, 0, 0),
    bd_ram(0, 0, 0),
    bd_ram(0, 0, 0),
    bd_ram(20, 4, 1),
    bd_ram(24, 4, 1),
    bd_ram(0, 0, 0),
    bd_ram(0, 0, 0),
    bd_ram(28, 4, 1),
];

impl BdRam {
    /// The value `rtw89_pci_reset_trx_rings` writes to the channel's
    /// `bdram` register.
    pub const fn value(self) -> u32 {
        prep(self.start_idx as u32, BDRAM_SIDX_MASK)
            | prep(self.max_num as u32, BDRAM_MAX_MASK)
            | prep(self.min_num as u32, BDRAM_MIN_MASK)
    }
}

/// `RTW89_PCI_TXBD_OPT_LS` and `RTW89_PCI_TXBD_OPT_DMA_HI`.
pub const TXBD_OPT_LS: u16 = 1 << 14;
pub const TXBD_OPT_DMA_HI: u16 = 0x3fc0;
/// `RTW89_PCI_RXBD_OPT_DMA_HI`.
pub const RXBD_OPT_DMA_HI: u16 = 0x3fc0;
/// The `struct rtw89_pci_rxbd_info` fields: `RTW89_PCI_RXBD_FS`,
/// `RTW89_PCI_RXBD_LS`, `RTW89_PCI_RXBD_WRITE_SIZE` and `RTW89_PCI_RXBD_TAG`.
pub const RXBD_FS: u32 = 1 << 15;
pub const RXBD_LS: u32 = 1 << 14;
pub const RXBD_WRITE_SIZE: u32 = 0x0000_3fff;
pub const RXBD_TAG: u32 = 0x1fff_0000;

/// `le16_encode_bits(upper_32_bits(dma), …_OPT_DMA_HI)`.
const fn dma_hi(dma: u64) -> u16 {
    prep((dma >> 32) as u32 & 0xffff, TXBD_OPT_DMA_HI as u32) as u16
}

/// `struct rtw89_pci_tx_bd_32`, eight little-endian bytes: length, option,
/// then the buffer's low 32 bits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxBd {
    pub length: u16,
    pub opt: u16,
    pub dma: u32,
}

impl TxBd {
    pub const SIZE: usize = 8;

    /// What `rtw89_pci_fwcmd_submit` (and `rtw89_pci_txbd_submit`) writes for
    /// one buffer: the last segment, the address's upper bits in the
    /// option, the length, and the address's low 32 bits.
    pub const fn last_segment(dma: u64, length: u16) -> Self {
        Self {
            length,
            opt: TXBD_OPT_LS | dma_hi(dma),
            dma: dma as u32,
        }
    }

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.length.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.opt.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.dma.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            length: u16::from_le_bytes([bytes[0], bytes[1]]),
            opt: u16::from_le_bytes([bytes[2], bytes[3]]),
            dma: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }
}

/// `struct rtw89_pci_rx_bd_32`, eight little-endian bytes: the buffer's
/// size, option, then its low 32 bits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxBd {
    pub buf_size: u16,
    pub opt: u16,
    pub dma: u32,
}

impl RxBd {
    pub const SIZE: usize = 8;

    /// What `rtw89_pci_init_rx_bd` writes over a zeroed BD.
    pub const fn new(dma: u64, buf_size: u16) -> Self {
        Self {
            buf_size,
            opt: dma_hi(dma),
            dma: dma as u32,
        }
    }

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.buf_size.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.opt.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.dma.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            buf_size: u16::from_le_bytes([bytes[0], bytes[1]]),
            opt: u16::from_le_bytes([bytes[2], bytes[3]]),
            dma: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }
}

/// The `struct rtw89_pci_rxbd_info` dword at the head of a filled RX
/// buffer, as `rtw89_pci_rxbd_info_update` decodes it. `len` counts the
/// bytes written from the buffer's start, this dword included.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxBdInfo {
    pub fs: bool,
    pub ls: bool,
    pub len: u16,
    pub tag: u16,
}

impl RxBdInfo {
    pub const fn decode(dword: u32) -> Self {
        Self {
            fs: dword & RXBD_FS != 0,
            ls: dword & RXBD_LS != 0,
            len: field(dword, RXBD_WRITE_SIZE) as u16,
            tag: field(dword, RXBD_TAG) as u16,
        }
    }

    /// The dword the chip writes for these fields.
    pub const fn encode(&self) -> u32 {
        (if self.fs { RXBD_FS } else { 0 })
            | (if self.ls { RXBD_LS } else { 0 })
            | prep(self.len as u32, RXBD_WRITE_SIZE)
            | prep(self.tag as u32, RXBD_TAG)
    }
}

/// `struct rtw89_pci_dma_ring` without its CPU pointer: where the ring's
/// BDs are for the device, their size and count, the registers that name
/// the ring, and the host (`wp`) and hardware (`rp`) indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaRing {
    pub dma: u64,
    pub desc_size: u8,
    pub addr: ChDmaAddr,
    pub len: u32,
    pub wp: u32,
    pub rp: u32,
}

/// `rtw89_pci_dma_recalc` with `rx_ring_eq_is_full` false: how many BDs the
/// hardware index `cur_idx` has moved past (from `rp` for TX, from `wp` for
/// RX), which also becomes `rp`. Like rtw89, an index outside the ring is
/// not refused here.
pub fn dma_recalc(ring: &mut DmaRing, cur_idx: u32, tx: bool) -> u32 {
    let (rp, wp, len) = (ring.rp, ring.wp, ring.len);
    let cur_rp = field(cur_idx, TXBD_HW_IDX_MASK);
    let from = if tx { rp } else { wp };
    let cnt = if cur_rp >= from {
        cur_rp - from
    } else {
        len.wrapping_sub(from - cur_rp)
    };
    ring.rp = cur_rp;
    cnt
}

/// `rtw89_pci_txbd_recalc`: the ring's index register, then
/// [`dma_recalc`] for TX.
pub fn txbd_recalc<I: Io + ?Sized>(io: &mut I, ring: &mut DmaRing) -> Result<u32, io::Error> {
    let idx = io.read32(ring.addr.idx)?;
    Ok(dma_recalc(ring, idx, true))
}

/// `rtw89_pci_rxbd_recalc`: the ring's index register, then
/// [`dma_recalc`] for RX.
pub fn rxbd_recalc<I: Io + ?Sized>(io: &mut I, ring: &mut DmaRing) -> Result<u32, io::Error> {
    let idx = io.read32(ring.addr.idx)?;
    Ok(dma_recalc(ring, idx, false))
}

/// `rtw89_pci_get_avail_txbd_num`: the free BDs, one kept back to tell a
/// full ring from an empty one.
pub fn avail_txbd(ring: &DmaRing) -> u32 {
    if ring.rp > ring.wp {
        return ring.rp - ring.wp - 1;
    }
    ring.len.wrapping_sub(ring.wp - ring.rp).wrapping_sub(1)
}

/// `rtw89_pci_tx_bd_ring_update`: the host index after `n_txbd` more BDs.
pub fn tx_bd_ring_update(ring: &mut DmaRing, n_txbd: u32) {
    let host_idx = ring.wp.wrapping_add(n_txbd);
    ring.wp = if host_idx < ring.len {
        host_idx
    } else {
        host_idx.wrapping_sub(ring.len)
    };
}

/// `rtw89_pci_rxbd_increase`.
pub fn rxbd_increase(ring: &mut DmaRing, cnt: u32) {
    ring.wp = ring.wp.wrapping_add(cnt);
    if ring.wp >= ring.len {
        ring.wp = ring.wp.wrapping_sub(ring.len);
    }
}

/// `rtw89_pci_validate_rx_tag`: whether `tag` is the one the ring expects,
/// 1 standing for a target of 0. With `check_rx_tag` false, as on an
/// RTL8852BE, every tag passes.
pub const fn validate_rx_tag(check_rx_tag: bool, target_rx_tag: u16, tag: u16) -> bool {
    if !check_rx_tag {
        return true;
    }
    let target = if target_rx_tag == 0 { 1 } else { target_rx_tag };
    tag == target
}

/// A buffer whose tag was still not the expected one after every retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleTag {
    pub expected: u16,
    pub observed: u16,
}

/// `rtw89_pci_sync_skb_for_device_and_validate_rx_info`: `read` syncs the
/// buffer for the CPU and decodes its info, once and then up to 1000 more
/// times while the tag is not the expected one. Whatever the outcome, the
/// ring then expects the tag after the last one read, in 13 bits.
pub fn sync_and_validate<E>(
    target_rx_tag: &mut u16,
    check_rx_tag: bool,
    mut read: impl FnMut() -> Result<RxBdInfo, E>,
) -> Result<Result<RxBdInfo, StaleTag>, E> {
    let mut retry = RX_TAG_RETRY;
    loop {
        let info = read()?;
        let valid = validate_rx_tag(check_rx_tag, *target_rx_tag, info.tag);
        if valid || retry == 0 {
            let expected = if *target_rx_tag == 0 {
                1
            } else {
                *target_rx_tag
            };
            *target_rx_tag = info.tag.wrapping_add(1) & RX_TAG_MAX;
            return Ok(if valid {
                Ok(info)
            } else {
                Err(StaleTag {
                    expected,
                    observed: info.tag,
                })
            });
        }
        retry -= 1;
    }
}

/// Why a ring operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Memory(MemoryError),
    Dma(DmaError),
    Io(io::Error),
    /// A mapping that reaches above 4 GiB, which the chip's 32-bit DMA
    /// cannot address.
    Above4GiB {
        address: u64,
        bytes: usize,
    },
    /// A TX channel `tx_dma_ch_mask` takes from the chip.
    NoRing(TxChannel),
    /// `rtw89_pci_tx_write`'s `-ENOSPC`: no free TX BD.
    NoTxBd,
    /// A buffer shorter than the length asked of it.
    Length {
        length: usize,
        bytes: usize,
    },
    /// `rtw89_pci_release_fwcmd`'s "failed to pre-release fwcmd": the
    /// hardware read more command buffers than were queued.
    CompletionBeyondPending,
    /// More command buffers kept than the ring and the kept tail can hold.
    QueueFull,
    /// A hardware index outside the ring, where rtw89 would go on to reuse
    /// buffers it never handed over. The ring is left as it was.
    Index(u32),
    /// `rtw89_pci_txbd_submit`'s "no available TXWD": every WD page of the
    /// ring carries a frame.
    NoTxWd,
    /// A data channel whose WD pages [`Rings::alloc_tx_wd`] has not
    /// allocated.
    NoWdRing(TxChannel),
    /// A frame's `ch_dma` that names no ring, or CH12, which
    /// `rtw89_pci_tx_write` keeps for firmware commands ("only fw cmd uses
    /// dma channel 12").
    Channel(u8),
}

impl From<MemoryError> for Error {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

impl From<DmaError> for Error {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The device address of a mapping of `bytes` at `address`, refused when
/// any of it lies above 4 GiB.
pub fn below_4gib(address: u64, bytes: usize) -> Result<u32, Error> {
    let last = (bytes as u64)
        .checked_sub(1)
        .and_then(|span| address.checked_add(span));
    match last {
        Some(last) if last <= u64::from(u32::MAX) => Ok(address as u32),
        _ => Err(Error::Above4GiB { address, bytes }),
    }
}

/// One native DMA allocation below 4 GiB: a BD pool, an RX buffer or a
/// firmware command buffer. Once the device may hold its address it is
/// published, and dropping it keeps the pages and mapping for good
/// ([`DmaMapping`]'s quarantine) unless [`Self::release`] unmapped it.
pub struct Buffer {
    cpu: CpuMapping,
    dma: DmaMapping,
    address: u32,
    published: bool,
    unmapped: bool,
}

impl Buffer {
    /// `bytes` of zeroed write-back RAM mapped into `domain` for
    /// `direction`, below 4 GiB.
    pub fn new(
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        bytes: usize,
        direction: Direction,
    ) -> Result<Self, Error> {
        let (cpu, dma) =
            crate::wifi::allocation::allocate_32bit::<Error>(source, domain, bytes, direction)?;
        let mut buffer = Self {
            cpu,
            dma,
            address: 0,
            published: false,
            unmapped: false,
        };
        buffer.address = below_4gib(buffer.dma.address()?, buffer.dma.bytes())?;
        Ok(buffer)
    }

    /// The device address.
    pub fn address(&self) -> u32 {
        self.address
    }

    /// The mapped bytes, whole pages.
    pub fn bytes(&self) -> usize {
        self.dma.bytes()
    }

    /// Copy `bytes` in at `offset`. The caller owns that range: the device
    /// was never given it, or gave it back.
    pub fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let pointer = self.cpu.address(offset, bytes.len())?;
        // SAFETY: `address` bounded the range inside this kept native
        // mapping, and the caller owns it, so no device write races the copy.
        unsafe {
            pointer
                .as_ptr()
                .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
        }
        Ok(())
    }

    /// Copy `out.len()` bytes out from `offset`, under the same ownership.
    pub fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        let pointer = self.cpu.address(offset, out.len())?;
        // SAFETY: as in `write`; the bytes are copied, not borrowed.
        unsafe {
            out.as_mut_ptr()
                .copy_from_nonoverlapping(pointer.as_ptr(), out.len());
        }
        Ok(())
    }

    fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        self.read(offset, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn sync_for_device(&self, range: Range<usize>) -> Result<(), Error> {
        Ok(self.dma.sync_for_device(range)?)
    }

    /// # Safety
    /// The device finished with `range` and cannot reach it again until the
    /// next handover.
    pub unsafe fn sync_for_cpu(&self, range: Range<usize>) -> Result<(), Error> {
        // SAFETY: forwarded.
        Ok(unsafe { self.dma.sync_for_cpu(range) }?)
    }

    /// Mark the allocation as one the device may reach.
    fn publish(&mut self) {
        self.published = true;
    }

    /// Unmap the allocation; a failed unmap keeps it for a retry.
    ///
    /// # Safety
    /// The device finished every access to it and cannot start another.
    pub unsafe fn release(&mut self) -> Result<(), Error> {
        if !self.unmapped {
            // SAFETY: forwarded.
            unsafe { self.dma.unmap()? };
            self.unmapped = true;
            self.published = false;
        }
        Ok(())
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.published && !self.unmapped {
            // SAFETY: the device was never given this allocation; a failed
            // unmap leaves the mapping to DmaMapping's quarantine.
            let _ = unsafe { self.dma.unmap() };
        }
    }
}

/// `rtwpci->h2c_queue` and `h2c_release_queue`: the command buffers CH12
/// was given, oldest first, and those the hardware read that are still
/// mapped. Both hold at most what the ring and the kept tail can.
pub struct FwCmdQueue<B> {
    queue: VecDeque<B>,
    release: VecDeque<B>,
}

/// What the two queues can hold: a full ring and the kept tail.
const FWCMD_CAPACITY: usize = TXBD_NUM_MAX as usize + MULTITAG;

impl<B> FwCmdQueue<B> {
    pub fn new() -> Result<Self, Error> {
        let mut queue = VecDeque::new();
        let mut release = VecDeque::new();
        queue
            .try_reserve_exact(FWCMD_CAPACITY)
            .map_err(|_| MemoryError::OutOfMemory)?;
        release
            .try_reserve_exact(FWCMD_CAPACITY)
            .map_err(|_| MemoryError::OutOfMemory)?;
        Ok(Self { queue, release })
    }

    /// `skb_queue_tail(&rtwpci->h2c_queue, skb)`.
    pub fn push(&mut self, buffer: B) -> Result<(), Error> {
        if self.queue.len() >= FWCMD_CAPACITY {
            return Err(Error::QueueFull);
        }
        self.queue.push_back(buffer);
        Ok(())
    }

    /// The buffers given and not yet read.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// The read buffers still mapped.
    pub fn kept(&self) -> usize {
        self.release.len()
    }

    /// `rtw89_pci_release_fwcmd`: `cnt` buffers the hardware read move to
    /// the release queue, then all of it is released but the newest
    /// [`MULTITAG`], or all with `release_all`. `free` releases the oldest;
    /// one it fails stays queued and its error is returned. When fewer than
    /// `cnt` are queued, those move and nothing is released.
    pub fn release<E: From<Error>>(
        &mut self,
        cnt: u32,
        release_all: bool,
        mut free: impl FnMut(&mut B) -> Result<(), E>,
    ) -> Result<(), E> {
        for _ in 0..cnt {
            let Some(buffer) = self.queue.pop_front() else {
                return Err(Error::CompletionBeyondPending.into());
            };
            if self.release.len() >= FWCMD_CAPACITY {
                self.queue.push_front(buffer);
                return Err(Error::QueueFull.into());
            }
            self.release.push_back(buffer);
        }
        let mut qlen = self.release.len();
        if !release_all {
            qlen = qlen.saturating_sub(MULTITAG);
        }
        for _ in 0..qlen {
            let Some(buffer) = self.release.front_mut() else {
                break;
            };
            free(buffer)?;
            self.release.pop_front();
        }
        Ok(())
    }

    fn all(&mut self) -> impl Iterator<Item = &mut B> {
        self.release.iter_mut().chain(self.queue.iter_mut())
    }
}

/// One TX ring: its BDs within the TX pool.
struct TxRing {
    bd: DmaRing,
    /// The ring's first byte within the pool.
    offset: usize,
}

/// One RX ring: its BDs within the RX pool, and a buffer behind each BD.
struct RxRing {
    bd: DmaRing,
    offset: usize,
    buffers: Vec<Buffer>,
    target_rx_tag: u16,
}

/// A filled RX buffer as [`Rings::deliver`] hands it over: its decoded info
/// and the bytes the chip wrote, from the buffer's start (the info dword
/// first, as rtw89's `skb->data`), cut at the buffer's size.
#[derive(Debug)]
pub struct Received<'a> {
    pub info: RxBdInfo,
    pub data: &'a [u8],
}

/// An RTL8852BE's PCIe rings: the seven TX BD rings, RXQ and RPQ with
/// their buffers, and the firmware command queue.
pub struct Rings {
    tx_pool: Buffer,
    rx_pool: Buffer,
    tx: [Option<TxRing>; TXCH_NUM],
    rx: [RxRing; RXCH_NUM],
    fwcmd: FwCmdQueue<Buffer>,
    /// The data channels' WD pages, once [`Self::alloc_tx_wd`] ran.
    wd: [Option<TxWd>; TXCH_NUM],
}

impl Rings {
    /// The subset of `rtw89_pci_alloc_trx_rings` this step needs, in its
    /// order: `rtw89_pci_alloc_tx_rings`' BD pool and rings (without WD
    /// pages), then `rtw89_pci_alloc_rx_rings`' BD pool and, ring by ring,
    /// a zeroed buffer behind each BD (`rtw89_pci_init_rx_bd`). The BDs are
    /// synced for the device; nothing reaches the device yet.
    pub fn new(source: &dyn PageSource, domain: Arc<dyn DmaDomain>) -> Result<Self, Error> {
        let desc_size = TxBd::SIZE;
        let len = TXBD_NUM_MAX;
        let ch_num = TXCH_NUM - TX_DMA_CH_MASK.count_ones() as usize;
        let ring_sz = desc_size * len as usize;
        let tx_pool = Buffer::new(
            source,
            domain.clone(),
            ring_sz * ch_num,
            Direction::Bidirectional,
        )?;
        let mut tx: [Option<TxRing>; TXCH_NUM] = core::array::from_fn(|_| None);
        let mut offset = 0;
        for txch in TxChannel::ALL {
            if !txch.present() {
                continue;
            }
            tx[txch as usize] = Some(TxRing {
                bd: DmaRing {
                    dma: u64::from(tx_pool.address()) + offset as u64,
                    desc_size: desc_size as u8,
                    addr: DMA_ADDR_SET_TX[txch as usize],
                    len,
                    wp: 0,
                    rp: 0,
                },
                offset,
            });
            offset += ring_sz;
        }
        tx_pool.sync_for_device(0..tx_pool.bytes())?;

        let desc_size = RxBd::SIZE;
        let len = RXBD_NUM_MAX;
        let ring_sz = desc_size * len as usize;
        let rx_pool = Buffer::new(
            source,
            domain.clone(),
            ring_sz * RXCH_NUM,
            Direction::Bidirectional,
        )?;
        let mut rx = Vec::new();
        rx.try_reserve_exact(RXCH_NUM)
            .map_err(|_| MemoryError::OutOfMemory)?;
        for rxch in RxChannel::ALL {
            let offset = ring_sz * rxch as usize;
            let mut buffers = Vec::new();
            buffers
                .try_reserve_exact(len as usize)
                .map_err(|_| MemoryError::OutOfMemory)?;
            for index in 0..len as usize {
                let buffer =
                    Buffer::new(source, domain.clone(), RX_BUF_SIZE, Direction::FromDevice)?;
                buffer.sync_for_device(0..RX_BUF_SIZE)?;
                let bd = RxBd::new(u64::from(buffer.address()), RX_BUF_SIZE as u16);
                rx_pool.write(offset + index * desc_size, &bd.encode())?;
                buffers.push(buffer);
            }
            rx.push(RxRing {
                bd: DmaRing {
                    dma: u64::from(rx_pool.address()) + offset as u64,
                    desc_size: desc_size as u8,
                    addr: DMA_ADDR_SET_RX[rxch as usize],
                    len,
                    wp: 0,
                    rp: 0,
                },
                offset,
                buffers,
                target_rx_tag: 0,
            });
        }
        rx_pool.sync_for_device(0..rx_pool.bytes())?;
        let rx: [RxRing; RXCH_NUM] = rx.try_into().map_err(|_| Error::Index(0))?;
        Ok(Self {
            tx_pool,
            rx_pool,
            tx,
            rx,
            fwcmd: FwCmdQueue::new()?,
            wd: core::array::from_fn(|_| None),
        })
    }

    /// The TX ring of `txch`, when the chip has it.
    pub fn tx_ring(&self, txch: TxChannel) -> Option<&DmaRing> {
        self.tx[txch as usize].as_ref().map(|ring| &ring.bd)
    }

    pub fn rx_ring(&self, rxch: RxChannel) -> &DmaRing {
        &self.rx[rxch as usize].bd
    }

    /// The RX ring's `target_rx_tag`.
    pub fn rx_target_tag(&self, rxch: RxChannel) -> u16 {
        self.rx[rxch as usize].target_rx_tag
    }

    /// The RX BD at `index` of `rxch`, as the ring holds it.
    pub fn rx_bd(&self, rxch: RxChannel, index: usize) -> Result<RxBd, Error> {
        let ring = &self.rx[rxch as usize];
        if index >= ring.bd.len as usize {
            return Err(Error::Index(index as u32));
        }
        let mut bytes = [0; RxBd::SIZE];
        self.rx_pool
            .read(ring.offset + index * RxBd::SIZE, &mut bytes)?;
        Ok(RxBd::decode(&bytes))
    }

    /// The TX BD at `index` of `txch`, as the ring holds it.
    pub fn tx_bd(&self, txch: TxChannel, index: usize) -> Result<TxBd, Error> {
        let ring = self.tx[txch as usize].as_ref().ok_or(Error::NoRing(txch))?;
        if index >= ring.bd.len as usize {
            return Err(Error::Index(index as u32));
        }
        let mut bytes = [0; TxBd::SIZE];
        self.tx_pool
            .read(ring.offset + index * TxBd::SIZE, &mut bytes)?;
        Ok(TxBd::decode(&bytes))
    }

    /// The command buffers queued and kept.
    pub fn fwcmd(&self) -> (usize, usize) {
        (self.fwcmd.queued(), self.fwcmd.kept())
    }

    /// Every allocation, which the device may reach from the first ring
    /// address on.
    fn publish(&mut self) {
        self.tx_pool.publish();
        self.rx_pool.publish();
        for ring in &mut self.rx {
            for buffer in &mut ring.buffers {
                buffer.publish();
            }
        }
    }

    /// `rtw89_pci_ops_reset`: `rtw89_pci_reset_trx_rings` programs every
    /// ring's count, BD RAM share and base and zeroes its indices, then each
    /// data channel's WD pages are released (`rtw89_pci_release_tx_ring`:
    /// a frame still held is unmapped and counted as `RTW89_TX_MACID_DROP`)
    /// and the command buffers are all released. At the pre-init no data
    /// channel has WD pages yet, so their release finds nothing.
    ///
    /// # Safety
    /// The chip's DMA is stopped and idle, as `rtw89_pci_ops_mac_pre_init_ax`
    /// leaves it before this, and `io` reaches the function whose DMA domain
    /// these rings were allocated in.
    pub(super) unsafe fn reset<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), Error> {
        // A base store may expose every BD and buffer, even when a later
        // access fails: keep them all from here on.
        self.publish();
        fence(Ordering::Release);
        for txch in TxChannel::ALL {
            if !txch.present() {
                continue;
            }
            let Some(ring) = self.tx[txch as usize].as_mut() else {
                return Err(Error::NoRing(txch));
            };
            let bd_ring = &mut ring.bd;
            bd_ring.wp = 0;
            bd_ring.rp = 0;
            io.write16(bd_ring.addr.num, bd_ring.len as u16)?;
            if bd_ring.addr.bdram != 0 {
                io.write32(
                    bd_ring.addr.bdram,
                    BD_RAM_TABLE_SINGLE[txch as usize].value(),
                )?;
            }
            if bd_ring.addr.desa_l != 0 {
                io.write32(bd_ring.addr.desa_l, bd_ring.dma as u32)?;
                io.write32(bd_ring.addr.desa_l + 4, (bd_ring.dma >> 32) as u32)?;
            }
        }
        for ring in &mut self.rx {
            let bd_ring = &mut ring.bd;
            bd_ring.wp = 0;
            bd_ring.rp = 0;
            ring.target_rx_tag = 0;
            io.write16(bd_ring.addr.num, bd_ring.len as u16)?;
            if bd_ring.addr.desa_l != 0 {
                io.write32(bd_ring.addr.desa_l, bd_ring.dma as u32)?;
                io.write32(bd_ring.addr.desa_l + 4, (bd_ring.dma >> 32) as u32)?;
            }
        }
        // rtw89_pci_release_tx_ring for every data channel with WD pages.
        for wd in self.wd.iter_mut().flatten() {
            wd.ring.release_ring(|_, mut frame| {
                // SAFETY: the caller stopped the chip's DMA and saw it idle,
                // so no frame is read any more. A frame whose unmap fails
                // stays published and is kept for good.
                let _ = unsafe { frame.release() };
            });
        }
        let queued = self.fwcmd.queued() as u32;
        self.fwcmd.release(queued, true, |buffer| {
            // SAFETY: the caller stopped the chip's DMA and saw it idle, so
            // no command buffer is read any more.
            unsafe { buffer.release() }
        })
    }

    /// `rtw89_pci_get_avail_txbd_num` of `txch`.
    pub fn avail_txbd(&self, txch: TxChannel) -> Result<u32, Error> {
        Ok(avail_txbd(self.tx_ring(txch).ok_or(Error::NoRing(txch))?))
    }

    /// `rtw89_pci_tx_write` on CH12 with `rtw89_pci_fwcmd_submit`'s BD:
    /// the first `length` bytes of `buffer` (the TXWD body and the H2C
    /// packet behind it) become the next BD, and the host index moves on.
    /// [`Self::tx_kick_off`] hands it to the chip. A buffer that may have
    /// reached a BD is kept for good when a later step fails.
    pub fn fwcmd_submit(&mut self, mut buffer: Buffer, length: u16) -> Result<(), Error> {
        if usize::from(length) > buffer.bytes() {
            return Err(Error::Length {
                length: length.into(),
                bytes: buffer.bytes(),
            });
        }
        buffer.sync_for_device(0..usize::from(length))?;
        let ring = self.tx[TxChannel::Ch12 as usize]
            .as_mut()
            .ok_or(Error::NoRing(TxChannel::Ch12))?;
        if avail_txbd(&ring.bd) == 0 {
            return Err(Error::NoTxBd);
        }
        let offset = ring.offset + ring.bd.wp as usize * TxBd::SIZE;
        let bd = TxBd::last_segment(u64::from(buffer.address()), length);
        buffer.publish();
        self.tx_pool.write(offset, &bd.encode())?;
        self.tx_pool.sync_for_device(offset..offset + TxBd::SIZE)?;
        self.fwcmd.push(buffer)?;
        tx_bd_ring_update(&mut ring.bd, 1);
        Ok(())
    }

    /// `__rtw89_pci_tx_kick_off`: the host index written to the ring's
    /// index register.
    pub fn tx_kick_off<I: Io + ?Sized>(&self, io: &mut I, txch: TxChannel) -> Result<(), Error> {
        let ring = self.tx_ring(txch).ok_or(Error::NoRing(txch))?;
        fence(Ordering::Release);
        Ok(io.write16(ring.addr.idx, ring.wp as u16)?)
    }

    /// `rtw89_pci_reclaim_tx_fwcmd`: the BDs the hardware read
    /// (`rtw89_pci_txbd_recalc`), whose buffers `rtw89_pci_release_fwcmd`
    /// then releases but the newest [`MULTITAG`]. Returns how many it read.
    pub fn reclaim_fwcmd<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<u32, Error> {
        let ring = self.tx[TxChannel::Ch12 as usize]
            .as_mut()
            .ok_or(Error::NoRing(TxChannel::Ch12))?;
        let mut bd = ring.bd;
        let cnt = txbd_recalc(io, &mut bd)?;
        if bd.rp >= bd.len {
            return Err(Error::Index(bd.rp));
        }
        ring.bd = bd;
        if cnt == 0 {
            return Ok(0);
        }
        self.fwcmd.release(cnt, false, |buffer| {
            // SAFETY: the hardware index moved past this buffer and
            // MULTITAG more, which is where rtw89 unmaps it.
            unsafe { buffer.release() }
        })?;
        Ok(cnt)
    }

    /// `rtw89_pci_poll_rxq_dma`'s ring work for `rxch`: the BDs the hardware
    /// filled (`rtw89_pci_rxbd_recalc`), at most `budget` of them, each
    /// synced for the CPU, its info read and its tag checked as
    /// `rtw89_pci_rxbd_deliver_skbs` does, handed to `sink` unless the tag
    /// stayed stale, synced back for the device; then the host index
    /// (`rtw89_pci_rxbd_deliver`). Returns how many BDs were consumed.
    pub fn deliver<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        rxch: RxChannel,
        budget: u32,
        mut sink: impl FnMut(Received<'_>),
    ) -> Result<u32, Error> {
        let ring = &mut self.rx[rxch as usize];
        let mut bd = ring.bd;
        let cnt = rxbd_recalc(io, &mut bd)?;
        if bd.rp >= bd.len {
            return Err(Error::Index(bd.rp));
        }
        ring.bd = bd;
        if cnt == 0 {
            return Ok(0);
        }
        let cnt = cnt.min(budget);
        for _ in 0..cnt {
            let index = ring.bd.wp as usize;
            let buffer = ring.buffers.get(index).ok_or(Error::Index(ring.bd.wp))?;
            let checked = sync_and_validate(&mut ring.target_rx_tag, CHECK_RX_TAG, || {
                // SAFETY: the hardware index moved past this BD, so the chip
                // finished writing its buffer and gets it back only when
                // the host index below passes it.
                unsafe { buffer.sync_for_cpu(0..RX_BUF_SIZE) }?;
                Ok::<_, Error>(RxBdInfo::decode(buffer.read_u32(0)?))
            })?;
            if let Ok(info) = checked {
                let length = usize::from(info.len).min(RX_BUF_SIZE);
                let pointer = buffer.cpu.address(0, length)?;
                // SAFETY: the buffer is the CPU's until the host index
                // passes it, and the borrow ends with `sink`.
                let data = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), length) };
                sink(Received { info, data });
            }
            buffer.sync_for_device(0..RX_BUF_SIZE)?;
            rxbd_increase(&mut ring.bd, 1);
        }
        fence(Ordering::Release);
        io.write16(ring.bd.addr.idx, ring.bd.wp as u16)?;
        Ok(cnt)
    }

    /// Unmap every allocation. One that fails stays mapped and kept, and
    /// its error is returned.
    ///
    /// # Safety
    /// The chip's DMA is stopped and drained, and no access can start again.
    pub unsafe fn release_after_stop(&mut self) -> Result<(), Error> {
        for wd in self.wd.iter_mut().flatten() {
            for frame in wd.ring.frames_mut() {
                // SAFETY: covered by this function's contract.
                unsafe { frame.release()? };
            }
            // SAFETY: covered by this function's contract.
            unsafe { wd.pages.release()? };
        }
        for buffer in self.fwcmd.all() {
            // SAFETY: covered by this function's contract.
            unsafe { buffer.release()? };
        }
        for ring in &mut self.rx {
            for buffer in &mut ring.buffers {
                // SAFETY: covered by this function's contract.
                unsafe { buffer.release()? };
            }
        }
        // SAFETY: covered by this function's contract.
        unsafe {
            self.rx_pool.release()?;
            self.tx_pool.release()?;
        }
        Ok(())
    }
}

/// `RTW89_PCI_TXWD_NUM_MAX`: the WD pages of every data channel.
pub const TXWD_NUM_MAX: usize = 512;
/// `RTW89_PCI_TXWD_PAGE_SIZE`.
pub const TXWD_PAGE_SIZE: usize = 128;
/// `RTW89_PCI_TXWP_VALID`: set beside the page's sequence in its WP info.
pub const TXWP_VALID: u16 = 1 << 15;
/// `sizeof(struct rtw89_pci_tx_wp_info)`: four 16-bit sequences.
pub const WP_INFO_SIZE: usize = 8;
/// The `struct rtw89_pci_tx_addr_info_32` option: `RTW89_PCI_ADDR_MSDU_LS`,
/// `RTW89_PCI_ADDR_LS`, `RTW89_PCI_ADDR_HIGH_MASK` and the mask of
/// `RTW89_PCI_ADDR_NUM`.
pub const ADDR_MSDU_LS: u16 = 1 << 15;
pub const ADDR_LS: u16 = 1 << 14;
pub const ADDR_HIGH_MASK: u16 = 0x3fc0;
pub const ADDR_NUM_MASK: u16 = 0x003f;

/// `struct rtw89_pci_tx_addr_info_32`, eight little-endian bytes behind the
/// WP info: the frame's length, the option, then its low 32 bits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddrInfo {
    pub length: u16,
    pub option: u16,
    pub dma: u32,
}

impl AddrInfo {
    pub const SIZE: usize = 8;

    /// `rtw89_pci_fill_txaddr_info`, RTL8852BE's `fill_txaddr_info`: one
    /// entry for the whole frame (`add_info_nr` 1), its last MSDU, the
    /// address's upper bits in the option. rtw89 returns [`Self::SIZE`].
    pub const fn fill(total_len: u32, dma: u64) -> Self {
        Self {
            length: total_len as u16,
            option: ADDR_MSDU_LS
                | (1 & ADDR_NUM_MASK)
                | prep((dma >> 32) as u32 & 0xffff, ADDR_HIGH_MASK as u32) as u16,
            dma: dma as u32,
        }
    }

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.length.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.option.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.dma.to_le_bytes());
        bytes
    }
}

/// A WD page as `rtw89_pci_txwd_submit` leaves it, zeroed before: the
/// TXWD body (and info), the WP info naming the page, the address info,
/// and `txwd->len`, how many of those bytes the BD hands over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxWdPage {
    pub bytes: [u8; TXWD_PAGE_SIZE],
    pub len: u32,
}

/// `rtw89_pci_txwd_submit` for page `seq` and a frame of `skb_len` bytes at
/// `dma`: the WP info's first sequence is `seq` with `RTW89_PCI_TXWP_VALID`,
/// the others 0, the address info is `rtw89_pci_fill_txaddr_info`'s, and
/// `rtw89_core_fill_txdesc` writes the body and info in front.
pub fn txwd_page(desc: &DescInfo, seq: u16, skb_len: u32, dma: u64) -> TxWdPage {
    let (wd, txwd_len) = desc.wd();
    let mut bytes = [0; TXWD_PAGE_SIZE];
    bytes[..txwd_len].copy_from_slice(&wd[..txwd_len]);
    bytes[txwd_len..txwd_len + 2].copy_from_slice(&(seq | TXWP_VALID).to_le_bytes());
    let at = txwd_len + WP_INFO_SIZE;
    bytes[at..at + AddrInfo::SIZE].copy_from_slice(&AddrInfo::fill(skb_len, dma).encode());
    TxWdPage {
        bytes,
        len: (at + AddrInfo::SIZE) as u32,
    }
}

/// One frame's submission: its WD page's sequence, the page, and the BD
/// `rtw89_pci_txbd_submit` points at the page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Submitted {
    pub seq: u16,
    pub page: TxWdPage,
    pub bd: TxBd,
}

/// `rtw89_pci_tx_write`'s ring work for a data channel, over its indices
/// and WD pages: a free BD (`-ENOSPC`, [`Error::NoTxBd`]), a free page
/// ([`Error::NoTxWd`]), that page filled for a frame of `skb_len` bytes at
/// `dma` and the BD at the host index pointing at it. `store` writes both,
/// at the BD's index, before anything moves; then `frame` is queued on the
/// page, the page goes on the busy list and the host index moves on.
/// Returns the page's sequence number, which the frame's report will name.
pub fn txbd_submit<F, E: From<Error>>(
    bd: &mut DmaRing,
    wd: &mut WdRing<F>,
    desc: &DescInfo,
    skb_len: u32,
    dma: u64,
    frame: F,
    store: impl FnOnce(u32, &Submitted) -> Result<(), E>,
) -> Result<u16, E> {
    if avail_txbd(bd) == 0 {
        return Err(Error::NoTxBd.into());
    }
    let seq = wd.peek().ok_or(Error::NoTxWd)?;
    let page = txwd_page(desc, seq, skb_len, dma);
    let submitted = Submitted {
        seq,
        page,
        bd: TxBd::last_segment(wd.page_dma(seq), page.len as u16),
    };
    store(bd.wp, &submitted)?;
    match wd.submit(frame) {
        Ok(taken) if taken == seq => {}
        _ => return Err(Error::NoTxWd.into()),
    }
    tx_bd_ring_update(bd, 1);
    Ok(seq)
}

/// One data channel's WD pages: their memory and their lists.
struct TxWd {
    pages: Buffer,
    ring: WdRing<Buffer>,
}

/// `rtw89_pci_txbd_recalc`, refusing a hardware index outside the ring
/// before the ring moves.
fn recalc_tx<I: Io + ?Sized>(io: &mut I, ring: &mut DmaRing) -> Result<u32, Error> {
    let mut bd = *ring;
    let cnt = txbd_recalc(io, &mut bd)?;
    if bd.rp >= bd.len {
        return Err(Error::Index(bd.rp));
    }
    *ring = bd;
    Ok(cnt)
}

/// `rtw89_pci_rxbd_recalc`, refusing a hardware index outside the ring
/// before the ring moves.
fn recalc_rx<I: Io + ?Sized>(io: &mut I, ring: &mut DmaRing) -> Result<u32, Error> {
    let mut bd = *ring;
    let cnt = rxbd_recalc(io, &mut bd)?;
    if bd.rp >= bd.len {
        return Err(Error::Index(bd.rp));
    }
    *ring = bd;
    Ok(cnt)
}

/// `rtw89_pci_release_rpp` for one report: parsed, dropped where rtw89
/// warns (or where the named ring has no WD pages), else its page released
/// (`rtw89_pci_release_txwd_skb`), the frame unmapped as rtw89 unmaps it,
/// and handed to `released`.
fn release_rpp<I: Io + ?Sized>(
    tx: &mut [Option<TxRing>; TXCH_NUM],
    wd: &mut [Option<TxWd>; TXCH_NUM],
    io: &mut I,
    dword: u32,
    released: &mut impl FnMut(Completion),
) -> Result<(), Error> {
    let info = RppInfo::parse(dword);
    let Some((txch, seq)) = info.target() else {
        return Ok(());
    };
    let (Some(ring), Some(pages)) = (tx[txch as usize].as_mut(), wd[txch as usize].as_mut()) else {
        return Ok(());
    };
    let status = info.status();
    let frame = pages
        .ring
        .release(seq, status, || recalc_tx(io, &mut ring.bd))?;
    if let Some(mut frame) = frame {
        // SAFETY: the chip's report released the frame, so its DMA read it
        // for the last time, which is where rtw89 unmaps it. A frame whose
        // unmap fails stays published and is kept for good.
        let _ = unsafe { frame.release() };
        released(Completion { txch, seq, status });
    }
    Ok(())
}

impl Rings {
    /// `rtw89_pci_alloc_tx_wd_ring` for every data channel the chip has
    /// (not CH12, whose commands carry their own body): 512 pages of 128
    /// bytes in one zeroed allocation below 4 GiB, each free in sequence
    /// order. A channel that has its pages keeps them.
    pub fn alloc_tx_wd(
        &mut self,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<(), Error> {
        for txch in TxChannel::ALL {
            if !txch.present() || txch == TxChannel::Ch12 || self.wd[txch as usize].is_some() {
                continue;
            }
            let pages = Buffer::new(
                source,
                domain.clone(),
                TXWD_NUM_MAX * TXWD_PAGE_SIZE,
                Direction::ToDevice,
            )?;
            let ring = WdRing::new(u64::from(pages.address()))?;
            self.wd[txch as usize] = Some(TxWd { pages, ring });
        }
        Ok(())
    }

    /// The WD pages of `txch`, once allocated: free count, busy list,
    /// counters.
    pub fn wd_ring(&self, txch: TxChannel) -> Option<&WdRing<Buffer>> {
        self.wd[txch as usize].as_ref().map(|wd| &wd.ring)
    }

    /// `rtw89_pci_ops_tx_write` for one frame: the first `length` bytes of
    /// `frame` go on the ring `desc.ch_dma` names, behind the next free WD
    /// page, which [`txbd_submit`] fills from `desc` and points the next BD
    /// at; the host index moves on and [`Self::tx_kick_off`] hands it to
    /// the chip. Returns the page's sequence number, which the frame's
    /// [`Completion`] names. A frame the ring could not take is dropped,
    /// unmapped; one that may have reached a BD is kept for good when a
    /// later step fails.
    pub fn tx_write(
        &mut self,
        desc: &DescInfo,
        mut frame: Buffer,
        length: u16,
    ) -> Result<u16, Error> {
        let txch = TxChannel::ALL
            .get(usize::from(desc.ch_dma))
            .copied()
            .ok_or(Error::Channel(desc.ch_dma))?;
        // check the tx type and dma channel for fw cmd queue
        if txch == TxChannel::Ch12 {
            return Err(Error::Channel(desc.ch_dma));
        }
        if usize::from(length) > frame.bytes() {
            return Err(Error::Length {
                length: length.into(),
                bytes: frame.bytes(),
            });
        }
        let ring = self.tx[txch as usize].as_mut().ok_or(Error::NoRing(txch))?;
        let TxWd { pages, ring: wd } = self.wd[txch as usize]
            .as_mut()
            .ok_or(Error::NoWdRing(txch))?;
        if avail_txbd(&ring.bd) == 0 {
            return Err(Error::NoTxBd);
        }
        if wd.peek().is_none() {
            return Err(Error::NoTxWd);
        }
        frame.sync_for_device(0..usize::from(length))?;
        let dma = u64::from(frame.address());
        frame.publish();
        let (tx_pool, offset) = (&self.tx_pool, ring.offset);
        txbd_submit(
            &mut ring.bd,
            wd,
            desc,
            length.into(),
            dma,
            frame,
            |index, submitted: &Submitted| {
                let at = usize::from(submitted.seq) * TXWD_PAGE_SIZE;
                pages.publish();
                pages.write(at, &submitted.page.bytes)?;
                pages.sync_for_device(at..at + TXWD_PAGE_SIZE)?;
                let at = offset + index as usize * TxBd::SIZE;
                tx_pool.write(at, &submitted.bd.encode())?;
                tx_pool.sync_for_device(at..at + TxBd::SIZE)
            },
        )
    }

    /// `rtw89_pci_reclaim_txbd` for `txch`: the BDs the hardware read
    /// (`rtw89_pci_txbd_recalc`) take their pages off the busy list, and
    /// those already reported go back free. Returns how many it read.
    pub fn reclaim_txbd<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        txch: TxChannel,
    ) -> Result<u32, Error> {
        let ring = self.tx[txch as usize].as_mut().ok_or(Error::NoRing(txch))?;
        let wd = self.wd[txch as usize]
            .as_mut()
            .ok_or(Error::NoWdRing(txch))?;
        let cnt = recalc_tx(io, &mut ring.bd)?;
        wd.ring.reclaim(cnt);
        Ok(cnt)
    }

    /// `rtw89_pci_poll_rpq_dma`'s ring work: the RPQ buffers the hardware
    /// filled (`rtw89_pci_rxbd_recalc`), all of them, released by
    /// `rtw89_pci_release_tx`; each frame a report releases is unmapped and
    /// handed to `released`. Returns how many buffers were consumed.
    pub fn poll_rpq<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        mut released: impl FnMut(Completion),
    ) -> Result<u32, Error> {
        let cnt = recalc_rx(io, &mut self.rx[RxChannel::Rpq as usize].bd)?;
        if cnt == 0 {
            return Ok(0);
        }
        self.release_tx(io, cnt, &mut released)?;
        Ok(cnt)
    }

    /// `rtw89_pci_release_tx`: `cnt` RPQ buffers, one at a time; one that
    /// releases nothing skips the rest ("failed to release TX skbs"). Then
    /// the host index.
    fn release_tx<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        mut cnt: u32,
        released: &mut impl FnMut(Completion),
    ) -> Result<(), Error> {
        while cnt > 0 {
            let release_cnt = self.release_tx_skbs(io, released)?;
            if release_cnt == 0 {
                // skip the rest RXBD bufs
                rxbd_increase(&mut self.rx[RxChannel::Rpq as usize].bd, cnt);
                break;
            }
            cnt -= release_cnt;
        }
        let bd = &self.rx[RxChannel::Rpq as usize].bd;
        fence(Ordering::Release);
        Ok(io.write16(bd.addr.idx, bd.wp as u16)?)
    }

    /// `rtw89_pci_release_tx_skbs`: the RPQ buffer at the host index synced
    /// for the CPU and its tag checked, its reports walked
    /// ([`release::reports`]) and each released (`rtw89_pci_release_rpp`),
    /// then synced back and the host index moved on. Returns 1, or 0 for a
    /// buffer whose tag stayed stale or that is not FS and LS.
    fn release_tx_skbs<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        released: &mut impl FnMut(Completion),
    ) -> Result<u32, Error> {
        let Self { tx, wd, rx, .. } = self;
        let ring = &mut rx[RxChannel::Rpq as usize];
        let buffer = ring
            .buffers
            .get(ring.bd.wp as usize)
            .ok_or(Error::Index(ring.bd.wp))?;
        let checked = sync_and_validate(&mut ring.target_rx_tag, CHECK_RX_TAG, || {
            // SAFETY: the hardware index moved past this BD, so the chip
            // finished writing its buffer and gets it back only when the
            // host index passes it.
            unsafe { buffer.sync_for_cpu(0..RX_BUF_SIZE) }?;
            Ok::<_, Error>(RxBdInfo::decode(buffer.read_u32(0)?))
        })?;
        let Ok(info) = checked else {
            // failed to update RXBD info
            buffer.sync_for_device(0..RX_BUF_SIZE)?;
            return Ok(0);
        };
        let pointer = buffer.cpu.address(0, RX_BUF_SIZE)?;
        // SAFETY: the buffer is the CPU's until the host index passes it,
        // and the borrow ends before it is synced back.
        let data = unsafe { core::slice::from_raw_parts(pointer.as_ptr(), RX_BUF_SIZE) };
        let mut outcome = Ok(1);
        match release::reports(info, data) {
            Ok(reports) => {
                for dword in reports {
                    if let Err(error) = release_rpp(tx, wd, io, dword, released) {
                        outcome = Err(error);
                        break;
                    }
                }
            }
            // cannot process RP frame not set FS/LS
            Err(_) => outcome = Ok(0),
        }
        buffer.sync_for_device(0..RX_BUF_SIZE)?;
        let cnt = outcome?;
        if cnt == 1 {
            rxbd_increase(&mut ring.bd, 1);
        }
        Ok(cnt)
    }

    /// `rtw89_pci_check_and_reclaim_tx_resource` for `txch`: how many frames
    /// it can take now. CH12 reclaims its commands' buffers
    /// (`__rtw89_pci_check_and_reclaim_tx_fwcmd_resource`) and counts free
    /// BDs. A data channel short of BDs or pages first releases what RPQ
    /// holds (`rtw89_pci_release_tx`, frames handed to `released`), then,
    /// still short of BDs, reclaims those the hardware read; it counts the
    /// lesser of free BDs and free pages.
    pub fn check_and_reclaim_tx_resource<I: Io + ?Sized>(
        &mut self,
        io: &mut I,
        txch: TxChannel,
        mut released: impl FnMut(Completion),
    ) -> Result<u32, Error> {
        if txch == TxChannel::Ch12 {
            self.reclaim_fwcmd(io)?;
            return self.avail_txbd(txch);
        }
        let free = |rings: &Self| -> Result<(u32, u32), Error> {
            let wd = rings.wd_ring(txch).ok_or(Error::NoWdRing(txch))?;
            Ok((rings.avail_txbd(txch)?, wd.curr_num()))
        };
        let (bd_cnt, wd_cnt) = free(self)?;
        if wd_cnt == 0 || bd_cnt == 0 {
            let cnt = recalc_rx(io, &mut self.rx[RxChannel::Rpq as usize].bd)?;
            if cnt != 0 {
                self.release_tx(io, cnt, &mut released)?;
            } else if wd_cnt == 0 {
                return Ok(0);
            }
            if self.avail_txbd(txch)? == 0 {
                self.reclaim_txbd(io, txch)?;
            }
        }
        let (bd_cnt, wd_cnt) = free(self)?;
        Ok(bd_cnt.min(wd_cnt))
    }
}
