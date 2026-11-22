// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! The TXWD body an RTL8852B's DMA reads in front of a packet, as pinned
//! rtw89 builds it: `struct rtw89_txwd_body` (core.h), its fields as txrx.h
//! names them, and `rtw89_core_fill_txdesc` (core.c), which
//! `rtw8852b_chip_ops` names for both `fill_txdesc` and `fill_txdesc_fwcmd`.
//!
//! [`DescInfo`] holds the `struct rtw89_tx_desc_info` members the body
//! takes. [`DescInfo::fwcmd`] is what `rtw89_core_tx_update_desc_info`
//! leaves for a firmware command (`RTW89_CORE_TX_TYPE_FWCMD`, through
//! `rtw89_core_tx_update_h2c_info`): the packet's length, DMA channel
//! `RTW89_DMA_H2C`, no WD page, and `fw_dl` as `rtw89_h2c_tx` was asked.
//! [`DescInfo::body`] is what `rtw89_core_fill_txdesc` writes into the 24
//! zeroed bytes `rtw89_pci_fwcmd_submit` pushes in front of the command:
//! dwords 0, 2 and 3 (`rtw89_build_txwd_body0`, `…_body2`, `…_body3`), the
//! others left zero.
//!
//! What this leaves out, and why: the WD info `rtw89_core_fill_txdesc`
//! appends when `en_wd_info` is set (so `WD_INFO_EN` stays clear here), and
//! how the data path fills the other members (`rtw89_core_tx_update_mgmt_info`,
//! `rtw89_core_tx_update_data_info`): a firmware command has neither, and
//! the data path is a later step. A body built here proves only its bytes;
//! nothing shows the chip accepts it.
use super::io::prep;

/// `sizeof(struct rtw89_txwd_body)`, which is also
/// `rtw8852b_chip_info.h2c_desc_size`.
pub const BODY_SIZE: usize = 24;

/// TX WD body dword 0: `RTW89_TXWD_BODY0_*`.
pub const BODY0_WP_OFFSET: u32 = 0xff00_0000;
pub const BODY0_MORE_DATA: u32 = 1 << 23;
pub const BODY0_WD_INFO_EN: u32 = 1 << 22;
pub const BODY0_FW_DL: u32 = 1 << 20;
pub const BODY0_CHANNEL_DMA: u32 = 0x000f_0000;
pub const BODY0_HDR_LLC_LEN: u32 = 0x0000_f800;
pub const BODY0_STF_MODE: u32 = 1 << 10;
pub const BODY0_WD_PAGE: u32 = 1 << 7;
pub const BODY0_HW_AMSDU: u32 = 1 << 5;
pub const BODY0_HW_SSN_SEL: u32 = 0x0000_000c;
pub const BODY0_HW_SSN_MODE: u32 = 0x0000_0003;
/// TX WD body dword 2: `RTW89_TXWD_BODY2_*`.
pub const BODY2_MACID: u32 = 0x7f00_0000;
pub const BODY2_TID_INDICATE: u32 = 1 << 23;
pub const BODY2_QSEL: u32 = 0x007e_0000;
pub const BODY2_TXPKT_SIZE: u32 = 0x0000_3fff;
/// TX WD body dword 3: `RTW89_TXWD_BODY3_*`.
pub const BODY3_BK: u32 = 1 << 13;
pub const BODY3_AGG_EN: u32 = 1 << 12;
pub const BODY3_SW_SEQ: u32 = 0x0000_0fff;

/// `RTW89_DMA_H2C`: the DMA channel of firmware commands.
pub const DMA_H2C: u8 = 12;

/// The `struct rtw89_tx_desc_info` members the TXWD body takes, in their
/// declared widths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DescInfo {
    pub pkt_size: u16,
    pub wp_offset: u8,
    pub mac_id: u8,
    pub qsel: u8,
    pub ch_dma: u8,
    pub hdr_llc_len: u8,
    pub wd_page: bool,
    pub tid_indicate: bool,
    pub agg_en: bool,
    pub bk: bool,
    pub fw_dl: bool,
    pub seq: u16,
    pub hw_ssn_sel: u8,
    pub hw_seq_mode: u8,
}

impl DescInfo {
    /// `rtw89_core_tx_update_desc_info` for `RTW89_CORE_TX_TYPE_FWCMD`:
    /// `pkt_size` is the skb's length, cut to the member's 16 bits, then
    /// `rtw89_core_tx_update_h2c_info` clears `is_bmc` and `wd_page` and
    /// picks `RTW89_DMA_H2C`. Every other member stays as `rtw89_h2c_tx`'s
    /// zeroed request left it, but `fw_dl`.
    pub const fn fwcmd(skb_len: u32, fw_dl: bool) -> Self {
        Self {
            pkt_size: skb_len as u16,
            wp_offset: 0,
            mac_id: 0,
            qsel: 0,
            ch_dma: DMA_H2C,
            hdr_llc_len: 0,
            wd_page: false,
            tid_indicate: false,
            agg_en: false,
            bk: false,
            fw_dl,
            seq: 0,
            hw_ssn_sel: 0,
            hw_seq_mode: 0,
        }
    }

    /// `rtw89_build_txwd_body0`; `en_wd_info` is never set here.
    pub const fn body0(&self) -> u32 {
        prep(self.wp_offset as u32, BODY0_WP_OFFSET)
            | prep(self.ch_dma as u32, BODY0_CHANNEL_DMA)
            | prep(self.hdr_llc_len as u32, BODY0_HDR_LLC_LEN)
            | prep(self.wd_page as u32, BODY0_WD_PAGE)
            | prep(self.fw_dl as u32, BODY0_FW_DL)
            | prep(self.hw_ssn_sel as u32, BODY0_HW_SSN_SEL)
            | prep(self.hw_seq_mode as u32, BODY0_HW_SSN_MODE)
    }

    /// `rtw89_build_txwd_body2`.
    pub const fn body2(&self) -> u32 {
        prep(self.tid_indicate as u32, BODY2_TID_INDICATE)
            | prep(self.qsel as u32, BODY2_QSEL)
            | prep(self.pkt_size as u32, BODY2_TXPKT_SIZE)
            | prep(self.mac_id as u32, BODY2_MACID)
    }

    /// `rtw89_build_txwd_body3`.
    pub const fn body3(&self) -> u32 {
        prep(self.seq as u32, BODY3_SW_SEQ)
            | prep(self.agg_en as u32, BODY3_AGG_EN)
            | prep(self.bk as u32, BODY3_BK)
    }

    /// The six dwords `rtw89_core_fill_txdesc` leaves in a zeroed body.
    pub const fn dwords(&self) -> [u32; 6] {
        [self.body0(), 0, self.body2(), self.body3(), 0, 0]
    }

    /// The body as the chip reads it, little-endian.
    pub fn body(&self) -> [u8; BODY_SIZE] {
        let mut bytes = [0; BODY_SIZE];
        for (index, dword) in self.dwords().into_iter().enumerate() {
            bytes[4 * index..4 * index + 4].copy_from_slice(&dword.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests;
