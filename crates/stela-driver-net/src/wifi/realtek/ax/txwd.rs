// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! The TXWD body and WD info an RTL8852B's DMA reads in front of a packet,
//! as pinned rtw89 builds them: `struct rtw89_txwd_body` and `struct
//! rtw89_txwd_info` (core.h), their fields as txrx.h names them, and
//! `rtw89_core_fill_txdesc` (core.c), which `rtw8852b_chip_ops` names for
//! both `fill_txdesc` and `fill_txdesc_fwcmd`.
//!
//! [`DescInfo`] holds the `struct rtw89_tx_desc_info` members the body and
//! the info take, in their declared widths. [`DescInfo::fwcmd`] is what
//! `rtw89_core_tx_update_desc_info` leaves for a firmware command
//! (`RTW89_CORE_TX_TYPE_FWCMD`, through `rtw89_core_tx_update_h2c_info`):
//! the packet's length, DMA channel `RTW89_DMA_H2C`, no WD page, and
//! `fw_dl` as `rtw89_h2c_tx` was asked. A frame's caller fills the members
//! as `rtw89_core_tx_update_desc_info` and its `rtw89_core_tx_update_mgmt_info`
//! or `rtw89_core_tx_update_data_info` would: the queue from [`qsel`] or
//! [`QSEL_B0_MGMT`], its channel from [`ch_dma`], the 802.11 sequence
//! number, `wd_page`, and `en_wd_info` with the rate, A-MPDU and security
//! members of the info.
//!
//! [`DescInfo::body`] is what `rtw89_core_fill_txdesc` writes into a zeroed
//! body: dwords 0, 2 and 3 (`rtw89_build_txwd_body0`, `…_body2`, `…_body3`),
//! the others left zero. With `en_wd_info` it also writes the info behind
//! the body, dwords 0 to 4 (`rtw89_build_txwd_info0` to `…_info4`), dword 5
//! left zero ([`DescInfo::wd`]).
//!
//! What this leaves out, and why: the `rtw89_tx_desc_info` members only the
//! other generations' builders read (`addr_info_nr`, `sec_keyid` and
//! `sec_seq` for the v1 body, `er_cap` for the v1 info) and those no builder
//! reads (`hiq`, `upd_wlan_hdr`, `mlo`, `sw_mld`): the AX descriptor has no
//! field for them. How a frame's members are chosen
//! (`rtw89_core_tx_update_desc_info` and its helpers) is the station's, a
//! later step. A descriptor built here proves only its bytes; nothing shows
//! the chip accepts it.
use super::io::prep;

/// `sizeof(struct rtw89_txwd_body)`, which is also
/// `rtw8852b_chip_info.h2c_desc_size` and `txwd_body_size`.
pub const BODY_SIZE: usize = 24;
/// `sizeof(struct rtw89_txwd_info)`: `rtw8852b_chip_info.txwd_info_size`.
pub const INFO_SIZE: usize = 24;

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
/// TX WD info dword 0: `RTW89_TXWD_INFO0_*`.
pub const INFO0_USE_RATE: u32 = 1 << 30;
pub const INFO0_DATA_BW: u32 = 0x3000_0000;
pub const INFO0_GI_LTF: u32 = 0x0e00_0000;
pub const INFO0_DATA_RATE: u32 = 0x01ff_0000;
pub const INFO0_DATA_STBC: u32 = 1 << 12;
pub const INFO0_DATA_LDPC: u32 = 1 << 11;
pub const INFO0_DISDATAFB: u32 = 1 << 10;
pub const INFO0_MULTIPORT_ID: u32 = 0x0000_0070;
/// TX WD info dword 1: `RTW89_TXWD_INFO1_*`.
pub const INFO1_DATA_TXCNT_LMT_SEL: u32 = 1 << 31;
pub const INFO1_DATA_TXCNT_LMT: u32 = 0x7e00_0000;
pub const INFO1_DATA_RTY_LOWEST_RATE: u32 = 0x01ff_0000;
pub const INFO1_A_CTRL_BSR: u32 = 1 << 14;
pub const INFO1_MAX_AGGNUM: u32 = 0x0000_00ff;
/// TX WD info dword 2: `RTW89_TXWD_INFO2_*`.
pub const INFO2_AMPDU_DENSITY: u32 = 0x001c_0000;
pub const INFO2_SEC_TYPE: u32 = 0x0000_1e00;
pub const INFO2_SEC_HW_ENC: u32 = 1 << 8;
pub const INFO2_SEC_CAM_IDX: u32 = 0x0000_00ff;
/// TX WD info dword 3: `RTW89_TXWD_INFO3_SPE_RPT`.
pub const INFO3_SPE_RPT: u32 = 1 << 10;
/// TX WD info dword 4: `RTW89_TXWD_INFO4_*`.
pub const INFO4_HW_RTS_EN: u32 = 1 << 31;
pub const INFO4_RTS_EN: u32 = 1 << 27;
pub const INFO4_SW_DEFINE: u32 = 0x0000_000f;

/// `RTW89_DMA_H2C`: the DMA channel of firmware commands.
pub const DMA_H2C: u8 = 12;

/// `enum rtw89_tx_qsel` (txrx.h): the MAC queues a descriptor names.
pub const QSEL_BE_0: u8 = 0x00;
pub const QSEL_BK_0: u8 = 0x01;
pub const QSEL_VI_0: u8 = 0x02;
pub const QSEL_VO_0: u8 = 0x03;
pub const QSEL_B0_BCN: u8 = 0x10;
pub const QSEL_B0_HI: u8 = 0x11;
pub const QSEL_B0_MGMT: u8 = 0x12;
pub const QSEL_B1_HI: u8 = 0x19;
pub const QSEL_B1_MGMT: u8 = 0x1a;
/// `RTW89_MGMT_HW_SSN_SEL` and `RTW89_MGMT_HW_SEQ_MODE`: the hardware
/// sequence number `rtw89_core_tx_update_mgmt_info` asks for.
pub const MGMT_HW_SSN_SEL: u8 = 1;
pub const MGMT_HW_SEQ_MODE: u8 = 1;

/// `rtw89_core_get_qsel` (txrx.h): a TID's AC queue of band 0; a TID above
/// 7, which rtw89 warns of, is best effort.
pub const fn qsel(tid: u8) -> u8 {
    match tid {
        1 | 2 => QSEL_BK_0,
        4 | 5 => QSEL_VI_0,
        6 | 7 => QSEL_VO_0,
        _ => QSEL_BE_0,
    }
}

/// `rtw89_core_get_tid_indicate` (txrx.h): the second TID of each AC.
pub const fn tid_indicate(tid: u8) -> bool {
    matches!(tid, 2 | 3 | 5 | 7)
}

/// `rtw89_core_get_ch_dma` (core.c), RTL8852B's `get_ch_dma` for PCIe: the
/// `enum rtw89_tx_channel` of a queue. A queue it does not name, which
/// rtw89 warns of, goes to ACH0.
pub const fn ch_dma(qsel: u8) -> u8 {
    match qsel {
        0x01 | 0x05 | 0x09 | 0x0d => 1,
        0x02 | 0x06 | 0x0a | 0x0e => 2,
        0x03 | 0x07 | 0x0b | 0x0f => 3,
        QSEL_B0_MGMT => 8,
        QSEL_B0_HI => 9,
        QSEL_B1_MGMT => 10,
        QSEL_B1_HI => 11,
        _ => 0,
    }
}

/// The `struct rtw89_tx_desc_info` members the AX body and info take, in
/// their declared widths; `sn` and `tx_cnt_lmt` are 4- and 6-bit fields
/// there, cut here where the builders place them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DescInfo {
    /// The frame's length (`skb->len`).
    pub pkt_size: u16,
    pub wp_offset: u8,
    pub mac_id: u8,
    /// `enum rtw89_tx_qsel`.
    pub qsel: u8,
    /// `enum rtw89_tx_channel`: the ring the frame goes on.
    pub ch_dma: u8,
    pub hdr_llc_len: u8,
    /// A broadcast or multicast receiver: no RTS.
    pub is_bmc: bool,
    /// The WD info follows the body.
    pub en_wd_info: bool,
    pub wd_page: bool,
    /// `data_rate` is used as given.
    pub use_rate: bool,
    /// No rate fallback.
    pub dis_data_fb: bool,
    pub tid_indicate: bool,
    pub agg_en: bool,
    pub bk: bool,
    pub ampdu_density: u8,
    pub ampdu_num: u8,
    /// The chip encrypts with security CAM entry `sec_cam_idx`.
    pub sec_en: bool,
    /// A TX report is asked for.
    pub report: bool,
    pub tx_cnt_lmt_en: bool,
    pub sn: u8,
    pub tx_cnt_lmt: u8,
    pub sec_type: u8,
    pub sec_cam_idx: u8,
    /// `enum rtw89_hw_rate`.
    pub data_rate: u16,
    pub data_retry_lowest_rate: u16,
    /// `enum rtw89_bandwidth`.
    pub data_bw: u8,
    /// `enum rtw89_gi_ltf`.
    pub gi_ltf: u8,
    pub fw_dl: bool,
    /// The 802.11 sequence number (`SW_SEQ`).
    pub seq: u16,
    pub a_ctrl_bsr: bool,
    pub hw_ssn_sel: u8,
    pub hw_seq_mode: u8,
    pub port: u8,
    pub stbc: bool,
    pub ldpc: bool,
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
            is_bmc: false,
            en_wd_info: false,
            wd_page: false,
            use_rate: false,
            dis_data_fb: false,
            tid_indicate: false,
            agg_en: false,
            bk: false,
            ampdu_density: 0,
            ampdu_num: 0,
            sec_en: false,
            report: false,
            tx_cnt_lmt_en: false,
            sn: 0,
            tx_cnt_lmt: 0,
            sec_type: 0,
            sec_cam_idx: 0,
            data_rate: 0,
            data_retry_lowest_rate: 0,
            data_bw: 0,
            gi_ltf: 0,
            fw_dl,
            seq: 0,
            a_ctrl_bsr: false,
            hw_ssn_sel: 0,
            hw_seq_mode: 0,
            port: 0,
            stbc: false,
            ldpc: false,
        }
    }

    /// `rtw89_build_txwd_body0`.
    pub const fn body0(&self) -> u32 {
        prep(self.wp_offset as u32, BODY0_WP_OFFSET)
            | prep(self.en_wd_info as u32, BODY0_WD_INFO_EN)
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

    /// `rtw89_build_txwd_info0`.
    pub const fn info0(&self) -> u32 {
        prep(self.use_rate as u32, INFO0_USE_RATE)
            | prep(self.data_bw as u32, INFO0_DATA_BW)
            | prep(self.gi_ltf as u32, INFO0_GI_LTF)
            | prep(self.data_rate as u32, INFO0_DATA_RATE)
            | prep(self.stbc as u32, INFO0_DATA_STBC)
            | prep(self.ldpc as u32, INFO0_DATA_LDPC)
            | prep(self.dis_data_fb as u32, INFO0_DISDATAFB)
            | prep(self.port as u32, INFO0_MULTIPORT_ID)
    }

    /// `rtw89_build_txwd_info1`.
    pub const fn info1(&self) -> u32 {
        prep(self.ampdu_num as u32, INFO1_MAX_AGGNUM)
            | prep(self.a_ctrl_bsr as u32, INFO1_A_CTRL_BSR)
            | prep(
                self.data_retry_lowest_rate as u32,
                INFO1_DATA_RTY_LOWEST_RATE,
            )
            | prep(self.tx_cnt_lmt_en as u32, INFO1_DATA_TXCNT_LMT_SEL)
            | prep(self.tx_cnt_lmt as u32, INFO1_DATA_TXCNT_LMT)
    }

    /// `rtw89_build_txwd_info2`.
    pub const fn info2(&self) -> u32 {
        prep(self.ampdu_density as u32, INFO2_AMPDU_DENSITY)
            | prep(self.sec_type as u32, INFO2_SEC_TYPE)
            | prep(self.sec_en as u32, INFO2_SEC_HW_ENC)
            | prep(self.sec_cam_idx as u32, INFO2_SEC_CAM_IDX)
    }

    /// `rtw89_build_txwd_info3`.
    pub const fn info3(&self) -> u32 {
        prep(self.report as u32, INFO3_SPE_RPT)
    }

    /// `rtw89_build_txwd_info4`: RTS unless the receiver is a group,
    /// hardware RTS always.
    pub const fn info4(&self) -> u32 {
        prep(!self.is_bmc as u32, INFO4_RTS_EN)
            | prep(1, INFO4_HW_RTS_EN)
            | prep(self.sn as u32, INFO4_SW_DEFINE)
    }

    /// The six body dwords `rtw89_core_fill_txdesc` leaves in a zeroed body.
    pub const fn dwords(&self) -> [u32; 6] {
        [self.body0(), 0, self.body2(), self.body3(), 0, 0]
    }

    /// The six info dwords it leaves in zeroed info when `en_wd_info` is set.
    pub const fn info_dwords(&self) -> [u32; 6] {
        [
            self.info0(),
            self.info1(),
            self.info2(),
            self.info3(),
            self.info4(),
            0,
        ]
    }

    /// The body as the chip reads it, little-endian.
    pub fn body(&self) -> [u8; BODY_SIZE] {
        let mut bytes = [0; BODY_SIZE];
        for (index, dword) in self.dwords().into_iter().enumerate() {
            bytes[4 * index..4 * index + 4].copy_from_slice(&dword.to_le_bytes());
        }
        bytes
    }

    /// `rtw89_core_fill_txdesc` over zeroed bytes: the body, then the info
    /// when `en_wd_info` is set, and how many bytes that is
    /// (`txwd_body_size`, plus `txwd_info_size` with the info).
    pub fn wd(&self) -> ([u8; BODY_SIZE + INFO_SIZE], usize) {
        let mut bytes = [0; BODY_SIZE + INFO_SIZE];
        bytes[..BODY_SIZE].copy_from_slice(&self.body());
        if !self.en_wd_info {
            return (bytes, BODY_SIZE);
        }
        for (index, dword) in self.info_dwords().into_iter().enumerate() {
            let at = BODY_SIZE + 4 * index;
            bytes[at..at + 4].copy_from_slice(&dword.to_le_bytes());
        }
        (bytes, BODY_SIZE + INFO_SIZE)
    }
}

#[cfg(test)]
mod tests;
