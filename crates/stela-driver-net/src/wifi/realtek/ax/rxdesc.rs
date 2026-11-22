// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! What an RTL8852BE writes into an RXQ buffer, read as pinned rtw89 reads
//! it (core.c, pci.c, rtw8852b_common.c), for every packet type:
//!
//! - [`RxDescInfo::query`]: `rtw89_core_query_rxdesc`, RTL8852B's
//!   `query_rxdesc`, for the AX short and long descriptor, every field it
//!   sets, `shift` left at 0 as the AX query leaves it;
//! - [`split`]: `rtw89_pci_rxbd_deliver_skbs` for a buffer that holds one
//!   whole packet: the descriptor behind the `rtw89_pci_rxbd_info` dword and
//!   the packet behind the descriptor and driver info, `copy_len` bytes as
//!   rtw89 copies them;
//! - [`PhyPpdu::process`]: `rtw89_core_rx_process_ppdu_sts` up to its
//!   pending frames: `rtw89_core_rx_process_mac_ppdu` (the MAC info, its
//!   users, RX counters and PLCP header skipped), `rtw89_core_rx_process_phy_ppdu`
//!   with `rtw89_core_update_phy_ppdu` (the PHY status header's IE map and
//!   RSSI), and `rtw89_core_rx_parse_phy_sts` (the IEs walked by AX's
//!   `physt_ie_len`, IE00 and IE01 parsed by `rtw89_core_parse_phy_status_ie00`
//!   and `_ie01`, then `__rtw8852bx_convert_rpl_to_rssi`);
//! - [`RxStatus::update`]: the part of `rtw89_core_update_rx_status` the
//!   PPDU match and the report read: the tuned frequency, the FCS and
//!   decryption flags, the bandwidth, rate index and GI the match compares;
//! - [`RxStatus::query_ppdu`]: `__rtw8852bx_query_ppdu` with
//!   `rtw8852bx_fill_freq_with_ppdu`: the signal from the stronger path, each
//!   path's, and the frequency IE01's channel index names;
//! - [`Sorter`]: `rtw89_core_rx` and `rtw89_core_rx_process_report`: C2H and
//!   PPDU status told apart from frames, a frame of a long descriptor whose
//!   type is management or data held until the PPDU status of its PPDU
//!   count arrives (`rtw89_core_rx_pending_skb`, matched by
//!   `rtw89_core_rx_ppdu_match`) or the count moves on
//!   (`rtw89_core_flush_ppdu_rx_queue`).
//!
//! What this leaves out, and why:
//! - Packets spread over more than one RX buffer, which
//!   `rtw89_pci_rxbd_deliver_skbs` reassembles: an RX buffer holds 11498
//!   bytes, more than the longest MPDU, so [`split`] refuses a segment.
//! - What `rtw89_core_rx_to_mac80211` and its helpers do for mac80211:
//!   radiotap, statistics, station and CFO tracking
//!   (`rtw89_phy_cfo_parse`), antenna diversity, the packet number check,
//!   the MCC correction and `rtw89_correct_cck_chan`, which moves a CCK rate
//!   reported on 5 GHz to the previous channel: Stela has no previous
//!   channel and reports the rate as read. IE09 and IE10, which rtw89 parses
//!   in monitor mode only.
//! - Bounds rtw89 does not check: a descriptor, MAC info or PHY status
//!   header past the bytes written is refused here ([`Error`]), where rtw89
//!   reads past them.
//! - The frequency `rtw89_core_update_rx_status` takes during a firmware
//!   scan: Stela tunes the channel itself, so the tuned one is the
//!   chandef's.
//!
//! Reading a descriptor proves what the chip wrote, not that the frame is
//! intact: [`RxDescInfo::crc32_err`] and [`RxDescInfo::icv_err`] say what the
//! chip found.
use super::{
    c2h::{
        RX_TYPE_C2H, RX_TYPE_PPDU_STAT, RX_TYPE_WIFI, RXBD_INFO_SIZE, RXDESC_LONG, RXDESC_SHORT,
    },
    io::field,
    pci::ring::RxBdInfo,
};
use alloc::vec::Vec;

/// RX descriptor dword 0 (`AX_RXD_*`).
pub const RXD_RPKT_LEN_MASK: u32 = 0x0000_3fff;
pub const RXD_BB_SEL: u32 = 1 << 22;
pub const RXD_MAC_INFO_VLD: u32 = 1 << 23;
pub const RXD_RPKT_TYPE_MASK: u32 = 0x0f00_0000;
pub const RXD_DRV_INFO_SIZE_MASK: u32 = 0x7000_0000;
pub const RXD_LONG_RXD: u32 = 1 << 31;
/// Dword 1.
pub const RXD_PPDU_TYPE_MASK: u32 = 0x0000_000f;
pub const RXD_PPDU_CNT_MASK: u32 = 0x0000_0070;
pub const RXD_SR_EN: u32 = 1 << 7;
pub const RXD_USER_ID_MASK: u32 = 0x0000_ff00;
pub const RXD_RX_DATARATE_MASK: u32 = 0x01ff_0000;
pub const RXD_RX_GI_LTF_MASK: u32 = 0x0e00_0000;
pub const RXD_BW_MASK: u32 = 0xc000_0000;
/// Dword 3.
pub const RXD_A1_MATCH: u32 = 1 << 0;
pub const RXD_SW_DEC: u32 = 1 << 1;
pub const RXD_HW_DEC: u32 = 1 << 2;
pub const RXD_AMPDU: u32 = 1 << 3;
pub const RXD_CRC32_ERR: u32 = 1 << 9;
pub const RXD_ICV_ERR: u32 = 1 << 10;
/// Dword 4 (long descriptor).
pub const RXD_TYPE_MASK: u32 = 0x0000_0003;
/// Dword 5.
pub const RXD_SEC_CAM_IDX_MASK: u32 = 0x0000_00ff;
pub const RXD_ADDR_CAM_MASK: u32 = 0x0000_ff00;
pub const RXD_MAC_ID_MASK: u32 = 0x00ff_0000;
pub const RXD_RX_PL_ID_MASK: u32 = 0x0f00_0000;
pub const RXD_ADDR_CAM_VLD: u32 = 1 << 28;
/// Dword 7.
pub const RXD_SEC_TYPE_MASK: u32 = 0x001e_0000;

/// `enum rtw89_rx_frame_type`.
pub const RX_TYPE_MGNT: u8 = 0;
pub const RX_TYPE_CTRL: u8 = 1;
pub const RX_TYPE_DATA: u8 = 2;
/// `PPDU_FILTER_BITMAP`: `PHYSTS_MGNT | PHYSTS_DATA`, the frame types held
/// for their PPDU status.
pub const PPDU_FILTER_BITMAP: u32 = 1 << RX_TYPE_MGNT | 1 << RX_TYPE_DATA;
/// `RTW89_MAX_PPDU_CNT`.
pub const MAX_PPDU_CNT: u8 = 8;

/// `RTW89_PPDU_MAC_INFO_SIZE`, `_USR_SIZE` and `_RX_CNT_SIZE`, and
/// `rtw8852b_chip_info.ppdu_max_usr`.
pub const PPDU_MAC_INFO_SIZE: usize = 8;
pub const PPDU_MAC_INFO_USR_SIZE: usize = 4;
pub const PPDU_MAC_RX_CNT_SIZE: usize = 96;
pub const PPDU_MAX_USR: u8 = 4;
/// `struct rtw89_rxinfo`: `RTW89_RXINFO_W0_USR_NUM`, `_RX_CNT_VLD` and
/// `RTW89_RXINFO_W1_PLCP_LEN`; `struct rtw89_rxinfo_user`'s bits.
pub const RXINFO_W0_USR_NUM: u32 = 0x0000_000f;
pub const RXINFO_W0_RX_CNT_VLD: u32 = 1 << 29;
pub const RXINFO_W1_PLCP_LEN: u32 = 0x00ff_0000;
pub const RXINFO_USER_MAC_ID_VALID: u32 = 1 << 0;
pub const RXINFO_USER_DATA: u32 = 1 << 1;
pub const RXINFO_USER_BCN: u32 = 1 << 4;

/// `PHY_STS_HDR_LEN` and `struct rtw89_phy_sts_hdr`'s fields.
pub const PHY_STS_HDR_LEN: usize = 8;
pub const PHY_STS_HDR_W0_IE_MAP: u32 = 0x0000_001f;
pub const PHY_STS_HDR_W0_HDR_2_EN: u32 = 1 << 5;
pub const PHY_STS_HDR_W0_VALID: u32 = 1 << 7;
pub const PHY_STS_HDR_W0_LEN: u32 = 0x0000_ff00;
pub const PHY_STS_HDR_W0_RSSI_AVG: u32 = 0xff00_0000;
/// `struct rtw89_phy_sts_hdr_v2`'s path enables, read when HDR_2_EN is set.
pub const PHY_STS_HDR_V2_W0_PATH_EN: u32 = 0x001f_0000;
/// `struct rtw89_phy_sts_iehdr`.
pub const PHY_STS_IEHDR_TYPE: u32 = 0x0000_001f;
pub const PHY_STS_IEHDR_LEN: u32 = 0x0000_0fe0;
/// IE00 (CCK) and IE01 (OFDM) fields.
pub const PHY_STS_IE00_W0_RPL: u32 = 0x0000_ff80;
pub const PHY_STS_IE00_W3_RX_PATH_EN: u32 = 0xf000_0000;
pub const PHY_STS_IE01_W0_RSSI_AVG_FD: u32 = 0x0000_ff00;
pub const PHY_STS_IE01_W0_CH_IDX: u32 = 0x00ff_0000;
pub const PHY_STS_IE01_W0_RX_PATH_EN: u32 = 0xf000_0000;
pub const PHY_STS_IE01_W2_AVG_SNR: u32 = 0x0000_003f;
pub const PHY_STS_IE01_W2_EVM_MAX: u32 = 0x0000_ff00;
pub const PHY_STS_IE01_W2_EVM_MIN: u32 = 0x00ff_0000;
pub const PHY_STS_IE01_W2_SU: u32 = 1 << 27;
pub const PHY_STS_IE01_W2_LDPC: u32 = 1 << 28;
pub const PHY_STS_IE01_W2_STBC: u32 = 1 << 30;
pub const PHY_STS_IE01_W3_BF: u32 = 1 << 8;
/// `RTW89_PHYSTS_IE00_CMN_CCK`, `RTW89_PHYSTS_IE01_CMN_OFDM` and
/// `RTW89_PHYSTS_IE09_FTR_0`.
pub const PHYSTS_IE00_CMN_CCK: u8 = 0;
pub const PHYSTS_IE01_CMN_OFDM: u8 = 1;
pub const PHYSTS_IE09_FTR_0: u8 = 9;
/// `RTW89_CCK_PKT`: IE maps below it are reports rtw89 bypasses outside
/// monitor mode.
pub const CCK_PKT: u8 = 11;
/// `VAR_LEN` and `VAR_LEN_UNIT`.
pub const VAR_LEN: u8 = 0xff;
pub const VAR_LEN_UNIT: u16 = 8;
/// `rtw89_phy_gen_ax.physt_ie_len`, by IE type.
pub const PHYST_IE_LEN: [u8; 32] = [
    16, 32, 24, 24, 8, 8, 8, 8, VAR_LEN, 8, VAR_LEN, 176, VAR_LEN, VAR_LEN, VAR_LEN, VAR_LEN,
    VAR_LEN, VAR_LEN, 16, 24, VAR_LEN, VAR_LEN, VAR_LEN, 0, 24, 24, 24, 24, 32, 32, 32, 32,
];
/// `RTW89_HW_RATE_OFDM6`.
pub const HW_RATE_OFDM6: u16 = 0x4;
/// `MAX_RSSI` and `RSSI_FACTOR` of `RTW89_RSSI_RAW_TO_DBM`.
pub const MAX_RSSI: i16 = 110;
pub const RSSI_FACTOR: u8 = 1;
/// `RF_PATH_MAX` and RTL8852B's `rf_path_num`.
pub const RF_PATH_MAX: usize = 4;
pub const RF_PATH_NUM: usize = 2;

/// The data rate's mode (`DATA_RATE_MODE_CTRL_MASK`) and its indices on an
/// AX chip.
const DATA_RATE_MODE_CTRL_MASK: u16 = 0x0180;
const DATA_RATE_NOT_HT_IDX_MASK: u16 = 0x000f;
const DATA_RATE_HT_IDX_MASK: u16 = 0x001f;
const DATA_RATE_VHT_HE_IDX_MASK: u16 = 0x000f;
pub const DATA_RATE_MODE_NON_HT: u8 = 0;
pub const DATA_RATE_MODE_HT: u8 = 1;
pub const DATA_RATE_MODE_VHT: u8 = 2;
pub const DATA_RATE_MODE_HE: u8 = 3;

/// `NL80211_RATE_INFO_HE_GI_0_8`, `_1_6` and `_3_2`, and the `U8_MAX` the
/// PPDU match's conversion gives an unknown GI.
pub const HE_GI_0_8: u8 = 0;
pub const HE_GI_1_6: u8 = 1;
pub const HE_GI_3_2: u8 = 2;
pub const GI_UNKNOWN: u8 = u8::MAX;

/// Why a buffer or a report was not read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A buffer that is not one whole packet (`fs` and `ls` not both set).
    Segmented { fs: bool, ls: bool },
    /// Fewer bytes written than the descriptor or a header needs.
    Truncated { needed: usize, written: usize },
}

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn need(needed: usize, written: usize) -> Result<(), Error> {
    if needed > written {
        return Err(Error::Truncated { needed, written });
    }
    Ok(())
}

/// `struct rtw89_rx_desc_info` as `rtw89_core_query_rxdesc` fills it from
/// zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxDescInfo {
    pub pkt_size: u16,
    pub drv_info_size: u8,
    pub long_rxdesc: bool,
    pub pkt_type: u8,
    pub mac_info_valid: bool,
    /// `enum rtw89_bandwidth` as the descriptor's two bits give it.
    pub bw: u8,
    pub data_rate: u16,
    pub gi_ltf: u8,
    pub user_id: u8,
    pub sr_en: bool,
    pub ppdu_cnt: u8,
    pub ppdu_type: u8,
    pub free_run_cnt: u32,
    pub icv_err: bool,
    pub crc32_err: bool,
    pub hw_dec: bool,
    pub sw_dec: bool,
    pub addr1_match: bool,
    pub ampdu: bool,
    /// Never read by the AX query: 0.
    pub shift: u8,
    /// Never read by the AX query: 0, PHY 0.
    pub bb_sel: bool,
    /// Where the descriptor starts plus the shift and driver info.
    pub offset: u16,
    pub rxd_len: u16,
    pub ready: bool,
    /// The long descriptor's fields, 0 for a short one.
    pub frame_type: u8,
    pub addr_cam_valid: bool,
    pub addr_cam_id: u8,
    pub sec_cam_id: u8,
    pub mac_id: u8,
    pub rx_pl_id: u8,
    pub sec_type: u8,
}

impl RxDescInfo {
    /// `rtw89_core_query_rxdesc(rtwdev, desc_info, data, data_offset)` over
    /// a zeroed `desc_info`: the descriptor at `data_offset` of `data`,
    /// whose short 16 bytes, or long 32, must be there.
    pub fn query(data: &[u8], data_offset: usize) -> Result<Self, Error> {
        need(data_offset + RXDESC_SHORT, data.len())?;
        let w = |n: usize| dword(data, data_offset + 4 * n);
        let (dword0, dword1, dword2, dword3) = (w(0), w(1), w(2), w(3));
        let mut desc = Self {
            pkt_size: field(dword0, RXD_RPKT_LEN_MASK) as u16,
            drv_info_size: field(dword0, RXD_DRV_INFO_SIZE_MASK) as u8,
            long_rxdesc: dword0 & RXD_LONG_RXD != 0,
            pkt_type: field(dword0, RXD_RPKT_TYPE_MASK) as u8,
            mac_info_valid: dword0 & RXD_MAC_INFO_VLD != 0,
            bw: field(dword1, RXD_BW_MASK) as u8,
            data_rate: field(dword1, RXD_RX_DATARATE_MASK) as u16,
            gi_ltf: field(dword1, RXD_RX_GI_LTF_MASK) as u8,
            user_id: field(dword1, RXD_USER_ID_MASK) as u8,
            sr_en: dword1 & RXD_SR_EN != 0,
            ppdu_cnt: field(dword1, RXD_PPDU_CNT_MASK) as u8,
            ppdu_type: field(dword1, RXD_PPDU_TYPE_MASK) as u8,
            free_run_cnt: dword2,
            icv_err: dword3 & RXD_ICV_ERR != 0,
            crc32_err: dword3 & RXD_CRC32_ERR != 0,
            hw_dec: dword3 & RXD_HW_DEC != 0,
            sw_dec: dword3 & RXD_SW_DEC != 0,
            addr1_match: dword3 & RXD_A1_MATCH != 0,
            ampdu: dword3 & RXD_AMPDU != 0,
            ..Self::default()
        };
        // shift_len = desc_info->shift << 1, the shift never read: 0.
        let shift_len = u16::from(desc.shift) << 1;
        let drv_info_len = u16::from(desc.drv_info_size) << 3;
        desc.offset = data_offset as u16 + shift_len + drv_info_len;
        desc.rxd_len = if desc.long_rxdesc {
            RXDESC_LONG as u16
        } else {
            RXDESC_SHORT as u16
        };
        desc.ready = true;
        if !desc.long_rxdesc {
            return Ok(desc);
        }
        need(data_offset + RXDESC_LONG, data.len())?;
        let (dword4, dword5, dword7) = (w(4), w(5), w(7));
        desc.frame_type = field(dword4, RXD_TYPE_MASK) as u8;
        desc.addr_cam_valid = dword5 & RXD_ADDR_CAM_VLD != 0;
        desc.addr_cam_id = field(dword5, RXD_ADDR_CAM_MASK) as u8;
        desc.sec_cam_id = field(dword5, RXD_SEC_CAM_IDX_MASK) as u8;
        desc.mac_id = field(dword5, RXD_MAC_ID_MASK) as u8;
        desc.rx_pl_id = field(dword5, RXD_RX_PL_ID_MASK) as u8;
        desc.sec_type = field(dword7, RXD_SEC_TYPE_MASK) as u8;
        Ok(desc)
    }

    /// Where the packet starts: behind the descriptor and driver info.
    pub const fn packet_offset(&self) -> usize {
        self.offset as usize + self.rxd_len as usize
    }
}

/// One whole packet of an RX buffer: its descriptor and its bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    pub desc: RxDescInfo,
    /// What rtw89 copies into the packet's skb: from behind the descriptor
    /// and driver info to the last byte written, `rx_info->len - offset`.
    pub data: &'a [u8],
}

/// `rtw89_pci_rxbd_deliver_skbs` for one buffer that is its packet's first
/// and last segment: the descriptor read at [`RXBD_INFO_SIZE`] and the
/// bytes behind it to `info.len`.
pub fn split(info: RxBdInfo, data: &[u8]) -> Result<Packet<'_>, Error> {
    if !(info.fs && info.ls) {
        return Err(Error::Segmented {
            fs: info.fs,
            ls: info.ls,
        });
    }
    let written = data.len().min(usize::from(info.len));
    let data = &data[..written];
    let desc = RxDescInfo::query(data, RXBD_INFO_SIZE)?;
    let start = desc.packet_offset();
    need(start, written)?;
    Ok(Packet {
        desc,
        data: &data[start..],
    })
}

/// Why a PPDU status gave no PHY status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PpduError {
    /// `rtw89_core_rx_process_mac_ppdu`'s "Invalid user number".
    UserNumber(u8),
    /// The MAC info and what it skips run past the report.
    MacInfoLength,
    /// The PHY status header's valid bit is clear.
    Invalid,
    /// "phy ppdu len mismatch": the header's length is not the report's.
    LengthMismatch { header: u32, report: u32 },
    /// The IE map is below `RTW89_CCK_PKT`, which rtw89 bypasses outside
    /// monitor mode.
    Bypassed(u8),
    /// "phy status parse failed": an IE of length 0 or past the end.
    ParseFailed,
    /// A PHY status shorter than its header (rtw89 reads past it).
    Truncated,
}

/// `struct rtw89_rx_phy_ppdu` as rtw89 fills it from one PPDU status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PhyPpdu {
    pub rssi_avg: u8,
    pub rssi: [u8; RF_PATH_MAX],
    pub mac_id: u8,
    pub chan_idx: u8,
    pub phy_idx: u8,
    /// `enum rtw89_phy_status_bitmap`.
    pub ie: u8,
    pub rate: u16,
    pub rpl_avg: u8,
    pub rx_path_en: u8,
    pub ofdm_has: bool,
    pub avg_snr: u8,
    pub evm_max: u8,
    pub evm_min: u8,
    pub has_data: bool,
    pub has_bcn: bool,
    pub su: bool,
    pub ldpc: bool,
    pub stbc: bool,
    pub bf: bool,
    pub to_self: bool,
    pub valid: bool,
    pub hdr_2_en: bool,
    /// `phy_ppdu->ie09` is set: an A1-matched report carried IE09 (SIG-A),
    /// which `rtw89_core_parse_phy_status_ie09` keeps on an AX chip.
    pub ie09: bool,
    /// Stela's own, which rtw89 keeps no copy of: paths A's and B's RSSI as
    /// the PHY status header gave them, once it was valid and its length
    /// the report's, before `__rtw8852bx_convert_rpl_to_rssi` moved them by
    /// IE01's FD average. Only an A1-matched report carries that average;
    /// the others' RSSI comes out as the header's less its own average.
    pub hdr_rssi: Option<[u8; RF_PATH_NUM]>,
}

impl PhyPpdu {
    /// `rtw89_core_rx_process_ppdu_sts` for the report `data` its
    /// descriptor `desc` describes, up to `rtw89_core_rx_pending_skb`: the
    /// PHY PPDU and, when it fell short, why. `valid` is set once the IEs
    /// parsed, as rtw89 sets it.
    pub fn process(desc: &RxDescInfo, data: &[u8]) -> (Self, Option<PpduError>) {
        let mut phy = Self {
            to_self: desc.addr1_match,
            rate: desc.data_rate,
            mac_id: desc.mac_id,
            phy_idx: u8::from(desc.bb_sel),
            ..Self::default()
        };
        let mut buf = 0..data.len();
        if desc.mac_info_valid {
            match process_mac_ppdu(data, &mut phy) {
                Ok(range) => buf = range,
                Err(error) => return (phy, Some(error)),
            }
        }
        if let Err(error) = process_phy_ppdu(&data[buf.clone()], &mut phy) {
            return (phy, Some(error));
        }
        // rtw89_core_rx_process_phy_sts
        match parse_phy_sts(&data[buf], &mut phy) {
            Ok(()) => {
                phy.valid = true;
                (phy, None)
            }
            Err(error) => (phy, Some(error)),
        }
    }
}

/// `rtw89_core_rx_process_mac_ppdu` on an AX chip: where the PHY status
/// starts and ends in `data`.
fn process_mac_ppdu(data: &[u8], phy: &mut PhyPpdu) -> Result<core::ops::Range<usize>, PpduError> {
    if data.len() < PPDU_MAC_INFO_SIZE {
        return Err(PpduError::MacInfoLength);
    }
    let (w0, w1) = (dword(data, 0), dword(data, 4));
    let rx_cnt_valid = w0 & RXINFO_W0_RX_CNT_VLD != 0;
    // rtw89 keeps the PLCP size in a u8: a header of 32 units or more wraps.
    let plcp_size = usize::from((field(w1, RXINFO_W1_PLCP_LEN) << 3) as u8);
    let usr_num = field(w0, RXINFO_W0_USR_NUM) as u8;
    if usr_num > PPDU_MAX_USR {
        return Err(PpduError::UserNumber(usr_num));
    }
    for index in 0..usize::from(usr_num) {
        let at = PPDU_MAC_INFO_SIZE + index * PPDU_MAC_INFO_USR_SIZE;
        if at + 4 > data.len() {
            return Err(PpduError::MacInfoLength);
        }
        let user = dword(data, at);
        if user & RXINFO_USER_MAC_ID_VALID == 0 {
            continue;
        }
        phy.has_data = user & RXINFO_USER_DATA != 0;
        phy.has_bcn = user & RXINFO_USER_BCN != 0;
        break;
    }
    let mut phy_sts = PPDU_MAC_INFO_SIZE + usize::from(usr_num) * PPDU_MAC_INFO_USR_SIZE;
    // 8-byte alignment
    if usr_num & 1 != 0 {
        phy_sts += PPDU_MAC_INFO_USR_SIZE;
    }
    if rx_cnt_valid {
        phy_sts += PPDU_MAC_RX_CNT_SIZE;
    }
    phy_sts += plcp_size;
    if phy_sts > data.len() {
        return Err(PpduError::MacInfoLength);
    }
    Ok(phy_sts..data.len())
}

/// `rtw89_core_rx_process_phy_ppdu` with `rtw89_core_update_phy_ppdu` over
/// the PHY status `buf`.
fn process_phy_ppdu(buf: &[u8], phy: &mut PhyPpdu) -> Result<(), PpduError> {
    if buf.len() < PHY_STS_HDR_LEN {
        return Err(PpduError::Truncated);
    }
    let (w0, w1) = (dword(buf, 0), dword(buf, 4));
    if w0 & PHY_STS_HDR_W0_VALID == 0 {
        return Err(PpduError::Invalid);
    }
    let header = field(w0, PHY_STS_HDR_W0_LEN) << 3;
    if header != buf.len() as u32 {
        return Err(PpduError::LengthMismatch {
            header,
            report: buf.len() as u32,
        });
    }
    phy.ie = field(w0, PHY_STS_HDR_W0_IE_MAP) as u8;
    phy.rssi_avg = field(w0, PHY_STS_HDR_W0_RSSI_AVG) as u8;
    phy.rssi = w1.to_le_bytes();
    phy.hdr_rssi = Some([phy.rssi[0], phy.rssi[1]]);
    phy.hdr_2_en = w0 & PHY_STS_HDR_W0_HDR_2_EN != 0;
    if phy.hdr_2_en {
        // rtw89_core_update_phy_ppdu_hdr_v2
        if buf.len() < 2 * PHY_STS_HDR_LEN {
            return Err(PpduError::Truncated);
        }
        phy.rx_path_en = field(dword(buf, PHY_STS_HDR_LEN), PHY_STS_HDR_V2_W0_PATH_EN) as u8;
    }
    Ok(())
}

/// `rtw89_core_get_phy_status_ie_len`.
fn ie_len(w0: u32) -> u16 {
    let ie = field(w0, PHY_STS_IEHDR_TYPE) as usize;
    match PHYST_IE_LEN[ie] {
        VAR_LEN => field(w0, PHY_STS_IEHDR_LEN) as u16 * VAR_LEN_UNIT,
        len => u16::from(len),
    }
}

/// `rtw89_core_rx_parse_phy_sts` outside monitor mode, with
/// `__rtw8852bx_convert_rpl_to_rssi`.
fn parse_phy_sts(buf: &[u8], phy: &mut PhyPpdu) -> Result<(), PpduError> {
    if phy.ie < CCK_PKT {
        return Err(PpduError::Bypassed(phy.ie));
    }
    let mut pos = PHY_STS_HDR_LEN;
    if phy.hdr_2_en {
        pos += PHY_STS_HDR_LEN;
    }
    let end = buf.len();
    while pos < end {
        // The header's word rtw89 reads its type and length from; fewer
        // bytes give no IE that fits, as rtw89's read past them would not.
        if pos + 4 > end {
            phy.ie09 = false;
            return Err(PpduError::ParseFailed);
        }
        let w0 = dword(buf, pos);
        // Eight zero bytes behind an IE09, which RTL8922D reports.
        if phy.ie09 && end - pos == 8 && w0 == 0 {
            break;
        }
        let start = pos;
        let len = usize::from(ie_len(w0));
        pos += len;
        if pos > end || len == 0 {
            // Clear pointers to prevent accessing out of IE.
            phy.ie09 = false;
            return Err(PpduError::ParseFailed);
        }
        process_phy_status_ie(&buf[start..pos], phy);
    }
    // __rtw8852bx_convert_rpl_to_rssi
    let delta = phy.rpl_avg.wrapping_sub(phy.rssi_avg);
    for rssi in &mut phy.rssi[..RF_PATH_NUM] {
        *rssi = rssi.wrapping_add(delta);
    }
    phy.rssi_avg = phy.rpl_avg;
    Ok(())
}

/// `rtw89_core_process_phy_status_ie` outside monitor mode for the IE `ie`,
/// which lies wholly within the PHY status.
fn process_phy_status_ie(ie: &[u8], phy: &mut PhyPpdu) {
    let kind = field(dword(ie, 0), PHY_STS_IEHDR_TYPE) as u8;
    // Only A1-matched reports, but IE01's channel index for a scan.
    if !(phy.to_self || kind == PHYSTS_IE01_CMN_OFDM) {
        return;
    }
    let w = |n: usize| dword(ie, 4 * n);
    match kind {
        PHYSTS_IE00_CMN_CCK => {
            // rtw89_core_parse_phy_status_ie00: 16 bytes.
            let rpl = field(w(0), PHY_STS_IE00_W0_RPL) as u16;
            phy.rpl_avg = (rpl >> 1) as u8;
            if !phy.hdr_2_en {
                phy.rx_path_en = field(w(3), PHY_STS_IE00_W3_RX_PATH_EN) as u8;
            }
        }
        PHYSTS_IE01_CMN_OFDM => {
            // rtw89_core_parse_phy_status_ie01: 32 bytes.
            phy.chan_idx = field(w(0), PHY_STS_IE01_W0_CH_IDX) as u8;
            phy.ldpc = w(2) & PHY_STS_IE01_W2_LDPC != 0;
            phy.stbc = w(2) & PHY_STS_IE01_W2_STBC != 0;
            phy.bf = w(3) & PHY_STS_IE01_W3_BF != 0;
            if !phy.hdr_2_en {
                phy.rx_path_en = field(w(0), PHY_STS_IE01_W0_RX_PATH_EN) as u8;
            }
            if phy.rate < HW_RATE_OFDM6 || !phy.to_self {
                return;
            }
            phy.rpl_avg = field(w(0), PHY_STS_IE01_W0_RSSI_AVG_FD) as u8;
            phy.su = w(2) & PHY_STS_IE01_W2_SU != 0;
            phy.avg_snr = field(w(2), PHY_STS_IE01_W2_AVG_SNR) as u8;
            phy.evm_max = field(w(2), PHY_STS_IE01_W2_EVM_MAX) as u8;
            phy.evm_min = field(w(2), PHY_STS_IE01_W2_EVM_MIN) as u8;
            phy.ofdm_has = true;
            // rtw89_phy_cfo_parse feeds CFO tracking, which Stela runs
            // none of.
        }
        // rtw89_core_parse_phy_status_ie09 with physt_gen 0.
        PHYSTS_IE09_FTR_0 => phy.ie09 = true,
        _ => {}
    }
}

/// `RTW89_RSSI_RAW_TO_DBM`.
pub fn rssi_raw_to_dbm(rssi: u8) -> i8 {
    (i16::from((rssi >> RSSI_FACTOR) as i8) - MAX_RSSI) as i8
}

/// `enum nl80211_band`'s 2.4, 5 and 6 GHz bands.
pub const NL80211_BAND_2GHZ: u8 = 0;
pub const NL80211_BAND_5GHZ: u8 = 1;
pub const NL80211_BAND_6GHZ: u8 = 3;

/// `rtw89_ch_base_table`.
const CH_BASE_TABLE: [u8; 16] = [
    1, 0xff, 36, 100, 132, 149, 0xff, 1, 33, 65, 97, 129, 161, 193, 225, 0xff,
];
/// `RTW89_CH_BASE_IDX_5G_LAST`.
const CH_BASE_IDX_5G_LAST: u8 = 5;

/// `rtw89_decode_chan_idx`: the channel and its `nl80211_band`, a reserved
/// base's 0xff included as rtw89 adds to it.
pub fn decode_chan_idx(chan_idx: u8) -> (u8, u8) {
    let idx = chan_idx >> 4;
    let offset = chan_idx & 0x0f;
    if idx == 0 {
        return (offset, NL80211_BAND_2GHZ);
    }
    let band = if idx <= CH_BASE_IDX_5G_LAST {
        NL80211_BAND_5GHZ
    } else {
        NL80211_BAND_6GHZ
    };
    (
        CH_BASE_TABLE[usize::from(idx)].wrapping_add(offset << 1),
        band,
    )
}

/// cfg80211's `ieee80211_channel_to_frequency` (net/wireless/util.c) for
/// the bands an `nl80211_band` above names, in MHz; 0 where it supports
/// none.
pub fn channel_to_frequency(channel: u8, band: u8) -> u32 {
    let channel = u32::from(channel);
    if channel == 0 {
        return 0;
    }
    match band {
        NL80211_BAND_2GHZ if channel == 14 => 2484,
        NL80211_BAND_2GHZ if channel < 14 => 2407 + channel * 5,
        NL80211_BAND_5GHZ if (182..=196).contains(&channel) => 4000 + channel * 5,
        NL80211_BAND_5GHZ => 5000 + channel * 5,
        NL80211_BAND_6GHZ if channel == 2 => 5935,
        NL80211_BAND_6GHZ if channel <= 233 => 5950 + channel * 5,
        _ => 0,
    }
}

/// The data rate's mode, `rtw89_get_data_rate_mode` on an AX chip.
pub fn data_rate_mode(data_rate: u16) -> u8 {
    ((data_rate & DATA_RATE_MODE_CTRL_MASK) >> DATA_RATE_MODE_CTRL_MASK.trailing_zeros()) as u8
}

/// The rate index `rtw89_core_update_rx_status` and
/// `rtw89_core_rx_ppdu_match` derive by mode.
pub fn rate_idx(data_rate: u16) -> u8 {
    (match data_rate_mode(data_rate) {
        DATA_RATE_MODE_NON_HT => data_rate & DATA_RATE_NOT_HT_IDX_MASK,
        DATA_RATE_MODE_HT => data_rate & DATA_RATE_HT_IDX_MASK,
        _ => data_rate & DATA_RATE_VHT_HE_IDX_MASK,
    }) as u8
}

/// `rtw89_rxdesc_to_nl_he_gi`: an unknown GI is `HE_GI_3_2` for an RX
/// status and [`GI_UNKNOWN`] for the match.
pub fn he_gi(gi_ltf: u8, rx_status: bool) -> u8 {
    match gi_ltf {
        1 | 3 | 5 => HE_GI_0_8,
        2 | 4 => HE_GI_1_6,
        0 => HE_GI_3_2,
        _ if rx_status => HE_GI_3_2,
        _ => GI_UNKNOWN,
    }
}

/// The part of `struct ieee80211_rx_status` rtw89 fills that the PPDU match
/// and Stela's report read.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxStatus {
    /// In MHz.
    pub freq: u32,
    /// `enum nl80211_band`.
    pub band: u8,
    /// dBm; 0 is no signal (`RX_FLAG_NO_SIGNAL_VAL`).
    pub signal: i8,
    pub chains: u8,
    pub chain_signal: [i8; RF_PATH_NUM],
    pub rate_idx: u8,
    /// `rtw89_get_data_rate_mode`'s mode: the encoding.
    pub mode: u8,
    pub he_gi: u8,
    /// `enum rate_info_bw`, as `rtw89_hw_to_rate_info_bw` gives it.
    pub bw: u8,
    pub failed_fcs_crc: bool,
    pub decrypted: bool,
}

impl RxStatus {
    /// `rtw89_core_update_rx_status` for the frame `desc` describes on a
    /// channel whose primary is at `freq` MHz in `band`.
    pub fn update(desc: &RxDescInfo, freq: u32, band: u8) -> Self {
        Self {
            freq,
            band,
            failed_fcs_crc: desc.icv_err || desc.crc32_err,
            decrypted: desc.hw_dec && !(desc.sw_dec || desc.icv_err),
            bw: hw_to_rate_info_bw(desc.bw),
            rate_idx: rate_idx(desc.data_rate),
            mode: data_rate_mode(desc.data_rate),
            // he_gi is used to match ppdu, so we always fill it.
            he_gi: he_gi(desc.gi_ltf, true),
            ..Self::default()
        }
    }

    /// `__rtw8852bx_query_ppdu`: the signal, when none was set, from the
    /// stronger of paths A and B, each path's signal, and the frequency of
    /// IE01's channel index once the PHY status parsed.
    pub fn query_ppdu(&mut self, phy: &PhyPpdu) {
        if self.signal == 0 {
            self.signal = rssi_raw_to_dbm(phy.rssi[0].max(phy.rssi[1]));
        }
        for path in 0..RF_PATH_NUM {
            self.chains |= 1 << path;
            self.chain_signal[path] = rssi_raw_to_dbm(phy.rssi[path]);
        }
        if phy.valid {
            // rtw8852bx_fill_freq_with_ppdu
            if phy.chan_idx == 0 {
                return;
            }
            let (channel, band) = decode_chan_idx(phy.chan_idx);
            self.freq = channel_to_frequency(channel, band);
            self.band = band;
        }
    }
}

/// `rtw89_core_rx_ppdu_match`: the PPDU status `desc` describes belongs to
/// the frame of `status` when the current PPDU count is its and the rate
/// index, GI and bandwidth agree.
pub fn ppdu_match(curr_rx_ppdu_cnt: u8, desc: &RxDescInfo, status: &RxStatus) -> bool {
    curr_rx_ppdu_cnt == desc.ppdu_cnt
        && status.rate_idx == rate_idx(desc.data_rate)
        && status.he_gi == he_gi(desc.gi_ltf, false)
        && status.bw == hw_to_rate_info_bw(desc.bw)
}

/// `RATE_INFO_BW_20`, `_40`, `_80` and `_160`.
pub const RATE_INFO_BW_20: u8 = 0;
pub const RATE_INFO_BW_40: u8 = 3;
pub const RATE_INFO_BW_80: u8 = 4;
pub const RATE_INFO_BW_160: u8 = 5;

/// `rtw89_hw_to_rate_info_bw` for `enum rtw89_bandwidth`.
pub fn hw_to_rate_info_bw(bw: u8) -> u8 {
    match bw {
        3 => RATE_INFO_BW_160,
        2 => RATE_INFO_BW_80,
        1 => RATE_INFO_BW_40,
        _ => RATE_INFO_BW_20,
    }
}

/// A frame as the sorter hands it on: its RX status, the PPDU status that
/// matched it (whether or not it parsed), and what the caller kept of it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivered<T> {
    pub status: RxStatus,
    pub desc: RxDescInfo,
    /// The PHY PPDU of the status that matched it, `None` when the frame
    /// went on without one.
    pub ppdu: Option<PhyPpdu>,
    pub frame: T,
}

/// What [`Sorter::receive`] made of one packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sorted {
    /// A frame, delivered or held for its PPDU status.
    Wifi { held: bool },
    /// A C2H, which rtw89 hands to `rtw89_fw_c2h_irqsafe`.
    C2h,
    /// A PPDU status, how its PHY status fell short, and how many held
    /// frames it delivered and matched.
    PpduStatus {
        error: Option<PpduError>,
        delivered: usize,
        matched: usize,
    },
    /// Any other type, which rtw89 drops ("unhandled pkt_type").
    Unhandled(u8),
}

/// `rtwdev->ppdu_sts` for PHY 0: the current PPDU count and the frames held
/// for its status, as `rtw89_core_ppdu_sts_init` starts them.
#[derive(Debug)]
pub struct Sorter<T> {
    pub curr_rx_ppdu_cnt: u8,
    pending: Vec<(RxStatus, RxDescInfo, T)>,
    /// The tuned channel's primary, `chandef->chan`, and its band.
    freq: u32,
    band: u8,
}

impl<T> Sorter<T> {
    /// No PPDU count yet (`U8_MAX`), on a channel whose primary is `freq`
    /// MHz in `band` (`nl80211_band`).
    pub fn new(freq: u32, band: u8) -> Self {
        Self {
            curr_rx_ppdu_cnt: u8::MAX,
            pending: Vec::new(),
            freq,
            band,
        }
    }

    /// Frames held for their PPDU status.
    pub fn held(&self) -> usize {
        self.pending.len()
    }

    /// `rtw89_core_rx` for `packet`: `keep` makes what is kept of a frame
    /// from its bytes, and `deliver` takes each frame as rtw89 hands it to
    /// `rtw89_core_rx_to_mac80211`.
    pub fn receive(
        &mut self,
        packet: &Packet<'_>,
        keep: impl FnOnce(&[u8]) -> T,
        mut deliver: impl FnMut(Delivered<T>),
    ) -> Sorted {
        let desc = &packet.desc;
        match desc.pkt_type {
            RX_TYPE_WIFI => {}
            RX_TYPE_C2H => return Sorted::C2h,
            RX_TYPE_PPDU_STAT => {
                let (phy, error) = PhyPpdu::process(desc, packet.data);
                let (delivered, matched) = self.pending_skb(desc, &phy, &mut deliver);
                return Sorted::PpduStatus {
                    error,
                    delivered,
                    matched,
                };
            }
            other => return Sorted::Unhandled(other),
        }
        if self.curr_rx_ppdu_cnt != desc.ppdu_cnt {
            self.flush(&mut deliver);
            self.curr_rx_ppdu_cnt = desc.ppdu_cnt;
        }
        let status = RxStatus::update(desc, self.freq, self.band);
        let frame = keep(packet.data);
        if desc.long_rxdesc && (1u32 << desc.frame_type) & PPDU_FILTER_BITMAP != 0 {
            self.pending.push((status, *desc, frame));
            return Sorted::Wifi { held: true };
        }
        deliver(Delivered {
            status,
            desc: *desc,
            ppdu: None,
            frame,
        });
        Sorted::Wifi { held: false }
    }

    /// `rtw89_core_flush_ppdu_rx_queue`: every held frame, without a PPDU.
    pub fn flush(&mut self, deliver: &mut impl FnMut(Delivered<T>)) {
        for (status, desc, frame) in self.pending.drain(..) {
            deliver(Delivered {
                status,
                desc,
                ppdu: None,
                frame,
            });
        }
    }

    /// `rtw89_core_rx_pending_skb`: unless the current count is past
    /// `RTW89_MAX_PPDU_CNT` (none yet), every held frame, its signal from
    /// `phy` when the PPDU status `desc` matches it. How many went and how
    /// many matched.
    fn pending_skb(
        &mut self,
        desc: &RxDescInfo,
        phy: &PhyPpdu,
        deliver: &mut impl FnMut(Delivered<T>),
    ) -> (usize, usize) {
        if self.curr_rx_ppdu_cnt > MAX_PPDU_CNT {
            return (0, 0);
        }
        let curr = self.curr_rx_ppdu_cnt;
        let mut matched = 0;
        let count = self.pending.len();
        for (mut status, frame_desc, frame) in self.pending.drain(..) {
            let ppdu = if ppdu_match(curr, desc, &status) {
                matched += 1;
                status.query_ppdu(phy);
                Some(*phy)
            } else {
                None
            };
            deliver(Delivered {
                status,
                desc: frame_desc,
                ppdu,
                frame,
            });
        }
        (count, matched)
    }
}

#[cfg(test)]
pub(super) mod tests;
