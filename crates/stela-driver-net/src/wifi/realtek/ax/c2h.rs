// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
//! C2H, what an RTL8852BE's firmware reports back on RXQ, as pinned rtw89
//! recognizes it:
//!
//! - [`RxDesc::query`]: the part of `rtw89_core_query_rxdesc` (core.c,
//!   `rtw8852b_chip_ops.query_rxdesc`) that finds a packet in an RX buffer:
//!   its type, length, the long descriptor and the driver info in front of
//!   it, with the AX descriptor's fields as txrx.h names them;
//! - [`parse`]: `rtw89_pci_rxbd_deliver_skbs` (pci.c) for a buffer that
//!   holds one whole packet: the descriptor read after the
//!   `rtw89_pci_rxbd_info` dword, the packet copied out from behind the
//!   descriptor and driver info (`rtw89_skb_put_rx_data`), and handed on
//!   as a C2H when its type is `RTW89_CORE_RX_TYPE_C2H`, as
//!   `rtw89_core_rx_process_report` does;
//! - [`C2h`]: `rtw89_fw_c2h_parse_attr` (fw.c), the C2H header's category,
//!   class, function and length;
//! - [`C2h::event`]: where `rtw89_fw_c2h_cmd_handle` and
//!   `rtw89_mac_c2h_handle` (mac.c) send a C2H, as far as the two acks:
//!   the MAC info class's REC_ACK and DONE_ACK, decoded as
//!   `rtw89_mac_c2h_rec_ack` and `rtw89_mac_c2h_done_ack` decode them. Every
//!   other C2H is [`Event::Other`], its header and payload left raw.
//! - [`receive`]: [`Rings::deliver`] on RXQ with [`parse`] for each buffer.
//!
//! What this leaves out, and why:
//! - Packets spread over more than one RX buffer, which rtw89 reassembles:
//!   a C2H fits one buffer, and one that does not is refused.
//! - `RTW89_FLAG_RUNNING`, without which `rtw89_fw_c2h_cmd_handle` drops
//!   every C2H, and `rtw89_fw_c2h_chk_atomic`'s choice between handling a
//!   C2H at once and queueing it: Stela polls RXQ itself and decides what
//!   to do with what it reads. rtw89 itself reads no C2H while it
//!   downloads the firmware; it polls registers instead.
//! - What the acks complete (scan and power-save waits) and every other
//!   handler: later steps.
//!
//! Where rtw89 reads past what the chip wrote (a descriptor, packet or ack
//! longer than the buffer's written bytes) or copies fewer bytes than the
//! descriptor claims, this refuses the buffer. Recognizing a C2H proves
//! nothing about the firmware's state beyond its having written it.
use super::{
    io::{Io, field},
    pci::ring::{self, Received, Rings, RxBdInfo, RxChannel},
};

/// `sizeof(struct rtw89_pci_rxbd_info)`: where the RX descriptor starts in
/// a buffer, the `data_offset` `rtw89_pci_rxbd_deliver_skbs` passes.
pub const RXBD_INFO_SIZE: usize = 4;
/// `sizeof(struct rtw89_rxdesc_short)` and `sizeof(struct rtw89_rxdesc_long)`.
pub const RXDESC_SHORT: usize = 16;
pub const RXDESC_LONG: usize = 32;
/// RX descriptor dword 0: `AX_RXD_*`.
pub const RXD_RPKT_LEN_MASK: u32 = 0x0000_3fff;
pub const RXD_SHIFT_MASK: u32 = 0x0000_c000;
pub const RXD_MAC_INFO_VLD: u32 = 1 << 23;
pub const RXD_RPKT_TYPE_MASK: u32 = 0x0f00_0000;
pub const RXD_DRV_INFO_SIZE_MASK: u32 = 0x7000_0000;
pub const RXD_LONG_RXD: u32 = 1 << 31;

/// `enum rtw89_core_rx_type`: received frames, PPDU status and C2H.
pub const RX_TYPE_WIFI: u8 = 0;
pub const RX_TYPE_PPDU_STAT: u8 = 1;
pub const RX_TYPE_C2H: u8 = 10;

/// `RTW89_C2H_HEADER_LEN`.
pub const HEADER_LEN: usize = 8;
/// `struct rtw89_c2h_hdr`'s fields: `RTW89_C2H_HDR_W0_CATEGORY`, `…_CLASS`,
/// `…_FUNC` and `RTW89_C2H_HDR_W1_LEN`.
pub const HDR_W0_CATEGORY: u32 = 0x0000_0003;
pub const HDR_W0_CLASS: u32 = 0x0000_00fc;
pub const HDR_W0_FUNC: u32 = 0x0000_ff00;
pub const HDR_W1_LEN: u32 = 0x0000_3fff;

/// `enum rtw89_fw_c2h_category`.
pub const C2H_CAT_TEST: u8 = 0;
pub const C2H_CAT_MAC: u8 = 1;
pub const C2H_CAT_OUTSRC: u8 = 2;
/// `RTW89_MAC_C2H_CLASS_INFO` with `RTW89_MAC_C2H_FUNC_REC_ACK` and
/// `RTW89_MAC_C2H_FUNC_DONE_ACK`.
pub const MAC_C2H_CLASS_INFO: u8 = 0x0;
pub const MAC_C2H_FUNC_REC_ACK: u8 = 0;
pub const MAC_C2H_FUNC_DONE_ACK: u8 = 1;

/// `sizeof(struct rtw89_c2h_rev_ack)` and `sizeof(struct rtw89_c2h_done_ack)`:
/// the header and the dword that names the command.
pub const ACK_LEN: usize = 12;
/// `RTW89_C2H_REV_ACK_W2_*`: the acknowledged command.
pub const REV_ACK_W2_CAT: u32 = 0x0000_0003;
pub const REV_ACK_W2_CLASS: u32 = 0x0000_00fc;
pub const REV_ACK_W2_FUNC: u32 = 0x0000_ff00;
pub const REV_ACK_W2_H2C_SEQ: u32 = 0x00ff_0000;
/// `RTW89_C2H_DONE_ACK_W2_*`: the completed command and what it returned.
pub const DONE_ACK_W2_CAT: u32 = 0x0000_0003;
pub const DONE_ACK_W2_CLASS: u32 = 0x0000_00fc;
pub const DONE_ACK_W2_FUNC: u32 = 0x0000_ff00;
pub const DONE_ACK_W2_H2C_RETURN: u32 = 0x00ff_0000;
pub const DONE_ACK_W2_H2C_SEQ: u32 = 0xff00_0000;

/// Why a buffer was not read as a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A buffer that is not one whole packet (`fs` and `ls` not both set).
    Segmented { fs: bool, ls: bool },
    /// Fewer bytes than the descriptor, the packet it claims, the C2H
    /// header or the ack needed.
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

/// The `struct rtw89_rx_desc_info` members `rtw89_core_query_rxdesc` sets
/// that find the packet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RxDesc {
    pub pkt_size: u16,
    pub pkt_type: u8,
    pub drv_info_size: u8,
    pub long_rxdesc: bool,
    pub mac_info_valid: bool,
    /// Where the descriptor starts plus the driver info. The AX query
    /// never reads `AX_RXD_SHIFT_MASK` and leaves `shift` at 0.
    pub offset: u16,
    pub rxd_len: u16,
}

impl RxDesc {
    /// `rtw89_core_query_rxdesc`'s dword 0 over `data` from its start, the
    /// descriptor at `data_offset`; the short descriptor's 16 bytes, or
    /// the long one's 32, must be there.
    pub fn query(data: &[u8], data_offset: usize) -> Result<Self, Error> {
        need(data_offset + RXDESC_SHORT, data.len())?;
        let dword0 = dword(data, data_offset);
        let long_rxdesc = dword0 & RXD_LONG_RXD != 0;
        let rxd_len = if long_rxdesc {
            RXDESC_LONG
        } else {
            RXDESC_SHORT
        };
        need(data_offset + rxd_len, data.len())?;
        let drv_info_size = field(dword0, RXD_DRV_INFO_SIZE_MASK) as u8;
        // shift_len = desc_info->shift << 1, with shift never set: 0.
        let drv_info_len = drv_info_size << 3;
        Ok(Self {
            pkt_size: field(dword0, RXD_RPKT_LEN_MASK) as u16,
            pkt_type: field(dword0, RXD_RPKT_TYPE_MASK) as u8,
            drv_info_size,
            long_rxdesc,
            mac_info_valid: dword0 & RXD_MAC_INFO_VLD != 0,
            offset: data_offset as u16 + u16::from(drv_info_len),
            rxd_len: rxd_len as u16,
        })
    }

    /// Where the packet starts: behind the descriptor and driver info.
    pub const fn packet_offset(&self) -> usize {
        self.offset as usize + self.rxd_len as usize
    }
}

/// `struct rtw89_fw_c2h_attr` as `rtw89_fw_c2h_parse_attr` fills it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Attr {
    pub category: u8,
    pub class: u8,
    pub func: u8,
    /// The length the header claims, itself included; rtw89 hands it to
    /// the handlers unchecked, and so is it here.
    pub len: u16,
}

/// The command an ack names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ack {
    pub cat: u8,
    pub class: u8,
    pub func: u8,
    pub seq: u8,
}

/// Where rtw89 sends a C2H, as far as this step tells them apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// `RTW89_MAC_C2H_FUNC_REC_ACK`: the firmware received the command.
    RecAck(Ack),
    /// `RTW89_MAC_C2H_FUNC_DONE_ACK`: the firmware ran the command, which
    /// returned `h2c_return`.
    DoneAck { ack: Ack, h2c_return: u8 },
    /// Any other C2H: its header and payload are the [`C2h`]'s.
    Other,
}

/// One C2H as `rtw89_fw_c2h_irqsafe` receives it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C2h<'a> {
    pub attr: Attr,
    /// The whole packet, header included, as the descriptor sized it.
    pub data: &'a [u8],
}

impl<'a> C2h<'a> {
    /// `rtw89_fw_c2h_parse_attr` over a packet of at least the header.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        need(HEADER_LEN, data.len())?;
        let (w0, w1) = (dword(data, 0), dword(data, 4));
        Ok(Self {
            attr: Attr {
                category: field(w0, HDR_W0_CATEGORY) as u8,
                class: field(w0, HDR_W0_CLASS) as u8,
                func: field(w0, HDR_W0_FUNC) as u8,
                len: field(w1, HDR_W1_LEN) as u16,
            },
            data,
        })
    }

    /// The bytes behind the header.
    pub fn payload(&self) -> &'a [u8] {
        &self.data[HEADER_LEN..]
    }

    /// `rtw89_fw_c2h_cmd_handle`'s category switch and
    /// `rtw89_mac_c2h_handle`'s info class: a MAC C2H of the info class is
    /// REC_ACK (function 0) or DONE_ACK (function 1), whose third dword
    /// names the command; an ack shorter than that is refused.
    pub fn event(&self) -> Result<Event, Error> {
        let attr = self.attr;
        if attr.category != C2H_CAT_MAC || attr.class != MAC_C2H_CLASS_INFO {
            return Ok(Event::Other);
        }
        match attr.func {
            MAC_C2H_FUNC_REC_ACK => {
                need(ACK_LEN, self.data.len())?;
                let w2 = dword(self.data, 8);
                Ok(Event::RecAck(Ack {
                    cat: field(w2, REV_ACK_W2_CAT) as u8,
                    class: field(w2, REV_ACK_W2_CLASS) as u8,
                    func: field(w2, REV_ACK_W2_FUNC) as u8,
                    seq: field(w2, REV_ACK_W2_H2C_SEQ) as u8,
                }))
            }
            MAC_C2H_FUNC_DONE_ACK => {
                need(ACK_LEN, self.data.len())?;
                let w2 = dword(self.data, 8);
                Ok(Event::DoneAck {
                    ack: Ack {
                        cat: field(w2, DONE_ACK_W2_CAT) as u8,
                        class: field(w2, DONE_ACK_W2_CLASS) as u8,
                        func: field(w2, DONE_ACK_W2_FUNC) as u8,
                        seq: field(w2, DONE_ACK_W2_H2C_SEQ) as u8,
                    },
                    h2c_return: field(w2, DONE_ACK_W2_H2C_RETURN) as u8,
                })
            }
            _ => Ok(Event::Other),
        }
    }
}

/// `RTW89_PHY_C2H_CLASS_RA` and its `RTW89_PHY_C2H_FUNC_STS_RPT`, the rate
/// report `rtw89_phy_c2h_handle` sends to `rtw89_phy_c2h_ra_rpt`.
pub const PHY_C2H_CLASS_RA: u8 = 0x1;
pub const PHY_C2H_FUNC_STS_RPT: u8 = 0x0;
/// `sizeof(struct rtw89_c2h_ra_rpt)`: the header, `w2` and `w3`.
pub const RA_RPT_LEN: usize = 16;
/// `RTW89_C2H_RA_RPT_W2_*` and `RTW89_C2H_RA_RPT_W3_*`. The `_B7` and `_B2`
/// bits are the BE format's, which an AX chip's report never uses.
pub const RA_RPT_W2_MACID: u32 = 0x0000_ffff;
pub const RA_RPT_W2_RETRY_RATIO: u32 = 0x00ff_0000;
pub const RA_RPT_W3_MCSNSS: u32 = 0x0000_007f;
pub const RA_RPT_W3_MD_SEL: u32 = 0x0000_0300;
pub const RA_RPT_W3_GILTF: u32 = 0x0000_1c00;
pub const RA_RPT_W3_BW: u32 = 0x0000_6000;

/// What `__rtw89_phy_c2h_ra_rpt_iter` reads of `struct rtw89_c2h_ra_rpt` on
/// an AX chip (`format_v1` false).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RaRpt {
    /// `RTW89_C2H_RA_RPT_W2_MACID` as rtw89 keeps it, in a `u8`: its low
    /// eight bits.
    pub mac_id: u8,
    /// Read by the BE format alone; an AX chip's report leaves
    /// `retry_ratio` at 0.
    pub retry_ratio: u8,
    /// `RTW89_C2H_RA_RPT_W3_MCSNSS`: the rate, as its mode reads it.
    pub rate: u8,
    /// `enum rtw89_ra_report_mode`.
    pub mode: u8,
    /// `enum rtw89_gi_ltf`.
    pub giltf: u8,
    /// `enum rtw89_bandwidth`.
    pub bw: u8,
}

impl C2h<'_> {
    /// `rtw89_fw_c2h_cmd_handle`'s OUTSRC category and `rtw89_phy_c2h_handle`'s
    /// RA class to `rtw89_phy_c2h_ra_rpt`: `None` for any other C2H; a report
    /// shorter than `struct rtw89_c2h_ra_rpt`, which rtw89 would read past,
    /// is refused.
    pub fn ra_report(&self) -> Option<Result<RaRpt, Error>> {
        let attr = self.attr;
        if attr.category != C2H_CAT_OUTSRC
            || attr.class != PHY_C2H_CLASS_RA
            || attr.func != PHY_C2H_FUNC_STS_RPT
        {
            return None;
        }
        Some(need(RA_RPT_LEN, self.data.len()).map(|()| {
            let (w2, w3) = (dword(self.data, 8), dword(self.data, 12));
            RaRpt {
                mac_id: field(w2, RA_RPT_W2_MACID) as u8,
                retry_ratio: 0,
                rate: field(w3, RA_RPT_W3_MCSNSS) as u8,
                mode: field(w3, RA_RPT_W3_MD_SEL) as u8,
                giltf: field(w3, RA_RPT_W3_GILTF) as u8,
                bw: field(w3, RA_RPT_W3_BW) as u8,
            }
        }))
    }
}

/// What one RX buffer holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Packet<'a> {
    C2h(C2h<'a>),
    /// Any other packet type, for later steps: its descriptor.
    Other(RxDesc),
}

/// `rtw89_pci_rxbd_deliver_skbs` for one buffer, from its `rxbd_info`
/// dword: `info` as decoded and `data` as the chip wrote it, at most
/// `info.len` bytes. The buffer must hold one whole packet, and the
/// descriptor, the packet it sizes behind the driver info, and a C2H's
/// header must lie within the written bytes.
pub fn parse(info: RxBdInfo, data: &[u8]) -> Result<Packet<'_>, Error> {
    if !(info.fs && info.ls) {
        return Err(Error::Segmented {
            fs: info.fs,
            ls: info.ls,
        });
    }
    let data = &data[..data.len().min(usize::from(info.len))];
    let desc = RxDesc::query(data, RXBD_INFO_SIZE)?;
    if desc.pkt_type != RX_TYPE_C2H {
        return Ok(Packet::Other(desc));
    }
    let start = desc.packet_offset();
    let end = start + usize::from(desc.pkt_size);
    need(end, data.len())?;
    Ok(Packet::C2h(C2h::parse(&data[start..end])?))
}

/// `rtw89_pci_poll_rxq_dma` on RXQ: at most `budget` filled buffers, each
/// [`parse`]d and handed to `sink`, then given back to the chip. Returns
/// how many buffers were consumed.
pub fn receive<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    budget: u32,
    mut sink: impl FnMut(Result<Packet<'_>, Error>),
) -> Result<u32, ring::Error> {
    rings.deliver(io, RxChannel::Rxq, budget, |Received { info, data }| {
        sink(parse(info, data))
    })
}

#[cfg(test)]
pub(super) mod tests;
