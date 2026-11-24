// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! H2C, the host-to-firmware commands an RTL8852BE takes on its firmware
//! command channel CH12, as pinned rtw89 builds and sends them:
//!
//! - the 8-byte header (`struct fwcmd_hdr`, fw.h) as [`Header`].
//!   [`Sequence::set_hdr`] is `rtw89_h2c_pkt_set_hdr` (fw.c): it asks
//!   REC_ACK of every command whose sequence number is a multiple of four,
//!   as rtw89 does on an AX chip, and then advances `rtwdev->fw.h2c_seq`.
//!   [`Sequence::set_hdr_fwdl`] is `rtw89_h2c_pkt_set_hdr_fwdl`, the
//!   firmware header download's, which asks for no ack and leaves the
//!   sequence where it was;
//! - [`Packet`]: what `rtw89_fw_h2c_alloc_skb_with_hdr` (or `…_no_hdr`) and
//!   the header leave in the skb, and [`Packet::frame`], the bytes
//!   `rtw89_pci_fwcmd_submit` maps: the TXWD body ([`super::txwd`],
//!   `h2c_desc_size` bytes) and the packet behind it;
//! - [`Channel::send`]: `rtw89_h2c_tx` (core.c) over `rtw89_pci_ops`:
//!   `rtw89_pci_check_and_reclaim_tx_resource` on CH12
//!   (`rtw89_pci_reclaim_tx_fwcmd`, then the free BDs), `rtw89_pci_tx_write`
//!   with `rtw89_pci_fwcmd_submit` ([`Rings::fwcmd_submit`]), then
//!   `rtw89_pci_ops_tx_kick_off` ([`Rings::tx_kick_off`]).
//!
//! The firmware download sends its header with [`Channel::fwdl_header`] and
//! each part of a section, at most [`FWDL_SECTION_PER_PKT_LEN`] bytes, with
//! [`Channel::fwdl_part`], then sets the sequence back to 0
//! ([`Channel::reset_sequence`]) as `__rtw89_fw_download` does once the
//! image is in. The commands that follow use [`Channel::command`], and
//! their REC_ACK and DONE_ACK come back as C2H ([`super::c2h`]).
//!
//! What this leaves out, and why:
//! - `rtw89_h2c_tx`'s silent drop while `RTW89_FLAG_POWERON` is clear, and
//!   the paused HCI (`hci.paused`, `kick_map`) of rtw89's low-power paths:
//!   a command is sent here only to a chip the caller powered on, and Stela
//!   never pauses the HCI.
//! - `rtw89_h2c_tx_and_wait` and its completions: waiting for an ack is the
//!   caller's, over [`super::c2h`].
//! - The H2CREG/C2HREG register mailbox (`rtw89_fw_msg_reg`): rtw89 does
//!   not use it before the firmware runs. Its first user on this path is
//!   the phycap read of the efuse step (`rtw89_mac_read_phycap`).
//!
//! Where rtw89 would cut a length silently into a 14-bit field, the header
//! does the same, but [`Channel::send`] refuses a packet that does not fit
//! TXPKT_SIZE. A packet sent proves only that its BD was written and the
//! host index moved: no firmware has accepted any H2C yet, and nothing here
//! shows that the chip fetched it.
use super::{
    io::{self, Io, field, prep},
    pci::ring::{self, Buffer, Rings, TxChannel},
    txwd::{self, DescInfo},
};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain},
    memory::PageSource,
};
use alloc::sync::Arc;

/// `H2C_HEADER_LEN`.
pub const HEADER_LEN: usize = 8;
/// The `fwcmd_hdr` fields: `H2C_HDR_CAT`, `H2C_HDR_CLASS`, `H2C_HDR_FUNC`,
/// `H2C_HDR_DEL_TYPE` and `H2C_HDR_H2C_SEQ` in `hdr0`; `H2C_HDR_TOTAL_LEN`,
/// `H2C_HDR_REC_ACK` and `H2C_HDR_DONE_ACK` in `hdr1`.
pub const HDR_CAT: u32 = 0x0000_0003;
pub const HDR_CLASS: u32 = 0x0000_00fc;
pub const HDR_FUNC: u32 = 0x0000_ff00;
pub const HDR_DEL_TYPE: u32 = 0x000f_0000;
pub const HDR_H2C_SEQ: u32 = 0xff00_0000;
pub const HDR_TOTAL_LEN: u32 = 0x0000_3fff;
pub const HDR_REC_ACK: u32 = 1 << 14;
pub const HDR_DONE_ACK: u32 = 1 << 15;

/// `FWCMD_TYPE_H2C`: the delivery type of every H2C rtw89 sends.
pub const FWCMD_TYPE_H2C: u8 = 0;
/// `H2C_CAT_TEST`, `H2C_CAT_MAC` and `H2C_CAT_OUTSRC`.
pub const H2C_CAT_TEST: u8 = 0;
pub const H2C_CAT_MAC: u8 = 1;
pub const H2C_CAT_OUTSRC: u8 = 2;
/// `H2C_CL_MAC_FWDL` and `H2C_FUNC_MAC_FWHDR_DL`.
pub const H2C_CL_MAC_FWDL: u8 = 0x3;
pub const H2C_FUNC_MAC_FWHDR_DL: u8 = 0x0;
/// `FWDL_SECTION_PER_PKT_LEN`: the bytes of a section each download part
/// carries on an AX chip.
pub const FWDL_SECTION_PER_PKT_LEN: usize = 2020;
/// `rtw8852b_chip_info.h2c_desc_size`: the TXWD body in front of each H2C.
pub const H2C_DESC_SIZE: usize = txwd::BODY_SIZE;
/// The longest packet TXPKT_SIZE can carry.
pub const MAX_PACKET: usize = txwd::BODY2_TXPKT_SIZE as usize;

/// Which firmware function an H2C asks for: the header's delivery type,
/// category, class and function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Function {
    pub del_type: u8,
    pub cat: u8,
    pub class: u8,
    pub func: u8,
}

impl Function {
    /// A MAC command of `class` and `func`, delivered as H2C.
    pub const fn mac(class: u8, func: u8) -> Self {
        Self {
            del_type: FWCMD_TYPE_H2C,
            cat: H2C_CAT_MAC,
            class,
            func,
        }
    }
}

/// What `__rtw89_fw_download_hdr` names for the firmware header.
pub const FWHDR_DL: Function = Function::mac(H2C_CL_MAC_FWDL, H2C_FUNC_MAC_FWHDR_DL);

/// `struct fwcmd_hdr`: two little-endian dwords.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Header {
    pub hdr0: u32,
    pub hdr1: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[0..4].copy_from_slice(&self.hdr0.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.hdr1.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Self {
        Self {
            hdr0: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            hdr1: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    pub const fn function(&self) -> Function {
        Function {
            del_type: field(self.hdr0, HDR_DEL_TYPE) as u8,
            cat: field(self.hdr0, HDR_CAT) as u8,
            class: field(self.hdr0, HDR_CLASS) as u8,
            func: field(self.hdr0, HDR_FUNC) as u8,
        }
    }

    /// The sequence number.
    pub const fn seq(&self) -> u8 {
        field(self.hdr0, HDR_H2C_SEQ) as u8
    }

    /// The length the header claims, itself included.
    pub const fn total_len(&self) -> u16 {
        field(self.hdr1, HDR_TOTAL_LEN) as u16
    }

    pub const fn rec_ack(&self) -> bool {
        self.hdr1 & HDR_REC_ACK != 0
    }

    pub const fn done_ack(&self) -> bool {
        self.hdr1 & HDR_DONE_ACK != 0
    }
}

/// `hdr0` for `function` at sequence number `seq`.
const fn hdr0(function: Function, seq: u8) -> u32 {
    prep(function.del_type as u32, HDR_DEL_TYPE)
        | prep(function.cat as u32, HDR_CAT)
        | prep(function.class as u32, HDR_CLASS)
        | prep(function.func as u32, HDR_FUNC)
        | prep(seq as u32, HDR_H2C_SEQ)
}

/// `rtwdev->fw.h2c_seq`: the next command's sequence number, a `u8` that
/// wraps. It starts at 0 and the firmware download sets it back to 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sequence(pub u8);

impl Sequence {
    /// `rtw89_h2c_pkt_set_hdr` on an AX chip: the header for a payload of
    /// `len` bytes, REC_ACK asked when `rack` is or when the sequence
    /// number is a multiple of four, DONE_ACK when `dack` is; then the
    /// sequence advances. The total length is `len` and the header, cut to
    /// 14 bits as rtw89 cuts it.
    pub fn set_hdr(&mut self, function: Function, rack: bool, dack: bool, len: u32) -> Header {
        let rack = rack || self.0.is_multiple_of(4);
        let header = Header {
            hdr0: hdr0(function, self.0),
            hdr1: prep(len.wrapping_add(HEADER_LEN as u32), HDR_TOTAL_LEN)
                | if rack { HDR_REC_ACK } else { 0 }
                | if dack { HDR_DONE_ACK } else { 0 },
        };
        self.0 = self.0.wrapping_add(1);
        header
    }

    /// `rtw89_h2c_pkt_set_hdr_fwdl`: the header at the current sequence
    /// number, asking for no ack; the sequence does not advance.
    pub const fn set_hdr_fwdl(&self, function: Function, len: u32) -> Header {
        Header {
            hdr0: hdr0(function, self.0),
            hdr1: prep(len.wrapping_add(HEADER_LEN as u32), HDR_TOTAL_LEN),
        }
    }
}

/// One H2C as `rtw89_h2c_tx` takes it: the header, when it has one, and
/// the payload behind it, with `fwdl` for the TXWD's FW_DL.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub header: Option<Header>,
    pub payload: &'a [u8],
    pub fwdl: bool,
}

impl Packet<'_> {
    /// The skb's length when `rtw89_h2c_tx` takes it: header and payload.
    pub fn length(&self) -> usize {
        self.header.map_or(0, |_| HEADER_LEN) + self.payload.len()
    }

    /// What `rtw89_core_tx_update_desc_info` makes of it.
    pub fn desc(&self) -> DescInfo {
        DescInfo::fwcmd(self.length() as u32, self.fwdl)
    }

    /// The bytes `rtw89_pci_fwcmd_submit` maps: TXWD body and packet.
    pub fn frame_length(&self) -> usize {
        H2C_DESC_SIZE + self.length()
    }

    /// Write the frame into `out`, which must be [`Self::frame_length`]
    /// bytes long.
    pub fn frame(&self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != self.frame_length() {
            return Err(Error::Length(out.len()));
        }
        self.pieces(|offset, bytes| {
            out[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        })
    }

    /// The frame's pieces, each with its offset: body, header, payload.
    fn pieces(
        &self,
        mut write: impl FnMut(usize, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        write(0, &self.desc().body())?;
        let mut offset = H2C_DESC_SIZE;
        if let Some(header) = self.header {
            write(offset, &header.encode())?;
            offset += HEADER_LEN;
        }
        write(offset, self.payload)
    }
}

/// Why an H2C was not sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `rtw89_h2c_tx`'s `-ENOSPC`: CH12 had no free BD after reclaiming
    /// what the chip read.
    NoResource,
    /// A packet longer than TXPKT_SIZE can carry, or a frame buffer of the
    /// wrong size.
    Length(usize),
    /// A register access the interface refused.
    Io(io::Error),
    /// Allocating, mapping or queueing the command buffer failed.
    Ring(ring::Error),
}

impl From<ring::Error> for Error {
    fn from(error: ring::Error) -> Self {
        match error {
            ring::Error::Io(error) => Self::Io(error),
            error => Self::Ring(error),
        }
    }
}

/// An RTL8852BE's H2C channel: `rtwdev->fw.h2c_seq`, and the DMA
/// allocation the command buffers come from.
pub struct Channel<'s> {
    source: &'s dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    sequence: Sequence,
}

impl<'s> Channel<'s> {
    /// A channel at sequence number 0, whose command buffers come from
    /// `source` and are mapped into `domain`, the domain of the rings.
    pub fn new(source: &'s dyn PageSource, domain: Arc<dyn DmaDomain>) -> Self {
        Self {
            source,
            domain,
            sequence: Sequence::default(),
        }
    }

    pub fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// `fw_info->h2c_seq = 0`, as `__rtw89_fw_download` sets it once the
    /// image is in.
    pub fn reset_sequence(&mut self) {
        self.sequence = Sequence::default();
    }

    /// A command: `rtw89_h2c_pkt_set_hdr` with `FWCMD_TYPE_H2C` over
    /// `payload`, sent without FW_DL.
    pub fn command<'p>(
        &mut self,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &'p [u8],
    ) -> Packet<'p> {
        Packet {
            header: Some(self.sequence.set_hdr(
                Function::mac(class, func),
                rack,
                dack,
                payload.len() as u32,
            )),
            payload,
            fwdl: false,
        }
    }

    /// The firmware header: `__rtw89_fw_download_hdr`'s
    /// `rtw89_h2c_pkt_set_hdr_fwdl` over `payload`, sent without FW_DL.
    pub fn fwdl_header<'p>(&self, payload: &'p [u8]) -> Packet<'p> {
        Packet {
            header: Some(self.sequence.set_hdr_fwdl(FWHDR_DL, payload.len() as u32)),
            payload,
            fwdl: false,
        }
    }

    /// One part of a section: `__rtw89_fw_download_main`'s skb, which has
    /// no header, sent with FW_DL.
    pub fn fwdl_part(payload: &[u8]) -> Packet<'_> {
        Packet {
            header: None,
            payload,
            fwdl: true,
        }
    }

    /// `rtw89_h2c_tx` over an RTL8852BE's PCIe rings: what the chip read on
    /// CH12 is reclaimed, a free BD is required, the frame is copied into
    /// a fresh command buffer that becomes the next BD, and the host index
    /// is written. The register accesses are rtw89's: CH12's index read,
    /// then its host index written.
    pub fn send<I: Io + ?Sized>(
        &self,
        io: &mut I,
        rings: &mut Rings,
        packet: &Packet<'_>,
    ) -> Result<(), Error> {
        let length = packet.length();
        if length > MAX_PACKET {
            return Err(Error::Length(length));
        }
        // __rtw89_pci_check_and_reclaim_tx_fwcmd_resource
        rings.reclaim_fwcmd(io)?;
        if rings.avail_txbd(TxChannel::Ch12)? == 0 {
            return Err(Error::NoResource);
        }
        let frame = packet.frame_length();
        let buffer = Buffer::new(self.source, self.domain.clone(), frame, Direction::ToDevice)?;
        packet.pieces(|offset, bytes| Ok(buffer.write(offset, bytes)?))?;
        rings.fwcmd_submit(buffer, frame as u16)?;
        rings.tx_kick_off(io, TxChannel::Ch12)?;
        Ok(())
    }
}

impl Channel<'_> {
    /// A command of any category: `rtw89_h2c_pkt_set_hdr` with `function`
    /// over `payload`, sent without FW_DL. [`Self::command`] is this for
    /// `H2C_CAT_MAC`.
    pub fn command_for<'p>(
        &mut self,
        function: Function,
        rack: bool,
        dack: bool,
        payload: &'p [u8],
    ) -> Packet<'p> {
        Packet {
            header: Some(
                self.sequence
                    .set_hdr(function, rack, dack, payload.len() as u32),
            ),
            payload,
            fwdl: false,
        }
    }
}
pub mod phy;
pub mod ra;
pub mod station;

#[cfg(test)]
mod tests;
