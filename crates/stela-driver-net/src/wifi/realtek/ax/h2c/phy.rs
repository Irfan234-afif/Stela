// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! The PHY's H2C, category `H2C_CAT_OUTSRC`, as pinned rtw89 builds them
//! (fw.c, fw.h, phy.c):
//!
//! - [`Outsrc`]: where an OUTSRC command goes, `rtw89_h2c_pkt_set_hdr` with
//!   `FWCMD_TYPE_H2C` and `H2C_CAT_OUTSRC`, then `rtw89_h2c_tx`; on an
//!   RTL8852BE that is [`Channel::outsrc`] on CH12 ([`super::super::mac::Fwcmd`]);
//! - [`RfRegInfo`]: `struct rtw89_fw_h2c_rf_reg_info`, the RF writes rtw89
//!   mirrors to the firmware while it loads a radio table
//!   (`rtw89_phy_cofig_rf_reg_store`), and [`RfRegInfo::send`], its
//!   `rtw89_phy_config_rf_reg_fw` with `rtw89_fw_h2c_rf_reg`: up to
//!   [`RF_PAGE_NUM`] pages of at most [`RF_PAGE_SIZE`] words, page `i` as
//!   function `i` of `H2C_CL_OUTSRC_RF_REG_A` (path A) or
//!   `H2C_CL_OUTSRC_RF_REG_B` (any other path), asking no ack. A write past
//!   the last page is not stored, and `curr_idx` stays at the end.
//!
//! A page sent proves only that its BD was written: what the firmware does
//! with the RF values, and whether it accepted the page (no ack is asked),
//! is not observable here.
use super::{Channel, Error, FWCMD_TYPE_H2C, Function, H2C_CAT_OUTSRC, Packet};
use crate::wifi::realtek::ax::{io::Io, mac::Fwcmd};
use alloc::vec::Vec;

/// `RTW89_H2C_RF_PAGE_SIZE`: words per RF_REG page.
pub const RF_PAGE_SIZE: usize = 500;
/// `RTW89_H2C_RF_PAGE_NUM`: pages per path.
pub const RF_PAGE_NUM: usize = 3;
/// `H2C_CL_OUTSRC_RF_REG_A` and `H2C_CL_OUTSRC_RF_REG_B`.
pub const H2C_CL_OUTSRC_RF_REG_A: u8 = 0x8;
pub const H2C_CL_OUTSRC_RF_REG_B: u8 = 0x9;

/// An OUTSRC command of `class` and `func`, delivered as H2C.
pub const fn outsrc(class: u8, func: u8) -> Function {
    Function {
        del_type: FWCMD_TYPE_H2C,
        cat: H2C_CAT_OUTSRC,
        class,
        func,
    }
}

impl Channel<'_> {
    /// An OUTSRC command: `rtw89_h2c_pkt_set_hdr` with `FWCMD_TYPE_H2C`
    /// and `H2C_CAT_OUTSRC` over `payload`, sent without FW_DL. Like
    /// [`Channel::command`], it takes the next sequence number.
    pub fn outsrc<'p>(
        &mut self,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &'p [u8],
    ) -> Packet<'p> {
        Packet {
            header: Some(self.sequence.set_hdr(
                outsrc(class, func),
                rack,
                dack,
                payload.len() as u32,
            )),
            payload,
            fwdl: false,
        }
    }
}

/// Where the PHY's H2C go: `rtw89_h2c_pkt_set_hdr` with `FWCMD_TYPE_H2C`
/// and `H2C_CAT_OUTSRC`, which takes the next sequence number whatever
/// follows, then `rtw89_h2c_tx`.
pub trait Outsrc<I: Io + ?Sized> {
    fn send_outsrc(
        &mut self,
        io: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), Error>;
}

impl<I: Io + ?Sized> Outsrc<I> for Fwcmd<'_, '_> {
    /// [`Channel::outsrc`], then [`Channel::send`].
    fn send_outsrc(
        &mut self,
        io: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), Error> {
        let packet = self.channel.outsrc(class, func, rack, dack, payload);
        self.channel.send(io, self.rings, &packet)
    }
}

/// Why [`RfRegInfo::send`] stopped, as `rtw89_phy_config_rf_reg_fw`
/// returns it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RfRegError {
    /// "rf reg h2c total len %d larger than %d" (`-EINVAL`): more words
    /// than the pages hold, which [`RfRegInfo::store`] never leaves.
    TooLong { words: u16 },
    /// `rtw89_fw_h2c_rf_reg` failed for `page`; the pages after it were
    /// not sent.
    Page { page: u8, error: Error },
}

/// `struct rtw89_fw_h2c_rf_reg_info`: the path and the words stored so
/// far, at most [`RF_PAGE_NUM`] times [`RF_PAGE_SIZE`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RfRegInfo {
    /// `rf_path`, which picks the class.
    pub rf_path: u8,
    /// `rtw89_phy_config_rf_h2c` up to `curr_idx`, as CPU words.
    words: Vec<u32>,
}

impl RfRegInfo {
    /// No words, for `rf_path`.
    pub fn new(rf_path: u8) -> Self {
        Self {
            rf_path,
            words: Vec::new(),
        }
    }

    /// `curr_idx`.
    pub fn curr_idx(&self) -> u16 {
        self.words.len() as u16
    }

    /// The words stored, in order.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// `rtw89_phy_cofig_rf_reg_store`: `addr << 20 | data`, cut to 32 bits
    /// as rtw89 cuts it, as the next word. A word past the last page is
    /// refused (rtw89's "RF parameters exceed size") with the index it
    /// would have had.
    pub fn store(&mut self, addr: u32, data: u32) -> Result<(), u16> {
        let index = self.curr_idx();
        if usize::from(index) / RF_PAGE_SIZE >= RF_PAGE_NUM {
            return Err(index);
        }
        self.words.push((addr << 20) | data);
        Ok(())
    }

    /// The class `rtw89_fw_h2c_rf_reg` picks: RF_REG_A for path A, RF_REG_B
    /// for every other path.
    pub const fn class(&self) -> u8 {
        if self.rf_path == 0 {
            H2C_CL_OUTSRC_RF_REG_A
        } else {
            H2C_CL_OUTSRC_RF_REG_B
        }
    }

    /// `rtw89_phy_config_rf_reg_fw`: each page in order, the last holding
    /// what remains, as `rtw89_fw_h2c_rf_reg` sends it (function = page, no
    /// REC_ACK or DONE_ACK asked, the words little-endian); the first page
    /// that fails stops the rest. Nothing is sent without words. Either way
    /// `curr_idx` returns to 0.
    pub fn send<I: Io + ?Sized, C: Outsrc<I> + ?Sized>(
        &mut self,
        io: &mut I,
        commands: &mut C,
    ) -> Result<(), RfRegError> {
        let result = self.send_pages(io, commands);
        self.words.clear();
        result
    }

    fn send_pages<I: Io + ?Sized, C: Outsrc<I> + ?Sized>(
        &self,
        io: &mut I,
        commands: &mut C,
    ) -> Result<(), RfRegError> {
        if self.words.len() > RF_PAGE_NUM * RF_PAGE_SIZE {
            return Err(RfRegError::TooLong {
                words: self.curr_idx(),
            });
        }
        let class = self.class();
        for (page, words) in self.words.chunks(RF_PAGE_SIZE).enumerate() {
            let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            commands
                .send_outsrc(io, class, page as u8, false, false, &payload)
                .map_err(|error| RfRegError::Page {
                    page: page as u8,
                    error,
                })?;
        }
        Ok(())
    }
}
