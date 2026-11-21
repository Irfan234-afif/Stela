// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! RTL8852B's RF calibration tables ([`table`]) and `rtw89_rfk_parser`, which
//! runs one: each entry is a register write `_rfk_handler` dispatches, from
//! pinned rtw89/phy.h and phy.c. Running a table proves nothing about the
//! calibration it belongs to.
use crate::wifi::realtek::ax::io::{Error, Io, Registers};

pub mod table;

/// One `struct rtw89_reg5_def`, by its `RTW89_DECL_RFK_*` flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry {
    /// `RTW89_DECL_RFK_WRF`: `rtw89_write_rf`.
    RfWrite {
        path: u8,
        address: u32,
        mask: u32,
        data: u32,
    },
    /// `RTW89_DECL_RFK_WM`: `rtw89_phy_write32_mask`.
    Mask { address: u32, mask: u32, data: u32 },
    /// `RTW89_DECL_RFK_WS`: `rtw89_phy_write32_set`.
    Set { address: u32, bits: u32 },
    /// `RTW89_DECL_RFK_WC`: `rtw89_phy_write32_clr`.
    Clear { address: u32, bits: u32 },
    /// `RTW89_DECL_RFK_DELAY`: `udelay`.
    Delay { microseconds: u32 },
}

/// `rtw89_rfk_parser`: every entry of `table`, in order. The first access
/// the chip refuses ends it.
pub fn run<I: Io + ?Sized>(io: &mut I, table: &[Entry]) -> Result<(), Error> {
    for entry in table {
        match *entry {
            Entry::RfWrite {
                path,
                address,
                mask,
                data,
            } => io.write_rf(path, address, mask, data)?,
            Entry::Mask {
                address,
                mask,
                data,
            } => io.phy_write32_mask(address, mask, data)?,
            Entry::Set { address, bits } => io.phy_write32_set(address, bits)?,
            Entry::Clear { address, bits } => io.phy_write32_clr(address, bits)?,
            Entry::Delay { microseconds } => io.delay_us(u64::from(microseconds)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
