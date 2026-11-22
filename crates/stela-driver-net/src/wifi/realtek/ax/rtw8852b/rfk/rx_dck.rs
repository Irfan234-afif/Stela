// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's RX DC offset calibration, `rtw8852b_rx_dck`, `_rx_dck` and
//! `_set_rx_dck` from pinned rtw89/rtw8852b_rfk.c, line by line: with the
//! scheduler stopped and each path out of TX mode, every path is put in RX
//! mode with its fine tune cleared, its DCK triggered, and its fine tune
//! and RF 0x05 put back. That the triggers were written is all a return
//! proves.
use super::{RF_PATH_NUM, Scheduler, paused, reg::*};
use crate::wifi::realtek::ax::{
    io::{Error, Io, Registers},
    mac,
    registers::RFREG_MASK,
};

/// `rtw8852b_rx_dck(rtwdev, RTW89_PHY_0, …)`: `_rx_dck` with the scheduler
/// stopped and both paths out of TX mode, between the coex notifications
/// `BTC_WRFKT_RXDCK` start and stop, no-ops here. `is_tssi_mode` is
/// `rtwdev->is_tssi_mode` for paths A and B: a path in TSSI mode has its
/// TSSI tracking enabled for the calibration. Returns the scheduler's
/// refusal, which rtw89 ignores.
pub fn rx_dck<I: Io + ?Sized, S: Scheduler<I> + ?Sized>(
    io: &mut I,
    scheduler: &mut S,
    is_tssi_mode: [bool; RF_PATH_NUM as usize],
) -> Result<Option<mac::Cause>, Error> {
    paused(io, scheduler, |io| rx_dck_paths(io, is_tssi_mode))
}

/// `_set_rx_dck`.
pub(crate) fn set_rx_dck<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<(), Error> {
    io.write_rf(path, RR_DCK1, RR_DCK1_CLR, 0x0)?;
    io.write_rf(path, RR_DCK, RR_DCK_LV, 0x0)?;
    io.write_rf(path, RR_DCK, RR_DCK_LV, 0x1)?;
    // mdelay(1)
    io.delay_us(1000);
    Ok(())
}

/// `_rx_dck`.
fn rx_dck_paths<I: Io + ?Sized>(
    io: &mut I,
    is_tssi_mode: [bool; RF_PATH_NUM as usize],
) -> Result<(), Error> {
    for path in 0..RF_PATH_NUM {
        let tssi = is_tssi_mode[usize::from(path)];
        let rf_reg5 = io.read_rf(path, RR_RSV1, RFREG_MASK)?;
        // u8 dck_tune
        let dck_tune = io.read_rf(path, RR_DCK, RR_DCK_FINE)? as u8;

        if tssi {
            io.phy_write32_mask(
                R_P0_TSSI_TRK + (u32::from(path) << 13),
                B_P0_TSSI_TRK_EN,
                0x1,
            )?;
        }

        io.write_rf(path, RR_RSV1, RR_RSV1_RST, 0x0)?;
        io.write_rf(path, RR_DCK, RR_DCK_FINE, 0x0)?;
        io.write_rf(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX)?;
        set_rx_dck(io, path)?;
        io.write_rf(path, RR_DCK, RR_DCK_FINE, u32::from(dck_tune))?;
        io.write_rf(path, RR_RSV1, RFREG_MASK, rf_reg5)?;

        if tssi {
            io.phy_write32_mask(
                R_P0_TSSI_TRK + (u32::from(path) << 13),
                B_P0_TSSI_TRK_EN,
                0x0,
            )?;
        }
    }
    Ok(())
}
