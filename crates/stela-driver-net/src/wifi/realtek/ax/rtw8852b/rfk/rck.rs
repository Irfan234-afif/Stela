// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's RF resistor-capacitor calibration, `rtw8852b_rck` and `_rck`
//! from pinned rtw89/rtw8852b_rfk.c: each path is put in RX mode, its RCK
//! triggered, and the code it reports written back. The register reads
//! rtw89 makes for its log lines are made here too. That RCK reported done
//! is all a return proves.
use super::{RF_PATH_NUM, poll, reg::*};
use crate::wifi::realtek::ax::{
    io::{Error, Io, Registers},
    registers::RFREG_MASK,
};

/// `rtw8852b_rck`: `_rck` on paths A and B. Returns, per path, whether its
/// RCK never reported done within 30 us, which rtw89 only logs before
/// writing back the code it read anyway.
pub fn rck<I: Io + ?Sized>(io: &mut I) -> Result<[bool; RF_PATH_NUM as usize], Error> {
    let mut timed_out = [false; RF_PATH_NUM as usize];
    for path in 0..RF_PATH_NUM {
        timed_out[usize::from(path)] = rck_path(io, path)?;
    }
    Ok(timed_out)
}

/// `_rck`: whether the poll on `RR_RCKS` bit 3 timed out.
fn rck_path<I: Io + ?Sized>(io: &mut I, path: u8) -> Result<bool, Error> {
    let rf_reg5 = io.read_rf(path, RR_RSV1, RFREG_MASK)?;

    io.write_rf(path, RR_RSV1, RR_RSV1_RST, 0x0)?;
    io.write_rf(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX)?;

    // "[RCK] RF0x00 = 0x%05x"
    io.read_rf(path, RR_MOD, RFREG_MASK)?;

    // RCK trigger
    io.write_rf(path, RR_RCKC, RFREG_MASK, 0x00240)?;

    let done = poll(io, 2, 30, |io| Ok(io.read_rf(path, RR_RCKS, 1 << 3)? != 0))?;

    let rck_val = io.read_rf(path, RR_RCKC, RR_RCKC_CA)?;

    io.write_rf(path, RR_RCKC, RFREG_MASK, rck_val)?;
    io.write_rf(path, RR_RSV1, RFREG_MASK, rf_reg5)?;

    // "[RCK] RF 0x1b = 0x%x"
    io.read_rf(path, RR_RCKC, RFREG_MASK)?;
    Ok(!done)
}
