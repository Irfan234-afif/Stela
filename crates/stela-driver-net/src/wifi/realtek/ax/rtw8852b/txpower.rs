// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2024 Realtek Corporation
//! RTL8852B's `set_txpwr` and `set_txpwr_ctrl` as pinned rtw89's
//! rtw8852b_common.c makes them: [`set_txpwr`] is `__rtw8852bx_set_txpwr`,
//! the AX generation's by-rate, offset, limit and RU limit pages
//! ([`super::super::txpower`]) with RTL8852B's TX shape
//! (`rtw8852bx_set_tx_shape`, its 2.4 GHz DFIR from
//! `rtw8852bx_bb_set_tx_shape_dfir`) between them, closed by the reference
//! of `rtw8852bx_set_txpwr_diff`; [`set_txpwr_ctrl`] is
//! `__rtw8852bx_set_txpwr_ctrl`. Each makes the reads and writes its rtw89
//! counterpart makes, in the same order, read-modify-write included.
//!
//! `rtw8852bx_set_txpwr_diff` sets the reference from the paths' antenna
//! gain offset (`rtw89_phy_ant_gain_pwr_offset`) and SAR difference
//! (`rtw8852bx_get_txpwr_sar_diff`). Without ACPI's antenna gain policy
//! the first is 0, and with one SAR bound for both paths (none, or Stela's
//! [`super::super::txpower::Cap`]) the second is 0, so the reference is
//! [`set_txpwr_ref`]'s at 0. A per-path offset is the seam:
//! [`set_txpwr_ref`] takes any.
//!
//! What a write proves: that the registers took rtw89's values. What the
//! chip sends at them is TSSI's (3.8): this sets no TSSI or DPK state.
use super::super::{
    io::{Error, Registers},
    registers::{
        DCFO_OPT, DPD_PWR_CW, DPD_REF, DPD_TSSI_CW, PWR_RATE_CTRL, PWR_REF, TXFIR0,
        TXSHAPE_TRIANGULAR_CFG,
    },
    txpower::{
        Band, Chan, Power, RS_CCK, RS_OFDM, mac_txpwr_write32_mask, set_byrate, set_limit,
        set_limit_ru, set_offset,
    },
};

/// `RF_PATH_NUM_8852BX`'s BB TX power bases, `addr[]` of
/// `rtw8852bx_set_txpwr_ref`.
const TXPWR_REF_BASE: [u32; 2] = [0x5800, 0x7800];
/// `ofst_ofdm` and `ofst_cck` from each base.
const OFST_OFDM: u32 = 0x4;
const OFST_CCK: u32 = 0x8;

/// `rtw8852bx_bb_set_tx_shape_dfir`'s `param_flat`, `param_sharp` and
/// `param_sharp_14`.
const DFIR_FLAT: [u32; 8] = [
    0x023D23FF, 0x0029B354, 0x000FC1C8, 0x00FDB053, 0x00F86F9A, 0x06FAEF92, 0x00FE5FCC, 0x00FFDFF5,
];
const DFIR_SHARP: [u32; 8] = [
    0x023D83FF, 0x002C636A, 0x0013F204, 0x00008090, 0x00F87FB0, 0x06F99F83, 0x00FDBFBA, 0x00003FF5,
];
const DFIR_SHARP_14: [u32; 8] = [
    0x023B13FF, 0x001C42DE, 0x00FDB0AD, 0x00F60F6E, 0x00FD8F92, 0x0602D011, 0x0001C02C, 0x00FFF00A,
];

/// `u32_encode_bits`.
const fn encode(value: u32, field: u32) -> u32 {
    (value << field.trailing_zeros()) & field
}

/// `rtw8852bx_bb_cal_txpwr_ref`: the TSSI offset, power and reference
/// codewords for a reference `reference` (1/4 dB) less `pwr_ofst_decrease`
/// (1/8 dB), the RF codeword held to 15 through 63.
pub fn bb_cal_txpwr_ref(reference: i16, pwr_ofst_decrease: u16) -> u32 {
    const TSSI_16DBM_CW: i32 = 0x12c;
    const BASE_CW_0DB: i32 = 0x27;
    let pwr_s10_3 =
        ((i32::from(reference) << 1) + (BASE_CW_0DB << 3) - i32::from(pwr_ofst_decrease)) as i16;
    let bb_pwr_cw = u32::from(pwr_s10_3 as u16 & 0x7);
    let rf_pwr_cw = i32::from((pwr_s10_3 as u16 & 0x1f8) >> 3).clamp(15, 63) as u32;
    let pwr_cw = (rf_pwr_cw << 3) | bb_pwr_cw;
    let tssi_ofst_cw = ((TSSI_16DBM_CW + (i32::from(reference) << 1) - (16 << 3)) as u32)
        .wrapping_sub(u32::from(pwr_ofst_decrease));
    encode(tssi_ofst_cw, DPD_TSSI_CW)
        | encode(pwr_cw, DPD_PWR_CW)
        | encode(reference as u32, DPD_REF)
}

/// `rtw8852bx_set_txpwr_ref`: `R_AX_PWR_REF` cleared, then each path's OFDM
/// and CCK reference at 0 dB, path A lowered by a positive `pwr_ofst`
/// (path A's power less path B's, 1/8 dB) and path B by a negative one.
pub fn set_txpwr_ref<I: Registers + ?Sized>(io: &mut I, pwr_ofst: i16) -> Result<(), Error> {
    const MASK: u32 = DPD_TSSI_CW | DPD_PWR_CW | DPD_REF;
    mac_txpwr_write32_mask(io, PWR_RATE_CTRL, PWR_REF, 0)?;
    let ofst_dec = if pwr_ofst > 0 {
        [0, pwr_ofst as u16]
    } else {
        [pwr_ofst.unsigned_abs(), 0]
    };
    for offset in [OFST_OFDM, OFST_CCK] {
        for (base, decrease) in TXPWR_REF_BASE.into_iter().zip(ofst_dec) {
            let value = bb_cal_txpwr_ref(0, decrease);
            io.phy_write32_mask(base + offset, MASK, value)?;
        }
    }
    Ok(())
}

/// `rtw8852bx_bb_set_tx_shape_dfir`: the 2.4 GHz DFIR for channel 14 or
/// the flat or sharp shape.
fn set_tx_shape_dfir<I: Registers + ?Sized>(
    io: &mut I,
    chan: &Chan,
    tx_shape_idx: u8,
) -> Result<(), Error> {
    if chan.channel > 14 {
        // rtw89 warns and writes nothing.
        return Ok(());
    }
    let param = if chan.channel == 14 {
        &DFIR_SHARP_14
    } else if tx_shape_idx == 0 {
        &DFIR_FLAT
    } else {
        &DFIR_SHARP
    };
    for (i, &value) in (0u32..).zip(param) {
        io.phy_write32_mask(TXFIR0 + (i << 2), u32::MAX, value)?;
    }
    Ok(())
}

/// `rtw8852bx_set_tx_shape`: on 2.4 GHz the CCK shape's DFIR, then the OFDM
/// shape's triangular config.
pub fn set_tx_shape<I: Registers + ?Sized>(
    io: &mut I,
    power: &Power<'_>,
    chan: &Chan,
) -> Result<(), Error> {
    let tx_shape_cck = power.tx_shape_idx(chan.band, RS_CCK);
    let tx_shape_ofdm = power.tx_shape_idx(chan.band, RS_OFDM);
    if chan.band == Band::Ghz2 {
        set_tx_shape_dfir(io, chan, tx_shape_cck)?;
    }
    io.phy_write32_mask(DCFO_OPT, TXSHAPE_TRIANGULAR_CFG, u32::from(tx_shape_ofdm))
}

/// `__rtw8852bx_set_txpwr` at PHY 0.
pub fn set_txpwr<I: Registers + ?Sized>(
    io: &mut I,
    power: &Power<'_>,
    chan: &Chan,
) -> Result<(), Error> {
    set_byrate(io, power, chan)?;
    set_offset(io, power, chan)?;
    set_tx_shape(io, power, chan)?;
    set_limit(io, power, chan)?;
    set_limit_ru(io, power, chan)?;
    // rtw8852bx_set_txpwr_diff: no antenna gain offset, no SAR difference.
    set_txpwr_ref(io, 0)
}

/// `__rtw8852bx_set_txpwr_ctrl` at PHY 0.
pub fn set_txpwr_ctrl<I: Registers + ?Sized>(io: &mut I) -> Result<(), Error> {
    set_txpwr_ref(io, 0)
}
