// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The channels RTL8852B's calibrations ran on, told to the firmware:
//! `rtw89_fw_h2c_rf_ntfy_mcc` from pinned rtw89/fw.c, which
//! `rtw8852b_rfk_channel` sends last, and `rtw8852b_mcc_get_ch_info` from
//! rtw8852b_rfk.c with `rtw89_rfk_chan_lookup` from phy.c, which picks the
//! MCC table first.
//!
//! The H2C is `H2C_CAT_OUTSRC`, class `H2C_CL_OUTSRC_RF_FW_NOTIFY`, function
//! `H2C_FUNC_OUTSRC_RF_GET_MCCCH`, asking for no ack, with `struct
//! rtw89_fw_h2c_rf_get_mccch`: rtw89 sends the `_v0` layout only to a
//! firmware with `RFK_NTFY_MCC_V0`, which its feature table gives RTL8852C
//! alone. That the H2C went to the ring is all a return proves; the
//! firmware does not answer it.
use super::{Channel, RfkMcc};
use crate::wifi::realtek::ax::{coex::Commands, h2c, io::Io};

/// `H2C_CL_OUTSRC_RF_FW_NOTIFY` and `H2C_FUNC_OUTSRC_RF_GET_MCCCH`.
pub const H2C_CL_OUTSRC_RF_FW_NOTIFY: u8 = 0xa;
pub const H2C_FUNC_OUTSRC_RF_GET_MCCCH: u8 = 0x2;
/// `sizeof(struct rtw89_fw_h2c_rf_get_mccch)`.
pub const RF_GET_MCCCH_LEN: usize = 20;
/// `__RTW89_RFK_CHS_NR_V0`: the tables an RTL8852B looks through.
const RFK_CHS_NR_V0: usize = 2;

/// `struct rtw89_fw_h2c_rf_get_mccch` for `mcc`: `ch_0_0`, `ch_0_1`,
/// `ch_1_0`, `ch_1_1` and `current_channel`, little-endian words.
pub fn rf_get_mccch(mcc: &RfkMcc) -> [u8; RF_GET_MCCCH_LEN] {
    let idx = usize::from(mcc.table_idx);
    let words = [mcc.ch[0], mcc.ch[0], mcc.ch[1], mcc.ch[1], mcc.ch[idx]];
    let mut payload = [0; RF_GET_MCCCH_LEN];
    for (bytes, word) in payload.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *bytes = u32::from(word).to_le_bytes();
    }
    payload
}

/// `rtw89_fw_h2c_rf_ntfy_mcc`: [`rf_get_mccch`] to `commands`, which rtw89
/// sends without asking for an ack.
pub fn rf_ntfy_mcc<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    mcc: &RfkMcc,
) -> Result<(), h2c::Error> {
    commands.send(
        io,
        H2C_CL_OUTSRC_RF_FW_NOTIFY,
        H2C_FUNC_OUTSRC_RF_GET_MCCCH,
        false,
        false,
        &rf_get_mccch(mcc),
    )
}

/// `rfk_chan_is_equivalent` for a table that keeps its band
/// (`has_band`) and not its width: set, and the same number and band.
fn is_equivalent(ch: u8, band: u8, channel: Channel) -> bool {
    ch != 0 && ch == channel.number && band == channel.band as u8
}

/// `rtw8852b_mcc_get_ch_info(rtwdev, RTW89_PHY_0)` on `channel`, the
/// entity's first channel: the table that already holds it, or the first
/// that holds none of the entity's channels, or table 0, made current and
/// given `channel`.
///
/// Stela runs one channel context, so the entity's channels
/// (`rtw89_iterate_entity_chan`) are `channel` alone; a table that does
/// not hold it is idle, and the first table is taken unless the second
/// holds `channel`.
pub fn mcc_get_ch_info(mcc: &mut RfkMcc, channel: Channel) {
    // rtw89_rfk_chan_lookup
    let mut sel = None;
    let mut idx = None;
    for i in 0..RFK_CHS_NR_V0 {
        if is_equivalent(mcc.ch[i], mcc.band[i], channel) {
            idx = Some(i);
            break;
        }

        let found = is_equivalent(mcc.ch[i], mcc.band[i], channel);
        if !found && sel.is_none() {
            sel = Some(i);
        }
    }
    let idx = idx.or(sel).unwrap_or(0);

    mcc.ch[idx] = channel.number;
    mcc.band[idx] = channel.band as u8;
    mcc.table_idx = idx as u8;
}
