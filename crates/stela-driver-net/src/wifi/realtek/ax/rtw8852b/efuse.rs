// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2024 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B's own efuse: the sizes `rtw8852b_chip_info` gives the AX
//! generation's dump (rtw8852b.c), the layout of its logical map,
//! `struct rtw8852bx_efuse` (rtw8852b_common.h), and the two readers its
//! chip ops name, `__rtw8852bx_read_efuse` and `__rtw8852bx_read_phycap`
//! (rtw8852b_common.c), which make no access. [`super::super::efuse`] runs
//! them on the maps it reads.
//!
//! Each reader stores what its rtw89 counterpart stores, where it stores it:
//! flags rtw89 only ever sets stay set, and entries it skips keep what they
//! held. What it leaves out, and why:
//! - USB's MAC address at 0x488 (`struct rtw8852bx_u_efuse`): the chip is
//!   reached over PCIe, whose address is at 0x400.
//! - The rest of `struct rtw8852bx_efuse` (channel plan, IQK, BB swing, the
//!   board's antenna and coexistence bits, power indexes): no rtw89 code
//!   reads them on an RTL8852B.
//! - `rtw89_debug` dumps, which make no access.
//!
//! Decoding the fields proves nothing about them: a blank efuse decodes as
//! readily as a programmed one, and nothing here shows that the address is
//! the one on the card's label or that the trims suit its radio.
use super::super::efuse::{Efuse, EfuseGain, PowerTrim, Tssi};

/// `rtw8852b_chip_info`'s efuse sizes: `sec_ctrl_efuse_size`,
/// `physical_efuse_size`, `logical_efuse_size`, `dav_phy_efuse_size`,
/// `dav_log_efuse_size`, `phycap_addr` and `phycap_size`.
pub const SEC_CTRL_EFUSE_SIZE: usize = 4;
pub const PHYSICAL_EFUSE_SIZE: usize = 1216;
pub const LOGICAL_EFUSE_SIZE: usize = 2048;
pub const DAV_PHY_EFUSE_SIZE: usize = 96;
pub const DAV_LOG_EFUSE_SIZE: usize = 16;
pub const PHYCAP_ADDR: u32 = 0x580;
pub const PHYCAP_SIZE: usize = 128;
/// `rtw89_parse_efuse_map_ax`'s `full_log_size`: the main logical map, then
/// the DAV one.
pub const FULL_LOG_SIZE: usize = LOGICAL_EFUSE_SIZE + DAV_LOG_EFUSE_SIZE;
/// `RF_PATH_NUM_8852BX`.
pub const RF_PATH_NUM_8852BX: usize = 2;

/// Where `struct rtw8852bx_efuse`, which is packed, keeps what
/// `__rtw8852bx_read_efuse` reads: each path's `struct
/// rtw8852bx_tssi_offset`, `xtal_k`, `rfe_type`, `country_code`, each
/// path's thermal value, the RX gain offsets, and the PCIe MAC address
/// (`e.mac_addr`). [`SIZE`] is the structure's size.
pub const PATH_A_TSSI: usize = 0x210;
pub const PATH_B_TSSI: usize = 0x23a;
pub const XTAL_K: usize = 0x2b9;
pub const RFE_TYPE: usize = 0x2ca;
pub const COUNTRY_CODE: usize = 0x2cb;
pub const PATH_A_THERM: usize = 0x2d0;
pub const PATH_B_THERM: usize = 0x2d1;
pub const RX_GAIN_2G_OFDM: usize = 0x2d4;
pub const RX_GAIN_2G_CCK: usize = 0x2d6;
pub const RX_GAIN_5G_LOW: usize = 0x2d8;
pub const RX_GAIN_5G_MID: usize = 0x2da;
pub const RX_GAIN_5G_HIGH: usize = 0x2dc;
pub const E_MAC_ADDR: usize = 0x400;
pub const SIZE: usize = 0x48e;
// The structure lies within the main logical map, as rtw89 casts it.
const _: () = assert!(SIZE <= LOGICAL_EFUSE_SIZE);
/// Where `struct rtw8852bx_tssi_offset` keeps `cck_tssi`, `bw40_tssi` and
/// `bw40_1s_tssi_5g`, and its size.
pub const CCK_TSSI: usize = 0;
pub const BW40_TSSI: usize = 6;
pub const BW40_1S_TSSI_5G: usize = 18;
pub const TSSI_OFFSET_SIZE: usize = 32;

/// `TSSI_CCK_CH_GROUP_NUM`, `TSSI_MCS_2G_CH_GROUP_NUM`,
/// `TSSI_MCS_5G_CH_GROUP_NUM`, `TSSI_MCS_CH_GROUP_NUM` and
/// `TSSI_TRIM_CH_GROUP_NUM` (core.h).
pub const TSSI_CCK_CH_GROUP_NUM: usize = 6;
pub const TSSI_MCS_2G_CH_GROUP_NUM: usize = 5;
pub const TSSI_MCS_5G_CH_GROUP_NUM: usize = 14;
pub const TSSI_MCS_CH_GROUP_NUM: usize = TSSI_MCS_2G_CH_GROUP_NUM + TSSI_MCS_5G_CH_GROUP_NUM;
pub const TSSI_TRIM_CH_GROUP_NUM: usize = 8;
/// `enum rtw89_gain_offset` up to `RTW89_GAIN_OFFSET_5G_HIGH`, and
/// `RTW89_SUBBAND_2GHZ_5GHZ_NR`: the 2 GHz and 5 GHz entries an RTL8852B
/// fills.
pub const GAIN_OFFSET_2G_CCK: usize = 0;
pub const GAIN_OFFSET_2G_OFDM: usize = 1;
pub const GAIN_OFFSET_5G_LOW: usize = 2;
pub const GAIN_OFFSET_5G_MID: usize = 3;
pub const GAIN_OFFSET_5G_HIGH: usize = 4;
pub const GAIN_OFFSET_2G_5G: usize = 5;
pub const SUBBAND_2GHZ_5GHZ_NR: usize = 5;

/// `rtw8852bx_phycap_parsing_power_cal`'s `PWR_K_CHK_OFFSET` and
/// `PWR_K_CHK_VALUE`.
pub const PWR_K_CHK_OFFSET: u32 = 0x5e9;
pub const PWR_K_CHK_VALUE: u8 = 0xaa;
/// `tssi_trim_addr`: each path's first TSSI trim, the others below it.
pub const TSSI_TRIM_ADDR: [u32; RF_PATH_NUM_8852BX] = [0x5d6, 0x5ab];
/// `thm_trim_addr` and `pabias_trim_addr`.
pub const THM_TRIM_ADDR: [u32; RF_PATH_NUM_8852BX] = [0x5df, 0x5dc];
pub const PABIAS_TRIM_ADDR: [u32; RF_PATH_NUM_8852BX] = [0x5de, 0x5db];
/// `rtw8852bx_phycap_parsing_gain_comp`'s `comp_addrs`, by path and subband;
/// 0 for the subband it skips.
pub const COMP_ADDRS: [[u32; SUBBAND_2GHZ_5GHZ_NR]; RF_PATH_NUM_8852BX] = [
    [0x5bb, 0x5ba, 0, 0x5b9, 0x5b8],
    [0x590, 0x58f, 0, 0x58e, 0x58d],
];

/// `_decode_efuse_gain`: the high and low nibbles, each sign-extended
/// (`FIELD_GET_SIGNED`), and whether the byte is programmed (not 0xff).
pub const fn decode_efuse_gain(data: u8) -> (i8, i8, bool) {
    let high = (data as i8) >> 4;
    let low = ((data << 4) as i8) >> 4;
    (high, low, data != 0xff)
}

/// `__rtw8852bx_read_efuse` over PCIe: the country code, the TSSI offsets
/// and thermal values (`rtw8852bx_efuse_parsing_tssi`), the RX gain offsets
/// (`rtw8852bx_efuse_parsing_gain_offset`), the MAC address, the RFE type
/// and the crystal cap, from `log_map` as `rtw89_parse_efuse_map_ax`
/// decoded it.
pub fn read_efuse(
    log_map: &[u8; FULL_LOG_SIZE],
    efuse: &mut Efuse,
    tssi: &mut Tssi,
    gain: &mut EfuseGain,
) {
    efuse.country_code = [log_map[COUNTRY_CODE], log_map[COUNTRY_CODE + 1]];
    efuse_parsing_tssi(log_map, tssi);
    efuse_parsing_gain_offset(log_map, gain);
    efuse
        .addr
        .copy_from_slice(&log_map[E_MAC_ADDR..E_MAC_ADDR + 6]);
    efuse.rfe_type = log_map[RFE_TYPE];
    efuse.xtal_cap = log_map[XTAL_K];
}

/// `rtw8852bx_efuse_parsing_tssi`.
fn efuse_parsing_tssi(map: &[u8; FULL_LOG_SIZE], tssi: &mut Tssi) {
    tssi.thermal = [map[PATH_A_THERM], map[PATH_B_THERM]];
    for (path, base) in [PATH_A_TSSI, PATH_B_TSSI].into_iter().enumerate() {
        let ofst = &map[base..base + TSSI_OFFSET_SIZE];
        for (to, &from) in tssi.tssi_cck[path]
            .iter_mut()
            .zip(&ofst[CCK_TSSI..CCK_TSSI + TSSI_CCK_CH_GROUP_NUM])
        {
            *to = from as i8;
        }
        let mcs = ofst[BW40_TSSI..BW40_TSSI + TSSI_MCS_2G_CH_GROUP_NUM]
            .iter()
            .chain(&ofst[BW40_1S_TSSI_5G..BW40_1S_TSSI_5G + TSSI_MCS_5G_CH_GROUP_NUM]);
        for (to, &from) in tssi.tssi_mcs[path].iter_mut().zip(mcs) {
            *to = from as i8;
        }
    }
}

/// `rtw8852bx_efuse_parsing_gain_offset`: path A's offset in each byte's
/// high nibble, path B's in its low one; valid when any byte is programmed.
fn efuse_parsing_gain_offset(map: &[u8; FULL_LOG_SIZE], gain: &mut EfuseGain) {
    let mut valid = false;
    for (at, index) in [
        (RX_GAIN_2G_CCK, GAIN_OFFSET_2G_CCK),
        (RX_GAIN_2G_OFDM, GAIN_OFFSET_2G_OFDM),
        (RX_GAIN_5G_LOW, GAIN_OFFSET_5G_LOW),
        (RX_GAIN_5G_MID, GAIN_OFFSET_5G_MID),
        (RX_GAIN_5G_HIGH, GAIN_OFFSET_5G_HIGH),
    ] {
        let (high, low, programmed) = decode_efuse_gain(map[at]);
        gain.offset[0][index] = high;
        gain.offset[1][index] = low;
        valid |= programmed;
    }
    gain.offset_valid = valid;
}

/// The phycap byte at physical efuse address `address`.
fn phycap(map: &[u8; PHYCAP_SIZE], address: u32) -> u8 {
    map[(address - PHYCAP_ADDR) as usize]
}

/// `__rtw8852bx_read_phycap`: the power calibration mark
/// (`rtw8852bx_phycap_parsing_power_cal`), the TSSI, thermal and PA bias
/// trims, and the RX gain compensation, from the phycap bytes
/// `rtw89_parse_phycap_map_ax` read from [`PHYCAP_ADDR`].
pub fn read_phycap(
    map: &[u8; PHYCAP_SIZE],
    efuse: &mut Efuse,
    tssi: &mut Tssi,
    trim: &mut PowerTrim,
    gain: &mut EfuseGain,
) {
    // rtw8852bx_phycap_parsing_power_cal
    if phycap(map, PWR_K_CHK_OFFSET) == PWR_K_CHK_VALUE {
        efuse.power_k_valid = true;
    }

    // rtw8852bx_phycap_parsing_tssi: each path's trims at decreasing
    // addresses, all zero when none is programmed.
    let mut pg = false;
    for (path, &first) in TSSI_TRIM_ADDR.iter().enumerate() {
        for (group, trim) in tssi.tssi_trim[path].iter_mut().enumerate() {
            let value = phycap(map, first - group as u32);
            *trim = value as i8;
            pg |= value != 0xff;
        }
    }
    if !pg {
        tssi.tssi_trim = [[0; TSSI_TRIM_CH_GROUP_NUM]; RF_PATH_NUM_8852BX];
    }

    // rtw8852bx_phycap_parsing_thermal_trim
    for (path, &address) in THM_TRIM_ADDR.iter().enumerate() {
        trim.thermal_trim[path] = phycap(map, address);
        if trim.thermal_trim[path] != 0xff {
            trim.pg_thermal_trim = true;
        }
    }

    // rtw8852bx_phycap_parsing_pa_bias_trim
    for (path, &address) in PABIAS_TRIM_ADDR.iter().enumerate() {
        trim.pa_bias_trim[path] = phycap(map, address);
        if trim.pa_bias_trim[path] != 0xff {
            trim.pg_pa_bias_trim = true;
        }
    }

    // rtw8852bx_phycap_parsing_gain_comp: the low nibble of each byte.
    let mut valid = false;
    for (path, addresses) in COMP_ADDRS.iter().enumerate() {
        for (subband, &address) in addresses.iter().enumerate() {
            if address == 0 {
                continue;
            }
            let (_, low, programmed) = decode_efuse_gain(phycap(map, address));
            gain.comp[path][subband] = low;
            valid |= programmed;
        }
    }
    gain.comp_valid = valid;
}

#[cfg(test)]
mod tests;
