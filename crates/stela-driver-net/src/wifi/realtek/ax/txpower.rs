// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! The AX generation's TX power tables and the pages it writes from them,
//! as pinned rtw89 builds and writes them for an RTL8852B:
//!
//! - [`Tables::load`]: `rtw89_load_rfe_data_from_fw` (fw.c) with its
//!   `rtw89_fw_load_txpwr_byrate`, `_lmt_2ghz`, `_lmt_5ghz`,
//!   `_lmt_ru_2ghz`, `_lmt_ru_5ghz`, `rtw89_fw_load_tx_shape_lmt` and
//!   `_lmt_ru`, each entry checked as their `fw_*_entry_valid` check it and
//!   copied as `rtw89_txpwr_entcpy` copies it, from the confs
//!   [`super::elements`] chose for the board's RFE type, RFE 0's where the
//!   firmware has none of its own;
//! - [`Power`]: `rtw89_phy_read_txpwr_byrate`, `rtw89_phy_read_txpwr_limit`
//!   and `_limit_ru` (phy.c) under a [`Regulation`], their
//!   `rtw89_phy_fill_txpwr_limit_ax` and `_limit_ru_ax` pages for a
//!   channel, and `rtw89_get_tx_shape_idx` (core.h);
//! - [`set_byrate`], [`set_offset`], [`set_limit`] and [`set_limit_ru`]:
//!   `rtw89_phy_set_txpwr_byrate_ax`, `_offset_ax`, `_limit_ax` and
//!   `_limit_ru_ax`, through `rtw89_mac_txpwr_write32` and its mask variant
//!   at PHY 0 of an SCC chip (`rtw89_mac_get_txpwr_cr_ax`).
//!
//! RTL8852B's own steps, the TX shape and the reference that close
//! `__rtw8852bx_set_txpwr`, are [`super::rtw8852b::txpower`].
//!
//! Units are rtw89's: the tables hold RF units of 1/4 dB
//! (`txpwr_factor_rf`), the pages MAC units of 1/2 dB (`txpwr_factor_mac`),
//! the BB reference 1/8 dB (`txpwr_factor_bb`).
//!
//! Stela's addition, not rtw89's: a [`Cap`] from regulatory.db. rtw89
//! bounds each limit by its regulation table, its SAR query and, on 6 GHz,
//! the TPE; Stela has no SAR source, where `rtw89_query_sar` returns
//! `RTW89_SAR_TXPWR_MAC_MAX`, and puts the country's EIRP from
//! regulatory.db in that place, less the antenna gain cfg80211 reads the
//! database under and, for two chains, their combining, as rtw88's
//! `Limits` does for an RTL8822C ([`Cap::eirp`]). [`Cap::NONE`] is
//! rtw89's SAR-less bound exactly.
//!
//! What this leaves out, and why:
//! - the driver's compiled `rtw89_8852b_dflt_parms` tables, which rtw89
//!   keeps for a firmware lacking a table: such firmware is refused
//!   ([`Error::Missing`]) rather than carried with tables Stela does not
//!   have. The pinned image has RFE 0 tables for every slot;
//! - the DA tables and antenna gain (`rtw89_can_apply_ant_gain`), which
//!   need ACPI's antenna gain policy: without it `regd_enabled` is 0, so
//!   rtw89 reads no DA limit and adds no offset;
//! - SAR and TAS (`rtw89_query_sar`), whose sources are ACPI or the
//!   nl80211 SAR API; the [`Cap`] stands where they would;
//! - 6 GHz and 160 MHz, which an RTL8852B does not support;
//! - DBCC and PHY 1: an RTL8852B runs SCC on PHY 0.
//!
//! Writing the pages proves the registers took them, not what the radio
//! sends: that is TSSI's and DPK's (3.8) and the air's.
use super::{
    elements::{RfeData, TxpwrConf, TxpwrSlot},
    io::{Error as IoError, Registers},
    regd::Regulation,
    registers::{
        CMAC1_END_ADDR, CMAC1_START_ADDR, PWR_BY_RATE, PWR_LMT, PWR_RATE_CTRL, PWR_RATE_OFST_CTRL,
        PWR_RU_LMT,
    },
};
use crate::wifi::regulatory::database::Country;
use alloc::vec::Vec;

/// `enum rtw89_band`, the bands an RTL8852B has.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Band {
    Ghz2 = 0,
    Ghz5 = 1,
}

/// `RTW89_BAND_NUM`: 2.4, 5 and 6 GHz.
pub const BAND_NUM: usize = 3;

/// `enum rtw89_bandwidth`, the widths an RTL8852B supports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Width {
    Mhz20 = 0,
    Mhz40 = 1,
    Mhz80 = 2,
}

/// `RTW89_BYR_BW_NUM`.
pub const BYR_BW_NUM: usize = 5;
/// `RTW89_2G_BW_NUM`, `RTW89_5G_BW_NUM`.
pub const BW_NUM_2G: usize = 2;
pub const BW_NUM_5G: usize = 4;
/// `RTW89_2G_CH_NUM`, `RTW89_5G_CH_NUM`.
pub const CH_NUM_2G: usize = 14;
pub const CH_NUM_5G: usize = 53;
/// `RTW89_NTX_NUM`, `RTW89_BF_NUM`, `RTW89_OFDMA_NUM`.
pub const NTX_NUM: usize = 2;
pub const BF_NUM: usize = 2;
pub const OFDMA_NUM: usize = 2;
/// `RTW89_NSS_NUM`, `RTW89_NSS_HEDCM_NUM`.
pub const NSS_NUM: usize = 4;
pub const NSS_HEDCM_NUM: usize = 2;
/// `RTW89_RU_NUM`, `RTW89_REGD_NUM`, `NUM_OF_RTW89_REG_6GHZ_POWER`.
pub const RU_NUM: usize = 8;
pub const REGD_NUM: usize = 16;
pub const REG_6GHZ_POWER_NUM: usize = 3;

/// `enum rtw89_rate_section`.
pub const RS_CCK: u8 = 0;
pub const RS_OFDM: u8 = 1;
pub const RS_MCS: u8 = 2;
pub const RS_HEDCM: u8 = 3;
pub const RS_OFFSET: u8 = 4;
/// `RTW89_RS_LMT_NUM`, `RTW89_RS_TX_SHAPE_NUM`.
pub const RS_LMT_NUM: usize = 3;
pub const RS_TX_SHAPE_NUM: usize = 2;

/// `enum rtw89_rate_num` and the offsets' count.
pub const RATE_CCK_NUM: usize = 4;
pub const RATE_OFDM_NUM: usize = 8;
pub const RATE_HEDCM_NUM: usize = 4;
pub const RATE_MCS_NUM: usize = 16;
pub const RATE_OFFSET_NUM: usize = 8;
/// `RTW89_RATE_OFFSET_NUM_AX`.
pub const RATE_OFFSET_NUM_AX: u8 = 5;

/// `enum rtw89_ru_bandwidth`, the RUs the AX pages hold.
pub const RU26: u8 = 0;
pub const RU52: u8 = 1;
pub const RU106: u8 = 2;

/// `rtw8852b_chip_info.rf_path_num`: the NSS and NTX the pages cover.
pub const RF_PATH_NUM: u8 = 2;
/// `RTW89_TXPWR_LMT_PAGE_SIZE_AX`, `RTW89_TXPWR_LMT_RU_PAGE_SIZE_AX`.
pub const LMT_PAGE_SIZE: usize = 40;
pub const LMT_RU_PAGE_SIZE: usize = 24;
/// `RTW89_SAR_TXPWR_MAC_MAX`: what `rtw89_query_sar` gives without a SAR
/// source.
pub const SAR_TXPWR_MAC_MAX: i8 = 63;

/// `rtw89_rs_idx_num_ax` and `rtw89_rs_nss_num_ax`, by rate section.
const RS_IDX_NUM_AX: [u8; 5] = [4, 8, 12, 4, 5];
const RS_NSS_NUM_AX: [u8; 5] = [1, 1, NSS_NUM as u8, NSS_HEDCM_NUM as u8, 1];

/// Why the tables or a page could not be made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A table the board's RFE type and RFE 0 both lack in the firmware,
    /// where rtw89 would fall back to its compiled tables.
    Missing(TxpwrSlot),
    /// The tables' memory could not be allocated.
    NoMemory,
    /// A channel geometry an RTL8852B does not tune.
    Channel,
    Io(IoError),
}

impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}

/// `ieee80211_channel_to_frequency` for the bands an RTL8852B has.
pub const fn channel_freq_mhz(band: Band, channel: u8) -> u32 {
    let channel = channel as u32;
    match band {
        Band::Ghz2 if channel == 14 => 2484,
        Band::Ghz2 => 2407 + channel * 5,
        Band::Ghz5 => 5000 + channel * 5,
    }
}

/// Whether a 20 MHz channel is one of `rtw89_channels_2ghz` or
/// `rtw89_channels_5ghz`.
fn valid_20(band: Band, channel: u8) -> bool {
    match band {
        Band::Ghz2 => (1..=14).contains(&channel),
        Band::Ghz5 => {
            matches!(channel, 36..=64 | 100..=144) && channel.is_multiple_of(4)
                || matches!(channel, 149..=177) && channel % 4 == 1
        }
    }
}

/// The fields of `struct rtw89_chan` the TX power steps read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chan {
    pub band: Band,
    /// `channel`: the center channel.
    pub channel: u8,
    /// `primary_channel`.
    pub primary: u8,
    /// `band_width`.
    pub width: Width,
}

impl Chan {
    /// A channel of `width` centered on `channel`, its primary 20 MHz
    /// channel `primary`, refused unless every 20 MHz channel it spans is
    /// one rtw89 registers and the primary is one of them.
    pub fn new(band: Band, channel: u8, primary: u8, width: Width) -> Result<Self, Error> {
        let chan = Self {
            band,
            channel,
            primary,
            width,
        };
        let half = match width {
            Width::Mhz20 => 0,
            Width::Mhz40 => 2,
            Width::Mhz80 => 6,
        };
        // A 2.4 GHz 40 MHz channel spans two of channels 1 to 13; channel
        // 14 is 12 MHz from 13 and pairs with none.
        if band == Band::Ghz2 && width == Width::Mhz80
            || band == Band::Ghz2 && width == Width::Mhz40 && !(3..=11).contains(&channel)
            || channel < half
            || !chan.subchannels().all(|sub| valid_20(band, sub))
            || !chan.subchannels().any(|sub| sub == primary)
        {
            return Err(Error::Channel);
        }
        // Each 40 and 80 MHz block of 5 GHz starts where the band plan
        // does: 36, 100 and 149 begin one.
        if band == Band::Ghz5 && width != Width::Mhz20 {
            let first = channel - half;
            let span = 4 * (half / 2 + 1);
            let base = if first >= 149 {
                149
            } else if first >= 100 {
                100
            } else {
                36
            };
            if !(first - base).is_multiple_of(span) {
                return Err(Error::Channel);
            }
        }
        Ok(chan)
    }

    /// The 20 MHz channels the channel spans, lowest first.
    pub fn subchannels(&self) -> impl Iterator<Item = u8> {
        let (half, count) = match self.width {
            Width::Mhz20 => (0, 1),
            Width::Mhz40 => (2, 2),
            Width::Mhz80 => (6, 4),
        };
        let first = self.channel.wrapping_sub(half);
        (0..count).map(move |index| first.wrapping_add(4 * index))
    }

    /// The center frequency, `chan->freq` for the center channel.
    pub fn freq_mhz(&self) -> u32 {
        channel_freq_mhz(self.band, self.channel)
    }

    /// The width in MHz.
    pub fn width_mhz(&self) -> u32 {
        20 << (self.width as u32)
    }
}

/// `struct rtw89_rate_desc`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateDesc {
    pub nss: u8,
    pub rs: u8,
    pub ofdma: u8,
    pub idx: u8,
}

/// `struct rtw89_txpwr_byrate`, in RF units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Byrate {
    pub cck: [i8; RATE_CCK_NUM],
    pub ofdm: [i8; RATE_OFDM_NUM],
    pub mcs: [[[i8; RATE_MCS_NUM]; NSS_NUM]; OFDMA_NUM],
    pub hedcm: [[[i8; RATE_HEDCM_NUM]; NSS_HEDCM_NUM]; OFDMA_NUM],
    pub offset: [i8; RATE_OFFSET_NUM],
    /// Where `rtw89_phy_raw_byr_seek` points an unknown section.
    pub trap: i8,
}

impl Byrate {
    /// `sizeof(struct rtw89_txpwr_byrate)`.
    pub const SIZE: usize = 165;
    const ZERO: Self = Self {
        cck: [0; RATE_CCK_NUM],
        ofdm: [0; RATE_OFDM_NUM],
        mcs: [[[0; RATE_MCS_NUM]; NSS_NUM]; OFDMA_NUM],
        hedcm: [[[0; RATE_HEDCM_NUM]; NSS_HEDCM_NUM]; OFDMA_NUM],
        offset: [0; RATE_OFFSET_NUM],
        trap: 0,
    };

    /// `rtw89_phy_raw_byr_seek`; the trap for anything it cannot name.
    fn seek(&self, desc: &RateDesc) -> i8 {
        let (idx, nss, ofdma) = (
            usize::from(desc.idx),
            usize::from(desc.nss),
            usize::from(desc.ofdma),
        );
        let slot = match desc.rs {
            RS_CCK => self.cck.get(idx),
            RS_OFDM => self.ofdm.get(idx),
            RS_MCS => self
                .mcs
                .get(ofdma)
                .and_then(|m| m.get(nss))
                .and_then(|m| m.get(idx)),
            RS_HEDCM => self
                .hedcm
                .get(ofdma)
                .and_then(|m| m.get(nss))
                .and_then(|m| m.get(idx)),
            RS_OFFSET => self.offset.get(idx),
            _ => None,
        };
        *slot.unwrap_or(&self.trap)
    }

    /// [`Byrate::seek`]'s slot, to write.
    fn seek_mut(&mut self, desc: &RateDesc) -> &mut i8 {
        let (idx, nss, ofdma) = (
            usize::from(desc.idx),
            usize::from(desc.nss),
            usize::from(desc.ofdma),
        );
        let slot = match desc.rs {
            RS_CCK => self.cck.get_mut(idx),
            RS_OFDM => self.ofdm.get_mut(idx),
            RS_MCS => self
                .mcs
                .get_mut(ofdma)
                .and_then(|m| m.get_mut(nss))
                .and_then(|m| m.get_mut(idx)),
            RS_HEDCM => self
                .hedcm
                .get_mut(ofdma)
                .and_then(|m| m.get_mut(nss))
                .and_then(|m| m.get_mut(idx)),
            RS_OFFSET => self.offset.get_mut(idx),
            _ => None,
        };
        match slot {
            Some(slot) => slot,
            None => &mut self.trap,
        }
    }

    /// The struct's bytes, in its member order.
    pub fn bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0; Self::SIZE];
        let all = self
            .cck
            .iter()
            .chain(&self.ofdm)
            .chain(self.mcs.iter().flatten().flatten())
            .chain(self.hedcm.iter().flatten().flatten())
            .chain(&self.offset)
            .chain(core::iter::once(&self.trap));
        for (byte, &value) in out.iter_mut().zip(all) {
            *byte = value as u8;
        }
        out
    }
}

/// `rtw89_phy_txpwr_rf_to_mac`.
const fn rf_to_mac(txpwr_rf: i8) -> i8 {
    txpwr_rf >> 1
}

/// `rtw89_phy_txpwr_dbm_to_mac`.
const fn dbm_to_mac(dbm: i8) -> i8 {
    let mac = (dbm as i16) << 1;
    if mac < -64 {
        -64
    } else if mac > 63 {
        63
    } else {
        mac as i8
    }
}

/// `rtw89_phy_get_tpe_constraint` off 6 GHz: no constraint.
const TPE_CONSTRAINT: i8 = dbm_to_mac(i8::MAX);

/// A zeroed table of `n` entries, or [`Error::NoMemory`].
fn zeroed<T: Copy>(n: usize, zero: T) -> Result<Vec<T>, Error> {
    let mut table = Vec::new();
    table.try_reserve_exact(n).map_err(|_| Error::NoMemory)?;
    table.resize(n, zero);
    Ok(table)
}

/// `__fw_txpwr_entry_acceptable`: an entry longer than rtw89's struct only
/// when the excess is zero.
fn acceptable(entry: &[u8], size: usize) -> bool {
    entry
        .get(size..)
        .is_none_or(|excess| excess.iter().all(|&b| b == 0))
}

/// `rtw89_txpwr_entcpy` over a zeroed entry: as many bytes as both hold.
fn entcpy<const N: usize>(entry: &[u8]) -> [u8; N] {
    let mut copy = [0; N];
    let n = N.min(entry.len());
    copy[..n].copy_from_slice(&entry[..n]);
    copy
}

/// The entries of a conf `fw_*_entry_valid` would see: acceptable ones,
/// copied to the struct's size.
fn entries<'a, const N: usize>(conf: &TxpwrConf<'a>) -> impl Iterator<Item = [u8; N]> + 'a {
    conf.entries()
        .filter(|entry| acceptable(entry, N))
        .map(entcpy::<N>)
}

/// The TX power tables `rtw89_load_rfe_data_from_fw` leaves in
/// `rtwdev->byr` and the `struct rtw89_rfe_data` arrays an RTL8852B reads,
/// in rtw89's index order and units.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tables {
    /// `byr[band][bw]`.
    byr: Vec<Byrate>,
    /// `lmt_2ghz.v[bw][ntx][rs][bf][regd][ch_idx]`.
    lmt_2ghz: Vec<i8>,
    /// `lmt_5ghz.v[bw][ntx][rs][bf][regd][ch_idx]`.
    lmt_5ghz: Vec<i8>,
    /// `lmt_ru_2ghz.v[ru][ntx][regd][ch_idx]`.
    lmt_ru_2ghz: Vec<i8>,
    /// `lmt_ru_5ghz.v[ru][ntx][regd][ch_idx]`.
    lmt_ru_5ghz: Vec<i8>,
    /// `tx_shape_lmt.v[band][rs][regd][reg6]`.
    tx_shape_lmt: Vec<u8>,
    /// `tx_shape_lmt_ru.v[band][regd][reg6]`.
    tx_shape_lmt_ru: Vec<u8>,
}

/// Where in `lmt_*ghz.v` a limit is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitAt {
    pub bw: u8,
    pub ntx: u8,
    pub rs: u8,
    pub bf: u8,
    pub regd: u8,
    pub ch_idx: u8,
}

/// The index of `lmt_*ghz.v[bw][ntx][rs][bf][regd][ch_idx]`.
const fn lmt_index(
    ch_num: usize,
    bw: usize,
    ntx: usize,
    rs: usize,
    bf: usize,
    regd: usize,
    ch: usize,
) -> usize {
    ((((bw * NTX_NUM + ntx) * RS_LMT_NUM + rs) * BF_NUM + bf) * REGD_NUM + regd) * ch_num + ch
}

/// The index of `lmt_ru_*ghz.v[ru][ntx][regd][ch_idx]`.
const fn lmt_ru_index(ch_num: usize, ru: usize, ntx: usize, regd: usize, ch: usize) -> usize {
    ((ru * NTX_NUM + ntx) * REGD_NUM + regd) * ch_num + ch
}

impl Tables {
    /// The tables of the confs [`super::elements`] chose:
    /// `rtw89_load_rfe_data_from_fw` over an RTL8852B's slots, then
    /// `rtw89_load_txpwr_table` for the by-rate table.
    pub fn load(rfe: Option<&RfeData<'_>>) -> Result<Self, Error> {
        let conf = |slot| {
            rfe.and_then(|rfe| rfe.conf(slot))
                .ok_or(Error::Missing(slot))
        };
        let byrate = conf(TxpwrSlot::Byrate)?;
        let lmt_2ghz = conf(TxpwrSlot::Lmt2ghz)?;
        let lmt_5ghz = conf(TxpwrSlot::Lmt5ghz)?;
        let lmt_ru_2ghz = conf(TxpwrSlot::LmtRu2ghz)?;
        let lmt_ru_5ghz = conf(TxpwrSlot::LmtRu5ghz)?;
        let tx_shape_lmt = conf(TxpwrSlot::TxShapeLmt)?;
        let tx_shape_lmt_ru = conf(TxpwrSlot::TxShapeLmtRu)?;
        let mut tables = Self {
            byr: zeroed(BAND_NUM * BYR_BW_NUM, Byrate::ZERO)?,
            lmt_2ghz: zeroed(
                BW_NUM_2G * NTX_NUM * RS_LMT_NUM * BF_NUM * REGD_NUM * CH_NUM_2G,
                0,
            )?,
            lmt_5ghz: zeroed(
                BW_NUM_5G * NTX_NUM * RS_LMT_NUM * BF_NUM * REGD_NUM * CH_NUM_5G,
                0,
            )?,
            lmt_ru_2ghz: zeroed(RU_NUM * NTX_NUM * REGD_NUM * CH_NUM_2G, 0)?,
            lmt_ru_5ghz: zeroed(RU_NUM * NTX_NUM * REGD_NUM * CH_NUM_5G, 0)?,
            tx_shape_lmt: zeroed(
                BAND_NUM * RS_TX_SHAPE_NUM * REGD_NUM * REG_6GHZ_POWER_NUM,
                0,
            )?,
            tx_shape_lmt_ru: zeroed(BAND_NUM * REGD_NUM * REG_6GHZ_POWER_NUM, 0)?,
        };
        tables.load_lmt(lmt_2ghz, BW_NUM_2G, CH_NUM_2G, false);
        tables.load_lmt(lmt_5ghz, BW_NUM_5G, CH_NUM_5G, true);
        tables.load_lmt_ru(lmt_ru_2ghz, CH_NUM_2G, false);
        tables.load_lmt_ru(lmt_ru_5ghz, CH_NUM_5G, true);
        tables.load_tx_shape_lmt(tx_shape_lmt);
        tables.load_tx_shape_lmt_ru(tx_shape_lmt_ru);
        tables.load_byrate(byrate);
        Ok(tables)
    }

    /// `rtw89_fw_load_txpwr_byrate` with `fw_txpwr_byrate_entry_valid`.
    fn load_byrate(&mut self, conf: &TxpwrConf<'_>) {
        for e in entries::<11>(conf) {
            let [band, nss, rs, shf, len, d0, d1, d2, d3, bw, ofdma] = e;
            let end = u32::from(shf) + u32::from(len);
            let fits = match rs {
                RS_CCK => end <= RATE_CCK_NUM as u32,
                RS_OFDM => end <= RATE_OFDM_NUM as u32,
                RS_MCS => {
                    end <= RATE_MCS_NUM as u32
                        && usize::from(nss) < NSS_NUM
                        && usize::from(ofdma) < OFDMA_NUM
                }
                RS_HEDCM => {
                    end <= RATE_HEDCM_NUM as u32
                        && usize::from(nss) < NSS_HEDCM_NUM
                        && usize::from(ofdma) < OFDMA_NUM
                }
                RS_OFFSET => end <= RATE_OFFSET_NUM as u32,
                _ => false,
            };
            if usize::from(band) >= BAND_NUM || usize::from(bw) >= BYR_BW_NUM || !fits {
                continue;
            }
            let head = &mut self.byr[usize::from(band) * BYR_BW_NUM + usize::from(bw)];
            let mut data = u32::from_le_bytes([d0, d1, d2, d3]);
            for i in 0..len {
                let desc = RateDesc {
                    nss,
                    rs,
                    ofdma,
                    idx: shf + i,
                };
                *head.seek_mut(&desc) = data as u8 as i8;
                data >>= 8;
            }
        }
    }

    /// `rtw89_fw_load_txpwr_lmt_2ghz` and `_5ghz` with their checks.
    fn load_lmt(&mut self, conf: &TxpwrConf<'_>, bw_num: usize, ch_num: usize, five: bool) {
        let table = if five {
            &mut self.lmt_5ghz
        } else {
            &mut self.lmt_2ghz
        };
        for [bw, nt, rs, bf, regd, ch_idx, v] in entries::<7>(conf) {
            let (bw, nt, rs, bf, regd, ch) = (
                usize::from(bw),
                usize::from(nt),
                usize::from(rs),
                usize::from(bf),
                usize::from(regd),
                usize::from(ch_idx),
            );
            if bw >= bw_num
                || nt >= NTX_NUM
                || rs >= RS_LMT_NUM
                || bf >= BF_NUM
                || regd >= REGD_NUM
                || ch >= ch_num
            {
                continue;
            }
            table[lmt_index(ch_num, bw, nt, rs, bf, regd, ch)] = v as i8;
        }
    }

    /// `rtw89_fw_load_txpwr_lmt_ru_2ghz` and `_5ghz` with their checks.
    fn load_lmt_ru(&mut self, conf: &TxpwrConf<'_>, ch_num: usize, five: bool) {
        let table = if five {
            &mut self.lmt_ru_5ghz
        } else {
            &mut self.lmt_ru_2ghz
        };
        for [ru, nt, regd, ch_idx, v] in entries::<5>(conf) {
            let (ru, nt, regd, ch) = (
                usize::from(ru),
                usize::from(nt),
                usize::from(regd),
                usize::from(ch_idx),
            );
            if ru >= RU_NUM || nt >= NTX_NUM || regd >= REGD_NUM || ch >= ch_num {
                continue;
            }
            table[lmt_ru_index(ch_num, ru, nt, regd, ch)] = v as i8;
        }
    }

    /// `rtw89_fw_load_tx_shape_lmt` with `fw_tx_shape_lmt_entry_valid`.
    fn load_tx_shape_lmt(&mut self, conf: &TxpwrConf<'_>) {
        for [band, rs, regd, v, reg6] in entries::<5>(conf) {
            let (band, rs, regd, reg6) = (
                usize::from(band),
                usize::from(rs),
                usize::from(regd),
                usize::from(reg6),
            );
            if band >= BAND_NUM
                || rs >= RS_TX_SHAPE_NUM
                || regd >= REGD_NUM
                || reg6 >= REG_6GHZ_POWER_NUM
            {
                continue;
            }
            self.tx_shape_lmt
                [((band * RS_TX_SHAPE_NUM + rs) * REGD_NUM + regd) * REG_6GHZ_POWER_NUM + reg6] = v;
        }
    }

    /// `rtw89_fw_load_tx_shape_lmt_ru` with `fw_tx_shape_lmt_ru_entry_valid`.
    fn load_tx_shape_lmt_ru(&mut self, conf: &TxpwrConf<'_>) {
        for [band, regd, v, reg6] in entries::<4>(conf) {
            let (band, regd, reg6) = (usize::from(band), usize::from(regd), usize::from(reg6));
            if band >= BAND_NUM || regd >= REGD_NUM || reg6 >= REG_6GHZ_POWER_NUM {
                continue;
            }
            self.tx_shape_lmt_ru[(band * REGD_NUM + regd) * REG_6GHZ_POWER_NUM + reg6] = v;
        }
    }

    /// `byr[band][bw]`.
    pub fn byr(&self, band: usize, bw: usize) -> Option<&Byrate> {
        if bw >= BYR_BW_NUM {
            return None;
        }
        self.byr.get(band * BYR_BW_NUM + bw)
    }

    /// `lmt_2ghz.v` or `lmt_5ghz.v` at the indices, in RF units.
    pub fn lmt(&self, band: Band, at: LimitAt) -> i8 {
        let (table, ch_num) = match band {
            Band::Ghz2 => (&self.lmt_2ghz, CH_NUM_2G),
            Band::Ghz5 => (&self.lmt_5ghz, CH_NUM_5G),
        };
        let index = lmt_index(
            ch_num,
            usize::from(at.bw),
            usize::from(at.ntx),
            usize::from(at.rs),
            usize::from(at.bf),
            usize::from(at.regd),
            usize::from(at.ch_idx),
        );
        table.get(index).copied().unwrap_or(0)
    }

    /// `lmt_ru_2ghz.v` or `lmt_ru_5ghz.v` at the indices, in RF units.
    pub fn lmt_ru(&self, band: Band, ru: u8, ntx: u8, regd: u8, ch_idx: u8) -> i8 {
        let (table, ch_num) = match band {
            Band::Ghz2 => (&self.lmt_ru_2ghz, CH_NUM_2G),
            Band::Ghz5 => (&self.lmt_ru_5ghz, CH_NUM_5G),
        };
        let index = lmt_ru_index(
            ch_num,
            usize::from(ru),
            usize::from(ntx),
            usize::from(regd),
            usize::from(ch_idx),
        );
        table.get(index).copied().unwrap_or(0)
    }

    /// The tables' bytes in rtw89's layout: `byr`, `lmt_2ghz.v`,
    /// `lmt_5ghz.v`, `lmt_ru_2ghz.v`, `lmt_ru_5ghz.v`, `tx_shape_lmt.v` and
    /// `tx_shape_lmt_ru.v`, each as C lays out its array.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for byr in &self.byr {
            out.extend_from_slice(&byr.bytes());
        }
        for table in [
            &self.lmt_2ghz,
            &self.lmt_5ghz,
            &self.lmt_ru_2ghz,
            &self.lmt_ru_5ghz,
        ] {
            out.extend(table.iter().map(|&v| v as u8));
        }
        out.extend_from_slice(&self.tx_shape_lmt);
        out.extend_from_slice(&self.tx_shape_lmt_ru);
        out
    }
}

/// Stela's bound on each limit from regulatory.db, by NTX, in MAC units:
/// what stands where rtw89's SAR query does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cap {
    pub mac: [i8; NTX_NUM],
}

/// cfg80211's `DBI_TO_MBI(6)`: the antenna gain regulatory.db's EIRP is
/// read under, as rtw88's `Limits` reads it.
pub const ANTENNA_MBM: i32 = 600;
/// Two chains sending one frame: 3.01 dB.
pub const COMBINING_MBM: i32 = 301;

impl Cap {
    /// No bound: `RTW89_SAR_TXPWR_MAC_MAX`, rtw89's own without SAR.
    pub const NONE: Self = Self {
        mac: [SAR_TXPWR_MAC_MAX; NTX_NUM],
    };

    /// The bound an EIRP of `max_eirp_mbm` gives: per chain, the EIRP less
    /// [`ANTENNA_MBM`], and less [`COMBINING_MBM`] for the 2TX page, floored
    /// to 1/2 dB so it never rounds above the EIRP, and clamped as
    /// `rtw89_phy_txpwr_dbm_to_mac` clamps.
    pub fn eirp(max_eirp_mbm: i32) -> Self {
        let bound = |less: i32| {
            max_eirp_mbm
                .saturating_sub(less)
                .div_euclid(50)
                .clamp(-64, i32::from(SAR_TXPWR_MAC_MAX)) as i8
        };
        Self {
            mac: [bound(ANTENNA_MBM), bound(ANTENNA_MBM + COMBINING_MBM)],
        }
    }

    /// The bound for `chan` in `country`: [`Cap::eirp`] of the rule
    /// holding the channel's whole width (`freq_reg_info`'s choice), or
    /// `None` when no rule holds it, where nothing may be sent.
    pub fn country(country: &Country, chan: &Chan) -> Option<Self> {
        let rule = country.rule(chan.freq_mhz() * 1000, chan.width_mhz() * 1000)?;
        Some(Self::eirp(i32::from(rule.max_eirp_mbm)))
    }
}

/// rtw89's TX power reads for one regulation and cap.
#[derive(Clone, Copy, Debug)]
pub struct Power<'a> {
    pub tables: &'a Tables,
    pub regulation: &'a Regulation,
    pub cap: Cap,
}

/// `rtw89_channel_to_idx` off 6 GHz; 0 for an unknown channel, as rtw89
/// warns and gives.
fn channel_to_idx(channel: u8) -> u8 {
    match channel {
        1..=14 => channel - 1,
        36..=64 => (channel - 36) / 2,
        100..=144 => (channel - 100) / 2 + 15,
        149..=177 => (channel - 149) / 2 + 38,
        _ => 0,
    }
}

impl Power<'_> {
    /// `rtw89_phy_read_txpwr_byrate`, in MAC units.
    pub fn read_byrate(&self, band: Band, bw: u8, desc: &RateDesc) -> i8 {
        let band = if desc.rs == RS_CCK { Band::Ghz2 } else { band };
        let byrate = self
            .tables
            .byr(band as usize, usize::from(bw))
            .map_or(0, |head| head.seek(desc));
        rf_to_mac(byrate)
    }

    /// `rtw89_phy_read_txpwr_limit`, in MAC units: the regulation's limit,
    /// the worldwide one where the table has none, bounded by the [`Cap`]
    /// where rtw89 bounds it by SAR, and by the TPE constraint.
    pub fn read_limit(&self, band: Band, bw: u8, ntx: u8, rs: u8, bf: u8, ch: u8) -> i8 {
        let bw_num = match band {
            Band::Ghz2 => BW_NUM_2G,
            Band::Ghz5 => BW_NUM_5G,
        };
        if usize::from(bw) >= bw_num {
            return 0;
        }
        let at = LimitAt {
            bw,
            ntx,
            rs,
            bf,
            regd: self.regulation.txpwr_regd(band),
            ch_idx: channel_to_idx(ch),
        };
        let mut lmt = self.tables.lmt(band, at);
        if lmt == 0 {
            let ww = LimitAt {
                regd: super::regd::WW,
                ..at
            };
            lmt = self.tables.lmt(band, ww);
        }
        // No DA limit without antenna gain: min(lmt + 0, S8_MAX).
        let lmt = rf_to_mac(lmt);
        lmt.min(self.sar(ntx)).min(TPE_CONSTRAINT)
    }

    /// `rtw89_phy_read_txpwr_limit_ru`, in MAC units, bounded as
    /// [`Power::read_limit`] is.
    pub fn read_limit_ru(&self, band: Band, ru: u8, ntx: u8, ch: u8) -> i8 {
        let ch_idx = channel_to_idx(ch);
        let regd = self.regulation.txpwr_regd(band);
        let mut lmt_ru = self.tables.lmt_ru(band, ru, ntx, regd, ch_idx);
        if lmt_ru == 0 {
            lmt_ru = self.tables.lmt_ru(band, ru, ntx, super::regd::WW, ch_idx);
        }
        rf_to_mac(lmt_ru).min(self.sar(ntx)).min(TPE_CONSTRAINT)
    }

    /// What stands where `rtw89_query_sar` does: the cap of the NTX.
    fn sar(&self, ntx: u8) -> i8 {
        self.cap
            .mac
            .get(usize::from(ntx))
            .copied()
            .unwrap_or(SAR_TXPWR_MAC_MAX)
    }

    /// `__fill_txpwr_limit_nonbf_bf`.
    fn nonbf_bf(&self, band: Band, bw: Width, ntx: u8, rs: u8, ch: u8) -> [i8; BF_NUM] {
        [0, 1].map(|bf| self.read_limit(band, bw as u8, ntx, rs, bf, ch))
    }

    /// `rtw89_phy_fill_txpwr_limit_ax`: `struct rtw89_txpwr_limit_ax`'s
    /// bytes for `chan` at `ntx`.
    pub fn fill_limit(&self, chan: &Chan, ntx: u8) -> [i8; LMT_PAGE_SIZE] {
        // cck_20m 0, cck_40m 2, ofdm 4, mcs_20m[8] 6, mcs_40m[4] 22,
        // mcs_80m[2] 30, mcs_160m 34, mcs_40m_0p5 36, mcs_40m_2p5 38.
        let mut lmt = [0; LMT_PAGE_SIZE];
        let mut put = |at: usize, pair: [i8; BF_NUM]| lmt[at..at + BF_NUM].copy_from_slice(&pair);
        let (band, ch, pri) = (chan.band, chan.channel, chan.primary);
        let (w20, w40, w80) = (Width::Mhz20, Width::Mhz40, Width::Mhz80);
        match chan.width {
            Width::Mhz20 => {
                put(0, self.nonbf_bf(band, w20, ntx, RS_CCK, ch));
                put(2, self.nonbf_bf(band, w40, ntx, RS_CCK, ch));
                put(4, self.nonbf_bf(band, w20, ntx, RS_OFDM, ch));
                put(6, self.nonbf_bf(band, w20, ntx, RS_MCS, ch));
            }
            Width::Mhz40 => {
                put(0, self.nonbf_bf(band, w20, ntx, RS_CCK, ch.wrapping_sub(2)));
                put(2, self.nonbf_bf(band, w40, ntx, RS_CCK, ch));
                put(4, self.nonbf_bf(band, w20, ntx, RS_OFDM, pri));
                put(6, self.nonbf_bf(band, w20, ntx, RS_MCS, ch.wrapping_sub(2)));
                put(8, self.nonbf_bf(band, w20, ntx, RS_MCS, ch.wrapping_add(2)));
                put(22, self.nonbf_bf(band, w40, ntx, RS_MCS, ch));
            }
            Width::Mhz80 => {
                put(4, self.nonbf_bf(band, w20, ntx, RS_OFDM, pri));
                put(6, self.nonbf_bf(band, w20, ntx, RS_MCS, ch.wrapping_sub(6)));
                put(8, self.nonbf_bf(band, w20, ntx, RS_MCS, ch.wrapping_sub(2)));
                put(
                    10,
                    self.nonbf_bf(band, w20, ntx, RS_MCS, ch.wrapping_add(2)),
                );
                put(
                    12,
                    self.nonbf_bf(band, w20, ntx, RS_MCS, ch.wrapping_add(6)),
                );
                put(
                    22,
                    self.nonbf_bf(band, w40, ntx, RS_MCS, ch.wrapping_sub(4)),
                );
                put(
                    24,
                    self.nonbf_bf(band, w40, ntx, RS_MCS, ch.wrapping_add(4)),
                );
                put(30, self.nonbf_bf(band, w80, ntx, RS_MCS, ch));
                let n = self.nonbf_bf(band, w40, ntx, RS_MCS, ch.wrapping_sub(4));
                let p = self.nonbf_bf(band, w40, ntx, RS_MCS, ch.wrapping_add(4));
                put(36, [n[0].min(p[0]), n[1].min(p[1])]);
            }
        }
        lmt
    }

    /// `rtw89_phy_fill_txpwr_limit_ru_ax`: `struct rtw89_txpwr_limit_ru_ax`'s
    /// bytes (ru26[8], ru52[8], ru106[8]) for `chan` at `ntx`.
    pub fn fill_limit_ru(&self, chan: &Chan, ntx: u8) -> [i8; LMT_RU_PAGE_SIZE] {
        let mut lmt_ru = [0; LMT_RU_PAGE_SIZE];
        let ch = chan.channel;
        let subchannels: &[u8] = match chan.width {
            Width::Mhz20 => &[ch],
            Width::Mhz40 => &[ch.wrapping_sub(2), ch.wrapping_add(2)],
            Width::Mhz80 => &[
                ch.wrapping_sub(6),
                ch.wrapping_sub(2),
                ch.wrapping_add(2),
                ch.wrapping_add(6),
            ],
        };
        for (section, ru) in [RU26, RU52, RU106].into_iter().enumerate() {
            for (index, &sub) in subchannels.iter().enumerate() {
                lmt_ru[section * 8 + index] = self.read_limit_ru(chan.band, ru, ntx, sub);
            }
        }
        lmt_ru
    }

    /// `rtw89_get_tx_shape_idx` with firmware TX shape tables, off 6 GHz.
    pub fn tx_shape_idx(&self, band: Band, rs: u8) -> u8 {
        let rs = if usize::from(rs) >= RS_TX_SHAPE_NUM {
            RS_OFDM
        } else {
            rs
        };
        let regd = usize::from(self.regulation.txpwr_regd(band));
        let index = ((band as usize * RS_TX_SHAPE_NUM + usize::from(rs)) * REGD_NUM + regd)
            * REG_6GHZ_POWER_NUM;
        self.tables.tx_shape_lmt.get(index).copied().unwrap_or(0)
    }
}

/// `rtw89_mac_get_txpwr_cr_ax` at PHY 0 of an SCC chip: the register, or
/// `None` where rtw89 logs and refuses it.
fn txpwr_cr(register: u32) -> Option<u32> {
    let cmac1 = CMAC1_START_ADDR..=CMAC1_END_ADDR;
    ((PWR_RATE_CTRL..=CMAC1_END_ADDR).contains(&register) && !cmac1.contains(&register))
        .then_some(register)
}

/// `rtw89_mac_txpwr_write32` at PHY 0; a refused register is skipped, as
/// rtw89's callers ignore its `-EINVAL`.
pub fn mac_txpwr_write32<I: Registers + ?Sized>(
    io: &mut I,
    register: u32,
    value: u32,
) -> Result<(), IoError> {
    match txpwr_cr(register) {
        Some(cr) => io.write32(cr, value),
        None => Ok(()),
    }
}

/// `rtw89_mac_txpwr_write32_mask` at PHY 0, refusals skipped likewise.
pub fn mac_txpwr_write32_mask<I: Registers + ?Sized>(
    io: &mut I,
    register: u32,
    mask: u32,
    value: u32,
) -> Result<(), IoError> {
    match txpwr_cr(register) {
        Some(cr) => io.write32_mask(cr, mask, value),
        None => Ok(()),
    }
}

/// Four signed bytes as one little-endian word (`FIELD_PREP` of each).
fn word(bytes: &[i8; 4]) -> u32 {
    u32::from_le_bytes([
        bytes[0] as u8,
        bytes[1] as u8,
        bytes[2] as u8,
        bytes[3] as u8,
    ])
}

/// `rtw89_phy_set_txpwr_byrate_ax`: by NSS, the CCK, OFDM, MCS and HE DCM
/// rates of bandwidth 0, four to a word, from `R_AX_PWR_BY_RATE` up.
pub fn set_byrate<I: Registers + ?Sized>(
    io: &mut I,
    power: &Power<'_>,
    chan: &Chan,
) -> Result<(), IoError> {
    let mut register = PWR_BY_RATE;
    let mut v = [0i8; 4];
    for nss in 0..RF_PATH_NUM {
        for rs in [RS_CCK, RS_OFDM, RS_MCS, RS_HEDCM] {
            if nss >= RS_NSS_NUM_AX[usize::from(rs)] {
                continue;
            }
            for idx in 0..RS_IDX_NUM_AX[usize::from(rs)] {
                let desc = RateDesc {
                    nss,
                    rs,
                    ofdma: 0,
                    idx,
                };
                v[usize::from(idx % 4)] = power.read_byrate(chan.band, 0, &desc);
                if (idx + 1) % 4 != 0 {
                    continue;
                }
                mac_txpwr_write32(io, register, word(&v))?;
                register += 4;
            }
        }
    }
    Ok(())
}

/// `rtw89_phy_set_txpwr_offset_ax`: the HE, VHT, HT, OFDM and CCK offsets,
/// a nibble each, into `R_AX_PWR_RATE_OFST_CTRL`'s low 20 bits.
pub fn set_offset<I: Registers + ?Sized>(
    io: &mut I,
    power: &Power<'_>,
    chan: &Chan,
) -> Result<(), IoError> {
    let mut value = 0;
    for idx in 0..RATE_OFFSET_NUM_AX {
        let desc = RateDesc {
            nss: 0,
            rs: RS_OFFSET,
            ofdma: 0,
            idx,
        };
        let v = power.read_byrate(chan.band, 0, &desc) as u8 as u32;
        value |= (v & 0xf) << (4 * u32::from(idx));
    }
    mac_txpwr_write32_mask(io, PWR_RATE_OFST_CTRL, 0x000f_ffff, value)
}

/// `rtw89_phy_set_txpwr_limit_ax`: per NTX, the limit page as words from
/// `R_AX_PWR_LMT` up.
pub fn set_limit<I: Registers + ?Sized>(
    io: &mut I,
    power: &Power<'_>,
    chan: &Chan,
) -> Result<(), IoError> {
    let mut register = PWR_LMT;
    for ntx in 0..RF_PATH_NUM {
        let lmt = power.fill_limit(chan, ntx);
        for bytes in lmt.as_chunks::<4>().0 {
            mac_txpwr_write32(io, register, word(bytes))?;
            register += 4;
        }
    }
    Ok(())
}

/// `rtw89_phy_set_txpwr_limit_ru_ax`: per NTX, the RU limit page as words
/// from `R_AX_PWR_RU_LMT` up.
pub fn set_limit_ru<I: Registers + ?Sized>(
    io: &mut I,
    power: &Power<'_>,
    chan: &Chan,
) -> Result<(), IoError> {
    let mut register = PWR_RU_LMT;
    for ntx in 0..RF_PATH_NUM {
        let lmt_ru = power.fill_limit_ru(chan, ntx);
        for bytes in lmt_ru.as_chunks::<4>().0 {
            mac_txpwr_write32(io, register, word(bytes))?;
            register += 4;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
