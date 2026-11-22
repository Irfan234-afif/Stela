// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
// Copyright(c) 2020-2022 Realtek Corporation
// Copyright(c) 2024 Realtek Corporation
//! An RTL8852B tuned to one 2.4 or 5 GHz channel at 20, 40 or 80 MHz on band
//! 0 and PHY 0, as pinned rtw89's `__rtw89_set_channel` (core.c) tunes it
//! for `conf.chans[0]` on an AX chip, which takes no second band:
//!
//! 1. `rtw89_chip_set_channel_prepare`, RTL8852B's `rtw8852b_set_channel_help`
//!    entered (rtw8852b.c), as [`enter`]: the scheduler's TX stopped with
//!    `RTW89_SCH_TX_SEL_ALL`, CMAC0's PPDU status off
//!    (`rtw89_mac_cfg_ppdu_status_ax`, mac.c), both paths' TSSI tracking held
//!    (`rtw8852b_tssi_cont_en_phyidx`), the ADC FIFO in reset, then 40 us and
//!    the BB held in reset (`rtw8852b_bb_reset_en`);
//! 2. `chip->ops->set_channel`, `rtw8852b_set_channel`, as [`set_channel`]:
//!    `__rtw8852bx_set_channel_mac` (rtw8852b_common.c, the RF mode, TX
//!    subcarriers and band checks), `__rtw8852bx_set_channel_bb` (the CCK
//!    SCO thresholds, `rtw8852bx_ctrl_ch` with the gain error, gain offset
//!    and RPL compensation, `rtw8852bx_ctrl_bw` with `rtw8852b_bw_setting`,
//!    the CCK enable, the 5 GHz BT share bits, the encoded primary channel,
//!    `rtw8852bx_5m_mask`, the POP bit and `__rtw8852bx_bb_reset_all`) and
//!    `rtw8852b_set_channel_rf` (rtw8852b_rfk.c: RF 0x18's channel through
//!    `_ch_setting`, with S0's write through `_set_ch`, `_set_s0_arfc18` and
//!    `_lck_check`, then its bandwidth through `_bw_setting` and the RX
//!    baseband filter through `_set_rxbb_bw`, on both paths);
//! 3. `chip->ops->set_txpwr`, the caller's closure (step 3.5's);
//! 4. `rtw89_chip_set_channel_done`, the help exited, as [`done`]: PPDU
//!    status back on, the ADC FIFO and TSSI tracking released, the BB out of
//!    reset (CCK CCA and the PD hit back on 2.4 GHz), and the scheduler's
//!    TX enables put back.
//!
//! [`switch`] runs the four in that order. [`Channel::new`] is
//! `rtw89_chan_create`'s (chan.c) for the channels an RTL8852B tunes: it
//! derives the subband, the primary's index and the frequency, and refuses
//! a channel or width the 802.11 channel plan does not give the band.
//!
//! The inputs that are not the channel come from other steps, each named
//! where [`Inputs`] holds it: `rtwdev->bb_gain.ax` from the BB gain table
//! (3.3), `rtwdev->efuse_gain`'s efuse part from [`efuse`]
//! ([`Info::efuse_gain`]), its `offset_base` and `rssi_base`, which
//! `__rtw8852bx_bb_sethw` reads after the BB table loads (3.3/3.10),
//! `hal->antenna_rx` ([`Info::hal`]) and whether a monitor interface
//! is up.
//!
//! What rtw89 does around the switch and is left to later steps:
//! - `chip->ops->set_txpwr` (3.5): [`switch`] calls the closure it is given
//!   where rtw89 calls it.
//! - The band change's notices, `rtw89_btc_ntfy_switch_band` (coex, 3.9)
//!   and `rtw89_chip_rfk_band_changed` (RTL8852B's TSSI scan, 3.8), which
//!   rtw89 sends after the help exits when the PHY had no channel yet or the
//!   band changed: [`Switched::band_notice`] says when they are owed.
//! - `rtw89_chip_rfk_channel_for_pure_mon_vif`: Stela runs no monitor-only
//!   interface. The RF calibrations of a channel (3.6-3.8) are the caller's.
//! - Channel contexts, MCC, DBCC and PHY 1: rtw89 tunes an AX chip's band 0
//!   alone, and `dbcc_en` is false on an RTL8852B, so every
//!   `rtw89_phy_write32_idx` reaches PHY 0's register.
//! - RTL8852BT's branches (its ADC configuration, CSI tone and external
//!   loss average) and 6 GHz, which an RTL8852B does not tune.
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included, and the RF reads rtw89's debug
//! lines make, whose arguments are evaluated whatever is printed; the two in
//! `_lck_check`'s last line are made left to right, as clang evaluates them
//! (C leaves the order unspecified). The LCK poll reads RF 0xb7's busy bit
//! every 1 us for 1000 us, counted in steps, and a timeout skips
//! `_lck_check`, as in rtw89; [`Tuned::lck_timeouts`] counts them.
//!
//! Where it departs from rtw89, which logs and carries on:
//! - rtw89 ignores what `rtw89_mac_stop_sch_tx`, `rtw89_mac_cfg_ppdu_status`
//!   and `rtw89_mac_resume_sch_tx` return. So does this, but it reports them
//!   ([`Help`], [`Done`]); only an access the interface refuses, which rtw89
//!   has no failure for, ends the switch.
//! - An RF access whose SWSI never goes idle or never answers ends the switch
//!   with [`io::Error::Timeout`] ([`Registers::read_rf`]), where rtw89 reads
//!   `INV_RF_DATA` (and `_bw_setting` skips the path) or drops the write.
//!
//! A switch that returns proves only that every access was made as rtw89
//! makes it: nothing here shows that the synthesizer locked, that the chip
//! hears the channel, or that the regulatory domain allows it.
//!
//! [`efuse`]: crate::wifi::realtek::ax::efuse
//! [`Info::efuse_gain`]: crate::wifi::realtek::ax::efuse::Info::efuse_gain
//! [`Info::hal`]: crate::wifi::realtek::ax::efuse::Info::hal
use crate::wifi::realtek::ax::{
    efuse::{EfuseGain, RF_B},
    h2creg::Mailbox,
    io::{self, CR_BASE, Io, Registers, prep},
    mac::{self, Cause},
    registers::*,
};

/// `enum rtw89_band`: the bands an RTL8852B tunes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Band {
    /// `RTW89_BAND_2G`.
    Ghz2,
    /// `RTW89_BAND_5G`.
    Ghz5,
}

/// `enum rtw89_bandwidth`: the widths an RTL8852B tunes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Width {
    /// `RTW89_CHANNEL_WIDTH_20`.
    Mhz20,
    /// `RTW89_CHANNEL_WIDTH_40`.
    Mhz40,
    /// `RTW89_CHANNEL_WIDTH_80`.
    Mhz80,
}

/// `enum rtw89_subband` up to 5 GHz: `RTW89_CH_2G` and the 5 GHz bands
/// (`RTW89_CH_5G_BAND_2` is unused).
pub const CH_2G: u8 = 0;
pub const CH_5G_BAND_1: u8 = 1;
pub const CH_5G_BAND_3: u8 = 3;
pub const CH_5G_BAND_4: u8 = 4;

/// `enum rtw89_sc_offset`: the 20 MHz primary's place in a wider channel.
pub const SC_DONT_CARE: u8 = 0;
pub const SC_20_UPPER: u8 = 1;
pub const SC_20_LOWER: u8 = 2;
pub const SC_20_UPMOST: u8 = 3;
pub const SC_20_LOWEST: u8 = 4;

/// The 5 GHz 20 MHz channels rtw89 lists (`rtw89_channels_5ghz`, UNII-4's
/// 169 to 177 included), the 40 MHz channels' centers and the 80 MHz ones'.
const CHANNELS_5G: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];
const CENTERS_40_5G: [u8; 14] = [
    38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175,
];
const CENTERS_80_5G: [u8; 7] = [42, 58, 106, 122, 138, 155, 171];

/// A center, primary and width that is not a channel an RTL8852B tunes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Invalid {
    pub center: u8,
    pub primary: u8,
    pub width: Width,
}

/// `struct rtw89_chan` for band 0, as `rtw89_chan_create` fills it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel {
    center: u8,
    primary: u8,
    band: Band,
    width: Width,
}

impl Channel {
    /// `rtw89_chan_create(chan, center, primary, band, width)`, the band
    /// the primary's: channels 1 to 14 at 2.4 GHz (40 MHz around a center
    /// from 3 to 11, channel 14 at 20 MHz alone, no 80 MHz), and the 5 GHz
    /// channels at 20, 40 and 80 MHz around the 802.11 plan's centers.
    pub fn new(center: u8, primary: u8, width: Width) -> Result<Self, Invalid> {
        let invalid = Invalid {
            center,
            primary,
            width,
        };
        let apart = center.abs_diff(primary);
        let (band, valid) = if (1..=14).contains(&primary) {
            let valid = match width {
                Width::Mhz20 => apart == 0,
                Width::Mhz40 => (3..=11).contains(&center) && apart == 2,
                Width::Mhz80 => false,
            };
            (Band::Ghz2, valid)
        } else if CHANNELS_5G.contains(&primary) {
            let valid = match width {
                Width::Mhz20 => apart == 0,
                Width::Mhz40 => CENTERS_40_5G.contains(&center) && apart == 2,
                Width::Mhz80 => CENTERS_80_5G.contains(&center) && (apart == 2 || apart == 6),
            };
            (Band::Ghz5, valid)
        } else {
            return Err(invalid);
        };
        if !valid {
            return Err(invalid);
        }
        Ok(Self {
            center,
            primary,
            band,
            width,
        })
    }

    /// `chan->channel`, the center.
    pub fn center(&self) -> u8 {
        self.center
    }
    /// `chan->primary_channel`.
    pub fn primary(&self) -> u8 {
        self.primary
    }
    pub fn band(&self) -> Band {
        self.band
    }
    pub fn width(&self) -> Width {
        self.width
    }

    /// `chan->freq`: the center's frequency in MHz
    /// (`ieee80211_channel_to_frequency`).
    pub fn freq(&self) -> u32 {
        frequency(self.band, self.center)
    }

    /// `chan->subband_type` (`rtw89_get_subband_type`), from the center.
    pub fn subband(&self) -> u8 {
        match (self.band, self.center) {
            (Band::Ghz2, _) => CH_2G,
            (Band::Ghz5, 100..=144) => CH_5G_BAND_3,
            (Band::Ghz5, 149..=177) => CH_5G_BAND_4,
            (Band::Ghz5, _) => CH_5G_BAND_1,
        }
    }

    /// `chan->pri_ch_idx` (`rtw89_get_primary_chan_idx`): an `SC_20_*`
    /// value, or [`SC_DONT_CARE`] at 20 MHz.
    pub fn pri_ch_idx(&self) -> u8 {
        let center = frequency(self.band, self.center);
        let primary = frequency(self.band, self.primary);
        match self.width {
            Width::Mhz20 => SC_DONT_CARE,
            Width::Mhz40 if primary > center => SC_20_UPPER,
            Width::Mhz40 => SC_20_LOWER,
            Width::Mhz80 if primary > center => {
                SC_20_UPPER + ((primary - center - 10) / 20) as u8 * 2
            }
            Width::Mhz80 => SC_20_LOWER + ((center - primary - 10) / 20) as u8 * 2,
        }
    }

    /// `rtw89_phy_get_txsc(rtwdev, chan, dbw)`: the TX subchannel of width
    /// `dbw` that holds the primary.
    pub fn txsc(&self, dbw: Width) -> u8 {
        let (primary, center) = (self.primary, self.center);
        if self.width == dbw || self.width == Width::Mhz20 {
            return 0;
        }
        match (self.width, dbw) {
            (Width::Mhz40, _) => {
                if primary > center {
                    1
                } else {
                    2
                }
            }
            (_, Width::Mhz20) if primary > center => (primary - center) >> 1,
            (_, Width::Mhz20) => ((center - primary) >> 1) + 1,
            _ if primary > center => 9,
            _ => 10,
        }
    }

    /// `rtw89_encode_chan_idx(rtwdev, chan->primary_channel, band)`: the
    /// base's index in `rtw89_ch_base_table` and the primary's offset from it.
    pub fn chan_idx(&self) -> u8 {
        const BASES_5G: [(u8, u8); 4] = [(5, 149), (4, 132), (3, 100), (2, 36)];
        match self.band {
            Band::Ghz2 => self.primary & 0x0f,
            Band::Ghz5 => {
                let (index, base) = BASES_5G
                    .into_iter()
                    .find(|&(_, base)| self.primary >= base)
                    .unwrap_or((0, self.primary));
                (index << 4) | (((self.primary - base) >> 1) & 0x0f)
            }
        }
    }
}

/// `ieee80211_channel_to_frequency` for the 2.4 and 5 GHz bands.
fn frequency(band: Band, channel: u8) -> u32 {
    match band {
        Band::Ghz2 if channel == 14 => 2484,
        Band::Ghz2 => 2407 + 5 * u32::from(channel),
        Band::Ghz5 => 5000 + 5 * u32::from(channel),
    }
}

/// `LNA_GAIN_NUM` and `TIA_GAIN_NUM`.
pub const LNA_GAIN_NUM: usize = 7;
pub const TIA_GAIN_NUM: usize = 2;
/// `RTW89_BB_RXSC_NUM_40` and `RTW89_BB_RXSC_NUM_80`.
pub const BB_RXSC_NUM_40: usize = 9;
pub const BB_RXSC_NUM_80: usize = 13;
/// `enum rtw89_phy_bb_gain_band` up to 5 GHz: 2G, 5G_L, 5G_M, 5G_H.
pub const BB_GAIN_BAND_2G_5G: usize = 4;
/// `BB_PATH_NUM_8852BX`.
pub const BB_PATH_NUM: usize = 2;

/// The part of `struct rtw89_phy_bb_gain_info` a channel switch reads, for
/// the 2.4 and 5 GHz gain bands: what `rtw89_phy_config_bb_gain_ax` leaves
/// from the BB gain table (3.3). Zeroed, as `rtwdev` is allocated, until
/// that table loads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BbGain {
    pub lna_gain: [[[i8; LNA_GAIN_NUM]; BB_PATH_NUM]; BB_GAIN_BAND_2G_5G],
    pub tia_gain: [[[i8; TIA_GAIN_NUM]; BB_PATH_NUM]; BB_GAIN_BAND_2G_5G],
    pub rpl_ofst_20: [[i8; BB_PATH_NUM]; BB_GAIN_BAND_2G_5G],
    pub rpl_ofst_40: [[[i8; BB_RXSC_NUM_40]; BB_PATH_NUM]; BB_GAIN_BAND_2G_5G],
    pub rpl_ofst_80: [[[i8; BB_RXSC_NUM_80]; BB_PATH_NUM]; BB_GAIN_BAND_2G_5G],
}

/// What a channel switch reads besides the channel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Inputs {
    /// `rtwdev->bb_gain.ax`, from the BB gain table (3.3).
    pub bb_gain: BbGain,
    /// `rtwdev->efuse_gain`'s efuse part: [`Info::efuse_gain`].
    ///
    /// [`Info::efuse_gain`]: crate::wifi::realtek::ax::efuse::Info::efuse_gain
    pub efuse_gain: EfuseGain,
    /// `efuse_gain->offset_base[RTW89_PHY_0]` and `rssi_base[RTW89_PHY_0]`:
    /// R_P0_RPL1's and R_P1_RPL1's bias fields as `__rtw8852bx_bb_sethw`
    /// reads them after the BB table loads (3.3/3.10); 0 before.
    pub offset_base: i8,
    pub rssi_base: i8,
    /// `hal->antenna_rx` ([`Info::hal`]): [`RF_B`] takes path B's
    /// gain offsets for the RPL bias.
    ///
    /// [`Info::hal`]: crate::wifi::realtek::ax::efuse::Info::hal
    pub antenna_rx: u8,
    /// `IEEE80211_CONF_MONITOR`: a monitor interface is up, and
    /// `rtw8852bx_bb_set_pop` clears the POP enable.
    pub monitor: bool,
}

/// What `rtw8852b_set_channel` left to tell: how many of S0's RF 0x18
/// writes (`_set_s0_arfc18`) saw the LPF busy past their bound, which rtw89
/// only logs ("[LCK]LCK timeout").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tuned {
    pub lck_timeouts: u8,
}

/// What entering `rtw8852b_set_channel_help` read and what rtw89 ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Help {
    /// `p->tx_en`: CTN_TXEN as read before the stop.
    pub tx_en: u16,
    /// `rtw89_chip_stop_sch_tx`'s failure.
    pub stop_sch_tx: Option<Cause>,
    /// `rtw89_mac_cfg_ppdu_status(…, false)`'s failure.
    pub ppdu_status: Option<Cause>,
}

/// What exiting `rtw8852b_set_channel_help` returned and rtw89 ignored.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Done {
    /// `rtw89_mac_cfg_ppdu_status(…, true)`'s failure.
    pub ppdu_status: Option<Cause>,
    /// `rtw89_chip_resume_sch_tx`'s failure.
    pub resume_sch_tx: Option<Cause>,
}

/// What [`switch`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Switched {
    pub help: Help,
    pub tuned: Tuned,
    pub done: Done,
    /// rtw89 now sends `rtw89_btc_ntfy_switch_band` and
    /// `rtw89_chip_rfk_band_changed`: PHY 0 had no channel or the band
    /// changed (`!entity_active || chan_rcd->band_changed`).
    pub band_notice: bool,
}

/// `__rtw89_set_channel(rtwdev, chan, RTW89_MAC_0, RTW89_PHY_0)` up to the
/// band change's notices: the help entered, the channel set, TX power set
/// by `set_txpwr` (3.5), the help exited. `previous` is the band PHY 0 was
/// last tuned to, `None` before the first switch. `firmware` is the mailbox
/// of a running firmware (`RTW89_FLAG_FW_RDY`), through which the
/// scheduler's TX is stopped and resumed ([`mac::resume_sch_tx`]).
pub fn switch<I: Io + ?Sized>(
    io: &mut I,
    mut firmware: Option<&mut Mailbox>,
    chan: &Channel,
    inputs: &Inputs,
    previous: Option<Band>,
    set_txpwr: impl FnOnce(&mut I, &Channel) -> Result<(), io::Error>,
) -> Result<Switched, io::Error> {
    let help = enter(io, firmware.as_deref_mut(), chan)?;
    let tuned = set_channel(io, chan, inputs)?;
    set_txpwr(io, chan)?;
    let done = done(io, firmware, chan, &help)?;
    Ok(Switched {
        help,
        tuned,
        done,
        band_notice: previous != Some(chan.band),
    })
}

/// A result rtw89 ignores: kept, unless the interface refused an access.
fn ignored(result: Result<(), Cause>) -> Result<Option<Cause>, io::Error> {
    match result {
        Ok(()) => Ok(None),
        Err(Cause::Io(error)) if !matches!(error, io::Error::Timeout { .. }) => Err(error),
        Err(cause) => Ok(Some(cause)),
    }
}

/// `rtw8852b_set_channel_help(rtwdev, true, p, chan, RTW89_MAC_0,
/// RTW89_PHY_0)`. The stop is `rtw89_mac_stop_sch_tx` with
/// `RTW89_SCH_TX_SEL_ALL`: CTN_TXEN read, then every enable set to 0, which
/// is `rtw89_set_hw_sch_tx_en(rtwdev, 0, 0, B_AX_CTN_TXEN_ALL_MASK)`, the
/// call [`mac::resume_sch_tx`] makes with 0; the enables read are kept
/// whatever the stop returns, as rtw89 keeps them.
pub fn enter<I: Io + ?Sized>(
    io: &mut I,
    firmware: Option<&mut Mailbox>,
    chan: &Channel,
) -> Result<Help, io::Error> {
    let tx_en = io.read16(CTN_TXEN)?;
    let stop_sch_tx = ignored(mac::resume_sch_tx(io, firmware, 0))?;
    let ppdu_status = ignored(cfg_ppdu_status(io, false))?;
    tssi_cont_en(io, false)?;
    adc_en(io, false)?;
    io.delay_us(40);
    bb_reset_en(io, chan.band, false)?;
    Ok(Help {
        tx_en,
        stop_sch_tx,
        ppdu_status,
    })
}

/// `rtw8852b_set_channel_help(rtwdev, false, p, chan, RTW89_MAC_0,
/// RTW89_PHY_0)`, with the enables [`enter`] read.
pub fn done<I: Io + ?Sized>(
    io: &mut I,
    firmware: Option<&mut Mailbox>,
    chan: &Channel,
    help: &Help,
) -> Result<Done, io::Error> {
    let ppdu_status = ignored(cfg_ppdu_status(io, true))?;
    adc_en(io, true)?;
    tssi_cont_en(io, true)?;
    bb_reset_en(io, chan.band, true)?;
    let resume_sch_tx = ignored(mac::resume_sch_tx(io, firmware, help.tx_en))?;
    Ok(Done {
        ppdu_status,
        resume_sch_tx,
    })
}

/// `rtw8852b_set_channel(rtwdev, chan, RTW89_MAC_0, RTW89_PHY_0)`.
pub fn set_channel<I: Io + ?Sized>(
    io: &mut I,
    chan: &Channel,
    inputs: &Inputs,
) -> Result<Tuned, io::Error> {
    set_channel_mac(io, chan)?;
    set_channel_bb(io, chan, inputs)?;
    set_channel_rf(io, chan)
}

/// `rtw89_mac_cfg_ppdu_status_ax(rtwdev, RTW89_MAC_0, enable)`.
fn cfg_ppdu_status<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), Cause> {
    // rtw89_mac_check_mac_en(rtwdev, 0, RTW89_CMAC_SEL)
    let value = io.read32(CMAC_FUNC_EN)?;
    if value == R32_EA || value == R32_DEAD || value & CMAC_EN != CMAC_EN {
        return Err(Cause::CmacOff { value });
    }
    if !enable {
        io.write32_clr(PPDU_STAT, PPDU_STAT_RPT_EN)?;
        return Ok(());
    }
    io.write32(
        PPDU_STAT,
        PPDU_STAT_RPT_EN | APP_MAC_INFO_RPT | APP_PLCP_HDR_RPT | PPDU_STAT_RPT_CRC32,
    )?;
    io.write32_mask(HW_RPT_FWD, FWD_PPDU_STAT_MASK, PRPT_DEST_HOST)?;
    Ok(())
}

/// `rtw8852b_tssi_cont_en_phyidx(rtwdev, en, RTW89_PHY_0)` without DBCC:
/// `rtw8852b_tssi_cont_en` for path A, then B.
fn tssi_cont_en<I: Io + ?Sized>(io: &mut I, en: bool) -> Result<(), io::Error> {
    const TSSI_TRK: [u32; 2] = [R_P0_TSSI_TRK, R_P1_TSSI_TRK];
    const CTRL_BBRST: [u32; 2] = [R_P0_TXPW_RSTB, R_P1_TXPW_RSTB];
    let hold = u32::from(!en);
    for path in 0..2 {
        io.phy_write32_mask(CTRL_BBRST[path], B_P0_TXPW_RSTB_MANON, hold)?;
        io.phy_write32_mask(TSSI_TRK[path], B_P0_TSSI_TRK_EN, hold)?;
    }
    Ok(())
}

/// `rtw8852b_adc_en`.
fn adc_en<I: Io + ?Sized>(io: &mut I, en: bool) -> Result<(), io::Error> {
    io.phy_write32_mask(R_ADC_FIFO, B_ADC_FIFO_RST, if en { 0 } else { 0xf })
}

/// `rtw8852b_bb_reset_en(rtwdev, band, RTW89_PHY_0, en)`.
fn bb_reset_en<I: Io + ?Sized>(io: &mut I, band: Band, en: bool) -> Result<(), io::Error> {
    if en {
        io.phy_write32_mask(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 0)?;
        io.phy_write32_mask(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 0)?;
        io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)?;
        if band == Band::Ghz2 {
            io.phy_write32_mask(R_RXCCA, B_RXCCA_DIS, 0)?;
        }
        io.phy_write32_mask(R_PD_CTRL, B_PD_HIT_DIS, 0)
    } else {
        io.phy_write32_mask(R_RXCCA, B_RXCCA_DIS, 1)?;
        io.phy_write32_mask(R_PD_CTRL, B_PD_HIT_DIS, 1)?;
        io.phy_write32_mask(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 7)?;
        io.phy_write32_mask(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 7)?;
        io.delay_us(1);
        io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 0)
    }
}

/// `__rtw8852bx_set_channel_mac(rtwdev, chan, RTW89_MAC_0)`.
fn set_channel_mac<I: Io + ?Sized>(io: &mut I, chan: &Channel) -> Result<(), io::Error> {
    let (txsc20, txsc40) = match chan.width {
        Width::Mhz80 => (chan.txsc(Width::Mhz20), chan.txsc(Width::Mhz40)),
        Width::Mhz40 => (chan.txsc(Width::Mhz20), 0),
        Width::Mhz20 => (0, 0),
    };
    match chan.width {
        Width::Mhz80 => {
            io.write8_mask(WMAC_RFMOD, WMAC_RFMOD_MASK, 1 << 1)?;
            io.write32(
                TX_SUB_CARRIER_VALUE,
                u32::from(txsc20) | u32::from(txsc40) << 4,
            )?;
        }
        Width::Mhz40 => {
            io.write8_mask(WMAC_RFMOD, WMAC_RFMOD_MASK, 1 << 0)?;
            io.write32(TX_SUB_CARRIER_VALUE, txsc20.into())?;
        }
        Width::Mhz20 => {
            io.write8_clr(WMAC_RFMOD, WMAC_RFMOD_MASK as u8)?;
            io.write32(TX_SUB_CARRIER_VALUE, 0)?;
        }
    }
    let checks = (CHECK_CCK_EN | RTS_LIMIT_IN_OFDM6) as u8;
    if chan.center > 14 {
        io.write8_clr(TXRATE_CHK, BAND_MODE as u8)?;
        io.write8_set(TXRATE_CHK, checks)
    } else {
        io.write8_set(TXRATE_CHK, BAND_MODE as u8)?;
        io.write8_clr(TXRATE_CHK, checks)
    }
}

/// `rtw8852bx_sco_barker_threshold` and `rtw8852bx_sco_cck_threshold`, by
/// 2.4 GHz channel.
const SCO_BARKER_THRESHOLD: [u32; 14] = [
    0x1cfea, 0x1d0e1, 0x1d1d7, 0x1d2cd, 0x1d3c3, 0x1d4b9, 0x1d5b0, 0x1d6a6, 0x1d79c, 0x1d892,
    0x1d988, 0x1da7f, 0x1db75, 0x1ddc4,
];
const SCO_CCK_THRESHOLD: [u32; 14] = [
    0x27de3, 0x27f35, 0x28088, 0x281da, 0x2832d, 0x2847f, 0x285d2, 0x28724, 0x28877, 0x289c9,
    0x28b1c, 0x28c6e, 0x28dc1, 0x290ed,
];

/// `rtw8852bx_sco_mapping`: the SCO compensation for a center.
fn sco_mapping(central_ch: u8) -> u32 {
    match central_ch {
        1 => 109,
        2..=6 => 108,
        7..=10 => 107,
        11..=14 => 106,
        36 | 38 => 51,
        40..=58 => 50,
        60..=64 => 49,
        100 | 102 => 48,
        104..=126 => 47,
        128..=151 => 46,
        153..=177 => 45,
        _ => 0,
    }
}

/// `struct rtw8852bx_bb_gain`: one gain's register on each path, at 2.4
/// and 5 GHz, and its byte.
struct GainRegister {
    gain_g: [u32; 2],
    gain_a: [u32; 2],
    gain_mask: u32,
}

const fn gain(gain_g: [u32; 2], gain_a: [u32; 2], gain_mask: u32) -> GainRegister {
    GainRegister {
        gain_g,
        gain_a,
        gain_mask,
    }
}

/// `bb_gain_lna` and `bb_gain_tia`.
const BB_GAIN_LNA: [GainRegister; LNA_GAIN_NUM] = [
    gain([0x4678, 0x475c], [0x45dc, 0x4740], 0x00ff_0000),
    gain([0x4678, 0x475c], [0x45dc, 0x4740], 0xff00_0000),
    gain([0x467c, 0x4760], [0x4660, 0x4744], 0x0000_00ff),
    gain([0x467c, 0x4760], [0x4660, 0x4744], 0x0000_ff00),
    gain([0x467c, 0x4760], [0x4660, 0x4744], 0x00ff_0000),
    gain([0x467c, 0x4760], [0x4660, 0x4744], 0xff00_0000),
    gain([0x4680, 0x4764], [0x4664, 0x4748], 0x0000_00ff),
];
const BB_GAIN_TIA: [GainRegister; TIA_GAIN_NUM] = [
    gain([0x4680, 0x4764], [0x4664, 0x4748], 0x00ff_0000),
    gain([0x4680, 0x4764], [0x4664, 0x4748], 0xff00_0000),
];

/// `rtw89_subband_to_bb_gain_band`.
fn bb_gain_band(subband: u8) -> usize {
    match subband {
        CH_5G_BAND_1 => 1,
        CH_5G_BAND_3 => 2,
        CH_5G_BAND_4 => 3,
        _ => 0,
    }
}

/// `rtw89_subband_to_gain_offset_band_of_ofdm`: `RTW89_GAIN_OFFSET_2G_OFDM`
/// and the 5 GHz low, mid and high offsets.
fn gain_offset_band_of_ofdm(subband: u8) -> usize {
    match subband {
        CH_5G_BAND_1 => 2,
        CH_5G_BAND_3 => 3,
        CH_5G_BAND_4 => 4,
        _ => 1,
    }
}

/// A gain as rtw89 hands it to `rtw89_phy_write32_mask`: sign-extended,
/// truncated to the field.
fn signed(value: i32) -> u32 {
    value as u32
}

/// `rtw8852bx_set_gain_error(rtwdev, subband, path)`.
fn set_gain_error<I: Io + ?Sized>(
    io: &mut I,
    gain: &BbGain,
    subband: u8,
    path: usize,
) -> Result<(), io::Error> {
    let band = bb_gain_band(subband);
    let register = |entry: &GainRegister| {
        if subband == CH_2G {
            entry.gain_g[path]
        } else {
            entry.gain_a[path]
        }
    };
    for (entry, value) in BB_GAIN_LNA.iter().zip(gain.lna_gain[band][path]) {
        io.phy_write32_mask(register(entry), entry.gain_mask, signed(value.into()))?;
    }
    for (entry, value) in BB_GAIN_TIA.iter().zip(gain.tia_gain[band][path]) {
        io.phy_write32_mask(register(entry), entry.gain_mask, signed(value.into()))?;
    }
    Ok(())
}

/// `clamp_t(s32, value, S8_MIN, S8_MAX)`, and its halves for the CCK
/// offset.
fn clamp8(value: i32) -> u32 {
    signed(value.clamp(i8::MIN.into(), i8::MAX.into()))
}

/// `rtw8852bx_set_gain_offset(rtwdev, subband, RTW89_PHY_0)` for an
/// RTL8852B, which takes no external loss average.
pub(crate) fn set_gain_offset<I: Io + ?Sized>(
    io: &mut I,
    inputs: &Inputs,
    subband: u8,
) -> Result<(), io::Error> {
    const GAIN_ERR_ADDR: [u32; 2] = [R_P0_AGC_RSVD, R_P1_AGC_RSVD];
    const RSSI_OFST_ADDR: [u32; 2] = [R_PATH0_G_TIA1_LNA6_OP1DB_V1, R_PATH1_G_TIA1_LNA6_OP1DB_V1];
    let gain = &inputs.efuse_gain;
    let offset_base = i32::from(inputs.offset_base);
    let rssi_base = i32::from(inputs.rssi_base);
    if gain.comp_valid {
        for (register, comp) in GAIN_ERR_ADDR.into_iter().zip(gain.comp) {
            let comp = i32::from(comp[usize::from(subband)]);
            io.phy_write32_mask(register, MASKBYTE0, clamp8(comp << 2))?;
        }
    }
    if !gain.offset_valid {
        return Ok(());
    }
    let band = gain_offset_band_of_ofdm(subband);
    let offset = |path: usize, band: usize| -i32::from(gain.offset[path][band]);
    for (path, register) in RSSI_OFST_ADDR.into_iter().enumerate() {
        let value = -((offset(path, band) << 2) + (offset_base >> 2));
        io.phy_write32_mask(register, B_PATH0_R_G_OFST_MASK, clamp8(value))?;
    }
    let rx = if inputs.antenna_rx == RF_B { 1 } else { 0 };
    let (offset_ofdm, offset_cck) = (offset(rx, band), offset(rx, 0));
    let value = (offset_ofdm << 4) + offset_base;
    io.phy_write32_mask(R_P0_RPL1, B_P0_RPL1_BIAS_MASK, clamp8(value))?;
    let value = (offset_ofdm << 4) + rssi_base;
    io.phy_write32_mask(R_P1_RPL1, B_P0_RPL1_BIAS_MASK, clamp8(value))?;
    if subband == CH_2G {
        let value = (offset_cck << 3) + (offset_base >> 1);
        let value = value.clamp(i32::from(i8::MIN) >> 1, i32::from(i8::MAX) >> 1);
        io.phy_write32_mask(R_RX_RPL_OFST, B_RX_RPL_OFST_CCK_MASK, signed(value))?;
    }
    Ok(())
}

/// `rtw8852bx_set_rxsc_rpl_comp(rtwdev, subband)`: each RX subchannel's
/// RPL offset, the paths' average, on both paths.
fn set_rxsc_rpl_comp<I: Io + ?Sized>(
    io: &mut I,
    gain: &BbGain,
    subband: u8,
) -> Result<(), io::Error> {
    let band = bb_gain_band(subband);
    let average = |a: i8, b: i8| signed((i32::from(a) + i32::from(b)) >> 1);
    let ofst_20 = gain.rpl_ofst_20[band];
    let [ofst_40_a, ofst_40_b] = gain.rpl_ofst_40[band];
    let [ofst_80_a, ofst_80_b] = gain.rpl_ofst_80[band];
    let ofst_40 = |i: usize| average(ofst_40_a[i], ofst_40_b[i]);
    let ofst_80 = |i: usize| average(ofst_80_a[i], ofst_80_b[i]);

    let value = (prep(average(ofst_20[0], ofst_20[1]), B_P0_RPL1_20_MASK)
        | prep(ofst_40(0), B_P0_RPL1_40_MASK)
        | prep(ofst_40(1), B_P0_RPL1_41_MASK))
        >> B_P0_RPL1_SHIFT;
    io.phy_write32_mask(R_P0_RPL1, B_P0_RPL1_MASK, value)?;
    io.phy_write32_mask(R_P1_RPL1, B_P0_RPL1_MASK, value)?;

    let value = prep(ofst_40(2), B_P0_RTL2_42_MASK)
        | prep(ofst_80(0), B_P0_RTL2_80_MASK)
        | prep(ofst_80(1), B_P0_RTL2_81_MASK)
        | prep(ofst_80(10), B_P0_RTL2_8A_MASK);
    phy_write32(io, R_P0_RPL2, value)?;
    phy_write32(io, R_P1_RPL2, value)?;

    let value = prep(ofst_80(2), B_P0_RTL3_82_MASK)
        | prep(ofst_80(3), B_P0_RTL3_83_MASK)
        | prep(ofst_80(4), B_P0_RTL3_84_MASK)
        | prep(ofst_80(9), B_P0_RTL3_89_MASK);
    phy_write32(io, R_P0_RPL3, value)?;
    phy_write32(io, R_P1_RPL3, value)
}

/// `rtw89_phy_write32`: the BB register written whole, without a read.
fn phy_write32<I: Io + ?Sized>(io: &mut I, register: u32, value: u32) -> Result<(), io::Error> {
    io.write32(CR_BASE + register, value)
}

/// `rtw8852bx_ctrl_ch(rtwdev, chan, RTW89_PHY_0)`.
fn ctrl_ch<I: Io + ?Sized>(io: &mut I, chan: &Channel, inputs: &Inputs) -> Result<(), io::Error> {
    let central_ch = chan.center;
    let subband = chan.subband();
    let is_2g = u32::from(central_ch <= 14);
    io.phy_write32_mask(R_PATH0_BAND_SEL_V1, B_PATH0_BAND_SEL_MSK_V1, is_2g)?;
    io.phy_write32_mask(R_PATH1_BAND_SEL_V1, B_PATH1_BAND_SEL_MSK_V1, is_2g)?;
    io.phy_write32_mask(R_FC0_BW_V1, B_FC0_BW_INV, sco_mapping(central_ch))?;
    // The CCK TX filter: channel 14's coefficients, or everyone else's.
    let fir = if central_ch == 14 {
        [
            0x3b13ff, 0x1c42de, 0xfdb0ad, 0xf60f6e, 0xfd8f92, 0x2d011, 0x1c02c, 0xfff00a,
        ]
    } else {
        [
            0x3d23ff, 0x29b354, 0xfc1c8, 0xfdb053, 0xf86f9a, 0xfaef92, 0xfe5fcc, 0xffdff5,
        ]
    };
    let registers = [
        (R_TXFIR0, B_TXFIR_C01),
        (R_TXFIR2, B_TXFIR_C23),
        (R_TXFIR4, B_TXFIR_C45),
        (R_TXFIR6, B_TXFIR_C67),
        (R_TXFIR8, B_TXFIR_C89),
        (R_TXFIRA, B_TXFIR_CAB),
        (R_TXFIRC, B_TXFIR_CCD),
        (R_TXFIRE, B_TXFIR_CEF),
    ];
    for ((register, mask), value) in registers.into_iter().zip(fir) {
        io.phy_write32_mask(register, mask, value)?;
    }
    set_gain_error(io, &inputs.bb_gain, subband, 0)?;
    set_gain_error(io, &inputs.bb_gain, subband, 1)?;
    set_gain_offset(io, inputs, subband)?;
    set_rxsc_rpl_comp(io, &inputs.bb_gain, subband)
}

/// `rtw8852b_bw_setting(rtwdev, bw, path)` at 20, 40 or 80 MHz.
fn bw_setting<I: Io + ?Sized>(io: &mut I, path: usize) -> Result<(), io::Error> {
    const ADC_SEL: [u32; 2] = [0xc0ec, 0xc1ec];
    const WBADC_SEL: [u32; 2] = [0xc0e4, 0xc1e4];
    io.phy_write32_mask(ADC_SEL[path], 0x6000, 0)?;
    io.phy_write32_mask(WBADC_SEL[path], 0x30, 2)
}

/// `rtw8852bx_ctrl_bw(rtwdev, pri_ch, bw, RTW89_PHY_0)` for an RTL8852B.
fn ctrl_bw<I: Io + ?Sized>(io: &mut I, pri_ch: u8, bw: Width) -> Result<(), io::Error> {
    let rx_path_0 = io.phy_read32_mask(R_CHBW_MOD_V1, B_ANT_RX_SEG0)?;
    let (bw_set, prich) = match bw {
        Width::Mhz20 => (0, 0),
        Width::Mhz40 => (1, pri_ch),
        Width::Mhz80 => (2, pri_ch),
    };
    io.phy_write32_mask(R_FC0_BW_V1, B_FC0_BW_SET, bw_set)?;
    io.phy_write32_mask(R_CHBW_MOD_V1, B_CHBW_MOD_SBW, 0)?;
    io.phy_write32_mask(R_CHBW_MOD_V1, B_CHBW_MOD_PRICH, prich.into())?;
    io.phy_write32_mask(R_P0_RFMODE_ORI_RX, B_P0_RFMODE_ORI_RX_ALL, 0x333)?;
    io.phy_write32_mask(R_P1_RFMODE_ORI_RX, B_P1_RFMODE_ORI_RX_ALL, 0x333)?;
    if bw == Width::Mhz40 {
        // The CCK primary channel.
        io.phy_write32_mask(R_RXSC, B_RXSC_EN, u32::from(pri_ch == SC_20_UPPER))?;
    }
    bw_setting(io, 0)?;
    bw_setting(io, 1)?;
    match rx_path_0 {
        1 => io.phy_write32_mask(R_P1_RFMODE_ORI_RX, B_P1_RFMODE_ORI_RX_ALL, 0x111),
        2 => io.phy_write32_mask(R_P0_RFMODE_ORI_RX, B_P0_RFMODE_ORI_RX_ALL, 0x111),
        _ => Ok(()),
    }
}

/// `rtw8852bx_5m_mask(rtwdev, chan, RTW89_PHY_0)`.
fn mask_5m<I: Io + ?Sized>(io: &mut I, chan: &Channel) -> Result<(), io::Error> {
    let pri_ch = chan.pri_ch_idx();
    let (enable, low) = match chan.width {
        // Prich=1: mask 5M high, Prich=2: mask 5M low.
        Width::Mhz40 => (true, pri_ch == SC_20_LOWER),
        // Prich=3: mask 5M high, Prich=4: mask 5M low, else disable.
        Width::Mhz80 => (
            pri_ch == SC_20_UPMOST || pri_ch == SC_20_LOWEST,
            pri_ch == SC_20_LOWEST,
        ),
        Width::Mhz20 => (false, false),
    };
    if !enable {
        io.phy_write32_mask(R_PATH0_5MDET_V1, B_PATH0_5MDET_EN, 0)?;
        io.phy_write32_mask(R_PATH1_5MDET_V1, B_PATH1_5MDET_EN, 0)?;
        return io.phy_write32_mask(R_ASSIGN_SBD_OPT_V1, B_ASSIGN_SBD_OPT_EN_V1, 0);
    }
    let (sb2, sb0) = if low { (0, 1) } else { (1, 0) };
    for register in [R_PATH0_5MDET_V1, R_PATH1_5MDET_V1] {
        io.phy_write32_mask(register, B_PATH0_5MDET_TH, 0x4)?;
        io.phy_write32_mask(register, B_PATH0_5MDET_EN, 0x1)?;
        io.phy_write32_mask(register, B_PATH0_5MDET_SB2, sb2)?;
        io.phy_write32_mask(register, B_PATH0_5MDET_SB0, sb0)?;
    }
    io.phy_write32_mask(R_ASSIGN_SBD_OPT_V1, B_ASSIGN_SBD_OPT_EN_V1, 1)
}

/// `__rtw8852bx_bb_reset_all(rtwdev, RTW89_PHY_0)`.
fn bb_reset_all<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.phy_write32_mask(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 7)?;
    io.phy_write32_mask(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 7)?;
    io.delay_us(1);
    io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)?;
    io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 0)?;
    io.phy_write32_mask(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 0)?;
    io.phy_write32_mask(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 0)?;
    io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)
}

/// `__rtw8852bx_set_channel_bb(rtwdev, chan, RTW89_PHY_0)` for an RTL8852B.
fn set_channel_bb<I: Io + ?Sized>(
    io: &mut I,
    chan: &Channel,
    inputs: &Inputs,
) -> Result<(), io::Error> {
    let cck_en = chan.center <= 14;
    if cck_en {
        // rtw8852bx_ctrl_sco_cck(rtwdev, chan->primary_channel)
        let ch_element = usize::from(chan.primary - 1);
        io.phy_write32_mask(R_RXSCOBC, B_RXSCOBC_TH, SCO_BARKER_THRESHOLD[ch_element])?;
        io.phy_write32_mask(R_RXSCOCCK, B_RXSCOCCK_TH, SCO_CCK_THRESHOLD[ch_element])?;
    }
    ctrl_ch(io, chan, inputs)?;
    ctrl_bw(io, chan.pri_ch_idx(), chan.width)?;
    // rtw8852bx_ctrl_cck_en
    io.phy_write32_mask(R_UPD_CLK_ADC, B_ENABLE_CCK, u32::from(cck_en))?;
    io.phy_write32_mask(R_RXCCA, B_RXCCA_DIS, u32::from(!cck_en))?;
    if chan.band == Band::Ghz5 {
        io.phy_write32_mask(R_PATH0_BT_SHARE_V1, B_PATH0_BT_SHARE_V1, 0)?;
        io.phy_write32_mask(R_PATH0_BTG_PATH_V1, B_PATH0_BTG_PATH_V1, 0)?;
        io.phy_write32_mask(R_PATH1_BT_SHARE_V1, B_PATH1_BT_SHARE_V1, 0)?;
        io.phy_write32_mask(R_PATH1_BTG_PATH_V1, B_PATH1_BTG_PATH_V1, 0)?;
        io.phy_write32_mask(R_CHBW_MOD_V1, B_BT_SHARE, 0)?;
        io.phy_write32_mask(R_FC0_BW_V1, B_ANT_RX_BT_SEG0, 0)?;
        io.phy_write32_mask(R_BT_DYN_DC_EST_EN_V1, B_BT_DYN_DC_EST_EN_MSK, 0)?;
        io.phy_write32_mask(R_GNT_BT_WGT_EN, B_GNT_BT_WGT_EN, 0)?;
    }
    io.phy_write32_mask(R_MAC_PIN_SEL, B_CH_IDX_SEG0, chan.chan_idx().into())?;
    mask_5m(io, chan)?;
    if inputs.monitor {
        // rtw8852bx_bb_set_pop
        io.phy_write32_clr(R_PKT_CTRL, B_PKT_POP_EN)?;
    }
    bb_reset_all(io)
}

/// RF path A and B.
const RF_PATH_A: u8 = 0;
const RF_PATH_B: u8 = 1;
/// `INV_RF_DATA`.
const INV_RF_DATA: u32 = u32::MAX;
/// `_set_s0_arfc18`'s `read_poll_timeout_atomic(…, 1, 1000, …)`.
const LCK_STEP_US: u64 = 1;
const LCK_BOUND_US: u64 = 1000;

/// RF 0x18's bits `_ch_setting` and `_bw_setting` clear before setting
/// `RR_CFGCH_BW2`.
const CFGCH_CLEARED: u32 = !(RR_CFGCH_POW_LCK | RR_CFGCH_TRX_AH | RR_CFGCH_BCN | RR_CFGCH_BW2);

/// `rtw8852b_set_channel_rf(rtwdev, chan, RTW89_PHY_0)`:
/// `rtw8852b_ctrl_bw_ch`'s `_ctrl_ch`, `_ctrl_bw` and `_rxbb_bw`.
fn set_channel_rf<I: Io + ?Sized>(io: &mut I, chan: &Channel) -> Result<Tuned, io::Error> {
    let mut tuned = Tuned::default();
    for (path, dav) in [
        (RF_PATH_A, true),
        (RF_PATH_B, true),
        (RF_PATH_A, false),
        (RF_PATH_B, false),
    ] {
        ch_setting(io, &mut tuned, path, chan.center, dav)?;
    }
    for (path, dav) in [
        (RF_PATH_A, true),
        (RF_PATH_B, true),
        (RF_PATH_A, false),
        (RF_PATH_B, false),
    ] {
        bw_setting_rf(io, path, chan.width, dav)?;
    }
    // _rxbb_bw: _kpath is RF_AB without DBCC.
    for path in [RF_PATH_A, RF_PATH_B] {
        set_rxbb_bw(io, chan.width, path)?;
    }
    Ok(tuned)
}

/// `_ch_setting(rtwdev, path, central_ch, dav)`.
fn ch_setting<I: Io + ?Sized>(
    io: &mut I,
    tuned: &mut Tuned,
    path: u8,
    central_ch: u8,
    dav: bool,
) -> Result<(), io::Error> {
    let reg18 = if dav { RR_CFGCH } else { RR_CFGCH_V1 };
    let mut value = io.read_rf(path, reg18, RFREG_MASK)?;
    value &= !(RR_CFGCH_BAND1
        | RR_CFGCH_POW_LCK
        | RR_CFGCH_TRX_AH
        | RR_CFGCH_BCN
        | RR_CFGCH_BAND0
        | RR_CFGCH_CH);
    value |= prep(central_ch.into(), RR_CFGCH_CH);
    if central_ch > 14 {
        value |= prep(CFGCH_BAND1_5G, RR_CFGCH_BAND1) | prep(CFGCH_BAND0_5G, RR_CFGCH_BAND0);
    }
    value &= CFGCH_CLEARED & RFREG_MASK;
    value |= RR_CFGCH_BW2;
    if path == RF_PATH_A && dav {
        // _set_ch
        if set_s0_arfc18(io, tuned, value)? {
            lck_check(io, tuned)?;
        }
    } else {
        io.write_rf(path, reg18, RFREG_MASK, value)?;
    }
    io.write_rf(path, RR_LCKST, RR_LCKST_BIN, 0)?;
    io.write_rf(path, RR_LCKST, RR_LCKST_BIN, 1)?;
    // Its debug line's read.
    io.read_rf(path, reg18, RFREG_MASK)?;
    Ok(())
}

/// `_set_s0_arfc18(rtwdev, val)`: whether the LPF went idle in time (rtw89
/// returns the opposite, whether it timed out).
fn set_s0_arfc18<I: Io + ?Sized>(
    io: &mut I,
    tuned: &mut Tuned,
    value: u32,
) -> Result<bool, io::Error> {
    let backup = io.read_rf(RF_PATH_A, RR_LDO, RFREG_MASK)?;
    io.write_rf(RF_PATH_A, RR_LDO, RR_LDO_SEL, 1)?;
    io.write_rf(RF_PATH_A, RR_CFGCH, RFREG_MASK, value)?;
    let mut waited = 0;
    let idle = loop {
        if io.read_rf(RF_PATH_A, RR_LPF, RR_LPF_BUSY)? == 0 {
            break true;
        }
        if waited >= LCK_BOUND_US {
            break false;
        }
        io.delay_us(LCK_STEP_US);
        waited += LCK_STEP_US;
    };
    if !idle {
        tuned.lck_timeouts = tuned.lck_timeouts.saturating_add(1);
    }
    io.write_rf(RF_PATH_A, RR_LDO, RFREG_MASK, backup)?;
    Ok(idle)
}

/// Whether S0's synthesizer reads locked (`RR_SYNFB_LK`).
fn locked<I: Io + ?Sized>(io: &mut I) -> Result<bool, io::Error> {
    Ok(io.read_rf(RF_PATH_A, RR_SYNFB, RR_SYNFB_LK)? != 0)
}

/// `_lck_check`: while S0's synthesizer reads unlocked, the MMD reset, RF
/// 0x18 written again, then the synthesizer turned off and on.
fn lck_check<I: Io + ?Sized>(io: &mut I, tuned: &mut Tuned) -> Result<(), io::Error> {
    if !locked(io)? {
        // "[LCK]SYN MMD reset"
        io.write_rf(RF_PATH_A, RR_MMD, RR_MMD_RST_EN, 1)?;
        io.write_rf(RF_PATH_A, RR_MMD, RR_MMD_RST_SYN, 0)?;
        io.write_rf(RF_PATH_A, RR_MMD, RR_MMD_RST_SYN, 1)?;
        io.write_rf(RF_PATH_A, RR_MMD, RR_MMD_RST_EN, 0)?;
    }
    io.delay_us(10);
    if !locked(io)? {
        // "[LCK]re-set RF 0x18"
        rewrite_cfgch(io, tuned)?;
    }
    if !locked(io)? {
        // "[LCK]SYN off/on"
        let value = io.read_rf(RF_PATH_A, RR_POW, RFREG_MASK)?;
        io.write_rf(RF_PATH_A, RR_POW, RFREG_MASK, value)?;
        let value = io.read_rf(RF_PATH_A, RR_SX, RFREG_MASK)?;
        io.write_rf(RF_PATH_A, RR_SX, RFREG_MASK, value)?;
        io.write_rf(RF_PATH_A, RR_SYNLUT, RR_SYNLUT_MOD, 1)?;
        io.write_rf(RF_PATH_A, RR_POW, RR_POW_SYN, 0)?;
        io.write_rf(RF_PATH_A, RR_POW, RR_POW_SYN, 3)?;
        io.write_rf(RF_PATH_A, RR_SYNLUT, RR_SYNLUT_MOD, 0)?;
        rewrite_cfgch(io, tuned)?;
        // Its debug line's reads, left to right.
        io.read_rf(RF_PATH_A, RR_VCO, RFREG_MASK)?;
        io.read_rf(RF_PATH_A, RR_SYNFB, RFREG_MASK)?;
    }
    Ok(())
}

/// `_lck_check`'s LCK trigger around S0's RF 0x18 written as it reads.
fn rewrite_cfgch<I: Io + ?Sized>(io: &mut I, tuned: &mut Tuned) -> Result<(), io::Error> {
    io.write_rf(RF_PATH_A, RR_LCK_TRG, RR_LCK_TRGSEL, 1)?;
    let value = io.read_rf(RF_PATH_A, RR_CFGCH, RFREG_MASK)?;
    set_s0_arfc18(io, tuned, value)?;
    io.write_rf(RF_PATH_A, RR_LCK_TRG, RR_LCK_TRGSEL, 0)
}

/// `_bw_setting(rtwdev, path, bw, dav)`.
fn bw_setting_rf<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    bw: Width,
    dav: bool,
) -> Result<(), io::Error> {
    let reg18 = if dav { RR_CFGCH } else { RR_CFGCH_V1 };
    let mut value = io.read_rf(path, reg18, RFREG_MASK)?;
    if value == INV_RF_DATA {
        return Ok(());
    }
    value &= !RR_CFGCH_BW;
    value |= prep(
        match bw {
            Width::Mhz20 => CFGCH_BW_20M,
            Width::Mhz40 => CFGCH_BW_40M,
            Width::Mhz80 => CFGCH_BW_80M,
        },
        RR_CFGCH_BW,
    );
    value &= CFGCH_CLEARED & RFREG_MASK;
    value |= RR_CFGCH_BW2;
    io.write_rf(path, reg18, RFREG_MASK, value)?;
    // Its debug line's read.
    io.read_rf(path, reg18, RFREG_MASK)?;
    Ok(())
}

/// `_set_rxbb_bw(rtwdev, bw, path)`.
fn set_rxbb_bw<I: Io + ?Sized>(io: &mut I, bw: Width, path: u8) -> Result<(), io::Error> {
    io.write_rf(path, RR_LUTWE2, RR_LUTWE2_RTXBW, 1)?;
    io.write_rf(path, RR_LUTWA, RR_LUTWA_M2, 0x12)?;
    let lb = match bw {
        Width::Mhz20 => 0x1b,
        Width::Mhz40 => 0x13,
        Width::Mhz80 => 0xb,
    };
    io.write_rf(path, RR_LUTWD0, RR_LUTWD0_LB, lb)?;
    // Its debug line's read.
    io.read_rf(path, RR_LUTWD0, RR_LUTWD0_LB)?;
    io.write_rf(path, RR_LUTWE2, RR_LUTWE2_RTXBW, 0)
}

#[cfg(test)]
mod tests;
