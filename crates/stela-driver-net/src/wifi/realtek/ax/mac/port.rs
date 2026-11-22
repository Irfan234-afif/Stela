// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! A port's MAC configuration on an RTL8852B, as pinned rtw89 writes it:
//! [`update`] is `rtw89_mac_port_update` (mac.c) through
//! `rtw89_port_base_ax`, with the `rtw89_mac_port_cfg_*` steps in its order,
//! and [`dmac_tbl_init`] and [`cmac_tbl_init`] are `rtw89_mac_dmac_tbl_init`
//! and `rtw89_mac_cmac_tbl_init`, which `rtw89_mac_vif_init` runs after it.
//!
//! What a [`Port`] holds is what those steps read of `rtw89_vif_link` and
//! its `ieee80211_bss_conf`: the port, the network type, the beacon
//! interval, the DTIM period and the BSS color. Every link here is band 0
//! (`RTW89_MAC_0`), where `rtw89_mac_reg_by_idx` leaves each register as it
//! is.
//!
//! What this leaves out, and why:
//! - `rtw89_mac_bcn_drop` in the first step, and the AP's beacon window and
//!   TX: a station's network type is never `RTW89_NET_TYPE_AP_MODE`.
//! - `rtw89_mac_port_tsf_resync_all`: with no AP among the links it returns
//!   before touching a register, and a station is the only link here.
//! - RTL8852A's TBTT backup and early-interrupt clears: not this chip.
//! - The secure-boot check of the table inits: stage 1 refuses a chip whose
//!   efuse asks for secure boot, so rtw89's `sec->secure_boot` is false.
//!
//! A port written proves only that the registers took the values: whether
//! the chip then filters by BSSID or syncs its TSF to the AP's beacons is
//! not observable here.
use super::super::{
    io::{self, Io, Registers, prep},
    registers::*,
};

/// `RTW89_PORT_NUM`.
pub const PORT_NUM: u8 = 5;
/// `RTW89_NET_TYPE_*`.
pub const NET_TYPE_NO_LINK: u8 = 0;
pub const NET_TYPE_AD_HOC: u8 = 1;
pub const NET_TYPE_INFRA: u8 = 2;
pub const NET_TYPE_AP_MODE: u8 = 3;
/// mac.c's `BCN_INTERVAL`, `BCN_ERLY_DEF`, `BCN_SETUP_DEF`, `BCN_HOLD_DEF`,
/// `BCN_MASK_DEF`, `TBTT_ERLY_DEF`, `TBTT_AGG_DEF` and `BCN_ERLY_SET_DLY`
/// (microseconds).
pub const BCN_INTERVAL: u16 = 100;
pub const BCN_ERLY_DEF: u32 = 160;
pub const BCN_SETUP_DEF: u32 = 2;
pub const BCN_HOLD_DEF: u32 = 200;
pub const BCN_MASK_DEF: u32 = 0;
pub const TBTT_ERLY_DEF: u16 = 5;
pub const TBTT_AGG_DEF: u16 = 1;
pub const BCN_ERLY_SET_DLY_US: u64 = 10 * 2;

/// What `rtw89_mac_port_update` reads of a link.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Port {
    /// `rtwvif_link->port`.
    pub port: u8,
    /// `rtwvif_link->net_type`, an `RTW89_NET_TYPE_*`.
    pub net_type: u8,
    /// `bss_conf->beacon_int`, 0 before the BSS is known.
    pub beacon_int: u16,
    /// `bss_conf->dtim_period`.
    pub dtim_period: u8,
    /// `bss_conf->he_bss_color.color`.
    pub bss_color: u8,
}

/// Why a port was not written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `rtw89_mac_port_update`'s `-EINVAL`: no such port.
    Port(u8),
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Port {
    /// `rtw89_mac_reg_by_port` on band 0.
    const fn reg(&self, base: u32) -> u32 {
        base + self.port as u32 * 0x40
    }

    fn set<I: Io + ?Sized>(
        &self,
        io: &mut I,
        base: u32,
        bits: u32,
        en: bool,
    ) -> Result<(), io::Error> {
        if en {
            io.write32_set(self.reg(base), bits)
        } else {
            io.write32_clr(self.reg(base), bits)
        }
    }
}

/// `rtw89_mac_port_update` on band 0, its steps in rtw89's order.
pub fn update<I: Io + ?Sized>(io: &mut I, port: &Port) -> Result<(), Error> {
    if port.port >= PORT_NUM {
        return Err(Error::Port(port.port));
    }
    let p = port;
    let infra_or_adhoc = p.net_type == NET_TYPE_INFRA || p.net_type == NET_TYPE_AD_HOC;
    // rtw89_mac_port_cfg_func_sw
    if io.read32_mask(p.reg(PORT_CFG_P0), PORT_FUNC_EN)? != 0 {
        io.delay_us((u64::from(p.beacon_int) + 1) * 1000);
        io.write32_clr(p.reg(PORT_CFG_P0), PORT_FUNC_EN | BRK_SETUP)?;
        io.write32_set(p.reg(PORT_CFG_P0), TSFTR_RST)?;
        io.write32(p.reg(BCN_CNT_TMR_P0), 0)?;
    }
    // rtw89_mac_port_cfg_tx_rpt and _rx_rpt, both off.
    p.set(io, PORT_CFG_P0, TXBCN_RPT_EN, false)?;
    p.set(io, PORT_CFG_P0, RXBCN_RPT_EN, false)?;
    // rtw89_mac_port_cfg_net_type
    io.write32_mask(p.reg(PORT_CFG_P0), NET_TYPE_MASK, p.net_type.into())?;
    // rtw89_mac_port_cfg_bcn_prct
    p.set(
        io,
        PORT_CFG_P0,
        TBTT_PROHIB_EN | BRK_SETUP,
        p.net_type != NET_TYPE_NO_LINK,
    )?;
    // rtw89_mac_port_cfg_rx_sw, _rx_sync_by_nettype, _tx_sw_by_nettype
    p.set(io, PORT_CFG_P0, RX_BSSID_FIT_EN, infra_or_adhoc)?;
    p.set(io, PORT_CFG_P0, TSF_UDT_EN, infra_or_adhoc)?;
    p.set(
        io,
        PORT_CFG_P0,
        BCNTX_EN,
        p.net_type == NET_TYPE_AP_MODE || p.net_type == NET_TYPE_AD_HOC,
    )?;
    // rtw89_mac_port_cfg_bcn_intv
    let bcn_int = if p.beacon_int != 0 {
        p.beacon_int
    } else {
        BCN_INTERVAL
    };
    io.write32_mask(p.reg(BCN_SPACE_CFG_P0), BCN_SPACE_MASK, bcn_int.into())?;
    // rtw89_mac_port_cfg_hiq_win
    let hiq_win = [
        P0MB_HGQ_WINDOW_CFG_0,
        PORT_HGQ_WINDOW_CFG,
        PORT_HGQ_WINDOW_CFG + 1,
        PORT_HGQ_WINDOW_CFG + 2,
        PORT_HGQ_WINDOW_CFG + 3,
    ];
    let win = if p.net_type == NET_TYPE_AP_MODE {
        16
    } else {
        0
    };
    io.write8(hiq_win[usize::from(p.port)], win)?;
    // rtw89_mac_port_cfg_hiq_dtim
    io.write8_set(MD_TSFT_STMP_CTL, UPD_HGQMD | UPD_TIMIE)?;
    io.write16_mask(p.reg(DTIM_CTRL_P0), DTIM_NUM_MASK, p.dtim_period.into())?;
    // rtw89_mac_port_cfg_hiq_drop
    let mut value = io.read32(MBSSID_DROP_0)?;
    value &= !prep(1 << p.port, PORT_DROP_4_0_MASK);
    if p.port == 0 {
        value &= !1;
    }
    io.write32(MBSSID_DROP_0, value)?;
    // rtw89_mac_port_cfg_bcn_setup_time, _hold_time, _mask_area,
    // _tbtt_early and _tbtt_agg
    io.write32_mask(p.reg(TBTT_PROHIB_P0), TBTT_SETUP_MASK, BCN_SETUP_DEF)?;
    io.write32_mask(p.reg(TBTT_PROHIB_P0), TBTT_HOLD_MASK, BCN_HOLD_DEF)?;
    io.write32_mask(p.reg(BCN_AREA_P0), BCN_MSK_AREA_MASK, BCN_MASK_DEF)?;
    io.write16_mask(p.reg(TBTTERLYINT_CFG_P0), TBTTERLY_MASK, TBTT_ERLY_DEF)?;
    io.write16_mask(p.reg(TBTT_AGG_P0), TBTT_AGG_NUM_MASK, TBTT_AGG_DEF)?;
    // rtw89_mac_port_cfg_bss_color
    let color_reg = if p.port >= 4 {
        PTCL_BSS_COLOR_0 + 4
    } else {
        PTCL_BSS_COLOR_0
    };
    io.write32_mask(
        color_reg,
        BSS_COLOR_PORT_MASKS[usize::from(p.port)],
        p.bss_color.into(),
    )?;
    // rtw89_mac_port_cfg_mbssid
    if p.net_type != NET_TYPE_AP_MODE && p.port == 0 {
        io.write32_clr(MBSSID_CTRL, P0MB_ALL_MASK)?;
    }
    // rtw89_mac_port_cfg_func_en(rtwdev, rtwvif_link, true)
    p.set(io, PORT_CFG_P0, PORT_FUNC_EN, true)?;
    // rtw89_mac_port_tsf_resync_all: no AP, nothing written.
    io.delay_us(BCN_ERLY_SET_DLY_US);
    // rtw89_mac_port_cfg_bcn_early
    io.write32_mask(p.reg(BCNERLYINT_CFG_P0), BCNERLY_MASK, BCN_ERLY_DEF)?;
    // rtw89_mac_port_cfg_bcn_psr_rpt: a transmitted BSSID's index is 0.
    io.write32_mask(BCN_PSR_RPT_P0 + u32::from(p.port) * 4, BCAID_P0_MASK, 0)?;
    Ok(())
}

/// `rtw89_mac_dmac_tbl_init`: MAC ID `macid`'s four DMAC table words
/// zeroed through the indirect window.
pub fn dmac_tbl_init<I: Io + ?Sized>(io: &mut I, macid: u8) -> Result<(), io::Error> {
    for i in 0..4 {
        io.write32(
            FILTER_MODEL_ADDR,
            DMAC_TBL_BASE_ADDR + (u32::from(macid) << 4) + (i << 2),
        )?;
        io.write32(INDIR_ACCESS_ENTRY, 0)?;
    }
    Ok(())
}

/// The eight words `rtw89_mac_cmac_tbl_init` writes, as rtw89 spells them.
pub const CMAC_TBL_INIT: [u32; 8] = [0x4, 0x400a_0004, 0, 0, 0, 0x0e43_000b, 0, 0x000b_8109];

/// `rtw89_mac_cmac_tbl_init`: MAC ID `macid`'s CMAC table set to
/// [`CMAC_TBL_INIT`] through the indirect window.
pub fn cmac_tbl_init<I: Io + ?Sized>(io: &mut I, macid: u8) -> Result<(), io::Error> {
    io.write32(
        FILTER_MODEL_ADDR,
        CMAC_TBL_BASE_ADDR + u32::from(macid) * CCTL_INFO_SIZE,
    )?;
    for (i, word) in (0u32..).zip(CMAC_TBL_INIT) {
        io.write32(INDIR_ACCESS_ENTRY + 4 * i, word)?;
    }
    Ok(())
}
