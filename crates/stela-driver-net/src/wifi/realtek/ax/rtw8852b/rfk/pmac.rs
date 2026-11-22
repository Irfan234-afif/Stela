// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2024 Realtek Corporation
//! The BB helpers of pinned rtw89/rtw8852b_common.c that TSSI's alignment
//! reaches through `rtw8852bx_info`, line by line: the PLCP of an HT20
//! MCS7 packet, the PMAC packet TX, its power and TX path, the RX path,
//! the backup and restore of what they change, and the TX mode switch
//! back. They run with PHY 0 and DBCC off, where `rtw89_phy_write32_idx`
//! and `rtw89_phy_read32_idx` are the plain BB accesses. That the writes
//! were made is all a return proves; nothing here sees a packet leave.
use super::super::channel;
use super::{Band, Channel, RF_AB, RF_PATH_A, RF_PATH_B, reg::*, tssi::subband};
use crate::wifi::realtek::ax::{
    io::{Error, Io, Registers},
    registers::MASKDWORD,
};

/// `enum rtw89_rf_path`'s `RF_PATH_AB` and `RF_PATH_ABCD`.
pub const RF_PATH_AB: u8 = 4;
pub const RF_PATH_ABCD: u8 = 14;
/// `enum rtw89_rf_path_bit`'s `RF_A`, `RF_B` and `RF_ABCD`.
pub const RF_A: u8 = 0b0001;
pub const RF_B: u8 = 0b0010;
pub const RF_ABCD: u8 = 0b1111;

/// `rtw8852bx_pmac_ht20_mcs7_tbl`: `{addr, mask, data}`.
const PMAC_HT20_MCS7: [(u32, u32, u32); 120] = [
    (0x4580, 0x0000ffff, 0x0),
    (0x4580, 0xffff0000, 0x0),
    (0x4584, 0x0000ffff, 0x0),
    (0x4584, 0xffff0000, 0x0),
    (0x4580, 0x0000ffff, 0x1),
    (0x4578, 0x00ffffff, 0x2018b),
    (0x4570, 0x03ffffff, 0x7),
    (0x4574, 0x03ffffff, 0x32407),
    (0x45b8, 0x00000010, 0x0),
    (0x45b8, 0x00000100, 0x0),
    (0x45b8, 0x00000080, 0x0),
    (0x45b8, 0x00000008, 0x0),
    (0x45a0, 0x0000ff00, 0x0),
    (0x45a0, 0xff000000, 0x1),
    (0x45a4, 0x0000ff00, 0x2),
    (0x45a4, 0xff000000, 0x3),
    (0x45b8, 0x00000020, 0x0),
    (0x4568, 0xe0000000, 0x0),
    (0x45b8, 0x00000002, 0x1),
    (0x456c, 0xe0000000, 0x0),
    (0x45b4, 0x00006000, 0x0),
    (0x45b4, 0x00001800, 0x1),
    (0x45b8, 0x00000040, 0x0),
    (0x45b8, 0x00000004, 0x0),
    (0x45b8, 0x00000200, 0x0),
    (0x4598, 0xf8000000, 0x0),
    (0x45b8, 0x00100000, 0x0),
    (0x45a8, 0x00000fc0, 0x0),
    (0x45b8, 0x00200000, 0x0),
    (0x45b0, 0x00000038, 0x0),
    (0x45b0, 0x000001c0, 0x0),
    (0x45a0, 0x000000ff, 0x0),
    (0x45b8, 0x00400000, 0x0),
    (0x4590, 0x000007ff, 0x0),
    (0x45b0, 0x00000e00, 0x0),
    (0x45ac, 0x0000001f, 0x0),
    (0x45b8, 0x00800000, 0x0),
    (0x45a8, 0x0003f000, 0x0),
    (0x45b8, 0x01000000, 0x0),
    (0x45b0, 0x00007000, 0x0),
    (0x45b0, 0x00038000, 0x0),
    (0x45a0, 0x00ff0000, 0x0),
    (0x45b8, 0x02000000, 0x0),
    (0x4590, 0x003ff800, 0x0),
    (0x45b0, 0x001c0000, 0x0),
    (0x45ac, 0x000003e0, 0x0),
    (0x45b8, 0x04000000, 0x0),
    (0x45a8, 0x00fc0000, 0x0),
    (0x45b8, 0x08000000, 0x0),
    (0x45b0, 0x00e00000, 0x0),
    (0x45b0, 0x07000000, 0x0),
    (0x45a4, 0x000000ff, 0x0),
    (0x45b8, 0x10000000, 0x0),
    (0x4594, 0x000007ff, 0x0),
    (0x45b0, 0x38000000, 0x0),
    (0x45ac, 0x00007c00, 0x0),
    (0x45b8, 0x20000000, 0x0),
    (0x45a8, 0x3f000000, 0x0),
    (0x45b8, 0x40000000, 0x0),
    (0x45b4, 0x00000007, 0x0),
    (0x45b4, 0x00000038, 0x0),
    (0x45a4, 0x00ff0000, 0x0),
    (0x45b8, 0x80000000, 0x0),
    (0x4594, 0x003ff800, 0x0),
    (0x45b4, 0x000001c0, 0x0),
    (0x4598, 0xf8000000, 0x0),
    (0x45b8, 0x00100000, 0x0),
    (0x45a8, 0x00000fc0, 0x7),
    (0x45b8, 0x00200000, 0x0),
    (0x45b0, 0x00000038, 0x0),
    (0x45b0, 0x000001c0, 0x0),
    (0x45a0, 0x000000ff, 0x0),
    (0x45b4, 0x06000000, 0x0),
    (0x45b0, 0x00000007, 0x0),
    (0x45b8, 0x00080000, 0x0),
    (0x45a8, 0x0000003f, 0x0),
    (0x457c, 0xffe00000, 0x1),
    (0x4530, 0xffffffff, 0x0),
    (0x4588, 0x00003fff, 0x0),
    (0x4598, 0x000001ff, 0x0),
    (0x4534, 0xffffffff, 0x0),
    (0x4538, 0xffffffff, 0x0),
    (0x453c, 0xffffffff, 0x0),
    (0x4588, 0x0fffc000, 0x0),
    (0x4598, 0x0003fe00, 0x0),
    (0x4540, 0xffffffff, 0x0),
    (0x4544, 0xffffffff, 0x0),
    (0x4548, 0xffffffff, 0x0),
    (0x458c, 0x00003fff, 0x0),
    (0x4598, 0x07fc0000, 0x0),
    (0x454c, 0xffffffff, 0x0),
    (0x4550, 0xffffffff, 0x0),
    (0x4554, 0xffffffff, 0x0),
    (0x458c, 0x0fffc000, 0x0),
    (0x459c, 0x000001ff, 0x0),
    (0x4558, 0xffffffff, 0x0),
    (0x455c, 0xffffffff, 0x0),
    (0x4530, 0xffffffff, 0x4e790001),
    (0x4588, 0x00003fff, 0x0),
    (0x4598, 0x000001ff, 0x1),
    (0x4534, 0xffffffff, 0x0),
    (0x4538, 0xffffffff, 0x4b),
    (0x45ac, 0x38000000, 0x7),
    (0x4588, 0xf0000000, 0x0),
    (0x459c, 0x7e000000, 0x0),
    (0x45b8, 0x00040000, 0x0),
    (0x45b8, 0x00020000, 0x0),
    (0x4590, 0xffc00000, 0x0),
    (0x45b8, 0x00004000, 0x0),
    (0x4578, 0xff000000, 0x0),
    (0x45b8, 0x00000400, 0x0),
    (0x45b8, 0x00000800, 0x0),
    (0x45b8, 0x00001000, 0x0),
    (0x45b8, 0x00002000, 0x0),
    (0x45b4, 0x00018000, 0x0),
    (0x45ac, 0x07800000, 0x0),
    (0x45b4, 0x00000600, 0x2),
    (0x459c, 0x0001fe00, 0x80),
    (0x45ac, 0x00078000, 0x3),
    (0x459c, 0x01fe0000, 0x1),
];

/// `struct rtw8852bx_bb_tssi_bak`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TssiBak {
    pub tx_path: u8,
    pub rx_path: u8,
    pub p0_rfmode: u32,
    pub p0_rfmode_ftm: u32,
    pub p1_rfmode: u32,
    pub p1_rfmode_ftm: u32,
    /// S9.
    pub tx_pwr: i16,
}

/// `sign_extend32(value, index)`.
pub(crate) const fn sign_extend32(value: u32, index: u32) -> i32 {
    let shift = 31 - index;
    ((value << shift) as i32) >> shift
}

/// `__rtw8852bx_bb_set_plcp_tx`.
pub fn set_plcp_tx<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    for (address, mask, data) in PMAC_HT20_MCS7 {
        io.phy_write32_mask(address, mask, data)?;
    }
    Ok(())
}

/// `__rtw8852bx_bb_set_pmac_pkt_tx(rtwdev, enable, tx_cnt, period, …,
/// RTW89_PHY_0, chan)`: `rtw8852bx_bb_set_pmac_tx` with `PKTS_TX` and not
/// CCK, which stops the packets or starts `tx_cnt` of them every `period`.
pub fn set_pmac_pkt_tx<I: Io + ?Sized>(
    io: &mut I,
    enable: bool,
    tx_cnt: u16,
    period: u16,
    channel: Channel,
) -> Result<(), Error> {
    if !enable {
        // rtw8852bx_stop_pmac_tx, PKTS_TX
        io.phy_write32_mask(R_PMAC_TX_PRD, B_PMAC_PTX_EN, 0)?;
        io.phy_write32_mask(R_PD_CTRL, B_PD_HIT_DIS, 0)?;
        if channel.band == Band::Ghz2 {
            io.phy_write32_clr(R_RXCCA, B_RXCCA_DIS)?;
        }
        return Ok(());
    }

    io.phy_write32_mask(R_PMAC_GNT, B_PMAC_GNT_TXEN, 1)?;
    io.phy_write32_mask(R_PMAC_GNT, B_PMAC_GNT_RXEN, 1)?;
    io.phy_write32_mask(R_PMAC_RX_CFG1, B_PMAC_OPT1_MSK, 0x3f)?;
    io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 0)?;
    io.phy_write32_mask(R_PD_CTRL, B_PD_HIT_DIS, 1)?;
    io.phy_write32_set(R_RXCCA, B_RXCCA_DIS)?;
    io.phy_write32_mask(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)?;

    // rtw8852bx_start_pmac_tx, PKTS_TX
    io.phy_write32_mask(R_PMAC_TX_PRD, B_PMAC_PTX_EN, 1)?;
    io.phy_write32_mask(R_PMAC_TX_PRD, B_PMAC_TX_PRD_MSK, period.into())?;
    io.phy_write32_mask(R_PMAC_TX_CNT, B_PMAC_TX_CNT_MSK, tx_cnt.into())?;
    io.phy_write32_mask(R_PMAC_TX_CTRL, B_PMAC_TXEN_DIS, 1)?;
    io.phy_write32_mask(R_PMAC_TX_CTRL, B_PMAC_TXEN_DIS, 0)
}

/// `__rtw8852bx_bb_set_power`.
pub fn set_power<I: Io + ?Sized>(io: &mut I, pwr_dbm: i16) -> Result<(), Error> {
    io.phy_write32_mask(R_MAC_SEL, B_MAC_SEL_PWR_EN, 1)?;
    io.phy_write32_mask(R_TXPWR, B_TXPWR_MSK, i32::from(pwr_dbm) as u32)
}

/// `__rtw8852bx_bb_cfg_tx_path`: `tx_path` is an `enum rtw89_rf_path`; one
/// that is not A, B or AB only sets the MAC select, where rtw89 logs "Error
/// Tx Path".
pub fn cfg_tx_path<I: Io + ?Sized>(io: &mut I, tx_path: u8) -> Result<(), Error> {
    io.phy_write32_mask(R_MAC_SEL, B_MAC_SEL_MOD, 7)?;

    let (sel, map) = match tx_path {
        RF_PATH_A => (1, 0),
        RF_PATH_B => (2, 0),
        RF_PATH_AB => (3, 4),
        _ => return Ok(()),
    };
    io.phy_write32_mask(R_TXPATH_SEL, B_TXPATH_SEL_MSK, sel)?;
    io.phy_write32_mask(R_TXNSS_MAP, B_TXNSS_MAP_MSK, map)
}

/// `__rtw8852bx_bb_tx_mode_switch`: mode 0 hands TX back from the PMAC.
pub fn tx_mode_switch<I: Io + ?Sized>(io: &mut I, mode: u8) -> Result<(), Error> {
    if mode != 0 {
        return Ok(());
    }

    io.phy_write32_mask(R_PMAC_GNT, B_PMAC_GNT_TXEN, 0)?;
    io.phy_write32_mask(R_PMAC_GNT, B_PMAC_GNT_RXEN, 0)?;
    io.phy_write32_mask(R_PMAC_RX_CFG1, B_PMAC_OPT1_MSK, 0)?;
    io.phy_write32_mask(R_PMAC_RXMOD, B_PMAC_RXMOD_MSK, 0)?;
    io.phy_write32_mask(R_MAC_SEL, B_MAC_SEL_DPD_EN, 0)?;
    io.phy_write32_mask(R_MAC_SEL, B_MAC_SEL_MOD, 0)?;
    io.phy_write32_mask(R_MAC_SEL, B_MAC_SEL_PWR_EN, 0)
}

/// `__rtw8852bx_bb_backup_tssi`.
pub fn backup_tssi<I: Io + ?Sized>(io: &mut I) -> Result<TssiBak, Error> {
    let tx_path = io.phy_read32_mask(R_TXPATH_SEL, B_TXPATH_SEL_MSK)? as u8;
    let rx_path = io.phy_read32_mask(R_CHBW_MOD_V1, B_ANT_RX_SEG0)? as u8;
    let p0_rfmode = io.phy_read32_mask(R_P0_RFMODE, MASKDWORD)?;
    let p0_rfmode_ftm = io.phy_read32_mask(R_P0_RFMODE_FTM_RX, MASKDWORD)?;
    let p1_rfmode = io.phy_read32_mask(R_P1_RFMODE, MASKDWORD)?;
    let p1_rfmode_ftm = io.phy_read32_mask(R_P1_RFMODE_FTM_RX, MASKDWORD)?;
    let tmp = io.phy_read32_mask(R_TXPWR, B_TXPWR_MSK)?;
    Ok(TssiBak {
        tx_path,
        rx_path,
        p0_rfmode,
        p0_rfmode_ftm,
        p1_rfmode,
        p1_rfmode_ftm,
        tx_pwr: sign_extend32(tmp, 8) as i16,
    })
}

/// `__rtw8852bx_bb_restore_tssi`.
pub fn restore_tssi<I: Io + ?Sized>(io: &mut I, bak: &TssiBak) -> Result<(), Error> {
    io.phy_write32_mask(R_TXPATH_SEL, B_TXPATH_SEL_MSK, bak.tx_path.into())?;
    if bak.tx_path == RF_AB {
        io.phy_write32_mask(R_TXNSS_MAP, B_TXNSS_MAP_MSK, 0x4)?;
    } else {
        io.phy_write32_mask(R_TXNSS_MAP, B_TXNSS_MAP_MSK, 0x0)?;
    }
    io.phy_write32_mask(R_CHBW_MOD_V1, B_ANT_RX_SEG0, bak.rx_path.into())?;
    io.phy_write32_mask(R_MAC_SEL, B_MAC_SEL_PWR_EN, 1)?;
    io.phy_write32_mask(R_P0_RFMODE, MASKDWORD, bak.p0_rfmode)?;
    io.phy_write32_mask(R_P0_RFMODE_FTM_RX, MASKDWORD, bak.p0_rfmode_ftm)?;
    io.phy_write32_mask(R_P1_RFMODE, MASKDWORD, bak.p1_rfmode)?;
    io.phy_write32_mask(R_P1_RFMODE_FTM_RX, MASKDWORD, bak.p1_rfmode_ftm)?;
    io.phy_write32_mask(R_TXPWR, B_TXPWR_MSK, i32::from(bak.tx_pwr) as u32)
}

/// `__rtw8852bx_ctrl_btg_bt_rx(rtwdev, en, RTW89_PHY_0)`.
fn ctrl_btg_bt_rx<I: Io + ?Sized>(io: &mut I, en: bool) -> Result<(), Error> {
    let writes: [(u32, u32, u32); 11] = if en {
        [
            (R_PATH0_BT_SHARE_V1, B_PATH0_BT_SHARE_V1, 0x1),
            (R_PATH0_BTG_PATH_V1, B_PATH0_BTG_PATH_V1, 0x0),
            (R_PATH1_G_LNA6_OP1DB_V1, B_PATH1_G_LNA6_OP1DB_V1, 0x20),
            (
                R_PATH1_G_TIA0_LNA6_OP1DB_V1,
                B_PATH1_G_TIA0_LNA6_OP1DB_V1,
                0x30,
            ),
            (R_PATH1_BT_SHARE_V1, B_PATH1_BT_SHARE_V1, 0x1),
            (R_PATH1_BTG_PATH_V1, B_PATH1_BTG_PATH_V1, 0x1),
            (R_PMAC_GNT, B_PMAC_GNT_P1, 0x0),
            (R_CHBW_MOD_V1, B_BT_SHARE, 0x1),
            (R_FC0_BW_V1, B_ANT_RX_BT_SEG0, 0x2),
            (R_BT_DYN_DC_EST_EN_V1, B_BT_DYN_DC_EST_EN_MSK, 0x1),
            (R_GNT_BT_WGT_EN, B_GNT_BT_WGT_EN, 0x1),
        ]
    } else {
        [
            (R_PATH0_BT_SHARE_V1, B_PATH0_BT_SHARE_V1, 0x0),
            (R_PATH0_BTG_PATH_V1, B_PATH0_BTG_PATH_V1, 0x0),
            (R_PATH1_G_LNA6_OP1DB_V1, B_PATH1_G_LNA6_OP1DB_V1, 0x1a),
            (
                R_PATH1_G_TIA0_LNA6_OP1DB_V1,
                B_PATH1_G_TIA0_LNA6_OP1DB_V1,
                0x2a,
            ),
            (R_PATH1_BT_SHARE_V1, B_PATH1_BT_SHARE_V1, 0x0),
            (R_PATH1_BTG_PATH_V1, B_PATH1_BTG_PATH_V1, 0x0),
            (R_PMAC_GNT, B_PMAC_GNT_P1, 0xc),
            (R_CHBW_MOD_V1, B_BT_SHARE, 0x0),
            (R_FC0_BW_V1, B_ANT_RX_BT_SEG0, 0x0),
            (R_BT_DYN_DC_EST_EN_V1, B_BT_DYN_DC_EST_EN_MSK, 0x1),
            (R_GNT_BT_WGT_EN, B_GNT_BT_WGT_EN, 0x0),
        ]
    };
    for (address, mask, data) in writes {
        io.phy_write32_mask(address, mask, data)?;
    }
    Ok(())
}

/// `__rtw8852bx_bb_ctrl_rx_path`: `rx_path` is an `enum
/// rtw89_rf_path_bit`. The gain offsets are `gain`'s, as a channel switch
/// takes them, for the subband of `channel`.
pub fn ctrl_rx_path<I: Io + ?Sized>(
    io: &mut I,
    rx_path: u8,
    channel: Channel,
    gain: &channel::Inputs,
) -> Result<(), Error> {
    let settings = match rx_path {
        RF_A => Some((1, 0, 0)),
        RF_B => Some((2, 0, 0)),
        RF_AB => Some((3, 1, 1)),
        _ => None,
    };
    if let Some((ant, mcs, nss)) = settings {
        io.phy_write32_mask(R_CHBW_MOD_V1, B_ANT_RX_SEG0, ant)?;
        io.phy_write32_mask(R_FC0_BW_V1, B_ANT_RX_1RCCA_SEG0, ant)?;
        io.phy_write32_mask(R_FC0_BW_V1, B_ANT_RX_1RCCA_SEG1, ant)?;
        io.phy_write32_mask(R_RXHT_MCS_LIMIT, B_RXHT_MCS_LIMIT, mcs)?;
        io.phy_write32_mask(R_RXVHT_MCS_LIMIT, B_RXVHT_MCS_LIMIT, mcs)?;
        io.phy_write32_mask(R_RXHE, B_RXHE_USER_MAX, 4)?;
        io.phy_write32_mask(R_RXHE, B_RXHE_MAX_NSS, nss)?;
        io.phy_write32_mask(R_RXHE, B_RXHETB_MAX_NSS, nss)?;
    }

    channel::set_gain_offset(io, gain, subband(channel))?;

    ctrl_btg_bt_rx(
        io,
        channel.band == Band::Ghz2 && (rx_path == RF_B || rx_path == RF_AB),
    )?;

    let rst_mask0 = B_P0_TXPW_RSTB_MANON | B_P0_TXPW_RSTB_TSSI;
    let rst_mask1 = B_P1_TXPW_RSTB_MANON | B_P1_TXPW_RSTB_TSSI;
    if rx_path == RF_A {
        io.phy_write32_mask(R_P0_TXPW_RSTB, rst_mask0, 1)?;
        io.phy_write32_mask(R_P0_TXPW_RSTB, rst_mask0, 3)
    } else {
        io.phy_write32_mask(R_P1_TXPW_RSTB, rst_mask1, 1)?;
        io.phy_write32_mask(R_P1_TXPW_RSTB, rst_mask1, 3)
    }
}
