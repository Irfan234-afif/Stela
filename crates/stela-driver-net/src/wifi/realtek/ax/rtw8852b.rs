// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2022 Realtek Corporation
//! What is RTL8852B's own in pinned rtw89, beside the AX generation's shared
//! layers: its RF calibration tables ([`rfk`]), its efuse layout and readers
//! ([`efuse`]), the values its power functions and chip info give
//! [`super::power`], and the PCIe HCI flow control and DLE tables its chip
//! info gives [`super::dle`].
use super::{
    dle::{
        ChipQuota, DMA_CH_NUM, DleMem, GRP_0, HcifcMode, HfcChCfg, HfcParamIni, HfcPubCfg, QTA_NUM,
        QtaMode, mac_size,
    },
    registers::SCOREBOARD,
};

pub mod efuse;
pub mod rfk;

/// `RTL8852B_RFE_05_SPS_ANA`: what `rtw8852b_pwr_sps_ana` writes to
/// `R_AX_SPS_ANA_ON_CTRL2` on a board of RFE type 5.
pub const RTL8852B_RFE_05_SPS_ANA: u16 = 0x4a82;

/// `rtw8852b_chip_info.btc_sb`: each scoreboard entry's `cfg` register, 0
/// for an entry the chip leaves unset.
pub const BTC_SB_CFG: [u32; 2] = [SCOREBOARD, 0];

/// `rtw8852b_hfc_chcfg_pcie`: `{min, max, grp}` for ACH0 to FWCMDQ.
pub const RTW8852B_HFC_CHCFG_PCIE: [HfcChCfg; DMA_CH_NUM] = [
    HfcChCfg::new(5, 341, GRP_0), // ACH 0
    HfcChCfg::new(5, 341, GRP_0), // ACH 1
    HfcChCfg::new(4, 342, GRP_0), // ACH 2
    HfcChCfg::new(4, 342, GRP_0), // ACH 3
    HfcChCfg::new(0, 0, GRP_0),   // ACH 4
    HfcChCfg::new(0, 0, GRP_0),   // ACH 5
    HfcChCfg::new(0, 0, GRP_0),   // ACH 6
    HfcChCfg::new(0, 0, GRP_0),   // ACH 7
    HfcChCfg::new(4, 342, GRP_0), // B0MGQ
    HfcChCfg::new(4, 342, GRP_0), // B0HIQ
    HfcChCfg::new(0, 0, GRP_0),   // B1MGQ
    HfcChCfg::new(0, 0, GRP_0),   // B1HIQ
    HfcChCfg::new(40, 0, 0),      // FWCMDQ
];

/// `rtw8852b_hfc_pubcfg_pcie`.
pub const RTW8852B_HFC_PUBCFG_PCIE: HfcPubCfg = HfcPubCfg {
    grp0: 446,
    grp1: 0,
    pub_max: 446,
    wp_thrd: 0,
};

/// `rtw8852b_hfc_param_ini_pcie`, indexed by [`QtaMode`]; the entries rtw89
/// leaves out are `{NULL}`.
pub const RTW8852B_HFC_PARAM_INI_PCIE: [HfcParamIni; QTA_NUM] = [
    // RTW89_QTA_SCC
    HfcParamIni {
        ch_cfg: Some(&RTW8852B_HFC_CHCFG_PCIE),
        pub_cfg: Some(&RTW8852B_HFC_PUBCFG_PCIE),
        prec_cfg: Some(&mac_size::HFC_PRECCFG_PCIE),
        mode: HcifcMode::Poh,
    },
    // RTW89_QTA_DBCC
    HfcParamIni::NULL,
    // RTW89_QTA_DLFW
    HfcParamIni {
        ch_cfg: None,
        pub_cfg: None,
        prec_cfg: Some(&mac_size::HFC_PRECCFG_PCIE),
        mode: HcifcMode::Poh,
    },
    // RTW89_QTA_WOW
    HfcParamIni::NULL,
    // RTW89_QTA_INVALID
    HfcParamIni::NULL,
];

/// `rtw8852b_dle_mem_pcie`, indexed by [`QtaMode`]. `None` stands for an
/// entry whose sizes and quotas are NULL: DBCC, which rtw89 leaves zeroed
/// (its mode then reads SCC, so `get_dle_mem_cfg` refuses it), and INVALID.
pub const RTW8852B_DLE_MEM_PCIE: [Option<DleMem>; QTA_NUM] = [
    Some(DleMem {
        mode: QtaMode::Scc,
        wde_size: &mac_size::WDE_SIZE7,
        ple_size: &mac_size::PLE_SIZE6,
        wde_min_qt: &mac_size::WDE_QT7,
        wde_max_qt: &mac_size::WDE_QT7,
        ple_min_qt: &mac_size::PLE_QT18,
        ple_max_qt: &mac_size::PLE_QT58,
    }),
    None,
    Some(DleMem {
        mode: QtaMode::Dlfw,
        wde_size: &mac_size::WDE_SIZE9,
        ple_size: &mac_size::PLE_SIZE8,
        wde_min_qt: &mac_size::WDE_QT4,
        wde_max_qt: &mac_size::WDE_QT4,
        ple_min_qt: &mac_size::PLE_QT13,
        ple_max_qt: &mac_size::PLE_QT13,
    }),
    Some(DleMem {
        mode: QtaMode::Wow,
        wde_size: &mac_size::WDE_SIZE7,
        ple_size: &mac_size::PLE_SIZE6,
        wde_min_qt: &mac_size::WDE_QT7,
        wde_max_qt: &mac_size::WDE_QT7,
        ple_min_qt: &mac_size::PLE_QT18,
        ple_max_qt: &mac_size::PLE_QT_52B_WOW,
    }),
    None,
];

/// `rtw8852b_chip_info.fifo_size`: the DLE's bytes.
pub const FIFO_SIZE: u32 = 196_608;
/// `rtw8852b_chip_info.dle_scc_rsvd_size`: the bytes SCC leaves out of the
/// DLE.
pub const DLE_SCC_RSVD_SIZE: u32 = 98_304;

/// What the DLE and HFC code reads from `rtw8852b_chip_info` over PCIe
/// (`RTW89_HCI_DLE_TYPE_PCIE`).
pub const PCIE_QUOTA: ChipQuota = ChipQuota {
    hfc_param_ini: &RTW8852B_HFC_PARAM_INI_PCIE,
    dle_mem: &RTW8852B_DLE_MEM_PCIE,
    fifo_size: FIFO_SIZE,
    dle_scc_rsvd_size: DLE_SCC_RSVD_SIZE,
};
