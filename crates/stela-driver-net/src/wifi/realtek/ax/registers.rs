// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The rtw89 register names the AX layers read and write, as pinned
//! rtw89/reg.h, mac.h, phy.h and core.h define them. MAC registers are
//! BAR2 offsets; BB and RF registers are named without `cr_base`, which
//! [`super::io`] adds.

/// `R_AX_SYS_CFG1` and its cut field, `B_AX_CHIP_VER_MASK`.
pub const SYS_CFG1: u32 = 0x00f0;
pub const CHIP_VER_MASK: u32 = 0x0000_f000;

/// `R_AX_WLAN_XTAL_SI_CTRL` and its fields.
pub const WLAN_XTAL_SI_CTRL: u32 = 0x0270;
pub const XTAL_SI_CMD_POLL: u32 = 1 << 31;
pub const XTAL_SI_MODE_MASK: u32 = 0x0300_0000;
pub const XTAL_SI_BITMASK_MASK: u32 = 0x00ff_0000;
pub const XTAL_SI_DATA_MASK: u32 = 0x0000_ff00;
pub const XTAL_SI_ADDR_MASK: u32 = 0x0000_00ff;
/// `XTAL_SI_NORMAL_WRITE` and `XTAL_SI_NORMAL_READ`.
pub const XTAL_SI_NORMAL_WRITE: u32 = 0;
pub const XTAL_SI_NORMAL_READ: u32 = 1;
/// `XTAL_SI_CV` and `XTAL_SI_ACV_MASK`: the analog cut.
pub const XTAL_SI_CV: u8 = 0x41;
pub const XTAL_SI_ACV_MASK: u8 = 0x0f;

/// `R_AX_CMAC_REG_START` to `R_AX_CMAC_REG_END`: the registers whose reads
/// `rtw89_pci_ops_read32_cmac` retries (`ACCESS_CMAC`).
pub const CMAC_REG_START: u32 = 0xc000;
pub const CMAC_REG_END: u32 = 0xffff;
/// `R_AX_CK_EN`, written `B_AX_CMAC_ALLCKEN` before each retry.
pub const CK_EN: u32 = 0xc004;
pub const CMAC_ALLCKEN: u32 = u32::MAX;
/// `MAC_REG_POOL_COUNT`.
pub const MAC_REG_POOL_COUNT: usize = 10;
/// `RTW89_R32_DEAD`: what a register block that is off reads as.
pub const R32_DEAD: u32 = 0xdead_beef;
/// `RTW89_R32_EA`: what a read the bus did not complete returns.
pub const R32_EA: u32 = 0xeaea_eaea;

/// `R_SWSI_DATA_V1` and its fields: an indirect RF write.
pub const SWSI_DATA_V1: u32 = 0x0370;
pub const SWSI_DATA_VAL_V1: u32 = 0x000f_ffff;
pub const SWSI_DATA_ADDR_V1: u32 = 0x0ff0_0000;
pub const SWSI_DATA_PATH_V1: u32 = 0x7000_0000;
pub const SWSI_DATA_BIT_MASK_EN_V1: u32 = 1 << 31;
/// `R_SWSI_BIT_MASK_V1`.
pub const SWSI_BIT_MASK_V1: u32 = 0x0374;
/// `R_SWSI_READ_ADDR_V1` and its fields: an indirect RF read.
pub const SWSI_READ_ADDR_V1: u32 = 0x0378;
pub const SWSI_READ_ADDR_ADDR_V1: u32 = 0x0000_00ff;
pub const SWSI_READ_ADDR_PATH_V1: u32 = 0x0000_0700;
pub const SWSI_READ_ADDR_MASK_V1: u32 = 0x0000_07ff;
/// `R_SWSI_V1` and its status bits.
pub const SWSI_V1: u32 = 0x174c;
pub const SWSI_W_BUSY_V1: u32 = 1 << 24;
pub const SWSI_R_BUSY_V1: u32 = 1 << 25;
pub const SWSI_R_DATA_DONE_V1: u32 = 1 << 26;

/// `RFREG_MASK`: an RF register's 20 bits.
pub const RFREG_MASK: u32 = 0x000f_ffff;
/// `MASKDWORD`.
pub const MASKDWORD: u32 = u32::MAX;
/// `RTW89_RF_ADDR_ADSEL_MASK`: an RF address with this bit set is reached
/// directly through the BB window, otherwise through SWSI.
pub const RF_ADDR_ADSEL: u32 = 1 << 16;

/// `enum rtw89_cv`: the cuts `hal.cv` takes from SYS_CFG1.
pub const CHIP_CAV: u8 = 0;
pub const CHIP_CBV: u8 = 1;
pub const CHIP_CCV: u8 = 2;

/// `R_AX_SYS_ISO_CTRL` and its bits.
pub const SYS_ISO_CTRL: u32 = 0x0000;
pub const PWC_EV2EF_B15: u32 = 1 << 15;
pub const PWC_EV2EF_B14: u32 = 1 << 14;
pub const ISO_EB2CORE: u32 = 1 << 8;

/// `R_AX_SYS_FUNC_EN` and its BB reset bits, `B_AX_FEN_BB_GLB_RSTN` and
/// `B_AX_FEN_BBRSTB`.
pub const SYS_FUNC_EN: u32 = 0x0002;
pub const FEN_BB_GLB_RSTN: u32 = 1 << 1;
pub const FEN_BBRSTB: u32 = 1 << 0;

/// `R_AX_SYS_PW_CTRL` and its bits.
pub const SYS_PW_CTRL: u32 = 0x0004;
pub const DIS_WLBT_PDNSUSEN_SOPC: u32 = 1 << 18;
pub const RDY_SYSPWR: u32 = 1 << 17;
pub const EN_WLON: u32 = 1 << 16;
pub const APDM_HPDN: u32 = 1 << 15;
pub const AFSM_PCIE_SUS_EN: u32 = 1 << 12;
pub const AFSM_WLSUS_EN: u32 = 1 << 11;
pub const APFM_SWLPS: u32 = 1 << 10;
pub const APFM_OFFMAC: u32 = 1 << 9;
pub const APFN_ONMAC: u32 = 1 << 8;

/// `R_AX_SYS_SWR_CTRL1` and `B_AX_SYM_CTRL_SPS_PWMFREQ`.
pub const SYS_SWR_CTRL1: u32 = 0x0010;
pub const SYM_CTRL_SPS_PWMFREQ: u32 = 1 << 10;

/// `R_AX_SYS_ADIE_PAD_PWR_CTRL` and its WL pad bits.
pub const SYS_ADIE_PAD_PWR_CTRL: u32 = 0x0018;
pub const SYM_PADPDN_WL_PTA_1P3: u32 = 1 << 6;
pub const SYM_PADPDN_WL_RFC_1P3: u32 = 1 << 5;

/// `R_AX_AFE_LDO_CTRL` and `B_AX_AON_OFF_PC_EN`.
pub const AFE_LDO_CTRL: u32 = 0x0020;
pub const AON_OFF_PC_EN: u32 = 1 << 23;

/// `R_AX_EFUSE_CTRL` and its fields: one physical efuse byte per request.
pub const EFUSE_CTRL: u32 = 0x0030;
pub const EF_RDY: u32 = 1 << 29;
pub const EF_ADDR_MASK: u32 = 0x07ff_0000;
pub const EF_DATA_MASK: u32 = 0x0000_ffff;
/// `R_AX_EFUSE_CTRL_1_V1` and `B_AX_EF_BURST`.
pub const EFUSE_CTRL_1_V1: u32 = 0x0038;
pub const EF_BURST: u32 = 1 << 19;

/// `R_AX_SYS_SDIO_CTRL` and `B_AX_PCIE_CALIB_EN_V1`.
pub const SYS_SDIO_CTRL: u32 = 0x0070;
pub const PCIE_CALIB_EN_V1: u32 = 1 << 12;

/// `R_AX_HCI_LDO_CTRL` and `B_AX_R_AX_VADJ_MASK`.
pub const HCI_LDO_CTRL: u32 = 0x007a;
pub const R_AX_VADJ_MASK: u32 = 0x0000_000f;

/// `R_AX_PLATFORM_ENABLE` and `B_AX_PLATFORM_EN`.
pub const PLATFORM_ENABLE: u32 = 0x0088;
pub const PLATFORM_EN: u32 = 1 << 0;

/// `R_AX_WLLPS_CTRL`, `B_AX_DIS_WLBT_LPSEN_LOPC`, and `SW_LPS_OPTION`, the
/// value a PCIe power-off leaves in it.
pub const WLLPS_CTRL: u32 = 0x0090;
pub const DIS_WLBT_LPSEN_LOPC: u32 = 1 << 1;
pub const SW_LPS_OPTION: u32 = 0x0001_a0b2;

/// `R_AX_SCOREBOARD`, and `MAC_AX_NOTIFY_TP_MAJOR` and
/// `MAC_AX_NOTIFY_PWR_MAJOR`, which power-on and power-off write to its top
/// byte.
pub const SCOREBOARD: u32 = 0x00ac;
pub const MAC_AX_NOTIFY_TP_MAJOR: u8 = 0x81;
pub const MAC_AX_NOTIFY_PWR_MAJOR: u8 = 0x80;

/// `R_AX_PMC_DBG_CTRL2` and `B_AX_SYSON_DIS_PMCR_AX_WRMSK`.
pub const PMC_DBG_CTRL2: u32 = 0x00cc;
pub const SYSON_DIS_PMCR_AX_WRMSK: u32 = 1 << 2;

/// `R_AX_SPS_DIG_ON_CTRL0` and its fields.
pub const SPS_DIG_ON_CTRL0: u32 = 0x0200;
pub const VREFPFM_L_MASK: u32 = 0x03c0_0000;
pub const REG_ZCDC_H_MASK: u32 = 0x0006_0000;
pub const VOL_L1_MASK: u32 = 0x0000_000f;

/// `R_AX_SPS_ANA_ON_CTRL2`.
pub const SPS_ANA_ON_CTRL2: u32 = 0x0228;

/// `R_AX_EECS_EESK_FUNC_SEL`, `B_AX_PINMUX_EESK_FUNC_SEL_MASK` and
/// `PINMUX_EESK_FUNC_SEL_BT_LOG`.
pub const EECS_EESK_FUNC_SEL: u32 = 0x02d8;
pub const PINMUX_EESK_FUNC_SEL_MASK: u32 = 0x0000_00f0;
pub const PINMUX_EESK_FUNC_SEL_BT_LOG: u32 = 0x1;

/// `R_AX_WLRF_CTRL` and `B_AX_AFC_AFEDIG`.
pub const WLRF_CTRL: u32 = 0x02f0;
pub const AFC_AFEDIG: u32 = 1 << 17;

/// `R_AX_IC_PWR_STATE`, `B_AX_WLMAC_PWR_STE_MASK` and `MAC_AX_MAC_ON`.
pub const IC_PWR_STATE: u32 = 0x03f0;
pub const WLMAC_PWR_STE_MASK: u32 = 0x0000_0300;
pub const MAC_AX_MAC_ON: u32 = 1;

/// `R_AX_SPS_DIG_OFF_CTRL0` and its fields.
pub const SPS_DIG_OFF_CTRL0: u32 = 0x0400;
pub const R1_L1_MASK: u32 = 0x0000_00c0;
pub const C3_L1_MASK: u32 = 0x0000_0030;
pub const C2_L1_MASK: u32 = 0x0000_000c;
pub const C1_L1_MASK: u32 = 0x0000_0003;

/// `R_AX_HCI_FUNC_EN` (`rtw8852b_chip_info.hci_func_en_addr`) and its DMA
/// enables, `B_AX_HCI_RXDMA_EN` and `B_AX_HCI_TXDMA_EN`.
pub const HCI_FUNC_EN: u32 = 0x8380;
pub const HCI_RXDMA_EN: u32 = 1 << 1;
pub const HCI_TXDMA_EN: u32 = 1 << 0;

/// `R_AX_DMAC_FUNC_EN` and the bits power-on sets in it.
/// `B_AX_DMAC_FUNC_EN` is [`DMAC_FUNC_EN_BIT`], since the register takes the
/// bare name.
pub const DMAC_FUNC_EN: u32 = 0x8400;
pub const MAC_FUNC_EN: u32 = 1 << 30;
pub const DMAC_FUNC_EN_BIT: u32 = 1 << 29;
pub const MPDU_PROC_EN: u32 = 1 << 28;
pub const WD_RLS_EN: u32 = 1 << 27;
pub const DLE_WDE_EN: u32 = 1 << 26;
pub const TXPKT_CTRL_EN: u32 = 1 << 25;
pub const STA_SCH_EN: u32 = 1 << 24;
pub const DLE_PLE_EN: u32 = 1 << 23;
pub const PKT_BUF_EN: u32 = 1 << 22;
pub const DMAC_TBL_EN: u32 = 1 << 21;
pub const PKT_IN_EN: u32 = 1 << 20;
pub const DLE_CPUIO_EN: u32 = 1 << 19;
pub const DISPATCHER_EN: u32 = 1 << 18;
pub const BBRPT_EN: u32 = 1 << 17;
pub const MAC_SEC_EN: u32 = 1 << 16;
pub const DMACREG_GCKEN: u32 = 1 << 15;

/// `R_AX_DMAC_CLK_EN` and the clocks the DMAC pre-init enables:
/// `B_AX_DLE_WDE_CLK_EN`, `B_AX_DLE_PLE_CLK_EN` and `B_AX_DISPATCHER_CLK_EN`.
pub const DMAC_CLK_EN: u32 = 0x8404;
pub const DLE_WDE_CLK_EN: u32 = 1 << 26;
pub const DLE_PLE_CLK_EN: u32 = 1 << 23;
pub const DISPATCHER_CLK_EN: u32 = 1 << 18;

/// `R_AX_HCI_FC_CTRL` (`rtw8852b_page_regs.hci_fc_ctrl`) and the fields the
/// H2C-only flow control sets: `B_AX_HCI_FC_CH12_FULL_COND_MASK`,
/// `B_AX_HCI_FC_CH12_EN` and `B_AX_HCI_FC_EN`.
pub const HCI_FC_CTRL: u32 = 0x8a00;
pub const HCI_FC_CH12_FULL_COND_MASK: u32 = 0x0000_0c00;
pub const HCI_FC_CH12_EN: u32 = 1 << 3;
pub const HCI_FC_EN: u32 = 1 << 0;
/// `R_AX_CH_PAGE_CTRL` (`rtw8852b_page_regs.ch_page_ctrl`) and
/// `B_AX_PREC_PAGE_CH12_MASK`, the H2C channel's pre-cost.
pub const CH_PAGE_CTRL: u32 = 0x8a04;
pub const PREC_PAGE_CH12_MASK: u32 = 0x01ff_0000;

/// `R_AX_WDE_PKTBUF_CFG` and its fields.
pub const WDE_PKTBUF_CFG: u32 = 0x8c08;
pub const WDE_FREE_PAGE_NUM_MASK: u32 = 0x1fff_0000;
pub const WDE_START_BOUND_MASK: u32 = 0x0000_3f00;
pub const WDE_PAGE_SEL_MASK: u32 = 0x0000_0003;
/// `R_AX_WDE_QTA0_CFG` to `R_AX_WDE_QTA4_CFG`, of which the AX quota leaves
/// QTA2 (the unused DCPU) alone, and `B_AX_WDE_MAX_SIZE_MASK` and
/// `B_AX_WDE_MIN_SIZE_MASK`.
pub const WDE_QTA0_CFG: u32 = 0x8c40;
pub const WDE_QTA1_CFG: u32 = 0x8c44;
pub const WDE_QTA3_CFG: u32 = 0x8c4c;
pub const WDE_QTA4_CFG: u32 = 0x8c50;
pub const WDE_MAX_SIZE_MASK: u32 = 0x0fff_0000;
pub const WDE_MIN_SIZE_MASK: u32 = 0x0000_0fff;
/// `R_AX_WDE_INI_STATUS` and `WDE_MGN_INI_RDY`, `B_AX_WDE_Q_MGN_INI_RDY` with
/// `B_AX_WDE_BUF_MGN_INI_RDY`.
pub const WDE_INI_STATUS: u32 = 0x8d00;
pub const WDE_Q_MGN_INI_RDY: u32 = 1 << 1;
pub const WDE_BUF_MGN_INI_RDY: u32 = 1 << 0;
pub const WDE_MGN_INI_RDY: u32 = WDE_Q_MGN_INI_RDY | WDE_BUF_MGN_INI_RDY;

/// `R_AX_PLE_PKTBUF_CFG` and its fields.
pub const PLE_PKTBUF_CFG: u32 = 0x9008;
pub const PLE_FREE_PAGE_NUM_MASK: u32 = 0x1fff_0000;
pub const PLE_START_BOUND_MASK: u32 = 0x0000_3f00;
pub const PLE_PAGE_SEL_MASK: u32 = 0x0000_0003;
/// `R_AX_PLE_QTA0_CFG` to `R_AX_PLE_QTA10_CFG`, one per
/// `struct rtw89_ple_quota` member in order, and `B_AX_PLE_MAX_SIZE_MASK`
/// and `B_AX_PLE_MIN_SIZE_MASK`. QTA11 (`tx_rpt`) is RTL8852C's alone.
pub const PLE_QTA0_CFG: u32 = 0x9040;
pub const PLE_QTA1_CFG: u32 = 0x9044;
pub const PLE_QTA2_CFG: u32 = 0x9048;
pub const PLE_QTA3_CFG: u32 = 0x904c;
pub const PLE_QTA4_CFG: u32 = 0x9050;
pub const PLE_QTA5_CFG: u32 = 0x9054;
pub const PLE_QTA6_CFG: u32 = 0x9058;
pub const PLE_QTA7_CFG: u32 = 0x905c;
pub const PLE_QTA8_CFG: u32 = 0x9060;
pub const PLE_QTA9_CFG: u32 = 0x9064;
pub const PLE_QTA10_CFG: u32 = 0x9068;
pub const PLE_MAX_SIZE_MASK: u32 = 0x0fff_0000;
pub const PLE_MIN_SIZE_MASK: u32 = 0x0000_0fff;
/// `R_AX_PLE_INI_STATUS` and `PLE_MGN_INI_RDY`, `B_AX_PLE_Q_MGN_INI_RDY` with
/// `B_AX_PLE_BUF_MGN_INI_RDY`.
pub const PLE_INI_STATUS: u32 = 0x9100;
pub const PLE_Q_MGN_INI_RDY: u32 = 1 << 1;
pub const PLE_BUF_MGN_INI_RDY: u32 = 1 << 0;
pub const PLE_MGN_INI_RDY: u32 = PLE_Q_MGN_INI_RDY | PLE_BUF_MGN_INI_RDY;

/// mac.h's DLE page sizes (`RTW89_WDE_PG_*`, `RTW89_PLE_PG_*`), their page
/// selections (`S_AX_WDE_PAGE_SEL_*`, `S_AX_PLE_PAGE_SEL_*`), and
/// `DLE_BOUND_UNIT`, the PLE start bound's unit in bytes.
pub const WDE_PG_64: u16 = 64;
pub const WDE_PG_128: u16 = 128;
pub const WDE_PG_256: u16 = 256;
pub const S_AX_WDE_PAGE_SEL_64: u32 = 0;
pub const S_AX_WDE_PAGE_SEL_128: u32 = 1;
pub const PLE_PG_64: u16 = 64;
pub const PLE_PG_128: u16 = 128;
pub const PLE_PG_256: u16 = 256;
pub const S_AX_PLE_PAGE_SEL_128: u32 = 1;
pub const S_AX_PLE_PAGE_SEL_256: u32 = 2;
pub const DLE_BOUND_UNIT: u32 = 8 * 1024;

/// `R_AX_CMAC_FUNC_EN` and the bits power-on sets in it.
pub const CMAC_FUNC_EN: u32 = 0xc000;
pub const CMAC_EN: u32 = 1 << 30;
pub const CMAC_TXEN: u32 = 1 << 29;
pub const CMAC_RXEN: u32 = 1 << 28;
pub const FORCE_CMACREG_GCKEN: u32 = 1 << 15;
pub const PHYINTF_EN: u32 = 1 << 5;
pub const CMAC_DMA_EN: u32 = 1 << 4;
pub const PTCLTOP_EN: u32 = 1 << 3;
pub const SCHEDULER_EN: u32 = 1 << 2;
pub const TMAC_EN: u32 = 1 << 1;
pub const RMAC_EN: u32 = 1 << 0;

/// XTAL SI offsets (`enum rtw89_mac_xtal_si_offset`) and the bits power-on
/// and power-off write in them.
pub const XTAL_SI_XTAL_XMD_2: u8 = 0x24;
pub const XTAL_SI_LDO_LPS: u8 = 0x70;
pub const XTAL_SI_XTAL_XMD_4: u8 = 0x26;
pub const XTAL_SI_LPS_CAP: u8 = 0x0f;
pub const XTAL_SI_WL_RFC_S0: u8 = 0x80;
pub const XTAL_SI_RF00: u8 = 1 << 0;
pub const XTAL_SI_WL_RFC_S1: u8 = 0x81;
pub const XTAL_SI_RF10: u8 = 1 << 0;
pub const XTAL_SI_ANAPAR_WL: u8 = 0x90;
pub const XTAL_SI_SRAM2RFC: u8 = 1 << 7;
pub const XTAL_SI_GND_SHDN_WL: u8 = 1 << 6;
pub const XTAL_SI_SHDN_WL: u8 = 1 << 5;
pub const XTAL_SI_RFC2RF: u8 = 1 << 4;
pub const XTAL_SI_OFF_EI: u8 = 1 << 3;
pub const XTAL_SI_OFF_WEI: u8 = 1 << 2;
pub const XTAL_SI_PON_EI: u8 = 1 << 1;
pub const XTAL_SI_PON_WEI: u8 = 1 << 0;
pub const XTAL_SI_SRAM_CTRL: u8 = 0xa1;
pub const XTAL_SI_SRAM_DIS: u8 = 1 << 1;
