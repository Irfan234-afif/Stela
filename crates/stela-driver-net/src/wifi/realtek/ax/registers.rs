// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The rtw89 register names the AX layers read and write, as pinned
//! rtw89/reg.h, pci.h, mac.h, phy.h and core.h define them. MAC registers
//! are BAR2 offsets; BB and RF registers are named without `cr_base`, which
//! [`super::io`] adds. The PCIe PHY registers reached through MDIO and the
//! configuration space offsets are named at the end.

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

/// `R_AX_SYS_WL_EFUSE_CTRL` and `B_AX_AUTOLOAD_SUS`, which
/// `rtw89_parse_efuse_map_ax` reads as the efuse being valid.
pub const SYS_WL_EFUSE_CTRL: u32 = 0x000a;
pub const AUTOLOAD_SUS: u16 = 1 << 5;

/// `R_AX_SYS_PW_CTRL` and its bits.
pub const SYS_PW_CTRL: u32 = 0x0004;
pub const DIS_WLBT_PDNSUSEN_SOPC: u32 = 1 << 18;
/// `B_AX_PSUS_OFF_CAPC_EN`, which `rtw89_pci_aphy_pwrcut` clears.
pub const PSUS_OFF_CAPC_EN: u32 = 1 << 14;
pub const RDY_SYSPWR: u32 = 1 << 17;
pub const EN_WLON: u32 = 1 << 16;
pub const APDM_HPDN: u32 = 1 << 15;
pub const AFSM_PCIE_SUS_EN: u32 = 1 << 12;
pub const AFSM_WLSUS_EN: u32 = 1 << 11;
pub const APFM_SWLPS: u32 = 1 << 10;
pub const APFM_OFFMAC: u32 = 1 << 9;
pub const APFN_ONMAC: u32 = 1 << 8;

/// `R_AX_SYS_CLK_CTRL` and `B_AX_CPU_CLK_EN`, the WCPU's clock.
pub const SYS_CLK_CTRL: u32 = 0x0008;
pub const CPU_CLK_EN: u32 = 1 << 14;

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

/// `R_AX_DBG_CTRL` and its two selectors, `B_AX_DBG_SEL0` and
/// `B_AX_DBG_SEL1`, which `rtw89_fw_prog_cnt_dump` points at the WCPU's
/// program counter.
pub const DBG_CTRL: u32 = 0x0058;
pub const DBG_SEL1: u32 = 0x00ff_0000;
pub const DBG_SEL0: u32 = 0x0000_00ff;
/// `FW_PROG_CNTR_DBG_SEL` (mac.h).
pub const FW_PROG_CNTR_DBG_SEL: u32 = 0xf2;

/// `R_AX_SYS_SDIO_CTRL` and its bits: `B_AX_PCIE_DIS_L2_CTRL_LDO_HCI` and
/// `B_AX_PCIE_DIS_WLSUS_AFT_PDN`, which `rtw89_pci_hci_ldo` sets and clears,
/// and `B_AX_PCIE_CALIB_EN_V1`.
pub const SYS_SDIO_CTRL: u32 = 0x0070;
pub const PCIE_DIS_L2_CTRL_LDO_HCI: u32 = 1 << 15;
pub const PCIE_DIS_WLSUS_AFT_PDN: u32 = 1 << 14;
pub const PCIE_CALIB_EN_V1: u32 = 1 << 12;

/// `R_AX_HCI_OPT_CTRL` and `BIT_WAKE_CTRL`, `rtw89_pci_power_wake_ax`'s bit.
pub const HCI_OPT_CTRL: u32 = 0x0074;
pub const WAKE_CTRL: u32 = 1 << 5;

/// `R_AX_HCI_LDO_CTRL` and `B_AX_R_AX_VADJ_MASK`.
pub const HCI_LDO_CTRL: u32 = 0x007a;
pub const R_AX_VADJ_MASK: u32 = 0x0000_000f;

/// `R_AX_PLATFORM_ENABLE` and its bits: `B_AX_APB_WRAP_EN`, `B_AX_WCPU_EN`
/// (the WCPU runs) and `B_AX_PLATFORM_EN`.
pub const PLATFORM_ENABLE: u32 = 0x0088;
pub const APB_WRAP_EN: u32 = 1 << 2;
pub const WCPU_EN: u32 = 1 << 1;
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

/// `R_AX_DBG_PORT_SEL`, where `rtw89_fw_prog_cnt_dump` reads the program
/// counter [`DBG_CTRL`] selects.
pub const DBG_PORT_SEL: u32 = 0x00c0;

/// `R_AX_PMC_DBG_CTRL2` and `B_AX_SYSON_DIS_PMCR_AX_WRMSK`.
pub const PMC_DBG_CTRL2: u32 = 0x00cc;
pub const SYSON_DIS_PMCR_AX_WRMSK: u32 = 1 << 2;

/// `R_AX_SYS_STATUS1`, `B_AX_SEL_0XC0_MASK` and `MAC_DBG_SEL` (mac.h): what
/// [`DBG_PORT_SEL`] reads.
pub const SYS_STATUS1: u32 = 0x00f4;
pub const SEL_0XC0_MASK: u32 = 0x0003_0000;
pub const MAC_DBG_SEL: u32 = 1;

/// `R_AX_HALT_H2C_CTRL`, `R_AX_HALT_C2H_CTRL`, `R_AX_HALT_H2C` and
/// `R_AX_HALT_C2H`.
pub const HALT_H2C_CTRL: u32 = 0x0160;
pub const HALT_C2H_CTRL: u32 = 0x0164;
pub const HALT_H2C: u32 = 0x0168;
pub const HALT_C2H: u32 = 0x016c;

/// `R_AX_WCPU_FW_CTRL` and its fields: the IDMEM share mode a secure boot
/// records (`B_AX_IDMEM_SHARE_MODE_RECORD_MASK` and `…_VALID`), the download
/// status (`B_AX_WCPU_FWDL_STS_MASK`), the two paths' ready bits
/// (`B_AX_FWDL_PATH_RDY`, `B_AX_H2C_PATH_RDY`) and `B_AX_WCPU_FWDL_EN`.
pub const WCPU_FW_CTRL: u32 = 0x01e0;
pub const IDMEM_SHARE_MODE_RECORD_MASK: u32 = 0x0f00_0000;
pub const IDMEM_SHARE_MODE_RECORD_VALID: u32 = 1 << 23;
pub const WCPU_FWDL_STS_MASK: u32 = 0x0000_00e0;
pub const FWDL_PATH_RDY: u32 = 1 << 2;
pub const H2C_PATH_RDY: u32 = 1 << 1;
pub const WCPU_FWDL_EN: u32 = 1 << 0;
/// `R_AX_BOOT_REASON` and `B_AX_BOOT_REASON_MASK`.
pub const BOOT_REASON: u32 = 0x01e6;
pub const BOOT_REASON_MASK: u32 = 0x0000_0007;
/// `R_AX_UDM1` and `R_AX_UDM2`.
pub const UDM1: u32 = 0x01f4;
pub const UDM2: u32 = 0x01f8;
/// UDM1's `B_AX_UDM1_HALMAC_C2H_ENQ_CNT_MASK` and
/// `B_AX_UDM1_HALMAC_H2C_DEQ_CNT_MASK`, where the register mailbox counts
/// what it received and sent (`rtw8852b_chip_info.c2h_counter_reg` and
/// `.h2c_counter_reg` reach them a byte up, at `R_AX_UDM1 + 1`).
pub const UDM1_HALMAC_C2H_ENQ_CNT_MASK: u32 = 0x0000_f000;
pub const UDM1_HALMAC_H2C_DEQ_CNT_MASK: u32 = 0x0000_0f00;

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

/// `R_AX_SEC_CTRL` and `B_AX_SEC_IDMEM_SIZE_CONFIG_MASK`, which
/// `rtw89_mac_enable_cpu_ax` sets to 2 on an RTL885xB.
pub const SEC_CTRL: u32 = 0x0c00;
pub const SEC_IDMEM_SIZE_CONFIG_MASK: u32 = 0x0003_0000;

/// `R_AX_PCIE_INIT_CFG1` (`rtw8852b_pci_info.init_cfg_reg`) and its bits.
pub const PCIE_INIT_CFG1: u32 = 0x1000;
pub const PCIE_RXRST_KEEP_REG: u32 = 1 << 23;
pub const PCIE_TXRST_KEEP_REG: u32 = 1 << 22;
pub const RXBD_MODE: u32 = 1 << 18;
pub const PCIE_MAX_RXDMA_MASK: u32 = 0x0001_c000;
pub const RXHCI_EN: u32 = 1 << 13;
pub const LATENCY_CONTROL: u32 = 1 << 12;
pub const TXHCI_EN: u32 = 1 << 11;
pub const PCIE_MAX_TXDMA_MASK: u32 = 0x0000_0700;
pub const RST_BDRAM: u32 = 1 << 3;
/// `R_AX_PCIE_INIT_CFG2` and the WD DMA intervals, `B_AX_WD_ITVL_IDLE` and
/// `B_AX_WD_ITVL_ACT`.
pub const PCIE_INIT_CFG2: u32 = 0x1004;
pub const WD_ITVL_IDLE: u32 = 0x0f00_0000;
pub const WD_ITVL_ACT: u32 = 0x000f_0000;
/// `R_AX_PCIE_PS_CTRL` and `B_AX_L1OFF_PWR_OFF_EN`.
pub const PCIE_PS_CTRL: u32 = 0x1008;
pub const L1OFF_PWR_OFF_EN: u32 = 1 << 5;
/// `R_AX_PCIE_DMA_STOP1` (`rtw8852b_pci_info.dma_stop1` and `dma_io_stop`)
/// and its bits; `B_AX_TX_STOP1_MASK_V1` stops the seven TX channels an
/// RTL8852BE has.
pub const PCIE_DMA_STOP1: u32 = 0x1010;
pub const STOP_PCIEIO: u32 = 1 << 20;
pub const STOP_WPDMA: u32 = 1 << 19;
pub const STOP_CH12: u32 = 1 << 18;
pub const STOP_CH9: u32 = 1 << 17;
pub const STOP_CH8: u32 = 1 << 16;
pub const STOP_ACH3: u32 = 1 << 11;
pub const STOP_ACH2: u32 = 1 << 10;
pub const STOP_ACH1: u32 = 1 << 9;
pub const STOP_ACH0: u32 = 1 << 8;
pub const TX_STOP1_MASK_V1: u32 =
    STOP_ACH0 | STOP_ACH1 | STOP_ACH2 | STOP_ACH3 | STOP_CH8 | STOP_CH9 | STOP_CH12;
/// `R_AX_TXBD_RWPTR_CLR1` and the index clears of the seven TX channels.
pub const TXBD_RWPTR_CLR1: u32 = 0x1014;
pub const CLR_CH12_IDX: u32 = 1 << 10;
pub const CLR_CH9_IDX: u32 = 1 << 9;
pub const CLR_CH8_IDX: u32 = 1 << 8;
pub const CLR_ACH3_IDX: u32 = 1 << 3;
pub const CLR_ACH2_IDX: u32 = 1 << 2;
pub const CLR_ACH1_IDX: u32 = 1 << 1;
pub const CLR_ACH0_IDX: u32 = 1 << 0;
/// `R_AX_RXBD_RWPTR_CLR` (`rtw8852b_pci_info.rxbd_rwptr_clr_reg`),
/// `B_AX_CLR_RPQ_IDX` and `B_AX_CLR_RXQ_IDX`.
pub const RXBD_RWPTR_CLR: u32 = 0x1018;
pub const CLR_RPQ_IDX: u32 = 1 << 1;
pub const CLR_RXQ_IDX: u32 = 1 << 0;
/// `R_AX_PCIE_DMA_BUSY1` (`rtw8852b_pci_info.dma_busy1` and
/// `dma_busy3_reg`) and its bits; `DMA_BUSY1_CHECK_V1` covers the seven TX
/// channels.
pub const PCIE_DMA_BUSY1: u32 = 0x101c;
pub const CH12_BUSY: u32 = 1 << 18;
pub const CH9_BUSY: u32 = 1 << 17;
pub const CH8_BUSY: u32 = 1 << 16;
pub const ACH3_BUSY: u32 = 1 << 11;
pub const ACH2_BUSY: u32 = 1 << 10;
pub const ACH1_BUSY: u32 = 1 << 9;
pub const ACH0_BUSY: u32 = 1 << 8;
pub const RPQ_BUSY: u32 = 1 << 1;
pub const RXQ_BUSY: u32 = 1 << 0;
pub const DMA_BUSY1_CHECK_V1: u32 =
    ACH0_BUSY | ACH1_BUSY | ACH2_BUSY | ACH3_BUSY | CH8_BUSY | CH9_BUSY | CH12_BUSY;

/// The BD count registers (`R_AX_*_RXBD_NUM`, `R_AX_*_TXBD_NUM`), 16 bits
/// wide.
pub const RXQ_RXBD_NUM: u32 = 0x1020;
pub const RPQ_RXBD_NUM: u32 = 0x1022;
pub const ACH0_TXBD_NUM: u32 = 0x1024;
pub const ACH1_TXBD_NUM: u32 = 0x1026;
pub const ACH2_TXBD_NUM: u32 = 0x1028;
pub const ACH3_TXBD_NUM: u32 = 0x102a;
pub const ACH4_TXBD_NUM: u32 = 0x102c;
pub const ACH5_TXBD_NUM: u32 = 0x102e;
pub const ACH6_TXBD_NUM: u32 = 0x1030;
pub const ACH7_TXBD_NUM: u32 = 0x1032;
pub const CH8_TXBD_NUM: u32 = 0x1034;
pub const CH9_TXBD_NUM: u32 = 0x1036;
pub const CH12_TXBD_NUM: u32 = 0x1038;
pub const CH10_TXBD_NUM: u32 = 0x1338;
pub const CH11_TXBD_NUM: u32 = 0x133a;
/// The BD index registers (`R_AX_*_RXBD_IDX`, `R_AX_*_TXBD_IDX`): the host
/// index in `TXBD_HOST_IDX_MASK`, the hardware's in `TXBD_HW_IDX_MASK`.
pub const RXQ_RXBD_IDX: u32 = 0x1050;
pub const RPQ_RXBD_IDX: u32 = 0x1054;
pub const ACH0_TXBD_IDX: u32 = 0x1058;
pub const ACH1_TXBD_IDX: u32 = 0x105c;
pub const ACH2_TXBD_IDX: u32 = 0x1060;
pub const ACH3_TXBD_IDX: u32 = 0x1064;
pub const ACH4_TXBD_IDX: u32 = 0x1068;
pub const ACH5_TXBD_IDX: u32 = 0x106c;
pub const ACH6_TXBD_IDX: u32 = 0x1070;
pub const ACH7_TXBD_IDX: u32 = 0x1074;
pub const CH8_TXBD_IDX: u32 = 0x1078;
pub const CH9_TXBD_IDX: u32 = 0x107c;
pub const CH12_TXBD_IDX: u32 = 0x1080;
pub const CH10_TXBD_IDX: u32 = 0x137c;
pub const CH11_TXBD_IDX: u32 = 0x1380;
pub const TXBD_HW_IDX_MASK: u32 = 0x0fff_0000;
pub const TXBD_HOST_IDX_MASK: u32 = 0x0000_0fff;

/// `R_AX_DBI_FLAG` and its fields, and `R_AX_DBI_WDATA` and
/// `R_AX_DBI_RDATA`: configuration space reached through BAR2.
pub const DBI_FLAG: u32 = 0x1090;
pub const DBI_RFLAG: u32 = 1 << 17;
pub const DBI_WFLAG: u32 = 1 << 16;
pub const DBI_WREN_MSK: u32 = 0x0000_f000;
pub const DBI_ADDR_MSK: u32 = 0x0000_0ffc;
pub const DBI_2LSB: u32 = 0x0000_0003;
pub const DBI_WDATA: u32 = 0x1094;
pub const DBI_RDATA: u32 = 0x1098;
/// `R_AX_MDIO_CFG` and its fields, and `R_AX_MDIO_WDATA` and
/// `R_AX_MDIO_RDATA`: the PCIe PHY's registers, 16 bits each.
pub const MDIO_CFG: u32 = 0x10a0;
pub const MDIO_PHY_ADDR_MASK: u32 = 0x0000_3000;
pub const MDIO_RFLAG: u16 = 1 << 9;
pub const MDIO_WFLAG: u16 = 1 << 8;
pub const MDIO_WDATA: u32 = 0x10a4;
pub const MDIO_RDATA: u32 = 0x10a6;

/// The BD base registers (`R_AX_*_RXBD_DESA_L`, `R_AX_*_TXBD_DESA_L`), each
/// followed by its upper half (`_DESA_H`).
pub const RXQ_RXBD_DESA_L: u32 = 0x1100;
pub const RXQ_RXBD_DESA_H: u32 = 0x1104;
pub const RPQ_RXBD_DESA_L: u32 = 0x1108;
pub const RPQ_RXBD_DESA_H: u32 = 0x110c;
pub const ACH0_TXBD_DESA_L: u32 = 0x1110;
pub const ACH0_TXBD_DESA_H: u32 = 0x1114;
pub const ACH1_TXBD_DESA_L: u32 = 0x1118;
pub const ACH1_TXBD_DESA_H: u32 = 0x111c;
pub const ACH2_TXBD_DESA_L: u32 = 0x1120;
pub const ACH2_TXBD_DESA_H: u32 = 0x1124;
pub const ACH3_TXBD_DESA_L: u32 = 0x1128;
pub const ACH3_TXBD_DESA_H: u32 = 0x112c;
pub const ACH4_TXBD_DESA_L: u32 = 0x1130;
pub const ACH4_TXBD_DESA_H: u32 = 0x1134;
pub const ACH5_TXBD_DESA_L: u32 = 0x1138;
pub const ACH5_TXBD_DESA_H: u32 = 0x113c;
pub const ACH6_TXBD_DESA_L: u32 = 0x1140;
pub const ACH6_TXBD_DESA_H: u32 = 0x1144;
pub const ACH7_TXBD_DESA_L: u32 = 0x1148;
pub const ACH7_TXBD_DESA_H: u32 = 0x114c;
pub const CH8_TXBD_DESA_L: u32 = 0x1150;
pub const CH8_TXBD_DESA_H: u32 = 0x1154;
pub const CH9_TXBD_DESA_L: u32 = 0x1158;
pub const CH9_TXBD_DESA_H: u32 = 0x115c;
pub const CH12_TXBD_DESA_L: u32 = 0x1160;
pub const CH12_TXBD_DESA_H: u32 = 0x1164;
pub const CH10_TXBD_DESA_L: u32 = 0x1358;
pub const CH10_TXBD_DESA_H: u32 = 0x135c;
pub const CH11_TXBD_DESA_L: u32 = 0x1360;
pub const CH11_TXBD_DESA_H: u32 = 0x1364;

/// `R_AX_PCIE_DBG_CTRL` and the bits `rtw89_pci_set_dbg` sets in it and in
/// `R_AX_PCIE_EXP_CTRL`: `B_AX_ASFF_FULL_NO_STK` and `B_AX_EN_STUCK_DBG`.
pub const PCIE_DBG_CTRL: u32 = 0x11c0;
pub const ASFF_FULL_NO_STK: u32 = 1 << 1;
pub const EN_STUCK_DBG: u32 = 1 << 0;
/// `R_AX_LBC_WATCHDOG` and its fields.
pub const LBC_WATCHDOG: u32 = 0x11d8;
pub const LBC_TIMER: u32 = 0x0000_00f0;
pub const LBC_FLAG: u32 = 1 << 1;
pub const LBC_EN: u32 = 1 << 0;

/// The TX channels' BD RAM controls (`R_AX_*_BDRAM_CTRL`) and their fields.
pub const ACH0_BDRAM_CTRL: u32 = 0x1200;
pub const ACH1_BDRAM_CTRL: u32 = 0x1204;
pub const ACH2_BDRAM_CTRL: u32 = 0x1208;
pub const ACH3_BDRAM_CTRL: u32 = 0x120c;
pub const ACH4_BDRAM_CTRL: u32 = 0x1210;
pub const ACH5_BDRAM_CTRL: u32 = 0x1214;
pub const ACH6_BDRAM_CTRL: u32 = 0x1218;
pub const ACH7_BDRAM_CTRL: u32 = 0x121c;
pub const CH8_BDRAM_CTRL: u32 = 0x1220;
pub const CH9_BDRAM_CTRL: u32 = 0x1224;
pub const CH12_BDRAM_CTRL: u32 = 0x1228;
pub const CH10_BDRAM_CTRL: u32 = 0x1320;
pub const CH11_BDRAM_CTRL: u32 = 0x1324;
pub const BDRAM_SIDX_MASK: u32 = 0x0000_00ff;
pub const BDRAM_MAX_MASK: u32 = 0x0000_ff00;
pub const BDRAM_MIN_MASK: u32 = 0x00ff_0000;

/// `R_AX_PCIE_EXP_CTRL` (`rtw8852b_pci_info.exp_ctrl_reg`), its tag count
/// (`max_tag_num_mask`, `B_AX_MAX_TAG_NUM`) and `B_AX_SIC_EN_FORCE_CLKREQ`.
pub const PCIE_EXP_CTRL: u32 = 0x13f0;
pub const MAX_TAG_NUM: u32 = 0x0007_0000;
pub const SIC_EN_FORCE_CLKREQ: u32 = 1 << 4;

/// `R_AX_HCI_FUNC_EN` (`rtw8852b_chip_info.hci_func_en_addr`) and its DMA
/// enables, `B_AX_HCI_RXDMA_EN` and `B_AX_HCI_TXDMA_EN`.
pub const HCI_FUNC_EN: u32 = 0x8380;
pub const HCI_RXDMA_EN: u32 = 1 << 1;
pub const HCI_TXDMA_EN: u32 = 1 << 0;

/// The register mailbox (`rtw8852b_h2c_regs`, `rtw8852b_c2h_regs`,
/// `rtw8852b_chip_info.h2c_ctrl_reg` and `.c2h_ctrl_reg`): `R_AX_H2CREG_DATA0`
/// to `R_AX_H2CREG_DATA3`, `R_AX_C2HREG_DATA0` to `R_AX_C2HREG_DATA3`,
/// `R_AX_H2CREG_CTRL` with `B_AX_H2CREG_TRIGGER`, and `R_AX_C2HREG_CTRL`.
pub const H2CREG_DATA0: u32 = 0x8140;
pub const H2CREG_DATA1: u32 = 0x8144;
pub const H2CREG_DATA2: u32 = 0x8148;
pub const H2CREG_DATA3: u32 = 0x814c;
pub const C2HREG_DATA0: u32 = 0x8150;
pub const C2HREG_DATA1: u32 = 0x8154;
pub const C2HREG_DATA2: u32 = 0x8158;
pub const C2HREG_DATA3: u32 = 0x815c;
pub const H2CREG_CTRL: u32 = 0x8160;
pub const H2CREG_TRIGGER: u8 = 1 << 0;
pub const C2HREG_CTRL: u32 = 0x8164;

/// `R_AX_BOOT_DBG` (`rtw89_mac_gen_ax.boot_dbg`), which a failed download
/// reads.
pub const BOOT_DBG: u32 = 0x83f0;

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

/// `R_AX_TX_ADDRESS_INFO_MODE_SETTING` and `B_AX_HOST_ADDR_INFO_8B_SEL`.
pub const TX_ADDRESS_INFO_MODE_SETTING: u32 = 0x8810;
pub const HOST_ADDR_INFO_8B_SEL: u32 = 1 << 0;

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

/// `R_AX_PKTIN_SETTING` and `B_AX_WD_ADDR_INFO_LENGTH`.
pub const PKTIN_SETTING: u32 = 0x9a00;
pub const WD_ADDR_INFO_LENGTH: u32 = 1 << 1;

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
/// The XTAL SI offsets and fields `rtw89_dump_physical_efuse_map_dav` reads
/// a DAV efuse byte through: `XTAL_SI_LOW_ADDR` with `XTAL_SI_LOW_ADDR_MASK`,
/// `XTAL_SI_CTRL` with `XTAL_SI_MODE_SEL_MASK`, `XTAL_SI_RDY` and
/// `XTAL_SI_HIGH_ADDR_MASK`, `XTAL_SI_READ_VAL`, and `FULL_BIT_MASK`.
pub const XTAL_SI_LOW_ADDR: u8 = 0x62;
pub const XTAL_SI_LOW_ADDR_MASK: u8 = 0xff;
pub const XTAL_SI_CTRL: u8 = 0x63;
pub const XTAL_SI_MODE_SEL_MASK: u8 = 0xc0;
pub const XTAL_SI_RDY: u8 = 1 << 5;
pub const XTAL_SI_HIGH_ADDR_MASK: u8 = 0x07;
pub const XTAL_SI_READ_VAL: u8 = 0x7a;
pub const FULL_BIT_MASK: u8 = 0xff;

// The full MAC init's registers (`rtw89_mac_init`'s `sys_init_ax`,
// `trx_init_ax` and their callees), in the order rtw89 reaches them.
/// `R_AX_PHYREG_SET` and `PHYREG_SET_XYN_CYCLE`, which
/// `__rtw8852bx_mac_enable_bb_rf` writes last.
pub const PHYREG_SET: u32 = 0x8040;
pub const PHYREG_SET_XYN_CYCLE: u8 = 0xe;

/// The `R_AX_DMAC_FUNC_EN` bit `dmac_func_en_ax` adds to the pre-init's,
/// and the `R_AX_DMAC_CLK_EN` clocks it enables.
pub const DMAC_CRPRT: u32 = 1 << 31;
pub const MAC_SEC_CLK_EN: u32 = 1 << 16;
pub const DLE_CPUIO_CLK_EN: u32 = 1 << 19;
pub const PKT_IN_CLK_EN: u32 = 1 << 20;
pub const STA_SCH_CLK_EN: u32 = 1 << 24;
pub const TXPKT_CTRL_CLK_EN: u32 = 1 << 25;
pub const WD_RLS_CLK_EN: u32 = 1 << 27;
pub const BBRPT_CLK_EN: u32 = 1 << 17;

/// The `R_AX_CMAC_FUNC_EN` bit and the `R_AX_CK_EN` clocks
/// `cmac_func_en_ax` sets for CMAC0, and `B_AX_OCP_L1_MASK`, which
/// `chip_func_en_ax` sets in `R_AX_SPS_DIG_ON_CTRL0`.
pub const CMAC_CRPRT: u32 = 1 << 31;
pub const CMAC_CKEN: u32 = 1 << 30;
pub const PHYINTF_CKEN: u32 = 1 << 5;
pub const CMAC_DMA_CKEN: u32 = 1 << 4;
pub const PTCLTOP_CKEN: u32 = 1 << 3;
pub const SCHEDULER_CKEN: u32 = 1 << 2;
pub const TMAC_CKEN: u32 = 1 << 1;
pub const RMAC_CKEN: u32 = 1 << 0;
pub const OCP_L1_MASK: u32 = 0x0000_e000;

/// The rest of `rtw8852b_page_regs` and the HCI flow-control fields the
/// full flow control sets and reads back. Channel `ch`'s page control and
/// page information are 4 * `ch` past `R_AX_ACH0_PAGE_CTRL` and
/// `R_AX_ACH0_PAGE_INFO`.
pub const HCI_FC_MODE_MASK: u32 = 0x0000_0006;
pub const HCI_FC_WD_FULL_COND_MASK: u32 = 0x0000_0030;
pub const HCI_FC_WP_CH07_FULL_COND_MASK: u32 = 0x0000_00c0;
pub const HCI_FC_WP_CH811_FULL_COND_MASK: u32 = 0x0000_0300;
pub const PREC_PAGE_CH011_MASK: u32 = 0x0000_01ff;
pub const ACH0_PAGE_CTRL: u32 = 0x8a10;
pub const MIN_PG_MASK: u32 = 0x0000_1fff;
pub const MAX_PG_MASK: u32 = 0x1fff_0000;
pub const GRP: u32 = 1 << 31;
pub const ACH0_PAGE_INFO: u32 = 0x8a50;
pub const AVAL_PG_MASK: u32 = 0x0fff_0000;
pub const USE_PG_MASK: u32 = 0x0000_1fff;
pub const PUB_PAGE_CTRL1: u32 = 0x8a90;
pub const PUBPG_G0_MASK: u32 = 0x0000_1fff;
pub const PUBPG_G1_MASK: u32 = 0x1fff_0000;
pub const PUB_PAGE_CTRL2: u32 = 0x8a94;
pub const PUBPG_ALL_MASK: u32 = 0x0000_1fff;
pub const PUB_PAGE_INFO1: u32 = 0x8a98;
pub const G0_USE_PG_MASK: u32 = 0x0000_1fff;
pub const G1_USE_PG_MASK: u32 = 0x1fff_0000;
pub const PUB_PAGE_INFO2: u32 = 0x8a9c;
pub const PUB_AVAL_PG_MASK: u32 = 0x0000_1fff;
pub const PUB_PAGE_INFO3: u32 = 0x8a8c;
pub const G0_AVAL_PG_MASK: u32 = 0x0000_1fff;
pub const G1_AVAL_PG_MASK: u32 = 0x1fff_0000;
pub const WP_PAGE_CTRL1: u32 = 0x8aa0;
pub const PREC_PAGE_WP_CH07_MASK: u32 = 0x0000_01ff;
pub const PREC_PAGE_WP_CH811_MASK: u32 = 0x01ff_0000;
pub const WP_PAGE_CTRL2: u32 = 0x8aa4;
pub const WP_THRD_MASK: u32 = 0x0000_1fff;
pub const WP_PAGE_INFO1: u32 = 0x8aa8;
pub const WP_AVAL_PG_MASK: u32 = 0x1fff_0000;

/// `R_AX_SS_CTRL`, the STA scheduler's control, and its bits.
pub const SS_CTRL: u32 = 0x9e10;
pub const SS_INIT_DONE_1: u32 = 1 << 31;
pub const SS_WARM_INIT_FLG: u32 = 1 << 29;
pub const SS_NONEMPTY_SS2FINFO_EN: u32 = 1 << 28;
pub const SS_EN: u8 = 1 << 0;

/// The MPDU processor's forwarding and A-MSDU settings `mpdu_proc_init_ax`
/// writes.
pub const MPDU_PROC: u32 = 0x9c00;
pub const A_ICV_ERR: u32 = 1 << 1;
pub const APPEND_FCS: u32 = 1 << 0;
pub const ACTION_FWD0: u32 = 0x9c04;
pub const TRXCFG_MPDU_PROC_ACT_FRWD: u32 = 0x02a9_5a95;
pub const TF_FWD: u32 = 0x9c14;
pub const TRXCFG_MPDU_PROC_TF_FRWD: u32 = 0x0000_aa55;
pub const CUT_AMSDU_CTRL: u32 = 0x9c40;
pub const TRXCFG_MPDU_PROC_CUT_CTRL: u32 = 0x010e_05f0;

/// The security engine's control and MPDU options `sec_eng_init_ax` sets.
pub const SEC_ENG_CTRL: u32 = 0x9d00;
pub const TX_PARTIAL_MODE: u32 = 1 << 11;
pub const CLK_EN_CGCMP: u32 = 1 << 10;
pub const CLK_EN_WAPI: u32 = 1 << 9;
pub const CLK_EN_WEP_TKIP: u32 = 1 << 8;
pub const MC_DEC: u32 = 1 << 3;
pub const BC_DEC: u32 = 1 << 2;
pub const SEC_RX_DEC: u32 = 1 << 1;
pub const SEC_TX_ENC: u32 = 1 << 0;
pub const SEC_MPDU_PROC: u32 = 0x9d04;
pub const APPEND_ICV: u32 = 1 << 1;
pub const APPEND_MIC: u32 = 1 << 0;

/// CMAC0's scheduler registers `scheduler_init_ax` sets.
pub const PREBKF_CFG_0: u32 = 0xc338;
pub const PREBKF_TIME_MASK: u32 = 0x0000_001f;
pub const SCH_PREBKF_24US: u32 = 0x18;
pub const PREBKF_CFG_1: u32 = 0xc33c;
pub const SIFS_MACTXEN_T1_MASK: u32 = 0x0000_007f;
pub const SIFS_MACTXEN_T1: u32 = 0x47;
pub const CCA_CFG_0: u32 = 0xc340;
pub const BTCCA_EN: u32 = 1 << 5;
pub const SCH_EXT_CTRL: u32 = 0xc3fc;
pub const PORT_RST_TSF_ADV: u32 = 1 << 1;

/// CMAC0's address CAM control, whose clear bit the chip drops once the CAM
/// is cleared.
pub const ADDR_CAM_CTRL: u32 = 0xce34;
pub const ADDR_CAM_RANGE_MASK: u32 = 0x00ff_0000;
pub const ADDR_CAM_CLR: u32 = 1 << 8;
pub const ADDR_CAM_EN: u32 = 1 << 0;

/// CMAC0's RX filters: per frame type, the MAC filter (`DEFAULT_AX_RX_FLTR`
/// is `rtw89_mac_gen_ax.default_rx_fltr`, which `rtw89_core_init` gives
/// `hal.rx_fltr`) with its maximum MPDU length, and the PLCP header checks.
pub const PLCP_HDR_FLTR: u32 = 0xce04;
pub const HE_SIGB_CRC_CHK: u32 = 1 << 6;
pub const VHT_MU_SIGB_CRC_CHK: u32 = 1 << 5;
pub const VHT_SU_SIGB_CRC_CHK: u32 = 1 << 4;
pub const SIGA_CRC_CHK: u32 = 1 << 3;
pub const LSIG_PARITY_CHK_EN: u32 = 1 << 2;
pub const CCK_SIG_CHK: u32 = 1 << 1;
pub const CCK_CRC_CHK: u32 = 1 << 0;
pub const RX_FLTR_OPT: u32 = 0xce20;
pub const RX_MPDU_MAX_LEN_MASK: u32 = 0x003f_0000;
pub const DEFAULT_AX_RX_FLTR: u32 = 0x0300_44be;
pub const CTRL_FLTR: u32 = 0xce24;
pub const MGNT_FLTR: u32 = 0xce28;
pub const DATA_FLTR: u32 = 0xce2c;
pub const RX_FLTR_FRAME_TO_HOST: u32 = 0x5555_5555;

/// CMAC0's CCA control and the checks it enables and disables.
pub const CCA_CONTROL: u32 = 0xc390;
pub const TB_CHK_TX_NAV: u32 = 1 << 31;
pub const TB_CHK_BASIC_NAV: u32 = 1 << 30;
pub const TB_CHK_BTCCA: u32 = 1 << 29;
pub const TB_CHK_EDCCA: u32 = 1 << 28;
pub const TB_CHK_CCA_S80: u32 = 1 << 27;
pub const TB_CHK_CCA_S40: u32 = 1 << 26;
pub const TB_CHK_CCA_S20: u32 = 1 << 25;
pub const TB_CHK_CCA_P20: u32 = 1 << 24;
pub const SIFS_CHK_BTCCA: u32 = 1 << 21;
pub const SIFS_CHK_EDCCA: u32 = 1 << 20;
pub const SIFS_CHK_CCA_S80: u32 = 1 << 19;
pub const SIFS_CHK_CCA_S40: u32 = 1 << 18;
pub const SIFS_CHK_CCA_S20: u32 = 1 << 17;
pub const SIFS_CHK_CCA_P20: u32 = 1 << 16;
pub const CTN_CHK_TXNAV: u32 = 1 << 8;
pub const CTN_CHK_INTRA_NAV: u32 = 1 << 7;
pub const CTN_CHK_BASIC_NAV: u32 = 1 << 6;
pub const CTN_CHK_BTCCA: u32 = 1 << 5;
pub const CTN_CHK_EDCCA: u32 = 1 << 4;
pub const CTN_CHK_CCA_S80: u32 = 1 << 3;
pub const CTN_CHK_CCA_S40: u32 = 1 << 2;
pub const CTN_CHK_CCA_S20: u32 = 1 << 1;
pub const CTN_CHK_CCA_P20: u32 = 1 << 0;

/// CMAC0's response checks (`R_AX_RSP_CHK_SIG`, `R_AX_TRXPTCL_RESP_0`), the
/// SIFS fields of the latter, and the response rate settings
/// (`rtw8852b_rrsr_cfgs`).
pub const RSP_CHK_SIG: u32 = 0xcc00;
pub const RSP_CHK_BASIC_NAV: u32 = 1 << 21;
pub const RSP_CHK_INTRA_NAV: u32 = 1 << 20;
pub const RSP_CHK_TXNAV: u32 = 1 << 19;
pub const TRXPTCL_RESP_0: u32 = 0xcc04;
pub const RSP_CHK_SEC_CCA_80: u32 = 1 << 28;
pub const RSP_CHK_SEC_CCA_40: u32 = 1 << 27;
pub const RSP_CHK_SEC_CCA_20: u32 = 1 << 26;
pub const RSP_CHK_BTCCA: u32 = 1 << 25;
pub const RSP_CHK_EDCCA: u32 = 1 << 24;
pub const RSP_CHK_CCA: u32 = 1 << 23;
pub const WMAC_SPEC_SIFS_OFDM_MASK: u32 = 0x0000_ff00;
pub const WMAC_SPEC_SIFS_CCK_MASK: u32 = 0x0000_00ff;
pub const WMAC_SPEC_SIFS_OFDM_52B: u32 = 0x11;
pub const WMAC_SPEC_SIFS_CCK: u32 = 0xa;
pub const TRXPTCL_RRSR_CTL_0: u32 = 0xcc08;
pub const WMAC_RESP_RSC_MASK: u32 = 0x0000_0c00;
pub const WMAC_RESP_REF_RATE_SEL: u32 = 1 << 9;
pub const RXTRIG_TEST_USER_2: u32 = 0xccb0;
pub const RXTRIG_FCSCHK_EN: u32 = 1 << 20;

/// The WMAC's NAV control, which `nav_ctrl_init_ax` sets for both bands at
/// once.
pub const WMAC_NAV_CTL: u32 = 0xcc80;
pub const WMAC_NAV_UPPER_EN: u32 = 1 << 26;
pub const WMAC_PLCP_UP_NAV_EN: u32 = 1 << 17;
pub const WMAC_TF_UP_NAV_EN: u32 = 1 << 16;
pub const WMAC_NAV_UPPER_MASK: u32 = 0x0000_ff00;
pub const NAV_25MS: u32 = 0xc4;

/// CMAC0's spatial reuse and BSSID source controls, each reached a byte at a
/// time.
pub const RX_SR_CTRL: u32 = 0xce4a;
pub const SR_EN: u8 = 1 << 0;
pub const BSSID_SRC_CTRL: u32 = 0xce4b;
pub const PLCP_SRC_EN: u8 = 1 << 0;

/// CMAC0's TMAC registers `tmac_init_ax` sets.
pub const MAC_LOOPBACK: u32 = 0xcc20;
pub const MACLBK_EN: u32 = 1 << 0;
pub const TCR0: u32 = 0xca00;
pub const TCR_UDF_THSD_MASK: u32 = 0x007f_0000;
pub const TCR_UDF_THSD: u32 = 6;
pub const TXD_FIFO_CTRL: u32 = 0xca1c;
pub const TXDFIFO_HIGH_MCS_THRE_MASK: u32 = 0x0000_f000;
pub const TXDFIFO_HIGH_MCS_THRE: u32 = 7;
pub const TXDFIFO_LOW_MCS_THRE_MASK: u32 = 0x0000_0f00;
pub const TXDFIFO_LOW_MCS_THRE: u32 = 7;

/// CMAC0's RMAC registers `rmac_init_ax` sets: the BA CAM's control, whose
/// reset field the chip clears once the CAM is reset, the deadlock
/// protection's timers, and the receive configuration's channel enables.
pub const RESPBA_CAM_CTRL: u32 = 0xce3c;
pub const SSN_SEL: u8 = 1 << 2;
pub const BACAM_RST_MASK: u32 = 0x0000_0003;
pub const S_AX_BACAM_RST_ALL: u32 = 2;
pub const DLK_PROTECT_CTL: u32 = 0xce02;
pub const RX_DLK_CCA_TIME_MASK: u32 = 0x0000_ff00;
pub const RX_DLK_DATA_TIME_MASK: u32 = 0x0000_00f0;
pub const RCR: u32 = 0xce00;
pub const CH_EN_MASK: u32 = 0x0000_000f;

/// CMAC0's TX sub-carrier values and response rate enables.
pub const TX_SUB_CARRIER_VALUE: u32 = 0xc088;
pub const TXSC_80M_MASK: u32 = 0x0000_0f00;
pub const TXSC_40M_MASK: u32 = 0x0000_00f0;
pub const TXSC_20M_MASK: u32 = 0x0000_000f;
pub const PTCL_RRSR1: u32 = 0xc090;
pub const RRSR_RATE_EN_MASK: u32 = 0x0000_0f00;
pub const RRSR_OFDM_CCK_EN: u32 = 3;

/// CMAC0's protocol registers `ptcl_init_ax` sets.
pub const SIFS_SETTING: u32 = 0xc624;
pub const HW_CTS2SELF_PKT_LEN_TH_MASK: u32 = 0xff00_0000;
pub const HW_CTS2SELF_PKT_LEN_TH_TWW_MASK: u32 = 0x00fc_0000;
pub const HW_CTS2SELF_EN: u32 = 1 << 16;
pub const S_AX_CTS2S_TH_1K: u32 = 4;
pub const S_AX_CTS2S_TH_SEC_256B: u32 = 1;
pub const PTCL_FSM_MON: u32 = 0xc6e8;
pub const PTCL_TX_ARB_TO_MODE: u32 = 1 << 6;
pub const PTCL_TX_ARB_TO_THR_MASK: u32 = 0x0000_003f;
pub const S_AX_PTCL_TO_2MS: u32 = 0x3f;
pub const PTCL_COMMON_SETTING_0: u32 = 0xc600;
pub const PTCL_TRIGGER_SS_EN_UL: u32 = 1 << 4;
pub const PTCL_TRIGGER_SS_EN_1: u32 = 1 << 3;
pub const PTCL_TRIGGER_SS_EN_0: u32 = 1 << 2;
pub const CMAC_TX_MODE_1: u32 = 1 << 1;
pub const CMAC_TX_MODE_0: u32 = 1 << 0;
pub const PTCLRPT_FULL_HDL: u32 = 0xc660;
pub const SPE_RPT_PATH_MASK: u32 = 0x0000_0030;
pub const FWD_TO_WLCPU: u32 = 1;
pub const AGG_LEN_VHT_0: u32 = 0xc618;
pub const AMPDU_MAX_LEN_VHT_MASK: u32 = 0x000f_ffff;

/// CMAC0's RX DMA control and `RX_FULL_MODE`, its RU pointers' full modes.
pub const RXDMA_CTRL_0: u32 = 0xc804;
pub const RX_FULL_MODE: u8 = 0x3f;

/// The DMAC error interrupt masks `enable_imr_ax` sets, with
/// `rtw8852b_imr_info`'s values.
pub const WDRLS_ERR_IMR: u32 = 0x9430;
pub const WDRLS_IMR_EN_CLR: u32 = 0x0000_3337;
pub const WDRLS_IMR_SET: u32 = 0x0000_3327;
pub const SEC_DEBUG: u32 = 0x9d1c;
pub const IMR_ERROR: u32 = 1 << 3;
pub const MPDU_TX_ERR_IMR: u32 = 0x9bf4;
pub const TX_HDR3_SIZE_ERR_INT_EN: u32 = 1 << 5;
pub const TX_OFFSET_ERR_INT_EN: u32 = 1 << 4;
pub const TX_MPDU_SIZE_ZERO_INT_EN: u32 = 1 << 3;
pub const TX_NXT_ERRPKTID_INT_EN: u32 = 1 << 2;
pub const TX_GET_ERRPKTID_INT_EN: u32 = 1 << 1;
pub const MPDU_RX_ERR_IMR: u32 = 0x9cf4;
pub const RPT_ERR_INT_EN: u32 = 1 << 3;
pub const MHDRLEN_ERR_INT_EN: u32 = 1 << 1;
pub const GETPKTID_ERR_INT_EN: u32 = 1 << 0;
pub const STA_SCHEDULER_ERR_IMR: u32 = 0x9ef0;
pub const PLE_B_PKTID_ERR_INT_EN: u32 = 1 << 2;
pub const RPT_HANG_TIMEOUT_INT_EN: u32 = 1 << 1;
pub const SEARCH_HANG_TIMEOUT_INT_EN: u32 = 1 << 0;
pub const STA_SCHEDULER_IMR_SET: u32 = 0x0000_0007;
pub const TXPKTCTL_ERR_IMR_ISR: u32 = 0x9f1c;
pub const TXPKTCTL_IMR_B0_CLR: u32 = 0x0000_030f;
pub const TXPKTCTL_IMR_B0_SET: u32 = 0x0000_0101;
pub const TXPKTCTL_ERR_IMR_ISR_B1: u32 = 0x9f2c;
pub const TXPKTCTL_IMR_B1_CLR: u32 = 0x0000_030f;
pub const TXPKTCTL_IMR_B1_SET: u32 = 0x0000_0303;
pub const WDE_ERR_IMR: u32 = 0x8c38;
pub const WDE_IMR_CLR: u32 = 0x070f_f0ff;
pub const WDE_IMR_SET: u32 = 0x070f_f0ff;
pub const PLE_ERR_IMR: u32 = 0x9038;
pub const PLE_IMR_CLR: u32 = 0x070f_f0ff;
pub const PLE_IMR_SET: u32 = 0x070f_f0df;
pub const PKTIN_ERR_IMR: u32 = 0x9a20;
pub const PKTIN_GETPKTID_ERR_INT_EN: u32 = 1 << 0;
pub const HOST_DISPATCHER_ERR_IMR: u32 = 0x8850;
pub const HOST_DISP_IMR_CLR: u32 = 0xff0f_ffff;
pub const HOST_DISP_IMR_SET: u32 = 0x0c00_0161;
pub const CPU_DISPATCHER_ERR_IMR: u32 = 0x8854;
pub const CPU_DISP_IMR_CLR: u32 = 0xff07_ffff;
pub const CPU_DISP_IMR_SET: u32 = 0x0400_0062;
pub const OTHER_DISPATCHER_ERR_IMR: u32 = 0x8858;
pub const OTHER_DISP_IMR_CLR: u32 = 0x3f03_1f1f;
pub const CPUIO_ERR_IMR: u32 = 0x9840;
pub const CPUIO_IMR_CLR: u32 = 0x0000_1111;
pub const CPUIO_IMR_SET: u32 = 0x0000_1111;
pub const BBRPT_COM_ERR_IMR_ISR: u32 = 0x960c;
pub const BBRPT_COM_NULL_PLPKTID_ERR_INT_EN: u32 = 1 << 0;
pub const BBRPT_CHINFO_ERR_IMR_ISR: u32 = 0x962c;
pub const BBRPT_CHINFO_IMR_CLR: u32 = 0x0000_00ff;
pub const BBRPT_DFS_ERR_IMR_ISR: u32 = 0x963c;
pub const BBRPT_DFS_TO_ERR_INT_EN: u32 = 1 << 0;
pub const LA_ERRFLAG: u32 = 0x966c;
pub const LA_IMR_DATA_LOSS_ERR: u32 = 1 << 0;

/// CMAC0's error interrupt masks `enable_imr_ax` sets, with
/// `rtw8852b_imr_info`'s values; its PHY interface mask clears and sets
/// nothing.
pub const SCHEDULE_ERR_IMR: u32 = 0xc3e8;
pub const SORT_NON_IDLE_ERR_INT_EN: u32 = 1 << 1;
pub const FSM_TIMEOUT_ERR_INT_EN: u32 = 1 << 0;
pub const PTCL_IMR0: u32 = 0xc6c0;
pub const PTCL_IMR_CLR_ALL: u32 = 0xffff_ffff;
pub const PTCL_IMR_SET: u32 = 0x1080_0001;
pub const DLE_CTRL: u32 = 0xc800;
pub const DLE_IMR_CLR: u32 = 0x0080_c000;
pub const DLE_IMR_SET: u32 = 0x0000_c000;
pub const PHYINFO_ERR_IMR: u32 = 0xccfc;
pub const RMAC_ERR_ISR: u32 = 0xcef4;
pub const RMAC_IMR_CLR: u32 = 0x000f_f000;
pub const RMAC_IMR_SET: u32 = 0x000e_4000;
pub const TMAC_ERR_IMR_ISR: u32 = 0xccec;
pub const TMAC_IMR_CLR: u32 = 0x0000_0780;
pub const TMAC_IMR_SET: u32 = 0x0000_0780;

/// The DMAC's and CMAC0's error interrupt enables `err_imr_ctrl_ax` writes.
pub const DMAC_ERR_IMR: u32 = 0x8520;
pub const DMAC_ERR_IMR_EN: u32 = 0xffff_ffff;
pub const CMAC_ERR_IMR: u32 = 0xc160;
pub const CMAC0_ERR_IMR_EN: u32 = 0xffff_ffff;

/// The WD release mode and release report settings `set_host_rpr_ax` makes
/// over PCIe.
pub const WDRLS_CFG: u32 = 0x9408;
pub const WDRLS_MODE_MASK: u32 = 0x0000_0003;
pub const RLSRPT0_CFG0: u32 = 0x9410;
pub const RLSRPT0_FLTR_MAP_MASK: u32 = 0x0f00_0000;
pub const RLSRPT0_CFG1: u32 = 0x9414;
pub const RLSRPT0_TO_MASK: u32 = 0x00ff_0000;
pub const RLSRPT0_AGGNUM_MASK: u32 = 0x0000_00ff;

/// CMAC0's contention TX enables, which `rtw89_set_hw_sch_tx_en` reaches 16
/// bits at a time.
pub const CTN_TXEN: u32 = 0xc348;
pub const CTN_TXEN_ALL_MASK: u32 = 0x0000_ffff;
pub const CTN_TXEN_HGQ: u32 = 1 << 11;
pub const CTN_TXEN_MGQ: u32 = 1 << 8;

/// The PCIe PHY's MDIO pages (`MDIO_PG0_G1` to `MDIO_PG1_G2`): page 0 holds
/// addresses below 0x20, page 1 the rest, one pair per link generation.
pub const MDIO_PG0_G1: u16 = 0;
pub const MDIO_PG1_G1: u16 = 1;
pub const MDIO_PG0_G2: u16 = 2;
pub const MDIO_PG1_G2: u16 = 3;
/// `RAC_REG_REV2`, `BAC_CMU_EN_DLY_MASK` and `PCIE_DPHY_DLY_25US`.
pub const RAC_REG_REV2: u8 = 0x1b;
pub const BAC_CMU_EN_DLY_MASK: u16 = 0xf000;
pub const PCIE_DPHY_DLY_25US: u16 = 0x1;
/// `RAC_REG_FLD_0`, `BAC_AUTOK_N_MASK` and `PCIE_AUTOK_4`.
pub const RAC_REG_FLD_0: u8 = 0x1d;
pub const BAC_AUTOK_N_MASK: u16 = 0x000c;
pub const PCIE_AUTOK_4: u16 = 0x3;
/// `RAC_CTRL_PPR_V1` and `B_AX_CALIB_EN`.
pub const RAC_CTRL_PPR_V1: u8 = 0x30;
pub const CALIB_EN: u16 = 1 << 13;

/// Configuration space offsets: `RTW89_PCIE_PHY_RATE` (the link status's
/// low byte) with `RTW89_PCIE_PHY_RATE_MASK`, and `RTW89_PCIE_L1_CTRL` with
/// `RTW89_PCIE_BIT_L1`.
pub const PCIE_PHY_RATE: u16 = 0x82;
pub const PCIE_PHY_RATE_MASK: u8 = 0x03;
pub const PCIE_L1_CTRL: u16 = 0x0719;
pub const PCIE_BIT_L1: u8 = 1 << 3;
