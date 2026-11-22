// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2020 Realtek Corporation
//! An RTL8852BE's PCIe pre-init as pinned rtw89 runs it at probe:
//! `rtw89_pci_ops_mac_pre_init_ax` (pci.c), which `rtw89_mac_partial_init`
//! reaches through `hci.ops->mac_pre_init` right after the DMAC pre-init
//! ([`super::dle::partial_init_before_hci`]). After it,
//! `rtw89_mac_fwdl_preconfig` makes no access on an AX chip and
//! `rtw89_fw_download` follows, so this is everything between the two.
//!
//! In rtw89's order, [`mac_pre_init`] makes the PCIe settings RTL8852B's
//! branches make, among them the PCIe PHY's (`rtw89_pci_dphy_delay` and
//! `rtw89_pci_autok_x` over MDIO) and `rtw89_pci_auto_refclk_cal` with
//! `autook_en` false, which reads the link's rate and turns the PHY's clock
//! calibration off with ASPM L1 held off meanwhile. It then stops the DMA
//! (`rtw89_pci_ctrl_dma_all`), waits for every channel to go idle, clears the
//! indices, sets the DMA mode (`rtw89_pci_mode_op`), programs every ring
//! ([`ring::Rings`], `rtw89_pci_ops_reset`), resets the BD RAM, stops every
//! TX channel but the firmware command channel CH12, and starts the DMA
//! again. RX DMA then runs on RXQ and RPQ, and CH12 is the only TX channel
//! the chip fetches from; nothing is fetched until a command is kicked off.
//! As in rtw89, the DMA stop comes after the PCIe settings, so the HCI DMA
//! enables the DMAC pre-init set stay on until then.
//!
//! Configuration space is read and written as `rtw89_pci_read_config_byte`
//! and `rtw89_pci_write_config_byte` do: through the configuration space,
//! and through the chip's DBI window when that access fails.
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included. Polls follow `read_poll_timeout`
//! counted in steps ([`Registers::poll32`]): MDIO every 10 us for 2000 us,
//! DBI every 10 us for 200 us, the DMA idle polls every 10 us for 100 us and
//! the BD RAM reset every 1 us for 100 us.
//!
//! What this leaves out, and why:
//! - Other chips' branches: RTL8852A's and RTL8852C's settings, PHY
//!   deglitching, EQ and I/O recovery, and the PCI BER quirk, which no DMI,
//!   SSID or chip quirk sets for an RTL8852BE.
//! - `rtw89_pci_auto_refclk_cal`'s calibration proper and `__get_target`:
//!   rtw89 runs them only with `autook_en`, and the pre-init passes false.
//! - `rtw89_pci_link_cfg` and `rtw89_pci_l1ss_cfg`, which
//!   `rtw89_pci_basic_cfg` calls once `rtw89_chip_info_setup` returns (and
//!   on resume), and `rtw89_pci_ltr_set`, which
//!   `rtw89_pci_ops_mac_post_init_ax` calls in the full MAC init after the
//!   download: Stela never enables the chip's ASPM, CLKREQ, L1SS or LTR and
//!   leaves them as the platform left them, off.
//! - Interrupts: the pre-init does not touch them; a later step configures
//!   them.
//!
//! A pre-init that returns proves only that the bits rtw89 polls answered
//! and that the rings' addresses were written. No packet has moved, and
//! nothing here shows that the chip fetches from the rings correctly or that
//! the firmware download will succeed.
use super::io::{self, Io, Registers, prep};
use super::registers::*;
use crate::bus::pci::ConfigSpace;

pub mod ring;

use ring::Rings;

/// `rtw8852b_pci_info`'s DMA settings: `tx_burst`, `rx_burst`,
/// `multi_tag_num`, `wd_dma_idle_intvl` and `wd_dma_act_intvl`, and
/// `lbc_tmr`, as `enum mac_ax_*` numbers them.
const MAC_AX_TX_BURST_2048B: u32 = 7;
const MAC_AX_RX_BURST_128B: u32 = 3;
const MAC_AX_TAG_NUM_8: u32 = 7;
const MAC_AX_WD_DMA_INTVL_256NS: u32 = 1;
const MAC_AX_LBC_TMR_2MS: u32 = 8;
/// `RTW89_PCI_WR_RETRY_CNT`.
const WR_RETRY_CNT: u64 = 20;
/// `RTW89_PCI_POLL_BDRAM_RST_CNT`.
const POLL_BDRAM_RST_CNT: u64 = 100;

/// `enum rtw89_pcie_phy`: the link generation the MDIO page follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRate {
    Gen1,
    Gen2,
}

/// Why the PCIe pre-init failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An access the interface refused, or a poll that timed out:
    /// [`io::Error::Timeout`] names the register and the bits it waited on
    /// (`MDIO_CFG` for MDIO, `DBI_FLAG + 2` for DBI).
    Io(io::Error),
    /// `rtw89_pci_auto_refclk_cal`'s `-EOPNOTSUPP`: the link status's
    /// low byte named neither 2.5 nor 5 GT/s.
    PhyRate(u8),
    /// Programming or releasing a ring failed.
    Ring(ring::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ring::Error> for Error {
    fn from(error: ring::Error) -> Self {
        match error {
            ring::Error::Io(error) => Self::Io(error),
            error => Self::Ring(error),
        }
    }
}

/// `rtw89_pci_ops_mac_pre_init_ax` on an RTL8852BE.
///
/// # Safety
/// `io` and `config` reach the same RTL8852BE function, whose DMA domain
/// `rings` was allocated in, and no other worker programs that function
/// meanwhile. From the first ring address written, the chip may read the
/// BDs and write the RX buffers whenever its DMA runs: the caller keeps
/// `rings` for as long as that may happen (dropping it keeps the memory for
/// good) and releases it only after stopping and draining the DMA.
pub unsafe fn mac_pre_init<I: Io + ?Sized, C: ConfigSpace + ?Sized>(
    io: &mut I,
    config: &mut C,
    rings: &mut Rings,
) -> Result<(), Error> {
    // rtw89_pci_ber: no quirk sets RTW89_QUIRK_PCI_BER on an RTL8852BE.
    // rtw89_pci_rxdma_prefth: RTL8852A only.
    l1off_pwroff(io)?;
    // rtw89_pci_deglitch_setting: RTL8852A and RTL8852C only.
    // rtw89_pci_l2_rxen_lat: RTL8852A only.
    aphy_pwrcut(io)?;
    hci_ldo(io)?;
    // rtw89 ignores what rtw89_pci_dphy_delay returns.
    match dphy_delay(io) {
        Ok(()) | Err(Error::Io(io::Error::Timeout { .. })) => {}
        Err(error) => return Err(error),
    }
    autok_x(io)?;
    auto_refclk_cal(io, config)?;
    power_wake(io, true)?;
    // rtw89_pci_autoload_hang, rtw89_pci_l12_vmain, rtw89_pci_gen2_force_ib,
    // rtw89_pci_l1_ent_lat and rtw89_pci_wd_exit_l1: RTL8852C only.
    set_sic(io)?;
    set_lbc(io)?;
    // rtw89_pci_set_io_rcy: RTL8852C only.
    set_dbg(io)?;
    set_keep_reg(io)?;

    io.write32_set(PCIE_DMA_STOP1, STOP_WPDMA)?;
    // stop DMA activities
    ctrl_dma_all(io, false)?;
    poll_dma_all_idle(io)?;
    clr_idx_all(io)?;
    mode_op(io)?;
    // fill TRX BD indexes
    // SAFETY: the DMA was stopped and polled idle just above, and the
    // caller's contract binds `rings` to this function's DMA domain.
    unsafe { rings.reset(io)? };
    rst_bdram(io)?;
    // disable all channels except to FW CMD channel to download firmware
    ctrl_txdma_ch(io, false)?;
    ctrl_txdma_fw_ch(io, true)?;
    // start DMA activities
    ctrl_dma_all(io, true)?;
    Ok(())
}

/// `rtw89_pci_ctrl_dma_trx`: TXHCI_EN and RXHCI_EN in `init_cfg_reg`.
fn ctrl_dma_trx<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    let bits = RXHCI_EN | TXHCI_EN;
    if enable {
        io.write32_set(PCIE_INIT_CFG1, bits)
    } else {
        io.write32_clr(PCIE_INIT_CFG1, bits)
    }
}

/// `rtw89_pci_ctrl_dma_io`: STOP_PCIEIO (`dma_io_stop`), cleared to enable.
fn ctrl_dma_io<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    if enable {
        io.write32_clr(PCIE_DMA_STOP1, STOP_PCIEIO)
    } else {
        io.write32_set(PCIE_DMA_STOP1, STOP_PCIEIO)
    }
}

/// `rtw89_pci_ctrl_dma_all`: the DMA's I/O, then its TX and RX engines.
pub fn ctrl_dma_all<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    ctrl_dma_io(io, enable)?;
    ctrl_dma_trx(io, enable)
}

/// `rtw89_pci_ctrl_txdma_ch_ax`: every TX channel's stop bit in
/// `dma_stop1`; `dma_stop2` is 0 on an RTL8852BE.
pub fn ctrl_txdma_ch<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    if enable {
        io.write32_clr(PCIE_DMA_STOP1, TX_STOP1_MASK_V1)
    } else {
        io.write32_set(PCIE_DMA_STOP1, TX_STOP1_MASK_V1)
    }
}

/// `rtw89_pci_ctrl_txdma_fw_ch_ax`: CH12's stop bit alone.
pub fn ctrl_txdma_fw_ch<I: Io + ?Sized>(io: &mut I, enable: bool) -> Result<(), io::Error> {
    if enable {
        io.write32_clr(PCIE_DMA_STOP1, STOP_CH12)
    } else {
        io.write32_set(PCIE_DMA_STOP1, STOP_CH12)
    }
}

/// `read_poll_timeout(op, …, step_us, bound_us, false, …)` over a register
/// narrower than 32 bits: the value that satisfied `ready`.
fn poll<I: Io + ?Sized, T: Copy>(
    io: &mut I,
    register: u32,
    mask: u32,
    step_us: u64,
    bound_us: u64,
    read: impl Fn(&mut I, u32) -> Result<T, io::Error>,
    ready: impl Fn(T) -> bool,
) -> Result<T, io::Error> {
    let mut waited = 0;
    loop {
        let value = read(io, register)?;
        if ready(value) {
            return Ok(value);
        }
        if waited >= bound_us {
            return Err(io::Error::Timeout { register, mask });
        }
        io.delay_us(step_us);
        waited += step_us;
    }
}

/// `u16_replace_bits`.
const fn replace16(value: u16, field: u16, mask: u16) -> u16 {
    (value & !mask) | prep(field as u32, mask as u32) as u16
}

/// `rtw89_pci_check_mdio`: the PHY address and its page for `speed`, then
/// `rw_bit`, which the chip clears once the access is done.
fn check_mdio<I: Io + ?Sized>(
    io: &mut I,
    addr: u8,
    speed: PhyRate,
    rw_bit: u16,
) -> Result<(), io::Error> {
    io.write8(MDIO_CFG, addr & 0x1f)?;
    let mut val = io.read16(MDIO_CFG)?;
    let page = match (speed, addr < 0x20) {
        (PhyRate::Gen1, true) => MDIO_PG0_G1,
        (PhyRate::Gen1, false) => MDIO_PG1_G1,
        (PhyRate::Gen2, true) => MDIO_PG0_G2,
        (PhyRate::Gen2, false) => MDIO_PG1_G2,
    };
    val = replace16(val, page, MDIO_PHY_ADDR_MASK as u16);
    io.write16(MDIO_CFG, val)?;
    io.write16_set(MDIO_CFG, rw_bit)?;
    poll(
        io,
        MDIO_CFG,
        rw_bit.into(),
        10,
        2000,
        |io, register| io.read16(register),
        |val| val & rw_bit == 0,
    )
    .map(|_| ())
}

/// `rtw89_read16_mdio`.
fn read16_mdio<I: Io + ?Sized>(io: &mut I, addr: u8, speed: PhyRate) -> Result<u16, io::Error> {
    check_mdio(io, addr, speed, MDIO_RFLAG)?;
    io.read16(MDIO_RDATA)
}

/// `rtw89_write16_mdio`.
fn write16_mdio<I: Io + ?Sized>(
    io: &mut I,
    addr: u8,
    data: u16,
    speed: PhyRate,
) -> Result<(), io::Error> {
    io.write16(MDIO_WDATA, data)?;
    check_mdio(io, addr, speed, MDIO_WFLAG)
}

/// `rtw89_write16_mdio_mask`.
fn write16_mdio_mask<I: Io + ?Sized>(
    io: &mut I,
    addr: u8,
    mask: u16,
    data: u16,
    speed: PhyRate,
) -> Result<(), io::Error> {
    let val = read16_mdio(io, addr, speed)?;
    write16_mdio(io, addr, replace16(val, data, mask), speed)
}

/// `rtw89_dbi_write8`: one configuration byte through the DBI window.
fn dbi_write8<I: Io + ?Sized>(io: &mut I, addr: u16, data: u8) -> Result<(), io::Error> {
    let addr_2lsb = addr & DBI_2LSB as u16;
    let mut write_addr = addr & DBI_ADDR_MSK as u16;
    write_addr |= prep(1 << addr_2lsb, DBI_WREN_MSK) as u16;
    io.write8(DBI_WDATA + u32::from(addr_2lsb), data)?;
    io.write16(DBI_FLAG, write_addr)?;
    io.write8(DBI_FLAG + 2, (DBI_WFLAG >> 16) as u8)?;
    poll(
        io,
        DBI_FLAG + 2,
        0xff,
        10,
        10 * WR_RETRY_CNT,
        |io, register| io.read8(register),
        |flag| flag == 0,
    )
    .map(|_| ())
}

/// `rtw89_dbi_read8`: one configuration byte through the DBI window.
fn dbi_read8<I: Io + ?Sized>(io: &mut I, addr: u16) -> Result<u8, io::Error> {
    let read_addr = addr & DBI_ADDR_MSK as u16;
    io.write16(DBI_FLAG, read_addr)?;
    io.write8(DBI_FLAG + 2, (DBI_RFLAG >> 16) as u8)?;
    poll(
        io,
        DBI_FLAG + 2,
        0xff,
        10,
        10 * WR_RETRY_CNT,
        |io, register| io.read8(register),
        |flag| flag == 0,
    )?;
    io.read8(DBI_RDATA + u32::from(addr & 3))
}

/// `rtw89_pci_write_config_byte` for an RTL8852B: the configuration space,
/// or DBI when that write fails.
fn write_config_byte<I: Io + ?Sized, C: ConfigSpace + ?Sized>(
    io: &mut I,
    config: &mut C,
    addr: u16,
    data: u8,
) -> Result<(), io::Error> {
    match config.write8(addr, data) {
        Ok(()) => Ok(()),
        Err(_) => dbi_write8(io, addr, data),
    }
}

/// `rtw89_pci_read_config_byte` for an RTL8852B: the configuration space,
/// or DBI when that read fails.
fn read_config_byte<I: Io + ?Sized, C: ConfigSpace + ?Sized>(
    io: &mut I,
    config: &mut C,
    addr: u16,
) -> Result<u8, io::Error> {
    match config.read8(addr) {
        Ok(value) => Ok(value),
        Err(_) => dbi_read8(io, addr),
    }
}

/// `rtw89_pci_autok_x`.
fn autok_x<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    Ok(write16_mdio_mask(
        io,
        RAC_REG_FLD_0,
        BAC_AUTOK_N_MASK,
        PCIE_AUTOK_4,
        PhyRate::Gen1,
    )?)
}

/// `rtw89_pci_auto_refclk_cal(rtwdev, false)`: the link's rate picks the
/// MDIO page; with ASPM L1 held off, the PHY's clock calibration is turned
/// off when it was on, and L1 is set back. As in rtw89, setting L1 back
/// decides what returns, so an MDIO timeout behind a successful restore
/// returns success.
fn auto_refclk_cal<I: Io + ?Sized, C: ConfigSpace + ?Sized>(
    io: &mut I,
    config: &mut C,
) -> Result<(), Error> {
    let val8 = read_config_byte(io, config, PCIE_PHY_RATE)?;
    let phy_rate = match val8 & PCIE_PHY_RATE_MASK {
        0x1 => PhyRate::Gen1,
        0x2 => PhyRate::Gen2,
        _ => return Err(Error::PhyRate(val8)),
    };
    // Disable L1BD
    let bdr_ori = read_config_byte(io, config, PCIE_L1_CTRL)?;
    let l1_flag = bdr_ori & PCIE_BIT_L1 != 0;
    if l1_flag {
        write_config_byte(io, config, PCIE_L1_CTRL, bdr_ori & !PCIE_BIT_L1)?;
    }

    let calibration = calibration_off(io, phy_rate);
    // !autook_en: goto end

    // end: Set L1BD to ori
    if !l1_flag {
        return Ok(calibration?);
    }
    let restored = write_config_byte(io, config, PCIE_L1_CTRL, bdr_ori);
    match calibration {
        Ok(()) | Err(io::Error::Timeout { .. }) => Ok(restored?),
        Err(refused) => {
            restored?;
            Err(refused.into())
        }
    }
}

/// `rtw89_pci_auto_refclk_cal`'s first MDIO steps: B_AX_CALIB_EN cleared
/// in RAC_CTRL_PPR_V1 when it was set.
fn calibration_off<I: Io + ?Sized>(io: &mut I, phy_rate: PhyRate) -> Result<(), io::Error> {
    let val16 = read16_mdio(io, RAC_CTRL_PPR_V1, phy_rate)?;
    if val16 & CALIB_EN != 0 {
        write16_mdio(io, RAC_CTRL_PPR_V1, val16 & !CALIB_EN, phy_rate)?;
    }
    Ok(())
}

/// `rtw89_pci_l1off_pwroff`.
fn l1off_pwroff<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_clr(PCIE_PS_CTRL, L1OFF_PWR_OFF_EN)
}

/// `rtw89_pci_aphy_pwrcut`.
fn aphy_pwrcut<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_clr(SYS_PW_CTRL, PSUS_OFF_CAPC_EN)
}

/// `rtw89_pci_hci_ldo` for an RTL8852B.
fn hci_ldo<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_set(SYS_SDIO_CTRL, PCIE_DIS_L2_CTRL_LDO_HCI)?;
    io.write32_clr(SYS_SDIO_CTRL, PCIE_DIS_WLSUS_AFT_PDN)
}

/// `rtw89_pci_dphy_delay`.
fn dphy_delay<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    Ok(write16_mdio_mask(
        io,
        RAC_REG_REV2,
        BAC_CMU_EN_DLY_MASK,
        PCIE_DPHY_DLY_25US,
        PhyRate::Gen1,
    )?)
}

/// `rtw89_pci_power_wake_ax`.
fn power_wake<I: Io + ?Sized>(io: &mut I, pwr_up: bool) -> Result<(), io::Error> {
    if pwr_up {
        io.write32_set(HCI_OPT_CTRL, WAKE_CTRL)
    } else {
        io.write32_clr(HCI_OPT_CTRL, WAKE_CTRL)
    }
}

/// `rtw89_pci_set_sic`.
fn set_sic<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_clr(PCIE_EXP_CTRL, SIC_EN_FORCE_CLKREQ)
}

/// `rtw89_pci_set_lbc` with `lbc_en` enabled: the timer and enables
/// written, then set once more.
fn set_lbc<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    let mut lbc = io.read32(LBC_WATCHDOG)?;
    lbc = (lbc & !LBC_TIMER) | prep(MAC_AX_LBC_TMR_2MS, LBC_TIMER);
    lbc |= LBC_FLAG | LBC_EN;
    io.write32(LBC_WATCHDOG, lbc)?;
    io.write32_set(LBC_WATCHDOG, lbc)
}

/// `rtw89_pci_set_dbg` for an RTL8852B.
fn set_dbg<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_set(PCIE_DBG_CTRL, ASFF_FULL_NO_STK | EN_STUCK_DBG)?;
    io.write32_mask(PCIE_EXP_CTRL, EN_STUCK_DBG | ASFF_FULL_NO_STK, EN_STUCK_DBG)
}

/// `rtw89_pci_set_keep_reg`.
fn set_keep_reg<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_set(PCIE_INIT_CFG1, PCIE_TXRST_KEEP_REG | PCIE_RXRST_KEEP_REG)
}

/// `rtw89_pci_clr_idx_all_ax` for an RTL8852B: the seven TX channels'
/// indices, then RXQ's and RPQ's.
fn clr_idx_all<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    let val = CLR_ACH0_IDX
        | CLR_ACH1_IDX
        | CLR_ACH2_IDX
        | CLR_ACH3_IDX
        | CLR_CH8_IDX
        | CLR_CH9_IDX
        | CLR_CH12_IDX;
    io.write32_set(TXBD_RWPTR_CLR1, val)?;
    io.write32_set(RXBD_RWPTR_CLR, CLR_RXQ_IDX | CLR_RPQ_IDX)
}

/// `rtw89_pci_poll_dma_all_idle`: `rtw89_pci_poll_txdma_ch_idle_ax`, whose
/// `dma_busy2_reg` is 0 here, then `rtw89_pci_poll_rxdma_ch_idle_ax`.
fn poll_dma_all_idle<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    let check = DMA_BUSY1_CHECK_V1;
    io.poll32(PCIE_DMA_BUSY1, check, 10, 100, |busy| busy & check == 0)?;
    let check = RXQ_BUSY | RPQ_BUSY;
    io.poll32(PCIE_DMA_BUSY1, check, 10, 100, |busy| busy & check == 0)?;
    Ok(())
}

/// `rtw89_pci_mode_op` with `rtw8852b_pci_info`: BD truncation (which only
/// an RTL8852A of cut B sets in INIT_CFG1), packet RX BDs, 2048-byte TX and
/// 128-byte RX bursts, multiple tags, eight of them, 256 ns WD intervals,
/// and the 8-byte address info truncation implies.
fn mode_op<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    // rxbd_mode MAC_AX_RXBD_PKT
    io.write32_clr(PCIE_INIT_CFG1, RXBD_MODE)?;
    io.write32_mask(PCIE_INIT_CFG1, PCIE_MAX_TXDMA_MASK, MAC_AX_TX_BURST_2048B)?;
    io.write32_mask(PCIE_INIT_CFG1, PCIE_MAX_RXDMA_MASK, MAC_AX_RX_BURST_128B)?;
    // tag_mode MAC_AX_TAG_MULTI
    let val32 = io.read32(PCIE_INIT_CFG1)? | LATENCY_CONTROL;
    io.write32(PCIE_INIT_CFG1, val32)?;
    io.write32_mask(PCIE_EXP_CTRL, MAX_TAG_NUM, MAC_AX_TAG_NUM_8)?;
    io.write32_mask(PCIE_INIT_CFG2, WD_ITVL_IDLE, MAC_AX_WD_DMA_INTVL_256NS)?;
    io.write32_mask(PCIE_INIT_CFG2, WD_ITVL_ACT, MAC_AX_WD_DMA_INTVL_256NS)?;
    // txbd_trunc_mode MAC_AX_BD_TRUNC
    io.write32_set(TX_ADDRESS_INFO_MODE_SETTING, HOST_ADDR_INFO_8B_SEL)?;
    io.write32_clr(PKTIN_SETTING, WD_ADDR_INFO_LENGTH)
}

/// `rtw89_pci_rst_bdram_ax`: RST_BDRAM set, then polled until the chip
/// clears it.
fn rst_bdram<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_set(PCIE_INIT_CFG1, RST_BDRAM)?;
    io.poll32(PCIE_INIT_CFG1, RST_BDRAM, 1, POLL_BDRAM_RST_CNT, |val| {
        val & RST_BDRAM == 0
    })
    .map(|_| ())
}

#[cfg(test)]
mod tests;
