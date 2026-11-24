// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! Powering a PCIe RTL8852B on and off as pinned rtw89 does:
//! `rtw89_mac_pwr_on` and `rtw89_mac_pwr_off` (mac.c) around
//! `rtw89_mac_power_switch`, with RTL8852B's `rtw8852b_pwr_on_func` and
//! `rtw8852b_pwr_off_func` (rtw8852b.c), the AX generation's
//! `reset_pwr_state`, the scoreboard notice, and the physical efuse read the
//! first power-on makes (`rtw89_efuse_read_fw_secure_ax`, efuse.c), which
//! [`efuse::read_fw_secure`] makes.
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included. `fsleep(1000)` is a 1000 us
//! delay, and each `read_poll_timeout(…, 1000, 20000, …)` reads every
//! 1000 us for up to 20000 us counted in steps ([`Registers::poll32`]).
//!
//! What this leaves out, and why:
//! - USB and SDIO branches, `rtw89_mac_power_switch_boot_mode` among them:
//!   the chip is reached over PCIe.
//! - `__rtw89_leave_ps_mode`, which `rtw89_mac_power_switch` calls while
//!   firmware is ready: Stela never puts the chip in LPS, so it would make no
//!   access. These functions assume no firmware runs.
//! - Callees that make no access on an AX chip: `clr_aon_intr`,
//!   `efuse_read_ecv`, `efuse_read_thermal_k`, `efuse_read_pwr_data` and
//!   `set_vcore_cfg` are NULL in `rtw89_mac_gen_ax`, so
//!   `rtw89_mac_set_vcore_reset` reaches nothing either.
//! - Interpreting the secure-boot efuse bytes (`rtw89_efuse_recognize_mss_*`):
//!   they are returned raw ([`PoweredOn::secure_efuse`]); the firmware
//!   download decides secure boot from them ([`super::fwdl::FwSecure`]).
//!
//! A power-on that returns proves only that the bits rtw89 polls answered.
//! It proves nothing about the rails, clocks, analog front end or firmware,
//! and nothing here enables, stops or proves the end of the chip's DMA.
use super::{
    efuse,
    io::{self, Io, Registers},
    registers::*,
    rtw8852b::{BTC_SB_CFG, RTL8852B_RFE_05_SPS_ANA},
};

/// `read_poll_timeout(…, 1000, 20000, …)`: the power polls' step and bound.
const POLL_STEP_US: u64 = 1000;
const POLL_BOUND_US: u64 = 20_000;

/// What rtw89's power path reads from its own state rather than the chip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inputs {
    /// `hal.cv`: SYS_CFG1's cut, as [`Registers::chip_version`] or
    /// [`Profile::cut`](crate::wifi::realtek::identity::Profile::cut) reads it.
    pub cut: u8,
    /// `efuse.rfe_type`: 0 until the efuse is read, as at rtw89's first
    /// power-on.
    pub rfe_type: u8,
    /// `efuse.valid`.
    pub efuse_valid: bool,
    /// `efuse.power_k_valid`.
    pub power_k_valid: bool,
    /// `RTW89_FLAG_PROBE_DONE`: clear at the first power-on, the only one that
    /// reads the secure-boot efuse bytes.
    pub probe_done: bool,
}

impl Inputs {
    /// rtw89's state at its first power-on, before the efuse is read.
    pub const fn first(cut: u8) -> Self {
        Self {
            cut,
            rfe_type: 0,
            efuse_valid: false,
            power_k_valid: false,
            probe_done: false,
        }
    }
}

/// Why a power step failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An access the interface refused, or a poll that timed out:
    /// [`io::Error::Timeout`] names the register and the bits it waited on.
    Io(io::Error),
    /// `rtw89_mac_reset_pwr_state_ax`'s `-EBUSY`: IC_PWR_STATE reads the WL
    /// MAC as already on.
    AlreadyOn,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// What a successful [`power_on`] saw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoweredOn {
    /// Why the first attempt failed, when `rtw89_mac_pwr_on` powered the chip
    /// off and on again: [`Error::AlreadyOn`] for a chip a previous boot left
    /// on.
    pub first_failure: Option<Error>,
    /// The physical efuse bytes at [`efuse::EFUSE_EXTERNALPN_ADDR_AX`] and the
    /// next address, uninterpreted, or why the fifth attempt to read them failed,
    /// which rtw89 only warns about. `None` once probe is done, where rtw89
    /// does not read them.
    pub secure_efuse: Option<Result<[u8; 2], io::Error>>,
}

/// `rtw89_mac_pwr_on`: power on, and when that fails, power off (whatever
/// that returns) and power on once more.
pub fn power_on<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<PoweredOn, Error> {
    match switch_on(io, inputs) {
        Ok(secure_efuse) => Ok(PoweredOn {
            first_failure: None,
            secure_efuse,
        }),
        Err(first) => {
            // rtw89 ignores the power-off's result.
            let _ = switch_off(io, inputs);
            let secure_efuse = switch_on(io, inputs)?;
            Ok(PoweredOn {
                first_failure: Some(first),
                secure_efuse,
            })
        }
    }
}

/// `rtw89_mac_pwr_off`: `rtw89_mac_set_vcore_reset`, which makes no access
/// on an AX chip, then the power-off. rtw89 ignores the result; it is
/// returned here to be logged.
pub fn power_off<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<(), Error> {
    switch_off(io, inputs)
}

/// `rtw89_mac_power_switch(rtwdev, true)` on a PCIe RTL8852B with no
/// firmware running: the secure-boot efuse bytes when probe is not done.
fn switch_on<I: Io + ?Sized>(
    io: &mut I,
    inputs: &Inputs,
) -> Result<Option<Result<[u8; 2], io::Error>>, Error> {
    reset_pwr_state(io)?;
    pwr_on_func(io, inputs)?;
    // rtw89 ignores what `efuse_read_fw_secure` returns.
    let secure_efuse = (!inputs.probe_done).then(|| efuse::read_fw_secure(io, inputs.cut));
    update_scoreboard(io, MAC_AX_NOTIFY_TP_MAJOR)?;
    Ok(secure_efuse)
}

/// `rtw89_mac_power_switch(rtwdev, false)` on a PCIe RTL8852B that is not
/// unplugged, with no firmware running.
fn switch_off<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<(), Error> {
    pwr_off_func(io, inputs)?;
    update_scoreboard(io, MAC_AX_NOTIFY_PWR_MAJOR)?;
    Ok(())
}

/// `rtw89_mac_reset_pwr_state_ax` for PCIe: refuse a WL MAC that reads as
/// on.
fn reset_pwr_state<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    // rtw89 keeps the field in a u8.
    let state = io.read32_mask(IC_PWR_STATE, WLMAC_PWR_STE_MASK)? as u8;
    if u32::from(state) == MAC_AX_MAC_ON {
        return Err(Error::AlreadyOn);
    }
    Ok(())
}

/// `rtw89_mac_update_scoreboard`: `value` in the top byte of each scoreboard
/// register the chip names.
fn update_scoreboard<I: Io + ?Sized>(io: &mut I, value: u8) -> Result<(), io::Error> {
    for register in BTC_SB_CFG {
        if register != 0 {
            io.write8(register + 3, value)?;
        }
    }
    Ok(())
}

/// One power poll: SYS_PW_CTRL or AFE_LDO_CTRL until `bits` read as `set`.
fn poll<I: Io + ?Sized>(io: &mut I, register: u32, bits: u32, set: bool) -> Result<(), io::Error> {
    io.poll32(register, bits, POLL_STEP_US, POLL_BOUND_US, |value| {
        (value & bits != 0) == set
    })
    .map(|_| ())
}

/// `rtw8852b_pwr_sps_ana`.
fn pwr_sps_ana<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<(), io::Error> {
    if inputs.rfe_type == 0x5 {
        io.write16(SPS_ANA_ON_CTRL2, RTL8852B_RFE_05_SPS_ANA)?;
    }
    Ok(())
}

/// `rtw8852b_pwr_sps_dig_off`.
fn pwr_sps_dig_off<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<(), io::Error> {
    let fields: &[(u32, u32)] = if inputs.rfe_type == 0x5 {
        &[
            (C1_L1_MASK, 0x1),
            (C2_L1_MASK, 0x1),
            (C3_L1_MASK, 0x2),
            (R1_L1_MASK, 0x1),
        ]
    } else {
        &[(C1_L1_MASK, 0x1), (C3_L1_MASK, 0x3)]
    };
    for &(mask, data) in fields {
        io.write32_mask(SPS_DIG_OFF_CTRL0, mask, data)?;
    }
    Ok(())
}

/// `rtw8852b_pwr_on_func` over PCIe.
fn pwr_on_func<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<(), io::Error> {
    pwr_sps_ana(io, inputs)?;

    io.write32_clr(SYS_PW_CTRL, AFSM_WLSUS_EN | AFSM_PCIE_SUS_EN)?;
    io.write32_set(SYS_PW_CTRL, DIS_WLBT_PDNSUSEN_SOPC)?;
    io.write32_set(WLLPS_CTRL, DIS_WLBT_LPSEN_LOPC)?;
    io.write32_clr(SYS_PW_CTRL, APDM_HPDN)?;
    io.write32_clr(SYS_PW_CTRL, APFM_SWLPS)?;
    poll(io, SYS_PW_CTRL, RDY_SYSPWR, true)?;

    io.write32_set(AFE_LDO_CTRL, AON_OFF_PC_EN)?;
    poll(io, AFE_LDO_CTRL, AON_OFF_PC_EN, true)?;

    pwr_sps_dig_off(io, inputs)?;
    io.write32_set(SYS_PW_CTRL, EN_WLON)?;
    io.write32_set(SYS_PW_CTRL, APFN_ONMAC)?;
    poll(io, SYS_PW_CTRL, APFN_ONMAC, false)?;

    let platform = PLATFORM_EN as u8;
    io.write8_set(PLATFORM_ENABLE, platform)?;
    io.write8_clr(PLATFORM_ENABLE, platform)?;
    io.write8_set(PLATFORM_ENABLE, platform)?;
    io.write8_clr(PLATFORM_ENABLE, platform)?;
    io.write8_set(PLATFORM_ENABLE, platform)?;
    io.write32_clr(SYS_SDIO_CTRL, PCIE_CALIB_EN_V1)?;

    io.write32_set(SYS_ADIE_PAD_PWR_CTRL, SYM_PADPDN_WL_PTA_1P3)?;
    io.write_xtal_si(XTAL_SI_ANAPAR_WL, XTAL_SI_GND_SHDN_WL, XTAL_SI_GND_SHDN_WL)?;
    io.write32_set(SYS_ADIE_PAD_PWR_CTRL, SYM_PADPDN_WL_RFC_1P3)?;
    for (offset, value, mask) in [
        (XTAL_SI_ANAPAR_WL, XTAL_SI_SHDN_WL, XTAL_SI_SHDN_WL),
        (XTAL_SI_ANAPAR_WL, XTAL_SI_OFF_WEI, XTAL_SI_OFF_WEI),
        (XTAL_SI_ANAPAR_WL, XTAL_SI_OFF_EI, XTAL_SI_OFF_EI),
        (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_RFC2RF),
        (XTAL_SI_ANAPAR_WL, XTAL_SI_PON_WEI, XTAL_SI_PON_WEI),
        (XTAL_SI_ANAPAR_WL, XTAL_SI_PON_EI, XTAL_SI_PON_EI),
        (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_SRAM2RFC),
        (XTAL_SI_SRAM_CTRL, 0, XTAL_SI_SRAM_DIS),
        (XTAL_SI_XTAL_XMD_2, 0, XTAL_SI_LDO_LPS),
        (XTAL_SI_XTAL_XMD_4, 0, XTAL_SI_LPS_CAP),
    ] {
        io.write_xtal_si(offset, value, mask)?;
    }

    io.write32_set(PMC_DBG_CTRL2, SYSON_DIS_PMCR_AX_WRMSK)?;
    io.write32_set(SYS_ISO_CTRL, ISO_EB2CORE)?;
    io.write32_clr(SYS_ISO_CTRL, PWC_EV2EF_B15)?;
    io.delay_us(1000);
    io.write32_clr(SYS_ISO_CTRL, PWC_EV2EF_B14)?;
    io.write32_clr(PMC_DBG_CTRL2, SYSON_DIS_PMCR_AX_WRMSK)?;

    if inputs.efuse_valid && !inputs.power_k_valid {
        io.write32_mask(SPS_DIG_ON_CTRL0, VOL_L1_MASK, 0x9)?;
        io.write32_mask(SPS_DIG_ON_CTRL0, VREFPFM_L_MASK, 0xa)?;
        if inputs.cut == CHIP_CBV {
            io.write32_set(PMC_DBG_CTRL2, SYSON_DIS_PMCR_AX_WRMSK)?;
            io.write16_mask(HCI_LDO_CTRL, R_AX_VADJ_MASK, 0xa)?;
            io.write32_clr(PMC_DBG_CTRL2, SYSON_DIS_PMCR_AX_WRMSK)?;
        }
    }

    // func_en:
    io.write32_set(
        DMAC_FUNC_EN,
        MAC_FUNC_EN
            | DMAC_FUNC_EN_BIT
            | MPDU_PROC_EN
            | WD_RLS_EN
            | DLE_WDE_EN
            | TXPKT_CTRL_EN
            | STA_SCH_EN
            | DLE_PLE_EN
            | PKT_BUF_EN
            | DMAC_TBL_EN
            | PKT_IN_EN
            | DLE_CPUIO_EN
            | DISPATCHER_EN
            | BBRPT_EN
            | MAC_SEC_EN
            | DMACREG_GCKEN,
    )?;
    io.write32_set(
        CMAC_FUNC_EN,
        CMAC_EN
            | CMAC_TXEN
            | CMAC_RXEN
            | FORCE_CMACREG_GCKEN
            | PHYINTF_EN
            | CMAC_DMA_EN
            | PTCLTOP_EN
            | SCHEDULER_EN
            | TMAC_EN
            | RMAC_EN,
    )?;
    io.write32_mask(
        EECS_EESK_FUNC_SEL,
        PINMUX_EESK_FUNC_SEL_MASK,
        PINMUX_EESK_FUNC_SEL_BT_LOG,
    )
}

/// `rtw8852b_pwr_off_func` over PCIe.
fn pwr_off_func<I: Io + ?Sized>(io: &mut I, inputs: &Inputs) -> Result<(), io::Error> {
    pwr_sps_ana(io, inputs)?;

    for (offset, value, mask) in [
        (XTAL_SI_ANAPAR_WL, XTAL_SI_RFC2RF, XTAL_SI_RFC2RF),
        (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_OFF_EI),
        (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_OFF_WEI),
        (XTAL_SI_WL_RFC_S0, 0, XTAL_SI_RF00),
        (XTAL_SI_WL_RFC_S1, 0, XTAL_SI_RF10),
        (XTAL_SI_ANAPAR_WL, XTAL_SI_SRAM2RFC, XTAL_SI_SRAM2RFC),
        (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_PON_EI),
        (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_PON_WEI),
    ] {
        io.write_xtal_si(offset, value, mask)?;
    }

    io.write32_set(SYS_PW_CTRL, EN_WLON)?;
    io.write32_clr(WLRF_CTRL, AFC_AFEDIG)?;
    io.write8_clr(SYS_FUNC_EN, (FEN_BB_GLB_RSTN | FEN_BBRSTB) as u8)?;
    io.write32_clr(SYS_ADIE_PAD_PWR_CTRL, SYM_PADPDN_WL_RFC_1P3)?;
    io.write_xtal_si(XTAL_SI_ANAPAR_WL, 0, XTAL_SI_SHDN_WL)?;
    io.write32_clr(SYS_ADIE_PAD_PWR_CTRL, SYM_PADPDN_WL_PTA_1P3)?;
    io.write_xtal_si(XTAL_SI_ANAPAR_WL, 0, XTAL_SI_GND_SHDN_WL)?;

    io.write32_set(SYS_PW_CTRL, APFM_OFFMAC)?;
    poll(io, SYS_PW_CTRL, APFM_OFFMAC, false)?;

    io.write32(WLLPS_CTRL, SW_LPS_OPTION)?;
    io.write32_set(SYS_SWR_CTRL1, SYM_CTRL_SPS_PWMFREQ)?;
    io.write32_mask(SPS_DIG_ON_CTRL0, REG_ZCDC_H_MASK, 0x3)?;
    io.write32_set(SYS_PW_CTRL, APFM_SWLPS)
}

#[cfg(test)]
mod tests;
