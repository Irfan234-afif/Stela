// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! An RTL8852BE's efuse and phycap as pinned rtw89 reads them at probe, once
//! its firmware runs: `rtw89_chip_efuse_info_setup` (core.c) after
//! `rtw89_mac_partial_init` has downloaded the firmware ([`super::fwdl`]).
//! That is [`info_setup`], in rtw89's order:
//!
//! 1. `rtw89_parse_efuse_map_ax` (efuse.c, [`parse_efuse_map`]): the autoload
//!    bit as the efuse's validity, the physical map (1216 bytes from address
//!    0 through DDV, EFUSE_CTRL one byte at a time) and the DAV map (96 bytes
//!    from address 0 through XTAL SI), each dump attempted up to
//!    [`DUMP_ATTEMPTS`] times (`rtw89_dump_physical_efuse_map`); then both
//!    decoded into one logical map over 0xff, the main map's 2048 bytes and
//!    the DAV map's 16 (`rtw89_dump_logical_efuse_map`); then RTL8852B's
//!    reader on it ([`rtw8852b::efuse::read_efuse`]).
//! 2. `rtw89_parse_phycap_map_ax` ([`parse_phycap_map`]): 128 physical bytes
//!    from 0x580 through DDV, then RTL8852B's phycap reader
//!    ([`rtw8852b::efuse::read_phycap`]).
//! 3. `rtw89_mac_setup_phycap` (mac.c, [`setup_phycap`]): the firmware's own
//!    phycap, asked for with `RTW89_FWCMD_H2CREG_FUNC_GET_FEATURE` over the
//!    register mailbox ([`h2creg`], `rtw89_mac_read_phycap`): part 0 alone on
//!    an AX chip, which sets the NSS and antennas.
//! 4. `rtw89_core_setup_phycap`, which makes no access, and
//!    `rtw89_hci_mac_pre_deinit` ([`pci::mac_pre_deinit`]).
//!
//! The physical read the first power-on makes, the two bytes
//! `rtw89_efuse_read_fw_secure_ax` hands its MSS recognizers, is here too
//! ([`read_fw_secure`]); [`super::power`] calls it.
//!
//! The logical map's format, as `rtw89_dump_logical_efuse_map` decodes it:
//! from byte 4 (`sec_ctrl_efuse_size`), a block is a two-byte header, then
//! two bytes for each of its four words whose bit in the header's low nibble
//! is clear. The header names the block `((hdr1 & 0x0f) << 4) | (hdr2 >>
//! 4)`, whose word `i` is logical bytes `block * 8 + i * 2` and the next. A
//! later block overwrites an earlier one's words. A header byte of 0xff
//! ends the map; a word that would end past byte 1211 is `-EINVAL`. rtw89
//! decodes the DAV map with the main map's bounds, so a DAV map that does not
//! end within its 96 bytes, or names a block past its 16 logical bytes,
//! would be read or written past its buffer: undefined in C, refused here
//! ([`Logical::Overrun`]).
//!
//! Each step makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included. A DDV byte is polled every 1 us
//! for up to 1 s after a first 1 us step, a DAV byte's ready bit every 1 us
//! for up to 10 ms, both counted in steps ([`Registers::poll32`]).
//!
//! What this leaves out, and why:
//! - `rtw89_mac_partial_init`, which runs before: the DMAC and PCIe pre-init
//!   and the download are [`super::dle`], [`super::pci`] and [`super::fwdl`].
//! - `rtw89_switch_efuse_bank` and `cnv_efuse_state`, which make no access on
//!   an RTL8852B, and `rtw89_mac_setup_phycap_part1`, which an AX chip skips.
//! - USB's MAC address and `-EOPNOTSUPP` for other buses: PCIe only.
//! - `rtw89_core_setup_phycap`'s `support_igi` (RTL8852A only) and
//!   `thermal_prot_th` (0 without a thermal quirk, which nothing sets on an
//!   RTL8852BE); [`Hal::support_cckpd`] is kept.
//! - The efuse version, thermal-K, power data and vcore reads the BE
//!   generation makes, and the firmware elements `rtw89_chip_info_setup`
//!   recognizes next, which are a later step's.
//!
//! What a read proves: that EFUSE_CTRL and XTAL SI answered every byte and
//! the firmware answered the phycap request. Nothing here shows that the
//! efuse was programmed (a blank one reads as 0xff throughout and decodes
//! without error), that the MAC address is the one on the card's label, or
//! that the RFE type, crystal cap and trims suit the board.
use super::{
    h2creg::{self, H2cReg, Mailbox},
    io::{self, Io, Registers, field, prep},
    pci,
    power::Inputs,
    registers::*,
    rtw8852b::efuse::{
        self as chip, DAV_PHY_EFUSE_SIZE, FULL_LOG_SIZE, GAIN_OFFSET_2G_5G, LOGICAL_EFUSE_SIZE,
        PHYCAP_ADDR, PHYCAP_SIZE, PHYSICAL_EFUSE_SIZE, RF_PATH_NUM_8852BX, SEC_CTRL_EFUSE_SIZE,
        SUBBAND_2GHZ_5GHZ_NR, TSSI_CCK_CH_GROUP_NUM, TSSI_MCS_CH_GROUP_NUM, TSSI_TRIM_CH_GROUP_NUM,
    },
};

/// The attempts `rtw89_dump_physical_efuse_map` makes.
pub const DUMP_ATTEMPTS: usize = 5;
/// `EFUSE_EXTERNALPN_ADDR_AX`: the first of the two physical efuse bytes
/// `rtw89_efuse_read_fw_secure_ax` reads.
pub const EFUSE_EXTERNALPN_ADDR_AX: u32 = 0x5ec;
/// `read_poll_timeout_atomic(…, 1, 1000000, true, …)`: a DDV byte's step and
/// bound.
const DDV_STEP_US: u64 = 1;
const DDV_BOUND_US: u64 = 1_000_000;
/// `read_poll_timeout_atomic(…, 1, 10000, false, …)`: a DAV byte's ready
/// poll.
const DAV_STEP_US: u64 = 1;
const DAV_BOUND_US: u64 = 10_000;
/// `RTW89_FWCMD_H2CREG_FUNC_GET_FEATURE`, `RTW89_FWCMD_C2HREG_FUNC_PHY_CAP`
/// and `RTW89_H2CREG_GET_FEATURE_PART_NUM`.
pub const H2CREG_FUNC_GET_FEATURE: u8 = 3;
pub const C2HREG_FUNC_PHY_CAP: u8 = 3;
pub const H2CREG_GET_FEATURE_PART_NUM: u32 = 0x00ff_0000;
/// The phycap fields `rtw89_mac_setup_phycap_part0` reads
/// (`RTW89_C2HREG_PHYCAP_*`), and `RTW89_C2HREG_PHYCAP_W1_PROT_11BE`.
pub const C2HREG_PHYCAP_W0_RX_NSS: u32 = 0x00ff_0000;
pub const C2HREG_PHYCAP_W1_TX_NSS: u32 = 0x0000_00ff;
pub const C2HREG_PHYCAP_W1_PROT: u32 = 0x0000_ff00;
pub const C2HREG_PHYCAP_W3_ANT_TX_NUM: u32 = 0x0000_ff00;
pub const C2HREG_PHYCAP_W3_ANT_RX_NUM: u32 = 0x00ff_0000;
pub const C2HREG_PHYCAP_W1_PROT_11BE: u8 = 4;
/// `rtw8852b_chip_info.tx_nss` and `.rx_nss`.
const CHIP_TX_NSS: u8 = 2;
const CHIP_RX_NSS: u8 = 2;
/// `enum rtw89_rf_path_bit`'s `RF_A` and `RF_B`: what the antenna bitmaps
/// hold.
pub const RF_A: u8 = 1 << 0;
pub const RF_B: u8 = 1 << 1;

/// Why a logical map could not be decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Logical {
    /// `rtw89_dump_logical_efuse_map`'s `-EINVAL`: the word at physical
    /// `offset` would end past the usable map or its logical bytes past the
    /// logical map.
    Corrupt { offset: usize },
    /// rtw89 would read or write past its buffer at `offset` (physical for a
    /// header or word, logical for a store): undefined in C.
    Overrun { offset: usize },
}

/// Why the efuse or phycap could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An access the interface refused, or a poll that timed out:
    /// [`io::Error::Timeout`] names EFUSE_CTRL and EF_RDY for a DDV byte,
    /// WLAN_XTAL_SI_CTRL and XTAL_SI_CMD_POLL for an XTAL SI request, and
    /// H2CREG_CTRL or C2HREG_CTRL with mask 0xff for the mailbox.
    Io(io::Error),
    /// A DAV byte whose XTAL SI register `offset` never read `mask` within
    /// its bound: `rtw89_dump_physical_efuse_map_dav`'s "failed to read dav
    /// efuse" (`-ETIMEDOUT`).
    XtalSi { offset: u8, mask: u8 },
    /// The main map (`dav` false) or the DAV map could not be decoded.
    Logical { dav: bool, error: Logical },
    /// `rtw89_mac_read_phycap`'s `-EINVAL`: the firmware answered with
    /// another function than `RTW89_FWCMD_C2HREG_FUNC_PHY_CAP`.
    PhycapId(u8),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// `struct rtw89_efuse` as an RTL8852BE's probe fills it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Efuse {
    /// SYS_WL_EFUSE_CTRL read AUTOLOAD_SUS, whatever the maps hold.
    pub valid: bool,
    /// The phycap carries the power calibration mark.
    pub power_k_valid: bool,
    /// `xtal_k`: the crystal cap.
    pub xtal_cap: u8,
    /// The PCIe MAC address, as stored.
    pub addr: [u8; 6],
    pub rfe_type: u8,
    /// Two bytes, as stored; rtw89 keeps them as `char`.
    pub country_code: [u8; 2],
}

impl Efuse {
    /// Whether [`Self::addr`] is an individual address: bit 0 of its first
    /// byte clear. rtw89 checks nothing of the kind; a blank efuse's
    /// ff:ff:ff:ff:ff:ff is not one, and neither is any multicast address.
    pub fn unicast(&self) -> bool {
        self.addr[0] & 1 == 0
    }

    /// What a power cycle after probe hands [`super::power`]: this efuse's
    /// RFE type and validity, and probe done, so the secure-boot bytes are
    /// not read again.
    pub fn power_inputs(&self, cut: u8) -> Inputs {
        Inputs {
            cut,
            rfe_type: self.rfe_type,
            efuse_valid: self.valid,
            power_k_valid: self.power_k_valid,
            probe_done: true,
        }
    }
}

/// The efuse part of `struct rtw89_tssi_info`, one row per RF path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tssi {
    pub thermal: [u8; RF_PATH_NUM_8852BX],
    pub tssi_trim: [[i8; TSSI_TRIM_CH_GROUP_NUM]; RF_PATH_NUM_8852BX],
    pub tssi_cck: [[i8; TSSI_CCK_CH_GROUP_NUM]; RF_PATH_NUM_8852BX],
    /// The 2 GHz groups, then the 5 GHz ones.
    pub tssi_mcs: [[i8; TSSI_MCS_CH_GROUP_NUM]; RF_PATH_NUM_8852BX],
}

/// The efuse part of `struct rtw89_power_trim_info`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PowerTrim {
    pub pg_thermal_trim: bool,
    pub pg_pa_bias_trim: bool,
    pub thermal_trim: [u8; RF_PATH_NUM_8852BX],
    pub pa_bias_trim: [u8; RF_PATH_NUM_8852BX],
}

/// The efuse part of `struct rtw89_phy_efuse_gain`: the 2 GHz and 5 GHz
/// entries, by RF path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EfuseGain {
    pub offset_valid: bool,
    pub comp_valid: bool,
    /// Indexed by `enum rtw89_gain_offset` ([`chip::GAIN_OFFSET_2G_CCK`] to
    /// [`chip::GAIN_OFFSET_5G_HIGH`]).
    pub offset: [[i8; GAIN_OFFSET_2G_5G]; RF_PATH_NUM_8852BX],
    /// Indexed by `enum rtw89_subband`; the unused `RTW89_CH_5G_BAND_2`
    /// stays 0.
    pub comp: [[i8; SUBBAND_2GHZ_5GHZ_NR]; RF_PATH_NUM_8852BX],
}

/// What `rtw89_mac_setup_phycap` and `rtw89_core_setup_phycap` leave in
/// `struct rtw89_hal`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hal {
    /// The firmware's NSS, capped at the chip's 2; 2 when it says 0.
    pub tx_nss: u8,
    pub rx_nss: u8,
    /// [`RF_A`]/[`RF_B`] bitmaps: [`RF_B`] for a firmware that names one
    /// antenna or one TX stream over two antennas, otherwise 0 as at probe.
    pub antenna_tx: u8,
    pub antenna_rx: u8,
    pub tx_path_diversity: bool,
    /// The firmware names a protocol below 802.11be.
    pub no_eht: bool,
    /// `rtw89_core_setup_phycap`: every RTL8852B cut but CAV.
    pub support_cckpd: bool,
    /// The four words the firmware's phycap answer carried.
    pub phycap: [u32; h2creg::C2HREG_MAX],
}

/// What [`info_setup`] read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Info {
    pub efuse: Efuse,
    pub tssi: Tssi,
    pub pwr_trim: PowerTrim,
    pub efuse_gain: EfuseGain,
    pub hal: Hal,
    /// The logical map rtw89 dumps as `log_map:`, the main map's
    /// [`LOGICAL_EFUSE_SIZE`] bytes then the DAV map's.
    pub log_map: [u8; FULL_LOG_SIZE],
    /// The physical bytes from [`PHYCAP_ADDR`].
    pub phycap_map: [u8; PHYCAP_SIZE],
}

impl Info {
    /// rtw89's state before the efuse is read: zeroed, as `rtwdev` is
    /// allocated, and the maps blank.
    pub fn probe() -> Self {
        Self {
            efuse: Efuse::default(),
            tssi: Tssi::default(),
            pwr_trim: PowerTrim::default(),
            efuse_gain: EfuseGain::default(),
            hal: Hal::default(),
            log_map: [0xff; FULL_LOG_SIZE],
            phycap_map: [0xff; PHYCAP_SIZE],
        }
    }
}

/// `rtw89_chip_efuse_info_setup` on a PCIe RTL8852B of cut `cut` whose
/// firmware runs, after `rtw89_mac_partial_init`: the efuse and phycap maps
/// read and parsed, the firmware's phycap asked for over `mailbox`, and the
/// HCI's pre-deinit. A failure returns before the steps after it, as in
/// rtw89, whose caller then powers the chip off.
pub fn info_setup<I: Io + ?Sized>(
    io: &mut I,
    cut: u8,
    mailbox: &mut Mailbox,
) -> Result<Info, Error> {
    let mut info = Info::probe();
    info_setup_into(io, cut, mailbox, &mut info)?;
    Ok(info)
}

/// [`info_setup`] over `info`, as rtw89 fills `rtwdev`: what each step read
/// stays when a later one fails. The power-off rtw89 makes after a failure
/// reads the RFE type ([`Efuse::rfe_type`]) the efuse map gave by then.
pub fn info_setup_into<I: Io + ?Sized>(
    io: &mut I,
    cut: u8,
    mailbox: &mut Mailbox,
    info: &mut Info,
) -> Result<(), Error> {
    parse_efuse_map(io, cut, info)?;
    parse_phycap_map(io, cut, info)?;
    setup_phycap(io, mailbox, &mut info.hal)?;
    core_setup_phycap(cut, &mut info.hal);
    pci::mac_pre_deinit(io)?;
    Ok(())
}

/// `rtw89_parse_efuse_map_ax` on an RTL8852BE: [`Efuse::valid`] from the
/// autoload bit, the physical and DAV maps dumped, decoded into
/// [`Info::log_map`], and RTL8852B's reader run on it. rtw89 frees the maps
/// on failure; `info` may then hold some of what was read.
pub fn parse_efuse_map<I: Io + ?Sized>(io: &mut I, cut: u8, info: &mut Info) -> Result<(), Error> {
    if io.read16(SYS_WL_EFUSE_CTRL)? & AUTOLOAD_SUS != 0 {
        info.efuse.valid = true;
    }
    // Otherwise rtw89 warns "failed to check efuse autoload" and goes on.

    let mut phy_map = [0; PHYSICAL_EFUSE_SIZE];
    let mut dav_phy_map = [0; DAV_PHY_EFUSE_SIZE];
    dump_physical_efuse_map(io, cut, &mut phy_map, 0, false)?;
    dump_physical_efuse_map(io, cut, &mut dav_phy_map, 0, true)?;

    let mut log_map = [0xff; FULL_LOG_SIZE];
    let (main, dav) = log_map.split_at_mut(LOGICAL_EFUSE_SIZE);
    dump_logical_efuse_map(&phy_map, main).map_err(|error| Error::Logical { dav: false, error })?;
    dump_logical_efuse_map(&dav_phy_map, dav)
        .map_err(|error| Error::Logical { dav: true, error })?;
    info.log_map = log_map;

    chip::read_efuse(
        &info.log_map,
        &mut info.efuse,
        &mut info.tssi,
        &mut info.efuse_gain,
    );
    Ok(())
}

/// `rtw89_parse_phycap_map_ax` on an RTL8852BE: [`PHYCAP_SIZE`] physical
/// bytes from [`PHYCAP_ADDR`] through DDV into [`Info::phycap_map`], then
/// RTL8852B's phycap reader on them.
pub fn parse_phycap_map<I: Io + ?Sized>(io: &mut I, cut: u8, info: &mut Info) -> Result<(), Error> {
    let mut phycap_map = [0; PHYCAP_SIZE];
    dump_physical_efuse_map(io, cut, &mut phycap_map, PHYCAP_ADDR, false)?;
    info.phycap_map = phycap_map;
    chip::read_phycap(
        &info.phycap_map,
        &mut info.efuse,
        &mut info.tssi,
        &mut info.pwr_trim,
        &mut info.efuse_gain,
    );
    Ok(())
}

/// `rtw89_mac_setup_phycap` on an AX chip: `rtw89_mac_setup_phycap_part0`,
/// whose `rtw89_mac_read_phycap(rtwdev, &c2h_info, 0)` sends
/// `RTW89_FWCMD_H2CREG_FUNC_GET_FEATURE` for part 0 with no content and
/// expects `RTW89_FWCMD_C2HREG_FUNC_PHY_CAP` back; `hal` takes the NSS and
/// antennas it names. An RTL8852B has two RF paths, so the one-path
/// antenna-diversity branch is not taken.
pub fn setup_phycap<I: Io + ?Sized>(
    io: &mut I,
    mailbox: &mut Mailbox,
    hal: &mut Hal,
) -> Result<(), Error> {
    // rtw89_mac_read_phycap: cnv_efuse_state makes no access on AX.
    let h2c = H2cReg {
        id: H2CREG_FUNC_GET_FEATURE,
        content_len: 0,
        regs: [prep(0, H2CREG_GET_FEATURE_PART_NUM), 0, 0, 0],
    };
    let c2h = mailbox.exchange(io, &h2c)?;
    if c2h.id != C2HREG_FUNC_PHY_CAP {
        return Err(Error::PhycapId(c2h.id));
    }

    let [w0, w1, _, w3] = c2h.regs;
    let tx_nss = field(w1, C2HREG_PHYCAP_W1_TX_NSS) as u8;
    let rx_nss = field(w0, C2HREG_PHYCAP_W0_RX_NSS) as u8;
    let tx_ant = field(w3, C2HREG_PHYCAP_W3_ANT_TX_NUM) as u8;
    let rx_ant = field(w3, C2HREG_PHYCAP_W3_ANT_RX_NUM) as u8;

    hal.tx_nss = if tx_nss != 0 {
        tx_nss.min(CHIP_TX_NSS)
    } else {
        CHIP_TX_NSS
    };
    hal.rx_nss = if rx_nss != 0 {
        rx_nss.min(CHIP_RX_NSS)
    } else {
        CHIP_RX_NSS
    };
    if tx_ant == 1 {
        hal.antenna_tx = RF_B;
    }
    if rx_ant == 1 {
        hal.antenna_rx = RF_B;
    }
    if tx_nss == 1 && tx_ant == 2 && rx_ant == 2 {
        hal.antenna_tx = RF_B;
        hal.tx_path_diversity = true;
    }
    // rf_path_num is 2: no one-path antenna diversity.

    let protocol = field(w1, C2HREG_PHYCAP_W1_PROT) as u8;
    if protocol < C2HREG_PHYCAP_W1_PROT_11BE {
        hal.no_eht = true;
    }
    hal.phycap = c2h.regs;
    // An AX chip stops after part 0.
    Ok(())
}

/// `rtw89_core_setup_phycap` on an RTL8852B: CCK PD on every cut but CAV.
fn core_setup_phycap(cut: u8, hal: &mut Hal) {
    hal.support_cckpd = cut > CHIP_CAV;
}

/// `rtw89_efuse_read_fw_secure_ax`'s read: `rtw89_dump_physical_efuse_map`
/// of the two bytes from [`EFUSE_EXTERNALPN_ADDR_AX`] through DDV, as the
/// first power-on makes it. What rtw89 decides from them is
/// [`super::fwdl::FwSecure::recognize`]'s.
pub fn read_fw_secure<I: Io + ?Sized>(io: &mut I, cut: u8) -> Result<[u8; 2], io::Error> {
    let mut map = [0; 2];
    attempts(|| dump_physical_ddv(io, cut, EFUSE_EXTERNALPN_ADDR_AX, &mut map))?;
    Ok(map)
}

/// `rtw89_dump_physical_efuse_map`: `map.len()` bytes from `dump_addr`
/// through DAV (`dav`) or DDV, up to [`DUMP_ATTEMPTS`] attempts, the last
/// one's failure returned. An empty `map` reads nothing.
/// `rtw89_switch_efuse_bank` makes no access on an RTL8852B.
pub fn dump_physical_efuse_map<I: Io + ?Sized>(
    io: &mut I,
    cut: u8,
    map: &mut [u8],
    dump_addr: u32,
    dav: bool,
) -> Result<(), Error> {
    if map.is_empty() {
        return Ok(());
    }
    if dav {
        attempts(|| dump_physical_dav(io, dump_addr, map))
    } else {
        attempts(|| dump_physical_ddv(io, cut, dump_addr, map).map_err(Error::Io))
    }
}

/// `rtw89_dump_physical_efuse_map`'s retries: an attempt and up to
/// [`DUMP_ATTEMPTS`] - 1 more after a failure, each of which rtw89 warns
/// about.
fn attempts<E>(mut attempt: impl FnMut() -> Result<(), E>) -> Result<(), E> {
    let mut result = attempt();
    for _ in 1..DUMP_ATTEMPTS {
        if result.is_ok() {
            break;
        }
        result = attempt();
    }
    result
}

/// `rtw89_dump_physical_efuse_map_ddv` on an RTL8852B: power the efuse up,
/// read one byte per address through EFUSE_CTRL, power it down. A byte that
/// never reads ready ends the attempt before the power-down, as in rtw89.
fn dump_physical_ddv<I: Io + ?Sized>(
    io: &mut I,
    cut: u8,
    dump_addr: u32,
    map: &mut [u8],
) -> Result<(), io::Error> {
    enable_efuse_pwr_cut_ddv(io, cut)?;
    for (addr, byte) in (dump_addr..).zip(map.iter_mut()) {
        let efuse_ctl = prep(addr, EF_ADDR_MASK);
        io.write32(EFUSE_CTRL, efuse_ctl & !EF_RDY)?;
        // read_poll_timeout_atomic(…, 1, 1000000, true, …) waits one step
        // before its first read, and that step counts toward the bound.
        io.delay_us(DDV_STEP_US);
        let efuse_ctl = io.poll32(
            EFUSE_CTRL,
            EF_RDY,
            DDV_STEP_US,
            DDV_BOUND_US - DDV_STEP_US,
            |value| value & EF_RDY != 0,
        )?;
        *byte = efuse_ctl as u8;
    }
    disable_efuse_pwr_cut_ddv(io, cut)
}

/// `rtw89_enable_efuse_pwr_cut_ddv` on an RTL8852B, with OTP burst mode on a
/// CAV (`rtw89_enable_otp_burst_mode`).
fn enable_efuse_pwr_cut_ddv<I: Io + ?Sized>(io: &mut I, cut: u8) -> Result<(), io::Error> {
    io.write8_set(PMC_DBG_CTRL2, SYSON_DIS_PMCR_AX_WRMSK as u8)?;
    io.write16_set(SYS_ISO_CTRL, PWC_EV2EF_B14 as u16)?;
    io.delay_us(1000);
    io.write16_set(SYS_ISO_CTRL, PWC_EV2EF_B15 as u16)?;
    io.write16_clr(SYS_ISO_CTRL, ISO_EB2CORE as u16)?;
    if cut == CHIP_CAV {
        io.write32_set(EFUSE_CTRL_1_V1, EF_BURST)?;
    }
    Ok(())
}

/// `rtw89_disable_efuse_pwr_cut_ddv` on an RTL8852B.
fn disable_efuse_pwr_cut_ddv<I: Io + ?Sized>(io: &mut I, cut: u8) -> Result<(), io::Error> {
    if cut == CHIP_CAV {
        io.write32_clr(EFUSE_CTRL_1_V1, EF_BURST)?;
    }
    io.write16_set(SYS_ISO_CTRL, ISO_EB2CORE as u16)?;
    io.write16_clr(SYS_ISO_CTRL, PWC_EV2EF_B15 as u16)?;
    io.delay_us(1000);
    io.write16_clr(SYS_ISO_CTRL, PWC_EV2EF_B14 as u16)?;
    io.write8_clr(PMC_DBG_CTRL2, SYSON_DIS_PMCR_AX_WRMSK as u8)
}

/// `rtw89_dump_physical_efuse_map_dav`: per byte, XTAL_SI_CTRL set to read
/// mode, the address's low byte and high bits written, the mode cleared to
/// start the read, XTAL_SI_CTRL read through XTAL SI until it shows
/// XTAL_SI_RDY, then XTAL_SI_READ_VAL. A ready poll's XTAL SI read that
/// times out counts as not ready, as rtw89's condition reads it.
fn dump_physical_dav<I: Io + ?Sized>(
    io: &mut I,
    dump_addr: u32,
    map: &mut [u8],
) -> Result<(), Error> {
    for (addr, byte) in (dump_addr..).zip(map.iter_mut()) {
        io.write_xtal_si(XTAL_SI_CTRL, 0x40, FULL_BIT_MASK)?;
        io.write_xtal_si(XTAL_SI_LOW_ADDR, addr as u8, XTAL_SI_LOW_ADDR_MASK)?;
        io.write_xtal_si(XTAL_SI_CTRL, (addr >> 8) as u8, XTAL_SI_HIGH_ADDR_MASK)?;
        io.write_xtal_si(XTAL_SI_CTRL, 0, XTAL_SI_MODE_SEL_MASK)?;

        let mut waited = 0;
        loop {
            match io.read_xtal_si(XTAL_SI_CTRL) {
                Ok(value) if value & XTAL_SI_RDY != 0 => break,
                Ok(_) | Err(io::Error::Timeout { .. }) => {}
                Err(error) => return Err(error.into()),
            }
            if waited >= DAV_BOUND_US {
                return Err(Error::XtalSi {
                    offset: XTAL_SI_CTRL,
                    mask: XTAL_SI_RDY,
                });
            }
            io.delay_us(DAV_STEP_US);
            waited += DAV_STEP_US;
        }

        *byte = io.read_xtal_si(XTAL_SI_READ_VAL)?;
    }
    Ok(())
}

/// `rtw89_dump_logical_efuse_map` with RTL8852B's sizes: `phy_map` decoded
/// over `log_map`, which the caller filled with 0xff. rtw89 bounds the walk
/// by the main map's sizes whatever the buffers; an index past `phy_map` or
/// `log_map` that it would read or write is [`Logical::Overrun`].
pub fn dump_logical_efuse_map(phy_map: &[u8], log_map: &mut [u8]) -> Result<(), Logical> {
    let physical_size = PHYSICAL_EFUSE_SIZE;
    let logical_size = LOGICAL_EFUSE_SIZE;
    let sec_ctrl_size = SEC_CTRL_EFUSE_SIZE;
    let byte = |offset: usize| {
        phy_map
            .get(offset)
            .copied()
            .ok_or(Logical::Overrun { offset })
    };
    let mut phy_idx = sec_ctrl_size;
    while phy_idx < physical_size - sec_ctrl_size {
        let hdr1 = byte(phy_idx)?;
        let hdr2 = byte(phy_idx + 1)?;
        // invalid_efuse_header
        if hdr1 == 0xff || hdr2 == 0xff {
            break;
        }
        // get_efuse_blk_idx
        let blk_idx = usize::from(((hdr2 & 0xf0) >> 4) | ((hdr1 & 0x0f) << 4));
        let word_en = hdr2 & 0xf;
        phy_idx += 2;

        for i in 0..4 {
            // invalid_efuse_content
            if word_en & (1 << i) != 0 {
                continue;
            }
            // block_idx_to_logical_idx
            let log_idx = (blk_idx << 3) + (i << 1);
            if phy_idx + 1 > physical_size - sec_ctrl_size - 1 || log_idx + 1 > logical_size {
                return Err(Logical::Corrupt { offset: phy_idx });
            }
            let word = [byte(phy_idx)?, byte(phy_idx + 1)?];
            log_map
                .get_mut(log_idx..log_idx + 2)
                .ok_or(Logical::Overrun { offset: log_idx })?
                .copy_from_slice(&word);
            phy_idx += 2;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests;
