// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! Downloading an RTL8852BE's firmware as pinned rtw89 does at probe:
//! `rtw89_fw_download(rtwdev, RTW89_FW_NORMAL, false)` (fw.c), which
//! `rtw89_mac_partial_init` (mac.c) calls right after the PCIe pre-init
//! ([`super::pci::mac_pre_init`]). Between the two,
//! `rtw89_mac_fwdl_preconfig` makes no access: `fwdl_preconfig` is NULL in
//! `rtw89_mac_gen_ax`.
//!
//! [`download`] makes at most [`DOWNLOAD_ATTEMPTS`] attempts, as
//! `rtw89_fw_download` does, with no power cycle or pre-init between them.
//! Each one is `__rtw89_fw_download`:
//!
//! 1. [`disable_cpu`]: `rtw89_mac_disable_cpu_ax`, whose watchdog step on an
//!    RTL885xB toggles APB_WRAP_EN;
//! 2. [`enable_cpu`]: `rtw89_mac_enable_cpu_ax(rtwdev, 0, true, false)`, which
//!    refuses a WCPU that still runs and starts it in download mode;
//! 3. `rtw89_fw_download_suit`: the H2C path's ready bit polled, the header
//!    sent (`__rtw89_fw_download_hdr`), the download path's ready bit polled,
//!    HALT_H2C_CTRL and HALT_C2H_CTRL cleared (`rtw89_fw_download_hdr`), then
//!    every section in parts of at most [`AxImage::part_bytes`] (2020) bytes
//!    (`__rtw89_fw_download_main`). An AX chip checks nothing after the
//!    parts;
//! 4. the H2C sequence back to 0, 5 ms, then [`check_rdy`]:
//!    `rtw89_fw_check_rdy(rtwdev, RTW89_FWDL_CHECK_FREERTOS_DONE)`, which
//!    polls WCPU_FW_CTRL's status until the firmware reports
//!    `RTW89_FWDL_WCPU_FW_INIT_RDY` and decodes the status it gave up on.
//!
//! A failure after the CPU was enabled reads what `rtw89_fw_dl_fail_dump`
//! reads ([`fail_dump`]) before the next attempt; an [`enable_cpu`] refusal
//! returns before it, as in rtw89. Every poll is 1 us apart for up to
//! [`FWDL_WAIT_CNT`] us, counted in steps ([`Registers::poll32`]).
//!
//! The header is the image's fixed header and section descriptors, without
//! the dynamic header, with W7's part size set to the part size
//! (`__rtw89_fw_download_tweak_hdr_v0`); it carries the current H2C sequence
//! number and asks for no ack ([`Channel::fwdl_header`]). Each part has no
//! header and sets the TXWD's FW_DL ([`Channel::fwdl_part`]). rtw89 paces
//! nothing between parts: no delay, poll or ack. Each `rtw89_h2c_tx` only
//! reclaims what the chip read on CH12 and needs a free BD; a full ring is
//! `-ENOSPC`, which fails the attempt ([`Channel::send`]).
//!
//! Secure boot: rtw89 decides it at the first power-on from two physical
//! efuse bytes ([`FwSecure::recognize`], `rtw89_efuse_read_fw_secure_ax`).
//! Without it, `rtw89_fw_hdr_parser_v0` selects no signature key and
//! overrides no length, and `rtw89_fwdl_secure_idmem_share_mode_ax` makes no
//! access, so a security section (type [`FWDL_SECURITY_SECTION_TYPE`]) is
//! sent as any other: its bytes, checksum included, and none of the MSS
//! signatures behind it. That is the only path here. A chip that rtw89
//! would boot securely is refused before any access ([`Failure::SecureBoot`]):
//! choosing its MSS signature and RTL8852B's 960-byte override are the
//! secure-boot step's.
//!
//! What this leaves out, and why:
//! - BB MCU suits and `include_bb`: `bbmcu_nr` is 0 on an RTL8852B.
//! - `rtw89_fw_hdr_parser_v1` and `__rtw89_fw_download_tweak_hdr_v1`: the
//!   image ([`AxImage`]) refuses header version 1, and the parsing itself
//!   makes no access.
//! - `rtw89_mac_enable_cpu_ax` with `dlfw` false, USB's shorter path-ready
//!   bound, and RTL8922A's secure-boot malloc info: not reached here.
//! - `RTW89_FLAG_FW_RDY`, `rec_seq`, the H2C/C2H counters and the RPWM/CPWM
//!   sequence numbers `__rtw89_fw_download` resets: Stela keeps no such
//!   state; a [`Downloaded`] stands for the flag.
//!
//! A download that returns proves only that WCPU_FW_CTRL read
//! `RTW89_FWDL_WCPU_FW_INIT_RDY` (FREERTOS_DONE): the firmware booted far
//! enough to say so. It proves nothing about its radio, the efuse, or that it
//! will accept the commands that follow.
use super::super::firmware::AxImage;
use super::{
    h2c::{self, Channel, MAX_PACKET},
    io::{self, Io, Registers, field, prep},
    pci::ring::Rings,
    registers::*,
};

/// The attempts `rtw89_fw_download` makes.
pub const DOWNLOAD_ATTEMPTS: usize = 5;
/// `FWDL_WAIT_CNT`: the PCIe bound, in microseconds, of the path-ready and
/// status polls, each 1 us apart (`read_poll_timeout_atomic(…, 1,
/// FWDL_WAIT_CNT, …)`).
pub const FWDL_WAIT_CNT: u64 = 400_000;
const FWDL_POLL_STEP_US: u64 = 1;
/// `__rtw89_fw_download`'s `mdelay(5)` before FREERTOS_DONE is polled.
pub const FREERTOS_DELAY_US: u64 = 5000;
/// The program counter reads `rtw89_fw_prog_cnt_dump` makes, each followed
/// by `fsleep(10)`.
pub const PROG_CNT_READS: usize = 15;
const PROG_CNT_DELAY_US: u64 = 10;
/// `FWDL_SECURITY_SECTION_TYPE`.
pub const FWDL_SECURITY_SECTION_TYPE: u8 = 9;
/// Where `struct rtw89_fw_hdr`'s W7 lies, and its `FW_HDR_W7_PART_SIZE`.
const FW_HDR_W7: usize = 28;
pub const FW_HDR_W7_PART_SIZE: u32 = 0x0000_ffff;
/// `struct rtw89_fw_hdr` with `FWDL_SECTION_MAX_NUM` section descriptors:
/// the longest header `__rtw89_fw_download_hdr` sends.
pub const MAX_BASE_HEADER: usize = 32 + 16 * 10;
/// The boot reason `__rtw89_fw_download` gives `rtw89_mac_enable_cpu_ax`.
const BOOT_REASON_DOWNLOAD: u16 = 0;
/// `B_AX_SEC_IDMEM_SIZE_CONFIG_MASK`'s value on an RTL885xB.
const SEC_IDMEM_SIZE_CONFIG: u32 = 0x2;

/// `enum rtw89_fw_dl_status`: WCPU_FW_CTRL's status field.
pub const FWDL_INITIAL_STATE: u8 = 0;
pub const FWDL_FWDL_ONGOING: u8 = 1;
pub const FWDL_CHECKSUM_FAIL: u8 = 2;
pub const FWDL_SECURITY_FAIL: u8 = 3;
pub const FWDL_CV_NOT_MATCH: u8 = 4;
pub const FWDL_RSVD0: u8 = 5;
pub const FWDL_WCPU_FWDL_RDY: u8 = 6;
pub const FWDL_WCPU_FW_INIT_RDY: u8 = 7;

/// `EFUSE_B1_MSSDEVTYPE_MASK`, `EFUSE_B2_CUSTOMER_MASK` and
/// `EFUSE_B2_SERIALNUM_MASK` (efuse.c).
const EFUSE_B1_MSSDEVTYPE_MASK: u8 = 0x0f;
const EFUSE_B2_CUSTOMER_MASK: u8 = 0x0f;
const EFUSE_B2_SERIALNUM_MASK: u8 = 0x70;
/// `otp_key_info_externalPN`, `otp_key_info_customer` and
/// `otp_key_info_serialNum`, entry by entry.
const OTP_KEY_INFO: [(u8, u8, u8); 2] = [(0x0, 0x0, 0x0), (0x0, 0x1, 0x1)];
/// `MSS_DEV_TYPE_FWSEC_NONLIN_INBOX_NON_COB`, and every
/// `enum rtw89_efuse_mss_dev_type` that `get_mss_dev_type_idx` knows.
const MSS_DEV_TYPE_FWSEC_NONLIN_INBOX_NON_COB: u8 = 0xa;
const MSS_DEV_TYPES: [u8; 5] = [0xf, 0xc, 0xa, 0x9, 0x6];

/// What `rtw89_efuse_read_fw_secure_ax` leaves in `rtwdev->fw.sec`, as far
/// as deciding secure boot goes: which MSS recognizer took the efuse bytes,
/// and whether either did. The MSS index, device type, customer index and
/// key number they also record are the secure-boot step's.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FwSecure {
    /// The bytes at `EFUSE_EXTERNALPN_ADDR_AX` and the next address, or
    /// `None` when reading them failed.
    pub efuse: Option<[u8; 2]>,
    /// `rtw89_efuse_recognize_mss_index_v0` found the bytes in the OTP key
    /// table.
    pub can_mss_v0: bool,
    /// `rtw89_efuse_recognize_mss_info_v1` found a device type it knows.
    pub can_mss_v1: bool,
    pub secure_boot: bool,
}

impl FwSecure {
    /// `rtw89_efuse_read_fw_secure_ax` on an RTL8852B over what its physical
    /// efuse read gave ([`super::power::PoweredOn::secure_efuse`] of the
    /// first power-on, the only one that reads it): a failed read or two
    /// blank bytes leave secure boot off; otherwise it is on when either MSS
    /// recognizer takes the bytes.
    pub fn recognize(read: Result<[u8; 2], io::Error>) -> Self {
        let Ok(efuse) = read else {
            return Self::default();
        };
        let [b1, b2] = efuse;
        let mut sec = Self {
            efuse: Some(efuse),
            ..Self::default()
        };
        if b1 == 0xff && b2 == 0xff {
            return sec;
        }
        // rtw89_efuse_recognize_mss_index_v0
        let external_pn = 0xff - b1;
        let customer = 0xf - (b2 & EFUSE_B2_CUSTOMER_MASK);
        let serial_num = 0x7 - ((b2 & EFUSE_B2_SERIALNUM_MASK) >> 4);
        sec.can_mss_v0 = OTP_KEY_INFO.contains(&(external_pn, customer, serial_num));
        // rtw89_efuse_recognize_mss_info_v1, whose RTL8852B case comes first.
        let mss_dev_type = if b1 == 0xff && b2 == 0x6e {
            MSS_DEV_TYPE_FWSEC_NONLIN_INBOX_NON_COB
        } else {
            b1 & EFUSE_B1_MSSDEVTYPE_MASK
        };
        sec.can_mss_v1 = MSS_DEV_TYPES.contains(&mss_dev_type);
        sec.secure_boot = sec.can_mss_v0 || sec.can_mss_v1;
        sec
    }
}

/// Why one attempt failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `rtw89_mac_enable_cpu_ax`'s `-EFAULT`: PLATFORM_ENABLE still read
    /// WCPU_EN after the CPU was disabled.
    CpuEnabled,
    /// An access the interface refused, or a path-ready poll that timed out
    /// (`-ETIMEDOUT`): [`io::Error::Timeout`] names WCPU_FW_CTRL and
    /// H2C_PATH_RDY or FWDL_PATH_RDY.
    Io(io::Error),
    /// Sending the header or a part failed: [`h2c::Error::NoResource`] is
    /// `rtw89_h2c_tx`'s `-ENOSPC`.
    H2c(h2c::Error),
    /// `rtw89_fw_check_rdy`'s verdicts on the status WCPU_FW_CTRL last read
    /// when FREERTOS_DONE did not come: `RTW89_FWDL_CHECKSUM_FAIL`,
    /// `RTW89_FWDL_SECURITY_FAIL` and `RTW89_FWDL_CV_NOT_MATCH`
    /// (`-EINVAL`), or any other (`-EBUSY`).
    ChecksumFail,
    SecurityFail,
    CvNotMatch,
    UnexpectedStatus(u8),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<h2c::Error> for Error {
    fn from(error: h2c::Error) -> Self {
        match error {
            h2c::Error::Io(error) => Self::Io(error),
            error => Self::H2c(error),
        }
    }
}

/// What `rtw89_fw_dl_fail_dump` reads after a failed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailDump {
    /// WCPU_FW_CTRL ("fwdl 0x1E0").
    pub wcpu_fw_ctrl: u32,
    /// BOOT_DBG.
    pub boot_dbg: u32,
    /// The WCPU's program counter, read [`PROG_CNT_READS`] times.
    pub pc: [u32; PROG_CNT_READS],
}

/// One failed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub error: Error,
    /// The registers read after it, or the access that refused reading
    /// them; `None` when [`enable_cpu`] failed, where rtw89 reads none.
    pub dump: Option<Result<FailDump, io::Error>>,
}

/// A download whose firmware reported FREERTOS_DONE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Downloaded {
    /// Why each earlier attempt failed, oldest first, then `None`.
    pub retried: [Option<Attempt>; DOWNLOAD_ATTEMPTS - 1],
    /// The H2C packets the attempt that succeeded sent: the header and
    /// every part.
    pub packets: usize,
}

/// Why no firmware runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "every attempt's error and registers come back without allocating on failure"
)]
pub enum Failure {
    /// rtw89 would boot this chip securely, which this path does not do;
    /// nothing was accessed.
    SecureBoot(FwSecure),
    /// An image this download cannot send as rtw89 does: a part size of 0 or
    /// one TXPKT_SIZE cannot carry, or a base header that is not a fixed
    /// header with at most ten section descriptors. Nothing was accessed.
    Image {
        part_bytes: usize,
        header_bytes: usize,
    },
    /// Every attempt failed: why, oldest first.
    Attempts([Attempt; DOWNLOAD_ATTEMPTS]),
}

/// `rtw89_fw_download(rtwdev, RTW89_FW_NORMAL, false)` on an RTL8852BE whose
/// PCIe pre-init ran over `rings`, with `image` as the normal suit and
/// `secure` as the first power-on decided it. `channel` sends on `rings`; its
/// sequence number goes back to 0 once the image is in.
///
/// The chip may read every command buffer handed over on CH12 for as long
/// as its DMA runs, and `rings` keeps each one until the chip has moved past
/// it, as for any H2C ([`Channel::send`]).
#[expect(
    clippy::result_large_err,
    reason = "every attempt's error and registers come back without allocating on failure"
)]
pub fn download<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    channel: &mut Channel<'_>,
    image: &AxImage<'_>,
    secure: &FwSecure,
) -> Result<Downloaded, Failure> {
    if secure.secure_boot {
        return Err(Failure::SecureBoot(*secure));
    }
    let header_bytes = image.base_header.len();
    if image.part_bytes == 0
        || image.part_bytes > MAX_PACKET
        || !(32..=MAX_BASE_HEADER).contains(&header_bytes)
    {
        return Err(Failure::Image {
            part_bytes: image.part_bytes,
            header_bytes,
        });
    }
    let unused = Attempt {
        error: Error::CpuEnabled,
        dump: None,
    };
    let mut failed = [unused; DOWNLOAD_ATTEMPTS];
    for index in 0..DOWNLOAD_ATTEMPTS {
        match attempt(io, rings, channel, image) {
            Ok(packets) => {
                let mut retried = [None; DOWNLOAD_ATTEMPTS - 1];
                for (slot, attempt) in retried.iter_mut().zip(&failed[..index]) {
                    *slot = Some(*attempt);
                }
                return Ok(Downloaded { retried, packets });
            }
            Err(attempt) => failed[index] = attempt,
        }
    }
    Err(Failure::Attempts(failed))
}

/// The H2C packets a download of `image` sends: the header, then each
/// section's parts.
pub fn packets(image: &AxImage<'_>) -> usize {
    let part = image.part_bytes.max(1);
    1 + image
        .sections
        .iter()
        .map(|section| section.data.len().div_ceil(part))
        .sum::<usize>()
}

/// `__rtw89_fw_download` for the normal suit of a non-secure RTL8852BE: the
/// H2C packets it sent.
fn attempt<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    channel: &mut Channel<'_>,
    image: &AxImage<'_>,
) -> Result<usize, Attempt> {
    let early = |error: Error| Attempt { error, dump: None };
    disable_cpu(io).map_err(|error| early(error.into()))?;
    enable_cpu(io).map_err(early)?;
    let packets = match download_suit(io, rings, channel, image) {
        Ok(packets) => packets,
        Err(error) => {
            return Err(Attempt {
                error,
                dump: Some(fail_dump(io)),
            });
        }
    };
    // No BB MCU suit follows: bbmcu_nr is 0.
    channel.reset_sequence();
    io.delay_us(FREERTOS_DELAY_US);
    if let Err(error) = check_rdy(io) {
        return Err(Attempt {
            error,
            dump: Some(fail_dump(io)),
        });
    }
    Ok(packets)
}

/// `rtw89_mac_disable_cpu_ax` on an RTL8852B: the WCPU stopped, its download
/// mode and both paths' ready bits cleared, its clock gated, the watchdog
/// disabled the RTL885xB way (APB_WRAP_EN cleared and set), and the platform
/// reset. Clearing `RTW89_FLAG_FW_RDY` is the caller's.
pub fn disable_cpu<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32_clr(PLATFORM_ENABLE, WCPU_EN)?;
    io.write32_clr(WCPU_FW_CTRL, WCPU_FWDL_EN | H2C_PATH_RDY | FWDL_PATH_RDY)?;
    io.write32_clr(SYS_CLK_CTRL, CPU_CLK_EN)?;
    // rtw89_disable_fw_watchdog, rtw89_is_rtl885xb
    io.write32_clr(PLATFORM_ENABLE, APB_WRAP_EN)?;
    io.write32_set(PLATFORM_ENABLE, APB_WRAP_EN)?;
    io.write32_clr(PLATFORM_ENABLE, PLATFORM_EN)?;
    io.write32_set(PLATFORM_ENABLE, PLATFORM_EN)
}

/// `rtw89_mac_enable_cpu_ax(rtwdev, 0, true, false)`, as
/// `__rtw89_fw_download` calls it: refuse a WCPU that runs, clear the
/// mailboxes and halt registers, enable the WCPU's clock, set the download
/// status to `RTW89_FWDL_INITIAL_STATE` with download mode on, size the
/// IDMEM the RTL885xB way, record boot reason 0 and start the WCPU.
pub fn enable_cpu<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    if io.read32(PLATFORM_ENABLE)? & WCPU_EN != 0 {
        return Err(Error::CpuEnabled);
    }
    io.write32(UDM1, 0)?;
    io.write32(UDM2, 0)?;
    io.write32(HALT_H2C_CTRL, 0)?;
    io.write32(HALT_C2H_CTRL, 0)?;
    io.write32(HALT_H2C, 0)?;
    io.write32(HALT_C2H, 0)?;

    io.write32_set(SYS_CLK_CTRL, CPU_CLK_EN)?;

    let mut val = io.read32(WCPU_FW_CTRL)?;
    val &= !(WCPU_FWDL_EN | H2C_PATH_RDY | FWDL_PATH_RDY);
    val = (val & !WCPU_FWDL_STS_MASK) | prep(FWDL_INITIAL_STATE.into(), WCPU_FWDL_STS_MASK);
    // dlfw
    val |= WCPU_FWDL_EN;
    io.write32(WCPU_FW_CTRL, val)?;

    // rtw89_is_rtl885xb
    io.write32_mask(SEC_CTRL, SEC_IDMEM_SIZE_CONFIG_MASK, SEC_IDMEM_SIZE_CONFIG)?;

    io.write16_mask(BOOT_REASON, BOOT_REASON_MASK, BOOT_REASON_DOWNLOAD)?;
    io.write32_set(PLATFORM_ENABLE, WCPU_EN)?;
    Ok(())
}

/// `rtw89_fw_get_rdy_ax`: WCPU_FW_CTRL's status field, read 8 bits wide.
pub fn get_rdy<I: Io + ?Sized>(io: &mut I) -> Result<u8, io::Error> {
    Ok(field(io.read8(WCPU_FW_CTRL)?.into(), WCPU_FWDL_STS_MASK) as u8)
}

/// `rtw89_fwdl_check_path_ready_ax` over PCIe: WCPU_FW_CTRL read 8 bits wide
/// until H2C_PATH_RDY (`h2c_or_fwdl`) or FWDL_PATH_RDY is set.
pub fn check_path_ready<I: Io + ?Sized>(io: &mut I, h2c_or_fwdl: bool) -> Result<(), io::Error> {
    let check = if h2c_or_fwdl {
        H2C_PATH_RDY
    } else {
        FWDL_PATH_RDY
    };
    let mut waited = 0;
    loop {
        let val = io.read8(WCPU_FW_CTRL)?;
        if u32::from(val) & check != 0 {
            return Ok(());
        }
        if waited >= FWDL_WAIT_CNT {
            return Err(io::Error::Timeout {
                register: WCPU_FW_CTRL,
                mask: check,
            });
        }
        io.delay_us(FWDL_POLL_STEP_US);
        waited += FWDL_POLL_STEP_US;
    }
}

/// `rtw89_fw_check_rdy` on an AX chip, whose status read ignores the check
/// type: [`get_rdy`] until it reads `RTW89_FWDL_WCPU_FW_INIT_RDY`, and
/// otherwise the verdict on the status read last.
pub fn check_rdy<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    let mut waited = 0;
    loop {
        let val = get_rdy(io)?;
        if val == FWDL_WCPU_FW_INIT_RDY {
            return Ok(());
        }
        if waited >= FWDL_WAIT_CNT {
            return Err(match val {
                FWDL_CHECKSUM_FAIL => Error::ChecksumFail,
                FWDL_SECURITY_FAIL => Error::SecurityFail,
                FWDL_CV_NOT_MATCH => Error::CvNotMatch,
                other => Error::UnexpectedStatus(other),
            });
        }
        io.delay_us(FWDL_POLL_STEP_US);
        waited += FWDL_POLL_STEP_US;
    }
}

/// `rtw89_fw_download_suit` for a non-secure chip: the H2C packets it sent.
/// `rtw89_fw_hdr_parser` makes no access (`image` is its result), and
/// neither does `rtw89_fwdl_secure_idmem_share_mode` without secure boot.
fn download_suit<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    channel: &Channel<'_>,
    image: &AxImage<'_>,
) -> Result<usize, Error> {
    check_path_ready(io, true)?;
    download_hdr(io, rings, channel, image)?;
    let parts = download_main(io, rings, channel, image)?;
    Ok(1 + parts)
}

/// `rtw89_fw_download_hdr`: `__rtw89_fw_download_hdr`'s packet, the download
/// path's ready bit, then HALT_H2C_CTRL and HALT_C2H_CTRL cleared.
fn download_hdr<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    channel: &Channel<'_>,
    image: &AxImage<'_>,
) -> Result<(), Error> {
    let mut header = [0; MAX_BASE_HEADER];
    let len = tweak_header(image, &mut header);
    channel.send(io, rings, &channel.fwdl_header(&header[..len]))?;
    check_path_ready(io, false)?;
    io.write32(HALT_H2C_CTRL, 0)?;
    io.write32(HALT_C2H_CTRL, 0)?;
    Ok(())
}

/// What `__rtw89_fw_download_hdr` copies into its skb: the base header
/// (`hdr_len - dynamic_hdr_len` bytes), with
/// `__rtw89_fw_download_tweak_hdr_v0` applied: W7's part size becomes the
/// part size, and, with no secure boot, no section length is overridden.
/// Returns the length; [`download`] bounded it.
pub fn tweak_header(image: &AxImage<'_>, out: &mut [u8; MAX_BASE_HEADER]) -> usize {
    let len = image.base_header.len();
    out[..len].copy_from_slice(image.base_header);
    let mut w7 = [0; 4];
    w7.copy_from_slice(&out[FW_HDR_W7..FW_HDR_W7 + 4]);
    let w7 = (u32::from_le_bytes(w7) & !FW_HDR_W7_PART_SIZE)
        | prep(image.part_bytes as u32, FW_HDR_W7_PART_SIZE);
    out[FW_HDR_W7..FW_HDR_W7 + 4].copy_from_slice(&w7.to_le_bytes());
    len
}

/// `rtw89_fw_download_main` on an AX chip: `__rtw89_fw_download_main` for
/// each section in order, then nothing. Without secure boot no section is
/// ignored, overridden or given a key, so each is sent whole, a part of at
/// most [`AxImage::part_bytes`] at a time; a section of no bytes sends
/// nothing. Returns the parts sent.
fn download_main<I: Io + ?Sized>(
    io: &mut I,
    rings: &mut Rings,
    channel: &Channel<'_>,
    image: &AxImage<'_>,
) -> Result<usize, Error> {
    let mut sent = 0;
    for section in &image.sections {
        for part in section.data.chunks(image.part_bytes) {
            channel.send(io, rings, &Channel::fwdl_part(part))?;
            sent += 1;
        }
    }
    Ok(sent)
}

/// `rtw89_fw_dl_fail_dump` on an AX chip: WCPU_FW_CTRL and BOOT_DBG, then
/// `rtw89_fw_prog_cnt_dump`: the debug port pointed at the WCPU's program
/// counter (DBG_CTRL, then SYS_STATUS1's selector) and read
/// [`PROG_CNT_READS`] times, 10 us apart.
pub fn fail_dump<I: Io + ?Sized>(io: &mut I) -> Result<FailDump, io::Error> {
    let wcpu_fw_ctrl = io.read32(WCPU_FW_CTRL)?;
    let boot_dbg = io.read32(BOOT_DBG)?;
    io.write32(
        DBG_CTRL,
        prep(FW_PROG_CNTR_DBG_SEL, DBG_SEL0) | prep(FW_PROG_CNTR_DBG_SEL, DBG_SEL1),
    )?;
    io.write32_mask(SYS_STATUS1, SEL_0XC0_MASK, MAC_DBG_SEL)?;
    let mut pc = [0; PROG_CNT_READS];
    for value in &mut pc {
        *value = io.read32(DBG_PORT_SEL)?;
        io.delay_us(PROG_CNT_DELAY_US);
    }
    Ok(FailDump {
        wcpu_fw_ctrl,
        boot_dbg,
        pc,
    })
}

#[cfg(test)]
mod tests;
