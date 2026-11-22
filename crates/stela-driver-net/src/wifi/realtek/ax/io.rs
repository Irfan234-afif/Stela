// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! RTL8852B register access over BAR2 as rtw89 reaches it, from pinned
//! rtw89/core.h, pci.c, phy.c, phy.h and mac.c:
//!
//! - MAC registers directly (`rtw89_read32`, `rtw89_write32_mask`), with the
//!   CMAC reads `rtw89_pci_ops_read32_cmac` retries after enabling the CMAC
//!   clocks;
//! - BB registers behind the AX generation's `cr_base`
//!   (`rtw89_phy_read32_mask`);
//! - RF registers as `rtw89_phy_read_rf_v1` and `rtw89_phy_write_rf_v1` reach
//!   them: directly through the BB window when the address carries ADSEL,
//!   otherwise through SWSI;
//! - the crystal's registers through XTAL SI (`rtw89_mac_read_xtal_si_ax`).
//!
//! Each helper makes the reads and writes its rtw89 counterpart makes, in the
//! same order, read-modify-write included. Polls follow `read_poll_timeout`:
//! a read every step until the condition holds, and one read past the bound
//! before giving up. The bound is counted in steps, so a delay that runs long
//! only lengthens it. Nothing here powers the chip or proves its state.
use super::registers::*;
use crate::{Clock, bus::mmio::Mmio};
use alloc::sync::Arc;
use core::ptr::NonNull;

/// BAR2 bytes the AX layers reach: MAC registers below 0x10000, BB and the
/// direct RF windows from [`CR_BASE`] up to 0x1ffff.
pub const BAR_BYTES: usize = 0x2_0000;
/// `rtw89_phy_gen_ax.cr_base`.
pub const CR_BASE: u32 = 0x1_0000;
/// `rtw8852b_chip_info.rf_base_addr`, one per RF path (`rf_path_num` is 2).
pub const RF_BASE: [u32; 2] = [0xe000, 0xf000];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A BAR mapping smaller than [`BAR_BYTES`] or not 4-byte aligned.
    Window { bytes: usize },
    /// A clock that does not count.
    InvalidClock,
    /// An access outside the window, misaligned, or after quarantine.
    Register { register: u32 },
    /// A poll that did not see its condition within its bound.
    Timeout { register: u32, mask: u32 },
    /// An RF path the chip does not have.
    RfPath(u8),
}

/// Exact register access to one RTL8852B.
///
/// # Safety
/// Reads are volatile observations of the one exclusively owned function,
/// stores complete in program order, and no other worker resets or programs
/// the function meanwhile. Delays wait at least the time asked.
pub unsafe trait Io {
    fn read8(&mut self, register: u32) -> Result<u8, Error>;
    fn read16(&mut self, register: u32) -> Result<u16, Error>;
    fn read32(&mut self, register: u32) -> Result<u32, Error>;
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error>;
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error>;
    fn delay_us(&mut self, microseconds: u64);
}

// SAFETY: forwards to the interface it borrows, with that interface's promises.
unsafe impl<I: Io + ?Sized> Io for &mut I {
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        (**self).read8(register)
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        (**self).read16(register)
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        (**self).read32(register)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        (**self).write8(register, value)
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        (**self).write16(register, value)
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        (**self).write32(register, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        (**self).delay_us(microseconds);
    }
}

/// `__ffs(mask)`, which rtw89 never takes of 0.
const fn shift(mask: u32) -> u32 {
    if mask == 0 { 0 } else { mask.trailing_zeros() }
}

/// The field `mask` selects, shifted down (`u32_get_bits`).
pub const fn field(value: u32, mask: u32) -> u32 {
    (value & mask) >> shift(mask)
}

/// `value` placed in the field `mask` selects, truncated (`FIELD_PREP`).
pub const fn prep(value: u32, mask: u32) -> u32 {
    (value << shift(mask)) & mask
}

/// The chip's versions as `rtw89_read_chip_ver` reads them on an RTL8852B.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipVersion {
    /// SYS_CFG1's cut (`hal->cv`).
    pub cut: u8,
    /// The analog cut XTAL SI gives (`hal->acv`), or `None` when XTAL SI
    /// did not answer, where rtw89 leaves it unset.
    pub acv: Option<u8>,
}

/// The rtw89 register helpers, over any [`Io`].
pub trait Registers: Io {
    /// `rtw89_read32_mask`.
    fn read32_mask(&mut self, register: u32, mask: u32) -> Result<u32, Error> {
        Ok(field(self.read32(register)?, mask))
    }
    /// `rtw89_write32_mask`: a read, then the write.
    fn write32_mask(&mut self, register: u32, mask: u32, data: u32) -> Result<(), Error> {
        if register & 3 != 0 {
            return Err(Error::Register { register });
        }
        let original = self.read32(register)?;
        self.write32(register, (original & !mask) | prep(data, mask))
    }
    /// `rtw89_write32_set`.
    fn write32_set(&mut self, register: u32, bits: u32) -> Result<(), Error> {
        let value = self.read32(register)?;
        self.write32(register, value | bits)
    }
    /// `rtw89_write32_clr`.
    fn write32_clr(&mut self, register: u32, bits: u32) -> Result<(), Error> {
        let value = self.read32(register)?;
        self.write32(register, value & !bits)
    }
    /// `rtw89_write16_mask`: the mask's low 16 bits, a read, then the write.
    fn write16_mask(&mut self, register: u32, mask: u32, data: u16) -> Result<(), Error> {
        let mask = mask & 0xffff;
        let original = self.read16(register)?;
        self.write16(
            register,
            (original & !(mask as u16)) | prep(u32::from(data), mask) as u16,
        )
    }
    /// `rtw89_write16_set`.
    fn write16_set(&mut self, register: u32, bits: u16) -> Result<(), Error> {
        let value = self.read16(register)?;
        self.write16(register, value | bits)
    }
    /// `rtw89_write16_clr`.
    fn write16_clr(&mut self, register: u32, bits: u16) -> Result<(), Error> {
        let value = self.read16(register)?;
        self.write16(register, value & !bits)
    }
    /// `rtw89_write8_set`.
    fn write8_set(&mut self, register: u32, bits: u8) -> Result<(), Error> {
        let value = self.read8(register)?;
        self.write8(register, value | bits)
    }
    /// `rtw89_write8_clr`.
    fn write8_clr(&mut self, register: u32, bits: u8) -> Result<(), Error> {
        let value = self.read8(register)?;
        self.write8(register, value & !bits)
    }
    /// `rtw89_phy_read32`.
    fn phy_read32(&mut self, register: u32) -> Result<u32, Error> {
        self.read32(phy(register)?)
    }
    /// `rtw89_phy_read32_mask`.
    fn phy_read32_mask(&mut self, register: u32, mask: u32) -> Result<u32, Error> {
        self.read32_mask(phy(register)?, mask)
    }
    /// `rtw89_phy_write32_mask`.
    fn phy_write32_mask(&mut self, register: u32, mask: u32, data: u32) -> Result<(), Error> {
        self.write32_mask(phy(register)?, mask, data)
    }
    /// `rtw89_phy_write32_set`.
    fn phy_write32_set(&mut self, register: u32, bits: u32) -> Result<(), Error> {
        self.write32_set(phy(register)?, bits)
    }
    /// `rtw89_phy_write32_clr`.
    fn phy_write32_clr(&mut self, register: u32, bits: u32) -> Result<(), Error> {
        self.write32_clr(phy(register)?, bits)
    }
    /// `read_poll_timeout(rtw89_read32, value, ready(value), step_us,
    /// bound_us, false, …)`: the value that satisfied `ready`.
    fn poll32(
        &mut self,
        register: u32,
        mask: u32,
        step_us: u64,
        bound_us: u64,
        ready: impl Fn(u32) -> bool,
    ) -> Result<u32, Error> {
        let mut waited = 0;
        loop {
            let value = self.read32(register)?;
            if ready(value) {
                return Ok(value);
            }
            if waited >= bound_us {
                return Err(Error::Timeout { register, mask });
            }
            self.delay_us(step_us);
            waited += step_us;
        }
    }
    /// `rtw89_phy_read_rf_v1`.
    fn read_rf(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, Error> {
        let base = rf_base(path)?;
        let mask = mask & RFREG_MASK;
        if address & RF_ADDR_ADSEL != 0 {
            // rtw89_phy_read_rf
            return self.phy_read32_mask(base + ((address & 0xff) << 2), mask);
        }
        // rtw89_phy_read_rf_a
        swsi_idle(self)?;
        let request =
            prep(u32::from(path), SWSI_READ_ADDR_PATH_V1) | prep(address, SWSI_READ_ADDR_ADDR_V1);
        self.phy_write32_mask(SWSI_READ_ADDR_V1, SWSI_READ_ADDR_MASK_V1, request)?;
        self.delay_us(2);
        let done = poll_rf(self, |io| {
            io.phy_read32_mask(SWSI_V1, SWSI_R_DATA_DONE_V1)
                .map(|done| done != 0)
        })?;
        if !done {
            return Err(Error::Timeout {
                register: CR_BASE + SWSI_V1,
                mask: SWSI_R_DATA_DONE_V1,
            });
        }
        self.phy_read32_mask(SWSI_V1, mask)
    }
    /// `rtw89_phy_write_rf_v1`.
    fn write_rf(&mut self, path: u8, address: u32, mask: u32, data: u32) -> Result<(), Error> {
        let base = rf_base(path)?;
        let mask = mask & RFREG_MASK;
        if address & RF_ADDR_ADSEL != 0 {
            // rtw89_phy_write_rf, then its delay "to ensure writing properly".
            self.phy_write32_mask(base + ((address & 0xff) << 2), mask, data)?;
            self.delay_us(1);
            return Ok(());
        }
        // rtw89_phy_write_rf_a
        swsi_idle(self)?;
        let mut data = data & RFREG_MASK;
        let masked = mask != RFREG_MASK;
        if masked {
            self.phy_write32_mask(SWSI_BIT_MASK_V1, RFREG_MASK, mask)?;
            data = (data << shift(mask)) & RFREG_MASK;
        }
        let value = prep(u32::from(masked), SWSI_DATA_BIT_MASK_EN_V1)
            | prep(u32::from(path), SWSI_DATA_PATH_V1)
            | prep(address, SWSI_DATA_ADDR_V1)
            | prep(data, SWSI_DATA_VAL_V1);
        self.phy_write32_mask(SWSI_DATA_V1, MASKDWORD, value)
    }
    /// `rtw89_mac_read_xtal_si_ax`.
    fn read_xtal_si(&mut self, offset: u8) -> Result<u8, Error> {
        let request = prep(u32::from(offset), XTAL_SI_ADDR_MASK)
            | prep(XTAL_SI_NORMAL_READ, XTAL_SI_MODE_MASK)
            | XTAL_SI_CMD_POLL;
        let done = xtal_si(self, request)?;
        Ok(field(done, XTAL_SI_DATA_MASK) as u8)
    }
    /// `rtw89_mac_write_xtal_si_ax`.
    fn write_xtal_si(&mut self, offset: u8, value: u8, mask: u8) -> Result<(), Error> {
        let request = prep(u32::from(offset), XTAL_SI_ADDR_MASK)
            | prep(u32::from(value), XTAL_SI_DATA_MASK)
            | prep(u32::from(mask), XTAL_SI_BITMASK_MASK)
            | prep(XTAL_SI_NORMAL_WRITE, XTAL_SI_MODE_MASK)
            | XTAL_SI_CMD_POLL;
        xtal_si(self, request).map(|_| ())
    }
    /// `rtw89_read_chip_ver` for an RTL8852B: SYS_CFG1's cut, then the
    /// analog cut through XTAL SI.
    fn chip_version(&mut self) -> Result<ChipVersion, Error> {
        let cut = self.read32_mask(SYS_CFG1, CHIP_VER_MASK)? as u8;
        let acv = match self.read_xtal_si(XTAL_SI_CV) {
            Ok(value) => Some(value & XTAL_SI_ACV_MASK),
            Err(Error::Timeout { .. }) => None,
            Err(error) => return Err(error),
        };
        Ok(ChipVersion { cut, acv })
    }
}

impl<I: Io + ?Sized> Registers for I {}

/// A BB register's BAR2 offset.
fn phy(register: u32) -> Result<u32, Error> {
    register
        .checked_add(CR_BASE)
        .ok_or(Error::Register { register })
}

fn rf_base(path: u8) -> Result<u32, Error> {
    RF_BASE
        .get(usize::from(path))
        .copied()
        .ok_or(Error::RfPath(path))
}

/// `read_poll_timeout_atomic(…, 1, 30, false, …)` over a condition that may
/// read more than once, as `rtw89_phy_check_swsi_busy` does: whether the
/// condition held within the bound.
fn poll_rf<I: Io + ?Sized>(
    io: &mut I,
    mut ready: impl FnMut(&mut I) -> Result<bool, Error>,
) -> Result<bool, Error> {
    const STEP_US: u64 = 1;
    const BOUND_US: u64 = 30;
    let mut waited = 0;
    loop {
        if ready(io)? {
            return Ok(true);
        }
        if waited >= BOUND_US {
            return Ok(false);
        }
        io.delay_us(STEP_US);
        waited += STEP_US;
    }
}

/// Wait until SWSI neither writes nor reads: `rtw89_phy_check_swsi_busy`
/// reads the write-busy bit, and the read-busy bit only when the first is
/// clear.
fn swsi_idle<I: Io + ?Sized>(io: &mut I) -> Result<(), Error> {
    let idle = poll_rf(io, |io| {
        let busy = match io.phy_read32_mask(SWSI_V1, SWSI_W_BUSY_V1)? {
            0 => io.phy_read32_mask(SWSI_V1, SWSI_R_BUSY_V1)?,
            busy => busy,
        };
        Ok(busy == 0)
    })?;
    if idle {
        Ok(())
    } else {
        Err(Error::Timeout {
            register: CR_BASE + SWSI_V1,
            mask: SWSI_W_BUSY_V1 | SWSI_R_BUSY_V1,
        })
    }
}

/// Write an XTAL SI request and wait, every 50 us for up to 50 ms, for the
/// chip to clear its poll bit: the register as it then reads.
fn xtal_si<I: Io + ?Sized>(io: &mut I, request: u32) -> Result<u32, Error> {
    io.write32(WLAN_XTAL_SI_CTRL, request)?;
    io.poll32(WLAN_XTAL_SI_CTRL, XTAL_SI_CMD_POLL, 50, 50_000, |value| {
        value & XTAL_SI_CMD_POLL == 0
    })
}

/// Volatile MMIO over one RTL8852B's BAR2, with `rtw89_pci_ops`' CMAC reads.
/// The owner keeps the PCI claim and mapping; after [`Self::quarantine`]
/// every access is refused and the owner is kept for good.
pub struct NativeIo {
    registers: Mmio,
    clock: Clock,
    bytes: usize,
    owner: Option<Arc<dyn core::any::Any>>,
}

impl NativeIo {
    /// # Safety
    /// `window` is the exclusive uncached BAR2 mapping of one RTL8852B
    /// function, at least `bytes` long, and `owner` keeps that claim and
    /// mapping. No other worker resets or programs the function while this
    /// lives. `clock` is calibrated for the processor that uses it.
    pub unsafe fn new(
        window: NonNull<u8>,
        bytes: usize,
        owner: Arc<dyn core::any::Any>,
        clock: Clock,
    ) -> Result<Self, Error> {
        if bytes < BAR_BYTES || window.as_ptr().addr() & 3 != 0 {
            return Err(Error::Window { bytes });
        }
        if clock.ticks_per_microsecond == 0 {
            return Err(Error::InvalidClock);
        }
        Ok(Self {
            // SAFETY: the constructor's exclusive mapped-BAR contract.
            registers: unsafe { Mmio::new(window.as_ptr() as u64, bytes) },
            clock,
            bytes,
            owner: Some(owner),
        })
    }

    /// Refuse every later access and keep the claim and mapping for good:
    /// the device may still reach them.
    pub fn quarantine(&mut self) {
        if let Some(owner) = self.owner.take() {
            core::mem::forget(owner);
        }
    }

    fn check(&self, register: u32, width: usize) -> Result<usize, Error> {
        let offset = register as usize;
        if self.owner.is_none()
            || !offset.is_multiple_of(width)
            || offset.checked_add(width).is_none_or(|end| end > self.bytes)
        {
            return Err(Error::Register { register });
        }
        Ok(offset)
    }

    /// `rtw89_pci_ops_read32_cmac`: a CMAC register that reads as
    /// `RTW89_R32_DEAD` is read again after its clocks are enabled, up to
    /// `MAC_REG_POOL_COUNT` times, and then reported as read.
    fn read32_cmac(&mut self, offset: usize) -> u32 {
        let mut value = self.registers.read32(offset);
        for _ in 0..MAC_REG_POOL_COUNT {
            if value != R32_DEAD {
                return value;
            }
            self.registers.write32(CK_EN as usize, CMAC_ALLCKEN);
            value = self.registers.read32(offset);
        }
        value
    }
}

/// `ACCESS_CMAC`.
fn cmac(register: u32) -> bool {
    (CMAC_REG_START..=CMAC_REG_END).contains(&register)
}

// SAFETY: the constructor binds the exclusive BAR2 mapping; each access is a
// volatile load or store, with no cached state.
unsafe impl Io for NativeIo {
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        let offset = self.check(register, 1)?;
        if !cmac(register) {
            return Ok(self.registers.read8(offset));
        }
        Ok((self.read32_cmac(offset & !3) >> ((offset & 3) * 8)) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        let offset = self.check(register, 2)?;
        if !cmac(register) {
            return Ok(self.registers.read16(offset));
        }
        Ok((self.read32_cmac(offset & !3) >> ((offset & 3) * 8)) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        let offset = self.check(register, 4)?;
        if !cmac(register) {
            return Ok(self.registers.read32(offset));
        }
        Ok(self.read32_cmac(offset))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        let offset = self.check(register, 1)?;
        self.registers.write8(offset, value);
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        let offset = self.check(register, 2)?;
        self.registers.write16(offset, value);
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        let offset = self.check(register, 4)?;
        self.registers.write32(offset, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.clock.delay(microseconds);
    }
}

#[cfg(test)]
mod tests;
