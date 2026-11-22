// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! A whole RTL8852BE for stage 1's tests ([`super::bootstrap`]): one MAC
//! register file and one access log, answering every poll the first slices
//! make, and a WCPU that takes its firmware from the CH12 ring. It is put
//! together from the slices' own models:
//!
//! - the PCIe pre-init's ([`super::pci::tests::Model`]) holds MAC space, the
//!   configuration space and the PCIe PHY behind MDIO and DBI, reads the DMA
//!   as idle, drops RST_BDRAM, and logs every access;
//! - the efuse step's ([`super::efuse::tests::Model`]), unlogged, answers EFUSE_CTRL
//!   from its DDV map, XTAL SI from its registers (the analog cut at
//!   [`XTAL_SI_CV`] among them) and its DAV map, and the register mailbox,
//!   whose H2C it answers with its phycap words. Every access to those
//!   registers reaches it, and the value it gives is what the log shows;
//! - here, as the power step's and the DMAC pre-init's models answer them:
//!   SYS_PW_CTRL reading RDY_SYSPWR and completing the ON and OFF MAC
//!   requests, IC_PWR_STATE reading whether the WL MAC is on, and the DLE's
//!   ready bits; as the MAC init's model answers them ([`super::mac`]): the
//!   STA scheduler's init done, no public page used and every one
//!   available, and the address CAM's clear and the BA CAM's reset
//!   completing at once; and the WCPU.
//!
//! The WCPU starts an attempt when WCPU_EN goes from 0 to 1, and reads
//! H2C_PATH_RDY at once. A kick on CH12 hands it every BD up to the new
//! host index: as the chip's DMA would, it reads each BD from the ring base
//! CH12_TXBD_DESA_L names and the frame behind it from the DMA domain, keeps
//! the frame and moves the hardware index. An attempt's first frame is the
//! firmware header, whose section descriptors and part size say how many
//! parts follow; FWDL_PATH_RDY reads set once the header is in, and once
//! every part is in WCPU_FW_CTRL reports the attempt's scripted status,
//! FREERTOS_DONE (`RTW89_FWDL_WCPU_FW_INIT_RDY`) unless the script says
//! otherwise.
//!
//! For stage 2 ([`super::radio`]) it also answers the radio's accesses as
//! a chip whose radio idles: the ring index clears of the PCIe pre-init
//! reset CH12's and RXQ's indices, SWSI reads complete at once (the RF data
//! being what the SWSI register holds), the LTE indirect access is always
//! ready and keeps its own registers, and packets queued with
//! [`Chip::queue_rx`] are written into RXQ's next buffers, as the chip's DMA
//! would, before the host next reads RXQ's index.
//!
//! It checks nothing the firmware would check (no checksum, no cut) and
//! sends no C2H on RXQ by itself. Delays take no time.
use super::{
    efuse::tests::{Case, Model as Efuse},
    fwdl::{FW_HDR_W7_PART_SIZE, FWDL_WCPU_FW_INIT_RDY},
    h2c::{H2C_DESC_SIZE, HEADER_LEN},
    h2creg::C2H_REGS,
    io::{self, CR_BASE, Io, prep},
    pci::{
        ring::{RXBD_NUM_MAX, RxBd, RxBdInfo, TXBD_NUM_MAX, TxBd},
        tests::{Access, Domain, Model as Bus},
    },
    registers::*,
};
use crate::bus::pci::{ConfigError, ConfigSpace};
use alloc::{sync::Arc, vec, vec::Vec};
use core::cell::RefCell;

/// The registers the efuse step's model answers, each at the one width
/// rtw89 reaches it.
const EFUSE_REGISTERS: [(u32, u32); 8] = [
    (EFUSE_CTRL, 4),
    (WLAN_XTAL_SI_CTRL, 4),
    (H2CREG_CTRL, 1),
    (C2HREG_CTRL, 1),
    (C2H_REGS[0], 4),
    (C2H_REGS[1], 4),
    (C2H_REGS[2], 4),
    (C2H_REGS[3], 4),
];

/// The registers given behavior here, each reached 32 bits at a time.
const WIDE: [u32; 4] = [SYS_PW_CTRL, IC_PWR_STATE, WDE_INI_STATUS, PLE_INI_STATUS];
/// The LTE access's ready byte and SWSI's status, as MAC addresses.
const LTE_CTRL_BYTE3: u32 = LTE_CTRL + 3;
const SWSI: u32 = CR_BASE + SWSI_V1;

fn overlaps(register: u32, width: u32, at: u32, bytes: u32) -> bool {
    register < at + bytes && at < register + width
}

struct State {
    /// The WL MAC is on.
    on: bool,
    /// The status each attempt reports once its parts are in, the last one
    /// repeating.
    script: Vec<u8>,
    /// Every attempt's frames, as the chip read them: the TXWD body and the
    /// packet behind it.
    attempts: Vec<Vec<Vec<u8>>>,
    /// The packets the current attempt's header announced.
    expected: Option<usize>,
    /// The next CH12 BD the chip reads.
    host: u32,
    /// The next RXQ BD the chip fills, and the packets waiting for one.
    rx_hw: u32,
    rx_queue: Vec<Vec<u8>>,
    rx_tag: u16,
    /// The LTE indirect access's registers, by word.
    lte: [u32; 64],
}

pub(crate) struct Chip {
    bus: Bus,
    efuse: RefCell<Efuse>,
    state: RefCell<State>,
    domain: Arc<Domain>,
}

impl Chip {
    /// A cold chip of cut `case.cut` and analog cut `acv`, with `case`'s
    /// efuse and firmware mailbox, whose DMA reaches `domain`, and whose
    /// firmware reports FREERTOS_DONE once it is in. Its link is Gen 1 with
    /// ASPM L1 and the PHY's calibration on, as the pre-init's model's.
    pub(crate) fn new(case: &Case, acv: u8, domain: Arc<Domain>) -> Self {
        let bus = Bus::zeroed(0x11, 0x08, true);
        let mut efuse = Efuse::zeroed(case);
        efuse.logging = false;
        efuse.xtal[usize::from(XTAL_SI_CV)] = acv;
        bus.set(SYS_CFG1, 4, prep(case.cut.into(), CHIP_VER_MASK));
        bus.set(SYS_WL_EFUSE_CTRL, 2, efuse.get(SYS_WL_EFUSE_CTRL, 2));
        Self {
            bus,
            efuse: RefCell::new(efuse),
            state: RefCell::new(State {
                on: false,
                script: vec![FWDL_WCPU_FW_INIT_RDY],
                attempts: Vec::new(),
                expected: None,
                host: 0,
                rx_hw: 0,
                rx_queue: Vec::new(),
                rx_tag: 0,
                lte: [0; 64],
            }),
            domain,
        }
    }

    /// The chip as a previous boot left it: the WL MAC on.
    pub(crate) fn left_on(self) -> Self {
        self.state.borrow_mut().on = true;
        self
    }

    /// The status each attempt reports once its parts are in, the last one
    /// repeating.
    pub(crate) fn statuses(self, script: &[u8]) -> Self {
        assert!(!script.is_empty());
        self.state.borrow_mut().script = script.to_vec();
        self
    }

    pub(crate) fn log(&self) -> Vec<Access> {
        self.bus.log()
    }

    /// Whether later accesses are logged.
    pub(crate) fn logging(&self, on: bool) {
        self.bus.logging(on);
    }

    /// Whether the WL MAC is on.
    pub(crate) fn on(&self) -> bool {
        self.state.borrow().on
    }

    /// Every attempt's frames, oldest first.
    pub(crate) fn attempts(&self) -> Vec<Vec<Vec<u8>>> {
        self.state.borrow().attempts.clone()
    }

    /// Packets for RXQ, each what follows the `rxbd_info` dword (the RX
    /// descriptor, driver info and packet), written into the next buffers
    /// before the host next reads RXQ's index.
    pub(crate) fn queue_rx(&self, packets: impl IntoIterator<Item = Vec<u8>>) {
        self.state.borrow_mut().rx_queue.extend(packets);
    }

    /// The packets still queued for RXQ.
    pub(crate) fn rx_queued(&self) -> usize {
        self.state.borrow().rx_queue.len()
    }

    /// Write the queued packets into RXQ's buffers from the next BD on, as
    /// the chip's DMA would, and move RXQ's hardware index past them.
    fn deliver_rx(&self) {
        let state = &mut *self.state.borrow_mut();
        let base = u64::from(self.bus.get(RXQ_RXBD_DESA_L, 4))
            | u64::from(self.bus.get(RXQ_RXBD_DESA_H, 4)) << 32;
        if base == 0 || state.rx_queue.is_empty() {
            return;
        }
        for packet in state.rx_queue.drain(..) {
            let at = base + u64::from(state.rx_hw) * RxBd::SIZE as u64;
            let bytes = self.domain.device_read(at, RxBd::SIZE);
            let bd = RxBd::decode(bytes.as_slice().try_into().unwrap());
            let info = RxBdInfo {
                fs: true,
                ls: true,
                len: (4 + packet.len()) as u16,
                tag: state.rx_tag,
            };
            let mut buffer = info.encode().to_le_bytes().to_vec();
            buffer.extend_from_slice(&packet);
            self.domain.device_write(bd.dma.into(), &buffer);
            state.rx_tag = state.rx_tag.wrapping_add(1) & 0x1fff;
            state.rx_hw = (state.rx_hw + 1) % RXBD_NUM_MAX;
        }
        self.bus.set(RXQ_RXBD_IDX + 2, 2, state.rx_hw);
    }

    fn efuse_register(register: u32, width: u32) -> bool {
        EFUSE_REGISTERS.contains(&(register, width))
    }

    fn check(register: u32, width: u32) {
        for (at, bytes) in EFUSE_REGISTERS {
            if overlaps(register, width, at, bytes) {
                assert!(
                    (register, width) == (at, bytes),
                    "{register:#x} reached {width} bytes wide"
                );
            }
        }
        for at in WIDE {
            if overlaps(register, width, at, 4) {
                assert!(
                    (register, width) == (at, 4),
                    "{register:#x} reached {width} bytes wide"
                );
            }
        }
    }

    /// The WCPU runs.
    fn cpu(&self) -> bool {
        self.bus.get(PLATFORM_ENABLE, 4) & WCPU_EN != 0
    }

    /// What a register with behavior reads, or `None` for plain memory.
    fn answer(&self, register: u32, width: u32) -> Option<u32> {
        if Self::efuse_register(register, width) {
            let mut efuse = self.efuse.borrow_mut();
            let value = match width {
                1 => efuse.read8(register).map(u32::from),
                _ => efuse.read32(register),
            };
            return Some(value.unwrap());
        }
        let state = self.state.borrow();
        let stored = self.bus.get(register, width);
        match (register, width) {
            (SYS_PW_CTRL, _) => Some(stored | RDY_SYSPWR),
            (IC_PWR_STATE, _) => Some(
                (stored & !WLMAC_PWR_STE_MASK)
                    | prep(u32::from(state.on) * MAC_AX_MAC_ON, WLMAC_PWR_STE_MASK),
            ),
            (WDE_INI_STATUS, _) => Some(stored | WDE_MGN_INI_RDY),
            (LTE_CTRL_BYTE3, 1) => Some(stored | u32::from(LTE_CTRL_READY)),
            (SWSI, 4) => Some((stored & !(SWSI_W_BUSY_V1 | SWSI_R_BUSY_V1)) | SWSI_R_DATA_DONE_V1),
            (PLE_INI_STATUS, _) => Some(stored | PLE_MGN_INI_RDY),
            (SS_CTRL, 4) => Some(stored | SS_INIT_DONE_1),
            (PUB_PAGE_INFO1, 4) => Some(stored & !(G0_USE_PG_MASK | G1_USE_PG_MASK)),
            (PUB_PAGE_INFO2, 4) => {
                let available = self.bus.get(PUB_PAGE_CTRL2, 4) & PUBPG_ALL_MASK;
                Some((stored & !PUB_AVAL_PG_MASK) | prep(available, PUB_AVAL_PG_MASK))
            }
            (WCPU_FW_CTRL, 1 | 4) if self.cpu() => {
                let frames = state.attempts.last().map_or(0, Vec::len);
                let mut value = stored | H2C_PATH_RDY;
                if frames > 0 {
                    value |= FWDL_PATH_RDY;
                }
                if state.expected.is_some_and(|expected| frames >= expected) {
                    let attempt = state.attempts.len().min(state.script.len());
                    let status = state.script[attempt.max(1) - 1];
                    value = (value & !WCPU_FWDL_STS_MASK) | prep(status.into(), WCPU_FWDL_STS_MASK);
                }
                Some(value)
            }
            _ => None,
        }
    }

    fn read(&self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        if (register, width) == (RXQ_RXBD_IDX, 4) {
            self.deliver_rx();
        }
        if let Some(value) = self.answer(register, width) {
            self.bus.set(register, width, value);
        }
        let mut bus = &self.bus;
        let value = match width {
            1 => Io::read8(&mut bus, register).map(u32::from),
            2 => Io::read16(&mut bus, register).map(u32::from),
            _ => Io::read32(&mut bus, register),
        };
        value.unwrap()
    }

    fn write(&self, register: u32, width: u32, value: u32) {
        Self::check(register, width);
        let cpu = self.cpu();
        let mut bus = &self.bus;
        match width {
            1 => Io::write8(&mut bus, register, value as u8),
            2 => Io::write16(&mut bus, register, value as u16),
            _ => Io::write32(&mut bus, register, value),
        }
        .unwrap();
        if Self::efuse_register(register, width) {
            let mut efuse = self.efuse.borrow_mut();
            match width {
                1 => efuse.write8(register, value as u8),
                _ => efuse.write32(register, value),
            }
            .unwrap();
        }
        match (register, width) {
            (ADDR_CAM_CTRL, 4) => self.bus.set(register, 4, value & !ADDR_CAM_CLR),
            (RESPBA_CAM_CTRL, 4) => self.bus.set(register, 4, value & !BACAM_RST_MASK),
            _ => {}
        }
        let state = &mut *self.state.borrow_mut();
        match (register, width) {
            (TXBD_RWPTR_CLR1, 4) if value & CLR_CH12_IDX != 0 => {
                state.host = 0;
                self.bus.set(CH12_TXBD_IDX + 2, 2, 0);
            }
            (RXBD_RWPTR_CLR, 4) if value & CLR_RXQ_IDX != 0 => {
                state.rx_hw = 0;
                self.bus.set(RXQ_RXBD_IDX + 2, 2, 0);
            }
            (LTE_CTRL, 4) => {
                let word = ((value & 0xffff) as usize / 4) % state.lte.len();
                match value & 0xffff_0000 {
                    LTE_CTRL_WRITE => state.lte[word] = self.bus.get(LTE_WDATA, 4),
                    LTE_CTRL_READ => self.bus.set(LTE_RDATA, 4, state.lte[word]),
                    _ => {}
                }
            }
            _ => {}
        }
        if register == SYS_PW_CTRL {
            let mut stored = value;
            if value & APFN_ONMAC != 0 {
                stored &= !APFN_ONMAC;
                state.on = true;
            }
            if value & APFM_OFFMAC != 0 {
                stored &= !APFM_OFFMAC;
                state.on = false;
            }
            self.bus.set(SYS_PW_CTRL, 4, stored);
        }
        if !cpu && self.cpu() {
            state.attempts.push(Vec::new());
            state.expected = None;
        }
        if register == CH12_TXBD_IDX && width == 2 {
            self.kick(state, value);
        }
    }

    /// The chip reads every CH12 BD up to the host index `to`, and the
    /// frame behind each, then moves the hardware index there.
    fn kick(&self, state: &mut State, to: u32) {
        let base = u64::from(self.bus.get(CH12_TXBD_DESA_L, 4))
            | u64::from(self.bus.get(CH12_TXBD_DESA_L + 4, 4)) << 32;
        while state.host != to {
            let at = base + u64::from(state.host) * TxBd::SIZE as u64;
            let bytes = self.domain.device_read(at, TxBd::SIZE);
            let bd = TxBd::decode(bytes.as_slice().try_into().unwrap());
            let frame = self.domain.device_read(bd.dma.into(), bd.length.into());
            let frames = state
                .attempts
                .last_mut()
                .expect("a command kicked before the WCPU started");
            if frames.is_empty() {
                state.expected = Some(announced(&frame));
            }
            frames.push(frame);
            state.host = (state.host + 1) % TXBD_NUM_MAX;
        }
        self.bus.set(CH12_TXBD_IDX + 2, 2, to);
    }
}

/// The packets a firmware header frame announces, as the WCPU reads them
/// off the wire: itself, then each section's parts of the part size W7
/// names, a checksum counting toward its section.
pub(crate) fn announced(frame: &[u8]) -> usize {
    let header = &frame[H2C_DESC_SIZE + HEADER_LEN..];
    let le32 = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let sections = ((le32(24) >> 8) & 0xff) as usize;
    let part = (le32(28) & FW_HDR_W7_PART_SIZE) as usize;
    let parts: usize = (0..sections)
        .map(|index| {
            let flags = le32(32 + 16 * index + 4);
            let checksum = if flags & (1 << 28) != 0 { 8 } else { 0 };
            ((flags & 0x00ff_ffff) as usize + checksum).div_ceil(part)
        })
        .sum();
    1 + parts
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for &Chip {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.read(register, 1) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.read(register, 2) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(self.read(register, 4))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.write(register, 1, value.into());
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.write(register, 2, value.into());
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.write(register, 4, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        let mut bus = &self.bus;
        bus.delay_us(microseconds);
    }
}

/// The pre-init's model's configuration space, logged with the registers.
impl ConfigSpace for &Chip {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        ConfigSpace::read8(&&self.bus, offset)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        ConfigSpace::read16(&&self.bus, offset)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        ConfigSpace::read32(&&self.bus, offset)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        ConfigSpace::write8(&mut &self.bus, offset, value)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        ConfigSpace::write16(&mut &self.bus, offset, value)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        ConfigSpace::write32(&mut &self.bus, offset, value)
    }
}
