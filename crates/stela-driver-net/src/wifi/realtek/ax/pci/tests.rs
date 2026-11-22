extern crate std;

use super::ring::{
    Buffer, CHECK_RX_TAG, DMA_ADDR_SET_RX, DMA_ADDR_SET_TX, DmaRing, FwCmdQueue, RX_BUF_SIZE,
    RX_TAG_MAX, RXBD_FS, RXBD_LS, Received, RxBd, RxBdInfo, RxChannel, StaleTag, TXBD_OPT_LS, TxBd,
    TxChannel, avail_txbd, below_4gib, dma_recalc, rxbd_increase, rxbd_recalc, sync_and_validate,
    tx_bd_ring_update, txbd_recalc, validate_rx_tag,
};
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping},
        memory::{CacheAttribute, MemoryError, PageBacking, PageSource, PinnedPages},
        pages::DmaPages,
    },
    pci::{ConfigError, ConfigFailure},
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    collections::BTreeMap,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{alloc::Layout, cell::RefCell, ops::Range, ptr::NonNull};
use std::sync::Mutex;

/// One access, as the C oracle's harness records it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Access {
    Read {
        width: u32,
        register: u32,
        value: u32,
    },
    Write {
        width: u32,
        register: u32,
        value: u32,
    },
    Delay(u64),
    /// A configuration read, `None` when the configuration space refused it.
    ConfigRead {
        offset: u16,
        value: Option<u8>,
    },
    ConfigWrite {
        offset: u16,
        value: u8,
        accepted: bool,
    },
}

pub(crate) fn r8(register: u32, value: u32) -> Access {
    Access::Read {
        width: 1,
        register,
        value,
    }
}
pub(crate) fn r16(register: u32, value: u32) -> Access {
    Access::Read {
        width: 2,
        register,
        value,
    }
}
pub(crate) fn r32(register: u32, value: u32) -> Access {
    Access::Read {
        width: 4,
        register,
        value,
    }
}
pub(crate) fn w8(register: u32, value: u32) -> Access {
    Access::Write {
        width: 1,
        register,
        value,
    }
}
pub(crate) fn w16(register: u32, value: u32) -> Access {
    Access::Write {
        width: 2,
        register,
        value,
    }
}
pub(crate) fn w32(register: u32, value: u32) -> Access {
    Access::Write {
        width: 4,
        register,
        value,
    }
}
fn cr(offset: u16, value: u8) -> Access {
    Access::ConfigRead {
        offset,
        value: Some(value),
    }
}
fn cw(offset: u16, value: u8) -> Access {
    Access::ConfigWrite {
        offset,
        value,
        accepted: true,
    }
}

/// The C oracle's record: tag, register, value, each a little-endian u32.
pub(crate) fn push(trace: &mut Vec<u8>, tag: u32, register: u32, value: u32) {
    for word in [tag, register, value] {
        trace.extend_from_slice(&word.to_le_bytes());
    }
}
pub(crate) fn encode(log: &[Access]) -> Vec<u8> {
    let mut trace = Vec::new();
    for access in log {
        match *access {
            Access::Read {
                width,
                register,
                value,
            } => push(&mut trace, width, register, value),
            Access::Write {
                width,
                register,
                value,
            } => push(&mut trace, 4 + width, register, value),
            Access::Delay(microseconds) => push(&mut trace, 9, 0, microseconds as u32),
            Access::ConfigRead {
                offset,
                value: Some(value),
            } => push(&mut trace, 21, offset.into(), value.into()),
            Access::ConfigRead {
                offset,
                value: None,
            } => push(&mut trace, 23, offset.into(), 0),
            Access::ConfigWrite {
                offset,
                value,
                accepted,
            } => push(
                &mut trace,
                if accepted { 22 } else { 24 },
                offset.into(),
                value.into(),
            ),
        }
    }
    trace
}

/// What the model's MAC space and PHY registers hold before the first
/// access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fill {
    /// MAC byte `i` holds `i * 37 + 11`; PHY register `a` of page `p`
    /// `(p * 32 + a) * 0x0b0b + 0x1234`.
    Pattern,
    Ones,
    Zeros,
}

/// How the model misbehaves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Faults {
    /// Every configuration access fails.
    config_fails: bool,
    /// The DBI flag never clears.
    dbi_stuck: bool,
    /// MDIO never completes for this PHY address, or for any with 0x20.
    mdio_stuck: Option<u8>,
    /// ACH0 never goes idle.
    tx_busy: bool,
    /// RXQ never goes idle.
    rx_busy: bool,
    /// RST_BDRAM never clears.
    bdram_stuck: bool,
}

/// MAC space and, behind `io::CR_BASE`, the BB and direct RF windows.
const MEMORY: usize = super::super::io::BAR_BYTES;
const CONFIG: usize = 0x1000;

struct State {
    memory: Vec<u8>,
    config: Vec<u8>,
    mdio: [[u16; 32]; 4],
    log: Vec<Access>,
    /// Whether accesses are logged; [`Model::logging`] turns it off for
    /// long polls.
    logging: bool,
    faults: Faults,
    waited_us: u64,
}

/// The register model the C oracle's harness uses: MAC space as bytes, the
/// PCIe PHY behind MDIO_CFG, configuration space behind the configuration
/// accessors and the DBI window, PCIE_DMA_BUSY1 idle unless held busy, and
/// RST_BDRAM dropped as it is written unless stuck. Shared references
/// implement both [`Io`] and [`ConfigSpace`], so the pre-init can take one
/// of each and both log to one trace.
pub(crate) struct Model(RefCell<State>);

fn overlaps(register: u32, width: u32, at: u32, bytes: u32) -> bool {
    register < at + bytes && at < register + width
}

impl State {
    fn record(&mut self, access: Access) {
        if self.logging {
            self.log.push(access);
        }
    }
    fn get(&self, register: u32, width: u32) -> u32 {
        let at = register as usize;
        let mut bytes = [0; 4];
        bytes[..width as usize].copy_from_slice(&self.memory[at..at + width as usize]);
        u32::from_le_bytes(bytes)
    }
    fn set(&mut self, register: u32, width: u32, value: u32) {
        let at = register as usize;
        self.memory[at..at + width as usize]
            .copy_from_slice(&value.to_le_bytes()[..width as usize]);
    }
    fn check(register: u32, width: u32) {
        assert!(
            register as usize + width as usize <= MEMORY,
            "{register:#x}"
        );
        if overlaps(register, width, PCIE_INIT_CFG1, 4)
            || overlaps(register, width, PCIE_DMA_BUSY1, 4)
        {
            assert!(
                width == 4 && register.is_multiple_of(4),
                "{register:#x} reached {width} bytes wide"
            );
        }
    }
    fn mdio_update(&mut self) {
        let mut cfg = self.get(MDIO_CFG, 2);
        let (addr, page) = ((cfg & 0x1f) as usize, ((cfg >> 12) & 3) as usize);
        if let Some(stuck) = self.faults.mdio_stuck
            && (stuck == 0x20 || usize::from(stuck) == addr)
        {
            return;
        }
        if cfg & u32::from(MDIO_RFLAG) != 0 {
            let value = self.mdio[page][addr];
            self.set(MDIO_RDATA, 2, value.into());
            cfg &= !u32::from(MDIO_RFLAG);
        }
        if cfg & u32::from(MDIO_WFLAG) != 0 {
            self.mdio[page][addr] = self.get(MDIO_WDATA, 2) as u16;
            cfg &= !u32::from(MDIO_WFLAG);
        }
        self.set(MDIO_CFG, 2, cfg);
    }
    fn dbi_update(&mut self) {
        let flag = self.memory[DBI_FLAG as usize + 2];
        let ctrl = self.get(DBI_FLAG, 2);
        let at = (ctrl & DBI_ADDR_MSK) as usize;
        if self.faults.dbi_stuck || flag & 3 == 0 {
            return;
        }
        if u32::from(flag) & (DBI_RFLAG >> 16) != 0 {
            for lane in 0..4 {
                self.memory[DBI_RDATA as usize + lane] = self.config[at + lane];
            }
        }
        if u32::from(flag) & (DBI_WFLAG >> 16) != 0 {
            for lane in 0..4 {
                if ctrl & (1 << (12 + lane)) != 0 {
                    self.config[at + lane] = self.memory[DBI_WDATA as usize + lane];
                }
            }
        }
        self.memory[DBI_FLAG as usize + 2] = 0;
    }
    fn read(&mut self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        let mut value = self.get(register, width);
        if register == PCIE_DMA_BUSY1 {
            value &= !(DMA_BUSY1_CHECK_V1 | RXQ_BUSY | RPQ_BUSY);
            if self.faults.tx_busy {
                value |= ACH0_BUSY;
            }
            if self.faults.rx_busy {
                value |= RXQ_BUSY;
            }
        }
        self.record(Access::Read {
            width,
            register,
            value,
        });
        value
    }
    fn write(&mut self, register: u32, width: u32, value: u32) {
        Self::check(register, width);
        self.record(Access::Write {
            width,
            register,
            value,
        });
        let mut stored = value;
        if register == PCIE_INIT_CFG1 && !self.faults.bdram_stuck {
            stored &= !RST_BDRAM;
        }
        self.set(register, width, stored);
        if overlaps(register, width, MDIO_CFG, 2) {
            self.mdio_update();
        }
        if overlaps(register, width, DBI_FLAG + 2, 1) {
            self.dbi_update();
        }
    }
}

impl Model {
    fn new(fill: Fill, phy_rate: u8, l1_ctrl: u8, calib: bool, faults: Faults) -> Self {
        let memory = match fill {
            Fill::Pattern => (0..MEMORY).map(|at| (at * 37 + 11) as u8).collect(),
            Fill::Ones => vec![0xff; MEMORY],
            Fill::Zeros => vec![0; MEMORY],
        };
        let mut config: Vec<u8> = (0..CONFIG).map(|at| (at * 13 + 7) as u8).collect();
        config[usize::from(PCIE_PHY_RATE)] = phy_rate;
        config[usize::from(PCIE_L1_CTRL)] = l1_ctrl;
        let mut mdio = [[0u16; 32]; 4];
        for (page, registers) in mdio.iter_mut().enumerate() {
            for (addr, register) in registers.iter_mut().enumerate() {
                *register = match fill {
                    Fill::Pattern => ((page * 32 + addr) * 0x0b0b + 0x1234) as u16,
                    Fill::Ones => 0xffff,
                    Fill::Zeros => 0,
                };
            }
        }
        for page in [1, 3] {
            let ppr = &mut mdio[page][usize::from(RAC_CTRL_PPR_V1 & 0x1f)];
            *ppr = if calib {
                *ppr | CALIB_EN
            } else {
                *ppr & !CALIB_EN
            };
        }
        Self(RefCell::new(State {
            memory,
            config,
            mdio,
            log: Vec::new(),
            logging: true,
            faults,
            waited_us: 0,
        }))
    }
    pub(crate) fn zeroed(phy_rate: u8, l1_ctrl: u8, calib: bool) -> Self {
        Self::new(Fill::Zeros, phy_rate, l1_ctrl, calib, Faults::default())
    }
    pub(crate) fn log(&self) -> Vec<Access> {
        self.0.borrow().log.clone()
    }
    pub(crate) fn take_log(&self) -> Vec<Access> {
        core::mem::take(&mut self.0.borrow_mut().log)
    }
    pub(crate) fn set(&self, register: u32, width: u32, value: u32) {
        self.0.borrow_mut().set(register, width, value);
    }
    /// What the register file holds, without an access.
    pub(crate) fn get(&self, register: u32, width: u32) -> u32 {
        self.0.borrow().get(register, width)
    }
    /// Whether later accesses are logged.
    pub(crate) fn logging(&self, on: bool) {
        self.0.borrow_mut().logging = on;
    }
    fn count(&self, access: Access) -> usize {
        self.0
            .borrow()
            .log
            .iter()
            .filter(|seen| **seen == access)
            .count()
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for &Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.0.borrow_mut().read(register, 1) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.0.borrow_mut().read(register, 2) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(self.0.borrow_mut().read(register, 4))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.0.borrow_mut().write(register, 1, value.into());
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.0.borrow_mut().write(register, 2, value.into());
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.0.borrow_mut().write(register, 4, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        let mut state = self.0.borrow_mut();
        state.waited_us += microseconds;
        state.record(Access::Delay(microseconds));
    }
}

fn refused(offset: u16, width: usize) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Access { offset, width })
}

impl ConfigSpace for &Model {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        let mut state = self.0.borrow_mut();
        assert!(usize::from(offset) < CONFIG, "{offset:#x}");
        if state.faults.config_fails {
            state.record(Access::ConfigRead {
                offset,
                value: None,
            });
            return Err(refused(offset, 1));
        }
        let value = state.config[usize::from(offset)];
        state.record(cr(offset, value));
        Ok(value)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        Err(refused(offset, 2))
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        Err(refused(offset, 4))
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        let mut state = self.0.borrow_mut();
        assert!(usize::from(offset) < CONFIG, "{offset:#x}");
        if state.faults.config_fails {
            state.record(Access::ConfigWrite {
                offset,
                value,
                accepted: false,
            });
            return Err(refused(offset, 1));
        }
        state.config[usize::from(offset)] = value;
        state.record(cw(offset, value));
        Ok(())
    }
    fn write16(&mut self, offset: u16, _: u16) -> Result<(), ConfigError> {
        Err(refused(offset, 2))
    }
    fn write32(&mut self, offset: u16, _: u32) -> Result<(), ConfigError> {
        Err(refused(offset, 4))
    }
}

/// The C oracle's fixed DMA addresses: the TX BD pool, the RX BD pool, and
/// the RX buffers in allocation order.
const TX_POOL_DMA: u64 = 0xfffe_0000;
const RX_POOL_DMA: u64 = 0xfffd_0000;
const RX_BUF_DMA: u64 = 0x8000_0000;

struct Pages {
    pointer: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
}
// SAFETY: exclusively kept zeroed, aligned RAM for a serialized model; no
// privileged allocation or physical DMA is claimed.
unsafe impl Send for Pages {}
// SAFETY: no safe byte references or concurrent device access are exposed.
unsafe impl Sync for Pages {}
// SAFETY: `cpu_base` and `physical` describe the one kept, aligned, zeroed
// test allocation for its whole life.
unsafe impl PageBacking for Pages {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the matching allocation with this
        // layout and is freed once.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

pub(crate) struct Source;
impl PageSource for Source {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let rounded = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(rounded, alignment).unwrap();
        // SAFETY: the layout has a nonzero size.
        let pointer =
            NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        let physical = (0..rounded / 4096)
            .map(|page| pointer.as_ptr() as u64 + page as u64 * 4096)
            .collect();
        PinnedPages::new(
            Box::new(Pages {
                pointer,
                layout,
                physical,
            }),
            bytes,
            alignment,
        )
    }
}

/// Where the domain places each mapping, by allocation order.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Placement {
    /// The C oracle's addresses.
    Oracle,
    /// The oracle's, but mapping `index` at `address`.
    Moved { index: usize, address: u64 },
}

struct Mapped {
    _pages: PinnedPages,
    cpu: usize,
    bytes: usize,
    direction: Direction,
}

#[derive(Default)]
struct DomainState {
    maps: usize,
    mappings: BTreeMap<u64, Mapped>,
    unmaps: usize,
    /// The address of every mapping unmapped, in order.
    unmapped: Vec<u64>,
    syncs_for_device: usize,
    syncs_for_cpu: usize,
}

/// A DMA domain that places mappings where [`Placement`] says and keeps a
/// CPU view of each, so a test can play the device.
pub(crate) struct Domain {
    placement: Placement,
    state: Mutex<DomainState>,
}

impl Domain {
    pub(crate) fn new(placement: Placement) -> Arc<Self> {
        Arc::new(Self {
            placement,
            state: Mutex::new(DomainState::default()),
        })
    }
    /// Copy `bytes` into the mapping that holds `address`, as the device.
    pub(crate) fn device_write(&self, address: u64, bytes: &[u8]) {
        let state = self.state.lock().unwrap();
        let (&base, mapped) = state.mappings.range(..=address).next_back().unwrap();
        let offset = (address - base) as usize;
        assert!(offset + bytes.len() <= mapped.bytes);
        assert_ne!(mapped.direction, Direction::ToDevice);
        // SAFETY: the range lies inside a live mapping this domain keeps,
        // and the test plays the device while the CPU holds no reference.
        unsafe {
            ((mapped.cpu + offset) as *mut u8)
                .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
        }
    }
    /// Copy `length` bytes out of the mapping that holds `address`, as the
    /// device reads them.
    pub(crate) fn device_read(&self, address: u64, length: usize) -> Vec<u8> {
        let state = self.state.lock().unwrap();
        let (&base, mapped) = state.mappings.range(..=address).next_back().unwrap();
        let offset = (address - base) as usize;
        assert!(offset + length <= mapped.bytes);
        assert_ne!(mapped.direction, Direction::FromDevice);
        let mut bytes = vec![0; length];
        // SAFETY: the range lies inside a live mapping this domain keeps,
        // and the test plays the device while the CPU writes none of it.
        unsafe {
            bytes
                .as_mut_ptr()
                .copy_from_nonoverlapping((mapped.cpu + offset) as *const u8, length);
        }
        bytes
    }
    pub(crate) fn unmaps(&self) -> usize {
        self.state.lock().unwrap().unmaps
    }
    /// The addresses unmapped since the last call, in order.
    pub(crate) fn take_unmapped(&self) -> Vec<u64> {
        core::mem::take(&mut self.state.lock().unwrap().unmapped)
    }
    pub(crate) fn live(&self) -> usize {
        self.state.lock().unwrap().mappings.len()
    }
}

// SAFETY: pinned allocations are held while mapped; IOVA placement and
// cache visibility are serialized model events, never hardware claims.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        _limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
        let mut state = self.state.lock().unwrap();
        let index = state.maps;
        state.maps += 1;
        let address = match self.placement {
            Placement::Moved {
                index: moved,
                address,
            } if moved == index => address,
            _ => match index {
                0 => TX_POOL_DMA,
                1 => RX_POOL_DMA,
                n => RX_BUF_DMA + 0x3000 * (n as u64 - 2),
            },
        };
        let cpu = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap()
            .address(0, pages.bytes())
            .unwrap()
            .as_ptr() as usize;
        state.mappings.insert(
            address,
            Mapped {
                _pages: pages.clone(),
                cpu,
                bytes: pages.bytes(),
                direction,
            },
        );
        Ok(DomainMapping {
            id: address,
            address,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, mapping: DomainMapping) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        state.unmaps += 1;
        state.unmapped.push(mapping.id);
        state
            .mappings
            .remove(&mapping.id)
            .map(|_| ())
            .ok_or(DmaError::Unmapped)
    }
    unsafe fn sync_for_device(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.mappings[&mapping.id].direction, direction);
        assert!(range.end <= mapping.bytes);
        state.syncs_for_device += 1;
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.mappings[&mapping.id].direction, direction);
        assert_ne!(direction, Direction::ToDevice);
        assert!(range.end <= mapping.bytes);
        state.syncs_for_cpu += 1;
        Ok(())
    }
}

pub(crate) fn new_rings(domain: &Arc<Domain>) -> Rings {
    Rings::new(&Source, domain.clone()).unwrap()
}

pub(crate) fn release(rings: &mut Rings) {
    // SAFETY: no modeled device keeps any of these mappings.
    unsafe { rings.release_after_stop() }.unwrap();
}

/// `rtw89_pci_ops_mac_pre_init_ax` over `model`.
fn pre_init(model: &Model, rings: &mut Rings) -> Result<(), Error> {
    let (mut io, mut config) = (model, model);
    // SAFETY: the model and these rings belong to this test alone; no
    // modeled device reaches the rings.
    unsafe { mac_pre_init(&mut io, &mut config, rings) }
}

/// One MDIO access as `rtw89_pci_check_mdio` makes it on a model whose
/// MDIO_CFG kept `previous_page` from the access before.
fn mdio(addr: u8, page: u16, previous_page: u16, rw_bit: u16) -> Vec<Access> {
    let low = u32::from(addr & 0x1f);
    let paged = low | u32::from(page) << 12;
    vec![
        w8(MDIO_CFG, low),
        r16(MDIO_CFG, low | u32::from(previous_page) << 12),
        w16(MDIO_CFG, paged),
        r16(MDIO_CFG, paged),
        w16(MDIO_CFG, paged | u32::from(rw_bit)),
        r16(MDIO_CFG, paged),
    ]
}

/// What `rtw89_pci_reset_trx_rings` writes for the oracle's addresses.
fn ring_writes() -> Vec<Access> {
    let mut expected = Vec::new();
    for (k, (txch, bdram)) in [
        (TxChannel::Ach0, 0x0002_0500),
        (TxChannel::Ach1, 0x0002_0505),
        (TxChannel::Ach2, 0x0002_050a),
        (TxChannel::Ach3, 0x0002_050f),
        (TxChannel::Ch8, 0x0001_0414),
        (TxChannel::Ch9, 0x0001_0418),
        (TxChannel::Ch12, 0x0001_041c),
    ]
    .into_iter()
    .enumerate()
    {
        let addr = DMA_ADDR_SET_TX[txch as usize];
        expected.extend([
            w16(addr.num, 256),
            w32(addr.bdram, bdram),
            w32(addr.desa_l, TX_POOL_DMA as u32 + 2048 * k as u32),
            w32(addr.desa_h, 0),
        ]);
    }
    for (k, num, desa_l) in [
        (0, RXQ_RXBD_NUM, RXQ_RXBD_DESA_L),
        (1, RPQ_RXBD_NUM, RPQ_RXBD_DESA_L),
    ] {
        expected.extend([
            w16(num, 256),
            w32(desa_l, RX_POOL_DMA as u32 + 2048 * k),
            w32(desa_l + 4, 0),
        ]);
    }
    expected
}

/// The accesses of the pre-init on a zeroed model whose link is 2.5 GT/s,
/// whose ASPM L1 is on and whose PHY calibrates, transcribed from
/// rtw89_pci_ops_mac_pre_init_ax and its callees.
fn cold_pre_init() -> Vec<Access> {
    let mut expected = vec![
        // rtw89_pci_l1off_pwroff
        r32(PCIE_PS_CTRL, 0),
        w32(PCIE_PS_CTRL, 0),
        // rtw89_pci_aphy_pwrcut
        r32(SYS_PW_CTRL, 0),
        w32(SYS_PW_CTRL, 0),
        // rtw89_pci_hci_ldo
        r32(SYS_SDIO_CTRL, 0),
        w32(SYS_SDIO_CTRL, 0x8000),
        r32(SYS_SDIO_CTRL, 0x8000),
        w32(SYS_SDIO_CTRL, 0x8000),
    ];
    // rtw89_pci_dphy_delay: CMU_EN_DLY to 25 us in RAC_REG_REV2, page 0.
    expected.extend(mdio(RAC_REG_REV2, 0, 0, MDIO_RFLAG));
    expected.push(r16(MDIO_RDATA, 0));
    expected.push(w16(MDIO_WDATA, 0x1000));
    expected.extend(mdio(RAC_REG_REV2, 0, 0, MDIO_WFLAG));
    // rtw89_pci_autok_x: AUTOK_N to 4 in RAC_REG_FLD_0, page 0.
    expected.extend(mdio(RAC_REG_FLD_0, 0, 0, MDIO_RFLAG));
    expected.push(r16(MDIO_RDATA, 0));
    expected.push(w16(MDIO_WDATA, 0x000c));
    expected.extend(mdio(RAC_REG_FLD_0, 0, 0, MDIO_WFLAG));
    // rtw89_pci_auto_refclk_cal(rtwdev, false): gen 1, L1 off meanwhile,
    // CALIB_EN cleared in RAC_CTRL_PPR_V1 (page 1), L1 back.
    expected.extend([
        cr(PCIE_PHY_RATE, 0x11),
        cr(PCIE_L1_CTRL, 0x08),
        cw(PCIE_L1_CTRL, 0),
    ]);
    expected.extend(mdio(RAC_CTRL_PPR_V1, 1, 0, MDIO_RFLAG));
    expected.push(r16(MDIO_RDATA, CALIB_EN.into()));
    expected.push(w16(MDIO_WDATA, 0));
    expected.extend(mdio(RAC_CTRL_PPR_V1, 1, 1, MDIO_WFLAG));
    expected.push(cw(PCIE_L1_CTRL, 0x08));
    expected.extend([
        // rtw89_pci_power_wake_ax(rtwdev, true)
        r32(HCI_OPT_CTRL, 0),
        w32(HCI_OPT_CTRL, 0x20),
        // rtw89_pci_set_sic
        r32(PCIE_EXP_CTRL, 0),
        w32(PCIE_EXP_CTRL, 0),
        // rtw89_pci_set_lbc: a 2 ms timer, FLAG and EN, written twice
        r32(LBC_WATCHDOG, 0),
        w32(LBC_WATCHDOG, 0x83),
        r32(LBC_WATCHDOG, 0x83),
        w32(LBC_WATCHDOG, 0x83),
        // rtw89_pci_set_dbg
        r32(PCIE_DBG_CTRL, 0),
        w32(PCIE_DBG_CTRL, 0x3),
        r32(PCIE_EXP_CTRL, 0),
        w32(PCIE_EXP_CTRL, 0x1),
        // rtw89_pci_set_keep_reg
        r32(PCIE_INIT_CFG1, 0),
        w32(PCIE_INIT_CFG1, 0x00c0_0000),
        // STOP_WPDMA
        r32(PCIE_DMA_STOP1, 0),
        w32(PCIE_DMA_STOP1, 0x0008_0000),
        // rtw89_pci_ctrl_dma_all(rtwdev, false)
        r32(PCIE_DMA_STOP1, 0x0008_0000),
        w32(PCIE_DMA_STOP1, 0x0018_0000),
        r32(PCIE_INIT_CFG1, 0x00c0_0000),
        w32(PCIE_INIT_CFG1, 0x00c0_0000),
        // rtw89_pci_poll_dma_all_idle: TX, then RX
        r32(PCIE_DMA_BUSY1, 0),
        r32(PCIE_DMA_BUSY1, 0),
        // rtw89_pci_clr_idx_all_ax
        r32(TXBD_RWPTR_CLR1, 0),
        w32(TXBD_RWPTR_CLR1, 0x070f),
        r32(RXBD_RWPTR_CLR, 0),
        w32(RXBD_RWPTR_CLR, 0x3),
        // rtw89_pci_mode_op
        r32(PCIE_INIT_CFG1, 0x00c0_0000),
        w32(PCIE_INIT_CFG1, 0x00c0_0000),
        r32(PCIE_INIT_CFG1, 0x00c0_0000),
        w32(PCIE_INIT_CFG1, 0x00c0_0700),
        r32(PCIE_INIT_CFG1, 0x00c0_0700),
        w32(PCIE_INIT_CFG1, 0x00c0_c700),
        r32(PCIE_INIT_CFG1, 0x00c0_c700),
        w32(PCIE_INIT_CFG1, 0x00c0_d700),
        r32(PCIE_EXP_CTRL, 0x1),
        w32(PCIE_EXP_CTRL, 0x0007_0001),
        r32(PCIE_INIT_CFG2, 0),
        w32(PCIE_INIT_CFG2, 0x0100_0000),
        r32(PCIE_INIT_CFG2, 0x0100_0000),
        w32(PCIE_INIT_CFG2, 0x0101_0000),
        r32(TX_ADDRESS_INFO_MODE_SETTING, 0),
        w32(TX_ADDRESS_INFO_MODE_SETTING, 0x1),
        r32(PKTIN_SETTING, 0),
        w32(PKTIN_SETTING, 0),
    ]);
    // rtw89_pci_ops_reset: rtw89_pci_reset_trx_rings
    expected.extend(ring_writes());
    expected.extend([
        // rtw89_pci_rst_bdram_ax
        r32(PCIE_INIT_CFG1, 0x00c0_d700),
        w32(PCIE_INIT_CFG1, 0x00c0_d708),
        r32(PCIE_INIT_CFG1, 0x00c0_d700),
        // rtw89_pci_ctrl_txdma_ch_ax(rtwdev, false)
        r32(PCIE_DMA_STOP1, 0x0018_0000),
        w32(PCIE_DMA_STOP1, 0x001f_0f00),
        // rtw89_pci_ctrl_txdma_fw_ch_ax(rtwdev, true)
        r32(PCIE_DMA_STOP1, 0x001f_0f00),
        w32(PCIE_DMA_STOP1, 0x001b_0f00),
        // rtw89_pci_ctrl_dma_all(rtwdev, true)
        r32(PCIE_DMA_STOP1, 0x001b_0f00),
        w32(PCIE_DMA_STOP1, 0x000b_0f00),
        r32(PCIE_INIT_CFG1, 0x00c0_d700),
        w32(PCIE_INIT_CFG1, 0x00c0_ff00),
    ]);
    expected
}

#[test]
fn pre_init_follows_rtw89_access_for_access() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0x11, 0x08, true);
    assert_eq!(pre_init(&model, &mut rings), Ok(()));
    assert_eq!(model.log(), cold_pre_init());
    assert_eq!(model.0.borrow().waited_us, 0);
    // The PHY's calibration was turned off, ASPM L1 left as it was, and
    // only CH12 of the TX channels runs.
    let state = model.0.borrow();
    assert_eq!(state.mdio[1][0x10], 0);
    assert_eq!(state.config[usize::from(PCIE_L1_CTRL)], 0x08);
    assert_eq!(
        state.get(PCIE_DMA_STOP1, 4) & TX_STOP1_MASK_V1,
        TX_STOP1_MASK_V1 & !STOP_CH12
    );
    assert_eq!(
        state.get(PCIE_DMA_STOP1, 4) & (STOP_PCIEIO | STOP_WPDMA),
        STOP_WPDMA
    );
    assert_eq!(
        state.get(PCIE_INIT_CFG1, 4) & (TXHCI_EN | RXHCI_EN),
        TXHCI_EN | RXHCI_EN
    );
    drop(state);
    release(&mut rings);
}

#[test]
fn a_pre_init_without_l1_or_calibration_leaves_both_alone() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0x12, 0x37, false);
    assert_eq!(pre_init(&model, &mut rings), Ok(()));
    let log = model.log();
    // Gen 2 pages; nothing written to configuration space or the PPR.
    assert!(
        !log.iter()
            .any(|access| matches!(access, Access::ConfigWrite { .. }))
    );
    let reads = mdio(RAC_CTRL_PPR_V1, MDIO_PG1_G2, MDIO_PG0_G1, MDIO_RFLAG);
    let at = log
        .windows(reads.len())
        .position(|window| window == reads)
        .unwrap();
    assert_eq!(log[at + reads.len()], r16(MDIO_RDATA, 0));
    assert_eq!(log[at + reads.len() + 1], r32(HCI_OPT_CTRL, 0));
    release(&mut rings);
}

#[test]
fn every_ring_is_programmed_where_rtw89_lays_it_out_below_4_gib() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0x11, 0x00, false);
    pre_init(&model, &mut rings).unwrap();
    let log = model.log();
    let writes = ring_writes();
    assert!(log.windows(writes.len()).any(|window| window == writes));

    let mut k = 0;
    for txch in TxChannel::ALL {
        let Some(ring) = rings.tx_ring(txch) else {
            assert!(!txch.present());
            assert_eq!(rings.avail_txbd(txch), Err(ring::Error::NoRing(txch)));
            continue;
        };
        assert!(txch.present());
        assert_eq!(ring.dma, TX_POOL_DMA + 2048 * k);
        assert_eq!((ring.len, ring.desc_size, ring.wp, ring.rp), (256, 8, 0, 0));
        assert_eq!(ring.addr, DMA_ADDR_SET_TX[txch as usize]);
        assert!(ring.dma + 2048 <= 1 << 32);
        for index in 0..256 {
            assert_eq!(rings.tx_bd(txch, index), Ok(TxBd::default()));
        }
        k += 1;
    }
    assert_eq!(k, 7);
    for rxch in RxChannel::ALL {
        let ring = rings.rx_ring(rxch);
        assert_eq!(ring.dma, RX_POOL_DMA + 2048 * rxch as u64);
        assert_eq!((ring.len, ring.desc_size, ring.wp, ring.rp), (256, 8, 0, 0));
        assert_eq!(ring.addr, DMA_ADDR_SET_RX[rxch as usize]);
        assert_eq!(rings.rx_target_tag(rxch), 0);
        for index in 0..256 {
            let bd = rings.rx_bd(rxch, index).unwrap();
            let buffer = RX_BUF_DMA + 0x3000 * (rxch as u64 * 256 + index as u64);
            assert_eq!(bd, RxBd::new(buffer, RX_BUF_SIZE as u16));
            assert_eq!((bd.buf_size, bd.opt), (11498, 0));
            assert!(u64::from(bd.dma) + RX_BUF_SIZE as u64 <= 1 << 32);
        }
    }
    // Two pools and 512 buffers, all still mapped.
    assert_eq!(domain.live(), 514);
    release(&mut rings);
    assert_eq!(domain.live(), 0);
}

#[test]
fn a_mapping_that_reaches_above_4_gib_is_refused() {
    for (index, address, bytes) in [
        // The TX BD pool above 4 GiB.
        (0, 0x1_0000_0000, 0x4000),
        // An RX buffer whose last page crosses 4 GiB.
        (5, 0xffff_e000, 0x3000),
    ] {
        let domain = Domain::new(Placement::Moved { index, address });
        assert_eq!(
            Rings::new(&Source, domain.clone()).err(),
            Some(ring::Error::Dma(DmaError::AddressLimit)),
            "{address:#x}"
        );
        // Nothing the device was never given stays mapped.
        assert_eq!(domain.live(), 0, "{address:#x}");
        assert!(below_4gib(address, bytes).is_err());
    }
    // The RX BD pool's one page ending at 4 GiB is accepted.
    let domain = Domain::new(Placement::Moved {
        index: 1,
        address: 0xffff_f000,
    });
    let mut rings = new_rings(&domain);
    assert_eq!(rings.rx_ring(RxChannel::Rpq).dma, 0xffff_f800);
    release(&mut rings);

    assert_eq!(below_4gib(0xffff_f000, 0x1000), Ok(0xffff_f000));
    assert_eq!(
        below_4gib(0xffff_f000, 0x1001),
        Err(ring::Error::Above4GiB {
            address: 0xffff_f000,
            bytes: 0x1001
        })
    );
    assert!(below_4gib(0, 0).is_err());
    assert!(below_4gib(u64::MAX, 1).is_err());
}

#[test]
fn bds_encode_and_decode_as_pci_h_lays_them_out() {
    // rtw89_pci_fwcmd_submit's BD: LS, the upper address bits in the
    // option's DMA_HI, the length, the low 32 bits.
    let bd = TxBd::last_segment(0x9_8765_4000, 0x0123);
    assert_eq!(
        bd,
        TxBd {
            length: 0x0123,
            opt: 0x4240,
            dma: 0x8765_4000,
        }
    );
    assert_eq!(
        bd.encode(),
        [0x23, 0x01, 0x40, 0x42, 0x00, 0x40, 0x65, 0x87]
    );
    assert_eq!(TxBd::decode(&bd.encode()), bd);
    assert_eq!(TxBd::last_segment(0xffff_f000, 2044).opt, TXBD_OPT_LS);
    // Only DMA_HI's eight bits of the upper half are kept.
    assert_eq!(TxBd::last_segment(0x1ff_0000_0000, 1).opt, 0x7fc0);

    // rtw89_pci_init_rx_bd's BD.
    let bd = RxBd::new(0x8000_3000, RX_BUF_SIZE as u16);
    assert_eq!(
        bd.encode(),
        [0xea, 0x2c, 0x00, 0x00, 0x00, 0x30, 0x00, 0x80]
    );
    assert_eq!(RxBd::decode(&bd.encode()), bd);
    assert_eq!(RxBd::new(0xf_0000_1000, 8).opt, 0x03c0);

    // rtw89_pci_rxbd_info_update's fields.
    assert_eq!(
        RxBdInfo::decode(u32::MAX),
        RxBdInfo {
            fs: true,
            ls: true,
            len: 0x3fff,
            tag: 0x1fff,
        }
    );
    assert_eq!(RxBdInfo::decode(0), RxBdInfo::default());
    let info = RxBdInfo {
        fs: true,
        ls: false,
        len: 2000,
        tag: 7,
    };
    assert_eq!(info.encode(), RXBD_FS | 2000 | 7 << 16);
    assert_eq!(RxBdInfo::decode(info.encode()), info);
    // Bits outside the fields are not part of the info.
    assert_eq!(RxBdInfo::decode(0xe000_0000 | info.encode()), info);
}

#[test]
fn the_rx_tag_check_accepts_the_expected_tag_and_refuses_a_stale_one() {
    // A target of 0 expects 1.
    assert!(validate_rx_tag(true, 7, 7));
    assert!(!validate_rx_tag(true, 7, 6));
    assert!(validate_rx_tag(true, 0, 1));
    assert!(!validate_rx_tag(true, 0, 0));
    // rtw8852b_pci_info leaves the check off.
    const { assert!(!CHECK_RX_TAG) };
    assert!(validate_rx_tag(false, 7, 6));

    let info = |tag| RxBdInfo {
        fs: true,
        ls: true,
        len: 64,
        tag,
    };
    // The expected tag passes at once, and the next is expected.
    let mut target = 7;
    let mut reads = 0;
    let checked = sync_and_validate(&mut target, true, || {
        reads += 1;
        Ok::<_, ()>(info(7))
    });
    assert_eq!(checked, Ok(Ok(info(7))));
    assert_eq!((reads, target), (1, 8));

    // A stale one is read once and again 1000 times, refused, and the tag
    // after it is expected next.
    let mut reads = 0;
    let checked = sync_and_validate(&mut target, true, || {
        reads += 1;
        Ok::<_, ()>(info(6))
    });
    assert_eq!(
        checked,
        Ok(Err(StaleTag {
            expected: 8,
            observed: 6
        }))
    );
    assert_eq!((reads, target), (1001, 7));

    // One that turns current on a retry passes.
    let mut reads = 0;
    let checked = sync_and_validate(&mut target, true, || {
        reads += 1;
        Ok::<_, ()>(info(if reads < 5 { 6 } else { 7 }))
    });
    assert_eq!(checked, Ok(Ok(info(7))));
    assert_eq!((reads, target), (5, 8));

    // The tag wraps in 13 bits.
    let mut target = RX_TAG_MAX;
    sync_and_validate(&mut target, true, || Ok::<_, ()>(info(RX_TAG_MAX)))
        .unwrap()
        .unwrap();
    assert_eq!(target, 0);
    // A read that fails ends the check with its error.
    assert_eq!(
        sync_and_validate(&mut target, true, || Err::<RxBdInfo, _>("dma")),
        Err("dma")
    );
}

#[test]
fn the_index_arithmetic_is_rtw89s() {
    let mut ring = DmaRing {
        dma: 0,
        desc_size: 8,
        addr: DMA_ADDR_SET_TX[TxChannel::Ch12 as usize],
        len: 256,
        wp: 0,
        rp: 0,
    };
    // One BD is kept back to tell full from empty.
    assert_eq!(avail_txbd(&ring), 255);
    ring.wp = 255;
    assert_eq!(avail_txbd(&ring), 0);
    tx_bd_ring_update(&mut ring, 1);
    assert_eq!(ring.wp, 0);
    ring.rp = 1;
    assert_eq!(avail_txbd(&ring), 0);
    // The hardware's index is TXBD_HW_IDX_MASK; the count wraps.
    ring.rp = 250;
    ring.wp = 4;
    assert_eq!(dma_recalc(&mut ring, 4 << 16 | 4, true), 10);
    assert_eq!(ring.rp, 4);
    ring.wp = 250;
    assert_eq!(dma_recalc(&mut ring, 3 << 16 | 0xfff, false), 9);
    assert_eq!(ring.rp, 3);
    rxbd_increase(&mut ring, 6);
    assert_eq!(ring.wp, 0);
}

#[test]
fn the_command_queue_keeps_the_newest_multitag_read_buffers() {
    let mut queue = FwCmdQueue::new().unwrap();
    for buffer in 0..12u32 {
        queue.push(buffer).unwrap();
    }
    let freed = RefCell::new(Vec::new());
    let free = |buffer: &mut u32| {
        freed.borrow_mut().push(*buffer);
        Ok::<_, ring::Error>(())
    };
    // Five read: all kept.
    queue.release(5, false, &free).unwrap();
    assert_eq!((queue.queued(), queue.kept()), (7, 5));
    // Five more: the oldest two go.
    queue.release(5, false, &free).unwrap();
    assert_eq!((queue.queued(), queue.kept()), (2, 8));
    assert_eq!(*freed.borrow(), [0, 1]);
    // More read than queued: those move, nothing goes.
    assert_eq!(
        queue.release(3, false, &free),
        Err(ring::Error::CompletionBeyondPending)
    );
    assert_eq!((queue.queued(), queue.kept()), (0, 10));
    assert_eq!(*freed.borrow(), [0, 1]);
    // A release that fails keeps the buffer.
    assert_eq!(
        queue.release(0, true, |_| Err(ring::Error::NoTxBd)),
        Err(ring::Error::NoTxBd)
    );
    assert_eq!(queue.kept(), 10);
    // Releasing all empties it.
    queue.release(0, true, &free).unwrap();
    assert_eq!((queue.queued(), queue.kept()), (0, 0));
    assert_eq!(freed.into_inner(), (0..12).collect::<Vec<_>>());
}

#[test]
fn ch12_takes_command_buffers_kicks_them_off_and_releases_them_as_read() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0x11, 0x00, false);
    pre_init(&model, &mut rings).unwrap();
    model.take_log();

    let mut addresses = Vec::new();
    for index in 0..10u16 {
        let buffer = Buffer::new(&Source, domain.clone(), 64, Direction::ToDevice).unwrap();
        buffer.write(0, &[index as u8; 64]).unwrap();
        addresses.push(buffer.address());
        rings.fwcmd_submit(buffer, 40 + index).unwrap();
        assert_eq!(
            rings.tx_bd(TxChannel::Ch12, index.into()),
            Ok(TxBd::last_segment(
                addresses[usize::from(index)].into(),
                40 + index
            ))
        );
    }
    assert!(addresses.iter().all(|&address| address < 0x8100_0000));
    assert_eq!(rings.tx_ring(TxChannel::Ch12).unwrap().wp, 10);
    assert_eq!(rings.avail_txbd(TxChannel::Ch12), Ok(245));
    assert_eq!(rings.fwcmd(), (10, 0));
    // Nothing reaches the chip until the host index is written.
    assert!(model.log().is_empty());
    let mut io = &model;
    rings.tx_kick_off(&mut io, TxChannel::Ch12).unwrap();
    assert_eq!(model.take_log(), [w16(CH12_TXBD_IDX, 10)]);
    // A length past the buffer's pages is refused.
    let buffer = Buffer::new(&Source, domain.clone(), 64, Direction::ToDevice).unwrap();
    assert_eq!(
        rings.fwcmd_submit(buffer, 4097),
        Err(ring::Error::Length {
            length: 4097,
            bytes: 4096
        })
    );
    assert_eq!(rings.fwcmd(), (10, 0));

    // The chip read three: they stay mapped behind MULTITAG.
    let unmaps = domain.unmaps();
    model.set(CH12_TXBD_IDX + 2, 2, 3);
    assert_eq!(rings.reclaim_fwcmd(&mut io), Ok(3));
    assert_eq!(model.take_log(), [r32(CH12_TXBD_IDX, 3 << 16 | 10)]);
    assert_eq!(rings.fwcmd(), (7, 3));
    assert_eq!(domain.unmaps(), unmaps);
    // All ten read: the two oldest are unmapped.
    model.set(CH12_TXBD_IDX + 2, 2, 10);
    assert_eq!(rings.reclaim_fwcmd(&mut io), Ok(7));
    assert_eq!(rings.fwcmd(), (0, 8));
    assert_eq!(domain.unmaps(), unmaps + 2);
    assert_eq!(rings.reclaim_fwcmd(&mut io), Ok(0));
    // An index outside the ring is refused and leaves the ring as it was.
    model.set(CH12_TXBD_IDX + 2, 2, 0x100);
    assert_eq!(rings.reclaim_fwcmd(&mut io), Err(ring::Error::Index(0x100)));
    assert_eq!(rings.tx_ring(TxChannel::Ch12).unwrap().rp, 10);
    model.set(CH12_TXBD_IDX + 2, 2, 10);
    assert_eq!(rings.reclaim_fwcmd(&mut io), Ok(0));

    // A full ring refuses another buffer and unmaps it.
    let ring = *rings.tx_ring(TxChannel::Ch12).unwrap();
    assert_eq!((ring.wp, ring.rp), (10, 10));
    for _ in 0..255 {
        let buffer = Buffer::new(&Source, domain.clone(), 32, Direction::ToDevice).unwrap();
        rings.fwcmd_submit(buffer, 32).unwrap();
    }
    assert_eq!(rings.avail_txbd(TxChannel::Ch12), Ok(0));
    let live = domain.live();
    let buffer = Buffer::new(&Source, domain.clone(), 32, Direction::ToDevice).unwrap();
    assert_eq!(rings.fwcmd_submit(buffer, 32), Err(ring::Error::NoTxBd));
    assert_eq!(domain.live(), live);
    assert_eq!(rings.tx_ring(TxChannel::Ch12).unwrap().wp, 9);
    release(&mut rings);
    assert_eq!(domain.live(), 0);
}

#[test]
fn rxq_hands_over_what_the_chip_filled_and_writes_the_host_index() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0x11, 0x00, false);
    pre_init(&model, &mut rings).unwrap();
    model.take_log();
    let mut io = &model;

    // Nothing filled: one index read.
    let mut received = Vec::new();
    let sink = |packet: Received<'_>| received.push((packet.info, packet.data.to_vec()));
    assert_eq!(rings.deliver(&mut io, RxChannel::Rxq, 64, sink), Ok(0));
    assert!(received.is_empty());
    assert_eq!(model.take_log(), [r32(RXQ_RXBD_IDX, 0)]);

    // The chip fills five buffers and moves its index.
    let mut filled = Vec::new();
    for index in 0..5u16 {
        let payload: Vec<u8> = (0..24 + index)
            .map(|byte| (byte as u8) ^ (index as u8))
            .collect();
        let info = RxBdInfo {
            fs: true,
            ls: true,
            len: 4 + payload.len() as u16,
            tag: index + 1,
        };
        let mut bytes = info.encode().to_le_bytes().to_vec();
        bytes.extend(&payload);
        let bd = rings.rx_bd(RxChannel::Rxq, index.into()).unwrap();
        domain.device_write(bd.dma.into(), &bytes);
        filled.push((info, bytes));
    }
    model.set(RXQ_RXBD_IDX + 2, 2, 5);
    let mut received = Vec::new();
    let sink = |packet: Received<'_>| received.push((packet.info, packet.data.to_vec()));
    // A budget of two takes two.
    assert_eq!(rings.deliver(&mut io, RxChannel::Rxq, 2, sink), Ok(2));
    assert_eq!(received, filled[..2]);
    assert_eq!(
        model.take_log(),
        [r32(RXQ_RXBD_IDX, 5 << 16), w16(RXQ_RXBD_IDX, 2)]
    );
    let ring = rings.rx_ring(RxChannel::Rxq);
    assert_eq!((ring.wp, ring.rp), (2, 5));
    assert_eq!(rings.rx_target_tag(RxChannel::Rxq), 3);
    // The rest follow, counted from the host index.
    let mut received = Vec::new();
    let sink = |packet: Received<'_>| received.push((packet.info, packet.data.to_vec()));
    assert_eq!(rings.deliver(&mut io, RxChannel::Rxq, 64, sink), Ok(3));
    assert_eq!(received, filled[2..]);
    assert_eq!(model.take_log()[1], w16(RXQ_RXBD_IDX, 5));
    // RPQ is its own ring, and an index outside a ring is refused.
    model.set(RPQ_RXBD_IDX + 2, 2, 0x100);
    assert_eq!(
        rings.deliver(&mut io, RxChannel::Rpq, 64, |_| panic!("nothing filled")),
        Err(ring::Error::Index(0x100))
    );
    release(&mut rings);
}

#[test]
fn an_unsupported_link_rate_stops_the_pre_init_after_reading_it() {
    for phy_rate in [0x13, 0x10, 0xff] {
        let domain = Domain::new(Placement::Oracle);
        let mut rings = new_rings(&domain);
        let model = Model::zeroed(phy_rate, 0x08, true);
        assert_eq!(pre_init(&model, &mut rings), Err(Error::PhyRate(phy_rate)));
        assert_eq!(model.log().last(), Some(&cr(PCIE_PHY_RATE, phy_rate)));
        release(&mut rings);
    }
}

#[test]
fn configuration_space_that_refuses_is_reached_through_dbi() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let faults = Faults {
        config_fails: true,
        ..Faults::default()
    };
    let model = Model::new(Fill::Zeros, 0x11, 0x08, true, faults);
    assert_eq!(pre_init(&model, &mut rings), Ok(()));
    let log = model.log();
    let start = log
        .iter()
        .position(|access| {
            *access
                == Access::ConfigRead {
                    offset: PCIE_PHY_RATE,
                    value: None,
                }
        })
        .unwrap();
    assert_eq!(
        log[start + 1..start + 5],
        [
            w16(DBI_FLAG, 0x080),
            w8(DBI_FLAG + 2, 0x2),
            r8(DBI_FLAG + 2, 0),
            r8(DBI_RDATA + 2, 0x11),
        ]
    );
    // L1 is cleared and set back through DBI's byte lane 1 of 0x718.
    let clear = Access::ConfigWrite {
        offset: PCIE_L1_CTRL,
        value: 0,
        accepted: false,
    };
    let at = log.iter().position(|access| *access == clear).unwrap();
    assert_eq!(
        log[at + 1..at + 5],
        [
            w8(DBI_WDATA + 1, 0),
            w16(DBI_FLAG, 0x2718),
            w8(DBI_FLAG + 2, 0x1),
            r8(DBI_FLAG + 2, 0),
        ]
    );
    assert_eq!(model.0.borrow().config[usize::from(PCIE_L1_CTRL)], 0x08);
    release(&mut rings);

    // A DBI flag that never clears times out after 20 steps of 10 us.
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let faults = Faults {
        config_fails: true,
        dbi_stuck: true,
        ..Faults::default()
    };
    let model = Model::new(Fill::Zeros, 0x11, 0x08, true, faults);
    assert_eq!(
        pre_init(&model, &mut rings),
        Err(Error::Io(io::Error::Timeout {
            register: DBI_FLAG + 2,
            mask: 0xff
        }))
    );
    assert_eq!(model.count(r8(DBI_FLAG + 2, 2)), 21);
    assert_eq!(model.count(Access::Delay(10)), 20);
    release(&mut rings);
}

#[test]
fn mdio_that_never_completes_fails_where_rtw89_fails() {
    let faults = |stuck| Faults {
        mdio_stuck: Some(stuck),
        ..Faults::default()
    };
    let timeout = Err(Error::Io(io::Error::Timeout {
        register: MDIO_CFG,
        mask: MDIO_RFLAG.into(),
    }));
    for (stuck, l1_ctrl, expected) in [
        // rtw89 ignores rtw89_pci_dphy_delay's timeout, not autok_x's.
        (0x20, 0x08, timeout),
        (RAC_REG_REV2, 0x08, Ok(())),
        // The PPR read times out; setting L1 back decides what returns.
        (RAC_CTRL_PPR_V1 & 0x1f, 0x08, Ok(())),
        (RAC_CTRL_PPR_V1 & 0x1f, 0x00, timeout),
    ] {
        let domain = Domain::new(Placement::Oracle);
        let mut rings = new_rings(&domain);
        let model = Model::new(Fill::Zeros, 0x11, l1_ctrl, true, faults(stuck));
        assert_eq!(
            pre_init(&model, &mut rings),
            expected,
            "{stuck:#x} {l1_ctrl:#x}"
        );
        let polls = model.count(Access::Delay(10));
        match stuck {
            0x20 => assert_eq!(polls, 400),
            _ => assert_eq!(polls, 200),
        }
        if stuck == RAC_CTRL_PPR_V1 & 0x1f && l1_ctrl != 0 {
            assert_eq!(
                model
                    .log()
                    .iter()
                    .filter(|access| matches!(access, Access::ConfigWrite { .. }))
                    .count(),
                2
            );
        }
        release(&mut rings);
    }
}

#[test]
fn dma_that_stays_busy_and_a_bd_ram_reset_that_never_ends_time_out() {
    for (faults, register, mask, reads, step) in [
        (
            Faults {
                tx_busy: true,
                ..Faults::default()
            },
            PCIE_DMA_BUSY1,
            DMA_BUSY1_CHECK_V1,
            11,
            10,
        ),
        (
            Faults {
                rx_busy: true,
                ..Faults::default()
            },
            PCIE_DMA_BUSY1,
            RXQ_BUSY | RPQ_BUSY,
            12,
            10,
        ),
        (
            Faults {
                bdram_stuck: true,
                ..Faults::default()
            },
            PCIE_INIT_CFG1,
            RST_BDRAM,
            0,
            1,
        ),
    ] {
        let domain = Domain::new(Placement::Oracle);
        let mut rings = new_rings(&domain);
        let model = Model::new(Fill::Zeros, 0x11, 0x00, false, faults);
        assert_eq!(
            pre_init(&model, &mut rings),
            Err(Error::Io(io::Error::Timeout { register, mask })),
            "{faults:?}"
        );
        let log = model.log();
        if reads != 0 {
            let busy = log
                .iter()
                .filter(
                    |access| matches!(access, Access::Read { register: at, .. } if *at == register),
                )
                .count();
            assert_eq!(busy, reads, "{faults:?}");
        } else {
            // 101 reads a step apart, the last after RST_BDRAM was set.
            assert_eq!(model.count(Access::Delay(1)), 100);
            assert!(
                matches!(log.last(), Some(Access::Read { register: PCIE_INIT_CFG1, value, .. }) if value & RST_BDRAM != 0)
            );
        }
        assert_eq!(
            model.count(Access::Delay(step)),
            if reads == 0 { 100 } else { 10 }
        );
        release(&mut rings);
    }
}

/// One pre-init case of the C oracle, in its order.
#[derive(Clone, Copy, Debug)]
struct Case {
    fill: Fill,
    phy_rate: u8,
    l1_ctrl: u8,
    calib: bool,
    faults: Faults,
}

fn pre_init_cases() -> Vec<Case> {
    let case = |fill, phy_rate, l1_ctrl, calib, faults| Case {
        fill,
        phy_rate,
        l1_ctrl,
        calib,
        faults,
    };
    let none = Faults::default();
    let config = Faults {
        config_fails: true,
        ..none
    };
    let dbi = Faults {
        dbi_stuck: true,
        ..config
    };
    let mdio = |stuck| Faults {
        mdio_stuck: Some(stuck),
        ..none
    };
    let tx = Faults {
        tx_busy: true,
        ..none
    };
    let rx = Faults {
        rx_busy: true,
        ..none
    };
    let bdram = Faults {
        bdram_stuck: true,
        ..none
    };
    use Fill::*;
    vec![
        case(Pattern, 0x11, 0x0f, true, none),
        case(Ones, 0x12, 0x08, true, none),
        case(Zeros, 0x11, 0x00, false, none),
        case(Pattern, 0x42, 0x37, true, none),
        case(Pattern, 0x13, 0x08, true, none),
        case(Pattern, 0x10, 0x08, true, none),
        case(Pattern, 0x11, 0x08, true, config),
        case(Pattern, 0x12, 0x00, false, config),
        case(Pattern, 0x11, 0x08, true, dbi),
        case(Pattern, 0x11, 0x08, true, mdio(0x20)),
        case(Pattern, 0x11, 0x08, true, mdio(0x10)),
        case(Pattern, 0x11, 0x00, true, mdio(0x10)),
        case(Pattern, 0x11, 0x08, true, mdio(0x1b)),
        case(Pattern, 0x11, 0x08, true, tx),
        case(Pattern, 0x11, 0x08, true, rx),
        case(Pattern, 0x11, 0x08, true, bdram),
        case(Ones, 0x11, 0x08, true, config),
    ]
}

/// The errno rtw89 returns for `result`.
fn errno(result: Result<(), Error>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(Error::Io(io::Error::Timeout { .. })) => -110,
        Err(Error::PhyRate(_)) => -95,
        Err(error) => panic!("the model refuses nothing: {error:?}"),
    }
}

fn push_ring(trace: &mut Vec<u8>, channel: u32, ring: &DmaRing) {
    push(trace, 30, channel, ring.len);
    push(trace, 31, ring.desc_size.into(), ring.dma as u32);
    push(trace, 32, ring.wp, ring.rp);
    push(trace, 33, ring.addr.num, ring.addr.idx);
    push(trace, 34, ring.addr.bdram, ring.addr.desa_l);
    push(trace, 35, ring.addr.desa_h, (ring.dma >> 32) as u32);
}

/// The harness's records of every ring and the command queues.
fn push_rings(trace: &mut Vec<u8>, rings: &Rings) {
    for txch in TxChannel::ALL {
        if let Some(ring) = rings.tx_ring(txch) {
            push_ring(trace, txch as u32, ring);
        }
    }
    for rxch in RxChannel::ALL {
        push_ring(trace, 0x100 | rxch as u32, rings.rx_ring(rxch));
        // No delivery in progress: diliver_desc.ready and diliver_skb clear.
        push(trace, 36, rings.rx_target_tag(rxch).into(), 0);
    }
    let (queued, kept) = rings.fwcmd();
    push(trace, 37, queued as u32, kept as u32);
}

/// The next length-prefixed segment of the oracle's trace.
pub(crate) fn segment<'a>(trace: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length = u32::from_le_bytes(trace[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let segment = &trace[*offset..*offset + length];
    *offset += length;
    segment
}

/// `rtw8852b_chip_info.h2c_desc_size`: the TXWD body
/// `rtw89_pci_fwcmd_submit` pushes in front of each command.
const H2C_DESC_SIZE: u32 = 24;

#[test]
#[ignore = "oracle: STELA_RTW89_PCI_ORACLE"]
fn pre_init_register_trace_matches_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_PCI_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;

    // rtw89_pci_alloc_trx_rings, then hci.ops->mac_pre_init.
    let cases = pre_init_cases();
    assert_eq!(cases.len(), 17);
    for case in cases {
        let domain = Domain::new(Placement::Oracle);
        let mut rings = new_rings(&domain);
        let model = Model::new(
            case.fill,
            case.phy_rate,
            case.l1_ctrl,
            case.calib,
            case.faults,
        );
        let result = pre_init(&model, &mut rings);
        let mut expected = encode(&model.log());
        push(&mut expected, 11, 0, errno(result) as u32);
        if result.is_ok() {
            push_rings(&mut expected, &rings);
        }
        assert_eq!(segment(&trace, &mut offset), expected, "{case:?}");
        release(&mut rings);
    }

    // rtw89_pci_alloc_trx_rings alone, with every RX BD.
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let mut expected = Vec::new();
    push_rings(&mut expected, &rings);
    for rxch in RxChannel::ALL {
        for index in 0..256u32 {
            let bd = rings.rx_bd(rxch, index as usize).unwrap();
            let at = (rxch as u32) << 16 | index;
            push(
                &mut expected,
                40,
                at,
                u32::from(bd.buf_size) | u32::from(bd.opt) << 16,
            );
            push(&mut expected, 41, at, bd.dma);
        }
    }
    assert_eq!(segment(&trace, &mut offset), expected, "allocation");
    release(&mut rings);

    // rtw89_pci_sync_skb_for_device_and_validate_rx_info.
    let mut expected = Vec::new();
    for (dword, target, check) in [
        (RXBD_FS | RXBD_LS | 100 | 5 << 16, 0, false),
        (RXBD_FS | RXBD_LS | 64 | 1 << 16, 0, true),
        (RXBD_FS | 2000 | 7 << 16, 7, true),
        (RXBD_LS | 24 | 6 << 16, 7, true),
        (RXBD_FS | RXBD_LS | 11498 | 0x1fff << 16, 0x1fff, true),
        (RXBD_FS | RXBD_LS | 8, 0, true),
        (u32::MAX, 3, false),
        (0, 0x1234, false),
    ] {
        let mut target = target;
        let mut reads = 0;
        let checked = sync_and_validate(&mut target, check, || {
            reads += 1;
            Ok::<_, ()>(RxBdInfo::decode(dword))
        })
        .unwrap();
        let info = RxBdInfo::decode(dword);
        let ret: i32 = if checked.is_ok() { 0 } else { -11 };
        push(&mut expected, 50, ret as u32, target.into());
        push(
            &mut expected,
            51,
            u32::from(info.fs) | u32::from(info.ls) << 1,
            u32::from(info.len) | u32::from(info.tag) << 16,
        );
        push(&mut expected, 52, reads, 0);
    }
    assert_eq!(segment(&trace, &mut offset), expected, "RX info");

    // rtw89_pci_txbd_recalc and rtw89_pci_rxbd_recalc.
    let model = Model::zeroed(0, 0, false);
    let mut expected = Vec::new();
    for (tx, len, wp, rp, idx) in [
        (true, 256, 5, 0, 3 << 16 | 5),
        (true, 256, 4, 250, 4 << 16 | 4),
        (true, 256, 7, 7, 7 << 16 | 7),
        (true, 256, 9, 2, 0xf123_ffff),
        (false, 256, 10, 0, 12 << 16),
        (false, 256, 250, 0, 3 << 16 | 0xfff),
        (false, 256, 0, 0, 0),
        (false, 256, 17, 9, 0x0fff_0000),
    ] {
        let addr = if tx {
            DMA_ADDR_SET_TX[TxChannel::Ch12 as usize]
        } else {
            DMA_ADDR_SET_RX[RxChannel::Rxq as usize]
        };
        let mut ring = DmaRing {
            dma: 0,
            desc_size: 8,
            addr,
            len,
            wp,
            rp,
        };
        model.set(addr.idx, 4, idx);
        let mut io = &model;
        let cnt = if tx {
            txbd_recalc(&mut io, &mut ring)
        } else {
            rxbd_recalc(&mut io, &mut ring)
        }
        .unwrap();
        expected.extend(encode(&model.take_log()));
        push(&mut expected, 53, cnt, ring.rp);
    }
    assert_eq!(segment(&trace, &mut offset), expected, "recalc");

    // rtw89_pci_get_avail_txbd_num, rtw89_pci_tx_bd_ring_update and
    // rtw89_pci_rxbd_increase.
    let mut expected = Vec::new();
    for (len, wp, rp, n) in [
        (256, 0, 0, 1),
        (256, 255, 0, 1),
        (256, 254, 0, 1),
        (256, 10, 11, 1),
        (256, 3, 200, 5),
        (256, 200, 3, 100),
        (256, 0, 1, 0),
    ] {
        let mut ring = DmaRing {
            dma: 0,
            desc_size: 8,
            addr: DMA_ADDR_SET_TX[TxChannel::Ch12 as usize],
            len,
            wp,
            rp,
        };
        push(&mut expected, 54, avail_txbd(&ring), 0);
        tx_bd_ring_update(&mut ring, n);
        push(&mut expected, 55, ring.wp, avail_txbd(&ring));
        let mut rx = DmaRing { wp, ..ring };
        rxbd_increase(&mut rx, n);
        push(&mut expected, 56, rx.wp, 0);
    }
    assert_eq!(segment(&trace, &mut offset), expected, "TX index");

    // rtw89_pci_fwcmd_submit on CH12.
    let mut expected = Vec::new();
    for (queued, (length, dma, wp)) in [
        (100, 0x1234_5000, 0),
        (2020, 0xffff_f000, 255),
        (0, 0x8000_0000, 17),
        (8, 0x9_8765_4000, 3),
    ]
    .into_iter()
    .enumerate()
    {
        let mut ring = DmaRing {
            dma: 0,
            desc_size: 8,
            addr: DMA_ADDR_SET_TX[TxChannel::Ch12 as usize],
            len: 256,
            wp,
            rp: wp,
        };
        let total = length + H2C_DESC_SIZE;
        let bd = TxBd::last_segment(dma, total as u16);
        tx_bd_ring_update(&mut ring, 1);
        push(&mut expected, 70, 0, ring.wp);
        push(
            &mut expected,
            71,
            u32::from(bd.length) | u32::from(bd.opt) << 16,
            bd.dma,
        );
        push(&mut expected, 72, total, queued as u32 + 1);
    }
    assert_eq!(segment(&trace, &mut offset), expected, "fwcmd submit");

    // rtw89_pci_release_fwcmd.
    let mut expected = Vec::new();
    for (kept, queued, cnt, all) in [
        (0, 3, 3, false),
        (8, 4, 2, false),
        (5, 10, 10, false),
        (3, 4, 6, false),
        (6, 5, 0, true),
        (2, 7, 7, true),
    ] {
        let mut queue = FwCmdQueue::new().unwrap();
        for i in 0..kept {
            queue.push((0x10_0000 + 0x1000 * i, 0x40 + i)).unwrap();
        }
        queue
            .release(kept, false, |_| -> Result<(), ring::Error> {
                panic!("MULTITAG keeps up to eight")
            })
            .unwrap();
        for i in 0..queued {
            queue.push((0x20_0000 + 0x1000 * i, 0x80 + i)).unwrap();
        }
        let result = queue.release(cnt, all, |&mut (dma, length)| {
            push(&mut expected, 60, dma, length);
            Ok::<(), ring::Error>(())
        });
        assert_eq!(result.is_err(), cnt > queued);
        push(
            &mut expected,
            61,
            queue.queued() as u32,
            queue.kept() as u32,
        );
    }
    assert_eq!(segment(&trace, &mut offset), expected, "release fwcmd");
    assert_eq!(offset, trace.len());
}
