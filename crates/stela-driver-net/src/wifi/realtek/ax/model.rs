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
//! being what the SWSI register holds, or, for a register SWSI wrote, what
//! it wrote), the LTE indirect access is always
//! ready and keeps its own registers, and packets queued with
//! [`Chip::queue_rx`] are written into RXQ's next buffers, as the chip's DMA
//! would, before the host next reads RXQ's index.
//!
//! For a station ([`super::hardware`]) it is also the chip a data path
//! runs on: a kick on a data ring (ACH0 to ACH3, B0MGQ, B0HIQ) hands it each
//! BD's WD page, whose TXWD body, info, WP info and address info it reads
//! as the DMA would, and the frame the address info names ([`Sent`]); the
//! ring index clears reset those rings' and RPQ's indices; release reports
//! queued with [`Chip::release`] are written into RPQ's next buffers before
//! the host next reads RPQ's index; and every SWSI write is kept in an RF
//! register file ([`Chip::rf`]), whose RF 0x18 says where the radio stands
//! ([`Chip::tuned`]). [`Ap`] plays an AP over that: it hears what the chip
//! hands the air, releases each frame through RPQ, answers on RXQ as an AP
//! answers a station, and beacons while the radio stands on its channel.
//!
//! It checks nothing the firmware would check (no checksum, no cut) and
//! sends no C2H on RXQ by itself. Delays take no time.
use super::{
    efuse::tests::{Case, Model as Efuse},
    fwdl::{FW_HDR_W7_PART_SIZE, FWDL_WCPU_FW_INIT_RDY},
    h2c::{H2C_DESC_SIZE, HDR_CAT, HDR_CLASS, HDR_FUNC, HEADER_LEN},
    h2creg::C2H_REGS,
    io::{self, CR_BASE, Io, field, prep},
    pci::{
        release::{TX_DONE, TX_RETRY_LIMIT},
        ring::{
            ADDR_HIGH_MASK, DMA_ADDR_SET_TX, RXBD_NUM_MAX, RxBd, RxBdInfo, TXBD_NUM_MAX, TXCH_NUM,
            TXWP_VALID, TxBd,
        },
        tests::{Access, Domain, Model as Bus},
    },
    registers::*,
    rxdesc::{
        RX_TYPE_DATA, RX_TYPE_MGNT, RXD_HW_DEC, RXD_ICV_ERR,
        tests::{Rxd, ppdu_status},
    },
    txwd::{BODY_SIZE, BODY0_FW_DL, BODY0_WD_INFO_EN, BODY2_QSEL, INFO_SIZE},
};
use crate::Mac;
use crate::bus::pci::{ConfigError, ConfigSpace};
use crate::wifi::sae::{self, Derivation, Exchange};
use alloc::{collections::BTreeMap, rc::Rc, sync::Arc, vec, vec::Vec};
use core::cell::RefCell;
use zeroize::Zeroizing;

/// The data rings a station's frames go on: ACH0 to ACH3, B0MGQ and
/// B0HIQ, by `enum rtw89_tx_channel`.
const DATA_RINGS: [usize; 6] = [0, 1, 2, 3, 8, 9];

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
/// SWSI's indirect RF write, as a MAC address.
const SWSI_WRITE: u32 = CR_BASE + SWSI_DATA_V1;
/// SWSI's indirect RF read request, as a MAC address.
const SWSI_READ: u32 = CR_BASE + SWSI_READ_ADDR_V1;

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
    /// The next BD the chip reads of each data ring.
    tx_host: [u32; TXCH_NUM],
    /// Every frame the data rings handed over, oldest first.
    sent: Vec<Sent>,
    /// The next RPQ BD the chip fills, and the release reports waiting for
    /// one.
    rpq_hw: u32,
    rpq_queue: Vec<u32>,
    rpq_tag: u16,
    /// What SWSI wrote of each path's RF registers.
    rf: [BTreeMap<u32, u32>; 2],
    /// The indirect access window from `R_AX_INDIR_ACCESS_ENTRY` on, past
    /// the MAC and BB space the register file holds, by its address.
    indirect: BTreeMap<u32, u32>,
    /// The data rings' DMA stands still.
    stalled: bool,
}

/// One frame a data ring handed the chip, as its DMA read it.
#[derive(Clone, Debug)]
pub(crate) struct Sent {
    /// The ring it went on, `enum rtw89_tx_channel`.
    pub txch: u8,
    /// The TXWD body's dwords, and the WD info's when WD_INFO_EN is set.
    pub body: [u32; 6],
    pub info: Option<[u32; 6]>,
    /// The WD page's sequence, which its release report names.
    pub seq: u16,
    pub frame: Vec<u8>,
}

impl Sent {
    pub(crate) fn qsel(&self) -> u8 {
        field(self.body[2], BODY2_QSEL) as u8
    }
}

/// One H2C the firmware took after the last download: its header's
/// category, class and function, and its payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Command {
    pub cat: u8,
    pub class: u8,
    pub func: u8,
    pub payload: Vec<u8>,
}

fn dwords<const N: usize>(bytes: &[u8]) -> [u32; N] {
    core::array::from_fn(|index| {
        u32::from_le_bytes(bytes[4 * index..4 * index + 4].try_into().unwrap())
    })
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
                tx_host: [0; TXCH_NUM],
                sent: Vec::new(),
                rpq_hw: 0,
                rpq_queue: Vec::new(),
                rpq_tag: 0,
                rf: [BTreeMap::new(), BTreeMap::new()],
                indirect: BTreeMap::new(),
                stalled: false,
            }),
            domain,
        }
    }

    /// The frames the data rings handed over from the `from`th on.
    pub(crate) fn sent_from(&self, from: usize) -> Vec<Sent> {
        let state = self.state.borrow();
        state.sent.get(from..).unwrap_or_default().to_vec()
    }

    /// How many frames the data rings handed over.
    pub(crate) fn sent_count(&self) -> usize {
        self.state.borrow().sent.len()
    }

    /// `sent` released with `status` (`RTW89_TX_DONE` and the like): its
    /// report, written into RPQ's next buffer before the host next reads
    /// RPQ's index.
    pub(crate) fn release(&self, sent: &Sent, status: u8) {
        let dword = u32::from(sent.seq) << 16
            | u32::from(status & 7) << 13
            | u32::from(sent.qsel() & 0x1f) << 8
            | field(sent.body[2], 0x7f00_0000);
        self.state.borrow_mut().rpq_queue.push(dword);
    }

    /// What SWSI last wrote of RF register `address` of `path`.
    pub(crate) fn rf(&self, path: usize, address: u32) -> Option<u32> {
        self.state.borrow().rf[path].get(&address).copied()
    }

    /// The channel the synthesizer stands on: RF 0x18's channel field of
    /// path A, the center of the channel tuned.
    pub(crate) fn tuned(&self) -> Option<u8> {
        self.rf(0, 0x18).map(|value| (value & 0xff) as u8)
    }

    /// Every H2C of the last download's attempt behind its firmware, in the
    /// order the firmware took them.
    pub(crate) fn commands(&self) -> Vec<Command> {
        let state = self.state.borrow();
        let Some(frames) = state.attempts.last() else {
            return Vec::new();
        };
        frames
            .iter()
            .filter(|frame| frame.len() >= H2C_DESC_SIZE + HEADER_LEN)
            .filter(|frame| dwords::<1>(frame)[0] & BODY0_FW_DL == 0)
            .map(|frame| {
                let [hdr0] = dwords::<1>(&frame[H2C_DESC_SIZE..]);
                Command {
                    cat: field(hdr0, HDR_CAT) as u8,
                    class: field(hdr0, HDR_CLASS) as u8,
                    func: field(hdr0, HDR_FUNC) as u8,
                    payload: frame[H2C_DESC_SIZE + HEADER_LEN..].to_vec(),
                }
            })
            .collect()
    }

    /// Whether the data rings' DMA stands still: a kick moves nothing until
    /// it runs again, when it reads every BD the host index has passed.
    pub(crate) fn stall(&self, stalled: bool) {
        let state = &mut *self.state.borrow_mut();
        state.stalled = stalled;
        if !stalled {
            for txch in DATA_RINGS {
                let to = self.bus.get(DMA_ADDR_SET_TX[txch].idx, 2);
                self.kick_data(state, txch, to);
            }
        }
    }

    /// Write the queued release reports into RPQ's buffers from the next BD
    /// on, one to a buffer behind a short RX descriptor, while the host has
    /// given buffers back, and move RPQ's hardware index past them.
    fn deliver_rpq(&self) {
        let state = &mut *self.state.borrow_mut();
        let base = u64::from(self.bus.get(RPQ_RXBD_DESA_L, 4))
            | u64::from(self.bus.get(RPQ_RXBD_DESA_H, 4)) << 32;
        if base == 0 || state.rpq_queue.is_empty() {
            return;
        }
        let host = self.bus.get(RPQ_RXBD_IDX, 2);
        let room = (RXBD_NUM_MAX - 1)
            .saturating_sub((state.rpq_hw + RXBD_NUM_MAX - host) % RXBD_NUM_MAX)
            as usize;
        let ready: Vec<u32> = state
            .rpq_queue
            .drain(..room.min(state.rpq_queue.len()))
            .collect();
        for dword in ready {
            let at = base + u64::from(state.rpq_hw) * RxBd::SIZE as u64;
            let bytes = self.domain.device_read(at, RxBd::SIZE);
            let bd = RxBd::decode(bytes.as_slice().try_into().unwrap());
            let mut packet = vec![0; 16];
            packet[..4].copy_from_slice(&4u32.to_le_bytes());
            packet.extend_from_slice(&dword.to_le_bytes());
            let info = RxBdInfo {
                fs: true,
                ls: true,
                len: (4 + packet.len()) as u16,
                tag: state.rpq_tag,
            };
            let mut buffer = info.encode().to_le_bytes().to_vec();
            buffer.extend_from_slice(&packet);
            self.domain.device_write(bd.dma.into(), &buffer);
            state.rpq_tag = state.rpq_tag.wrapping_add(1) & 0x1fff;
            state.rpq_hw = (state.rpq_hw + 1) % RXBD_NUM_MAX;
        }
        self.bus.set(RPQ_RXBD_IDX + 2, 2, state.rpq_hw);
    }

    /// The chip reads every BD of data ring `txch` up to the host index
    /// `to`: the WD page each names, and the frame its address info names;
    /// then it moves the hardware index there.
    fn kick_data(&self, state: &mut State, txch: usize, to: u32) {
        if state.stalled {
            return;
        }
        let addr = DMA_ADDR_SET_TX[txch];
        let base =
            u64::from(self.bus.get(addr.desa_l, 4)) | u64::from(self.bus.get(addr.desa_h, 4)) << 32;
        while state.tx_host[txch] != to {
            let at = base + u64::from(state.tx_host[txch]) * TxBd::SIZE as u64;
            let bytes = self.domain.device_read(at, TxBd::SIZE);
            let bd = TxBd::decode(bytes.as_slice().try_into().unwrap());
            let page = self.domain.device_read(bd.dma.into(), bd.length.into());
            let body = dwords::<6>(&page);
            let mut at = BODY_SIZE;
            let info = (body[0] & BODY0_WD_INFO_EN != 0).then(|| {
                at += INFO_SIZE;
                dwords::<6>(&page[BODY_SIZE..])
            });
            let seq = u16::from_le_bytes([page[at], page[at + 1]]) & !TXWP_VALID;
            let addr_info = &page[at + 8..at + 16];
            let length = u16::from_le_bytes([addr_info[0], addr_info[1]]);
            let option = u16::from_le_bytes([addr_info[2], addr_info[3]]);
            let dma = u64::from(u32::from_le_bytes(addr_info[4..8].try_into().unwrap()))
                | u64::from(field(option.into(), ADDR_HIGH_MASK.into())) << 32;
            let frame = self.domain.device_read(dma, length.into());
            state.sent.push(Sent {
                txch: txch as u8,
                body,
                info,
                seq,
                frame,
            });
            state.tx_host[txch] = (state.tx_host[txch] + 1) % TXBD_NUM_MAX;
        }
        self.bus.set(addr.idx + 2, 2, to);
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
        if register >= INDIR_ACCESS_ENTRY {
            return self
                .state
                .borrow()
                .indirect
                .get(&register)
                .copied()
                .unwrap_or(0);
        }
        Self::check(register, width);
        if (register, width) == (RXQ_RXBD_IDX, 4) {
            self.deliver_rx();
        }
        if (register, width) == (RPQ_RXBD_IDX, 4) {
            self.deliver_rpq();
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
        if register >= INDIR_ACCESS_ENTRY {
            assert_eq!(width, 4, "{register:#x} reached {width} bytes wide");
            self.state.borrow_mut().indirect.insert(register, value);
            return;
        }
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
        match (register, width) {
            (TXBD_RWPTR_CLR1, 4) => {
                for txch in DATA_RINGS
                    .into_iter()
                    .filter(|&txch| value & 1 << txch != 0)
                {
                    state.tx_host[txch] = 0;
                    self.bus.set(DMA_ADDR_SET_TX[txch].idx + 2, 2, 0);
                }
            }
            (RXBD_RWPTR_CLR, 4) if value & CLR_RPQ_IDX != 0 => {
                state.rpq_hw = 0;
                self.bus.set(RPQ_RXBD_IDX + 2, 2, 0);
            }
            (SWSI_WRITE, 4) => {
                let path = field(value, SWSI_DATA_PATH_V1) as usize;
                let address = field(value, SWSI_DATA_ADDR_V1);
                let data = field(value, SWSI_DATA_VAL_V1);
                if let Some(rf) = state.rf.get_mut(path) {
                    let old = rf.get(&address).copied().unwrap_or(0);
                    let new = if value & SWSI_DATA_BIT_MASK_EN_V1 != 0 {
                        let mask = self.bus.get(CR_BASE + SWSI_BIT_MASK_V1, 4) & RFREG_MASK;
                        (old & !mask) | (data & mask)
                    } else {
                        data
                    };
                    rf.insert(address, new);
                }
            }
            // An indirect RF read of a register SWSI wrote reads what it
            // wrote; any other reads what the SWSI register holds.
            (SWSI_READ, 4) => {
                let path = field(value, SWSI_READ_ADDR_PATH_V1) as usize;
                let address = field(value, SWSI_READ_ADDR_ADDR_V1);
                if let Some(&data) = state.rf.get(path).and_then(|rf| rf.get(&address)) {
                    let stored = self.bus.get(SWSI, 4);
                    self.bus.set(SWSI, 4, (stored & !RFREG_MASK) | data);
                }
            }
            _ => {}
        }
        if width == 2
            && let Some(txch) = DATA_RINGS
                .into_iter()
                .find(|&txch| DMA_ADDR_SET_TX[txch].idx == register)
        {
            self.kick_data(state, txch, value);
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

/// The chip behind a shared handle, so a station's hardware can own its
/// register interface while the test keeps playing the device and the air.
#[derive(Clone)]
pub(crate) struct Shared(pub(crate) Rc<Chip>);

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Shared {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Io::read8(&mut &*self.0, register)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Io::read16(&mut &*self.0, register)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Io::read32(&mut &*self.0, register)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        Io::write8(&mut &*self.0, register, value)
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        Io::write16(&mut &*self.0, register, value)
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        Io::write32(&mut &*self.0, register, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        Io::delay_us(&mut &*self.0, microseconds);
    }
}

/// How the AP's BSS is protected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Protection {
    /// WPA2-Personal: AKM 00-0f-ac:2, CCMP for both ciphers.
    Wpa2Psk,
    /// WPA3-Personal: AKM 00-0f-ac:8, CCMP, PMF required with BIP-CMAC-128.
    Wpa3Sae,
}

/// The user's AP as the model plays it: 5 GHz channel 36 at 80 MHz
/// (center 42), HT, VHT and HE, beaconing every 100 TU. It hears what the
/// chip hands the air, releases each frame through RPQ (acknowledged unless
/// lost or gone), answers on RXQ as an AP answers a station (probe,
/// authentication by open system or SAE, association), and beacons on each
/// look while the radio stands on its channel. Frames it sends carry a long
/// RX descriptor and a PPDU status, as the chip writes them.
pub(crate) struct Ap {
    pub bssid: [u8; 6],
    pub station: [u8; 6],
    pub ssid: Vec<u8>,
    /// The primary channel and, for 80 MHz, the center.
    pub primary: u8,
    pub center: u8,
    pub protection: Protection,
    pub password: Vec<u8>,
    /// The beacons leave the SSID out.
    pub hidden: bool,
    /// The AP stopped beaconing.
    pub quiet: bool,
    /// The AP takes no frame at all.
    pub gone: bool,
    /// Management frames lost before the AP hears them.
    pub losses: usize,
    /// Other channels its beacons reach, as an adjacent channel hears a
    /// strong AP.
    pub heard_on: Vec<u8>,
    /// The channel the radio stood on as each probe left.
    pub probed: Vec<u8>,
    /// Each frame's release status, as the AP gave it.
    pub statuses: Vec<u8>,
    answered: usize,
    ppdu: u8,
    sae: Option<Exchange>,
    confirm: Option<sae::Frame>,
    random: u8,
}

/// The beacon interval, in TU.
pub(crate) const BEACON_INTERVAL: u16 = 100;
/// The AP's association ID.
pub(crate) const AID: u16 = 1;

impl Ap {
    /// The user's AP, `bssid`, for `station` on 5 GHz channel 36/80.
    pub(crate) fn new(
        bssid: [u8; 6],
        station: [u8; 6],
        ssid: &[u8],
        protection: Protection,
    ) -> Self {
        Self {
            bssid,
            station,
            ssid: ssid.to_vec(),
            primary: 36,
            center: 42,
            protection,
            password: b"correct horse battery".to_vec(),
            hidden: false,
            quiet: false,
            gone: false,
            losses: 0,
            heard_on: Vec::new(),
            probed: Vec::new(),
            statuses: Vec::new(),
            answered: 0,
            ppdu: 0,
            sae: None,
            confirm: None,
            random: 7,
        }
    }

    /// The RSN element the AP beacons.
    pub(crate) fn rsn(&self) -> Vec<u8> {
        let akm = match self.protection {
            Protection::Wpa2Psk => 2,
            Protection::Wpa3Sae => 8,
        };
        let mut body = vec![
            1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac,
        ];
        body.push(akm);
        match self.protection {
            Protection::Wpa2Psk => body.extend_from_slice(&[0, 0]),
            // MFPR and MFPC, no PMKID, BIP-CMAC-128.
            Protection::Wpa3Sae => body.extend_from_slice(&[0xc0, 0, 0, 0, 0, 0x0f, 0xac, 6]),
        }
        let mut element = vec![48, body.len() as u8];
        element.extend_from_slice(&body);
        element
    }

    /// The HT, VHT and HE capabilities and operations, and WMM's
    /// parameters: two streams at 80 MHz around the center, BSS color 5.
    fn operation(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // HT: LDPC, 40 MHz, SM power save off, both SGIs, TX STBC, one RX
        // STBC stream; 64K A-MPDU, 4 us spacing; MCS 0-15.
        out.extend_from_slice(&[45, 26, 0xef, 0x01, 0x17, 0xff, 0xff]);
        out.extend_from_slice(&[0; 21]);
        // HT operation: the primary, the secondary above, any width.
        out.extend_from_slice(&[61, 22, self.primary, 0x05]);
        out.extend_from_slice(&[0; 20]);
        // VHT: MPDU 11454, RX LDPC, SGI 80, TX STBC, one RX STBC stream, the
        // largest A-MPDU; MCS 0-9 on two streams.
        let vht: u32 = 2 | 0x10 | 0x20 | 0x80 | 0x100 | 7 << 23;
        out.extend_from_slice(&[191, 12]);
        out.extend_from_slice(&vht.to_le_bytes());
        out.extend_from_slice(&[0xfa, 0xff, 0, 0, 0xfa, 0xff, 0, 0]);
        // VHT operation: 80 MHz around the center.
        out.extend_from_slice(&[192, 5, 1, self.center, 0, 0xfc, 0xff]);
        // HE: 40 and 80 MHz on 5 GHz; MCS 0-11 on two streams.
        out.extend_from_slice(&[255, 22, 35, 0, 0, 0, 0, 0, 0, 0x04]);
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(&[0xfa, 0xff, 0xfa, 0xff]);
        // HE operation: RTS threshold 1023, BSS color 5, HE-MCS 0-7 basic.
        out.extend_from_slice(&[255, 7, 36, 0xf0, 0x3f, 0x00, 0x05, 0xfc, 0xff]);
        // WMM: best effort at the defaults of each class.
        out.extend_from_slice(&[
            221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43,
            0x5e, 0, 0x62, 0x32, 0x2f, 0,
        ]);
        out
    }

    /// The AP's rates: 6, 12 and 24 Mb/s basic, and the rest of OFDM's.
    const RATES: [u8; 10] = [1, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c];

    /// The beacon's fixed fields and elements, or a probe response's to
    /// `receiver`, naming the SSID unless `hidden`.
    fn advertised(&self, subtype: u8, receiver: [u8; 6], hidden: bool) -> Vec<u8> {
        let mut frame = vec![subtype, 0, 0, 0];
        frame.extend_from_slice(&receiver);
        frame.extend_from_slice(&self.bssid);
        frame.extend_from_slice(&self.bssid);
        frame.extend_from_slice(&[0; 2 + 8]);
        frame.extend_from_slice(&BEACON_INTERVAL.to_le_bytes());
        frame.extend_from_slice(&0x0011u16.to_le_bytes());
        let ssid: &[u8] = if hidden { &[] } else { &self.ssid };
        frame.extend_from_slice(&[0, ssid.len() as u8]);
        frame.extend_from_slice(ssid);
        frame.extend_from_slice(&Self::RATES);
        // TIM: DTIM count 0, period 1.
        frame.extend_from_slice(&[5, 4, 0, 1, 0, 0]);
        frame.extend_from_slice(&self.rsn());
        frame.extend_from_slice(&self.operation());
        frame
    }

    /// The beacon as the air carries it, without its FCS.
    pub(crate) fn beacon(&self) -> Vec<u8> {
        self.advertised(0x80, [0xff; 6], self.hidden)
    }

    /// A management frame of `subtype` from the AP to the station.
    pub(crate) fn management(&self, subtype: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = vec![subtype, 0, 0, 0];
        frame.extend_from_slice(&self.station);
        frame.extend_from_slice(&self.bssid);
        frame.extend_from_slice(&self.bssid);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(body);
        frame
    }

    /// Whether the radio stands on the AP's channel: its primary at 20 MHz,
    /// or its center at 80.
    pub(crate) fn here(&self, chip: &Chip) -> bool {
        chip.tuned()
            .is_some_and(|tuned| tuned == self.primary || tuned == self.center)
    }

    /// `frame` (without its FCS) arriving: the chip writes it behind a long
    /// RX descriptor, decrypted by the hardware or not, then its PPDU
    /// status, A1-matched, at -55 dBm.
    pub(crate) fn hear(&mut self, chip: &Chip, frame: &[u8], decrypted: bool) {
        self.ppdu = (self.ppdu + 1) % 8;
        let frame_type = if frame[0] & 0x0c == 0x08 {
            RX_TYPE_DATA
        } else {
            RX_TYPE_MGNT
        };
        let rxd = Rxd::frame(frame_type, self.ppdu);
        let mut bytes = frame.to_vec();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut packet = rxd.packet(&bytes);
        if decrypted {
            packet[12] |= RXD_HW_DEC as u8;
        }
        let status = Rxd::ppdu_of(&rxd).packet(&ppdu_status([110, 104], 100, 120, 0x20));
        chip.queue_rx([packet, status]);
    }

    /// `frame` arriving with an ICV error the hardware found.
    pub(crate) fn hear_failed(&mut self, chip: &Chip, frame: &[u8]) {
        self.ppdu = (self.ppdu + 1) % 8;
        let rxd = Rxd::frame(RX_TYPE_DATA, self.ppdu);
        let mut bytes = frame.to_vec();
        bytes.extend_from_slice(&[0; 4]);
        let mut packet = rxd.packet(&bytes);
        packet[12] |= RXD_HW_DEC as u8;
        packet[13] |= (RXD_ICV_ERR >> 8) as u8;
        let status = Rxd::ppdu_of(&rxd).packet(&ppdu_status([110, 104], 100, 120, 0x20));
        chip.queue_rx([packet, status]);
    }

    /// The PMK the SAE exchange gave, once it was accepted.
    pub(crate) fn pmk(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.sae.as_ref().and_then(Exchange::pmk)
    }

    /// Answer every frame the chip handed the air since the last call, and
    /// beacon once while the radio stands on the AP's channel.
    pub(crate) fn serve(&mut self, chip: &Chip) {
        for sent in chip.sent_from(self.answered) {
            self.answered += 1;
            let bytes = &sent.frame;
            let kind = bytes[0];
            let lost = matches!(kind, 0xb0 | 0x00) && self.losses > 0;
            // A frame to the AP off its channel finds no one to acknowledge it.
            let unheard = bytes[4] & 1 == 0 && !self.here(chip);
            let status = if lost || self.gone || unheard {
                TX_RETRY_LIMIT
            } else {
                TX_DONE
            };
            chip.release(&sent, status);
            self.statuses.push(status);
            if lost {
                self.losses -= 1;
                continue;
            }
            if self.gone || unheard {
                continue;
            }
            match kind {
                0x40 => self.probed(chip, bytes),
                0xb0 => self.authenticate(chip, bytes),
                0x00 => {
                    let mut body = vec![0x11, 0, 0, 0];
                    body.extend_from_slice(&(AID | 0xc000).to_le_bytes());
                    body.extend_from_slice(&Self::RATES);
                    body.extend_from_slice(&self.operation());
                    let response = self.management(0x10, &body);
                    self.hear(chip, &response, false);
                }
                _ => {}
            }
        }
        let leaked = chip
            .tuned()
            .is_some_and(|tuned| self.heard_on.contains(&tuned));
        if !self.quiet && (self.here(chip) || leaked) {
            let beacon = self.beacon();
            self.hear(chip, &beacon, false);
        }
    }

    /// A probe: recorded with the channel it left on, and answered on the
    /// AP's channel when it asks for the AP's name or any.
    fn probed(&mut self, chip: &Chip, bytes: &[u8]) {
        self.probed.extend(chip.tuned());
        let length = usize::from(bytes[25]);
        let name = &bytes[26..26 + length];
        if self.here(chip) && (name == self.ssid || (name.is_empty() && !self.hidden)) {
            let response = self.advertised(0x50, self.station, false);
            self.hear(chip, &response, false);
        }
    }

    /// An authentication: open system's answer, or the AP's side of SAE,
    /// whose commit answers the station's and whose confirm answers its
    /// confirm once that verified.
    fn authenticate(&mut self, chip: &Chip, bytes: &[u8]) {
        let field = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let (algorithm, transaction, status) = (field(24), field(26), field(28));
        let data = &bytes[30..];
        match (algorithm, transaction) {
            (0, 1) => {
                let answer = self.management(0xb0, &[0, 0, 2, 0, 0, 0]);
                self.hear(chip, &answer, false);
            }
            (3, 1) => {
                let mut random = self.random;
                let mut next = || {
                    random = random.wrapping_add(1);
                    [random; 32]
                };
                let mut exchange = Exchange::new(
                    Derivation::HuntingAndPecking,
                    &self.password,
                    None,
                    None,
                    Mac(self.bssid),
                    Mac(self.station),
                    &mut next,
                )
                .unwrap();
                self.random = random;
                let confirm = exchange.receive(1, status, data).unwrap().unwrap();
                let commit = exchange.commit();
                self.sae = Some(exchange);
                self.confirm = Some(confirm);
                self.answer_sae(chip, &commit);
            }
            (3, 2) => {
                let Some(exchange) = &mut self.sae else {
                    return;
                };
                if exchange.receive(2, 0, data) == Ok(None)
                    && let Some(confirm) = self.confirm.take()
                {
                    self.answer_sae(chip, &confirm);
                }
            }
            _ => {}
        }
    }

    fn answer_sae(&mut self, chip: &Chip, frame: &sae::Frame) {
        let mut body = vec![3, 0];
        body.extend_from_slice(&frame.transaction.to_le_bytes());
        body.extend_from_slice(&frame.status.to_le_bytes());
        body.extend_from_slice(&frame.data);
        let answer = self.management(0xb0, &body);
        self.hear(chip, &answer, false);
    }
}
