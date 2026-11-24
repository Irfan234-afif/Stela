extern crate std;

use super::super::{
    super::{
        io::{self, Io},
        registers::{ACH0_TXBD_IDX, RPQ_RXBD_IDX},
        txwd::{self, DescInfo},
    },
    ring::{
        AddrInfo, Buffer, ChDmaAddr, DmaRing, Error, Rings, RxBdInfo, RxChannel, Submitted,
        TXWD_NUM_MAX, TXWD_PAGE_SIZE, TxBd, TxChannel, dma_recalc, txbd_submit, txwd_page,
    },
    tests::Source,
};
use super::*;
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DomainMapping},
    memory::{CacheAttribute, PinnedPages},
    pages::DmaPages,
};
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{convert::Infallible, ops::Range};
use std::sync::Mutex;

struct Mapped {
    _pages: PinnedPages,
    cpu: usize,
    bytes: usize,
    direction: Direction,
}

#[derive(Default)]
struct DomainState {
    next: u64,
    mappings: BTreeMap<u64, Mapped>,
    unmapped: Vec<u64>,
}

/// A DMA domain that places each mapping on its own pages, one page apart,
/// and keeps a CPU view of each, so a test can play the device.
struct Sequential {
    state: Mutex<DomainState>,
}

impl Sequential {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(DomainState {
                next: 0x2000_0000,
                ..DomainState::default()
            }),
        })
    }

    fn view(&self, address: u64, length: usize, write: bool) -> usize {
        let state = self.state.lock().unwrap();
        let (&base, mapped) = state.mappings.range(..=address).next_back().unwrap();
        let offset = (address - base) as usize;
        assert!(offset + length <= mapped.bytes);
        let refused = if write {
            Direction::ToDevice
        } else {
            Direction::FromDevice
        };
        assert_ne!(mapped.direction, refused);
        mapped.cpu + offset
    }

    fn device_read(&self, address: u64, length: usize) -> Vec<u8> {
        let cpu = self.view(address, length, false);
        let mut bytes = vec![0; length];
        // SAFETY: the range lies inside a live mapping this domain keeps,
        // and the test plays the device while the CPU writes none of it.
        unsafe {
            bytes
                .as_mut_ptr()
                .copy_from_nonoverlapping(cpu as *const u8, length);
        }
        bytes
    }

    fn device_write(&self, address: u64, bytes: &[u8]) {
        let cpu = self.view(address, bytes.len(), true);
        // SAFETY: as in `device_read`, the CPU holding no reference.
        unsafe {
            (cpu as *mut u8).copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
        }
    }

    fn live(&self) -> usize {
        self.state.lock().unwrap().mappings.len()
    }

    fn unmapped(&self) -> Vec<u64> {
        core::mem::take(&mut self.state.lock().unwrap().unmapped)
    }
}

// SAFETY: pinned allocations are held while mapped; IOVA placement and
// cache visibility are model events of this test, never hardware claims.
unsafe impl DmaDomain for Sequential {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        _limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
        let mut state = self.state.lock().unwrap();
        let address = state.next;
        state.next += pages.bytes().next_multiple_of(0x1000) as u64 + 0x1000;
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
        let state = self.state.lock().unwrap();
        assert_eq!(state.mappings[&mapping.id].direction, direction);
        assert!(range.end <= mapping.bytes);
        Ok(())
    }

    unsafe fn sync_for_cpu(
        &self,
        mapping: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let state = self.state.lock().unwrap();
        assert_eq!(state.mappings[&mapping.id].direction, direction);
        assert_ne!(direction, Direction::ToDevice);
        assert!(range.end <= mapping.bytes);
        Ok(())
    }
}

/// A register file whose index registers read what the test set, and a
/// log of the stores.
#[derive(Default)]
struct Registers {
    values: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Registers {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.read32(register)? as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.read32(register)? as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(self.values.get(&register).copied().unwrap_or(0))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.write32(register, value.into())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.write32(register, value.into())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.writes.push((register, value));
        Ok(())
    }
    fn delay_us(&mut self, _microseconds: u64) {}
}

fn ring(idx: u32) -> DmaRing {
    DmaRing {
        dma: 0,
        desc_size: TxBd::SIZE as u8,
        addr: ChDmaAddr {
            num: 0,
            idx,
            bdram: 0,
            desa_l: 0,
            desa_h: 0,
        },
        len: 256,
        wp: 0,
        rp: 0,
    }
}

fn no_read() -> Result<u32, Infallible> {
    panic!("a page on no list reclaims nothing")
}

fn read(cnt: u32) -> impl FnOnce() -> Result<u32, Infallible> {
    move || Ok(cnt)
}

/// A data frame of best effort on ACH0 with WD info, as the station's
/// path would describe it.
fn data_desc(len: u16, seq: u16) -> DescInfo {
    DescInfo {
        pkt_size: len,
        qsel: txwd::QSEL_BE_0,
        ch_dma: txwd::ch_dma(txwd::QSEL_BE_0),
        wd_page: true,
        en_wd_info: true,
        seq,
        mac_id: 1,
        data_retry_lowest_rate: 0x4,
        ..DescInfo::default()
    }
}

#[test]
fn wd_pages_are_reused_in_report_order_and_released_by_sequence() {
    let mut wd = WdRing::<u32>::new(0x8000).unwrap();
    assert_eq!(
        (wd.curr_num(), wd.peek(), wd.page_dma(3)),
        (512, Some(0), 0x8180)
    );
    for frame in 0..3 {
        assert_eq!(wd.submit(100 + frame), Ok(frame as u16));
    }
    assert_eq!(wd.busy().collect::<Vec<_>>(), [0, 1, 2]);
    // The hardware read all three BDs: the pages leave the busy list but
    // stay taken until their reports.
    wd.reclaim(3);
    assert_eq!((wd.busy().count(), wd.curr_num()), (0, 509));
    // Reports come out of order; each releases the frame its sequence names.
    assert_eq!(wd.release(1, TxStatus::RetryLimit, no_read), Ok(Some(101)));
    assert_eq!(wd.release(2, TxStatus::Done, no_read), Ok(Some(102)));
    assert_eq!(wd.release(0, TxStatus::Done, no_read), Ok(Some(100)));
    assert_eq!(wd.curr_num(), 512);
    let stats = wd.stats();
    assert_eq!(
        (stats.tx_cnt, stats.tx_acked, stats.tx_retry_lmt),
        (3, 2, 1)
    );
    // The rest of the never-used pages go first, then the reported ones in
    // report order.
    for seq in 3..512 {
        assert_eq!(wd.submit(seq.into()), Ok(seq));
    }
    assert_eq!(wd.submit(0), Ok(1));
    assert_eq!(wd.submit(0), Ok(2));
    assert_eq!(wd.submit(0), Ok(0));
    // Every page carries a frame now: no available TXWD.
    assert_eq!((wd.curr_num(), wd.submit(7)), (0, Err(7)));
}

#[test]
fn a_report_before_its_bd_is_read_frees_the_frame_and_the_reclaim_the_page() {
    let mut wd = WdRing::<u32>::new(0).unwrap();
    wd.submit(10).unwrap();
    wd.submit(11).unwrap();
    // Page 1's report comes while the hardware index shows nothing read:
    // rtw89 reclaims (nothing), warns, and releases the frame, but the page
    // stays busy.
    assert_eq!(wd.release(1, TxStatus::Done, read(0)), Ok(Some(11)));
    assert!(!wd.holds(1));
    assert_eq!((wd.curr_num(), wd.busy().count()), (510, 2));
    // A repeated report finds no frame.
    assert_eq!(wd.release(1, TxStatus::Done, read(0)), Ok(None));
    // Both BDs read: page 0 waits for its report, page 1 goes back free.
    wd.reclaim(2);
    assert_eq!((wd.curr_num(), wd.peek()), (511, Some(2)));
    assert!(wd.holds(0));
    // A report that names a page in neither list reclaims nothing first.
    assert_eq!(wd.release(0, TxStatus::LifeTime, no_read), Ok(Some(10)));
    assert_eq!(wd.curr_num(), 512);
    // A BD count past the busy pages stops at the last.
    wd.submit(12).unwrap();
    wd.reclaim(5);
    assert_eq!(wd.busy().count(), 0);
    let stats = wd.stats();
    assert_eq!(
        (stats.tx_cnt, stats.tx_acked, stats.tx_life_time),
        (3, 1, 1)
    );
}

#[test]
fn a_report_for_a_free_page_reclaims_and_releases_nothing() {
    let mut wd = WdRing::<u32>::new(0).unwrap();
    let mut asked = false;
    let released = wd.release(7, TxStatus::Done, || {
        asked = true;
        Ok::<_, Infallible>(0)
    });
    assert_eq!((released, asked, wd.curr_num()), (Ok(None), true, 512));
    assert_eq!(wd.release(512, TxStatus::Done, no_read), Ok(None));
    assert_eq!(wd.stats(), TxStats::default());
}

#[test]
fn a_ring_release_drops_every_frame_held_as_macid_drop() {
    let mut wd = WdRing::<u32>::new(0).unwrap();
    for frame in 0..4 {
        wd.submit(frame).unwrap();
    }
    wd.reclaim(2);
    wd.release(0, TxStatus::Done, no_read).unwrap();
    let mut released = Vec::new();
    wd.release_ring(|seq, frame| released.push((seq, frame)));
    assert_eq!(released, [(1, 1), (2, 2), (3, 3)]);
    assert_eq!((wd.curr_num(), wd.busy().count()), (512, 0));
    assert_eq!(wd.stats().tx_mac_id_drop, 3);
    // The pages come back after the 508 never used, in rtw89's order.
    for seq in 4..512 {
        assert_eq!(wd.submit(0), Ok(seq));
    }
    assert_eq!([wd.submit(0), wd.submit(0)], [Ok(0), Ok(1)]);
}

#[test]
fn reports_parse_as_pci_h_lays_them_out() {
    let dword = 1 << 31 | 0x1ff << 16 | 1 << 13 | 0x12 << 8 | 0x2a;
    let info = RppInfo::parse(dword);
    assert_eq!(
        info,
        RppInfo {
            seq: 0x1ff,
            qsel: 0x12,
            tx_status: 1,
            txch: 8
        }
    );
    assert_eq!(info.target(), Some((TxChannel::Ch8, 0x1ff)));
    assert_eq!(info.status(), TxStatus::RetryLimit);
    // Each AC queue of any port to its ring; band 0 high to CH9.
    for (qsel, txch) in [(0x0, 0), (0x4, 0), (0xd, 1), (0x6, 2), (0xf, 3), (0x11, 9)] {
        assert_eq!(RppInfo::parse(qsel << 8).txch, txch, "{qsel:#x}");
    }
    // Band 1's queues name rings the chip lacks; a sequence past the pages
    // names no page: rtw89 drops both.
    assert_eq!(RppInfo::parse(0x1a << 8).target(), None);
    assert_eq!(RppInfo::parse(0x19 << 8).target(), None);
    assert_eq!(RppInfo::parse(512 << 16).target(), None);
    // A queue no ring is named for goes to ACH0.
    assert_eq!(
        RppInfo::parse(0x7fff << 16 | 0x14 << 8).txch,
        TxChannel::Ach0 as u8
    );
    for raw in 0..8 {
        assert_eq!(TxStatus::from_raw(raw).raw(), raw);
    }
    assert!(TxStatus::Done.acked() && !TxStatus::RetryLimit.acked());
    assert_eq!(TxStatus::from_raw(5), TxStatus::Invalid(5));
}

#[test]
fn an_rpq_buffer_gives_its_reports_from_behind_the_descriptor() {
    let mut buffer = vec![0u8; 128];
    // A short descriptor with one 8-byte unit of driver info, then three
    // reports and two bytes of a fourth.
    buffer[4..8].copy_from_slice(&(1u32 << 28).to_le_bytes());
    for (index, dword) in [0x11u32, 0x22, 0x33].into_iter().enumerate() {
        let at = 4 + 16 + 8 + 4 * index;
        buffer[at..at + 4].copy_from_slice(&dword.to_le_bytes());
    }
    let info = |len| RxBdInfo {
        fs: true,
        ls: true,
        len,
        tag: 0,
    };
    let all: Vec<u32> = reports(info(4 + 16 + 8 + 14), &buffer).unwrap().collect();
    assert_eq!(all, [0x11, 0x22, 0x33]);
    // A long descriptor moves them back by 16.
    buffer[4..8].copy_from_slice(&(1u32 << 31).to_le_bytes());
    let long: Vec<u32> = reports(info(4 + 32 + 8), &buffer).unwrap().collect();
    assert_eq!(long, [0x33, 0]);
    // A length past the buffer stops at its end.
    assert_eq!(
        reports(info(0x3fff), &buffer).unwrap().count(),
        (128 - 36) / 4
    );
    assert_eq!(
        reports(
            RxBdInfo {
                ls: false,
                ..info(64)
            },
            &buffer
        )
        .err(),
        Some(rxdesc::Error::Segmented {
            fs: true,
            ls: false
        })
    );
}

#[test]
fn a_wd_page_holds_the_body_info_wp_info_and_address_info() {
    let desc = data_desc(1500, 0x123);
    let page = txwd_page(&desc, 0x1a5, 1500, 0x0000_0012_3456_7000);
    assert_eq!(page.len, 24 + 24 + 8 + 8);
    let (wd, wd_len) = desc.wd();
    assert_eq!((&page.bytes[..48], wd_len), (&wd[..], 48));
    assert_eq!(
        page.bytes[0..4],
        (txwd::BODY0_WD_INFO_EN | txwd::BODY0_WD_PAGE).to_le_bytes()
    );
    // The WP info names the page, valid; the other three sequences are 0.
    assert_eq!(page.bytes[48..56], [0xa5, 0x81, 0, 0, 0, 0, 0, 0]);
    let addr = AddrInfo::fill(1500, 0x0000_0012_3456_7000);
    assert_eq!(
        addr,
        AddrInfo {
            length: 1500,
            option: 1 << 15 | 1 | 0x12 << 6,
            dma: 0x3456_7000
        }
    );
    assert_eq!(page.bytes[56..64], addr.encode());
    assert!(page.bytes[64..].iter().all(|&byte| byte == 0));
    // Without WD info the WP info follows the body.
    let desc = DescInfo {
        en_wd_info: false,
        ..desc
    };
    let page = txwd_page(&desc, 3, 60, 0x1000);
    assert_eq!(page.len, 40);
    assert_eq!(page.bytes[24..26], [3, 0x80]);
    assert_eq!(page.bytes[32..34], 60u16.to_le_bytes());
    // The info's fields, as txrx.h places them.
    let desc = DescInfo {
        use_rate: true,
        data_bw: 2,
        gi_ltf: 1,
        data_rate: 0x1ab,
        stbc: true,
        ldpc: true,
        dis_data_fb: true,
        port: 5,
        ampdu_num: 0x3f,
        a_ctrl_bsr: true,
        data_retry_lowest_rate: 0x104,
        tx_cnt_lmt_en: true,
        tx_cnt_lmt: 0x7f,
        ampdu_density: 7,
        sec_type: 0xf,
        sec_en: true,
        sec_cam_idx: 0x81,
        report: true,
        is_bmc: true,
        sn: 0x1e,
        ..DescInfo::default()
    };
    assert_eq!(
        desc.info_dwords(),
        [
            1 << 30 | 2 << 28 | 1 << 25 | 0x1ab << 16 | 1 << 12 | 1 << 11 | 1 << 10 | 5 << 4,
            1 << 31 | 0x3f << 25 | 0x104 << 16 | 1 << 14 | 0x3f,
            7 << 18 | 0xf << 9 | 1 << 8 | 0x81,
            1 << 10,
            1 << 31 | 0xe,
            0
        ]
    );
    // RTS for an individual receiver.
    assert_eq!(DescInfo::default().info4(), 1 << 31 | 1 << 27);
}

#[test]
fn the_bd_ring_wraps_around_while_the_pages_turn_over() {
    let mut bd = ring(ACH0_TXBD_IDX);
    let mut wd = WdRing::<u32>::new(0x10_0000).unwrap();
    let mut seqs = Vec::new();
    for frame in 0..700u32 {
        let index = bd.wp;
        let mut stored = None;
        let seq = txbd_submit(
            &mut bd,
            &mut wd,
            &data_desc(100, frame as u16),
            100,
            0x4000_0000 + u64::from(frame) * 0x1000,
            frame,
            |at, submitted: &Submitted| {
                stored = Some((at, *submitted));
                Ok::<(), Error>(())
            },
        )
        .unwrap();
        let (at, submitted) = stored.unwrap();
        assert_eq!((at, submitted.seq), (index, seq));
        assert_eq!(
            submitted.bd,
            TxBd::last_segment(0x10_0000 + u64::from(seq) * 128, 64)
        );
        assert_eq!(bd.wp, (index + 1) % 256);
        seqs.push(seq);
        // The hardware reads the BD and the chip reports the frame sent.
        let hw = bd.wp << 16;
        let released = wd.release(seq, TxStatus::Done, || {
            Ok::<_, Infallible>(dma_recalc(&mut bd, hw, true))
        });
        assert_eq!(released, Ok(Some(frame)));
    }
    // The host index went round the ring twice; the 512 pages turned over.
    assert_eq!((bd.wp, bd.rp), (700 % 256, 700 % 256));
    assert_eq!(seqs[..3], [0, 1, 2]);
    assert_eq!(seqs[511..515], [511, 0, 1, 2]);
    assert_eq!((wd.curr_num(), wd.stats().tx_acked), (512, 700));

    // A ring whose BDs are all given: no free BD, before any page is taken.
    let mut bd = ring(ACH0_TXBD_IDX);
    let mut wd = WdRing::<u32>::new(0).unwrap();
    let store = |_: u32, _: &Submitted| Ok::<(), Error>(());
    for frame in 0..255 {
        txbd_submit(&mut bd, &mut wd, &DescInfo::default(), 1, 0, frame, store).unwrap();
    }
    assert_eq!(
        txbd_submit(&mut bd, &mut wd, &DescInfo::default(), 1, 0, 0, store),
        Err(Error::NoTxBd)
    );
    assert_eq!((wd.curr_num(), bd.wp), (512 - 255, 255));
    // A store that fails moves nothing.
    bd.rp = 255;
    assert_eq!(
        txbd_submit(&mut bd, &mut wd, &DescInfo::default(), 1, 0, 0, |_, _| Err(
            Error::Index(9)
        )),
        Err(Error::Index(9))
    );
    assert_eq!((wd.curr_num(), bd.wp), (512 - 255, 255));
}

fn frame(source: &Source, domain: &Arc<Sequential>, bytes: &[u8]) -> Buffer {
    let buffer = Buffer::new(source, domain.clone(), bytes.len(), Direction::ToDevice).unwrap();
    buffer.write(0, bytes).unwrap();
    buffer
}

/// The device's side of one RPQ buffer: a short descriptor, then `rpps`.
fn rpq_write(domain: &Sequential, rings: &Rings, index: usize, rpps: &[u32]) {
    let mut bytes = Vec::new();
    let len = 4 + 16 + 4 * rpps.len();
    let info = RxBdInfo {
        fs: true,
        ls: true,
        len: len as u16,
        tag: 0,
    };
    bytes.extend(info.encode().to_le_bytes());
    bytes.extend([0; 16]);
    for rpp in rpps {
        bytes.extend(rpp.to_le_bytes());
    }
    let bd = rings.rx_bd(RxChannel::Rpq, index).unwrap();
    domain.device_write(bd.dma.into(), &bytes);
}

fn rpp(seq: u16, status: u8, qsel: u8) -> u32 {
    u32::from(seq) << 16 | u32::from(status) << 13 | u32::from(qsel) << 8
}

#[test]
fn frames_go_out_through_their_wd_pages_and_come_back_on_rpq_reports() {
    let domain = Sequential::new();
    let dyn_domain: Arc<dyn DmaDomain> = domain.clone();
    let mut rings = Rings::new(&Source, dyn_domain.clone()).unwrap();
    let mut io = Registers::default();
    let desc = data_desc(64, 0x10);
    // No WD pages yet.
    let buffer = frame(&Source, &domain, &[0xab; 64]);
    let address = u64::from(buffer.address());
    assert_eq!(
        rings.tx_write(&desc, buffer, 64),
        Err(Error::NoWdRing(TxChannel::Ach0))
    );
    // The chip was never given it: it is unmapped at once.
    assert_eq!(domain.unmapped(), [address]);
    rings.alloc_tx_wd(&Source, dyn_domain.clone()).unwrap();
    let live = domain.live();
    // The firmware command ring and the rings the chip lacks have no pages.
    assert!(rings.wd_ring(TxChannel::Ch12).is_none());
    assert!(rings.wd_ring(TxChannel::Ach4).is_none());
    assert_eq!(rings.wd_ring(TxChannel::Ch9).unwrap().curr_num(), 512);

    // Two frames on ACH0, one on the management ring.
    let mut sent = Vec::new();
    for (index, desc) in [
        desc,
        data_desc(64, 0x11),
        DescInfo {
            qsel: txwd::QSEL_B0_MGMT,
            ch_dma: txwd::ch_dma(txwd::QSEL_B0_MGMT),
            hw_ssn_sel: txwd::MGMT_HW_SSN_SEL,
            hw_seq_mode: txwd::MGMT_HW_SEQ_MODE,
            use_rate: true,
            dis_data_fb: true,
            ..data_desc(64, 0)
        },
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = [index as u8; 64];
        let buffer = frame(&Source, &domain, &bytes);
        let dma = u64::from(buffer.address());
        let seq = rings.tx_write(&desc, buffer, 64).unwrap();
        sent.push((desc.ch_dma, seq, dma));
    }
    assert_eq!(
        sent.iter()
            .map(|&(ch, seq, _)| (ch, seq))
            .collect::<Vec<_>>(),
        [(0, 0), (0, 1), (8, 0)]
    );
    assert_eq!(domain.live(), live + 3);
    // What the chip reads: the BD points at the WD page, the page at the
    // frame, and the frame is the caller's bytes.
    for (index, &(ch, seq, dma)) in sent.iter().enumerate() {
        let txch = TxChannel::ALL[usize::from(ch)];
        let wd = rings.wd_ring(txch).unwrap();
        let bd = rings.tx_bd(txch, if ch == 0 { index } else { 0 }).unwrap();
        assert_eq!(bd, TxBd::last_segment(wd.page_dma(seq), 64));
        let page = domain.device_read(wd.page_dma(seq), TXWD_PAGE_SIZE);
        let desc = if ch == 0 {
            data_desc(64, 0x10 + index as u16)
        } else {
            DescInfo {
                qsel: txwd::QSEL_B0_MGMT,
                ch_dma: 8,
                hw_ssn_sel: 1,
                hw_seq_mode: 1,
                use_rate: true,
                dis_data_fb: true,
                ..data_desc(64, 0)
            }
        };
        assert_eq!(page, txwd_page(&desc, seq, 64, dma).bytes);
        assert_eq!(domain.device_read(dma, 64), [index as u8; 64]);
    }
    assert_eq!(rings.wd_ring(TxChannel::Ach0).unwrap().stats().tx_cnt, 2);

    // Kick-off hands ACH0's host index to the chip.
    rings.tx_kick_off(&mut io, TxChannel::Ach0).unwrap();
    assert_eq!(io.writes, [(ACH0_TXBD_IDX, 2)]);
    io.writes.clear();

    // The chip read both BDs and wrote one RPQ buffer: frame 1 acked,
    // frame 0 out of retries, the management frame acked.
    io.values.insert(ACH0_TXBD_IDX, 2 << 16);
    rpq_write(
        &domain,
        &rings,
        0,
        &[
            rpp(1, TX_DONE, txwd::QSEL_BE_0),
            rpp(0, TX_RETRY_LIMIT, txwd::QSEL_BE_0),
            rpp(0, TX_DONE, txwd::QSEL_B0_MGMT),
        ],
    );
    io.values.insert(RPQ_RXBD_IDX, 1 << 16);
    let mut completions = Vec::new();
    assert_eq!(rings.poll_rpq(&mut io, |c| completions.push(c)), Ok(1));
    assert_eq!(
        completions,
        [
            Completion {
                txch: TxChannel::Ach0,
                seq: 1,
                status: TxStatus::Done
            },
            Completion {
                txch: TxChannel::Ach0,
                seq: 0,
                status: TxStatus::RetryLimit
            },
            Completion {
                txch: TxChannel::Ch8,
                seq: 0,
                status: TxStatus::Done
            },
        ]
    );
    // Each frame is unmapped as its report comes; the RPQ buffer goes back.
    assert_eq!(domain.unmapped(), [sent[1].2, sent[0].2, sent[2].2]);
    assert_eq!(io.writes, [(RPQ_RXBD_IDX, 1)]);
    let ach0 = rings.wd_ring(TxChannel::Ach0).unwrap();
    assert_eq!((ach0.curr_num(), ach0.busy().count()), (512, 0));
    let stats = ach0.stats();
    assert_eq!((stats.tx_acked, stats.tx_retry_lmt), (1, 1));
    // The management ring's BD was never read: its page waits on the busy
    // list until the hardware index moves.
    let ch8 = rings.wd_ring(TxChannel::Ch8).unwrap();
    assert_eq!((ch8.curr_num(), ch8.busy().count()), (511, 1));
    io.values
        .insert(super::super::ring::DMA_ADDR_SET_TX[8].idx, 1 << 16);
    assert_eq!(rings.reclaim_txbd(&mut io, TxChannel::Ch8), Ok(1));
    assert_eq!(rings.wd_ring(TxChannel::Ch8).unwrap().curr_num(), 512);
    // Nothing more on RPQ.
    assert_eq!(rings.poll_rpq(&mut io, |_| panic!("no report")), Ok(0));

    // SAFETY: no modeled device keeps any of these mappings.
    unsafe { rings.release_after_stop() }.unwrap();
    assert_eq!(domain.live(), 0);
}

#[test]
fn a_full_ring_releases_what_rpq_holds_before_it_refuses_a_frame() {
    let domain = Sequential::new();
    let dyn_domain: Arc<dyn DmaDomain> = domain.clone();
    let mut rings = Rings::new(&Source, dyn_domain.clone()).unwrap();
    rings.alloc_tx_wd(&Source, dyn_domain).unwrap();
    let mut io = Registers::default();
    for seq in 0..255 {
        let buffer = frame(&Source, &domain, &[0; 32]);
        assert_eq!(rings.tx_write(&data_desc(32, seq), buffer, 32), Ok(seq));
    }
    let buffer = frame(&Source, &domain, &[0; 32]);
    assert_eq!(
        rings.tx_write(&data_desc(32, 255), buffer, 32),
        Err(Error::NoTxBd)
    );
    // Nothing on RPQ and nothing read: still full.
    assert_eq!(
        rings.check_and_reclaim_tx_resource(&mut io, TxChannel::Ach0, |_| panic!("no report")),
        Ok(0)
    );
    // The chip read 100 BDs and reported 40 of those frames in two RPQ
    // buffers: the reports free nothing until the BDs are reclaimed,
    // which the reports' own release does.
    io.values.insert(ACH0_TXBD_IDX, 100 << 16);
    let first: Vec<u32> = (0..30).map(|seq| rpp(seq, TX_DONE, 0)).collect();
    let second: Vec<u32> = (30..40).map(|seq| rpp(seq, TX_LIFE_TIME, 0x4)).collect();
    rpq_write(&domain, &rings, 0, &first);
    rpq_write(&domain, &rings, 1, &second);
    io.values.insert(RPQ_RXBD_IDX, 2 << 16);
    let mut done = Vec::new();
    let free = rings.check_and_reclaim_tx_resource(&mut io, TxChannel::Ach0, |c| done.push(c));
    // 100 BDs free again, 512 - 255 + 40 pages.
    assert_eq!(free, Ok(100));
    assert_eq!(done.len(), 40);
    assert!(done[..30].iter().all(|c| c.status == TxStatus::Done));
    assert!(done[30..].iter().all(|c| c.status == TxStatus::LifeTime));
    let ach0 = rings.wd_ring(TxChannel::Ach0).unwrap();
    assert_eq!(
        (ach0.curr_num(), ach0.busy().count()),
        (512 - 255 + 40, 155)
    );
    // A firmware command data channel 12 is refused, so is a ring past 12.
    let buffer = frame(&Source, &domain, &[0; 32]);
    let ch12 = DescInfo {
        ch_dma: 12,
        ..data_desc(32, 0)
    };
    assert_eq!(rings.tx_write(&ch12, buffer, 32), Err(Error::Channel(12)));
    let buffer = frame(&Source, &domain, &[0; 32]);
    let past = DescInfo {
        ch_dma: 13,
        ..data_desc(32, 0)
    };
    assert_eq!(rings.tx_write(&past, buffer, 32), Err(Error::Channel(13)));
    let buffer = frame(&Source, &domain, &[0; 32]);
    assert_eq!(
        rings.tx_write(&data_desc(32, 0), buffer, 4097),
        Err(Error::Length {
            length: 4097,
            bytes: 4096
        })
    );
    // Stopping releases every mapping, the frames still held among them.
    // SAFETY: no modeled device keeps any of these mappings.
    unsafe { rings.release_after_stop() }.unwrap();
    assert_eq!(domain.live(), 0);
}

/// `enum rtw89_tx_channel`'s data channels with WD pages, and the harness's
/// addresses (`tx_manifest.json`'s `harness`).
const WD_DMA_BASE: u64 = 0x1000_0000;
const WD_DMA_STEP: u64 = 0x10_0000;
const IDX_BASE: u32 = 0x1000;
const DESC_WORDS: usize = 35;
const ENOSPC: u32 = -28i32 as u32;
const EINVAL: u32 = -22i32 as u32;

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect()
}

/// A `struct rtw89_tx_desc_info` as the harness's `fill_desc` assigns it.
fn desc_from(w: &[u32]) -> DescInfo {
    DescInfo {
        pkt_size: w[0] as u16,
        wp_offset: w[1] as u8,
        mac_id: w[2] as u8,
        qsel: w[3] as u8,
        ch_dma: w[4] as u8,
        hdr_llc_len: w[5] as u8,
        is_bmc: w[6] != 0,
        en_wd_info: w[7] != 0,
        wd_page: w[8] != 0,
        use_rate: w[9] != 0,
        dis_data_fb: w[10] != 0,
        tid_indicate: w[11] != 0,
        agg_en: w[12] != 0,
        bk: w[13] != 0,
        ampdu_density: w[14] as u8,
        ampdu_num: w[15] as u8,
        sec_en: w[16] != 0,
        report: w[17] != 0,
        tx_cnt_lmt_en: w[18] != 0,
        sn: w[19] as u8,
        tx_cnt_lmt: w[20] as u8,
        sec_type: w[21] as u8,
        sec_cam_idx: w[22] as u8,
        data_rate: w[23] as u16,
        data_retry_lowest_rate: w[24] as u16,
        data_bw: w[25] as u8,
        gi_ltf: w[26] as u8,
        fw_dl: w[27] != 0,
        seq: w[28] as u16,
        a_ctrl_bsr: w[29] != 0,
        hw_ssn_sel: w[30] as u8,
        hw_seq_mode: w[31] as u8,
        port: w[32] as u8,
        stbc: w[33] != 0,
        ldpc: w[34] != 0,
    }
}

#[derive(Default)]
struct Coverage {
    written: usize,
    no_bd: usize,
    no_wd: usize,
    refused: usize,
    reused: usize,
    completions: [usize; 8],
    early: usize,
}

fn state(bd: &DmaRing, wd: &WdRing<u32>) -> [u32; 9] {
    let stats = wd.stats();
    [
        bd.wp,
        bd.rp,
        wd.curr_num(),
        wd.busy().count() as u32,
        stats.tx_cnt as u32,
        stats.tx_acked as u32,
        stats.tx_retry_lmt as u32,
        stats.tx_life_time as u32,
        stats.tx_mac_id_drop as u32,
    ]
}

fn data_ring(txch: u8) -> Option<usize> {
    TxChannel::ALL
        .get(usize::from(txch))
        .filter(|txch| txch.present() && **txch != TxChannel::Ch12)
        .map(|&txch| txch as usize)
}

fn scenario(ops: &[u32], cov: &mut Coverage) -> Vec<u32> {
    let mut bd: [DmaRing; 13] = core::array::from_fn(|txch| ring(IDX_BASE + 4 * txch as u32));
    let mut wd: [Option<WdRing<u32>>; 13] = core::array::from_fn(|txch| {
        data_ring(txch as u8).map(|_| WdRing::new(WD_DMA_BASE + WD_DMA_STEP * txch as u64).unwrap())
    });
    let mut hw = [0u32; 13];
    let mut used = [[false; TXWD_NUM_MAX]; 13];
    let (mut ids, mut at, mut out) = (0, 0, Vec::new());
    let comps = |out: &mut Vec<u32>, comps: &[(u32, bool)]| {
        out.push(comps.len() as u32);
        for &(id, acked) in comps {
            out.extend([id, acked.into()]);
        }
    };
    while at < ops.len() {
        let op = ops[at];
        at += 1;
        match op {
            0 => {
                assert_eq!(ops[at], 0, "a data or management frame");
                let desc = desc_from(&ops[at + 1..]);
                let len = ops[at + 1 + DESC_WORDS];
                let dma =
                    u64::from(ops[at + 2 + DESC_WORDS]) | u64::from(ops[at + 3 + DESC_WORDS]) << 32;
                at += 4 + DESC_WORDS;
                ids += 1;
                let txch = usize::from(desc.ch_dma);
                let old_wp = bd[txch].wp;
                let mut stored = None;
                let result = match wd[txch].as_mut() {
                    Some(ring) => txbd_submit(
                        &mut bd[txch],
                        ring,
                        &desc,
                        len,
                        dma,
                        ids,
                        |index, submitted: &Submitted| {
                            stored = Some((index, *submitted));
                            Ok::<(), Error>(())
                        },
                    ),
                    None => Err(Error::Channel(desc.ch_dma)),
                };
                match result {
                    Ok(seq) => {
                        let (index, submitted) = stored.unwrap();
                        assert_eq!((index, submitted.seq), (old_wp, seq));
                        out.extend([0, old_wp]);
                        out.extend(words(&submitted.bd.encode()));
                        out.extend(words(&submitted.page.bytes));
                        cov.written += 1;
                        cov.reused += usize::from(used[txch][usize::from(seq)]);
                        used[txch][usize::from(seq)] = true;
                    }
                    Err(Error::NoTxBd) => {
                        out.extend([ENOSPC, old_wp]);
                        cov.no_bd += 1;
                    }
                    Err(Error::NoTxWd) => {
                        out.extend([ENOSPC, old_wp]);
                        cov.no_wd += 1;
                    }
                    Err(Error::Channel(_)) => {
                        out.extend([EINVAL, old_wp]);
                        cov.refused += 1;
                    }
                    Err(other) => panic!("{other:?}"),
                }
                if let Some(ring) = wd[txch].as_ref() {
                    out.extend(state(&bd[txch], ring));
                }
            }
            1 => {
                let txch = ops[at] as usize;
                at += 1;
                out.extend([1, bd[txch].addr.idx, bd[txch].wp & 0xffff]);
            }
            2 => {
                hw[ops[at] as usize] = ops[at + 1];
                at += 2;
            }
            3 => {
                let info = RppInfo::parse(ops[at]);
                at += 1;
                out.extend([
                    u32::from(info.seq),
                    info.qsel.into(),
                    info.tx_status.into(),
                    info.txch.into(),
                ]);
                let (mut reads, mut released) = (0, Vec::new());
                if let Some((txch, seq)) = info.target()
                    && let Some(ring) = wd[txch as usize].as_mut()
                {
                    let (bd, hw) = (&mut bd[txch as usize], hw[txch as usize]);
                    let busy = ring.busy().any(|busy| busy == seq);
                    let frame = ring
                        .release(seq, info.status(), || {
                            reads += 1;
                            Ok::<_, Infallible>(dma_recalc(bd, hw, true))
                        })
                        .unwrap();
                    if let Some(id) = frame {
                        released.push((id, info.status().acked()));
                        cov.completions[usize::from(info.tx_status)] += 1;
                        cov.early += usize::from(busy && ring.busy().any(|busy| busy == seq));
                    }
                }
                out.push(reads);
                comps(&mut out, &released);
                if let Some(txch) = data_ring(info.txch) {
                    out.extend(state(&bd[txch], wd[txch].as_ref().unwrap()));
                }
            }
            4 => {
                let txch = ops[at] as usize;
                at += 1;
                let cnt = dma_recalc(&mut bd[txch], hw[txch], true);
                let ring = wd[txch].as_mut().unwrap();
                ring.reclaim(cnt);
                out.push(1);
                out.extend(state(&bd[txch], ring));
            }
            5 => {
                let txch = ops[at] as usize;
                at += 1;
                let ring = wd[txch].as_mut().unwrap();
                let mut released = Vec::new();
                ring.release_ring(|_, id| released.push((id, false)));
                comps(&mut out, &released);
                out.extend(state(&bd[txch], ring));
            }
            other => panic!("operation {other}"),
        }
    }
    out
}

fn replay(input: &[u32], cov: &mut Coverage) -> Vec<u32> {
    match input[0] {
        0 => words(&desc_from(&input[1..]).wd().0),
        1 => {
            let info = AddrInfo::fill(input[1], u64::from(input[2]) | u64::from(input[3]) << 32);
            let mut out = vec![AddrInfo::SIZE as u32, 1];
            out.extend(words(&info.encode()));
            out
        }
        2 => {
            let info = RppInfo::parse(input[1]);
            vec![
                info.seq.into(),
                info.qsel.into(),
                info.tx_status.into(),
                info.txch.into(),
            ]
        }
        3 => scenario(&input[1..], cov),
        kind => panic!("case kind {kind}"),
    }
}

#[test]
#[ignore = "oracle: STELA_RTW89_TRX_ORACLE"]
fn txwd_addr_info_and_rpp_match_unchanged_c() {
    use super::super::tests::segment;
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_TRX_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("tx_trace.bin")).unwrap();
    let (mut offset, mut cases, mut kinds) = (0, 0, [0usize; 4]);
    let mut cov = Coverage::default();
    while offset < trace.len() {
        let input = words(segment(&trace, &mut offset));
        let expected = words(segment(&trace, &mut offset));
        let actual = replay(&input, &mut cov);
        if expected != actual {
            let first = expected
                .iter()
                .zip(&actual)
                .position(|(e, a)| e != a)
                .unwrap_or(expected.len().min(actual.len()));
            panic!(
                "case {cases}: word {first} of {}/{}: C {:x?}, Rust {:x?}",
                expected.len(),
                actual.len(),
                expected.get(first),
                actual.get(first)
            );
        }
        kinds[input[0] as usize] += 1;
        cases += 1;
    }
    assert_eq!(offset, trace.len());
    // Every kind the generator makes, each reached.
    assert_eq!((cases, kinds), (992, [300, 200, 456, 36]));
    assert!(
        cov.written > 3000
            && cov.no_bd > 0
            && cov.no_wd > 0
            && cov.refused > 0
            && cov.reused > 200
            && cov.early > 0
            && cov.completions.iter().all(|&count| count > 0),
        "{} written, {} without a BD, {} without a page, {} refused, {} reused, {} early, \
         completions {:?}",
        cov.written,
        cov.no_bd,
        cov.no_wd,
        cov.refused,
        cov.reused,
        cov.early,
        cov.completions
    );
}
