extern crate std;

use super::super::pci::{
    ring::{RX_BUF_SIZE, RXBD_FS, RXBD_LS, Received, RxChannel},
    tests::{Domain, Model, Placement, new_rings, r32, release, w16},
};
use super::super::registers::RXQ_RXBD_IDX;
use super::*;
use alloc::{vec, vec::Vec};

/// One RX buffer of the C oracle's C2H segment: an RX descriptor, driver
/// info, a packet whose first three dwords are `w0`, `w1` and `w2`, and
/// padding written past it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Case {
    pub(crate) pkt_type: u8,
    pub(crate) long_rxd: bool,
    pub(crate) drv_info: u8,
    pub(crate) shift: u8,
    pub(crate) mac_info: bool,
    pub(crate) pad: usize,
    pub(crate) w0: u32,
    pub(crate) w1: u32,
    pub(crate) w2: u32,
    pub(crate) pkt_size: u16,
}

#[allow(clippy::too_many_arguments)]
const fn case(
    pkt_type: u8,
    long_rxd: bool,
    drv_info: u8,
    shift: u8,
    mac_info: bool,
    pad: usize,
    w0: u32,
    w1: u32,
    w2: u32,
    pkt_size: u16,
) -> Case {
    Case {
        pkt_type,
        long_rxd,
        drv_info,
        shift,
        mac_info,
        pad,
        w0,
        w1,
        w2,
        pkt_size,
    }
}

/// The C oracle's cases, in its order.
pub(crate) const CASES: [Case; 25] = [
    // REC_ACK of class 3 function 0, sequence 0x2a.
    case(10, false, 0, 0, false, 0, 0x001, 12, 0x002a_000d, 12),
    // DONE_ACK of class 2 function 3, returning 0, sequence 0x55.
    case(10, false, 0, 0, false, 0, 0x101, 12, 0x5500_0309, 12),
    // DONE_ACK returning 0x7f at sequence 0xff, a longer packet, padding.
    case(10, false, 0, 0, false, 4, 0x101, 12, 0xff7f_1725, 16),
    // REC_ACK behind a long descriptor and 16 bytes of driver info.
    case(
        10,
        true,
        2,
        0,
        true,
        0,
        0xab00_0001,
        0xc00c,
        0xff80_ffff,
        12,
    ),
    // REC_ACK with a shift the AX query never reads.
    case(10, false, 7, 3, false, 3, 0x001, 20, 0x00ff_0705, 20),
    // The info class's log, a function without a handler, one past them.
    case(10, false, 0, 0, false, 0, 0x201, 40, 0x0102_0304, 40),
    case(10, false, 0, 0, false, 0, 0x401, 16, 0x0000_000d, 16),
    case(10, false, 0, 0, false, 0, 0x701, 12, 0x0000_000d, 12),
    // The offload class: an atomic function and a queued one.
    case(10, false, 0, 0, false, 0, 0x205, 24, 0x0000_000d, 24),
    case(10, false, 0, 0, false, 0, 0x905, 32, 0x0000_0000, 32),
    // FWDBG, which rtw89 ignores, and a class it does not know.
    case(10, false, 0, 0, false, 0, 0x015, 12, 0x0011_000d, 12),
    case(10, false, 0, 0, false, 0, 0x0fd, 12, 0x0011_000d, 12),
    // REC_ACK's class and function in the TEST, OUTSRC and fourth
    // categories, and a BTC class.
    case(10, false, 0, 0, false, 0, 0x000, 12, 0x0011_000d, 12),
    case(10, false, 0, 0, false, 0, 0x002, 12, 0x0011_000d, 12),
    case(10, false, 0, 0, false, 0, 0x142, 12, 0x0011_000d, 12),
    case(10, false, 0, 0, false, 0, 0x003, 12, 0x0011_000d, 12),
    // REC_ACK whose header claims no length: rtw89 does not read it.
    case(10, false, 0, 0, false, 0, 0x001, 0, 0x0042_000d, 12),
    // ROLE, which rtw89 ignores.
    case(10, false, 0, 0, false, 0, 0x06d, 12, 0x0011_000d, 12),
    // Other packet types: a frame, PPDU status, a TX report, type 15.
    case(0, false, 0, 0, false, 0, 0x001, 12, 0x0011_000d, 64),
    case(1, false, 0, 0, true, 0, 0x001, 12, 0x0011_000d, 48),
    case(6, false, 1, 0, false, 0, 0x001, 12, 0x0011_000d, 16),
    case(15, true, 0, 0, false, 2, 0x001, 12, 0x0011_000d, 20),
    // REC_ACK with padding behind it.
    case(10, false, 0, 0, false, 9, 0x001, 12, 0x0001_080d, 12),
    // DONE_ACK with every other bit of its dwords set.
    case(
        10,
        false,
        0,
        0,
        false,
        0,
        0xffff_0101,
        0xffff_c00c,
        0xffff_ffff,
        12,
    ),
    // A 2000-byte log behind a long descriptor and driver info.
    case(10, true, 1, 0, false, 0, 0x201, 2000, 0, 2000),
];

/// The buffer the chip writes for case `index` of `cases`, and its
/// `rxbd_info` dword (tag `index + 1`).
pub(crate) fn build(index: usize, case: &Case) -> (Vec<u8>, u32) {
    let rxd_len = if case.long_rxd {
        RXDESC_LONG
    } else {
        RXDESC_SHORT
    };
    let dword0 = u32::from(case.pkt_size)
        | u32::from(case.shift) << 14
        | u32::from(case.mac_info) << 23
        | u32::from(case.pkt_type) << 24
        | u32::from(case.drv_info) << 28
        | u32::from(case.long_rxd) << 31;
    let mut bytes = vec![0; RXBD_INFO_SIZE];
    bytes.extend(dword0.to_le_bytes());
    for k in 1..rxd_len as u32 / 4 {
        bytes.extend((0xa5a5_0000 | k).to_le_bytes());
    }
    bytes.extend((0..8 * u32::from(case.drv_info)).map(|k| (k * 17 + 3) as u8));
    let words = [case.w0, case.w1, case.w2];
    bytes.extend((0..u32::from(case.pkt_size)).map(|k| {
        if k < 12 {
            (words[k as usize / 4] >> (8 * (k % 4))) as u8
        } else {
            (k * 31 + 5) as u8
        }
    }));
    bytes.extend(core::iter::repeat_n(0xee, case.pad));
    let info = RXBD_FS | RXBD_LS | bytes.len() as u32 | (index as u32 + 1) << 16;
    bytes[..4].copy_from_slice(&info.to_le_bytes());
    (bytes, info)
}

/// `check` over what [`parse`] makes of case `index`.
fn parsed<R>(index: usize, check: impl FnOnce(Packet<'_>) -> R) -> R {
    let (bytes, info) = build(index, &CASES[index]);
    check(parse(RxBdInfo::decode(info), &bytes).unwrap())
}

/// `check` over the C2H of case `index`.
fn c2h<R>(index: usize, check: impl FnOnce(C2h<'_>) -> R) -> R {
    parsed(index, |packet| match packet {
        Packet::C2h(c2h) => check(c2h),
        other => panic!("case {index}: {other:?}"),
    })
}

fn event(index: usize) -> Result<Event, Error> {
    c2h(index, |c2h| c2h.event())
}

#[test]
fn rec_ack_and_done_ack_name_the_command_and_its_sequence() {
    let ack = |cat, class, func, seq| Ack {
        cat,
        class,
        func,
        seq,
    };
    assert_eq!(event(0), Ok(Event::RecAck(ack(1, 3, 0, 0x2a))));
    assert_eq!(
        event(1),
        Ok(Event::DoneAck {
            ack: ack(1, 2, 3, 0x55),
            h2c_return: 0
        })
    );
    assert_eq!(
        event(2),
        Ok(Event::DoneAck {
            ack: ack(1, 9, 0x17, 0xff),
            h2c_return: 0x7f
        })
    );
    // REC_ACK's sequence is bits 16 to 23; the byte above is not its.
    assert_eq!(event(3), Ok(Event::RecAck(ack(3, 0x3f, 0xff, 0x80))));
    assert_eq!(event(4), Ok(Event::RecAck(ack(1, 1, 7, 0xff))));
    // A header that claims no length is reported, not refused.
    assert_eq!(c2h(16, |c2h| c2h.attr.len), 0);
    assert_eq!(event(16), Ok(Event::RecAck(ack(1, 3, 0, 0x42))));
    // Padding written past the packet stays out of it.
    assert_eq!(c2h(22, |c2h| c2h.data.len()), 12);
    assert_eq!(
        event(23),
        Ok(Event::DoneAck {
            ack: ack(3, 0x3f, 0xff, 0xff),
            h2c_return: 0xff
        })
    );
}

#[test]
fn every_other_c2h_keeps_its_header_and_payload_raw() {
    for (index, (category, class, func)) in [
        (5, (1, 0, 2)),
        (6, (1, 0, 4)),
        (7, (1, 0, 7)),
        (8, (1, 1, 2)),
        (9, (1, 1, 9)),
        (10, (1, 5, 0)),
        (11, (1, 0x3f, 0)),
        (12, (0, 0, 0)),
        (13, (2, 0, 0)),
        (14, (2, 0x10, 1)),
        (15, (3, 0, 0)),
        (17, (1, 0x1b, 0)),
    ] {
        let case = CASES[index];
        c2h(index, |c2h| {
            assert_eq!(
                (c2h.attr.category, c2h.attr.class, c2h.attr.func),
                (category, class, func),
                "case {index}"
            );
            assert_eq!(c2h.attr.len, (case.w1 & 0x3fff) as u16);
            assert_eq!(c2h.event(), Ok(Event::Other), "case {index}");
            assert_eq!(c2h.data.len(), usize::from(case.pkt_size));
            assert_eq!(c2h.payload(), &c2h.data[HEADER_LEN..]);
            assert_eq!(c2h.payload()[..4], case.w2.to_le_bytes());
        });
    }
    // The log's 2000 bytes, behind a long descriptor and 8 bytes of driver
    // info.
    c2h(24, |log| {
        assert_eq!(log.data.len(), 2000);
        assert_eq!(log.data[12], (12 * 31 + 5) as u8);
        assert_eq!(log.data[1999], (1999 * 31 + 5) as u8);
    });
}

#[test]
fn other_packet_types_are_left_with_their_descriptor() {
    for (index, (pkt_type, long_rxdesc, drv_info_size)) in [
        (18, (RX_TYPE_WIFI, false, 0)),
        (19, (RX_TYPE_PPDU_STAT, false, 0)),
        (20, (6, false, 1)),
        (21, (15, true, 0)),
    ] {
        let desc = parsed(index, |packet| match packet {
            Packet::Other(desc) => desc,
            other => panic!("case {index}: {other:?}"),
        });
        assert_eq!(
            (desc.pkt_type, desc.long_rxdesc, desc.drv_info_size),
            (pkt_type, long_rxdesc, drv_info_size)
        );
        assert_eq!(desc.pkt_size, CASES[index].pkt_size);
    }
}

#[test]
fn the_descriptor_places_the_packet_behind_driver_info_and_never_a_shift() {
    let (bytes, _) = build(3, &CASES[3]);
    let desc = RxDesc::query(&bytes, RXBD_INFO_SIZE).unwrap();
    assert_eq!(
        desc,
        RxDesc {
            pkt_size: 12,
            pkt_type: RX_TYPE_C2H,
            drv_info_size: 2,
            long_rxdesc: true,
            mac_info_valid: true,
            offset: 4 + 16,
            rxd_len: 32,
        }
    );
    assert_eq!(desc.packet_offset(), 52);
    let (bytes, _) = build(4, &CASES[4]);
    let desc = RxDesc::query(&bytes, RXBD_INFO_SIZE).unwrap();
    assert_eq!((desc.offset, desc.rxd_len), (4 + 56, 16));
}

#[test]
fn truncated_and_segmented_buffers_are_refused() {
    let (bytes, dword) = build(0, &CASES[0]);
    let info = RxBdInfo::decode(dword);
    // Every cut of a 32-byte REC_ACK buffer falls short of something.
    for written in 0..bytes.len() {
        let needed = if written < 20 { 20 } else { 32 };
        assert_eq!(
            parse(info, &bytes[..written]),
            Err(Error::Truncated { needed, written }),
            "{written}"
        );
        // A buffer that claims fewer bytes than were copied is cut there.
        let short = RxBdInfo {
            len: written as u16,
            ..info
        };
        assert_eq!(
            parse(short, &bytes),
            Err(Error::Truncated { needed, written })
        );
    }
    assert!(parse(info, &bytes).is_ok());
    // A long descriptor needs its 32 bytes.
    let (bytes, dword) = build(3, &CASES[3]);
    let info = RxBdInfo::decode(dword);
    assert_eq!(
        parse(info, &bytes[..30]),
        Err(Error::Truncated {
            needed: 36,
            written: 30
        })
    );
    // A packet shorter than the C2H header, or an ack shorter than its
    // third dword.
    let mut tiny = CASES[0];
    tiny.pkt_size = 7;
    let (bytes, dword) = build(0, &tiny);
    assert_eq!(
        parse(RxBdInfo::decode(dword), &bytes),
        Err(Error::Truncated {
            needed: 8,
            written: 7
        })
    );
    for (index, size) in [(0, 11), (1, 8)] {
        let mut short = CASES[index];
        short.pkt_size = size;
        let (bytes, dword) = build(index, &short);
        let Ok(Packet::C2h(c2h)) = parse(RxBdInfo::decode(dword), &bytes) else {
            panic!("case {index}");
        };
        assert_eq!(
            c2h.event(),
            Err(Error::Truncated {
                needed: 12,
                written: size.into()
            })
        );
    }
    // A short log is still a C2H: only acks need the third dword.
    let mut short = CASES[5];
    short.pkt_size = 8;
    let (bytes, dword) = build(5, &short);
    let Ok(Packet::C2h(c2h)) = parse(RxBdInfo::decode(dword), &bytes) else {
        panic!("short log");
    };
    assert_eq!((c2h.event(), c2h.payload()), (Ok(Event::Other), &[][..]));
    // One segment of a packet spread over several buffers.
    let (bytes, dword) = build(0, &CASES[0]);
    for (fs, ls) in [(true, false), (false, true), (false, false)] {
        let info = RxBdInfo {
            fs,
            ls,
            ..RxBdInfo::decode(dword)
        };
        assert_eq!(parse(info, &bytes), Err(Error::Segmented { fs, ls }));
    }
}

#[test]
fn c2h_comes_back_from_rxq() {
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0, 0, false);
    let mut io = &model;
    // The chip fills three buffers: REC_ACK, a frame, and a cut packet.
    let mut written = Vec::new();
    for (slot, index) in [0usize, 18, 1].into_iter().enumerate() {
        let (mut bytes, _) = build(index, &CASES[index]);
        if slot == 2 {
            // The descriptor claims 12 bytes; the chip wrote 10 of them.
            let len = bytes.len() as u32 - 2;
            let info = RXBD_FS | RXBD_LS | len | 3 << 16;
            bytes[..4].copy_from_slice(&info.to_le_bytes());
        }
        let bd = rings.rx_bd(RxChannel::Rxq, slot).unwrap();
        domain.device_write(bd.dma.into(), &bytes);
        written.push(bytes);
    }
    model.set(RXQ_RXBD_IDX + 2, 2, 3);
    let mut seen = Vec::new();
    let consumed = receive(&mut io, &mut rings, 64, |packet| {
        seen.push(packet.map(|packet| match packet {
            Packet::C2h(c2h) => (Some(c2h.event()), None),
            Packet::Other(desc) => (None, Some(desc.pkt_type)),
        }))
    });
    assert_eq!(consumed, Ok(3));
    assert_eq!(
        seen,
        [
            Ok((
                Some(Ok(Event::RecAck(Ack {
                    cat: 1,
                    class: 3,
                    func: 0,
                    seq: 0x2a
                }))),
                None
            )),
            Ok((None, Some(RX_TYPE_WIFI))),
            Err(Error::Truncated {
                needed: 32,
                written: 30
            }),
        ]
    );
    assert_eq!(
        model.take_log(),
        [r32(RXQ_RXBD_IDX, 3 << 16), w16(RXQ_RXBD_IDX, 3)]
    );
    // What deliver hands over is what parse reads.
    let mut again = Vec::new();
    domain.device_write(
        rings.rx_bd(RxChannel::Rxq, 3).unwrap().dma.into(),
        &written[0],
    );
    model.set(RXQ_RXBD_IDX + 2, 2, 4);
    rings
        .deliver(&mut io, RxChannel::Rxq, 1, |Received { info, data }| {
            assert!(data.len() <= RX_BUF_SIZE);
            again.push(parse(info, data).map(|packet| matches!(packet, Packet::C2h(_))));
        })
        .unwrap();
    assert_eq!(again, [Ok(true)]);
    release(&mut rings);
}
