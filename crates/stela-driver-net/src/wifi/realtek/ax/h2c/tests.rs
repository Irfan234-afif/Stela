extern crate std;

use super::super::{
    c2h::{
        self, Event, Packet as RxPacket, RXBD_INFO_SIZE, RxDesc,
        tests::{CASES, build},
    },
    pci::{
        ring::{RxBdInfo, TXBD_OPT_LS},
        tests::{
            Domain, Model, Placement, Source, encode, new_rings, push, r32, release, segment, w16,
        },
    },
    registers::CH12_TXBD_IDX,
};
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};

#[test]
fn a_header_packs_what_rtw89_h2c_pkt_set_hdr_packs() {
    let mut sequence = Sequence(5);
    let header = sequence.set_hdr(Function::mac(0x02, 0x03), false, true, 7);
    // Category 1, class 2, function 3, type 0, sequence 5.
    assert_eq!(header.hdr0, 0x0500_0309);
    // Seven bytes and the header, DONE_ACK, no REC_ACK at an odd sequence.
    assert_eq!(header.hdr1, HDR_DONE_ACK | 15);
    assert_eq!(
        header.encode(),
        [0x09, 0x03, 0x00, 0x05, 0x0f, 0x80, 0x00, 0x00]
    );
    assert_eq!(Header::decode(&header.encode()), header);
    assert_eq!(header.function(), Function::mac(2, 3));
    assert_eq!((header.seq(), header.total_len()), (5, 15), "{header:x?}");
    assert!(!header.rec_ack() && header.done_ack());
    assert_eq!(sequence, Sequence(6));

    // Fields wider than theirs are cut, as FIELD_PREP cuts them, and so is
    // a length past 14 bits.
    let wide = Function {
        del_type: 0x13,
        cat: 5,
        class: 0x41,
        func: 0xff,
    };
    let header = Sequence(1).set_hdr(wide, true, false, 0x3ff8);
    assert_eq!(header.hdr0, 0x0103_ff05);
    assert_eq!(header.hdr1, HDR_REC_ACK);
    let header = Sequence(1).set_hdr(wide, false, false, u32::MAX - 3);
    assert_eq!(header.total_len(), 4);
}

#[test]
fn rec_ack_is_asked_of_every_fourth_command_across_the_wrap() {
    let mut sequence = Sequence::default();
    for n in 0..520u32 {
        let header = sequence.set_hdr(Function::mac(1, 2), false, false, 4);
        assert_eq!(header.seq(), n as u8);
        assert_eq!(header.rec_ack(), n % 4 == 0, "{n}");
        assert!(!header.done_ack());
    }
    assert_eq!(sequence, Sequence(8));
    // Asked for, every command carries it.
    for _ in 0..8 {
        assert!(
            sequence
                .set_hdr(Function::mac(1, 2), true, false, 4)
                .rec_ack()
        );
    }
}

#[test]
fn the_firmware_header_asks_for_no_ack_and_keeps_the_sequence() {
    let sequence = Sequence(8);
    let header = sequence.set_hdr_fwdl(FWHDR_DL, 64);
    // MAC category, FWDL class, FWHDR_DL function, sequence 8.
    assert_eq!(header.hdr0, 0x0800_000d);
    assert_eq!(header.hdr1, 72);
    assert_eq!(sequence, Sequence(8));
    // Even at a multiple of four.
    assert!(!Sequence(0).set_hdr_fwdl(FWHDR_DL, 0).rec_ack());
}

#[test]
fn frames_are_the_txwd_body_then_the_packet() {
    let payload = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4];
    let source = Source;
    let domain = Domain::new(Placement::Oracle);
    let mut channel = Channel::new(&source, domain);

    let command = channel.command(0x08, 0x10, false, false, &payload);
    assert_eq!(channel.sequence(), Sequence(1));
    assert_eq!((command.length(), command.frame_length()), (13, 37));
    let mut frame = vec![0; 37];
    command.frame(&mut frame).unwrap();
    assert_eq!(frame[..24], DescInfo::fwcmd(13, false).body());
    assert_eq!(frame[24..32], command.header.unwrap().encode());
    assert_eq!(frame[32..], payload);
    assert_eq!(command.frame(&mut frame[1..]), Err(Error::Length(36)));

    // The firmware header carries the sequence it found, without FW_DL.
    let header = channel.fwdl_header(&payload);
    assert_eq!(header.header.unwrap().seq(), 1);
    assert_eq!(channel.sequence(), Sequence(1));
    assert!(!header.desc().fw_dl);

    // A download part has no header and sets FW_DL.
    let part = Channel::fwdl_part(&payload);
    assert_eq!((part.length(), part.frame_length()), (5, 29));
    let mut frame = vec![0; 29];
    part.frame(&mut frame).unwrap();
    assert_eq!(frame[..24], DescInfo::fwcmd(5, true).body());
    assert_eq!(frame[24..], payload);

    channel.reset_sequence();
    assert_eq!(channel.sequence(), Sequence(0));
}

#[test]
fn an_h2c_goes_out_on_ch12_behind_its_txwd_body() {
    let source = Source;
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0, 0, false);
    let mut io = &model;
    let mut channel = Channel::new(&source, domain.clone());

    // A command: CH12's index read for the reclaim, then the host index.
    let payload: Vec<u8> = (0..16).collect();
    let packet = channel.command(0x01, 0x10, false, false, &payload);
    channel.send(&mut io, &mut rings, &packet).unwrap();
    assert_eq!(
        model.take_log(),
        [r32(CH12_TXBD_IDX, 0), w16(CH12_TXBD_IDX, 1)]
    );
    let bd = rings.tx_bd(TxChannel::Ch12, 0).unwrap();
    assert_eq!(bd.length, 48);
    assert_eq!(bd.opt, TXBD_OPT_LS);
    assert!(bd.dma < 0x8100_0000);
    let mapped = domain.device_read(bd.dma.into(), 48);
    let mut frame = vec![0; 48];
    packet.frame(&mut frame).unwrap();
    assert_eq!(mapped, frame);
    // The body names CH12 and the 24 bytes of header and payload.
    assert_eq!(mapped[..12], [0, 0, 12, 0, 0, 0, 0, 0, 24, 0, 0, 0]);
    // Sequence 0 asks for REC_ACK.
    assert_eq!(mapped[24..32], [0x05, 0x10, 0, 0, 0x18, 0x40, 0, 0]);
    assert_eq!(rings.fwcmd(), (1, 0));

    // A download part: FW_DL and no header.
    let part = vec![0x77; FWDL_SECTION_PER_PKT_LEN];
    channel
        .send(&mut io, &mut rings, &Channel::fwdl_part(&part))
        .unwrap();
    let bd = rings.tx_bd(TxChannel::Ch12, 1).unwrap();
    assert_eq!(
        usize::from(bd.length),
        H2C_DESC_SIZE + FWDL_SECTION_PER_PKT_LEN
    );
    let mapped = domain.device_read(bd.dma.into(), bd.length.into());
    assert_eq!(mapped[..4], (txwd::BODY0_FW_DL | 12 << 16).to_le_bytes());
    assert_eq!(mapped[8..12], 2020u32.to_le_bytes());
    assert!(mapped[24..].iter().all(|&byte| byte == 0x77));
    assert_eq!(
        model.take_log(),
        [r32(CH12_TXBD_IDX, 1), w16(CH12_TXBD_IDX, 2)]
    );

    // The chip read both: the next send reclaims them, kept behind
    // MULTITAG.
    model.set(CH12_TXBD_IDX + 2, 2, 2);
    let packet = channel.command(0x01, 0x11, false, false, &[]);
    channel.send(&mut io, &mut rings, &packet).unwrap();
    assert_eq!(
        model.take_log(),
        [r32(CH12_TXBD_IDX, 2 << 16 | 2), w16(CH12_TXBD_IDX, 3)]
    );
    assert_eq!(rings.fwcmd(), (1, 2));

    // A full ring: no BD after the reclaim is rtw89's -ENOSPC, with no
    // buffer mapped and no host index written.
    for _ in 0..254 {
        let packet = channel.command(0x08, 0, false, false, &[]);
        channel.send(&mut io, &mut rings, &packet).unwrap();
    }
    assert_eq!(rings.avail_txbd(TxChannel::Ch12), Ok(0));
    model.take_log();
    let live = domain.live();
    let packet = channel.command(0x08, 0, false, false, &[]);
    assert_eq!(
        channel.send(&mut io, &mut rings, &packet),
        Err(Error::NoResource)
    );
    assert_eq!(model.take_log(), [r32(CH12_TXBD_IDX, 2 << 16 | 1)]);
    assert_eq!(domain.live(), live);

    // A packet TXPKT_SIZE cannot carry is refused before any access.
    let long = vec![0; MAX_PACKET - HEADER_LEN + 1];
    let packet = channel.command(0x08, 0, false, false, &long);
    assert_eq!(
        channel.send(&mut io, &mut rings, &packet),
        Err(Error::Length(MAX_PACKET + 1))
    );
    assert!(model.log().is_empty());
    release(&mut rings);
    assert_eq!(domain.live(), 0);
}

/// The C oracle's header arguments: `rtw89_h2c_pkt_set_hdr`'s length.
const LENS: [u32; 10] = [0, 4, 8, 12, 2020, 2028, 0x3ff7, 0x3ff8, 0x4000, 0xffff_fffc];

#[derive(Clone, Copy, Debug)]
enum Op {
    Command {
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        len: u32,
    },
    FwdlHeader(u32),
    FwdlPart(u32),
    /// The chip read up to this index.
    Hardware(u32),
    /// The chip read everything given.
    HardwareAll,
    /// Empty commands of `class` until one is refused.
    Fill(u8),
}

const fn command(class: u8, func: u8, rack: bool, dack: bool, len: u32) -> Op {
    Op::Command {
        class,
        func,
        rack,
        dack,
        len,
    }
}

/// The C oracle's CH12 script, in its order.
const SCRIPT: [Op; 16] = [
    command(0x01, 0x10, false, false, 16),
    command(0x02, 0x03, false, true, 7),
    Op::FwdlHeader(64),
    Op::FwdlPart(2020),
    Op::FwdlPart(2020),
    Op::FwdlPart(333),
    Op::Hardware(3),
    command(0x3f, 0xff, true, true, 0),
    Op::Hardware(7),
    command(0x05, 0x01, false, false, 4),
    command(0x05, 0x02, false, false, 1),
    Op::Hardware(9),
    Op::Fill(0x08),
    Op::HardwareAll,
    command(0x01, 0x02, false, false, 12),
    command(0x0c, 0x20, false, false, 8),
];

/// Little-endian words of `bytes`, the last one zero-padded, each recorded
/// with its index.
fn push_words(trace: &mut Vec<u8>, tag: u32, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut word = [0; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        push(trace, tag, index as u32, u32::from_le_bytes(word));
    }
}

/// The CH12 ring, its register model and channel, as the oracle's `send`
/// segment drives them.
struct Ch12<'a> {
    domain: &'a Domain,
    model: &'a Model,
    rings: &'a mut Rings,
    channel: Channel<'a>,
    /// Each mapped frame's length, by address, for the unmaps.
    frames: BTreeMap<u64, u32>,
    sent: u32,
}

impl Ch12<'_> {
    /// The oracle's `send_one`: the records of one `rtw89_h2c_tx`, and
    /// whether it returned 0.
    fn send(&mut self, trace: &mut Vec<u8>, op: Op) -> bool {
        let sent = self.sent;
        self.sent += 1;
        let len = match op {
            Op::Command { len, .. } | Op::FwdlHeader(len) | Op::FwdlPart(len) => len,
            _ => unreachable!(),
        };
        let payload: Vec<u8> = (0..len).map(|k| (k * 7 + sent * 13 + 1) as u8).collect();
        let packet = match op {
            Op::Command {
                class,
                func,
                rack,
                dack,
                ..
            } => self.channel.command(class, func, rack, dack, &payload),
            Op::FwdlHeader(_) => self.channel.fwdl_header(&payload),
            _ => Channel::fwdl_part(&payload),
        };
        let wp = self.rings.tx_ring(TxChannel::Ch12).unwrap().wp;
        let mut io = self.model;
        let result = self.channel.send(&mut io, self.rings, &packet);
        trace.extend(encode(&self.model.take_log()));
        for address in self.domain.take_unmapped() {
            push(
                trace,
                60,
                address as u32,
                self.frames.remove(&address).unwrap(),
            );
        }
        let ret: i32 = match result {
            Ok(()) => 0,
            Err(Error::NoResource) => -28,
            Err(error) => panic!("the model refuses nothing: {error:?}"),
        };
        push(trace, 11, 0, ret as u32);
        if result.is_ok() {
            let bd = self.rings.tx_bd(TxChannel::Ch12, wp as usize).unwrap();
            push(
                trace,
                122,
                wp,
                u32::from(bd.length) | u32::from(bd.opt) << 16,
            );
            push(trace, 123, bd.dma, bd.length.into());
            let mapped = self.domain.device_read(bd.dma.into(), bd.length.into());
            push_words(trace, 124, &mapped);
            self.frames.insert(bd.dma.into(), bd.length.into());
        }
        let (queued, kept) = self.rings.fwcmd();
        push(trace, 126, queued as u32, kept as u32);
        push(trace, 127, self.channel.sequence().0.into(), 0);
        result.is_ok()
    }
}

#[test]
#[ignore = "oracle: STELA_RTW89_H2C_ORACLE"]
fn h2c_headers_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_H2C_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;

    // rtw89_h2c_pkt_set_hdr and rtw89_h2c_pkt_set_hdr_fwdl from h2c_seq 0.
    let mut expected = Vec::new();
    let mut sequence = Sequence::default();
    for i in 0..600u32 {
        let function = Function {
            del_type: ((i * 5) & 0x1f) as u8,
            cat: (i % 6) as u8,
            class: ((i * 7) & 0x7f) as u8,
            func: (i * 13 + 1) as u8,
        };
        let len = LENS[i as usize % 10];
        let before = sequence.0;
        let header = if i % 7 == 3 {
            sequence.set_hdr_fwdl(function, len)
        } else {
            sequence.set_hdr(function, i % 3 == 0, i % 5 == 1, len)
        };
        push(&mut expected, 100, before.into(), header.hdr0);
        push(&mut expected, 101, header.hdr1, sequence.0.into());
    }
    assert_eq!(segment(&trace, &mut offset), expected, "headers");

    // rtw89_core_tx_update_desc_info with rtw89_chip_fill_txdesc_fwcmd,
    // then rtw89_core_fill_txdesc over set members.
    let mut expected = Vec::new();
    let skb_lens = [0, 8, 12, 32, 2020, 2028, 0x3fff, 0x4000, 0x1_0007, u32::MAX];
    for (e, len) in skb_lens.into_iter().enumerate() {
        let desc = DescInfo::fwcmd(len, e % 3 == 2);
        // is_bmc and en_wd_info: never set for a command.
        push(
            &mut expected,
            110,
            desc.pkt_size.into(),
            u32::from(desc.ch_dma) | u32::from(desc.wd_page) << 8 | u32::from(desc.fw_dl) << 10,
        );
        for (k, dword) in desc.dwords().into_iter().enumerate() {
            push(&mut expected, 111, k as u32, dword);
        }
    }
    for j in 0..8u32 {
        let desc = DescInfo {
            wp_offset: (j * 37 + 3) as u8,
            ch_dma: (j * 5 + 1) as u8,
            hdr_llc_len: (j * 11) as u8,
            wd_page: (j & 1) != 0,
            fw_dl: ((j >> 1) & 1) != 0,
            hw_ssn_sel: (j * 3) as u8,
            hw_seq_mode: (j * 7) as u8,
            tid_indicate: ((j >> 2) & 1) != 0,
            qsel: (j * 9 + 2) as u8,
            pkt_size: (j * 0x1357 + 0x89) as u16,
            mac_id: (j * 29 + 5) as u8,
            seq: (j * 0x321 + 7) as u16,
            agg_en: j % 3 == 0,
            bk: j % 3 == 1,
        };
        for (k, dword) in desc.dwords().into_iter().enumerate() {
            push(&mut expected, 112, k as u32, dword);
        }
    }
    assert_eq!(segment(&trace, &mut offset), expected, "TXWD");

    // rtw89_h2c_tx over the CH12 script.
    let source = Source;
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0, 0, false);
    let mut ch12 = Ch12 {
        domain: &domain,
        model: &model,
        rings: &mut rings,
        channel: Channel::new(&source, domain.clone()),
        frames: BTreeMap::new(),
        sent: 0,
    };
    let mut expected = Vec::new();
    for op in SCRIPT {
        match op {
            Op::Hardware(_) | Op::HardwareAll => {
                let idx = match op {
                    Op::Hardware(idx) => idx,
                    _ => ch12.rings.tx_ring(TxChannel::Ch12).unwrap().wp,
                };
                model.set(CH12_TXBD_IDX + 2, 2, idx);
                push(&mut expected, 125, idx, 0);
            }
            Op::Fill(class) => {
                for n in 0..=256u32 {
                    assert!(n < 256, "CH12 never filled");
                    if !ch12.send(&mut expected, command(class, n as u8, false, false, 0)) {
                        break;
                    }
                }
            }
            op => assert!(ch12.send(&mut expected, op), "{op:?}"),
        }
    }
    assert_eq!(segment(&trace, &mut offset), expected, "CH12");
    drop(ch12);
    release(&mut rings);

    // rtw89_pci_rxbd_deliver_skbs on RXQ.
    let mut expected = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        let (bytes, dword) = build(index, case);
        let desc = RxDesc::query(&bytes, RXBD_INFO_SIZE).unwrap();
        push(
            &mut expected,
            130,
            desc.pkt_type.into(),
            desc.pkt_size.into(),
        );
        push(
            &mut expected,
            131,
            u32::from(desc.drv_info_size)
                | u32::from(desc.long_rxdesc) << 8
                | u32::from(desc.mac_info_valid) << 9,
            u32::from(desc.offset) | u32::from(desc.rxd_len) << 16,
        );
        match c2h::parse(RxBdInfo::decode(dword), &bytes).unwrap() {
            RxPacket::Other(other) => {
                assert_eq!(other, desc);
                push(&mut expected, 132, desc.pkt_type.into(), 0);
            }
            RxPacket::C2h(c2h) => {
                push(&mut expected, 133, c2h.data.len() as u32, 0);
                push_words(&mut expected, 134, c2h.data);
                let attr = c2h.attr;
                push(
                    &mut expected,
                    137,
                    u32::from(attr.category)
                        | u32::from(attr.class) << 8
                        | u32::from(attr.func) << 16,
                    attr.len.into(),
                );
                let ack = |ack: c2h::Ack| {
                    u32::from(ack.cat) | u32::from(ack.class) << 8 | u32::from(ack.func) << 16
                };
                match c2h.event().unwrap() {
                    Event::RecAck(rec) => push(&mut expected, 135, ack(rec), rec.seq.into()),
                    Event::DoneAck {
                        ack: done,
                        h2c_return,
                    } => push(
                        &mut expected,
                        136,
                        ack(done),
                        u32::from(h2c_return) | u32::from(done.seq) << 8,
                    ),
                    Event::Other => push(&mut expected, 138, 0, 0),
                }
            }
        }
    }
    assert_eq!(segment(&trace, &mut offset), expected, "C2H");
    assert_eq!(offset, trace.len());
}
