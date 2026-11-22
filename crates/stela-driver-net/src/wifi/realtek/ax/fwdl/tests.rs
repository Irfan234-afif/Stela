extern crate std;

use super::super::{
    features::{Features, ver_code},
    h2c::{self, FWDL_SECTION_PER_PKT_LEN, H2C_DESC_SIZE, HEADER_LEN, Header, Sequence},
    pci::{
        ring::{TXBD_OPT_LS, TxBd, TxChannel},
        tests::{Domain, Model, Placement, Source, new_rings, push, release, segment},
    },
    txwd,
};
use super::*;
use crate::wifi::realtek::firmware::Rtw89;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::cell::RefCell;

/// How the modeled WCPU answers one attempt, as the C oracle's
/// `struct behavior`: whether a kick moves CH12's hardware index, whether
/// each path's ready bit ever comes up, and the status it reports once every
/// packet is in.
#[derive(Clone, Copy, Debug)]
struct Behavior {
    consume: bool,
    h2c: bool,
    fwdl: bool,
    status: u8,
}

const OK: Behavior = Behavior {
    consume: true,
    h2c: true,
    fwdl: true,
    status: FWDL_WCPU_FW_INIT_RDY,
};
const NO_H2C: Behavior = Behavior { h2c: false, ..OK };
const NO_FWDL: Behavior = Behavior { fwdl: false, ..OK };
const fn status(status: u8) -> Behavior {
    Behavior { status, ..OK }
}
/// CH12's hardware index never moves.
const fn hold(status: u8) -> Behavior {
    Behavior {
        consume: false,
        status,
        ..OK
    }
}

/// Reads of WCPU_FW_CTRL before a bit the model raises shows.
const LAG: u32 = 2;
const MEMORY: usize = 0x1_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fill {
    /// Byte `i` holds `i * 37 + 11`, as in the C oracle.
    Pattern,
    Zeros,
}

struct State {
    memory: Vec<u8>,
    records: Vec<[u32; 3]>,
    packets: Vec<u8>,
    script: Vec<Behavior>,
    sticky: bool,
    attempt: u32,
    kicks: u32,
    reads: u32,
    host: u32,
    expected: u32,
    domain: Arc<Domain>,
    ch12_bd: u64,
    /// Each handed-over command buffer's length, by address, for unmaps.
    frames: BTreeMap<u64, u32>,
}

/// The C oracle's register and WCPU model: MAC space as bytes; WCPU_EN
/// going from 0 to 1 starts an attempt, which answers as its [`Behavior`];
/// a kick on CH12 hands over every BD up to the new host index, records it
/// and its bytes, and moves the hardware index unless held. Unmaps the
/// domain saw are recorded before the next access, where the C harness
/// records them as they happen, between CH12's index read and the next
/// access.
struct Chip(RefCell<State>);

impl State {
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
    fn cpu(&self) -> bool {
        self.memory[PLATFORM_ENABLE as usize] & WCPU_EN as u8 != 0
    }
    fn behavior(&self) -> Behavior {
        let index = (self.attempt.max(1) as usize).min(self.script.len());
        self.script[index - 1]
    }
    fn drain(&mut self) {
        for address in self.domain.take_unmapped() {
            let size = self
                .frames
                .remove(&address)
                .expect("unmapped before kicked");
            self.records.push([60, address as u32, size]);
        }
    }
    fn read(&mut self, register: u32, width: u32) -> u32 {
        self.drain();
        assert!(
            register as usize + width as usize <= MEMORY,
            "{register:#x}"
        );
        let mut value = self.get(register, width);
        if register == WCPU_FW_CTRL && self.cpu() {
            let behavior = self.behavior();
            self.reads += 1;
            if behavior.h2c && (self.kicks > 0 || self.reads > LAG) {
                value |= H2C_PATH_RDY;
            }
            if behavior.fwdl && self.kicks > 0 && (self.kicks > 1 || self.reads > LAG) {
                value |= FWDL_PATH_RDY;
            }
            if self.kicks >= self.expected && self.reads > LAG {
                value = (value & !WCPU_FWDL_STS_MASK)
                    | prep(behavior.status.into(), WCPU_FWDL_STS_MASK);
            }
        }
        self.records.push([width, register, value]);
        value
    }
    fn write(&mut self, register: u32, width: u32, value: u32) {
        self.drain();
        assert!(
            register as usize + width as usize <= MEMORY,
            "{register:#x}"
        );
        self.records.push([4 + width, register, value]);
        if register <= PLATFORM_ENABLE && PLATFORM_ENABLE < register + width {
            let was = self.cpu();
            self.set(register, width, value);
            if self.sticky && was {
                self.memory[PLATFORM_ENABLE as usize] |= WCPU_EN as u8;
            }
            if !was && self.cpu() {
                self.attempt += 1;
                self.kicks = 0;
                self.reads = 0;
            }
        } else if register == CH12_TXBD_IDX && width == 2 {
            self.set(register, width, value);
            self.kick(register, value);
        } else {
            self.set(register, width, value);
        }
    }
    fn kick(&mut self, register: u32, to: u32) {
        while self.host != to {
            let at = self.ch12_bd + u64::from(self.host) * TxBd::SIZE as u64;
            let bytes = self.domain.device_read(at, TxBd::SIZE);
            let bd = TxBd::decode(bytes.as_slice().try_into().unwrap());
            self.records.push([
                122,
                self.host,
                u32::from(bd.length) | u32::from(bd.opt) << 16,
            ]);
            self.records.push([123, bd.dma, 0]);
            let frame = self.domain.device_read(bd.dma.into(), bd.length.into());
            self.packets
                .extend_from_slice(&(frame.len() as u32).to_le_bytes());
            self.packets.extend_from_slice(&frame);
            self.packets
                .resize(self.packets.len().next_multiple_of(4), 0);
            self.frames.insert(bd.dma.into(), bd.length.into());
            self.host = (self.host + 1) % 256;
        }
        self.kicks += 1;
        self.reads = 0;
        if self.behavior().consume {
            self.set(register + 2, 2, to);
        }
    }
}

impl Chip {
    fn new(
        fill: Fill,
        domain: Arc<Domain>,
        ch12_bd: u64,
        script: &[Behavior],
        sticky: bool,
        expected: u32,
    ) -> Self {
        let mut memory: Vec<u8> = match fill {
            Fill::Pattern => (0..MEMORY).map(|at| (at * 37 + 11) as u8).collect(),
            Fill::Zeros => vec![0; MEMORY],
        };
        memory[CH12_TXBD_IDX as usize..CH12_TXBD_IDX as usize + 4].fill(0);
        Self(RefCell::new(State {
            memory,
            records: Vec::new(),
            packets: Vec::new(),
            script: script.to_vec(),
            sticky,
            attempt: 0,
            kicks: 0,
            reads: 0,
            host: 0,
            expected,
            domain,
            ch12_bd,
            frames: BTreeMap::new(),
        }))
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for &Chip {
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
        state.drain();
        state.records.push([9, 0, microseconds as u32]);
    }
}

/// One section of a synthetic image: its type, size, whether a checksum
/// follows, and its MSS signature count.
struct Synthetic {
    kind: u8,
    size: u32,
    checksum: bool,
    mssc: u32,
}

const fn section(kind: u8, size: u32, checksum: bool, mssc: u32) -> Synthetic {
    Synthetic {
        kind,
        size,
        checksum,
        mssc,
    }
}

/// Image A: three parts, one exactly full with its checksum, none, and a
/// security section with one signature, behind a dynamic header.
const SYN_A: [Synthetic; 4] = [
    section(2, 4041, false, 0),
    section(1, 2012, true, 0),
    section(3, 0, false, 0),
    section(9, 100, true, 1),
];
/// Image B: a checksum that spills into a second part, then one byte.
const SYN_B: [Synthetic; 2] = [section(1, 2013, true, 0), section(2, 1, false, 0)];

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// The C oracle's `synthetic`: a legacy single image of header version 0
/// whose part size field is not 2020.
fn synthetic(seed: u8, sections: &[Synthetic], dynamic: u32) -> Vec<u8> {
    let n = sections.len() as u32;
    let base = 32 + 16 * n;
    let hdr = base + dynamic;
    let total = hdr
        + sections
            .iter()
            .map(|s| s.size + if s.checksum { 8 } else { 0 } + s.mssc * 512)
            .sum::<u32>();
    let mut b = vec![0u8; total as usize];
    put32(&mut b, 0, 0x0000_8852);
    put32(&mut b, 4, 0x121d_1d00);
    put32(&mut b, 8, 0x1234_5678 ^ u32::from(seed));
    put32(&mut b, 12, if dynamic != 0 { hdr << 16 } else { 0 });
    put32(&mut b, 16, 0x2a0b_0c0d);
    put32(&mut b, 20, 2024);
    put32(&mut b, 24, n << 8 | 0x11);
    put32(
        &mut b,
        28,
        0x5a00_0000 | if dynamic != 0 { 1 << 16 } else { 0 } | 0x1234,
    );
    for (i, s) in sections.iter().enumerate() {
        let at = 32 + 16 * i;
        put32(&mut b, at, 0xb800_0000 + i as u32 * 0x10_0000);
        put32(
            &mut b,
            at + 4,
            s.size | u32::from(s.kind) << 24 | u32::from(s.checksum) << 28,
        );
        put32(&mut b, at + 8, s.mssc);
    }
    if dynamic != 0 {
        put32(&mut b, base as usize, dynamic);
        for k in 4..dynamic {
            b[(base + k) as usize] = (k * 5 + u32::from(seed)) as u8;
        }
    }
    let mut at = hdr as usize;
    for (i, s) in sections.iter().enumerate() {
        let length = s.size + if s.checksum { 8 } else { 0 };
        for k in 0..length {
            b[at + k as usize] = (k * 31 + i as u32 * 17 + u32::from(seed)) as u8;
        }
        at += length as usize;
        for k in 0..s.mssc * 512 {
            b[at + k as usize] = (k * 13 + 0x5a) as u8;
        }
        at += (s.mssc * 512) as usize;
    }
    b
}

fn syn_a() -> Vec<u8> {
    synthetic(1, &SYN_A, 16)
}

fn syn_b() -> Vec<u8> {
    synthetic(2, &SYN_B, 0)
}

/// What one download left behind.
struct Run {
    records: Vec<[u32; 3]>,
    packets: Vec<u8>,
    result: Result<Downloaded, Failure>,
    sequence: Sequence,
    attempts: u32,
}

/// [`download`] of `image` over a fresh [`Chip`], rings and channel, with
/// `before` given the channel first.
fn run_with(
    image: &AxImage<'_>,
    script: &[Behavior],
    sticky: bool,
    fill: Fill,
    before: impl FnOnce(&mut &Chip, &mut Rings, &mut Channel<'_>),
) -> Run {
    let source = Source;
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let ch12_bd = rings.tx_ring(TxChannel::Ch12).unwrap().dma;
    let chip = Chip::new(
        fill,
        domain.clone(),
        ch12_bd,
        script,
        sticky,
        packets(image) as u32,
    );
    let mut channel = Channel::new(&source, domain.clone());
    let mut io = &chip;
    before(&mut io, &mut rings, &mut channel);
    let result = download(
        &mut io,
        &mut rings,
        &mut channel,
        image,
        &FwSecure::default(),
    );
    let sequence = channel.sequence();
    drop(channel);
    let mut state = chip.0.into_inner();
    state.drain();
    release(&mut rings);
    Run {
        records: state.records,
        packets: state.packets,
        result,
        sequence,
        attempts: state.attempt,
    }
}

fn run(image: &AxImage<'_>, script: &[Behavior], sticky: bool, fill: Fill) -> Run {
    run_with(image, script, sticky, fill, |_, _, _| {})
}

/// The frames the packet stream holds, each the bytes the chip read.
fn frames(packets: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < packets.len() {
        let length = u32::from_le_bytes(packets[at..at + 4].try_into().unwrap()) as usize;
        out.push(&packets[at + 4..at + 4 + length]);
        at += 4 + length.next_multiple_of(4);
    }
    out
}

fn r(width: u32, register: u32, value: u32) -> [u32; 3] {
    [width, register, value]
}
fn w(width: u32, register: u32, value: u32) -> [u32; 3] {
    [4 + width, register, value]
}
fn delay(microseconds: u32) -> [u32; 3] {
    [9, 0, microseconds]
}
fn bd(index: u32, length: u32, dma: u32) -> [[u32; 3]; 2] {
    [
        [122, index, length | u32::from(TXBD_OPT_LS) << 16],
        [123, dma, 0],
    ]
}

/// The first command buffer's address in the test domain, after the two
/// BD pools and the 512 RX buffers, and the step between buffers.
const CMD_DMA: u32 = 0x8060_0000;
const CMD_STEP: u32 = 0x3000;

#[test]
fn a_download_makes_rtw89s_accesses_and_packets_in_its_order() {
    let image = syn_b();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    let run = run(&parsed.image, &[OK], false, Fill::Zeros);
    assert_eq!(
        run.result,
        Ok(Downloaded {
            retried: [None; 4],
            packets: 4
        })
    );
    let header = 24 + 8 + 64;
    let mut expected = vec![
        // rtw89_mac_disable_cpu_ax
        r(4, PLATFORM_ENABLE, 0),
        w(4, PLATFORM_ENABLE, 0),
        r(4, WCPU_FW_CTRL, 0),
        w(4, WCPU_FW_CTRL, 0),
        r(4, SYS_CLK_CTRL, 0),
        w(4, SYS_CLK_CTRL, 0),
        r(4, PLATFORM_ENABLE, 0),
        w(4, PLATFORM_ENABLE, 0),
        r(4, PLATFORM_ENABLE, 0),
        w(4, PLATFORM_ENABLE, APB_WRAP_EN),
        r(4, PLATFORM_ENABLE, APB_WRAP_EN),
        w(4, PLATFORM_ENABLE, APB_WRAP_EN),
        r(4, PLATFORM_ENABLE, APB_WRAP_EN),
        w(4, PLATFORM_ENABLE, APB_WRAP_EN | PLATFORM_EN),
        // rtw89_mac_enable_cpu_ax
        r(4, PLATFORM_ENABLE, APB_WRAP_EN | PLATFORM_EN),
        w(4, UDM1, 0),
        w(4, UDM2, 0),
        w(4, HALT_H2C_CTRL, 0),
        w(4, HALT_C2H_CTRL, 0),
        w(4, HALT_H2C, 0),
        w(4, HALT_C2H, 0),
        r(4, SYS_CLK_CTRL, 0),
        w(4, SYS_CLK_CTRL, CPU_CLK_EN),
        r(4, WCPU_FW_CTRL, 0),
        w(4, WCPU_FW_CTRL, WCPU_FWDL_EN),
        r(4, SEC_CTRL, 0),
        w(4, SEC_CTRL, 0x2_0000),
        r(2, BOOT_REASON, 0),
        w(2, BOOT_REASON, 0),
        r(4, PLATFORM_ENABLE, APB_WRAP_EN | PLATFORM_EN),
        w(4, PLATFORM_ENABLE, APB_WRAP_EN | WCPU_EN | PLATFORM_EN),
        // The H2C path, ready on the third read.
        r(1, WCPU_FW_CTRL, WCPU_FWDL_EN),
        delay(1),
        r(1, WCPU_FW_CTRL, WCPU_FWDL_EN),
        delay(1),
        r(1, WCPU_FW_CTRL, WCPU_FWDL_EN | H2C_PATH_RDY),
        // The header: CH12's reclaim, then its kick.
        r(4, CH12_TXBD_IDX, 0),
        w(2, CH12_TXBD_IDX, 1),
    ];
    expected.extend(bd(0, header, CMD_DMA));
    let ready = WCPU_FWDL_EN | H2C_PATH_RDY;
    expected.extend([
        // The download path.
        r(1, WCPU_FW_CTRL, ready),
        delay(1),
        r(1, WCPU_FW_CTRL, ready),
        delay(1),
        r(1, WCPU_FW_CTRL, ready | FWDL_PATH_RDY),
        w(4, HALT_H2C_CTRL, 0),
        w(4, HALT_C2H_CTRL, 0),
    ]);
    // Section 0's 2021 bytes, checksum included, in 2020 and 1; then
    // section 1's single byte. The chip read each BD as it was kicked.
    for (index, length) in [(1, 24 + 2020), (2, 25), (3, 25)] {
        expected.extend([
            r(4, CH12_TXBD_IDX, index << 16 | index),
            w(2, CH12_TXBD_IDX, index + 1),
        ]);
        expected.extend(bd(index, length, CMD_DMA + CMD_STEP * index));
    }
    let ready = ready | FWDL_PATH_RDY;
    expected.extend([
        delay(5000),
        // FREERTOS_DONE on the third read.
        r(1, WCPU_FW_CTRL, ready),
        delay(1),
        r(1, WCPU_FW_CTRL, ready),
        delay(1),
        r(1, WCPU_FW_CTRL, ready | WCPU_FWDL_STS_MASK),
    ]);
    assert_eq!(run.records, expected);
    assert_eq!(run.sequence, Sequence(0));

    let frames = frames(&run.packets);
    assert_eq!(frames.len(), 4);
    // The header: no FW_DL, then the H2C header at sequence 0 asking for
    // no ack, then the base header with W7's part size set to 2020.
    let desc = txwd::DescInfo::fwcmd((HEADER_LEN + 64) as u32, false);
    assert_eq!(frames[0][..24], desc.body());
    let h2c = Header::decode(frames[0][24..32].try_into().unwrap());
    assert_eq!(h2c.function(), h2c::FWHDR_DL);
    assert_eq!((h2c.seq(), h2c.total_len()), (0, 72));
    assert!(!h2c.rec_ack() && !h2c.done_ack());
    let mut tweaked = image[..64].to_vec();
    tweaked[28..32].copy_from_slice(&0x5a00_07e4u32.to_le_bytes());
    assert_eq!(frames[0][32..], tweaked);
    // The parts: FW_DL, no header.
    let sections = &parsed.image.sections;
    for (frame, payload) in frames[1..].iter().zip([
        &sections[0].data[..2020],
        &sections[0].data[2020..],
        sections[1].data,
    ]) {
        let desc = txwd::DescInfo::fwcmd(payload.len() as u32, true);
        assert_eq!(frame[..24], desc.body());
        assert_eq!(&frame[24..], payload);
    }
}

#[test]
fn sections_go_out_whole_in_parts_of_2020_bytes_and_signatures_stay_behind() {
    let image = syn_a();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    assert_eq!(parsed.image.part_bytes, FWDL_SECTION_PER_PKT_LEN);
    assert_eq!(packets(&parsed.image), 6);
    let run = run(&parsed.image, &[OK], false, Fill::Pattern);
    assert_eq!(run.result.map(|done| done.packets), Ok(6));
    let frames = frames(&run.packets);
    assert_eq!(
        frames.iter().map(|frame| frame.len()).collect::<Vec<_>>(),
        [
            H2C_DESC_SIZE + HEADER_LEN + 96,
            H2C_DESC_SIZE + 2020,
            H2C_DESC_SIZE + 2020,
            H2C_DESC_SIZE + 1,
            H2C_DESC_SIZE + 2020,
            H2C_DESC_SIZE + 108,
        ]
    );
    // The header leaves the 16-byte dynamic header out.
    let mut tweaked = image[..96].to_vec();
    tweaked[28..32].copy_from_slice(&0x5a01_07e4u32.to_le_bytes());
    assert_eq!(frames[0][H2C_DESC_SIZE + HEADER_LEN..], tweaked);
    let mut header = [0; MAX_BASE_HEADER];
    assert_eq!(tweak_header(&parsed.image, &mut header), 96);
    assert_eq!(header[..96], tweaked);
    // The parts are the sections' bytes in order, checksums included; the
    // empty section sends nothing, and the security section's signature
    // is not sent.
    let sent: Vec<u8> = frames[1..]
        .iter()
        .flat_map(|frame| frame[H2C_DESC_SIZE..].iter().copied())
        .collect();
    let sections: Vec<u8> = parsed
        .image
        .sections
        .iter()
        .flat_map(|section| section.data.iter().copied())
        .collect();
    assert_eq!(sent, sections);
    let security = &parsed.image.sections[3];
    assert_eq!(security.kind, FWDL_SECURITY_SECTION_TYPE);
    assert_eq!((security.data.len(), security.signatures.len()), (108, 512));
    assert_eq!(
        sent.len() + 96 + 16 + 512,
        image.len(),
        "everything but the dynamic header and the signature"
    );
}

#[test]
fn the_header_carries_the_current_sequence_and_the_download_sets_it_back_to_0() {
    let image = syn_b();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    let run = run_with(
        &parsed.image,
        &[OK],
        false,
        Fill::Pattern,
        |io, rings, channel| {
            let command = channel.command(0x01, 0x02, false, false, &[1, 2, 3, 4]);
            channel.send(io, rings, &command).unwrap();
        },
    );
    assert!(run.result.is_ok());
    let frames = frames(&run.packets);
    let h2c = Header::decode(frames[1][24..32].try_into().unwrap());
    assert_eq!(h2c.function(), h2c::FWHDR_DL);
    assert_eq!(h2c.seq(), 1);
    assert_eq!(run.sequence, Sequence(0));
}

/// The reads of `register`, `width` bytes wide, in `records`.
fn poll_reads(records: &[[u32; 3]], width: u32, register: u32) -> usize {
    records
        .iter()
        .filter(|record| record[..2] == [width, register])
        .count()
}

#[test]
fn a_failed_attempt_is_retried_and_its_timeout_names_the_path() {
    let image = syn_a();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    let run = run(&parsed.image, &[NO_H2C, OK], false, Fill::Pattern);
    let done = run.result.unwrap();
    assert_eq!(done.packets, 6);
    let first = done.retried[0].unwrap();
    assert_eq!(
        first.error,
        Error::Io(io::Error::Timeout {
            register: WCPU_FW_CTRL,
            mask: H2C_PATH_RDY
        })
    );
    let dump = first.dump.unwrap().unwrap();
    // The program counter reads are of one unchanging register here.
    assert!(dump.pc.iter().all(|&pc| pc == dump.pc[0]));
    assert_eq!(dump.wcpu_fw_ctrl & H2C_PATH_RDY, 0);
    assert_eq!(done.retried[1..], [None; 3]);
    assert_eq!(run.attempts, 2);
    // The first attempt polled FWDL_WAIT_CNT steps and read once more; its
    // dump read the program counter fifteen times, 10 us apart.
    // Each attempt clears UDM1 once, after its CPU was disabled.
    let starts: Vec<usize> = run
        .records
        .iter()
        .enumerate()
        .filter(|(_, record)| **record == w(4, UDM1, 0))
        .map(|(at, _)| at)
        .collect();
    assert_eq!(starts.len(), 2);
    let first_attempt = &run.records[starts[0]..starts[1]];
    assert_eq!(
        poll_reads(first_attempt, 1, WCPU_FW_CTRL),
        FWDL_WAIT_CNT as usize + 1
    );
    assert_eq!(
        first_attempt
            .iter()
            .filter(|record| **record == delay(1))
            .count(),
        FWDL_WAIT_CNT as usize
    );
    assert_eq!(poll_reads(first_attempt, 4, DBG_PORT_SEL), PROG_CNT_READS);
    assert_eq!(
        first_attempt
            .iter()
            .filter(|record| **record == delay(10))
            .count(),
        PROG_CNT_READS
    );
    // No packet went out before the H2C path was ready.
    assert_eq!(frames(&run.packets).len(), 6);
}

#[test]
fn a_download_path_that_never_comes_up_is_named_too() {
    let image = syn_b();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    let run = run(&parsed.image, &[NO_FWDL, OK], false, Fill::Pattern);
    let done = run.result.unwrap();
    assert_eq!(
        done.retried[0].unwrap().error,
        Error::Io(io::Error::Timeout {
            register: WCPU_FW_CTRL,
            mask: FWDL_PATH_RDY
        })
    );
    // The header went out in each attempt, the parts only in the second.
    assert_eq!(frames(&run.packets).len(), 1 + 4);
}

#[test]
fn five_failed_attempts_return_each_ones_error_and_dump() {
    let image = syn_b();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    let run = run(
        &parsed.image,
        &[status(1), status(2), status(3), status(4), status(6)],
        false,
        Fill::Pattern,
    );
    let Err(Failure::Attempts(attempts)) = run.result else {
        panic!("{:?}", run.result);
    };
    assert_eq!(
        attempts.map(|attempt| attempt.error),
        [
            Error::UnexpectedStatus(1),
            Error::ChecksumFail,
            Error::SecurityFail,
            Error::CvNotMatch,
            Error::UnexpectedStatus(6),
        ]
    );
    for (attempt, status) in attempts.iter().zip([1, 2, 3, 4, 6]) {
        let dump = attempt.dump.unwrap().unwrap();
        assert_eq!(field(dump.wcpu_fw_ctrl, WCPU_FWDL_STS_MASK), status);
    }
    assert_eq!(run.attempts, 5);
    assert_eq!(frames(&run.packets).len(), 5 * 4);
    // The sequence went back to 0 before each status poll.
    assert_eq!(run.sequence, Sequence(0));
}

#[test]
fn check_rdy_decodes_the_status_it_gave_up_on() {
    for status in 0..=7u8 {
        let model = Model::zeroed(0, 0, false);
        // Every other bit set, which the status field leaves out.
        model.set(WCPU_FW_CTRL, 4, u32::from(status) << 5 | 0xffff_ff1f);
        let mut io = &model;
        let result = check_rdy(&mut io);
        let expected = match status {
            7 => Ok(()),
            2 => Err(Error::ChecksumFail),
            3 => Err(Error::SecurityFail),
            4 => Err(Error::CvNotMatch),
            other => Err(Error::UnexpectedStatus(other)),
        };
        assert_eq!(result, expected, "{status}");
        let log = model.log();
        let reads = if status == 7 {
            1
        } else {
            FWDL_WAIT_CNT as usize + 1
        };
        assert_eq!(log.len(), 2 * reads - 1, "{status}");
        assert_eq!(get_rdy(&mut io), Ok(status));
    }
}

#[test]
fn a_wcpu_that_stays_enabled_is_refused_five_times_without_a_dump() {
    let image = syn_b();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    let run = run(&parsed.image, &[OK], true, Fill::Pattern);
    let Err(Failure::Attempts(attempts)) = run.result else {
        panic!("{:?}", run.result);
    };
    for attempt in attempts {
        assert_eq!(
            attempt,
            Attempt {
                error: Error::CpuEnabled,
                dump: None
            }
        );
    }
    assert!(run.packets.is_empty());
    // Each attempt stopped at PLATFORM_ENABLE's read.
    assert_eq!(
        run.records
            .iter()
            .filter(|record| record[..2] == [8, UDM1])
            .count(),
        0
    );
}

#[test]
fn a_ch12_with_no_free_bd_fails_each_attempt_as_enospc() {
    let image = syn_b();
    let parsed = Rtw89::parse(&image, 2).unwrap();
    // 254 commands the chip never reads leave one free BD: the header takes
    // it, and the first part finds none.
    let run = run_with(
        &parsed.image,
        &[hold(FWDL_WCPU_FW_INIT_RDY)],
        false,
        Fill::Pattern,
        |io, rings, channel| {
            for _ in 0..254 {
                let command = channel.command(0x08, 0, false, false, &[]);
                channel.send(io, rings, &command).unwrap();
            }
        },
    );
    let Err(Failure::Attempts(attempts)) = run.result else {
        panic!("{:?}", run.result);
    };
    for attempt in attempts {
        assert_eq!(attempt.error, Error::H2c(h2c::Error::NoResource));
        assert!(matches!(attempt.dump, Some(Ok(_))));
    }
    let frames = frames(&run.packets);
    assert_eq!(frames.len(), 255);
    // The header carried the sequence the commands left, which stays.
    let h2c = Header::decode(frames[254][24..32].try_into().unwrap());
    assert_eq!((h2c.function(), h2c.seq()), (h2c::FWHDR_DL, 254));
    assert_eq!(run.sequence, Sequence(254));
}

#[test]
fn secure_boot_and_unsendable_images_are_refused_before_any_access() {
    let image = syn_b();
    let mut parsed = Rtw89::parse(&image, 2).unwrap();
    let source = Source;
    let domain = Domain::new(Placement::Oracle);
    let mut rings = new_rings(&domain);
    let model = Model::zeroed(0, 0, false);
    let mut io = &model;
    let mut channel = Channel::new(&source, domain.clone());

    let secure = FwSecure::recognize(Ok([0xff, 0x7f]));
    assert!(secure.secure_boot);
    assert_eq!(
        download(&mut io, &mut rings, &mut channel, &parsed.image, &secure),
        Err(Failure::SecureBoot(secure))
    );
    parsed.image.part_bytes = 0;
    assert_eq!(
        download(
            &mut io,
            &mut rings,
            &mut channel,
            &parsed.image,
            &FwSecure::default()
        ),
        Err(Failure::Image {
            part_bytes: 0,
            header_bytes: 64
        })
    );
    assert!(model.log().is_empty());
    assert_eq!(rings.fwcmd(), (0, 0));
    drop(channel);
    release(&mut rings);
}

#[test]
fn secure_boot_is_decided_as_rtw89_efuse_read_fw_secure_ax_decides() {
    let off = FwSecure::default();
    assert_eq!(
        FwSecure::recognize(Err(io::Error::Timeout {
            register: 0x30,
            mask: 0
        })),
        off
    );
    // (b1, b2): v0, v1.
    for (efuse, v0, v1) in [
        // Blank: neither recognizer runs.
        ([0xff, 0xff], false, false),
        // The OTP key table's two entries; b1 0xff is device type 0xf.
        ([0xff, 0x7f], true, true),
        ([0xff, 0x6e], true, true),
        ([0xff, 0xee], true, true),
        ([0xff, 0x00], false, true),
        ([0xfe, 0x7f], false, false),
        ([0x00, 0x00], false, false),
        // Known device types in b1's low nibble.
        ([0x3c, 0x00], false, true),
        ([0x16, 0x5a], false, true),
        ([0x29, 0x12], false, true),
        ([0x4a, 0x00], false, true),
        ([0x1b, 0x00], false, false),
        ([0x05, 0x7f], false, false),
    ] {
        let sec = FwSecure::recognize(Ok(efuse));
        assert_eq!(
            sec,
            FwSecure {
                efuse: Some(efuse),
                can_mss_v0: v0,
                can_mss_v1: v1,
                secure_boot: v0 || v1,
            },
            "{efuse:02x?}"
        );
    }
}

/// The oracle's record compression: a pair of records repeated back to back
/// is kept once, followed by (12, further repeats, 0).
fn rle(records: &[[u32; 3]]) -> Vec<[u32; 3]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < records.len() {
        if i + 3 < records.len() && records[i] == records[i + 2] && records[i + 1] == records[i + 3]
        {
            let mut j = i + 2;
            let mut repeats = 0;
            while j + 1 < records.len()
                && records[j] == records[i]
                && records[j + 1] == records[i + 1]
            {
                repeats += 1;
                j += 2;
            }
            out.extend([records[i], records[i + 1], [12, repeats, 0]]);
            i = j;
        } else {
            out.push(records[i]);
            i += 1;
        }
    }
    out
}

#[test]
fn the_compression_keeps_a_repeated_pair_once() {
    let a = [1, 2, 3];
    let b = [4, 5, 6];
    let c = [7, 8, 9];
    assert_eq!(rle(&[a, b, a, b, a, b, c]), [a, b, [12, 2, 0], c]);
    assert_eq!(rle(&[a, b, a, c]), [a, b, a, c]);
    assert_eq!(rle(&[a, a, a, a, a]), [a, a, [12, 1, 0], a]);
}

fn bytes(records: &[[u32; 3]]) -> Vec<u8> {
    let mut trace = Vec::new();
    for &[tag, a, b] in records {
        push(&mut trace, tag, a, b);
    }
    trace
}

/// The C oracle's version codes for the feature segment.
const VERSIONS: [u32; 22] = [
    0,
    ver_code(0, 29, 25, 255),
    ver_code(0, 29, 26, 0),
    ver_code(0, 29, 28, 255),
    ver_code(0, 29, 29, 0),
    ver_code(0, 29, 29, 6),
    ver_code(0, 29, 29, 7),
    ver_code(0, 29, 29, 14),
    ver_code(0, 29, 29, 15),
    ver_code(0, 29, 29, 18),
    ver_code(0, 29, 29, 255),
    ver_code(0, 29, 30, 0),
    ver_code(0, 29, 126, 255),
    ver_code(0, 29, 127, 0),
    ver_code(0, 29, 127, 255),
    ver_code(0, 29, 128, 0),
    ver_code(0, 29, 129, 0),
    ver_code(0, 29, 130, 0),
    ver_code(0, 29, 255, 255),
    ver_code(0, 30, 0, 0),
    ver_code(1, 0, 0, 0),
    u32::MAX,
];

/// The feature bits in [`Feature`]'s order and their count from bit 16,
/// where the C oracle counts every bit rtw89's map holds.
fn feature_word(features: Features) -> u32 {
    u32::from(features.bits()) | features.bits().count_ones() << 16
}

#[derive(Clone, Copy, Debug)]
enum Image {
    SynA,
    SynB,
    Pinned,
}

/// One download of the C oracle's, in its order.
struct Case {
    image: Image,
    cut: u8,
    sticky: bool,
    script: &'static [Behavior],
}

const CASES: [Case; 10] = [
    Case {
        image: Image::SynA,
        cut: 2,
        sticky: false,
        script: &[OK],
    },
    Case {
        image: Image::SynB,
        cut: 2,
        sticky: false,
        script: &[OK],
    },
    Case {
        image: Image::Pinned,
        cut: 1,
        sticky: false,
        script: &[OK],
    },
    Case {
        image: Image::Pinned,
        cut: 2,
        sticky: false,
        script: &[OK],
    },
    Case {
        image: Image::SynA,
        cut: 2,
        sticky: false,
        script: &[NO_H2C, OK],
    },
    Case {
        image: Image::SynA,
        cut: 2,
        sticky: false,
        script: &[NO_FWDL, status(2), status(3), status(4), OK],
    },
    Case {
        image: Image::SynB,
        cut: 2,
        sticky: false,
        script: &[status(1)],
    },
    Case {
        image: Image::SynB,
        cut: 2,
        sticky: false,
        script: &[status(0), status(5), status(6), status(2), status(4)],
    },
    Case {
        image: Image::SynB,
        cut: 2,
        sticky: true,
        script: &[OK],
    },
    Case {
        image: Image::Pinned,
        cut: 2,
        sticky: false,
        script: &[hold(0), hold(FWDL_WCPU_FW_INIT_RDY)],
    },
];

/// The return rtw89 gives for an attempt's error.
fn errno(error: Error) -> i32 {
    match error {
        Error::CpuEnabled => -14,
        Error::Io(io::Error::Timeout { .. }) => -110,
        Error::H2c(h2c::Error::NoResource) => -28,
        Error::ChecksumFail | Error::SecurityFail | Error::CvNotMatch => -22,
        Error::UnexpectedStatus(_) => -16,
        other => panic!("the model refuses nothing: {other:?}"),
    }
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_IMAGES, STELA_RTW89_FWDL_ORACLE"]
fn fwdl_packets_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_FWDL_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let images = std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap());
    let pinned = std::fs::read(images.join("rtw89/rtw8852b_fw-2.bin")).unwrap();
    let mut offset = 0;

    // rtw89_efuse_read_fw_secure_ax over every pair of efuse bytes.
    let mut expected = Vec::new();
    for base in (0..0x1_0000u32).step_by(32) {
        let (mut secure, mut v0, mut v1) = (0, 0, 0);
        for k in 0..32 {
            let pair = base + k;
            let sec = FwSecure::recognize(Ok([(pair >> 8) as u8, pair as u8]));
            secure |= u32::from(sec.secure_boot) << k;
            v0 |= u32::from(sec.can_mss_v0) << k;
            v1 |= u32::from(sec.can_mss_v1) << k;
        }
        push(&mut expected, 140, base, secure);
        push(&mut expected, 141, base, v0);
        push(&mut expected, 142, base, v1);
    }
    // A failed read: the harness's -ETIMEDOUT, and every flag clear.
    let failed = FwSecure::recognize(Err(io::Error::Timeout {
        register: 0x30,
        mask: 0,
    }));
    push(
        &mut expected,
        143,
        -110i32 as u32,
        u32::from(failed.secure_boot)
            | u32::from(failed.can_mss_v0) << 1
            | u32::from(failed.can_mss_v1) << 2,
    );
    assert_eq!(segment(&trace, &mut offset), expected, "secure boot");

    // The feature rows by version, then the pinned image's suits.
    let mut expected = Vec::new();
    for version in VERSIONS {
        push(
            &mut expected,
            150,
            version,
            feature_word(Features::of(version)),
        );
    }
    for cut in [1, 2] {
        let parsed = Rtw89::parse(&pinned, cut).unwrap();
        push(
            &mut expected,
            151,
            cut.into(),
            feature_word(Features::of_image(&parsed.image)),
        );
    }
    assert_eq!(segment(&trace, &mut offset), expected, "features");

    // The downloads.
    let (a, b) = (syn_a(), syn_b());
    for (index, case) in CASES.iter().enumerate() {
        let bytes_of = match case.image {
            Image::SynA => &a,
            Image::SynB => &b,
            Image::Pinned => &pinned,
        };
        let parsed = Rtw89::parse(bytes_of, case.cut).unwrap();
        let mut run = run(&parsed.image, case.script, case.sticky, Fill::Pattern);
        let (ret, ready) = match run.result {
            Ok(_) => (0, true),
            Err(Failure::Attempts(attempts)) => {
                (errno(attempts[DOWNLOAD_ATTEMPTS - 1].error), false)
            }
            Err(other) => panic!("case {index}: {other:?}"),
        };
        run.records.push([11, 0, ret as u32]);
        run.records.push([127, run.sequence.0.into(), 0]);
        run.records.push([128, ready.into(), 0]);
        let records = bytes(&rle(&run.records));
        assert!(
            segment(&trace, &mut offset) == records.as_slice(),
            "case {index}: accesses"
        );
        assert!(
            segment(&trace, &mut offset) == run.packets.as_slice(),
            "case {index}: packets"
        );
    }
    assert_eq!(offset, trace.len());
}
