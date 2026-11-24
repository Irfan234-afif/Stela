use super::*;
use crate::wifi::realtek::ax::{
    efuse::tests::{Case, Model, PHYCAP_OK, mailbox},
    pci::tests::{Access, r8, r32, w8, w32},
    registers::CHIP_CBV,
};
use alloc::vec::Vec;

/// A model whose firmware takes every H2C and answers `c2h`, with MAC space
/// zeroed.
fn model(c2h: Option<[u32; 4]>) -> Model {
    let mut case = Case::blank(CHIP_CBV);
    case.c2h = c2h;
    Model::zeroed(&case)
}

const GET_FEATURE: H2cReg = H2cReg {
    id: 3,
    content_len: 0,
    regs: [0; 4],
};

#[test]
fn an_exchange_makes_rtw89s_accesses_in_its_order() {
    let mut io = model(Some(PHYCAP_OK));
    let mut opened = mailbox();
    let info = H2cReg {
        id: 3,
        content_len: 0,
        regs: [0x00ab_0000, 0x1111_1111, 0x2222_2222, 0x3333_3333],
    };
    assert_eq!(
        opened.exchange(&mut io, &info),
        Ok(C2hReg {
            id: 3,
            content_len: 14,
            regs: PHYCAP_OK,
        })
    );
    assert_eq!(
        io.log,
        [
            // rtw89_fw_write_h2c_reg: the function and the length in words
            // replace the first word's header bits; the rest is sent as given.
            r8(H2CREG_CTRL, 0),
            w32(H2CREG_DATA0, 0x00ab_0103),
            w32(H2CREG_DATA1, 0x1111_1111),
            w32(H2CREG_DATA2, 0x2222_2222),
            w32(H2CREG_DATA3, 0x3333_3333),
            r8(UDM1 + 1, 0),
            w8(UDM1 + 1, 0x01),
            w8(H2CREG_CTRL, 1),
            // rtw89_fw_read_c2h_reg
            r8(C2HREG_CTRL, 1),
            r32(C2HREG_DATA0, PHYCAP_OK[0]),
            r32(C2HREG_DATA1, PHYCAP_OK[1]),
            r32(C2HREG_DATA2, PHYCAP_OK[2]),
            r32(C2HREG_DATA3, PHYCAP_OK[3]),
            w8(C2HREG_CTRL, 0),
            r8(UDM1 + 1, 0x01),
            w8(UDM1 + 1, 0x11),
        ]
    );
}

#[test]
fn each_exchange_is_counted_in_its_udm1_nibble_and_the_counters_wrap_as_bytes() {
    let mut io = model(Some(PHYCAP_OK));
    let mut counted = mailbox();
    for _ in 0..17 {
        counted.exchange(&mut io, &GET_FEATURE).unwrap();
    }
    // The 17th of each: 17 in a byte, 1 in each nibble.
    assert_eq!((counted.h2c_counter(), counted.c2h_counter()), (17, 17));
    assert_eq!(io.get(UDM1 + 1, 1), 0x11);

    // Each counter's write keeps the other nibble.
    let mut io = model(Some(PHYCAP_OK));
    io.write8(UDM1 + 1, 0xa0).unwrap();
    let mut kept = mailbox();
    kept.write_h2c(&mut io, &GET_FEATURE).unwrap();
    assert_eq!(io.get(UDM1 + 1, 1), 0xa1);
    io.write8(UDM1 + 1, 0x0b).unwrap();
    kept.read_c2h(&mut io, 0).unwrap();
    assert_eq!(io.get(UDM1 + 1, 1), 0x1b);

    // The 256th H2C counts 0.
    let mut io = model(None);
    let mut wrapped = mailbox();
    for _ in 0..256 {
        wrapped.write_h2c(&mut io, &GET_FEATURE).unwrap();
    }
    assert_eq!(wrapped.h2c_counter(), 0);
    assert_eq!(io.get(UDM1 + 1, 1), 0x00);
}

#[test]
fn the_length_counts_words_header_included() {
    for (content_len, len) in [(0u8, 1u32), (2, 1), (3, 2), (6, 2), (7, 3), (14, 4)] {
        let mut io = model(None);
        let info = H2cReg {
            id: 0x7f,
            content_len,
            regs: [0xffff_ffff, 0, 0, 0],
        };
        mailbox().write_h2c(&mut io, &info).unwrap();
        // FUNC (bits 6:0) and LEN (bits 11:8) replaced, bit 7 and the rest
        // kept.
        assert_eq!(
            io.log[1],
            w32(H2CREG_DATA0, 0xffff_f0ff | len << 8),
            "{content_len}"
        );
    }
    // A C2H's content length is its LEN in words, less the header, in a byte.
    for (w0, id, content_len) in [(0x0000_0403u32, 3u8, 14u8), (0x0000_0081, 1, 254)] {
        let mut io = model(Some([w0, 0, 0, 0]));
        io.write8(H2CREG_CTRL, H2CREG_TRIGGER).unwrap();
        let c2h = mailbox().read_c2h(&mut io, 0).unwrap();
        assert_eq!((c2h.id, c2h.content_len), (id, content_len), "{w0:#x}");
    }
}

fn reads(log: &[Access], register: u32) -> usize {
    log.iter()
        .filter(|access| matches!(access, Access::Read { register: at, .. } if *at == register))
        .count()
}

#[test]
fn a_firmware_that_never_takes_or_answers_is_a_timeout_naming_the_control_register() {
    // H2CREG_CTRL never clears: read every 1000 us for up to 5000 us, then
    // nothing written and nothing counted.
    let mut case = Case::blank(CHIP_CBV);
    case.h2c_busy = true;
    let mut io = Model::zeroed(&case);
    let mut busy = mailbox();
    assert_eq!(
        busy.exchange(&mut io, &GET_FEATURE),
        Err(io::Error::Timeout {
            register: H2CREG_CTRL,
            mask: 0xff,
        })
    );
    let mut expected = Vec::new();
    for poll in 0..6 {
        if poll > 0 {
            expected.push(Access::Delay(1000));
        }
        expected.push(r8(H2CREG_CTRL, 1));
    }
    assert_eq!(io.log, expected);
    assert_eq!(busy.h2c_counter(), 0);

    // No C2H within a bound the caller gives: 11 reads 1 us apart for 10 us,
    // C2HREG_CTRL left alone and nothing counted.
    let mut io = model(None);
    let mut silent = mailbox();
    io.write8(H2CREG_CTRL, H2CREG_TRIGGER).unwrap();
    io.log.clear();
    assert_eq!(
        silent.read_c2h(&mut io, 10),
        Err(io::Error::Timeout {
            register: C2HREG_CTRL,
            mask: 0xff,
        })
    );
    assert_eq!(reads(&io.log, C2HREG_CTRL), 11);
    assert_eq!(io.log.len(), 21);
    assert_eq!(silent.c2h_counter(), 0);

    // The default bound is RTW89_C2H_TIMEOUT.
    let mut io = model(None);
    io.logging = false;
    assert!(silent.read_c2h(&mut io, 0).is_err());
    assert_eq!(io.waited_us, C2H_TIMEOUT);
}
