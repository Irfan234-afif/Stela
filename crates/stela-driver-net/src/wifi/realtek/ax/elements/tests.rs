extern crate std;

use super::super::pci::tests::segment;
use super::*;
use crate::wifi::realtek::firmware::Rtw89;
use alloc::{format, string::ToString, vec, vec::Vec};

const VER: [u8; 4] = [1, 2, 3, 4];

/// A `struct rtw89_fw_element_hdr` and its body; `size` stands in for the
/// body's length when given.
fn element(id: u32, fixed: [u8; 8], body: &[u8], aid: u16, size: Option<u32>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&size.unwrap_or(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&VER);
    out.extend_from_slice(&aid.to_le_bytes());
    out.extend_from_slice(&[0; 10]);
    out.extend_from_slice(&fixed);
    out.extend_from_slice(body);
    out
}

fn plain(id: Id, body: &[u8]) -> Vec<u8> {
    element(id as u32, [0; 8], body, 0, None)
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            (i as u8)
                .wrapping_mul(37)
                .wrapping_add(seed.wrapping_mul(11))
                ^ 5
        })
        .collect()
}

fn regs(n: u32, seed: u32) -> Vec<u8> {
    (0..n)
        .flat_map(|i| {
            let mut pair = (0x4000 + 4 * i + seed * 0x100).to_le_bytes().to_vec();
            pair.extend_from_slice(&(0xa500_0000 + i * 3 + seed).to_le_bytes());
            pair
        })
        .collect()
}

fn radio(id: Id, idx: u8, n: u32, seed: u32) -> Vec<u8> {
    element(
        id as u32,
        [idx, 0, 0, 0, 0, 0, 0, 0],
        &regs(n, seed),
        0,
        None,
    )
}

fn txpwr_fixed(rfe: u8, ent_sz: u8, num: u32) -> [u8; 8] {
    let n = num.to_le_bytes();
    [0, 0, rfe, ent_sz, n[0], n[1], n[2], n[3]]
}

fn txpwr(id: Id, rfe: u8, ent_sz: u8, num: u32, seed: u8) -> Vec<u8> {
    let body = pattern(num as usize * usize::from(ent_sz), seed);
    element(id as u32, txpwr_fixed(rfe, ent_sz, num), &body, 0, None)
}

fn trk_fixed(bitmap: u32) -> [u8; 8] {
    let b = bitmap.to_le_bytes();
    [b[0], b[1], b[2], b[3], 0, 0, 0, 0]
}

fn trk(bitmap: u32, rows: usize) -> Vec<u8> {
    element(18, trk_fixed(bitmap), &pattern(rows * 30, 99), 0, None)
}

fn regd(ent_sz: u8, num: u32, body: &[u8]) -> Vec<u8> {
    element(20, txpwr_fixed(0, ent_sz, num), body, 0, None)
}

fn bbmcu(id: Id, cv: u8, hdr_ver: u8) -> Vec<u8> {
    let mut body = pattern(48, cv);
    body[15] = hdr_ver;
    element(id as u32, [cv, 0, 0, 0, 0, 0, 0, 0], &body, 0, None)
}

/// An MFW container of one 37-byte entry, then the pieces, each at the
/// next 16-byte boundary of the file.
fn container(pieces: &[Vec<u8>]) -> Vec<u8> {
    let mut file = vec![0xff, 1, 0, 0, 0, 29, 29, 18, 0, 0, 0, 0, 0, 0, 0, 0];
    file.extend_from_slice(&[1, 5, 0, 0]);
    file.extend_from_slice(&32u32.to_le_bytes());
    file.extend_from_slice(&37u32.to_le_bytes());
    file.extend_from_slice(&[0; 4]);
    file.extend_from_slice(&pattern(37, 2));
    for piece in pieces {
        file.resize(file.len().next_multiple_of(16), 0);
        file.extend_from_slice(piece);
    }
    file
}

/// Every element of RTL8852B's `needed_fw_elms`, RFE type 0, in the
/// order [`NEEDED_ORDER`] names.
fn required() -> Vec<Vec<u8>> {
    vec![
        plain(Id::BbReg, &regs(4, 1)),
        radio(Id::RadioA, 0, 3, 2),
        radio(Id::RadioB, 1, 3, 3),
        plain(Id::RfNctl, &regs(2, 4)),
        trk(0xfff0, 20),
        txpwr(Id::TxpwrByrate, 0, 9, 2, 5),
        txpwr(Id::TxpwrLmt2ghz, 0, 7, 3, 6),
        txpwr(Id::TxpwrLmt5ghz, 0, 7, 3, 7),
        txpwr(Id::TxpwrLmtRu2ghz, 0, 5, 2, 8),
        txpwr(Id::TxpwrLmtRu5ghz, 0, 5, 2, 9),
        txpwr(Id::TxShapeLmt, 0, 4, 2, 10),
        txpwr(Id::TxShapeLmtRu, 0, 3, 2, 11),
    ]
}

const NEEDED_ORDER: [Id; 12] = [
    Id::BbReg,
    Id::RadioA,
    Id::RadioB,
    Id::RfNctl,
    Id::TxpwrTrk,
    Id::TxpwrByrate,
    Id::TxpwrLmt2ghz,
    Id::TxpwrLmt5ghz,
    Id::TxpwrLmtRu2ghz,
    Id::TxpwrLmtRu5ghz,
    Id::TxShapeLmt,
    Id::TxShapeLmtRu,
];

/// [`container`], kept for the test's length, so tables may borrow it.
fn build(pieces: &[Vec<u8>]) -> &'static [u8] {
    Vec::leak(container(pieces))
}

/// `rtw89_mfw_get_size`.
fn mfw_size(file: &[u8]) -> usize {
    if file.first() != Some(&0xff) {
        return 0;
    }
    let last = 16 + (usize::from(file[1]) - 1) * 16;
    (le32(file, last + 4) + le32(file, last + 8)) as usize
}

fn parse_traced(file: &[u8], board: Board) -> (Result<Elements<'_>, Error>, Vec<(u32, Outcome)>) {
    let base = mfw_size(file);
    let mut seen = Vec::new();
    let result = Elements::parse(&file[base..], base, board, |element, outcome| {
        seen.push((element.id, outcome))
    });
    (result, seen)
}

fn parse(file: &[u8], board: Board) -> Result<Elements<'_>, Error> {
    parse_traced(file, board).0
}

const CARD: Board = Board::rtl8852b(1, 1);

#[test]
fn a_complete_set_builds_every_table() {
    let mut pieces = required();
    pieces.insert(0, element(31, [0; 8], &pattern(5, 1), 0, None));
    let file = container(&pieces);
    let (result, seen) = parse_traced(&file, CARD);
    let elements = result.unwrap();
    assert_eq!(seen[0], (31, Outcome::Unhandled));
    assert!(seen[1..].iter().all(|&(_, o)| o == Outcome::Recognized));
    assert_eq!(elements.recognized, RTL8852B_NEEDED);
    assert_eq!(elements.optional(), 0);
    assert_eq!(RTL8852B_NEEDED.count_ones() as usize, NEEDED_ORDER.len());

    let bb = elements.bb_tbl.unwrap();
    assert_eq!(bb.n_regs(), 4);
    assert_eq!(
        bb.reg(1),
        Some(Reg2 {
            addr: 0x4104,
            data: 0xa500_0004
        })
    );
    assert_eq!(bb.regs().count(), 4);
    assert!(!bb.radio);
    let a = elements.radio(0).unwrap();
    let b = elements.radio(1).unwrap();
    assert_eq!((a.rf_path, a.radio, a.n_regs()), (0, true, 3));
    assert_eq!((b.rf_path, b.radio, b.n_regs()), (1, true, 3));
    assert!(elements.radio(2).is_none() && elements.radio(3).is_none());
    assert!(!elements.rf_nctl.unwrap().radio);
    assert!(elements.bb_gain.is_none());

    let rfe = elements.rfe_data.unwrap();
    let byrate = rfe.conf(TxpwrSlot::Byrate).unwrap();
    assert_eq!((byrate.rfe_type, byrate.ent_sz, byrate.num_ents), (0, 9, 2));
    assert_eq!(byrate.entries().count(), 2);
    assert_eq!(byrate.entries().nth(1), Some(&pattern(18, 5)[9..]));
    assert!(rfe.conf(TxpwrSlot::Lmt6ghz).is_none());

    let trk = elements.txpwr_trk.unwrap();
    assert!((0..4).all(|ty| trk.delta[ty].is_none()));
    assert_eq!(trk.delta[4], Some(0));
    assert_eq!(trk.delta[7], Some(9));
    assert_eq!(trk.delta[8], Some(12));
    assert_eq!(trk.delta[15], Some(19));
    assert_eq!(trk.rows(4).unwrap().len(), 90);
    assert_eq!(trk.rows(8).unwrap().len(), 30);
    let contents = pattern(600, 99);
    assert_eq!(trk.delta(5, 2, 29), Some(contents[(3 + 2) * 30 + 29] as i8));
    assert_eq!(trk.delta(8, 1, 0), None);
    assert_eq!(trk.delta(0, 0, 0), None);
    assert!(elements.regd.is_none());
}

#[test]
fn firmware_without_a_needed_element_is_refused_naming_it() {
    for (index, id) in NEEDED_ORDER.into_iter().enumerate() {
        let mut pieces = required();
        pieces.remove(index);
        let error = parse(build(&pieces), CARD).unwrap_err();
        assert_eq!(error, Error::Missing { mask: id.bit() }, "{}", id.name());
        assert_eq!(error.missing().collect::<Vec<_>>(), [id]);
        assert_eq!(error.errno(), Some(-2));
        assert!(error.to_string().ends_with(&format!(": {}", id.name())));
    }
    // No elements at all.
    let error = parse(build(&[]), CARD).unwrap_err();
    assert_eq!(
        error,
        Error::Missing {
            mask: RTL8852B_NEEDED
        }
    );
    assert_eq!(error.missing().count(), 12);
}

#[test]
fn an_element_of_another_aid_is_ignored() {
    let mut pieces = required();
    pieces.insert(0, element(2, [0; 8], &regs(2, 10), 0x1234, None));
    let file = container(&pieces);
    let (result, seen) = parse_traced(&file, CARD);
    assert_eq!(seen[0], (2, Outcome::Ignored));
    // The table of AID 0 comes after and is taken.
    assert_eq!(seen[1], (2, Outcome::Recognized));
    assert_eq!(result.unwrap().bb_tbl.unwrap().n_regs(), 4);
    // A chip of that AID takes the first, and the table of AID 0 is a
    // second one.
    let board = Board {
        aid: 0x1234,
        ..CARD
    };
    let (result, seen) = parse_traced(&file, board);
    assert_eq!(
        &seen[..2],
        [(2, Outcome::Recognized), (2, Outcome::Ignored)]
    );
    assert_eq!(result.unwrap().bb_tbl.unwrap().n_regs(), 2);

    // A needed element of another AID alone is missing.
    let mut pieces = required();
    pieces[3] = element(8, [0; 8], &regs(2, 4), 7, None);
    assert_eq!(
        parse(build(&pieces), CARD).unwrap_err(),
        Error::Missing {
            mask: Id::RfNctl.bit()
        }
    );
    // TX power tables of another AID are not taken either.
    let mut pieces = required();
    pieces.push(element(9, txpwr_fixed(1, 9, 1), &pattern(9, 1), 0x55, None));
    let elements = parse(build(&pieces), CARD).unwrap();
    assert_eq!(
        elements
            .rfe_data
            .unwrap()
            .conf(TxpwrSlot::Byrate)
            .unwrap()
            .rfe_type,
        0
    );
}

#[test]
fn tx_power_tables_follow_the_rfe_type_with_rfe_0_as_the_fallback() {
    let mut pieces = required();
    pieces.splice(
        5..6,
        [
            txpwr(Id::TxpwrByrate, 0, 9, 2, 20),
            txpwr(Id::TxpwrByrate, 3, 9, 1, 21),
            txpwr(Id::TxpwrByrate, 0, 9, 3, 22),
            txpwr(Id::TxpwrByrate, 3, 9, 4, 23),
        ],
    );
    let file = container(&pieces);
    let byrate = |rfe| {
        let elements = parse(&file, Board::rtl8852b(rfe, 1)).unwrap();
        let conf = *elements.rfe_data.unwrap().conf(TxpwrSlot::Byrate).unwrap();
        (conf.rfe_type, conf.num_ents)
    };
    // The last of the board's type wins over every default.
    assert_eq!(byrate(3), (3, 4));
    // Without one, the last default.
    assert_eq!(byrate(5), (0, 3));
    assert_eq!(byrate(0), (0, 3));

    // Once the board's type is taken, a later default does not replace it.
    let mut pieces = required();
    pieces.splice(
        5..6,
        [
            txpwr(Id::TxpwrByrate, 3, 9, 1, 21),
            txpwr(Id::TxpwrByrate, 0, 9, 3, 22),
        ],
    );
    let elements = parse(build(&pieces), Board::rtl8852b(3, 1)).unwrap();
    let conf = elements.rfe_data.unwrap().confs[TxpwrSlot::Byrate as usize].unwrap();
    assert_eq!((conf.rfe_type, conf.num_ents), (3, 1));

    // An element of another type counts as recognized though nothing is
    // taken from it.
    let mut pieces = required();
    pieces[6] = txpwr(Id::TxpwrLmt2ghz, 7, 7, 2, 24);
    let elements = parse(build(&pieces), CARD).unwrap();
    assert!(elements.recognized & Id::TxpwrLmt2ghz.bit() != 0);
    assert!(
        elements
            .rfe_data
            .unwrap()
            .conf(TxpwrSlot::Lmt2ghz)
            .is_none()
    );
    let elements = parse(build(&pieces), Board::rtl8852b(7, 1)).unwrap();
    assert_eq!(
        elements
            .rfe_data
            .unwrap()
            .conf(TxpwrSlot::Lmt2ghz)
            .unwrap()
            .num_ents,
        2
    );

    // An entry stride of 0 holds no entry, whatever the count.
    let mut pieces = required();
    pieces.push(element(13, txpwr_fixed(1, 0, 5), &[], 0, None));
    pieces.push(plain(Id::DiagMac, &[0; 4]));
    let elements = parse(build(&pieces), CARD).unwrap();
    let conf = *elements
        .rfe_data
        .unwrap()
        .conf(TxpwrSlot::LmtRu2ghz)
        .unwrap();
    assert_eq!((conf.num_ents, conf.data.len()), (5, 0));
    assert_eq!(conf.entries().count(), 0);
}

#[test]
fn the_first_register_table_of_a_kind_wins_and_its_idx_picks_the_radio_slot() {
    let mut pieces = required();
    pieces[1] = radio(Id::RadioA, 1, 2, 2);
    pieces[2] = radio(Id::RadioB, 0, 5, 3);
    pieces.push(plain(Id::BbReg, &regs(1, 9)));
    pieces.push(plain(Id::BbGain, &[0x11; 20]));
    let file = container(&pieces);
    let (result, seen) = parse_traced(&file, CARD);
    let elements = result.unwrap();
    assert_eq!(seen[12], (2, Outcome::Ignored));
    assert_eq!(elements.bb_tbl.unwrap().n_regs(), 4);
    // The path follows the id, the slot the idx.
    assert_eq!(elements.radio(1).unwrap().rf_path, 0);
    assert_eq!(elements.radio(0).unwrap().rf_path, 1);
    assert_eq!(elements.radio(0).unwrap().n_regs(), 5);
    // A remainder past whole registers is dropped.
    assert_eq!(elements.bb_gain.unwrap().n_regs(), 2);
    assert_eq!(elements.optional(), Id::BbGain.bit());

    // An idx past RF_PATH_MAX: ignored for another AID, refused otherwise.
    let mut pieces = required();
    pieces.push(element(6, [4, 0, 0, 0, 0, 0, 0, 0], &regs(1, 1), 9, None));
    assert!(parse(build(&pieces), CARD).is_ok());
    let mut pieces = required();
    pieces.push(radio(Id::RadioC, 4, 1, 1));
    assert_eq!(
        parse(build(&pieces), CARD).unwrap_err(),
        Error::RadioIndex { id: 6, idx: 4 }
    );
}

#[test]
fn a_truncated_element_ends_the_walk() {
    // The needed tracking element's size reaches the file's end.
    let mut pieces = required();
    let mut last = pieces.remove(4);
    last[4..8].copy_from_slice(&640u32.to_le_bytes());
    pieces.push(last);
    let (result, seen) = parse_traced(build(&pieces), CARD);
    assert_eq!(
        result.unwrap_err(),
        Error::Missing {
            mask: Id::TxpwrTrk.bit()
        }
    );
    assert_eq!(seen.len(), 11);

    // In the middle, it hides everything after it.
    let mut pieces = required();
    pieces.insert(4, element(3, [0; 8], &regs(1, 1), 0, Some(0x10_0000)));
    let error = parse(build(&pieces), CARD).unwrap_err();
    let after = NEEDED_ORDER[4..].iter().fold(0, |mask, id| mask | id.bit());
    assert_eq!(error, Error::Missing { mask: after });

    // An optional one at the end costs nothing else.
    let mut pieces = required();
    let entry = [b'I', b'D', 1, 2, 3, 0, 0, 0, 0];
    let mut truncated = regd(9, 1, &entry);
    truncated[4..8].copy_from_slice(&64u32.to_le_bytes());
    pieces.push(truncated);
    assert!(parse(build(&pieces), CARD).unwrap().regd.is_none());

    // A size rtw89's 32-bit offset would wrap stops the walk too.
    let mut pieces = required();
    pieces.insert(4, element(31, [0; 8], &[0; 16], 0, Some(u32::MAX - 0x40)));
    assert_eq!(
        parse(build(&pieces), CARD).unwrap_err(),
        Error::Missing { mask: after }
    );
}

#[test]
fn a_misaligned_element_is_not_found() {
    // An element placed straight after one of odd size, with no padding to
    // the next boundary: the walk reads its header three bytes in, an id
    // no handler takes and a size past the file, and stops.
    let mut pieces = required();
    let nctl = pieces.remove(3);
    pieces.push(plain(Id::AfePwrSeq, &pattern(13, 3)));
    let mut file = container(&pieces);
    file.extend_from_slice(&nctl);
    let (result, seen) = parse_traced(&file, CARD);
    assert_eq!(
        result.unwrap_err(),
        Error::Missing {
            mask: Id::RfNctl.bit()
        }
    );
    assert_eq!(seen.last(), Some(&(27, Outcome::Recognized)));
    // Padded, it is found.
    pieces.push(nctl);
    assert!(parse(build(&pieces), CARD).is_ok());
}

#[test]
fn an_element_needs_a_byte_after_its_header_to_be_reached() {
    // The walk goes on while a header and one more byte fit: an empty
    // regulation element ending the file is never read.
    let mut pieces = required();
    pieces.push(regd(0, 2, &[]));
    let (result, seen) = parse_traced(build(&pieces), CARD);
    assert!(result.unwrap().regd.is_none());
    assert_eq!(seen.len(), 12);
    // With a byte after it, it is, and its entries of no size refuse the
    // firmware.
    let mut pieces = required();
    pieces.push(regd(0, 2, &[0; 3]));
    let error = parse(build(&pieces), CARD).unwrap_err();
    assert_eq!(error, Error::RegdInvalidEntries { invalid: 2 });
    assert_eq!(error.errno(), Some(-22));
    // A file ending within a header after the last element.
    let mut file = container(&required());
    file.resize(file.len().next_multiple_of(16) + 31, 0xee);
    assert!(parse(&file, CARD).is_ok());
}

#[test]
fn the_tracking_table_needs_both_bands_and_the_rows_its_types_take() {
    let mut pieces = required();
    pieces[4] = trk(0xfef0, 19);
    let error = parse(build(&pieces), CARD).unwrap_err();
    assert_eq!(
        error,
        Error::TxpwrTrkBitmap {
            needed: 0xfff0,
            bitmap: 0xfef0
        }
    );
    assert_eq!(error.errno(), Some(-2));

    pieces[4] = element(18, trk_fixed(0xfff0), &pattern(599, 3), 0, None);
    let (result, seen) = parse_traced(build(&pieces), CARD);
    let error = result.unwrap_err();
    assert_eq!(
        error,
        Error::TxpwrTrkOverflow {
            rows: 20,
            size: 599
        }
    );
    assert_eq!(error.errno(), Some(-14));
    assert_eq!(seen.last(), Some(&(18, Outcome::Refused)));

    // Types past 2.4 GHz's end the bitmap's walk.
    pieces[4] = trk(0x0f_fff0, 20);
    let table = parse(build(&pieces), CARD).unwrap().txpwr_trk.unwrap();
    assert_eq!(table.contents.len(), 600);
    // 6 GHz types take four rows each, ahead of the others.
    pieces[4] = trk(0xffff, 36);
    let table = parse(build(&pieces), CARD).unwrap().txpwr_trk.unwrap();
    assert_eq!(table.delta[1], Some(4));
    assert_eq!(table.delta[4], Some(16));
    assert_eq!(table.rows(3).unwrap().len(), 120);
    assert_eq!(
        table.delta(3, 3, 29),
        Some(pattern(1080, 99)[15 * 30 + 29] as i8)
    );

    // The last tracking element wins.
    let mut pieces = required();
    pieces.push(element(18, trk_fixed(0xfff0), &[7; 600], 0, None));
    let table = parse(build(&pieces), CARD).unwrap().txpwr_trk.unwrap();
    assert_eq!(table.delta(8, 0, 0), Some(7));
}

#[test]
fn regulation_entries_take_defaults_and_unknown_rules_become_na() {
    let mut pieces = required();
    let short = [b'I', b'D', 1, 2, 16, b'U', b'S', 2, 2, 2];
    pieces.push(regd(5, 2, &short));
    let mut long = Vec::new();
    long.extend_from_slice(&[b'I', b'D', 0, 1, 2]);
    long.extend_from_slice(&u32::MAX.to_le_bytes());
    long.extend_from_slice(&[1, 2, 3]);
    long.extend_from_slice(&[b'J', b'P', 3, 3, 17]);
    long.extend_from_slice(&2u32.to_le_bytes());
    long.extend_from_slice(&[4, 5, 6]);
    pieces.push(regd(12, 2, &long));
    let file = container(&pieces);
    let elements = parse(&file, CARD).unwrap();
    // The latter element replaces the former; fmap's bits past DAG drop.
    assert_eq!(
        elements.regd.unwrap().map,
        [
            Regd {
                alpha2: *b"ID",
                txpwr_regd: [0, 1, 2],
                func_bitmap: 3
            },
            Regd {
                alpha2: *b"JP",
                txpwr_regd: [3, 3, REGD_NA],
                func_bitmap: 2
            },
        ]
    );
    // Short entries keep the defaults past their bytes.
    pieces.pop();
    let elements = parse(build(&pieces), CARD).unwrap();
    assert_eq!(
        elements.regd.unwrap().map,
        [
            Regd {
                alpha2: *b"ID",
                txpwr_regd: [1, 2, REGD_NA],
                func_bitmap: 0
            },
            Regd {
                alpha2: *b"US",
                txpwr_regd: [2, 2, 2],
                func_bitmap: 0
            },
        ]
    );
    // More countries than a u8 counts: ignored, the earlier map stays.
    pieces.push(regd(9, 300, &[0; 9]));
    let (result, seen) = parse_traced(build(&pieces), CARD);
    assert_eq!(seen.last(), Some(&(20, Outcome::Ignored)));
    assert_eq!(result.unwrap().regd.unwrap().map.len(), 2);
}

#[test]
fn bb_mcu_suits_follow_the_cut() {
    let mut pieces = required();
    pieces.extend([
        bbmcu(Id::Bbmcu0, 5, 0),
        bbmcu(Id::Bbmcu0, 1, 1),
        bbmcu(Id::Bbmcu0, 0, 0),
        bbmcu(Id::Bbmcu1, 0, 0),
    ]);
    let file = container(&pieces);
    let elements = parse(&file, CARD).unwrap();
    let suit = elements.bbmcu[0].unwrap();
    assert_eq!((suit.hdr_ver, suit.data.len()), (1, 48));
    assert_eq!(elements.bbmcu[1].unwrap().hdr_ver, 0);
    let elements = parse(&file, Board::rtl8852b(1, 0)).unwrap();
    assert_eq!(elements.bbmcu[0].unwrap().hdr_ver, 0);
    let mut pieces = required();
    pieces.push(bbmcu(Id::Bbmcu1, 0, 2));
    let error = parse(build(&pieces), CARD).unwrap_err();
    assert_eq!(error, Error::UnknownSuitHeader { id: 1, hdr_ver: 2 });
    assert_eq!(error.errno(), Some(-2));
}

#[test]
fn the_other_handlers_keep_their_elements() {
    let mut pieces = required();
    pieces.extend([
        element(19, [1, 0, 0, 0, 2, 0, 0, 0], &[1; 6], 0, None),
        element(19, [1, 0, 0, 0, 20, 0, 0, 0], &[2; 4], 0, None),
        plain(Id::AfePwrSeq, &[3; 13]),
        plain(Id::DiagMac, &[4; 40]),
        plain(Id::DiagMac, &[5; 3]),
        element(29, [9, 0, 0, 0, 0, 0, 0, 0], &[6; 8], 0, None),
        element(29, [0, 0, 0, 0, 0, 0, 0, 0], &[7; 8], 0x1234, None),
        element(29, [0, 0, 0, 0, 0, 0, 0, 0], &[8; 8], 0, None),
        element(29, [1, 0, 0, 0, 0, 0, 0, 0], &[9; 8], 0, None),
    ]);
    let (result, seen) = parse_traced(build(&pieces), CARD);
    let elements = result.unwrap();
    let outcomes: Vec<_> = seen[12..].iter().map(|&(_, o)| o).collect();
    use Outcome::*;
    assert_eq!(
        outcomes,
        [
            Recognized, Ignored, Recognized, Recognized, Recognized, Ignored, Ignored, Recognized,
            Ignored
        ]
    );
    let formats = elements.rfk_log_fmt.unwrap();
    assert_eq!(formats[2].unwrap().body, [1; 6]);
    assert_eq!(formats.iter().flatten().count(), 1);
    assert_eq!(elements.afe.unwrap().body, [3; 13]);
    assert_eq!(elements.diag_mac.unwrap().body, [5; 3]);
    assert_eq!(elements.tx_comp.unwrap().body, [8; 8]);
    assert_eq!(
        elements.optional(),
        Id::RfklogFmt.bit() | Id::AfePwrSeq.bit() | Id::DiagMac.bit() | Id::TxComp.bit()
    );
    // An RFK log element with an id past the formats still allocates them.
    let mut pieces = required();
    pieces.push(element(19, [1, 0, 0, 0, 20, 0, 0, 0], &[2; 4], 0, None));
    let elements = parse(build(&pieces), CARD).unwrap();
    assert_eq!(elements.rfk_log_fmt, Some([None; RFK_LOG_FUNC_NUM]));
}

#[test]
fn reads_past_the_file_are_refused() {
    // The size check leaves the 32 header bytes out: registers past the
    // file's end would be read.
    let mut pieces = required();
    pieces.push(element(3, [0; 8], &regs(2, 1), 0, Some(40)));
    let error = parse(build(&pieces), CARD).unwrap_err();
    assert!(matches!(error, Error::BeyondFile { id: 3, .. }));
    assert_eq!(error.errno(), None);
    // A TX power table whose entries run past the file.
    let mut pieces = required();
    pieces.push(element(12, txpwr_fixed(1, 8, 1000), &[0; 8], 0, None));
    assert!(matches!(
        parse(build(&pieces), CARD).unwrap_err(),
        Error::BeyondFile { id: 12, .. }
    ));
    // One reading past its element but not the file is rtw89's: the next
    // element's bytes.
    let mut pieces = required();
    pieces.push(element(12, txpwr_fixed(1, 8, 4), &[0x5a; 8], 0, None));
    pieces.push(plain(Id::DiagMac, &[0; 40]));
    let elements = parse(build(&pieces), CARD).unwrap();
    let conf = *elements.rfe_data.unwrap().conf(TxpwrSlot::Lmt6ghz).unwrap();
    assert_eq!(conf.data.len(), 32);
    assert_eq!(&conf.data[..8], [0x5a; 8]);
    assert_eq!(&conf.data[16..20], (Id::DiagMac as u32).to_le_bytes());
}

#[test]
fn a_legacy_image_has_no_elements() {
    let file = [0u8; 200];
    let error = Elements::parse(&file, 0, CARD, |_, _| {}).unwrap_err();
    assert_eq!(error, Error::NotContainer);
    assert_eq!(error.errno(), Some(-22));
}

/// The oracle's images, in its order: the pinned firmware, then the
/// synthetic containers it wrote beside its trace.
const IMAGES: [&str; 10] = [
    "pinned",
    "syn-all",
    "syn-missing",
    "syn-truncated",
    "syn-trk-bitmap",
    "syn-trk-overflow",
    "syn-regd-invalid",
    "syn-bbmcu-header",
    "syn-legacy",
    "syn-tail",
];
const ABSENT: u32 = u32::MAX;

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Each table as the oracle serializes it: its id, its count
/// ([`ABSENT`] when absent) and its bytes.
fn serialize(elements: &Elements<'_>) -> Vec<(u32, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let phy = |t: u32, table: &Option<PhyTable<'_>>| match table {
        None => (t, ABSENT, Vec::new()),
        Some(table) => {
            let mut bytes = words(&[table.rf_path.into(), table.radio.into()]);
            for reg in table.regs() {
                bytes.extend(words(&[reg.addr, reg.data]));
            }
            (t, table.n_regs() as u32, bytes)
        }
    };
    out.push(phy(0, &elements.bb_tbl));
    out.push(phy(1, &elements.bb_gain));
    for (path, table) in elements.rf_radio.iter().enumerate() {
        out.push(phy(2 + path as u32, table));
    }
    out.push(phy(6, &elements.rf_nctl));
    for (index, slot) in TxpwrSlot::ALL.into_iter().enumerate() {
        let t = 7 + index as u32;
        match elements.rfe_data.as_ref().and_then(|data| data.conf(slot)) {
            None => out.push((t, ABSENT, Vec::new())),
            Some(conf) => {
                let mut bytes =
                    words(&[conf.rfe_type.into(), conf.ent_sz.into(), conf.offset as u32]);
                bytes.extend_from_slice(conf.data);
                out.push((t, conf.num_ents, bytes));
            }
        }
    }
    match &elements.txpwr_trk {
        None => out.push((22, ABSENT, Vec::new())),
        Some(trk) => {
            let mut bytes = Vec::new();
            for row in trk.delta {
                bytes.extend(words(&[row.map_or(ABSENT, |row| {
                    (trk.offset + row * DELTA_SWINGIDX_SIZE) as u32
                })]));
            }
            for ty in 0..TXPWR_TRK_TYPE_NR {
                if let Some(rows) = trk.rows(ty) {
                    bytes.extend_from_slice(rows);
                }
            }
            out.push((22, trk.delta.iter().flatten().count() as u32, bytes));
        }
    }
    match &elements.regd {
        None => out.push((23, ABSENT, Vec::new())),
        Some(regd) => {
            let mut bytes = Vec::new();
            for entry in &regd.map {
                let [r2, r5, r6] = entry.txpwr_regd;
                bytes.extend_from_slice(&[
                    entry.alpha2[0],
                    entry.alpha2[1],
                    0,
                    r2,
                    r5,
                    r6,
                    entry.func_bitmap,
                    0,
                ]);
            }
            out.push((23, regd.map.len() as u32, bytes));
        }
    }
    for (t, element) in [
        (24, &elements.afe),
        (25, &elements.diag_mac),
        (26, &elements.tx_comp),
    ] {
        out.push(match element {
            None => (t, ABSENT, Vec::new()),
            Some(element) => (t, element.size, words(&[element.offset as u32])),
        });
    }
    out.push(match &elements.rfk_log_fmt {
        None => (27, ABSENT, Vec::new()),
        Some(formats) => {
            let offsets: Vec<u32> = formats
                .iter()
                .map(|e| e.map_or(ABSENT, |e| e.offset as u32))
                .collect();
            (27, formats.iter().flatten().count() as u32, words(&offsets))
        }
    });
    for (index, suit) in elements.bbmcu.iter().enumerate() {
        let t = 28 + index as u32;
        out.push(match suit {
            None => (t, ABSENT, Vec::new()),
            Some(suit) => (
                t,
                suit.data.len() as u32,
                words(&[suit.offset as u32, suit.hdr_ver.into()]),
            ),
        });
    }
    out.push((30, 0, words(&[elements.rfe_data.is_some().into()])));
    out
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_IMAGES, STELA_RTW89_ELEMENTS_ORACLE"]
fn pinned_firmware_elements_build_the_tables_linux_builds() {
    use sha2::{Digest, Sha256};
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_ELEMENTS_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let images = std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_IMAGES").unwrap());
    let pinned = std::fs::read(images.join("rtw89/rtw8852b_fw-2.bin")).unwrap();
    let synthetic: Vec<Vec<u8>> = IMAGES[1..]
        .iter()
        .map(|name| std::fs::read(directory.join(format!("{name}.bin"))).unwrap())
        .collect();
    let firmware = Rtw89::parse(&pinned, 1).unwrap();
    let (mut offset, mut cases, mut pinned_rfes) = (0, 0, Vec::new());
    while offset < trace.len() {
        let got = segment(&trace, &mut offset);
        let word = |index: usize| le32(got, index * 4);
        let (image, rfe, aid, cv) = (word(0), word(1), word(2), word(3));
        let board = Board {
            rfe_type: rfe as u8,
            aid: aid as u16,
            cv: cv as u8,
        };
        let mut seen = Vec::new();
        let record = |element: &Element<'_>, outcome: Outcome| {
            if outcome != Outcome::Unhandled {
                seen.push((element.id, element.size, element.ver, element.aid, outcome));
            }
        };
        let result = if image == 0 {
            Elements::recognize_with(&firmware, board, record)
        } else {
            let file = &synthetic[image as usize - 1];
            let base = mfw_size(file);
            Elements::parse(&file[base..], base, board, record)
        };
        let ret = match &result {
            Ok(_) => 0,
            Err(error) => error.errno().unwrap(),
        };
        let mut expected = words(&[image, rfe, aid, cv, ret as u32, seen.len() as u32]);
        for (id, size, ver, element_aid, outcome) in &seen {
            let handler = match outcome {
                Outcome::Recognized => 0,
                Outcome::Ignored => 1,
                _ => ret,
            };
            expected.extend(words(&[
                *id,
                *size,
                u32::from_le_bytes(*ver),
                (*element_aid).into(),
                handler as u32,
            ]));
        }
        let tables = result.as_ref().map(serialize).unwrap_or_default();
        for (t, count, bytes) in &tables {
            expected.extend(words(&[*t, *count, bytes.len() as u32]));
            expected.extend_from_slice(&Sha256::digest(bytes));
        }
        assert!(
            got == expected.as_slice(),
            "case {cases}: {} at RFE {rfe}, AID {aid:#x}, CV {cv}: returned {ret} after {}              handlers",
            IMAGES[image as usize],
            seen.len()
        );
        if image == 0 {
            pinned_rfes.push(rfe);
        }
        if image == 0 && rfe == 1 {
            let mut full = Vec::new();
            for (t, count, bytes) in &tables {
                full.extend(words(&[*t, *count, bytes.len() as u32]));
                full.extend_from_slice(bytes);
                full.resize(full.len().next_multiple_of(4), 0);
            }
            assert!(
                segment(&trace, &mut offset) == full.as_slice(),
                "RFE 1's tables in full"
            );
        }
        cases += 1;
    }
    assert_eq!(offset, trace.len());
    assert_eq!(cases, 29);
    assert_eq!(pinned_rfes, (0..16).chain([51, 255]).collect::<Vec<u32>>());
}
