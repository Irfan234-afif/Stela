use super::*;
use crate::wifi::realtek::ax::{
    elements::RegdData,
    txpower::{Chan, Width},
};
use alloc::vec;

const BLANK: [u8; 2] = [0xff; 2];

fn chan(band: Band, channel: u8, primary: u8, width: Width) -> Chan {
    Chan::new(band, channel, primary, width).unwrap()
}

#[test]
fn indonesia_reads_etsi_on_both_bands_from_rtw89s_map() {
    let id = Regulation::new(&RTW89_REGD_MAP, BLANK, *b"ID");
    assert_eq!(id.regd().alpha2, *b"ID");
    assert_eq!(id.regd().txpwr_regd, [ETSI, ETSI, ETSI]);
    assert_eq!(id.txpwr_regd(Band::Ghz2), ETSI);
    assert_eq!(id.txpwr_regd(Band::Ghz5), ETSI);
    assert!(!id.programmed && !id.is_ww() && !id.unii4());
}

#[test]
fn the_united_states_alone_keep_unii4() {
    let us = Regulation::new(&RTW89_REGD_MAP, BLANK, *b"US");
    assert_eq!(us.txpwr_regd(Band::Ghz5), FCC);
    assert!(us.unii4());
    let id = Regulation::new(&RTW89_REGD_MAP, BLANK, *b"ID");
    let ca = Regulation::new(&RTW89_REGD_MAP, BLANK, *b"CA");
    let ch169 = chan(Band::Ghz5, 169, 169, Width::Mhz20);
    let ch165 = chan(Band::Ghz5, 165, 165, Width::Mhz20);
    let ch171 = chan(Band::Ghz5, 171, 165, Width::Mhz80);
    let ch13 = chan(Band::Ghz2, 13, 13, Width::Mhz20);
    assert!(us.permits(&ch169) && us.permits(&ch171));
    for other in [id, ca] {
        assert!(!other.unii4());
        assert!(!other.permits(&ch169) && !other.permits(&ch171));
        assert!(other.permits(&ch165) && other.permits(&ch13));
    }
    // A map without the US blocks UNII-4 for every country.
    let map = vec![RTW89_REGD_MAP[15], RTW89_REGD_MAP[91]];
    assert_eq!(map[0].alpha2, *b"US");
    assert!(Regulation::new(&map, BLANK, *b"US").unii4());
    assert!(!Regulation::new(&map[1..], BLANK, *b"US").unii4());
}

#[test]
fn a_country_the_map_lacks_reads_worldwide() {
    for alpha2 in [*b"XX", *b"00"] {
        let ww = Regulation::new(&RTW89_REGD_MAP, BLANK, alpha2);
        assert!(ww.is_ww() && !ww.programmed && !ww.unii4());
        assert_eq!(ww.regd(), WW_REGD);
        assert_eq!(ww.txpwr_regd(Band::Ghz2), WW);
        assert_eq!(ww.txpwr_regd(Band::Ghz5), WW);
    }
}

#[test]
fn an_efuse_country_of_the_map_holds_against_the_stack() {
    let programmed = Regulation::new(&RTW89_REGD_MAP, *b"US", *b"ID");
    assert!(programmed.programmed && programmed.unii4());
    assert_eq!(programmed.regd().alpha2, *b"US");
    // An efuse country the map lacks leaves the stack's.
    let unknown = Regulation::new(&RTW89_REGD_MAP, *b"XX", *b"ID");
    assert!(!unknown.programmed);
    assert_eq!(unknown.regd().alpha2, *b"ID");
}

#[test]
fn the_united_kingdom_follows_etsi() {
    let gb = Regulation::new(&RTW89_REGD_MAP, BLANK, *b"GB");
    assert_eq!(gb.regd().txpwr_regd, [UK, UK, UK]);
    assert_eq!(gb.txpwr_regd(Band::Ghz2), ETSI);
    let literal = Regulation {
        uk_follow_etsi: false,
        ..gb
    };
    assert_eq!(literal.txpwr_regd(Band::Ghz5), UK);
}

#[test]
fn the_firmwares_map_replaces_rtw89s() {
    let mut elements = Elements::default();
    assert_eq!(map(&elements).len(), 242);
    let own = Regd {
        alpha2: *b"ID",
        txpwr_regd: [FCC, MKK, NA],
        func_bitmap: 0,
    };
    elements.regd = Some(RegdData { map: vec![own] });
    assert_eq!(map(&elements), [own]);
    let id = Regulation::new(map(&elements), BLANK, *b"ID");
    assert_eq!(
        (id.txpwr_regd(Band::Ghz2), id.txpwr_regd(Band::Ghz5)),
        (FCC, MKK)
    );
    // US is not in that map: worldwide, UNII-4 blocked.
    let us = Regulation::new(map(&elements), BLANK, *b"US");
    assert!(us.is_ww() && !us.unii4());
}

#[test]
fn rtw89s_map_starts_and_ends_as_regd_c_does() {
    assert_eq!(RTW89_REGD_MAP[0].alpha2, *b"AR");
    assert_eq!(RTW89_REGD_MAP[0].txpwr_regd, [MEXICO, MEXICO, FCC]);
    assert_eq!(RTW89_REGD_MAP[15].func_bitmap, 1);
    assert_eq!(RTW89_REGD_MAP[91].alpha2, *b"ID");
    assert!(RTW89_REGD_MAP.len() <= MAX_COUNTRY_NUM);
}
