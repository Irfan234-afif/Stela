// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! The regulation an RTL8852B's TX power limits are read under, chosen as
//! pinned rtw89's regd.c chooses it for a PCIe chip with no ACPI DSM:
//!
//! - the map (`rtw89_regd_setup`): the firmware's REGD element when
//!   [`super::elements`] recognized one, else rtw89's own `rtw89_regd_map`
//!   ([`RTW89_REGD_MAP`]), each country's `txpwr_regd` per band;
//! - the country (`rtw89_regd_init_hint`, then `rtw89_regd_notifier` and
//!   its `rtw89_regd_notifier_apply`): the efuse's country code when the
//!   map has it, which then holds (`programmed`) whatever the stack later
//!   asks; otherwise the stack's alpha2, and the worldwide `rtw89_ww_regd`
//!   ([`WW_REGD`]) when the map lacks that too;
//! - UNII-4 (`rtw89_regd_setup_unii4`, `rtw89_regd_apply_policy_unii4`):
//!   with no ACPI answer rtw89 takes `RTW89_ACPI_CONF_UNII4_US` alone, so
//!   only the map's US entry may use channels 169, 173 and 177;
//! - `txpwr_uk_follow_etsi` (`rtw89_regd_setup_reg_rules`): set before the
//!   ACPI DSM is asked and kept when it does not answer, so `RTW89_UK`
//!   reads as `RTW89_ETSI` (`rtw89_regd_get`).
//!
//! What this leaves out: the ACPI DSM itself (Stela evaluates none, so each
//! policy takes the default rtw89 takes when the DSM fails), the 6 GHz
//! policies (an RTL8852B has no 6 GHz band, where `rtw89_regd_setup_6ghz`
//! returns at once), TAS and antenna gain (both need ACPI tables), and the
//! cfg80211 flags the notifier sets (`REGULATORY_COUNTRY_IE_IGNORE`), which
//! steer what the stack hints next and are the station's concern. Nothing
//! here touches a register or proves a country's law: the map is Realtek's.
use super::{
    elements::{Elements, Regd},
    txpower::{Band, Chan},
};

/// `enum rtw89_regulation_type`.
pub const WW: u8 = 0;
pub const ETSI: u8 = 1;
pub const FCC: u8 = 2;
pub const MKK: u8 = 3;
pub const NA: u8 = 4;
pub const IC: u8 = 5;
pub const KCC: u8 = 6;
pub const ACMA: u8 = 7;
pub const NCC: u8 = 8;
pub const MEXICO: u8 = 9;
pub const CHILE: u8 = 10;
pub const UKRAINE: u8 = 11;
pub const CN: u8 = 12;
pub const QATAR: u8 = 13;
pub const UK: u8 = 14;
pub const THAILAND: u8 = 15;

/// `RTW89_REGD_MAX_COUNTRY_NUM`: the index `rtw89_regd_get_index` gives
/// the worldwide regulation.
pub const MAX_COUNTRY_NUM: usize = 255;
/// The 5 GHz channels `RTW89_5GHZ_UNII4_START_INDEX` and
/// `RTW89_5GHZ_UNII4_CHANNEL_NUM` name in `rtw89_channels_5ghz`.
pub const UNII4_CHANNELS: [u8; 3] = [169, 173, 177];

/// `COUNTRY_REGD`.
const fn entry(alpha2: [u8; 2], rule_2ghz: u8, rule_5ghz: u8, rule_6ghz: u8, fmap: u8) -> Regd {
    Regd {
        alpha2,
        txpwr_regd: [rule_2ghz, rule_5ghz, rule_6ghz],
        func_bitmap: fmap,
    }
}

/// `rtw89_ww_regd`.
pub const WW_REGD: Regd = entry(*b"00", WW, WW, WW, 0x0);

/// `rtw89_regd_map`, in its order.
pub const RTW89_REGD_MAP: [Regd; 242] = [
    entry(*b"AR", MEXICO, MEXICO, FCC, 0x0),
    entry(*b"BO", FCC, FCC, NA, 0x0),
    entry(*b"BR", FCC, FCC, FCC, 0x0),
    entry(*b"CL", CHILE, CHILE, CHILE, 0x0),
    entry(*b"CO", FCC, FCC, FCC, 0x0),
    entry(*b"CR", FCC, FCC, FCC, 0x0),
    entry(*b"EC", FCC, FCC, NA, 0x0),
    entry(*b"SV", FCC, FCC, FCC, 0x0),
    entry(*b"GT", FCC, FCC, FCC, 0x0),
    entry(*b"HN", FCC, FCC, FCC, 0x0),
    entry(*b"MX", MEXICO, MEXICO, FCC, 0x0),
    entry(*b"NI", FCC, FCC, NA, 0x0),
    entry(*b"PA", FCC, FCC, NA, 0x0),
    entry(*b"PY", FCC, FCC, FCC, 0x0),
    entry(*b"PE", FCC, FCC, FCC, 0x0),
    entry(*b"US", FCC, FCC, FCC, 0x1),
    entry(*b"UY", FCC, FCC, NA, 0x0),
    entry(*b"VE", FCC, FCC, NA, 0x0),
    entry(*b"PR", FCC, FCC, NA, 0x0),
    entry(*b"DO", FCC, FCC, FCC, 0x0),
    entry(*b"AT", ETSI, ETSI, ETSI, 0x2),
    entry(*b"BE", ETSI, ETSI, ETSI, 0x2),
    entry(*b"CY", ETSI, ETSI, ETSI, 0x2),
    entry(*b"CZ", ETSI, ETSI, ETSI, 0x2),
    entry(*b"DK", ETSI, ETSI, ETSI, 0x2),
    entry(*b"EE", ETSI, ETSI, ETSI, 0x2),
    entry(*b"FI", ETSI, ETSI, ETSI, 0x2),
    entry(*b"FR", ETSI, ETSI, ETSI, 0x2),
    entry(*b"DE", ETSI, ETSI, ETSI, 0x2),
    entry(*b"GR", ETSI, ETSI, ETSI, 0x2),
    entry(*b"HU", ETSI, ETSI, ETSI, 0x2),
    entry(*b"IS", ETSI, ETSI, ETSI, 0x2),
    entry(*b"IE", ETSI, ETSI, ETSI, 0x2),
    entry(*b"IT", ETSI, ETSI, ETSI, 0x2),
    entry(*b"LV", ETSI, ETSI, ETSI, 0x2),
    entry(*b"LI", ETSI, ETSI, ETSI, 0x2),
    entry(*b"LT", ETSI, ETSI, ETSI, 0x2),
    entry(*b"LU", ETSI, ETSI, ETSI, 0x2),
    entry(*b"MT", ETSI, ETSI, ETSI, 0x2),
    entry(*b"MC", ETSI, ETSI, ETSI, 0x2),
    entry(*b"NL", ETSI, ETSI, ETSI, 0x2),
    entry(*b"NO", ETSI, ETSI, ETSI, 0x2),
    entry(*b"PL", ETSI, ETSI, ETSI, 0x2),
    entry(*b"PT", ETSI, ETSI, ETSI, 0x2),
    entry(*b"SK", ETSI, ETSI, ETSI, 0x2),
    entry(*b"SI", ETSI, ETSI, ETSI, 0x2),
    entry(*b"ES", ETSI, ETSI, ETSI, 0x2),
    entry(*b"SE", ETSI, ETSI, ETSI, 0x2),
    entry(*b"CH", ETSI, ETSI, ETSI, 0x2),
    entry(*b"GB", UK, UK, UK, 0x0),
    entry(*b"AL", ETSI, ETSI, NA, 0x0),
    entry(*b"AZ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"BH", ETSI, ETSI, ETSI, 0x0),
    entry(*b"BA", ETSI, ETSI, NA, 0x0),
    entry(*b"BG", ETSI, ETSI, ETSI, 0x2),
    entry(*b"HR", ETSI, ETSI, ETSI, 0x2),
    entry(*b"EG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GH", ETSI, ETSI, ETSI, 0x0),
    entry(*b"IQ", ETSI, ETSI, NA, 0x0),
    entry(*b"IL", ETSI, ETSI, ETSI, 0x0),
    entry(*b"JO", ETSI, ETSI, ETSI, 0x0),
    entry(*b"KZ", ETSI, ETSI, NA, 0x0),
    entry(*b"KE", ETSI, ETSI, ETSI, 0x0),
    entry(*b"KW", ETSI, ETSI, ETSI, 0x0),
    entry(*b"KG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"LB", ETSI, ETSI, ETSI, 0x0),
    entry(*b"LS", ETSI, ETSI, ETSI, 0x0),
    entry(*b"MK", ETSI, ETSI, NA, 0x0),
    entry(*b"MA", ETSI, ETSI, ETSI, 0x0),
    entry(*b"MZ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"NA", ETSI, ETSI, ETSI, 0x0),
    entry(*b"NG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"OM", ETSI, ETSI, ETSI, 0x0),
    entry(*b"QA", QATAR, QATAR, QATAR, 0x0),
    entry(*b"RO", ETSI, ETSI, ETSI, 0x2),
    entry(*b"RU", ETSI, ETSI, NA, 0x0),
    entry(*b"SA", ETSI, ETSI, ETSI, 0x0),
    entry(*b"SN", ETSI, ETSI, NA, 0x0),
    entry(*b"RS", ETSI, ETSI, ETSI, 0x0),
    entry(*b"ME", ETSI, ETSI, NA, 0x0),
    entry(*b"ZA", ETSI, ETSI, ETSI, 0x0),
    entry(*b"TR", ETSI, ETSI, ETSI, 0x0),
    entry(*b"UA", UKRAINE, UKRAINE, UKRAINE, 0x0),
    entry(*b"AE", ETSI, ETSI, ETSI, 0x0),
    entry(*b"YE", ETSI, ETSI, NA, 0x0),
    entry(*b"ZW", ETSI, ETSI, ETSI, 0x0),
    entry(*b"BD", ETSI, ETSI, ETSI, 0x0),
    entry(*b"KH", ETSI, ETSI, NA, 0x0),
    entry(*b"CN", CN, CN, CN, 0x0),
    entry(*b"HK", ETSI, ETSI, ETSI, 0x0),
    entry(*b"IN", ETSI, ETSI, NA, 0x0),
    entry(*b"ID", ETSI, ETSI, ETSI, 0x0),
    entry(*b"KR", KCC, KCC, KCC, 0x1),
    entry(*b"MY", ETSI, ETSI, ETSI, 0x0),
    entry(*b"PK", ETSI, ETSI, ETSI, 0x0),
    entry(*b"PH", ETSI, ETSI, ETSI, 0x0),
    entry(*b"SG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"LK", ETSI, ETSI, NA, 0x0),
    entry(*b"TW", FCC, FCC, ETSI, 0x0),
    entry(*b"TH", THAILAND, THAILAND, THAILAND, 0x0),
    entry(*b"VN", ETSI, ETSI, ETSI, 0x0),
    entry(*b"AU", ACMA, ACMA, ACMA, 0x0),
    entry(*b"NZ", ACMA, ACMA, ACMA, 0x0),
    entry(*b"PG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"CA", IC, IC, IC, 0x1),
    entry(*b"JP", MKK, MKK, MKK, 0x0),
    entry(*b"JM", FCC, FCC, FCC, 0x0),
    entry(*b"AN", FCC, FCC, FCC, 0x0),
    entry(*b"TT", FCC, FCC, NA, 0x0),
    entry(*b"TN", ETSI, ETSI, ETSI, 0x0),
    entry(*b"AF", ETSI, ETSI, NA, 0x0),
    entry(*b"DZ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"AS", FCC, FCC, NA, 0x0),
    entry(*b"AD", ETSI, ETSI, NA, 0x0),
    entry(*b"AO", ETSI, ETSI, NA, 0x0),
    entry(*b"AI", ETSI, ETSI, ETSI, 0x0),
    entry(*b"AQ", ETSI, ETSI, NA, 0x0),
    entry(*b"AG", FCC, FCC, FCC, 0x0),
    entry(*b"AM", ETSI, ETSI, ETSI, 0x0),
    entry(*b"AW", FCC, FCC, FCC, 0x0),
    entry(*b"BS", FCC, FCC, FCC, 0x0),
    entry(*b"BB", FCC, FCC, FCC, 0x0),
    entry(*b"BY", ETSI, ETSI, NA, 0x0),
    entry(*b"BZ", FCC, FCC, NA, 0x0),
    entry(*b"BJ", ETSI, ETSI, NA, 0x0),
    entry(*b"BM", FCC, FCC, FCC, 0x0),
    entry(*b"BT", ETSI, ETSI, NA, 0x0),
    entry(*b"BW", ETSI, ETSI, ETSI, 0x0),
    entry(*b"BV", ETSI, ETSI, NA, 0x0),
    entry(*b"IO", ETSI, ETSI, NA, 0x0),
    entry(*b"VG", FCC, FCC, FCC, 0x0),
    entry(*b"BN", ETSI, ETSI, NA, 0x0),
    entry(*b"BF", ETSI, ETSI, ETSI, 0x0),
    entry(*b"MM", ETSI, ETSI, NA, 0x0),
    entry(*b"BI", ETSI, ETSI, ETSI, 0x0),
    entry(*b"CM", ETSI, ETSI, NA, 0x0),
    entry(*b"CV", ETSI, ETSI, NA, 0x0),
    entry(*b"KY", FCC, FCC, FCC, 0x0),
    entry(*b"CF", ETSI, ETSI, NA, 0x0),
    entry(*b"TD", ETSI, ETSI, ETSI, 0x0),
    entry(*b"CX", ACMA, ACMA, NA, 0x0),
    entry(*b"CC", ACMA, ACMA, NA, 0x0),
    entry(*b"KM", ETSI, ETSI, NA, 0x0),
    entry(*b"CG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"CD", ETSI, ETSI, ETSI, 0x0),
    entry(*b"CK", ETSI, ETSI, NA, 0x0),
    entry(*b"CI", ETSI, ETSI, NA, 0x0),
    entry(*b"DJ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"DM", FCC, FCC, NA, 0x0),
    entry(*b"GQ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"ER", ETSI, ETSI, NA, 0x0),
    entry(*b"ET", ETSI, ETSI, NA, 0x0),
    entry(*b"FK", ETSI, ETSI, NA, 0x0),
    entry(*b"FO", ETSI, ETSI, NA, 0x0),
    entry(*b"FJ", FCC, FCC, NA, 0x0),
    entry(*b"GF", ETSI, ETSI, NA, 0x0),
    entry(*b"PF", ETSI, ETSI, NA, 0x0),
    entry(*b"TF", ETSI, ETSI, NA, 0x0),
    entry(*b"GA", ETSI, ETSI, NA, 0x0),
    entry(*b"GM", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GE", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GI", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GL", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GD", FCC, FCC, FCC, 0x0),
    entry(*b"GP", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GU", FCC, FCC, FCC, 0x0),
    entry(*b"GG", ETSI, ETSI, NA, 0x0),
    entry(*b"GN", ETSI, ETSI, ETSI, 0x0),
    entry(*b"GW", ETSI, ETSI, NA, 0x0),
    entry(*b"GY", FCC, FCC, NA, 0x0),
    entry(*b"HT", FCC, FCC, FCC, 0x0),
    entry(*b"HM", ACMA, ACMA, NA, 0x0),
    entry(*b"VA", ETSI, ETSI, NA, 0x0),
    entry(*b"IM", ETSI, ETSI, NA, 0x0),
    entry(*b"JE", ETSI, ETSI, NA, 0x0),
    entry(*b"KI", ETSI, ETSI, NA, 0x0),
    entry(*b"XK", ETSI, ETSI, ETSI, 0x0),
    entry(*b"LA", ETSI, ETSI, ETSI, 0x0),
    entry(*b"LR", ETSI, ETSI, ETSI, 0x0),
    entry(*b"LY", ETSI, ETSI, NA, 0x0),
    entry(*b"MO", ETSI, ETSI, NA, 0x0),
    entry(*b"MG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"MW", ETSI, ETSI, NA, 0x0),
    entry(*b"MV", ETSI, ETSI, NA, 0x0),
    entry(*b"ML", ETSI, ETSI, NA, 0x0),
    entry(*b"MH", FCC, FCC, FCC, 0x0),
    entry(*b"MQ", ETSI, ETSI, NA, 0x0),
    entry(*b"MR", ETSI, ETSI, NA, 0x0),
    entry(*b"MU", ETSI, ETSI, ETSI, 0x0),
    entry(*b"YT", ETSI, ETSI, ETSI, 0x0),
    entry(*b"FM", FCC, FCC, FCC, 0x0),
    entry(*b"MD", ETSI, ETSI, ETSI, 0x0),
    entry(*b"MN", ETSI, ETSI, ETSI, 0x0),
    entry(*b"MS", ETSI, ETSI, NA, 0x0),
    entry(*b"NR", ETSI, ETSI, NA, 0x0),
    entry(*b"NP", ETSI, ETSI, NA, 0x0),
    entry(*b"NC", ETSI, ETSI, NA, 0x0),
    entry(*b"NE", ETSI, ETSI, NA, 0x0),
    entry(*b"NU", ACMA, ACMA, NA, 0x0),
    entry(*b"NF", ACMA, ACMA, NA, 0x0),
    entry(*b"MP", FCC, FCC, FCC, 0x0),
    entry(*b"PW", FCC, FCC, FCC, 0x0),
    entry(*b"RE", ETSI, ETSI, NA, 0x0),
    entry(*b"RW", ETSI, ETSI, NA, 0x0),
    entry(*b"SH", ETSI, ETSI, NA, 0x0),
    entry(*b"KN", FCC, FCC, FCC, 0x0),
    entry(*b"LC", FCC, FCC, FCC, 0x0),
    entry(*b"MF", FCC, FCC, FCC, 0x0),
    entry(*b"SX", FCC, FCC, FCC, 0x0),
    entry(*b"PM", ETSI, ETSI, NA, 0x0),
    entry(*b"VC", FCC, FCC, NA, 0x0),
    entry(*b"WS", FCC, FCC, NA, 0x0),
    entry(*b"SM", ETSI, ETSI, NA, 0x0),
    entry(*b"ST", ETSI, ETSI, NA, 0x0),
    entry(*b"SC", FCC, FCC, NA, 0x0),
    entry(*b"SL", ETSI, ETSI, ETSI, 0x0),
    entry(*b"SB", ETSI, ETSI, NA, 0x0),
    entry(*b"SO", ETSI, ETSI, NA, 0x0),
    entry(*b"GS", ETSI, ETSI, NA, 0x0),
    entry(*b"SR", FCC, FCC, FCC, 0x0),
    entry(*b"SJ", ETSI, ETSI, NA, 0x0),
    entry(*b"SZ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"TJ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"TZ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"TG", ETSI, ETSI, ETSI, 0x0),
    entry(*b"TK", ACMA, ACMA, NA, 0x0),
    entry(*b"TO", ETSI, ETSI, NA, 0x0),
    entry(*b"TM", ETSI, ETSI, NA, 0x0),
    entry(*b"TC", ETSI, ETSI, NA, 0x0),
    entry(*b"TV", ETSI, NA, NA, 0x0),
    entry(*b"UG", ETSI, ETSI, NA, 0x0),
    entry(*b"VI", FCC, FCC, FCC, 0x0),
    entry(*b"UZ", ETSI, ETSI, ETSI, 0x0),
    entry(*b"VU", ETSI, ETSI, NA, 0x0),
    entry(*b"WF", ETSI, ETSI, NA, 0x0),
    entry(*b"EH", ETSI, ETSI, ETSI, 0x0),
    entry(*b"ZM", ETSI, ETSI, NA, 0x0),
    entry(*b"CU", ETSI, ETSI, NA, 0x0),
    entry(*b"IR", ETSI, ETSI, NA, 0x0),
    entry(*b"SY", ETSI, NA, NA, 0x0),
    entry(*b"SD", ETSI, ETSI, NA, 0x0),
    entry(*b"PS", ETSI, ETSI, NA, 0x0),
];

/// `regulatory->ctrl.map` as `rtw89_regd_setup` takes it: the REGD
/// element's map when there is one, else [`RTW89_REGD_MAP`].
pub fn map<'a>(elements: &'a Elements<'_>) -> &'a [Regd] {
    match &elements.regd {
        Some(data) => &data.map,
        None => &RTW89_REGD_MAP,
    }
}

/// `rtw89_regd_find_reg_by_name` with `rtw89_regd_get_index`: the first
/// entry naming `alpha2` and its index, or `None` for `rtw89_ww_regd`.
pub fn find(map: &[Regd], alpha2: [u8; 2]) -> Option<(usize, Regd)> {
    map.iter()
        .enumerate()
        .find(|(_, regd)| regd.alpha2 == alpha2)
        .map(|(index, regd)| (index, *regd))
}

/// `struct rtw89_regulatory_info` once the stack has named a country.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Regulation {
    /// `regulatory->regd`, with its index in the map; `None` is
    /// `rtw89_ww_regd`.
    found: Option<(usize, Regd)>,
    /// `regulatory->programmed`: the efuse named a country of the map.
    pub programmed: bool,
    /// `regulatory->txpwr_uk_follow_etsi`.
    pub uk_follow_etsi: bool,
    /// Whether `rtw89_regd_apply_policy_unii4` leaves UNII-4 enabled.
    unii4: bool,
}

impl Regulation {
    /// The regulation rtw89 settles on for a PCIe RTL8852B whose efuse
    /// holds `efuse_country` once the stack asks for `stack_alpha2`
    /// (`"00"` for none): `rtw89_regd_setup` without ACPI, then
    /// `rtw89_regd_init_hint`, then one `rtw89_regd_notifier`.
    pub fn new(map: &[Regd], efuse_country: [u8; 2], stack_alpha2: [u8; 2]) -> Self {
        // rtw89_regd_setup_unii4: every country blocked, then US cleared
        // when the map has it, as RTW89_ACPI_CONF_UNII4_US alone allows.
        let unii4_index = find(map, *b"US").map(|(index, _)| index);
        // rtw89_regd_init_hint: an efuse country of the map is programmed.
        let (found, programmed) = match find(map, efuse_country) {
            Some(found) => (Some(found), true),
            // rtw89_regd_notifier_apply.
            None => (find(map, stack_alpha2), false),
        };
        // rtw89_regd_apply_policy_unii4: blocked for the worldwide
        // regulation and every index whose bit stayed set.
        let unii4 = matches!((found, unii4_index), (Some((index, _)), Some(us)) if index == us);
        Self {
            found,
            programmed,
            // rtw89_regd_setup_reg_rules for PCIe, its DSM unanswered.
            uk_follow_etsi: true,
            unii4,
        }
    }

    /// `regulatory->regd`.
    pub fn regd(&self) -> Regd {
        self.found.map_or(WW_REGD, |(_, regd)| regd)
    }

    /// `rtw89_regd_is_ww`.
    pub fn is_ww(&self) -> bool {
        self.found.is_none()
    }

    /// `rtw89_regd_get`: the band's regulation type, `RTW89_UK` read as
    /// `RTW89_ETSI` while `txpwr_uk_follow_etsi` holds.
    pub fn txpwr_regd(&self, band: Band) -> u8 {
        let regd = self.regd().txpwr_regd[band as usize];
        if self.uk_follow_etsi && regd == UK {
            ETSI
        } else {
            regd
        }
    }

    /// Whether UNII-4's channels stay enabled.
    pub fn unii4(&self) -> bool {
        self.unii4
    }

    /// Whether every 20 MHz channel `chan` spans stays enabled: what
    /// `rtw89_regd_apply_policy_unii4` disables, a UNII-4 channel outside
    /// the US, is refused. The country's own rules are regulatory.db's
    /// ([`super::txpower::Cap::country`]).
    pub fn permits(&self, chan: &Chan) -> bool {
        self.unii4
            || chan.band != Band::Ghz5
            || chan
                .subchannels()
                .all(|channel| !UNII4_CHANNELS.contains(&channel))
    }
}

#[cfg(test)]
mod tests;
