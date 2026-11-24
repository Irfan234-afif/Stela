// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The firmware features pinned rtw89 turns on by version for an RTL8852B:
//! the RTL8852B rows of `fw_feat_tbl` (fw.c), applied as
//! `rtw89_fw_iterate_feature_cfg` applies them to an empty feature map.
//! `rtw89_fw_recognize_features` runs it over the normal suit's version,
//! which is the image the download sends ([`Features::of_image`]), once
//! `rtw89_fw_recognize` has picked it and before the download.
//!
//! A row compares the suit's version code (`RTW89_FW_VER_CODE`: major,
//! minor, sub-version and sub-index, one byte each, most significant first)
//! with its own, by `ge`, `le` or `lt`. Every RTL8852B row sets its feature;
//! the table's disabling rows (`__DIS_FW_FEAT`) belong to RTL8922A alone, so
//! none is carried.
//!
//! What this leaves out, and why: the other chips' rows, and
//! `rtw89_early_fw_feature_recognize`, which applies the same rows to the
//! container's version before probe to pick mac80211 capabilities; for the
//! pinned container that version is the image's. A feature recognized here
//! says only what rtw89 would expect of firmware of that version; nothing
//! here asks the firmware.
use super::super::firmware::AxImage;

/// `RTW89_FW_VER_CODE`.
pub const fn ver_code(major: u8, minor: u8, sub: u8, idx: u8) -> u32 {
    u32::from_be_bytes([major, minor, sub, idx])
}

/// The members of `enum rtw89_fw_feature` that RTL8852B's rows name, in the
/// order of those rows' first mention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Feature {
    NoLpsPg,
    TxWake,
    CrashTriggerType0,
    ScanOffload,
    BeaconFilter,
    BeaconLossCountV1,
    NoWowCpuIoRx,
    LpsDackByC2hReg,
    SerL1ByEvent,
    CrashTriggerType1,
    ScanOffloadExtraOp,
    BeaconTracking,
    SimSerL0l1ByHaltH2c,
}

impl Feature {
    /// Every feature, in declaration order.
    pub const ALL: [Self; 13] = [
        Self::NoLpsPg,
        Self::TxWake,
        Self::CrashTriggerType0,
        Self::ScanOffload,
        Self::BeaconFilter,
        Self::BeaconLossCountV1,
        Self::NoWowCpuIoRx,
        Self::LpsDackByC2hReg,
        Self::SerL1ByEvent,
        Self::CrashTriggerType1,
        Self::ScanOffloadExtraOp,
        Self::BeaconTracking,
        Self::SimSerL0l1ByHaltH2c,
    ];
}

/// `__fw_feat_cond_ge`, `__fw_feat_cond_le` and `__fw_feat_cond_lt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cond {
    Ge,
    Le,
    Lt,
}

impl Cond {
    /// Whether the suit's version code satisfies the row's.
    pub const fn holds(self, suit_ver_code: u32, comp_ver_code: u32) -> bool {
        match self {
            Self::Ge => suit_ver_code >= comp_ver_code,
            Self::Le => suit_ver_code <= comp_ver_code,
            Self::Lt => suit_ver_code < comp_ver_code,
        }
    }
}

/// One `struct __fw_feat_cfg` row that sets its feature (`__CFG_FW_FEAT`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub cond: Cond,
    pub ver_code: u32,
    pub feature: Feature,
}

const fn row(cond: Cond, major: u8, minor: u8, sub: u8, idx: u8, feature: Feature) -> Row {
    Row {
        cond,
        ver_code: ver_code(major, minor, sub, idx),
        feature,
    }
}

/// The `RTL8852B` rows of `fw_feat_tbl`, in the table's order.
pub const RTL8852B_ROWS: [Row; 13] = [
    row(Cond::Ge, 0, 29, 26, 0, Feature::NoLpsPg),
    row(Cond::Ge, 0, 29, 26, 0, Feature::TxWake),
    row(Cond::Ge, 0, 29, 29, 0, Feature::CrashTriggerType0),
    row(Cond::Ge, 0, 29, 29, 0, Feature::ScanOffload),
    row(Cond::Ge, 0, 29, 29, 7, Feature::BeaconFilter),
    row(Cond::Ge, 0, 29, 29, 15, Feature::BeaconLossCountV1),
    row(Cond::Lt, 0, 29, 30, 0, Feature::NoWowCpuIoRx),
    row(Cond::Ge, 0, 29, 127, 0, Feature::LpsDackByC2hReg),
    row(Cond::Ge, 0, 29, 127, 0, Feature::SerL1ByEvent),
    row(Cond::Ge, 0, 29, 128, 0, Feature::CrashTriggerType1),
    row(Cond::Ge, 0, 29, 128, 0, Feature::ScanOffloadExtraOp),
    row(Cond::Ge, 0, 29, 128, 0, Feature::BeaconTracking),
    row(Cond::Ge, 0, 29, 130, 0, Feature::SimSerL0l1ByHaltH2c),
];

/// `rtwdev->fw.feature_map`, as far as RTL8852B's rows reach it: one bit per
/// [`Feature`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Features(u16);

impl Features {
    /// `rtw89_fw_iterate_feature_cfg` for an RTL8852B over an empty map:
    /// every row whose condition the version code satisfies sets its
    /// feature.
    pub const fn of(suit_ver_code: u32) -> Self {
        let mut bits = 0;
        let mut index = 0;
        while index < RTL8852B_ROWS.len() {
            let row = RTL8852B_ROWS[index];
            if row.cond.holds(suit_ver_code, row.ver_code) {
                bits |= 1 << row.feature as u16;
            }
            index += 1;
        }
        Self(bits)
    }

    /// `rtw89_fw_recognize_features` with `image` as the normal suit:
    /// `RTW89_FW_SUIT_VER_CODE` of the version its header names.
    pub fn of_image(image: &AxImage<'_>) -> Self {
        Self::of(u32::from_be_bytes(image.version))
    }

    /// `RTW89_CHK_FW_FEATURE`.
    pub const fn has(self, feature: Feature) -> bool {
        self.0 & (1 << feature as u16) != 0
    }

    /// The features set, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Feature> {
        Feature::ALL
            .into_iter()
            .filter(move |&feature| self.has(feature))
    }

    /// One bit per feature, `1 << feature as u8`.
    pub const fn bits(self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests;
