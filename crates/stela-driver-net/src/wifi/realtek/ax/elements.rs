// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! The firmware elements an RTL8852B's tables come from, recognized as
//! pinned rtw89's `rtw89_fw_recognize_elements` (fw.c) recognizes them once
//! the firmware and the efuse are read: the BB, BB gain, radio and NCTL
//! register tables (`rtw89_build_phy_tbl_from_elm`), the TX power by-rate,
//! limit, RU limit and TX shape tables of the board's RFE type
//! (`rtw89_fw_recognize_txpwr_from_elm`), the TX power tracking deltas
//! (`rtw89_build_txpwr_trk_tbl_from_elm`), the regulation map
//! (`rtw89_recognize_regd_from_elm`), and the elements the other handlers
//! of `__fw_element_handlers` keep as they are.
//!
//! The elements follow the container's last entry, each at the next
//! 16-byte boundary of the file (`RTW89_FW_ELEMENT_ALIGN`), behind a 32-byte
//! `struct rtw89_fw_element_hdr` whose `size` counts the bytes after it.
//! The walk stops, as rtw89's does, at the first element whose offset plus
//! size reaches the file's end; an id without a handler is stepped over.
//! An element whose `aid` is set and differs from the chip's is ignored;
//! an RTL8852B is an AX chip, whose `hal->aid` rtw89 never sets
//! ([`RTL8852B_AID`]). Each handler's own selection is kept: the first
//! register table of a kind wins, the last TX power table naming the
//! board's RFE type wins and one naming RFE 0 is the fallback, the last
//! regulation map and tracking table win.
//!
//! Firmware lacking any element of `needed_fw_elms`
//! ([`RTL8852B_NEEDED`]) is refused with the elements it lacks. RTL8852B's
//! `needed_fw_elms` also sets `__RTW89_FW_ELEMENT_ID_INTL_TRANSITION`,
//! which makes rtw89 accept such firmware with a notice; that transition
//! is left out, so this refuses it.
//!
//! What this adds to rtw89: where a handler would read, or keep a pointer
//! to bytes it later reads, past the file's end (an element's size or entry
//! count running past it, which no length check of rtw89's catches), this
//! refuses the firmware ([`Error::BeyondFile`]) rather than read them; and
//! the size check that stops the walk is not done in 32 bits, so a size
//! that would wrap rtw89's `offset + elm_size` stops it too. Nothing here
//! touches a register: the tables are borrowed from the firmware for the
//! loaders to write.
use super::super::firmware::Rtw89;
use alloc::vec::Vec;
use core::fmt;

/// `RTW89_FW_ELEMENT_ALIGN`.
pub const ELEMENT_ALIGN: usize = 16;
/// `sizeof(struct rtw89_fw_element_hdr)`: the 24-byte header and the
/// union's 8 fixed bytes, after which `size` bytes follow.
pub const HEADER_LEN: usize = 32;
/// `DELTA_SWINGIDX_SIZE`: one row of TX power tracking deltas.
pub const DELTA_SWINGIDX_SIZE: usize = 30;
/// `RF_PATH_MAX`.
pub const RF_PATH_MAX: usize = 4;
/// `RTW89_TXPWR_CONF_DFLT_RFE_TYPE`.
pub const DFLT_RFE_TYPE: u8 = 0;
/// `RTW89_PHY_C2H_RFK_LOG_FUNC_NUM`.
pub const RFK_LOG_FUNC_NUM: usize = 15;
/// `RTW89_FW_TXPWR_TRK_TYPE_NR`.
pub const TXPWR_TRK_TYPE_NR: usize = 16;
/// `RTW89_REGD_MAX_COUNTRY_NUM`.
pub const REGD_MAX_COUNTRY_NUM: u32 = 255;
/// `RTW89_REGD_NUM`: rules from here up are unknown to the driver.
pub const REGD_NUM: u8 = 16;
/// `RTW89_NA`.
pub const REGD_NA: u8 = 4;
/// `NUM_OF_RTW89_REGD_FUNC`.
pub const NUM_OF_REGD_FUNC: u32 = 2;
/// `hal->aid` of an RTL8852B: rtw89 reads the AID only for BE chips.
pub const RTL8852B_AID: u16 = 0;

/// `enum rtw89_fw_element_id`, the ids `__fw_element_handlers` has a
/// handler for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Id {
    Bbmcu0 = 0,
    Bbmcu1 = 1,
    BbReg = 2,
    BbGain = 3,
    RadioA = 4,
    RadioB = 5,
    RadioC = 6,
    RadioD = 7,
    RfNctl = 8,
    TxpwrByrate = 9,
    TxpwrLmt2ghz = 10,
    TxpwrLmt5ghz = 11,
    TxpwrLmt6ghz = 12,
    TxpwrLmtRu2ghz = 13,
    TxpwrLmtRu5ghz = 14,
    TxpwrLmtRu6ghz = 15,
    TxShapeLmt = 16,
    TxShapeLmtRu = 17,
    TxpwrTrk = 18,
    RfklogFmt = 19,
    Regd = 20,
    TxpwrDaLmt2ghz = 21,
    TxpwrDaLmt5ghz = 22,
    TxpwrDaLmt6ghz = 23,
    TxpwrDaLmtRu2ghz = 24,
    TxpwrDaLmtRu5ghz = 25,
    TxpwrDaLmtRu6ghz = 26,
    AfePwrSeq = 27,
    DiagMac = 28,
    TxComp = 29,
}

impl Id {
    /// Every id, in value order.
    pub const ALL: [Self; 30] = [
        Self::Bbmcu0,
        Self::Bbmcu1,
        Self::BbReg,
        Self::BbGain,
        Self::RadioA,
        Self::RadioB,
        Self::RadioC,
        Self::RadioD,
        Self::RfNctl,
        Self::TxpwrByrate,
        Self::TxpwrLmt2ghz,
        Self::TxpwrLmt5ghz,
        Self::TxpwrLmt6ghz,
        Self::TxpwrLmtRu2ghz,
        Self::TxpwrLmtRu5ghz,
        Self::TxpwrLmtRu6ghz,
        Self::TxShapeLmt,
        Self::TxShapeLmtRu,
        Self::TxpwrTrk,
        Self::RfklogFmt,
        Self::Regd,
        Self::TxpwrDaLmt2ghz,
        Self::TxpwrDaLmt5ghz,
        Self::TxpwrDaLmt6ghz,
        Self::TxpwrDaLmtRu2ghz,
        Self::TxpwrDaLmtRu5ghz,
        Self::TxpwrDaLmtRu6ghz,
        Self::AfePwrSeq,
        Self::DiagMac,
        Self::TxComp,
    ];

    /// The id an element's header names, if a handler takes it.
    pub fn from_raw(raw: u32) -> Option<Self> {
        Self::ALL.get(usize::try_from(raw).ok()?).copied()
    }

    /// `BIT(id)`.
    pub const fn bit(self) -> u32 {
        1 << self as u32
    }

    /// The enumerator's name after `RTW89_FW_ELEMENT_ID_`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bbmcu0 => "BBMCU0",
            Self::Bbmcu1 => "BBMCU1",
            Self::BbReg => "BB_REG",
            Self::BbGain => "BB_GAIN",
            Self::RadioA => "RADIO_A",
            Self::RadioB => "RADIO_B",
            Self::RadioC => "RADIO_C",
            Self::RadioD => "RADIO_D",
            Self::RfNctl => "RF_NCTL",
            Self::TxpwrByrate => "TXPWR_BYRATE",
            Self::TxpwrLmt2ghz => "TXPWR_LMT_2GHZ",
            Self::TxpwrLmt5ghz => "TXPWR_LMT_5GHZ",
            Self::TxpwrLmt6ghz => "TXPWR_LMT_6GHZ",
            Self::TxpwrLmtRu2ghz => "TXPWR_LMT_RU_2GHZ",
            Self::TxpwrLmtRu5ghz => "TXPWR_LMT_RU_5GHZ",
            Self::TxpwrLmtRu6ghz => "TXPWR_LMT_RU_6GHZ",
            Self::TxShapeLmt => "TX_SHAPE_LMT",
            Self::TxShapeLmtRu => "TX_SHAPE_LMT_RU",
            Self::TxpwrTrk => "TXPWR_TRK",
            Self::RfklogFmt => "RFKLOG_FMT",
            Self::Regd => "REGD",
            Self::TxpwrDaLmt2ghz => "TXPWR_DA_LMT_2GHZ",
            Self::TxpwrDaLmt5ghz => "TXPWR_DA_LMT_5GHZ",
            Self::TxpwrDaLmt6ghz => "TXPWR_DA_LMT_6GHZ",
            Self::TxpwrDaLmtRu2ghz => "TXPWR_DA_LMT_RU_2GHZ",
            Self::TxpwrDaLmtRu5ghz => "TXPWR_DA_LMT_RU_5GHZ",
            Self::TxpwrDaLmtRu6ghz => "TXPWR_DA_LMT_RU_6GHZ",
            Self::AfePwrSeq => "AFE_PWR_SEQ",
            Self::DiagMac => "DIAG_MAC",
            Self::TxComp => "TX_COMP",
        }
    }

    /// The `struct rtw89_rfe_data` member a TX power element fills.
    pub const fn txpwr_slot(self) -> Option<TxpwrSlot> {
        Some(match self {
            Self::TxpwrByrate => TxpwrSlot::Byrate,
            Self::TxpwrLmt2ghz => TxpwrSlot::Lmt2ghz,
            Self::TxpwrLmt5ghz => TxpwrSlot::Lmt5ghz,
            Self::TxpwrLmt6ghz => TxpwrSlot::Lmt6ghz,
            Self::TxpwrDaLmt2ghz => TxpwrSlot::DaLmt2ghz,
            Self::TxpwrDaLmt5ghz => TxpwrSlot::DaLmt5ghz,
            Self::TxpwrDaLmt6ghz => TxpwrSlot::DaLmt6ghz,
            Self::TxpwrLmtRu2ghz => TxpwrSlot::LmtRu2ghz,
            Self::TxpwrLmtRu5ghz => TxpwrSlot::LmtRu5ghz,
            Self::TxpwrLmtRu6ghz => TxpwrSlot::LmtRu6ghz,
            Self::TxpwrDaLmtRu2ghz => TxpwrSlot::DaLmtRu2ghz,
            Self::TxpwrDaLmtRu5ghz => TxpwrSlot::DaLmtRu5ghz,
            Self::TxpwrDaLmtRu6ghz => TxpwrSlot::DaLmtRu6ghz,
            Self::TxShapeLmt => TxpwrSlot::TxShapeLmt,
            Self::TxShapeLmtRu => TxpwrSlot::TxShapeLmtRu,
            _ => return None,
        })
    }
}

/// `BITS_OF_RTW89_TXPWR_FW_ELEMENTS_TX_SHAPE`.
const TX_SHAPE: u32 = Id::TxShapeLmt.bit() | Id::TxShapeLmtRu.bit();
/// `BITS_OF_RTW89_TXPWR_FW_ELEMENTS_NO_6GHZ`.
const TXPWR_NO_6GHZ: u32 = Id::TxpwrByrate.bit()
    | Id::TxpwrLmt2ghz.bit()
    | Id::TxpwrLmt5ghz.bit()
    | Id::TxpwrLmtRu2ghz.bit()
    | Id::TxpwrLmtRu5ghz.bit()
    | TX_SHAPE;
/// `RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_BASE`.
const AX_BASE: u32 =
    Id::BbReg.bit() | Id::RadioA.bit() | Id::RadioB.bit() | Id::RfNctl.bit() | Id::TxpwrTrk.bit();
/// RTL8852B's `needed_fw_elms` without its transition bit:
/// `RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_NO_6GHZ`.
pub const RTL8852B_NEEDED: u32 = AX_BASE | TXPWR_NO_6GHZ;

/// `RTW89_DEFAULT_NEEDED_FW_TXPWR_TRK_5GHZ`: types 4 to 7.
pub const TXPWR_TRK_5GHZ: u32 = 0x0000_00f0;
/// `RTW89_DEFAULT_NEEDED_FW_TXPWR_TRK_2GHZ`: types 8 to 15.
pub const TXPWR_TRK_2GHZ: u32 = 0x0000_ff00;
/// The tracking types an RTL8852B needs: its `support_bands` are 2 and
/// 5 GHz.
pub const RTL8852B_TXPWR_TRK_NEEDED: u32 = TXPWR_TRK_5GHZ | TXPWR_TRK_2GHZ;

/// What the handlers compare an element with: the efuse's RFE type,
/// `hal->aid` and `hal->cv`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Board {
    pub rfe_type: u8,
    pub aid: u16,
    pub cv: u8,
}

impl Board {
    /// An RTL8852B of this RFE type and cut.
    pub const fn rtl8852b(rfe_type: u8, cv: u8) -> Self {
        Self {
            rfe_type,
            aid: RTL8852B_AID,
            cv,
        }
    }
}

/// One `struct rtw89_fw_element_hdr` the walk reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    /// The header's offset in the file.
    pub offset: usize,
    pub id: u32,
    /// `size`, the bytes after the 32-byte header.
    pub size: u32,
    pub ver: [u8; 4],
    pub aid: u16,
    /// The union's 8 fixed bytes (`idx`, `rfe_type`, `bitmap` and so on).
    pub fixed: [u8; 8],
    /// The `size` bytes after the header, cut at the file's end.
    pub body: &'a [u8],
    /// Every byte from the body's start to the file's end.
    tail: &'a [u8],
}

impl<'a> Element<'a> {
    /// The body's offset in the file.
    pub const fn body_offset(&self) -> usize {
        self.offset + HEADER_LEN
    }

    /// The first `len` bytes from the body's start, which rtw89 reads or
    /// keeps whatever the element's size.
    fn take(&self, len: u64) -> Result<&'a [u8], Error> {
        usize::try_from(len)
            .ok()
            .and_then(|len| self.tail.get(..len))
            .ok_or(Error::BeyondFile {
                id: self.id,
                offset: self.offset,
            })
    }
}

/// `struct rtw89_reg2_def`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reg2 {
    pub addr: u32,
    pub data: u32,
}

/// `struct rtw89_phy_table`, its registers borrowed from the element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyTable<'a> {
    /// `n_regs` pairs of little-endian `addr` and `data`.
    raw: &'a [u8],
    /// `rf_path`: the radio element's path, 0 for the others.
    pub rf_path: u8,
    /// Whether rtw89 set `config`, which it does for the radio tables
    /// alone, to `rtw89_phy_config_rf_reg_v1` (RTL8852B is not RTL8852A).
    pub radio: bool,
    /// Where the registers start in the file.
    pub offset: usize,
}

impl<'a> PhyTable<'a> {
    /// `n_regs`: `size / sizeof(struct rtw89_reg2_def)`, a remainder
    /// dropped.
    pub const fn n_regs(&self) -> usize {
        self.raw.len() / 8
    }

    /// `regs[index]`.
    pub fn reg(&self, index: usize) -> Option<Reg2> {
        let pair = self.raw.get(index * 8..index * 8 + 8)?;
        Some(Reg2 {
            addr: le32(pair, 0),
            data: le32(pair, 4),
        })
    }

    /// `regs[0..n_regs]`.
    pub fn regs(&self) -> impl ExactSizeIterator<Item = Reg2> + 'a {
        let (pairs, _) = self.raw.as_chunks::<8>();
        pairs.iter().map(|pair| Reg2 {
            addr: le32(pair, 0),
            data: le32(pair, 4),
        })
    }
}

/// The `struct rtw89_rfe_data` members TX power elements fill, in its
/// order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum TxpwrSlot {
    Byrate,
    Lmt2ghz,
    Lmt5ghz,
    Lmt6ghz,
    DaLmt2ghz,
    DaLmt5ghz,
    DaLmt6ghz,
    LmtRu2ghz,
    LmtRu5ghz,
    LmtRu6ghz,
    DaLmtRu2ghz,
    DaLmtRu5ghz,
    DaLmtRu6ghz,
    TxShapeLmt,
    TxShapeLmtRu,
}

impl TxpwrSlot {
    /// Every slot, in `struct rtw89_rfe_data`'s order.
    pub const ALL: [Self; 15] = [
        Self::Byrate,
        Self::Lmt2ghz,
        Self::Lmt5ghz,
        Self::Lmt6ghz,
        Self::DaLmt2ghz,
        Self::DaLmt5ghz,
        Self::DaLmt6ghz,
        Self::LmtRu2ghz,
        Self::LmtRu5ghz,
        Self::LmtRu6ghz,
        Self::DaLmtRu2ghz,
        Self::DaLmtRu5ghz,
        Self::DaLmtRu6ghz,
        Self::TxShapeLmt,
        Self::TxShapeLmtRu,
    ];
}

/// `struct rtw89_txpwr_conf` once valid: the entries borrowed from the
/// element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxpwrConf<'a> {
    pub rfe_type: u8,
    /// `ent_sz`: the stride, which may differ from the entry struct's size.
    pub ent_sz: u8,
    pub num_ents: u32,
    /// `num_ents * ent_sz` bytes from the element's content.
    pub data: &'a [u8],
    /// Where `data` starts in the file.
    pub offset: usize,
}

impl<'a> TxpwrConf<'a> {
    /// `rtw89_for_each_in_txpwr_conf`: each entry's `ent_sz` bytes, of
    /// which `rtw89_txpwr_entcpy` copies as many as the entry struct holds
    /// over its zeroes.
    pub fn entries(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        strided(self.data, self.ent_sz)
    }
}

/// `data` cut into `stride`-byte entries; none when the stride is 0, as a
/// cursor stepping by 0 never starts below an end it already reached.
fn strided(data: &[u8], stride: u8) -> impl Iterator<Item = &[u8]> {
    let stride = usize::from(stride);
    let count = data.len().checked_div(stride).unwrap_or(0);
    (0..count).map(move |index| &data[index * stride..(index + 1) * stride])
}

/// `struct rtw89_rfe_data`, its configurations alone; rtw89 allocates it at
/// the first TX power element whose AID matches.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RfeData<'a> {
    pub confs: [Option<TxpwrConf<'a>>; 15],
}

impl<'a> RfeData<'a> {
    /// The member's `conf`, if valid.
    pub fn conf(&self, slot: TxpwrSlot) -> Option<&TxpwrConf<'a>> {
        self.confs[slot as usize].as_ref()
    }
}

/// `struct rtw89_fw_txpwr_track_cfg`: per `enum rtw89_fw_txpwr_trk_type`,
/// the delta rows its band reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxpwrTrk<'a> {
    /// `contents`: the rows the bitmap's types take, in type order.
    pub contents: &'a [u8],
    /// Where `contents` starts in the file.
    pub offset: usize,
    /// `delta[type]`: the type's first row in `contents`.
    pub delta: [Option<usize>; TXPWR_TRK_TYPE_NR],
}

impl<'a> TxpwrTrk<'a> {
    /// The rows a type spans: 4 subbands for a 6 GHz type, 3 for 5 GHz, 1
    /// for 2.4 GHz.
    pub const fn subbands(ty: usize) -> usize {
        match ty {
            0..=3 => 4,
            4..=7 => 3,
            _ => 1,
        }
    }

    /// `delta[type][subband][index]`, as signed.
    pub fn delta(&self, ty: usize, subband: usize, index: usize) -> Option<i8> {
        let row = (*self.delta.get(ty)?)?;
        if subband >= Self::subbands(ty) || index >= DELTA_SWINGIDX_SIZE {
            return None;
        }
        self.contents
            .get((row + subband) * DELTA_SWINGIDX_SIZE + index)
            .map(|&delta| delta as i8)
    }

    /// The type's rows, `subbands(ty) * DELTA_SWINGIDX_SIZE` bytes.
    pub fn rows(&self, ty: usize) -> Option<&'a [u8]> {
        let row = (*self.delta.get(ty)?)?;
        let start = row * DELTA_SWINGIDX_SIZE;
        self.contents
            .get(start..start + Self::subbands(ty) * DELTA_SWINGIDX_SIZE)
    }
}

/// `struct rtw89_regd`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Regd {
    pub alpha2: [u8; 2],
    /// `txpwr_regd[RTW89_BAND_2G..=RTW89_BAND_6G]`: an `enum
    /// rtw89_regulation_type`, [`REGD_NA`] where the element's rule is
    /// unknown.
    pub txpwr_regd: [u8; 3],
    /// `func_bitmap`: bit 0 TAS, bit 1 DAG.
    pub func_bitmap: u8,
}

/// `struct rtw89_regd_data`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegdData {
    pub map: Vec<Regd>,
}

/// A BB MCU suit `__rtw89_fw_recognize_from_elm` takes: `fw_suit->data`
/// and `size`, and the header version `rtw89_fw_update_ver` read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BbMcu<'a> {
    pub data: &'a [u8],
    pub offset: usize,
    pub hdr_ver: u8,
}

/// `struct rtw89_fw_elm_info`, `rtwdev->rfe_data` and the BB MCU suits:
/// what `rtw89_fw_recognize_elements` leaves behind.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Elements<'a> {
    pub bb_tbl: Option<PhyTable<'a>>,
    pub bb_gain: Option<PhyTable<'a>>,
    /// Indexed by the element's `idx`, not by its id.
    pub rf_radio: [Option<PhyTable<'a>>; RF_PATH_MAX],
    pub rf_nctl: Option<PhyTable<'a>>,
    pub txpwr_trk: Option<TxpwrTrk<'a>>,
    /// Allocated at the first RFK log element; indexed by `rfk_id`.
    pub rfk_log_fmt: Option<[Option<Element<'a>>; RFK_LOG_FUNC_NUM]>,
    pub regd: Option<RegdData>,
    pub afe: Option<Element<'a>>,
    pub diag_mac: Option<Element<'a>>,
    pub tx_comp: Option<Element<'a>>,
    pub rfe_data: Option<RfeData<'a>>,
    /// `fw_info->bbmcu0` and `bbmcu1`.
    pub bbmcu: [Option<BbMcu<'a>>; 2],
    /// The ids whose handler returned 0: the bits rtw89 clears from the
    /// needed mask.
    pub recognized: u32,
}

/// What a handler made of an element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// It returned 0. A TX power element of another RFE type is recognized
    /// too, though not taken.
    Recognized,
    /// It returned 1: another AID, a table of that kind already taken, or
    /// an entry it cannot hold.
    Ignored,
    /// It failed, which refuses the firmware with the error returned.
    Refused,
    /// No handler takes the id; the walk steps over it.
    Unhandled,
}

/// Why the firmware's elements are refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The firmware is no container, so it has no elements (`-EINVAL`).
    NotContainer,
    /// Needed elements are missing, as bits of [`Id`] (`-ENOENT`).
    Missing { mask: u32 },
    /// The tracking element lacks types the bands need (`-ENOENT`).
    TxpwrTrkBitmap { needed: u32, bitmap: u32 },
    /// The tracking element's types need more rows than it has
    /// (`-EFAULT`).
    TxpwrTrkOverflow { rows: u32, size: u32 },
    /// A regulation element's entries have no size (`-EINVAL`).
    RegdInvalidEntries { invalid: u32 },
    /// A BB MCU suit's header version is unknown (`-ENOENT`).
    UnknownSuitHeader { id: u32, hdr_ver: u8 },
    /// A radio element's `idx` is past `RF_PATH_MAX`, which rtw89 would
    /// index with.
    RadioIndex { id: u32, idx: u8 },
    /// A handler would read past the file's end.
    BeyondFile { id: u32, offset: usize },
}

impl Error {
    /// The errno rtw89 returns, where it returns one.
    pub const fn errno(&self) -> Option<i32> {
        match self {
            Self::NotContainer | Self::RegdInvalidEntries { .. } => Some(-22),
            Self::Missing { .. } | Self::TxpwrTrkBitmap { .. } => Some(-2),
            Self::UnknownSuitHeader { .. } => Some(-2),
            Self::TxpwrTrkOverflow { .. } => Some(-14),
            Self::RadioIndex { .. } | Self::BeyondFile { .. } => None,
        }
    }

    /// The missing elements, in id order.
    pub fn missing(&self) -> impl Iterator<Item = Id> + '_ {
        let mask = match self {
            Self::Missing { mask } => *mask,
            _ => 0,
        };
        Id::ALL.into_iter().filter(move |id| mask & id.bit() != 0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotContainer => f.write_str("firmware is no container and has no elements"),
            Self::Missing { mask } => {
                write!(f, "firmware elements {mask:#010x} are unrecognized:")?;
                for id in self.missing() {
                    write!(f, " {}", id.name())?;
                }
                Ok(())
            }
            Self::TxpwrTrkBitmap { needed, bitmap } => {
                write!(f, "needed txpwr trk bitmap {needed:08x} but {bitmap:08x}")
            }
            Self::TxpwrTrkOverflow { rows, size } => {
                write!(f, "unexpected txpwr trk offset {rows} over size {size}")
            }
            Self::RegdInvalidEntries { invalid } => {
                write!(f, "regd element has {invalid} invalid ents")
            }
            Self::UnknownSuitHeader { id, hdr_ver } => {
                write!(f, "element {id}: unknown firmware header version {hdr_ver}")
            }
            Self::RadioIndex { id, idx } => write!(f, "element {id}: radio index {idx}"),
            Self::BeyondFile { id, offset } => {
                write!(f, "element {id} at {offset:#x} runs past the file")
            }
        }
    }
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

const fn align(offset: usize) -> usize {
    (offset + ELEMENT_ALIGN - 1) & !(ELEMENT_ALIGN - 1)
}

impl<'a> Elements<'a> {
    /// `rtw89_fw_recognize_elements` over a parsed firmware's trailing
    /// elements.
    pub fn recognize(firmware: &Rtw89<'a>, board: Board) -> Result<Self, Error> {
        Self::recognize_with(firmware, board, |_, _| {})
    }

    /// [`Self::recognize`], telling `seen` what became of each element the
    /// walk reached, in order.
    pub fn recognize_with(
        firmware: &Rtw89<'a>,
        board: Board,
        seen: impl FnMut(&Element<'a>, Outcome),
    ) -> Result<Self, Error> {
        Self::parse(
            firmware.trailing_elements,
            firmware.elements_offset,
            board,
            seen,
        )
    }

    /// The walk over `trailing`, the file from `base` (`rtw89_mfw_get_size`,
    /// 0 for no container) to its end.
    pub fn parse(
        trailing: &'a [u8],
        base: usize,
        board: Board,
        mut seen: impl FnMut(&Element<'a>, Outcome),
    ) -> Result<Self, Error> {
        let file_size = base + trailing.len();
        let mut unrecognized = RTL8852B_NEEDED;
        let mut elements = Self::default();
        let mut offset = align(base);
        if offset == 0 {
            return Err(Error::NotContainer);
        }
        while offset + HEADER_LEN < file_size {
            let header = &trailing[offset - base..offset - base + HEADER_LEN];
            let size = le32(header, 4);
            // "firmware element size exceeds": the walk ends, and whatever
            // is still unrecognized decides.
            if offset as u64 + u64::from(size) >= file_size as u64 {
                break;
            }
            let tail = &trailing[offset - base + HEADER_LEN..];
            let element = Element {
                offset,
                id: le32(header, 0),
                size,
                ver: header[8..12].try_into().unwrap(),
                aid: le16(header, 12),
                fixed: header[24..32].try_into().unwrap(),
                body: &tail[..tail.len().min(size as usize)],
                tail,
            };
            offset = align(offset + HEADER_LEN + size as usize);
            let Some(id) = Id::from_raw(element.id) else {
                seen(&element, Outcome::Unhandled);
                continue;
            };
            match elements.handle(id, &element, board) {
                Ok(true) => {
                    seen(&element, Outcome::Recognized);
                    elements.recognized |= id.bit();
                    unrecognized &= !id.bit();
                }
                Ok(false) => seen(&element, Outcome::Ignored),
                Err(error) => {
                    seen(&element, Outcome::Refused);
                    return Err(error);
                }
            }
        }
        if unrecognized != 0 {
            return Err(Error::Missing { mask: unrecognized });
        }
        Ok(elements)
    }

    /// The elements found beyond the needed ones.
    pub const fn optional(&self) -> u32 {
        self.recognized & !RTL8852B_NEEDED
    }

    /// `rf_radio[path]`.
    pub fn radio(&self, path: usize) -> Option<&PhyTable<'a>> {
        self.rf_radio.get(path)?.as_ref()
    }

    /// One `__fw_element_handlers` entry: `Ok(true)` for 0, `Ok(false)` for
    /// 1.
    fn handle(&mut self, id: Id, element: &Element<'a>, board: Board) -> Result<bool, Error> {
        let aid_differs = element.aid != 0 && element.aid != board.aid;
        match id {
            Id::Bbmcu0 | Id::Bbmcu1 => self.bbmcu(id, element, board),
            Id::BbReg
            | Id::BbGain
            | Id::RadioA
            | Id::RadioB
            | Id::RadioC
            | Id::RadioD
            | Id::RfNctl => self.phy(id, element, aid_differs),
            Id::TxpwrTrk => {
                if aid_differs {
                    return Ok(false);
                }
                self.txpwr_trk = Some(txpwr_trk(element)?);
                Ok(true)
            }
            Id::RfklogFmt => {
                // rtw89_build_rfk_log_fmt_from_elm allocates before it
                // looks at the id.
                let formats = self.rfk_log_fmt.get_or_insert([None; RFK_LOG_FUNC_NUM]);
                let Some(slot) = formats.get_mut(usize::from(element.fixed[4])) else {
                    return Ok(false);
                };
                element.take(element.size.into())?;
                *slot = Some(*element);
                Ok(true)
            }
            Id::Regd => {
                let Some(regd) = regd(element)? else {
                    return Ok(false);
                };
                self.regd = Some(regd);
                Ok(true)
            }
            Id::AfePwrSeq | Id::DiagMac => {
                element.take(element.size.into())?;
                let slot = if id == Id::AfePwrSeq {
                    &mut self.afe
                } else {
                    &mut self.diag_mac
                };
                *slot = Some(*element);
                Ok(true)
            }
            Id::TxComp => {
                let rfe_type = element.fixed[0];
                if aid_differs
                    || (rfe_type != 0 && rfe_type != board.rfe_type)
                    || self.tx_comp.is_some()
                {
                    return Ok(false);
                }
                element.take(element.size.into())?;
                self.tx_comp = Some(*element);
                Ok(true)
            }
            Id::TxpwrByrate
            | Id::TxpwrLmt2ghz
            | Id::TxpwrLmt5ghz
            | Id::TxpwrLmt6ghz
            | Id::TxpwrLmtRu2ghz
            | Id::TxpwrLmtRu5ghz
            | Id::TxpwrLmtRu6ghz
            | Id::TxShapeLmt
            | Id::TxShapeLmtRu
            | Id::TxpwrDaLmt2ghz
            | Id::TxpwrDaLmt5ghz
            | Id::TxpwrDaLmt6ghz
            | Id::TxpwrDaLmtRu2ghz
            | Id::TxpwrDaLmtRu5ghz
            | Id::TxpwrDaLmtRu6ghz => {
                let Some(slot) = id.txpwr_slot() else {
                    return Ok(false);
                };
                if aid_differs {
                    return Ok(false);
                }
                let data = self.rfe_data.get_or_insert_with(RfeData::default);
                let conf = &mut data.confs[slot as usize];
                let rfe_type = element.fixed[2];
                // The last of the board's RFE type wins; one of the default
                // type stands in until one does.
                let take = rfe_type == board.rfe_type
                    || (rfe_type == DFLT_RFE_TYPE
                        && conf.is_none_or(|conf| conf.rfe_type == DFLT_RFE_TYPE));
                if take {
                    let ent_sz = element.fixed[3];
                    let num_ents = le32(&element.fixed, 4);
                    *conf = Some(TxpwrConf {
                        rfe_type,
                        ent_sz,
                        num_ents,
                        data: element.take(u64::from(num_ents) * u64::from(ent_sz))?,
                        offset: element.body_offset(),
                    });
                }
                Ok(true)
            }
        }
    }

    /// `rtw89_build_phy_tbl_from_elm`.
    fn phy(&mut self, id: Id, element: &Element<'a>, aid_differs: bool) -> Result<bool, Error> {
        let (index, rf_path) = match id {
            Id::RadioA => (element.fixed[0], Some(0)),
            Id::RadioB => (element.fixed[0], Some(1)),
            Id::RadioC => (element.fixed[0], Some(2)),
            Id::RadioD => (element.fixed[0], Some(3)),
            _ => (0, None),
        };
        if aid_differs {
            return Ok(false);
        }
        let slot = match id {
            Id::BbReg => &mut self.bb_tbl,
            Id::BbGain => &mut self.bb_gain,
            Id::RfNctl => &mut self.rf_nctl,
            _ => self
                .rf_radio
                .get_mut(usize::from(index))
                .ok_or(Error::RadioIndex {
                    id: element.id,
                    idx: index,
                })?,
        };
        if slot.is_some() {
            return Ok(false);
        }
        let n_regs = element.size / 8;
        *slot = Some(PhyTable {
            raw: element.take(u64::from(n_regs) * 8)?,
            rf_path: rf_path.unwrap_or(0),
            radio: rf_path.is_some(),
            offset: element.body_offset(),
        });
        Ok(true)
    }

    /// `__rtw89_fw_recognize_from_elm` for a BB MCU suit.
    fn bbmcu(&mut self, id: Id, element: &Element<'a>, board: Board) -> Result<bool, Error> {
        // Suits come in decreasing cut order: the first not above the
        // chip's wins.
        let slot = &mut self.bbmcu[id as usize];
        if board.cv < element.fixed[0] || slot.is_some() {
            return Ok(false);
        }
        // rtw89_fw_update_ver: the header version is bits 31:24 of w3, and
        // either header reads eight words.
        let header = element.take(32)?;
        let hdr_ver = header[15];
        if hdr_ver > 1 {
            return Err(Error::UnknownSuitHeader {
                id: element.id,
                hdr_ver,
            });
        }
        *slot = Some(BbMcu {
            data: element.take(element.size.into())?,
            offset: element.body_offset(),
            hdr_ver,
        });
        Ok(true)
    }
}

/// `rtw89_build_txpwr_trk_tbl_from_elm`, past its AID check.
fn txpwr_trk<'a>(element: &Element<'a>) -> Result<TxpwrTrk<'a>, Error> {
    let needed = RTL8852B_TXPWR_TRK_NEEDED;
    let bitmap = le32(&element.fixed, 0);
    if bitmap & needed != needed {
        return Err(Error::TxpwrTrkBitmap { needed, bitmap });
    }
    let mut delta = [None; TXPWR_TRK_TYPE_NR];
    let mut rows = 0u32;
    let (mut ty, mut bits) = (0, bitmap);
    while bits != 0 {
        if bits & 1 != 0 {
            // A type past 2.4 GHz's ends the walk over the bitmap.
            if ty >= TXPWR_TRK_TYPE_NR {
                break;
            }
            delta[ty] = Some(rows as usize);
            rows += TxpwrTrk::subbands(ty) as u32;
            if u64::from(rows) * DELTA_SWINGIDX_SIZE as u64 > u64::from(element.size) {
                return Err(Error::TxpwrTrkOverflow {
                    rows,
                    size: element.size,
                });
            }
        }
        ty += 1;
        bits >>= 1;
    }
    Ok(TxpwrTrk {
        contents: element.take(u64::from(rows) * DELTA_SWINGIDX_SIZE as u64)?,
        offset: element.body_offset(),
        delta,
    })
}

/// `rtw89_recognize_regd_from_elm`: `None` where it returns 1.
fn regd(element: &Element<'_>) -> Result<Option<RegdData>, Error> {
    let ent_sz = element.fixed[3];
    let num_ents = le32(&element.fixed, 4);
    if num_ents > REGD_MAX_COUNTRY_NUM {
        return Ok(None);
    }
    // The entries step by ent_sz: none fit when it is 0.
    if ent_sz == 0 && num_ents != 0 {
        return Err(Error::RegdInvalidEntries { invalid: num_ents });
    }
    let data = element.take(u64::from(num_ents) * u64::from(ent_sz))?;
    let map = strided(data, ent_sz).map(regd_entcpy).collect();
    Ok(Some(RegdData { map }))
}

/// `rtw89_regd_entcpy`: the entry's first bytes over
/// `struct rtw89_fw_regd_entry`'s defaults (no alpha2, every rule
/// `RTW89_NA`, no function).
fn regd_entcpy(cursor: &[u8]) -> Regd {
    let mut entry = [0, 0, REGD_NA, REGD_NA, REGD_NA, 0, 0, 0, 0];
    let valid = cursor.len().min(entry.len());
    entry[..valid].copy_from_slice(&cursor[..valid]);
    let rule = |raw: u8| if raw < REGD_NUM { raw } else { REGD_NA };
    let fmap = le32(&entry, 5);
    Regd {
        alpha2: [entry[0], entry[1]],
        txpwr_regd: [rule(entry[2]), rule(entry[3]), rule(entry[4])],
        func_bitmap: (fmap & ((1 << NUM_OF_REGD_FUNC) - 1)) as u8,
    }
}

#[cfg(test)]
pub(super) mod tests;
