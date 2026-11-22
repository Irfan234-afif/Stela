// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! An RTL8852B's address and BSSID CAMs as pinned rtw89 keeps them for a
//! station (cam.c) and sends them to the firmware (fw.c):
//!
//! - [`Info`] is `rtw89_cam_info`'s address and BSSID CAM maps;
//!   [`Info::init`] and [`Info::deinit`] are `rtw89_cam_init` and
//!   `rtw89_cam_deinit`, with `rtw89_cam_init_bssid_cam` and
//!   `rtw89_cam_init_addr_cam` (RTL8852B's long entry, `ADDR_CAM_ENT_SIZE`);
//! - [`addr_cam`] is the payload of `rtw89_fw_h2c_cam` on an AX chip
//!   (`struct rtw89_h2c_addr_cam_v0`, address CAM version 0), which
//!   `rtw89_cam_fill_addr_cam_info` and `rtw89_cam_fill_bssid_cam_info`
//!   fill, and [`send_addr_cam`] sends it.
//!
//! A station's AP shares the link's address CAM entry, so the AP-mode and
//! TDLS entries rtw89 keeps per station are not built. An address CAM sent
//! proves only that its H2C's BD was written: whether the firmware matched
//! frames by it is answered, if at all, by DONE_ACK on RXQ.
use super::{
    h2c::{
        Error as H2cError,
        station::{Error, Link, Peer, UpdMode},
    },
    io::{Io, prep},
    mac::{Commands, port::NET_TYPE_INFRA},
};

/// `rtw8852b_chip_info.acam_num` and `.bcam_num`.
pub const ACAM_NUM: u8 = 128;
pub const BCAM_NUM: u8 = 10;
/// `RTW89_SEC_CAM_IN_ADDR_CAM`: the key slots of an address CAM entry.
pub const SEC_CAM_IN_ADDR_CAM: usize = 7;
/// `ADDR_CAM_ENT_SIZE` (RTL8852B's) and `BSSID_CAM_ENT_SIZE`.
pub const ADDR_CAM_ENT_SIZE: u8 = 0x40;
pub const BSSID_CAM_ENT_SIZE: u8 = 0x08;
/// `RTW89_BSSID_MATCH_ALL` and `RTW89_BSSID_MATCH_5_BYTES`.
pub const BSSID_MATCH_ALL: u32 = 0x3f;
pub const BSSID_MATCH_5_BYTES: u32 = 0x1f;
/// `enum rtw89_add_cam_sec_mode`.
pub const ADDR_CAM_SEC_NONE: u8 = 0;
pub const ADDR_CAM_SEC_ALL_UNI: u8 = 1;
pub const ADDR_CAM_SEC_NORMAL: u8 = 2;
pub const ADDR_CAM_SEC_4GROUP: u8 = 3;
/// `RTW89_NO_MSK`, `RTW89_SMA` and `RTW89_TMA`.
pub const NO_MSK: u8 = 0;
pub const SMA: u8 = 1;
pub const TMA: u8 = 2;

/// `H2C_CL_MAC_ADDR_CAM_UPDATE` with `H2C_FUNC_MAC_ADDR_CAM_UPD`, and
/// `sizeof(struct rtw89_h2c_addr_cam_v0)`.
pub const H2C_CL_MAC_ADDR_CAM_UPDATE: u8 = 0x6;
pub const H2C_FUNC_MAC_ADDR_CAM_UPD: u8 = 0x0;
pub const ADDR_CAM_LEN: usize = 60;

/// cam.h's `ADDR_CAM_W*` fields of address CAM version 0.
pub const ADDR_CAM_W1_IDX: u32 = 0x0000_00ff;
pub const ADDR_CAM_W1_OFFSET: u32 = 0x0000_ff00;
pub const ADDR_CAM_W1_LEN: u32 = 0x00ff_0000;
pub const ADDR_CAM_W2_VALID: u32 = 1 << 0;
pub const ADDR_CAM_W2_NET_TYPE: u32 = 0x0000_0006;
pub const ADDR_CAM_W2_BCN_HIT_COND: u32 = 0x0000_0018;
pub const ADDR_CAM_W2_HIT_RULE: u32 = 0x0000_0060;
pub const ADDR_CAM_W2_BB_SEL: u32 = 1 << 7;
pub const ADDR_CAM_W2_ADDR_MASK: u32 = 0x0000_3f00;
pub const ADDR_CAM_W2_MASK_SEL: u32 = 0x0000_c000;
pub const ADDR_CAM_W2_SMA_HASH: u32 = 0x00ff_0000;
pub const ADDR_CAM_W2_TMA_HASH: u32 = 0xff00_0000;
pub const ADDR_CAM_W3_BSSID_CAM_IDX: u32 = 0x0000_003f;
pub const ADDR_CAM_W8_MACID: u32 = 0x0000_00ff;
pub const ADDR_CAM_W8_PORT_INT: u32 = 0x0000_0700;
pub const ADDR_CAM_W8_TSF_SYNC: u32 = 0x0000_3800;
pub const ADDR_CAM_W8_TF_TRS: u32 = 1 << 14;
pub const ADDR_CAM_W8_LSIG_TXOP: u32 = 1 << 15;
pub const ADDR_CAM_W8_TGT_IND: u32 = 0x0700_0000;
pub const ADDR_CAM_W8_FRM_TGT_IND: u32 = 0x3800_0000;
pub const ADDR_CAM_W9_AID12: u32 = 0x0000_0fff;
pub const ADDR_CAM_W9_WOL_PATTERN: u32 = 1 << 12;
pub const ADDR_CAM_W9_WOL_UC: u32 = 1 << 13;
pub const ADDR_CAM_W9_WOL_MAGIC: u32 = 1 << 14;
pub const ADDR_CAM_W9_WAPI: u32 = 1 << 15;
pub const ADDR_CAM_W9_SEC_ENT_MODE: u32 = 0x0003_0000;
/// `ADDR_CAM_W9_SEC_ENT0_KEYID`: slot `i`'s key ID is 2 bits at 18 + 2i.
pub const ADDR_CAM_W9_SEC_ENT0_KEYID: u32 = 0x000c_0000;
pub const ADDR_CAM_W10_SEC_ENT_VALID: u32 = 0x0000_00ff;
pub const ADDR_CAM_W12_BSSID_IDX: u32 = 0x0000_00ff;
pub const ADDR_CAM_W12_BSSID_OFFSET: u32 = 0x0000_ff00;
pub const ADDR_CAM_W12_BSSID_LEN: u32 = 0x00ff_0000;
pub const ADDR_CAM_W13_BSSID_VALID: u32 = 1 << 0;
pub const ADDR_CAM_W13_BSSID_BB_SEL: u32 = 1 << 1;
pub const ADDR_CAM_W13_BSSID_MASK: u32 = 0x0000_00fc;
pub const ADDR_CAM_W13_BSSID_BSS_COLOR: u32 = 0x0000_3f00;

/// `struct rtw89_addr_cam_entry`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddrCamEntry {
    pub addr_cam_idx: u8,
    pub offset: u8,
    pub len: u8,
    pub valid: bool,
    pub addr_mask: u8,
    pub mask_sel: u8,
    pub sec_ent_mode: u8,
    /// `sec_cam_map`: which of the seven key slots hold a key.
    pub sec_cam_map: u8,
    pub sec_ent_keyid: [u8; SEC_CAM_IN_ADDR_CAM],
    pub sec_ent: [u8; SEC_CAM_IN_ADDR_CAM],
    pub bssid_cam_idx: u8,
    pub wapi: bool,
}

/// `struct rtw89_bssid_cam_entry`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BssidCamEntry {
    pub bssid: [u8; 6],
    pub phy_idx: u8,
    pub bssid_cam_idx: u8,
    pub offset: u8,
    pub len: u8,
    pub valid: bool,
}

/// `rtw89_cam_info`: which address and BSSID CAM entries are taken.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub addr_cam_map: u128,
    pub bssid_cam_map: u16,
}

/// `find_first_zero_bit` over the low `n` bits of `map`: `n` when every
/// bit is set.
fn first_zero(map: u128, n: u8) -> u8 {
    (0..n).find(|&i| map & (1 << i) == 0).unwrap_or(n)
}

impl Info {
    /// `rtw89_cam_init_addr_cam`: the first free address CAM entry, long,
    /// valid, unmasked, in the normal key mode with no keys, tied to BSSID
    /// CAM entry `bssid_cam_idx`. An entry already valid is left as it is.
    pub fn init_addr_cam(
        &mut self,
        addr_cam: &mut AddrCamEntry,
        bssid_cam_idx: u8,
    ) -> Result<(), Error> {
        if addr_cam.valid {
            return Ok(());
        }
        let idx = first_zero(self.addr_cam_map, ACAM_NUM);
        if idx >= ACAM_NUM {
            return Err(Error::CamFull("address CAM"));
        }
        self.addr_cam_map |= 1 << idx;
        *addr_cam = AddrCamEntry {
            addr_cam_idx: idx,
            len: ADDR_CAM_ENT_SIZE,
            offset: 0,
            valid: true,
            addr_mask: 0,
            mask_sel: NO_MSK,
            sec_ent_mode: ADDR_CAM_SEC_NORMAL,
            sec_cam_map: 0,
            sec_ent_keyid: [0; SEC_CAM_IN_ADDR_CAM],
            sec_ent: [0; SEC_CAM_IN_ADDR_CAM],
            bssid_cam_idx,
            wapi: addr_cam.wapi,
        };
        Ok(())
    }

    /// `rtw89_cam_init_bssid_cam`: the first free BSSID CAM entry, valid,
    /// on `phy_idx`, holding `bssid`. An entry already valid is left as it
    /// is.
    pub fn init_bssid_cam(
        &mut self,
        phy_idx: u8,
        bssid_cam: &mut BssidCamEntry,
        bssid: [u8; 6],
    ) -> Result<(), Error> {
        if bssid_cam.valid {
            return Ok(());
        }
        let idx = first_zero(self.bssid_cam_map.into(), BCAM_NUM);
        if idx >= BCAM_NUM {
            return Err(Error::CamFull("BSSID CAM"));
        }
        self.bssid_cam_map |= 1 << idx;
        *bssid_cam = BssidCamEntry {
            bssid,
            phy_idx,
            bssid_cam_idx: idx,
            offset: 0,
            len: BSSID_CAM_ENT_SIZE,
            valid: true,
        };
        Ok(())
    }

    /// `rtw89_cam_init`: the link's BSSID CAM entry, then its address CAM
    /// entry tied to it.
    pub fn init(&mut self, link: &mut Link) -> Result<(), Error> {
        let bssid = link.bssid;
        self.init_bssid_cam(link.phy_idx, &mut link.bssid_cam, bssid)?;
        let bssid_cam_idx = link.bssid_cam.bssid_cam_idx;
        self.init_addr_cam(&mut link.addr_cam, bssid_cam_idx)
    }

    /// `rtw89_cam_deinit`: both of the link's entries invalid and freed.
    pub fn deinit(&mut self, link: &mut Link) {
        link.addr_cam.valid = false;
        self.addr_cam_map &= !(1 << (link.addr_cam.addr_cam_idx & 0x7f));
        link.bssid_cam.valid = false;
        self.bssid_cam_map &= !(1 << (link.bssid_cam.bssid_cam_idx & 0xf));
    }
}

/// `rtw89_cam_addr_hash`: the bytes of `addr` from `start` XORed.
pub fn addr_hash(start: u8, addr: &[u8; 6]) -> u8 {
    addr.iter()
        .skip(usize::from(start))
        .fold(0, |hash, byte| hash ^ byte)
}

/// `rtw89_fw_h2c_cam`'s payload on an AX chip: `rtw89_cam_fill_addr_cam_info`
/// (version 0) and `rtw89_cam_fill_bssid_cam_info` over the link's own
/// address CAM entry, as a station's AP shares it. The transmitter is
/// `peer`'s address when there is one, else the BSSID; the sender is
/// `scan_mac_addr` when given, else the link's address.
pub fn addr_cam(
    link: &Link,
    peer: Option<&Peer>,
    scan_mac_addr: Option<[u8; 6]>,
) -> [u8; ADDR_CAM_LEN] {
    let addr_cam = &link.addr_cam;
    let bssid_cam = &link.bssid_cam;
    let sma = scan_mac_addr.unwrap_or(link.mac_addr);
    let tma = peer.map_or(link.bssid, |peer| peer.addr);
    let (mut sma_start, mut tma_start) = (0, 0);
    if addr_cam.addr_mask != 0 {
        let start = addr_cam.addr_mask.trailing_zeros() as u8;
        if addr_cam.mask_sel == SMA {
            sma_start = start;
        } else if addr_cam.mask_sel == TMA {
            tma_start = start;
        }
    }
    let sma_hash = addr_hash(sma_start, &sma);
    let tma_hash = addr_hash(tma_start, &tma);
    let mac_id = link.mac_id;
    let word = |bytes: [u8; 4]| u32::from_le_bytes(bytes);

    let mut w = [0u32; ADDR_CAM_LEN / 4];
    w[1] = prep(addr_cam.addr_cam_idx.into(), ADDR_CAM_W1_IDX)
        | prep(addr_cam.offset.into(), ADDR_CAM_W1_OFFSET)
        | prep(addr_cam.len.into(), ADDR_CAM_W1_LEN);
    w[2] = prep(addr_cam.valid.into(), ADDR_CAM_W2_VALID)
        | prep(link.net_type.into(), ADDR_CAM_W2_NET_TYPE)
        | prep(link.bcn_hit_cond.into(), ADDR_CAM_W2_BCN_HIT_COND)
        | prep(link.hit_rule.into(), ADDR_CAM_W2_HIT_RULE)
        | prep(link.phy_idx.into(), ADDR_CAM_W2_BB_SEL)
        | prep(addr_cam.addr_mask.into(), ADDR_CAM_W2_ADDR_MASK)
        | prep(addr_cam.mask_sel.into(), ADDR_CAM_W2_MASK_SEL)
        | prep(sma_hash.into(), ADDR_CAM_W2_SMA_HASH)
        | prep(tma_hash.into(), ADDR_CAM_W2_TMA_HASH);
    w[3] = prep(addr_cam.bssid_cam_idx.into(), ADDR_CAM_W3_BSSID_CAM_IDX);
    w[4] = word([sma[0], sma[1], sma[2], sma[3]]);
    w[5] = word([sma[4], sma[5], tma[0], tma[1]]);
    w[6] = word([tma[2], tma[3], tma[4], tma[5]]);
    w[8] = prep(link.port.into(), ADDR_CAM_W8_PORT_INT)
        | prep(link.port.into(), ADDR_CAM_W8_TSF_SYNC)
        | prep(link.trigger.into(), ADDR_CAM_W8_TF_TRS)
        | prep(link.lsig_txop.into(), ADDR_CAM_W8_LSIG_TXOP)
        | prep(link.tgt_ind.into(), ADDR_CAM_W8_TGT_IND)
        | prep(link.frm_tgt_ind.into(), ADDR_CAM_W8_FRM_TGT_IND)
        | prep(mac_id.into(), ADDR_CAM_W8_MACID);
    // An AP link would carry its station's AID instead: not built here.
    if link.net_type == NET_TYPE_INFRA {
        w[9] = prep(u32::from(link.bss.aid & 0xfff), ADDR_CAM_W9_AID12);
    }
    // The wake-on-WLAN bits are never set for a station.
    w[9] |= prep(addr_cam.wapi.into(), ADDR_CAM_W9_WAPI)
        | prep(addr_cam.sec_ent_mode.into(), ADDR_CAM_W9_SEC_ENT_MODE);
    for (i, keyid) in addr_cam.sec_ent_keyid.iter().enumerate() {
        w[9] |= prep((*keyid).into(), ADDR_CAM_W9_SEC_ENT0_KEYID << (2 * i));
    }
    let e = &addr_cam.sec_ent;
    w[10] =
        prep(addr_cam.sec_cam_map.into(), ADDR_CAM_W10_SEC_ENT_VALID) | word([0, e[0], e[1], e[2]]);
    w[11] = word([e[3], e[4], e[5], e[6]]);
    // rtw89_cam_fill_bssid_cam_info: a transmitted BSSID, matched whole.
    w[12] = prep(bssid_cam.bssid_cam_idx.into(), ADDR_CAM_W12_BSSID_IDX)
        | prep(bssid_cam.offset.into(), ADDR_CAM_W12_BSSID_OFFSET)
        | prep(bssid_cam.len.into(), ADDR_CAM_W12_BSSID_LEN);
    let b = &bssid_cam.bssid;
    w[13] = prep(bssid_cam.valid.into(), ADDR_CAM_W13_BSSID_VALID)
        | prep(BSSID_MATCH_ALL, ADDR_CAM_W13_BSSID_MASK)
        | prep(bssid_cam.phy_idx.into(), ADDR_CAM_W13_BSSID_BB_SEL)
        | prep(link.bss.bss_color.into(), ADDR_CAM_W13_BSSID_BSS_COLOR)
        | word([0, 0, b[0], b[1]]);
    w[14] = word([b[2], b[3], b[4], b[5]]);

    let mut bytes = [0; ADDR_CAM_LEN];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(w) {
        *chunk = word.to_le_bytes();
    }
    bytes
}

/// `rtw89_fw_h2c_cam`: [`addr_cam`] as `H2C_FUNC_MAC_ADDR_CAM_UPD`, asking
/// DONE_ACK. Version 0 carries no update mode, so `upd_mode` names only
/// why rtw89 sends it.
pub fn send_addr_cam<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &Link,
    peer: Option<&Peer>,
    scan_mac_addr: Option<[u8; 6]>,
    upd_mode: UpdMode,
) -> Result<(), H2cError> {
    let _ = upd_mode;
    let payload = addr_cam(link, peer, scan_mac_addr);
    commands.send(
        io,
        H2C_CL_MAC_ADDR_CAM_UPDATE,
        H2C_FUNC_MAC_ADDR_CAM_UPD,
        false,
        true,
        &payload,
    )
}

#[cfg(test)]
mod tests;
