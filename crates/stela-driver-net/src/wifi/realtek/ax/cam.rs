// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
//! An RTL8852B's address, BSSID and security CAMs as pinned rtw89 keeps them
//! for a station (cam.c) and sends them to the firmware (fw.c):
//!
//! - [`Info`] is `rtw89_cam_info`'s maps and security entries;
//!   [`Info::init`] and [`Info::deinit`] are `rtw89_cam_init` and
//!   `rtw89_cam_deinit`, with `rtw89_cam_init_bssid_cam` and
//!   `rtw89_cam_init_addr_cam` (RTL8852B's long entry, `ADDR_CAM_ENT_SIZE`);
//! - [`addr_cam`] is the payload of `rtw89_fw_h2c_cam` on an AX chip
//!   (`struct rtw89_h2c_addr_cam_v0`, address CAM version 0), which
//!   `rtw89_cam_fill_addr_cam_info` and `rtw89_cam_fill_bssid_cam_info`
//!   fill, and [`send_addr_cam`] sends it;
//! - [`write_key`] is `rtw89_cam_sec_key_add` for what a station keeps in
//!   hardware: a CCMP-128 pairwise or group key gets a security CAM entry
//!   (`rtw89_cam_sec_key_install`), sent as `H2C_FUNC_MAC_SEC_UPD`
//!   ([`sec_key_cmd`], `rtw89_cam_send_sec_key_cmd`), then a slot of the
//!   link's address CAM entry (`__rtw89_cam_attach_sec_cam` with
//!   `rtw89_cam_get_addr_cam_key_idx`), which the address CAM H2C carries;
//!   [`clear_key`] is `rtw89_cam_sec_key_del` with the firmware informed.
//!
//! RTL8852B has no `h2c_dctl_sec_cam` (rtw8852b.c), so the address CAM is
//! the only table a key reaches. Its `hw_sec_hdr` is false: the chip
//! neither builds nor strips a CCMP header, the host makes each IV
//! (`IEEE80211_KEY_FLAG_GENERATE_IV`, Stela's `Protection::HostIv`) and the
//! chip encrypts and decrypts the payload under the key. Its
//! `hw_mgmt_tx_encrypt` is false: protected management frames are sealed
//! by the host (`IEEE80211_KEY_FLAG_SW_MGMT_TX`), with `ccmp::seal` and
//! `ccmp::open`.
//!
//! Refused here, and why:
//! - TKIP, pairwise or group: RTL8852B's `hw_tkip_crypto` is false, so rtw89
//!   refuses it as well (`-EOPNOTSUPP`, before anything is sent) and
//!   mac80211 keeps the key in software. Stela's station does the same with
//!   a TKIP group key, decrypting the AP's group frames on the host
//!   ([`crate::wifi::security::tkip`]); it never chooses TKIP pairwise.
//! - The IGTK (AES-CMAC, `RTW89_SEC_KEY_TYPE_BIP_CCMP128`): rtw89 puts it
//!   in the CAM, but Stela checks BIP in software, so it stays there.
//! - WEP, CCMP-256 and GCMP: no Stela station negotiates them.
//!
//! A key written proves only that its H2C's BD was written: whether the
//! firmware took it is answered, if at all, by REC_ACK on RXQ, and whether
//! the chip decrypts with it shows only in received frames.
use super::{
    h2c::{
        Error as H2cError,
        station::{Error, Link, Peer, UpdMode},
    },
    io::{Io, prep},
    mac::{Commands, port::NET_TYPE_INFRA},
};
use alloc::collections::BTreeMap;
use zeroize::Zeroize;

/// `rtw8852b_chip_info.acam_num`, `.bcam_num` and `.scam_num`.
pub const ACAM_NUM: u8 = 128;
pub const BCAM_NUM: u8 = 10;
pub const SCAM_NUM: u8 = 128;
/// `RTW89_SEC_CAM_IN_ADDR_CAM`: the key slots of an address CAM entry.
pub const SEC_CAM_IN_ADDR_CAM: usize = 7;
/// `ADDR_CAM_ENT_SIZE` (RTL8852B's), `BSSID_CAM_ENT_SIZE` and
/// `RTW89_SEC_CAM_LEN`.
pub const ADDR_CAM_ENT_SIZE: u8 = 0x40;
pub const BSSID_CAM_ENT_SIZE: u8 = 0x08;
pub const SEC_CAM_LEN: u8 = 20;
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
/// `RTW89_SEC_KEY_TYPE_TKIP`, `_CCMP128` and `_BIP_CCMP128`.
pub const SEC_KEY_TYPE_TKIP: u8 = 3;
pub const SEC_KEY_TYPE_CCMP128: u8 = 6;
pub const SEC_KEY_TYPE_BIP_CCMP128: u8 = 10;

/// `H2C_CL_MAC_ADDR_CAM_UPDATE` with `H2C_FUNC_MAC_ADDR_CAM_UPD`, and
/// `sizeof(struct rtw89_h2c_addr_cam_v0)`.
pub const H2C_CL_MAC_ADDR_CAM_UPDATE: u8 = 0x6;
pub const H2C_FUNC_MAC_ADDR_CAM_UPD: u8 = 0x0;
pub const ADDR_CAM_LEN: usize = 60;
/// `H2C_CL_MAC_SEC_CAM` with `H2C_FUNC_MAC_SEC_UPD`, and `H2C_SEC_CAM_LEN`.
pub const H2C_CL_MAC_SEC_CAM: u8 = 0xa;
pub const H2C_FUNC_MAC_SEC_UPD: u8 = 0x1;
pub const H2C_SEC_CAM_LEN: usize = 24;

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

/// `struct rtw89_sec_cam_entry`, with what rtw89 reads of its
/// `key_conf`: whether the key is pairwise and its key ID. The key is
/// zeroed when the entry is dropped.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecCamEntry {
    pub sec_cam_idx: u8,
    pub offset: u8,
    pub len: u8,
    pub key_type: u8,
    pub ext_key: bool,
    pub spp_mode: bool,
    pub key: [u8; 32],
    pub pairwise: bool,
    pub keyidx: u8,
}

impl Drop for SecCamEntry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// `rtw89_cam_info`: which address, BSSID and security CAM entries are
/// taken, and each security entry's key.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub addr_cam_map: u128,
    pub bssid_cam_map: u16,
    pub sec_cam_map: u128,
    pub sec_entries: BTreeMap<u8, SecCamEntry>,
}

/// `find_first_zero_bit` over the low `n` bits of `map`: `n` when every
/// bit is set.
fn first_zero(map: u128, n: u8) -> u8 {
    (0..n).find(|&i| map & (1 << i) == 0).unwrap_or(n)
}

/// `find_next_zero_bit` over the low `n` bits of `map` from `start`.
fn next_zero(map: u8, n: usize, start: usize) -> usize {
    (start..n).find(|&i| map & (1 << i) == 0).unwrap_or(n)
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

    /// The security CAM entry of a station key: pairwise, or group with
    /// key ID `keyidx`.
    pub fn find_key(&self, pairwise: bool, keyidx: u8) -> Option<u8> {
        self.sec_entries
            .values()
            .find(|entry| entry.pairwise == pairwise && (pairwise || entry.keyidx == keyidx))
            .map(|entry| entry.sec_cam_idx)
    }

    /// `rtw89_cam_get_avail_sec_cam` for a 128-bit key: the first free
    /// entry, taken.
    fn take_sec_cam(&mut self) -> Result<u8, Error> {
        let idx = first_zero(self.sec_cam_map, SCAM_NUM);
        if idx >= SCAM_NUM {
            return Err(Error::CamFull("security CAM"));
        }
        self.sec_cam_map |= 1 << idx;
        Ok(idx)
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

/// `rtw89_cam_get_sec_key_cmd`: the security CAM entry's H2C, its first
/// 128 bits of key, or the next 128 for `ext_key`'s second entry.
pub fn sec_key_cmd(entry: &SecCamEntry, ext_key: bool) -> [u8; H2C_SEC_CAM_LEN] {
    let mut cmd = [0; H2C_SEC_CAM_LEN];
    let w0 = u32::from(entry.sec_cam_idx.wrapping_add(ext_key.into()))
        | u32::from(entry.offset) << 8
        | u32::from(entry.len) << 16;
    let w1 =
        u32::from(entry.key_type & 0xf) | u32::from(ext_key) << 4 | u32::from(entry.spp_mode) << 5;
    cmd[0..4].copy_from_slice(&w0.to_le_bytes());
    cmd[4..8].copy_from_slice(&w1.to_le_bytes());
    let from = if ext_key { 16 } else { 0 };
    cmd[8..24].copy_from_slice(&entry.key[from..from + 16]);
    cmd
}

/// `rtw89_cam_send_sec_key_cmd`: [`sec_key_cmd`] as `H2C_FUNC_MAC_SEC_UPD`,
/// asking REC_ACK, and for an extended key its second entry the same way.
pub fn send_sec_key_cmd<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    entry: &SecCamEntry,
) -> Result<(), H2cError> {
    let mut cmd = sec_key_cmd(entry, false);
    let sent = commands.send(
        io,
        H2C_CL_MAC_SEC_CAM,
        H2C_FUNC_MAC_SEC_UPD,
        true,
        false,
        &cmd,
    );
    cmd.zeroize();
    sent?;
    if !entry.ext_key {
        return Ok(());
    }
    let mut cmd = sec_key_cmd(entry, true);
    let sent = commands.send(
        io,
        H2C_CL_MAC_SEC_CAM,
        H2C_FUNC_MAC_SEC_UPD,
        true,
        false,
        &cmd,
    );
    cmd.zeroize();
    sent
}

/// The ciphers a station key may be under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cipher {
    Ccmp128,
    Tkip,
    /// AES-CMAC, the IGTK's.
    AesCmac,
    Other,
}

/// A station key as `rtw89_ops_set_key` gets it: its cipher, whether it
/// is pairwise, its key ID and its material.
#[derive(Clone, Copy, Debug)]
pub struct Key<'a> {
    pub cipher: Cipher,
    pub pairwise: bool,
    pub keyidx: u8,
    pub material: &'a [u8],
}

/// `rtw89_cam_get_addr_cam_key_idx`: the free slot of the address CAM
/// entry a key takes in its mode.
fn addr_cam_key_idx(addr_cam: &AddrCamEntry, key_type: u8, pairwise: bool) -> Result<usize, Error> {
    let map = addr_cam.sec_cam_map;
    let full = Error::CamFull("address CAM key slots");
    let (start, last) = match addr_cam.sec_ent_mode {
        ADDR_CAM_SEC_NONE => return Err(Error::Invalid("address CAM key mode")),
        ADDR_CAM_SEC_ALL_UNI => (0, SEC_CAM_IN_ADDR_CAM - 1),
        _ if key_type == SEC_KEY_TYPE_BIP_CCMP128 => {
            if addr_cam.sec_ent_mode == ADDR_CAM_SEC_4GROUP {
                return if map & (1 << 6) != 0 {
                    Err(Error::Invalid("address CAM BIP slot"))
                } else {
                    Ok(6)
                };
            }
            (5, 6)
        }
        _ if pairwise => (0, 1),
        ADDR_CAM_SEC_NORMAL => (2, 4),
        _ => (2, 5),
    };
    let idx = next_zero(map, SEC_CAM_IN_ADDR_CAM, start);
    if idx > last {
        return Err(full);
    }
    Ok(idx)
}

/// `rtw89_cam_sec_key_add` for a station link: a CCMP-128 key gets a
/// security CAM entry, sent, then a slot of the link's address CAM entry,
/// which goes to the firmware with `RTW89_ROLE_INFO_CHANGE`; `peer` is the
/// AP for a pairwise key. What it returns is the entry, rtw89's
/// `key->hw_key_idx`. A key that fails after its entry was taken is
/// released, as `rtw89_cam_sec_key_install` releases it.
pub fn write_key<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    cams: &mut Info,
    link: &mut Link,
    peer: Option<&Peer>,
    key: &Key<'_>,
) -> Result<u8, Error> {
    let key_type = match key.cipher {
        Cipher::Ccmp128 => SEC_KEY_TYPE_CCMP128,
        Cipher::Tkip => return Err(Error::Unsupported("TKIP on an RTL8852B")),
        Cipher::AesCmac => return Err(Error::Unsupported("the IGTK stays in the host")),
        Cipher::Other => return Err(Error::Unsupported("a cipher other than CCMP-128")),
    };
    if key.material.len() != 16 {
        return Err(Error::Invalid("CCMP-128 key length"));
    }
    let idx = cams.take_sec_cam()?;
    let mut entry = SecCamEntry {
        sec_cam_idx: idx,
        key_type,
        len: SEC_CAM_LEN,
        pairwise: key.pairwise,
        keyidx: key.keyidx,
        ..SecCamEntry::default()
    };
    entry.key[..16].copy_from_slice(key.material);
    let installed = send_sec_key_cmd(io, commands, &entry)
        .map_err(Error::H2c)
        .and_then(|()| attach(io, commands, link, peer, &entry));
    match installed {
        Ok(()) => {
            cams.sec_entries.insert(idx, entry);
            Ok(idx)
        }
        Err(error) => {
            cams.sec_cam_map &= !(1 << idx);
            Err(error)
        }
    }
}

/// `__rtw89_cam_attach_sec_cam`: the key's address CAM slot, then the
/// address CAM sent; a failed send frees the slot again.
fn attach<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &mut Link,
    peer: Option<&Peer>,
    entry: &SecCamEntry,
) -> Result<(), Error> {
    let slot = addr_cam_key_idx(&link.addr_cam, entry.key_type, entry.pairwise)?;
    link.addr_cam.sec_ent_keyid[slot] = entry.keyidx;
    link.addr_cam.sec_ent[slot] = entry.sec_cam_idx;
    link.addr_cam.sec_cam_map |= 1 << slot;
    // RTL8852B has no h2c_dctl_sec_cam.
    if let Err(error) = send_addr_cam(io, commands, link, peer, None, UpdMode::InfoChange) {
        link.addr_cam.sec_cam_map &= !(1 << slot);
        return Err(Error::H2c(error));
    }
    Ok(())
}

/// `rtw89_cam_sec_key_del` with `inform_fw` for security CAM entry
/// `sec_cam_idx`: every address CAM slot holding it cleared, the address
/// CAM sent with `RTW89_ROLE_INFO_CHANGE`, then the entry freed whatever
/// the send returned. As rtw89 notes, a slot no longer valid disables the
/// entry, so no security CAM H2C follows.
pub fn clear_key<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    cams: &mut Info,
    link: &mut Link,
    peer: Option<&Peer>,
    sec_cam_idx: u8,
) -> Result<(), Error> {
    let entry = cams
        .sec_entries
        .remove(&sec_cam_idx)
        .ok_or(Error::Invalid("security CAM entry"))?;
    for slot in 0..SEC_CAM_IN_ADDR_CAM {
        if link.addr_cam.sec_cam_map & (1 << slot) != 0
            && link.addr_cam.sec_ent[slot] == entry.sec_cam_idx
        {
            link.addr_cam.sec_cam_map &= !(1 << slot);
        }
    }
    let sent = send_addr_cam(io, commands, link, peer, None, UpdMode::InfoChange);
    cams.sec_cam_map &= !(1 << sec_cam_idx);
    if entry.ext_key {
        cams.sec_cam_map &= !(1 << (sec_cam_idx.wrapping_add(1) & 0x7f));
    }
    sent.map_err(Error::H2c)
}

#[cfg(test)]
mod tests;
