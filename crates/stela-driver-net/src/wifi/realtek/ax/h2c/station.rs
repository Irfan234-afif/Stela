// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! An RTL8852B station's role, MAC ID and CMAC table H2C, and the order
//! pinned rtw89 sends them in as a station interface comes up, joins and
//! leaves:
//!
//! - [`role_maintain`], [`join_info`], [`default_cmac_tbl`],
//!   [`assoc_cmac_tbl`], [`txtime_cmac_tbl`] and [`macid_pause`] build the
//!   payloads of `rtw89_fw_h2c_role_maintain`,
//!   `rtw89_fw_h2c_join_info` (its AX form, one word),
//!   `rtw89_fw_h2c_default_cmac_tbl`, `rtw89_fw_h2c_assoc_cmac_tbl`,
//!   `rtw89_fw_h2c_txtime_cmac_tbl` and `rtw89_fw_h2c_macid_pause` (fw.c),
//!   the CMAC tables as `H2C_FUNC_MAC_CCTLINFO_UD`, RTL8852B's
//!   `h2c_cctl_func_id`; the address CAM's is [`super::super::cam`]'s;
//! - [`vif_init`] is `rtw89_mac_vif_init` (mac.c): the port
//!   ([`super::super::mac::port`]), the DMAC and CMAC table inits, the MAC
//!   ID unpaused, the role created, the join info as disconnected, the
//!   BSSID and address CAMs taken and sent, and the default CMAC table;
//!   [`vif_deinit`] is `rtw89_mac_vif_deinit`;
//! - [`bssid_changed`] is `rtw89_ops_link_info_changed`'s
//!   `BSS_CHANGED_BSSID` (mac80211.c);
//! - [`sta_assoc`] is what `rtw89_station_mode_sta_assoc` sends for a
//!   station's AP: `rtw89_vif_type_mapping` as associated, then
//!   `rtw89_core_sta_link_assoc` (core.c) up to its `rtw89_phy_ra_assoc`;
//!   [`bss_assoc`] is the port update of `__rtw89_ops_bss_link_assoc` that
//!   follows; [`sta_disconnect`] is `rtw89_core_sta_link_disconnect`.
//!
//! What 4.7's `Device` hooks are to call, in this order:
//! - when the interface comes up: [`Link::station`], then [`vif_init`];
//! - when the BSSID is set (before authenticating) and when it is cleared
//!   on leaving: [`bssid_changed`];
//! - when joined: [`sta_assoc`], then the RA H2C of 4.5
//!   (`rtw89_phy_ra_assoc`), then [`bss_assoc`] with the BSS's beacon
//!   interval and DTIM period in [`Link::bss`];
//! - when left: [`sta_disconnect`], then [`bssid_changed`] to all zeros;
//! - keys: [`super::super::cam::write_key`] and
//!   [`super::super::cam::clear_key`].
//!
//! What this leaves out, and why:
//! - AP, ad hoc, P2P, TDLS and MLO links: Stela is a station of one link;
//!   the AP-client roles and the per-station address CAM of an AP are not
//!   built.
//! - The rest of `rtw89_core_sta_link_assoc` for a station: the RA H2C is
//!   4.5's; `rtw89_mac_bf_assoc` and `rtw89_mac_bf_monitor_calc`
//!   (beamformee CSI), `rtw89_fw_h2c_general_pkt` and
//!   `rtw89_fw_h2c_set_bcn_fltr_cfg` (offloads for low power and the
//!   firmware's beacon filter), the BTC role notice, the UL TB and beacon
//!   tracking, the HTC template, DIG and the ER capability are not sent
//!   or kept. `rtw89_core_sta_link_disconnect` likewise drops only the
//!   beamformee and general-packet steps, and `rtw89_core_sta_link_add`,
//!   `_disassoc` and `_remove` send nothing else for a station.
//! - The rest of `__rtw89_ops_bss_link_assoc`: `rtw89_phy_set_bss_color`
//!   (the BB's spatial-reuse color), the UL TB TX power offset (none on
//!   RTL8852B), `rtw89_mac_set_he_obss_narrow_bw_ru` (only on a radar
//!   channel) and `rtw89_mac_set_he_tb` (BE chips only).
//! - `rtw89_fw_h2c_join_info`'s BE form and `H2C_FUNC_MAC_MACID_PAUSE_SLEEP`:
//!   RTL8852B's firmware has neither feature.
//!
//! An H2C sent proves only that its BD was written: whether the firmware
//! took the role, the join or a table is answered, if at all, by its
//! REC_ACK and DONE_ACK on RXQ ([`super::super::c2h`]), which nothing here
//! waits for.
use super::super::{
    cam::{self, AddrCamEntry, BssidCamEntry},
    io::{self, Io, prep},
    mac::{
        Commands, H2C_CL_MAC_FW_OFLD,
        port::{self, NET_TYPE_AP_MODE, NET_TYPE_INFRA, NET_TYPE_NO_LINK, Port},
    },
    registers::{CMAC_EN, CMAC_FUNC_EN, R32_DEAD, R32_EA},
};
use super::Error as H2cError;

/// `H2C_CL_MAC_MEDIA_RPT` with `H2C_FUNC_MAC_JOININFO` and
/// `H2C_FUNC_MAC_FWROLE_MAINTAIN`.
pub const H2C_CL_MAC_MEDIA_RPT: u8 = 0x8;
pub const H2C_FUNC_MAC_JOININFO: u8 = 0x0;
pub const H2C_FUNC_MAC_FWROLE_MAINTAIN: u8 = 0x4;
/// `H2C_CL_MAC_FR_EXCHG` with `H2C_FUNC_MAC_CCTLINFO_UD`, RTL8852B's
/// `h2c_cctl_func_id`.
pub const H2C_CL_MAC_FR_EXCHG: u8 = 0x5;
pub const H2C_FUNC_MAC_CCTLINFO_UD: u8 = 0x2;
/// `H2C_FUNC_MAC_MACID_PAUSE` of `H2C_CL_MAC_FW_OFLD`.
pub const H2C_FUNC_MAC_MACID_PAUSE: u8 = 0x8;
/// `H2C_CMC_TBL_LEN`: the control word, eight value words and their eight
/// mask words.
pub const CMC_TBL_LEN: usize = 68;
/// `sizeof(struct rtw89_fw_macid_pause_grp)`.
pub const MACID_PAUSE_LEN: usize = 32;

/// `RTW89_H2C_ROLE_MAINTAIN_W0_*`.
pub const ROLE_MAINTAIN_W0_MACID: u32 = 0x0000_00ff;
pub const ROLE_MAINTAIN_W0_SELF_ROLE: u32 = 0x0000_0300;
pub const ROLE_MAINTAIN_W0_UPD_MODE: u32 = 0x0000_1c00;
pub const ROLE_MAINTAIN_W0_WIFI_ROLE: u32 = 0x0001_e000;
pub const ROLE_MAINTAIN_W0_BAND: u32 = 0x0006_0000;
pub const ROLE_MAINTAIN_W0_PORT: u32 = 0x0038_0000;
/// `RTW89_H2C_JOININFO_W0_*`.
pub const JOININFO_W0_MACID: u32 = 0x0000_00ff;
pub const JOININFO_W0_OP: u32 = 1 << 8;
pub const JOININFO_W0_BAND: u32 = 1 << 9;
pub const JOININFO_W0_WMM: u32 = 0x0000_0c00;
pub const JOININFO_W0_TGR: u32 = 1 << 12;
pub const JOININFO_W0_ISHESTA: u32 = 1 << 13;
pub const JOININFO_W0_DLBW: u32 = 0x0000_c000;
pub const JOININFO_W0_TF_MAC_PAD: u32 = 0x0003_0000;
pub const JOININFO_W0_DL_T_PE: u32 = 0x001c_0000;
pub const JOININFO_W0_PORT_ID: u32 = 0x00e0_0000;
pub const JOININFO_W0_NET_TYPE: u32 = 0x0300_0000;
pub const JOININFO_W0_WIFI_ROLE: u32 = 0x3c00_0000;
pub const JOININFO_W0_SELF_ROLE: u32 = 0xc000_0000;

/// `enum rtw89_upd_mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpdMode {
    Create = 0,
    Remove = 1,
    TypeChange = 2,
    InfoChange = 3,
    ConDisconn = 4,
    BandSw = 5,
    FwRestore = 6,
}

/// `RTW89_SELF_ROLE_CLIENT`, `_AP` and `_AP_CLIENT`.
pub const SELF_ROLE_CLIENT: u8 = 0;
pub const SELF_ROLE_AP: u8 = 1;
pub const SELF_ROLE_AP_CLIENT: u8 = 2;
/// `RTW89_WIFI_ROLE_STATION`.
pub const WIFI_ROLE_STATION: u8 = 1;
/// `RTW89_HW_RATE_CCK1` and `RTW89_HW_RATE_OFDM6`.
pub const HW_RATE_CCK1: u32 = 0x0;
pub const HW_RATE_OFDM6: u32 = 0x4;
/// `RF_AB`: both TX paths, what `__rtw89_fw_h2c_set_tx_path` takes while
/// `hal->antenna_tx` is 0, as nothing here sets it.
pub const RF_AB: u32 = 0x3;
/// `RTW89_PPE_BW_NUM`: 20, 40, 80, 160 and 320 MHz.
pub const PPE_BW_NUM: usize = 5;
/// `RTW89_PE_DURATION_0`, `_8` and `_16`.
pub const PE_DURATION_0: u8 = 0;
pub const PE_DURATION_8: u8 = 1;
pub const PE_DURATION_16: u8 = 2;
/// include/linux/ieee80211.h: `IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT`,
/// `IEEE80211_HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK`,
/// `IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK`,
/// `IEEE80211_PPE_THRES_INFO_PPET_SIZE`, `IEEE80211_PPE_THRES_NSS_MASK`
/// and `IEEE80211_HE_PPE_THRES_MAX_LEN`.
pub const HE_PHY_CAP6_PPE_THRESHOLD_PRESENT: u8 = 0x80;
pub const HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK: u8 = 0xc0;
pub const PPE_THRES_RU_INDEX_BITMASK_MASK: u8 = 0x78;
pub const PPE_THRES_INFO_PPET_SIZE: u32 = 3;
pub const PPE_THRES_NSS_MASK: u16 = 7;
pub const HE_PPE_THRES_MAX_LEN: usize = 25;

/// What a station link's H2C read of its `ieee80211_bss_conf` and its
/// `vif->cfg`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Bss {
    /// `vif->cfg.aid`.
    pub aid: u16,
    /// `bss_conf->beacon_int`, 0 until the BSS is known.
    pub beacon_int: u16,
    /// `bss_conf->dtim_period`.
    pub dtim_period: u8,
    /// `bss_conf->he_bss_color.color`.
    pub bss_color: u8,
    /// `bss_conf->he_support`.
    pub he_support: bool,
    /// The channel is on 2.4 GHz (`chan->band_type == RTW89_BAND_2G`).
    pub two_ghz: bool,
}

/// A station's `rtw89_vif_link`: the members its H2C and port read. The
/// wake-on-WLAN, LSIG TXOP and target-indication members rtw89 sends are
/// never set for a station and stay 0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Link {
    pub mac_id: u8,
    pub port: u8,
    /// `mac_idx` and `phy_idx`: band 0 and PHY 0 for the one link.
    pub mac_idx: u8,
    pub phy_idx: u8,
    pub mac_addr: [u8; 6],
    pub bssid: [u8; 6],
    /// An `RTW89_NET_TYPE_*`.
    pub net_type: u8,
    pub self_role: u8,
    pub wifi_role: u8,
    pub wmm: u8,
    pub trigger: bool,
    pub lsig_txop: bool,
    pub tgt_ind: u8,
    pub frm_tgt_ind: u8,
    pub bcn_hit_cond: u8,
    pub hit_rule: u8,
    pub addr_cam: AddrCamEntry,
    pub bssid_cam: BssidCamEntry,
    pub bss: Bss,
    /// `rtwdev->hal.tx_nss`, from the efuse ([`super::super::efuse`]).
    pub tx_nss: u8,
}

impl Link {
    /// A station link as `rtw89_ops_add_interface` leaves it before
    /// `rtw89_mac_add_vif`: MAC ID `mac_id`, port `port`, band and PHY 0,
    /// `mac_addr` its address, no BSSID, `rtw89_vif_type_mapping` not
    /// associated, no hit rule or beacon hit condition.
    pub fn station(mac_id: u8, port: u8, mac_addr: [u8; 6], tx_nss: u8) -> Self {
        let mut link = Self {
            mac_id,
            port,
            mac_addr,
            tx_nss,
            ..Self::default()
        };
        link.type_mapping(false);
        link
    }

    /// `rtw89_vif_type_mapping` for a station (not P2P).
    pub fn type_mapping(&mut self, assoc: bool) {
        self.wifi_role = WIFI_ROLE_STATION;
        if assoc {
            self.net_type = NET_TYPE_INFRA;
            self.trigger = self.bss.he_support;
        } else {
            self.net_type = NET_TYPE_NO_LINK;
            self.trigger = false;
        }
        self.self_role = SELF_ROLE_CLIENT;
        self.addr_cam.sec_ent_mode = cam::ADDR_CAM_SEC_NORMAL;
    }

    /// What `rtw89_mac_port_update` reads of the link.
    pub fn port(&self) -> Port {
        Port {
            port: self.port,
            net_type: self.net_type,
            beacon_int: self.bss.beacon_int,
            dtim_period: self.bss.dtim_period,
            bss_color: self.bss.bss_color,
        }
    }
}

/// The HE capabilities of a peer that `__get_sta_he_pkt_padding` reads:
/// `he_cap.he_cap_elem.phy_cap_info` and `he_cap.ppe_thres`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeCap {
    pub phy_cap_info: [u8; 11],
    pub ppe_thres: [u8; HE_PPE_THRES_MAX_LEN],
}

/// A station's AP as rtw89's `ieee80211_link_sta` and `rtw89_sta_link`
/// give it to the station H2C: its address, its RX streams, and its HE
/// capabilities when it has them (`he_cap.has_he`). A station's AP shares
/// the link's MAC ID and address CAM.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Peer {
    pub addr: [u8; 6],
    pub rx_nss: u8,
    pub he: Option<HeCap>,
}

/// Why a station step stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `rtw89_mac_port_update`'s `-EINVAL`: no such port.
    Port(u8),
    /// `rtw89_mac_check_mac_en`'s `-EFAULT` for CMAC0: CMAC_FUNC_EN read
    /// `value`.
    CmacOff {
        value: u32,
    },
    /// `-EBUSY`: the CAM named has no free entry.
    CamFull(&'static str),
    /// `-EOPNOTSUPP`: a key the security CAM does not take here.
    Unsupported(&'static str),
    /// `-EINVAL` or `-ENOENT`: what the named argument asked does not exist
    /// or does not fit.
    Invalid(&'static str),
    Io(io::Error),
    H2c(H2cError),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<H2cError> for Error {
    fn from(error: H2cError) -> Self {
        Self::H2c(error)
    }
}

impl From<port::Error> for Error {
    fn from(error: port::Error) -> Self {
        match error {
            port::Error::Port(port) => Self::Port(port),
            port::Error::Io(error) => Self::Io(error),
        }
    }
}

/// The MAC ID a link's H2C names: its station's, or its own.
fn mac_id(link: &Link, peer: Option<&Peer>) -> u8 {
    // A station's AP has the link's MAC ID (__rtw89_ops_sta_add).
    let _ = peer;
    link.mac_id
}

/// `rtw89_fw_h2c_role_maintain`'s payload.
pub fn role_maintain(link: &Link, peer: Option<&Peer>, upd_mode: UpdMode) -> [u8; 4] {
    let self_role = if link.net_type == NET_TYPE_AP_MODE && peer.is_some() {
        SELF_ROLE_AP_CLIENT
    } else {
        link.self_role
    };
    let w0 = prep(mac_id(link, peer).into(), ROLE_MAINTAIN_W0_MACID)
        | prep(self_role.into(), ROLE_MAINTAIN_W0_SELF_ROLE)
        | prep(upd_mode as u32, ROLE_MAINTAIN_W0_UPD_MODE)
        | prep(link.wifi_role.into(), ROLE_MAINTAIN_W0_WIFI_ROLE)
        | prep(link.mac_idx.into(), ROLE_MAINTAIN_W0_BAND)
        | prep(link.port.into(), ROLE_MAINTAIN_W0_PORT);
    w0.to_le_bytes()
}

/// `rtw89_fw_h2c_join_info`'s payload on an AX chip.
pub fn join_info(link: &Link, peer: Option<&Peer>, dis_conn: bool) -> [u8; 4] {
    let mut self_role = link.self_role;
    let mut net_type = link.net_type;
    if net_type == NET_TYPE_AP_MODE && peer.is_some() {
        self_role = SELF_ROLE_AP_CLIENT;
        if dis_conn {
            net_type = NET_TYPE_NO_LINK;
        }
    }
    let w0 = prep(mac_id(link, peer).into(), JOININFO_W0_MACID)
        | prep(dis_conn.into(), JOININFO_W0_OP)
        | prep(link.mac_idx.into(), JOININFO_W0_BAND)
        | prep(link.wmm.into(), JOININFO_W0_WMM)
        | prep(link.trigger.into(), JOININFO_W0_TGR)
        | prep(link.port.into(), JOININFO_W0_PORT_ID)
        | prep(net_type.into(), JOININFO_W0_NET_TYPE)
        | prep(link.wifi_role.into(), JOININFO_W0_WIFI_ROLE)
        | prep(self_role.into(), JOININFO_W0_SELF_ROLE);
    w0.to_le_bytes()
}

/// A CMAC table as fw.h's `SET_CTRL_INFO_*` and `SET_CMC_TBL_*` fill it:
/// word 0 the MAC ID and operation, words 1 to 8 the values, words 9 to 16
/// their masks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CmacTable(pub [u32; 17]);

/// The CMAC table fields the station H2C set: the value word and its mask.
pub mod cmc {
    pub const MACID: (usize, u32) = (0, 0x0000_007f);
    pub const OPERATION: (usize, u32) = (0, 1 << 7);
    pub const MGQ_RPT_EN: (usize, u32) = (1, 1 << 21);
    pub const DISRTSFB: (usize, u32) = (1, 1 << 25);
    pub const DISDATAFB: (usize, u32) = (1, 1 << 26);
    pub const AMPDU_TIME_SEL: (usize, u32) = (2, 1 << 9);
    pub const RTS_TXCNT_LMT_SEL: (usize, u32) = (2, 1 << 11);
    pub const RTS_RTY_LOWEST_RATE: (usize, u32) = (2, 0xf000_0000);
    pub const DATA_TX_CNT_LMT: (usize, u32) = (3, 0x0000_003f);
    pub const DATA_TXCNT_LMT_SEL: (usize, u32) = (3, 1 << 6);
    pub const AMPDU_MAX_TIME: (usize, u32) = (3, 0xf000_0000);
    pub const MULTI_PORT_ID: (usize, u32) = (5, 0x0000_0007);
    pub const TXPWR_MODE: (usize, u32) = (5, 0x0000_0e00);
    pub const DATA_DCM: (usize, u32) = (5, 1 << 12);
    pub const BSR_QUEUE_SIZE_FORMAT: (usize, u32) = (6, 1 << 13);
    pub const NTX_PATH_EN: (usize, u32) = (6, 0x000f_0000);
    pub const PATH_MAP_A: (usize, u32) = (6, 0x0030_0000);
    pub const PATH_MAP_B: (usize, u32) = (6, 0x00c0_0000);
    pub const PATH_MAP_C: (usize, u32) = (6, 0x0300_0000);
    pub const PATH_MAP_D: (usize, u32) = (6, 0x0c00_0000);
    pub const ANTSEL_A: (usize, u32) = (6, 1 << 28);
    pub const ANTSEL_B: (usize, u32) = (6, 1 << 29);
    pub const ANTSEL_C: (usize, u32) = (6, 1 << 30);
    pub const ANTSEL_D: (usize, u32) = (6, 1 << 31);
    pub const ULDL: (usize, u32) = (7, 1 << 17);
    pub const DOPPLER_CTRL: (usize, u32) = (7, 0x000c_0000);
    pub const NOMINAL_PKT_PADDING: (usize, u32) = (7, 0x0030_0000);
    pub const NOMINAL_PKT_PADDING40: (usize, u32) = (7, 0x00c0_0000);
    pub const TXPWR_TOLERENCE: (usize, u32) = (7, 0x0f00_0000);
    pub const NOMINAL_PKT_PADDING80: (usize, u32) = (7, 0xc000_0000);
    pub const NOMINAL_PKT_PADDING160: (usize, u32) = (8, 0x3000_0000);
}

impl CmacTable {
    /// `SET_CTRL_INFO_MACID` and `SET_CTRL_INFO_OPERATION(…, 1)`.
    fn new(macid: u8) -> Self {
        let mut table = Self::default();
        table.ctrl(cmc::MACID, macid.into());
        table.ctrl(cmc::OPERATION, 1);
        table
    }

    /// A `SET_CTRL_INFO_*`: the value alone.
    fn ctrl(&mut self, (word, mask): (usize, u32), value: u32) {
        self.0[word] = (self.0[word] & !mask) | prep(value, mask);
    }

    /// A `SET_CMC_TBL_*`: the value, and its mask word's field all ones.
    fn set(&mut self, (word, mask): (usize, u32), value: u32) {
        self.0[word] = (self.0[word] & !mask) | prep(value, mask);
        self.0[word + 8] |= mask;
    }

    pub fn bytes(&self) -> [u8; CMC_TBL_LEN] {
        let mut bytes = [0; CMC_TBL_LEN];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(self.0) {
            *chunk = word.to_le_bytes();
        }
        bytes
    }
}

/// `rtw89_fw_h2c_default_cmac_tbl`'s payload on an RTL8852B over PCIe
/// (`hci.tx_rpt_enabled` is false), with `__rtw89_fw_h2c_set_tx_path` for
/// two RF paths.
pub fn default_cmac_tbl(link: &Link, peer: Option<&Peer>) -> [u8; CMC_TBL_LEN] {
    let mut t = CmacTable::new(mac_id(link, peer));
    t.set(cmc::TXPWR_MODE, 0);
    // __rtw89_fw_h2c_set_tx_path: two paths, both used, so B maps to 1.
    t.set(cmc::NTX_PATH_EN, RF_AB);
    t.set(cmc::PATH_MAP_A, 0);
    t.set(cmc::PATH_MAP_B, 1);
    t.set(cmc::PATH_MAP_C, 0);
    t.set(cmc::PATH_MAP_D, 0);
    t.set(cmc::ANTSEL_A, 0);
    t.set(cmc::ANTSEL_B, 0);
    t.set(cmc::ANTSEL_C, 0);
    t.set(cmc::ANTSEL_D, 0);
    t.set(cmc::MGQ_RPT_EN, 0);
    t.set(cmc::DOPPLER_CTRL, 0);
    t.set(cmc::TXPWR_TOLERENCE, 0);
    if link.net_type == NET_TYPE_AP_MODE {
        t.set(cmc::DATA_DCM, 0);
    }
    t.bytes()
}

/// `__get_sta_he_pkt_padding`: the nominal packet padding of each
/// bandwidth, from the peer's PPE thresholds or, without them, its nominal
/// padding field. A PPE threshold rtw89 would read past `ppe_thres` reads
/// as 0 here.
pub fn he_pkt_padding(he: &HeCap, rx_nss: u8, tx_nss: u8) -> [u8; PPE_BW_NUM] {
    let mut pads = [0; PPE_BW_NUM];
    let nss = u32::from(rx_nss.min(tx_nss).wrapping_sub(1));
    let ppe_thres_hdr = he.ppe_thres[0];
    if he.phy_cap_info[6] & HE_PHY_CAP6_PPE_THRESHOLD_PRESENT == 0 {
        let pad = (he.phy_cap_info[9] & HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK) >> 6;
        return [pad; PPE_BW_NUM];
    }
    let ru_bitmap = (ppe_thres_hdr & PPE_THRES_RU_INDEX_BITMASK_MASK) >> 3;
    let mut n = ru_bitmap.count_ones() as u8;
    n = 7u8.wrapping_add(((u32::from(n) * PPE_THRES_INFO_PPET_SIZE * 2) * (nss & 0xff)) as u8);
    for (i, pad) in pads.iter_mut().enumerate() {
        if ru_bitmap & (1 << i) == 0 {
            *pad = 1;
            continue;
        }
        let idx = usize::from(n >> 3);
        let mut sh = u32::from(n & 7);
        n = n.wrapping_add((PPE_THRES_INFO_PPET_SIZE * 2) as u8);
        let byte = |at: usize| he.ppe_thres.get(at).copied().unwrap_or(0);
        let ppe = u16::from_le_bytes([byte(idx), byte(idx + 1)]);
        let ppe16 = (ppe >> sh) & PPE_THRES_NSS_MASK;
        sh += PPE_THRES_INFO_PPET_SIZE;
        let ppe8 = (ppe >> sh) & PPE_THRES_NSS_MASK;
        *pad = if ppe16 != 7 && ppe8 == 7 {
            PE_DURATION_16
        } else if ppe8 != 7 {
            PE_DURATION_8
        } else {
            PE_DURATION_0
        };
    }
    pads
}

/// `rtw89_fw_h2c_assoc_cmac_tbl`'s payload for a station link (not P2P)
/// as `H2C_FUNC_MAC_CCTLINFO_UD`.
pub fn assoc_cmac_tbl(link: &Link, peer: Option<&Peer>) -> [u8; CMC_TBL_LEN] {
    let mut pads = [0; PPE_BW_NUM];
    if let Some(he) = peer.and_then(|peer| peer.he.as_ref().map(|he| (he, peer.rx_nss))) {
        pads = he_pkt_padding(he.0, he.1, link.tx_nss);
    }
    let lowest_rate = if link.bss.two_ghz {
        HW_RATE_CCK1
    } else {
        HW_RATE_OFDM6
    };
    let mut t = CmacTable::new(mac_id(link, peer));
    t.set(cmc::DISRTSFB, 1);
    t.set(cmc::DISDATAFB, 1);
    t.set(cmc::RTS_RTY_LOWEST_RATE, lowest_rate);
    t.set(cmc::RTS_TXCNT_LMT_SEL, 0);
    t.set(cmc::DATA_TXCNT_LMT_SEL, 0);
    // A station's vif type: uplink and downlink.
    t.set(cmc::ULDL, 1);
    t.set(cmc::MULTI_PORT_ID, link.port.into());
    t.set(cmc::NOMINAL_PKT_PADDING, pads[0].into());
    t.set(cmc::NOMINAL_PKT_PADDING40, pads[1].into());
    t.set(cmc::NOMINAL_PKT_PADDING80, pads[2].into());
    t.set(cmc::NOMINAL_PKT_PADDING160, pads[3].into());
    if let Some(peer) = peer {
        t.set(cmc::BSR_QUEUE_SIZE_FORMAT, peer.he.is_some().into());
    }
    if link.net_type == NET_TYPE_AP_MODE {
        t.set(cmc::DATA_DCM, 0);
    }
    t.bytes()
}

/// What `rtw89_fw_h2c_txtime_cmac_tbl` reads of an `rtw89_sta_link`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxTime {
    pub mac_id: u8,
    pub cctl_tx_time: bool,
    pub ampdu_max_time: u8,
    pub cctl_tx_retry_limit: bool,
    pub data_tx_cnt_lmt: u8,
}

/// `rtw89_fw_h2c_txtime_cmac_tbl`'s payload.
pub fn txtime_cmac_tbl(sta: &TxTime) -> [u8; CMC_TBL_LEN] {
    let mut t = CmacTable::new(sta.mac_id);
    if sta.cctl_tx_time {
        t.set(cmc::AMPDU_TIME_SEL, 1);
        t.set(cmc::AMPDU_MAX_TIME, sta.ampdu_max_time.into());
    }
    if sta.cctl_tx_retry_limit {
        t.set(cmc::DATA_TXCNT_LMT_SEL, 1);
        t.set(cmc::DATA_TX_CNT_LMT, sta.data_tx_cnt_lmt.into());
    }
    t.bytes()
}

/// `rtw89_fw_h2c_macid_pause`'s payload as `H2C_FUNC_MAC_MACID_PAUSE`:
/// bit `sh` of group `grp` in the mask, and in the pause words when
/// `pause` is.
pub fn macid_pause(sh: u8, grp: u8, pause: bool) -> [u8; MACID_PAUSE_LEN] {
    let mut bytes = [0; MACID_PAUSE_LEN];
    let set = (1u32 << (sh & 31)).to_le_bytes();
    let grp = usize::from(grp & 3);
    bytes[16 + 4 * grp..20 + 4 * grp].copy_from_slice(&set);
    if pause {
        bytes[4 * grp..4 * grp + 4].copy_from_slice(&set);
    }
    bytes
}

/// `rtw89_fw_h2c_role_maintain`: [`role_maintain`] as
/// `H2C_FUNC_MAC_FWROLE_MAINTAIN`, asking DONE_ACK.
pub fn send_role_maintain<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &Link,
    peer: Option<&Peer>,
    upd_mode: UpdMode,
) -> Result<(), H2cError> {
    let payload = role_maintain(link, peer, upd_mode);
    commands.send(
        io,
        H2C_CL_MAC_MEDIA_RPT,
        H2C_FUNC_MAC_FWROLE_MAINTAIN,
        false,
        true,
        &payload,
    )
}

/// `rtw89_fw_h2c_join_info`: [`join_info`] as `H2C_FUNC_MAC_JOININFO`,
/// asking DONE_ACK.
pub fn send_join_info<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &Link,
    peer: Option<&Peer>,
    dis_conn: bool,
) -> Result<(), H2cError> {
    let payload = join_info(link, peer, dis_conn);
    commands.send(
        io,
        H2C_CL_MAC_MEDIA_RPT,
        H2C_FUNC_MAC_JOININFO,
        false,
        true,
        &payload,
    )
}

/// A CMAC table as `H2C_FUNC_MAC_CCTLINFO_UD` of `H2C_CL_MAC_FR_EXCHG`,
/// asking DONE_ACK.
pub fn send_cmac_tbl<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    table: &[u8; CMC_TBL_LEN],
) -> Result<(), H2cError> {
    commands.send(
        io,
        H2C_CL_MAC_FR_EXCHG,
        H2C_FUNC_MAC_CCTLINFO_UD,
        false,
        true,
        table,
    )
}

/// `rtw89_mac_set_macid_pause`: CMAC0 checked, then
/// `rtw89_fw_h2c_macid_pause` asking REC_ACK, whose failure rtw89 ignores
/// and which is returned here for the caller to ignore as well.
pub fn set_macid_pause<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    macid: u8,
    pause: bool,
) -> Result<Result<(), H2cError>, Error> {
    let value = io.read32(CMAC_FUNC_EN)?;
    if value == R32_EA || value == R32_DEAD || value & CMAC_EN != CMAC_EN {
        return Err(Error::CmacOff { value });
    }
    let payload = macid_pause(macid & 0x1f, macid >> 5, pause);
    Ok(commands.send(
        io,
        H2C_CL_MAC_FW_OFLD,
        H2C_FUNC_MAC_MACID_PAUSE,
        true,
        false,
        &payload,
    ))
}

/// `rtw89_mac_vif_init` for a station link on an RTL8852B, its steps in
/// rtw89's order. The BSSID and address CAM entries come from `cams`.
pub fn vif_init<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    cams: &mut cam::Info,
    link: &mut Link,
) -> Result<(), Error> {
    port::update(io, &link.port())?;
    port::dmac_tbl_init(io, link.mac_id)?;
    port::cmac_tbl_init(io, link.mac_id)?;
    // rtw89 ignores what the H2C returned.
    let _ = set_macid_pause(io, commands, link.mac_id, false)?;
    send_role_maintain(io, commands, link, None, UpdMode::Create)?;
    send_join_info(io, commands, link, None, true)?;
    cams.init(link)?;
    cam::send_addr_cam(io, commands, link, None, None, UpdMode::Create)?;
    send_cmac_tbl(io, commands, &default_cmac_tbl(link, None))?;
    // RTL8852B has no h2c_default_dmac_tbl.
    Ok(())
}

/// `rtw89_mac_vif_deinit`: the role removed, the link's CAM entries freed,
/// and the address CAM sent as removed.
pub fn vif_deinit<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    cams: &mut cam::Info,
    link: &mut Link,
) -> Result<(), Error> {
    send_role_maintain(io, commands, link, None, UpdMode::Remove)?;
    cams.deinit(link);
    cam::send_addr_cam(io, commands, link, None, None, UpdMode::Remove)?;
    Ok(())
}

/// `BSS_CHANGED_BSSID`: the link's BSSID and its BSSID CAM entry's
/// (`rtw89_cam_bssid_changed`), then the address CAM sent with
/// `RTW89_ROLE_INFO_CHANGE`, whose failure rtw89 ignores and which is
/// returned here.
pub fn bssid_changed<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &mut Link,
    bssid: [u8; 6],
) -> Result<(), H2cError> {
    link.bssid = bssid;
    link.bssid_cam.bssid = bssid;
    cam::send_addr_cam(io, commands, link, None, None, UpdMode::InfoChange)
}

/// `rtw89_station_mode_sta_assoc` for the AP `peer`, up to
/// `rtw89_phy_ra_assoc`: `rtw89_vif_type_mapping` as associated, then
/// `rtw89_core_sta_link_assoc`'s CMAC table, join info and address CAM
/// with `RTW89_ROLE_CON_DISCONN`. `link.bss` is the BSS joined.
pub fn sta_assoc<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &mut Link,
    peer: &Peer,
) -> Result<(), Error> {
    link.type_mapping(true);
    send_cmac_tbl(io, commands, &assoc_cmac_tbl(link, Some(peer)))?;
    send_join_info(io, commands, link, Some(peer), false)?;
    cam::send_addr_cam(io, commands, link, Some(peer), None, UpdMode::ConDisconn)?;
    Ok(())
}

/// `__rtw89_ops_bss_link_assoc`'s `rtw89_mac_port_update`, with the link
/// now associated.
pub fn bss_assoc<I: Io + ?Sized>(io: &mut I, link: &Link) -> Result<(), Error> {
    Ok(port::update(io, &link.port())?)
}

/// `rtw89_core_sta_link_disconnect` for a station's AP `peer`:
/// `rtw89_vif_type_mapping` as not associated, then the CMAC table, the
/// join info as disconnected and the address CAM with
/// `RTW89_ROLE_CON_DISCONN`.
pub fn sta_disconnect<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    link: &mut Link,
    peer: &Peer,
) -> Result<(), Error> {
    link.type_mapping(false);
    send_cmac_tbl(io, commands, &assoc_cmac_tbl(link, Some(peer)))?;
    send_join_info(io, commands, link, Some(peer), true)?;
    cam::send_addr_cam(io, commands, link, Some(peer), None, UpdMode::ConDisconn)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
