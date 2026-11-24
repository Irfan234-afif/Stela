// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
// Copyright(c) 2024 Realtek Corporation
//! An RTL8852B's BT coexistence (BTC) brought up with its antennas given to
//! Wi-Fi alone, as pinned rtw89 brings it up when the interface starts with
//! `BTC_MODE_WL`: `rtw89_btc_ntfy_poweron`, which only counts, then
//! `rtw89_btc_ntfy_init(rtwdev, BTC_MODE_WL)` (coex.c) with firmware
//! 0.29.29, whose `rtw89_btc_ver` entry (`RTW89_FW_VER_CODE(0, 29, 29, 0)`
//! in `rtw89_btc_ver_defs`) sets the H2C formats: TDMA version 3, slots
//! version 1, control version 1, init version 0, monitored registers
//! version 2. [`init_wl_only`] makes the reads, writes and H2Cs rtw89 makes,
//! in its order:
//!
//! 1. `rtw8852b_btc_set_rfe` ([`set_rfe`]): two antennas shared with BT
//!    behind its BTG path for an odd RFE type (or 0), three with BT on its
//!    own for an even one; no access;
//! 2. `__rtw8852bx_btc_init_cfg` (rtw8852b_common.c): the PTA init
//!    `rtw89_mac_coex_init` (mac.c) in RTK mode with the inner direction,
//!    through the LTE indirect access for `R_AX_LTE_SW_CFG_2`; WL TX
//!    responses and beacons at high priority
//!    (`__rtw8852bx_btc_set_wl_pri`); both RF paths' grant debug off
//!    (`RR_WLSEL`); the TRX mask table for the antenna type
//!    (`rtw8852bx_set_trx_mask`); the PTA break table; the BT counters;
//! 3. `_write_scbd(BTC_ALL_BT, BTC_WSCB_ACTIVE | BTC_WSCB_ON |
//!    BTC_WSCB_BTLOG, true)`, which only notes the scoreboard: its write is
//!    `_action_common`'s, step 7;
//! 4. `rtw89_mac_get_ctrl_path`, which rtw89 only warns about ("PTA owner
//!    warning", [`Init::pta_owner`]);
//! 5. `_set_init_info` and the rest of `rtw89_btc_ntfy_init` before
//!    `_run_coex`: the H2Cs `CXDRVINFO_INIT` and `CXDRVINFO_CTRL`
//!    (`SET_DRV_INFO`), `SET_SLOT_TABLE` with every slot and
//!    `SET_MREG_TABLE` with RTL8852B's monitored registers, then the same
//!    four again in the opposite order, as rtw89 sends them. Its
//!    `_set_ext_interface` sends nothing with a GPIO debug version below 7,
//!    and its two `_set_wl_tx_power(…, RTW89_PHY_0)` calls pass the PHY
//!    index 0 as a PHY map, so neither changes a level or makes an access;
//! 6. `_run_coex(BTC_RSN_NTFY_INIT)` reduced to `_action_wl_only`:
//!    `_set_ant(BTC_ANT_WONLY)` grants WL by software on both paths and BT
//!    nothing (`_set_gnt`, `rtw89_mac_cfg_gnt` through `R_AX_LTE_SW_CFG_1`),
//!    hands WLAN the PTA (`rtw89_mac_cfg_ctrl_path`) and sets band 0's
//!    polluter table to WL's grant (`_set_bt_plut`, `rtw89_mac_cfg_plt_ax`);
//!    `_set_policy(BTC_CXP_OFF_BT)` turns Bluetooth's TDMA off
//!    (`rtw89_btc_set_policy_v1`, `_fw_set_policy`): one `SET_CX_POLICY`
//!    H2C with the TDMA, which changed because `_set_tdma_bind` binds WL's
//!    hardware band 0 with no BT ([`TDMA_BIND_HWB0`]), and the OFF slot's
//!    new coex table;
//! 7. `_action_common`'s scoreboard write (`_sned_h2c_w2bscbd`,
//!    `rtw89_mac_cfg_sb`) for BT 0, then its millisecond's wait.
//!
//! Where `rtw89_core_start` calls `rtw89_btc_ntfy_init(rtwdev,
//! BTC_MODE_NORMAL)` and its `_run_coex` takes `_action_wl_init`, this
//! takes `BTC_MODE_WL` and `_action_wl_only`, as the plan's step 3.9 asks:
//! Stela does not bring the card's Bluetooth up, so Wi-Fi owns the antennas
//! alone. The init should run where rtw89 runs it, after the BB and RF
//! tables are loaded and before the first channel is set (3.10): the TDMA
//! binding above holds only while no channel has given WL a band.
//!
//! `CXDRVINFO_INIT` and `CXDRVINFO_CTRL` are sent, twice each, as rtw89
//! sends them; they tell the firmware the antennas, the module and that WL
//! runs alone. What the firmware does without them, or with them, is only
//! provable on hardware (3.10).
//!
//! The seams, and what is left out:
//! - The rest of `_run_coex` before the action: `_update_run_ctrl_info`
//!   (which sends nothing with control version 1), `_update_bt_scbd` (BT's
//!   scoreboard read), the state map and freerun check, and
//!   `_set_coex_binding`, whose binding with no band and no BT link is
//!   folded into [`TDMA_BIND_HWB0`].
//! - `_action_common` but its scoreboard write: the BTG and pre-AGC
//!   controls, the TX limits, the BT slot request, AFH, RX AGC, the RF TRX
//!   parameters, the BT RX scan priority, the firmware report map and
//!   `CXDRVINFO_ROLE`. Each concerns a BT link, a channel or the reports
//!   rtw89 parses, none of which Stela has yet.
//! - Bluetooth itself: BT info C2Hs, the periodic coex run, scan, role and
//!   RFK notices, power-off, and other chips' and firmware versions'
//!   formats.
//!
//! Each register step makes the accesses its rtw89 counterpart makes, in
//! the same order, read-modify-write included. The LTE access polls its
//! ready bit as `read_poll_timeout` does, every 50 us for 50000 us. Like
//! rtw89, the init goes on past what rtw89 ignores: a PTA init stopped by
//! an LTE that never readied ([`Init::coex_init`]), an RF write the SWSI
//! never took, a grant write past an unready LTE ([`Init::gnt`]), a
//! polluter table skipped with CMAC0 off ([`Init::plt`]), and refused H2Cs
//! ([`Init::h2c_failed`]). An access the interface refuses ends it.
//!
//! An init that returns proves that its writes and H2Cs were made; not that
//! the firmware took the H2Cs (their acks come back on RXQ), that the PTA
//! grants WL, or that the radio hears anything.
use super::{
    h2c::{self, FWCMD_TYPE_H2C, Function, H2C_CAT_OUTSRC},
    io::{self, Io, Registers, field, prep},
    mac::Fwcmd,
    registers::*,
};
use alloc::vec::Vec;

/// RF registers: `RR_WLSEL`, and the LUT write enable, address and data
/// `rtw8852bx_set_trx_mask` writes.
const RR_WLSEL: u32 = 0x02;
const RR_LUTWA: u32 = 0x33;
const RR_LUTWD0: u32 = 0x3f;
const RR_LUTWE: u32 = 0xef;
/// `RF_PATH_A` and `RF_PATH_B`.
const RF_PATH_A: u8 = 0;
const RF_PATH_B: u8 = 1;
/// `BTC_BT_SS_GROUP` and `BTC_BT_TX_GROUP`.
const BTC_BT_SS_GROUP: u32 = 0x0;
const BTC_BT_TX_GROUP: u32 = 0x2;
/// `rtw89_mac_read_lte`'s `read_poll_timeout(…, 50, 50000, …)`.
const LTE_POLL_STEP_US: u64 = 50;
const LTE_POLL_BOUND_US: u64 = 50000;
/// `rtw89_mac_cfg_sb`'s `fsleep(1000)`, "avoid BT FW loss information".
const SCOREBOARD_WAIT_US: u64 = 1000;

/// `BTFC_SET`, and the `enum rtw89_btc_btf_set` functions sent here.
pub const BTFC_SET: u8 = 0x10;
pub const SET_SLOT_TABLE: u8 = 0x1;
pub const SET_MREG_TABLE: u8 = 0x2;
pub const SET_CX_POLICY: u8 = 0x3;
pub const SET_DRV_INFO: u8 = 0x5;
/// `CXDRVINFO_INIT` and `CXDRVINFO_CTRL`.
pub const CXDRVINFO_INIT: u8 = 0;
pub const CXDRVINFO_CTRL: u8 = 6;
/// `enum btc_w2b_scoreboard`: the bits the init sets in WL's scoreboard.
pub const BTC_WSCB_ACTIVE: u32 = 1 << 0;
pub const BTC_WSCB_ON: u32 = 1 << 1;
pub const BTC_WSCB_BTLOG: u32 = 1 << 14;
/// `BTC_ANT_SHARED` and `BTC_ANT_DEDICATED`.
pub const BTC_ANT_SHARED: u8 = 0;
pub const BTC_ANT_DEDICATED: u8 = 1;
/// `BTC_BT_ALONE` and `BTC_BT_BTG`.
pub const BTC_BT_ALONE: u8 = 0;
pub const BTC_BT_BTG: u8 = 1;
/// `BTC_SWITCH_INTERNAL`.
pub const BTC_SWITCH_INTERNAL: u8 = 0;
/// `RTW89_BTC_DEFAULT_ANISO`: the isolation in dB rtw89 assumes.
pub const DEFAULT_ANISO: u8 = 10;
/// RTL8852B's `afh_guard_ch`.
pub const AFH_GUARD_CH: u8 = 6;
/// The firmware 0.29.29 `rtw89_btc_ver` entry's TDMA, slot and monitored
/// register formats (`fcxtdma`, `fcxslots`, `fcxmreg`).
pub const FCXTDMA: u8 = 3;
pub const FCXSLOTS: u8 = 1;
pub const FCXMREG: u8 = 2;
/// `BTF_SET_SLOT_TABLE_VER`.
pub const BTF_SET_SLOT_TABLE_VER: u8 = 1;
/// `CXPOLICY_TDMA` and `CXPOLICY_SLOT`, a policy TLV's types.
pub const CXPOLICY_TDMA: u8 = 0;
pub const CXPOLICY_SLOT: u8 = 1;
/// `CXST_OFF` and `CXST_MAX`: the OFF slot, and the slot count.
pub const CXST_OFF: usize = 0;
pub const CXST_MAX: usize = 18;
/// `SLOT_MIX` and `SLOT_ISO`.
pub const SLOT_MIX: u16 = 0;
pub const SLOT_ISO: u16 = 1;
/// `cxtbl[2]`, the coex table `BTC_CXP_OFF_BT` gives the OFF slot.
pub const CXTBL_OFF_BT: u32 = 0xe555_5555;
/// The TDMA binding `_set_tdma_bind` makes when `_set_coex_binding` finds
/// no RF band shared with BT: no BT selected, WL on hardware band 0
/// (`BIT(RTW89_MAC_0)`), neither TDD nor FDD.
pub const TDMA_BIND_HWB0: u8 = 0x01;

/// `struct rtw89_btc_ant_info` as `rtw8852b_btc_set_rfe` leaves it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ant {
    /// `BTC_ANT_SHARED` or `BTC_ANT_DEDICATED`.
    pub kind: u8,
    pub num: u8,
    pub isolation: u8,
    pub single_pos: u8,
    pub diversity: u8,
    pub btg_pos: u8,
    pub stream_cnt: u8,
}

/// `struct rtw89_btc_module`, the fields `CXDRVINFO_INIT` carries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Module {
    pub ant: Ant,
    pub rfe_type: u8,
    /// `kt_ver`: the chip's cut.
    pub kt_ver: u8,
    pub bt_solo: u8,
    /// `BTC_BT_ALONE` or `BTC_BT_BTG`.
    pub bt0_pos: u8,
    pub bt0_sw_type: u8,
    pub wa_type: u8,
    pub kt_ver_adie: u8,
}

/// `rtw8852b_btc_set_rfe` over the module `_reset_btc_var` leaves (zeroed
/// but the isolation): the antennas by RFE type `rfe_type` (the efuse's),
/// and cut `cv` as the module's version.
pub fn set_rfe(rfe_type: u8, cv: u8) -> Module {
    let num = if rfe_type > 0 && rfe_type.is_multiple_of(2) {
        3
    } else {
        2
    };
    let (kind, bt0_pos) = if num == 3 {
        (BTC_ANT_DEDICATED, BTC_BT_ALONE)
    } else {
        (BTC_ANT_SHARED, BTC_BT_BTG)
    };
    Module {
        ant: Ant {
            kind,
            num,
            isolation: DEFAULT_ANISO,
            ..Ant::default()
        },
        rfe_type,
        kt_ver: cv,
        bt0_pos,
        bt0_sw_type: BTC_SWITCH_INTERNAL,
        ..Module::default()
    }
}

/// `struct rtw89_btc_fbtc_slot`: a TDMA slot's length in ms, coex table
/// and type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub dur: u16,
    pub cxtbl: u32,
    pub cxtype: u16,
}

impl Slot {
    const fn new(dur: u16, cxtbl: u32, cxtype: u16) -> Self {
        Self { dur, cxtbl, cxtype }
    }

    /// The packed little-endian bytes the firmware takes.
    pub fn encode(&self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..2].copy_from_slice(&self.dur.to_le_bytes());
        bytes[2..6].copy_from_slice(&self.cxtbl.to_le_bytes());
        bytes[6..].copy_from_slice(&self.cxtype.to_le_bytes());
        bytes
    }
}

/// coex.c's `s_def`: every slot as `_reset_btc_var` sets it.
pub const SLOTS: [Slot; CXST_MAX] = [
    Slot::new(100, 0x5555_5555, SLOT_MIX),
    Slot::new(5, 0xea5a_5a5a, SLOT_ISO),
    Slot::new(70, 0xea5a_5a5a, SLOT_ISO),
    Slot::new(15, 0xea5a_5a5a, SLOT_ISO),
    Slot::new(15, 0xea5a_5a5a, SLOT_ISO),
    Slot::new(250, 0xe555_5555, SLOT_MIX),
    Slot::new(7, 0xea5a_5a5a, SLOT_MIX),
    Slot::new(5, 0xe555_5555, SLOT_MIX),
    Slot::new(50, 0xe555_5555, SLOT_MIX),
    Slot::new(20, 0xea5a_5a5a, SLOT_ISO),
    Slot::new(500, 0x5555_5555, SLOT_MIX),
    Slot::new(5, 0xea5a_5a5a, SLOT_MIX),
    Slot::new(5, 0xffff_ffff, SLOT_ISO),
    Slot::new(5, 0xe555_5555, SLOT_MIX),
    Slot::new(5, 0x5555_5555, SLOT_MIX),
    Slot::new(250, 0xea5a_5a5a, SLOT_MIX),
    Slot::new(50, 0xffff_ffff, SLOT_ISO),
    Slot::new(50, 0xffff_dfff, SLOT_ISO),
];

/// `struct rtw89_btc_fbtc_tdma`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tdma {
    pub kind: u8,
    pub rxflctrl: u8,
    pub txflctrl: u8,
    pub bind: u8,
    pub leak_n: u8,
    pub ext_ctrl: u8,
    pub rxflctrl_role: u8,
    pub option_ctrl: u8,
}

impl Tdma {
    pub fn encode(&self) -> [u8; 8] {
        [
            self.kind,
            self.rxflctrl,
            self.txflctrl,
            self.bind,
            self.leak_n,
            self.ext_ctrl,
            self.rxflctrl_role,
            self.option_ctrl,
        ]
    }
}

/// `t_def[CXTD_OFF]`: TDMA off, as `_reset_btc_var` leaves both the TDMA
/// and what the firmware last took.
pub const TDMA_OFF: Tdma = Tdma {
    kind: 0,
    rxflctrl: 0,
    txflctrl: 0,
    bind: 0,
    leak_n: 0,
    ext_ctrl: 0,
    rxflctrl_role: 0,
    option_ctrl: 0,
};

/// `REG_MAC` and `REG_BB`, a monitored register's space.
pub const REG_MAC: u16 = 0;
pub const REG_BB: u16 = 1;
/// `rtw89_btc_8852b_mon_reg`: the registers the firmware reports, each its
/// space, width in bytes and offset.
pub const MON_REGS: [(u16, u16, u32); 16] = [
    (REG_MAC, 4, 0xda24),
    (REG_MAC, 4, 0xda28),
    (REG_MAC, 4, 0xda2c),
    (REG_MAC, 4, 0xda30),
    (REG_MAC, 4, 0xda4c),
    (REG_MAC, 4, 0xda10),
    (REG_MAC, 4, 0xda20),
    (REG_MAC, 4, 0xda34),
    (REG_MAC, 4, 0xcef4),
    (REG_MAC, 4, 0x8424),
    (REG_MAC, 4, 0xd200),
    (REG_MAC, 4, 0xd220),
    (REG_BB, 4, 0x980),
    (REG_BB, 4, 0x4738),
    (REG_BB, 4, 0x4688),
    (REG_BB, 4, 0x4694),
];

/// Where the coex H2Cs go: `rtw89_h2c_pkt_set_hdr` with `FWCMD_TYPE_H2C`
/// and `H2C_CAT_OUTSRC`, which takes the next sequence number whatever
/// follows, then `rtw89_h2c_tx`.
pub trait Commands<I: Io + ?Sized> {
    fn send(
        &mut self,
        io: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error>;
}

/// The `H2C_CAT_OUTSRC` function `class` and `func`, delivered as H2C.
pub const fn outsrc(class: u8, func: u8) -> Function {
    Function {
        del_type: FWCMD_TYPE_H2C,
        cat: H2C_CAT_OUTSRC,
        class,
        func,
    }
}

impl<I: Io + ?Sized> Commands<I> for Fwcmd<'_, '_> {
    /// [`h2c::Channel::command_for`], then [`h2c::Channel::send`].
    fn send(
        &mut self,
        io: &mut I,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error> {
        let packet = self
            .channel
            .command_for(outsrc(class, func), rack, dack, payload);
        self.channel.send(io, self.rings, &packet)
    }
}

/// One RF path's software grants (`struct rtw89_mac_ax_gnt`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Gnt {
    pub gnt_bt_sw_en: bool,
    pub gnt_bt: bool,
    pub gnt_wl_sw_en: bool,
    pub gnt_wl: bool,
}

/// `_set_gnt(…, BTC_GNT_SW_HI, BTC_GNT_SW_LO, …)`: WL granted and BT
/// refused, both by software.
pub const GNT_WL_ONLY: Gnt = Gnt {
    gnt_bt_sw_en: true,
    gnt_bt: false,
    gnt_wl_sw_en: true,
    gnt_wl: true,
};

/// What `rtw89_mac_cfg_gnt` writes to `R_AX_LTE_SW_CFG_1` for both paths'
/// grants.
pub fn gnt_value(gnt: &[Gnt; 2]) -> u32 {
    let bits = [
        [
            GNT_BT_RFC_S0_SW_VAL | GNT_BT_BB_S0_SW_VAL,
            GNT_BT_RFC_S0_SW_CTRL | GNT_BT_BB_S0_SW_CTRL,
            GNT_WL_RFC_S0_SW_VAL | GNT_WL_BB_S0_SW_VAL,
            GNT_WL_RFC_S0_SW_CTRL | GNT_WL_BB_S0_SW_CTRL,
        ],
        [
            GNT_BT_RFC_S1_SW_VAL | GNT_BT_BB_S1_SW_VAL,
            GNT_BT_RFC_S1_SW_CTRL | GNT_BT_BB_S1_SW_CTRL,
            GNT_WL_RFC_S1_SW_VAL | GNT_WL_BB_S1_SW_VAL,
            GNT_WL_RFC_S1_SW_CTRL | GNT_WL_BB_S1_SW_CTRL,
        ],
    ];
    let mut value = 0;
    for (band, [bt, bt_sw_en, wl, wl_sw_en]) in gnt.iter().zip(bits) {
        for (on, bits) in [
            (band.gnt_bt, bt),
            (band.gnt_bt_sw_en, bt_sw_en),
            (band.gnt_wl, wl),
            (band.gnt_wl_sw_en, wl_sw_en),
        ] {
            if on {
                value |= bits;
            }
        }
    }
    value
}

/// What rtw89's `rtwdev->btc` holds after the init, for the steps after
/// it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Coex {
    /// `mdinfo`, and through it `ant_type` and `btg_pos`.
    pub module: Module,
    /// `cx.wl.scbd[BTC_BT_1ST]`: WL's scoreboard bits.
    pub scbd: u32,
    /// `dm.tdma` and `dm.slot.v1`: the policy last set.
    pub tdma: Tdma,
    pub slots: [Slot; CXST_MAX],
    /// `dm.tdma_now` and `dm.slot_now.v1`: what the firmware was last
    /// sent.
    pub tdma_now: Tdma,
    pub slots_now: [Slot; CXST_MAX],
}

impl Coex {
    /// `_reset_btc_var(rtwdev, BTC_RESET_ALL)` with the module of
    /// `module`.
    fn new(module: Module) -> Self {
        Self {
            module,
            scbd: 0,
            tdma: TDMA_OFF,
            slots: SLOTS,
            tdma_now: TDMA_OFF,
            slots_now: SLOTS,
        }
    }
}

/// What the init leaves, and what rtw89 ignores or only warns about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Init {
    pub coex: Coex,
    /// What `rtw89_mac_coex_init` returned, which `__rtw8852bx_btc_init_cfg`
    /// ignores: an LTE that never readied for its read or write of
    /// `R_AX_LTE_SW_CFG_2` stops it there.
    pub coex_init: Result<(), io::Error>,
    /// `rtw89_mac_get_ctrl_path` read the PTA owned by BT before the init
    /// gave it to WLAN: rtw89's "PTA owner warning".
    pub pta_owner: bool,
    /// What `rtw89_mac_cfg_gnt` returned: an LTE that never readied, after
    /// which the grants were written anyway.
    pub gnt: Result<(), io::Error>,
    /// What `rtw89_mac_cfg_plt_ax` returned: CMAC0 off, with the value
    /// CMAC_FUNC_EN read, and the polluter table not written.
    pub plt: Result<(), u32>,
    /// H2Cs refused, which rtw89 ignores, and the first refusal.
    pub h2c_failed: u32,
    pub h2c_error: Option<h2c::Error>,
}

/// The H2C counters: rtw89 goes on whatever each send returns.
struct Sent {
    failed: u32,
    error: Option<h2c::Error>,
}

impl Sent {
    fn note(&mut self, result: Result<(), h2c::Error>) {
        if let Err(error) = result {
            self.failed += 1;
            self.error.get_or_insert(error);
        }
    }
}

/// `rtw89_btc_ntfy_poweron` then `rtw89_btc_ntfy_init(rtwdev,
/// BTC_MODE_WL)` on an RTL8852B with firmware 0.29.29, reduced to the
/// WL-only action, its H2Cs to `commands`: RFE type `rfe_type` (the
/// efuse's) and cut `cv`.
///
/// The chip is powered, its MAC initialized ([`super::mac::init`]) and its
/// firmware running. An access the interface refuses ends the init with
/// that error; nothing rtw89 ignores does.
pub fn init_wl_only<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    rfe_type: u8,
    cv: u8,
) -> Result<Init, io::Error> {
    let mut coex = Coex::new(set_rfe(rfe_type, cv));
    let coex_init = init_cfg(io, coex.module.ant.kind)?;
    // _write_scbd notes the bits; _action_common writes them.
    coex.scbd |= BTC_WSCB_ACTIVE | BTC_WSCB_ON | BTC_WSCB_BTLOG;
    let pta_owner = ctrl_path(io)?;
    let mut sent = Sent {
        failed: 0,
        error: None,
    };
    // _set_init_info, then the rest of rtw89_btc_ntfy_init.
    sent.note(drv_info_init(io, commands, &coex.module));
    sent.note(drv_info_ctrl(io, commands));
    sent.note(set_slots(io, commands, &coex.slots));
    sent.note(set_monreg(io, commands));
    sent.note(set_monreg(io, commands));
    sent.note(set_slots(io, commands, &coex.slots));
    sent.note(drv_info_init(io, commands, &coex.module));
    sent.note(drv_info_ctrl(io, commands));
    // _run_coex(BTC_RSN_NTFY_INIT): _action_wl_only.
    let gnt = cfg_gnt(io, &[GNT_WL_ONLY; 2])?;
    cfg_ctrl_path(io, true)?;
    let plt = cfg_plt(io, TX_PLT_GNT_WL | RX_PLT_GNT_WL)?;
    if let Some(result) = set_policy_off_bt(io, commands, &mut coex) {
        sent.note(result);
    }
    // _action_common's _sned_h2c_w2bscbd for BT 0; RTL8852B has no second.
    cfg_sb(io, coex.scbd)?;
    Ok(Init {
        coex,
        coex_init,
        pta_owner,
        gnt,
        plt,
        h2c_failed: sent.failed,
        h2c_error: sent.error,
    })
}

/// `__rtw8852bx_btc_init_cfg` for antennas of `kind`: what
/// `rtw89_mac_coex_init` returned, which it ignores.
fn init_cfg<I: Io + ?Sized>(io: &mut I, kind: u8) -> Result<Result<(), io::Error>, io::Error> {
    let coex_init = coex_init(io)?;
    // BTC_PRI_MASK_TX_RESP and BTC_PRI_MASK_BEACON.
    io.write32_set(BTC_BT_COEX_MSK_TABLE, BTC_PRI_MASK_TX_RESP_V1)?;
    io.write32_set(WL_PRI_MSK, PTA_WL_PRI_MASK_BCNQ)?;
    write_rf(io, RF_PATH_A, RR_WLSEL, 0)?;
    write_rf(io, RF_PATH_B, RR_WLSEL, 0)?;
    let masks = if kind == BTC_ANT_SHARED {
        [
            (RF_PATH_A, BTC_BT_SS_GROUP, 0x5ff),
            (RF_PATH_B, BTC_BT_SS_GROUP, 0x5ff),
            (RF_PATH_A, BTC_BT_TX_GROUP, 0x5ff),
            (RF_PATH_B, BTC_BT_TX_GROUP, 0x55f),
        ]
    } else {
        [
            (RF_PATH_A, BTC_BT_SS_GROUP, 0x5df),
            (RF_PATH_B, BTC_BT_SS_GROUP, 0x5df),
            (RF_PATH_A, BTC_BT_TX_GROUP, 0x5ff),
            (RF_PATH_B, BTC_BT_TX_GROUP, 0x5ff),
        ]
    };
    for (path, group, value) in masks {
        set_trx_mask(io, path, group, value)?;
    }
    io.write32(BTC_BREAK_TABLE, BTC_BREAK_PARAM)?;
    io.write32_set(CSR_MODE, BT_CNT_RST | STATIS_BT_EN)?;
    Ok(coex_init)
}

/// `rtw8852bx_set_trx_mask`.
fn set_trx_mask<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    group: u32,
    value: u32,
) -> Result<(), io::Error> {
    write_rf(io, path, RR_LUTWE, 0x20000)?;
    write_rf(io, path, RR_LUTWA, group)?;
    write_rf(io, path, RR_LUTWD0, value)?;
    write_rf(io, path, RR_LUTWE, 0)
}

/// `rtw89_write_rf` over the whole register, whose failure rtw89 ignores:
/// a SWSI that stayed busy leaves the write unmade.
fn write_rf<I: Io + ?Sized>(
    io: &mut I,
    path: u8,
    address: u32,
    data: u32,
) -> Result<(), io::Error> {
    match io.write_rf(path, address, RFREG_MASK, data) {
        Err(io::Error::Timeout { .. }) => Ok(()),
        result => result,
    }
}

/// `rtw89_mac_coex_init` for an RTL8852B in `RTW89_MAC_AX_COEX_RTK_MODE`
/// with `RTW89_MAC_AX_COEX_INNER`: its result, a timeout when the LTE
/// access never readied.
fn coex_init<I: Io + ?Sized>(io: &mut I) -> Result<Result<(), io::Error>, io::Error> {
    io.write8_set(GPIO_MUXCFG, ENBT)?;
    io.write8_set(BTC_FUNC_EN, PTA_WL_TX_EN)?;
    io.write8_set(BT_COEX_CFG_2 + 1, (GNT_BT_POLARITY >> 8) as u8)?;
    io.write8_set(CSR_MODE, (STATIS_BT_EN | WL_ACT_MSK) as u8)?;
    io.write8_set(CSR_MODE + 2, (BT_CNT_RST >> 16) as u8)?;
    io.write8_clr(TRXPTCL_RESP_0 + 3, (RSP_CHK_BTCCA >> 24) as u8)?;
    let value = io.read16(CCA_CFG_0)?;
    io.write16(
        CCA_CFG_0,
        (value | BTCCA_EN as u16) & !(BTCCA_BRK_TXOP_EN as u16),
    )?;
    let (value, ready) = read_lte(io, LTE_SW_CFG_2)?;
    if !ready {
        return Ok(Err(lte_timeout()));
    }
    if !write_lte(io, LTE_SW_CFG_2, value & WL_RX_CTRL)? {
        return Ok(Err(lte_timeout()));
    }
    let value = io.read8(GPIO_MUXCFG)?;
    io.write8(
        GPIO_MUXCFG,
        (value & !(BTMODE_MASK as u8)) | prep(BT_MODE_0_3, BTMODE_MASK) as u8,
    )?;
    let value = io.read8(TDMA_MODE)?;
    io.write8(TDMA_MODE, value | RTK_BT_ENABLE)?;
    let value = io.read8(BT_COEX_CFG_5)?;
    io.write8(
        BT_COEX_CFG_5,
        (value & !(BT_RPT_SAMPLE_RATE_MASK as u8)) | prep(RTK_RATE, BT_RPT_SAMPLE_RATE_MASK) as u8,
    )?;
    let value = io.read8(GPIO_MUXCFG + 1)?;
    io.write8(GPIO_MUXCFG + 1, (value & !(1 << 2)) | 1 << 1)?;
    Ok(Ok(()))
}

/// What an LTE access that never readied reports.
const fn lte_timeout() -> io::Error {
    io::Error::Timeout {
        register: LTE_CTRL + 3,
        mask: LTE_CTRL_READY as u32,
    }
}

/// `read_poll_timeout(rtw89_read8, …, R_AX_LTE_CTRL + 3)` on the LTE
/// access's ready bit: whether it readied.
fn lte_ready<I: Io + ?Sized>(io: &mut I) -> Result<bool, io::Error> {
    let mut waited = 0;
    loop {
        if io.read8(LTE_CTRL + 3)? & LTE_CTRL_READY != 0 {
            return Ok(true);
        }
        if waited >= LTE_POLL_BOUND_US {
            return Ok(false);
        }
        io.delay_us(LTE_POLL_STEP_US);
        waited += LTE_POLL_STEP_US;
    }
}

/// `rtw89_mac_read_lte`: the LTE register at `offset`, read whether or not
/// the access readied, and whether it did.
fn read_lte<I: Io + ?Sized>(io: &mut I, offset: u32) -> Result<(u32, bool), io::Error> {
    let ready = lte_ready(io)?;
    io.write32(LTE_CTRL, LTE_CTRL_READ | offset)?;
    Ok((io.read32(LTE_RDATA)?, ready))
}

/// `rtw89_mac_write_lte`: `value` written to the LTE register at `offset`
/// whether or not the access readied, and whether it did.
fn write_lte<I: Io + ?Sized>(io: &mut I, offset: u32, value: u32) -> Result<bool, io::Error> {
    let ready = lte_ready(io)?;
    io.write32(LTE_WDATA, value)?;
    io.write32(LTE_CTRL, LTE_CTRL_WRITE | offset)?;
    Ok(ready)
}

/// The software grants in `R_AX_LTE_SW_CFG_1`, through the LTE access:
/// [`gnt_value`]`(&[`[`GNT_WL_ONLY`]`; 2])` once the init ran. A timeout
/// when the access never readied.
pub fn read_gnt<I: Io + ?Sized>(io: &mut I) -> Result<u32, io::Error> {
    match read_lte(io, LTE_SW_CFG_1)? {
        (value, true) => Ok(value),
        (_, false) => Err(lte_timeout()),
    }
}

/// `rtw89_mac_cfg_gnt`: its result, a timeout when the LTE access never
/// readied before the grants were written.
fn cfg_gnt<I: Io + ?Sized>(io: &mut I, gnt: &[Gnt; 2]) -> Result<Result<(), io::Error>, io::Error> {
    Ok(match write_lte(io, LTE_SW_CFG_1, gnt_value(gnt))? {
        true => Ok(()),
        false => Err(lte_timeout()),
    })
}

/// `rtw89_mac_get_ctrl_path` for an RTL885xB: whether BT owns the PTA.
fn ctrl_path<I: Io + ?Sized>(io: &mut I) -> Result<bool, io::Error> {
    let value = io.read8(SYS_SDIO_CTRL + 3)?;
    Ok(field(value.into(), LTE_MUX_CTRL_PATH >> 24) != 0)
}

/// `rtw89_mac_cfg_ctrl_path`: the PTA to WLAN, or to BT.
fn cfg_ctrl_path<I: Io + ?Sized>(io: &mut I, wl: bool) -> Result<(), io::Error> {
    let value = io.read8(SYS_SDIO_CTRL + 3)?;
    let bit = (LTE_MUX_CTRL_PATH >> 24) as u8;
    io.write8(
        SYS_SDIO_CTRL + 3,
        if wl { value | bit } else { value & !bit },
    )
}

/// `rtw89_mac_cfg_plt_ax` for band 0, `plt` the table's grant bits: CMAC0
/// checked as `rtw89_mac_check_mac_en` checks it, then the table written
/// with its enable. `Err` with what CMAC_FUNC_EN read when CMAC0 is off.
fn cfg_plt<I: Io + ?Sized>(io: &mut I, plt: u16) -> Result<Result<(), u32>, io::Error> {
    let value = io.read32(CMAC_FUNC_EN)?;
    if value == R32_EA || value == R32_DEAD || value & CMAC_EN != CMAC_EN {
        return Ok(Err(value));
    }
    io.write16(BT_PLT, plt | PLT_EN)?;
    Ok(Ok(()))
}

/// `rtw89_mac_cfg_sb` with the chip powered (`RTW89_FLAG_POWERON`): WL's
/// scoreboard bits `scbd` toggled in with the firmware's byte, then the
/// wait rtw89 gives BT's firmware.
fn cfg_sb<I: Io + ?Sized>(io: &mut I, scbd: u32) -> Result<(), io::Error> {
    let fw = field(io.read32(SCOREBOARD)?, SB_FW_MASK) & !SB_BTGS1_NOTIFY | SB_NOTIFY_TP_MAJOR;
    io.write32(
        SCOREBOARD,
        SB_TOGGLE | prep(scbd & SB_DRV_MASK, SB_DRV_MASK) | prep(fw, SB_FW_MASK),
    )?;
    io.delay_us(SCOREBOARD_WAIT_US);
    Ok(())
}

/// `rtw89_fw_h2c_cxdrv_init`'s payload (`struct rtw89_h2c_cxinit`) for a
/// WL-only init of `module`: the antennas, the module, the guard channels
/// and WL alone with its init done.
pub fn cxinit(module: &Module) -> [u8; 14] {
    let ant = &module.ant;
    let ant_info = (ant.single_pos & 0x1)
        | (ant.diversity & 0x1) << 1
        | (ant.btg_pos & 0x3) << 2
        | (ant.stream_cnt & 0xf) << 4;
    let mod_info = (module.bt_solo & 0x1)
        | (module.bt0_pos & 0x1) << 1
        | (module.bt0_sw_type & 0x1) << 2
        | (module.wa_type & 0x7) << 3;
    // wl_only, wl_init_ok; no DBCC, no other coex, not BT alone.
    let info = 1 | 1 << 1;
    [
        CXDRVINFO_INIT,
        12,
        ant.kind,
        ant.num,
        ant.isolation,
        ant_info,
        module.rfe_type,
        module.kt_ver,
        mod_info,
        module.kt_ver_adie,
        AFH_GUARD_CH,
        info,
        0,
        0,
    ]
}

/// `rtw89_fw_h2c_cxdrv_init` as `_fw_set_drv_info(CXDRVINFO_INIT)` sends
/// it for init version 0: no ack asked.
fn drv_info_init<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    module: &Module,
) -> Result<(), h2c::Error> {
    commands.send(io, BTFC_SET, SET_DRV_INFO, false, false, &cxinit(module))
}

/// `rtw89_fw_h2c_cxdrv_ctrl`'s payload for control version 1: no manual
/// control, BT not ignored, no freerun, and no trace step.
pub const CXCTRL: [u8; 6] = [CXDRVINFO_CTRL, 4, 0, 0, 0, 0];

/// `rtw89_fw_h2c_cxdrv_ctrl` as `_fw_set_drv_info(CXDRVINFO_CTRL)` sends it
/// with driver info version 0: no ack asked.
fn drv_info_ctrl<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
) -> Result<(), h2c::Error> {
    commands.send(io, BTFC_SET, SET_DRV_INFO, false, false, &CXCTRL)
}

/// `_send_fw_cmd(rtwdev, BTFC_SET, func, payload)` with the H2C macro
/// unsupported (RTL8852B's `para_ver` has no `BTC_FEAT_H2C_MACRO`):
/// `rtw89_fw_h2c_raw_with_hdr` asking DONE_ACK.
fn send_fw_cmd<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    func: u8,
    payload: &[u8],
) -> Result<(), h2c::Error> {
    commands.send(io, BTFC_SET, func, false, true, payload)
}

/// `rtw89_btc_fw_set_slots`' payload for slot version 1
/// (`struct rtw89_btc_btf_set_slot_table`): every slot of `slots`.
pub fn slot_table(slots: &[Slot; CXST_MAX]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + 8 * CXST_MAX);
    payload.extend_from_slice(&[BTF_SET_SLOT_TABLE_VER, CXST_MAX as u8]);
    for slot in slots {
        payload.extend_from_slice(&slot.encode());
    }
    payload
}

/// `rtw89_btc_fw_set_slots`: `SET_SLOT_TABLE`.
fn set_slots<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    slots: &[Slot; CXST_MAX],
) -> Result<(), h2c::Error> {
    send_fw_cmd(io, commands, SET_SLOT_TABLE, &slot_table(slots))
}

/// `btc_fw_set_monreg`'s payload for monitored register version 2
/// (`struct rtw89_btc_btf_set_mon_reg_v1`): [`MON_REGS`].
pub fn monreg_table() -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + 8 * MON_REGS.len());
    payload.extend_from_slice(&[FCXMREG, MON_REGS.len() as u8]);
    for (kind, bytes, offset) in MON_REGS {
        payload.extend_from_slice(&kind.to_le_bytes());
        payload.extend_from_slice(&bytes.to_le_bytes());
        payload.extend_from_slice(&offset.to_le_bytes());
    }
    payload
}

/// `btc_fw_set_monreg`: `SET_MREG_TABLE`.
fn set_monreg<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
) -> Result<(), h2c::Error> {
    send_fw_cmd(io, commands, SET_MREG_TABLE, &monreg_table())
}

/// `_fw_set_policy`'s payload: `_append_tdma` (version 3, the TDMA when it
/// differs from what the firmware last took) then `_append_slot_v1` (each
/// slot that differs), `update_policy_force` clear.
pub fn policy(coex: &Coex) -> Vec<u8> {
    let mut payload = Vec::new();
    if coex.tdma != coex.tdma_now {
        // struct rtw89_btc_fbtc_tdma_v3: fver, rsvd, rsvd1, then the TDMA.
        payload.extend_from_slice(&[CXPOLICY_TDMA, 12, FCXTDMA, 0, 0, 0]);
        payload.extend_from_slice(&coex.tdma.encode());
    }
    for (index, (slot, now)) in coex.slots.iter().zip(&coex.slots_now).enumerate() {
        if slot != now {
            // struct btc_fbtc_1slot: fver, slot id, then the slot.
            payload.extend_from_slice(&[CXPOLICY_SLOT, 10, FCXSLOTS, index as u8]);
            payload.extend_from_slice(&slot.encode());
        }
    }
    payload
}

/// `_set_policy(rtwdev, BTC_CXP_OFF_BT, BTC_ACT_WL_ONLY)`:
/// `rtw89_btc_set_policy_v1`'s TDMA off with the OFF slot's table
/// [`CXTBL_OFF_BT`] and `_set_tdma_bind`'s binding, then `_fw_set_policy`'s
/// `SET_CX_POLICY` when anything changed. `_send_fw_cmd` returns 0 whether
/// or not the H2C went, so what the firmware last took follows the policy
/// either way. `None` when nothing changed and nothing was sent.
fn set_policy_off_bt<I: Io + ?Sized, C: Commands<I> + ?Sized>(
    io: &mut I,
    commands: &mut C,
    coex: &mut Coex,
) -> Option<Result<(), h2c::Error>> {
    coex.tdma = Tdma {
        bind: TDMA_BIND_HWB0,
        ..TDMA_OFF
    };
    coex.slots[CXST_OFF] = Slot {
        cxtbl: CXTBL_OFF_BT,
        ..SLOTS[CXST_OFF]
    };
    let payload = policy(coex);
    if payload.is_empty() {
        return None;
    }
    let result = send_fw_cmd(io, commands, SET_CX_POLICY, &payload);
    coex.tdma_now = coex.tdma;
    coex.slots_now = coex.slots;
    Some(result)
}

#[cfg(test)]
mod tests;
