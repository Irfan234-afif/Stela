extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    cam::{self, Cipher, Key},
    h2c::{Function, Header, Sequence},
    io::field,
    registers::{
        CMAC_EN, CMAC_FUNC_EN, NET_TYPE_MASK, PORT_CFG_P0, PORT_FUNC_EN, R32_DEAD, RX_BSSID_FIT_EN,
        TSF_UDT_EN,
    },
};
use alloc::{vec, vec::Vec};

/// The C oracle's register model: MAC space, the indirect window
/// included, as bytes, and the trace its accesses leave: reads tagged by
/// width, writes by 4 plus width, delays 9 in microseconds.
pub(crate) struct Model {
    pub memory: Vec<u8>,
    pub trace: Vec<u32>,
}

impl Model {
    pub fn new(fill: u8) -> Self {
        Self {
            memory: vec![fill; 0x4_0100],
            trace: Vec::new(),
        }
    }

    pub fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.trace.extend([tag, a, b]);
    }

    pub fn get(&self, register: u32, width: u32) -> u32 {
        let at = register as usize;
        let mut word = [0; 4];
        word[..width as usize].copy_from_slice(&self.memory[at..at + width as usize]);
        u32::from_le_bytes(word)
    }

    pub fn set(&mut self, register: u32, width: u32, value: u32) {
        let at = register as usize;
        self.memory[at..at + width as usize]
            .copy_from_slice(&value.to_le_bytes()[..width as usize]);
    }

    fn read(&mut self, register: u32, width: u32) -> u32 {
        let value = self.get(register, width);
        self.mark(width, register, value);
        value
    }

    fn write(&mut self, register: u32, width: u32, value: u32) {
        self.mark(4 + width, register, value);
        self.set(register, width, value);
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Ok(self.read(register, 1) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Ok(self.read(register, 2) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        Ok(self.read(register, 4))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.write(register, 1, value.into());
        Ok(())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.write(register, 2, value.into());
        Ok(())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.write(register, 4, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.mark(9, microseconds as u32, 0);
    }
}

/// The C oracle's `rtw89_h2c_tx` stand-in: the H2C `rtw89_h2c_pkt_set_hdr`
/// built, recorded with its length and the sequence after it (tag 40) and
/// as little-endian words (tag 41), then taken, or refused with `-ENOSPC`.
pub(crate) struct Recorder {
    pub sequence: Sequence,
    pub refuse: bool,
    pub sent: Vec<(Header, Vec<u8>)>,
}

impl Recorder {
    pub fn new(sequence: u8) -> Self {
        Self {
            sequence: Sequence(sequence),
            refuse: false,
            sent: Vec::new(),
        }
    }

    /// Each H2C's class and function, in the order sent.
    pub fn functions(&self) -> Vec<(u8, u8)> {
        self.sent
            .iter()
            .map(|(header, _)| {
                let function = header.function();
                (function.class, function.func)
            })
            .collect()
    }
}

impl Commands<Model> for Recorder {
    fn send(
        &mut self,
        io: &mut Model,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), H2cError> {
        let header =
            self.sequence
                .set_hdr(Function::mac(class, func), rack, dack, payload.len() as u32);
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(payload);
        io.mark(40, bytes.len() as u32, self.sequence.0.into());
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            io.mark(41, index as u32, u32::from_le_bytes(word));
        }
        self.sent.push((header, payload.to_vec()));
        if self.refuse {
            Err(H2cError::NoResource)
        } else {
            Ok(())
        }
    }
}

pub(crate) const OWN: [u8; 6] = [0x00, 0xe0, 0x4c, 0x88, 0x52, 0xbe];
pub(crate) const AP: [u8; 6] = [0x9c, 0x53, 0x22, 0x5b, 0x7a, 0x31];

/// The oracle's `he()`: HE capabilities with PHY capability bytes 6 and
/// 9, the PPE threshold header and patterned thresholds.
fn he(phy6: u8, phy9: u8, hdr: u8, seed: u8) -> HeCap {
    let mut cap = HeCap::default();
    cap.phy_cap_info[6] = phy6;
    cap.phy_cap_info[9] = phy9;
    cap.ppe_thres[0] = hdr;
    for (i, threshold) in (1u32..).zip(cap.ppe_thres.iter_mut().skip(1)) {
        *threshold = (u32::from(seed) * i + 0x31 * (i & 3)) as u8;
    }
    cap
}

/// What rtw89 returns for an error here.
fn errno(result: Result<(), Error>) -> u32 {
    let code: i32 = match result {
        Ok(()) => 0,
        Err(Error::Port(_) | Error::Invalid(_)) => -22,
        Err(Error::CmacOff { .. }) => -14,
        Err(Error::CamFull(_)) => -16,
        Err(Error::Unsupported(_)) => -95,
        Err(Error::H2c(H2cError::NoResource)) => -28,
        Err(error) => panic!("{error:?}"),
    };
    code as u32
}

fn step(io: &mut Model, id: u32, result: Result<(), Error>) {
    let code = errno(result);
    io.mark(50, id, code);
}

fn key(cipher: Cipher, pairwise: bool, keyidx: u8, material: &[u8]) -> Key<'_> {
    Key {
        cipher,
        pairwise,
        keyidx,
        material,
    }
}

fn material(seed: u8) -> [u8; 16] {
    core::array::from_fn(|i| seed + i as u8)
}

/// `rtw89_core_sta_link_assoc` after its H2C: the stubs' marks, which on
/// an RTL8852B Device are 4.5's RA H2C and what Stela leaves out; then
/// the port update.
fn assoc(io: &mut Model, h2c: &mut Recorder, link: &mut Link, peer: &Peer, id: u32) {
    let result = sta_assoc(io, h2c, link, peer);
    if result.is_ok() {
        io.mark(70, 0, 0);
        io.mark(71, 0, 0);
        io.mark(72, link.mac_id.into(), 0);
        io.mark(73, 1, 0);
    }
    step(io, id, result);
    let result = bss_assoc(io, link);
    step(io, id + 1, result);
}

/// A key written, its return and its entry (rtw89's `hw_key_idx`, which
/// keeps the entry it was given when the key failed).
fn add(world: &mut World, peer: Option<&Peer>, id: u32, key: &Key<'_>) -> u8 {
    let World {
        io,
        h2c,
        cams,
        link,
    } = world;
    let taken = cams.sec_cam_map.trailing_ones() as u8;
    let result = cam::write_key(io, h2c, cams, link, peer, key);
    let index = *result.as_ref().unwrap_or(&taken);
    step(io, id, result.map(|_| ()));
    io.mark(61, index.into(), 0);
    index
}

struct World {
    io: Model,
    h2c: Recorder,
    cams: cam::Info,
    link: Link,
}

impl World {
    fn new(fill: u8, sequence: u8, mac_id: u8, port: u8) -> Self {
        Self {
            io: Model::new(fill),
            h2c: Recorder::new(sequence),
            cams: cam::Info::default(),
            link: Link::station(mac_id, port, OWN, 2),
        }
    }

    fn vif_init(&mut self, id: u32) {
        let result = vif_init(&mut self.io, &mut self.h2c, &mut self.cams, &mut self.link);
        step(&mut self.io, id, result);
    }

    fn vif_deinit(&mut self, id: u32) {
        let result = vif_deinit(&mut self.io, &mut self.h2c, &mut self.cams, &mut self.link);
        step(&mut self.io, id, result);
    }

    fn bssid(&mut self, id: u32, bssid: [u8; 6]) {
        let result = bssid_changed(&mut self.io, &mut self.h2c, &mut self.link, bssid);
        step(&mut self.io, id, result.map_err(Error::H2c));
    }

    fn assoc(&mut self, peer: &Peer, id: u32) {
        assoc(&mut self.io, &mut self.h2c, &mut self.link, peer, id);
    }

    fn clear(&mut self, peer: Option<&Peer>, id: u32, entry: u8) {
        let result = cam::clear_key(
            &mut self.io,
            &mut self.h2c,
            &mut self.cams,
            &mut self.link,
            peer,
            entry,
        );
        step(&mut self.io, id, result);
    }

    fn cmac_tbl(&mut self, id: u32, table: &[u8; CMC_TBL_LEN]) {
        let result = send_cmac_tbl(&mut self.io, &mut self.h2c, table);
        step(&mut self.io, id, result.map_err(Error::H2c));
    }
}

fn segments(trace: &[u8]) -> Vec<Vec<u32>> {
    let mut segments = Vec::new();
    let mut offset = 0;
    while offset < trace.len() {
        let length = u32::from_le_bytes(trace[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        segments.push(
            trace[offset..offset + length]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .collect(),
        );
        offset += length;
    }
    segments
}

/// The user's join: interface up, BSSID, HE association on 5 GHz, keys,
/// disconnect, BSSID cleared, interface down.
fn join_and_leave() -> Model {
    let mut w = World::new(0, 0, 0, 0);
    w.io.set(CMAC_FUNC_EN, 4, CMAC_EN);
    w.vif_init(1);
    w.bssid(2, AP);
    w.link.bss = Bss {
        aid: 0x1003,
        beacon_int: 100,
        dtim_period: 2,
        bss_color: 0x2b,
        he_support: true,
        two_ghz: false,
    };
    let peer = Peer {
        addr: AP,
        rx_nss: 2,
        he: Some(he(HE_PHY_CAP6_PPE_THRESHOLD_PRESENT, 0, 0x39, 0x1d)),
    };
    w.assoc(&peer, 3);
    let (m1, m2, m4) = (material(0x10), material(0x20), material(0x40));
    let k1 = add(&mut w, Some(&peer), 5, &key(Cipher::Ccmp128, true, 0, &m1));
    let k2 = add(&mut w, None, 6, &key(Cipher::Ccmp128, false, 1, &m2));
    // The harness's TKIP keys, group and pairwise, never get an entry:
    // their hw_key_idx stays 0, nothing is sent, and mac80211 never asks to
    // delete them.
    for (id, pairwise, keyidx, material) in [(7, false, 2, [0x30; 32]), (8, true, 0, [0x50; 32])] {
        let result = cam::write_key(
            &mut w.io,
            &mut w.h2c,
            &mut w.cams,
            &mut w.link,
            pairwise.then_some(&peer),
            &key(Cipher::Tkip, pairwise, keyidx, &material),
        );
        step(&mut w.io, id, result.map(|_| ()));
        w.io.mark(61, 0, 0);
    }
    let k4 = add(&mut w, None, 9, &key(Cipher::Ccmp128, false, 2, &m4));
    w.clear(None, 10, k2);
    w.clear(Some(&peer), 11, k1);
    w.clear(None, 12, k4);
    w.io.mark(74, 0, 0);
    let result = sta_disconnect(&mut w.io, &mut w.h2c, &mut w.link, &peer);
    step(&mut w.io, 13, result);
    w.bssid(14, [0; 6]);
    w.vif_deinit(15);
    w.io
}

/// All-ones registers, MAC ID 37 on port 1: TX-time tables, a pause, a
/// non-HE association on 2.4 GHz and refused H2C.
fn second_port() -> Model {
    let mut w = World::new(0xff, 0xfe, 37, 1);
    w.link.bss.two_ghz = true;
    w.vif_init(1);
    let mut sta = TxTime {
        mac_id: 37,
        cctl_tx_time: true,
        ampdu_max_time: 0xa,
        cctl_tx_retry_limit: true,
        data_tx_cnt_lmt: 0x2a,
    };
    w.cmac_tbl(2, &txtime_cmac_tbl(&sta));
    sta.cctl_tx_time = false;
    sta.cctl_tx_retry_limit = false;
    w.cmac_tbl(3, &txtime_cmac_tbl(&sta));
    let result = set_macid_pause(&mut w.io, &mut w.h2c, 37, true).map(|_| ());
    step(&mut w.io, 4, result);
    w.bssid(5, AP);
    w.link.bss = Bss {
        aid: 0x7ff,
        beacon_int: 200,
        dtim_period: 3,
        bss_color: 0,
        he_support: false,
        two_ghz: true,
    };
    let peer = Peer {
        addr: AP,
        rx_nss: 1,
        he: None,
    };
    w.assoc(&peer, 6);
    let m1 = material(0x50);
    w.h2c.refuse = true;
    add(&mut w, Some(&peer), 8, &key(Cipher::Ccmp128, true, 0, &m1));
    w.h2c.refuse = false;
    add(&mut w, Some(&peer), 9, &key(Cipher::Ccmp128, true, 0, &m1));
    w.h2c.refuse = true;
    w.vif_deinit(10);
    w.io
}

fn cmac_off() -> Model {
    let mut w = World::new(0, 0, 0, 0);
    w.io.set(CMAC_FUNC_EN, 4, R32_DEAD);
    w.vif_init(1);
    w.io
}

/// The oracle's HE capabilities: RX streams, PHY capability bytes 6 and
/// 9, the PPE threshold header and the thresholds' seed.
const CAPS: [[u8; 5]; 9] = [
    [2, 0x00, 0x80, 0x00, 0x00],
    [1, 0x00, 0x40, 0x00, 0x00],
    [2, 0x00, 0xc0, 0x00, 0x00],
    [2, 0x80, 0x00, 0x39, 0x1d],
    [1, 0x80, 0x00, 0x78, 0x07],
    [4, 0x80, 0x00, 0x7b, 0x55],
    [1, 0x80, 0x00, 0x08, 0xff],
    [2, 0x80, 0x00, 0x11, 0x00],
    [3, 0xbf, 0x3f, 0x29, 0xe3],
];

fn paddings() -> Model {
    let mut w = World::new(0, 0x10, 5, 0);
    w.link.type_mapping(true);
    let mut peer = Peer {
        addr: AP,
        ..Peer::default()
    };
    for (i, [rx_nss, phy6, phy9, hdr, seed]) in (0u32..).zip(CAPS) {
        peer.rx_nss = rx_nss;
        peer.he = Some(he(phy6, phy9, hdr, seed));
        let table = assoc_cmac_tbl(&w.link, Some(&peer));
        w.cmac_tbl(i, &table);
    }
    peer.he = None;
    let table = assoc_cmac_tbl(&w.link, Some(&peer));
    w.cmac_tbl(100, &table);
    let table = assoc_cmac_tbl(&w.link, None);
    w.cmac_tbl(101, &table);
    w.io
}

#[test]
#[ignore = "oracle: STELA_RTW89_H2C_ORACLE"]
fn station_h2c_bytes_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_H2C_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("station.bin")).unwrap();
    let expected = segments(&trace);
    assert_eq!(expected.len(), 4, "segments");
    let names = ["join and leave", "second port", "CMAC off", "paddings"];
    let models = [join_and_leave(), second_port(), cmac_off(), paddings()];
    for ((name, model), expected) in names.iter().zip(models).zip(expected) {
        let at = model
            .trace
            .chunks(3)
            .zip(expected.chunks(3))
            .position(|(ours, theirs)| ours != theirs);
        assert!(
            at.is_none(),
            "{name}: record {at:?} differs: {:x?} against {:x?}",
            at.map(|at| &model.trace[3 * at..3 * at + 3]),
            at.map(|at| &expected[3 * at..3 * at + 3])
        );
        assert_eq!(model.trace.len(), expected.len(), "{name}: lengths");
    }
}

#[test]
fn a_station_joins_and_leaves_in_rtw89_order() {
    let mut w = World::new(0, 0, 0, 0);
    w.io.set(CMAC_FUNC_EN, 4, CMAC_EN);
    vif_init(&mut w.io, &mut w.h2c, &mut w.cams, &mut w.link).unwrap();
    let addr_cam = (
        cam::H2C_CL_MAC_ADDR_CAM_UPDATE,
        cam::H2C_FUNC_MAC_ADDR_CAM_UPD,
    );
    let cmac = (H2C_CL_MAC_FR_EXCHG, H2C_FUNC_MAC_CCTLINFO_UD);
    let join_info = (H2C_CL_MAC_MEDIA_RPT, H2C_FUNC_MAC_JOININFO);
    let role = (H2C_CL_MAC_MEDIA_RPT, H2C_FUNC_MAC_FWROLE_MAINTAIN);
    assert_eq!(
        w.h2c.functions(),
        [
            (H2C_CL_MAC_FW_OFLD, H2C_FUNC_MAC_MACID_PAUSE),
            role,
            join_info,
            addr_cam,
            cmac,
        ]
    );
    // The port is on, not linked; the role is created and the join info
    // says disconnected.
    assert_eq!(w.io.get(PORT_CFG_P0, 4) & PORT_FUNC_EN, PORT_FUNC_EN);
    let word =
        |h2c: &Recorder, i: usize| u32::from_le_bytes(h2c.sent[i].1[..4].try_into().unwrap());
    assert_eq!(
        field(word(&w.h2c, 1), ROLE_MAINTAIN_W0_UPD_MODE),
        UpdMode::Create as u32
    );
    assert_eq!(
        field(word(&w.h2c, 1), ROLE_MAINTAIN_W0_WIFI_ROLE),
        WIFI_ROLE_STATION.into()
    );
    assert_eq!(word(&w.h2c, 2) & JOININFO_W0_OP, JOININFO_W0_OP);
    assert_eq!(
        field(word(&w.h2c, 2), JOININFO_W0_NET_TYPE),
        NET_TYPE_NO_LINK.into()
    );

    w.h2c.sent.clear();
    bssid_changed(&mut w.io, &mut w.h2c, &mut w.link, AP).unwrap();
    w.link.bss = Bss {
        aid: 1,
        beacon_int: 100,
        dtim_period: 1,
        he_support: true,
        ..Bss::default()
    };
    let peer = Peer {
        addr: AP,
        rx_nss: 2,
        he: Some(HeCap::default()),
    };
    sta_assoc(&mut w.io, &mut w.h2c, &mut w.link, &peer).unwrap();
    bss_assoc(&mut w.io, &w.link).unwrap();
    assert_eq!(w.h2c.functions(), [addr_cam, cmac, join_info, addr_cam]);
    // Joined: infrastructure, triggered by an HE BSS, the port filtering
    // by BSSID and syncing its TSF.
    assert_eq!(word(&w.h2c, 2) & JOININFO_W0_OP, 0);
    assert_eq!(
        field(word(&w.h2c, 2), JOININFO_W0_NET_TYPE),
        NET_TYPE_INFRA.into()
    );
    assert_eq!(word(&w.h2c, 2) & JOININFO_W0_TGR, JOININFO_W0_TGR);
    let port_cfg = w.io.get(PORT_CFG_P0, 4);
    assert_eq!(field(port_cfg, NET_TYPE_MASK), NET_TYPE_INFRA.into());
    assert_ne!(port_cfg & RX_BSSID_FIT_EN, 0);
    assert_ne!(port_cfg & TSF_UDT_EN, 0);

    w.h2c.sent.clear();
    sta_disconnect(&mut w.io, &mut w.h2c, &mut w.link, &peer).unwrap();
    bssid_changed(&mut w.io, &mut w.h2c, &mut w.link, [0; 6]).unwrap();
    vif_deinit(&mut w.io, &mut w.h2c, &mut w.cams, &mut w.link).unwrap();
    assert_eq!(
        w.h2c.functions(),
        [cmac, join_info, addr_cam, addr_cam, role, addr_cam]
    );
    assert_eq!(word(&w.h2c, 1) & JOININFO_W0_OP, JOININFO_W0_OP);
    assert_eq!(
        field(word(&w.h2c, 1), JOININFO_W0_NET_TYPE),
        NET_TYPE_NO_LINK.into()
    );
    assert_eq!(
        field(word(&w.h2c, 4), ROLE_MAINTAIN_W0_UPD_MODE),
        UpdMode::Remove as u32
    );
    assert!(!w.link.addr_cam.valid && !w.link.bssid_cam.valid);
    assert_eq!((w.cams.addr_cam_map, w.cams.bssid_cam_map), (0, 0));
}

#[test]
fn a_dead_cmac_stops_the_interface_before_any_h2c() {
    let mut io = cmac_off();
    let trace = core::mem::take(&mut io.trace);
    assert_eq!(trace[trace.len() - 3..], [50, 1, (-14i32) as u32]);
    assert!(!trace.chunks(3).any(|record| record[0] == 40));
    let mut h2c = Recorder::new(0);
    let mut link = Link::station(0, 0, OWN, 2);
    assert_eq!(
        vif_init(&mut io, &mut h2c, &mut cam::Info::default(), &mut link),
        Err(Error::CmacOff { value: R32_DEAD })
    );
    assert!(h2c.sent.is_empty());
    assert_eq!(
        port::update(
            &mut io,
            &Port {
                port: 5,
                ..Port::default()
            }
        ),
        Err(port::Error::Port(5))
    );
}

#[test]
fn cmac_tables_set_their_masks_with_their_values() {
    let mut link = Link::station(3, 2, OWN, 2);
    let words = |table: [u8; CMC_TBL_LEN]| -> Vec<u32> {
        table
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect()
    };
    let table = words(default_cmac_tbl(&link, None));
    // MAC ID 3, operation; both TX paths with B mapped to path 1.
    assert_eq!(table[0], 0x83);
    assert_eq!(field(table[6], cmc::NTX_PATH_EN.1), RF_AB);
    assert_eq!(field(table[6], cmc::PATH_MAP_B.1), 1);
    assert_eq!(table[14] & cmc::NTX_PATH_EN.1, cmc::NTX_PATH_EN.1);
    // The CCK lowest rate on 2.4 GHz, port 2, uplink and downlink.
    link.bss.two_ghz = true;
    let table = words(assoc_cmac_tbl(&link, None));
    assert_eq!(field(table[2], cmc::RTS_RTY_LOWEST_RATE.1), HW_RATE_CCK1);
    assert_eq!(
        table[10] & cmc::RTS_RTY_LOWEST_RATE.1,
        cmc::RTS_RTY_LOWEST_RATE.1
    );
    assert_eq!(field(table[5], cmc::MULTI_PORT_ID.1), 2);
    assert_eq!(field(table[7], cmc::ULDL.1), 1);
    // No PPE thresholds: the nominal padding field for every bandwidth.
    let mut cap = HeCap::default();
    cap.phy_cap_info[9] = 0x80;
    assert_eq!(he_pkt_padding(&cap, 2, 2), [PE_DURATION_16; PPE_BW_NUM]);
    // MAC ID 37 is bit 5 of group 1.
    let pause = macid_pause(37 & 0x1f, 37 >> 5, true);
    assert_eq!(pause[4..8], [0x20, 0, 0, 0]);
    assert_eq!(pause[20..24], [0x20, 0, 0, 0]);
}
