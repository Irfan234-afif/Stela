use super::*;
use crate::wifi::realtek::ax::{
    h2c::station::{
        self, Bss,
        tests::{AP, Model, OWN, Recorder},
    },
    io::field,
    registers::{CMAC_EN, CMAC_FUNC_EN},
};

fn word(payload: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(payload[4 * index..4 * index + 4].try_into().unwrap())
}

/// A station link up, its BSSID set and joined to `AP` as AID 0x1003.
fn joined() -> (Model, Recorder, Info, Link, Peer) {
    let mut io = Model::new(0);
    io.set(CMAC_FUNC_EN, 4, CMAC_EN);
    let mut h2c = Recorder::new(0);
    let mut cams = Info::default();
    let mut link = Link::station(0, 0, OWN, 2);
    station::vif_init(&mut io, &mut h2c, &mut cams, &mut link).unwrap();
    station::bssid_changed(&mut io, &mut h2c, &mut link, AP).unwrap();
    link.bss = Bss {
        aid: 0x1003,
        beacon_int: 100,
        dtim_period: 1,
        bss_color: 0x2b,
        he_support: true,
        two_ghz: false,
    };
    let peer = Peer {
        addr: AP,
        rx_nss: 2,
        he: None,
    };
    station::sta_assoc(&mut io, &mut h2c, &mut link, &peer).unwrap();
    h2c.sent.clear();
    (io, h2c, cams, link, peer)
}

#[test]
fn a_joined_station_s_address_cam_entry_is_rtw89_s() {
    let (_, _, cams, link, peer) = joined();
    // The first address and BSSID entries: long, valid, normal key mode.
    assert_eq!((cams.addr_cam_map, cams.bssid_cam_map), (1, 1));
    let h2c = addr_cam(&link, Some(&peer), None);
    assert_eq!(word(&h2c, 0), 0);
    assert_eq!(field(word(&h2c, 1), ADDR_CAM_W1_IDX), 0);
    assert_eq!(
        field(word(&h2c, 1), ADDR_CAM_W1_LEN),
        ADDR_CAM_ENT_SIZE.into()
    );
    let w2 = word(&h2c, 2);
    assert_eq!(w2 & ADDR_CAM_W2_VALID, ADDR_CAM_W2_VALID);
    assert_eq!(field(w2, ADDR_CAM_W2_NET_TYPE), 2, "infrastructure");
    assert_eq!(
        field(w2, ADDR_CAM_W2_SMA_HASH),
        OWN.iter().fold(0, |hash, byte| hash ^ u32::from(*byte))
    );
    assert_eq!(
        field(w2, ADDR_CAM_W2_TMA_HASH),
        AP.iter().fold(0, |hash, byte| hash ^ u32::from(*byte))
    );
    // Sender then transmitter, byte by byte.
    let mut addresses = h2c[16..28].to_vec();
    addresses.truncate(12);
    assert_eq!(addresses[..6], OWN);
    assert_eq!(addresses[6..], AP);
    // MAC ID 0 on port 0, triggered by the HE BSS; the AID cut to 12 bits.
    let w8 = word(&h2c, 8);
    assert_eq!(field(w8, ADDR_CAM_W8_MACID), 0);
    assert_eq!(w8 & ADDR_CAM_W8_TF_TRS, ADDR_CAM_W8_TF_TRS);
    let w9 = word(&h2c, 9);
    assert_eq!(field(w9, ADDR_CAM_W9_AID12), 0x003);
    assert_eq!(
        field(w9, ADDR_CAM_W9_SEC_ENT_MODE),
        ADDR_CAM_SEC_NORMAL.into()
    );
    assert_eq!(word(&h2c, 10), 0, "no keys");
    // BSSID entry 0, 8 bytes, valid, matched whole, color 0x2b, the BSSID.
    assert_eq!(field(word(&h2c, 12), ADDR_CAM_W12_BSSID_LEN), 8);
    let w13 = word(&h2c, 13);
    assert_eq!(w13 & ADDR_CAM_W13_BSSID_VALID, 1);
    assert_eq!(field(w13, ADDR_CAM_W13_BSSID_MASK), BSSID_MATCH_ALL);
    assert_eq!(field(w13, ADDR_CAM_W13_BSSID_BSS_COLOR), 0x2b);
    assert_eq!(h2c[54..60], AP);
}
