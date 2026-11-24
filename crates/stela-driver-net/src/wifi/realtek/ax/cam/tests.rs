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

#[test]
fn ccmp_keys_take_rtw89_s_slots_and_tkip_and_the_igtk_stay_out() {
    let (mut io, mut h2c, mut cams, mut link, peer) = joined();
    let ptk = [0x11; 16];
    let pairwise = Key {
        cipher: Cipher::Ccmp128,
        pairwise: true,
        keyidx: 0,
        material: &ptk,
    };
    let entry = write_key(
        &mut io,
        &mut h2c,
        &mut cams,
        &mut link,
        Some(&peer),
        &pairwise,
    )
    .unwrap();
    assert_eq!(entry, 0);
    // The security CAM H2C asks REC_ACK and carries the key as it is;
    // then the address CAM names the entry in slot 0.
    assert_eq!(
        h2c.functions(),
        [
            (H2C_CL_MAC_SEC_CAM, H2C_FUNC_MAC_SEC_UPD),
            (H2C_CL_MAC_ADDR_CAM_UPDATE, H2C_FUNC_MAC_ADDR_CAM_UPD),
        ]
    );
    let (header, cmd) = &h2c.sent[0];
    assert!(header.rec_ack() && !header.done_ack());
    assert_eq!(word(cmd, 0), u32::from(SEC_CAM_LEN) << 16);
    assert_eq!(word(cmd, 1), SEC_KEY_TYPE_CCMP128.into());
    assert_eq!(cmd[8..24], ptk);
    assert_eq!(
        field(word(&h2c.sent[1].1, 10), ADDR_CAM_W10_SEC_ENT_VALID),
        1
    );

    // A group key in slot 2, its key ID beside it.
    let gtk = [0x22; 16];
    let group = Key {
        cipher: Cipher::Ccmp128,
        pairwise: false,
        keyidx: 1,
        material: &gtk,
    };
    let group_entry = write_key(&mut io, &mut h2c, &mut cams, &mut link, None, &group).unwrap();
    assert_eq!(group_entry, 1);
    assert_eq!(link.addr_cam.sec_cam_map, 0b101);
    assert_eq!(link.addr_cam.sec_ent[2], 1);
    assert_eq!(link.addr_cam.sec_ent_keyid[2], 1);
    assert_eq!(cams.find_key(false, 1), Some(1));
    assert_eq!(cams.find_key(true, 0), Some(0));

    // TKIP, the IGTK and a short key are refused without an H2C or an
    // entry.
    h2c.sent.clear();
    let tkip = [0x33; 32];
    for (cipher, material) in [
        (Cipher::Tkip, &tkip[..]),
        (Cipher::AesCmac, &gtk[..]),
        (Cipher::Other, &gtk[..]),
        (Cipher::Ccmp128, &gtk[..15]),
    ] {
        let refused = Key {
            cipher,
            pairwise: false,
            keyidx: 2,
            material,
        };
        let result = write_key(&mut io, &mut h2c, &mut cams, &mut link, None, &refused);
        assert!(
            matches!(result, Err(Error::Unsupported(_) | Error::Invalid(_))),
            "{cipher:?}: {result:?}"
        );
    }
    assert!(h2c.sent.is_empty());
    assert_eq!(cams.sec_cam_map, 0b11);

    // Clearing the group key frees its slot and its entry.
    clear_key(&mut io, &mut h2c, &mut cams, &mut link, None, group_entry).unwrap();
    assert_eq!(link.addr_cam.sec_cam_map, 0b1);
    assert_eq!(cams.sec_cam_map, 0b1);
    assert_eq!(cams.find_key(false, 1), None);
    assert_eq!(
        clear_key(&mut io, &mut h2c, &mut cams, &mut link, None, group_entry),
        Err(Error::Invalid("security CAM entry"))
    );
}

#[test]
fn key_slots_fill_as_rtw89_s_normal_mode_fills_them() {
    let mut addr_cam = AddrCamEntry {
        sec_ent_mode: ADDR_CAM_SEC_NORMAL,
        ..AddrCamEntry::default()
    };
    let ccmp = SEC_KEY_TYPE_CCMP128;
    assert_eq!(addr_cam_key_idx(&addr_cam, ccmp, true), Ok(0));
    addr_cam.sec_cam_map = 0b11;
    assert_eq!(
        addr_cam_key_idx(&addr_cam, ccmp, true),
        Err(Error::CamFull("address CAM key slots"))
    );
    assert_eq!(addr_cam_key_idx(&addr_cam, ccmp, false), Ok(2));
    addr_cam.sec_cam_map = 0b1_1111;
    assert!(addr_cam_key_idx(&addr_cam, ccmp, false).is_err());
    assert_eq!(
        addr_cam_key_idx(&addr_cam, SEC_KEY_TYPE_BIP_CCMP128, false),
        Ok(5)
    );
    addr_cam.sec_ent_mode = ADDR_CAM_SEC_4GROUP;
    assert_eq!(addr_cam_key_idx(&addr_cam, ccmp, false), Ok(5));
    assert_eq!(
        addr_cam_key_idx(&addr_cam, SEC_KEY_TYPE_BIP_CCMP128, false),
        Ok(6)
    );
    addr_cam.sec_ent_mode = ADDR_CAM_SEC_NONE;
    assert!(addr_cam_key_idx(&addr_cam, ccmp, true).is_err());
}
