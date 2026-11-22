use super::*;

#[test]
fn the_layout_is_rtw8852bx_efuse_packed() {
    // struct rtw8852bx_tssi_offset: 6 CCK, 5 BW40, 7 reserved, 14 5 GHz.
    assert_eq!(BW40_TSSI, CCK_TSSI + TSSI_CCK_CH_GROUP_NUM);
    assert_eq!(BW40_1S_TSSI_5G, BW40_TSSI + TSSI_MCS_2G_CH_GROUP_NUM + 7);
    assert_eq!(TSSI_OFFSET_SIZE, BW40_1S_TSSI_5G + TSSI_MCS_5G_CH_GROUP_NUM);
    // rsvd[0x210], path A, rsvd1[10], path B, rsvd2[94], channel_plan, xtal_k.
    assert_eq!(PATH_B_TSSI, PATH_A_TSSI + TSSI_OFFSET_SIZE + 10);
    assert_eq!(XTAL_K, PATH_B_TSSI + TSSI_OFFSET_SIZE + 94 + 1);
    // xtal_k, rsvd3, iqk_lck, rsvd4[5], two bitfield bytes around rsvd5,
    // eeprom_version, customer_id, two BB swings, tx_cali_pwr_trk_mode,
    // trx_path_selection, rfe_type, country_code[2], rsvd7[3], the thermals.
    assert_eq!(RFE_TYPE, XTAL_K + 1 + 1 + 1 + 5 + 3 + 1 + 1 + 2 + 1 + 1);
    assert_eq!(COUNTRY_CODE, RFE_TYPE + 1);
    assert_eq!(PATH_A_THERM, COUNTRY_CODE + 2 + 3);
    assert_eq!(PATH_B_THERM, PATH_A_THERM + 1);
    assert_eq!(RX_GAIN_2G_OFDM, PATH_B_THERM + 1 + 2);
    for (later, earlier) in [
        (RX_GAIN_2G_CCK, RX_GAIN_2G_OFDM),
        (RX_GAIN_5G_LOW, RX_GAIN_2G_CCK),
        (RX_GAIN_5G_MID, RX_GAIN_5G_LOW),
        (RX_GAIN_5G_HIGH, RX_GAIN_5G_MID),
    ] {
        assert_eq!(later, earlier + 2);
    }
    // The PCIe address opens the union after 0x400 bytes; the USB one,
    // 0x88 bytes into it, ends the structure.
    assert_eq!(E_MAC_ADDR, 0x400);
    assert_eq!(SIZE, E_MAC_ADDR + 0x88 + 6);
    // The phycap addresses all fall in the 128 bytes from 0x580.
    let last = PHYCAP_ADDR + PHYCAP_SIZE as u32;
    for address in [PWR_K_CHK_OFFSET]
        .into_iter()
        .chain(THM_TRIM_ADDR)
        .chain(PABIAS_TRIM_ADDR)
        .chain(TSSI_TRIM_ADDR)
        .chain(TSSI_TRIM_ADDR.map(|first| first - 7))
        .chain(COMP_ADDRS.into_iter().flatten().filter(|&at| at != 0))
    {
        assert!((PHYCAP_ADDR..last).contains(&address), "{address:#x}");
    }
}

#[test]
fn decode_efuse_gain_sign_extends_each_nibble() {
    assert_eq!(decode_efuse_gain(0x12), (1, 2, true));
    assert_eq!(decode_efuse_gain(0xf1), (-1, 1, true));
    assert_eq!(decode_efuse_gain(0x8f), (-8, -1, true));
    assert_eq!(decode_efuse_gain(0x77), (7, 7, true));
    assert_eq!(decode_efuse_gain(0x00), (0, 0, true));
    assert_eq!(decode_efuse_gain(0xff), (-1, -1, false));
}

/// A logical map whose every byte holds its offset's low byte.
fn counting() -> [u8; FULL_LOG_SIZE] {
    let mut map = [0; FULL_LOG_SIZE];
    for (at, byte) in map.iter_mut().enumerate() {
        *byte = at as u8;
    }
    map
}

#[test]
fn read_efuse_takes_each_field_from_its_offset() {
    let map = counting();
    let mut efuse = Efuse::default();
    let mut tssi = Tssi::default();
    let mut gain = EfuseGain::default();
    read_efuse(&map, &mut efuse, &mut tssi, &mut gain);
    assert_eq!(
        efuse,
        Efuse {
            valid: false,
            power_k_valid: false,
            xtal_cap: 0xb9,
            addr: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
            rfe_type: 0xca,
            country_code: [0xcb, 0xcc],
        }
    );
    assert_eq!(tssi.thermal, [0xd0, 0xd1]);
    assert_eq!(tssi.tssi_cck[0], [0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
    assert_eq!(tssi.tssi_cck[1], [0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]);
    // BW40's five, then the 5 GHz fourteen after seven reserved bytes.
    let mcs_a: [i8; TSSI_MCS_CH_GROUP_NUM] = core::array::from_fn(|group| {
        let at = if group < 5 {
            0x216 + group
        } else {
            0x222 + group - 5
        };
        at as u8 as i8
    });
    assert_eq!(tssi.tssi_mcs[0], mcs_a);
    assert_eq!(tssi.tssi_mcs[1][0], 0x40);
    assert_eq!(tssi.tssi_mcs[1][18] as u8, 0x59);
    // 2G CCK 0xd6, 2G OFDM 0xd4, 5G low 0xd8, mid 0xda, high 0xdc.
    assert_eq!(gain.offset[0], [-3, -3, -3, -3, -3]);
    assert_eq!(gain.offset[1], [6, 4, -8, -6, -4]);
    assert!(gain.offset_valid);
    // The trims and compensations are the phycap's.
    assert_eq!(tssi.tssi_trim, [[0; 8]; 2]);
    assert!(!gain.comp_valid);
}

#[test]
fn read_phycap_zeroes_unprogrammed_tssi_trims_and_only_ever_sets_its_flags() {
    let mut map = [0xff; PHYCAP_SIZE];
    let mut efuse = Efuse {
        power_k_valid: true,
        ..Efuse::default()
    };
    let mut tssi = Tssi {
        tssi_trim: [[5; 8]; 2],
        ..Tssi::default()
    };
    let mut trim = PowerTrim {
        pg_thermal_trim: true,
        pg_pa_bias_trim: true,
        ..PowerTrim::default()
    };
    let mut gain = EfuseGain {
        comp: [[9; 5]; 2],
        comp_valid: true,
        ..EfuseGain::default()
    };
    read_phycap(&map, &mut efuse, &mut tssi, &mut trim, &mut gain);
    // A blank phycap clears nothing rtw89 only sets, zeroes the TSSI trims,
    // and gives blank compensations, the unused subband untouched.
    assert!(efuse.power_k_valid);
    assert_eq!(tssi.tssi_trim, [[0; 8]; 2]);
    assert!(trim.pg_thermal_trim && trim.pg_pa_bias_trim);
    assert_eq!(trim.thermal_trim, [0xff; 2]);
    assert_eq!(gain.comp, [[-1, -1, 9, -1, -1]; 2]);
    assert!(!gain.comp_valid);

    // One programmed TSSI trim keeps all sixteen as read.
    map[(0x5a4 - PHYCAP_ADDR) as usize] = 0x02;
    map[(PWR_K_CHK_OFFSET - PHYCAP_ADDR) as usize] = PWR_K_CHK_VALUE;
    map[(0x5dc - PHYCAP_ADDR) as usize] = 0x0c;
    map[(0x58d - PHYCAP_ADDR) as usize] = 0x0e;
    let mut efuse = Efuse::default();
    let mut tssi = Tssi::default();
    let mut trim = PowerTrim::default();
    let mut gain = EfuseGain::default();
    read_phycap(&map, &mut efuse, &mut tssi, &mut trim, &mut gain);
    assert!(efuse.power_k_valid);
    assert_eq!(tssi.tssi_trim[0], [-1; 8]);
    assert_eq!(tssi.tssi_trim[1], [-1, -1, -1, -1, -1, -1, -1, 2]);
    assert_eq!(
        trim,
        PowerTrim {
            pg_thermal_trim: true,
            pg_pa_bias_trim: false,
            thermal_trim: [0xff, 0x0c],
            pa_bias_trim: [0xff, 0xff],
        }
    );
    assert_eq!(gain.comp[1][4], -2);
    assert!(gain.comp_valid);
}
