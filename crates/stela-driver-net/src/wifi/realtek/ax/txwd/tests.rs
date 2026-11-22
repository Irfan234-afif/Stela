use super::*;

#[test]
fn a_firmware_command_body_names_ch12_and_the_commands_length() {
    // A 40-byte H2C (header and payload), no download part.
    let desc = DescInfo::fwcmd(40, false);
    assert_eq!(desc.ch_dma, DMA_H2C);
    assert_eq!(desc.dwords(), [12 << 16, 0, 40, 0, 0, 0]);
    let mut expected = [0u8; BODY_SIZE];
    expected[2] = 12;
    expected[8] = 40;
    assert_eq!(desc.body(), expected);

    // A 2020-byte download part sets FW_DL beside the channel.
    let desc = DescInfo::fwcmd(2020, true);
    let body = desc.body();
    assert_eq!(body[0..4], (BODY0_FW_DL | 12 << 16).to_le_bytes());
    assert_eq!(body[8..12], 2020u32.to_le_bytes());
    assert!(body[4..8].iter().chain(&body[12..]).all(|&byte| byte == 0));
}

#[test]
fn lengths_are_cut_as_rtw89_cuts_them() {
    // skb->len into the u16 member, then into TXPKT_SIZE's 14 bits.
    assert_eq!(DescInfo::fwcmd(0x3fff, false).body2(), 0x3fff);
    assert_eq!(DescInfo::fwcmd(0x4000, false).body2(), 0);
    assert_eq!(DescInfo::fwcmd(0x1_0007, false).pkt_size, 7);
    assert_eq!(DescInfo::fwcmd(0x1_0007, false).body2(), 7);
}

#[test]
fn every_body_field_lands_where_txrx_h_puts_it() {
    let desc = DescInfo {
        pkt_size: 0xffff,
        wp_offset: 0xab,
        mac_id: 0xff,
        qsel: 0xff,
        ch_dma: 0x1f,
        hdr_llc_len: 0xff,
        wd_page: true,
        tid_indicate: true,
        agg_en: true,
        bk: true,
        fw_dl: true,
        seq: 0xffff,
        hw_ssn_sel: 0xff,
        hw_seq_mode: 0xff,
    };
    assert_eq!(
        desc.body0(),
        0xab00_0000
            | BODY0_FW_DL
            | BODY0_CHANNEL_DMA
            | BODY0_HDR_LLC_LEN
            | BODY0_WD_PAGE
            | BODY0_HW_SSN_SEL
            | BODY0_HW_SSN_MODE
    );
    assert_eq!(desc.body0() & (BODY0_WD_INFO_EN | BODY0_MORE_DATA), 0);
    assert_eq!(
        desc.body2(),
        BODY2_MACID | BODY2_TID_INDICATE | BODY2_QSEL | BODY2_TXPKT_SIZE
    );
    assert_eq!(desc.body3(), BODY3_BK | BODY3_AGG_EN | BODY3_SW_SEQ);
    assert_eq!(DescInfo::default().dwords(), [0; 6]);
}
