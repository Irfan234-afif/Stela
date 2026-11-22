use super::*;
use crate::wifi::realtek::firmware::Rtw89;
use alloc::{vec, vec::Vec};

fn set(version: u32) -> Vec<Feature> {
    Features::of(version).iter().collect()
}

#[test]
fn a_version_code_is_major_minor_sub_and_index_from_the_top_byte() {
    assert_eq!(ver_code(0, 29, 29, 18), 0x001d_1d12);
    assert_eq!(ver_code(1, 2, 3, 4), 0x0102_0304);
}

#[test]
fn rtl8852b_rows_turn_features_on_by_version() {
    use Feature::*;
    // Before every `ge` row, only the `lt` one holds.
    assert_eq!(set(0), [NoWowCpuIoRx]);
    assert_eq!(set(ver_code(0, 29, 25, 255)), [NoWowCpuIoRx]);
    assert_eq!(set(ver_code(0, 29, 26, 0)), [NoLpsPg, TxWake, NoWowCpuIoRx]);
    assert_eq!(
        set(ver_code(0, 29, 28, 255)),
        [NoLpsPg, TxWake, NoWowCpuIoRx]
    );
    let at_29 = [
        NoLpsPg,
        TxWake,
        CrashTriggerType0,
        ScanOffload,
        NoWowCpuIoRx,
    ];
    assert_eq!(set(ver_code(0, 29, 29, 0)), at_29);
    assert_eq!(set(ver_code(0, 29, 29, 6)), at_29);
    let at_29_7 = [
        NoLpsPg,
        TxWake,
        CrashTriggerType0,
        ScanOffload,
        BeaconFilter,
        NoWowCpuIoRx,
    ];
    assert_eq!(set(ver_code(0, 29, 29, 7)), at_29_7);
    assert_eq!(set(ver_code(0, 29, 29, 14)), at_29_7);
    // The pinned firmware, 0.29.29.18, and everything up to 0.29.30.0.
    let pinned = [
        NoLpsPg,
        TxWake,
        CrashTriggerType0,
        ScanOffload,
        BeaconFilter,
        BeaconLossCountV1,
        NoWowCpuIoRx,
    ];
    for version in [
        ver_code(0, 29, 29, 15),
        ver_code(0, 29, 29, 18),
        ver_code(0, 29, 29, 255),
    ] {
        assert_eq!(set(version), pinned, "{version:#x}");
    }
    // NO_WOW_CPU_IO_RX is `lt` 0.29.30.0.
    let after_30 = [
        NoLpsPg,
        TxWake,
        CrashTriggerType0,
        ScanOffload,
        BeaconFilter,
        BeaconLossCountV1,
    ];
    assert_eq!(set(ver_code(0, 29, 30, 0)), after_30);
    assert_eq!(set(ver_code(0, 29, 126, 255)), after_30);
    let mut at_127 = after_30.to_vec();
    at_127.extend([LpsDackByC2hReg, SerL1ByEvent]);
    assert_eq!(set(ver_code(0, 29, 127, 0)), at_127);
    let mut at_128 = at_127.clone();
    at_128.extend([CrashTriggerType1, ScanOffloadExtraOp, BeaconTracking]);
    assert_eq!(set(ver_code(0, 29, 128, 0)), at_128);
    assert_eq!(set(ver_code(0, 29, 129, 0)), at_128);
    let mut all = at_128.clone();
    all.push(SimSerL0l1ByHaltH2c);
    assert_eq!(set(ver_code(0, 29, 130, 0)), all);
    assert_eq!(set(u32::MAX), all);
    assert!(!Features::of(u32::MAX).has(NoWowCpuIoRx));
    assert_eq!(Features::default().iter().count(), 0);
}

#[test]
fn an_images_features_follow_the_version_its_header_names() {
    // A legacy image: a header of version 0 with no section.
    let mut image = vec![0u8; 32];
    image[4..8].copy_from_slice(&[0, 29, 29, 18]);
    let parsed = Rtw89::parse(&image, 2).unwrap();
    assert_eq!(parsed.image.version, [0, 29, 29, 18]);
    let features = Features::of_image(&parsed.image);
    assert_eq!(features, Features::of(ver_code(0, 29, 29, 18)));
    assert_eq!(features.bits(), 0x7f);
    assert!(features.has(Feature::BeaconLossCountV1));
    assert!(!features.has(Feature::SerL1ByEvent));
}
