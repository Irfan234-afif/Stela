//! The AP MLD links an association requests, as `ieee80211_mgd_assoc` and
//! `mt76_select_links` pick them.
use super::*;
use crate::wifi::station::tests::{beacon, join};

const AP_MLD: Mac = Mac([2, 9, 9, 9, 9, 9]);
const CHANNEL_1: Channel = Channel {
    band: Band::Ghz2,
    number: 1,
    frequency_mhz: 2412,
};
const CHANNEL_44: Channel = Channel {
    band: Band::Ghz5,
    number: 44,
    frequency_mhz: 5220,
};

/// The AP of link `link_id` of `mld` on `channel`, its RNR naming `reported`
/// APs of its own AP MLD: link ID, last BSSID byte and channel number each.
fn ap(link_id: u8, last: u8, channel: Channel, mld: Mac, reported: &[(u8, u8, u8)]) -> Bss {
    let mut elements = Basic {
        address: mld,
        link_id: Some(link_id),
        ..Basic::default()
    }
    .encode();
    for &(link_id, last, number) in reported {
        // One ieee80211_tbtt_info_ge_11 with MLD parameters, AP MLD ID 0.
        let mut rnr = vec![
            0x00, 16, 0, number, 0, 2, 0, 0, 0, 0, last, 0, 0, 0, 0, 0x40, 0, 0,
        ];
        rnr.extend_from_slice(&u16::from(link_id).to_le_bytes());
        elements.extend_from_slice(&[201, rnr.len() as u8]);
        elements.extend_from_slice(&rnr);
    }
    Bss {
        bssid: Mac([2, 0, 0, 0, 0, last]),
        channel,
        elements,
        ..beacon(&join(PortPolicy::Controlled))
    }
}

#[test]
fn an_ap_mld_names_itself_and_the_link_its_bss_is() {
    let setup = ap(0, 1, CHANNEL_44, AP_MLD, &[]);
    assert_eq!(ap_mld(&setup), Some((AP_MLD, 0)));
    let mut single = setup.clone();
    single.elements.clear();
    assert_eq!(ap_mld(&single), None);
}

/// mt76_select_links: the setup link and the first other link by ID on
/// another band, which the scan observed as a link of the same AP MLD.
#[test]
fn the_other_link_is_the_first_observed_on_another_band() {
    let setup = ap(
        0,
        1,
        CHANNEL_44,
        AP_MLD,
        &[(3, 3, 1), (2, 2, 1), (1, 4, 48)],
    );
    // Link 1 shares the setup link's band; link 3 comes after link 2.
    let same_band = ap(
        1,
        4,
        Channel {
            number: 48,
            frequency_mhz: 5240,
            ..CHANNEL_44
        },
        AP_MLD,
        &[],
    );
    let two = ap(2, 2, CHANNEL_1, AP_MLD, &[]);
    let three = ap(3, 3, CHANNEL_1, AP_MLD, &[]);
    let observed = [(10, &same_band), (30, &three), (20, &two)];
    let any = |_: &Bss| true;
    assert_eq!(
        other_link(&setup, AP_MLD, &observed, any).map(|(id, handle, _)| (id, handle)),
        Some((2, 20))
    );
    // A link the station may not use passes to the next.
    let not_two = |other: &Bss| other.bssid != two.bssid;
    assert_eq!(
        other_link(&setup, AP_MLD, &observed, not_two).map(|(id, handle, _)| (id, handle)),
        Some((3, 30))
    );
    // An AP the RNR names as another AP MLD's, or unobserved, is no link.
    let foreign = ap(2, 2, CHANNEL_1, Mac([2, 8, 8, 8, 8, 8]), &[]);
    assert!(other_link(&setup, AP_MLD, &[(20, &foreign)], any).is_none());
    assert!(other_link(&setup, AP_MLD, &[(10, &same_band)], any).is_none());
}

/// wpa_supplicant's `sm->mlo` link: the AP's whole RSN element and RSNXE.
#[test]
fn a_keyed_link_carries_its_aps_whole_rsn_element_and_rsnxe() {
    let mut bss = ap(1, 2, CHANNEL_1, AP_MLD, &[]);
    bss.elements = vec![48, 2, 1, 0, 244, 1, 0x20];
    let link = keyed_link(1, Mac([2, 0xa, 0, 0, 0, 1]), &bss);
    assert_eq!(
        (link.ap, link.rsn, link.rsnxe, link.accepted),
        (
            bss.bssid,
            vec![48, 2, 1, 0],
            Some(vec![244, 1, 0x20]),
            false
        )
    );
}

/// Drive the generic keeper over a vendor's owned model while the last
/// handshake reply is in flight. The caller observes the real native key and
/// supplies its descriptor/TX-free/IRQ/work retirement, rather than a counter
/// that pretends to be a drain.
pub(crate) fn assert_secondary_key_waits_for_retirement<R: Radio>(
    mut keeper: Keeper<R>,
    ptk: KeyIdentity,
    management: R::Management,
    key: IntegrityKey,
    retire: impl FnOnce(&mut R),
    mut has_key: impl FnMut(&mut R) -> bool,
) -> Keeper<R> {
    let supplicant = Supplicant::new(
        supplicant::Suites {
            akm: Akm::Psk,
            pairwise: crate::wifi::security::Cipher::Ccmp128,
            group: crate::wifi::security::Cipher::Ccmp128,
            management: Some(crate::wifi::security::management::ManagementCipher::Cmac128),
        },
        Zeroizing::new([0; 32]),
        keeper.link.mac(),
        AP_MLD,
        vec![],
        vec![],
    )
    .unwrap();
    keeper.state = State::Handshake {
        supplicant: Box::new(supplicant),
        bssid: AP_MLD,
        deadline: u64::MAX,
        mic_failed: false,
        ptk: Some(ptk),
        integrity: None,
        link_integrity: vec![(1, key)],
        management: Some(management),
    };
    keeper.complete().unwrap();
    assert!(
        matches!(&keeper.state, State::Handshake { link_integrity, .. } if link_integrity.len()==1)
    );
    assert!(!has_key(&mut keeper.link));
    assert!(!keeper.link.carrier());
    retire(&mut keeper.link);
    keeper.complete().unwrap();
    assert!(matches!(keeper.state, State::Connected { .. }));
    assert!(has_key(&mut keeper.link));
    assert!(keeper.link.carrier());
    keeper
}

const LOCAL: Mac = Mac([2, 0x12, 0x34, 0x56, 0x78, 0x9a]);
/// A mixed WPA/WPA2 AP's RSN element, TKIP its group cipher and CCMP and TKIP
/// its pairwise ones, then its WPA element.
const MIXED: [u8; 50] = [
    48, 24, 1, 0, 0, 0x0f, 0xac, 2, 2, 0, 0, 0x0f, 0xac, 4, 0, 0x0f, 0xac, 2, 1, 0, 0, 0x0f, 0xac,
    2, 0, 0, 221, 22, 0, 0x50, 0xf2, 1, 1, 0, 0, 0x50, 0xf2, 2, 1, 0, 0, 0x50, 0xf2, 2, 1, 0, 0,
    0x50, 0xf2, 2,
];

/// Each read all zeros.
struct Zeros;

impl Entropy for Zeros {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), stela_driver_base::entropy::EntropyError> {
        bytes.fill(0);
        Ok(())
    }
}

/// A radio whose scan hears its BSS at once, and that counts what the keeper
/// asks of it once it chose a BSS. `TKIP` is its [`Radio::TKIP_GROUP`].
struct Scripted<const TKIP: bool> {
    station: Station,
    bss: Vec<Bss>,
    scanned: bool,
    /// The advertisements asked for, which an association starts from.
    advertised: core::cell::Cell<usize>,
    /// The joins and SAE exchanges begun.
    joins: usize,
}

impl<const TKIP: bool> Scripted<TKIP> {
    /// A keeper of the network `test` over a radio that hears `bss`.
    fn hearing(bss: Bss) -> Keeper<Self> {
        core::mem::forget(crate::test_clock::virtualize());
        let radio = Self {
            station: Station::new(LOCAL).unwrap(),
            bss: vec![bss],
            scanned: false,
            advertised: core::cell::Cell::new(0),
            joins: 0,
        };
        let network = Network {
            ssid: b"test".to_vec(),
            secret: Secret::Psk(Zeroizing::new([0; 32])),
            country: None,
        };
        let clock = Clock {
            ticks_per_microsecond: 1,
        };
        Keeper::keep(radio, network, Arc::new(Zeros), clock)
    }
}

impl<const TKIP: bool> Link for Scripted<TKIP> {
    fn mac(&self) -> Mac {
        LOCAL
    }
    fn carrier(&mut self) -> bool {
        false
    }
    fn transmit(&mut self, _: &[u8]) -> Result<(), LinkError> {
        Err(LinkError::NoCarrier)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        Ok(None)
    }
}

impl<const TKIP: bool> Radio for Scripted<TKIP> {
    type Handle = usize;
    type Profile = ();
    type Management = ();
    type Error = &'static str;

    const NAME: &'static str = "scripted";
    const LISTEN_INTERVAL: u16 = 5;
    const TKIP_GROUP: bool = TKIP;

    fn deferred(_: &&'static str) -> bool {
        false
    }
    fn service(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    fn take_event(&mut self) -> Option<Event> {
        None
    }
    fn stage(&self) -> Stage {
        if self.scanned {
            Stage::Scanned
        } else {
            Stage::Idle
        }
    }
    fn station(&self) -> &Station {
        &self.station
    }
    fn channels(&self, band: Band) -> Vec<(Channel, u32)> {
        if band == Band::Ghz2 {
            vec![(CHANNEL_1, 0)]
        } else {
            Vec::new()
        }
    }
    fn probes(&self, _: Channel) -> bool {
        true
    }
    fn supported_channels(&self, _: Band) -> &'static [u8] {
        &[]
    }
    fn regulated_power_dbm(&self, _: u16) -> i32 {
        20
    }
    fn advertisement(&self, _: Band) -> Result<Advertisement, &'static str> {
        self.advertised.set(self.advertised.get() + 1);
        Err("no advertisement")
    }
    fn profile(&self, _: Peer) -> Result<(), &'static str> {
        Ok(())
    }
    fn begin_scan(&mut self, _: scan::Request, _: u64) -> Result<(), &'static str> {
        self.scanned = true;
        Ok(())
    }
    unsafe fn retire_scan(&mut self) -> Result<(), &'static str> {
        self.scanned = false;
        Ok(())
    }
    fn six_ghz_scan(
        &self,
        _: &scan::Request,
        _: scan::six_ghz::Options,
    ) -> Result<Option<scan::Request>, &'static str> {
        Ok(None)
    }
    fn bss(&self) -> Vec<(usize, &Bss)> {
        self.bss.iter().enumerate().collect()
    }
    fn observation(&self, _: usize) -> Result<Arc<NativeBssObservation>, &'static str> {
        Err("no observation")
    }
    fn join(&mut self, _: usize, _: Join, _: ()) -> Result<(), &'static str> {
        self.joins += 1;
        Ok(())
    }
    fn begin_external_authentication(
        &mut self,
        _: usize,
        _: (),
        _: Option<Affiliation>,
        _: u64,
    ) -> Result<Arc<external::Session>, &'static str> {
        self.joins += 1;
        Err("no SAE")
    }
    fn begin_six_ghz_external_authentication(
        &mut self,
        _: usize,
        _: Selection,
        _: (),
        _: Option<Affiliation>,
        _: u64,
    ) -> Result<Arc<external::Session>, &'static str> {
        self.joins += 1;
        Err("no SAE")
    }
    fn transmit_external_authentication(
        &mut self,
        _: &external::Session,
        _: external::Frame<'_>,
    ) -> Result<(), &'static str> {
        Err("no SAE")
    }
    fn associate_external(
        &mut self,
        _: &external::Session,
        _: usize,
        _: Join,
    ) -> Result<(), &'static str> {
        Err("no SAE")
    }
    fn configure(&mut self) -> Result<(), &'static str> {
        Err("no association")
    }
    fn send_control(&mut self, _: &[u8], _: Option<KeyIdentity>) -> Result<(), &'static str> {
        Err("no association")
    }
    fn install_key(
        &mut self,
        _: bool,
        _: u8,
        _: &[u8],
        _: ReplaySeed,
    ) -> Result<KeyIdentity, &'static str> {
        Err("no association")
    }
    fn install_link_key(
        &mut self,
        _: u8,
        _: u8,
        _: &[u8],
        _: ReplaySeed,
    ) -> Result<(), &'static str> {
        Err("no association")
    }
    unsafe fn install_management_key(
        &mut self,
        _: u64,
        _: u8,
        _: &[u8],
        _: PacketNumber,
    ) -> Result<(), &'static str> {
        Err("no association")
    }
    unsafe fn rotate_management_key(
        &mut self,
        _: &(),
        _: u8,
        _: &[u8],
        _: PacketNumber,
    ) -> Result<(), &'static str> {
        Err("no association")
    }
    fn authorize_port(&mut self, _: u64) -> Result<(), &'static str> {
        Err("no association")
    }
    fn deauthenticate(&mut self, _: u16) -> Result<(), &'static str> {
        Ok(())
    }
    unsafe fn retire_peer(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
}

/// The mixed WPA/WPA2 AP of the network `test`, heard on channel 1.
fn mixed() -> Bss {
    Bss {
        bssid: Mac([2, 0, 0, 0, 0, 1]),
        channel: CHANNEL_1,
        ssid: Some(b"test".to_vec()),
        signal_dbm: Some(-40),
        elements: MIXED.to_vec(),
        ..beacon(&join(PortPolicy::Controlled))
    }
}

/// The failure the keeper reports once its first scan has run.
fn first_failure<R: Radio>(keeper: &mut Keeper<R>) -> String {
    for _ in 0..4 {
        if let Err(LinkError::Adapter(failure)) = keeper.receive() {
            return failure;
        }
    }
    panic!("no failure reported");
}

#[test]
fn a_radio_without_tkip_group_keys_refuses_a_mixed_network_before_it_authenticates() {
    let mut keeper = Scripted::<false>::hearing(mixed());
    assert_eq!(
        first_failure(&mut keeper),
        "scripted: test offers only a TKIP group cipher, which scripted leaves to software"
    );
    assert_eq!(keeper.link.advertised.get(), 0);
    assert_eq!(keeper.link.joins, 0);
}

#[test]
fn a_radio_with_tkip_group_keys_goes_on_to_join_a_mixed_network() {
    let mut keeper = Scripted::<true>::hearing(mixed());
    assert_eq!(first_failure(&mut keeper), "no advertisement");
    assert_eq!(keeper.link.advertised.get(), 1);
}
