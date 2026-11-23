extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    c2h::RX_TYPE_PPDU_STAT,
    io::{self, CR_BASE, field},
    pci::tests::segment,
    registers::{
        WLAN_XTAL_SI_CTRL, XTAL_SI_ADDR_MASK, XTAL_SI_BITMASK_MASK, XTAL_SI_CMD_POLL,
        XTAL_SI_DATA_MASK, XTAL_SI_MODE_MASK, XTAL_SI_NORMAL_READ, XTAL_SI_NORMAL_WRITE,
    },
    rxdesc::{self, HW_RATE_OFDM6, PhyPpdu, RxDescInfo},
};
use alloc::vec::Vec;

const BAR: usize = 0x2_0000;

/// The C oracle's register model: BAR2 as little-endian bytes, byte i
/// holding i * 37 + 11, behaving per aligned word; WLAN_XTAL_SI_CTRL
/// written with its poll bit answers a read with the XTAL SI register in
/// its data field or applies a write under its mask, then clears the poll
/// bit, unless XTAL SI is stuck. XTAL SI register i starts at i * 29 + 0x47.
/// Reads are logged by width, writes by 4 plus width, delays 9.
struct Model {
    memory: Vec<u8>,
    xtal: [u8; 256],
    xtal_stuck: bool,
    log: Vec<[u32; 3]>,
    /// The XTAL SI requests written while stuck, each one rtw89 warns of.
    unanswered: Vec<u32>,
    /// A register the model refuses.
    refuse: Option<u32>,
}

impl Model {
    fn new(xtal_stuck: bool) -> Self {
        Self {
            memory: (0..BAR).map(|i| (i * 37 + 11) as u8).collect(),
            xtal: core::array::from_fn(|i| (i * 29 + 0x47) as u8),
            xtal_stuck,
            log: Vec::new(),
            unanswered: Vec::new(),
            refuse: None,
        }
    }

    fn get(&self, register: u32, width: u32) -> u32 {
        (0..width).fold(0, |v, i| {
            v | u32::from(self.memory[(register + i) as usize]) << (8 * i)
        })
    }

    fn set(&mut self, register: u32, width: u32, value: u32) {
        for i in 0..width {
            self.memory[(register + i) as usize] = (value >> (8 * i)) as u8;
        }
    }

    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push([tag, a, b]);
    }

    fn access(&self, register: u32, width: u32) -> Result<(), io::Error> {
        assert!(register as usize + width as usize <= BAR && register.is_multiple_of(width));
        if self.refuse == Some(register) {
            return Err(io::Error::Register { register });
        }
        Ok(())
    }

    fn read(&mut self, register: u32, width: u32) -> Result<u32, io::Error> {
        self.access(register, width)?;
        let mut value = self.get(register & !3, 4) >> ((register & 3) * 8);
        if width < 4 {
            value &= (1 << (8 * width)) - 1;
        }
        self.mark(width, register, value);
        Ok(value)
    }

    fn write(&mut self, register: u32, width: u32, value: u32) -> Result<(), io::Error> {
        self.access(register, width)?;
        self.mark(4 + width, register, value);
        self.set(register, width, value);
        let word = register & !3;
        let mut s = self.get(word, 4);
        if word == WLAN_XTAL_SI_CTRL && s & XTAL_SI_CMD_POLL != 0 {
            if self.xtal_stuck {
                self.unanswered.push(s);
                return Ok(());
            }
            let offset = field(s, XTAL_SI_ADDR_MASK) as usize;
            match field(s, XTAL_SI_MODE_MASK) {
                XTAL_SI_NORMAL_READ => {
                    s = (s & !XTAL_SI_DATA_MASK) | u32::from(self.xtal[offset]) << 8;
                }
                XTAL_SI_NORMAL_WRITE => {
                    let mask = field(s, XTAL_SI_BITMASK_MASK) as u8;
                    let data = field(s, XTAL_SI_DATA_MASK) as u8;
                    self.xtal[offset] = (self.xtal[offset] & !mask) | (data & mask);
                }
                _ => {}
            }
            self.set(word, 4, s & !XTAL_SI_CMD_POLL);
        }
        Ok(())
    }

    /// The step's warnings, as the oracle flushes them: each XTAL SI request
    /// left unanswered, by its mode (1 read, 2 write).
    fn flush(&mut self) {
        for request in core::mem::take(&mut self.unanswered) {
            let read = field(request, XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_READ;
            self.mark(70, if read { 1 } else { 2 }, 0);
        }
    }

    fn phy(&self, register: u32) -> u32 {
        self.get(CR_BASE + register, 4)
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware, and delays
// are counted, not waited.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        self.read(register, 1).map(|v| v as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        self.read(register, 2).map(|v| v as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        self.read(register, 4)
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), io::Error> {
        self.write(register, 1, value.into())
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), io::Error> {
        self.write(register, 2, value.into())
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.write(register, 4, value)
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.mark(9, 0, microseconds as u32);
    }
}

const fn channel(band: u32, width: u32) -> Channel {
    Channel {
        band: if band == 0 { Band::Ghz2 } else { Band::Ghz5 },
        width: match width {
            0 => Bandwidth::Mhz20,
            1 => Bandwidth::Mhz40,
            _ => Bandwidth::Mhz80,
        },
        number: 0,
    }
}

/// The oracle's state records: the environment monitor (90 to 97), DIG
/// (100 to 104) and CFO (110 to 115).
fn push_state(io: &mut Model, d: &Dynamic) {
    let (e, g, c) = (&d.env, &d.dig, &d.cfo);
    let b = |v: bool| u32::from(v);
    io.mark(
        90,
        u32::from(e.ccx_watchdog_result)
            | b(e.ccx_ongoing) << 8
            | u32::from(e.ccx_rac_lv) << 16
            | u32::from(e.ccx_unit_idx) << 24,
        u32::from(e.ifs_clm_mntr_time) | u32::from(e.ccx_period) << 16,
    );
    io.mark(
        91,
        u32::from(e.ifs_clm_app)
            | u32::from(e.edcca_clm_ratio) << 8
            | u32::from(e.ifs_clm_tx_ratio) << 16
            | u32::from(e.ifs_clm_edcca_excl_cca_ratio) << 24,
        u32::from(e.ifs_clm_cck_fa_ratio)
            | u32::from(e.ifs_clm_ofdm_fa_ratio) << 8
            | u32::from(e.ifs_clm_cck_cca_excl_fa_ratio) << 16
            | u32::from(e.ifs_clm_ofdm_cca_excl_fa_ratio) << 24,
    );
    io.mark(
        92,
        u32::from(e.ifs_clm_cck_fa_permil) | u32::from(e.ifs_clm_ofdm_fa_permil) << 16,
        u32::from(e.ifs_clm_total_ifs) | u32::from(e.ifs_clm_tx) << 16,
    );
    io.mark(
        93,
        u32::from(e.ifs_clm_cckfa) | u32::from(e.ifs_clm_ofdmfa) << 16,
        u32::from(e.ifs_clm_cckcca_excl_fa) | u32::from(e.ifs_clm_ofdmcca_excl_fa) << 16,
    );
    io.mark(94, e.ifs_clm_edcca_excl_cca.into(), 0);
    for i in 0..IFS_CLM_NUM {
        io.mark(
            95,
            i as u32 | u32::from(e.ifs_clm_th_l[i]) << 16,
            u32::from(e.ifs_clm_th_h[i]) | u32::from(e.ifs_clm_his[i]) << 16,
        );
        io.mark(
            96,
            u32::from(e.ifs_clm_avg[i]) | u32::from(e.ifs_clm_cca[i]) << 16,
            e.ifs_clm_ifs_avg[i],
        );
        io.mark(97, i as u32, e.ifs_clm_cca_avg[i]);
    }
    io.mark(
        100,
        u32::from(g.igi_rssi)
            | u32::from(g.igi_fa_rssi) << 8
            | u32::from(g.fa_rssi_ofst) << 16
            | u32::from(g.dyn_igi_max) << 24,
        u32::from(g.dyn_igi_min)
            | u32::from(g.dyn_pd_th_max) << 8
            | u32::from(g.dyn_pd_max_cnt) << 16
            | u32::from(g.pd_low_th_ofst) << 24,
    );
    io.mark(
        101,
        u32::from(g.noisy_lv as u8)
            | b(g.dyn_pd_th_en) << 8
            | b(g.is_linked_pre) << 9
            | b(g.bypass_dig) << 10
            | b(g.pause_dig) << 11,
        g.bak_dig,
    );
    io.mark(
        102,
        u32::from(g.fa_th[0]) | u32::from(g.fa_th[1]) << 16,
        u32::from(g.fa_th[2]) | u32::from(g.fa_th[3]) << 16,
    );
    io.mark(
        103,
        u32::from_le_bytes([
            g.igi_rssi_th[0],
            g.igi_rssi_th[1],
            g.igi_rssi_th[2],
            g.igi_rssi_th[3],
        ]),
        g.igi_rssi_th[4].into(),
    );
    // diag_bb_bitmap's RTW89_DIAG_BB_PD is bit 1.
    io.mark(104, b(g.diag_pd) << 1, g.diag_pd_cnt);
    io.mark(
        110,
        u32::from(c.cfo_timer_ms)
            | b(c.cfo_trig_by_timer_en) << 16
            | u32::from(c.phy_cfo_status) << 20
            | b(c.is_adjust) << 24
            | b(c.divergence_lock_en) << 25,
        u32::from(c.phy_cfo_trk_cnt)
            | u32::from(c.crystal_cap) << 8
            | u32::from(c.crystal_cap_default) << 16
            | u32::from(c.def_x_cap) << 24,
    );
    io.mark(
        111,
        u32::from(c.x_cap_ofst as u8)
            | u32::from(c.x_cap_lb) << 8
            | u32::from(c.x_cap_ub) << 16
            | u32::from(c.lock_cnt) << 24,
        c.packet_count,
    );
    io.mark(112, c.cfo_avg_pre as u32, c.dcfo_avg as u32);
    io.mark(113, c.dcfo_avg_pre as u32, c.packet_count_pre);
    for i in 0..CFO_TRACK_MAX_USER {
        if c.cfo_tail[i] == 0 && c.cfo_cnt[i] == 0 && c.cfo_avg[i] == 0 && c.pre_cfo_avg[i] == 0 {
            continue;
        }
        io.mark(
            114,
            i as u32 | u32::from(c.cfo_cnt[i]) << 16,
            c.cfo_tail[i] as u32,
        );
        io.mark(115, c.cfo_avg[i] as u32, c.pre_cfo_avg[i] as u32);
    }
}

fn records(segment: &[u8]) -> Vec<[u32; 3]> {
    segment
        .chunks(12)
        .map(|r| {
            core::array::from_fn(|i| u32::from_le_bytes(r[4 * i..4 * i + 4].try_into().unwrap()))
        })
        .collect()
}

fn encode(log: &[[u32; 3]]) -> Vec<u8> {
    log.iter().flatten().flat_map(|w| w.to_le_bytes()).collect()
}

/// One case as the Rust side runs it, from the inputs the C segment
/// records: its header (58) and each step's (60 to 64).
fn replay(c: &[[u32; 3]]) -> Vec<[u32; 3]> {
    let [tag, h0, h1] = c[0];
    assert_eq!(tag, 58);
    let (cv, cap, band, width) = (h0 as u8, (h0 >> 8) as u8, h0 >> 16 & 0xff, h0 >> 24);
    let (monitor, stuck) = (h1 & 0xff != 0, h1 >> 8 & 0xff != 0);
    let mut io = Model::new(stuck);
    io.mark(58, h0, h1);
    io.mark(50, 0, 0);
    let mut d = Dynamic::init(&mut io, cv, cap, channel(band, width), monitor).unwrap();
    io.flush();
    push_state(&mut io, &d);
    let mut queued = false;
    let mut at = 1;
    while at < c.len() {
        if c[at][0] != 60 {
            at += 1;
            continue;
        }
        let [_, n, s0] = c[at];
        let [_, tx, rx] = c[at + 1];
        let [_, tf, s2] = c[at + 2];
        io.mark(60, n, s0);
        io.mark(61, tx, rx);
        io.mark(62, tf, s2);
        at += 3;
        while c[at][0] == 63 {
            let [_, register, value] = c[at];
            io.set(CR_BASE + register, 4, value);
            io.mark(63, register, value);
            at += 1;
        }
        let mut cfos = Vec::new();
        while c[at][0] == 64 {
            let [_, mac_id, cfo] = c[at];
            cfos.push((mac_id as u8, cfo as u16 as i16));
            io.mark(64, mac_id, cfo);
            at += 1;
        }
        assert_eq!(cfos.len(), (s2 >> 16) as usize);
        let link = Link {
            stations: s0 as u8,
            rssi_min: (s0 >> 8) as u8,
        };
        let channel = channel(s0 >> 16 & 0xff, s0 >> 24);
        let traffic = Traffic {
            tx_throughput: tx,
            rx_throughput: rx,
            rx_tf_periodic: tf,
        };
        let (fires, event) = (s2 & 0xff, s2 >> 8 & 0xff);
        if event != 0 {
            io.mark(50, 10, event);
            match event {
                1 => d.dig_suspend(&mut io).unwrap(),
                2 => d.dig_resume(&mut io, link, false).unwrap(),
                3 => d.dig_resume(&mut io, link, true).unwrap(),
                _ => d.scan_complete(),
            }
            io.flush();
        }
        io.mark(50, 11, 0);
        for (mac_id, cfo) in cfos {
            if !d.cfo_parse(cfo, mac_id) {
                io.mark(70, 0, 0);
            }
        }
        io.mark(50, 1, 0);
        d.env_monitor_track(&mut io).unwrap();
        io.flush();
        io.mark(50, 2, 0);
        d.dig(&mut io, link, channel).unwrap();
        io.flush();
        io.mark(50, 3, 0);
        if let Some(ms) = d.cfo_track(&mut io, link, traffic).unwrap() {
            io.mark(80, ms.into(), 0);
            queued = true;
        }
        io.flush();
        for f in 0..fires {
            if !queued {
                continue;
            }
            queued = false;
            io.mark(50, 4, f);
            let next = d
                .cfo_track_work(&mut io, link, traffic, |io| {
                    io.mark(81, 0, 0);
                    Ok(())
                })
                .unwrap();
            if let Some(ms) = next {
                io.mark(80, ms.into(), 0);
                queued = true;
            }
            io.flush();
        }
        push_state(&mut io, &d);
    }
    io.log
}

#[test]
#[ignore = "oracle: STELA_RTW89_PHY_ORACLE"]
fn dig_and_cfo_tracking_match_unchanged_c_for_each_scripted_period() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_PHY_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("dig_cfo_trace.bin")).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < trace.len() {
        let got = records(segment(&trace, &mut offset));
        let expected = replay(&got);
        if got != expected {
            let first = got.iter().zip(&expected).position(|(c, rust)| c != rust);
            panic!(
                "case {cases}: {} records from C, {} from Rust; first difference at {first:?}: \
                 C {:x?}, Rust {:x?}",
                got.len(),
                expected.len(),
                first.and_then(|at| got.get(at)),
                first.and_then(|at| expected.get(at)),
            );
        }
        assert_eq!(encode(&got), encode(&expected));
        cases += 1;
    }
    assert_eq!(offset, trace.len());
    assert_eq!(cases, 8);
}

const LINKED: Link = Link {
    stations: 1,
    rssi_min: 120,
};
const G20: Channel = channel(0, 0);

/// The register model after `Dynamic::init` on cut CBV, crystal cap 0x3c.
fn started() -> (Model, Dynamic) {
    let mut io = Model::new(false);
    let d = Dynamic::init(&mut io, 1, 0x3c, G20, false).unwrap();
    io.log.clear();
    (io, d)
}

/// Report words putting `cck` and `ofdm` false alarms in the window just
/// read, the report ready.
fn report(io: &mut Model, cck: u16, ofdm: u16) {
    io.set(CR_BASE + IFSCNT, 4, IFSCNT_DONE_MSK);
    io.set(
        CR_BASE + IFS_CLM_FA,
        4,
        u32::from(ofdm) << 16 | u32::from(cck),
    );
}

#[test]
fn ewma_takes_the_first_value_whole_then_weighs_each_new_one() {
    let mut rssi = RssiAverage::new();
    assert_eq!(rssi.read(), 0);
    rssi.add(100);
    assert_eq!(rssi.read(), 100);
    // ((100 << 10) * 15 + 0) >> 4, read back without its 10 fraction bits.
    rssi.add(0);
    assert_eq!(rssi.read(), 93);
    let mut thermal = Ewma::<4, 4>::new();
    thermal.add(40);
    thermal.add(44);
    // ((40 << 4) * 3 + (44 << 4)) >> 2 = 656, 41 whole.
    assert_eq!(thermal.read(), 41);
}

#[test]
fn physts_bitmaps_give_ie01_to_cck_and_trigger_based_packets_past_the_reserved_page() {
    let mut io = Model::new(false);
    for page in 0..16 {
        io.set(
            CR_BASE + PHY_STS_BITMAP_ADDR_START + 4 * page,
            4,
            0x0000_00f0,
        );
    }
    physts_parsing_init(&mut io, false).unwrap();
    let bitmap = |io: &Model, page: u32| io.phy(PHY_STS_BITMAP_ADDR_START + 4 * page);
    // HE_MU and VHT_MU: IE13 added.
    assert_eq!(bitmap(&io, 6), 0x0000_20f0);
    // TRIG_BASE_PPDU (index 10, page 9): IE13 and IE01.
    assert_eq!(bitmap(&io, 9), 0x0000_20f2);
    // CCK_PKT (page 10): the path IEs dropped, IE01 added.
    assert_eq!(bitmap(&io, 10), 0x0000_0002);
    // LEGACY_OFDM_PKT: the path IEs dropped; HT and above IE20 too.
    assert_eq!(bitmap(&io, 11), 0);
    assert_eq!(bitmap(&io, 12), 1 << 20);
    assert_eq!(bitmap(&io, 14), 1 << 20);
    // No reserved page 9 or EHT page past HE's.
    assert_eq!(bitmap(&io, 15), 0x0000_00f0);
    assert_eq!(
        io.log.iter().filter(|r| r[0] == 8).count(),
        2 + 15,
        "two report enables and fifteen bitmaps"
    );
    // Monitor mode adds IE09 to SU and IE09 and IE10 to MU.
    physts_parsing_init(&mut io, true).unwrap();
    assert_eq!(bitmap(&io, 7) & 0x600, 0x600);
    assert_eq!(bitmap(&io, 13) & 0x600, 0x200);
}

#[test]
fn the_env_monitor_turns_false_alarms_into_permils_over_its_window() {
    let (mut io, mut d) = started();
    report(&mut io, 600, 1200);
    // The first window was never set: its period is 0 and so are the ratios.
    d.env_monitor_track(&mut io).unwrap();
    assert_eq!(d.env.ccx_watchdog_result & ENV_MON_IFS_CLM, ENV_MON_IFS_CLM);
    assert_eq!(
        (d.env.ifs_clm_cck_fa_permil, d.env.ifs_clm_ofdm_fa_permil),
        (0, 0)
    );
    // 1900 ms in 32 us units: 59375, written into the counter's period.
    assert_eq!((d.env.ccx_period, d.env.ccx_unit_idx), (59375, 3));
    assert_eq!(field(io.phy(IFS_COUNTER), IFS_CLM_PERIOD_MSK), 59375);
    assert!(d.env.ccx_ongoing);
    report(&mut io, 600, 1200);
    d.env_monitor_track(&mut io).unwrap();
    // (600 * 1000 + 29687) / 59375 and (1200 * 1000 + 29687) / 59375.
    assert_eq!(
        (d.env.ifs_clm_cck_fa_permil, d.env.ifs_clm_ofdm_fa_permil),
        (10, 20)
    );
    // A report not ready is not read.
    io.set(CR_BASE + IFSCNT, 4, 0);
    io.log.clear();
    d.env_monitor_track(&mut io).unwrap();
    assert_eq!(d.env.ccx_watchdog_result & ENV_MON_IFS_CLM, 0);
    assert!(!io.log.iter().any(|r| r[1] == CR_BASE + IFS_CLM_FA));
}

#[test]
fn dig_sets_the_pd_floors_from_the_link_rssi_and_backs_off_in_noisy_air() {
    let (mut io, mut d) = started();
    // Unlinked: RSSI 22, the PD floor off and spatial reuse disabled.
    assert_eq!(field(io.phy(SEG0R_PD_V1), SEG0R_PD_LOWER_BOUND_MSK), 0);
    assert_eq!(d.dig.fa_th, FA_TH_NOLINK);
    report(&mut io, 0, 0);
    d.env_monitor_track(&mut io).unwrap();
    d.dig(&mut io, LINKED, G20).unwrap();
    // First connected: 2 GHz thresholds, RSSI 120 halved to 60.
    assert_eq!(d.dig.fa_th, FA_TH_2G);
    assert_eq!(d.dig.igi_rssi, 60);
    // Quiet air, no offset: igi_fa_rssi 60 clamped to [50, 75]; under region
    // 16 + 7 at 20 MHz; floor (60 - 23 - 8) >> 1.
    assert_eq!(d.dig.igi_fa_rssi, 60);
    assert_eq!(d.dig.noisy_lv, DIG_NOISY_LEVEL0);
    assert_eq!(field(io.phy(SEG0R_PD_V1), SEG0R_PD_LOWER_BOUND_MSK), 14);
    assert_eq!(
        io.phy(SEG0R_PD_V1) & SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1,
        SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1
    );
    // CCK: max(60 - 23, -18) - 110 = -73 in the top byte.
    assert_eq!(
        field(io.phy(BMODE_PDTH_V1), BMODE_PDTH_LOWER_BOUND_MSK_V1),
        (-73i32) as u32 & 0xff
    );
    // igi_fa_rssi equals dyn_pd_th_max (60): no PAGC follow.
    assert_eq!(io.phy(PAGCUGC_EN[0]) & PAGCUGC_EN_MSK, 0);
    // Noisy air (permil sum past 88): level 3, +6 per track up to 25.
    for (ofst, rssi) in [(6, 66), (12, 75), (18, 75), (24, 75), (25, 75)] {
        report(&mut io, 3000, 3000);
        d.env_monitor_track(&mut io).unwrap();
        d.dig(&mut io, LINKED, G20).unwrap();
        assert_eq!(
            (d.dig.noisy_lv, d.dig.fa_rssi_ofst, d.dig.igi_fa_rssi),
            (3, ofst, rssi)
        );
    }
    // Above dyn_pd_th_max now: the PAGC follow is on.
    assert_eq!(io.phy(PAGCUGC_EN[3]) & PAGCUGC_EN_MSK, PAGCUGC_EN_MSK);
    // Pinned at dyn_igi_max with the air at its noisiest: the PD diagnosis
    // after five tracks.
    assert_eq!(d.dig.dyn_pd_max_cnt, 4);
    assert!(!d.dig.diag_pd);
    report(&mut io, 3000, 3000);
    d.env_monitor_track(&mut io).unwrap();
    d.dig(&mut io, LINKED, G20).unwrap();
    assert!(d.dig.diag_pd);
    assert_eq!(d.dig.diag_pd_cnt, 1);
}

#[test]
fn dig_holds_while_suspended_skips_one_track_after_a_scan_and_restores_its_floor() {
    let (mut io, mut d) = started();
    report(&mut io, 0, 0);
    d.dig(&mut io, LINKED, G20).unwrap();
    let floor = d.dig.bak_dig;
    assert_ne!(floor, 0);
    d.dig_suspend(&mut io).unwrap();
    assert_eq!(field(io.phy(SEG0R_PD_V1), SEG0R_PD_LOWER_BOUND_MSK), 0);
    io.log.clear();
    d.dig(&mut io, LINKED, G20).unwrap();
    assert!(io.log.is_empty(), "a paused DIG writes nothing");
    // Suspending twice does nothing.
    d.dig_suspend(&mut io).unwrap();
    assert!(io.log.is_empty());
    d.dig_resume(&mut io, LINKED, true).unwrap();
    assert_eq!(field(io.phy(SEG0R_PD_V1), SEG0R_PD_LOWER_BOUND_MSK), floor);
    d.scan_complete();
    io.log.clear();
    d.dig(&mut io, LINKED, G20).unwrap();
    assert!(io.log.is_empty() && !d.dig.bypass_dig);
    d.dig(&mut io, LINKED, G20).unwrap();
    assert!(!io.log.is_empty());
}

#[test]
fn cfo_parse_counts_each_mac_id_and_refuses_one_past_the_table() {
    let (_, mut d) = started();
    assert!(d.cfo_parse(-12, 0));
    assert!(d.cfo_parse(20, 0));
    assert!(d.cfo_parse(7, 63));
    assert!(!d.cfo_parse(7, 64));
    assert_eq!((d.cfo.cfo_tail[0], d.cfo.cfo_cnt[0]), (8, 2));
    assert_eq!(d.cfo.packet_count, 3);
}

#[test]
fn cfo_moves_the_crystal_by_three_or_one_and_stops_within_eight() {
    let (mut io, mut d) = started();
    let traffic = Traffic::default();
    let track = |d: &mut Dynamic, io: &mut Model, cfo: i16| {
        d.cfo_parse(cfo, 0);
        assert_eq!(d.cfo_track(io, LINKED, traffic).unwrap(), None);
        d.cfo.crystal_cap
    };
    assert_eq!(track(&mut d, &mut io, 130), 0x3f);
    assert_eq!(track(&mut d, &mut io, 90), 0x42);
    assert_eq!(track(&mut d, &mut io, 41), 0x43);
    assert_eq!(track(&mut d, &mut io, -13), 0x42);
    // Within 12: tracking still on, no step; within 8: off.
    assert_eq!(track(&mut d, &mut io, 12), 0x42);
    assert!(d.cfo.is_adjust);
    assert_eq!(track(&mut d, &mut io, 8), 0x42);
    assert!(!d.cfo.is_adjust);
    // Off, 9 starts it but steps nothing; it takes more than 12 to move.
    assert_eq!(track(&mut d, &mut io, 9), 0x42);
    assert_eq!(track(&mut d, &mut io, -13), 0x41);
    // Written through XTAL SI to SC_XO and SC_XI, and read back.
    assert_eq!(io.xtal[usize::from(XTAL_SI_XTAL_SC_XO)], 0x41);
    assert_eq!(io.xtal[usize::from(XTAL_SI_XTAL_SC_XI)], 0x41);
    assert_eq!(d.cfo.x_cap_ofst, 0x41 - 0x3c);
    // Unlinked, the cap steps back toward the default once per track.
    d.cfo_track(&mut io, Link::default(), traffic).unwrap();
    assert_eq!(d.cfo.crystal_cap, 0x40);
}

#[test]
fn the_cfo_timer_starts_at_100_mbps_and_stops_at_50() {
    let (mut io, mut d) = started();
    let fast = Traffic {
        tx_throughput: 100,
        ..Traffic::default()
    };
    let slow = Traffic {
        tx_throughput: 50,
        ..Traffic::default()
    };
    assert_eq!(d.cfo_track(&mut io, LINKED, fast).unwrap(), Some(250));
    assert!(d.cfo.cfo_trig_by_timer_en);
    // The timer applies the CFO: the track does not.
    d.cfo_parse(130, 0);
    assert_eq!(d.cfo_track(&mut io, LINKED, fast).unwrap(), None);
    assert_eq!(d.cfo.crystal_cap, 0x3c);
    let mut left = false;
    let next = d
        .cfo_track_work(&mut io, LINKED, fast, |_| {
            left = true;
            Ok(())
        })
        .unwrap();
    assert!(left);
    assert_eq!((next, d.cfo.crystal_cap), (Some(250), 0x3f));
    assert_eq!(d.cfo_track(&mut io, LINKED, slow).unwrap(), None);
    assert_eq!(d.cfo.phy_cfo_status, DCFO_STATE_NORMAL);
    // The work that was queued then finds the timer off.
    let next = d
        .cfo_track_work(&mut io, LINKED, slow, |_| {
            panic!("power save is left only when it runs")
        })
        .unwrap();
    assert_eq!(next, None);
}

#[test]
fn an_xtal_si_timeout_is_counted_and_its_read_taken_as_zero() {
    let mut io = Model::new(true);
    let d = Dynamic::init(&mut io, 1, 0x3c, G20, false).unwrap();
    assert_eq!(d.cfo.xtal_timeouts, 4);
    assert_eq!(d.cfo.crystal_cap, 0);
    assert_eq!(d.cfo.x_cap_ofst, -0x3c);
}

#[test]
fn a_refused_access_ends_the_step() {
    let (mut io, mut d) = started();
    io.refuse = Some(CR_BASE + SEG0R_PD_V1);
    assert_eq!(
        d.dig(&mut io, LINKED, G20),
        Err(io::Error::Register {
            register: CR_BASE + SEG0R_PD_V1
        })
    );
}

#[test]
fn an_a1_matched_ofdm_report_carries_its_fd_cfo_sign_extended() {
    let mut status = rxdesc::tests::ppdu_status([110, 104], 100, 120, 0x20);
    // IE01's second word, behind the MAC info (16 bytes), the PHY status
    // header (8) and IE01's first word.
    let w1 = 0xfffu32 << 8;
    status[28..32].copy_from_slice(&w1.to_le_bytes());
    let desc = RxDescInfo {
        mac_info_valid: true,
        addr1_match: true,
        data_rate: HW_RATE_OFDM6,
        pkt_type: RX_TYPE_PPDU_STAT,
        ..RxDescInfo::default()
    };
    let (phy, error) = PhyPpdu::process(&desc, &status);
    assert_eq!(error, None);
    assert_eq!(phy.cfo, Some(-1));
    status[28..32].copy_from_slice(&(0x7ffu32 << 8).to_le_bytes());
    assert_eq!(PhyPpdu::process(&desc, &status).0.cfo, Some(0x7ff));
    // Not A1-matched, or CCK: no CFO.
    let other = RxDescInfo {
        addr1_match: false,
        ..desc
    };
    assert_eq!(PhyPpdu::process(&other, &status).0.cfo, None);
    let cck = RxDescInfo {
        data_rate: 0,
        ..desc
    };
    assert_eq!(PhyPpdu::process(&cck, &status).0.cfo, None);
}
