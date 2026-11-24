extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    fwdl::{DOWNLOAD_ATTEMPTS, Downloaded},
    pci::tests::{Access, encode, push, r8, r16, r32, segment, w8, w16, w32},
    rtw8852b::efuse::{
        BW40_1S_TSSI_5G, BW40_TSSI, CCK_TSSI, COUNTRY_CODE, DAV_LOG_EFUSE_SIZE, E_MAC_ADDR,
        PATH_A_THERM, PATH_A_TSSI, PATH_B_THERM, PATH_B_TSSI, RFE_TYPE, RX_GAIN_2G_CCK,
        RX_GAIN_2G_OFDM, RX_GAIN_5G_HIGH, RX_GAIN_5G_LOW, RX_GAIN_5G_MID, SIZE, TSSI_OFFSET_SIZE,
        XTAL_K,
    },
};
use alloc::{vec, vec::Vec};

const MEMORY: usize = 0x1_0000;
/// The DDV and DAV efuse the model serves, each addressed by 11 bits.
pub(crate) const EFUSE_BYTES: usize = 0x800;
/// The C harness's `NEVER`: a DAV request that never reads ready.
const NEVER: u32 = u32::MAX;
/// The C harness's `PHYCAP_OK`: PHY_CAP with two streams each way over two
/// antennas, 802.11ax.
pub(crate) const PHYCAP_OK: [u32; 4] = [0x0202_0403, 0x0000_0302, 0, 0x0302_0200];

/// What the model serves in one case, as the C oracle's input segment names
/// it.
#[derive(Clone, Debug)]
pub(crate) struct Case {
    pub(crate) cut: u8,
    pub(crate) autoload: bool,
    /// EFUSE_CTRL reads before EF_RDY shows.
    pub(crate) ddv_late: u32,
    /// XTAL_SI_CTRL reads before XTAL_SI_RDY shows.
    pub(crate) dav_late: u32,
    /// The first DAV requests, which never read ready.
    pub(crate) dav_stuck: u32,
    /// H2CREG_CTRL reads nonzero: the firmware never takes an H2C.
    pub(crate) h2c_busy: bool,
    /// The C2H the firmware answers an H2C with, if any.
    pub(crate) c2h: Option<[u32; 4]>,
    pub(crate) ddv: Vec<u8>,
    pub(crate) dav: Vec<u8>,
}

impl Case {
    /// A blank efuse that autoloaded, and a firmware that answers
    /// [`PHYCAP_OK`].
    pub(crate) fn blank(cut: u8) -> Self {
        Self {
            cut,
            autoload: true,
            ddv_late: 0,
            dav_late: 0,
            dav_stuck: 0,
            h2c_busy: false,
            c2h: Some(PHYCAP_OK),
            ddv: vec![0xff; EFUSE_BYTES],
            dav: vec![0xff; EFUSE_BYTES],
        }
    }

    /// The C oracle's input segment.
    fn decode(bytes: &[u8]) -> Self {
        let word =
            |index: usize| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
        assert_eq!(bytes.len(), 11 * 4 + 2 * EFUSE_BYTES);
        let maps = &bytes[11 * 4..];
        Self {
            cut: word(0) as u8,
            autoload: word(1) != 0,
            ddv_late: word(2),
            dav_late: word(3),
            dav_stuck: word(4),
            h2c_busy: word(5) != 0,
            c2h: (word(6) != 0).then(|| [word(7), word(8), word(9), word(10)]),
            ddv: maps[..EFUSE_BYTES].to_vec(),
            dav: maps[EFUSE_BYTES..].to_vec(),
        }
    }
}

/// The register model the C oracle's harness uses: MAC space as
/// little-endian bytes, EFUSE_CTRL serving the DDV efuse, XTAL SI completing
/// every request and serving the DAV efuse, and the firmware taking each H2C
/// and answering it.
pub(crate) struct Model {
    memory: Vec<u8>,
    /// The XTAL SI registers.
    pub(crate) xtal: [u8; 256],
    ddv: Vec<u8>,
    dav: Vec<u8>,
    ddv_late: u32,
    ddv_wait: u32,
    dav_late: u32,
    dav_wait: u32,
    dav_stuck: u32,
    dav_requests: u32,
    c2h: Option<[u32; 4]>,
    /// No DDV byte ever reads ready.
    pub(crate) ddv_stuck: bool,
    /// XTAL SI never completes a request.
    pub(crate) xtal_stuck: bool,
    pub(crate) log: Vec<Access>,
    /// Whether accesses are logged; reads and delays are always counted.
    pub(crate) logging: bool,
    pub(crate) reads: Vec<usize>,
    pub(crate) waited_us: u64,
}

impl Model {
    /// The oracle's model: byte i holding i * 37 + 11.
    pub(crate) fn new(case: &Case) -> Self {
        Self::with((0..MEMORY).map(|at| (at * 37 + 11) as u8).collect(), case)
    }

    pub(crate) fn zeroed(case: &Case) -> Self {
        Self::with(vec![0; MEMORY], case)
    }

    fn with(mut memory: Vec<u8>, case: &Case) -> Self {
        let autoload = AUTOLOAD_SUS as u8;
        if case.autoload {
            memory[SYS_WL_EFUSE_CTRL as usize] |= autoload;
        } else {
            memory[SYS_WL_EFUSE_CTRL as usize] &= !autoload;
        }
        memory[H2CREG_CTRL as usize] = u8::from(case.h2c_busy);
        memory[C2HREG_CTRL as usize] = 0;
        Self {
            memory,
            xtal: [0; 256],
            ddv: case.ddv.clone(),
            dav: case.dav.clone(),
            ddv_late: case.ddv_late,
            ddv_wait: 0,
            dav_late: case.dav_late,
            dav_wait: 0,
            dav_stuck: case.dav_stuck,
            dav_requests: 0,
            c2h: case.c2h,
            ddv_stuck: false,
            xtal_stuck: false,
            log: Vec::new(),
            logging: true,
            reads: vec![0; MEMORY],
            waited_us: 0,
        }
    }

    pub(crate) fn get(&self, register: u32, width: u32) -> u32 {
        let at = register as usize;
        let mut bytes = [0; 4];
        bytes[..width as usize].copy_from_slice(&self.memory[at..at + width as usize]);
        u32::from_le_bytes(bytes)
    }

    fn set(&mut self, register: u32, width: u32, value: u32) {
        let at = register as usize;
        self.memory[at..at + width as usize]
            .copy_from_slice(&value.to_le_bytes()[..width as usize]);
    }

    fn check(register: u32, width: u32) {
        assert!(
            register as usize + width as usize <= MEMORY,
            "{register:#x}"
        );
        for wide in [EFUSE_CTRL, WLAN_XTAL_SI_CTRL] {
            if (wide..wide + 4).contains(&register) {
                assert!(
                    width == 4 && register == wide,
                    "{register:#x} reached {width} bytes wide"
                );
            }
        }
        if register == H2CREG_CTRL || register == C2HREG_CTRL {
            assert_eq!(width, 1, "{register:#x}");
        }
    }

    fn read(&mut self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        if register == EFUSE_CTRL {
            if self.ddv_wait > 0 {
                self.ddv_wait -= 1;
            } else if !self.ddv_stuck {
                let ready = self.get(EFUSE_CTRL, 4) | EF_RDY;
                self.set(EFUSE_CTRL, 4, ready);
            }
        }
        let value = self.get(register, width);
        self.reads[register as usize] += 1;
        if self.logging {
            self.log.push(Access::Read {
                width,
                register,
                value,
            });
        }
        value
    }

    fn write(&mut self, register: u32, width: u32, value: u32) {
        Self::check(register, width);
        if self.logging {
            self.log.push(Access::Write {
                width,
                register,
                value,
            });
        }
        let mut stored = value;
        match register {
            WLAN_XTAL_SI_CTRL if !self.xtal_stuck => {
                let offset = field(value, XTAL_SI_ADDR_MASK) as u8;
                let at = usize::from(offset);
                let data = field(value, XTAL_SI_DATA_MASK) as u8;
                let mask = field(value, XTAL_SI_BITMASK_MASK) as u8;
                stored = value & !XTAL_SI_CMD_POLL;
                if field(value, XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_WRITE {
                    self.xtal[at] = (self.xtal[at] & !mask) | (data & mask);
                    if offset == XTAL_SI_CTRL
                        && mask & XTAL_SI_MODE_SEL_MASK != 0
                        && self.xtal[at] & XTAL_SI_MODE_SEL_MASK == 0
                    {
                        let addr = usize::from(self.xtal[usize::from(XTAL_SI_LOW_ADDR)])
                            | usize::from(self.xtal[at] & XTAL_SI_HIGH_ADDR_MASK) << 8;
                        self.xtal[usize::from(XTAL_SI_READ_VAL)] = self.dav[addr];
                        self.dav_requests += 1;
                        self.dav_wait = if self.dav_requests <= self.dav_stuck {
                            NEVER
                        } else {
                            self.dav_late
                        };
                    }
                } else {
                    if offset == XTAL_SI_CTRL {
                        if self.dav_wait == 0 {
                            self.xtal[at] |= XTAL_SI_RDY;
                        } else if self.dav_wait != NEVER {
                            self.dav_wait -= 1;
                        }
                    }
                    stored = (stored & !XTAL_SI_DATA_MASK)
                        | prep(u32::from(self.xtal[at]), XTAL_SI_DATA_MASK);
                }
            }
            EFUSE_CTRL => {
                let addr = field(value, EF_ADDR_MASK) as usize;
                stored = (value & !(EF_DATA_MASK | EF_RDY)) | u32::from(self.ddv[addr]);
                self.ddv_wait = self.ddv_late;
            }
            H2CREG_CTRL if value & u32::from(H2CREG_TRIGGER) != 0 => {
                stored = 0;
                if let Some(words) = self.c2h {
                    for (register, word) in h2creg::C2H_REGS.into_iter().zip(words) {
                        self.set(register, 4, word);
                    }
                    self.set(C2HREG_CTRL, 1, 1);
                }
            }
            _ => {}
        }
        self.set(register, width, stored);
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
        self.waited_us += microseconds;
        if self.logging {
            self.log.push(Access::Delay(microseconds));
        }
    }
}

/// A mailbox as a download leaves it.
pub(crate) fn mailbox() -> Mailbox {
    Mailbox::after_download(&Downloaded {
        retried: [None; DOWNLOAD_ATTEMPTS - 1],
        packets: 0,
    })
}

/// The C harness's `encode`: one block per 8 logical bytes that hold anything
/// but 0xff, each word enabled where it does, written from physical byte
/// `at`. Returns the next free byte.
pub(crate) fn encode_blocks(map: &mut [u8], mut at: usize, logical: &[u8]) -> usize {
    for (blk, words) in logical.chunks(8).enumerate() {
        let mut word_en = 0xf;
        for i in 0..4 {
            if words[2 * i..2 * i + 2] != [0xff, 0xff] {
                word_en &= !(1 << i);
            }
        }
        if word_en == 0xf {
            continue;
        }
        map[at] = 0x30 | (blk >> 4) as u8;
        map[at + 1] = ((blk & 0xf) << 4) as u8 | word_en;
        at += 2;
        for i in 0..4 {
            if word_en & (1 << i) == 0 {
                map[at..at + 2].copy_from_slice(&words[2 * i..2 * i + 2]);
                at += 2;
            }
        }
    }
    at
}

/// The synthetic board: MAC 02:00:00:00:00:01, RFE type 1, crystal cap 0x3c,
/// country "US", thermal values, TSSI offsets and RX gain offsets, as the C
/// oracle's `fill_valid` programs them.
pub(crate) fn synthetic_logical() -> Vec<u8> {
    let mut log = vec![0xff; LOGICAL_EFUSE_SIZE];
    log[E_MAC_ADDR..E_MAC_ADDR + 6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    log[RFE_TYPE] = 1;
    log[XTAL_K] = 0x3c;
    log[COUNTRY_CODE..COUNTRY_CODE + 2].copy_from_slice(b"US");
    log[PATH_A_THERM] = 0x1d;
    log[PATH_B_THERM] = 0x1e;
    for (base, first) in [(PATH_A_TSSI, 0x20u8), (PATH_B_TSSI, 0x40)] {
        for i in 0..6 {
            log[base + CCK_TSSI + i] = first + i as u8;
        }
        for i in 0..5 {
            log[base + BW40_TSSI + i] = first + 0x10 + i as u8;
        }
        for i in 0..14 {
            log[base + BW40_1S_TSSI_5G + i] = first + 0x20 + i as u8;
        }
    }
    log[RX_GAIN_2G_CCK] = 0x12;
    log[RX_GAIN_2G_OFDM] = 0xf1;
    log[RX_GAIN_5G_LOW] = 0x8f;
    log[RX_GAIN_5G_MID] = 0x77;
    log
}

/// The C oracle's `phycap_programmed`.
pub(crate) fn program_phycap(ddv: &mut [u8], power_k: u8) {
    ddv[0x5e9] = power_k;
    for j in 0..8 {
        ddv[0x5d6 - j] = 0x01 + j as u8;
        ddv[0x5ab - j] = 0xf8 + j as u8;
    }
    for (address, value) in [
        (0x5df, 0x13),
        (0x5dc, 0xff),
        (0x5de, 0x87),
        (0x5db, 0x65),
        (0x5bb, 0x01),
        (0x5ba, 0x0f),
        (0x5b9, 0xff),
        (0x5b8, 0x08),
        (0x590, 0x07),
        (0x58f, 0xff),
        (0x58e, 0x09),
        (0x58d, 0xf3),
    ] {
        ddv[address] = value;
    }
}

/// The synthetic board's case, as the C oracle's `valid` case.
fn synthetic(cut: u8) -> Case {
    let mut case = Case::blank(cut);
    case.ddv[..4].copy_from_slice(&[0x00, 0x11, 0x22, 0x33]);
    encode_blocks(&mut case.ddv, 4, &synthetic_logical());
    program_phycap(&mut case.ddv, 0xaa);
    case
}

#[test]
fn a_synthetic_map_reads_as_rtw89_parses_it() {
    let case = synthetic(CHIP_CBV);
    let mut io = Model::new(&case);
    let mut mailbox = mailbox();
    let info = info_setup(&mut io, CHIP_CBV, &mut mailbox).unwrap();

    assert_eq!(
        info.efuse,
        Efuse {
            valid: true,
            power_k_valid: true,
            xtal_cap: 0x3c,
            addr: [0x02, 0, 0, 0, 0, 0x01],
            rfe_type: 1,
            country_code: *b"US",
        }
    );
    assert!(info.efuse.unicast());
    let mut log_map = [0xff; FULL_LOG_SIZE];
    log_map[..LOGICAL_EFUSE_SIZE].copy_from_slice(&synthetic_logical());
    assert_eq!(info.log_map, log_map);
    assert_eq!(info.phycap_map[..], case.ddv[0x580..0x600]);

    assert_eq!(info.tssi.thermal, [0x1d, 0x1e]);
    assert_eq!(info.tssi.tssi_cck[0], [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
    assert_eq!(info.tssi.tssi_cck[1][5], 0x45);
    assert_eq!(
        info.tssi.tssi_mcs[0][..6],
        [0x30, 0x31, 0x32, 0x33, 0x34, 0x40]
    );
    assert_eq!(info.tssi.tssi_mcs[1][18], 0x40 + 0x20 + 13);
    // Path A's trims from 0x5d6 down, path B's from 0x5ab down; 0xff is -1.
    assert_eq!(info.tssi.tssi_trim[0], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(info.tssi.tssi_trim[1], [-8, -7, -6, -5, -4, -3, -2, -1]);
    assert_eq!(
        info.pwr_trim,
        PowerTrim {
            pg_thermal_trim: true,
            pg_pa_bias_trim: true,
            thermal_trim: [0x13, 0xff],
            pa_bias_trim: [0x87, 0x65],
        }
    );
    assert_eq!(
        info.efuse_gain,
        EfuseGain {
            offset_valid: true,
            comp_valid: true,
            // 2G CCK 0x12, 2G OFDM 0xf1, 5G low 0x8f, 5G mid 0x77, 5G high
            // blank: path A the high nibble, path B the low one.
            offset: [[1, -1, -8, 7, -1], [2, 1, -1, 7, -1]],
            // The low nibbles of 0x5bb, 0x5ba, 0x5b9, 0x5b8 and 0x590,
            // 0x58f, 0x58e, 0x58d; the unused subband 2 stays 0.
            comp: [[1, -1, 0, -1, -8], [7, -1, 0, -7, 3]],
        }
    );
    assert_eq!(
        info.hal,
        Hal {
            tx_nss: 2,
            rx_nss: 2,
            antenna_tx: 0,
            antenna_rx: 0,
            tx_path_diversity: false,
            no_eht: true,
            support_cckpd: true,
            phycap: PHYCAP_OK,
        }
    );
    assert_eq!((mailbox.h2c_counter(), mailbox.c2h_counter()), (1, 1));
    assert_eq!(
        info.efuse.power_inputs(CHIP_CBV),
        Inputs {
            cut: CHIP_CBV,
            rfe_type: 1,
            efuse_valid: true,
            power_k_valid: true,
            probe_done: true,
        }
    );
}

/// An XTAL SI request the model completes at once: the write, then the poll
/// that reads it back without its poll bit; a read returns `data`.
fn xtal_write(offset: u8, value: u8, mask: u8) -> [Access; 2] {
    let request =
        u32::from(offset) | u32::from(value) << 8 | u32::from(mask) << 16 | XTAL_SI_CMD_POLL;
    [
        w32(WLAN_XTAL_SI_CTRL, request),
        r32(WLAN_XTAL_SI_CTRL, request & !XTAL_SI_CMD_POLL),
    ]
}
fn xtal_read(offset: u8, data: u8) -> [Access; 2] {
    let request = u32::from(offset) | 1 << 24 | XTAL_SI_CMD_POLL;
    [
        w32(WLAN_XTAL_SI_CTRL, request),
        r32(
            WLAN_XTAL_SI_CTRL,
            u32::from(offset) | 1 << 24 | u32::from(data) << 8,
        ),
    ]
}

/// A DDV dump of `map.len()` bytes from `from` on a zeroed model whose
/// SYS_ISO_CTRL holds `iso` and PMC_DBG_CTRL2 0, transcribed from
/// rtw89_enable_efuse_pwr_cut_ddv, rtw89_dump_physical_efuse_map_ddv and
/// rtw89_disable_efuse_pwr_cut_ddv for a cut other than CAV.
fn ddv_dump(expected: &mut Vec<Access>, iso: u32, from: u32, map: &[u8]) {
    expected.extend([
        r8(PMC_DBG_CTRL2, 0),
        w8(PMC_DBG_CTRL2, 0x4),
        r16(SYS_ISO_CTRL, iso),
        w16(SYS_ISO_CTRL, iso | 0x4000),
        delay(1000),
        r16(SYS_ISO_CTRL, iso | 0x4000),
        w16(SYS_ISO_CTRL, iso | 0xc000),
        r16(SYS_ISO_CTRL, iso | 0xc000),
        w16(SYS_ISO_CTRL, 0xc000),
    ]);
    for (addr, &byte) in (from..).zip(map) {
        expected.extend([
            w32(EFUSE_CTRL, addr << 16),
            delay(1),
            r32(EFUSE_CTRL, addr << 16 | EF_RDY | u32::from(byte)),
        ]);
    }
    expected.extend([
        r16(SYS_ISO_CTRL, 0xc000),
        w16(SYS_ISO_CTRL, 0xc100),
        r16(SYS_ISO_CTRL, 0xc100),
        w16(SYS_ISO_CTRL, 0x4100),
        delay(1000),
        r16(SYS_ISO_CTRL, 0x4100),
        w16(SYS_ISO_CTRL, 0x0100),
        r8(PMC_DBG_CTRL2, 0x4),
        w8(PMC_DBG_CTRL2, 0),
    ]);
}

fn delay(microseconds: u64) -> Access {
    Access::Delay(microseconds)
}

#[test]
fn info_setup_makes_rtw89s_accesses_in_its_order() {
    let case = synthetic(CHIP_CCV);
    let mut io = Model::zeroed(&case);
    info_setup(&mut io, CHIP_CCV, &mut mailbox()).unwrap();

    // rtw89_parse_efuse_map_ax: the autoload bit, then the DDV map.
    let mut expected = vec![r16(SYS_WL_EFUSE_CTRL, u32::from(AUTOLOAD_SUS))];
    ddv_dump(&mut expected, 0, 0, &case.ddv[..PHYSICAL_EFUSE_SIZE]);
    // The DAV map, a byte at a time through XTAL SI: the mode, the address,
    // the start, one ready read, then the value.
    for addr in 0..DAV_PHY_EFUSE_SIZE as u32 {
        expected.extend(xtal_write(XTAL_SI_CTRL, 0x40, 0xff));
        expected.extend(xtal_write(XTAL_SI_LOW_ADDR, addr as u8, 0xff));
        expected.extend(xtal_write(XTAL_SI_CTRL, (addr >> 8) as u8, 0x07));
        expected.extend(xtal_write(XTAL_SI_CTRL, 0, 0xc0));
        expected.extend(xtal_read(XTAL_SI_CTRL, XTAL_SI_RDY));
        expected.extend(xtal_read(XTAL_SI_READ_VAL, case.dav[addr as usize]));
    }
    // rtw89_parse_phycap_map_ax: SYS_ISO_CTRL keeps ISO_EB2CORE from the
    // first dump.
    ddv_dump(&mut expected, 0x0100, PHYCAP_ADDR, &case.ddv[0x580..0x600]);
    // rtw89_mac_read_phycap over the mailbox: GET_FEATURE part 0, one word.
    expected.extend([
        r8(H2CREG_CTRL, 0),
        w32(H2CREG_DATA0, 0x103),
        w32(H2CREG_DATA1, 0),
        w32(H2CREG_DATA2, 0),
        w32(H2CREG_DATA3, 0),
        r8(UDM1 + 1, 0),
        w8(UDM1 + 1, 0x01),
        w8(H2CREG_CTRL, 1),
        r8(C2HREG_CTRL, 1),
        r32(C2HREG_DATA0, PHYCAP_OK[0]),
        r32(C2HREG_DATA1, PHYCAP_OK[1]),
        r32(C2HREG_DATA2, PHYCAP_OK[2]),
        r32(C2HREG_DATA3, PHYCAP_OK[3]),
        w8(C2HREG_CTRL, 0),
        r8(UDM1 + 1, 0x01),
        w8(UDM1 + 1, 0x11),
        // rtw89_hci_mac_pre_deinit
        r32(HCI_OPT_CTRL, 0),
        w32(HCI_OPT_CTRL, 0),
    ]);
    assert_eq!(io.log.len(), expected.len());
    for (at, (seen, want)) in io.log.iter().zip(&expected).enumerate() {
        assert_eq!(seen, want, "access {at}");
    }
}

#[test]
fn a_cav_bursts_each_ddv_dump() {
    let case = synthetic(CHIP_CAV);
    let mut io = Model::zeroed(&case);
    let mut info = Info::probe();
    parse_phycap_map(&mut io, CHIP_CAV, &mut info).unwrap();
    let burst = io
        .log
        .iter()
        .position(|access| *access == w32(EFUSE_CTRL_1_V1, EF_BURST))
        .unwrap();
    assert_eq!(io.log[burst - 1], r32(EFUSE_CTRL_1_V1, 0));
    assert_eq!(io.log[burst + 1], w32(EFUSE_CTRL, PHYCAP_ADDR << 16));
    let idle = io
        .log
        .iter()
        .position(|access| *access == w32(EFUSE_CTRL_1_V1, 0))
        .unwrap();
    assert_eq!(io.log[idle - 1], r32(EFUSE_CTRL_1_V1, EF_BURST));
    assert!(matches!(
        io.log[idle - 2],
        Access::Read {
            register: EFUSE_CTRL,
            ..
        }
    ));
    assert!(info.efuse.power_k_valid);
    // Every other cut leaves EFUSE_CTRL_1_V1 alone.
    let mut io = Model::zeroed(&case);
    parse_phycap_map(&mut io, CHIP_CBV, &mut Info::probe()).unwrap();
    assert_eq!(io.reads[EFUSE_CTRL_1_V1 as usize], 0);
}

#[test]
fn the_logical_decode_takes_rtw89s_blocks_and_word_enables() {
    let mut phy = [0xff; PHYSICAL_EFUSE_SIZE];
    // sec_ctrl_efuse_size bytes, which the decode skips.
    phy[..4].copy_from_slice(&[0x00, 0x11, 0x22, 0x33]);
    let blocks: &[u8] = &[
        0xc8, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, // block 0x80, words 0-2; hdr1's top nibble ignored
        0x31, 0x2f, // block 0x12, no word
        0x35, 0x9d, 0x02, b'J', // block 0x59, word 1
        0x35, 0x9b, b'P', 0x00, // block 0x59, word 2
        0x35, 0x7a, 0x7f, 0x41, 0x00, 0x00, // block 0x57, words 0 and 2
        0x38, 0x0d, 0xaa, 0xbb, // block 0x80, word 1 again: later wins
    ];
    phy[4..4 + blocks.len()].copy_from_slice(blocks);
    let mut log = [0xff; LOGICAL_EFUSE_SIZE];
    dump_logical_efuse_map(&phy, &mut log).unwrap();

    let mut expected = [0xff; LOGICAL_EFUSE_SIZE];
    expected[0x400..0x406].copy_from_slice(&[0x00, 0x11, 0xaa, 0xbb, 0x44, 0x55]);
    expected[0x2ca..0x2ce].copy_from_slice(&[0x02, b'J', b'P', 0x00]);
    expected[0x2b8..0x2ba].copy_from_slice(&[0x7f, 0x41]);
    expected[0x2bc..0x2be].copy_from_slice(&[0x00, 0x00]);
    assert_eq!(log, expected);

    // Either header byte 0xff ends the map, whatever follows.
    let mut ended = phy;
    ended[4 + 8 + 1] = 0xff;
    let mut log = [0xff; LOGICAL_EFUSE_SIZE];
    dump_logical_efuse_map(&ended, &mut log).unwrap();
    let mut first = [0xff; LOGICAL_EFUSE_SIZE];
    first[0x400..0x406].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(log, first);
}

#[test]
fn an_empty_map_decodes_to_0xff_and_reads_invalid_without_autoload() {
    let mut case = Case::blank(CHIP_CCV);
    case.autoload = false;
    let mut io = Model::new(&case);
    let info = info_setup(&mut io, CHIP_CCV, &mut mailbox()).unwrap();
    assert_eq!(info.log_map, [0xff; FULL_LOG_SIZE]);
    assert_eq!(info.phycap_map, [0xff; PHYCAP_SIZE]);
    assert_eq!(
        info.efuse,
        Efuse {
            valid: false,
            power_k_valid: false,
            xtal_cap: 0xff,
            addr: [0xff; 6],
            rfe_type: 0xff,
            country_code: [0xff; 2],
        }
    );
    assert!(!info.efuse.unicast());
    assert_eq!(info.tssi.thermal, [0xff; 2]);
    assert_eq!(info.tssi.tssi_cck, [[-1; 6]; 2]);
    // No trim programmed: rtw89 zeroes them.
    assert_eq!(info.tssi.tssi_trim, [[0; 8]; 2]);
    assert!(!info.pwr_trim.pg_thermal_trim);
    assert!(!info.pwr_trim.pg_pa_bias_trim);
    assert_eq!(info.efuse_gain.offset, [[-1; 5]; 2]);
    assert!(!info.efuse_gain.offset_valid && !info.efuse_gain.comp_valid);

    // The autoload bit alone decides validity: a blank map that autoloaded
    // is valid, as rtw89 reads it.
    let mut io = Model::new(&Case::blank(CHIP_CCV));
    assert!(
        info_setup(&mut io, CHIP_CCV, &mut mailbox())
            .unwrap()
            .efuse
            .valid
    );
}

/// A chain of one-word blocks from byte 4 to 1204, then a four-word block
/// whose third word ends at byte 1211 and whose fourth would end past it.
fn corrupt(case: &mut Case) {
    let mut at = 4;
    for k in 0..300u32 {
        let blk = k as u8;
        case.ddv[at..at + 4].copy_from_slice(&[
            0x30 | (blk >> 4),
            ((blk & 0xf) << 4) | 0xe,
            k as u8,
            !k as u8,
        ]);
        at += 4;
    }
    case.ddv[at] = 0x30;
    case.ddv[at + 1] = 0x00;
    at += 2;
    while at < PHYSICAL_EFUSE_SIZE {
        case.ddv[at] = at as u8;
        at += 1;
    }
}

#[test]
fn a_corrupt_header_is_einval_naming_the_word_and_stops_before_the_phycap() {
    let mut case = Case::blank(CHIP_CBV);
    corrupt(&mut case);
    let mut io = Model::new(&case);
    let mut mailbox = mailbox();
    assert_eq!(
        info_setup(&mut io, CHIP_CBV, &mut mailbox),
        Err(Error::Logical {
            dav: false,
            error: Logical::Corrupt { offset: 1212 },
        })
    );
    // Both maps were dumped before the decode; nothing after it ran.
    assert_eq!(io.reads[EFUSE_CTRL as usize], PHYSICAL_EFUSE_SIZE);
    assert_eq!(io.reads[H2CREG_CTRL as usize], 0);
    assert_eq!(io.reads[HCI_OPT_CTRL as usize], 0);
    assert_eq!(mailbox.h2c_counter(), 0);

    // Without the fourth word, the third, which ends at byte 1211, is the
    // last the decode takes, and the walk ends there.
    let mut phy = [0xff; PHYSICAL_EFUSE_SIZE];
    phy.copy_from_slice(&case.ddv[..PHYSICAL_EFUSE_SIZE]);
    phy[1205] = 0x08;
    let mut log = [0xff; LOGICAL_EFUSE_SIZE];
    dump_logical_efuse_map(&phy, &mut log).unwrap();
    assert_eq!(log[..8], [0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xff, 0xff]);
}

#[test]
fn a_dav_map_rtw89_would_overrun_is_refused() {
    // No terminator within the DAV map's 96 bytes: rtw89 would read on.
    let mut dav = [0x30; DAV_PHY_EFUSE_SIZE];
    for pair in dav[4..].chunks_mut(4) {
        pair.copy_from_slice(&[0x30, 0x0e, 0x01, 0x02]);
    }
    let mut log = [0xff; DAV_LOG_EFUSE_SIZE];
    assert_eq!(
        dump_logical_efuse_map(&dav, &mut log),
        Err(Logical::Overrun { offset: 96 })
    );
    // Block 2 is past the DAV map's 16 logical bytes: rtw89 would write on.
    let mut dav = [0xff; DAV_PHY_EFUSE_SIZE];
    dav[4..8].copy_from_slice(&[0x30, 0x2e, 0x01, 0x02]);
    assert_eq!(
        dump_logical_efuse_map(&dav, &mut log),
        Err(Logical::Overrun { offset: 16 })
    );
    // Through the read, the DAV map is named.
    let mut case = Case::blank(CHIP_CBV);
    case.dav[4..8].copy_from_slice(&[0x30, 0x2e, 0x01, 0x02]);
    assert_eq!(
        info_setup(&mut Model::new(&case), CHIP_CBV, &mut mailbox()),
        Err(Error::Logical {
            dav: true,
            error: Logical::Overrun { offset: 16 },
        })
    );
}

#[test]
fn ready_bits_that_come_late_are_polled_a_step_apart() {
    let mut case = synthetic(CHIP_CBV);
    case.ddv_late = 2;
    case.dav_late = 3;
    let mut io = Model::new(&case);
    let info = info_setup(&mut io, CHIP_CBV, &mut mailbox()).unwrap();
    assert_eq!(info.efuse.addr, [0x02, 0, 0, 0, 0, 0x01]);
    // Each DDV byte: a step, then three reads a step apart.
    assert_eq!(
        io.reads[EFUSE_CTRL as usize],
        3 * (PHYSICAL_EFUSE_SIZE + PHYCAP_SIZE)
    );
    // Each DAV byte: four ready reads, a step apart, and four writes and a
    // value read, each one XTAL SI request.
    assert_eq!(
        io.reads[WLAN_XTAL_SI_CTRL as usize],
        DAV_PHY_EFUSE_SIZE * (4 + 4 + 1)
    );
    let steps = io.log.iter().filter(|access| **access == delay(1)).count();
    assert_eq!(
        steps,
        3 * (PHYSICAL_EFUSE_SIZE + PHYCAP_SIZE) + 3 * DAV_PHY_EFUSE_SIZE
    );
}

#[test]
fn a_ddv_byte_that_never_reads_ready_fails_five_attempts_naming_efuse_ctrl() {
    let mut io = Model::new(&synthetic(CHIP_CCV));
    io.ddv_stuck = true;
    io.logging = false;
    assert_eq!(
        info_setup(&mut io, CHIP_CCV, &mut mailbox()),
        Err(Error::Io(io::Error::Timeout {
            register: EFUSE_CTRL,
            mask: EF_RDY,
        }))
    );
    // Each attempt powers the efuse up (1000 us), then reads its first byte
    // once a microsecond for a second, counted in steps; a failed attempt
    // skips the power-down. The DAV map is never reached.
    assert_eq!(io.reads[EFUSE_CTRL as usize], DUMP_ATTEMPTS * 1_000_000);
    assert_eq!(io.waited_us, DUMP_ATTEMPTS as u64 * (1000 + 1_000_000));
    assert_eq!(io.reads[WLAN_XTAL_SI_CTRL as usize], 0);

    // The secure-boot read the power-on makes fails the same way.
    let mut io = Model::new(&Case::blank(CHIP_CCV));
    io.ddv_stuck = true;
    io.logging = false;
    assert_eq!(
        read_fw_secure(&mut io, CHIP_CCV),
        Err(io::Error::Timeout {
            register: EFUSE_CTRL,
            mask: EF_RDY,
        })
    );
}

#[test]
fn a_dav_byte_that_never_reads_ready_is_retried_and_then_named() {
    // One request never ready: the first attempt polls XTAL_SI_CTRL every
    // 1 us for 10 ms, then the second attempt reads every byte.
    let mut case = synthetic(CHIP_CBV);
    case.dav[4..8].copy_from_slice(&[0x30, 0x0e, 0xab, 0xcd]);
    case.dav_stuck = 1;
    let mut io = Model::new(&case);
    io.logging = false;
    let info = info_setup(&mut io, CHIP_CBV, &mut mailbox()).unwrap();
    assert_eq!(
        info.log_map[LOGICAL_EFUSE_SIZE..LOGICAL_EFUSE_SIZE + 2],
        [0xab, 0xcd]
    );
    assert_eq!(
        io.reads[WLAN_XTAL_SI_CTRL as usize],
        (4 + 10_001) + DAV_PHY_EFUSE_SIZE * (4 + 1 + 1)
    );

    // Every attempt's first request never ready: the fifth's failure.
    let mut case = synthetic(CHIP_CBV);
    case.dav_stuck = NEVER;
    let mut io = Model::new(&case);
    io.logging = false;
    assert_eq!(
        info_setup(&mut io, CHIP_CBV, &mut mailbox()),
        Err(Error::XtalSi {
            offset: XTAL_SI_CTRL,
            mask: XTAL_SI_RDY,
        })
    );
    assert_eq!(
        io.reads[WLAN_XTAL_SI_CTRL as usize],
        DUMP_ATTEMPTS * (4 + 10_001)
    );
    assert_eq!(io.reads[H2CREG_CTRL as usize], 0);
}

#[test]
fn xtal_si_that_never_completes_fails_each_dav_attempt_at_its_first_request() {
    let mut io = Model::new(&synthetic(CHIP_CBV));
    io.xtal_stuck = true;
    io.logging = false;
    assert_eq!(
        info_setup(&mut io, CHIP_CBV, &mut mailbox()),
        Err(Error::Io(io::Error::Timeout {
            register: WLAN_XTAL_SI_CTRL,
            mask: XTAL_SI_CMD_POLL,
        }))
    );
    // Every 50 us for up to 50 ms, counted in steps.
    assert_eq!(io.reads[WLAN_XTAL_SI_CTRL as usize], DUMP_ATTEMPTS * 1001);
}

#[test]
fn a_mailbox_the_firmware_never_takes_or_answers_names_its_register() {
    let mut case = synthetic(CHIP_CBV);
    case.h2c_busy = true;
    let mut io = Model::new(&case);
    let mut busy = mailbox();
    assert_eq!(
        info_setup(&mut io, CHIP_CBV, &mut busy),
        Err(Error::Io(io::Error::Timeout {
            register: H2CREG_CTRL,
            mask: 0xff,
        }))
    );
    // Every 1000 us for up to 5000 us, after the two DDV dumps' two power
    // delays each; nothing written, nothing counted.
    assert_eq!(io.reads[H2CREG_CTRL as usize], 6);
    assert_eq!(
        io.log
            .iter()
            .filter(|access| **access == delay(1000))
            .count(),
        2 * 2 + 5
    );
    assert!(io.log.iter().all(|access| !matches!(
        access,
        Access::Write {
            register: H2CREG_DATA0..=H2CREG_CTRL,
            ..
        }
    )));
    assert_eq!(busy.h2c_counter(), 0);
    assert_eq!(io.reads[HCI_OPT_CTRL as usize], 0);

    let mut case = synthetic(CHIP_CBV);
    case.c2h = None;
    let mut io = Model::new(&case);
    io.logging = false;
    let mut silent = mailbox();
    assert_eq!(
        info_setup(&mut io, CHIP_CBV, &mut silent),
        Err(Error::Io(io::Error::Timeout {
            register: C2HREG_CTRL,
            mask: 0xff,
        }))
    );
    // Every 1 us for up to a second, counted in steps.
    assert_eq!(io.reads[C2HREG_CTRL as usize], 1_000_001);
    assert_eq!((silent.h2c_counter(), silent.c2h_counter()), (1, 0));
}

/// What `rtw89_mac_setup_phycap` leaves in a zeroed HAL for a firmware that
/// answers `c2h`.
fn phycap(c2h: [u32; 4]) -> Result<Hal, Error> {
    let mut case = Case::blank(CHIP_CBV);
    case.c2h = Some(c2h);
    let mut io = Model::new(&case);
    let mut hal = Hal::default();
    setup_phycap(&mut io, &mut mailbox(), &mut hal).map(|()| hal)
}

#[test]
fn the_firmware_phycap_sets_nss_and_antennas_as_part0_does() {
    let hal = |tx_nss, rx_nss, antenna_tx, antenna_rx, tx_path_diversity, no_eht, phycap| Hal {
        tx_nss,
        rx_nss,
        antenna_tx,
        antenna_rx,
        tx_path_diversity,
        no_eht,
        support_cckpd: false,
        phycap,
    };
    assert_eq!(
        phycap(PHYCAP_OK),
        Ok(hal(2, 2, 0, 0, false, true, PHYCAP_OK))
    );
    // One TX stream over two antennas: path B, with TX path diversity; three
    // RX streams are capped at the chip's two; 802.11be lifts no_eht.
    let one = [0x0203_0403, 0x0000_0401, 0, 0x0302_0200];
    assert_eq!(phycap(one), Ok(hal(1, 2, RF_B, 0, true, false, one)));
    // No NSS named: the chip's; one antenna each way: path B.
    let b = [0x0200_0403, 0x0000_0300, 0, 0x0301_0100];
    assert_eq!(phycap(b), Ok(hal(2, 2, RF_B, RF_B, false, true, b)));
    // Another function than PHY_CAP is -EINVAL.
    assert_eq!(
        phycap([0x0202_0401, 0x0000_0302, 0, 0x0302_0200]),
        Err(Error::PhycapId(1))
    );
    // CCK PD on every cut but CAV.
    for (cut, cckpd) in [(CHIP_CAV, false), (CHIP_CBV, true), (CHIP_CCV, true)] {
        let mut hal = Hal::default();
        core_setup_phycap(cut, &mut hal);
        assert_eq!(hal.support_cckpd, cckpd, "cut {cut}");
    }
}

#[test]
fn an_empty_map_is_read_without_any_access() {
    let mut io = Model::new(&Case::blank(CHIP_CBV));
    dump_physical_efuse_map(&mut io, CHIP_CBV, &mut [], 0, false).unwrap();
    dump_physical_efuse_map(&mut io, CHIP_CBV, &mut [], 0, true).unwrap();
    assert!(io.log.is_empty());
}

/// rtw89's return for `result`, as the C harness records it.
fn errno(result: &Result<Info, Error>) -> i32 {
    const EBUSY: i32 = 16;
    const EINVAL: i32 = 22;
    const ETIMEDOUT: i32 = 110;
    match result {
        Ok(_) => 0,
        // rtw89_dump_physical_efuse_map_ddv returns -EBUSY for a byte that
        // never reads ready.
        Err(Error::Io(io::Error::Timeout {
            register: EFUSE_CTRL,
            ..
        })) => -EBUSY,
        Err(Error::Io(io::Error::Timeout { .. }) | Error::XtalSi { .. }) => -ETIMEDOUT,
        Err(
            Error::Logical {
                error: Logical::Corrupt { .. },
                ..
            }
            | Error::PhycapId(_),
        ) => -EINVAL,
        Err(error) => panic!("no rtw89 return for {error:?}"),
    }
}

/// The C harness's result records for a read that returned 0.
fn encode_results(out: &mut Vec<u8>, info: &Info, mailbox: &Mailbox) {
    let efuse = &info.efuse;
    let tssi = &info.tssi;
    let trim = &info.pwr_trim;
    let gain = &info.efuse_gain;
    let hal = &info.hal;
    push(out, 31, efuse.valid.into(), efuse.power_k_valid.into());
    let addr = efuse.addr;
    push(
        out,
        32,
        u32::from_le_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32::from_le_bytes([addr[4], addr[5], 0, 0]),
    );
    push(out, 33, efuse.rfe_type.into(), efuse.xtal_cap.into());
    push(
        out,
        34,
        efuse.country_code[0].into(),
        efuse.country_code[1].into(),
    );
    push(out, 35, tssi.thermal[0].into(), tssi.thermal[1].into());
    for (tag, rows) in [
        (36, tssi.tssi_cck.map(|row| row.to_vec())),
        (37, tssi.tssi_mcs.map(|row| row.to_vec())),
        (38, tssi.tssi_trim.map(|row| row.to_vec())),
    ] {
        for (path, row) in rows.iter().enumerate() {
            for (group, &value) in row.iter().enumerate() {
                push(
                    out,
                    tag,
                    (path as u32) << 8 | group as u32,
                    u32::from(value as u8),
                );
            }
        }
    }
    push(
        out,
        39,
        u32::from(trim.pg_thermal_trim) | u32::from(trim.pg_pa_bias_trim) << 1,
        u32::from_le_bytes([
            trim.thermal_trim[0],
            trim.thermal_trim[1],
            trim.pa_bias_trim[0],
            trim.pa_bias_trim[1],
        ]),
    );
    push(
        out,
        40,
        u32::from(gain.offset_valid) | u32::from(gain.comp_valid) << 1,
        0,
    );
    for (tag, rows) in [(41, gain.offset), (42, gain.comp)] {
        for (path, row) in rows.iter().enumerate() {
            for (index, &value) in row.iter().enumerate() {
                push(
                    out,
                    tag,
                    (path as u32) << 8 | index as u32,
                    u32::from(value as u8),
                );
            }
        }
    }
    // ant_diversity, support_igi and thermal_prot_th stay 0 on an RTL8852BE.
    push(
        out,
        43,
        u32::from_le_bytes([hal.tx_nss, hal.rx_nss, hal.antenna_tx, hal.antenna_rx]),
        u32::from(hal.tx_path_diversity)
            | u32::from(hal.no_eht) << 2
            | u32::from(hal.support_cckpd) << 3,
    );
    push(
        out,
        44,
        mailbox.h2c_counter().into(),
        mailbox.c2h_counter().into(),
    );
}

/// The first record at which `ours` and `theirs` differ, as a message.
fn same(ours: &[u8], theirs: &[u8], what: &str) {
    if ours == theirs {
        return;
    }
    let record = ours
        .chunks(12)
        .zip(theirs.chunks(12))
        .position(|(a, b)| a != b)
        .unwrap_or(ours.len().min(theirs.len()) / 12);
    let at = record * 12;
    panic!(
        "{what}: {} and {} bytes, first difference at record {record}: ours {:?}, C {:?}",
        ours.len(),
        theirs.len(),
        &ours[at.min(ours.len())..(at + 12).min(ours.len())],
        &theirs[at.min(theirs.len())..(at + 12).min(theirs.len())],
    );
}

#[test]
#[ignore = "oracle: STELA_RTW89_EFUSE_ORACLE"]
fn efuse_decode_matches_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_EFUSE_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;

    // struct rtw8852bx_efuse's layout, as the C compiler lays it out.
    let mut layout = Vec::new();
    for (field, at) in [
        SIZE,
        PATH_A_TSSI,
        PATH_B_TSSI,
        XTAL_K,
        RFE_TYPE,
        COUNTRY_CODE,
        PATH_A_THERM,
        PATH_B_THERM,
        RX_GAIN_2G_OFDM,
        RX_GAIN_2G_CCK,
        RX_GAIN_5G_LOW,
        RX_GAIN_5G_MID,
        RX_GAIN_5G_HIGH,
        E_MAC_ADDR,
        CCK_TSSI,
        BW40_TSSI,
        BW40_1S_TSSI_5G,
        TSSI_OFFSET_SIZE,
    ]
    .into_iter()
    .enumerate()
    {
        push(&mut layout, 20, field as u32, at as u32);
    }
    assert_eq!(segment(&trace, &mut offset), layout);

    let mut results = Vec::new();
    while offset < trace.len() {
        let case = Case::decode(segment(&trace, &mut offset));
        let accesses = segment(&trace, &mut offset);
        let recorded = segment(&trace, &mut offset);
        let log_map = segment(&trace, &mut offset);
        let phycap_map = segment(&trace, &mut offset);
        let index = results.len();

        let mut io = Model::new(&case);
        let mut mailbox = mailbox();
        let result = info_setup(&mut io, case.cut, &mut mailbox);
        same(
            &encode(&io.log),
            accesses,
            &std::format!("case {index}: accesses"),
        );
        let mut ours = Vec::new();
        push(&mut ours, 30, 1, errno(&result) as u32);
        if let Ok(info) = &result {
            encode_results(&mut ours, info, &mailbox);
        }
        same(&ours, recorded, &std::format!("case {index}: results"));
        match &result {
            Ok(info) => {
                assert_eq!(log_map, &info.log_map[..], "case {index}: log_map");
                assert_eq!(phycap_map, &info.phycap_map[..], "case {index}: phycap map");
            }
            Err(_) => assert!(log_map.is_empty() && phycap_map.is_empty(), "case {index}"),
        }
        results.push(result);
    }
    // valid, rfe5, empty, corrupt, layered, slow, dav_retry, mailbox_busy,
    // phycap_wrong_id, phycap_1ss_diversity, phycap_antenna_b.
    assert_eq!(results.len(), 11);
    let valid = results[0].as_ref().unwrap();
    assert_eq!(valid.efuse.addr, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!((valid.efuse.rfe_type, valid.efuse.xtal_cap), (1, 0x3c));
    let rfe5 = results[1].as_ref().unwrap();
    assert_eq!((rfe5.efuse.rfe_type, rfe5.efuse.xtal_cap), (5, 0x2a));
    assert!(!results[2].as_ref().unwrap().efuse.valid);
    assert_eq!(
        results[3],
        Err(Error::Logical {
            dav: false,
            error: Logical::Corrupt { offset: 1212 },
        })
    );
    assert_eq!(
        results[7],
        Err(Error::Io(io::Error::Timeout {
            register: H2CREG_CTRL,
            mask: 0xff
        }))
    );
    assert_eq!(results[8], Err(Error::PhycapId(1)));
}
