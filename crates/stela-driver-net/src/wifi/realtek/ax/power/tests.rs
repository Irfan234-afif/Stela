extern crate std;

use super::*;
use crate::wifi::realtek::ax::io::field;
use alloc::{vec, vec::Vec};

/// One access, as the C oracle's harness records it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Read {
        width: u32,
        register: u32,
        value: u32,
    },
    Write {
        width: u32,
        register: u32,
        value: u32,
    },
    Delay(u64),
}

fn r8(register: u32, value: u32) -> Access {
    Access::Read {
        width: 1,
        register,
        value,
    }
}
fn r16(register: u32, value: u32) -> Access {
    Access::Read {
        width: 2,
        register,
        value,
    }
}
fn r32(register: u32, value: u32) -> Access {
    Access::Read {
        width: 4,
        register,
        value,
    }
}
fn w8(register: u32, value: u32) -> Access {
    Access::Write {
        width: 1,
        register,
        value,
    }
}
fn w16(register: u32, value: u32) -> Access {
    Access::Write {
        width: 2,
        register,
        value,
    }
}
fn w32(register: u32, value: u32) -> Access {
    Access::Write {
        width: 4,
        register,
        value,
    }
}
fn delay(microseconds: u64) -> Access {
    Access::Delay(microseconds)
}
/// An XTAL SI request the model completes at once: the write, then the poll
/// that reads it back without its poll bit.
fn xtal(request: u32) -> [Access; 2] {
    [
        w32(WLAN_XTAL_SI_CTRL, request),
        r32(WLAN_XTAL_SI_CTRL, request & !XTAL_SI_CMD_POLL),
    ]
}

/// The C oracle's record of an access: tag, register, value, each a
/// little-endian u32. Reads are tagged by width, writes by 4 plus width,
/// delays 9.
fn push(trace: &mut Vec<u8>, tag: u32, register: u32, value: u32) {
    for word in [tag, register, value] {
        trace.extend_from_slice(&word.to_le_bytes());
    }
}
fn encode(log: &[Access]) -> Vec<u8> {
    let mut trace = Vec::new();
    for access in log {
        match *access {
            Access::Read {
                width,
                register,
                value,
            } => push(&mut trace, width, register, value),
            Access::Write {
                width,
                register,
                value,
            } => push(&mut trace, 4 + width, register, value),
            Access::Delay(microseconds) => push(&mut trace, 9, 0, microseconds as u32),
        }
    }
    trace
}

/// A poll the model never answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stuck {
    SysPwr,
    AonOffPc,
    OnMac,
    OffMac,
    XtalSi,
    Efuse,
}

const MEMORY: usize = 0x1_0000;

/// The register model the C oracle's harness uses: MAC space as
/// little-endian bytes, with SYS_PW_CTRL reading RDY_SYSPWR and clearing
/// the ON/OFF MAC requests it completes, IC_PWR_STATE reporting whether the
/// WL MAC is on, XTAL SI completing every request, and the efuse answering
/// every read with `efuse(address)`.
struct Model {
    memory: Vec<u8>,
    xtal: [u8; 256],
    log: Vec<Access>,
    /// Whether accesses are logged; reads and delays are always counted.
    logging: bool,
    reads: Vec<usize>,
    waited_us: u64,
    on: bool,
    /// A WL MAC that a power-off does not turn off.
    stays_on: bool,
    stuck: Option<Stuck>,
}

fn efuse(address: u32) -> u8 {
    (address * 7 + 3) as u8
}

/// The registers the model gives behavior; each is reached 32 bits at a
/// time.
fn special(register: u32) -> bool {
    [SYS_PW_CTRL, EFUSE_CTRL, WLAN_XTAL_SI_CTRL, IC_PWR_STATE]
        .iter()
        .any(|&at| (at..at + 4).contains(&register))
}

impl Model {
    fn zeroed() -> Self {
        Self::with(vec![0; MEMORY])
    }
    /// The oracle's starting memory.
    fn patterned() -> Self {
        Self::with((0..MEMORY).map(|at| (at * 37 + 11) as u8).collect())
    }
    fn with(memory: Vec<u8>) -> Self {
        Self {
            memory,
            xtal: [0; 256],
            log: Vec::new(),
            logging: true,
            reads: vec![0; MEMORY],
            waited_us: 0,
            on: false,
            stays_on: false,
            stuck: None,
        }
    }
    fn get(&self, register: u32, width: u32) -> u32 {
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
        assert!(
            !special(register) || (width == 4 && register.is_multiple_of(4)),
            "{register:#x} reached {width} bytes wide"
        );
    }
    fn read(&mut self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        let mut value = self.get(register, width);
        match register {
            SYS_PW_CTRL if self.stuck == Some(Stuck::SysPwr) => value &= !RDY_SYSPWR,
            SYS_PW_CTRL => value |= RDY_SYSPWR,
            AFE_LDO_CTRL if self.stuck == Some(Stuck::AonOffPc) => value &= !AON_OFF_PC_EN,
            IC_PWR_STATE => {
                value = (value & !WLMAC_PWR_STE_MASK)
                    | prep(u32::from(self.on) * MAC_AX_MAC_ON, WLMAC_PWR_STE_MASK);
            }
            _ => {}
        }
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
            SYS_PW_CTRL => {
                if value & APFN_ONMAC != 0 && self.stuck != Some(Stuck::OnMac) {
                    stored &= !APFN_ONMAC;
                    self.on = true;
                }
                if value & APFM_OFFMAC != 0 && self.stuck != Some(Stuck::OffMac) {
                    stored &= !APFM_OFFMAC;
                    self.on &= self.stays_on;
                }
            }
            WLAN_XTAL_SI_CTRL if self.stuck != Some(Stuck::XtalSi) => {
                let offset = field(value, XTAL_SI_ADDR_MASK) as usize;
                let data = field(value, XTAL_SI_DATA_MASK) as u8;
                let mask = field(value, XTAL_SI_BITMASK_MASK) as u8;
                stored = value & !XTAL_SI_CMD_POLL;
                if field(value, XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_WRITE {
                    self.xtal[offset] = (self.xtal[offset] & !mask) | (data & mask);
                } else {
                    stored = (stored & !XTAL_SI_DATA_MASK)
                        | prep(u32::from(self.xtal[offset]), XTAL_SI_DATA_MASK);
                }
            }
            EFUSE_CTRL if self.stuck == Some(Stuck::Efuse) => stored = value & !EF_RDY,
            EFUSE_CTRL => {
                let address = field(value, EF_ADDR_MASK);
                stored = (value & !EF_DATA_MASK) | EF_RDY | u32::from(efuse(address));
            }
            _ => {}
        }
        self.set(register, width, stored);
    }
    fn count(&self, access: Access) -> usize {
        self.log.iter().filter(|seen| **seen == access).count()
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

/// The accesses of a cold first power-on (cut CCV, RFE 0, efuse not read)
/// of a zeroed model, transcribed from rtw89_mac_power_switch,
/// rtw8852b_pwr_on_func, rtw89_efuse_read_fw_secure_ax and
/// rtw89_mac_update_scoreboard.
fn cold_power_on() -> Vec<Access> {
    let mut expected = vec![
        // rtw89_mac_reset_pwr_state_ax
        r32(IC_PWR_STATE, 0),
        // rtw8852b_pwr_on_func; SYS_PW_CTRL reads RDY_SYSPWR throughout.
        r32(SYS_PW_CTRL, 0x2_0000),
        w32(SYS_PW_CTRL, 0x2_0000),
        r32(SYS_PW_CTRL, 0x2_0000),
        w32(SYS_PW_CTRL, 0x6_0000),
        r32(WLLPS_CTRL, 0),
        w32(WLLPS_CTRL, 0x2),
        r32(SYS_PW_CTRL, 0x6_0000),
        w32(SYS_PW_CTRL, 0x6_0000),
        r32(SYS_PW_CTRL, 0x6_0000),
        w32(SYS_PW_CTRL, 0x6_0000),
        r32(SYS_PW_CTRL, 0x6_0000),
        r32(AFE_LDO_CTRL, 0),
        w32(AFE_LDO_CTRL, 0x80_0000),
        r32(AFE_LDO_CTRL, 0x80_0000),
        // rtw8852b_pwr_sps_dig_off, RFE 0: C1 1, C3 3.
        r32(SPS_DIG_OFF_CTRL0, 0),
        w32(SPS_DIG_OFF_CTRL0, 0x01),
        r32(SPS_DIG_OFF_CTRL0, 0x01),
        w32(SPS_DIG_OFF_CTRL0, 0x31),
        r32(SYS_PW_CTRL, 0x6_0000),
        w32(SYS_PW_CTRL, 0x7_0000),
        r32(SYS_PW_CTRL, 0x7_0000),
        w32(SYS_PW_CTRL, 0x7_0100),
        // The chip has cleared APFN_ONMAC.
        r32(SYS_PW_CTRL, 0x7_0000),
        r8(PLATFORM_ENABLE, 0),
        w8(PLATFORM_ENABLE, 1),
        r8(PLATFORM_ENABLE, 1),
        w8(PLATFORM_ENABLE, 0),
        r8(PLATFORM_ENABLE, 0),
        w8(PLATFORM_ENABLE, 1),
        r8(PLATFORM_ENABLE, 1),
        w8(PLATFORM_ENABLE, 0),
        r8(PLATFORM_ENABLE, 0),
        w8(PLATFORM_ENABLE, 1),
        r32(SYS_SDIO_CTRL, 0),
        w32(SYS_SDIO_CTRL, 0),
        r32(SYS_ADIE_PAD_PWR_CTRL, 0),
        w32(SYS_ADIE_PAD_PWR_CTRL, 0x40),
    ];
    expected.extend(xtal(0x8040_4090));
    expected.extend([
        r32(SYS_ADIE_PAD_PWR_CTRL, 0x40),
        w32(SYS_ADIE_PAD_PWR_CTRL, 0x60),
    ]);
    for request in [
        0x8020_2090,
        0x8004_0490,
        0x8008_0890,
        0x8010_0090,
        0x8001_0190,
        0x8002_0290,
        0x8080_0090,
        0x8002_00a1,
        0x8070_0024,
        0x800f_0026,
    ] {
        expected.extend(xtal(request));
    }
    expected.extend([
        r32(PMC_DBG_CTRL2, 0),
        w32(PMC_DBG_CTRL2, 0x4),
        r32(SYS_ISO_CTRL, 0),
        w32(SYS_ISO_CTRL, 0x100),
        r32(SYS_ISO_CTRL, 0x100),
        w32(SYS_ISO_CTRL, 0x100),
        delay(1000),
        r32(SYS_ISO_CTRL, 0x100),
        w32(SYS_ISO_CTRL, 0x100),
        r32(PMC_DBG_CTRL2, 0x4),
        w32(PMC_DBG_CTRL2, 0),
        // func_en
        r32(DMAC_FUNC_EN, 0),
        w32(DMAC_FUNC_EN, 0x7fff_8000),
        r32(CMAC_FUNC_EN, 0),
        w32(CMAC_FUNC_EN, 0x7000_803f),
        r32(EECS_EESK_FUNC_SEL, 0),
        w32(EECS_EESK_FUNC_SEL, 0x10),
        // rtw89_enable_efuse_pwr_cut_ddv
        r8(PMC_DBG_CTRL2, 0),
        w8(PMC_DBG_CTRL2, 0x4),
        r16(SYS_ISO_CTRL, 0x0100),
        w16(SYS_ISO_CTRL, 0x4100),
        delay(1000),
        r16(SYS_ISO_CTRL, 0x4100),
        w16(SYS_ISO_CTRL, 0xc100),
        r16(SYS_ISO_CTRL, 0xc100),
        w16(SYS_ISO_CTRL, 0xc000),
        // One byte each from 0x5ec, after a step.
        w32(EFUSE_CTRL, 0x05ec_0000),
        delay(1),
        r32(EFUSE_CTRL, 0x25ec_0077),
        w32(EFUSE_CTRL, 0x05ed_0000),
        delay(1),
        r32(EFUSE_CTRL, 0x25ed_007e),
        // rtw89_disable_efuse_pwr_cut_ddv
        r16(SYS_ISO_CTRL, 0xc000),
        w16(SYS_ISO_CTRL, 0xc100),
        r16(SYS_ISO_CTRL, 0xc100),
        w16(SYS_ISO_CTRL, 0x4100),
        delay(1000),
        r16(SYS_ISO_CTRL, 0x4100),
        w16(SYS_ISO_CTRL, 0x0100),
        r8(PMC_DBG_CTRL2, 0x4),
        w8(PMC_DBG_CTRL2, 0),
        // rtw89_mac_update_scoreboard
        w8(SCOREBOARD + 3, 0x81),
    ]);
    expected
}

/// The accesses of the power-off after [`cold_power_on`], transcribed from
/// rtw8852b_pwr_off_func and rtw89_mac_update_scoreboard.
fn power_off_after_cold_power_on() -> Vec<Access> {
    let mut expected = Vec::new();
    for request in [
        0x8010_1090,
        0x8008_0090,
        0x8004_0090,
        0x8001_0080,
        0x8001_0081,
        0x8080_8090,
        0x8002_0090,
        0x8001_0090,
    ] {
        expected.extend(xtal(request));
    }
    expected.extend([
        r32(SYS_PW_CTRL, 0x7_0000),
        w32(SYS_PW_CTRL, 0x7_0000),
        r32(WLRF_CTRL, 0),
        w32(WLRF_CTRL, 0),
        r8(SYS_FUNC_EN, 0),
        w8(SYS_FUNC_EN, 0),
        r32(SYS_ADIE_PAD_PWR_CTRL, 0x60),
        w32(SYS_ADIE_PAD_PWR_CTRL, 0x40),
    ]);
    expected.extend(xtal(0x8020_0090));
    expected.extend([
        r32(SYS_ADIE_PAD_PWR_CTRL, 0x40),
        w32(SYS_ADIE_PAD_PWR_CTRL, 0),
    ]);
    expected.extend(xtal(0x8040_0090));
    expected.extend([
        r32(SYS_PW_CTRL, 0x7_0000),
        w32(SYS_PW_CTRL, 0x7_0200),
        // The chip has cleared APFM_OFFMAC.
        r32(SYS_PW_CTRL, 0x7_0000),
        w32(WLLPS_CTRL, SW_LPS_OPTION),
        r32(SYS_SWR_CTRL1, 0),
        w32(SYS_SWR_CTRL1, 0x400),
        r32(SPS_DIG_ON_CTRL0, 0),
        w32(SPS_DIG_ON_CTRL0, 0x6_0000),
        r32(SYS_PW_CTRL, 0x7_0000),
        w32(SYS_PW_CTRL, 0x7_0400),
        w8(SCOREBOARD + 3, 0x80),
    ]);
    expected
}

#[test]
fn power_on_and_off_follow_rtw89_access_for_access() {
    let mut io = Model::zeroed();
    let inputs = Inputs::first(CHIP_CCV);
    assert_eq!(
        power_on(&mut io, &inputs),
        Ok(PoweredOn {
            first_failure: None,
            secure_efuse: Some(Ok([0x77, 0x7e])),
        })
    );
    assert_eq!(io.log, cold_power_on());
    assert!(io.on);
    io.log.clear();
    assert_eq!(power_off(&mut io, &inputs), Ok(()));
    assert_eq!(io.log, power_off_after_cold_power_on());
    assert!(!io.on);
}

/// The values written to `register`, in order.
fn writes(log: &[Access], register: u32) -> Vec<u32> {
    log.iter()
        .filter_map(|access| match *access {
            Access::Write {
                register: at,
                value,
                ..
            } if at == register => Some(value),
            _ => None,
        })
        .collect()
}

#[test]
fn rfe_type_5_alone_sets_the_sps_analog_value_and_four_digital_fields() {
    let mut five = Model::zeroed();
    let inputs = Inputs {
        rfe_type: 5,
        ..Inputs::first(CHIP_CCV)
    };
    power_on(&mut five, &inputs).unwrap();
    assert_eq!(five.log[1], w16(SPS_ANA_ON_CTRL2, 0x4a82));
    // C1 1, C2 1, C3 2, R1 1.
    assert_eq!(
        writes(&five.log, SPS_DIG_OFF_CTRL0),
        [0x01, 0x05, 0x25, 0x65]
    );
    five.log.clear();
    power_off(&mut five, &inputs).unwrap();
    assert_eq!(five.log[0], w16(SPS_ANA_ON_CTRL2, 0x4a82));

    // Any other RFE type, the first power-on's 0 among them, takes the
    // other branch: no analog value, C1 1 and C3 3.
    for rfe_type in [0, 1, 4, 6] {
        let mut other = Model::zeroed();
        let inputs = Inputs {
            rfe_type,
            ..Inputs::first(CHIP_CCV)
        };
        power_on(&mut other, &inputs).unwrap();
        power_off(&mut other, &inputs).unwrap();
        assert!(writes(&other.log, SPS_ANA_ON_CTRL2).is_empty());
        assert_eq!(writes(&other.log, SPS_DIG_OFF_CTRL0), [0x01, 0x31]);
    }
}

/// The accesses between the power-on's PMC write-mask release and its DMAC
/// function enable.
fn before_func_en(log: &[Access]) -> &[Access] {
    let release = log
        .iter()
        .position(|access| *access == w32(PMC_DBG_CTRL2, 0))
        .unwrap();
    let func_en = log
        .iter()
        .position(|access| *access == r32(DMAC_FUNC_EN, 0))
        .unwrap();
    &log[release + 1..func_en]
}

#[test]
fn a_valid_efuse_without_power_calibration_trims_the_regulator_and_a_cbv_its_hci_ldo() {
    let run = |cut, efuse_valid, power_k_valid| {
        let mut io = Model::zeroed();
        let inputs = Inputs {
            cut,
            efuse_valid,
            power_k_valid,
            probe_done: true,
            rfe_type: 0,
        };
        power_on(&mut io, &inputs).unwrap();
        before_func_en(&io.log).to_vec()
    };
    let regulator = [
        r32(SPS_DIG_ON_CTRL0, 0),
        w32(SPS_DIG_ON_CTRL0, 0x9),
        r32(SPS_DIG_ON_CTRL0, 0x9),
        w32(SPS_DIG_ON_CTRL0, 0x0280_0009),
    ];
    let mut cbv = regulator.to_vec();
    cbv.extend([
        r32(PMC_DBG_CTRL2, 0),
        w32(PMC_DBG_CTRL2, 0x4),
        r16(HCI_LDO_CTRL, 0),
        w16(HCI_LDO_CTRL, 0xa),
        r32(PMC_DBG_CTRL2, 0x4),
        w32(PMC_DBG_CTRL2, 0),
    ]);
    assert_eq!(run(CHIP_CBV, true, false), cbv);
    assert_eq!(run(CHIP_CCV, true, false), regulator);
    assert_eq!(run(CHIP_CAV, true, false), regulator);
    for cut in [CHIP_CAV, CHIP_CBV, CHIP_CCV] {
        assert_eq!(run(cut, true, true), []);
        assert_eq!(run(cut, false, false), []);
        assert_eq!(run(cut, false, true), []);
    }
}

#[test]
fn only_the_first_power_on_reads_the_secure_efuse_bytes_and_a_cav_bursts_them() {
    let mut io = Model::zeroed();
    let done = Inputs {
        probe_done: true,
        ..Inputs::first(CHIP_CCV)
    };
    let powered = power_on(&mut io, &done).unwrap();
    assert_eq!(powered.secure_efuse, None);
    assert_eq!(io.reads[EFUSE_CTRL as usize], 0);
    assert!(io.log.iter().all(|access| !matches!(
        access,
        Access::Read {
            register: EFUSE_CTRL | EFUSE_CTRL_1_V1,
            ..
        } | Access::Write {
            register: EFUSE_CTRL | EFUSE_CTRL_1_V1,
            ..
        }
    )));
    assert_eq!(io.log.last(), Some(&w8(SCOREBOARD + 3, 0x81)));

    let mut io = Model::zeroed();
    let powered = power_on(&mut io, &Inputs::first(CHIP_CAV)).unwrap();
    assert_eq!(powered.secure_efuse, Some(Ok([0x77, 0x7e])));
    let burst = io
        .log
        .iter()
        .position(|access| *access == w32(EFUSE_CTRL_1_V1, EF_BURST))
        .unwrap();
    let first = io
        .log
        .iter()
        .position(|access| *access == w32(EFUSE_CTRL, 0x05ec_0000))
        .unwrap();
    let idle = io
        .log
        .iter()
        .position(|access| *access == w32(EFUSE_CTRL_1_V1, 0))
        .unwrap();
    assert_eq!(io.log[burst - 1], r32(EFUSE_CTRL_1_V1, 0));
    assert_eq!(first, burst + 1);
    assert_eq!(io.log[idle - 1], r32(EFUSE_CTRL_1_V1, EF_BURST));
    assert_eq!(io.log[idle - 2], r32(EFUSE_CTRL, 0x25ed_007e));
}

#[test]
fn a_poll_that_never_answers_names_its_register_after_its_bound_in_steps() {
    fn timeout<T>(register: u32, mask: u32) -> Result<T, Error> {
        Err(Error::Io(io::Error::Timeout { register, mask }))
    }
    for (stuck, register, mask) in [
        (Stuck::SysPwr, SYS_PW_CTRL, RDY_SYSPWR),
        (Stuck::AonOffPc, AFE_LDO_CTRL, AON_OFF_PC_EN),
        (Stuck::OnMac, SYS_PW_CTRL, APFN_ONMAC),
    ] {
        let mut io = Model::zeroed();
        io.stuck = Some(stuck);
        let inputs = Inputs::first(CHIP_CCV);
        assert_eq!(
            power_on(&mut io, &inputs),
            timeout(register, mask),
            "{stuck:?}"
        );
        // Both attempts read 21 times, 1000 us apart, up to 20000 us; the
        // power-off between them waits on nothing.
        assert_eq!(io.count(delay(1000)), 2 * 20, "{stuck:?}");
        assert_eq!(writes(&io.log, SCOREBOARD + 3), [0x80], "{stuck:?}");
        assert_eq!(io.reads[EFUSE_CTRL as usize], 0, "{stuck:?}");
        // The second attempt ends in its poll: 21 reads with a step between,
        // after the write it waits on.
        let poll = &io.log[io.log.len() - 41..];
        for (at, access) in poll.iter().enumerate() {
            if at.is_multiple_of(2) {
                assert!(
                    matches!(access, Access::Read { register: seen, .. } if *seen == register),
                    "{stuck:?} {access:?}"
                );
            } else {
                assert_eq!(*access, delay(1000), "{stuck:?}");
            }
        }
        assert!(matches!(
            io.log[io.log.len() - 42],
            Access::Write { register: seen, .. } if seen == register
        ));
    }

    let mut io = Model::zeroed();
    io.stuck = Some(Stuck::OffMac);
    let inputs = Inputs::first(CHIP_CCV);
    power_on(&mut io, &inputs).unwrap();
    io.log.clear();
    assert_eq!(
        power_off(&mut io, &inputs),
        timeout(SYS_PW_CTRL, APFM_OFFMAC)
    );
    assert_eq!(io.count(delay(1000)), 20);
    assert_eq!(io.log.last(), Some(&r32(SYS_PW_CTRL, 0x7_0200)));

    // XTAL SI is read every 50 us for up to 50 ms, in the first attempt and
    // in the power-off whose failure rtw89 ignores. That power-off stops at
    // its first request, before APFM_OFFMAC, so the WL MAC the first attempt
    // turned on stays on and the second attempt is refused.
    let mut io = Model::zeroed();
    io.stuck = Some(Stuck::XtalSi);
    let mut alone = Model::zeroed();
    alone.stuck = Some(Stuck::XtalSi);
    assert_eq!(
        switch_on(&mut alone, &inputs),
        timeout(WLAN_XTAL_SI_CTRL, XTAL_SI_CMD_POLL)
    );
    assert_eq!(power_on(&mut io, &inputs), Err(Error::AlreadyOn));
    assert_eq!(io.reads[WLAN_XTAL_SI_CTRL as usize], 2 * 1001);
    assert_eq!(io.count(delay(50)), 2 * 1000);
    assert_eq!(io.reads[IC_PWR_STATE as usize], 2);
}

#[test]
fn an_efuse_byte_that_never_reads_ready_fails_five_attempts_without_failing_power_on() {
    let mut io = Model::zeroed();
    io.stuck = Some(Stuck::Efuse);
    io.logging = false;
    let powered = power_on(&mut io, &Inputs::first(CHIP_CCV)).unwrap();
    assert_eq!(
        powered.secure_efuse,
        Some(Err(io::Error::Timeout {
            register: EFUSE_CTRL,
            mask: EF_RDY
        }))
    );
    assert_eq!(powered.first_failure, None);
    // Each attempt powers the efuse up (1000 us), then reads its first byte
    // once a microsecond for a second: one step before the first read, and
    // the bound counted in steps. A failed attempt skips the power-down.
    assert_eq!(io.reads[EFUSE_CTRL as usize], 5 * 1_000_000);
    assert_eq!(io.waited_us, 1000 + 5 * (1000 + 1_000_000));
    // The power-on still ends with its scoreboard notice.
    assert_eq!(io.get(SCOREBOARD + 3, 1), 0x81);
}

#[test]
fn a_chip_left_on_is_powered_off_first_and_one_that_stays_on_is_refused() {
    let inputs = Inputs::first(CHIP_CCV);
    let mut warm = Model::zeroed();
    warm.on = true;
    assert_eq!(
        power_on(&mut warm, &inputs),
        Ok(PoweredOn {
            first_failure: Some(Error::AlreadyOn),
            secure_efuse: Some(Ok([0x77, 0x7e])),
        })
    );
    // rtw89_mac_pwr_on's retry: the refused state read, then exactly a
    // power-off and a power-on.
    let mut direct = Model::zeroed();
    direct.on = true;
    power_off(&mut direct, &inputs).unwrap();
    assert!(!direct.on);
    power_on(&mut direct, &inputs).unwrap();
    let mut expected = vec![r32(IC_PWR_STATE, 0x100)];
    expected.extend(direct.log);
    assert_eq!(warm.log, expected);
    assert!(warm.on);

    let mut stuck = Model::zeroed();
    stuck.on = true;
    stuck.stays_on = true;
    assert_eq!(power_on(&mut stuck, &inputs), Err(Error::AlreadyOn));
    assert_eq!(stuck.reads[IC_PWR_STATE as usize], 2);
    assert_eq!(stuck.log[0], r32(IC_PWR_STATE, 0x100));
    assert_eq!(stuck.log.last(), Some(&r32(IC_PWR_STATE, 0x100)));
    assert!(writes(&stuck.log, DMAC_FUNC_EN).is_empty());
    assert_eq!(writes(&stuck.log, SCOREBOARD + 3), [0x80]);
}

/// One case of the C oracle, in its order.
#[derive(Clone, Copy, Debug)]
struct Case {
    inputs: Inputs,
    warm: bool,
}

fn oracle_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for cut in [CHIP_CAV, CHIP_CBV, CHIP_CCV] {
        for rfe_type in [0, 5] {
            for (efuse_valid, power_k_valid) in [(false, false), (true, false), (true, true)] {
                for warm in [false, true] {
                    for probe_done in [false, true] {
                        cases.push(Case {
                            inputs: Inputs {
                                cut,
                                rfe_type,
                                efuse_valid,
                                power_k_valid,
                                probe_done,
                            },
                            warm,
                        });
                    }
                }
            }
        }
    }
    cases
}

/// The next length-prefixed segment of the oracle's trace.
fn segment<'a>(trace: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length = u32::from_le_bytes(trace[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let segment = &trace[*offset..*offset + length];
    *offset += length;
    segment
}

#[test]
#[ignore = "oracle: STELA_RTW89_POWER_ORACLE"]
fn power_on_and_off_register_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_POWER_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;
    let cases = oracle_cases();
    assert_eq!(cases.len(), 72);
    for case in cases {
        let mut io = Model::patterned();
        io.on = case.warm;
        let result = power_on(&mut io, &case.inputs);
        let mut on = encode(&io.log);
        // The harness records the two bytes rtw89 hands its MSS recognizers,
        // which it does only when they are not both 0xff, then the return.
        let (recognized, bytes) = match result {
            Ok(PoweredOn {
                secure_efuse: Some(Ok(bytes)),
                ..
            }) if bytes != [0xff; 2] => (1, u32::from(bytes[0]) << 8 | u32::from(bytes[1])),
            _ => (0, 0),
        };
        push(&mut on, 10, recognized, bytes);
        push(&mut on, 11, 0, if result.is_ok() { 0 } else { u32::MAX });
        io.log.clear();
        power_off(&mut io, &case.inputs).unwrap();
        let off = encode(&io.log);
        assert_eq!(segment(&trace, &mut offset), on, "power-on, {case:?}");
        assert_eq!(segment(&trace, &mut offset), off, "power-off, {case:?}");
    }
    assert_eq!(offset, trace.len());
}
