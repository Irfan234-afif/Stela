use super::*;
use alloc::{collections::BTreeMap, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Read(u32),
    Write(u32, u32),
    Delay(u64),
}

/// A register file that answers SWSI and XTAL SI as the chip does, and
/// records every access.
#[derive(Default)]
struct Model {
    registers: BTreeMap<u32, u32>,
    log: Vec<Access>,
    /// RF registers by (path, address).
    rf: BTreeMap<(u32, u32), u32>,
    /// Reads of R_SWSI_V1 that still show the write-busy bit.
    swsi_busy: usize,
    /// Whether SWSI never finishes a read.
    swsi_stuck: bool,
    /// XTAL SI registers by offset.
    xtal: BTreeMap<u32, u32>,
    /// Reads of the XTAL SI control register that still show the poll bit.
    xtal_busy: usize,
}

const SWSI: u32 = CR_BASE + SWSI_V1;

impl Model {
    fn get(&self, register: u32) -> u32 {
        self.registers.get(&register).copied().unwrap_or(0)
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        Ok((self.read32(register & !3)? >> ((register & 3) * 8)) as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        Ok((self.read32(register & !3)? >> ((register & 3) * 8)) as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        self.log.push(Access::Read(register));
        match register {
            SWSI if self.swsi_busy > 0 => {
                self.swsi_busy -= 1;
                Ok(SWSI_W_BUSY_V1)
            }
            WLAN_XTAL_SI_CTRL if self.xtal_busy > 0 => {
                self.xtal_busy -= 1;
                Ok(self.get(register) | XTAL_SI_CMD_POLL)
            }
            _ => Ok(self.get(register)),
        }
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        self.write32(register, u32::from(value))
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        self.write32(register, u32::from(value))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.log.push(Access::Write(register, value));
        match register {
            r if r == CR_BASE + SWSI_READ_ADDR_V1 => {
                let path = field(value, SWSI_READ_ADDR_PATH_V1);
                let address = field(value, SWSI_READ_ADDR_ADDR_V1);
                let data = self.rf.get(&(path, address)).copied().unwrap_or(0);
                let done = if self.swsi_stuck {
                    0
                } else {
                    SWSI_R_DATA_DONE_V1
                };
                self.registers.insert(SWSI, done | data);
            }
            r if r == CR_BASE + SWSI_DATA_V1 => {
                let key = (
                    field(value, SWSI_DATA_PATH_V1),
                    field(value, SWSI_DATA_ADDR_V1),
                );
                self.rf.insert(key, field(value, SWSI_DATA_VAL_V1));
            }
            WLAN_XTAL_SI_CTRL => {
                let offset = field(value, XTAL_SI_ADDR_MASK);
                let mut done = value & !XTAL_SI_CMD_POLL;
                if field(value, XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_READ {
                    let data = self.xtal.get(&offset).copied().unwrap_or(0);
                    done = (done & !XTAL_SI_DATA_MASK) | prep(data, XTAL_SI_DATA_MASK);
                }
                self.registers.insert(register, done);
                return Ok(());
            }
            _ => {}
        }
        self.registers.insert(register, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.log.push(Access::Delay(microseconds));
    }
}

#[test]
fn masks_read_modify_write_as_rtw89_core_h() {
    let mut io = Model::default();
    io.registers.insert(0x100, 0xaaaa_5555);
    assert_eq!(io.read32_mask(0x100, 0x0000_ff00), Ok(0x55));
    io.write32_mask(0x100, 0x00ff_0000, 0x1ff).unwrap();
    assert_eq!(io.get(0x100), 0xaaff_5555);
    io.write32_set(0x100, 0x0000_000f).unwrap();
    io.write32_clr(0x100, 0xa000_0000).unwrap();
    assert_eq!(io.get(0x100), 0x0aff_555f);
    // Each helper reads before it writes, as its rtw89 counterpart does.
    assert_eq!(
        io.log,
        [
            Access::Read(0x100),
            Access::Read(0x100),
            Access::Write(0x100, 0xaaff_5555),
            Access::Read(0x100),
            Access::Write(0x100, 0xaaff_555f),
            Access::Read(0x100),
            Access::Write(0x100, 0x0aff_555f),
        ]
    );
    assert_eq!(
        io.write32_mask(0x102, 1, 1),
        Err(Error::Register { register: 0x102 })
    );
    assert_eq!(field(0xf0, 0), 0);
    assert_eq!(prep(0x3, 0x30), 0x30);
    assert_eq!(prep(0x13, 0x30), 0x30);
}

#[test]
fn bb_registers_sit_behind_cr_base() {
    let mut io = Model::default();
    io.registers.insert(0x1_4000, 0x1234_5678);
    assert_eq!(io.phy_read32(0x4000), Ok(0x1234_5678));
    assert_eq!(io.phy_read32_mask(0x4000, 0xff00_0000), Ok(0x12));
    io.phy_write32_mask(0x4000, 0x0000_00ff, 0xab).unwrap();
    io.phy_write32_set(0x4004, 1).unwrap();
    io.phy_write32_clr(0x4004, 1).unwrap();
    assert_eq!(io.get(0x1_4000), 0x1234_56ab);
    assert!(io.log.iter().all(|access| match access {
        Access::Read(at) | Access::Write(at, _) => *at >= CR_BASE,
        Access::Delay(_) => false,
    }));
    assert_eq!(
        io.phy_read32(u32::MAX),
        Err(Error::Register { register: u32::MAX })
    );
}

#[test]
fn an_adsel_rf_address_is_reached_directly_through_the_bb_window() {
    let mut io = Model::default();
    // Path B's register 0x18: 0xf000 + 0x18 * 4, behind cr_base.
    io.registers.insert(0x1_f060, 0xfff0_1234);
    assert_eq!(io.read_rf(1, RF_ADDR_ADSEL | 0x18, MASKDWORD), Ok(0x0_1234));
    io.log.clear();
    io.write_rf(0, RF_ADDR_ADSEL | 0x118, 0x0000_0f00, 0x5)
        .unwrap();
    // The address keeps its low byte; the write is followed by 1 us.
    assert_eq!(
        io.log,
        [
            Access::Read(0x1_e060),
            Access::Write(0x1_e060, 0x500),
            Access::Delay(1),
        ]
    );
    assert_eq!(io.read_rf(2, 0, RFREG_MASK), Err(Error::RfPath(2)));
    assert_eq!(io.write_rf(7, 0, RFREG_MASK, 0), Err(Error::RfPath(7)));
}

#[test]
fn an_swsi_rf_read_waits_for_idle_then_for_its_data() {
    let mut io = Model::default();
    io.rf.insert((1, 0x18), 0x3_4567);
    io.swsi_busy = 2;
    assert_eq!(io.read_rf(1, 0x18, RFREG_MASK), Ok(0x3_4567));
    let request = CR_BASE + SWSI_READ_ADDR_V1;
    assert_eq!(
        io.log,
        [
            // Busy twice: one read each, the write-busy bit set.
            Access::Read(SWSI),
            Access::Delay(1),
            Access::Read(SWSI),
            Access::Delay(1),
            // Idle: the write-busy read, then the read-busy read.
            Access::Read(SWSI),
            Access::Read(SWSI),
            Access::Read(request),
            Access::Write(request, 0x118),
            Access::Delay(2),
            Access::Read(SWSI),
            Access::Read(SWSI),
        ]
    );
}

#[test]
fn swsi_that_stays_busy_or_never_answers_times_out_after_31_looks() {
    let mut io = Model {
        swsi_busy: usize::MAX,
        ..Model::default()
    };
    assert_eq!(
        io.read_rf(0, 0x10, RFREG_MASK),
        Err(Error::Timeout {
            register: SWSI,
            mask: SWSI_W_BUSY_V1 | SWSI_R_BUSY_V1
        })
    );
    let looks = |log: &[Access]| {
        log.iter()
            .filter(|access| **access == Access::Read(SWSI))
            .count()
    };
    assert_eq!(looks(&io.log), 31);
    let mut io = Model {
        swsi_stuck: true,
        ..Model::default()
    };
    assert_eq!(
        io.read_rf(0, 0x10, RFREG_MASK),
        Err(Error::Timeout {
            register: SWSI,
            mask: SWSI_R_DATA_DONE_V1
        })
    );
    // Two reads for idle, then 31 for the data.
    assert_eq!(looks(&io.log), 33);
}

#[test]
fn an_swsi_rf_write_carries_its_mask_and_shifted_data() {
    let mut io = Model::default();
    io.write_rf(1, 0xef, 0x0_f000, 0xa).unwrap();
    assert_eq!(io.get(CR_BASE + SWSI_BIT_MASK_V1), 0x0_f000);
    let data = io.get(CR_BASE + SWSI_DATA_V1);
    assert_eq!(field(data, SWSI_DATA_BIT_MASK_EN_V1), 1);
    assert_eq!(field(data, SWSI_DATA_PATH_V1), 1);
    assert_eq!(field(data, SWSI_DATA_ADDR_V1), 0xef);
    assert_eq!(field(data, SWSI_DATA_VAL_V1), 0xa000);
    // A whole-register write sends no mask.
    io.log.clear();
    io.write_rf(0, 0x00, MASKDWORD, 0x12345).unwrap();
    assert_eq!(
        io.log[2..],
        [
            Access::Read(CR_BASE + SWSI_DATA_V1),
            Access::Write(CR_BASE + SWSI_DATA_V1, 0x0001_2345),
        ]
    );
}

#[test]
fn xtal_si_requests_poll_every_50_us_for_50_ms() {
    let mut io = Model::default();
    io.xtal.insert(u32::from(XTAL_SI_CV), 0x37);
    io.xtal_busy = 3;
    io.registers.insert(SYS_CFG1, 0x0001_1f00);
    assert_eq!(
        io.chip_version(),
        Ok(ChipVersion {
            cut: 1,
            acv: Some(7)
        })
    );
    assert_eq!(
        io.log[1],
        Access::Write(WLAN_XTAL_SI_CTRL, 0x8100_0041),
        "read mode, offset 0x41, poll bit"
    );
    assert_eq!(
        io.log
            .iter()
            .filter(|access| **access == Access::Delay(50))
            .count(),
        3
    );
    io.log.clear();
    io.write_xtal_si(0x90, 0x12, 0x3f).unwrap();
    assert_eq!(io.log[0], Access::Write(WLAN_XTAL_SI_CTRL, 0x803f_1290));
    let mut io = Model {
        xtal_busy: usize::MAX,
        ..Model::default()
    };
    assert_eq!(
        io.read_xtal_si(0x41),
        Err(Error::Timeout {
            register: WLAN_XTAL_SI_CTRL,
            mask: XTAL_SI_CMD_POLL
        })
    );
    let reads = io
        .log
        .iter()
        .filter(|access| **access == Access::Read(WLAN_XTAL_SI_CTRL))
        .count();
    assert_eq!(reads, 50_000 / 50 + 1);
    // rtw89 leaves the analog cut unset when XTAL SI does not answer.
    io.registers.insert(SYS_CFG1, 0x0000_2000);
    io.xtal_busy = usize::MAX;
    assert_eq!(io.chip_version(), Ok(ChipVersion { cut: 2, acv: None }));
}

#[test]
fn native_io_bounds_its_window_and_retries_dead_cmac_reads() {
    use core::sync::atomic::AtomicU32;
    let memory: Arc<Vec<AtomicU32>> =
        Arc::new((0..BAR_BYTES / 4).map(|_| AtomicU32::new(0)).collect());
    let kept = Arc::downgrade(&memory);
    let base = NonNull::new(memory[0].as_ptr().cast::<u8>()).unwrap();
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    // SAFETY: the window is this test's own memory, which `memory` keeps;
    // nothing else reaches it.
    let refused = unsafe { NativeIo::new(base, BAR_BYTES - 4, memory.clone(), clock) };
    assert!(matches!(refused, Err(Error::Window { .. })));
    // SAFETY: as above.
    let unaligned = unsafe {
        NativeIo::new(
            NonNull::new(base.as_ptr().wrapping_add(2)).unwrap(),
            BAR_BYTES,
            memory.clone(),
            clock,
        )
    };
    assert!(matches!(unaligned, Err(Error::Window { .. })));
    // SAFETY: as above.
    let mut io = unsafe { NativeIo::new(base, BAR_BYTES, memory, clock) }.unwrap();
    io.write32(0x1_fffc, 0x0102_0304).unwrap();
    assert_eq!(io.read32(0x1_fffc), Ok(0x0102_0304));
    assert_eq!(io.read16(0x1_fffe), Ok(0x0102));
    assert_eq!(io.read8(0x1_fffd), Ok(0x03));
    for (register, width) in [(0x2_0000, 4), (0x1_fffe, 4), (u32::MAX, 1)] {
        let read = match width {
            1 => io.read8(register).map(u32::from),
            _ => io.read32(register),
        };
        assert_eq!(read, Err(Error::Register { register }));
    }
    // A dead register outside CMAC is reported as read.
    io.write32(0x0100, R32_DEAD).unwrap();
    assert_eq!(io.read32(0x0100), Ok(R32_DEAD));
    assert_eq!(io.read32(CK_EN), Ok(0));
    // A dead CMAC register is read again after its clocks are enabled.
    io.write32(0xc100, R32_DEAD).unwrap();
    assert_eq!(io.read32(0xc100), Ok(R32_DEAD));
    assert_eq!(io.read32(CK_EN), Ok(CMAC_ALLCKEN));
    io.write32(0xc200, 0x1122_3344).unwrap();
    assert_eq!(io.read16(0xc202), Ok(0x1122));
    assert_eq!(io.read8(0xc201), Ok(0x33));
    io.quarantine();
    assert_eq!(io.read32(0), Err(Error::Register { register: 0 }));
    assert_eq!(io.write32(0, 0), Err(Error::Register { register: 0 }));
    drop(io);
    assert!(kept.upgrade().is_some(), "a quarantined owner is kept");
}
