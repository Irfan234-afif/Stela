use super::*;
use crate::wifi::realtek::ax::io::CR_BASE;
use alloc::{collections::BTreeMap, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Read(u32),
    Write(u32, u32),
    Delay(u64),
}

/// A plain register file that records every access.
#[derive(Default)]
struct Recorder {
    registers: BTreeMap<u32, u32>,
    log: Vec<Access>,
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Recorder {
    fn read8(&mut self, register: u32) -> Result<u8, Error> {
        Ok(self.read32(register & !3)? as u8)
    }
    fn read16(&mut self, register: u32) -> Result<u16, Error> {
        Ok(self.read32(register & !3)? as u16)
    }
    fn read32(&mut self, register: u32) -> Result<u32, Error> {
        self.log.push(Access::Read(register));
        Ok(self.registers.get(&register).copied().unwrap_or(0))
    }
    fn write8(&mut self, register: u32, value: u8) -> Result<(), Error> {
        self.write32(register, u32::from(value))
    }
    fn write16(&mut self, register: u32, value: u16) -> Result<(), Error> {
        self.write32(register, u32::from(value))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.log.push(Access::Write(register, value));
        self.registers.insert(register, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u64) {
        self.log.push(Access::Delay(microseconds));
    }
}

#[test]
fn the_tables_hold_what_rtw8852b_rfk_table_c_declares() {
    // a804c5742bff: 51 tables, 527 WM, 4 WRF and 3 DELAY entries.
    assert_eq!(table::TABLES.len(), 51);
    let mut counts = [0usize; 5];
    for (_, entries) in table::TABLES {
        assert!(!entries.is_empty());
        for entry in *entries {
            counts[match entry {
                Entry::RfWrite { .. } => 0,
                Entry::Mask { .. } => 1,
                Entry::Set { .. } => 2,
                Entry::Clear { .. } => 3,
                Entry::Delay { .. } => 4,
            }] += 1;
        }
    }
    assert_eq!(counts, [4, 527, 0, 0, 3]);
    let mut names: Vec<_> = table::TABLES.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 51);
    assert!(names.iter().all(|name| name.starts_with("rtw8852b_")));
    assert_eq!(table::AFE_INIT.len(), 10);
    assert_eq!(
        table::AFE_INIT[0],
        Entry::Mask {
            address: 0xc0d4,
            mask: u32::MAX,
            data: 0x4486_888c
        }
    );
}

#[test]
fn a_table_runs_as_rtw89_rfk_parser_runs_it() {
    let mut io = Recorder::default();
    io.registers.insert(CR_BASE + 0x20f0, 0xffff_ffff);
    run(
        &mut io,
        &[
            Entry::Mask {
                address: 0x20f0,
                mask: 0xf00,
                data: 0x2,
            },
            Entry::Set {
                address: 0x20f4,
                bits: 1 << 24,
            },
            Entry::Clear {
                address: 0x20f0,
                bits: 0xff,
            },
            Entry::Delay { microseconds: 1 },
            Entry::RfWrite {
                path: 1,
                address: 0x1_008f,
                mask: 1 << 13,
                data: 1,
            },
        ],
    )
    .unwrap();
    assert_eq!(
        io.log,
        [
            Access::Read(CR_BASE + 0x20f0),
            Access::Write(CR_BASE + 0x20f0, 0xffff_f2ff),
            Access::Read(CR_BASE + 0x20f4),
            Access::Write(CR_BASE + 0x20f4, 1 << 24),
            Access::Read(CR_BASE + 0x20f0),
            Access::Write(CR_BASE + 0x20f0, 0xffff_f200),
            Access::Delay(1),
            // An ADSEL address: path B's register 0x8f, directly.
            Access::Read(CR_BASE + 0xf000 + 0x8f * 4),
            Access::Write(CR_BASE + 0xf000 + 0x8f * 4, 1 << 13),
            Access::Delay(1),
        ]
    );
    // Every generated table runs to its end on a register file.
    for (_, entries) in table::TABLES {
        let mut io = Recorder::default();
        run(&mut io, entries).unwrap();
    }
}

#[test]
fn the_first_refused_access_ends_a_table() {
    let mut io = Recorder::default();
    let refused = run(
        &mut io,
        &[
            Entry::RfWrite {
                path: 2,
                address: 0x1_0000,
                mask: 1,
                data: 1,
            },
            Entry::Delay { microseconds: 5 },
        ],
    );
    assert_eq!(refused, Err(Error::RfPath(2)));
    assert!(io.log.is_empty());
}
