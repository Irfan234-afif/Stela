// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020-2022 Realtek Corporation
//! Exact PCI candidates and SYS_CFG1 observations from pinned rtw88/89.
use super::firmware::{Layout, ParseError};
use crate::firmware::{self, Image, Provider, Requirement, Target};
use alloc::{format, string::String};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chip {
    Rtl8822C,
    Rtl8852B,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observed {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub pci_revision: u8,
    /// 32-bit SYS_CFG1 at 0xf0, with every bit kept.
    pub sys_cfg1: u32,
}

/// The revision of a chip binding ([`Profile::chip_target`]).
pub const CHIP_REVISION: &str = "linux-firmware";

/// `rtw_8822ce_id_table`.
pub const RTL8822C_DEVICES: [u16; 2] = [0xc822, 0xc82f];

/// `rtw89_8852be_id_table`.
pub const RTL8852B_DEVICES: [u16; 2] = [0xb852, 0xb85b];

/// The cut field of SYS_CFG1, bits 15:12 (`B_AX_CHIP_VER_MASK`, which
/// rtw88 reads at the same offset).
const fn cut_of(sys_cfg1: u32) -> u8 {
    ((sys_cfg1 >> 12) & 15) as u8
}

/// `enum rtw89_cv`'s name for an rtw89 cut, or `None` past `CHIP_CFV`.
pub fn rtw89_cut_name(cut: u8) -> Option<&'static str> {
    ["CAV", "CBV", "CCV", "CDV", "CEV", "CFV"]
        .get(usize::from(cut))
        .copied()
}

/// What a boot read of an RTL8852B before any driver powered it: its PCI
/// identity, SYS_CFG1 as `rtw89_read_chip_ver` reads it first, BAR2's size
/// and whether the function has MSI.
///
/// The read changes nothing on the chip. It does not give the analog cut
/// (ACV), which rtw89 reads through XTAL SI with register writes, and it
/// does not show whether firmware for the cut exists or whether the chip
/// powers on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unpowered {
    pub observed: Observed,
    pub bar2_bytes: u64,
    pub msi: bool,
}

impl fmt::Display for Unpowered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.observed;
        write!(
            f,
            "{:04x}:{:04x} subsystem={:04x}:{:04x} rev={:02x} bar2={:#x} msi={} sys_cfg1={:#010x}",
            o.vendor,
            o.device,
            o.subsystem_vendor,
            o.subsystem_device,
            o.pci_revision,
            self.bar2_bytes,
            if self.msi { "yes" } else { "no" },
            o.sys_cfg1,
        )?;
        // All ones is a master abort; rtw89 reads `RTW89_R32_DEAD` from a
        // register block that is off.
        if matches!(o.sys_cfg1, u32::MAX | 0xdead_beef) {
            return f.write_str(": the function did not answer, so no cut");
        }
        let cut = cut_of(o.sys_cfg1);
        match rtw89_cut_name(cut) {
            Some(name) => write!(f, " cut={cut} ({name})")?,
            None => write!(f, " cut={cut} (past rtw89's CHIP_CFV)")?,
        }
        f.write_str(": read before power-on")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    observed: Observed,
    chip: Chip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    UnsupportedPci,
    FailedRead,
    TestChip,
}

#[derive(Debug)]
pub enum StageError {
    Resource(firmware::Error),
    Format(ParseError),
}

#[derive(Debug)]
pub struct Staged<'a> {
    pub profile: Profile,
    pub image: Image<'a>,
    pub layout: Layout<'a>,
}

impl Profile {
    pub fn select(observed: Observed) -> Result<Self, IdentityError> {
        if observed.vendor != 0x10ec {
            return Err(IdentityError::UnsupportedPci);
        }
        let chip = match observed.device {
            device if RTL8822C_DEVICES.contains(&device) => Chip::Rtl8822C,
            device if RTL8852B_DEVICES.contains(&device) => Chip::Rtl8852B,
            _ => return Err(IdentityError::UnsupportedPci),
        };
        if observed.sys_cfg1 == u32::MAX {
            return Err(IdentityError::FailedRead);
        }
        // rtw88's BIT_RTL_ID distinguishes non-production silicon. Its test
        // firmware path is not interchangeable with the production image.
        if chip == Chip::Rtl8822C && observed.sys_cfg1 & (1 << 23) != 0 {
            return Err(IdentityError::TestChip);
        }
        Ok(Self { observed, chip })
    }

    pub fn observed(self) -> Observed {
        self.observed
    }
    pub fn chip(self) -> Chip {
        self.chip
    }
    pub fn cut(self) -> u8 {
        cut_of(self.observed.sys_cfg1)
    }
    pub fn firmware_name(self) -> &'static str {
        match self.chip {
            Chip::Rtl8822C => "rtw88/rtw8822c_fw.bin",
            Chip::Rtl8852B => "rtw89/rtw8852b_fw-2.bin",
        }
    }
    pub fn hardware_key(self) -> String {
        let p = self.observed;
        format!(
            "pci:{:04x}:{:04x}:subsys:{:04x}:{:04x}:rev:{:02x}",
            p.vendor, p.device, p.subsystem_vendor, p.subsystem_device, p.pci_revision
        )
    }
    pub fn revision_key(self) -> String {
        format!(
            "syscfg1-{:08x}:cut-{:02x}",
            self.observed.sys_cfg1,
            self.cut()
        )
    }
    /// The binding `stela setup` writes for an adapter it knows by PCI IDs
    /// alone: the chip, as rtw88 and rtw89 name one image per chip.
    pub fn chip_target(self) -> Target<'static> {
        Target {
            driver: "realtek-wifi",
            hardware: match self.chip {
                Chip::Rtl8822C => "pci:10ec:c822",
                Chip::Rtl8852B => "pci:10ec:b852",
            },
            revision: CHIP_REVISION,
            board: None,
        }
    }
    /// Whether `image` is this chip's file under the observed binding or the
    /// chip's ([`Self::chip_target`]).
    pub fn binds(self, image: &Image<'_>) -> bool {
        let hardware = self.hardware_key();
        let revision = self.revision_key();
        let observed = Target {
            driver: "realtek-wifi",
            hardware: &hardware,
            revision: &revision,
            board: None,
        };
        image.name() == self.firmware_name()
            && (image.target() == observed || image.target() == self.chip_target())
    }
    /// Load the image under the observed binding, or else under the chip's
    /// when the USB has none for this adapter. A failure is the observed
    /// request's.
    pub fn stage(self, provider: &dyn Provider) -> Result<Staged<'_>, StageError> {
        let hardware = self.hardware_key();
        let revision = self.revision_key();
        let observed = Requirement {
            name: self.firmware_name(),
            target: Target {
                driver: "realtek-wifi",
                hardware: &hardware,
                revision: &revision,
                board: None,
            },
            minimum_bytes: match self.chip {
                Chip::Rtl8822C => 64,
                Chip::Rtl8852B => 32,
            },
        };
        let chip = Requirement {
            target: self.chip_target(),
            ..observed
        };
        let image = match provider.load(observed) {
            Err(error)
                if matches!(
                    error.kind,
                    firmware::ErrorKind::Missing | firmware::ErrorKind::WrongTarget
                ) =>
            {
                provider
                    .load(chip)
                    .map_err(|_| StageError::Resource(error))?
            }
            loaded => loaded.map_err(StageError::Resource)?,
        };
        let layout = match self.chip {
            Chip::Rtl8822C => Layout::Rtw88(super::firmware::Rtw88::parse(image.bytes())?),
            Chip::Rtl8852B => {
                Layout::Rtw89(super::firmware::Rtw89::parse(image.bytes(), self.cut())?)
            }
        };
        Ok(Staged {
            profile: self,
            image,
            layout,
        })
    }
}
impl From<ParseError> for StageError {
    fn from(error: ParseError) -> Self {
        Self::Format(error)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::firmware::{Catalog, Provenance, Resource};
    use sha2::{Digest, Sha256};
    pub(crate) fn observed(device: u16, cut: u8) -> Observed {
        Observed {
            vendor: 0x10ec,
            device,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x1234,
            pci_revision: 1,
            sys_cfg1: u32::from(cut) << 12,
        }
    }
    pub(crate) fn profile() -> Profile {
        Profile::select(observed(0xc822, 0)).unwrap()
    }
    #[test]
    fn exact_pci_cut_and_raw_identity_are_not_replaced_by_a_marketing_name() {
        for device in [0xc822, 0xc82f, 0xb852, 0xb85b] {
            for cut in 0..16 {
                let o = observed(device, cut);
                let p = Profile::select(o).unwrap();
                assert_eq!(p.observed(), o);
                assert_eq!(p.cut(), cut);
                assert!(p.hardware_key().contains(&format!(":{device:04x}:")));
                assert!(p.revision_key().contains(&format!("cut-{cut:02x}")));
            }
        }
        let mut o = observed(0xb852, 1);
        for device in [0x8852, 0xc821, 0xb822, 0xffff] {
            o.device = device;
            assert_eq!(Profile::select(o), Err(IdentityError::UnsupportedPci));
        }
        o = observed(0xb852, 1);
        o.sys_cfg1 = u32::MAX;
        assert_eq!(Profile::select(o), Err(IdentityError::FailedRead));
        o = observed(0xc822, 1);
        o.sys_cfg1 |= 1 << 23;
        assert_eq!(Profile::select(o), Err(IdentityError::TestChip));
        o = observed(0xb852, 1);
        o.vendor = 0x8086;
        assert_eq!(Profile::select(o), Err(IdentityError::UnsupportedPci));
    }

    #[test]
    fn rtw89_cut_names_follow_enum_rtw89_cv() {
        // core.h: CHIP_CAV through CHIP_CFV, then CHIP_CV_MAX.
        let names = ["CAV", "CBV", "CCV", "CDV", "CEV", "CFV"];
        for (cut, name) in names.into_iter().enumerate() {
            assert_eq!(rtw89_cut_name(cut as u8), Some(name));
        }
        for cut in 6..=u8::MAX {
            assert_eq!(rtw89_cut_name(cut), None);
        }
        for device in RTL8852B_DEVICES {
            assert_eq!(
                Profile::select(observed(device, 1)).map(Profile::chip),
                Ok(Chip::Rtl8852B)
            );
        }
    }

    #[test]
    fn an_unpowered_read_names_the_word_its_cut_and_what_it_did_not_read() {
        use alloc::string::ToString;
        let mut observed = Observed {
            vendor: 0x10ec,
            device: 0xb852,
            subsystem_vendor: 0x1a3b,
            subsystem_device: 0x5470,
            pci_revision: 0,
            // A cut in bits 15:12 with neighbouring bits set, which the cut
            // must ignore and the word must keep.
            sys_cfg1: 0x0001_1f00,
        };
        let read = |observed, msi| {
            Unpowered {
                observed,
                bar2_bytes: 0x10_0000,
                msi,
            }
            .to_string()
        };
        assert_eq!(
            read(observed, true),
            "10ec:b852 subsystem=1a3b:5470 rev=00 bar2=0x100000 msi=yes \
             sys_cfg1=0x00011f00 cut=1 (CBV): read before power-on"
        );
        observed.sys_cfg1 = 0x0000_2000;
        assert!(
            read(observed, false)
                .ends_with("msi=no sys_cfg1=0x00002000 cut=2 (CCV): read before power-on")
        );
        observed.sys_cfg1 = 0x0000_9000;
        assert!(
            read(observed, true).ends_with("cut=9 (past rtw89's CHIP_CFV): read before power-on")
        );
        for dead in [u32::MAX, 0xdead_beef] {
            observed.sys_cfg1 = dead;
            let line = read(observed, true);
            assert!(
                line.ends_with(": the function did not answer, so no cut"),
                "{line}"
            );
            assert!(!line.contains("cut="), "{line}");
        }
    }

    #[test]
    fn provider_binding_is_exact_and_staged_sections_keep_the_original_bytes() {
        let profile = Profile::select(observed(0xc822, 1)).unwrap();
        let hardware = profile.hardware_key();
        let revision = profile.revision_key();
        let data = super::super::firmware::tests::legacy_fixture();
        let original = data.as_ptr();
        let hash = Sha256::digest(&data).into();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: profile.firmware_name(),
            target: Target {
                driver: "realtek-wifi",
                hardware: &hardware,
                revision: &revision,
                board: None,
            },
            provenance: Provenance {
                source: "synthetic-test",
                revision: "1",
                member: profile.firmware_name(),
                license: "MIT",
            },
            expected_length: data.len(),
            expected_sha256: hash,
            bytes: data,
        }])
        .unwrap();
        let staged = profile.stage(&catalog).unwrap();
        assert_eq!(staged.image.bytes().as_ptr(), original);
        let Layout::Rtw88(layout) = staged.layout else {
            panic!("wrong chip layout")
        };
        assert_eq!(layout.sections[0].data.as_ptr(), original.wrapping_add(64));
        for field in 0..5 {
            let mut observation = profile.observed();
            match field {
                0 => observation.device = 0xc82f,
                1 => observation.subsystem_vendor ^= 1,
                2 => observation.subsystem_device ^= 1,
                3 => observation.pci_revision ^= 1,
                _ => observation.sys_cfg1 ^= 1,
            }
            let wrong = Profile::select(observation).unwrap();
            assert!(matches!(
                wrong.stage(&catalog),
                Err(StageError::Resource(firmware::Error {
                    kind: firmware::ErrorKind::WrongTarget,
                    ..
                }))
            ));
        }
        assert!(matches!(
            profile.stage(&Catalog::from_handoff(vec![]).unwrap()),
            Err(StageError::Resource(firmware::Error {
                kind: firmware::ErrorKind::Missing,
                ..
            }))
        ));
    }

    #[test]
    fn an_adapter_with_no_observed_binding_takes_its_chips_image() {
        let data = super::super::firmware::tests::legacy_fixture();
        let hash = Sha256::digest(&data).into();
        let chip = profile().chip_target();
        assert_eq!(chip.hardware, "pci:10ec:c822");
        assert_eq!(chip.revision, CHIP_REVISION);
        let catalog = Catalog::from_handoff(vec![Resource {
            name: "rtw88/rtw8822c_fw.bin",
            target: chip,
            provenance: Provenance {
                source: "synthetic-test",
                revision: "1",
                member: "rtw88/rtw8822c_fw.bin",
                license: "MIT",
            },
            expected_length: data.len(),
            expected_sha256: hash,
            bytes: data,
        }])
        .unwrap();
        // Both RTL8822CE IDs, at any cut, are one chip.
        for device in RTL8822C_DEVICES {
            for cut in [0, 3] {
                let profile = Profile::select(observed(device, cut)).unwrap();
                let staged = profile.stage(&catalog).unwrap();
                assert_eq!(staged.image.target(), chip);
                assert!(profile.binds(&staged.image));
            }
        }
        // RTL8852B's chip is another chip.
        let rtl8852b = Profile::select(observed(0xb852, 1)).unwrap();
        assert_ne!(rtl8852b.chip_target(), chip);
        assert!(matches!(
            rtl8852b.stage(&catalog),
            Err(StageError::Resource(firmware::Error {
                kind: firmware::ErrorKind::Missing,
                ..
            }))
        ));
    }
}
