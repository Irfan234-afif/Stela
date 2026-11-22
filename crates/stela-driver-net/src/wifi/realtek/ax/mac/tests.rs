extern crate std;

use super::*;
use crate::wifi::realtek::ax::{
    dle::{HcifcMode, HfcChCfg, HfcChInfo, HfcPubInfo, mac_size},
    efuse::tests::mailbox,
    h2c::{Function, HEADER_LEN, Header, Sequence},
    h2creg::{C2HREG_HDR_FUNC_MASK, C2HREG_HDR_LEN_MASK},
    io::field,
    rtw8852b::{
        DMA_CH_MASK, PCIE_QUOTA, RTW8852B_DLE_MEM_PCIE, RTW8852B_HFC_CHCFG_PCIE,
        RTW8852B_HFC_PUBCFG_PCIE,
    },
};
use alloc::{boxed::Box, vec, vec::Vec};

/// One access, or one of the C oracle's harness records.
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
    /// A record the harness makes itself: a marker, an H2C's bytes.
    Mark {
        tag: u32,
        a: u32,
        b: u32,
    },
}

/// The C oracle's records: tag and two values, each a little-endian u32.
/// Reads are tagged by width, writes by 4 plus width, delays 9.
fn push(trace: &mut Vec<u8>, tag: u32, a: u32, b: u32) {
    for word in [tag, a, b] {
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
            Access::Mark { tag, a, b } => push(&mut trace, tag, a, b),
        }
    }
    trace
}

/// What the model's MAC space holds before the first access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fill {
    /// Byte `i` holds `i * 37 + 11`.
    Pattern,
    Ones,
    Zeros,
}

/// How the model's chip misbehaves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Faults {
    /// DMAC_FUNC_EN reads `RTW89_R32_DEAD`.
    dmac_dead: bool,
    /// CMAC_FUNC_EN reads `RTW89_R32_DEAD`.
    cmac_dead: bool,
    /// XTAL SI keeps its poll bit.
    xtal_stuck: bool,
    /// The STA scheduler never reports its init done.
    ss_stuck: bool,
    /// The address CAM keeps its clear bit.
    cam_stuck: bool,
    /// The BA CAM keeps its reset field.
    bacam_stuck: bool,
    /// One public page fewer is available than the maximum.
    pub_short: bool,
}

const MEMORY: usize = 0x1_0000;

/// The register model the C oracle's harness uses: MAC space as
/// little-endian bytes, behaving per aligned word.
///
/// Reads: WDE_INI_STATUS and PLE_INI_STATUS read both ready bits;
/// DMAC_FUNC_EN and CMAC_FUNC_EN read `RTW89_R32_DEAD` when the faults say;
/// SS_CTRL reads SS_INIT_DONE_1 set unless stuck; PUB_PAGE_INFO1 reads no
/// public page used and PUB_PAGE_INFO2 the maximum PUB_PAGE_CTRL2 holds as
/// available (one fewer when short).
///
/// Writes are stored, then: WLAN_XTAL_SI_CTRL drops its poll bit, the
/// address CAM its clear bit and the BA CAM its reset field, unless stuck;
/// a trigger written to H2CREG_CTRL leaves it 0 and, when the model has a
/// reply, puts the reply in C2HREG_DATA0..3 and 1 in C2HREG_CTRL.
struct Model {
    memory: Vec<u8>,
    log: Vec<Access>,
    faults: Faults,
    reply: Option<[u32; 4]>,
    waited_us: u64,
}

impl Model {
    fn new(fill: Fill, faults: Faults) -> Self {
        let memory = match fill {
            Fill::Pattern => (0..MEMORY).map(|at| (at * 37 + 11) as u8).collect(),
            Fill::Ones => vec![0xff; MEMORY],
            Fill::Zeros => vec![0; MEMORY],
        };
        Self {
            memory,
            log: Vec::new(),
            faults,
            reply: None,
            waited_us: 0,
        }
    }
    fn zeroed() -> Self {
        Self::new(Fill::Zeros, Faults::default())
    }
    fn faulty(faults: Faults) -> Self {
        Self::new(Fill::Zeros, faults)
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
    /// What the aligned word at `word` reads as.
    fn view(&self, word: u32) -> u32 {
        let faults = self.faults;
        let value = self.get(word, 4);
        match word {
            WDE_INI_STATUS => value | WDE_MGN_INI_RDY,
            PLE_INI_STATUS => value | PLE_MGN_INI_RDY,
            DMAC_FUNC_EN if faults.dmac_dead => R32_DEAD,
            CMAC_FUNC_EN if faults.cmac_dead => R32_DEAD,
            SS_CTRL if faults.ss_stuck => value & !SS_INIT_DONE_1,
            SS_CTRL => value | SS_INIT_DONE_1,
            PUB_PAGE_INFO1 => value & !(G0_USE_PG_MASK | G1_USE_PG_MASK),
            PUB_PAGE_INFO2 => {
                let available = field(self.get(PUB_PAGE_CTRL2, 4), PUBPG_ALL_MASK)
                    .wrapping_sub(faults.pub_short.into());
                (value & !PUB_AVAL_PG_MASK) | prep(available, PUB_AVAL_PG_MASK)
            }
            _ => value,
        }
    }
    fn check(register: u32, width: u32) {
        assert!(
            register as usize + width as usize <= MEMORY,
            "{register:#x}"
        );
        assert!(register.is_multiple_of(width), "{register:#x}/{width}");
    }
    fn read(&mut self, register: u32, width: u32) -> u32 {
        Self::check(register, width);
        let mut value = self.view(register & !3) >> ((register & 3) * 8);
        if width < 4 {
            value &= (1 << (8 * width)) - 1;
        }
        self.log.push(Access::Read {
            width,
            register,
            value,
        });
        value
    }
    fn write(&mut self, register: u32, width: u32, value: u32) {
        Self::check(register, width);
        self.log.push(Access::Write {
            width,
            register,
            value,
        });
        self.set(register, width, value);
        let faults = self.faults;
        let word = register & !3;
        let stored = self.get(word, 4);
        match word {
            WLAN_XTAL_SI_CTRL if !faults.xtal_stuck => {
                self.set(word, 4, stored & !XTAL_SI_CMD_POLL);
            }
            ADDR_CAM_CTRL if !faults.cam_stuck => self.set(word, 4, stored & !ADDR_CAM_CLR),
            RESPBA_CAM_CTRL if !faults.bacam_stuck => {
                self.set(word, 4, stored & !BACAM_RST_MASK);
            }
            _ => {}
        }
        if register == H2CREG_CTRL && value & u32::from(H2CREG_TRIGGER) != 0 {
            self.set(H2CREG_CTRL, width, 0);
            if let Some(reply) = self.reply {
                for (index, word) in reply.into_iter().enumerate() {
                    self.set(C2HREG_DATA0 + 4 * index as u32, 4, word);
                }
                self.set(C2HREG_CTRL, 1, 1);
            }
        }
    }
    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push(Access::Mark { tag, a, b });
    }
    /// The reads of `register`, `width` bytes wide.
    fn reads(&self, register: u32, width: u32) -> usize {
        self.log
            .iter()
            .filter(|access| {
                matches!(access, Access::Read { width: w, register: at, .. }
                    if *at == register && *w == width)
            })
            .count()
    }
    fn delays(&self, microseconds: u64) -> usize {
        self.log
            .iter()
            .filter(|access| **access == Access::Delay(microseconds))
            .count()
    }
    /// The values written to `register`, in order.
    fn writes(&self, register: u32) -> Vec<u32> {
        self.log
            .iter()
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
    /// Whether any access reached `register`.
    fn reached(&self, register: u32) -> bool {
        self.log.iter().any(|access| {
            matches!(access, Access::Read { register: at, .. } | Access::Write { register: at, .. }
                if *at == register)
        })
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
        self.log.push(Access::Delay(microseconds));
    }
}

/// The C oracle's `rtw89_h2c_tx` stand-in: the H2C `rtw89_h2c_pkt_set_hdr`
/// built, recorded with its length and the sequence after it (tag 40) and
/// as little-endian words (tag 41), then taken, or refused with `-ENOSPC`.
struct Recorder {
    sequence: Sequence,
    refuse: bool,
}

impl Recorder {
    fn new() -> Self {
        Self {
            sequence: Sequence::default(),
            refuse: false,
        }
    }
}

impl Commands<Model> for Recorder {
    fn send(
        &mut self,
        io: &mut Model,
        class: u8,
        func: u8,
        rack: bool,
        dack: bool,
        payload: &[u8],
    ) -> Result<(), h2c::Error> {
        let header =
            self.sequence
                .set_hdr(Function::mac(class, func), rack, dack, payload.len() as u32);
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(payload);
        io.mark(40, bytes.len() as u32, self.sequence.0.into());
        for (index, chunk) in bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            io.mark(41, index as u32, u32::from_le_bytes(word));
        }
        if self.refuse {
            Err(h2c::Error::NoResource)
        } else {
            Ok(())
        }
    }
}

/// An expected access sequence, written out as rtw89's code makes it.
#[derive(Default)]
struct Script(Vec<Access>);

impl Script {
    fn r(&mut self, width: u32, register: u32, value: u32) {
        self.0.push(Access::Read {
            width,
            register,
            value,
        });
    }
    fn w(&mut self, width: u32, register: u32, value: u32) {
        self.0.push(Access::Write {
            width,
            register,
            value,
        });
    }
    fn r32(&mut self, register: u32, value: u32) {
        self.r(4, register, value);
    }
    fn w32(&mut self, register: u32, value: u32) {
        self.w(4, register, value);
    }
    /// `rtw89_write32_set`, `_clr` or `_mask` over a register reading
    /// `before`: the read, then the write of `after`.
    fn rmw32(&mut self, register: u32, before: u32, after: u32) {
        self.r32(register, before);
        self.w32(register, after);
    }
    /// The same 8 bits wide.
    fn rmw8(&mut self, register: u32, before: u32, after: u32) {
        self.r(1, register, before);
        self.w(1, register, after);
    }
    /// An `rtw89_*_imr_enable` pair on a register that reads 0: the clear,
    /// then the set.
    fn imr(&mut self, register: u32, set: u32) {
        self.rmw32(register, 0, 0);
        self.rmw32(register, 0, set);
    }
    fn delay(&mut self, microseconds: u64) {
        self.0.push(Access::Delay(microseconds));
    }
    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.0.push(Access::Mark { tag, a, b });
    }
}

/// DMAC_FUNC_EN as `dmac_func_en_ax` writes it, and with the DLE's enables.
const DMAC_ON: u32 = 0xfb7d_0000;
const DMAC_DLE_ON: u32 = 0xfffd_0000;
/// CMAC_FUNC_EN as `cmac_func_en_ax` sets it.
const CMAC_ON: u32 = 0xf000_003f;
/// The offload-config H2C at sequence 0: REC_ACK for the multiple of four,
/// DONE_ACK as asked, 16 bytes in all.
const OFLD_CFG_H2C: [u8; 16] = [
    0x25, 0x14, 0x00, 0x00, 0x10, 0xc0, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00,
];

/// The accesses of the MAC init on a zeroed model, transcribed from
/// `rtw89_mac_init` after its partial init and every callee, with the H2C
/// the recorder takes last.
fn cold_init() -> Vec<Access> {
    let mut s = Script::default();
    // __rtw8852bx_mac_enable_bb_rf
    s.rmw8(SYS_FUNC_EN, 0, 0x03);
    s.rmw32(SPS_DIG_ON_CTRL0, 0, 0x0002_0000);
    s.rmw32(WLRF_CTRL, 0, 0x0002_0000);
    s.rmw32(WLRF_CTRL, 0x0002_0000, 0);
    s.rmw32(WLRF_CTRL, 0, 0x0002_0000);
    // rtw89_mac_write_xtal_si_ax for XTAL_SI_WL_RFC_S0 and _S1: 0xc7 under
    // every mask bit, a normal write, polled once.
    s.w32(WLAN_XTAL_SI_CTRL, 0x80ff_c780);
    s.r32(WLAN_XTAL_SI_CTRL, 0x00ff_c780);
    s.w32(WLAN_XTAL_SI_CTRL, 0x80ff_c781);
    s.r32(WLAN_XTAL_SI_CTRL, 0x00ff_c781);
    s.w(1, PHYREG_SET, 0x0e);

    // sys_init_ax: dmac_func_en_ax, cmac_func_en_ax, chip_func_en_ax
    s.w32(DMAC_FUNC_EN, DMAC_ON);
    s.w32(DMAC_CLK_EN, 0x0b1f_0000);
    s.rmw32(CK_EN, 0, 0x4000_003f);
    s.rmw32(CMAC_FUNC_EN, 0, CMAC_ON);
    s.rmw32(SPS_DIG_ON_CTRL0, 0x0002_0000, 0x0002_e000);

    // dmac_init_ax: rtw89_mac_dle_init(rtwdev, RTW89_QTA_SCC, …)
    s.r32(DMAC_FUNC_EN, DMAC_ON);
    s.rmw32(DMAC_FUNC_EN, DMAC_ON, DMAC_ON);
    s.rmw32(DMAC_CLK_EN, 0x0b1f_0000, 0x0f9f_0000);
    s.rmw32(WDE_PKTBUF_CFG, 0, 0x01fe_0000);
    s.rmw32(PLE_PKTBUF_CFG, 0, 0x01f0_0401);
    for (register, value) in [
        (WDE_QTA0_CFG, 0x01be_01be),
        (WDE_QTA1_CFG, 0x0030_0030),
        (WDE_QTA3_CFG, 0),
        (WDE_QTA4_CFG, 0x0010_0010),
    ] {
        s.w32(register, value);
    }
    for (index, value) in [
        0x0093_0093,
        0,
        0x0010_0010,
        0x0014_0014,
        0x009d_0011,
        0x000d_000d,
        0x00e5_0059,
        0,
        0x00ac_0020,
        0x000e_000e,
        0x0018_0008,
    ]
    .into_iter()
    .enumerate()
    {
        s.w32(PLE_QTA0_CFG + 4 * index as u32, value);
    }
    s.rmw32(DMAC_FUNC_EN, DMAC_ON, DMAC_DLE_ON);
    s.r32(WDE_INI_STATUS, 0x3);
    s.r32(PLE_INI_STATUS, 0x3);

    // rtw89_mac_hfc_init(rtwdev, true, true, true)
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    s.rmw32(HCI_FC_CTRL, 0, 0);
    for (ch, value) in [
        (0, 0x0155_0005),
        (1, 0x0155_0005),
        (2, 0x0156_0004),
        (3, 0x0156_0004),
        (8, 0x0156_0004),
        (9, 0x0156_0004),
    ] {
        s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
        s.w32(ACH0_PAGE_CTRL + 4 * ch, value);
    }
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    s.w32(PUB_PAGE_CTRL1, 446);
    s.w32(WP_PAGE_CTRL2, 0);
    // hfc_mix_cfg_ax: pre-costs 2 and 40, 446 public pages, WD full
    // condition 1.
    s.w32(CH_PAGE_CTRL, 0x0028_0002);
    s.w32(PUB_PAGE_CTRL2, 446);
    s.w32(WP_PAGE_CTRL1, 0);
    s.rmw32(HCI_FC_CTRL, 0, 0x10);
    s.rmw32(HCI_FC_CTRL, 0x10, 0x19);
    s.delay(10);
    for ch in [0, 1, 2, 3, 8, 9] {
        s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
        s.r32(ACH0_PAGE_INFO + 4 * ch, 0);
    }
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    for (register, value) in [
        (PUB_PAGE_INFO1, 0),
        (PUB_PAGE_INFO3, 0),
        (PUB_PAGE_INFO2, 446),
        (WP_PAGE_INFO1, 0),
        (HCI_FC_CTRL, 0x19),
        (CH_PAGE_CTRL, 0x0028_0002),
        (PUB_PAGE_CTRL2, 446),
        (WP_PAGE_CTRL1, 0),
        (WP_PAGE_CTRL2, 0),
        (PUB_PAGE_CTRL1, 446),
    ] {
        s.r32(register, value);
    }

    // sta_sch_init_ax
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    s.rmw8(SS_CTRL, 0, 0x01);
    s.r32(SS_CTRL, 0x8000_0001);
    s.rmw32(SS_CTRL, 0x8000_0001, 0xa000_0001);
    s.rmw32(SS_CTRL, 0xa000_0001, 0xa000_0001);
    // mpdu_proc_init_ax
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    s.w32(ACTION_FWD0, 0x02a9_5a95);
    s.w32(TF_FWD, 0x0000_aa55);
    s.rmw32(MPDU_PROC, 0, 0x3);
    s.w32(CUT_AMSDU_CTRL, 0x010e_05f0);
    // sec_eng_init_ax: TX partial mode off on an RTL8852B.
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    s.rmw32(SEC_ENG_CTRL, 0, 0x070f);
    s.rmw32(SEC_MPDU_PROC, 0, 0x3);

    // cmac_init_ax: scheduler_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(PREBKF_CFG_1, 0, 0x47);
    s.rmw32(SCH_EXT_CTRL, 0, 0x2);
    s.rmw32(CCA_CFG_0, 0, 0);
    s.rmw32(PREBKF_CFG_0, 0, 0x18);
    // addr_cam_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(ADDR_CAM_CTRL, 0, 0x007f_0101);
    s.r(2, ADDR_CAM_CTRL, 0x0001);
    // rx_fltr_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.w32(MGNT_FLTR, 0x5555_5555);
    s.w32(CTRL_FLTR, 0x5555_5555);
    s.w32(DATA_FLTR, 0x5555_5555);
    s.w32(RX_FLTR_OPT, 0x0300_44be);
    s.w(2, PLCP_HDR_FLTR, 0x7f);
    // cca_ctrl_init_ax, then _patch_dis_resp_chk's clears.
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(CCA_CONTROL, 0, 0x7121_00ff);
    s.rmw32(RSP_CHK_SIG, 0, 0);
    s.rmw32(TRXPTCL_RESP_0, 0, 0);
    // nav_ctrl_init_ax
    s.rmw32(WMAC_NAV_CTL, 0, 0x0403_0000);
    s.rmw32(WMAC_NAV_CTL, 0x0403_0000, 0x0403_c400);
    // spatial_reuse_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw8(RX_SR_CTRL, 0, 0);
    s.rmw8(BSSID_SRC_CTRL, 0, 0x01);
    // tmac_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(MAC_LOOPBACK, 0, 0);
    s.rmw32(TCR0, 0, 0x0006_0000);
    s.rmw32(TXD_FIFO_CTRL, 0, 0x7000);
    s.rmw32(TXD_FIFO_CTRL, 0x7000, 0x7700);
    // trxptcl_init_ax: CCK SIFS 0xa, RTL8852B's OFDM SIFS 0x11.
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(TRXPTCL_RESP_0, 0, 0x110a);
    s.rmw32(RXTRIG_TEST_USER_2, 0, 0x0010_0000);
    s.rmw32(TRXPTCL_RRSR_CTL_0, 0, 0);
    s.rmw32(TRXPTCL_RRSR_CTL_0, 0, 0x800);
    // rmac_init_ax: rst_bacam, polled once, then 89 RX pages of 128 bytes:
    // 11392 bytes, 22 units of 512.
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(RESPBA_CAM_CTRL, 0, 0x2);
    s.r32(RESPBA_CAM_CTRL, 0);
    s.rmw8(RESPBA_CAM_CTRL, 0, 0x04);
    s.r(2, DLK_PROTECT_CTL, 0);
    s.w(2, DLK_PROTECT_CTL, 0x20f0);
    s.rmw8(RCR, 0, 0x01);
    s.rmw32(RX_FLTR_OPT, 0x0300_44be, 0x0316_44be);
    s.rmw8(PLCP_HDR_FLTR, 0x7f, 0x6f);
    // cmac_com_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(TX_SUB_CARRIER_VALUE, 0, 0);
    s.rmw32(PTCL_RRSR1, 0, 0x300);
    // ptcl_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw32(SIFS_SETTING, 0, 0x0405_0000);
    s.rmw32(PTCL_FSM_MON, 0, 0x3f);
    s.rmw8(PTCL_COMMON_SETTING_0, 0, 0x03);
    s.rmw8(PTCL_COMMON_SETTING_0, 0x03, 0x03);
    s.rmw8(PTCLRPT_FULL_HDL, 0, 0x10);
    s.rmw32(AGG_LEN_VHT_0, 0, 0x0003_ff80);
    // cmac_dma_init_ax
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.rmw8(RXDMA_CTRL_0, 0, 0);

    // enable_imr_ax(…, RTW89_DMAC_SEL)
    s.r32(DMAC_FUNC_EN, DMAC_DLE_ON);
    s.imr(WDRLS_ERR_IMR, 0x3327);
    s.rmw32(SEC_DEBUG, 0, 0x8);
    s.imr(MPDU_TX_ERR_IMR, 0);
    s.imr(MPDU_RX_ERR_IMR, 0);
    s.imr(STA_SCHEDULER_ERR_IMR, 0x7);
    s.imr(TXPKTCTL_ERR_IMR_ISR, 0x101);
    s.imr(TXPKTCTL_ERR_IMR_ISR_B1, 0x303);
    s.imr(WDE_ERR_IMR, 0x070f_f0ff);
    s.imr(PLE_ERR_IMR, 0x070f_f0df);
    s.rmw32(PKTIN_ERR_IMR, 0, 0x1);
    s.imr(HOST_DISPATCHER_ERR_IMR, 0x0c00_0161);
    s.imr(CPU_DISPATCHER_ERR_IMR, 0x0400_0062);
    s.imr(OTHER_DISPATCHER_ERR_IMR, 0);
    s.imr(CPUIO_ERR_IMR, 0x1111);
    s.rmw32(BBRPT_COM_ERR_IMR_ISR, 0, 0x1);
    s.imr(BBRPT_CHINFO_ERR_IMR_ISR, 0);
    s.rmw32(BBRPT_DFS_ERR_IMR_ISR, 0, 0x1);
    s.rmw32(LA_ERRFLAG, 0, 0x1);
    // enable_imr_ax(…, RTW89_CMAC_SEL)
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.imr(SCHEDULE_ERR_IMR, 0x1);
    s.imr(PTCL_IMR0, 0x1080_0001);
    s.imr(DLE_CTRL, 0xc000);
    s.imr(PHYINFO_ERR_IMR, 0);
    s.imr(RMAC_ERR_ISR, 0x000e_4000);
    s.imr(TMAC_ERR_IMR_ISR, 0x780);
    // err_imr_ctrl_ax
    s.w32(DMAC_ERR_IMR, 0xffff_ffff);
    s.w32(CMAC_ERR_IMR, 0xffff_ffff);
    // set_host_rpr_ax
    s.rmw32(WDRLS_CFG, 0, 0);
    s.rmw32(RLSRPT0_CFG0, 0, 0x0f00_0000);
    s.rmw32(RLSRPT0_CFG1, 0, 30);
    s.rmw32(RLSRPT0_CFG1, 30, 0x00ff_001e);

    // rtw89_pci_ops_mac_post_init_ax
    s.rmw32(TX_ADDRESS_INFO_MODE_SETTING, 0, 0x1);
    s.rmw32(PKTIN_SETTING, 0, 0);
    s.rmw32(PCIE_DMA_STOP1, 0, 0);
    s.rmw32(PCIE_DMA_STOP1, 0, 0);

    // rtw89_fw_h2c_set_ofld_cfg
    s.mark(40, 16, 1);
    for (index, chunk) in OFLD_CFG_H2C.chunks(4).enumerate() {
        s.mark(
            41,
            index as u32,
            u32::from_le_bytes(chunk.try_into().unwrap()),
        );
    }
    s.0
}

/// What rtw89's `rtwdev->mac` holds after the MAC init on a zeroed model.
fn cold_state() -> (DleInfo, HfcParam, HfcInfo) {
    let dle_info = DleInfo {
        qta_mode: QtaMode::Scc,
        ple_pg_size: 128,
        ple_free_pg: 496,
        c0_rx_qta: 89,
        c1_rx_qta: 0,
    };
    let hfc_param = HfcParam {
        en: true,
        h2c_en: true,
        mode: HcifcMode::Poh,
        ch_cfg: Some(&RTW8852B_HFC_CHCFG_PCIE),
        pub_cfg: RTW8852B_HFC_PUBCFG_PCIE,
        prec_cfg: mac_size::HFC_PRECCFG_PCIE,
    };
    let hfc_info = HfcInfo {
        ch_info: [HfcChInfo::default(); dle::DMA_CH_NUM],
        pub_info: HfcPubInfo {
            pub_aval: 446,
            ..HfcPubInfo::default()
        },
    };
    (dle_info, hfc_param, hfc_info)
}

#[test]
fn mac_init_follows_rtw89_access_for_access() {
    let mut io = Model::zeroed();
    let mut recorder = Recorder::new();
    let init = init(&mut io, &mut recorder).unwrap();
    assert_eq!(io.log, cold_init());
    let (dle_info, hfc_param, hfc_info) = cold_state();
    assert_eq!(
        init,
        Init {
            dle_info,
            hfc_param,
            hfc_info,
            ba_cam_reset: None,
            ofld_cfg: Ok(()),
        }
    );
    assert_eq!(recorder.sequence, Sequence(1));
    assert_eq!(io.waited_us, 10);
}

#[test]
fn each_poll_that_never_answers_names_its_register_after_its_bound() {
    let stuck = |change: fn(&mut Faults)| {
        let mut faults = Faults::default();
        change(&mut faults);
        faults
    };
    for (faults, step, register, mask, width, polls, step_us) in [
        (
            stuck(|f| f.xtal_stuck = true),
            Step::EnableBbRf,
            WLAN_XTAL_SI_CTRL,
            XTAL_SI_CMD_POLL,
            4,
            1001,
            50,
        ),
        (
            stuck(|f| f.ss_stuck = true),
            Step::StaSchInit,
            SS_CTRL,
            SS_INIT_DONE_1,
            4,
            2001,
            1,
        ),
        (
            stuck(|f| f.cam_stuck = true),
            Step::AddrCamInit,
            ADDR_CAM_CTRL,
            ADDR_CAM_CLR,
            2,
            2001,
            1,
        ),
    ] {
        let mut io = Model::faulty(faults);
        let mut recorder = Recorder::new();
        assert_eq!(
            init(&mut io, &mut recorder),
            Err(Error {
                step,
                cause: Cause::Io(io::Error::Timeout { register, mask }),
            }),
            "{faults:?}"
        );
        // The XTAL SI poll gives up on the first RF path's write.
        assert_eq!(io.reads(register, width), polls, "{faults:?}");
        assert_eq!(io.delays(step_us), polls - 1, "{faults:?}");
        assert!(
            matches!(io.log.last(), Some(Access::Read { register: at, .. }) if *at == register)
        );
        // Nothing after the failed step: no H2C.
        assert_eq!(recorder.sequence, Sequence(0));
    }

    // A BA CAM whose reset never clears is only warned about: 1001 reads a
    // step apart after the write's own, then the init goes on.
    let mut io = Model::faulty(stuck(|f| f.bacam_stuck = true));
    let init = init(&mut io, &mut Recorder::new()).unwrap();
    assert_eq!(
        init.ba_cam_reset,
        Some(io::Error::Timeout {
            register: RESPBA_CAM_CTRL,
            mask: BACAM_RST_MASK,
        })
    );
    assert_eq!(io.reads(RESPBA_CAM_CTRL, 4), 1 + 1001);
    assert_eq!(io.delays(1), 1000);
    assert_eq!(init.ofld_cfg, Ok(()));
}

#[test]
fn a_mac_that_reads_off_or_public_pages_that_do_not_add_up_stop_the_init() {
    // DMAC_FUNC_EN dead: refused at the SCC DLE init's check, before any
    // quota.
    let mut io = Model::faulty(Faults {
        dmac_dead: true,
        ..Faults::default()
    });
    assert_eq!(
        init(&mut io, &mut Recorder::new()),
        Err(Error {
            step: Step::DleInit,
            cause: Cause::DmacOff { value: R32_DEAD },
        })
    );
    assert!(!io.reached(WDE_PKTBUF_CFG));

    // CMAC_FUNC_EN dead: the DMAC init completes, the first CMAC check
    // refuses.
    let mut io = Model::faulty(Faults {
        cmac_dead: true,
        ..Faults::default()
    });
    assert_eq!(
        init(&mut io, &mut Recorder::new()),
        Err(Error {
            step: Step::SchedulerInit,
            cause: Cause::CmacOff { value: R32_DEAD },
        })
    );
    assert_eq!(io.reads(SEC_MPDU_PROC, 4), 1);
    assert!(!io.reached(PREBKF_CFG_1));

    // One public page short with flow control read back enabled.
    let short = Faults {
        pub_short: true,
        ..Faults::default()
    };
    let mut io = Model::faulty(short);
    assert_eq!(
        init(&mut io, &mut Recorder::new()),
        Err(Error {
            step: Step::HfcInit,
            cause: Cause::Dle(dle::Error::HfcPubInfo {
                g0_used: 0,
                g1_used: 0,
                pub_aval: 445,
                pub_max: 446,
            }),
        })
    );
    assert!(!io.reached(SS_CTRL));

    // With flow control read back disabled the same pages pass: rtw89 checks
    // them only when HCI_FC_CTRL reads HCI_FC_EN.
    let mut io = Model::faulty(short);
    io.set(DMAC_FUNC_EN, 4, DMAC_DLE_ON);
    let (dle_info, ..) = cold_state();
    let mut param = HfcParam::ZERO;
    let mut info = HfcInfo::default();
    assert_eq!(
        dle::hfc_init(
            &mut io, &dle_info, &mut param, &mut info, true, false, false
        ),
        Ok(())
    );
    assert!(!param.en && !param.h2c_en);
    assert_eq!(info.pub_info.pub_aval, 445);
}

#[test]
fn rtl8852b_takes_its_own_branches_and_band_0_alone() {
    let mut io = Model::new(Fill::Ones, Faults::default());
    let init = init(&mut io, &mut Recorder::new()).unwrap();
    // SIFS: CCK 0xa and 8852B's OFDM 0x11 (RTL8852A's would be 0x15), over
    // the response checks _patch_dis_resp_chk cleared.
    let cca = RSP_CHK_SEC_CCA_80
        | RSP_CHK_SEC_CCA_40
        | RSP_CHK_SEC_CCA_20
        | RSP_CHK_BTCCA
        | RSP_CHK_EDCCA
        | RSP_CHK_CCA;
    let resp = io.writes(TRXPTCL_RESP_0);
    assert_eq!(resp.len(), 2);
    assert_eq!(resp[0], !cca);
    assert_eq!(field(resp[1], WMAC_SPEC_SIFS_OFDM_MASK), 0x11);
    assert_eq!(field(resp[1], WMAC_SPEC_SIFS_CCK_MASK), 0xa);
    assert_eq!(resp[1] & cca, 0);
    assert_eq!(
        io.writes(RSP_CHK_SIG),
        [!(RSP_CHK_TXNAV | RSP_CHK_INTRA_NAV | RSP_CHK_BASIC_NAV)]
    );
    // The security engine's TX partial mode cleared; RTL8852C would set UC
    // management decryption instead.
    assert_eq!(io.writes(SEC_ENG_CTRL), [!TX_PARTIAL_MODE]);
    // RTL885xB branches: TSF advance on port reset, OFDM and CCK response
    // rates, the VHT A-MPDU length, the CMAC DMA's full modes off.
    assert_eq!(io.writes(SCH_EXT_CTRL), [u32::MAX]);
    assert_eq!(io.writes(PTCL_RRSR1), [0xffff_f3ff]);
    assert_eq!(io.writes(AGG_LEN_VHT_0), [0xfff3_ff80]);
    assert_eq!(io.writes(RXDMA_CTRL_0), [0xc0]);
    // The maximum MPDU length 89 pages of 128 bytes allow, in 512-byte
    // units, over the filter rx_fltr_init_ax wrote.
    assert_eq!(
        io.writes(RX_FLTR_OPT),
        [
            DEFAULT_AX_RX_FLTR,
            (DEFAULT_AX_RX_FLTR & !RX_MPDU_MAX_LEN_MASK) | 0x0016_0000
        ]
    );
    // Band 0 alone: nothing at CMAC1's registers (CMAC0's plus 0x2000), and
    // neither CMAC1's power cut and isolation nor the preload, the SS2F path
    // or the LTR, which RTL8852B does not take or Stela leaves alone.
    assert!(io.log.iter().all(|access| match access {
        Access::Read { register, .. } | Access::Write { register, .. } => *register < 0xe000,
        _ => true,
    }));
    for register in [
        0x0024, // R_AX_AFE_CTRL1
        0x0080, // R_AX_SYS_ISO_CTRL_EXTEND
        0x8410, // R_AX_LTR_CTRL_0
        0x8414, // R_AX_LTR_CTRL_1
        0x8418, // R_AX_LTR_IDLE_LATENCY
        0x841c, // R_AX_LTR_ACTIVE_LATENCY
        0x9e50, // R_AX_SS2FINFO_PATH
        0x9f48, // R_AX_TXPKTCTL_B0_PRELD_CFG0
        0x9f4c, // R_AX_TXPKTCTL_B0_PRELD_CFG1
    ] {
        assert!(!io.reached(register), "{register:#x}");
    }
    // The SCC quota gives CMAC1 no DMA pages: rtw89_mac_is_qta_dbcc is false.
    let scc = RTW8852B_DLE_MEM_PCIE[QtaMode::Scc as usize].unwrap();
    assert_eq!((scc.ple_min_qt.cma1_dma, scc.ple_max_qt.cma1_dma), (0, 0));
    assert_eq!(init.dle_info.c1_rx_qta, 0);
}

#[test]
fn the_full_flow_control_sets_every_channel_rtl8852b_has() {
    assert_eq!(DMA_CH_MASK, 0x0cf0);
    let mut io = Model::zeroed();
    io.set(DMAC_FUNC_EN, 4, DMAC_DLE_ON);
    let (dle_info, expected, _) = cold_state();
    let mut param = HfcParam::ZERO;
    let mut info = HfcInfo::default();
    dle::hfc_init(&mut io, &dle_info, &mut param, &mut info, true, true, true).unwrap();
    assert_eq!(param, expected);
    let pages: Vec<(u32, u32)> = io
        .log
        .iter()
        .filter_map(|access| match *access {
            Access::Write {
                register, value, ..
            } if (ACH0_PAGE_CTRL..ACH0_PAGE_CTRL + 4 * 12).contains(&register) => {
                Some(((register - ACH0_PAGE_CTRL) / 4, value))
            }
            _ => None,
        })
        .collect();
    let expect: Vec<(u32, u32)> = [0, 1, 2, 3, 8, 9]
        .into_iter()
        .map(|ch: usize| {
            let HfcChCfg { min, max, grp } = RTW8852B_HFC_CHCFG_PCIE[ch];
            assert_eq!(grp, 0);
            (ch as u32, u32::from(min) | u32::from(max) << 16)
        })
        .collect();
    assert_eq!(pages, expect);

    // A channel table the pre-cost refuses is refused before that channel's
    // write, as hfc_ch_cfg_chk refuses it.
    let mut io = Model::zeroed();
    io.set(DMAC_FUNC_EN, 4, DMAC_DLE_ON);
    let mut quota = PCIE_QUOTA;
    let mut ini = *quota.hfc_param_ini;
    let mut channels = RTW8852B_HFC_CHCFG_PCIE;
    channels[2] = HfcChCfg::new(1, 342, 0);
    ini[QtaMode::Scc as usize].ch_cfg = Some(Box::leak(Box::new(channels)));
    quota.hfc_param_ini = Box::leak(Box::new(ini));
    let mut param = HfcParam::ZERO;
    let mut info = HfcInfo::default();
    assert_eq!(
        dle::hfc_init_with(
            &mut io, &quota, &dle_info, &mut param, &mut info, true, true, true
        ),
        Err(dle::Error::HfcChCfg { ch: 2 })
    );
    assert_eq!(io.writes(ACH0_PAGE_CTRL + 4), [0x0155_0005]);
    assert!(!io.reached(ACH0_PAGE_CTRL + 8));
}

#[test]
fn set_ofld_cfg_sends_rtw89s_bytes_and_a_refusal_is_ignored_like_rtw89() {
    let mut io = Model::zeroed();
    let mut recorder = Recorder::new();
    set_ofld_cfg(&mut io, &mut recorder).unwrap();
    let bytes: Vec<u8> = io
        .log
        .iter()
        .filter_map(|access| match *access {
            Access::Mark { tag: 41, b, .. } => Some(b),
            _ => None,
        })
        .flat_map(u32::to_le_bytes)
        .collect();
    assert_eq!(bytes, OFLD_CFG_H2C);
    let header = Header::decode(bytes[..HEADER_LEN].try_into().unwrap());
    assert_eq!(header.function(), Function::mac(0x9, 0x14));
    assert_eq!((header.seq(), header.total_len()), (0, 16));
    assert!(header.rec_ack() && header.done_ack());

    // At sequence 1 only DONE_ACK is asked.
    let mut io = Model::zeroed();
    set_ofld_cfg(&mut io, &mut recorder).unwrap();
    assert_eq!(
        io.log[1],
        Access::Mark {
            tag: 41,
            a: 0,
            b: 0x0100_1425
        }
    );
    assert_eq!(
        io.log[2],
        Access::Mark {
            tag: 41,
            a: 1,
            b: 0x0000_8010
        }
    );

    // A refused H2C still took its sequence number, and the init returns.
    let mut io = Model::zeroed();
    let mut recorder = Recorder::new();
    recorder.refuse = true;
    let init = init(&mut io, &mut recorder).unwrap();
    assert_eq!(init.ofld_cfg, Err(h2c::Error::NoResource));
    assert_eq!(recorder.sequence, Sequence(1));
}

#[test]
fn the_scheduler_s_tx_enables_go_through_the_register_or_the_running_firmware() {
    // Without firmware: CTN_TXEN read for tx_en, the CMAC checked, then the
    // selected bits cleared 16 bits at a time.
    for (sel, mask) in [
        (SchTxSel::All, 0xffff),
        (SchTxSel::Hiq, CTN_TXEN_HGQ),
        (SchTxSel::Mg0, CTN_TXEN_MGQ),
        (SchTxSel::Macid, 0xffff),
    ] {
        let mut io = Model::zeroed();
        io.set(CMAC_FUNC_EN, 4, CMAC_ON);
        io.set(CTN_TXEN, 2, 0x0f0f);
        assert_eq!(stop_sch_tx(&mut io, None, sel), Ok(0x0f0f), "{sel:?}");
        let mut s = Script::default();
        s.r(2, CTN_TXEN, 0x0f0f);
        s.r32(CMAC_FUNC_EN, CMAC_ON);
        s.r(2, CTN_TXEN, 0x0f0f);
        s.w(2, CTN_TXEN, 0x0f0f & !mask);
        assert_eq!(io.log, s.0, "{sel:?}");
    }
    let mut io = Model::zeroed();
    io.set(CMAC_FUNC_EN, 4, CMAC_ON);
    io.set(CTN_TXEN, 2, 0xff00);
    assert_eq!(resume_sch_tx(&mut io, None, 0x1234), Ok(()));
    assert_eq!(io.get(CTN_TXEN, 2), 0x1234);

    // With firmware: the request goes through the mailbox and needs
    // TX_PAUSE_RPT back; CTN_TXEN is only read.
    let pause = [
        prep(4, C2HREG_HDR_FUNC_MASK) | prep(1, C2HREG_HDR_LEN_MASK),
        0,
        0,
        0,
    ];
    let mut io = Model::zeroed();
    io.set(CMAC_FUNC_EN, 4, CMAC_ON);
    io.set(CTN_TXEN, 2, 0xabcd);
    io.reply = Some(pause);
    let mut fw = mailbox();
    assert_eq!(
        stop_sch_tx(&mut io, Some(&mut fw), SchTxSel::Hiq),
        Ok(0xabcd)
    );
    let mut s = Script::default();
    s.r(2, CTN_TXEN, 0xabcd);
    s.r32(CMAC_FUNC_EN, CMAC_ON);
    s.r(1, H2CREG_CTRL, 0);
    // SCH_TX_EN with 6 content bytes: two words, the header's included.
    s.w32(H2CREG_DATA0, 0x0000_0205);
    s.w32(H2CREG_DATA1, CTN_TXEN_HGQ);
    s.w32(H2CREG_DATA2, 0);
    s.w32(H2CREG_DATA3, 0);
    s.rmw8(UDM1 + 1, 0, 0x01);
    s.w(1, H2CREG_CTRL, 0x01);
    s.r(1, C2HREG_CTRL, 0x01);
    for (index, word) in pause.into_iter().enumerate() {
        s.r32(C2HREG_DATA0 + 4 * index as u32, word);
    }
    s.w(1, C2HREG_CTRL, 0);
    s.rmw8(UDM1 + 1, 0x01, 0x11);
    assert_eq!(io.log, s.0);
    assert_eq!((fw.h2c_counter(), fw.c2h_counter()), (1, 1));
    assert_eq!(io.get(CTN_TXEN, 2), 0xabcd);

    // Another function back is rtw89's -EINVAL.
    let mut io = Model::zeroed();
    io.set(CMAC_FUNC_EN, 4, CMAC_ON);
    io.reply = Some([prep(3, C2HREG_HDR_FUNC_MASK), 0, 0, 0]);
    assert_eq!(
        resume_sch_tx(&mut io, Some(&mut mailbox()), 0xffff),
        Err(Cause::TxPauseReport { id: 3 })
    );
    // A CMAC that reads off is refused before anything is asked.
    let mut io = Model::zeroed();
    assert_eq!(
        stop_sch_tx(&mut io, None, SchTxSel::All),
        Err(Cause::CmacOff { value: 0 })
    );
    assert_eq!(io.log.len(), 2);
}

#[test]
fn after_stage_1_the_init_runs_on_its_chip_and_sends_its_h2c_on_ch12() {
    use crate::wifi::realtek::{
        ax::{
            bootstrap::{
                self, Claim, Stage1,
                tests::{ACV, CUT, DEVICE, board, catalog, container},
            },
            h2c::H2C_DESC_SIZE,
            model::Chip,
            pci::tests::{Access as Bus, Domain, Placement, Source},
            txwd::DescInfo,
        },
        identity::tests::observed,
    };
    let domain = Domain::new(Placement::Oracle);
    let chip = Chip::new(&board(1), ACV, domain.clone());
    let catalog = catalog(container());
    let mut config = &chip;
    let claim = Claim {
        io: &chip,
        source: &Source,
        domain: domain.clone(),
        observed: observed(DEVICE, CUT),
    };
    // SAFETY: the model, its DMA domain and these pages belong to this test
    // alone; no device reaches them.
    let mut stage1 = unsafe { bootstrap::bring_up(claim, &mut config, &catalog, &mut ()) }.unwrap();
    let before = chip.log().len();
    let downloaded = chip.attempts()[0].len();

    let Stage1 {
        io, rings, channel, ..
    } = &mut stage1;
    let init = init(io, &mut Fwcmd { channel, rings }).unwrap();
    assert_eq!(init.ofld_cfg, Ok(()));
    assert_eq!(init.ba_cam_reset, None);
    assert_eq!(init.hfc_info.pub_info.pub_aval, 446);
    assert_eq!(stage1.channel.sequence(), Sequence(1));
    // The init begins where stage 1 stopped, with the BB reset bits.
    assert!(matches!(
        chip.log()[before],
        Bus::Read {
            width: 1,
            register: SYS_FUNC_EN,
            ..
        }
    ));
    // The chip fetched one frame more on CH12, after the download's: the
    // TXWD body and the offload-config H2C.
    let frames = &chip.attempts()[0];
    assert_eq!(frames.len(), downloaded + 1);
    let frame = frames.last().unwrap();
    assert_eq!(frame[..H2C_DESC_SIZE], DescInfo::fwcmd(16, false).body());
    assert_eq!(frame[H2C_DESC_SIZE..], OFLD_CFG_H2C);

    assert_eq!(stage1.power_off(), Ok(()));
    assert!(!chip.on());
}

/// What a case of the C oracle's second trace runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// The unchanged `rtw89_mac_init`, its PCIe pre-init, firmware download
    /// and power-off stubbed.
    MacInit,
    /// `rtw89_mac_stop_sch_tx(rtwdev, RTW89_MAC_0, &tx_en, sel)`.
    StopSch(SchTxSel),
    /// `rtw89_mac_resume_sch_tx(rtwdev, RTW89_MAC_0, tx_en)`.
    ResumeSch(u16),
}

/// One case of the C oracle's second trace, in its order.
#[derive(Clone, Copy, Debug)]
struct Case {
    kind: Kind,
    fill: Fill,
    faults: Faults,
    /// `rtw89_h2c_tx` returns `-ENOSPC`.
    h2c_refuse: bool,
    /// `RTW89_FLAG_FW_RDY`, with the firmware answering the mailbox with
    /// this function.
    firmware: Option<u8>,
    /// CMAC_FUNC_EN's CMAC_EN set (true) or cleared before a scheduler case.
    cmac_on: bool,
}

fn oracle_cases() -> Vec<Case> {
    let mac_init = |fill, change: fn(&mut Faults), h2c_refuse| {
        let mut faults = Faults::default();
        change(&mut faults);
        Case {
            kind: Kind::MacInit,
            fill,
            faults,
            h2c_refuse,
            firmware: None,
            cmac_on: true,
        }
    };
    let sch = |kind, fill, firmware, cmac_on| Case {
        kind,
        fill,
        faults: Faults::default(),
        h2c_refuse: false,
        firmware,
        cmac_on,
    };
    let rpt = Some(C2HREG_FUNC_TX_PAUSE_RPT);
    use {Fill::*, Kind::*, SchTxSel::*};
    vec![
        mac_init(Pattern, |_| {}, false),
        mac_init(Ones, |_| {}, false),
        mac_init(Zeros, |_| {}, false),
        mac_init(Pattern, |f| f.xtal_stuck = true, false),
        mac_init(Pattern, |f| f.ss_stuck = true, false),
        mac_init(Pattern, |f| f.cam_stuck = true, false),
        mac_init(Pattern, |f| f.bacam_stuck = true, false),
        mac_init(Pattern, |f| f.pub_short = true, false),
        mac_init(Pattern, |f| f.cmac_dead = true, false),
        mac_init(Pattern, |_| {}, true),
        mac_init(Pattern, |f| f.dmac_dead = true, false),
        sch(StopSch(All), Pattern, None, true),
        sch(StopSch(Hiq), Pattern, None, true),
        sch(StopSch(Mg0), Pattern, None, true),
        sch(StopSch(Macid), Pattern, None, true),
        sch(StopSch(All), Ones, None, true),
        sch(ResumeSch(0x1234), Pattern, None, true),
        sch(StopSch(All), Pattern, rpt, true),
        sch(StopSch(Mg0), Ones, rpt, true),
        sch(ResumeSch(0xbeef), Pattern, rpt, true),
        sch(StopSch(Hiq), Pattern, Some(0), true),
        sch(StopSch(All), Pattern, None, false),
    ]
}

/// The errno rtw89 returns for `cause`.
fn errno(cause: Cause) -> i32 {
    match cause {
        Cause::Io(io::Error::Timeout { .. }) => -110,
        Cause::DmacOff { .. }
        | Cause::CmacOff { .. }
        | Cause::Dle(
            dle::Error::DmacOff { .. } | dle::Error::HfcPubCfg | dle::Error::HfcPubInfo { .. },
        ) => -14,
        Cause::Dle(_) | Cause::TxPauseReport { .. } => -22,
        Cause::Io(error) => panic!("the model refuses no access: {error:?}"),
    }
}

/// The harness's records of `rtwdev->mac` after a MAC init that returned
/// 0: `dle_info` (14, 15), `hfc_param` (16 to 19, then 20 per channel when
/// `ch_cfg` is set), `hfc_param.ch_info` (21 per channel) and
/// `hfc_param.pub_info` (22, 23).
fn push_state(trace: &mut Vec<u8>, init: &Init) {
    let info = &init.dle_info;
    push(
        trace,
        14,
        info.qta_mode as u32,
        u32::from(info.ple_pg_size) | u32::from(info.ple_free_pg) << 16,
    );
    push(trace, 15, info.c0_rx_qta.into(), info.c1_rx_qta.into());
    let param = &init.hfc_param;
    push(
        trace,
        16,
        u32::from(param.en) | u32::from(param.h2c_en) << 1 | (param.mode as u32) << 8,
        param.ch_cfg.is_some().into(),
    );
    let pub_cfg = &param.pub_cfg;
    push(
        trace,
        17,
        u32::from(pub_cfg.grp0) | u32::from(pub_cfg.grp1) << 16,
        u32::from(pub_cfg.pub_max) | u32::from(pub_cfg.wp_thrd) << 16,
    );
    let prec = &param.prec_cfg;
    push(
        trace,
        18,
        u32::from(prec.ch011_prec) | u32::from(prec.h2c_prec) << 16,
        u32::from(prec.wp_ch07_prec) | u32::from(prec.wp_ch811_prec) << 16,
    );
    push(
        trace,
        19,
        0,
        u32::from(prec.ch011_full_cond)
            | u32::from(prec.h2c_full_cond) << 8
            | u32::from(prec.wp_ch07_full_cond) << 16
            | u32::from(prec.wp_ch811_full_cond) << 24,
    );
    for (channel, cfg) in param.ch_cfg.into_iter().flatten().enumerate() {
        push(
            trace,
            20,
            channel as u32 | u32::from(cfg.grp) << 8,
            u32::from(cfg.min) | u32::from(cfg.max) << 16,
        );
    }
    for (channel, entry) in init.hfc_info.ch_info.iter().enumerate() {
        push(
            trace,
            21,
            channel as u32,
            u32::from(entry.aval) | u32::from(entry.used) << 16,
        );
    }
    let pub_info = &init.hfc_info.pub_info;
    push(
        trace,
        22,
        u32::from(pub_info.g0_used) | u32::from(pub_info.g1_used) << 16,
        u32::from(pub_info.g0_aval) | u32::from(pub_info.g1_aval) << 16,
    );
    push(
        trace,
        23,
        u32::from(pub_info.pub_aval) | u32::from(pub_info.wp_aval) << 16,
        0,
    );
}

/// The next length-prefixed segment of the oracle's trace.
fn segment<'a>(trace: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let length = u32::from_le_bytes(trace[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    let segment = &trace[*offset..*offset + length];
    *offset += length;
    segment
}

/// One case as the Rust side runs it: the trace segment it gives.
fn replay(case: &Case) -> Vec<u8> {
    let mut io = Model::new(case.fill, case.faults);
    let mut expected;
    match case.kind {
        Kind::MacInit => {
            let mut recorder = Recorder::new();
            recorder.refuse = case.h2c_refuse;
            // rtw89_mac_partial_init: stage 1's DMAC pre-init, then the PCIe
            // pre-init's stub and the download's (RTW89_FW_NORMAL, no BB).
            let result = match dle::partial_init_before_hci(&mut io) {
                Ok(_) => {
                    io.mark(12, 0, 0);
                    io.mark(13, 1, 0);
                    init(&mut io, &mut recorder).map_err(|error| error.cause)
                }
                Err(error) => Err(Cause::from(error)),
            };
            if result.is_err() {
                // rtw89_mac_init's fail label: rtw89_mac_pwr_off's stub.
                io.mark(30, 0, 0);
            }
            expected = encode(&io.log);
            match result {
                Ok(init) => {
                    push(&mut expected, 11, 0, 0);
                    push_state(&mut expected, &init);
                }
                Err(cause) => push(&mut expected, 11, 0, errno(cause) as u32),
            }
            push(&mut expected, 24, recorder.sequence.0.into(), 0);
        }
        Kind::StopSch(_) | Kind::ResumeSch(_) => {
            // The scheduler cases start with an idle mailbox and CMAC_EN as
            // the case says.
            io.set(H2CREG_CTRL, 1, 0);
            io.set(C2HREG_CTRL, 1, 0);
            let cmac = io.get(CMAC_FUNC_EN, 4);
            let cmac = if case.cmac_on {
                cmac | CMAC_EN
            } else {
                cmac & !CMAC_EN
            };
            io.set(CMAC_FUNC_EN, 4, cmac);
            io.reply = case.firmware.map(|id| {
                [
                    prep(id.into(), C2HREG_HDR_FUNC_MASK) | prep(2, C2HREG_HDR_LEN_MASK),
                    0x1111_2222,
                    0x3333_4444,
                    0x5555_6666,
                ]
            });
            let mut fw = mailbox();
            let firmware = case.firmware.map(|_| &mut fw);
            let result = match case.kind {
                Kind::StopSch(sel) => stop_sch_tx(&mut io, firmware, sel).map(Some),
                Kind::ResumeSch(tx_en) => resume_sch_tx(&mut io, firmware, tx_en).map(|()| None),
                Kind::MacInit => unreachable!(),
            };
            expected = encode(&io.log);
            match result {
                Ok(tx_en) => {
                    push(&mut expected, 11, 0, 0);
                    if let Some(tx_en) = tx_en {
                        push(&mut expected, 25, tx_en.into(), 0);
                    }
                }
                Err(cause) => push(&mut expected, 11, 0, errno(cause) as u32),
            }
            push(
                &mut expected,
                26,
                fw.h2c_counter().into(),
                fw.c2h_counter().into(),
            );
        }
    }
    expected
}

#[test]
#[ignore = "oracle: STELA_RTW89_MAC_ORACLE"]
fn scc_init_register_trace_matches_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_MAC_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("init_trace.bin")).unwrap();
    let mut offset = 0;
    let cases = oracle_cases();
    assert_eq!(cases.len(), 22);
    for case in cases {
        assert_eq!(segment(&trace, &mut offset), replay(&case), "{case:?}");
    }
    assert_eq!(offset, trace.len());
}
