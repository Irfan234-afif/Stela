extern crate std;

use super::*;
use crate::wifi::realtek::ax::rtw8852b::{
    PCIE_QUOTA, RTW8852B_DLE_MEM_PCIE, RTW8852B_HFC_CHCFG_PCIE, RTW8852B_HFC_PARAM_INI_PCIE,
    RTW8852B_HFC_PUBCFG_PCIE,
};
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

fn r32(register: u32, value: u32) -> Access {
    Access::Read {
        width: 4,
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

/// How the model's DMAC_FUNC_EN answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dmac {
    /// As written.
    Answers,
    /// `RTW89_R32_DEAD` on every read.
    ReadsDead,
    /// `RTW89_R32_EA` on every read.
    ReadsEa,
    /// As written, less DMAC_FUNC_EN, which never sticks.
    DropsDmacFuncEn,
}

/// What the model's MAC space holds before the first access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fill {
    /// Byte `i` holds `i * 37 + 11`.
    Pattern,
    Ones,
    Zeros,
}

const MEMORY: usize = 0x1_0000;

/// The register model the C oracle's harness uses: MAC space as
/// little-endian bytes, WDE_INI_STATUS and PLE_INI_STATUS reading both
/// ready bits, or the queue's bit alone when stuck, and DMAC_FUNC_EN as
/// `dmac` says.
struct Model {
    memory: Vec<u8>,
    log: Vec<Access>,
    /// Whether accesses are logged; reads and delays are always counted.
    logging: bool,
    reads: Vec<usize>,
    waited_us: u64,
    wde_stuck: bool,
    ple_stuck: bool,
    dmac: Dmac,
}

/// The registers the model gives behavior; each is reached 32 bits at a
/// time.
fn special(register: u32) -> bool {
    [DMAC_FUNC_EN, WDE_INI_STATUS, PLE_INI_STATUS]
        .iter()
        .any(|&at| (at..at + 4).contains(&register))
}

impl Model {
    fn new(fill: Fill) -> Self {
        let memory = match fill {
            Fill::Pattern => (0..MEMORY).map(|at| (at * 37 + 11) as u8).collect(),
            Fill::Ones => vec![0xff; MEMORY],
            Fill::Zeros => vec![0; MEMORY],
        };
        Self {
            memory,
            log: Vec::new(),
            logging: true,
            reads: vec![0; MEMORY],
            waited_us: 0,
            wde_stuck: false,
            ple_stuck: false,
            dmac: Dmac::Answers,
        }
    }
    fn zeroed() -> Self {
        Self::new(Fill::Zeros)
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
            WDE_INI_STATUS if self.wde_stuck => {
                value = (value | WDE_Q_MGN_INI_RDY) & !WDE_BUF_MGN_INI_RDY;
            }
            WDE_INI_STATUS => value |= WDE_MGN_INI_RDY,
            PLE_INI_STATUS if self.ple_stuck => {
                value = (value | PLE_Q_MGN_INI_RDY) & !PLE_BUF_MGN_INI_RDY;
            }
            PLE_INI_STATUS => value |= PLE_MGN_INI_RDY,
            DMAC_FUNC_EN if self.dmac == Dmac::ReadsDead => value = R32_DEAD,
            DMAC_FUNC_EN if self.dmac == Dmac::ReadsEa => value = R32_EA,
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
        if register == DMAC_FUNC_EN && self.dmac == Dmac::DropsDmacFuncEn {
            stored &= !DMAC_FUNC_EN_BIT;
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

/// The DLFW quota's writes on a zeroed model: page buffers, then
/// `SET_QUOTA` for WDE QTA0, 1, 3, 4 and PLE QTA0 to QTA10.
fn dlfw_quota() -> Vec<Access> {
    let mut expected = vec![
        // dle_mix_cfg_ax: WDE 64-byte pages, no free page; PLE 128-byte
        // pages, 64 free, starting 1024 * 64 / 8192 = 8 units in.
        r32(WDE_PKTBUF_CFG, 0),
        w32(WDE_PKTBUF_CFG, 0),
        r32(PLE_PKTBUF_CFG, 0),
        w32(PLE_PKTBUF_CFG, 0x0040_0801),
        // wde_qt4 is zero, but the WCPU minimum is wde_qt7's 48.
        w32(WDE_QTA0_CFG, 0),
        w32(WDE_QTA1_CFG, 48),
        w32(WDE_QTA3_CFG, 0),
        w32(WDE_QTA4_CFG, 0),
    ];
    // ple_qt13, as both minimum and maximum: C2H 16 and H2C 48.
    for (index, value) in [0, 0, 0x0010_0010, 0x0030_0030, 0, 0, 0, 0, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        expected.push(w32(PLE_QTA0_CFG + 4 * index as u32, value));
    }
    expected
}

/// The accesses of a first probe's DMAC pre-init on a zeroed model,
/// transcribed from rtw89_mac_ctrl_hci_dma_trx, rtw89_mac_dmac_pre_init and
/// their callees.
fn cold_pre_init() -> Vec<Access> {
    let mut expected = vec![
        // rtw89_mac_ctrl_hci_dma_trx(rtwdev, true)
        r32(HCI_FUNC_EN, 0),
        w32(HCI_FUNC_EN, 0x3),
        // rtw89_mac_hci_func_en_ax
        w32(DMAC_FUNC_EN, 0x6044_0000),
        // rtw89_mac_dmac_func_pre_en_ax
        w32(DMAC_CLK_EN, 0x0004_0000),
        // rtw89_mac_dle_init: rtw89_mac_check_mac_en_ax
        r32(DMAC_FUNC_EN, 0x6044_0000),
        // dle_func_en_ax(rtwdev, false)
        r32(DMAC_FUNC_EN, 0x6044_0000),
        w32(DMAC_FUNC_EN, 0x6044_0000),
        // dle_clk_en_ax(rtwdev, true)
        r32(DMAC_CLK_EN, 0x0004_0000),
        w32(DMAC_CLK_EN, 0x0484_0000),
    ];
    expected.extend(dlfw_quota());
    expected.extend([
        // dle_func_en_ax(rtwdev, true)
        r32(DMAC_FUNC_EN, 0x6044_0000),
        w32(DMAC_FUNC_EN, 0x64c4_0000),
        // chk_dle_rdy_ax, WDE then PLE
        r32(WDE_INI_STATUS, 0x3),
        r32(PLE_INI_STATUS, 0x3),
        // rtw89_mac_hfc_init: rtw89_mac_check_mac_en_ax
        r32(DMAC_FUNC_EN, 0x64c4_0000),
        // hfc_func_en_ax(rtwdev, false, false)
        r32(HCI_FC_CTRL, 0),
        w32(HCI_FC_CTRL, 0),
        // hfc_h2c_cfg_ax: H2C pre-cost 40, full condition 0
        w32(CH_PAGE_CTRL, 0x0028_0000),
        r32(HCI_FC_CTRL, 0),
        w32(HCI_FC_CTRL, 0),
        // hfc_func_en_ax(rtwdev, false, true)
        r32(HCI_FC_CTRL, 0),
        w32(HCI_FC_CTRL, 0x8),
    ]);
    expected
}

/// What rtw89's `rtwdev->mac` holds after the pre-init: the SCC entry's DLE
/// info and flow-control parameters, H2C flow control alone enabled.
fn scc_pre_init() -> PreInit {
    PreInit {
        dle_info: DleInfo {
            qta_mode: QtaMode::Scc,
            ple_pg_size: 128,
            ple_free_pg: 496,
            c0_rx_qta: 89,
            c1_rx_qta: 0,
        },
        hfc_param: HfcParam {
            en: false,
            h2c_en: true,
            mode: HcifcMode::Poh,
            ch_cfg: Some(&RTW8852B_HFC_CHCFG_PCIE),
            pub_cfg: RTW8852B_HFC_PUBCFG_PCIE,
            prec_cfg: mac_size::HFC_PRECCFG_PCIE,
        },
    }
}

#[test]
fn dmac_pre_init_follows_rtw89_access_for_access() {
    let mut io = Model::zeroed();
    assert_eq!(partial_init_before_hci(&mut io), Ok(scc_pre_init()));
    assert_eq!(io.log, cold_pre_init());
    assert_eq!(io.waited_us, 0);

    // rtw89_mac_dmac_pre_init alone is the same less the HCI DMA enables.
    let mut alone = Model::zeroed();
    assert_eq!(dmac_pre_init(&mut alone), Ok(scc_pre_init()));
    assert_eq!(alone.log, cold_pre_init()[2..]);
}

#[test]
fn the_dlfw_quota_is_rtw8852b_pcie_s_and_flow_control_takes_the_scc_entry() {
    let dlfw = get_dle_mem_cfg(&PCIE_QUOTA, QtaMode::Dlfw).unwrap();
    assert_eq!(dlfw, RTW8852B_DLE_MEM_PCIE[2].as_ref().unwrap());
    assert_eq!(*dlfw.wde_size, DleSize::new(64, 0, 1024));
    assert_eq!(*dlfw.ple_size, DleSize::new(128, 64, 960));
    assert_eq!(*dlfw.wde_min_qt, WdeQuota::new([0; 4]));
    assert_eq!(dlfw.wde_max_qt, dlfw.wde_min_qt);
    assert_eq!(
        *dlfw.ple_min_qt,
        PleQuota::new([0, 0, 16, 48, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(dlfw.ple_max_qt, dlfw.ple_min_qt);
    // The DLFW pages fill the whole FIFO, SCC's what SCC leaves of it.
    assert_eq!(dle_used_size(dlfw), 196_608);
    assert_eq!(dle_expected_used_size(&PCIE_QUOTA, QtaMode::Dlfw), 196_608);
    let scc = get_dle_mem_cfg(&PCIE_QUOTA, QtaMode::Scc).unwrap();
    assert_eq!(dle_used_size(scc), 98_304);
    assert_eq!(dle_expected_used_size(&PCIE_QUOTA, QtaMode::Scc), 98_304);
    assert_eq!(scc.wde_min_qt.wcpu, 48);
    assert_eq!(
        DleInfo::of(scc),
        DleInfo {
            qta_mode: QtaMode::Scc,
            ple_pg_size: 128,
            ple_free_pg: 496,
            c0_rx_qta: 89,
            c1_rx_qta: 0,
        }
    );
    assert_eq!(
        get_dle_mem_cfg(&PCIE_QUOTA, QtaMode::Wow).map(|cfg| cfg.ple_max_qt),
        Some(&mac_size::PLE_QT_52B_WOW)
    );
    // DBCC's zeroed entry and INVALID's NULL one give nothing.
    assert_eq!(get_dle_mem_cfg(&PCIE_QUOTA, QtaMode::Dbcc), None);
    assert_eq!(get_dle_mem_cfg(&PCIE_QUOTA, QtaMode::Invalid), None);

    // SCC and DLFW name the same pre-costs, so which of them the flow
    // control takes changes no access; SCC's alone names channels and
    // public pages, and the pre-init keeps them.
    let ini = &RTW8852B_HFC_PARAM_INI_PCIE;
    assert_eq!(
        ini[QtaMode::Scc as usize].prec_cfg,
        Some(&mac_size::HFC_PRECCFG_PCIE)
    );
    assert_eq!(
        ini[QtaMode::Dlfw as usize].prec_cfg,
        Some(&mac_size::HFC_PRECCFG_PCIE)
    );
    assert_eq!(ini[QtaMode::Dlfw as usize].ch_cfg, None);
    assert_eq!(mac_size::HFC_PRECCFG_PCIE.h2c_prec, 40);
    assert_eq!(mac_size::HFC_PRECCFG_PCIE.h2c_full_cond, 0);
    let mut io = Model::zeroed();
    let pre_init = dmac_pre_init(&mut io).unwrap();
    assert_eq!(pre_init.dle_info.qta_mode, QtaMode::Scc);
    assert_eq!(pre_init.hfc_param.ch_cfg, Some(&RTW8852B_HFC_CHCFG_PCIE));
    assert_eq!(RTW8852B_HFC_CHCFG_PCIE[12], HfcChCfg::new(40, 0, 0));

    // With the DLFW entry's parameters the pre-costs stay and nothing else
    // is named.
    let mut param = HfcParam::ZERO;
    hfc_reset_param(&mut param, &PCIE_QUOTA, QtaMode::Dlfw);
    assert_eq!(
        param,
        HfcParam {
            prec_cfg: mac_size::HFC_PRECCFG_PCIE,
            ..HfcParam::ZERO
        }
    );
}

#[test]
fn a_dle_ready_bit_that_never_answers_names_its_register_after_2000_steps_of_1_us() {
    for (wde_stuck, register, mask) in [
        (true, WDE_INI_STATUS, WDE_MGN_INI_RDY),
        (false, PLE_INI_STATUS, PLE_MGN_INI_RDY),
    ] {
        let mut io = Model::zeroed();
        io.wde_stuck = wde_stuck;
        io.ple_stuck = !wde_stuck;
        assert_eq!(
            dmac_pre_init(&mut io),
            Err(Error::Io(io::Error::Timeout { register, mask })),
            "{register:#x}"
        );
        // 2001 reads a step apart; the queue's bit alone does not answer.
        assert_eq!(io.reads[register as usize], 2001);
        assert_eq!(io.count(delay(1)), 2000);
        assert_eq!(io.waited_us, 2000);
        assert_eq!(io.log.last(), Some(&r32(register, 0x2)));
        // A timeout returns without the error path or the flow control.
        assert!(writes(&io.log, HCI_FC_CTRL).is_empty());
        assert_eq!(writes(&io.log, DMAC_FUNC_EN).last(), Some(&0x64c4_0000));
        if !wde_stuck {
            assert_eq!(io.reads[WDE_INI_STATUS as usize], 1);
        }
    }
}

#[test]
fn a_dmac_that_reads_dead_ea_or_without_its_enables_is_refused_before_the_quota() {
    for (dmac, value) in [
        (Dmac::ReadsDead, R32_DEAD),
        (Dmac::ReadsEa, R32_EA),
        (Dmac::DropsDmacFuncEn, 0x4044_0000),
    ] {
        let mut io = Model::zeroed();
        io.dmac = dmac;
        assert_eq!(
            partial_init_before_hci(&mut io),
            Err(Error::DmacOff { value }),
            "{dmac:?}"
        );
        assert_eq!(io.log.len(), 5, "{dmac:?}");
        assert_eq!(io.log[..4], cold_pre_init()[..4]);
        assert_eq!(io.log[4], r32(DMAC_FUNC_EN, value));
    }
}

/// A quota of the chip's tables with one thing changed, leaked for the
/// `'static` borrows rtw89's tables have.
fn altered(change: impl FnOnce(&mut [Option<DleMem>; QTA_NUM], &mut ChipQuota)) -> ChipQuota {
    let mut dle_mem = RTW8852B_DLE_MEM_PCIE;
    let mut quota = PCIE_QUOTA;
    change(&mut dle_mem, &mut quota);
    quota.dle_mem = leak(dle_mem);
    quota
}

fn leak<T: 'static>(value: T) -> &'static T {
    alloc::boxed::Box::leak(alloc::boxed::Box::new(value))
}

#[test]
fn a_quota_that_does_not_fit_takes_rtw89s_error_path() {
    // rtw89's error label: the DLE disabled, then both INI statuses read.
    let failed = [
        r32(DMAC_FUNC_EN, 0x6044_0000),
        w32(DMAC_FUNC_EN, 0x6044_0000),
        r32(WDE_INI_STATUS, 0x3),
        r32(PLE_INI_STATUS, 0x3),
    ];
    let checked = r32(DMAC_FUNC_EN, 0x6044_0000);

    let small = altered(|_, quota| quota.fifo_size -= 64);
    let missing_scc = altered(|dle_mem, _| dle_mem[QtaMode::Scc as usize] = None);
    let missing_dlfw = altered(|dle_mem, _| dle_mem[QtaMode::Dlfw as usize] = None);
    // Pages of the size refused, as many bytes as before, so the FIFO is
    // still filled.
    let wde_256 = altered(|dle_mem, _| {
        dle_mem[QtaMode::Dlfw as usize].as_mut().unwrap().wde_size =
            leak(DleSize::new(256, 0, 256));
    });
    let ple_64 = altered(|dle_mem, _| {
        dle_mem[QtaMode::Dlfw as usize].as_mut().unwrap().ple_size =
            leak(DleSize::new(64, 128, 1920));
    });

    for (quota, error, before) in [
        (
            small,
            Error::DleSize {
                used: 196_608,
                expected: 196_544,
            },
            vec![checked],
        ),
        (missing_dlfw, Error::NoDleMem(QtaMode::Dlfw), vec![checked]),
        (missing_scc, Error::NoDleMem(QtaMode::Scc), vec![checked]),
        (
            wde_256,
            Error::WdePageSize(256),
            vec![
                checked,
                r32(DMAC_FUNC_EN, 0x6044_0000),
                w32(DMAC_FUNC_EN, 0x6044_0000),
                r32(DMAC_CLK_EN, 0x0004_0000),
                w32(DMAC_CLK_EN, 0x0484_0000),
                r32(WDE_PKTBUF_CFG, 0),
            ],
        ),
        (
            ple_64,
            Error::PlePageSize(64),
            vec![
                checked,
                r32(DMAC_FUNC_EN, 0x6044_0000),
                w32(DMAC_FUNC_EN, 0x6044_0000),
                r32(DMAC_CLK_EN, 0x0004_0000),
                w32(DMAC_CLK_EN, 0x0484_0000),
                r32(WDE_PKTBUF_CFG, 0),
                w32(WDE_PKTBUF_CFG, 0),
                r32(PLE_PKTBUF_CFG, 0),
            ],
        ),
    ] {
        let mut io = Model::zeroed();
        assert_eq!(dmac_pre_init_with(&mut io, &quota), Err(error), "{error:?}");
        let mut expected = cold_pre_init()[2..4].to_vec();
        expected.extend(before);
        expected.extend(failed);
        assert_eq!(io.log, expected, "{error:?}");
    }
}

#[test]
fn an_scc_dle_init_takes_the_scc_quota_without_an_extension() {
    let mut io = Model::zeroed();
    io.set(DMAC_FUNC_EN, 4, MAC_FUNC_EN | DMAC_FUNC_EN_BIT);
    assert_eq!(
        dle_init(&mut io, QtaMode::Scc, QtaMode::Invalid),
        Ok(DleInfo {
            qta_mode: QtaMode::Scc,
            ple_pg_size: 128,
            ple_free_pg: 496,
            c0_rx_qta: 89,
            c1_rx_qta: 0,
        })
    );
    // 510 free 64-byte WDE pages; 496 free 128-byte PLE pages starting
    // 512 * 64 / 8192 = 4 units in.
    assert_eq!(writes(&io.log, WDE_PKTBUF_CFG), [0x01fe_0000]);
    assert_eq!(writes(&io.log, PLE_PKTBUF_CFG), [0x01f0_0401]);
    // wde_qt7 both ways, the WCPU minimum its own 48.
    let wde: Vec<u32> = [WDE_QTA0_CFG, WDE_QTA1_CFG, WDE_QTA3_CFG, WDE_QTA4_CFG]
        .into_iter()
        .flat_map(|register| writes(&io.log, register))
        .collect();
    assert_eq!(wde, [0x01be_01be, 0x0030_0030, 0, 0x0010_0010]);
    // ple_qt18 as minimum, ple_qt58 as maximum.
    let ple: Vec<u32> = (0..11)
        .flat_map(|index| writes(&io.log, PLE_QTA0_CFG + 4 * index))
        .collect();
    assert_eq!(
        ple,
        [
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
    );
    // DLFW is checked against the whole FIFO: SCC's sizes as DLFW's fail
    // before any write.
    let mut io = Model::zeroed();
    io.set(DMAC_FUNC_EN, 4, MAC_FUNC_EN | DMAC_FUNC_EN_BIT);
    let scc_as_dlfw = altered(|dle_mem, _| {
        dle_mem[QtaMode::Dlfw as usize] = dle_mem[QtaMode::Scc as usize].map(|scc| DleMem {
            mode: QtaMode::Dlfw,
            ..scc
        });
    });
    assert_eq!(
        dle_init_with(&mut io, &scc_as_dlfw, QtaMode::Dlfw, QtaMode::Scc),
        Err(Error::DleSize {
            used: 98_304,
            expected: 196_608,
        })
    );
    assert!(writes(&io.log, WDE_PKTBUF_CFG).is_empty());
}

#[test]
fn the_hci_dma_enables_are_set_and_cleared_together() {
    let mut io = Model::new(Fill::Pattern);
    let before = io.get(HCI_FUNC_EN, 4);
    ctrl_hci_dma_trx(&mut io, true).unwrap();
    ctrl_hci_dma_trx(&mut io, false).unwrap();
    assert_eq!(
        io.log,
        [
            r32(HCI_FUNC_EN, before),
            w32(HCI_FUNC_EN, before | 0x3),
            r32(HCI_FUNC_EN, before | 0x3),
            w32(HCI_FUNC_EN, before & !0x3),
        ]
    );
}

/// What a case runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// `rtw89_mac_partial_init(rtwdev, false, false)`, the PCIe pre-init
    /// and the firmware download stubbed.
    PartialInit,
    /// `rtw89_mac_dle_init(rtwdev, RTW89_QTA_SCC, RTW89_QTA_INVALID)`.
    DleScc,
}

/// One case of the C oracle, in its order.
#[derive(Clone, Copy, Debug)]
struct Case {
    kind: Kind,
    fill: Fill,
    wde_stuck: bool,
    ple_stuck: bool,
    dmac: Dmac,
}

fn oracle_cases() -> Vec<Case> {
    let case = |kind, fill, wde_stuck, ple_stuck, dmac| Case {
        kind,
        fill,
        wde_stuck,
        ple_stuck,
        dmac,
    };
    use {Dmac::*, Fill::*, Kind::*};
    vec![
        case(PartialInit, Pattern, false, false, Answers),
        case(PartialInit, Ones, false, false, Answers),
        case(PartialInit, Zeros, false, false, Answers),
        case(PartialInit, Pattern, true, false, Answers),
        case(PartialInit, Pattern, false, true, Answers),
        case(PartialInit, Pattern, false, false, ReadsDead),
        case(PartialInit, Pattern, false, false, ReadsEa),
        case(PartialInit, Pattern, false, false, DropsDmacFuncEn),
        case(DleScc, Pattern, false, false, Answers),
        case(DleScc, Ones, false, false, Answers),
    ]
}

/// The errno rtw89 returns for `error`.
fn errno(error: Error) -> i32 {
    match error {
        Error::DmacOff { .. } | Error::HfcPubCfg | Error::HfcPubInfo { .. } => -14,
        Error::Io(io::Error::Timeout { .. }) => -110,
        Error::NoDleMem(_)
        | Error::DleSize { .. }
        | Error::WdePageSize(_)
        | Error::PlePageSize(_)
        | Error::HfcChCfg { .. } => -22,
        Error::Io(error) => panic!("the model refuses no access: {error:?}"),
    }
}

/// The harness's records of `rtwdev->mac.dle_info` (tags 14 and 15).
fn push_dle_info(trace: &mut Vec<u8>, info: &DleInfo) {
    push(
        trace,
        14,
        info.qta_mode as u32,
        u32::from(info.ple_pg_size) | u32::from(info.ple_free_pg) << 16,
    );
    push(trace, 15, info.c0_rx_qta.into(), info.c1_rx_qta.into());
}

/// The harness's records of `rtwdev->mac.hfc_param` (tags 16 to 20).
fn push_hfc_param(trace: &mut Vec<u8>, param: &HfcParam) {
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
#[ignore = "oracle: STELA_RTW89_MAC_ORACLE"]
fn dlfw_quota_register_trace_matches_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_MAC_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.bin")).unwrap();
    let mut offset = 0;
    let cases = oracle_cases();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let mut io = Model::new(case.fill);
        io.wde_stuck = case.wde_stuck;
        io.ple_stuck = case.ple_stuck;
        io.dmac = case.dmac;
        let mut expected;
        match case.kind {
            Kind::PartialInit => {
                let result = partial_init_before_hci(&mut io);
                expected = encode(&io.log);
                match result {
                    Ok(pre_init) => {
                        // The PCIe pre-init's stub, then the download's,
                        // with RTW89_FW_NORMAL and no BB: nothing between.
                        push(&mut expected, 12, 0, 0);
                        push(&mut expected, 13, 1, 0);
                        push(&mut expected, 11, 0, 0);
                        push_dle_info(&mut expected, &pre_init.dle_info);
                        push_hfc_param(&mut expected, &pre_init.hfc_param);
                    }
                    Err(error) => push(&mut expected, 11, 0, errno(error) as u32),
                }
            }
            Kind::DleScc => {
                let result = dle_init(&mut io, QtaMode::Scc, QtaMode::Invalid);
                expected = encode(&io.log);
                match result {
                    Ok(info) => {
                        push(&mut expected, 11, 0, 0);
                        push_dle_info(&mut expected, &info);
                    }
                    Err(error) => push(&mut expected, 11, 0, errno(error) as u32),
                }
            }
        }
        assert_eq!(segment(&trace, &mut offset), expected, "{case:?}");
    }
    assert_eq!(offset, trace.len());
}
