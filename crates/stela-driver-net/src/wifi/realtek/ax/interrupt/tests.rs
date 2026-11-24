extern crate std;

use super::*;
use crate::wifi::realtek::ax::pci::tests::{push, segment};
use alloc::{collections::BTreeMap, vec, vec::Vec};

/// One register access, or a record of the test's own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    Read { register: u32, value: u32 },
    Write { register: u32, value: u32 },
    Mark { tag: u32, a: u32, b: u32 },
}

/// MAC registers, 32 bits each, whose three HISRs clear the bits written
/// to them, as the C oracle's harness models them.
#[derive(Default)]
struct Model {
    registers: BTreeMap<u32, u32>,
    log: Vec<Access>,
}

const HISRS: [u32; 3] = [HISR0, PCIE_HISR00, PCIE_HISR10];
const RXQ_IDX: u32 = DMA_ADDR_SET_RX[RxChannel::Rxq as usize].idx;
const RPQ_IDX: u32 = DMA_ADDR_SET_RX[RxChannel::Rpq as usize].idx;
/// The masks rtw89 sets on an RTL8852B outside a recovery.
const NORMAL: [u32; 3] = [HALT_C2H_INT_EN, 0x011e_0007, HC10ISR_IND_INT_EN];

impl Model {
    fn get(&self, register: u32) -> u32 {
        self.registers.get(&register).copied().unwrap_or(0)
    }
    /// A register's value, set without an access.
    fn set(&mut self, register: u32, value: u32) {
        self.registers.insert(register, value);
    }
    fn hisrs(&mut self, values: [u32; 3]) {
        for (register, value) in HISRS.into_iter().zip(values) {
            self.set(register, value);
        }
    }
    fn mark(&mut self, tag: u32, a: u32, b: u32) {
        self.log.push(Access::Mark { tag, a, b });
    }
    fn take(&mut self) -> Vec<Access> {
        core::mem::take(&mut self.log)
    }
}

// SAFETY: a register file of this test alone; it reaches no hardware.
unsafe impl Io for Model {
    fn read8(&mut self, register: u32) -> Result<u8, io::Error> {
        Err(io::Error::Register { register })
    }
    fn read16(&mut self, register: u32) -> Result<u16, io::Error> {
        Err(io::Error::Register { register })
    }
    fn read32(&mut self, register: u32) -> Result<u32, io::Error> {
        let value = self.get(register);
        self.log.push(Access::Read { register, value });
        Ok(value)
    }
    fn write8(&mut self, register: u32, _: u8) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn write16(&mut self, register: u32, _: u16) -> Result<(), io::Error> {
        Err(io::Error::Register { register })
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), io::Error> {
        self.log.push(Access::Write { register, value });
        let next = if HISRS.contains(&register) {
            self.get(register) & !value
        } else {
            value
        };
        self.set(register, next);
        Ok(())
    }
    fn delay_us(&mut self, _: u64) {
        unreachable!("the interrupt registers need no delay");
    }
}

fn r(register: u32, value: u32) -> Access {
    Access::Read { register, value }
}
fn w(register: u32, value: u32) -> Access {
    Access::Write { register, value }
}
/// A ring's poll: the channel, its budget and what it handled.
fn polled(channel: RxChannel, budget: u32, handled: u32) -> Access {
    Access::Mark {
        tag: 70 + channel as u32,
        a: budget,
        b: handled,
    }
}

fn masks(values: [u32; 3]) -> [Access; 3] {
    [
        w(HIMR0, values[0]),
        w(PCIE_HIMR00, values[1]),
        w(PCIE_HIMR10, values[2]),
    ]
}

/// RPQ releases every report; RXQ delivers up to its budget and gives the
/// BDs back, moving the host index to the hardware's.
fn rings(
    pending: &mut [u32; RXCH_NUM],
) -> impl FnMut(&mut Model, RxChannel, u32) -> Result<u32, io::Error> + '_ {
    move |io, channel, budget| {
        let ring = channel as usize;
        let handled = match channel {
            RxChannel::Rpq => pending[ring],
            RxChannel::Rxq => pending[ring].min(budget),
        };
        pending[ring] -= handled;
        if channel == RxChannel::Rxq && handled != 0 {
            let idx = io.get(RXQ_IDX);
            io.set(
                RXQ_IDX,
                idx & TXBD_HW_IDX_MASK | idx >> 16 & TXBD_HOST_IDX_MASK,
            );
        }
        io.mark(70 + channel as u32, budget, handled);
        Ok(handled)
    }
}

const LENGTHS: [u32; RXCH_NUM] = [256, 256];

#[test]
fn masks_are_rtw89_pci_config_intr_mask_for_an_rtl8852b() {
    assert_eq!(
        Masks::new(false),
        Masks {
            halt_c2h: NORMAL[0],
            intrs: [NORMAL[1], NORMAL[2]],
        }
    );
    assert_eq!(
        Masks::new(true),
        Masks {
            halt_c2h: HALT_C2H_INT_EN,
            intrs: [HS0ISR_IND_INT_EN, 0],
        }
    );
    let interrupts = Interrupts::new(true);
    assert_eq!(interrupts.masks(), Masks::new(false));
    assert!(!interrupts.running() && !interrupts.under_recovery());
}

#[test]
fn enable_sets_the_masks_and_disable_clears_them_in_rtw89_order() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    interrupts.enable(&mut io).unwrap();
    assert!(interrupts.running());
    assert_eq!(io.take(), masks(NORMAL));
    interrupts.disable(&mut io).unwrap();
    assert!(!interrupts.running());
    assert_eq!(io.take(), masks([0; 3]));
}

#[test]
fn recognize_acknowledges_only_what_it_read_under_the_masks() {
    let mut io = Model::default();
    io.hisrs([HALT_C2H_INT_EN | WDT_TIMEOUT_INT_EN | 1, u32::MAX, u32::MAX]);
    let events = Interrupts::new(true).recognize(&mut io).unwrap();
    assert_eq!(
        io.take(),
        [
            r(HISR0, HALT_C2H_INT_EN | WDT_TIMEOUT_INT_EN | 1),
            r(PCIE_HISR00, u32::MAX),
            r(PCIE_HISR10, u32::MAX),
            w(HISR0, HALT_C2H_INT_EN),
            w(PCIE_HISR00, NORMAL[1]),
            w(PCIE_HISR10, NORMAL[2]),
        ]
    );
    // What the masks leave out stays latched.
    assert_eq!(io.get(HISR0), WDT_TIMEOUT_INT_EN | 1);
    assert_eq!(io.get(PCIE_HISR00), !NORMAL[1]);
    assert_eq!(io.get(PCIE_HISR10), !NORMAL[2]);
    assert!(events.rx() && events.rpq() && events.rdu() && events.dma_stuck());
    assert!(events.indications() && events.halt_c2h() && events.any());
    // RTL8852B's halt mask leaves the watchdog out, as rtw89's does.
    assert!(!events.wdt());
    assert!(!Events::default().any());
}

#[test]
fn a_look_masks_acknowledges_polls_rpq_then_rxq_and_unmasks() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    interrupts.enable(&mut io).unwrap();
    io.take();
    io.hisrs([0, RPQDMA_INT | RXDMA_INT | TXDMA_ACH0_INT_BIT, 0]);
    let mut pending = [5, 3];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    let events = Events {
        halt_c2h: 0,
        isrs: [RPQDMA_INT | RXDMA_INT, 0],
    };
    assert_eq!(
        look,
        Look {
            events: Some(events),
            unavailable: None,
            work: Some(3),
            more: false,
        }
    );
    let mut expected = masks([0; 3]).to_vec();
    expected.extend([
        r(HISR0, 0),
        r(PCIE_HISR00, RPQDMA_INT | RXDMA_INT | TXDMA_ACH0_INT_BIT),
        r(PCIE_HISR10, 0),
        w(HISR0, 0),
        w(PCIE_HISR00, RPQDMA_INT | RXDMA_INT),
        w(PCIE_HISR10, 0),
        w(PCIE_HISR00, RPQDMA_INT | RPQBD_FULL_INT),
        polled(RxChannel::Rpq, 64, 3),
        w(PCIE_HISR00, RXP1DMA_INT | RXDMA_INT | RDU_INT),
        polled(RxChannel::Rxq, 61, 5),
    ]);
    expected.extend(masks(NORMAL));
    assert_eq!(io.take(), expected);
    assert_eq!(pending, [0, 0]);
    // A TX channel's cause is no cause of rtw89's and stays latched.
    assert_eq!(io.get(PCIE_HISR00), TXDMA_ACH0_INT_BIT);
}

/// `B_AX_TXDMA_ACH0_INT`, which no mask here holds.
const TXDMA_ACH0_INT_BIT: u32 = 1 << 3;

#[test]
fn an_rdu_reads_both_rings_and_recovers_as_rxq_is_polled() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    interrupts.enable(&mut io).unwrap();
    io.take();
    io.hisrs([0, RDU_INT | RXDMA_INT, 0]);
    // RXQ's hardware index is one short of the host's: no BD left.
    io.set(RXQ_IDX, 5 << 16 | 6);
    io.set(RPQ_IDX, 10 << 16 | 20);
    let mut pending = [10, 0];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert_eq!(
        look.unavailable,
        Some([
            RingIndex {
                idx: 5 << 16 | 6,
                full: true,
            },
            RingIndex {
                idx: 10 << 16 | 20,
                full: false,
            },
        ])
    );
    let log = io.take();
    let at = |access: Access| log.iter().position(|a| *a == access).unwrap();
    // Recognized and acknowledged, the rings' indices read, then RXQ's
    // clear acknowledges the RDU again before RXQ gives its BDs back.
    let acknowledged = at(w(PCIE_HISR00, RDU_INT | RXDMA_INT));
    let rxq_read = at(r(RXQ_IDX, 5 << 16 | 6));
    let rpq_read = at(r(RPQ_IDX, 10 << 16 | 20));
    let cleared = at(w(PCIE_HISR00, ISR_CLEAR_RXQ.1));
    let drained = at(polled(RxChannel::Rxq, 64, 10));
    assert!(acknowledged < rxq_read && rxq_read < rpq_read && rpq_read < cleared);
    assert!(cleared < drained && drained < at(w(HIMR0, NORMAL[0])));
    assert_eq!(io.get(RXQ_IDX), 5 << 16 | 5);
    // The next look finds no RDU and reads no index.
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert_eq!(look.events, Some(Events::default()));
    assert_eq!(look.unavailable, None);
    assert!(
        !io.take()
            .iter()
            .any(|a| matches!(a, Access::Read { register, .. }
        if *register == RXQ_IDX || *register == RPQ_IDX))
    );
}

#[test]
fn rdu_compares_the_hardware_next_bd_with_the_host_index() {
    assert!(full(7 << 16, 8));
    assert!(full(5 << 16 | 6, 256));
    assert!(!full(5 << 16 | 5, 256));
    // Bits outside the two index fields are not read.
    assert!(full(0xf000_f000 | 3 << 16 | 4, 8));
    // A ring rtw89 never allocated is not full.
    assert!(!full(1 << 16 | 2, 0));
}

#[test]
fn a_spent_budget_leaves_the_masks_off_and_the_next_look_only_polls() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    interrupts.enable(&mut io).unwrap();
    io.take();
    io.hisrs([0, RXDMA_INT, 0]);
    let mut pending = [100, 0];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert_eq!((look.work, look.more), (Some(64), true));
    let log = io.take();
    assert!(log.ends_with(&[polled(RxChannel::Rxq, 64, 64)]));
    // The second look recognizes nothing: it polls as NAPI would again.
    io.hisrs([0, RXDMA_INT, 0]);
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert_eq!(
        look,
        Look {
            events: None,
            unavailable: None,
            work: Some(0),
            more: false,
        }
    );
    let mut expected = vec![
        w(PCIE_HISR00, ISR_CLEAR_RPQ.1),
        polled(RxChannel::Rpq, 64, 0),
        w(PCIE_HISR00, ISR_CLEAR_RXQ.1),
        polled(RxChannel::Rxq, 64, 36),
    ];
    expected.extend(masks(NORMAL));
    assert_eq!(io.take(), expected);

    // RPQ that takes the whole budget leaves RXQ for the next look.
    io.hisrs([0, RPQDMA_INT, 0]);
    let mut pending = [4, 100];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert_eq!((look.work, look.more), (Some(64), true));
    assert!(io.take().ends_with(&[
        w(PCIE_HISR00, ISR_CLEAR_RPQ.1),
        polled(RxChannel::Rpq, 64, 100),
    ]));
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert_eq!((look.work, look.more), (Some(0), false));
    assert_eq!(pending, [0, 0]);
}

#[test]
fn a_stopped_look_touches_nothing() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    io.hisrs([HALT_C2H_INT_EN, RXDMA_INT, 0]);
    let look = interrupts
        .look(
            &mut io,
            LENGTHS,
            |_: &mut Model, _, _| -> Result<u32, io::Error> {
                unreachable!("nothing is polled while stopped")
            },
        )
        .unwrap();
    assert_eq!(look, Look::default());
    assert!(io.take().is_empty());
}

#[test]
fn without_a_vector_no_mask_is_set_and_each_look_still_acknowledges() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(false);
    interrupts.enable(&mut io).unwrap();
    assert!(io.take().is_empty());
    io.hisrs([0, RXDMA_INT, 0]);
    let mut pending = [2, 0];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert!(look.events.unwrap().rx());
    let log = io.take();
    assert!(
        !log.iter()
            .any(|a| matches!(a, Access::Write { register, .. }
        if [HIMR0, PCIE_HIMR00, PCIE_HIMR10].contains(register)))
    );
    assert_eq!(io.get(PCIE_HISR00), 0);
    // The stop writes the masks off all the same.
    interrupts.disable(&mut io).unwrap();
    assert_eq!(io.take(), masks([0; 3]));
}

#[test]
fn a_recovering_look_acknowledges_the_indication_and_polls_nothing() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    interrupts.enable(&mut io).unwrap();
    io.take();
    interrupts.recovery_start(&mut io).unwrap();
    assert!(interrupts.under_recovery());
    let mut expected = masks([0; 3]).to_vec();
    expected.extend(masks([HALT_C2H_INT_EN, HS0ISR_IND_INT_EN, 0]));
    assert_eq!(io.take(), expected);

    io.hisrs([
        HALT_C2H_INT_EN,
        HS0ISR_IND_INT | RXDMA_INT | RDU_INT,
        HC10ISR_IND_INT,
    ]);
    let look = interrupts
        .look(
            &mut io,
            LENGTHS,
            |_: &mut Model, _, _| -> Result<u32, io::Error> {
                unreachable!("NAPI is not scheduled while recovering")
            },
        )
        .unwrap();
    let events = look.events.unwrap();
    assert_eq!(events.isrs, [HS0ISR_IND_INT, 0]);
    assert!(events.halt_c2h() && events.indications() && !events.rdu());
    assert_eq!(
        (look.unavailable, look.work, look.more),
        (None, None, false)
    );
    assert!(
        io.take()
            .ends_with(&masks([HALT_C2H_INT_EN, HS0ISR_IND_INT_EN, 0]))
    );
    assert_eq!(io.get(PCIE_HISR00), RXDMA_INT | RDU_INT);

    interrupts.recovery_complete(&mut io).unwrap();
    assert!(!interrupts.under_recovery());
    let mut expected = masks([0; 3]).to_vec();
    expected.extend(masks(NORMAL));
    assert_eq!(io.take(), expected);
    let mut pending = [1, 0];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    assert!(look.events.unwrap().rdu() && look.unavailable.is_some());
    assert_eq!((look.work, look.more), (Some(0), false));
}

#[test]
fn halt_and_watchdog_are_reported_and_left_latched_where_masked() {
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(true);
    interrupts.enable(&mut io).unwrap();
    io.hisrs([HALT_C2H_INT_EN | WDT_TIMEOUT_INT_EN, 0, 0]);
    let mut pending = [0, 0];
    let look = interrupts
        .look(&mut io, LENGTHS, rings(&mut pending))
        .unwrap();
    let events = look.events.unwrap();
    assert!(events.halt_c2h() && !events.wdt());
    assert_eq!(io.get(HISR0), WDT_TIMEOUT_INT_EN);
}

/// One step of an oracle case.
#[derive(Clone, Copy, Debug)]
enum Op {
    Look {
        hisr: [u32; 3],
        idx: [u32; RXCH_NUM],
        pending: [u32; RXCH_NUM],
    },
    Enable,
    Disable,
    RecoveryStart,
    RecoveryComplete,
}

const fn look(hisr: [u32; 3], idx: [u32; RXCH_NUM], pending: [u32; RXCH_NUM]) -> Op {
    Op::Look { hisr, idx, pending }
}

/// The oracle's `looks`, in its order.
fn look_cases() -> Vec<([u32; RXCH_NUM], Vec<Op>)> {
    use Op::*;
    const HALT: u32 = HALT_C2H_INT_EN;
    let rx = RXDMA_INT | TXDMA_ACH0_INT_BIT;
    let none = [0, 0];
    vec![
        (LENGTHS, vec![Enable, look([0, rx, 0], none, [5, 0])]),
        (
            LENGTHS,
            vec![
                Enable,
                look(
                    [0, RPQDMA_INT | RXP1DMA_INT, HC10ISR_IND_INT | 1 << 12],
                    none,
                    [10, 3],
                ),
            ],
        ),
        (
            LENGTHS,
            vec![
                Enable,
                look(
                    [0, RDU_INT | RXDMA_INT, 0],
                    [5 << 16 | 6, 10 << 16 | 20],
                    [255, 0],
                ),
                look([0, RDU_INT, 0], [69 << 16 | 70, 10 << 16 | 20], [30, 0]),
                look([0, 0, 0], [99 << 16 | 70, 10 << 16 | 20], none),
            ],
        ),
        (
            [8, 8],
            vec![
                Enable,
                look([0, RDU_INT, 0], [7 << 16, 3 << 16 | 4], [8, 2]),
            ],
        ),
        (
            LENGTHS,
            vec![
                Enable,
                look(
                    [0, RPQDMA_INT | RPQBD_FULL_INT | RXDMA_INT, 0],
                    none,
                    [4, 100],
                ),
                look([0, 0, 0], none, [4, 0]),
            ],
        ),
        (
            LENGTHS,
            vec![
                Enable,
                look([0, RXDMA_INT, 0], none, [60, 4]),
                look([0, 0, 0], none, none),
            ],
        ),
        (
            LENGTHS,
            vec![
                Enable,
                look(
                    [
                        HALT | WDT_TIMEOUT_INT_EN | 1,
                        HS0ISR_IND_INT | RXDMA_STUCK_INT | TXDMA_STUCK_INT,
                        0,
                    ],
                    none,
                    none,
                ),
            ],
        ),
        (
            LENGTHS,
            vec![
                look([HALT, RXDMA_INT, HC10ISR_IND_INT], none, [3, 3]),
                Enable,
                Disable,
                look([HALT, RXDMA_INT, HC10ISR_IND_INT], none, [3, 3]),
            ],
        ),
        (
            LENGTHS,
            vec![
                Enable,
                RecoveryStart,
                look(
                    [HALT, HS0ISR_IND_INT | RXDMA_INT | RDU_INT, HC10ISR_IND_INT],
                    [5 << 16 | 6, 0],
                    [1, 1],
                ),
                RecoveryComplete,
                look([0, RXDMA_INT, 0], none, [1, 1]),
            ],
        ),
        (LENGTHS, vec![Enable, look([0, 0, 0], none, none), Disable]),
    ]
}

/// The oracle's `recognized` HISR patterns.
const RECOGNIZED: [[u32; 3]; 7] = [
    [0, 0, 0],
    [
        HALT_C2H_INT_EN | WDT_TIMEOUT_INT_EN,
        RXDMA_INT | RPQDMA_INT,
        HC10ISR_IND_INT,
    ],
    [u32::MAX, u32::MAX, u32::MAX],
    [
        HALT_C2H_INT_EN,
        RDU_INT | RXP1DMA_INT | TXDMA_ACH0_INT_BIT,
        0,
    ],
    [
        WDT_TIMEOUT_INT_EN,
        HS0ISR_IND_INT | RXDMA_STUCK_INT | TXDMA_STUCK_INT | RPQBD_FULL_INT,
        1 << 12,
    ],
    [0x13ac_9571, 0x7723_5491, 0x129d_2157],
    [0xec53_6a8e, 0x88dc_ab6e, 0xed62_dea8],
];

/// What the oracle's `rtw89_mac_get_err_status` answers, and
/// `MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT`.
const ERR_STATUS: u32 = 0x1190;
const ERR_WDT_TIMEOUT: u32 = 0x2599;

fn encode(log: &[Access]) -> Vec<u8> {
    let mut trace = Vec::new();
    for access in log {
        match *access {
            Access::Read { register, value } => push(&mut trace, 4, register, value),
            Access::Write { register, value } => push(&mut trace, 8, register, value),
            Access::Mark { tag, a, b } => push(&mut trace, tag, a, b),
        }
    }
    trace
}

/// The oracle's ring stand-ins: `rtw89_pci_rxbd_recalc` (83),
/// `rtw89_pci_rxbd_deliver` (84) and `rtw89_pci_release_tx` (85).
fn oracle_rings(
    pending: &mut [u32; RXCH_NUM],
) -> impl FnMut(&mut Model, RxChannel, u32) -> Result<u32, io::Error> + '_ {
    move |io, channel, budget| {
        let ring = channel as usize;
        let count = pending[ring];
        io.mark(83, ring as u32, count);
        if count == 0 {
            return Ok(0);
        }
        Ok(match channel {
            RxChannel::Rpq => {
                pending[ring] = 0;
                io.mark(85, count, 0);
                count
            }
            RxChannel::Rxq => {
                let delivered = count.min(budget);
                pending[ring] -= delivered;
                io.mark(84, delivered, 0);
                delivered
            }
        })
    }
}

#[test]
#[ignore = "oracle: STELA_RTW89_PCI_ORACLE"]
fn interrupt_traces_match_unchanged_c() {
    let directory = std::path::PathBuf::from(std::env::var("STELA_RTW89_PCI_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("interrupt.bin")).unwrap();
    let mut offset = 0;

    // rtw89_chip_config_intr_mask: RESET, RECOVERY_START, NORMAL, LOW_POWER,
    // RECOVERY_COMPLETE, RECOVERY_START, RESET. NORMAL and LOW_POWER change
    // neither the masks nor the recovery flag.
    let mut io = Model::default();
    let mut interrupts = Interrupts::new(false);
    let mut expected = Vec::new();
    for step in 0..7 {
        match step {
            0 | 6 => interrupts = Interrupts::new(false),
            1 | 5 => interrupts.recovery_start(&mut io).unwrap(),
            4 => interrupts.recovery_complete(&mut io).unwrap(),
            _ => {}
        }
        let masks = interrupts.masks();
        push(
            &mut expected,
            90,
            masks.halt_c2h,
            interrupts.under_recovery().into(),
        );
        push(&mut expected, 91, masks.intrs[0], masks.intrs[1]);
    }
    assert!(io.take().is_empty());
    assert_eq!(segment(&trace, &mut offset), expected, "masks");

    // rtw89_chip_recognize_intrs, normal then recovering.
    for recovering in [false, true] {
        let mut interrupts = Interrupts::new(false);
        if recovering {
            interrupts.recovery_start(&mut Model::default()).unwrap();
        }
        let mut io = Model::default();
        for hisrs in RECOGNIZED {
            io.hisrs(hisrs);
            let events = interrupts.recognize(&mut io).unwrap();
            io.mark(93, events.halt_c2h, 0);
            io.mark(94, events.isrs[0], events.isrs[1]);
        }
        assert_eq!(
            segment(&trace, &mut offset),
            encode(&io.log),
            "recognize, recovering {recovering}"
        );
    }

    // Starts, stops, recoveries and looks.
    let cases = look_cases();
    assert_eq!(cases.len(), 10);
    for (case, (lengths, steps)) in cases.into_iter().enumerate() {
        let mut io = Model::default();
        let mut interrupts = Interrupts::new(true);
        for step in steps {
            match step {
                Op::Look { hisr, idx, pending } => {
                    io.hisrs(hisr);
                    io.set(RXQ_IDX, idx[0]);
                    io.set(RPQ_IDX, idx[1]);
                    let mut pending = pending;
                    let look = interrupts
                        .look(&mut io, lengths, oracle_rings(&mut pending))
                        .unwrap();
                    if let Some(events) = look.events {
                        if events.halt_c2h() {
                            io.mark(80, ERR_STATUS, 0);
                        }
                        if events.wdt() {
                            io.mark(80, ERR_WDT_TIMEOUT, 0);
                        }
                    }
                    io.mark(96, look.work.unwrap_or(u32::MAX), look.more.into());
                    continue;
                }
                Op::Enable => interrupts.enable(&mut io).unwrap(),
                Op::Disable => interrupts.disable(&mut io).unwrap(),
                Op::RecoveryStart => interrupts.recovery_start(&mut io).unwrap(),
                Op::RecoveryComplete => interrupts.recovery_complete(&mut io).unwrap(),
            }
            io.mark(
                92,
                interrupts.running().into(),
                interrupts.under_recovery().into(),
            );
        }
        assert_eq!(
            segment(&trace, &mut offset),
            encode(&io.log),
            "look case {case}"
        );
    }
    assert_eq!(offset, trace.len());
}
