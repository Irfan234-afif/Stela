// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2020 Realtek Corporation
//! An RTL8852BE's PCIe interrupts, masked and acknowledged as pinned rtw89
//! masks and acknowledges them, polled at each look and woken by the
//! function's MSI where one is routed.
//!
//! Mirrored from pci.c, with the members `rtw8852b_pci_info` names
//! (`rtw89_pci_config_intr_mask`, `rtw89_pci_enable_intr`,
//! `rtw89_pci_disable_intr`, `rtw89_pci_recognize_intrs` and
//! `rtw89_pci_isr_ax`):
//!
//! - [`Masks::new`] is `rtw89_pci_config_intr_mask`: the halt mask and the
//!   two PCIe masks, which only the recovery flag changes.
//! - [`Interrupts::enable`] and [`Interrupts::disable`] are
//!   `rtw89_pci_enable_intr_lock` and `rtw89_pci_disable_intr_lock`, the
//!   HCI start's and stop's: the running flag, then HIMR0, PCIE_HIMR00 and
//!   PCIE_HIMR10.
//! - [`Interrupts::recognize`] is `rtw89_pci_recognize_intrs`: HISR0,
//!   PCIE_HISR00 and PCIE_HISR10 read under the masks, then each written
//!   back, write-1-to-clear, with what was read.
//! - [`Interrupts::rx_unavailable`] is `rtw89_pci_isr_rxd_unavail`, the RX
//!   descriptor unavailable (RDU) handler: each RX ring's index read, and
//!   whether the hardware's next BD is the host's.
//! - [`Interrupts::recovery_start`] and [`Interrupts::recovery_complete`]
//!   are `rtw89_pci_ops_recovery_start` and `_complete`.
//! - [`Interrupts::look`] is one service as Linux runs it:
//!   `rtw89_pci_interrupt_handler` (the masks off while running),
//!   `rtw89_pci_interrupt_threadfn` (the causes recognized, RDU handled,
//!   the halt and watchdog causes reported, NAPI scheduled unless
//!   recovering) and `rtw89_pci_napi_poll` (RPQ's causes cleared and RPQ
//!   polled, then RXQ's, with RDU among them, and RXQ polled, and the masks
//!   on again once the budget was not spent). The caller's poll stands in
//!   for `rtw89_pci_poll_rpq_dma`'s release and `rtw89_pci_poll_rxq_dma`'s
//!   delivery; their budget arithmetic is kept here.
//!
//! An RDU needs no step of its own: the RXQ poll that follows it gives the
//! hardware its BDs back, and RXQ's clear acknowledges the RDU again behind
//! anything that latched since it was recognized.
//!
//! Stela has no interrupt thread. Each look runs the handler, the thread
//! and the poll in turn, whether or not an MSI arrived; the MSI only wakes
//! the core that looks. A look after one that spent its budget runs only
//! the poll, as NAPI polls again before any interrupt is unmasked. Without
//! a routed MSI ([`Interrupts::new`] with `vector` false) the masks are
//! never set and the looks write none, while each still recognizes and
//! acknowledges the causes.
//!
//! Left out: the low-power mask and handler (`rtw89_pci_ops_switch_mode`,
//! `rtw89_pci_low_power_interrupt_handler`), which only rtw89's power save
//! reaches; the halt and watchdog causes' `rtw89_ser_notify`, which 5.3
//! takes from [`Events::halt_c2h`] and [`Events::wdt`]; and the 8851B and
//! WiFi 7 variants. RTL8852B's halt mask holds `B_AX_HALT_C2H_INT_EN`
//! alone, so [`Events::wdt`] reads false here as in rtw89.
//!
//! Not proven: that the causes latch in HISR while their masks are off,
//! which the looks without an MSI rely on to report them (the rings are
//! polled from their indices either way); that an RDU recovers as
//! rtw89's comments say; and anything about the radio.
use super::io::{self, Io};
use super::pci::ring::{DMA_ADDR_SET_RX, RXCH_NUM, RxChannel};
use super::registers::*;

/// `NAPI_POLL_WEIGHT`: the budget of one NAPI poll.
pub const NAPI_POLL_WEIGHT: u32 = 64;

/// `rtw89_pci_isr_ax.isr_rdu`, `.isr_halt_c2h` and `.isr_wdt_timeout`.
pub const ISR_RDU: u32 = RDU_INT;
pub const ISR_HALT_C2H: u32 = HALT_C2H_INT_EN;
pub const ISR_WDT_TIMEOUT: u32 = WDT_TIMEOUT_INT_EN;
/// `rtw89_pci_isr_ax.isr_clear_rpq` and `.isr_clear_rxq`: the register and
/// the causes `rtw89_pci_napi_poll` clears before each ring's poll.
pub const ISR_CLEAR_RPQ: (u32, u32) = (PCIE_HISR00, RPQDMA_INT | RPQBD_FULL_INT);
pub const ISR_CLEAR_RXQ: (u32, u32) = (PCIE_HISR00, RXP1DMA_INT | RXDMA_INT | RDU_INT);

/// `rtwpci->halt_c2h_intrs` and `rtwpci->intrs`: what HIMR0, PCIE_HIMR00
/// and PCIE_HIMR10 are set to, and what their HISRs are read under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Masks {
    pub halt_c2h: u32,
    pub intrs: [u32; 2],
}

impl Masks {
    /// `rtw89_pci_config_intr_mask` for an RTL8852B (not 8851B, whose HS0
    /// indication is `B_AX_HS0ISR_IND_INT_EN_WKARND`).
    pub const fn new(under_recovery: bool) -> Self {
        let intrs = if under_recovery {
            [HS0ISR_IND_INT_EN, 0]
        } else {
            [
                TXDMA_STUCK_INT_EN
                    | RXDMA_INT_EN
                    | RXP1DMA_INT_EN
                    | RPQDMA_INT_EN
                    | RXDMA_STUCK_INT_EN
                    | RDU_INT_EN
                    | RPQBD_FULL_INT_EN
                    | HS0ISR_IND_INT_EN,
                HC10ISR_IND_INT_EN,
            ]
        };
        Self {
            halt_c2h: HALT_C2H_INT_EN,
            intrs,
        }
    }
}

/// `struct rtw89_pci_isrs` as `rtw89_pci_recognize_intrs` fills it: each
/// HISR as read, under its mask, and acknowledged.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Events {
    /// HISR0 under the halt mask.
    pub halt_c2h: u32,
    /// PCIE_HISR00 and PCIE_HISR10 under the PCIe masks.
    pub isrs: [u32; 2],
}

impl Events {
    /// RXQ's DMA (`B_AX_RXDMA_INT`, `B_AX_RXP1DMA_INT`): frames or C2H.
    pub const fn rx(self) -> bool {
        self.isrs[0] & (RXDMA_INT | RXP1DMA_INT) != 0
    }
    /// RPQ's DMA or its BDs full: release reports.
    pub const fn rpq(self) -> bool {
        self.isrs[0] & (RPQDMA_INT | RPQBD_FULL_INT) != 0
    }
    /// `isr_rdu`: an RX ring ran out of BDs.
    pub const fn rdu(self) -> bool {
        self.isrs[0] & ISR_RDU != 0
    }
    /// `isr_halt_c2h`: the firmware halted with an error to report.
    pub const fn halt_c2h(self) -> bool {
        self.halt_c2h & ISR_HALT_C2H != 0
    }
    /// `isr_wdt_timeout`: the firmware's watchdog fired; masked out on an
    /// RTL8852B.
    pub const fn wdt(self) -> bool {
        self.halt_c2h & ISR_WDT_TIMEOUT != 0
    }
    /// A TX or RX DMA stuck, which rtw89 acknowledges and leaves to its
    /// track work.
    pub const fn dma_stuck(self) -> bool {
        self.isrs[0] & (TXDMA_STUCK_INT | RXDMA_STUCK_INT) != 0
    }
    /// The HS0 and HC10 indications, the only causes while recovering.
    pub const fn indications(self) -> bool {
        self.isrs[0] & HS0ISR_IND_INT != 0 || self.isrs[1] & HC10ISR_IND_INT != 0
    }
    pub const fn any(self) -> bool {
        self.halt_c2h != 0 || self.isrs[0] != 0 || self.isrs[1] != 0
    }
}

/// One RX ring's index as `rtw89_pci_isr_rxd_unavail` reads it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingIndex {
    /// The index register: the hardware's index in `TXBD_HW_IDX_MASK`,
    /// the host's in `TXBD_HOST_IDX_MASK`.
    pub idx: u32,
    /// Whether the hardware's next BD is the host's: no BD left to fill.
    pub full: bool,
}

/// What a look found and did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Look {
    /// The causes recognized, unless the look only continued a poll or
    /// the interrupts are stopped.
    pub events: Option<Events>,
    /// The RX rings' indices, where the causes held an RDU.
    pub unavailable: Option<[RingIndex; RXCH_NUM]>,
    /// What `rtw89_pci_napi_poll` returns, where it ran.
    pub work: Option<u32>,
    /// Whether the budget was spent: the masks stay off and the next look
    /// polls again.
    pub more: bool,
}

/// `rtw89_pci_isr_rxd_unavail`'s test on one ring.
const fn full(idx: u32, len: u32) -> bool {
    let hw = (idx & TXBD_HW_IDX_MASK) >> TXBD_HW_IDX_MASK.trailing_zeros();
    let host = idx & TXBD_HOST_IDX_MASK;
    len != 0 && (hw + 1) % len == host
}

/// The interrupt state rtw89 keeps in `struct rtw89_pci`: the masks, the
/// running and recovery flags, and whether NAPI is still scheduled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interrupts {
    masks: Masks,
    vector: bool,
    running: bool,
    under_recovery: bool,
    scheduled: bool,
}

impl Interrupts {
    /// The state `rtw89_pci_request_irq` leaves,
    /// `RTW89_PCI_INTR_MASK_RESET`: stopped, not recovering. `vector` says
    /// whether an MSI the caller routed raises the function's causes, and so
    /// whether the masks are ever set.
    pub const fn new(vector: bool) -> Self {
        Self {
            masks: Masks::new(false),
            vector,
            running: false,
            under_recovery: false,
            scheduled: false,
        }
    }

    pub const fn masks(&self) -> Masks {
        self.masks
    }

    pub const fn running(&self) -> bool {
        self.running
    }

    pub const fn under_recovery(&self) -> bool {
        self.under_recovery
    }

    /// `rtw89_pci_enable_intr`, where the MSI is routed.
    fn enable_intr<I: Io + ?Sized>(&self, io: &mut I) -> Result<(), io::Error> {
        if self.vector {
            io.write32(HIMR0, self.masks.halt_c2h)?;
            io.write32(PCIE_HIMR00, self.masks.intrs[0])?;
            io.write32(PCIE_HIMR10, self.masks.intrs[1])?;
        }
        Ok(())
    }

    /// `rtw89_pci_disable_intr`, where the MSI is routed.
    fn disable_intr<I: Io + ?Sized>(&self, io: &mut I) -> Result<(), io::Error> {
        if self.vector {
            write_zero(io)?;
        }
        Ok(())
    }

    /// `rtw89_chip_config_intr_mask` with `RECOVERY_START` or
    /// `RECOVERY_COMPLETE`.
    fn configure(&mut self, under_recovery: bool) {
        self.under_recovery = under_recovery;
        self.masks = Masks::new(under_recovery);
    }

    /// `rtw89_pci_enable_intr_lock` (`rtw89_pci_ops_start`): running, then
    /// the masks on where the MSI is routed.
    pub fn enable<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), io::Error> {
        self.running = true;
        self.enable_intr(io)
    }

    /// `rtw89_pci_disable_intr_lock` (`rtw89_pci_ops_stop`): stopped, then
    /// the masks off, also without an MSI, so a stopped function stays quiet
    /// whatever the masks held. NAPI stops with it.
    pub fn disable<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), io::Error> {
        self.running = false;
        self.scheduled = false;
        write_zero(io)
    }

    /// `rtw89_pci_recognize_intrs`: each HISR read under its mask, then
    /// each written back with what was read, which clears those causes.
    pub fn recognize<I: Io + ?Sized>(&self, io: &mut I) -> Result<Events, io::Error> {
        let halt_c2h = io.read32(HISR0)? & self.masks.halt_c2h;
        let isrs = [
            io.read32(PCIE_HISR00)? & self.masks.intrs[0],
            io.read32(PCIE_HISR10)? & self.masks.intrs[1],
        ];
        io.write32(HISR0, halt_c2h)?;
        io.write32(PCIE_HISR00, isrs[0])?;
        io.write32(PCIE_HISR10, isrs[1])?;
        Ok(Events { halt_c2h, isrs })
    }

    /// `rtw89_pci_isr_rxd_unavail`: each RX ring's index read, RXQ then
    /// RPQ, with `lengths` the rings' BD counts in that order; rtw89 only
    /// logs what it reads.
    pub fn rx_unavailable<I: Io + ?Sized>(
        &self,
        io: &mut I,
        lengths: [u32; RXCH_NUM],
    ) -> Result<[RingIndex; RXCH_NUM], io::Error> {
        let mut rings = [RingIndex {
            idx: 0,
            full: false,
        }; RXCH_NUM];
        for channel in RxChannel::ALL {
            let i = channel as usize;
            let idx = io.read32(DMA_ADDR_SET_RX[i].idx)?;
            rings[i] = RingIndex {
                idx,
                full: full(idx, lengths[i]),
            };
        }
        Ok(rings)
    }

    /// `rtw89_pci_ops_recovery_start`: the masks off, the recovery masks
    /// taken, and those on.
    pub fn recovery_start<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), io::Error> {
        self.disable_intr(io)?;
        self.configure(true);
        self.enable_intr(io)
    }

    /// `rtw89_pci_ops_recovery_complete`: the masks off, the normal masks
    /// taken, and those on.
    pub fn recovery_complete<I: Io + ?Sized>(&mut self, io: &mut I) -> Result<(), io::Error> {
        self.disable_intr(io)?;
        self.configure(false);
        self.enable_intr(io)
    }

    /// One service: `rtw89_pci_interrupt_handler`, then
    /// `rtw89_pci_interrupt_threadfn`, then `rtw89_pci_napi_poll`, or the
    /// poll alone after a look that spent its budget. Nothing while
    /// stopped, as the handler leaves a cause that arrives after the stop.
    ///
    /// `lengths` are the RX rings' BD counts, RXQ then RPQ, for an RDU.
    /// `poll(io, channel, budget)` is a ring's poll: for
    /// [`RxChannel::Rpq`] it releases every report waiting and returns how
    /// many (rtw89 releases all of RPQ, whatever the budget); for
    /// [`RxChannel::Rxq`] it delivers up to `budget` frames and returns how
    /// many.
    ///
    /// An error leaves the masks off and NAPI scheduled where the look
    /// stopped; the next look polls again.
    pub fn look<I, E>(
        &mut self,
        io: &mut I,
        lengths: [u32; RXCH_NUM],
        mut poll: impl FnMut(&mut I, RxChannel, u32) -> Result<u32, E>,
    ) -> Result<Look, E>
    where
        I: Io + ?Sized,
        E: From<io::Error>,
    {
        let mut look = Look::default();
        if !self.running {
            return Ok(look);
        }
        if !self.scheduled {
            // rtw89_pci_interrupt_handler.
            self.disable_intr(io)?;
            // rtw89_pci_interrupt_threadfn.
            let events = self.recognize(io)?;
            look.events = Some(events);
            if events.rdu() {
                look.unavailable = Some(self.rx_unavailable(io, lengths)?);
            }
            if self.under_recovery {
                self.enable_intr(io)?;
                return Ok(look);
            }
            self.scheduled = true;
        }
        // rtw89_pci_napi_poll.
        let budget = NAPI_POLL_WEIGHT;
        io.write32(ISR_CLEAR_RPQ.0, ISR_CLEAR_RPQ.1)?;
        // rtw89_pci_poll_rpq_dma: all released, at most the budget counted.
        let mut work = poll(io, RxChannel::Rpq, budget)?.min(budget);
        let countdown = budget - work;
        if work == budget {
            look.work = Some(work);
            look.more = true;
            return Ok(look);
        }
        io.write32(ISR_CLEAR_RXQ.0, ISR_CLEAR_RXQ.1)?;
        // rtw89_pci_poll_rxq_dma, given the countdown as its budget: that
        // budget once the countdown runs out, otherwise its budget less the
        // countdown it began with, nothing.
        if poll(io, RxChannel::Rxq, countdown)? >= countdown {
            work += countdown;
        }
        look.work = Some(work);
        if work < budget {
            self.scheduled = false;
            self.enable_intr(io)?;
        } else {
            look.more = true;
        }
        Ok(look)
    }
}

/// `rtw89_pci_disable_intr`'s writes.
fn write_zero<I: Io + ?Sized>(io: &mut I) -> Result<(), io::Error> {
    io.write32(HIMR0, 0)?;
    io.write32(PCIE_HIMR00, 0)?;
    io.write32(PCIE_HIMR10, 0)
}

#[cfg(test)]
mod tests;
