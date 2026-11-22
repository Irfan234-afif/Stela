// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2019-2022 Realtek Corporation
//! Native RTL8852B (Realtek's AX generation) support adapted from pinned
//! rtw89 at Linux a804c5742bff224d4cb4d25dd383554d598be32b. The rtw88
//! modules beside this one serve RTL8822C alone; nothing here shares their
//! register map, firmware interface or DMA layout.
//!
//! Register access ([`io`]), RTL8852B's RF calibration tables
//! ([`rtw8852b::rfk`]), its power sequence ([`power`]), its DMAC's pre-init
//! with the firmware download's quota ([`dle`]), its PCIe pre-init with
//! the DMA rings ([`pci`]), and the firmware command channel, H2C out on
//! CH12 behind a TXWD body ([`h2c`], [`txwd`]) and C2H back on RXQ
//! ([`c2h`]), are the first slices. Powering the chip on, pre-initializing
//! its DMAC and PCIe DMA and handing it commands prove that its polled bits
//! answered, the ring addresses were written and the command BDs were
//! filled, nothing about its firmware or radio.
pub mod c2h;
pub mod dle;
pub mod h2c;
pub mod io;
pub mod pci;
pub mod power;
pub mod registers;
pub mod rtw8852b;
pub mod txwd;
