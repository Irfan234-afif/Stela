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
//! the DMA rings ([`pci`]), the firmware command channel, H2C out on
//! CH12 behind a TXWD body ([`h2c`], [`txwd`]) and C2H back on RXQ
//! ([`c2h`]), the firmware download ([`fwdl`]), the firmware features
//! rtw89 expects by version ([`features`]), and the efuse and phycap read
//! once the firmware runs ([`efuse`], [`rtw8852b::efuse`]) over the register
//! mailbox ([`h2creg`]) are the first slices, and [`bootstrap`] composes
//! them in rtw89's probe order into one power cycle, which [`attach`]
//! runs for a boot and ends with the chip cold again. The full MAC init
//! ([`mac`]) is the first slice after that power cycle's firmware runs, and
//! the BB, RF, TX power and regulation tables rtw89 takes from the
//! firmware's elements ([`elements`]) are the first its radio needs.
//! Stage 2 ([`radio`]) brings the chip up again as rtw89's interface start
//! does, tunes it and listens ([`listen`]), reading what RXQ holds as
//! rtw89 reads it ([`rxdesc`]).
//! Powering the chip on,
//! pre-initializing its DMAC and PCIe DMA and handing it commands prove that
//! its polled bits answered, the ring addresses were written and the command
//! BDs were filled; a download that returns proves that the firmware
//! reported FREERTOS_DONE, nothing about its radio; an efuse read proves
//! that every byte was answered, not what the bytes mean; a MAC init that
//! returns proves that its polls and checks answered, not that the radio
//! works.
pub mod attach;
pub mod bootstrap;
pub mod c2h;
pub mod cam;
pub mod capabilities;
pub mod coex;
pub mod dle;
pub mod dynamic;
pub mod efuse;
pub mod elements;
pub mod features;
pub mod fwdl;
pub mod h2c;
pub mod h2creg;
pub mod hardware;
pub mod interrupt;
pub mod io;
pub mod listen;
pub mod mac;
#[cfg(test)]
mod model;
pub mod pci;
pub mod phy;
pub mod power;
pub mod radio;
pub mod regd;
pub mod registers;
pub mod rtw8852b;
pub mod rxdesc;
pub mod txpower;
pub mod txwd;
