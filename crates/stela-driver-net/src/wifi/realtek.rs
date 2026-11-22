// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
//! Native Realtek PCIe Wi-Fi: RTL8822C stations by rtw88 ([`rtw88`]) on the
//! softMAC station any Realtek chip may run ([`station`]), and RTL8852B's
//! firmware layout and register access from rtw89 ([`ax`]), no station yet.
//! Pinned rtw88/rtw89 are hardware references, not a Linux kernel interface.
pub mod attach;
pub mod ax;
pub mod beacon;
pub mod bit_rate;
pub mod bootstrap;
pub mod calibrate;
pub mod ccmp;
pub mod coex;
pub mod commands;
pub mod deep;
pub mod descriptor;
pub mod download;
pub mod dynamic;
pub mod efuse;
pub mod features;
pub mod fifo;
pub mod firmware;
pub mod firmware_control;
pub mod hardware;
pub mod hci;
pub mod identity;
pub mod interrupt;
pub mod io;
pub mod link;
pub mod phy;
pub mod power;
pub mod receive;
pub mod regd;
pub mod registers;
pub mod rf;
pub mod rtw88;
pub mod station;
pub mod templates;
pub mod transmit;
