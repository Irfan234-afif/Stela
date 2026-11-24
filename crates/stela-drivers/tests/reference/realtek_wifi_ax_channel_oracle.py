#!/usr/bin/env python3
"""Unchanged pinned rtw89 channel switch for an RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. __rtw89_set_channel and
rtw89_chip_rfk_channel_for_pure_mon_vif (core.c), rtw89_chan_create with its
helpers and rtw89_assign_entity_chan (chan.c), rtw8852b_set_channel and
rtw8852b_set_channel_help with their helpers (rtw8852b.c),
__rtw8852bx_set_channel_mac, __rtw8852bx_set_channel_bb and every callee they
reach, RTL8852BT's included (rtw8852b_common.c), rtw8852b_set_channel_rf with
_ch_setting, _set_ch, _set_s0_arfc18, _lck_check, _bw_setting and _rxbb_bw
(rtw8852b_rfk.c), rtw89_phy_get_txsc, rtw89_encode_chan_idx, the PHY index
helpers and the RF v1 accessors with SWSI (phy.c), rtw89_mac_cfg_ppdu_status_ax,
rtw89_mac_stop_sch_tx, rtw89_mac_resume_sch_tx and rtw89_set_hw_sch_tx_en
(mac.c), the MMIO, BB and RF inlines of core.h, phy.h, chan.h and mac.h, and the
declarations they read are extracted unchanged, each with its SHA-256 in
manifest.json. They are compiled with clang under ASan and UBSan (without
shift-base: the kernel builds with -fno-strict-overflow, under which rtw89's
shifts of negative gain offsets are defined) against a harness that models
BAR2 as bytes, byte i holding i * 37 + 11, with CMAC_FUNC_EN holding CMAC_EN,
and the RF registers SWSI reaches as two files of 256 20-bit words, word a of
path p holding (a * 0x9e3 + p * 0x4f1b + 0x1a2b3) & RFREG_MASK. A write to
R_SWSI_READ_ADDR_V1 latches the request; R_SWSI_V1 reads B_SWSI_R_DATA_DONE_V1
with the requested word, never busy; a write to R_SWSI_DATA_V1 writes the word,
under R_SWSI_BIT_MASK_V1 when its mask bit is set. S0's RR_LPF reads its busy bit
clear (set when the case says the LPF is stuck) and S0's RR_SYNFB its lock bit
set (clear when the case says the synthesizer is unlocked). The direct RF window
is plain memory. chip->ops->set_txpwr, rtw89_btc_ntfy_switch_band and
chip->ops->rfk_band_changed are stubs that record markers.

Each case is one segment prefixed by its byte length: on a device whose state is
as rtwdev is allocated, each of the case's channels made with rtw89_chan_create,
assigned with rtw89_assign_entity_chan and switched to with
__rtw89_set_channel(rtwdev, chan, RTW89_MAC_0, RTW89_PHY_0). A segment is records
of three little-endian u32 (tag, a, b): reads are tagged by width, writes by 4
plus width, delays 9 (0, us), set_txpwr 12 (channel, primary),
rtw89_btc_ntfy_switch_band 13 (phy, band) and rfk_band_changed 14 (phy, band).
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'

# (inputs, unlocked, lpf_stuck, cmac_off, rx_path, [(center, primary, width)]);
# inputs 0 is the card's, 1 blank, 2 the card's with RF_B and a monitor; rx_path
# -1 leaves R_CHBW_MOD_V1 as the pattern has it. The Rust replay lists the same.
SINGLE = [(1, 1, 20), (3, 1, 40), (6, 6, 20), (8, 6, 40), (4, 6, 40), (13, 13, 20),
          (11, 13, 40), (14, 14, 20),
          (36, 36, 20), (38, 36, 40), (42, 36, 80), (42, 40, 80), (42, 44, 80),
          (100, 100, 20), (102, 100, 40), (106, 100, 80),
          (149, 149, 20), (151, 149, 40), (155, 149, 80),
          (165, 165, 20), (167, 165, 40), (171, 165, 80),
          (177, 177, 20), (175, 177, 40), (171, 177, 80)]
CASES = ([(0, 0, 0, 0, -1, [step]) for step in SINGLE] + [
    (1, 0, 0, 0, -1, [(1, 1, 20)]),
    (1, 0, 0, 0, -1, [(42, 36, 80)]),
    (2, 0, 0, 0, -1, [(6, 6, 20)]),
    (2, 0, 0, 0, -1, [(155, 149, 80)]),
    (0, 1, 0, 0, -1, [(36, 36, 20)]),
    (0, 0, 1, 0, -1, [(1, 1, 20)]),
    (0, 0, 0, 0, 1, [(38, 36, 40)]),
    (0, 0, 0, 0, 2, [(3, 1, 40)]),
    (0, 0, 0, 1, -1, [(6, 6, 20)]),
    (0, 0, 0, 0, -1, [(1, 1, 20), (6, 6, 20)]),
    (0, 0, 0, 0, -1, [(1, 1, 20), (42, 36, 80), (42, 36, 80)]),
])


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    reference, out = map(pathlib.Path, argv)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []

    def source(file):
        return (reference / 'rtw89' / file).read_text()

    def closing(text, brace):
        end, depth = brace + 1, 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        return end

    def record(file, name, body):
        manifest.append(dict(path='rtw89/' + file, symbol=name,
                             sha256=hashlib.sha256(body.encode()).hexdigest()))
        return body

    def function(file, name):
        """A function definition, from the blank line before it."""
        text = source(file)
        for m in re.finditer(r'\b' + re.escape(name) + r'\s*\(', text):
            end, depth = text.index('(', m.start()) + 1, 1
            while depth:
                depth += (text[end] == '(') - (text[end] == ')')
                end += 1
            while text[end].isspace():
                end += 1
            if text[end] != '{':
                continue
            start = text.rfind('\n\n', 0, m.start()) + 2
            return record(file, name, text[start:closing(text, end)])
        raise ValueError(f'{file}: no definition of {name}')

    def declaration(file, kind, name):
        """An enum or struct declaration, through its semicolon."""
        text = source(file)
        m = re.search(r'^' + kind + r' ' + re.escape(name) + r' \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {kind} {name}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, f'{kind} {name}', text[m.start():end])

    def definition(file, head):
        """A variable's initialized definition, through its semicolon."""
        text = source(file)
        m = re.search(r'^' + re.escape(head) + r' = \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {head}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, head, text[m.start():end])

    def defines(file, names):
        """Single-line object-like #defines, by name, in the order given."""
        text = source(file)
        lines = []
        for name in names:
            found = re.findall(r'^#define ' + re.escape(name) + r'\b[^\n]*$', text, re.M)
            if len(found) != 1:
                raise ValueError(f'{file}: #define {name} appears {len(found)} times')
            lines.append(found[0])
        return record(file, f'#define {" ".join(names)}', '\n'.join(lines))

    def lines_between(file, first, last):
        """The lines from the one starting with first through the one starting with last."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n', text.index('\n' + last, start) + 1)
        return record(file, f'{first.split()[2] if first.startswith("const") else first} block',
                      text[start:end])

    def fields(file, head, names):
        """Members of a designated initializer by name, each value scanned to
        the comma that ends it at its own depth."""
        text = source(file)
        m = re.search(r'^' + re.escape(head) + r' = \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {head}')
        body = record(file, head, text[m.start():closing(text, text.index('{', m.start()))])
        values = {}
        for name in names:
            found = list(re.finditer(r'\n\t\.' + name + r'\s*=\s*', body))
            if len(found) != 1:
                raise ValueError(f'{head}: .{name} is set {len(found)} times')
            start = end = found[0].end()
            depth = 0
            while True:
                c = body[end]
                if c in '({':
                    depth += 1
                elif c in ')}':
                    if depth == 0:
                        break
                    depth -= 1
                elif c == ',' and depth == 0:
                    break
                end += 1
            values[name] = body[start:end].strip()
        return values

    def expect(what, got, want):
        if got != want:
            raise ValueError(f'{what} is {got}, not {want}')

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    core_defines = defines('core.h', ['MASKBYTE0', 'MASKDWORD', 'RFREG_MASK', 'INV_RF_DATA', 'RF_PATH_MAX',
                                      'LNA_GAIN_NUM', 'TIA_GAIN_NUM', 'RTW89_R32_EA',
                                      'RTW89_R32_DEAD'])
    other_defines = '\n'.join([
        defines('phy.h', ['RTW89_RF_ADDR_ADSEL_MASK', 'EDCCA_PWROFST_DEFAULT']),
        defines('rtw8852b.h', ['RF_PATH_NUM_8852B']),
        defines('rtw8852b_common.h', ['BB_PATH_NUM_8852BX']),
        defines('mac.h', ['RTW89_MAC_AX_BAND_REG_OFFSET'])])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_subband'),
        declaration('core.h', 'enum', 'rtw89_tx_comp_band'),
        declaration('core.h', 'enum', 'rtw89_gain_offset'),
        declaration('core.h', 'enum', 'rtw89_sch_tx_sel'),
        declaration('core.h', 'enum', 'rtw89_band'),
        declaration('core.h', 'enum', 'rtw89_mac_idx'),
        declaration('core.h', 'enum', 'rtw89_phy_idx'),
        declaration('core.h', 'enum', 'rtw89_chanctx_idx'),
        declaration('core.h', 'enum', 'rtw89_rf_path'),
        declaration('core.h', 'enum', 'rtw89_rf_path_bit'),
        declaration('core.h', 'enum', 'rtw89_bandwidth'),
        declaration('core.h', 'enum', 'rtw89_sc_offset'),
        declaration('core.h', 'enum', 'rtw89_rfsi_ctrl_band'),
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_phy_bb_gain_band'),
        declaration('core.h', 'enum', 'rtw89_phy_bb_rxsc_num'),
        declaration('mac.h', 'enum', 'rtw89_mac_hwmod_sel'),
        declaration('core.h', 'struct', 'rtw89_chan'),
        declaration('core.h', 'struct', 'rtw89_chan_rcd'),
        declaration('core.h', 'struct', 'rtw89_channel_help_params'),
        declaration('core.h', 'struct', 'rtw89_phy_bb_gain_info'),
        declaration('core.h', 'struct', 'rtw89_phy_efuse_gain'),
    ])
    inlines = '\n\n'.join(
        [function('core.h', name) for name in [
            'rtw89_read32_mask', 'rtw89_write8_set', 'rtw89_write8_clr', 'rtw89_write32_set',
            'rtw89_write32_clr', 'rtw89_write32_mask', 'rtw89_write8_mask']]
        + [function('phy.h', name) for name in [
            'rtw89_raw_phy_write32', 'rtw89_phy_write32', 'rtw89_phy_write32_set',
            'rtw89_phy_write32_clr', 'rtw89_phy_write32_mask', 'rtw89_phy_read32_mask',
            'rtw89_subband_to_gain_offset_band_of_ofdm', 'rtw89_subband_to_bb_gain_band']]
        + [function('core.h', name) for name in [
            'rtw89_read_rf', 'rtw89_raw_write_rf', 'rtw89_write_rf', 'rtw89_hw_to_nl80211_band',
            'rtw89_chan_rcd_get_by_chan', 'rtw89_chip_set_channel_prepare',
            'rtw89_chip_set_channel_done', 'rtw89_chip_rfk_band_changed',
            'rtw89_chip_stop_sch_tx', 'rtw89_chip_resume_sch_tx']]
        + [function('chan.h', name) for name in ['rtw89_get_entity_state',
                                                  'rtw89_set_entity_state']]
        + [function('mac.h', name) for name in ['rtw89_mac_reg_by_idx', 'rtw89_mac_check_mac_en',
                                                 'rtw89_mac_cfg_ppdu_status']])
    phy = '\n\n'.join(
        [function('phy.c', 'rtw89_phy_get_txsc'),
         lines_between('phy.c', 'const u8 rtw89_ch_base_table[16]',
                       '#define RTW89_CH_OFFSET_MASK')]
        + [function('phy.c', name) for name in [
            'rtw89_encode_chan_idx', 'rtw89_phy_write32_idx', 'rtw89_phy_read32_idx',
            'rtw89_phy_check_swsi_busy', 'rtw89_phy_read_rf', 'rtw89_phy_read_rf_a',
            'rtw89_phy_read_rf_v1', 'rtw89_phy_write_rf', 'rtw89_phy_write_rf_a',
            'rtw89_phy_write_rf_v1']])
    chan = '\n\n'.join(function('chan.c', name) for name in [
        'rtw89_get_subband_type', 'rtw89_get_tx_comp_band', 'rtw89_get_primary_chan_idx',
        'rtw89_get_primary_sb_idx', 'rtw89_chan_create', 'rtw89_assign_entity_chan'])
    mac = '\n\n'.join(function('mac.c', name) for name in [
        'rtw89_mac_check_mac_en_ax', 'rtw89_mac_cfg_ppdu_status_ax', 'rtw89_set_hw_sch_tx_en',
        'rtw89_mac_stop_sch_tx', 'rtw89_mac_resume_sch_tx'])
    common = '\n\n'.join(
        [function('rtw8852b_common.c', '__rtw8852bx_set_channel_mac')]
        + [definition('rtw8852b_common.c', head) for head in [
            'static const u32 rtw8852bx_sco_barker_threshold[14]',
            'static const u32 rtw8852bx_sco_cck_threshold[14]']]
        + [function('rtw8852b_common.c', name) for name in [
            'rtw8852bx_ctrl_sco_cck', 'rtw8852bx_sco_mapping']]
        + [declaration('rtw8852b_common.c', 'struct', 'rtw8852bx_bb_gain')]
        + [definition('rtw8852b_common.c', head) for head in [
            'static const struct rtw8852bx_bb_gain bb_gain_lna[LNA_GAIN_NUM]',
            'static const struct rtw8852bx_bb_gain bb_gain_tia[TIA_GAIN_NUM]']]
        + [function('rtw8852b_common.c', name) for name in [
            'rtw8852bx_set_gain_error', 'rtw8852bt_ext_loss_avg_update',
            'rtw8852bx_set_gain_offset', 'rtw8852bx_set_rxsc_rpl_comp', 'rtw8852bx_ctrl_ch',
            'rtw8852b_bw_setting', 'rtw8852bt_adc_cfg', 'rtw8852bx_ctrl_bw',
            'rtw8852bx_ctrl_cck_en', 'rtw8852bx_5m_mask', '__rtw8852bx_bb_reset_all',
            'rtw8852bx_bb_set_pop', 'rtw8852bt_spur_freq']]
        + [lines_between('rtw8852b_common.c', '#define CARRIER_SPACING_312_5',
                         '#define MAX_TONE_NUM')]
        + [function('rtw8852b_common.c', name) for name in [
            'rtw8852bt_set_csi_tone_idx', '__rtw8852bx_set_channel_bb']]
        + [function('rtw8852b_common.h', name) for name in [
            'rtw8852bx_set_channel_mac', 'rtw8852bx_set_channel_bb']])
    rfk = '\n\n'.join(function('rtw8852b_rfk.c', name) for name in [
        '_kpath', '_bw_setting', '_ctrl_bw', '_set_s0_arfc18', '_lck_check', '_set_ch',
        '_ch_setting', '_ctrl_ch', '_set_rxbb_bw', '_rxbb_bw', 'rtw8852b_ctrl_bw_ch',
        'rtw8852b_set_channel_rf'])
    chip = '\n\n'.join(function('rtw8852b.c', name) for name in [
        'rtw8852b_bb_reset_en', 'rtw8852b_set_channel', 'rtw8852b_tssi_cont_en',
        'rtw8852b_tssi_cont_en_phyidx', 'rtw8852b_adc_en', 'rtw8852b_set_channel_help'])
    core = '\n\n'.join(function('core.c', name) for name in [
        'rtw89_chip_rfk_channel_for_pure_mon_vif', '__rtw89_set_channel'])

    ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                 ['set_channel', 'set_channel_help', 'read_rf', 'write_rf', 'set_txpwr',
                  'rfk_band_changed', 'stop_sch_tx', 'resume_sch_tx'])
    expect('rtw8852b_chip_ops', ops, dict(
        set_channel='rtw8852b_set_channel', set_channel_help='rtw8852b_set_channel_help',
        read_rf='rtw89_phy_read_rf_v1', write_rf='rtw89_phy_write_rf_v1',
        set_txpwr='rtw8852bx_set_txpwr', rfk_band_changed='rtw8852b_rfk_band_changed',
        stop_sch_tx='rtw89_mac_stop_sch_tx', resume_sch_tx='rtw89_mac_resume_sch_tx'))
    info = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  ['chip_id', 'ops', 'mac_def', 'phy_def', 'rf_base_addr', 'rf_path_num'])
    expect('rtw8852b_chip_info', info, dict(
        chip_id='RTL8852B', ops='&rtw8852b_chip_ops', mac_def='&rtw89_mac_gen_ax',
        phy_def='&rtw89_phy_gen_ax', rf_base_addr='{0xe000, 0xf000}', rf_path_num='2'))
    bx = fields('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info',
                ['set_channel_mac', 'set_channel_bb'])
    expect('rtw8852bx_info', bx, dict(set_channel_mac='__rtw8852bx_set_channel_mac',
                                      set_channel_bb='__rtw8852bx_set_channel_bb'))
    mac_def = fields('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax',
                     ['band1_offset', 'check_mac_en', 'cfg_ppdu_status'])
    expect('rtw89_mac_gen_ax', mac_def, dict(band1_offset='RTW89_MAC_AX_BAND_REG_OFFSET',
                                             check_mac_en='rtw89_mac_check_mac_en_ax',
                                             cfg_ppdu_status='rtw89_mac_cfg_ppdu_status_ax'))
    phy_def = fields('phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax', ['cr_base'])
    expect('rtw89_phy_gen_ax', phy_def, dict(cr_base='0x10000'))
    raw_io = fields('fw.c', 'static const struct rtw89_io_ops rtw89_raw_io',
                    ['phy_write32', 'write_rf'])
    expect('rtw89_raw_io', raw_io, dict(phy_write32='rtw89_raw_phy_write32',
                                        write_rf='rtw89_raw_write_rf'))

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define S8_MIN (-128)
#define S8_MAX 127
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define clamp_t(t, v, lo, hi) ({ t __v = (v), __lo = (lo), __hi = (hi); \
	__v < __lo ? __lo : __v > __hi ? __hi : __v; })
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define DIV_ROUND_CLOSEST(x, d) (((x) + ((d) / 2)) / (d))
#define fallthrough __attribute__((__fallthrough__))
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define lockdep_assert_wiphy(w) ((void)(w))
#define container_of_const(ptr, type, member) \
	((const type *)((const char *)(ptr) - offsetof(type, member)))
#define test_bit(nr, addr) ((int)(((addr)[(nr) / 64] >> ((nr) % 64)) & 1))
/* rtw89's log helpers are calls in the kernel: their arguments, register
 * reads among them, are evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound. */
#define read_poll_timeout(op, val, cond, sleep_us, timeout_us, sleep_before_read, args...) ({ \
	u64 __waited = 0; int __ret; \
	if ((sleep_before_read) && (sleep_us)) { model_delay(sleep_us); __waited += (sleep_us); } \
	for (;;) { \
		(val) = op(args); \
		if (cond) { __ret = 0; break; } \
		if (__waited >= (u64)(timeout_us)) { __ret = -ETIMEDOUT; break; } \
		model_delay(sleep_us); __waited += (sleep_us); \
	} \
	__ret; })
#define read_poll_timeout_atomic read_poll_timeout
#define udelay(us) model_delay(us)
#define fsleep(us) model_delay(us)
enum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_60GHZ, NL80211_BAND_6GHZ };
#define IEEE80211_CONF_MONITOR (1 << 0)
enum { RTW89_FLAG_FW_RDY, RTW89_FLAG_UNPLUGGED, NUM_OF_RTW89_FLAGS };
'''
    harness = r'''
struct rtw89_dev;
struct rtw89_vif;
struct rtw89_vif_link;
struct rtw89_chip_ops {
	void (*set_channel)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
			    enum rtw89_mac_idx mac_idx, enum rtw89_phy_idx phy_idx);
	void (*set_channel_help)(struct rtw89_dev *rtwdev, bool enter,
				 struct rtw89_channel_help_params *p, const struct rtw89_chan *chan,
				 enum rtw89_mac_idx mac_idx, enum rtw89_phy_idx phy_idx);
	u32 (*read_rf)(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr, u32 mask);
	bool (*write_rf)(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			 u32 mask, u32 data);
	void (*set_txpwr)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
			  enum rtw89_phy_idx phy_idx);
	void (*rfk_band_changed)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx,
				 const struct rtw89_chan *chan);
	int (*stop_sch_tx)(struct rtw89_dev *rtwdev, u8 mac_idx, u32 *tx_en,
			   enum rtw89_sch_tx_sel sel);
	int (*resume_sch_tx)(struct rtw89_dev *rtwdev, u8 mac_idx, u32 tx_en);
};
struct rtw89_mac_gen_def {
	u32 band1_offset;
	int (*check_mac_en)(struct rtw89_dev *rtwdev, u8 band, enum rtw89_mac_hwmod_sel sel);
	int (*cfg_ppdu_status)(struct rtw89_dev *rtwdev, u8 mac_idx, bool enable);
};
struct rtw89_phy_gen_def { u32 cr_base; };
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	const struct rtw89_phy_gen_def *phy_def;
	u32 rf_base_addr[2];
	u8 rf_path_num;
};
struct rtw89_io_ops {
	void (*phy_write32)(struct rtw89_dev *rtwdev, u32 addr, u32 data);
	void (*write_rf)(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			 u32 mask, u32 data);
};
struct rtw89_chanctx { struct rtw89_chan chan; struct rtw89_chan_rcd rcd; };
struct rtw89_hal {
	u8 antenna_rx;
	bool entity_active[RTW89_PHY_NUM];
	struct rtw89_chanctx chanctx[1];
};
struct ieee80211_conf { u32 flags; };
struct ieee80211_hw { struct ieee80211_conf conf; void *wiphy; };
struct rtw89_efuse { u8 rfe_type; };
struct rtw8852bx_info {
	void (*set_channel_mac)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				u8 mac_idx);
	void (*set_channel_bb)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
			       enum rtw89_phy_idx phy_idx);
};
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_io_ops *io;
	struct ieee80211_hw *hw;
	struct rtw89_hal hal;
	union { struct rtw89_phy_bb_gain_info ax; } bb_gain;
	struct rtw89_phy_efuse_gain efuse_gain;
	struct rtw89_efuse efuse;
	struct rtw89_vif *pure_monitor_mode_vif;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
	bool dbcc_en;
};

/* The register model. */
#define CR 0x10000
static u8 memory[0x20000];
static u32 rf[2][256];
static u32 rf_request;
static struct { int unlocked, lpf_stuck; } fault;
static u8 *segment;
static size_t segment_bytes, segment_capacity;
static void word(u32 v)
{
	if (segment_bytes + 4 > segment_capacity) {
		segment_capacity = segment_capacity ? 2 * segment_capacity : 4096;
		segment = realloc(segment, segment_capacity);
		if (!segment)
			abort();
	}
	for (int i = 0; i < 4; i++)
		segment[segment_bytes++] = v >> (8 * i);
}
static void record(u32 tag, u32 a, u32 b) { word(tag); word(a); word(b); }
static void model_delay(u64 us) { if (us > UINT32_MAX) abort(); record(9, 0, (u32)us); }
static u32 get(u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)memory[r + i] << (8 * i); return v; }
static void set(u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) memory[r + i] = v >> (8 * i); }
static void check(u32 r, u32 n)
{
	if (r + n > sizeof(memory) || r % n)
		abort();
}
/* What RF word a of path p reads as. */
static u32 rf_value(u32 p, u32 a)
{
	u32 v = rf[p][a];

	if (p == 0 && a == RR_LPF)
		v = fault.lpf_stuck ? v | RR_LPF_BUSY : v & ~RR_LPF_BUSY;
	if (p == 0 && a == RR_SYNFB)
		v = fault.unlocked ? v & ~RR_SYNFB_LK : v | RR_SYNFB_LK;
	return v;
}
static u32 model_read(u32 r, u32 n)
{
	u32 v;

	check(r, n);
	if (r == CR + R_SWSI_V1) {
		u32 p = FIELD_GET(B_SWSI_READ_ADDR_PATH_V1, rf_request);

		if (n != 4 || p > 1)
			abort();
		v = B_SWSI_R_DATA_DONE_V1 | rf_value(p, FIELD_GET(B_SWSI_READ_ADDR_ADDR_V1, rf_request));
	} else {
		v = get(r, n);
	}
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	check(r, n);
	record(4 + n, r, v);
	set(r, n, v);
	if (r == CR + R_SWSI_READ_ADDR_V1) {
		if (n != 4)
			abort();
		rf_request = v;
	}
	if (r == CR + R_SWSI_DATA_V1) {
		u32 p = FIELD_GET(B_SWSI_DATA_PATH_V1, v), a = FIELD_GET(B_SWSI_DATA_ADDR_V1, v);
		u32 d = FIELD_GET(B_SWSI_DATA_VAL_V1, v);

		if (n != 4 || p > 1)
			abort();
		if (v & B_SWSI_DATA_BIT_MASK_EN_V1) {
			u32 m = get(CR + R_SWSI_BIT_MASK_V1, 4) & RFREG_MASK;

			rf[p][a] = (rf[p][a] & ~m) | (d & m);
		} else {
			rf[p][a] = d;
		}
	}
}
/* PCIe reaches the registers through rtw89_raw_io and rtw89_pci_ops; these
 * stand for both. */
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* net/wireless/util.c's ieee80211_channel_to_freq_khz for 2.4 and 5 GHz, in MHz. */
static u32 ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	if (chan <= 0)
		return 0;
	if (band == NL80211_BAND_2GHZ)
		return chan == 14 ? 2484 : chan < 14 ? 2407 + chan * 5 : 0;
	if (band == NL80211_BAND_5GHZ)
		return chan >= 182 && chan <= 196 ? 4000 + chan * 5 : 5000 + chan * 5;
	abort();
}

/* Reached only off an RTL8852B with DBCC, a firmware that runs, or a monitor-only
 * interface: none is. */
static u32 rtw89_phy0_phy1_offset(struct rtw89_dev *d, u32 a) { (void)d; (void)a; abort(); }
static int rtw89_hw_sch_tx_en_h2c(struct rtw89_dev *d, u8 b, u16 e, u16 m)
{ (void)d; (void)b; (void)e; (void)m; abort(); }
static struct rtw89_vif_link *rtw89_vif_get_link_inst(struct rtw89_vif *v, u8 i)
{ (void)v; (void)i; abort(); }
static void rtw89_chip_rfk_channel(struct rtw89_dev *d, struct rtw89_vif_link *l)
{ (void)d; (void)l; abort(); }
/* RTL8852BT's alone. */
static u64 rtw89_db_to_linear(u32 db) { (void)db; abort(); }
static s8 rtw89_linear_to_db(u64 v) { (void)v; abort(); }
static s32 s32_div_u32_round_closest(s32 x, u32 d) { (void)x; (void)d; abort(); }
static void s32_div_u32_round_down(s32 x, u32 d, s32 *r) { (void)x; (void)d; (void)r; abort(); }
/* The seams: TX power (3.5), coex (3.9), the TSSI scan (3.8). */
static void stub_set_txpwr(struct rtw89_dev *d, const struct rtw89_chan *c, enum rtw89_phy_idx p)
{ (void)d; (void)p; record(12, c->channel, c->primary_channel); }
static void rtw89_btc_ntfy_switch_band(struct rtw89_dev *d, u8 p, u8 band)
{ (void)d; record(13, p, band); }
static void stub_rfk_band_changed(struct rtw89_dev *d, enum rtw89_phy_idx p,
				  const struct rtw89_chan *c)
{ (void)d; record(14, p, c->band_type); }

static void rtw8852b_set_channel(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				 enum rtw89_mac_idx mac_idx, enum rtw89_phy_idx phy_idx);
static void rtw8852b_set_channel_help(struct rtw89_dev *rtwdev, bool enter,
				      struct rtw89_channel_help_params *p,
				      const struct rtw89_chan *chan, enum rtw89_mac_idx mac_idx,
				      enum rtw89_phy_idx phy_idx);
u32 rtw89_phy_read_rf_v1(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr, u32 mask);
bool rtw89_phy_write_rf_v1(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			   u32 mask, u32 data);
int rtw89_mac_stop_sch_tx(struct rtw89_dev *rtwdev, u8 mac_idx, u32 *tx_en,
			  enum rtw89_sch_tx_sel sel);
int rtw89_mac_resume_sch_tx(struct rtw89_dev *rtwdev, u8 mac_idx, u32 tx_en);
static void __rtw8852bx_set_channel_mac(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
					u8 mac_idx);
static void __rtw8852bx_set_channel_bb(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				       enum rtw89_phy_idx phy_idx);
static void rtw89_raw_phy_write32(struct rtw89_dev *rtwdev, u32 addr, u32 data);
static void rtw89_raw_write_rf(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			       u32 mask, u32 data);

static const struct rtw89_chip_ops rtw8852b_chip_ops;
static const struct rtw89_mac_gen_def rtw89_mac_gen_ax;
static const struct rtw89_phy_gen_def rtw89_phy_gen_ax;
static const struct rtw89_io_ops rtw89_raw_io;
static const struct rtw8852bx_info rtw8852bx_info;
'''
    tables = (
        'static const struct rtw89_chip_ops rtw8852b_chip_ops = {\n'
        f"\t.set_channel = {ops['set_channel']},\n"
        f"\t.set_channel_help = {ops['set_channel_help']},\n"
        f"\t.read_rf = {ops['read_rf']},\n\t.write_rf = {ops['write_rf']},\n"
        '\t.set_txpwr = stub_set_txpwr,\n\t.rfk_band_changed = stub_rfk_band_changed,\n'
        f"\t.stop_sch_tx = {ops['stop_sch_tx']},\n\t.resume_sch_tx = {ops['resume_sch_tx']},\n"
        '};\n'
        'static const struct rtw89_mac_gen_def rtw89_mac_gen_ax = {\n'
        f"\t.band1_offset = {mac_def['band1_offset']},\n"
        f"\t.check_mac_en = {mac_def['check_mac_en']},\n"
        f"\t.cfg_ppdu_status = {mac_def['cfg_ppdu_status']},\n}};\n"
        'static const struct rtw89_phy_gen_def rtw89_phy_gen_ax = {\n'
        f"\t.cr_base = {phy_def['cr_base']},\n}};\n"
        'static const struct rtw89_io_ops rtw89_raw_io = {\n'
        f"\t.phy_write32 = {raw_io['phy_write32']},\n\t.write_rf = {raw_io['write_rf']},\n}};\n"
        'static const struct rtw8852bx_info rtw8852bx_info = {\n'
        f"\t.set_channel_mac = {bx['set_channel_mac']},\n"
        f"\t.set_channel_bb = {bx['set_channel_bb']},\n}};\n"
        'static const struct rtw89_chip_info rtw8852b_chip_info = {\n'
        f"\t.chip_id = {info['chip_id']},\n\t.ops = {info['ops']},\n"
        f"\t.mac_def = {info['mac_def']},\n\t.phy_def = {info['phy_def']},\n"
        f"\t.rf_base_addr = {info['rf_base_addr']},\n\t.rf_path_num = {info['rf_path_num']},\n}};\n")

    width = {20: 'RTW89_CHANNEL_WIDTH_20', 40: 'RTW89_CHANNEL_WIDTH_40',
             80: 'RTW89_CHANNEL_WIDTH_80'}
    rows = []
    for inputs, unlocked, lpf_stuck, cmac_off, rx_path, steps in CASES:
        body = ', '.join(
            f"{{{center}, {primary}, {'RTW89_BAND_2G' if primary <= 14 else 'RTW89_BAND_5G'}, "
            f'{width[w]}}}' for center, primary, w in steps)
        rows.append(f'\t{{{inputs}, {unlocked}, {lpf_stuck}, {cmac_off}, {rx_path}, '
                    f'{len(steps)}, {{{body}}}}},')
    main_c = r'''
struct step { u8 center, primary; enum rtw89_band band; enum rtw89_bandwidth bw; };
struct ocase { int inputs, unlocked, lpf_stuck, cmac_off, rx_path, n; struct step steps[3]; };
static const struct ocase cases[] = {
''' + '\n'.join(rows) + r'''
};
static s8 pattern(int a, int b, int c, int k) { return (s8)(((a * 31 + b * 17 + c * 7 + k * 3) % 41) - 20); }
static void inputs(struct rtw89_dev *dev, int kind)
{
	struct rtw89_phy_bb_gain_info *g = &dev->bb_gain.ax;
	struct rtw89_phy_efuse_gain *e = &dev->efuse_gain;

	if (kind == 1)
		return;
	for (int band = 0; band < 4; band++) {
		for (int path = 0; path < 2; path++) {
			for (int i = 0; i < LNA_GAIN_NUM; i++)
				g->lna_gain[band][path][i] = pattern(band, path, i, 1);
			for (int i = 0; i < TIA_GAIN_NUM; i++)
				g->tia_gain[band][path][i] = pattern(band, path, i, 2);
			g->rpl_ofst_20[band][path] = pattern(band, path, 0, 3);
			for (int i = 0; i < RTW89_BB_RXSC_NUM_40; i++)
				g->rpl_ofst_40[band][path][i] = pattern(band, path, i, 4);
			for (int i = 0; i < RTW89_BB_RXSC_NUM_80; i++)
				g->rpl_ofst_80[band][path][i] = pattern(band, path, i, 5);
		}
	}
	e->offset_valid = true;
	e->comp_valid = true;
	for (int path = 0; path < 2; path++) {
		for (int i = 0; i < 5; i++) {
			e->offset[path][i] = (s8)(((path * 5 + i * 3) % 15) - 7);
			e->comp[path][i] = (s8)(((path * 3 + i * 5) % 15) - 7);
		}
	}
	e->offset_base[RTW89_PHY_0] = -37;
	e->rssi_base[RTW89_PHY_0] = 21;
	if (kind == 2) {
		dev->hal.antenna_rx = RF_B;
		dev->hw->conf.flags |= IEEE80211_CONF_MONITOR;
	}
}
static void flush(FILE *out)
{
	u32 n = (u32)segment_bytes;
	u8 length[4] = {n, n >> 8, n >> 16, n >> 24};

	if (fwrite(length, 1, 4, out) != 4 || fwrite(segment, 1, segment_bytes, out) != segment_bytes)
		abort();
	segment_bytes = 0;
}
int main(int argc, char **argv)
{
	FILE *out;

	if (argc != 2 || !(out = fopen(argv[1], "wb")))
		return 2;
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		static struct rtw89_dev dev;
		static struct ieee80211_hw hw;

		memset(&dev, 0, sizeof(dev));
		memset(&hw, 0, sizeof(hw));
		dev.chip = &rtw8852b_chip_info;
		dev.io = &rtw89_raw_io;
		dev.hw = &hw;
		for (u32 i = 0; i < sizeof(memory); i++)
			memory[i] = (u8)(i * 37 + 11);
		for (u32 p = 0; p < 2; p++)
			for (u32 a = 0; a < 256; a++)
				rf[p][a] = (a * 0x9e3 + p * 0x4f1b + 0x1a2b3) & RFREG_MASK;
		rf_request = 0;
		fault.unlocked = cases[c].unlocked;
		fault.lpf_stuck = cases[c].lpf_stuck;
		set(R_AX_CMAC_FUNC_EN, 4, cases[c].cmac_off ? get(R_AX_CMAC_FUNC_EN, 4) & ~B_AX_CMAC_EN
							     : get(R_AX_CMAC_FUNC_EN, 4) | B_AX_CMAC_EN);
		if (cases[c].rx_path >= 0)
			set(CR + R_CHBW_MOD_V1, 4,
			    (get(CR + R_CHBW_MOD_V1, 4) & ~B_ANT_RX_SEG0) | (u32)cases[c].rx_path);
		inputs(&dev, cases[c].inputs);
		for (int s = 0; s < cases[c].n; s++) {
			const struct step *step = &cases[c].steps[s];
			struct rtw89_chan chan;

			rtw89_chan_create(&chan, step->center, step->primary, step->band, step->bw);
			rtw89_assign_entity_chan(&dev, RTW89_CHANCTX_0, &chan);
			__rtw89_set_channel(&dev, &dev.hal.chanctx[RTW89_CHANCTX_0].chan,
					    RTW89_MAC_0, RTW89_PHY_0);
		}
		flush(out);
	}
	if (fclose(out))
		abort();
	free(segment);
	printf("%zu\n", ARRAY_SIZE(cases));
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, core_defines, other_defines, declarations, harness, inlines, phy,
        chan, mac, common, rfk, chip, core, tables, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize=shift-base', '-fno-sanitize-recover=all',
                    '-Wno-unused-function', str(generated), '-o', str(exe)], check=True)
    trace = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    cases = int(run.stdout.strip())
    if cases != len(CASES):
        raise ValueError(f'{cases} cases run, {len(CASES)} listed')
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=cases,
        case_order=[dict(inputs=['card', 'blank', 'card, RF_B, monitor'][i], unlocked=bool(u),
                         lpf_stuck=bool(l), cmac_off=bool(m), rx_path=r,
                         channels=[dict(center=c, primary=p, width=w) for c, p, w in s])
                    for i, u, l, m, r, s in CASES],
        dispatch=dict(rtw8852b_chip_ops=ops, rtw8852b_chip_info=info, rtw8852bx_info=bx,
                      rtw89_mac_gen_ax=mac_def, rtw89_phy_gen_ax=phy_def, rtw89_raw_io=raw_io),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, RF, delays and the chip answers are a model; no physical evidence',
            'read_poll_timeout and its atomic form are modeled counted in steps',
            'register reads go straight to the model, below rtw89_pci_ops\' CMAC read retry',
            'ieee80211_channel_to_frequency is the harness\'s, from net/wireless/util.c',
            'the firmware is not running (RTW89_FLAG_FW_RDY clear): the scheduler stop and '
            'resume write CTN_TXEN; their mailbox path is the MAC oracle\'s',
            'set_txpwr, rtw89_btc_ntfy_switch_band and rfk_band_changed are stubs that record '
            'markers; DBCC, the firmware mailbox, a monitor-only interface and RTL8852BT\'s '
            'helpers abort if reached',
            'no function on this path reads the chip\'s cut, so the cases hold for cut 0, 1 '
            'and 2 alike',
            'debug-line arguments are evaluated in clang\'s order; C leaves it unspecified',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
