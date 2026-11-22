#!/usr/bin/env python3
"""Unchanged pinned rtw89 efuse and phycap read for a PCIe RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. Extracted unchanged, each with its SHA-256
in manifest.json:

- core.c: rtw89_chip_efuse_info_setup and rtw89_core_setup_phycap;
- efuse.c: the physical dump (rtw89_dump_physical_efuse_map with its DDV and
  DAV paths, the efuse power cut, OTP burst mode and bank switch), the logical
  decode with its macros, rtw89_parse_efuse_map_ax, rtw89_parse_phycap_map_ax
  and rtw89_cnv_efuse_state_ax;
- mac.c: rtw89_mac_read_phycap, rtw89_mac_setup_phycap with both parts, and
  the AX generation's XTAL SI; fw.c: rtw89_fw_write_h2c_reg,
  rtw89_fw_read_c2h_reg and rtw89_fw_msg_reg;
- rtw8852b_common.c: __rtw8852bx_read_efuse and __rtw8852bx_read_phycap with
  every parser they call; rtw8852b_common.h: struct rtw8852bx_efuse and its
  parts, and the read_efuse/read_phycap wrappers;
- pci.c: rtw89_pci_ops_mac_pre_deinit_ax and rtw89_pci_power_wake_ax; pci.h:
  rtw89_pci_ops_mac_pre_deinit;
- the core.h, mac.h and fw.h declarations, inlines and definitions they use,
  and reg.h.

rtw8852b_chip_info, rtw8852b_chip_ops, rtw8852bx_info, rtw89_mac_gen_ax,
rtw89_pci_gen_ax and rtw89_pci_ops give the values the harness's tables take,
member by member, each checked. Everything is compiled with clang under ASan
and UBSan. rtw89_mac_partial_init, which comes first in
rtw89_chip_efuse_info_setup and downloads the firmware, is a stub that only
counts its calls.

The model: MAC space as bytes, byte i holding i * 37 + 11, with
SYS_WL_EFUSE_CTRL's AUTOLOAD_SUS as the case says, H2CREG_CTRL 0 (or 1 for
a firmware that never takes an H2C) and C2HREG_CTRL 0. EFUSE_CTRL serves
the case's DDV efuse (2048 bytes) and shows EF_RDY after the case's number of
reads. XTAL SI completes every request at once; writing XTAL_SI_CTRL's mode
to 0 starts a DAV read of the address the low and high bits name, which
loads XTAL_SI_READ_VAL from the case's DAV efuse and sets XTAL_SI_RDY after
the case's number of XTAL_SI_CTRL reads, or never for the case's first DAV
requests. Triggering H2CREG_CTRL clears it and, when the case answers, puts
its four words in C2HREG_DATA0..3 and 1 in C2HREG_CTRL. Polls are
read_poll_timeout counted in steps, as in the other AX oracles.

trace.bin is segments, each prefixed by its byte length. The first holds
records of three little-endian u32 (20, field, offset): offsetof and sizeof
of struct rtw8852bx_efuse and struct rtw8852bx_tssi_offset fields. Then,
per case, five segments:

1. Inputs: cut, autoload, DDV reads before EF_RDY, XTAL_SI_CTRL reads before
   XTAL_SI_RDY, DAV requests never ready, H2C never taken, C2H answered, the
   four C2H words (each a u32), then the DDV and DAV efuse (2048 bytes each).
2. Accesses: records (tag, register, value), reads tagged by width, writes
   by 4 plus width, delays 9.
3. Results: (30, rtw89_mac_partial_init calls, return), and when it returned
   0: efuse valid and power_k_valid (31), MAC address (32), RFE type and
   crystal cap (33), country code (34), TSSI thermal (35), CCK (36), MCS
   (37) and trim (38) by path << 8 | group, power trims (39), gain validity
   (40), offsets (41) and compensations (42) by path << 8 | index, the HAL's
   phycap fields (43) and the mailbox counters (44).
4. The logical map rtw89 dumped as log_map, when it returned 0.
5. The phycap map read_phycap was given, when it returned 0.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'

CASES = [
    'valid', 'rfe5', 'empty', 'corrupt', 'layered', 'slow', 'dav_retry',
    'mailbox_busy', 'phycap_wrong_id', 'phycap_1ss_diversity', 'phycap_antenna_b',
]


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

    def locate(file, name):
        """A function definition, from the blank line before it, and where it starts."""
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
            return start, record(file, name, text[start:closing(text, end)])
        raise ValueError(f'{file}: no definition of {name}')

    def function(file, name):
        return locate(file, name)[1]

    def in_order(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        found = sorted(locate(file, name) for name in names)
        return '\n\n'.join(body for _, body in found)

    def declaration(file, kind, name):
        """An enum, struct or union declaration, through its semicolon."""
        text = source(file)
        m = re.search(r'^' + kind + r' ' + re.escape(name) + r' \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {kind} {name}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, f'{kind} {name}', text[m.start():end])

    def span(file, first, last):
        """Everything from the line starting `first` through the declaration `last`."""
        text = source(file)
        m = re.search(r'^' + re.escape(first), text, re.M)
        n = re.search(r'^' + re.escape(last) + r' \{', text, re.M)
        if not m or not n or n.start() < m.start():
            raise ValueError(f'{file}: no span {first} .. {last}')
        end = text.index(';', closing(text, text.index('{', n.start()))) + 1
        return record(file, f'{first} .. {last}', text[m.start():end])

    def defines(file, names):
        """#define lines, each with its continuation lines."""
        lines = source(file).split('\n')
        found = []
        for name in names:
            hits = [i for i, line in enumerate(lines)
                    if re.match(r'#define ' + re.escape(name) + r'[\s(]', line)]
            if len(hits) != 1:
                raise ValueError(f'{file}: #define {name} appears {len(hits)} times')
            at = hits[0]
            block = [lines[at]]
            while block[-1].endswith('\\'):
                at += 1
                block.append(lines[at])
            found.append('\n'.join(block))
        return record(file, 'defines ' + ', '.join(names), '\n'.join(found))

    def table(file, head):
        """An array definition, through its semicolon."""
        text = source(file)
        m = re.search(re.escape(head) + r'\[[^\]]*\] = \{', text)
        if not m:
            raise ValueError(f'{file}: no {head}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, head, text[m.start():end])

    def members(file, head, fields):
        """Fields of a designated initializer, by name."""
        text = source(file)
        m = re.search(re.escape(head) + r' = \{', text)
        if not m:
            raise ValueError(f'{file}: no {head}')
        body = record(file, head, text[m.start():closing(text, text.index('{', m.start()))])
        values = {}
        for field in fields:
            found = re.findall(r'\n\s*\.' + field + r'\s*=\s*(.*?),[ \t]*\n', body)
            if len(found) != 1:
                raise ValueError(f'{head}: .{field} is set {len(found)} times')
            values[field] = found[0]
        return values

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    core_defines = defines('core.h', [
        'RF_PATH_MAX', 'RTW89_EFUSE_SN_LEN', 'RTW89_EFUSE_UUID_LEN',
        'TSSI_TRIM_CH_GROUP_NUM', 'TSSI_TRIM_CH_GROUP_NUM_6G', 'TSSI_CCK_CH_GROUP_NUM',
        'TSSI_MCS_2G_CH_GROUP_NUM', 'TSSI_MCS_5G_CH_GROUP_NUM', 'TSSI_MCS_6G_CH_GROUP_NUM',
        'TSSI_MCS_CH_GROUP_NUM', 'TSSI_MAX_CH_NUM', 'TSSI_ALIMK_VALUE_NUM'])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_subband'),
        declaration('core.h', 'enum', 'rtw89_gain_offset'),
        declaration('core.h', 'enum', 'rtw89_hci_type'),
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_chip_gen'),
        declaration('core.h', 'enum', 'rtw89_cv'),
        declaration('core.h', 'enum', 'rtw89_phy_idx'),
        declaration('core.h', 'enum', 'rtw89_rf_path'),
        declaration('core.h', 'enum', 'rtw89_flags'),
        declaration('core.h', 'enum', 'rtw89_rf_path_bit'),
        declaration('core.h', 'enum', 'rtw89_efuse_block'),
        declaration('core.h', 'enum', 'rtw89_tssi_alimk_band'),
        declaration('core.h', 'enum', 'rtw89_quirks'),
        declaration('core.h', 'struct', 'rtw89_reg_def'),
        declaration('core.h', 'struct', 'rtw89_efuse'),
        declaration('core.h', 'struct', 'rtw89_tssi_info'),
        declaration('core.h', 'struct', 'rtw89_power_trim_info'),
        declaration('core.h', 'struct', 'rtw89_phy_efuse_gain'),
        declaration('mac.h', 'enum', 'rtw89_mac_xtal_si_offset'),
        span('fw.h', 'struct rtw89_c2hreg_hdr {', 'enum rtw89_mac_c2h_type'),
        declaration('efuse.c', 'enum', 'rtw89_efuse_bank'),
        defines('rtw8852b_common.h', ['RF_PATH_NUM_8852BX']),
        declaration('rtw8852b_common.h', 'struct', 'rtw8852bx_u_efuse'),
        declaration('rtw8852b_common.h', 'struct', 'rtw8852bx_e_efuse'),
        declaration('rtw8852b_common.h', 'struct', 'rtw8852bx_tssi_offset'),
        declaration('rtw8852b_common.h', 'struct', 'rtw8852bx_efuse'),
    ])
    helpers = '\n\n'.join(function('core.h', name) for name in [
        'rtw89_write8_set', 'rtw89_write16_set', 'rtw89_write32_set',
        'rtw89_write8_clr', 'rtw89_write16_clr', 'rtw89_write32_clr',
        'rtw89_read32_mask', 'rtw89_write32_mask', 'rtw89_write8_mask',
        'rtw89_hci_mac_pre_deinit'])
    xtal_inlines = '\n\n'.join(function('mac.h', name) for name in [
        'rtw89_mac_write_xtal_si', 'rtw89_mac_read_xtal_si'])
    xtal_si = in_order('mac.c', ['rtw89_mac_write_xtal_si_ax', 'rtw89_mac_read_xtal_si_ax'])
    efuse = in_order('efuse.c', [
        'rtw89_switch_efuse_bank', 'rtw89_enable_otp_burst_mode',
        'rtw89_enable_efuse_pwr_cut_ddv', 'rtw89_disable_efuse_pwr_cut_ddv',
        'rtw89_dump_physical_efuse_map_ddv', 'rtw89_cnv_efuse_state_ax',
        'rtw89_dump_physical_efuse_map_dav', '__rtw89_dump_physical_efuse_map',
        'rtw89_dump_physical_efuse_map', 'rtw89_dump_logical_efuse_map',
        'rtw89_parse_efuse_map_ax', 'rtw89_parse_phycap_map_ax'])
    mailbox = in_order('fw.c', [
        'rtw89_fw_write_h2c_reg', 'rtw89_fw_read_c2h_reg', 'rtw89_fw_msg_reg'])
    phycap = in_order('mac.c', [
        'rtw89_mac_read_phycap', 'rtw89_mac_setup_phycap_part0',
        'rtw89_mac_setup_phycap_part1', 'rtw89_mac_setup_phycap'])
    chip = in_order('rtw8852b_common.c', [
        'rtw8852bx_efuse_parsing_tssi', '_decode_efuse_gain',
        'rtw8852bx_efuse_parsing_gain_offset', '__rtw8852bx_read_efuse',
        'rtw8852bx_phycap_parsing_power_cal', 'rtw8852bx_phycap_parsing_tssi',
        'rtw8852bx_phycap_parsing_thermal_trim', 'rtw8852bx_phycap_parsing_pa_bias_trim',
        'rtw8852bx_phycap_parsing_gain_comp', '__rtw8852bx_read_phycap'])
    chip_wrappers = '\n\n'.join(function('rtw8852b_common.h', name) for name in [
        'rtw8852bx_read_efuse', 'rtw8852bx_read_phycap'])
    pci = in_order('pci.c', ['rtw89_pci_power_wake_ax', 'rtw89_pci_ops_mac_pre_deinit_ax'])
    pci_inline = function('pci.h', 'rtw89_pci_ops_mac_pre_deinit')
    core = in_order('core.c', ['rtw89_core_setup_phycap', 'rtw89_chip_efuse_info_setup'])
    regs = '\n\n'.join([
        table('rtw8852b.c', 'static const u32 rtw8852b_h2c_regs'),
        table('rtw8852b.c', 'static const u32 rtw8852b_c2h_regs'),
    ])

    mac_fields = ['parse_efuse_map', 'parse_phycap_map', 'cnv_efuse_state',
                  'write_xtal_si', 'read_xtal_si']
    mac_def = members('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax', mac_fields)
    ops = members('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                  ['read_efuse', 'read_phycap'])
    bx = members('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info',
                 ['read_efuse', 'read_phycap'])
    pci_gen = members('pci.c', 'const struct rtw89_pci_gen_def rtw89_pci_gen_ax',
                      ['mac_pre_deinit'])
    hci = members('pci.c', 'static const struct rtw89_hci_ops rtw89_pci_ops', ['mac_pre_deinit'])
    info_fields = ['chip_id', 'chip_gen', 'rf_path_num', 'tx_nss', 'rx_nss', 'thermal_th',
                   'sec_ctrl_efuse_size', 'physical_efuse_size', 'logical_efuse_size',
                   'dav_phy_efuse_size', 'dav_log_efuse_size', 'phycap_addr', 'phycap_size',
                   'h2c_ctrl_reg', 'h2c_counter_reg', 'h2c_regs',
                   'c2h_ctrl_reg', 'c2h_counter_reg', 'c2h_regs']
    info = members('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info', info_fields)

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
/* bitfield.h's FIELD_GET_SIGNED: the field moved to the top and shifted back
 * down arithmetically; the left shift is done unsigned to stay defined. */
#define FIELD_GET_SIGNED(m, v) \
	((long long)((unsigned long long)(v) << __builtin_clzll(m)) >> \
	 (__builtin_clzll(m) + __builtin_ctzll(m)))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) FIELD_GET(m, v)
#define u8_get_bits(v, m) ((u8)u32_get_bits(v, m))
#define u32p_replace_bits(p, v, m) (*(p) = (*(p) & ~(u32)(m)) | u32_encode_bits(v, m))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ETH_ALEN 6
#define ether_addr_copy(d, s) memcpy(d, s, ETH_ALEN)
#define __packed __attribute__((packed))
#define kmalloc(n, f) malloc(n)
#define kfree free
#define GFP_KERNEL 0
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
#define rtw89_warn(d, ...) ((void)(d))
#define rtw89_err(d, ...) ((void)(d))
#define rtw89_debug(d, m, ...) ((void)(d))
#define lockdep_assert_wiphy(w) ((void)0)
#define test_bit(n, a) ((((const unsigned long *)(a))[(n) / 64] >> ((n) % 64)) & 1UL)
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound; a sleep before the first read counts
 * toward the bound. The atomic variant is the same model. */
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
#define fsleep(us) model_delay(us)
#define udelay(us) model_delay(us)
'''
    harness = r'''
struct rtw89_dev;
struct rtw89_mac_gen_def {
	int (*parse_efuse_map)(struct rtw89_dev *rtwdev);
	int (*parse_phycap_map)(struct rtw89_dev *rtwdev);
	int (*cnv_efuse_state)(struct rtw89_dev *rtwdev, bool idle);
	int (*write_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 val, u8 mask);
	int (*read_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 *val);
};
struct rtw89_chip_ops {
	int (*read_efuse)(struct rtw89_dev *rtwdev, u8 *log_map, enum rtw89_efuse_block block);
	int (*read_phycap)(struct rtw89_dev *rtwdev, u8 *phycap_map);
};
struct rtw8852bx_info {
	int (*read_efuse)(struct rtw89_dev *rtwdev, u8 *log_map, enum rtw89_efuse_block block);
	int (*read_phycap)(struct rtw89_dev *rtwdev, u8 *phycap_map);
};
struct rtw89_hci_ops { int (*mac_pre_deinit)(struct rtw89_dev *rtwdev); };
struct rtw89_pci_gen_def { int (*mac_pre_deinit)(struct rtw89_dev *rtwdev); };
struct rtw89_pci_info { const struct rtw89_pci_gen_def *gen_def; };
struct rtw89_chip_variant { bool no_mcs_12_13; };
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	u8 thermal_th[2];
	u8 rf_path_num;
	u8 tx_nss;
	u8 rx_nss;
	u8 sec_ctrl_efuse_size;
	u32 physical_efuse_size;
	u32 logical_efuse_size;
	u32 dav_phy_efuse_size;
	u32 dav_log_efuse_size;
	u32 phycap_addr;
	u32 phycap_size;
	u32 h2c_ctrl_reg;
	const u32 *h2c_regs;
	struct rtw89_reg_def h2c_counter_reg;
	u32 c2h_ctrl_reg;
	const u32 *c2h_regs;
	struct rtw89_reg_def c2h_counter_reg;
};
struct rtw89_hal {
	u8 cv;
	u32 antenna_tx;
	u32 antenna_rx;
	u8 tx_nss;
	u8 rx_nss;
	bool tx_path_diversity;
	bool ant_diversity;
	bool support_cckpd;
	bool support_igi;
	bool no_mcs_12_13;
	bool no_eht;
	u8 thermal_prot_th;
};
struct rtw89_fw_info { u8 h2c_counter; u8 c2h_counter; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_chip_variant *variant;
	const struct rtw89_pci_info *pci_info;
	struct { enum rtw89_hci_type type; const struct rtw89_hci_ops *ops; } hci;
	struct rtw89_efuse efuse;
	struct rtw89_tssi_info tssi;
	struct rtw89_power_trim_info pwr_trim;
	struct rtw89_phy_efuse_gain efuse_gain;
	struct rtw89_hal hal;
	struct rtw89_fw_info fw;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
	unsigned long quirks[(NUM_OF_RTW89_QUIRKS + 63) / 64];
};
/* Reached only by the BE generation, which this harness never is. */
#define RTW89_CHK_FW_FEATURE(f, fw) (abort(), 0)

/* The register model. */
static u8 memory[0x10000];
static u8 xtal[256];
static u8 ddv[0x800], dav[0x800];
static u32 ddv_late, ddv_wait, dav_late, dav_wait, dav_stuck, dav_requests;
static int c2h_reply;
static u32 c2h_words[4];
#define NEVER UINT32_MAX
static u8 *segment;
static size_t segment_bytes, segment_capacity;
static void byte_out(u8 v)
{
	if (segment_bytes + 1 > segment_capacity) {
		segment_capacity = segment_capacity ? 2 * segment_capacity : 4096;
		segment = realloc(segment, segment_capacity);
		if (!segment)
			abort();
	}
	segment[segment_bytes++] = v;
}
static void word(u32 v) { for (int i = 0; i < 4; i++) byte_out(v >> (8 * i)); }
static void record(u32 tag, u32 r, u32 v) { word(tag); word(r); word(v); }
static void model_delay(u64 us) { if (us > UINT32_MAX) abort(); record(9, 0, (u32)us); }
static u32 get(u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)memory[r + i] << (8 * i); return v; }
static void set(u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) memory[r + i] = v >> (8 * i); }
static void check(u32 r, u32 n)
{
	if (r + n > sizeof(memory))
		abort();
	if (r >= R_AX_EFUSE_CTRL && r < R_AX_EFUSE_CTRL + 4 && (n != 4 || r != R_AX_EFUSE_CTRL))
		abort();
	if (r >= R_AX_WLAN_XTAL_SI_CTRL && r < R_AX_WLAN_XTAL_SI_CTRL + 4 &&
	    (n != 4 || r != R_AX_WLAN_XTAL_SI_CTRL))
		abort();
	if ((r == R_AX_H2CREG_CTRL || r == R_AX_C2HREG_CTRL) && n != 1)
		abort();
}
static u32 model_read(u32 r, u32 n)
{
	check(r, n);
	if (r == R_AX_EFUSE_CTRL) {
		if (ddv_wait)
			ddv_wait--;
		else
			set(r, 4, get(r, 4) | B_AX_EF_RDY);
	}
	u32 v = get(r, n);
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	check(r, n);
	record(4 + n, r, v);
	u32 stored = v;
	if (r == R_AX_WLAN_XTAL_SI_CTRL) {
		u32 offset = u32_get_bits(v, B_AX_WL_XTAL_SI_ADDR_MASK);
		u8 data = u32_get_bits(v, B_AX_WL_XTAL_SI_DATA_MASK);
		u8 mask = u32_get_bits(v, B_AX_WL_XTAL_SI_BITMASK_MASK);
		stored = v & ~B_AX_WL_XTAL_SI_CMD_POLL;
		if (u32_get_bits(v, B_AX_WL_XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_WRITE) {
			xtal[offset] = (xtal[offset] & ~mask) | (data & mask);
			if (offset == XTAL_SI_CTRL && (mask & XTAL_SI_MODE_SEL_MASK) &&
			    !(xtal[offset] & XTAL_SI_MODE_SEL_MASK)) {
				u32 addr = xtal[XTAL_SI_LOW_ADDR] |
					   (u32)(xtal[XTAL_SI_CTRL] & XTAL_SI_HIGH_ADDR_MASK) << 8;
				xtal[XTAL_SI_READ_VAL] = dav[addr];
				dav_requests++;
				dav_wait = dav_requests <= dav_stuck ? NEVER : dav_late;
			}
		} else {
			if (offset == XTAL_SI_CTRL) {
				if (dav_wait == 0)
					xtal[offset] |= XTAL_SI_RDY;
				else if (dav_wait != NEVER)
					dav_wait--;
			}
			stored = (stored & ~B_AX_WL_XTAL_SI_DATA_MASK) |
				 FIELD_PREP(B_AX_WL_XTAL_SI_DATA_MASK, xtal[offset]);
		}
	} else if (r == R_AX_EFUSE_CTRL) {
		stored = (v & ~(B_AX_EF_DATA_MASK | B_AX_EF_RDY)) |
			 ddv[u32_get_bits(v, B_AX_EF_ADDR_MASK)];
		ddv_wait = ddv_late;
	} else if (r == R_AX_H2CREG_CTRL && (v & B_AX_H2CREG_TRIGGER)) {
		stored = 0;
		if (c2h_reply) {
			for (u32 i = 0; i < 4; i++)
				set(R_AX_C2HREG_DATA0 + 4 * i, 4, c2h_words[i]);
			set(R_AX_C2HREG_CTRL, 1, 1);
		}
	}
	set(r, n, stored);
}
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* What rtw89 hands its debug dump and the chip's phycap reader. */
static u8 captured_log[4096], captured_phycap[256];
static u32 captured_log_bytes, captured_phycap_bytes;
#define rtw89_hex_dump(d, m, p, buf, len) capture_log((d), (buf), (len))
static void capture_log(struct rtw89_dev *d, const u8 *buf, u32 len)
{
	(void)d;
	if (len > sizeof(captured_log))
		abort();
	memcpy(captured_log, buf, len);
	captured_log_bytes = len;
}

/* rtw89_mac_partial_init runs the DMAC and PCIe pre-init and the download,
 * which other oracles check; here it only counts its calls. */
static u32 partial_init_calls;
static int rtw89_mac_partial_init(struct rtw89_dev *d, bool include_bb, bool bb_preinit)
{
	(void)d;
	if (include_bb || bb_preinit)
		abort();
	partial_init_calls++;
	return 0;
}
'''
    capture = (
        'static int capture_read_phycap(struct rtw89_dev *d, u8 *map)\n{\n'
        '\tif (d->chip->phycap_size > sizeof(captured_phycap))\n\t\tabort();\n'
        '\tmemcpy(captured_phycap, map, d->chip->phycap_size);\n'
        '\tcaptured_phycap_bytes = d->chip->phycap_size;\n'
        f"\treturn {ops['read_phycap']}(d, map);\n}}\n")
    tables = (
        'static const struct rtw8852bx_info rtw8852bx_info = {\n'
        + f"\t.read_efuse = {bx['read_efuse']},\n\t.read_phycap = {bx['read_phycap']},\n"
        + '};\n')
    late_tables = (
        'static const struct rtw89_mac_gen_def mac_gen_ax = {\n'
        + ''.join(f'\t.{field} = {mac_def[field]},\n' for field in mac_fields)
        + '};\nstatic const struct rtw89_chip_ops chip_ops = {\n'
        + f"\t.read_efuse = {ops['read_efuse']},\n\t.read_phycap = capture_read_phycap,\n"
        + '};\nstatic const struct rtw89_pci_gen_def pci_gen_ax = {\n'
        + f"\t.mac_pre_deinit = {pci_gen['mac_pre_deinit']},\n"
        + '};\nstatic const struct rtw89_pci_info pci_info = { .gen_def = &pci_gen_ax };\n'
        + 'static const struct rtw89_hci_ops hci_ops = {\n'
        + f"\t.mac_pre_deinit = {hci['mac_pre_deinit']},\n"
        + '};\nstatic const struct rtw89_chip_info chip_info = {\n'
        + '\t.ops = &chip_ops,\n\t.mac_def = &mac_gen_ax,\n'
        + ''.join(f'\t.{field} = {info[field]},\n' for field in info_fields)
        + '};\n')
    main_c = r'''
static void flush(FILE *out)
{
	u32 n = segment_bytes;
	u8 length[4] = {n, n >> 8, n >> 16, n >> 24};
	if (fwrite(length, 1, 4, out) != 4 || fwrite(segment, 1, n, out) != n)
		abort();
	segment_bytes = 0;
}

/* Synthetic efuse contents. */
#define EFUSE_AT(field) offsetof(struct rtw8852bx_efuse, field)
static u8 logical[2048];
static struct rtw8852bx_efuse *board(void)
{
	memset(logical, 0xff, sizeof(logical));
	return (struct rtw8852bx_efuse *)logical;
}
/* One block per 8 logical bytes that hold anything but 0xff, each word
 * enabled where it does, from physical byte `at`; the next free byte. */
static u32 encode(u8 *map, u32 at, const u8 *log, u32 log_size)
{
	for (u32 blk = 0; blk * 8 < log_size; blk++) {
		const u8 *w = log + blk * 8;
		u8 word_en = 0xf;
		for (u32 i = 0; i < 4; i++)
			if (w[2 * i] != 0xff || w[2 * i + 1] != 0xff)
				word_en &= ~(1U << i);
		if (word_en == 0xf)
			continue;
		map[at++] = 0x30 | (blk >> 4);
		map[at++] = (u8)((blk & 0xf) << 4) | word_en;
		for (u32 i = 0; i < 4; i++)
			if (!(word_en & (1U << i))) {
				map[at++] = w[2 * i];
				map[at++] = w[2 * i + 1];
			}
	}
	return at;
}
static void sec_ctrl(void) { ddv[0] = 0x00; ddv[1] = 0x11; ddv[2] = 0x22; ddv[3] = 0x33; }
static void fill_tssi(struct rtw8852bx_efuse *e, u8 a, u8 b)
{
	for (u32 i = 0; i < TSSI_CCK_CH_GROUP_NUM; i++) {
		e->path_a_tssi.cck_tssi[i] = a + i;
		e->path_b_tssi.cck_tssi[i] = b + i;
	}
	for (u32 i = 0; i < TSSI_MCS_2G_CH_GROUP_NUM; i++) {
		e->path_a_tssi.bw40_tssi[i] = a + 0x10 + i;
		e->path_b_tssi.bw40_tssi[i] = b + 0x10 + i;
	}
	for (u32 i = 0; i < TSSI_MCS_5G_CH_GROUP_NUM; i++) {
		e->path_a_tssi.bw40_1s_tssi_5g[i] = a + 0x20 + i;
		e->path_b_tssi.bw40_1s_tssi_5g[i] = b + 0x20 + i;
	}
}
/* Programmed phycap: power calibration mark, TSSI, thermal and PA bias trims
 * (some left blank) and gain compensations. */
static void phycap_programmed(u8 power_k)
{
	ddv[0x5e9] = power_k;
	for (u32 j = 0; j < 8; j++) {
		ddv[0x5d6 - j] = 0x01 + j;
		ddv[0x5ab - j] = 0xf8 + j;
	}
	ddv[0x5df] = 0x13; ddv[0x5dc] = 0xff;
	ddv[0x5de] = 0x87; ddv[0x5db] = 0x65;
	ddv[0x5bb] = 0x01; ddv[0x5ba] = 0x0f; ddv[0x5b9] = 0xff; ddv[0x5b8] = 0x08;
	ddv[0x590] = 0x07; ddv[0x58f] = 0xff; ddv[0x58e] = 0x09; ddv[0x58d] = 0xf3;
}
static void fill_valid(void)
{
	static const u8 mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
	struct rtw8852bx_efuse *e = board();
	memcpy(e->e.mac_addr, mac, 6);
	e->rfe_type = 1;
	e->xtal_k = 0x3c;
	e->country_code[0] = 'U';
	e->country_code[1] = 'S';
	e->path_a_therm = 0x1d;
	e->path_b_therm = 0x1e;
	fill_tssi(e, 0x20, 0x40);
	e->rx_gain_2g_cck = 0x12;
	e->rx_gain_2g_ofdm = 0xf1;
	e->rx_gain_5g_low = 0x8f;
	e->rx_gain_5g_mid = 0x77;
	sec_ctrl();
	encode(ddv, 4, logical, sizeof(logical));
	phycap_programmed(0xaa);
}
static void fill_rfe5(void)
{
	static const u8 mac[6] = {0x00, 0xe0, 0x4c, 0x88, 0x52, 0x01};
	u8 dav_log[16];
	struct rtw8852bx_efuse *e = board();
	memcpy(e->e.mac_addr, mac, 6);
	e->rfe_type = 5;
	e->xtal_k = 0x2a;
	e->path_a_therm = 0x22;
	e->path_b_therm = 0x23;
	fill_tssi(e, 0x05, 0x85);
	sec_ctrl();
	encode(ddv, 4, logical, sizeof(logical));
	memset(dav_log, 0xff, sizeof(dav_log));
	dav_log[0] = 0x12; dav_log[1] = 0x34;
	dav_log[4] = 0x56; dav_log[5] = 0x78;
	dav_log[14] = 0x9a; dav_log[15] = 0xbc;
	dav[0] = 0x01; dav[1] = 0x02; dav[2] = 0x03; dav[3] = 0x04;
	encode(dav, 4, dav_log, sizeof(dav_log));
	ddv[0x5e9] = 0x00;
}
static void fill_empty(void) {}
static void fill_corrupt(void)
{
	u32 at = 4;
	sec_ctrl();
	for (u32 k = 0; k < 300; k++) {
		u8 blk = k;
		ddv[at++] = 0x30 | (blk >> 4);
		ddv[at++] = (u8)((blk & 0xf) << 4) | 0xe;
		ddv[at++] = k;
		ddv[at++] = ~k;
	}
	/* A four-word block whose last two words run past byte 1211. */
	ddv[at++] = 0x30;
	ddv[at++] = 0x00;
	while (at < 1216)
		ddv[at] = (u8)at, at++;
}
static void fill_layered(void)
{
	static const u8 phy[] = {
		0xc8, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,	/* block 0x80, words 0-2 */
		0x31, 0x2f,					/* block 0x12, no word */
		0x35, 0x9d, 0x02, 'J',				/* block 0x59, word 1 */
		0x35, 0x9b, 'P', 0x00,				/* block 0x59, word 2 */
		0x35, 0x7a, 0x7f, 0x41, 0x00, 0x00,		/* block 0x57, words 0 and 2 */
		0x38, 0x0d, 0xaa, 0xbb,				/* block 0x80, word 1 again */
		0x35, 0xaa, 0x10, 0x11, 0x7f, 0x00,		/* block 0x5a, words 0 and 2 */
	};
	static const u8 dav_phy[] = {
		0x30, 0x17, 0x01, 0x02,				/* block 1, word 3 */
		0x30, 0x0e, 0x03, 0x04,				/* block 0, word 0 */
		0x30, 0x17, 0x05, 0x06,				/* block 1, word 3 again */
	};
	sec_ctrl();
	memcpy(ddv + 4, phy, sizeof(phy));
	memcpy(dav + 4, dav_phy, sizeof(dav_phy));
	phycap_programmed(0x55);
}

struct casedef {
	u8 cut;
	int autoload;
	u32 ddv_late, dav_late, dav_stuck;
	int h2c_busy, c2h_reply;
	u32 c2h[4];
	void (*fill)(void);
};
#define PHYCAP_OK {0x02020403, 0x00000302, 0x00000000, 0x03020200}
static const struct casedef cases[] = {
	/* valid */ {CHIP_CBV, 1, 0, 0, 0, 0, 1, PHYCAP_OK, fill_valid},
	/* rfe5 */ {CHIP_CAV, 1, 0, 0, 0, 0, 1, PHYCAP_OK, fill_rfe5},
	/* empty */ {CHIP_CCV, 0, 0, 0, 0, 0, 1, PHYCAP_OK, fill_empty},
	/* corrupt */ {CHIP_CBV, 1, 0, 0, 0, 0, 1, PHYCAP_OK, fill_corrupt},
	/* layered */ {CHIP_CCV, 1, 0, 0, 0, 0, 1, PHYCAP_OK, fill_layered},
	/* slow */ {CHIP_CAV, 1, 2, 2, 0, 0, 1, PHYCAP_OK, fill_valid},
	/* dav_retry */ {CHIP_CBV, 1, 0, 0, 1, 0, 1, PHYCAP_OK, fill_rfe5},
	/* mailbox_busy */ {CHIP_CBV, 1, 0, 0, 0, 1, 1, PHYCAP_OK, fill_valid},
	/* phycap_wrong_id */ {CHIP_CBV, 1, 0, 0, 0, 0, 1,
		{0x02020401, 0x00000302, 0, 0x03020200}, fill_valid},
	/* phycap_1ss_diversity */ {CHIP_CCV, 1, 0, 0, 0, 0, 1,
		{0x02030403, 0x00000401, 0, 0x03020200}, fill_valid},
	/* phycap_antenna_b */ {CHIP_CAV, 1, 0, 0, 0, 0, 1,
		{0x02000403, 0x00000300, 0, 0x03010100}, fill_valid},
};

static void layout(void)
{
	static const u32 at[] = {
		sizeof(struct rtw8852bx_efuse),
		EFUSE_AT(path_a_tssi), EFUSE_AT(path_b_tssi), EFUSE_AT(xtal_k),
		EFUSE_AT(rfe_type), EFUSE_AT(country_code), EFUSE_AT(path_a_therm),
		EFUSE_AT(path_b_therm), EFUSE_AT(rx_gain_2g_ofdm), EFUSE_AT(rx_gain_2g_cck),
		EFUSE_AT(rx_gain_5g_low), EFUSE_AT(rx_gain_5g_mid), EFUSE_AT(rx_gain_5g_high),
		EFUSE_AT(e.mac_addr),
		offsetof(struct rtw8852bx_tssi_offset, cck_tssi),
		offsetof(struct rtw8852bx_tssi_offset, bw40_tssi),
		offsetof(struct rtw8852bx_tssi_offset, bw40_1s_tssi_5g),
		sizeof(struct rtw8852bx_tssi_offset),
	};
	for (u32 i = 0; i < ARRAY_SIZE(at); i++)
		record(20, i, at[i]);
}

static void results(const struct rtw89_dev *dev)
{
	const struct rtw89_efuse *efuse = &dev->efuse;
	const struct rtw89_tssi_info *tssi = &dev->tssi;
	const struct rtw89_power_trim_info *trim = &dev->pwr_trim;
	const struct rtw89_phy_efuse_gain *gain = &dev->efuse_gain;
	const struct rtw89_hal *hal = &dev->hal;
	record(31, efuse->valid, efuse->power_k_valid);
	record(32, efuse->addr[0] | efuse->addr[1] << 8 | efuse->addr[2] << 16 |
		   (u32)efuse->addr[3] << 24, efuse->addr[4] | efuse->addr[5] << 8);
	record(33, efuse->rfe_type, efuse->xtal_cap);
	record(34, (u8)efuse->country_code[0], (u8)efuse->country_code[1]);
	record(35, tssi->thermal[0], tssi->thermal[1]);
	for (u32 i = 0; i < 2; i++)
		for (u32 j = 0; j < TSSI_CCK_CH_GROUP_NUM; j++)
			record(36, i << 8 | j, (u8)tssi->tssi_cck[i][j]);
	for (u32 i = 0; i < 2; i++)
		for (u32 j = 0; j < TSSI_MCS_CH_GROUP_NUM; j++)
			record(37, i << 8 | j, (u8)tssi->tssi_mcs[i][j]);
	for (u32 i = 0; i < 2; i++)
		for (u32 j = 0; j < TSSI_TRIM_CH_GROUP_NUM; j++)
			record(38, i << 8 | j, (u8)tssi->tssi_trim[i][j]);
	record(39, trim->pg_thermal_trim | trim->pg_pa_bias_trim << 1,
	       trim->thermal_trim[0] | trim->thermal_trim[1] << 8 |
	       trim->pa_bias_trim[0] << 16 | (u32)trim->pa_bias_trim[1] << 24);
	record(40, gain->offset_valid | gain->comp_valid << 1, 0);
	for (u32 p = 0; p < 2; p++)
		for (u32 i = 0; i <= RTW89_GAIN_OFFSET_5G_HIGH; i++)
			record(41, p << 8 | i, (u8)gain->offset[p][i]);
	for (u32 p = 0; p < 2; p++)
		for (u32 i = 0; i < RTW89_SUBBAND_2GHZ_5GHZ_NR; i++)
			record(42, p << 8 | i, (u8)gain->comp[p][i]);
	record(43, hal->tx_nss | hal->rx_nss << 8 | (hal->antenna_tx & 0xff) << 16 |
		   (hal->antenna_rx & 0xff) << 24,
	       hal->tx_path_diversity | hal->ant_diversity << 1 | hal->no_eht << 2 |
	       hal->support_cckpd << 3 | hal->support_igi << 4 | hal->thermal_prot_th << 8);
	record(44, dev->fw.h2c_counter, dev->fw.c2h_counter);
}

int main(int argc, char **argv)
{
	static struct rtw89_dev dev;
	static const struct rtw89_chip_variant variant = {0};
	unsigned count = 0;
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	layout();
	flush(out);
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		const struct casedef *k = &cases[c];
		for (size_t i = 0; i < sizeof(memory); i++)
			memory[i] = i * 37 + 11;
		if (k->autoload)
			memory[R_AX_SYS_WL_EFUSE_CTRL] |= B_AX_AUTOLOAD_SUS;
		else
			memory[R_AX_SYS_WL_EFUSE_CTRL] &= ~B_AX_AUTOLOAD_SUS;
		memory[R_AX_H2CREG_CTRL] = k->h2c_busy ? 1 : 0;
		memory[R_AX_C2HREG_CTRL] = 0;
		memset(xtal, 0, sizeof(xtal));
		memset(ddv, 0xff, sizeof(ddv));
		memset(dav, 0xff, sizeof(dav));
		k->fill();
		ddv_late = k->ddv_late;
		ddv_wait = 0;
		dav_late = k->dav_late;
		dav_wait = 0;
		dav_stuck = k->dav_stuck;
		dav_requests = 0;
		c2h_reply = k->c2h_reply;
		memcpy(c2h_words, k->c2h, sizeof(c2h_words));
		captured_log_bytes = 0;
		captured_phycap_bytes = 0;
		partial_init_calls = 0;

		word(k->cut); word(k->autoload); word(k->ddv_late); word(k->dav_late);
		word(k->dav_stuck); word(k->h2c_busy); word(k->c2h_reply);
		for (u32 i = 0; i < 4; i++)
			word(k->c2h[i]);
		for (u32 i = 0; i < sizeof(ddv); i++)
			byte_out(ddv[i]);
		for (u32 i = 0; i < sizeof(dav); i++)
			byte_out(dav[i]);
		flush(out);

		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip_info;
		dev.variant = &variant;
		dev.pci_info = &pci_info;
		dev.hci.type = RTW89_HCI_TYPE_PCIE;
		dev.hci.ops = &hci_ops;
		dev.hal.cv = k->cut;
		int ret = rtw89_chip_efuse_info_setup(&dev);
		flush(out);

		record(30, partial_init_calls, (u32)ret);
		if (!ret)
			results(&dev);
		flush(out);
		if (!ret)
			for (u32 i = 0; i < captured_log_bytes; i++)
				byte_out(captured_log[i]);
		flush(out);
		if (!ret)
			for (u32 i = 0; i < captured_phycap_bytes; i++)
				byte_out(captured_phycap[i]);
		flush(out);
		count++;
	}
	if (fclose(out))
		abort();
	printf("%u\n", count);
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, core_defines, declarations, harness,
        helpers, xtal_inlines, xtal_si, efuse, mailbox, phycap,
        chip, tables, chip_wrappers, capture, pci, pci_inline,
        core, regs, late_tables, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    str(generated), '-o', str(exe)], check=True)
    trace = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    cases = int(run.stdout.strip())
    if cases != len(CASES):
        raise ValueError(f'{cases} cases ran, {len(CASES)} are named')
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=CASES,
        dispatch=dict(rtw89_mac_gen_ax=mac_def, rtw8852b_chip_ops=ops, rtw8852bx_info=bx,
                      rtw89_pci_gen_ax=pci_gen, rtw89_pci_ops=hci, rtw8852b_chip_info=info),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays, the efuse and the firmware answers are a model; no physical evidence',
            'read_poll_timeout is modeled counted in steps, not by Linux timekeeping',
            'a DDV byte that never reads ready (a million polls per attempt) and a C2H that '
            'never comes are tested in Rust only',
            'DAV maps rtw89 would read or write past (undefined in C) are tested in Rust only',
            'rtw89_mac_partial_init is a stub: the download before the read is the fwdl oracle',
            'PCIe only: USB branches run with hci.type PCIE and are not exercised',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['trace_bytes', 'trace_sha256']} | {'cases': cases}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
