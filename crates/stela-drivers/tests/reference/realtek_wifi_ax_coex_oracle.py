#!/usr/bin/env python3
"""Unchanged pinned rtw89 WL-only coex init for a PCIe RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. The program runs, for each case, rtw89's
BTC bring-up as rtw89_core_start would with firmware 0.29.29.18 and
BTC_MODE_WL: rtw89_btc_init (rtw89_core_init's reset of every BTC variable),
rtw89_coex_recognize_ver (which picks the rtw89_btc_ver entry by firmware
version), rtw89_btc_ntfy_poweron, then rtw89_btc_ntfy_init(rtwdev,
BTC_MODE_WL), with every callee it reaches unchanged:
rtw8852b_btc_set_rfe, __rtw8852bx_btc_init_cfg (rtw89_mac_coex_init with the
LTE indirect access, __rtw8852bx_btc_set_wl_pri, the RF writes through
rtw89_phy_write_rf_v1, rtw8852bx_set_trx_mask), _write_scbd,
rtw89_mac_get_ctrl_path, _set_init_info, _fw_set_drv_info with
rtw89_fw_h2c_cxdrv_init and rtw89_fw_h2c_cxdrv_ctrl, rtw89_btc_fw_set_slots,
btc_fw_set_monreg, _set_ext_interface, _set_wl_tx_power with
rtw8852b_btc_set_wl_txpwr_ctrl (compiled, but the RTW89_PHY_0 rtw89 passes
as its PHY map is 0, so it returns at once), and _send_fw_cmd with
rtw89_fw_h2c_raw_with_hdr. The core.h BTC declarations from struct
rtw89_mac_ax_gnt through struct rtw89_btc, coex.h's from BTC_H2C_MAXLEN
through enum btc_mlo_rf_combin, and coex.c's from RTW89_COEX_VERSION through
BTC_B1_MAX (rtw89_btc_ver_defs, t_def, s_def and cxtbl among them) are
extracted as spans; each extraction is listed with its SHA-256 in
manifest.json.

The one changed piece is the seam: _run_coex is the harness's, reduced to
what a WL-only init runs of it: dm.run_reason and _update_dm_step as
_run_coex sets them, the unchanged _set_coex_binding (which decides the
TDMA binding), the unchanged _action_wl_only (_set_ant(BTC_ANT_WONLY) with
_set_gnt, rtw89_mac_cfg_gnt, rtw89_mac_cfg_ctrl_path and _set_bt_plut with
rtw89_mac_cfg_plt_ax; _set_policy(BTC_CXP_OFF_BT) with
rtw89_btc_set_policy_v1, _set_tdma_bind, _fw_set_policy, _append_tdma and
_append_slot), then _action_common's scoreboard write, _sned_h2c_w2bscbd
for each BT. Its _update_run_ctrl_info, _update_bt_scbd, state map and
freerun check, and _action_common's other steps are not run.

The model: MAC and BB space as bytes (0x20000), behaving per aligned word.
R_AX_LTE_CTRL reads bit 29 (the LTE ready bit) set unless the case keeps it
clear, and a write of 0xC00F0000 | offset stores R_AX_LTE_WDATA in the LTE
space at offset, one of 0x800F0000 | offset puts it in R_AX_LTE_RDATA; the
LTE space is 0x100 bytes of its own. BB R_SWSI_V1 reads its busy bits
clear. CMAC_FUNC_EN holds B_AX_CMAC_EN, or reads RTW89_R32_DEAD, as the case
says. rtw89_h2c_tx records the skb's length and the sequence after it (40)
and its bytes as little-endian words (41), then takes it or refuses it with
-ENOSPC.

Seven cases, each one segment prefixed by its byte length: rfe 1 and cut B
(the user's card) over zeroed memory, over patterned memory, rfe 2 and cut C
(three antennas, dedicated) over all-ones memory, rfe 0 and cut A over
zeroed memory, rfe 1 with the LTE never ready, rfe 1 with CMAC_FUNC_EN dead,
and rfe 1 over patterned memory with every H2C refused, starting at
sequence 0xfe. A segment is records of three little-endian u32 (tag,
register, value): reads are tagged by width, writes by 4 plus width, delays
9; then the state the init left: rtw89_btc_module (50, 51), the error map's
pta_owner bit, wl.scbd[0] (52), ant_type and btg_pos (53), the LTE space's
words at 0x38 and 0x3c (54), the H2C counters (55) and h2c_seq (24).
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'


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
            return m.start(), record(file, name, text[start:closing(text, end)])
        raise ValueError(f'{file}: no definition of {name}')

    def functions(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        return '\n\n'.join(body for _, body in sorted(locate(file, name) for name in names))

    def declaration(file, kind, name):
        """An enum, struct or union declaration, through its semicolon."""
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

    def span(file, first, last):
        """Everything from the line starting `first` through the declaration `last`."""
        text = source(file)
        m = re.search(r'^' + re.escape(first), text, re.M)
        n = re.search(r'^' + re.escape(last) + r' \{', text, re.M)
        if not m or not n or n.start() < m.start():
            raise ValueError(f'{file}: no span {first} .. {last}')
        end = text.index(';', closing(text, text.index('{', n.start()))) + 1
        return record(file, f'{first} .. {last}', text[m.start():end])

    def lines(file, first, last):
        """The lines from the one starting `first` through the first one after
        it starting `last`."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n', text.index('\n' + last, start) + 1)
        return record(file, f'{first} .. {last}', text[start:end])

    def fields(file, head, names):
        """Members of a designated initializer by name, each value scanned to
        the comma that ends it at its own depth; the initializer is recorded."""
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

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    core_defines = defines('core.h', ['MASKBYTE0', 'MASKBYTE1', 'MASKBYTE2', 'MASKBYTE3',
                                      'MASKDWORD', 'RFREG_MASK', 'RTW89_R32_EA',
                                      'RTW89_R32_DEAD'])
    phy_defines = defines('phy.h', ['RTW89_RF_ADDR_ADSEL_MASK'])
    mac_defines = defines('mac.h', [
        'RTW89_MAC_AX_COEX_RTK_MODE', 'RTW89_MAC_AX_COEX_CSR_MODE',
        'RTW89_MAC_AX_COEX_INNER', 'RTW89_MAC_AX_COEX_OUTPUT', 'RTW89_MAC_AX_COEX_INPUT',
        'RTW89_MAC_AX_PLT_LTE_RX', 'RTW89_MAC_AX_PLT_GNT_BT_TX',
        'RTW89_MAC_AX_PLT_GNT_BT_RX', 'RTW89_MAC_AX_PLT_GNT_WL',
        'RTW89_MAC_AX_BAND_REG_OFFSET'])
    fw_defines = defines('fw.h', [
        'H2C_HEADER_LEN', 'H2C_HDR_CAT', 'H2C_HDR_CLASS', 'H2C_HDR_FUNC', 'H2C_HDR_DEL_TYPE',
        'H2C_HDR_H2C_SEQ', 'H2C_HDR_TOTAL_LEN', 'H2C_HDR_REC_ACK', 'H2C_HDR_DONE_ACK',
        'FWCMD_TYPE_H2C', 'H2C_CAT_OUTSRC', 'BT_H2C_FUNC_BT2ND',
        'RTW89_H2C_CXINIT_ANT_INFO_POS', 'RTW89_H2C_CXINIT_ANT_INFO_DIVERSITY',
        'RTW89_H2C_CXINIT_ANT_INFO_BTG_POS', 'RTW89_H2C_CXINIT_ANT_INFO_STREAM_CNT',
        'RTW89_H2C_CXINIT_MOD_INFO_BT_SOLO', 'RTW89_H2C_CXINIT_MOD_INFO_BT_POS',
        'RTW89_H2C_CXINIT_MOD_INFO_SW_TYPE', 'RTW89_H2C_CXINIT_MOD_INFO_WA_TYPE',
        'RTW89_H2C_CXINIT_INFO_WL_ONLY', 'RTW89_H2C_CXINIT_INFO_WL_INITOK',
        'RTW89_H2C_CXINIT_INFO_DBCC_EN', 'RTW89_H2C_CXINIT_INFO_CX_OTHER',
        'RTW89_H2C_CXINIT_INFO_BT_ONLY', 'H2C_LEN_CXDRVHDR'])
    fw_c_defines = defines('fw.c', ['H2C_LEN_CXDRVINFO_CTRL'])
    coex_defines = defines('coex.c', [
        'BTC_DEFAULT_SIR_THRES', 'BTC_FDDR_TP_SETUP_TIME', 'BTC_FDDR_TP_HOLD_TIME',
        'BTC_FDDR_RX_LOW_RATE_THRES', 'BTC_TLV_HDR_LEN', 'BTC_TLV_HDR_LEN_V7',
        'WL_TX_POWER_NO_BTC_CTRL', 'WL_TX_POWER_ALL_TIME', 'WL_TX_POWER_WITH_BT',
        'WL_TX_POWER_INT_PART', 'WL_TX_POWER_FRA_PART', 'B_BTC_WL_TX_POWER_SIGN',
        'B_TSSI_WL_TX_POWER_SIGN', '_bind_is_btonly', 'BTC_PLATFORM_LITTLE_ENDIAN',
        '_tdma_set_flctrl', '_tdma_set_flctrl_role', '_tdma_set_rxflctrl',
        '_tdma_set_txflctrl', '_tdma_set_lek'])
    declarations = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_core_chip_id', 'rtw89_chip_gen', 'rtw89_cv', 'rtw89_band',
            'rtw89_wifi_role', 'rtw89_port', 'rtw89_bandwidth', 'rtw89_sc_offset',
            'rtw89_rf_path', 'rtw89_qta_mode', 'rtw89_mac_idx', 'rtw89_phy_idx',
            'rtw89_fbtc_bt_index', 'rtw89_flags', 'rtw89_fw_type']]
        + [declaration('mac.h', 'enum', 'rtw89_mac_hwmod_sel'),
           declaration('chan.h', 'enum', 'rtw89_mr_wtype'),
           declaration('core.h', 'struct', 'rtw89_txwd_body'),
           span('core.h', 'struct rtw89_mac_ax_gnt {', 'struct rtw89_btc'),
           span('coex.h', '#define BTC_H2C_MAXLEN', 'enum btc_mlo_rf_combin'),
           declaration('mac.h', 'struct', 'rtw89_mac_ax_coex'),
           declaration('mac.h', 'struct', 'rtw89_mac_ax_plt'),
           declaration('fw.h', 'struct', 'fwcmd_hdr'),
           declaration('fw.h', 'enum', 'rtw89_btc_btf_h2c_class'),
           declaration('fw.h', 'enum', 'rtw89_btc_btf_set'),
           declaration('fw.h', 'enum', 'rtw89_btc_cxdrvinfo'),
           declaration('fw.h', 'enum', 'rtw89_fbtc_gpio_type'),
           declaration('fw.h', 'struct', 'rtw89_h2c_cxhdr'),
           declaration('fw.h', 'struct', 'rtw89_h2c_cxinit'),
           declaration('rtw8852b.c', 'union', 'rtw8852b_btc_wl_txpwr_ctrl')])
    fw_inlines = '\n\n'.join(locate('fw.h', name)[1] for name in [
        'RTW89_SET_FWCMD_CXHDR_TYPE', 'RTW89_SET_FWCMD_CXHDR_LEN',
        'RTW89_SET_FWCMD_CXCTRL_MANUAL', 'RTW89_SET_FWCMD_CXCTRL_IGNORE_BT',
        'RTW89_SET_FWCMD_CXCTRL_ALWAYS_FREERUN', 'RTW89_SET_FWCMD_CXCTRL_TRACE_STEP'])
    helpers = '\n\n'.join(
        [locate('core.h', name)[1] for name in [
            'rtw89_write8_set', 'rtw89_write8_clr', 'rtw89_write32_set', 'rtw89_write32_clr',
            'rtw89_read32_mask', 'rtw89_read8_mask', 'rtw89_write32_mask',
            'rtw89_raw_write_rf', 'rtw89_write_rf', 'rtw89_is_rtl885xb',
            'rtw89_chip_mac_cfg_gnt', 'rtw89_chip_cfg_ctrl_path']]
        + [locate('phy.h', name)[1] for name in [
            'rtw89_phy_write32_mask', 'rtw89_phy_read32_mask']]
        + [locate('mac.h', name)[1] for name in [
            'rtw89_mac_check_mac_en', 'rtw89_mac_reg_by_idx', 'rtw89_mac_txpwr_write32_mask']]
        + [locate('coex.h', name)[1] for name in [
            'rtw89_get_antpath_type', '_slot_set_le', '_slot_set', '_slot_set_dur',
            '_slot_set_type', '_slot_set_tbl', 'btc_dw2b']]
        + [locate('rtw8852b_common.h', name)[1] for name in [
            'rtw8852bx_btc_init_cfg', 'rtw8852bx_btc_set_wl_pri']])
    coex_head = record('coex.c', 'RTW89_COEX_VERSION .. BTC_B1_MAX', lines(
        'coex.c', '#define RTW89_COEX_VERSION', '#define BTC_B1_MAX'))
    coex = functions('coex.c', [
        '_reset_h2c_macro', '_send_fw_cmd', '_reset_btc_var', '_append_tdma',
        '_append_slot_v1', '_append_slot_v7', '_append_slot', 'rtw89_btc_fw_set_slots',
        'btc_fw_set_monreg', '_update_dm_step', '_fw_set_policy', '_set_ext_interface',
        '_fw_set_drv_info', '_set_gnt', '_set_wl_tx_power', '_set_policy', '_set_tdma_bind',
        'rtw89_btc_set_policy_v1', '_set_bt_plut', '_set_ant', '_action_wl_only',
        '_sned_h2c_w2bscbd', '_write_scbd', '_set_bind_info', '_set_coex_binding',
        'rtw89_btc_init', 'rtw89_btc_ntfy_poweron', '_set_init_info', 'rtw89_btc_ntfy_init',
        'rtw89_coex_recognize_ver'])
    mac = functions('mac.c', [
        'rtw89_mac_write_lte', 'rtw89_mac_read_lte', 'rtw89_mac_check_mac_en_ax',
        'rtw89_mac_get_txpwr_cr_ax', 'rtw89_mac_coex_init', 'rtw89_mac_cfg_gnt',
        'rtw89_mac_cfg_plt_ax', 'rtw89_mac_cfg_sb', 'rtw89_mac_cfg_ctrl_path',
        'rtw89_mac_get_ctrl_path'])
    mac_h = locate('mac.h', 'rtw89_mac_cfg_plt')[1]
    phy = functions('phy.c', [
        'rtw89_phy_write_rf', 'rtw89_phy_check_swsi_busy', 'rtw89_phy_write_rf_a',
        'rtw89_phy_write_rf_v1'])
    fw = functions('fw.c', [
        'rtw89_h2c_pkt_set_hdr', 'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr',
        'rtw89_fw_h2c_cxdrv_init', 'rtw89_fw_h2c_cxdrv_ctrl', 'rtw89_fw_h2c_raw_with_hdr'])
    ps = locate('ps.c', 'rtw89_set_coex_ctrl_lps')[1]
    common = functions('rtw8852b_common.c', [
        'rtw8852bx_set_trx_mask', '__rtw8852bx_btc_init_cfg', '__rtw8852bx_btc_set_wl_pri'])
    chip = '\n\n'.join(
        [definition('rtw8852b.c', 'static const struct rtw89_btc_fbtc_mreg '
                    'rtw89_btc_8852b_mon_reg[]')]
        + [locate('rtw8852b.c', name)[1] for name in [
            'rtw8852b_btc_set_rfe', 'rtw8852b_btc_set_wl_txpwr_ctrl']])

    info_fields = ['chip_id', 'chip_gen', 'rf_base_addr', 'rf_path_num', 'h2c_desc_size',
                   'para_ver', 'scbd', 'mailbox', 'afh_guard_ch', 'mon_reg_num', 'mon_reg',
                   'btc_sb']
    info = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  info_fields + ['mac_def', 'phy_def', 'ops'])
    if (info['mac_def'], info['phy_def'], info['ops']) != (
            '&rtw89_mac_gen_ax', '&rtw89_phy_gen_ax', '&rtw8852b_chip_ops'):
        raise ValueError(f'rtw8852b_chip_info dispatch is {info}')
    ops_fields = ['write_rf', 'cfg_ctrl_path', 'mac_cfg_gnt', 'btc_set_rfe', 'btc_init_cfg',
                  'btc_set_wl_pri', 'btc_set_wl_txpwr_ctrl', 'btc_set_policy']
    chip_ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                      ops_fields)
    bx_fields = ['btc_init_cfg', 'btc_set_wl_pri']
    bx = fields('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info', bx_fields)
    mac_fields = ['band1_offset', 'check_mac_en', 'cfg_plt', 'get_txpwr_cr']
    mac_def = fields('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax', mac_fields)
    phy_def = fields('phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax', ['cr_base'])
    raw_io = fields('fw.c', 'static const struct rtw89_io_ops rtw89_raw_io', ['write_rf'])
    if raw_io != {'write_rf': 'rtw89_raw_write_rf'}:
        raise ValueError(f'rtw89_raw_io is {raw_io}')
    core = source('core.c')
    for line in ['\trtw89_btc_ntfy_poweron(rtwdev);\n',
                 '\trtw89_btc_ntfy_init(rtwdev, BTC_MODE_NORMAL);\n',
                 '\trtw89_btc_init(rtwdev);\n',
                 '\trtwdev->mac.qta_mode = RTW89_QTA_SCC;\n']:
        if line not in core:
            raise ValueError(f'core.c no longer has {line.strip()}')

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
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t __le64;
typedef uint8_t __u8;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define __counted_by(m)
#define BIT(n) (1U << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define GENMASK_ULL(h, l) ((~0ULL >> (63 - (h))) & (~0ULL << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define U8_MAX 0xff
#define U16_MAX 0xffff
#define U32_MAX 0xffffffffU
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_PREP_CONST(m, v) FIELD_PREP(m, v)
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u8_encode_bits(v, m) ((u8)FIELD_PREP(m, v))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) FIELD_GET(m, v)
#define u8p_replace_bits(p, v, m) (*(p) = (u8)((*(p) & ~(u32)(m)) | FIELD_PREP(m, v)))
/* The kernel stores through the unaligned pointer, as x86 allows. */
#define le32p_replace_bits(p, v, m) ({ void *__p = (p); u32 __x; memcpy(&__x, __p, 4); \
	__x = (__x & ~(u32)(m)) | FIELD_PREP(m, v); memcpy(__p, &__x, 4); })
#define cpu_to_le16(v) ((__le16)(v))
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define BUILD_BUG_ON(c) _Static_assert(!(c), #c)
#define EXPORT_SYMBOL(...)
#define WARN(c, ...) ((void)(c))
#define ETH_ALEN 6
#define lockdep_assert_wiphy(w) ((void)0)
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define flex_array_size(p, member, n) (sizeof((p)->member[0]) * (n))
#define clamp_t(t, v, lo, hi) ((t)(v) < (t)(lo) ? (t)(lo) : (t)(v) > (t)(hi) ? (t)(hi) : (t)(v))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define DECLARE_EWMA(name, p, w) struct ewma_##name { unsigned long internal; };
#define GFP_KERNEL 0
static void *kmalloc(size_t n, int flags) { (void)flags; void *p = malloc(n); if (!p) abort(); return p; }
static void kfree(void *p) { free(p); }
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound. The atomic form is the same here. */
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
#define test_bit(nr, addr) ((int)(((addr)[(nr) / 64] >> ((nr) % 64)) & 1))
struct wiphy;
struct wiphy_work { void (*func)(struct wiphy *, struct wiphy_work *); };
struct rtw89_dev;
struct rtw89_vif_link;
struct rtw89_sta_link;
struct sk_buff { u8 *head, *data; u32 len, size; };
'''
    harness = r'''
struct rtw89_reg_def { u32 addr; u32 mask; };
struct rtw89_sb_regs { struct { u32 cfg; u32 get; } n[2]; };
struct rtw89_mac_gen_def {
	u32 band1_offset;
	int (*check_mac_en)(struct rtw89_dev *rtwdev, u8 band, enum rtw89_mac_hwmod_sel sel);
	int (*cfg_plt)(struct rtw89_dev *rtwdev, struct rtw89_mac_ax_plt *plt);
	bool (*get_txpwr_cr)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx,
			     u32 reg_base, u32 *cr);
};
struct rtw89_phy_gen_def { u32 cr_base; };
struct rtw89_chip_ops {
	bool (*write_rf)(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			 u32 mask, u32 data);
	int (*cfg_ctrl_path)(struct rtw89_dev *rtwdev, bool wl);
	int (*mac_cfg_gnt)(struct rtw89_dev *rtwdev, const struct rtw89_mac_ax_coex_gnt *gnt_cfg);
	void (*btc_set_rfe)(struct rtw89_dev *rtwdev);
	void (*btc_init_cfg)(struct rtw89_dev *rtwdev);
	void (*btc_set_wl_pri)(struct rtw89_dev *rtwdev, u8 map, bool state);
	void (*btc_set_wl_txpwr_ctrl)(struct rtw89_dev *rtwdev, u32 txpwr_val);
	void (*btc_set_policy)(struct rtw89_dev *rtwdev, u16 policy_type);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_mac_gen_def *mac_def;
	const struct rtw89_phy_gen_def *phy_def;
	const struct rtw89_chip_ops *ops;
	u32 rf_base_addr[2];
	u8 rf_path_num;
	u32 h2c_desc_size;
	u8 para_ver;
	u8 scbd;
	u8 mailbox;
	u8 afh_guard_ch;
	u8 mon_reg_num;
	const struct rtw89_btc_fbtc_mreg *mon_reg;
	struct rtw89_sb_regs btc_sb;
};
struct rtw89_io_ops {
	void (*write_rf)(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			 u32 mask, u32 data);
};
struct rtw8852bx_info {
	void (*btc_init_cfg)(struct rtw89_dev *rtwdev);
	void (*btc_set_wl_pri)(struct rtw89_dev *rtwdev, u8 map, bool state);
};
extern const struct rtw8852bx_info rtw8852bx_info;
struct rtw89_fw_suit { u8 major_ver, minor_ver, sub_ver, sub_idex; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_io_ops *io;
	struct { enum rtw89_qta_mode qta_mode; } mac;
	struct { u8 cv; } hal;
	struct { u8 rfe_type; } efuse;
	struct { u8 h2c_seq; struct rtw89_fw_suit normal; } fw;
	struct rtw89_btc btc;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
	bool dbcc_en;
	u16 custid;
	struct { struct wiphy *wiphy; } *hw;
};

/* The register model: MAC and BB space as bytes, behaving per aligned word,
 * and the LTE space behind R_AX_LTE_CTRL. */
static u8 memory[0x20000];
static u8 lte[0x100];
static int lte_stuck, cmac_dead, h2c_refuse;
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
static void record(u32 tag, u32 r, u32 v) { word(tag); word(r); word(v); }
static void model_delay(u64 us) { if (us > UINT32_MAX) abort(); record(9, 0, (u32)us); }
static u32 get(const u8 *m, u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)m[r + i] << (8 * i); return v; }
static void set(u8 *m, u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) m[r + i] = v >> (8 * i); }
static void check(u32 r, u32 n)
{
	if (r + n > sizeof(memory) || r % n)
		abort();
}
static u32 view(u32 w)
{
	u32 v = get(memory, w, 4);
	switch (w) {
	case R_AX_LTE_CTRL:
		return lte_stuck ? v & ~BIT(29) : v | BIT(29);
	case R_AX_CMAC_FUNC_EN:
		return cmac_dead ? RTW89_R32_DEAD : v;
	case 0x10000 + R_SWSI_V1:
		return v & ~(B_SWSI_W_BUSY_V1 | B_SWSI_R_BUSY_V1);
	}
	return v;
}
static u32 model_read(u32 r, u32 n)
{
	check(r, n);
	u32 v = view(r & ~3u) >> ((r & 3) * 8);
	if (n < 4)
		v &= (1u << (8 * n)) - 1;
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	check(r, n);
	record(4 + n, r, v);
	set(memory, r, n, v);
	if (r == R_AX_LTE_CTRL && n == 4) {
		u32 offset = v & 0xffff;
		if (offset + 4 > sizeof(lte) || offset % 4)
			abort();
		if ((v & 0xffff0000) == 0xC00F0000)
			set(lte, offset, 4, get(memory, R_AX_LTE_WDATA, 4));
		else if ((v & 0xffff0000) == 0x800F0000)
			set(memory, R_AX_LTE_RDATA, 4, get(lte, offset, 4));
		else
			abort();
	}
}
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

static struct sk_buff *dev_alloc_skb(unsigned int length)
{
	struct sk_buff *s = calloc(1, sizeof(*s));
	if (!s)
		abort();
	s->head = malloc(length ? length : 1);
	if (!s->head)
		abort();
	memset(s->head, 0x5a, length);
	s->data = s->head;
	s->size = length;
	return s;
}
static void dev_kfree_skb_any(struct sk_buff *s) { free(s->head); free(s); }
static u32 skb_tailroom(const struct sk_buff *s) { return s->size - (u32)(s->data - s->head) - s->len; }
static void skb_reserve(struct sk_buff *s, unsigned int n)
{
	if (n > skb_tailroom(s))
		abort();
	s->data += n;
}
static void *skb_push(struct sk_buff *s, unsigned int n)
{
	if ((size_t)(s->data - s->head) < n)
		abort();
	s->data -= n;
	s->len += n;
	return s->data;
}
static void *skb_put(struct sk_buff *s, unsigned int n)
{
	if (n > skb_tailroom(s))
		abort();
	void *p = s->data + s->len;
	s->len += n;
	return p;
}
static void skb_put_data(struct sk_buff *s, const void *p, unsigned int n)
{
	memcpy(skb_put(s, n), p, n);
}

static u32 h2c_sent, h2c_failed;
/* rtw89_h2c_tx, the boundary to the PCIe rings the H2C oracle covers. */
static int rtw89_h2c_tx(struct rtw89_dev *d, struct sk_buff *skb, bool fwdl)
{
	record(40, skb->len, d->fw.h2c_seq | (u32)fwdl << 8);
	for (u32 k = 0; k < (skb->len + 3) / 4; k++) {
		u32 v = 0;
		for (u32 b = 0; b < 4 && 4 * k + b < skb->len; b++)
			v |= (u32)skb->data[4 * k + b] << (8 * b);
		record(41, k, v);
	}
	if (h2c_refuse) {
		h2c_failed++;
		return -ENOSPC;
	}
	h2c_sent++;
	dev_kfree_skb_any(skb);
	return 0;
}

/* Callees outside this slice: none is reached on this path, so each aborts. */
static void rtw89_leave_lps(struct rtw89_dev *d) { (void)d; abort(); }
#define UNREACHED(name) static int name(struct rtw89_dev *d, u8 t) { (void)d; (void)t; abort(); }
UNREACHED(rtw89_fw_h2c_cxdrv_init_v7)
UNREACHED(rtw89_fw_h2c_cxdrv_init_v10)
UNREACHED(rtw89_fw_h2c_cxdrv_init_v11)
UNREACHED(rtw89_fw_h2c_cxdrv_role)
UNREACHED(rtw89_fw_h2c_cxdrv_role_v1)
UNREACHED(rtw89_fw_h2c_cxdrv_role_v101)
UNREACHED(rtw89_fw_h2c_cxdrv_role_v2)
UNREACHED(rtw89_fw_h2c_cxdrv_role_v7)
UNREACHED(rtw89_fw_h2c_cxdrv_role_v8)
UNREACHED(rtw89_fw_h2c_cxdrv_role_v10)
UNREACHED(rtw89_fw_h2c_cxdrv_ctrl_v7)
UNREACHED(rtw89_fw_h2c_cxdrv_ctrl_v9)
UNREACHED(rtw89_fw_h2c_cxdrv_trx_v7)
UNREACHED(rtw89_fw_h2c_cxdrv_trx_v9)
UNREACHED(rtw89_fw_h2c_cxdrv_trx_v107)
UNREACHED(rtw89_fw_h2c_cxdrv_rfk)
UNREACHED(rtw89_fw_h2c_cxtxpwr_v7)
UNREACHED(rtw89_fw_h2c_cxtxpwr_v9)
UNREACHED(rtw89_fw_h2c_cxdrv_mlo_v2)
UNREACHED(rtw89_fw_h2c_cxdrv_osi_info)
UNREACHED(rtw89_fw_h2c_cxdrv_osi_info_v6)
static void _fw_set_gpio(struct rtw89_dev *d, u8 type, u32 val) { (void)d; (void)type; (void)val; abort(); }
static const struct rtw89_fw_suit *rtw89_fw_suit_get(struct rtw89_dev *d, enum rtw89_fw_type type)
{
	if (type != RTW89_FW_NORMAL)
		abort();
	return &d->fw.normal;
}
#define RTW89_FW_VER_CODE(major, minor, sub, idx) \
	(((major) << 24) | ((minor) << 16) | ((sub) << 8) | (idx))
#define RTW89_FW_SUIT_VER_CODE(s) \
	RTW89_FW_VER_CODE((s)->major_ver, (s)->minor_ver, (s)->sub_ver, (s)->sub_idex)
'''
    # coex.c's own forward declarations, then id_to_h2c, a name for debug
    # prints alone.
    forwards = lines('coex.c', 'static void _run_coex(struct rtw89_dev *rtwdev,',
                     'static const char *id_to_h2c(u32 id);') + r'''
static const char *id_to_h2c(u32 id) { (void)id; return ""; }
'''
    seam = r'''
/* The seam: _run_coex reduced to what a WL-only init runs of it. */
static void _run_coex(struct rtw89_dev *rtwdev, enum btc_reason_and_action reason)
{
	struct rtw89_btc *btc = &rtwdev->btc;
	struct rtw89_btc_dm *dm = &rtwdev->btc.dm;
	u8 i;

	dm->run_reason = reason;
	_update_dm_step(rtwdev, reason);
	if (!dm->wl_only || btc->manual_ctrl || !btc->cx.wl.status.map.init_ok)
		abort();
	_set_coex_binding(btc);
	_action_wl_only(rtwdev);
	for (i = BTC_BT_1ST; i <= BTC_BT_2ND; i++)
		_sned_h2c_w2bscbd(rtwdev, false, i);
}
'''
    tables = (
        'static const struct rtw89_mac_gen_def mac_gen_ax = {\n'
        + ''.join(f'\t.{name} = {mac_def[name]},\n' for name in mac_fields)
        + '};\nstatic const struct rtw89_phy_gen_def phy_gen_ax = {\n'
        + f'\t.cr_base = {phy_def["cr_base"]},\n'
        + '};\nstatic const struct rtw89_chip_ops chip_ops = {\n'
        + ''.join(f'\t.{name} = {chip_ops[name]},\n' for name in ops_fields)
        + '};\nstatic const struct rtw89_chip_info chip_info = {\n'
        + '\t.mac_def = &mac_gen_ax,\n\t.phy_def = &phy_gen_ax,\n\t.ops = &chip_ops,\n'
        + ''.join(f'\t.{name} = {info[name]},\n' for name in info_fields)
        + '};\nstatic const struct rtw89_io_ops raw_io = {\n'
        + f'\t.write_rf = {raw_io["write_rf"]},\n'
        + '};\n')
    bx_table = ('const struct rtw8852bx_info rtw8852bx_info = {\n'
                + ''.join(f'\t.{name} = {bx[name]},\n' for name in bx_fields) + '};\n')
    main_c = r'''
static void flush(FILE *out)
{
	u32 n = segment_bytes;
	u8 length[4] = {n, n >> 8, n >> 16, n >> 24};
	if (fwrite(length, 1, 4, out) != 4 || fwrite(segment, 1, n, out) != n)
		abort();
	segment_bytes = 0;
}
enum fill { PATTERN, ONES, ZEROS };
int main(int argc, char **argv)
{
	static const struct {
		enum fill fill;
		u8 rfe, cv;
		int lte_stuck, cmac_dead, h2c_refuse;
		u8 seq;
	} cases[] = {
		{ZEROS, 1, 1, 0, 0, 0, 0},
		{PATTERN, 1, 1, 0, 0, 0, 0},
		{ONES, 2, 2, 0, 0, 0, 0},
		{ZEROS, 0, 0, 0, 0, 0, 0},
		{ZEROS, 1, 1, 1, 0, 0, 0},
		{ZEROS, 1, 1, 0, 1, 0, 0},
		{PATTERN, 1, 1, 0, 0, 1, 0xfe},
	};
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		static struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		for (size_t i = 0; i < sizeof(memory); i++)
			memory[i] = cases[c].fill == PATTERN ? (u8)(i * 37 + 11) :
				    cases[c].fill == ONES ? 0xff : 0;
		for (size_t i = 0; i < sizeof(lte); i++)
			lte[i] = cases[c].fill == PATTERN ? (u8)(i * 53 + 7) :
				 cases[c].fill == ONES ? 0xff : 0;
		/* The MAC init left CMAC0 enabled. */
		set(memory, R_AX_CMAC_FUNC_EN, 4, get(memory, R_AX_CMAC_FUNC_EN, 4) | B_AX_CMAC_EN);
		lte_stuck = cases[c].lte_stuck;
		cmac_dead = cases[c].cmac_dead;
		h2c_refuse = cases[c].h2c_refuse;
		h2c_sent = h2c_failed = 0;
		dev.chip = &chip_info;
		dev.io = &raw_io;
		dev.mac.qta_mode = RTW89_QTA_SCC;
		dev.hal.cv = cases[c].cv;
		dev.efuse.rfe_type = cases[c].rfe;
		dev.fw.h2c_seq = cases[c].seq;
		dev.fw.normal = (struct rtw89_fw_suit){0, 29, 29, 18};
		dev.flags[RTW89_FLAG_POWERON / 64] |= 1UL << (RTW89_FLAG_POWERON % 64);
		rtw89_coex_recognize_ver(&dev);
		rtw89_btc_init(&dev);
		rtw89_btc_ntfy_poweron(&dev);
		rtw89_btc_ntfy_init(&dev, BTC_MODE_WL);
		const struct rtw89_btc *btc = &dev.btc;
		const struct rtw89_btc_module *md = &btc->mdinfo;
		record(50, md->rfe_type | (u32)md->kt_ver << 8 | (u32)md->bt_solo << 16 |
			   (u32)md->bt0_pos << 24,
		       md->bt0_sw_type | (u32)md->wa_type << 8 | (u32)md->kt_ver_adie << 16);
		record(51, md->ant.type | (u32)md->ant.num << 8 | (u32)md->ant.isolation << 16 |
			   (u32)md->ant.diversity << 24,
		       md->ant.single_pos | (u32)md->ant.btg_pos << 8 |
			   (u32)md->ant.stream_cnt << 16);
		record(52, btc->dm.error.map.pta_owner, btc->cx.wl.scbd[0]);
		record(53, btc->ant_type, btc->btg_pos);
		record(54, get(lte, R_AX_LTE_SW_CFG_1, 4), get(lte, R_AX_LTE_SW_CFG_2, 4));
		record(55, h2c_sent, h2c_failed);
		record(24, dev.fw.h2c_seq, 0);
		flush(out);
	}
	if (fclose(out))
		abort();
	printf("%zu\n", ARRAY_SIZE(cases));
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, core_defines, phy_defines, mac_defines, fw_defines, fw_c_defines,
        declarations, harness, fw_inlines, helpers, coex_head, coex_defines, forwards, mac,
        mac_h,
        phy, fw, ps,
        common, chip, coex, seam, tables, bx_table, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member', str(generated), '-o', str(exe)],
                   check=True)
    trace = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    cases = int(run.stdout.strip())
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=cases,
        case_order='rfe 1 cut B over zeroed, patterned memory; rfe 2 cut C over all-ones '
                   'memory; rfe 0 cut A zeroed; rfe 1 with the LTE never ready; rfe 1 with '
                   'CMAC_FUNC_EN dead; rfe 1 patterned with every H2C refused from sequence 0xfe',
        dispatch=dict(rtw8852b_chip_info=info, rtw8852b_chip_ops=chip_ops,
                      rtw8852bx_info=bx, rtw89_mac_gen_ax=mac_def, rtw89_phy_gen_ax=phy_def,
                      rtw89_raw_io=raw_io, firmware='0.29.29.18', mode='BTC_MODE_WL'),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays and the chip answers are a model; no physical evidence',
            'read_poll_timeout is modeled counted in steps, not by Linux timekeeping',
            '_run_coex is the harness\'s reduction to _set_coex_binding, _action_wl_only and '
            '_action_common\'s scoreboard write; the rest of _run_coex and _action_common is '
            'not run',
            'rtw89_core_start calls rtw89_btc_ntfy_init with BTC_MODE_NORMAL; this runs '
            'BTC_MODE_WL, the plan\'s WL-only mode',
            'rtw89_h2c_tx is a stub recording the skb; the CH12 path is the H2C oracle\'s',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
