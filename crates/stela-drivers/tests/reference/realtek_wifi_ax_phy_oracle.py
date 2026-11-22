#!/usr/bin/env python3
"""Unchanged pinned rtw89 BB and RF table loads for a PCIe RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY RTL8852B_IMAGE OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks; RTL8852B_IMAGE is the pinned
rtw89/rtw8852b_fw-2.bin. Extracted unchanged, each with its SHA-256 in
manifest.json:

- phy.c: rtw89_phy_init_bb_afe, rtw89_phy_init_bb_reg, rtw89_phy_init_rf_reg,
  rtw89_phy_init_rf_nctl with rtw89_phy_preinit_rf_nctl_ax and
  rtw89_phy_nctl_poll, rtw89_phy_init_reg, rtw89_phy_sel_headline,
  rtw89_phy_config_bb_reg, rtw89_phy_config_bb_gain_ax with its four
  rtw89_phy_cfg_bb_* helpers, union rtw89_phy_bb_gain_arg and enum
  rtw89_phy_bb_rxsc_start_idx, rtw89_phy_config_rf_reg_v1 (and the
  rtw89_phy_config_rf_reg and _noio callbacks rtw89_phy_init_rf_reg names),
  rtw89_phy_cofig_rf_reg_store, rtw89_phy_config_rf_reg_fw,
  rtw89_phy_bb_reset, rtw89_phy_write_rf_v1 with rtw89_phy_write_rf,
  rtw89_phy_write_rf_a and rtw89_phy_check_swsi_busy, rtw89_chip_rf_v1,
  rtw89_phy_write32_idx and rtw89_phy0_phy1_offset;
- fw.c: rtw89_fw_h2c_rf_reg with rtw89_fw_h2c_alloc_skb(_with_hdr) and
  rtw89_h2c_pkt_set_hdr; rtw89_fw_recognize_elements with every handler, as
  realtek_wifi_ax_elements_oracle.py extracts them, so the tables come from
  the image as rtw89 builds them;
- mac.h, mac.c: rtw89_chip_reset_bb_rf with the disable and enable hooks,
  rtw89_mac_txpwr_write32 with rtw89_mac_get_txpwr_cr_ax, the XTAL SI
  accessors; rtw8852b_common.c and .h: __rtw8852bx_mac_disable_bb_rf,
  __rtw8852bx_mac_enable_bb_rf, __rtw8852bx_bb_reset_all,
  __rtw8852bx_init_txpwr_unit, __rtw8852bx_set_txpwr_ul_tb_offset and their
  rtw8852bx_info wrappers; rtw8852b.c: rtw8852b_bb_reset; core.h and phy.h:
  the MMIO, RF and delay inlines, the chip hooks; reg.h whole.

rtw8852b_chip_info, rtw8852b_chip_ops, rtw8852bx_info, rtw89_phy_gen_ax and
rtw89_mac_gen_ax give the dispatch values, each checked; rtw89_core_start is
checked to run rtw89_phy_init_bb_afe before rtw89_mac_init, then
rtw89_chip_reset_bb_rf, rtw89_phy_init_bb_reg, rtw89_chip_bb_postinit and
rtw89_phy_init_rf_reg(rtwdev, false), and rtw89_phy_dm_init to run
rtw89_phy_init_rf_nctl; the harness runs them in that order. I/O is rtw89's
raw PCIe I/O (rtw89_raw_io: no packing, no delay hooks), DBCC off.
Everything is compiled with clang under ASan and UBSan.

The register model is BAR2 as bytes, byte i holding i * 37 + 11 at the
start of each case, behaving per aligned word: SWSI (R_SWSI_V1) reads
neither busy bit; the NCTL report (0x8080) reads as written, or 0 when a
case makes it stuck; WLAN_XTAL_SI_CTRL, written with its poll bit, puts a
read's register into its data field or applies a write's data under its
mask to an XTAL SI file (register i starting at i * 29 + 0x47), then clears
the poll bit, unless a case makes XTAL SI stuck. rtw89_h2c_tx records the
skb's length and the sequence after it (40) and its bytes as little-endian
words (41), then takes it or, at the call index a case names, refuses it
with -ENOSPC. Each rtw89_warn and rtw89_err is recorded by its format's
index in WARNINGS (an unknown format aborts), held until the step ends.

Cases: the pinned image for cuts 0, 1 and 2 with RFE types 0, 1 and 2; then
syn-phy.bin, the pinned image with synthetic BB, BB gain, radio A, radio B,
NCTL and AFE elements put before its own (rtw89 keeps the first table of
each kind and the last AFE element): RFE 3 cut 1, RFE 7 cut 0, RFE 1 cut 0
(the BB table's dont-care package ends at an ELSE, the radio tables have no
package), RFE 55 cut 1 (eFEM gain lines), and RFE 3 cut 1 with the NCTL
report stuck, with the second H2C refused, and with XTAL SI stuck.

trace.bin: per case, a segment prefixed by its byte length, of records of
three little-endian u32 (tag, a, b): reads tagged by width, writes by 4
plus width, delays 9 (microseconds in b); a step marker 50 (step: 0 AFE,
1 BB/RF reset, 2 BB tables, 3 BB post-init, 4 radio tables, 5 NCTL), each
step's warnings 70 (index), the reset's return 11 (0, ret); H2C 40 and 41;
then, when the reset returned 0, rtwdev->bb_gain.ax as words 60 (index,
word); last the H2C sequence 24.
"""
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'

WARNINGS = [
    'invalid PHY package: %d/%d\\n',
    'failed to load CR %x/%x\\n',
    'bb gain table with flow ctrl\\n',
    'bb gain {0x%x:0x%x} with unknown cfg type: %d\\n',
    'bb gain error {0x%x:0x%x} with unknown type: %d\\n',
    'bb rpl ofst {0x%x:0x%x} with unknown bw: %d\\n',
    'bb gain bypass {0x%x:0x%x} with unknown type: %d\\n',
    'bb gain op1db {0x%x:0x%x} with unknown type: %d\\n',
    'write rf busy swsi\\n',
    'unsupported rf path (%d)\\n',
    'RF parameters exceed size. path=%d, idx=%d',
    'rf reg h2c total len %d larger than %d\\n',
    'failed to send h2c\\n',
    'rf path %d reg h2c config failed\\n',
    'failed to poll nctl block\\n',
    'unexpected AFE class %u\\n',
    'unexpected AFE writing action %u\\n',
    'failed to poll AFE cat=%u addr=0x%x mask=0x%x\\n',
    'xtal si not ready(R): offset=%x\\n',
    'xtal si not ready(W): offset=%x val=%x mask=%x\\n',
]

# (image, rfe, cv, xtal_stuck, nctl_stuck, refuse_at, seq0)
CASES = (
    [(0, rfe, cv, 0, 0, -1, cv) for cv in (0, 1, 2) for rfe in (0, 1, 2)]
    + [(1, 3, 1, 0, 0, -1, 3), (1, 7, 0, 0, 0, -1, 0), (1, 1, 0, 0, 0, -1, 1),
       (1, 55, 1, 0, 0, -1, 2), (1, 3, 1, 0, 1, -1, 0), (1, 3, 1, 0, 0, 1, 0),
       (1, 3, 1, 1, 0, -1, 0)])

BYPASS = 0xbabecafe


def element(eid, fixed=bytes(8), body=b''):
    """A struct rtw89_fw_element_hdr (AID 0) and its body."""
    return struct.pack('<II4sHHII', eid, len(body), b'\x01\x02\x03\x04', 0, 0, 0, 0) + fixed + body


def regs(pairs):
    return b''.join(struct.pack('<II', a, d & 0xffffffff) for a, d in pairs)


def plain(base, n, seed, step=4):
    return [(base + step * i, (0x5a000000 + i * 0x01010101 * (seed + 1)) & 0xffffffff)
            for i in range(n)]


def pattern_word(address):
    return sum(((address + i) * 37 + 11 & 0xff) << (8 * i) for i in range(4))


def synthetic_elements():
    if_ = lambda target: [(0x80000000 | target, 0), (0x40000000, 0)]
    elif_ = lambda target: [(0x90000000 | target, 0), (0x40000000, 0)]
    else_, end = [(0xa0000000, 0)], [(0xb0000000, 0)]
    delays = [(a, 0x1234) for a in (0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9)]
    bb = ([(0xf0030001, 0), (0xf0070000, 0), (0xf0ff0002, 0)] + plain(0x4000, 6, 1) + delays
          + [(0x4100, BYPASS), (0x4104, 0x11112222)]
          + if_(0x030001) + plain(0x4200, 5, 2) + elif_(0x070000) + plain(0x4300, 4, 3)
          + else_ + plain(0x4400, 3, 4) + end + plain(0x4500, 3, 5))

    def gain(cfg, band, path, kind, data):
        return (cfg << 24 | band << 16 | path << 8 | kind, data)
    gains = []
    for band, path in ((0, 0), (3, 1), (7, 1)):
        for kind in (0, 1, 2, 3):
            gains.append(gain(0, band, path, kind, 0x80f17f05 + kind * 0x01020304 + band))
        for bw in range(6):
            for rxsc in (0, 1, 5, 9, 13):
                gains.append(gain(1, band, path, bw << 4 | rxsc,
                                  0xfe7f8102 + bw * 0x11 + rxsc * 0x01000100 + path))
        for kind in (0, 1, 2):
            gains.append(gain(2, band, path, kind, 0x0381fd7e + kind))
        for kind in (0, 1, 2, 3, 4):
            gains.append(gain(3, band, path, kind, 0x9a7b5c3d + kind * 0x0101))
    gains += [gain(4, 1, 0, 0, 0x1), gain(5, 1, 0, 0, 0x2), gain(0, 8, 0, 0, 0x3),
              gain(0, 1, 2, 0, 0x4), (0xfa, 0x5), (0xfe, 0x6), gain(6, 2, 1, 1, 0x7)]

    radio_low = [(0x05, 0x00001), (0x18, 0x10d24), (0xef, 0x80000), (0xfd, 0x00123),
                 (0xfe, 0), (0x10005, 0x00003)]
    radio_a = ([(0xf0030001, 0), (0xf0070000, 0)] + if_(0x030001) + radio_low
               + [(0x10000 | (i % 0xff), (i * 0x9e37) & 0xfffff) for i in range(1530)]
               + [(0x1ee, 0x12345), (0x2ab, 0xfffff), (0xfe, 0), (0x3ff, 0x00001)]
               + [(0x10000 | (i % 0x7f), (i * 0x1111) & 0xfffff) for i in range(20)]
               + elif_(0x070000) + [(0x10018, 0x00c01), (0x33, 0x2), (0x100ee, 0x4)] + end)
    radio_b = (radio_low + [(0x10000 | (i % 0xfe), (i * 0x7f3) & 0xfffff) for i in range(560)]
               + [(0x56, 0x00006), (0x10056, 0x00007)])
    nctl = plain(0x8000, 4, 6) + delays + [(0x8100, BYPASS)] + plain(0x8200, 5, 7)

    afe_infos = [
        (0, 2, 0, 0x1000, 0x00ff0000, 0x5a),
        (0, 0, 1, 0x4000, 0x0000ff00, 0x33),
        (0, 1, 5, 0x4004, 0xffffffff, 0x12345678),
        (0, 4, 0, 0x1004, 0x0000000f, 0x3),
        (0, 3, 0, 0x1008, 0x000000f0, 0x7),
        (0, 5, 1, 0x100c, 0x000000ff, 0x9),
        (0, 6, 0, 0x1010, 0x000000ff, 0x1),
        (0, 2, 2, 0x1000, 0x000000ff, 0x1),
        (2, 2, 0, 0x1000, 0x00ff0000, 0x5a),
        (2, 0, 0, 0x1014, 0x000000ff, (pattern_word(0x1014) & 0xff) ^ 1),
        (1, 2, 0, 25, 0, 0),
        (3, 2, 0, 0x1000, 0xff, 0),
        (2, 2, 5, 0x1018, 0x0000ff00, pattern_word(0x1018) >> 8 & 0xff),
    ]
    afe = b''.join(struct.pack('<6I', *info) for info in afe_infos) + b'\x01\x02\x03\x04\x05'
    return [
        element(2, body=regs(bb)),
        element(3, body=regs(gains)),
        element(4, bytes([0]) + bytes(7), regs(radio_a)),
        element(5, bytes([1]) + bytes(7), regs(radio_b)),
        element(8, body=regs(nctl)),
        element(27, body=afe),
    ]


def elements_offset(data):
    nr = data[1]
    shift, size = struct.unpack_from('<II', data, 16 + (nr - 1) * 16 + 4)
    return (shift + size + 15) & ~15


def synthetic_image(pinned):
    base = elements_offset(pinned)
    out = bytearray(pinned[:base])
    for piece in synthetic_elements():
        out += piece
        out += bytes(-len(out) % 16)
    return bytes(out + pinned[base:])


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    reference, image, out = map(pathlib.Path, argv)
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

    def locate(file, name, keep=True):
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
            body = text[start:closing(text, end)]
            return start, record(file, name, body) if keep else body
        raise ValueError(f'{file}: no definition of {name}')

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
        found_lines = []
        for name in names:
            found = re.findall(r'^#define ' + re.escape(name) + r'\b[^\n]*$', text, re.M)
            if len(found) != 1:
                raise ValueError(f'{file}: #define {name} appears {len(found)} times')
            found_lines.append(found[0])
        return record(file, f'#define {" ".join(names)}', '\n'.join(found_lines))

    def macro(file, name):
        """A #define with its continuation lines."""
        text = source(file)
        found = list(re.finditer(r'^#define ' + re.escape(name) + r'\b', text, re.M))
        if len(found) != 1:
            raise ValueError(f'{file}: #define {name} appears {len(found)} times')
        start = end = found[0].start()
        while True:
            line_end = text.index('\n', end)
            if not text[line_end - 1] == '\\':
                break
            end = line_end + 1
        return record(file, f'#define {name}', text[start:line_end])

    def lines(file, prefix, name):
        """Every line starting with prefix."""
        text = source(file)
        found = [line for line in text.splitlines() if line.startswith(prefix)]
        if not found:
            raise ValueError(f'{file}: no line starts with {prefix}')
        return record(file, name, '\n'.join(found))

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
            values[name] = ' '.join(body[start:end].split())
        return values

    def check(name, got, expected):
        if got != expected:
            raise ValueError(f'{name} is {got}')
        return got

    chip = check('rtw8852b_chip_info', fields(
        'rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
        ['chip_id', 'chip_gen', 'phy_def', 'support_bands', 'needed_fw_elms', 'bbmcu_nr',
         'rf_base_addr', 'rf_path_num', 'nctl_post_table', 'support_fw_cmd_ofld']), {
        'chip_id': 'RTL8852B', 'chip_gen': 'RTW89_CHIP_AX', 'phy_def': '&rtw89_phy_gen_ax',
        'support_bands': 'BIT(NL80211_BAND_2GHZ) | BIT(NL80211_BAND_5GHZ)',
        'needed_fw_elms': 'RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_NO_6GHZ | '
                          'BIT(__RTW89_FW_ELEMENT_ID_INTL_TRANSITION)',
        'bbmcu_nr': '0', 'rf_base_addr': '{0xe000, 0xf000}', 'rf_path_num': '2',
        'nctl_post_table': 'NULL', 'support_fw_cmd_ofld': 'false'})
    ops = check('rtw8852b_chip_ops', fields(
        'rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
        ['enable_bb_rf', 'disable_bb_rf', 'bb_preinit', 'bb_postinit', 'bb_reset', 'write_rf',
         'init_txpwr_unit']), {
        'enable_bb_rf': 'rtw8852bx_mac_enable_bb_rf',
        'disable_bb_rf': 'rtw8852bx_mac_disable_bb_rf', 'bb_preinit': 'NULL',
        'bb_postinit': 'NULL', 'bb_reset': 'rtw8852b_bb_reset',
        'write_rf': 'rtw89_phy_write_rf_v1', 'init_txpwr_unit': 'rtw8852bx_init_txpwr_unit'})
    bx_info = check('rtw8852bx_info', fields(
        'rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info',
        ['mac_enable_bb_rf', 'mac_disable_bb_rf', 'bb_reset_all', 'init_txpwr_unit',
         'set_txpwr_ul_tb_offset']), {
        'mac_enable_bb_rf': '__rtw8852bx_mac_enable_bb_rf',
        'mac_disable_bb_rf': '__rtw8852bx_mac_disable_bb_rf',
        'bb_reset_all': '__rtw8852bx_bb_reset_all',
        'init_txpwr_unit': '__rtw8852bx_init_txpwr_unit',
        'set_txpwr_ul_tb_offset': '__rtw8852bx_set_txpwr_ul_tb_offset'})
    phy_gen = check('rtw89_phy_gen_ax', fields(
        'phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax',
        ['cr_base', 'config_bb_gain', 'preinit_rf_nctl']), {
        'cr_base': '0x10000', 'config_bb_gain': 'rtw89_phy_config_bb_gain_ax',
        'preinit_rf_nctl': 'rtw89_phy_preinit_rf_nctl_ax'})
    mac_gen = check('rtw89_mac_gen_ax', fields(
        'mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax',
        ['band1_offset', 'get_txpwr_cr', 'write_xtal_si', 'read_xtal_si']), {
        'band1_offset': 'RTW89_MAC_AX_BAND_REG_OFFSET',
        'get_txpwr_cr': 'rtw89_mac_get_txpwr_cr_ax',
        'write_xtal_si': 'rtw89_mac_write_xtal_si_ax',
        'read_xtal_si': 'rtw89_mac_read_xtal_si_ax'})
    raw_io = check('rtw89_raw_io', fields(
        'fw.c', 'static const struct rtw89_io_ops rtw89_raw_io',
        ['pack', 'unpack', 'phy_write32', 'write_rf']), {
        'pack': 'NULL', 'unpack': 'NULL', 'phy_write32': 'rtw89_raw_phy_write32',
        'write_rf': 'rtw89_raw_write_rf'})

    def calls_in_order(file, function, calls):
        body = locate(file, function)[1]
        at = [body.find(call) for call in calls]
        if -1 in at or at != sorted(at):
            raise ValueError(f'{function} does not call {calls} in order: {at}')
    calls_in_order('core.c', 'rtw89_core_start', [
        'rtw89_phy_init_bb_afe(rtwdev);', 'rtw89_mac_init(rtwdev);',
        'rtw89_chip_reset_bb_rf(rtwdev);', 'rtw89_phy_init_bb_reg(rtwdev);',
        'rtw89_chip_bb_postinit(rtwdev);', 'rtw89_phy_init_rf_reg(rtwdev, false);',
        'rtw89_phy_dm_init(rtwdev);'])
    calls_in_order('phy.c', 'rtw89_phy_dm_init', ['rtw89_phy_init_rf_nctl(rtwdev);'])

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    head_defines = '\n'.join([
        defines('core.h', ['MASKDWORD', 'RFREG_MASK', 'BYPASS_CR_DATA', 'DELTA_SWINGIDX_SIZE',
                           'RF_PATH_MAX', 'RTW89_TXPWR_CONF_DFLT_RFE_TYPE',
                           'RTW89_REGD_MAX_COUNTRY_NUM', 'LNA_GAIN_NUM', 'TIA_GAIN_NUM']),
        macro('core.h', 'rtw89_txpwr_conf_valid'),
        defines('phy.h', ['RTW89_RF_ADDR_ADSEL_MASK', 'PHY_HEADLINE_VALID', 'PHY_COND_BRANCH_IF',
                          'PHY_COND_BRANCH_ELIF', 'PHY_COND_BRANCH_ELSE', 'PHY_COND_BRANCH_END',
                          'PHY_COND_CHECK', 'PHY_COND_DONT_CARE']),
        '\n'.join(macro('phy.h', name) for name in [
            'get_phy_headline', 'get_phy_target', 'get_phy_compare', 'get_phy_cond',
            'get_phy_cond_rfe', 'get_phy_cond_cv']),
        defines('mac.h', ['FULL_BIT_MASK', 'RTW89_MAC_AX_BAND_REG_OFFSET']),
        defines('fw.h', ['RTW89_MFW_SIG', 'RTW89_FW_ELEMENT_ALIGN', 'H2C_HEADER_LEN',
                         'H2C_HDR_CAT', 'H2C_HDR_CLASS', 'H2C_HDR_FUNC', 'H2C_HDR_DEL_TYPE',
                         'H2C_HDR_H2C_SEQ', 'H2C_HDR_TOTAL_LEN', 'H2C_HDR_REC_ACK',
                         'H2C_HDR_DONE_ACK', 'FWCMD_TYPE_H2C', 'H2C_CAT_OUTSRC',
                         'H2C_CL_OUTSRC_RF_REG_A', 'H2C_CL_OUTSRC_RF_REG_B',
                         'RTW89_H2C_RF_PAGE_SIZE', 'RTW89_H2C_RF_PAGE_NUM']),
        lines('fw.h', '#define FW_HDR_', 'FW_HDR_* defines'),
    ])
    declarations = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_core_chip_id', 'rtw89_chip_gen', 'rtw89_rf_path', 'rtw89_band',
            'rtw89_bandwidth', 'rtw89_mac_idx', 'rtw89_phy_idx', 'rtw89_qta_mode', 'rtw89_flags',
            'rtw89_regulation_type', 'rtw89_regd_func', 'rtw89_fw_type',
            'rtw89_phy_bb_gain_band', 'rtw89_phy_bb_rxsc_num']]
        + [declaration('phy.h', 'enum', 'rtw89_phy_c2h_rfk_log_func'),
           declaration('mac.h', 'enum', 'rtw89_mac_xtal_si_offset')]
        + [declaration('core.h', 'struct', name) for name in [
            'rtw89_reg2_def', 'rtw89_phy_table', 'rtw89_txpwr_conf', 'rtw89_regd',
            'rtw89_regd_data', 'rtw89_fw_suit', 'rtw89_phy_bb_gain_info', 'rtw89_io_ops']]
        + [declaration('fw.h', kind, name) for kind, name in [
            ('struct', 'rtw89_mfw_info'), ('struct', 'rtw89_mfw_hdr'),
            ('struct', 'rtw89_fw_hdr_section'), ('struct', 'rtw89_fw_hdr'),
            ('struct', 'rtw89_fw_hdr_section_v1'), ('struct', 'rtw89_fw_hdr_v1'),
            ('enum', 'rtw89_fw_element_id')]]
        + ['\n'.join(macro('fw.h', name) for name in [
            'BITS_OF_RTW89_TXPWR_FW_ELEMENTS_TX_SHAPE', 'BITS_OF_RTW89_TXPWR_FW_ELEMENTS_NO_6GHZ',
            'RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_BASE',
            'RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_NO_6GHZ'])]
        + [declaration('fw.h', kind, name) for kind, name in [
            ('struct', '__rtw89_fw_txpwr_element'), ('struct', '__rtw89_fw_regd_element'),
            ('enum', 'rtw89_fw_txpwr_trk_type'), ('struct', 'rtw89_fw_txpwr_track_cfg')]]
        + ['\n'.join(macro('fw.h', f'RTW89_DEFAULT_NEEDED_FW_TXPWR_TRK_{band}GHZ')
                     for band in ['6', '5', '2'])]
        + [declaration('fw.h', kind, name) for kind, name in [
            ('enum', 'rtw89_fw_afe_action'), ('enum', 'rtw89_fw_afe_cat'),
            ('enum', 'rtw89_fw_afe_class'), ('struct', 'rtw89_fw_element_hdr'),
            ('struct', 'rtw89_fw_regd_entry'), ('struct', 'fwcmd_hdr'),
            ('struct', 'rtw89_fw_h2c_rf_reg_info')]]
        + [declaration('phy.h', 'struct', 'rtw89_phy_rfk_log_fmt'),
           declaration('phy.h', 'struct', 'rtw89_rfk_tbl'),
           declaration('core.h', 'struct', 'rtw89_fw_elm_info')])
    fw_types = '\n\n'.join([
        declaration('fw.c', 'union', 'rtw89_fw_element_arg'),
        declaration('fw.c', 'struct', 'rtw89_fw_element_handler'),
    ])
    phy_types = '\n\n'.join([
        declaration('phy.c', 'union', 'rtw89_phy_bb_gain_arg'),
        declaration('phy.c', 'enum', 'rtw89_phy_bb_rxsc_start_idx'),
    ])
    core_h = in_order('core.h', [
        'rtw89_fw_suit_get', 'rtw89_io_pack', 'rtw89_io_unpack', 'rtw89_io_udelay',
        'rtw89_io_mdelay', 'rtw89_write8_set', 'rtw89_write8_clr', 'rtw89_write32_set',
        'rtw89_write32_clr', 'rtw89_read32_mask', 'rtw89_write32_mask', 'rtw89_raw_write_rf',
        'rtw89_write_rf', 'rtw89_chip_bb_postinit', '__rtw89_chip_init_txpwr_unit',
        'rtw89_chip_init_txpwr_unit'])
    phy_h = in_order('phy.h', [
        'rtw89_raw_phy_write32', 'rtw89_phy_write32', 'rtw89_phy_write32_set',
        'rtw89_phy_write32_clr', 'rtw89_phy_write32_mask', 'rtw89_phy_read32',
        'rtw89_phy_read32_mask', 'rtw89_phy_preinit_rf_nctl'])
    mac_h = in_order('mac.h', [
        'rtw89_mac_reg_by_idx', 'rtw89_chip_enable_bb_rf', 'rtw89_chip_disable_bb_rf',
        'rtw89_chip_reset_bb_rf', 'rtw89_mac_txpwr_write32', 'rtw89_mac_write_xtal_si',
        'rtw89_mac_read_xtal_si'])
    bx_h = in_order('rtw8852b_common.h', [
        'rtw8852bx_mac_enable_bb_rf', 'rtw8852bx_mac_disable_bb_rf', 'rtw8852bx_bb_reset_all',
        'rtw8852bx_init_txpwr_unit', 'rtw8852bx_set_txpwr_ul_tb_offset'])
    mac_c = in_order('mac.c', [
        'rtw89_mac_write_xtal_si_ax', 'rtw89_mac_read_xtal_si_ax', 'rtw89_mac_get_txpwr_cr_ax'])
    bx_c = in_order('rtw8852b_common.c', [
        '__rtw8852bx_bb_reset_all', '__rtw8852bx_set_txpwr_ul_tb_offset',
        '__rtw8852bx_init_txpwr_unit', '__rtw8852bx_mac_enable_bb_rf',
        '__rtw8852bx_mac_disable_bb_rf'])
    b_c = locate('rtw8852b.c', 'rtw8852b_bb_reset')[1]
    fw_h2c = in_order('fw.c', [
        'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr', 'rtw89_h2c_pkt_set_hdr',
        'rtw89_fw_h2c_rf_reg'])
    phy_c = in_order('phy.c', [
        'rtw89_phy0_phy1_offset', 'rtw89_phy_check_swsi_busy', 'rtw89_phy_write_rf',
        'rtw89_phy_write_rf_a', 'rtw89_phy_write_rf_v1', 'rtw89_chip_rf_v1',
        '__rtw89_phy_bb_reset', 'rtw89_phy_bb_reset', 'rtw89_phy_config_bb_reg',
        'rtw89_phy_cfg_bb_gain_error', 'rtw89_phy_cfg_bb_rpl_ofst',
        'rtw89_phy_cfg_bb_gain_bypass', 'rtw89_phy_cfg_bb_gain_op1db',
        'rtw89_phy_config_bb_gain_ax', 'rtw89_phy_cofig_rf_reg_store',
        'rtw89_phy_config_rf_reg_fw', 'rtw89_phy_config_rf_reg_noio', 'rtw89_phy_config_rf_reg',
        'rtw89_phy_config_rf_reg_v1', 'rtw89_phy_sel_headline', 'rtw89_phy_init_reg',
        'rtw89_phy_init_bb_reg', 'rtw89_phy_init_bb_afe', 'rtw89_phy_nctl_poll',
        'rtw89_phy_init_rf_reg', 'rtw89_phy_preinit_rf_nctl_ax', 'rtw89_phy_init_rf_nctl',
        'rtw89_phy_write32_idx'])
    handlers = ['__rtw89_fw_recognize_from_elm', 'rtw89_build_phy_tbl_from_elm',
                'rtw89_fw_recognize_txpwr_from_elm', 'rtw89_build_txpwr_trk_tbl_from_elm',
                'rtw89_build_rfk_log_fmt_from_elm', 'rtw89_recognize_regd_from_elm',
                'rtw89_build_afe_pwr_seq_from_elm', 'rtw89_recognize_diag_mac_from_elm',
                'rtw89_build_tx_comp_from_elm']
    fw_elements = '\n\n'.join([
        macro('fw.c', 'rtw89_for_each_in_regd_element'),
        in_order('fw.c', ['rtw89_mfw_get_hdr_ptr', 'rtw89_mfw_validate_hdr',
                          'rtw89_mfw_get_size', 'rtw89_fw_update_ver_v0',
                          'rtw89_fw_update_ver_v1', 'rtw89_fw_update_ver',
                          'rtw89_regd_entcpy'] + handlers),
        definition('fw.c', 'static const struct rtw89_fw_element_handler __fw_element_handlers[]'),
        locate('fw.c', 'rtw89_fw_recognize_elements')[1],
    ])
    extracted = '\n'.join([phy_c, fw_h2c, mac_c, bx_c, b_c])
    for text in WARNINGS:
        if '"' + text + '"' not in extracted:
            raise ValueError(f'no rtw89 format "{text}" in the extracted code')

    preamble = r'''
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int32_t s32;
typedef uint16_t __le16; typedef uint32_t __le32;
#define BIT(n) (1U << (n))
#define U8_MAX 255
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a) (((x) + ((__typeof__(x))(a) - 1)) & ~((__typeof__(x))(a) - 1))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define __packed __attribute__((packed))
#define __counted_by(m)
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_replace_bits(old, v, m) ((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, v))
#define le32_get_bits(v, m) u32_get_bits(v, m)
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
static void set_bit(long nr, unsigned long *addr) { addr[nr / 64] |= 1UL << (nr % 64); }
#define test_bit(nr, addr) ((int)(((addr)[(nr) / 64] >> ((nr) % 64)) & 1))
#define GFP_KERNEL 0
#define kzalloc_obj(x, ...) ((__typeof__(&(x)))calloc(1, sizeof(x)))
#define kzalloc_objs(x, n, ...) ((__typeof__(&(x)))calloc((n), sizeof(x)))
#define kfree(p) free((void *)(p))
#define devm_kzalloc(d, size, gfp) calloc(1, (size))
#define devm_kfree(d, p) free((void *)(p))
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
#define fallthrough __attribute__((__fallthrough__))
#define lockdep_assert_wiphy(w) ((void)0)
#define RTW89_DBG_REGD BIT(8)
#define RTW89_DBG_FW BIT(12)
#define RTW89_DBG_PHY_TRACK BIT(2)
/* rtw89's log helpers are calls in the kernel: their arguments are
 * evaluated whatever is printed. Warnings and errors are recorded by
 * format while the harness logs; info and debug lines are not. */
static void sink(const char *format, ...) { (void)format; }
static void logged(const char *format, ...);
#define rtw89_warn(d, ...) ((void)(d), logged(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), logged(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound. The atomic form is the same. */
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
#define mdelay(ms) model_delay((u64)(ms) * 1000)
#define fsleep(us) model_delay(us)
/* Kernel types the declarations name. */
enum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_60GHZ,
		    NL80211_BAND_6GHZ };
struct device { int unused; };
struct firmware { const u8 *data; size_t size; };
struct wiphy { char fw_version[32]; };
struct ieee80211_hw { struct wiphy *wiphy; };
struct sk_buff { u8 *head, *data; u32 len, size; };
struct rtw89_dev;
struct rtw89_reg5_def;
'''
    harness = r'''
/* struct rtw89_rfe_data's conf members, in its order: what the TX power
 * handler reaches through the table's offsets. */
struct rtw89_txpwr_conf_holder { struct rtw89_txpwr_conf conf; };
struct rtw89_rfe_data {
	struct rtw89_txpwr_conf_holder byrate, lmt_2ghz, lmt_5ghz, lmt_6ghz, da_lmt_2ghz,
		da_lmt_5ghz, da_lmt_6ghz, lmt_ru_2ghz, lmt_ru_5ghz, lmt_ru_6ghz, da_lmt_ru_2ghz,
		da_lmt_ru_5ghz, da_lmt_ru_6ghz, tx_shape_lmt, tx_shape_lmt_ru;
};
/* The members of rtw89's device and chip the extracted functions reach. */
struct rtw89_hal { u8 cv; u8 acv; u16 aid; };
struct rtw89_efuse { u8 rfe_type; };
struct rtw89_fw_req_info { const struct firmware *firmware; };
struct rtw89_fw_log { struct rtw89_fw_suit suit; };
struct rtw89_fw_info {
	struct rtw89_fw_req_info req;
	struct rtw89_fw_suit normal, wowlan, bbmcu0, bbmcu1;
	struct rtw89_fw_log log;
	struct rtw89_fw_elm_info elm_info;
	u8 h2c_seq;
};
struct rtw89_mac_gen_def {
	u32 band1_offset;
	bool (*get_txpwr_cr)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx,
			     u32 reg_base, u32 *cr);
	int (*write_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 val, u8 mask);
	int (*read_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 *val);
};
struct rtw89_phy_gen_def {
	u32 cr_base;
	u32 (*phy0_phy1_offset)(struct rtw89_dev *rtwdev, u32 addr);
	void (*config_bb_gain)(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
			       enum rtw89_rf_path rf_path, void *data);
	void (*preinit_rf_nctl)(struct rtw89_dev *rtwdev);
};
struct rtw89_chip_ops {
	int (*enable_bb_rf)(struct rtw89_dev *rtwdev);
	int (*disable_bb_rf)(struct rtw89_dev *rtwdev);
	void (*bb_postinit)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx);
	void (*bb_reset)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx);
	bool (*write_rf)(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			 u32 mask, u32 data);
	int (*init_txpwr_unit)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	u32 support_bands;
	u32 needed_fw_elms;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	const struct rtw89_phy_gen_def *phy_def;
	u8 rf_path_num;
	u32 rf_base_addr[2];
	u32 h2c_desc_size;
	const struct rtw89_phy_table *bb_table;
	const struct rtw89_phy_table *bb_gain_table;
	const struct rtw89_phy_table *rf_table[RF_PATH_MAX];
	const struct rtw89_phy_table *nctl_table;
	const struct rtw89_rfk_tbl *nctl_post_table;
};
struct rtw8852bx_info {
	int (*mac_enable_bb_rf)(struct rtw89_dev *rtwdev);
	int (*mac_disable_bb_rf)(struct rtw89_dev *rtwdev);
	void (*bb_reset_all)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx);
	int (*init_txpwr_unit)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx);
	void (*set_txpwr_ul_tb_offset)(struct rtw89_dev *rtwdev, s8 pw_ofst,
				       enum rtw89_mac_idx mac_idx);
};
static const struct rtw8852bx_info rtw8852bx_info;
struct rtw89_mac_info { enum rtw89_qta_mode qta_mode; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_io_ops *io;
	struct rtw89_hal hal;
	struct rtw89_efuse efuse;
	struct rtw89_fw_info fw;
	struct rtw89_mac_info mac;
	struct rtw89_rfe_data *rfe_data;
	struct { struct rtw89_phy_bb_gain_info ax; } bb_gain;
	struct device *dev;
	struct ieee80211_hw *hw;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
	bool dbcc_en;
};

/* The register model: BAR2 as bytes, behaving per aligned word. */
#define HARNESS_CR_BASE 0x10000u
static u8 memory[0x20000];
static u8 xtal[256];
static int xtal_stuck, nctl_stuck, h2c_refuse_at, h2c_calls, logging;
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
static u32 view(u32 w)
{
	u32 v = get(w, 4);
	if (w == HARNESS_CR_BASE + R_SWSI_V1)
		return v & ~(B_SWSI_W_BUSY_V1 | B_SWSI_R_BUSY_V1);
	if (w == HARNESS_CR_BASE + 0x8080 && nctl_stuck)
		return 0;
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
	set(r, n, v);
	u32 w = r & ~3u, s = get(w, 4);
	if (w == R_AX_WLAN_XTAL_SI_CTRL && (s & B_AX_WL_XTAL_SI_CMD_POLL) && !xtal_stuck) {
		u32 offset = u32_get_bits(s, B_AX_WL_XTAL_SI_ADDR_MASK);
		u32 mode = u32_get_bits(s, B_AX_WL_XTAL_SI_MODE_MASK);
		if (mode == XTAL_SI_NORMAL_READ) {
			s = (s & ~B_AX_WL_XTAL_SI_DATA_MASK) |
			    FIELD_PREP(B_AX_WL_XTAL_SI_DATA_MASK, xtal[offset]);
		} else if (mode == XTAL_SI_NORMAL_WRITE) {
			u8 mask = u32_get_bits(s, B_AX_WL_XTAL_SI_BITMASK_MASK);
			u8 data = u32_get_bits(s, B_AX_WL_XTAL_SI_DATA_MASK);
			xtal[offset] = (xtal[offset] & ~mask) | (data & mask);
		}
		set(w, 4, s & ~B_AX_WL_XTAL_SI_CMD_POLL);
	}
}
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* Warnings by format, held until the step ends. */
static const char *const formats[] = {
''' + ',\n'.join('\t"' + text + '"' for text in WARNINGS) + r'''
};
static u32 warns[1 << 16];
static u32 n_warns;
static void logged(const char *format, ...)
{
	if (!logging)
		return;
	for (u32 i = 0; i < ARRAY_SIZE(formats); i++) {
		if (!strcmp(format, formats[i])) {
			if (n_warns == ARRAY_SIZE(warns))
				abort();
			warns[n_warns++] = i;
			return;
		}
	}
	fprintf(stderr, "unexpected log: %s\n", format);
	abort();
}
static void flush(void)
{
	for (u32 i = 0; i < n_warns; i++)
		record(70, warns[i], 0);
	n_warns = 0;
}

/* skbs: headroom and tailroom exactly what was reserved and allocated. */
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
static void skb_put_data(struct sk_buff *s, const void *p, unsigned int n)
{
	if (n > skb_tailroom(s))
		abort();
	memcpy(s->data + s->len, p, n);
	s->len += n;
}
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
	if (h2c_calls++ == h2c_refuse_at)
		return -ENOSPC;
	dev_kfree_skb_any(skb);
	return 0;
}
/* Callees no case reaches: DBCC is off and RTL8852B has no NCTL post table. */
static u32 harness_phy0_phy1_offset(struct rtw89_dev *d, u32 addr) { (void)d; (void)addr; abort(); }
static void rtw89_rfk_parser(struct rtw89_dev *d, const struct rtw89_rfk_tbl *t) { (void)d; (void)t; abort(); }
void rtw89_phy_config_rf_reg(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
			     enum rtw89_rf_path rf_path, void *extra_data);
void rtw89_phy_config_rf_reg_v1(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
				enum rtw89_rf_path rf_path, void *extra_data);
void rtw89_phy_write32_idx(struct rtw89_dev *rtwdev, u32 addr, u32 mask, u32 data,
			   enum rtw89_phy_idx phy_idx);
bool rtw89_phy_write_rf_v1(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path,
			   u32 addr, u32 mask, u32 data);
int rtw89_fw_h2c_rf_reg(struct rtw89_dev *rtwdev, struct rtw89_fw_h2c_rf_reg_info *info,
			u16 len, u8 page);
static void rtw89_phy_config_bb_gain_ax(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
					enum rtw89_rf_path rf_path, void *extra_data);
static void rtw89_phy_preinit_rf_nctl_ax(struct rtw89_dev *rtwdev);
static void rtw8852b_bb_reset(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx);
'''
    case_table = ',\n'.join('\t{%d, %d, %d, %d, %d, %d, %d}' % case for case in CASES)
    main_c = r'''
static int __rtw8852bx_mac_enable_bb_rf(struct rtw89_dev *rtwdev);
static int __rtw8852bx_mac_disable_bb_rf(struct rtw89_dev *rtwdev);
static const struct rtw8852bx_info rtw8852bx_info = {
	.mac_enable_bb_rf = __rtw8852bx_mac_enable_bb_rf,
	.mac_disable_bb_rf = __rtw8852bx_mac_disable_bb_rf,
	.bb_reset_all = __rtw8852bx_bb_reset_all,
	.init_txpwr_unit = __rtw8852bx_init_txpwr_unit,
	.set_txpwr_ul_tb_offset = __rtw8852bx_set_txpwr_ul_tb_offset,
};
static const struct rtw89_chip_ops chip_ops = {
	.enable_bb_rf = rtw8852bx_mac_enable_bb_rf,
	.disable_bb_rf = rtw8852bx_mac_disable_bb_rf,
	.bb_postinit = NULL,
	.bb_reset = rtw8852b_bb_reset,
	.write_rf = rtw89_phy_write_rf_v1,
	.init_txpwr_unit = rtw8852bx_init_txpwr_unit,
};
static const struct rtw89_mac_gen_def mac_gen_ax = {
	.band1_offset = RTW89_MAC_AX_BAND_REG_OFFSET,
	.get_txpwr_cr = rtw89_mac_get_txpwr_cr_ax,
	.write_xtal_si = rtw89_mac_write_xtal_si_ax,
	.read_xtal_si = rtw89_mac_read_xtal_si_ax,
};
static const struct rtw89_phy_gen_def phy_gen_ax = {
	.cr_base = 0x10000,
	.phy0_phy1_offset = harness_phy0_phy1_offset,
	.config_bb_gain = rtw89_phy_config_bb_gain_ax,
	.preinit_rf_nctl = rtw89_phy_preinit_rf_nctl_ax,
};
static const struct rtw89_io_ops raw_io = {
	.pack = NULL,
	.unpack = NULL,
	.phy_write32 = rtw89_raw_phy_write32,
	.write_rf = rtw89_raw_write_rf,
};
struct kase { u32 image, rfe, cv, xtal_stuck, nctl_stuck; int refuse_at; u32 seq0; };
static const struct kase cases[] = {
''' + case_table + r'''
};
static void release(struct rtw89_dev *dev)
{
	struct rtw89_fw_elm_info *elm = &dev->fw.elm_info;
	struct rtw89_phy_table *phys[] = {elm->bb_tbl, elm->bb_gain, elm->rf_radio[0],
					  elm->rf_radio[1], elm->rf_radio[2], elm->rf_radio[3],
					  elm->rf_nctl};
	for (size_t i = 0; i < ARRAY_SIZE(phys); i++) {
		if (phys[i]) {
			free((void *)phys[i]->regs);
			free(phys[i]);
		}
	}
	free(elm->txpwr_trk);
	free(elm->rfk_log_fmt);
	free((void *)elm->regd);
	free(dev->rfe_data);
}
static void out32(FILE *o, u32 v)
{
	if (fwrite(&v, 4, 1, o) != 1)
		abort();
}
int main(int argc, char **argv)
{
	if (argc < 3)
		return 2;
	size_t n_images = (size_t)argc - 2;
	u8 **images = calloc(n_images, sizeof(*images));
	size_t *sizes = calloc(n_images, sizeof(*sizes));
	for (size_t i = 0; i < n_images; i++) {
		FILE *in = fopen(argv[2 + i], "rb");
		if (!in || fseek(in, 0, SEEK_END))
			abort();
		long size = ftell(in);
		if (size <= 0 || fseek(in, 0, SEEK_SET))
			abort();
		images[i] = malloc((size_t)size);
		if (!images[i] || fread(images[i], 1, (size_t)size, in) != (size_t)size)
			abort();
		fclose(in);
		sizes[i] = (size_t)size;
	}
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	const struct rtw89_chip_info chip = {
		.chip_id = CHIP_ID,
		.chip_gen = RTW89_CHIP_AX,
		.support_bands = SUPPORT_BANDS,
		.needed_fw_elms = (NEEDED_FW_ELMS) & ~BIT(__RTW89_FW_ELEMENT_ID_INTL_TRANSITION),
		.ops = &chip_ops,
		.mac_def = &mac_gen_ax,
		.phy_def = &phy_gen_ax,
		.rf_path_num = 2,
		.rf_base_addr = {0xe000, 0xf000},
		.h2c_desc_size = 32,
	};
	struct wiphy wiphy = {{0}};
	struct ieee80211_hw hw = {&wiphy};
	struct device device = {0};
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		const struct kase *k = &cases[c];
		if (k->image >= n_images)
			abort();
		for (u32 i = 0; i < sizeof(memory); i++)
			memory[i] = (u8)(i * 37 + 11);
		for (u32 i = 0; i < sizeof(xtal); i++)
			xtal[i] = (u8)(i * 29 + 0x47);
		xtal_stuck = k->xtal_stuck;
		nctl_stuck = k->nctl_stuck;
		h2c_refuse_at = k->refuse_at;
		h2c_calls = 0;
		segment_bytes = 0;
		n_warns = 0;
		struct firmware fw = {images[k->image], sizes[k->image]};
		static struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip;
		dev.io = &raw_io;
		dev.hal.cv = (u8)k->cv;
		dev.efuse.rfe_type = (u8)k->rfe;
		dev.fw.req.firmware = &fw;
		dev.fw.h2c_seq = (u8)k->seq0;
		dev.mac.qta_mode = RTW89_QTA_SCC;
		dev.dev = &device;
		dev.hw = &hw;
		logging = 0;
		if (rtw89_fw_recognize_elements(&dev))
			abort();
		logging = 1;
		record(50, 0, 0);
		rtw89_phy_init_bb_afe(&dev);
		flush();
		record(50, 1, 0);
		int ret = rtw89_chip_reset_bb_rf(&dev);
		flush();
		record(11, 0, (u32)ret);
		if (!ret) {
			record(50, 2, 0);
			rtw89_phy_init_bb_reg(&dev);
			flush();
			record(50, 3, 0);
			rtw89_chip_bb_postinit(&dev);
			flush();
			record(50, 4, 0);
			rtw89_phy_init_rf_reg(&dev, false);
			flush();
			record(50, 5, 0);
			rtw89_phy_init_rf_nctl(&dev);
			flush();
			u8 gain[sizeof(dev.bb_gain.ax) + 3] = {0};
			memcpy(gain, &dev.bb_gain.ax, sizeof(dev.bb_gain.ax));
			for (u32 i = 0; i < (sizeof(dev.bb_gain.ax) + 3) / 4; i++)
				record(60, i, (u32)gain[4 * i] | (u32)gain[4 * i + 1] << 8 |
					      (u32)gain[4 * i + 2] << 16 | (u32)gain[4 * i + 3] << 24);
		}
		record(24, dev.fw.h2c_seq, 0);
		out32(out, (u32)segment_bytes);
		if (segment_bytes && fwrite(segment, segment_bytes, 1, out) != 1)
			abort();
		release(&dev);
	}
	if (fclose(out))
		abort();
	for (size_t i = 0; i < n_images; i++)
		free(images[i]);
	free(images);
	free(sizes);
	free(segment);
	printf("{\"cases\": %zu, \"gain_bytes\": %zu}\n", ARRAY_SIZE(cases),
	       sizeof(struct rtw89_phy_bb_gain_info));
	return 0;
}
'''
    chip_c = '\n'.join([
        f'#define CHIP_ID {chip["chip_id"]}',
        f'#define SUPPORT_BANDS ({chip["support_bands"]})',
        f'#define NEEDED_FW_ELMS ({chip["needed_fw_elms"]})',
    ])
    program = '\n\n'.join([
        preamble, reg_h, head_defines, declarations, harness, phy_types, core_h, phy_h, mac_h,
        bx_h, mac_c, bx_c, b_c, fw_h2c, phy_c, fw_types, fw_elements, chip_c, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member', str(generated), '-o', str(exe)],
                   check=True)

    pinned = image.read_bytes()
    syn = synthetic_image(pinned)
    syn_path = out / 'syn-phy.bin'
    syn_path.write_bytes(syn)
    trace_path = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace_path), str(image), str(syn_path)], check=True,
                         capture_output=True, text=True)
    result = json.loads(run.stdout)
    if result['cases'] != len(CASES):
        raise ValueError(result)

    trace = trace_path.read_bytes()
    offset = 0
    outcomes = []
    for case in CASES:
        length = struct.unpack_from('<I', trace, offset)[0]
        body = trace[offset + 4:offset + 4 + length]
        offset += 4 + length
        tags = [struct.unpack_from('<III', body, i) for i in range(0, len(body), 12)]
        count = lambda f: sum(1 for t in tags if f(t))
        outcomes.append(dict(
            image=case[0], rfe=case[1], cv=case[2], xtal_stuck=case[3], nctl_stuck=case[4],
            refuse_at=case[5], seq0=case[6], bytes=length,
            reads=count(lambda t: t[0] in (1, 2, 4)), writes=count(lambda t: t[0] in (5, 6, 8)),
            delays=count(lambda t: t[0] == 9), h2c=count(lambda t: t[0] == 40),
            warnings=[WARNINGS[t[1]] for t in tags if t[0] == 70],
            reset=[t[2] - (1 << 32) if t[2] & 0x80000000 else t[2] for t in tags if t[0] == 11]))
    if offset != len(trace):
        raise ValueError('trace has trailing bytes')

    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=len(CASES), outcomes=outcomes,
        image=dict(path=str(image.resolve()), bytes=len(pinned),
                   sha256=hashlib.sha256(pinned).hexdigest()),
        synthetic={'syn-phy': hashlib.sha256(syn).hexdigest()},
        dispatch=dict(rtw8852b_chip_info=chip, rtw8852b_chip_ops=ops, rtw8852bx_info=bx_info,
                      rtw89_phy_gen_ax=phy_gen, rtw89_mac_gen_ax=mac_gen, rtw89_raw_io=raw_io),
        gain_bytes=result['gain_bytes'],
        trace_bytes=len(trace), trace_sha256=hashlib.sha256(trace).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'the register model answers SWSI as never busy and every XTAL SI request at once; '
            'the NCTL report reads as written unless stuck',
            'read_poll_timeout and its atomic form are modeled counted in steps; udelay, mdelay '
            'and fsleep are recorded, not slept',
            'rtw89_h2c_tx is a stub recording the skb; the CH12 path is the H2C oracle\'s',
            'needed_fw_elms is taken without __RTW89_FW_ELEMENT_ID_INTL_TRANSITION, as the '
            'elements oracle takes it; DBCC is off and no case reaches PHY 1 or BB MCU paths',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
