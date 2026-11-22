#!/usr/bin/env python3
"""Unchanged pinned rtw89 firmware element recognition for an RTL8852B.

Usage: script REFERENCE_DIRECTORY RTL8852B_IMAGE OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks; RTL8852B_IMAGE is the pinned
rtw89/rtw8852b_fw-2.bin. Extracted unchanged, each with its SHA-256 in
manifest.json:

- fw.c: rtw89_fw_recognize_elements, __fw_element_handlers and every
  handler in it (__rtw89_fw_recognize_from_elm, rtw89_build_phy_tbl_from_elm,
  rtw89_fw_recognize_txpwr_from_elm, rtw89_build_txpwr_trk_tbl_from_elm,
  rtw89_build_rfk_log_fmt_from_elm, rtw89_recognize_regd_from_elm with
  rtw89_regd_entcpy and rtw89_for_each_in_regd_element,
  rtw89_build_afe_pwr_seq_from_elm, rtw89_recognize_diag_mac_from_elm,
  rtw89_build_tx_comp_from_elm), union rtw89_fw_element_arg and struct
  rtw89_fw_element_handler; rtw89_mfw_get_size with rtw89_mfw_get_hdr_ptr
  and rtw89_mfw_validate_hdr; rtw89_fw_update_ver with its v0 and v1
  parsers;
- fw.h: the element ids, header and payload structs, the needed-element
  masks, the TX power tracking types, struct rtw89_fw_regd_entry, the MFW
  and firmware header structs and the FW_HDR_* defines; core.h and phy.h:
  the enums, struct rtw89_phy_table, rtw89_txpwr_conf, rtw89_regd,
  rtw89_regd_data, rtw89_fw_suit, rtw89_fw_elm_info,
  rtw89_phy_rfk_log_fmt and rtw89_fw_suit_get.

rtw8852b_chip_info gives chip_id, support_bands and needed_fw_elms, each
checked; needed_fw_elms is taken with its transition bit cleared, as the
Rust port refuses firmware that lacks a needed element. struct
rtw89_rfe_data is the harness's, its conf members alone, which is all the
TX power handler reaches through the table's offsets. The radio tables'
config callbacks are stubs, told apart by address. Everything is compiled
with clang under ASan and UBSan; every image is read into an allocation of
its exact size, so a handler reading past a file would stop the run.

The harness wraps each handler in the unchanged table, by #defines in
force for the table alone, to record what it returned for each element.

Cases: the pinned image for RFE types 0 to 15, 51 and 255 (AID 0, CV 1,
as an RTL8852B CBV has); then synthetic containers, each written to the
output directory as <name>.bin: syn-all (every handler, the selection by
AID, RFE type and CV, odd sizes, unknown ids, a TX power table reading past
its element, a regulation map with short and long entries and unknown
rules) for (RFE 3, AID 0, CV 1), (RFE 5, AID 0x1234, CV 1) and (RFE 7,
AID 0, CV 0); syn-missing, syn-truncated (the needed tracking element's
size reaching the file's end), syn-trk-bitmap, syn-trk-overflow,
syn-regd-invalid, syn-bbmcu-header, syn-legacy (no container) and syn-tail
(fewer than a header's bytes after the last element), each for RFE 1.

trace.bin: per case, a segment (prefixed by its byte length) of
little-endian u32: image index, RFE type, AID, CV,
rtw89_fw_recognize_elements' return and the number of handler records;
per record the element's id, size, ver (its four bytes as one LE word),
aid and the handler's return; then, when the return is 0, per table
(0 bb_tbl, 1 bb_gain, 2-5 rf_radio[0-3], 6 rf_nctl, 7-21 the TX power
confs in struct rtw89_rfe_data's order, 22 txpwr_trk, 23 regd, 24 afe,
25 diag_mac, 26 tx_comp, 27 rfk_log_fmt, 28 bbmcu0, 29 bbmcu1, 30 whether
rfe_data was allocated): its id, count (0xffffffff when absent), the byte
length of its serialization and the serialization's SHA-256. For the
pinned image at RFE 1, a second segment holds each table's id, count, byte
length and the serialization itself, zero-padded to four.

Serializations (LE u32 unless stated; offsets from the file's start):
register tables: rf_path, config (0 none, 1 rtw89_phy_config_rf_reg_v1,
2 rtw89_phy_config_rf_reg), then addr and data per register; count n_regs.
TX power confs: rfe_type, ent_sz, the data's offset, then num_ents * ent_sz
data bytes; count num_ents. Tracking: per type the delta's offset or
0xffffffff, then each present type's rows (4, 3 or 1 subbands of 30
bytes); count the present types. Regulation: per entry alpha2[0..3],
txpwr_regd[0..3], func_bitmap's low byte and a zero byte; count nr. AFE,
DIAG_MAC and TX_COMP: the header's offset; count the element's size. RFK
log formats: per rfk_id the header's offset or 0xffffffff; count those
set. BB MCU suits: data's offset and hdr_ver; count size. rfe_data: 1 when
allocated, else 0; count 0.
"""
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
ABSENT = 0xffffffff
PINNED_RFE_TYPES = list(range(16)) + [51, 255]
FULL_RFE = 1


def element(eid, fixed=bytes(8), body=b'', ver=b'\x01\x02\x03\x04', aid=0, size=None):
    """A struct rtw89_fw_element_hdr and its body."""
    assert len(fixed) == 8
    return struct.pack('<II4sHHII', eid, len(body) if size is None else size, ver, aid, 0, 0,
                       0) + fixed + body


def pattern(n, seed):
    return bytes((i * 37 + seed * 11 + 5) & 0xff for i in range(n))


def regs(n, seed):
    return b''.join(struct.pack('<II', 0x4000 + 4 * i + seed * 0x100, 0xa5000000 + i * 3 + seed)
                    for i in range(n))


def txpwr(eid, rfe, ent_sz, num, seed, aid=0, size=None, body=None):
    body = pattern(num * ent_sz, seed) if body is None else body
    return element(eid, bytes([0, 0, rfe, ent_sz]) + struct.pack('<I', num), body, aid=aid,
                   size=size)


def trk(bitmap, rows, size=None):
    return element(18, struct.pack('<II', bitmap, 0), pattern(rows * 30, 99), size=size)


def regd(ent_sz, entries, num=None):
    body = b''.join(entries)
    return element(20, bytes([0, 0, 0, ent_sz]) + struct.pack(
        '<I', len(entries) if num is None else num), body)


def bbmcu(eid, cv, hdr_ver):
    body = bytearray(pattern(48, cv + 7 * eid))
    body[15] = hdr_ver
    return element(eid, bytes([cv]) + bytes(7), bytes(body))


def container(pieces, legacy=False):
    """An MFW container of one 37-byte entry, its elements at 16-byte
    boundaries of the file, as rtw89 walks them."""
    if legacy:
        data = bytearray(b'\x00' + pattern(200, 1))
    else:
        data = bytearray(bytes([0xff, 1, 0, 0, 0, 29, 29, 18]) + bytes(8))
        data += struct.pack('<BBBBIII', 1, 5, 0, 0, 32, 37, 0) + pattern(37, 2)
    for piece in pieces:
        data += bytes(-len(data) % 16)
        data += piece
    return bytes(data)


def required(trk_piece=None):
    """Every element of RTL8852B's needed_fw_elms, RFE type 0."""
    return [
        element(2, body=regs(4, 1)),
        element(4, bytes([0]) + bytes(7), regs(3, 2)),
        element(5, bytes([1]) + bytes(7), regs(3, 3)),
        element(8, body=regs(2, 4)),
        trk(0xfff0, 20) if trk_piece is None else trk_piece,
        txpwr(9, 0, 9, 2, 5),
        txpwr(10, 0, 7, 3, 6),
        txpwr(11, 0, 7, 3, 7),
        txpwr(13, 0, 5, 2, 8),
        txpwr(14, 0, 5, 2, 9),
        txpwr(16, 0, 4, 2, 10),
        txpwr(17, 0, 3, 2, 11),
    ]


def regd_entry(alpha2, r2, r5, r6, fmap, extra=b''):
    return alpha2 + bytes([r2, r5, r6]) + struct.pack('<I', fmap) + extra


def synthetic():
    all_pieces = [
        element(31, body=pattern(5, 1)),
        element(2, body=regs(2, 10), aid=0x1234),
        element(2, body=regs(3, 11)),
        element(2, body=regs(1, 12)),
        element(3, body=regs(2, 13) + b'\x11\x22\x33\x44'),
        element(4, bytes([0]) + bytes(7), regs(2, 14)),
        element(5, bytes([1]) + bytes(7), regs(2, 15)),
        element(6, bytes([3]) + bytes(7), regs(1, 16)),
        element(7, bytes([2]) + bytes(7), regs(1, 17)),
        element(8, body=regs(1, 18)),
        bbmcu(0, 5, 0),
        bbmcu(0, 1, 1),
        bbmcu(0, 0, 0),
        bbmcu(1, 0, 0),
        txpwr(9, 0, 9, 2, 20),
        txpwr(9, 3, 9, 1, 21),
        txpwr(9, 0, 9, 3, 22),
        txpwr(9, 3, 9, 2, 23, aid=0x1234),
        txpwr(10, 7, 7, 2, 24),
        # Four entries of seven bytes in a body of fourteen: the conf reads
        # into the next element.
        txpwr(11, 0, 7, 4, 25, body=pattern(14, 25)),
        txpwr(13, 3, 0, 5, 26, body=b''),
        txpwr(14, 0, 5, 2, 27),
        txpwr(16, 0, 4, 1, 28),
        txpwr(17, 3, 3, 2, 29),
        txpwr(17, 0, 3, 1, 30),
        txpwr(12, 0, 8, 1, 31),
        txpwr(21, 3, 7, 1, 32),
        txpwr(25, 0, 5, 1, 33),
        trk(0x1fff0, 20),
        element(19, bytes([1, 0, 0, 0, 2, 0, 0, 0]), pattern(6, 40)),
        element(19, bytes([1, 0, 0, 0, 20, 0, 0, 0]), pattern(4, 41)),
        regd(5, [regd_entry(b'ID', 1, 2, 16, 0)[:5], regd_entry(b'US', 2, 2, 2, 0)[:5],
                 regd_entry(b'\xff\x00', 17, 4, 0, 0)[:5]]),
        regd(12, [regd_entry(b'ID', 0, 1, 2, 0xffffffff, b'\x01\x02\x03'),
                  regd_entry(b'JP', 3, 3, 3, 2, b'\x04\x05\x06')]),
        regd(9, [regd_entry(b'XX', 0, 0, 0, 0)], num=300),
        element(27, body=pattern(13, 50)),
        element(28, body=pattern(40, 51)),
        element(28, body=pattern(3, 52)),
        element(29, bytes([9]) + bytes(7), pattern(8, 53)),
        element(29, bytes([0]) + bytes(7), pattern(8, 54), aid=0x1234),
        element(29, bytes([0]) + bytes(7), pattern(8, 55)),
        element(29, bytes([7]) + bytes(7), pattern(8, 56)),
        element(200, body=pattern(1, 57)),
    ]
    base = required()
    truncated = required()[:4] + required()[5:]
    last = trk(0xfff0, 20)
    # The size reaches the file's end, though the bytes stop 32 short of it.
    truncated.append(last[:4] + struct.pack('<I', 640) + last[8:])
    images = [
        ('syn-all', container(all_pieces), [(3, 0, 1), (5, 0x1234, 1), (7, 0, 0)]),
        ('syn-missing', container([element(2, body=regs(4, 1)),
                                   element(4, bytes(8), regs(3, 2)),
                                   element(8, body=regs(2, 4)), txpwr(9, 0, 9, 2, 5)]),
         [(1, 0, 1)]),
        ('syn-truncated', container(truncated), [(1, 0, 1)]),
        ('syn-trk-bitmap', container(required(trk(0xfef0, 19))), [(1, 0, 1)]),
        ('syn-trk-overflow', container(required(
            element(18, struct.pack('<II', 0xfff0, 0), pattern(599, 3)))), [(1, 0, 1)]),
        ('syn-regd-invalid', container(base + [regd(0, [bytes(3)], num=2)]), [(1, 0, 1)]),
        ('syn-bbmcu-header', container(base + [bbmcu(1, 0, 2)]), [(1, 0, 1)]),
        ('syn-legacy', container([], legacy=True), [(1, 0, 1)]),
        ('syn-tail', container(base) + bytes(-len(container(base)) % 16) + pattern(20, 60),
         [(1, 0, 1)]),
    ]
    return images


def element_list(data):
    """The pinned image's elements as rtw89's walk reaches them."""
    nr = data[1]
    shift, size = struct.unpack_from('<II', data, 16 + (nr - 1) * 16 + 4)
    offset = (shift + size + 15) & ~15
    found = []
    while offset + 32 < len(data):
        eid, esize = struct.unpack_from('<II', data, offset)
        if offset + esize >= len(data):
            break
        entry = dict(offset=offset, id=eid, size=esize, ver=data[offset + 8:offset + 12].hex(),
                     aid=struct.unpack_from('<H', data, offset + 12)[0])
        fixed = data[offset + 24:offset + 32]
        if 9 <= eid <= 17 or 21 <= eid <= 26:
            entry.update(rfe_type=fixed[2], ent_sz=fixed[3],
                         num_ents=struct.unpack_from('<I', fixed, 4)[0])
        elif 4 <= eid <= 7:
            entry.update(idx=fixed[0])
        elif eid == 18:
            entry.update(bitmap='%08x' % struct.unpack_from('<I', fixed, 0)[0])
        elif eid == 20:
            entry.update(ent_sz=fixed[3], num_ents=struct.unpack_from('<I', fixed, 4)[0])
        found.append(entry)
        offset = (offset + 32 + esize + 15) & ~15
    return found


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
        lines = []
        for name in names:
            found = re.findall(r'^#define ' + re.escape(name) + r'\b[^\n]*$', text, re.M)
            if len(found) != 1:
                raise ValueError(f'{file}: #define {name} appears {len(found)} times')
            lines.append(found[0])
        return record(file, f'#define {" ".join(names)}', '\n'.join(lines))

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

    chip = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  ['chip_id', 'support_bands', 'needed_fw_elms', 'bbmcu_nr'])
    expected_chip = {
        'chip_id': 'RTL8852B',
        'support_bands': 'BIT(NL80211_BAND_2GHZ) | BIT(NL80211_BAND_5GHZ)',
        'needed_fw_elms': 'RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_NO_6GHZ | '
                          'BIT(__RTW89_FW_ELEMENT_ID_INTL_TRANSITION)',
        'bbmcu_nr': '0',
    }
    if chip != expected_chip:
        raise ValueError(f'rtw8852b_chip_info is {chip}')

    core_defines = defines('core.h', ['DELTA_SWINGIDX_SIZE', 'RF_PATH_MAX',
                                      'RTW89_TXPWR_CONF_DFLT_RFE_TYPE',
                                      'RTW89_REGD_MAX_COUNTRY_NUM'])
    core_macros = macro('core.h', 'rtw89_txpwr_conf_valid')
    fw_defines = '\n'.join([
        defines('fw.h', ['RTW89_MFW_SIG', 'RTW89_FW_ELEMENT_ALIGN']),
        lines('fw.h', '#define FW_HDR_', 'FW_HDR_* defines'),
    ])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_rf_path'),
        declaration('core.h', 'enum', 'rtw89_band'),
        declaration('core.h', 'enum', 'rtw89_regulation_type'),
        declaration('core.h', 'enum', 'rtw89_regd_func'),
        declaration('core.h', 'enum', 'rtw89_fw_type'),
        declaration('phy.h', 'enum', 'rtw89_phy_c2h_rfk_log_func'),
        declaration('core.h', 'struct', 'rtw89_reg2_def'),
        declaration('core.h', 'struct', 'rtw89_phy_table'),
        declaration('core.h', 'struct', 'rtw89_txpwr_conf'),
        declaration('core.h', 'struct', 'rtw89_regd'),
        declaration('core.h', 'struct', 'rtw89_regd_data'),
        declaration('core.h', 'struct', 'rtw89_fw_suit'),
        declaration('fw.h', 'struct', 'rtw89_mfw_info'),
        declaration('fw.h', 'struct', 'rtw89_mfw_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_section'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_section_v1'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_v1'),
        declaration('fw.h', 'enum', 'rtw89_fw_element_id'),
        '\n'.join(macro('fw.h', name) for name in [
            'BITS_OF_RTW89_TXPWR_FW_ELEMENTS_TX_SHAPE',
            'BITS_OF_RTW89_TXPWR_FW_ELEMENTS_NO_6GHZ',
            'RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_BASE',
            'RTW89_AX_GEN_DEF_NEEDED_FW_ELEMENTS_NO_6GHZ']),
        declaration('fw.h', 'struct', '__rtw89_fw_txpwr_element'),
        declaration('fw.h', 'struct', '__rtw89_fw_regd_element'),
        declaration('fw.h', 'enum', 'rtw89_fw_txpwr_trk_type'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_track_cfg'),
        '\n'.join(macro('fw.h', f'RTW89_DEFAULT_NEEDED_FW_TXPWR_TRK_{band}GHZ')
                  for band in ['6', '5', '2']),
        declaration('fw.h', 'struct', 'rtw89_fw_element_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_regd_entry'),
        declaration('phy.h', 'struct', 'rtw89_phy_rfk_log_fmt'),
        declaration('core.h', 'struct', 'rtw89_fw_elm_info'),
    ])
    fw_types = '\n\n'.join([
        declaration('fw.c', 'union', 'rtw89_fw_element_arg'),
        declaration('fw.c', 'struct', 'rtw89_fw_element_handler'),
    ])
    suit_get = locate('core.h', 'rtw89_fw_suit_get')[1]
    handlers = ['__rtw89_fw_recognize_from_elm', 'rtw89_build_phy_tbl_from_elm',
                'rtw89_fw_recognize_txpwr_from_elm', 'rtw89_build_txpwr_trk_tbl_from_elm',
                'rtw89_build_rfk_log_fmt_from_elm', 'rtw89_recognize_regd_from_elm',
                'rtw89_build_afe_pwr_seq_from_elm', 'rtw89_recognize_diag_mac_from_elm',
                'rtw89_build_tx_comp_from_elm']
    fw_c = '\n\n'.join([
        macro('fw.c', 'rtw89_for_each_in_regd_element'),
        in_order('fw.c', ['rtw89_mfw_get_hdr_ptr', 'rtw89_mfw_validate_hdr',
                          'rtw89_mfw_get_size', 'rtw89_fw_update_ver_v0',
                          'rtw89_fw_update_ver_v1', 'rtw89_fw_update_ver',
                          'rtw89_regd_entcpy'] + handlers),
    ])
    table = definition('fw.c',
                       'static const struct rtw89_fw_element_handler __fw_element_handlers[]')
    recognize = locate('fw.c', 'rtw89_fw_recognize_elements')[1]
    tracing = '\n'.join(
        [f'TRACED({name})' for name in handlers]
        + [f'#define {name} traced_{name}' for name in handlers])
    untracing = '\n'.join(f'#undef {name}' for name in handlers)

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
#define __packed __attribute__((packed))
#define __counted_by(m)
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define le32_get_bits(v, m) u32_get_bits(v, m)
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
static void set_bit(long nr, unsigned long *addr) { addr[nr / 64] |= 1UL << (nr % 64); }
#define GFP_KERNEL 0
#define kzalloc_obj(x, ...) ((__typeof__(&(x)))calloc(1, sizeof(x)))
#define kzalloc_objs(x, n, ...) ((__typeof__(&(x)))calloc((n), sizeof(x)))
#define kfree(p) free((void *)(p))
#define devm_kzalloc(d, size, gfp) calloc(1, (size))
#define devm_kfree(d, p) free((void *)(p))
#define RTW89_DBG_REGD BIT(8)
#define RTW89_DBG_FW BIT(12)
/* rtw89's log helpers are calls in the kernel: their arguments are
 * evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
/* Kernel types the declarations name. */
enum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_60GHZ,
		    NL80211_BAND_6GHZ };
struct device { int unused; };
struct firmware { const u8 *data; size_t size; };
struct wiphy { char fw_version[32]; };
struct ieee80211_hw { struct wiphy *wiphy; };
struct rtw89_dev;
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
/* The members of rtw89's device the extracted functions reach. */
struct rtw89_hal { u8 cv; u16 aid; };
struct rtw89_efuse { u8 rfe_type; };
struct rtw89_fw_req_info { const struct firmware *firmware; };
struct rtw89_fw_log { struct rtw89_fw_suit suit; };
struct rtw89_fw_info {
	struct rtw89_fw_req_info req;
	struct rtw89_fw_suit normal, wowlan, bbmcu0, bbmcu1;
	struct rtw89_fw_log log;
	struct rtw89_fw_elm_info elm_info;
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	u32 support_bands;
	u32 needed_fw_elms;
};
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	struct rtw89_hal hal;
	struct rtw89_efuse efuse;
	struct rtw89_fw_info fw;
	struct rtw89_rfe_data *rfe_data;
	struct device *dev;
	struct ieee80211_hw *hw;
};
/* The radio tables' config callbacks, told apart by address. */
void rtw89_phy_config_rf_reg(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
			     enum rtw89_rf_path rf_path, void *data)
{
	(void)rtwdev; (void)reg; (void)rf_path; (void)data; abort();
}
void rtw89_phy_config_rf_reg_v1(struct rtw89_dev *rtwdev, const struct rtw89_reg2_def *reg,
				enum rtw89_rf_path rf_path, void *data)
{
	(void)rtwdev; (void)reg; (void)rf_path; (void)data; abort();
}
'''
    trace_c = r'''
/* What each handler returned, per element, in the walk's order. */
static u32 records[4096][5];
static u32 n_records;
static int traced(const struct rtw89_fw_element_hdr *e, int ret)
{
	if (n_records == ARRAY_SIZE(records))
		abort();
	u32 *r = records[n_records++];
	r[0] = le32_to_cpu(e->id);
	r[1] = le32_to_cpu(e->size);
	memcpy(&r[2], e->ver, 4);
	r[3] = le16_to_cpu(e->aid);
	r[4] = (u32)ret;
	return ret;
}
#define TRACED(fn) \
static int traced_##fn(struct rtw89_dev *d, const struct rtw89_fw_element_hdr *e, \
		       const union rtw89_fw_element_arg a) \
{ \
	return traced(e, fn(d, e, a)); \
}
'''
    cases = []
    for rfe in PINNED_RFE_TYPES:
        cases.append((0, rfe, 0, 1, int(rfe == FULL_RFE)))
    images = synthetic()
    for index, (_, _, runs) in enumerate(images, 1):
        for rfe, aid, cv in runs:
            cases.append((index, rfe, aid, cv, 0))
    case_table = ',\n'.join('\t{%d, %d, %d, %d, %d}' % case for case in cases)
    main_c = r'''
struct kase { u32 image, rfe, aid, cv, full; };
static const struct kase cases[] = {
''' + case_table + r'''
};
static u8 *buf;
static size_t blen, bcap;
static void putb(const void *p, size_t n)
{
	if (blen + n > bcap) {
		bcap = (blen + n) * 2;
		buf = realloc(buf, bcap);
		if (!buf)
			abort();
	}
	memcpy(buf + blen, p, n);
	blen += n;
}
static void put32(u32 v) { putb(&v, 4); }
static void out32(FILE *o, u32 v)
{
	if (fwrite(&v, 4, 1, o) != 1)
		abort();
}
static void emit(FILE *o, u32 t, u32 count)
{
	out32(o, t);
	out32(o, count);
	out32(o, (u32)blen);
	if (blen && fwrite(buf, blen, 1, o) != 1)
		abort();
	blen = 0;
}
static void absent(FILE *o, u32 t)
{
	blen = 0;
	emit(o, t, 0xffffffff);
}
static const u8 *file;
static u32 at(const void *p) { return (u32)((const u8 *)p - file); }
static void phy(FILE *o, u32 t, const struct rtw89_phy_table *tbl)
{
	if (!tbl)
		return absent(o, t);
	put32(tbl->rf_path);
	put32(!tbl->config ? 0 : tbl->config == rtw89_phy_config_rf_reg_v1 ? 1 :
	      tbl->config == rtw89_phy_config_rf_reg ? 2 : 3);
	for (u32 i = 0; i < tbl->n_regs; i++) {
		put32(tbl->regs[i].addr);
		put32(tbl->regs[i].data);
	}
	emit(o, t, tbl->n_regs);
}
static const size_t conf_offsets[] = {
	offsetof(struct rtw89_rfe_data, byrate.conf),
	offsetof(struct rtw89_rfe_data, lmt_2ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_5ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_6ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_2ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_5ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_6ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_ru_2ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_ru_5ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_ru_6ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_ru_2ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_ru_5ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_ru_6ghz.conf),
	offsetof(struct rtw89_rfe_data, tx_shape_lmt.conf),
	offsetof(struct rtw89_rfe_data, tx_shape_lmt_ru.conf),
};
static u32 subbands(u32 type)
{
	return type <= __RTW89_FW_TXPWR_TRK_TYPE_6GHZ_MAX ? 4 :
	       type <= __RTW89_FW_TXPWR_TRK_TYPE_5GHZ_MAX ? 3 : 1;
}
static void element_ref(FILE *o, u32 t, const struct rtw89_fw_element_hdr *e)
{
	if (!e)
		return absent(o, t);
	put32(at(e));
	emit(o, t, le32_to_cpu(e->size));
}
static void suit(FILE *o, u32 t, const struct rtw89_fw_suit *s)
{
	if (!s->data)
		return absent(o, t);
	put32(at(s->data));
	put32(s->hdr_ver);
	emit(o, t, s->size);
}
static void tables(FILE *o, struct rtw89_dev *dev)
{
	const struct rtw89_fw_elm_info *elm = &dev->fw.elm_info;
	phy(o, 0, elm->bb_tbl);
	phy(o, 1, elm->bb_gain);
	for (u32 i = 0; i < RF_PATH_MAX; i++)
		phy(o, 2 + i, elm->rf_radio[i]);
	phy(o, 6, elm->rf_nctl);
	for (u32 i = 0; i < ARRAY_SIZE(conf_offsets); i++) {
		const struct rtw89_txpwr_conf *conf;
		if (!dev->rfe_data) {
			absent(o, 7 + i);
			continue;
		}
		conf = (const void *)((const u8 *)dev->rfe_data + conf_offsets[i]);
		if (!rtw89_txpwr_conf_valid(conf)) {
			absent(o, 7 + i);
			continue;
		}
		put32(conf->rfe_type);
		put32(conf->ent_sz);
		put32(at(conf->data));
		putb(conf->data, (size_t)conf->num_ents * conf->ent_sz);
		emit(o, 7 + i, conf->num_ents);
	}
	if (elm->txpwr_trk) {
		u32 n = 0;
		for (u32 t = 0; t < RTW89_FW_TXPWR_TRK_TYPE_NR; t++) {
			const void *d = elm->txpwr_trk->delta[t];
			put32(d ? at(d) : 0xffffffff);
			n += !!d;
		}
		for (u32 t = 0; t < RTW89_FW_TXPWR_TRK_TYPE_NR; t++)
			if (elm->txpwr_trk->delta[t])
				putb(elm->txpwr_trk->delta[t], subbands(t) * DELTA_SWINGIDX_SIZE);
		emit(o, 22, n);
	} else {
		absent(o, 22);
	}
	if (elm->regd) {
		for (u32 i = 0; i < elm->regd->nr; i++) {
			const struct rtw89_regd *r = &elm->regd->map[i];
			u8 tail[2] = {(u8)r->func_bitmap[0], 0};
			putb(r->alpha2, 3);
			putb(r->txpwr_regd, 3);
			putb(tail, 2);
		}
		emit(o, 23, elm->regd->nr);
	} else {
		absent(o, 23);
	}
	element_ref(o, 24, elm->afe);
	element_ref(o, 25, elm->diag_mac);
	element_ref(o, 26, elm->tx_comp);
	if (elm->rfk_log_fmt) {
		u32 n = 0;
		for (u32 i = 0; i < RTW89_PHY_C2H_RFK_LOG_FUNC_NUM; i++) {
			const void *e = elm->rfk_log_fmt->elm[i];
			put32(e ? at(e) : 0xffffffff);
			n += !!e;
		}
		emit(o, 27, n);
	} else {
		absent(o, 27);
	}
	suit(o, 28, &dev->fw.bbmcu0);
	suit(o, 29, &dev->fw.bbmcu1);
	put32(!!dev->rfe_data);
	emit(o, 30, 0);
}
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
		/* Exactly the file's size, so ASan sees a read past it. */
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
		.support_bands = SUPPORT_BANDS,
		.needed_fw_elms = (NEEDED_FW_ELMS) & ~BIT(__RTW89_FW_ELEMENT_ID_INTL_TRANSITION),
	};
	struct wiphy wiphy = {{0}};
	struct ieee80211_hw hw = {&wiphy};
	struct device device = {0};
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		const struct kase *k = &cases[c];
		if (k->image >= n_images)
			abort();
		struct firmware fw = {images[k->image], sizes[k->image]};
		struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip;
		dev.hal.aid = (u16)k->aid;
		dev.hal.cv = (u8)k->cv;
		dev.efuse.rfe_type = (u8)k->rfe;
		dev.fw.req.firmware = &fw;
		dev.dev = &device;
		dev.hw = &hw;
		file = fw.data;
		n_records = 0;
		int ret = rtw89_fw_recognize_elements(&dev);
		out32(out, k->image);
		out32(out, k->rfe);
		out32(out, k->aid);
		out32(out, k->cv);
		out32(out, (u32)ret);
		out32(out, n_records);
		for (u32 i = 0; i < n_records; i++)
			for (u32 j = 0; j < 5; j++)
				out32(out, records[i][j]);
		tables(out, &dev);
		release(&dev);
	}
	if (fclose(out))
		abort();
	for (size_t i = 0; i < n_images; i++)
		free(images[i]);
	free(images);
	free(sizes);
	free(buf);
	printf("{\"cases\": %zu}\n", ARRAY_SIZE(cases));
	return 0;
}
'''
    chip_c = '\n'.join([
        f'#define CHIP_ID {chip["chip_id"]}',
        f'#define SUPPORT_BANDS ({chip["support_bands"]})',
        f'#define NEEDED_FW_ELMS ({chip["needed_fw_elms"]})',
    ])
    program = '\n\n'.join([
        preamble, core_defines, core_macros, fw_defines, declarations, harness, suit_get,
        fw_types, fw_c, trace_c, tracing, table, untracing, recognize, chip_c, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member', str(generated), '-o', str(exe)],
                   check=True)

    paths = [image]
    for name, data, _ in images:
        path = out / f'{name}.bin'
        path.write_bytes(data)
        paths.append(path)
    raw = out / 'raw.bin'
    run = subprocess.run([str(exe), str(raw)] + [str(p) for p in paths], check=True,
                         capture_output=True, text=True)
    result = json.loads(run.stdout)
    if result['cases'] != len(cases):
        raise ValueError(result)

    data = raw.read_bytes()
    raw.unlink()
    offset = 0

    def take(n):
        nonlocal offset
        chunk = data[offset:offset + n]
        if len(chunk) != n:
            raise ValueError('raw trace ends early')
        offset += n
        return chunk

    def word():
        return struct.unpack('<I', take(4))[0]

    trace = bytearray()
    outcomes = []
    pinned_tables = {}
    for case in cases:
        header = [word() for _ in range(6)]
        if tuple(header[:4]) != case[:4]:
            raise ValueError(f'case {case}: header {header}')
        records = [word() for _ in range(5 * header[5])]
        segment = struct.pack('<%dI' % (6 + len(records)), *header, *records)
        full = bytearray()
        counts = {}
        for t in range(31):
            tid, count, length = word(), word(), word()
            body = take(length)
            if tid != t:
                raise ValueError(f'case {case}: table {tid} where {t}')
            counts[t] = None if count == ABSENT else count
            if header[4] == 0:
                segment += struct.pack('<3I', t, count, length) + hashlib.sha256(body).digest()
            full += struct.pack('<3I', t, count, length) + body + bytes(-length % 4)
        trace += struct.pack('<I', len(segment)) + segment
        if case[4]:
            trace += struct.pack('<I', len(full)) + full
        ret = header[4] - (1 << 32) if header[4] & 0x80000000 else header[4]
        outcomes.append(dict(image=case[0], rfe=case[1], aid=case[2], cv=case[3], ret=ret,
                             handled=header[5]))
        if case[0] == 0:
            pinned_tables[case[1]] = {
                str(t): count for t, count in counts.items() if count is not None}
    if offset != len(data):
        raise ValueError('raw trace has trailing bytes')
    trace_path = out / 'trace.bin'
    trace_path.write_bytes(bytes(trace))

    pinned = image.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=len(cases),
        images=['pinned'] + [name for name, _, _ in images],
        outcomes=outcomes,
        image=dict(path=str(image.resolve()), bytes=len(pinned),
                   sha256=hashlib.sha256(pinned).hexdigest()),
        pinned_elements=element_list(pinned),
        pinned_table_counts=pinned_tables,
        synthetic={name: hashlib.sha256(blob).hexdigest() for name, blob, _ in images},
        dispatch=dict(rtw8852b_chip_info=chip),
        trace_bytes=len(trace), trace_sha256=hashlib.sha256(trace).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'needed_fw_elms is taken without __RTW89_FW_ELEMENT_ID_INTL_TRANSITION, which '
            'would make rtw89 accept firmware lacking needed elements',
            'struct rtw89_rfe_data is the harness\'s, its conf members alone; the radio '
            'config callbacks are stubs no case calls',
            'no case makes a handler read past its file, which rtw89 does not check and the '
            'Rust port refuses; allocation failures are not modeled',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
