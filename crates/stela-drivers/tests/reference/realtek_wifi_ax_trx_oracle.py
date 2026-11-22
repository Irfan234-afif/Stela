#!/usr/bin/env python3
"""Unchanged pinned rtw89 AX RX descriptor and PPDU status parsing for a PCIe RTL8852B.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. For each synthetic RX buffer the program
runs, with every callee unchanged:

- rtw89_core_query_rxdesc (core.c), RTL8852B's query_rxdesc, at the data
  offset rtw89_pci_rxbd_deliver_skbs passes (sizeof(struct
  rtw89_pci_rxbd_info));
- for a PPDU status, the steps of rtw89_core_rx_process_ppdu_sts before
  rtw89_core_rx_pending_skb, over the skb rtw89_pci_rxbd_deliver_skbs would
  copy (rx_info->len - offset bytes from behind the descriptor):
  rtw89_core_rx_process_mac_ppdu, rtw89_core_rx_process_phy_ppdu with
  rtw89_core_update_phy_ppdu (and its _hdr_v2), and
  rtw89_core_rx_process_phy_sts with rtw89_core_rx_parse_phy_sts,
  rtw89_core_get_phy_status_ie_len, rtw89_core_process_phy_status_ie, the
  IE00, IE01, IE09 and IE10 parsers (and IE00/IE01's BE halves, compiled and
  not reached) and rtw89_chip_convert_rpl_to_rssi, RTL8852B's
  __rtw8852bx_convert_rpl_to_rssi;
- then __rtw8852bx_query_ppdu with rtw8852bx_fill_freq_with_ppdu and
  rtw89_decode_chan_idx (phy.c) on a zeroed RX status;
- and, when the case gives the descriptor of a frame, rtw89_core_rx_ppdu_match
  (with rtw89_rxdesc_to_nl_he_gi, _eht_gi, _he_eht_gi,
  rtw89_check_rx_statu_gi_match, txrx.h's data rate helpers and
  rtw89_hw_to_rate_info_bw) against the frame's RX status, at the case's
  current PPDU count.

The declarations are extracted as spans and each extraction is listed with
its SHA-256 in manifest.json.

The seams, the harness's: the control flow of rtw89_core_rx_process_ppdu_sts
(its three steps and their gotos, copied, with the step that stopped
recorded), the RX status fields rtw89_core_update_rx_status fills that the
match reads (its lines for the rate index by mode, the GI and the bandwidth,
copied), rtw89_phy_cfo_parse and rtw89_phy_antdiv_parse (CFO and antenna
diversity tracking, which change no PPDU field and are stubs),
ieee80211_iterate_stations_atomic (no station), and cfg80211's
ieee80211_channel_to_frequency, which the pinned tree does not hold, written
from net/wireless/util.c for the 2.4, 5 and 6 GHz bands.

The cases, generated from a fixed seed so no case reads past what rtw89
would: 200 descriptors of random words whose type is not a PPDU status, 17
crafted PPDU statuses (the user's AP's beacon status, A1-matched and not,
legacy and CCK rates, five users, a long PLCP header, each failure of the
MAC info, the header and the IE walk, HDR_2_EN, an IE09 followed by eight
zero bytes), and 400
random PPDU statuses of every shape. Each case is one segment prefixed by
its byte length: the buffer's length, the frame descriptor's length (0 for
none) and the current PPDU count, then the buffer and the frame descriptor behind an rxbd_info dword,
each padded to a word, then the count of output words and the words: the
descriptor's 31 fields in rtw89_core_query_rxdesc's order, and for a PPDU
status the step reached (0 parsed, 1 MAC info, 2 PHY header, 3 IE walk), 26
PHY PPDU fields, the RX status's signal, chains, both chain signals,
frequency and band, and for a frame descriptor its rate index, GI,
bandwidth and the match.
"""
import hashlib
import json
import pathlib
import random
import re
import struct
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
SEED = 0x8852_be10


def le32(*words):
    return b''.join(struct.pack('<I', w & 0xffff_ffff) for w in words)


def rxbd_info(length, fs=True, ls=True, tag=0):
    return le32((length & 0x3fff) | (int(fs) << 15) | (int(ls) << 14) | ((tag & 0x1fff) << 16))


def descriptor(pkt_size, pkt_type, *, long=False, mac_info=False, drv_info=0, ppdu_cnt=0,
               rate=0x4, gi=0, bw=0, a1=False, crc=False, frame_type=0, mac_id=0, rest=None):
    dword0 = (pkt_size & 0x3fff) | (int(mac_info) << 23) | ((pkt_type & 0xf) << 24) \
        | ((drv_info & 7) << 28) | (int(long) << 31)
    dword1 = ((ppdu_cnt & 7) << 4) | ((rate & 0x1ff) << 16) | ((gi & 7) << 25) | ((bw & 3) << 30)
    dword3 = int(a1) | (int(crc) << 9)
    words = [dword0, dword1, 0x1234_5678, dword3]
    if long:
        words += rest or [frame_type & 3, (mac_id & 0xff) << 16, 0, 0]
    return le32(*words)


def buffer(desc, drv_info, payload):
    body = desc + b'\xdd' * (8 * drv_info) + payload
    return rxbd_info(4 + len(body)) + body


def mac_info(users, rx_cnt=False, plcp=0, user_words=None):
    w0 = (users & 0xf) | (int(rx_cnt) << 29)
    w1 = (plcp & 0xff) << 16
    out = le32(w0, w1)
    for index in range(users):
        out += le32((user_words or [0x11])[index % len(user_words or [0x11])])
    if users & 1:
        out += le32(0)
    if rx_cnt:
        out += bytes(96)
    out += bytes(8 * plcp)
    return out


IE_LEN = [16, 32, 24, 24, 8, 8, 8, 8, None, 8, None, 176, None, None, None, None,
          None, None, 16, 24, None, None, None, 0, 24, 24, 24, 24, 32, 32, 32, 32]


def ie(kind, body_words=(), var_units=None):
    """One IE of `kind`, its length the table's or `var_units` 8-byte units."""
    length = IE_LEN[kind]
    if length is None:
        length = 8 * var_units
    w0 = kind | ((var_units or 0) & 0x7f) << 5 if IE_LEN[kind] is None else kind
    words = [w0] + list(body_words)
    data = le32(*words)[:length]
    return data + bytes(length - len(data))


def phy_status(ies, ie_map=12, rssi_avg=100, rssi=(110, 104, 0, 0), valid=True, hdr2=False,
               length=None, hdr2_word=0):
    body = (le32(hdr2_word, 0) if hdr2 else b'') + b''.join(ies)
    total = 8 + len(body)
    units = (total >> 3) if length is None else length
    w0 = (ie_map & 0x1f) | (int(hdr2) << 5) | (int(valid) << 7) | ((units & 0xff) << 8) \
        | ((rssi_avg & 0xff) << 24)
    w1 = rssi[0] | rssi[1] << 8 | rssi[2] << 16 | rssi[3] << 24
    return le32(w0, w1) + body


def crafted():
    """(buffer, frame descriptor, current count) cases a reader would write."""
    cases = []
    frame = descriptor(64, 0, long=True, ppdu_cnt=2, rate=0x4, a1=True)
    ie01 = ie(1, [120 << 8 | 0x20 << 16 | 0x3 << 28, 0x00f1_2300, 0x5c08_1234 | 1 << 27, 1 << 8])

    def ppdu(payload, *, mac=True, cnt=2, rate=0x4, a1=True, gi=0, bw=0, drv=0):
        desc = descriptor(len(payload), 1, mac_info=mac, ppdu_cnt=cnt, rate=rate, a1=a1, gi=gi,
                          bw=bw, drv_info=drv)
        return buffer(desc, drv, payload)

    beacon = mac_info(1, user_words=[0x11]) + phy_status([ie01])
    cases.append((ppdu(beacon), frame, 2))
    cases.append((ppdu(beacon, a1=False), frame, 2))
    cases.append((ppdu(beacon, rate=0x1), descriptor(64, 0, long=True, ppdu_cnt=2, rate=0x1,
                                                     a1=True), 2))
    cck = mac_info(2, user_words=[0x10, 0x19]) + phy_status(
        [ie(0, [0x1f0 << 7, 0, 0, 0x3 << 28])], ie_map=11)
    cases.append((ppdu(cck, rate=0x2), descriptor(64, 0, long=True, ppdu_cnt=1, rate=0x2), 1))
    cases.append((ppdu(mac_info(5) + phy_status([ie01])), frame, 2))
    cases.append((ppdu(mac_info(1, plcp=40) + phy_status([ie01])), frame, 2))
    cases.append((ppdu(mac_info(1, plcp=40)[:-320] + phy_status([ie01])), frame, 2))
    cases.append((ppdu(mac_info(1) + phy_status([ie01], valid=False)), frame, 2))
    cases.append((ppdu(mac_info(1) + phy_status([ie01], length=9)), frame, 2))
    cases.append((ppdu(mac_info(1) + phy_status([ie01], ie_map=3)), frame, 2))
    cases.append((ppdu(mac_info(1) + phy_status([ie01, ie(23)])), frame, 2))
    cases.append((ppdu(mac_info(1) + phy_status([ie(12, [], 9)[:16]], length=3)), frame, 2))
    cases.append((ppdu(mac_info(3, rx_cnt=True) + phy_status([ie01], hdr2=True,
                                                            hdr2_word=0x1f << 16)), frame, 2))
    cases.append((ppdu(mac_info(1) + phy_status([ie(9), ie01, bytes(8)])), frame, 2))
    cases.append((ppdu(phy_status([ie01]), mac=False), frame, 7))
    cases.append((ppdu(beacon, gi=6, bw=2, drv=2), descriptor(64, 0, long=True, ppdu_cnt=2,
                                                              gi=6, bw=2, a1=True), 2))
    cases.append((ppdu(beacon, cnt=3), frame, 3))
    return cases


def random_ppdu(rng):
    users = rng.choice([0, 1, 1, 2, 3, 4, 4, 5])
    rx_cnt = rng.random() < 0.3
    plcp = rng.choice([0, 0, 1, 2, 4])
    mac = rng.random() < 0.85
    ies = []
    for _ in range(rng.randint(0, 5)):
        kind = rng.choice([0, 1, 1, 2, 3, 4, 7, 9, 10, 11, 13, 18, 19, 23, 24, 31])
        words = [rng.getrandbits(32) for _ in range(8)]
        words[0] = 0
        units = rng.randint(1, 6) if IE_LEN[kind] is None else None
        ies.append(ie(kind, words[1:], units))
    if rng.random() < 0.1:
        ies.append(bytes(8))
    hdr2 = rng.random() < 0.1
    length = None if rng.random() < 0.9 else rng.randint(0, 40)
    status = phy_status(ies, ie_map=rng.randint(0, 16), rssi_avg=rng.getrandbits(8),
                        rssi=tuple(rng.getrandbits(8) for _ in range(4)),
                        valid=rng.random() < 0.9, hdr2=hdr2, length=length,
                        hdr2_word=rng.getrandbits(32))
    payload = (mac_info(users, rx_cnt, plcp, [rng.getrandbits(32) for _ in range(4)])
               if mac else b'') + status
    if mac and rng.random() < 0.05:
        # MAC info that runs past the report: the PLCP header too long.
        payload = mac_info(min(users, 4), rx_cnt, 255)[:-8 * 255] + status
    rate = rng.choice([0x0, 0x3, 0x4, 0x7, 0x80, 0x95, 0x100, 0x1ab, rng.getrandbits(9)])
    gi = rng.randint(0, 7)
    bw = rng.randint(0, 3)
    cnt = rng.randint(0, 7)
    a1 = rng.random() < 0.6
    drv = rng.choice([0, 0, 1, 3])
    desc = descriptor(len(payload), 1, mac_info=mac, ppdu_cnt=cnt, rate=rate, a1=a1, gi=gi, bw=bw,
                      drv_info=drv)
    frame = b''
    if rng.random() < 0.8:
        same = rng.random() < 0.5
        frame = descriptor(64, 0, long=True, ppdu_cnt=cnt if same else rng.randint(0, 7),
                           rate=rate if same else rng.getrandbits(9),
                           gi=gi if same else rng.randint(0, 7),
                           bw=bw if same else rng.randint(0, 3), a1=True)
    current = rng.choice([cnt, cnt, rng.randint(0, 8), 0xff])
    return buffer(desc, drv, payload), frame, current


def random_desc(rng):
    words = [rng.getrandbits(32) for _ in range(8)]
    while (words[0] >> 24) & 0xf == 1:
        words[0] = rng.getrandbits(32)
    data = le32(*words)
    return rxbd_info(4 + len(data)) + data, b'', rng.randint(0, 255)


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

    def lines(file, first, last):
        """The lines from the one starting `first` through the declaration or
        line starting `last`."""
        text = source(file)
        start = text.index('\n' + first) + 1
        at = text.index('\n' + last, start) + 1
        if text[at:].split('\n', 1)[0].rstrip().endswith('{'):
            end = text.index(';', closing(text, text.index('{', at))) + 1
        else:
            end = text.index('\n', at)
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

    core_defines = defines('core.h', [
        'MASKBYTE0', 'MAX_RSSI', 'RSSI_FACTOR', 'RTW89_RSSI_RAW_TO_DBM', 'PHY_STS_HDR_LEN', 'RF_PATH_MAX',
        'RTW89_MAX_PPDU_CNT', 'RTW89_PPDU_MAC_INFO_USR_SIZE', 'RTW89_PPDU_MAC_INFO_SIZE',
        'RTW89_PPDU_MAC_RX_CNT_SIZE', 'RTW89_PPDU_MAC_RX_CNT_SIZE_V1'])
    phy_defines = defines('phy.h', ['VAR_LEN', 'VAR_LEN_UNIT'])
    common_defines = defines('rtw8852b_common.h', ['RF_PATH_NUM_8852BX'])
    chan_defines = lines('phy.c', '#define RTW89_CH_BASE_IDX_2G', '#define RTW89_CH_OFFSET_MASK')
    declarations = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_core_chip_id', 'rtw89_chip_gen', 'rtw89_core_rx_type', 'rtw89_hw_rate',
            'rtw89_phy_idx', 'rtw89_rf_path', 'rtw89_bandwidth', 'rtw89_gi_ltf']]
        + [declaration('phy.h', 'enum', name) for name in [
            'rtw89_phy_status_ie_type', 'rtw89_phy_status_bitmap']]
        + [declaration('core.h', 'struct', name) for name in [
            'rtw89_rx_desc_info', 'rtw89_rxdesc_short', 'rtw89_rxdesc_long',
            'rtw89_rx_phy_ppdu']])
    txrx = lines('txrx.h', '#define DATA_RATE_MODE_CTRL_MASK', 'struct rtw89_phy_sts_ie10')
    helpers = '\n\n'.join(locate('core.h', name)[1] for name in [
        'rtw89_hw_to_rate_info_bw', 'rtw89_chip_convert_rpl_to_rssi'])
    core = functions('core.c', [
        'rtw89_core_rx_process_mac_ppdu', 'rtw89_core_get_phy_status_ie_len',
        'rtw89_core_parse_phy_status_ie01_v2', 'rtw89_core_parse_phy_status_ie01',
        'rtw89_core_parse_phy_status_ie00', 'rtw89_core_parse_phy_status_ie00_v2',
        'rtw89_core_parse_phy_status_ie09', 'rtw89_core_parse_phy_status_ie10',
        'rtw89_core_process_phy_status_ie', 'rtw89_core_update_phy_ppdu_hdr_v2',
        'rtw89_core_update_phy_ppdu', 'rtw89_core_rx_process_phy_ppdu',
        'rtw89_core_rx_parse_phy_sts', 'rtw89_core_rx_process_phy_sts',
        'rtw89_rxdesc_to_nl_he_gi', 'rtw89_rxdesc_to_nl_eht_gi',
        'rtw89_rxdesc_to_nl_he_eht_gi', 'rtw89_check_rx_statu_gi_match',
        'rtw89_core_rx_ppdu_match', 'rtw89_core_query_rxdesc'])
    phy = (definition('phy.c', 'const u8 rtw89_ch_base_table[16]') + '\n\n'
           + locate('phy.c', 'rtw89_decode_chan_idx')[1])
    common = functions('rtw8852b_common.c', [
        'rtw8852bx_fill_freq_with_ppdu', '__rtw8852bx_query_ppdu',
        '__rtw8852bx_convert_rpl_to_rssi'])

    info_fields = ['chip_id', 'chip_gen', 'rf_path_num', 'ppdu_max_usr', 'cfo_src_fd']
    info = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  info_fields + ['phy_def', 'ops'])
    if (info['phy_def'], info['ops']) != ('&rtw89_phy_gen_ax', '&rtw8852b_chip_ops'):
        raise ValueError(f'rtw8852b_chip_info dispatch is {info}')
    chip_ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                      ['query_ppdu', 'convert_rpl_to_rssi', 'query_rxdesc'])
    if chip_ops != {'query_ppdu': 'rtw8852bx_query_ppdu',
                    'convert_rpl_to_rssi': 'rtw8852bx_convert_rpl_to_rssi',
                    'query_rxdesc': 'rtw89_core_query_rxdesc'}:
        raise ValueError(f'rtw8852b_chip_ops dispatch is {chip_ops}')
    bx = fields('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info',
                ['query_ppdu', 'convert_rpl_to_rssi'])
    if bx != {'query_ppdu': '__rtw8852bx_query_ppdu',
              'convert_rpl_to_rssi': '__rtw8852bx_convert_rpl_to_rssi'}:
        raise ValueError(f'rtw8852bx_info dispatch is {bx}')
    phy_def = fields('phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax',
                     ['physt_ie_len', 'physt_gen'])
    pci = source('pci.c')
    for line in ['\tu32 rxinfo_size = sizeof(struct rtw89_pci_rxbd_info);\n',
                 '\t\trtw89_chip_query_rxdesc(rtwdev, desc_info, skb->data, rxinfo_size);\n',
                 '\tu32 copy_len = rx_info->len - offset;\n']:
        if line not in pci:
            raise ValueError(f'pci.c no longer has {line.strip()}')

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
#define __packed __attribute__((packed))
#define BIT(n) (1U << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define GENMASK_ULL(h, l) ((~0ULL >> (63 - (h))) & (~0ULL << (l)))
#define U8_MAX 0xff
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define le32_get_bits(v, m) FIELD_GET(m, v)
#define u16_get_bits(v, m) ((u16)FIELD_GET(m, v))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define unlikely(x) (x)
#define EXPORT_SYMBOL(...)
static inline s32 sign_extend32(u32 value, int index)
{
	u8 shift = 31 - index;
	return (s32)(value << shift) >> shift;
}
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), sink(__VA_ARGS__))
#define ieee80211_iterate_stations_atomic(hw, iterator, data) ((void)(hw), (void)(data))
struct rtw89_dev;
union rtw89_phy_sts_ie09;
struct rtw89_phy_sts_ie10;
enum nl80211_band { NL80211_BAND_2GHZ = 0, NL80211_BAND_5GHZ = 1, NL80211_BAND_60GHZ = 2,
		    NL80211_BAND_6GHZ = 3 };
enum nl80211_he_gi { NL80211_RATE_INFO_HE_GI_0_8, NL80211_RATE_INFO_HE_GI_1_6,
		     NL80211_RATE_INFO_HE_GI_3_2 };
enum nl80211_eht_gi { NL80211_RATE_INFO_EHT_GI_0_8, NL80211_RATE_INFO_EHT_GI_1_6,
		      NL80211_RATE_INFO_EHT_GI_3_2 };
enum rate_info_bw { RATE_INFO_BW_20 = 0, RATE_INFO_BW_5, RATE_INFO_BW_10, RATE_INFO_BW_40,
		    RATE_INFO_BW_80, RATE_INFO_BW_160, RATE_INFO_BW_HE_RU, RATE_INFO_BW_320,
		    RATE_INFO_BW_EHT_RU };
#define IEEE80211_CONF_MONITOR (1 << 0)
struct ieee80211_conf { u32 flags; };
struct ieee80211_hw { struct ieee80211_conf conf; };
/* The fields of struct ieee80211_rx_status the code here reads or writes. */
struct ieee80211_rx_status {
	u32 freq;
	enum nl80211_band band;
	s8 signal;
	u8 chains;
	s8 chain_signal[4];
	u8 rate_idx;
	u8 he_gi;
	struct { u8 gi; } eht;
	u8 bw;
};
/* cfg80211's ieee80211_channel_to_frequency (net/wireless/util.c), in MHz,
 * for the bands rtw89_decode_chan_idx gives. */
static int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	if (chan <= 0)
		return 0;
	switch (band) {
	case NL80211_BAND_2GHZ:
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
		break;
	case NL80211_BAND_5GHZ:
		if (chan >= 182 && chan <= 196)
			return 4000 + chan * 5;
		else
			return 5000 + chan * 5;
	case NL80211_BAND_6GHZ:
		if (chan == 2)
			return 5935;
		if (chan <= 233)
			return 5950 + chan * 5;
		break;
	default:
		break;
	}
	return 0;
}
'''
    harness = r'''
struct rtw89_phy_gen_def {
	u8 physt_ie_len[32];
	u8 physt_gen;
};
struct rtw89_chip_ops {
	void (*convert_rpl_to_rssi)(struct rtw89_dev *rtwdev, struct rtw89_rx_phy_ppdu *phy_ppdu);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	u8 rf_path_num;
	u8 ppdu_max_usr;
	bool cfo_src_fd;
	const struct rtw89_phy_gen_def *phy_def;
	const struct rtw89_chip_ops *ops;
};
struct rtw89_ppdu_sts_info { u8 curr_rx_ppdu_cnt[RTW89_PHY_NUM]; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	struct ieee80211_hw *hw;
	struct rtw89_ppdu_sts_info ppdu_sts;
};
struct sk_buff { u8 *data; u32 len; };
/* CFO and antenna diversity tracking change no PPDU field. */
static void rtw89_phy_cfo_parse(struct rtw89_dev *rtwdev, s16 cfo_val,
				struct rtw89_rx_phy_ppdu *phy_ppdu)
{
	(void)rtwdev; (void)cfo_val; (void)phy_ppdu;
}
static void rtw89_phy_antdiv_parse(struct rtw89_dev *rtwdev, struct rtw89_rx_phy_ppdu *phy_ppdu)
{
	(void)rtwdev; (void)phy_ppdu;
}
static void __rtw8852bx_convert_rpl_to_rssi(struct rtw89_dev *rtwdev,
					    struct rtw89_rx_phy_ppdu *phy_ppdu);
'''
    tables = (
        'static const struct rtw89_phy_gen_def phy_gen_ax = {\n'
        f'\t.physt_ie_len = {phy_def["physt_ie_len"]},\n'
        f'\t.physt_gen = {phy_def["physt_gen"]},\n'
        '};\nstatic const struct rtw89_chip_ops chip_ops = {\n'
        f'\t.convert_rpl_to_rssi = {bx["convert_rpl_to_rssi"]},\n'
        '};\nstatic const struct rtw89_chip_info chip_info = {\n'
        '\t.phy_def = &phy_gen_ax,\n\t.ops = &chip_ops,\n'
        + ''.join(f'\t.{name} = {info[name]},\n' for name in info_fields)
        + '};\n')
    main_c = r'''
static u32 out_words[256];
static u32 out_count;
static void put(u32 word)
{
	if (out_count >= 256)
		abort();
	out_words[out_count++] = word;
}
static u32 word_at(const u8 *data)
{
	return data[0] | (u32)data[1] << 8 | (u32)data[2] << 16 | (u32)data[3] << 24;
}
static void put_desc(const struct rtw89_rx_desc_info *d)
{
	put(d->pkt_size); put(d->drv_info_size); put(d->long_rxdesc); put(d->pkt_type);
	put(d->mac_info_valid); put(d->bw); put(d->data_rate); put(d->gi_ltf); put(d->user_id);
	put(d->sr_en); put(d->ppdu_cnt); put(d->ppdu_type); put(d->free_run_cnt);
	put(d->icv_err); put(d->crc32_err); put(d->hw_dec); put(d->sw_dec); put(d->addr1_match);
	put(d->ampdu); put(d->shift); put(d->bb_sel); put(d->offset); put(d->rxd_len);
	put(d->ready); put(d->frame_type); put(d->addr_cam_valid); put(d->addr_cam_id);
	put(d->sec_cam_id); put(d->mac_id); put(d->rx_pl_id); put(d->sec_type);
}
/* rtw89_core_rx_process_ppdu_sts up to rtw89_core_rx_pending_skb: its
 * steps and gotos, with the step that stopped returned. */
static u32 process_ppdu_sts(struct rtw89_dev *rtwdev, struct rtw89_rx_desc_info *desc_info,
			    struct sk_buff *skb, struct rtw89_rx_phy_ppdu *out)
{
	struct rtw89_rx_phy_ppdu phy_ppdu = {.buf = skb->data, .valid = false,
					     .len = skb->len,
					     .to_self = desc_info->addr1_match,
					     .rate = desc_info->data_rate,
					     .mac_id = desc_info->mac_id,
					     .phy_idx = desc_info->bb_sel};
	u32 step = 0;
	int ret;

	if (desc_info->mac_info_valid) {
		ret = rtw89_core_rx_process_mac_ppdu(rtwdev, skb, &phy_ppdu);
		if (ret) {
			step = 1;
			goto out;
		}
	}

	ret = rtw89_core_rx_process_phy_ppdu(rtwdev, &phy_ppdu);
	if (ret) {
		step = 2;
		goto out;
	}

	rtw89_core_rx_process_phy_sts(rtwdev, &phy_ppdu);
	if (!phy_ppdu.valid)
		step = 3;
out:
	*out = phy_ppdu;
	return step;
}
static void run_case(const u8 *buf, u32 buf_len, const u8 *frame, u32 frame_len, u8 current)
{
	static struct ieee80211_hw hw;
	struct rtw89_dev dev = {.chip = &chip_info, .hw = &hw};
	struct rtw89_rx_desc_info desc = {0};
	u32 rx_len = word_at(buf) & 0x3fff;

	rtw89_core_query_rxdesc(&dev, &desc, (u8 *)buf, 4);
	put_desc(&desc);
	if (desc.pkt_type != RTW89_CORE_RX_TYPE_PPDU_STAT)
		return;
	u32 offset = desc.offset + desc.rxd_len;
	if (offset > rx_len || rx_len > buf_len)
		abort();
	struct sk_buff skb = {.data = (u8 *)buf + offset, .len = rx_len - offset};
	struct rtw89_rx_phy_ppdu phy;
	put(process_ppdu_sts(&dev, &desc, &skb, &phy));
	put(phy.rssi_avg);
	for (int i = 0; i < 4; i++)
		put(phy.rssi[i]);
	put(phy.mac_id); put(phy.chan_idx); put(phy.phy_idx); put(phy.ie); put(phy.rate);
	put(phy.rpl_avg); put(phy.rx_path_en); put(phy.ofdm.has); put(phy.ofdm.avg_snr);
	put(phy.ofdm.evm_max); put(phy.ofdm.evm_min); put(phy.has_data); put(phy.has_bcn);
	put(phy.su); put(phy.ldpc); put(phy.stbc); put(phy.bf); put(phy.to_self); put(phy.valid);
	put(phy.hdr_2_en); put(phy.ie09 != NULL);
	struct ieee80211_rx_status status = {0};
	__rtw8852bx_query_ppdu(&dev, &phy, &status);
	put((u32)(s32)status.signal); put(status.chains);
	put((u32)(s32)status.chain_signal[0]); put((u32)(s32)status.chain_signal[1]);
	put(status.freq); put(status.band);
	if (!frame_len)
		return;
	/* rtw89_core_update_rx_status's fields the match reads. */
	struct rtw89_rx_desc_info frame_desc = {0};
	struct ieee80211_rx_status rx_status = {0};
	u16 data_rate;
	u8 data_rate_mode;
	bool eht = false;
	u8 gi;

	rtw89_core_query_rxdesc(&dev, &frame_desc, (u8 *)frame, 4);
	rx_status.bw = rtw89_hw_to_rate_info_bw(frame_desc.bw);
	data_rate = frame_desc.data_rate;
	data_rate_mode = rtw89_get_data_rate_mode(&dev, data_rate);
	if (data_rate_mode == DATA_RATE_MODE_NON_HT) {
		rx_status.rate_idx = rtw89_get_data_not_ht_idx(&dev, data_rate);
	} else if (data_rate_mode == DATA_RATE_MODE_HT) {
		rx_status.rate_idx = rtw89_get_data_ht_mcs(&dev, data_rate);
	} else if (data_rate_mode == DATA_RATE_MODE_VHT) {
		rx_status.rate_idx = rtw89_get_data_mcs(&dev, data_rate);
	} else if (data_rate_mode == DATA_RATE_MODE_HE) {
		rx_status.rate_idx = rtw89_get_data_mcs(&dev, data_rate);
	} else if (data_rate_mode == DATA_RATE_MODE_EHT) {
		rx_status.rate_idx = rtw89_get_data_mcs(&dev, data_rate);
		eht = true;
	}
	gi = rtw89_rxdesc_to_nl_he_eht_gi(&dev, frame_desc.gi_ltf, true, eht);
	if (eht)
		rx_status.eht.gi = gi;
	else
		rx_status.he_gi = gi;
	dev.ppdu_sts.curr_rx_ppdu_cnt[RTW89_PHY_0] = current;
	put(rx_status.rate_idx); put(rx_status.he_gi); put(rx_status.bw);
	put(rtw89_core_rx_ppdu_match(&dev, &desc, &rx_status));
}
static u8 *read_all(FILE *in, u32 *count)
{
	u8 length[4];
	if (fread(length, 1, 4, in) != 4)
		return NULL;
	*count = word_at(length);
	u8 *data = malloc(*count + 4);
	if (!data || fread(data, 1, *count, in) != *count)
		abort();
	return data;
}
int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wb");
	if (!in || !out)
		abort();
	u32 cases = 0, count;
	u8 *input;
	while ((input = read_all(in, &count))) {
		u32 buf_len = word_at(input), frame_len = word_at(input + 4);
		u8 current = input[8];
		const u8 *buf = input + 12;
		const u8 *frame = buf + ((buf_len + 3) & ~3u);
		out_count = 0;
		run_case(buf, buf_len, frame, frame_len, current);
		u32 bytes = 4 * out_count;
		if (fwrite(&bytes, 4, 1, out) != 1 || fwrite(out_words, 4, out_count, out) != out_count)
			abort();
		free(input);
		cases++;
	}
	if (fclose(out) || fclose(in))
		abort();
	printf("%u\n", cases);
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, core_defines, phy_defines, common_defines, chan_defines, declarations,
        harness, txrx, helpers, phy, core, common, tables, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')

    rng = random.Random(SEED)
    cases = [random_desc(rng) for _ in range(200)] + crafted() + \
        [random_ppdu(rng) for _ in range(400)]
    inputs = bytearray()
    for buf, frame, current in cases:
        # A frame descriptor goes behind its rxbd_info dword, as in a buffer.
        frame = rxbd_info(4 + len(frame)) + frame if frame else b""
        pad = lambda data: data + bytes(-len(data) % 4)
        body = le32(len(buf), len(frame), current & 0xff) + pad(buf) + pad(frame)
        inputs += le32(len(body)) + body
    input_path = out / 'inputs.bin'
    input_path.write_bytes(bytes(inputs))

    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member', str(generated), '-o', str(exe)],
                   check=True)
    outputs = out / 'outputs.bin'
    run = subprocess.run([str(exe), str(input_path), str(outputs)], check=True,
                         capture_output=True, text=True)
    count = int(run.stdout.strip())
    if count != len(cases):
        raise ValueError(f'{count} cases run of {len(cases)}')
    # The trace: each case's input segment, then its output segment.
    produced = outputs.read_bytes()
    trace = bytearray()
    at_in = at_out = 0
    for _ in cases:
        n = struct.unpack_from('<I', inputs, at_in)[0]
        trace += inputs[at_in:at_in + 4 + n]
        at_in += 4 + n
        m = struct.unpack_from('<I', produced, at_out)[0]
        trace += produced[at_out:at_out + 4 + m]
        at_out += 4 + m
    if at_out != len(produced):
        raise ValueError('outputs left over')
    data = bytes(trace)
    (out / 'trx_trace.bin').write_bytes(data)
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=len(cases), seed=SEED,
        case_order='200 random non-PPDU descriptors, 17 crafted PPDU statuses, 400 random '
                   'PPDU statuses',
        dispatch=dict(rtw8852b_chip_info=info, rtw8852b_chip_ops=chip_ops, rtw8852bx_info=bx,
                      rtw89_phy_gen_ax=phy_def),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'the buffers are synthetic; no capture of what a chip writes',
            'rtw89_core_rx_process_ppdu_sts\'s control flow and rtw89_core_update_rx_status\'s '
            'rate, GI and bandwidth lines are copied into the harness',
            'CFO and antenna diversity tracking are stubs; they change no PPDU field',
            'ieee80211_channel_to_frequency is the harness\'s, from net/wireless/util.c',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
