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

It then writes a second trace, tx_trace.bin, with tx_manifest.json beside
it, from a second program over the TX path, with every callee unchanged:

- rtw89_core_fill_txdesc (core.c) with its body and info builders, through
  rtw89_chip_fill_txdesc, over 300 random struct rtw89_tx_desc_info;
- rtw89_pci_fill_txaddr_info (pci.c), RTL8852BE's fill_txaddr_info, through
  rtw89_chip_fill_txaddr_info, over 200 random lengths and addresses;
- rtw89_pci_parse_rpp with rtw89_core_get_ch_dma, over every queue and
  status and 200 random reports;
- ring scenarios on one device whose rings are as rtw89_pci_alloc_tx_ring
  leaves them (rtw89_pci_alloc_tx_wd_ring run, a zeroed BD ring): frames
  written by rtw89_pci_ops_tx_write (rtw89_pci_tx_write,
  rtw89_pci_txbd_submit, rtw89_pci_txwd_submit, the WD page lists), kicked
  off by rtw89_pci_ops_tx_kick_off, the hardware index moved, BDs reclaimed
  by rtw89_pci_reclaim_txbd, reports released by rtw89_pci_release_rpp
  (rtw89_pci_release_txwd_skb, rtw89_pci_tx_status) and rings released by
  rtw89_pci_release_tx_ring. Six are crafted (the ring wrapping twice and
  the pages turning over; BDs, then pages, running out; reports before the
  BD is read, and repeated; reports rtw89 drops; a ring reset; a hardware
  index past the frames), thirty random.

Its seams, the harness's: list.h and skbuff.h's operations, the DMA mapping
(a frame maps where the case says, a channel's WD pages at its base),
register access (each ring's index register reads the hardware index the
case set; writes are logged), ieee80211_tx_status_ni (the frame and whether
it was acknowledged recorded), and rtw89_core_tx_wait_complete (no frame
waits). Each case is one segment of words: its kind (0 descriptor, 1
address info, 2 report, 3 scenario) and its inputs, a scenario's as
operations (0 write: the TX type, the 35 descriptor members, the length and
the address; 1 kick-off; 2 hardware index; 3 report; 4 reclaim; 5 ring
release). The output: the 12 descriptor words; the size, count and 8 bytes
of the address info; the report's sequence, queue, status and ring; for
each scenario operation what it returned and wrote (the BD, the whole WD
page, the index register write, the completions) and the ring's indices,
free pages, busy pages and counters.
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
    tx_oracle(out, dict(locate=locate, functions=functions, declaration=declaration,
                        defines=defines, lines=lines, fields=fields), manifest)
    return 0


TX_SEED = 0x8852_be41
# The harness's addresses: each data channel's WD pages, and each ring's
# index register, which reads the hardware index the case set.
WD_DMA_BASE = 0x1000_0000
WD_DMA_STEP = 0x10_0000
IDX_BASE = 0x1000
# The channels an RTL8852BE has, but CH12: those with WD pages.
DATA_CHANNELS = [0, 1, 2, 3, 8, 9]
# A queue of each channel, as rtw89_core_get_ch_dma maps them.
CHANNEL_QSELS = {0: [0x0, 0x4, 0x8, 0xc], 1: [0x1, 0x5, 0x9, 0xd], 2: [0x2, 0x6, 0xa, 0xe],
                 3: [0x3, 0x7, 0xb, 0xf], 8: [0x12], 9: [0x11]}
# struct rtw89_tx_desc_info's members the AX builders read, in the order a
# case gives them.
DESC_FIELDS = ['pkt_size', 'wp_offset', 'mac_id', 'qsel', 'ch_dma', 'hdr_llc_len', 'is_bmc',
               'en_wd_info', 'wd_page', 'use_rate', 'dis_data_fb', 'tid_indicate', 'agg_en', 'bk',
               'ampdu_density', 'ampdu_num', 'sec_en', 'report', 'tx_cnt_lmt_en', 'sn',
               'tx_cnt_lmt', 'sec_type', 'sec_cam_idx', 'data_rate', 'data_retry_lowest_rate',
               'data_bw', 'gi_ltf', 'fw_dl', 'seq', 'a_ctrl_bsr', 'hw_ssn_sel', 'hw_seq_mode',
               'port', 'stbc', 'ldpc']
OP_WRITE, OP_KICK, OP_HWIDX, OP_RPP, OP_RECLAIM, OP_RELEASE_RING = range(6)


def ch_dma(qsel):
    """rtw89_core_get_ch_dma, for the generator's own bookkeeping."""
    for txch, qsels in CHANNEL_QSELS.items():
        if qsel in qsels:
            return txch
    return {0x1a: 10, 0x19: 11}.get(qsel, 0)


def tx_desc(rng, txch=None):
    words = [rng.choice([0, 1, rng.getrandbits(4), rng.getrandbits(8), rng.getrandbits(16),
                         rng.getrandbits(32)]) for _ in DESC_FIELDS]
    if txch is not None:
        words[DESC_FIELDS.index('ch_dma')] = txch
        if txch in CHANNEL_QSELS:
            words[DESC_FIELDS.index('qsel')] = rng.choice(CHANNEL_QSELS[txch])
        words[DESC_FIELDS.index('en_wd_info')] = rng.random() < 0.8
        words[DESC_FIELDS.index('wd_page')] = 1
        words[DESC_FIELDS.index('fw_dl')] = 0
    return [int(word) & 0xffff_ffff for word in words]


class Ring:
    """What the generator expects of one data channel, to aim its reports
    at frames in flight; the oracle, not this, is what the trace holds."""

    def __init__(self):
        self.free = list(range(512))
        self.busy = []
        self.where = ['free'] * 512
        self.frame = [False] * 512
        self.wp = self.rp = self.hw = 0

    def write(self):
        avail = self.rp - self.wp - 1 if self.rp > self.wp else 256 - (self.wp - self.rp) - 1
        if avail == 0 or not self.free:
            return None
        seq = self.free.pop(0)
        self.frame[seq], self.where[seq] = True, 'busy'
        self.busy.append(seq)
        self.wp = (self.wp + 1) % 256
        return seq

    def reclaim(self):
        cnt = self.hw - self.rp if self.hw >= self.rp else 256 - (self.rp - self.hw)
        self.rp = self.hw
        for _ in range(cnt):
            if not self.busy:
                break
            seq = self.busy.pop(0)
            self.where[seq] = 'idle'
            if not self.frame[seq]:
                self.where[seq] = 'free'
                self.free.append(seq)

    def release(self, seq):
        if self.where[seq] != 'idle':
            self.reclaim()
        self.frame[seq] = False
        if self.where[seq] == 'idle':
            self.where[seq] = 'free'
            self.free.append(seq)

    def release_ring(self):
        for seq in self.busy:
            self.where[seq] = 'idle'
        self.busy = []
        for seq in range(512):
            if self.where[seq] == 'idle':
                self.frame[seq], self.where[seq] = False, 'free'
                self.free.append(seq)

    def flying(self):
        return [seq for seq in range(512) if self.frame[seq]]


class Scenario:
    def __init__(self, rng):
        self.rng = rng
        self.rings = {txch: Ring() for txch in DATA_CHANNELS}
        self.words = []
        self.ops = 0

    def op(self, *words):
        self.words += [w & 0xffff_ffff for w in words]
        self.ops += 1

    def write(self, txch, desc=None, length=None, dma=None):
        rng = self.rng
        if txch in self.rings:
            self.rings[txch].write()
        desc = desc or tx_desc(rng, txch)
        length = rng.choice([0, 24, 60, 1500, 2304, rng.getrandbits(14), rng.getrandbits(32)]) \
            if length is None else length
        dma = rng.choice([rng.getrandbits(32), rng.getrandbits(36), rng.getrandbits(64)]) \
            if dma is None else dma
        self.op(OP_WRITE, 0, *desc, length, dma, dma >> 32)

    def kick(self, txch):
        self.op(OP_KICK, txch)

    def hwidx(self, txch, index, noise=0):
        self.rings[txch].hw = index
        self.op(OP_HWIDX, txch, index << 16 | noise)

    def rpp(self, dword):
        seq, qsel = dword >> 16 & 0x7fff, dword >> 8 & 0x1f
        txch = ch_dma(qsel)
        if txch in self.rings and seq < 512:
            self.rings[txch].release(seq)
        self.op(OP_RPP, dword)

    def report(self, txch, seq, status=0, macid=0, polluted=False):
        qsel = self.rng.choice(CHANNEL_QSELS[txch])
        self.rpp(int(polluted) << 31 | seq << 16 | status << 13 | qsel << 8 | macid)

    def reclaim(self, txch):
        self.rings[txch].reclaim()
        self.op(OP_RECLAIM, txch)

    def release_ring(self, txch):
        self.rings[txch].release_ring()
        self.op(OP_RELEASE_RING, txch)


def crafted_scenarios(rng):
    out = []
    # The ring wraps twice and the pages turn over: each frame read and
    # reported at once.
    s = Scenario(rng)
    for _ in range(700):
        seq = s.rings[0].free[0]
        s.write(0)
        s.kick(0)
        s.hwidx(0, s.rings[0].wp)
        s.report(0, seq)
    out.append(s)
    # BDs run out, then pages: frames read but not reported hold their
    # pages; reports in any order give them back for reuse.
    s = Scenario(rng)
    for _ in range(256):
        s.write(1)
    s.kick(1)
    s.hwidx(1, 200)
    s.reclaim(1)
    for _ in range(300):
        s.write(1)
        if s.rings[1].wp % 50 == 0:
            s.kick(1)
            s.hwidx(1, (s.rings[1].wp - 3) % 256)
            s.reclaim(1)
    flying = s.rings[1].flying()
    rng.shuffle(flying)
    for index, seq in enumerate(flying):
        s.report(1, seq, status=index % 5 if index % 7 else 0)
        if index % 40 == 0:
            s.write(1)
    s.hwidx(1, s.rings[1].wp)
    s.reclaim(1)
    for _ in range(20):
        s.write(1)
    out.append(s)
    # Reports before the hardware read the BDs, and a report repeated.
    s = Scenario(rng)
    seqs = [s.rings[2].free[i] for i in range(3)]
    for _ in range(3):
        s.write(2)
    s.kick(2)
    s.report(2, seqs[1], status=1)
    s.report(2, seqs[1], status=0)
    s.hwidx(2, 3)
    s.reclaim(2)
    s.report(2, seqs[0], status=2)
    s.report(2, seqs[2], status=3)
    s.write(2)
    out.append(s)
    # Reports rtw89 drops or finds nothing behind: a free page, a sequence
    # past the pages, a queue of a ring the chip lacks, a queue no ring
    # names, invalid statuses, the polluted and MAC ID bits.
    s = Scenario(rng)
    for _ in range(4):
        s.write(3)
    s.kick(3)
    s.hwidx(3, 2)
    s.report(3, 300)
    s.rpp(0x7fff << 16 | 3 << 8)
    s.rpp(512 << 16 | 3 << 8)
    s.rpp(0 << 16 | 0x1a << 8)
    s.rpp(1 << 16 | 0x19 << 8)
    s.rpp(0 << 16 | 0x10 << 8)
    s.rpp(1 << 16 | 0x1f << 8 | 5 << 13)
    s.report(3, 2, status=4)
    s.report(3, 3, status=7, macid=0xff, polluted=True)
    out.append(s)
    # A ring reset with frames busy, read and reported, then reuse; the
    # management ring with and without WD info; CH12 refused.
    s = Scenario(rng)
    for txch in (3, 8, 9):
        for _ in range(10):
            s.write(txch)
        s.kick(txch)
        s.hwidx(txch, 4)
        s.reclaim(txch)
        s.report(txch, 5)
        s.report(txch, 1)
        s.release_ring(txch)
        for _ in range(3):
            s.write(txch)
    for wd_info in (0, 1):
        desc = tx_desc(rng, 8)
        desc[DESC_FIELDS.index('en_wd_info')] = wd_info
        s.write(8, desc)
    s.write(12)
    out.append(s)
    # A hardware index past the frames given: more BDs read than pages busy.
    s = Scenario(rng)
    for _ in range(5):
        s.write(0)
    s.kick(0)
    s.hwidx(0, 9)
    s.reclaim(0)
    s.write(0)
    s.hwidx(0, 9)
    s.report(0, 5)
    out.append(s)
    return out


def random_scenario(rng):
    s = Scenario(rng)
    for _ in range(300):
        txch = rng.choice(DATA_CHANNELS)
        ring = s.rings[txch]
        kind = rng.choices(['write', 'kick', 'hw', 'report', 'reclaim', 'rpp', 'reset', 'ch12'],
                           [40, 12, 14, 25, 5, 3, 0.3, 0.7])[0]
        if kind == 'write':
            s.write(txch)
        elif kind == 'kick':
            s.kick(txch)
        elif kind == 'hw':
            pending = (ring.wp - ring.rp) % 256
            index = (ring.rp + rng.randint(0, pending)) % 256
            if rng.random() < 0.03:
                index = rng.randrange(256)
            s.hwidx(txch, index, rng.getrandbits(12))
        elif kind == 'report':
            flying = ring.flying()
            if flying:
                seq = flying[0] if rng.random() < 0.4 else rng.choice(flying)
                status = rng.choices(range(8), [60, 15, 8, 8, 3, 2, 2, 2])[0]
                s.report(txch, seq, status, rng.getrandbits(8), rng.random() < 0.05)
        elif kind == 'reclaim':
            s.reclaim(txch)
        elif kind == 'rpp':
            s.rpp(rng.getrandbits(32))
        elif kind == 'reset':
            s.release_ring(txch)
        else:
            s.write(12)
    return s


def tx_oracle(out, h, manifest):
    """The TX trace: unchanged rtw89 TX descriptor, WD page, address info,
    kick-off and release report code over synthetic cases."""
    first_symbol = len(manifest)
    locate, functions, declaration = h['locate'], h['functions'], h['declaration']
    defines, lines, fields = h['defines'], h['lines'], h['fields']

    enums = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in ['rtw89_hci_type', 'rtw89_core_tx_type']]
        + [declaration('txrx.h', 'enum', name) for name in [
            'rtw89_tx_channel', 'rtw89_rx_channel', 'rtw89_tx_qsel']])
    tx_defines = '\n\n'.join([
        defines('core.h', ['RTW89_TX_DONE', 'RTW89_TX_RETRY_LIMIT', 'RTW89_TX_LIFE_TIME',
                           'RTW89_TX_MACID_DROP']),
        defines('pci.h', ['RTW89_PCI_TXBD_NUM_MAX', 'RTW89_PCI_RXBD_NUM_MAX',
                          'RTW89_PCI_TXWD_NUM_MAX', 'RTW89_PCI_TXWD_PAGE_SIZE', 'TXBD_HW_IDX_MASK',
                          'RTW89_PCI_TXWP_VALID', 'RTW89_PCI_ADDR_MSDU_LS', 'RTW89_PCI_ADDR_LS',
                          'RTW89_PCI_ADDR_HIGH_MASK', 'RTW89_PCI_ADDR_NUM',
                          'RTW89_PCI_RPP_POLLUTED', 'RTW89_PCI_RPP_SEQ', 'RTW89_PCI_RPP_TX_STATUS',
                          'RTW89_PCI_RPP_QSEL', 'RTW89_PCI_RPP_MACID']),
        lines('txrx.h', '#define RTW89_TXWD_BODY0_WP_OFFSET', '#define RTW89_TXWD_INFO4_SW_DEFINE')])
    structs = '\n\n'.join(
        [declaration('core.h', 'struct', name) for name in [
            'rtw89_txwd_body', 'rtw89_txwd_info', 'rtw89_tx_desc_info', 'rtw89_core_tx_request',
            'rtw89_rx_desc_info']]
        + [declaration('pci.h', 'struct', name) for name in [
            'rtw89_pci_ch_dma_addr', 'rtw89_pci_rpp_info', 'rtw89_pci_tx_data',
            'rtw89_pci_tx_bd_32', 'rtw89_pci_tx_wp_info', 'rtw89_pci_tx_addr_info_32',
            'rtw89_pci_rpp_fmt', 'rtw89_pci_tx_wd', 'rtw89_pci_dma_ring', 'rtw89_pci_dma_pool',
            'rtw89_pci_tx_wd_ring', 'rtw89_pci_tx_ring', 'rtw89_pci_tx_rings', 'rtw89_pci_rx_ring',
            'rtw89_pci_rx_rings', 'rtw89_pci']])
    helpers = '\n\n'.join(
        [locate('core.h', name)[1] for name in [
            'rtw89_chip_fill_txdesc', 'rtw89_chip_fill_txdesc_fwcmd', 'rtw89_chip_get_ch_dma']]
        + [locate('pci.h', name)[1] for name in [
            'rtw89_pci_get_next_txbd', 'rtw89_pci_dequeue_txwd', 'rtw89_pci_enqueue_txwd',
            'rtw89_chip_fill_txaddr_info']])
    core = functions('core.c', [
        'rtw89_core_get_ch_dma', 'rtw89_build_txwd_body0', 'rtw89_build_txwd_body2',
        'rtw89_build_txwd_body3', 'rtw89_build_txwd_info0', 'rtw89_build_txwd_info1',
        'rtw89_build_txwd_info2', 'rtw89_build_txwd_info3', 'rtw89_build_txwd_info4',
        'rtw89_core_fill_txdesc'])
    pci = functions('pci.c', [
        'rtw89_pci_dma_recalc', 'rtw89_pci_txbd_recalc', 'rtw89_pci_tx_status',
        'rtw89_pci_reclaim_txbd', 'rtw89_pci_release_busy_txwd', 'rtw89_pci_release_txwd_skb',
        'rtw89_pci_parse_rpp', 'rtw89_pci_release_rpp', 'rtw89_pci_release_pending_txwd_skb',
        'rtw89_pci_get_avail_txbd_num', '__rtw89_pci_tx_kick_off', 'rtw89_pci_tx_bd_ring_update',
        'rtw89_pci_ops_tx_kick_off', 'rtw89_pci_fill_txaddr_info', 'rtw89_pci_txwd_submit',
        'rtw89_pci_fwcmd_submit', 'rtw89_pci_txbd_submit', 'rtw89_pci_tx_write',
        'rtw89_pci_ops_tx_write', 'rtw89_pci_release_tx_ring', 'rtw89_pci_alloc_tx_wd_ring'])

    info = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  ['h2c_desc_size', 'txwd_body_size', 'txwd_info_size', 'ops'])
    if info['ops'] != '&rtw8852b_chip_ops':
        raise ValueError(f'rtw8852b_chip_info dispatch is {info}')
    chip_ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                      ['fill_txdesc', 'fill_txdesc_fwcmd', 'get_ch_dma'])
    if (chip_ops['fill_txdesc'], chip_ops['fill_txdesc_fwcmd'],
            re.sub(r'\s+', '', chip_ops['get_ch_dma'])) != (
            'rtw89_core_fill_txdesc', 'rtw89_core_fill_txdesc',
            '{rtw89_core_get_ch_dma,rtw89_core_get_ch_dma,NULL,}'):
        raise ValueError(f'rtw8852b_chip_ops dispatch is {chip_ops}')
    pci_fields = ['rx_ring_eq_is_full', 'rpp_fmt_size', 'tx_dma_ch_mask', 'fill_txaddr_info',
                  'parse_rpp']
    pci_info = fields('rtw8852be.c', 'static const struct rtw89_pci_info rtw8852b_pci_info',
                      pci_fields)
    if (pci_info['fill_txaddr_info'], pci_info['parse_rpp'], pci_info['rpp_fmt_size']) != (
            'rtw89_pci_fill_txaddr_info', 'rtw89_pci_parse_rpp',
            'sizeof(struct rtw89_pci_rpp_fmt)'):
        raise ValueError(f'rtw8852b_pci_info dispatch is {pci_info}')

    preamble = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t __le64;
typedef u64 dma_addr_t;
typedef int spinlock_t;
#define __packed __attribute__((packed))
#define __iomem
#define fallthrough __attribute__((__fallthrough__))
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define le32_get_bits(v, m) FIELD_GET(m, v)
#define le16_encode_bits(v, m) ((u16)((((u32)(u16)(v)) << __ffs(m)) & (m)))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define unlikely(x) (x)
#define EXPORT_SYMBOL(...)
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define set_bit(nr, addr) ((void)(nr), (void)(addr))
#define spin_lock_bh(l) ((void)(l))
#define spin_unlock_bh(l) ((void)(l))
static void sink(const char *format, ...) { (void)format; }
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), sink(__VA_ARGS__))
struct rtw89_dev;
struct sk_buff;
struct pci_dev;
struct ieee80211_vif;
struct ieee80211_sta;
struct rtw89_vif_link;
struct rtw89_sta_link;
struct list_head { struct list_head *next, *prev; };
struct sk_buff_head { struct sk_buff *next, *prev; u32 qlen; spinlock_t lock; };
'''
    harness = r'''
/* The members of struct ieee80211_tx_info rtw89_pci_tx_status touches. */
#define IEEE80211_TX_CTL_REQ_TX_STATUS BIT(0)
#define IEEE80211_TX_CTL_NO_ACK BIT(2)
#define IEEE80211_TX_STAT_ACK BIT(9)
#define IEEE80211_TX_STAT_NOACK_TRANSMITTED BIT(24)
struct ieee80211_tx_info { u32 flags; };
struct ieee80211_hw { int unused; };
struct rtw89_tx_skb_data { int unused; };
struct sk_buff {
	struct sk_buff *next, *prev;
	u8 *data;
	u32 len;
	u32 id;
	struct rtw89_pci_tx_data tx_data;
	struct rtw89_tx_skb_data skb_data;
	struct ieee80211_tx_info info;
};
/* include/linux/list.h and skbuff.h, the operations used. */
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define list_entry(ptr, type, member) container_of(ptr, type, member)
static inline void INIT_LIST_HEAD(struct list_head *list) { list->next = list; list->prev = list; }
static inline int list_empty(const struct list_head *head) { return head->next == head; }
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_entry((ptr)->next, type, member) : NULL)
static inline void list_add_tail(struct list_head *entry, struct list_head *head)
{
	struct list_head *prev = head->prev;
	entry->next = head;
	entry->prev = prev;
	prev->next = entry;
	head->prev = entry;
}
static inline void list_del_init(struct list_head *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	INIT_LIST_HEAD(entry);
}
static void skb_link(struct sk_buff_head *list, struct sk_buff *at, struct sk_buff *next, bool prev)
{
	if (at == (struct sk_buff *)list) {
		if (prev) list->prev = next; else list->next = next;
	} else {
		if (prev) at->prev = next; else at->next = next;
	}
}
static inline void skb_queue_head_init(struct sk_buff_head *list)
{
	list->next = list->prev = (struct sk_buff *)list;
	list->qlen = 0;
}
static inline u32 skb_queue_len(const struct sk_buff_head *list) { return list->qlen; }
static inline void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	struct sk_buff *prev = list->prev;
	newsk->next = (struct sk_buff *)list;
	newsk->prev = prev;
	skb_link(list, prev, newsk, false);
	list->prev = newsk;
	list->qlen++;
}
static inline void skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	struct sk_buff *next = skb->next, *prev = skb->prev;
	list->qlen--;
	skb_link(list, prev, next, false);
	skb_link(list, next, prev, true);
	skb->next = skb->prev = NULL;
}
static struct sk_buff *skb_next_of(struct sk_buff_head *list, struct sk_buff *skb)
{
	return skb == (struct sk_buff *)list ? list->next : skb->next;
}
#define skb_queue_walk_safe(queue, skb, tmp) \
	for (skb = (queue)->next, tmp = skb_next_of(queue, skb); \
	     skb != (struct sk_buff *)(queue); \
	     skb = tmp, tmp = skb_next_of(queue, skb))
static void *skb_push(struct sk_buff *skb, unsigned int len) { (void)skb; (void)len; abort(); }
struct rtw89_chip_ops {
	void (*fill_txdesc)(struct rtw89_dev *rtwdev, struct rtw89_tx_desc_info *desc_info,
			    void *txdesc);
	void (*fill_txdesc_fwcmd)(struct rtw89_dev *rtwdev, struct rtw89_tx_desc_info *desc_info,
				  void *txdesc);
	u8 (*get_ch_dma[RTW89_HCI_TYPE_NUM])(struct rtw89_dev *rtwdev, u8 qsel);
};
struct rtw89_chip_info {
	u32 h2c_desc_size;
	u32 txwd_body_size;
	u32 txwd_info_size;
	const struct rtw89_chip_ops *ops;
};
struct rtw89_pci_info {
	bool rx_ring_eq_is_full;
	u32 rpp_fmt_size;
	u32 tx_dma_ch_mask;
	u32 (*fill_txaddr_info)(struct rtw89_dev *rtwdev, void *txaddr_info_addr, u32 total_len,
				dma_addr_t dma, u8 *add_info_nr);
	void (*parse_rpp)(struct rtw89_dev *rtwdev, void *rpp, struct rtw89_pci_rpp_info *rpp_info);
};
struct rtw89_hci_info { enum rtw89_hci_type type; bool paused; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_pci_info *pci_info;
	struct rtw89_hci_info hci;
	struct ieee80211_hw *hw;
	u8 priv[] __attribute__((aligned(sizeof(void *))));
};
static inline struct rtw89_pci_tx_data *RTW89_PCI_TX_SKB_CB(struct sk_buff *skb)
{
	return &skb->tx_data;
}
static inline struct rtw89_tx_skb_data *RTW89_TX_SKB_CB(struct sk_buff *skb)
{
	return &skb->skb_data;
}
#define IEEE80211_SKB_CB(skb) (&(skb)->info)
/* No frame here waits for its status (rtw89_core_tx_wait_complete). */
static bool rtw89_core_tx_wait_complete(struct rtw89_dev *rtwdev,
					struct rtw89_tx_skb_data *skb_data, u8 tx_status)
{
	(void)rtwdev; (void)skb_data; (void)tx_status;
	return false;
}
#define ieee80211_tx_info_clear_status(info) ((void)(info))
/* The harness's DMA: a frame maps where the case says, WD pages where the
 * channel's base is; nothing is unmapped for real. */
static dma_addr_t next_map_dma, next_coherent_dma;
static u32 maps, unmaps;
#define DMA_TO_DEVICE 1
#define GFP_KERNEL 0
#define dma_map_single(d, p, l, r) (maps++, next_map_dma)
#define dma_mapping_error(d, a) 0
#define dma_unmap_single(d, a, s, r) (unmaps++)
static void *coherent(size_t size, dma_addr_t *dma)
{
	void *head = calloc(1, size);
	if (!head)
		abort();
	*dma = next_coherent_dma;
	return head;
}
#define dma_alloc_coherent(d, s, h, g) coherent(s, h)
/* The harness's registers: each ring's index register reads the hardware
 * index the case set; writes are logged. */
#define IDX_REG(txch) (0x1000u + 4u * (txch))
#define WD_DMA(txch) (0x10000000ull + 0x100000ull * (txch))
static u32 hw_idx[RTW89_TXCH_NUM];
static u32 reads, writes, write_log[8][2];
static u32 rtw89_read32(struct rtw89_dev *rtwdev, u32 addr)
{
	(void)rtwdev;
	for (u32 txch = 0; txch < RTW89_TXCH_NUM; txch++) {
		if (addr == IDX_REG(txch)) {
			reads++;
			return hw_idx[txch];
		}
	}
	abort();
}
static void rtw89_write16(struct rtw89_dev *rtwdev, u32 addr, u16 data)
{
	(void)rtwdev;
	if (writes >= 8)
		abort();
	write_log[writes][0] = addr;
	write_log[writes][1] = data;
	writes++;
}
static u32 comps[1024][2], ncomp;
static void ieee80211_tx_status_ni(struct ieee80211_hw *hw, struct sk_buff *skb)
{
	(void)hw;
	if (ncomp >= 1024)
		abort();
	comps[ncomp][0] = skb->id;
	comps[ncomp][1] = !!(skb->info.flags & IEEE80211_TX_STAT_ACK);
	ncomp++;
	free(skb);
}
'''
    tables = (
        'static const struct rtw89_chip_ops chip_ops = {\n'
        + ''.join(f'\t.{name} = {chip_ops[name]},\n' for name in chip_ops)
        + '};\nstatic const struct rtw89_chip_info chip_info = {\n\t.ops = &chip_ops,\n'
        + ''.join(f'\t.{name} = {info[name]},\n' for name in [
            'h2c_desc_size', 'txwd_body_size', 'txwd_info_size'])
        + '};\nstatic const struct rtw89_pci_info pci_info = {\n'
        + ''.join(f'\t.{name} = {pci_info[name]},\n' for name in pci_fields)
        + '};\nstatic struct ieee80211_hw hw;\n')
    main_c = r'''
static u32 *out_words;
static u32 out_count, out_cap;
static void put(u32 word)
{
	if (out_count >= out_cap) {
		out_cap = out_cap ? 2 * out_cap : 4096;
		out_words = realloc(out_words, 4 * out_cap);
		if (!out_words)
			abort();
	}
	out_words[out_count++] = word;
}
static u32 word_at(const u8 *data)
{
	return data[0] | (u32)data[1] << 8 | (u32)data[2] << 16 | (u32)data[3] << 24;
}
static void fill_desc(struct rtw89_tx_desc_info *d, const u32 *w)
{
	d->pkt_size = w[0]; d->wp_offset = w[1]; d->mac_id = w[2]; d->qsel = w[3];
	d->ch_dma = w[4]; d->hdr_llc_len = w[5]; d->is_bmc = w[6]; d->en_wd_info = w[7];
	d->wd_page = w[8]; d->use_rate = w[9]; d->dis_data_fb = w[10]; d->tid_indicate = w[11];
	d->agg_en = w[12]; d->bk = w[13]; d->ampdu_density = w[14]; d->ampdu_num = w[15];
	d->sec_en = w[16]; d->report = w[17]; d->tx_cnt_lmt_en = w[18]; d->sn = w[19];
	d->tx_cnt_lmt = w[20]; d->sec_type = w[21]; d->sec_cam_idx = w[22]; d->data_rate = w[23];
	d->data_retry_lowest_rate = w[24]; d->data_bw = w[25]; d->gi_ltf = w[26]; d->fw_dl = w[27];
	d->seq = w[28]; d->a_ctrl_bsr = w[29]; d->hw_ssn_sel = w[30]; d->hw_seq_mode = w[31];
	d->port = w[32]; d->stbc = w[33]; d->ldpc = w[34];
}
#define DESC_WORDS 35
static bool data_ring(u32 txch)
{
	return txch < RTW89_TXCH_NUM && !(pci_info.tx_dma_ch_mask & BIT(txch)) &&
	       txch != RTW89_TXCH_CH12;
}
/* A device whose rings are as rtw89_pci_alloc_tx_ring leaves them: the
 * WD pages by rtw89_pci_alloc_tx_wd_ring, a zeroed BD ring at index 0. */
static struct rtw89_dev *new_dev(void)
{
	struct rtw89_dev *dev = calloc(1, sizeof(*dev) + sizeof(struct rtw89_pci));
	if (!dev)
		abort();
	dev->chip = &chip_info;
	dev->pci_info = &pci_info;
	dev->hci.type = RTW89_HCI_TYPE_PCIE;
	dev->hw = &hw;
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)dev->priv;
	for (u32 txch = 0; txch < RTW89_TXCH_NUM; txch++) {
		if (pci_info.tx_dma_ch_mask & BIT(txch))
			continue;
		struct rtw89_pci_tx_ring *tx_ring = &rtwpci->tx.rings[txch];
		next_coherent_dma = WD_DMA(txch);
		if (rtw89_pci_alloc_tx_wd_ring(dev, NULL, tx_ring, txch))
			abort();
		tx_ring->bd_ring.head = calloc(RTW89_PCI_TXBD_NUM_MAX,
					       sizeof(struct rtw89_pci_tx_bd_32));
		if (!tx_ring->bd_ring.head)
			abort();
		tx_ring->bd_ring.desc_size = sizeof(struct rtw89_pci_tx_bd_32);
		tx_ring->bd_ring.len = RTW89_PCI_TXBD_NUM_MAX;
		tx_ring->bd_ring.addr.idx = IDX_REG(txch);
		INIT_LIST_HEAD(&tx_ring->busy_pages);
		tx_ring->txch = txch;
	}
	return dev;
}
static void free_dev(struct rtw89_dev *dev)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)dev->priv;
	for (u32 txch = 0; txch < RTW89_TXCH_NUM; txch++) {
		if (pci_info.tx_dma_ch_mask & BIT(txch))
			continue;
		struct rtw89_pci_tx_ring *tx_ring = &rtwpci->tx.rings[txch];
		if (txch != RTW89_TXCH_CH12) {
			for (u32 i = 0; i < tx_ring->wd_ring.page_num; i++) {
				struct sk_buff_head *queue = &tx_ring->wd_ring.pages[i].queue;
				while (skb_queue_len(queue)) {
					struct sk_buff *skb = queue->next;
					skb_unlink(skb, queue);
					free(skb);
				}
			}
			free(tx_ring->wd_ring.head);
		}
		free(tx_ring->bd_ring.head);
	}
	free(dev);
}
static void put_state(struct rtw89_dev *dev, u32 txch)
{
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)dev->priv;
	struct rtw89_pci_tx_ring *r = &rtwpci->tx.rings[txch];
	u32 busy = 0;
	for (struct list_head *at = r->busy_pages.next; at != &r->busy_pages; at = at->next)
		busy++;
	put(r->bd_ring.wp); put(r->bd_ring.rp); put(r->wd_ring.curr_num); put(busy);
	put((u32)r->tx_cnt); put((u32)r->tx_acked); put((u32)r->tx_retry_lmt);
	put((u32)r->tx_life_time); put((u32)r->tx_mac_id_drop);
}
static void put_comps(void)
{
	put(ncomp);
	for (u32 i = 0; i < ncomp; i++) {
		put(comps[i][0]);
		put(comps[i][1]);
	}
}
static void run_scenario(const u32 *w, u32 n)
{
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)dev->priv;
	u32 at = 0, ids = 0;
	memset(hw_idx, 0, sizeof(hw_idx));
	while (at < n) {
		u32 op = w[at++], txch;
		switch (op) {
		case 0: {
			if (at + 4 + DESC_WORDS > n)
				abort();
			struct sk_buff *skb = calloc(1, sizeof(*skb));
			if (!skb)
				abort();
			struct rtw89_core_tx_request req = {.tx_type = w[at], .skb = skb};
			fill_desc(&req.desc_info, w + at + 1);
			skb->len = w[at + 1 + DESC_WORDS];
			skb->id = ++ids;
			next_map_dma = w[at + 2 + DESC_WORDS] | (u64)w[at + 3 + DESC_WORDS] << 32;
			at += 4 + DESC_WORDS;
			txch = req.desc_info.ch_dma;
			if (txch >= RTW89_TXCH_NUM || (pci_info.tx_dma_ch_mask & BIT(txch)))
				abort();
			struct rtw89_pci_tx_ring *r = &rtwpci->tx.rings[txch];
			u32 old_wp = r->bd_ring.wp;
			int ret = rtw89_pci_ops_tx_write(dev, &req);
			put((u32)ret);
			put(old_wp);
			if (ret == 0) {
				const struct rtw89_pci_tx_bd_32 *bd =
					(const struct rtw89_pci_tx_bd_32 *)r->bd_ring.head + old_wp;
				put(word_at((const u8 *)bd));
				put(word_at((const u8 *)bd + 4));
				u32 seq = (bd->dma - (u32)WD_DMA(txch)) / RTW89_PCI_TXWD_PAGE_SIZE;
				if (seq >= RTW89_PCI_TXWD_NUM_MAX)
					abort();
				const u8 *page = r->wd_ring.pages[seq].vaddr;
				for (u32 i = 0; i < RTW89_PCI_TXWD_PAGE_SIZE; i += 4)
					put(word_at(page + i));
			} else {
				free(skb);
			}
			if (data_ring(txch))
				put_state(dev, txch);
			break;
		}
		case 1:
			txch = w[at++];
			writes = 0;
			rtw89_pci_ops_tx_kick_off(dev, txch);
			put(writes);
			for (u32 i = 0; i < writes; i++) {
				put(write_log[i][0]);
				put(write_log[i][1]);
			}
			break;
		case 2:
			txch = w[at++];
			if (txch >= RTW89_TXCH_NUM)
				abort();
			hw_idx[txch] = w[at++];
			break;
		case 3: {
			u32 dword = w[at++];
			struct rtw89_pci_rpp_info info = {0};
			rtw89_pci_parse_rpp(dev, &dword, &info);
			put(info.seq); put(info.qsel); put(info.tx_status); put(info.txch);
			reads = 0;
			ncomp = 0;
			rtw89_pci_release_rpp(dev, &dword);
			put(reads);
			put_comps();
			if (data_ring(info.txch))
				put_state(dev, info.txch);
			break;
		}
		case 4:
			txch = w[at++];
			if (!data_ring(txch))
				abort();
			reads = 0;
			rtw89_pci_reclaim_txbd(dev, &rtwpci->tx.rings[txch]);
			put(reads);
			put_state(dev, txch);
			break;
		case 5:
			txch = w[at++];
			if (!data_ring(txch))
				abort();
			ncomp = 0;
			rtw89_pci_release_tx_ring(dev, &rtwpci->tx.rings[txch]);
			put_comps();
			put_state(dev, txch);
			break;
		default:
			abort();
		}
	}
	free_dev(dev);
}
static void run_case(const u32 *w, u32 n)
{
	struct rtw89_dev dev = {.chip = &chip_info, .pci_info = &pci_info,
				.hci = {.type = RTW89_HCI_TYPE_PCIE}, .hw = &hw};
	if (n < 1)
		abort();
	switch (w[0]) {
	case 0: {
		if (n != 1 + DESC_WORDS)
			abort();
		struct rtw89_tx_desc_info desc = {0};
		u8 txdesc[sizeof(struct rtw89_txwd_body) + sizeof(struct rtw89_txwd_info)] = {0};
		fill_desc(&desc, w + 1);
		rtw89_chip_fill_txdesc(&dev, &desc, txdesc);
		for (u32 i = 0; i < sizeof(txdesc); i += 4)
			put(word_at(txdesc + i));
		break;
	}
	case 1: {
		if (n != 4)
			abort();
		u8 addr_info[sizeof(struct rtw89_pci_tx_addr_info_32)] = {0};
		u8 nr = 0;
		u32 size = rtw89_chip_fill_txaddr_info(&dev, addr_info, w[1],
						       w[2] | (u64)w[3] << 32, &nr);
		put(size); put(nr); put(word_at(addr_info)); put(word_at(addr_info + 4));
		break;
	}
	case 2: {
		if (n != 2)
			abort();
		u32 dword = w[1];
		struct rtw89_pci_rpp_info info = {0};
		rtw89_pci_parse_rpp(&dev, &dword, &info);
		put(info.seq); put(info.qsel); put(info.tx_status); put(info.txch);
		break;
	}
	case 3:
		run_scenario(w + 1, n - 1);
		break;
	default:
		abort();
	}
}
int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "wb");
	if (!in || !out)
		abort();
	u32 cases = 0;
	u8 length[4];
	while (fread(length, 1, 4, in) == 4) {
		u32 count = word_at(length);
		if (count % 4)
			abort();
		u32 *words = malloc(count + 4);
		if (!words || fread(words, 1, count, in) != count)
			abort();
		out_count = 0;
		run_case(words, count / 4);
		u32 bytes = 4 * out_count;
		if (fwrite(&bytes, 4, 1, out) != 1 ||
		    fwrite(out_words, 4, out_count, out) != out_count)
			abort();
		free(words);
		cases++;
	}
	free(out_words);
	if (fclose(out) || fclose(in))
		abort();
	printf("%u\n", cases);
	return 0;
}
'''
    program = '\n\n'.join([preamble, enums, tx_defines, structs, harness, helpers, core, pci,
                           tables, main_c])
    generated = out / 'tx_oracle.c'
    generated.write_text(program, newline='\n')

    rng = random.Random(TX_SEED)
    cases = []
    for _ in range(300):
        cases.append([0] + tx_desc(rng))
    for _ in range(200):
        total = rng.choice([0, 1, 24, 1500, 0xffff, 0x1_0000, rng.getrandbits(16),
                            rng.getrandbits(32)])
        dma = rng.choice([rng.getrandbits(32), rng.getrandbits(40), rng.getrandbits(64)])
        cases.append([1, total, dma & 0xffff_ffff, dma >> 32])
    for qsel in range(32):
        for status in range(8):
            cases.append([2, rng.getrandbits(15) << 16 | status << 13 | qsel << 8
                          | rng.getrandbits(8) | rng.getrandbits(1) << 31])
    for _ in range(200):
        cases.append([2, rng.getrandbits(32)])
    scenarios = crafted_scenarios(rng) + [random_scenario(rng) for _ in range(30)]
    for scenario in scenarios:
        cases.append([3] + scenario.words)
    inputs = bytearray()
    for words in cases:
        body = le32(*words)
        inputs += le32(len(body)) + body
    input_path = out / 'tx_inputs.bin'
    input_path.write_bytes(bytes(inputs))

    exe = out / 'tx_oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function', '-Wno-unused-variable',
                    '-Wno-unused-but-set-variable', '-Wno-address-of-packed-member',
                    str(generated), '-o', str(exe)], check=True)
    outputs = out / 'tx_outputs.bin'
    run = subprocess.run([str(exe), str(input_path), str(outputs)], check=True,
                         capture_output=True, text=True)
    count = int(run.stdout.strip())
    if count != len(cases):
        raise ValueError(f'{count} TX cases run of {len(cases)}')
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
        raise ValueError('TX outputs left over')
    data = bytes(trace)
    (out / 'tx_trace.bin').write_bytes(data)
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest[first_symbol:], cases=len(cases), seed=TX_SEED,
        case_order='300 random descriptors (rtw89_core_fill_txdesc), 200 address infos '
                   '(rtw89_pci_fill_txaddr_info), 256 crafted and 200 random release reports '
                   '(rtw89_pci_parse_rpp), 6 crafted and 30 random ring scenarios',
        scenario_ops=sum(scenario.ops for scenario in scenarios),
        harness=dict(wd_dma_base=WD_DMA_BASE, wd_dma_step=WD_DMA_STEP, idx_base=IDX_BASE,
                     idx_step=4),
        dispatch=dict(rtw8852b_chip_info=info, rtw8852b_chip_ops=chip_ops,
                      rtw8852b_pci_info=pci_info),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'the cases are synthetic; no capture of what a chip reads or reports',
            'list.h and skbuff.h operations, DMA mapping, register access and '
            'ieee80211_tx_status_ni are the harness\'s',
            'rtw89_core_tx_wait_complete is a stub: no frame waits for its status',
            'the rings are set up as rtw89_pci_alloc_tx_ring leaves them, by the harness',
            'rtw89_pci_release_tx and rtw89_pci_release_tx_skbs (the RPQ buffer walk) are not '
            'run; each report goes to rtw89_pci_release_rpp directly',
        ])
    (out / 'tx_manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'scenario_ops', 'trace_bytes',
                                              'trace_sha256']}))


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
