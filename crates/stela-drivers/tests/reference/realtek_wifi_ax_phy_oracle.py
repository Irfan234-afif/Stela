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

dig_cfo_trace.bin comes from a second program, so the first and its trace
stay as they are. Extracted unchanged with it: what rtw89_phy_dm_init runs
of the tracking (rtw89_phy_env_monitor_init, rtw89_phy_nhm_setting_init,
rtw89_physts_parsing_init, rtw89_phy_dig_init, rtw89_phy_cfo_init) and what
rtw89_track_work runs (rtw89_phy_env_monitor_track, rtw89_phy_dig,
rtw89_phy_cfo_track), with rtw89_phy_cfo_track_work, rtw89_phy_cfo_parse,
rtw89_phy_dig_suspend and rtw89_phy_dig_resume, every CCX, IFS-CLM,
EDCCA-CLM, PHY status bitmap, DIG and CFO helper they reach, phy.c's
statics and tables (rtw89_ccx_regs_ax, rtw89_physts_regs_ax,
rtw89_cfo_regs_ax), rtw8852b.c's rtw8852b_dig_regs and rtw8852b_dcfo_comp,
the XTAL SI accessors, and the declarations they read; rtw8852b_chip_info's
DIG and CFO members and rtw89_phy_gen_ax's are checked, and so are the call
orders of rtw89_phy_dm_init and rtw89_track_work and the lines of
rtw89_core_setup_phycap (support_cckpd, support_igi) the harness runs. The
register model is the first program's, XTAL SI included. dyn_cases() lists
the cases: each is a cut, the efuse's crystal cap, the channel, monitor
mode and XTAL SI stuck or not, then two-second periods, each giving the
associated stations and their lowest RSSI, the channel, the TX and RX
throughput and trigger frames, words put in BAR2 for the IFS-CLM, EDCCA-CLM
and DCFO reports, the CFOs handed to rtw89_phy_cfo_parse, an event (DIG
suspended, resumed, resumed restoring, or a scan's end setting bypass_dig)
and how often the queued CFO work's timer fires after the track. A segment
per case records its inputs (58 for the case; per period 60 to 62, 63 per
word put in BAR2 and 64 per CFO), then the accesses in the trace.bin form,
markers 50 (0 init, 10 event, 11 CFO parse, 1 environment monitor, 2 DIG,
3 CFO track, 4 CFO work), warnings 70 by DYN_WARNINGS, a work queued 80
(delay in ms) and power save left 81, and after the init and each period
the state: the environment monitor 90 to 97, DIG 100 to 104, CFO 110 to
115.
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


DYN_WARNINGS = [
    'mac_id %d is out of range\\n',
    'xtal si not ready(R): offset=%x\\n',
    'xtal si not ready(W): offset=%x val=%x mask=%x\\n',
    'xtal si read: offset=%x poll=%x\\n',
]

# The words each step puts in BAR2 before its track, by BB register:
# R_IFSCNT, R_IFS_CLM_TX_CNT, R_IFS_CLM_CCA, R_IFS_CLM_FA, R_IFS_HIS,
# R_IFS_AVG_L, R_IFS_AVG_H, R_IFS_CCA_L, R_IFS_CCA_H, R_CLM_EDCCA_RDY (and
# _RESULT), R_DCFO.
DYN_WORD_REGS = [0x1aec, 0x1acc, 0x1ad0, 0x1ad4, 0x1ad8, 0x1adc, 0x1ae0, 0x1ae4, 0x1ae8,
                 0x1ac8, 0x4264]


def dyn_step(seed, sta=0, rssi=0, band=0, bw=0, tx=0, rx=0, tf=0, done=1, cck=0, ofdm=0,
             edcca=0x11234, dcfo=0x5a, cfo=(), fires=0, event=0):
    """One two-second period: the station count and lowest RSSI, the channel
    (band 0 2 GHz, 1 5 GHz; width 0 20, 1 40, 2 80 MHz), the TX and RX
    throughput and trigger frames, the report words, the CFOs parsed before
    the track as (MAC ID, CFO), the CFO work's timer firings after it, and
    an event before it (1 suspend, 2 resume, 3 resume restoring, 4 scan
    complete)."""
    def h(k):
        return (seed * 0x9e3779b1 + k * 0x7f4a7c15 + 0x1234567) & 0xffffffff
    words = [done << 16 | (seed * 0x2f1b) & 0xffff | (seed * 0x51 << 17) & 0xfffe0000,
             h(1), h(2), ofdm << 16 | cck, h(3), h(4), h(5), h(6), h(7), edcca,
             0x3c000000 | (h(8) & 0x00ffff00) | dcfo]
    return dict(sta=sta, rssi=rssi, band=band, bw=bw, tx=tx, rx=rx, tf=tf, words=words,
                cfo=list(cfo), fires=fires, event=event)


def dyn_cases():
    """(cut, efuse crystal cap, band, width, monitor, XTAL SI stuck, steps)."""
    cases = []
    s = iter(range(1, 1000))
    quiet = dict(cck=100, ofdm=100)
    # 2 GHz at cut CBV: unlinked quiet then noisy, linked as RSSI rises and
    # the air grows noisy, CFOs that move the cap by 1 and 3 and stop it, a
    # report not ready, then the link lost.
    cases.append((1, 0x3c, 0, 0, 0, 0, [
        dyn_step(next(s), cck=600, ofdm=600),
        dyn_step(next(s), cck=12000, ofdm=12000),
        dyn_step(next(s), sta=1, rssi=100, cfo=[(0, 40), (0, 60), (0, 50)], **quiet),
        dyn_step(next(s), sta=1, rssi=110, cck=1500, ofdm=1500, cfo=[(0, 150), (0, 150)]),
        dyn_step(next(s), sta=1, rssi=120, cck=4000, ofdm=4000, cfo=[(0, -30), (0, -20)],
                 dcfo=0x07),
        dyn_step(next(s), sta=1, rssi=130, cck=4000, ofdm=4000, cfo=[(0, 5)]),
        dyn_step(next(s), sta=1, rssi=140, done=0, edcca=0x0000ffff),
        dyn_step(next(s), cck=300, ofdm=300),
        dyn_step(next(s), cck=300, ofdm=300),
    ]))
    # 5 GHz 80 MHz at cut CAV (no CCK PD), the cap near its lower bound:
    # pushed down to it, locked, stepped back to the default while locked,
    # then released.
    steps = [dyn_step(next(s), cck=50, ofdm=50, band=1, bw=2)]
    for rssi in (60, 70, 80, 90):
        steps.append(dyn_step(next(s), sta=1, rssi=rssi, band=1, bw=2, cck=rssi * 3,
                              ofdm=rssi * 5, cfo=[(0, -200)] * 3, dcfo=0x81))
    for i in range(17):
        steps.append(dyn_step(next(s), sta=1, rssi=100 + i, band=1, bw=2, cck=200 + 37 * i,
                              ofdm=150 + 91 * i, cfo=[(0, -60 + 9 * i)]))
    cases.append((0, 0x0a, 1, 2, 0, 0, steps))
    # 2 GHz 40 MHz at cut 2, high TX throughput: the CFO work's timer, the
    # enhanced state held under trigger frames, then dropped.
    steps = [dyn_step(next(s), sta=1, rssi=90, bw=1, tx=150, rx=20, cfo=[(0, 100)], fires=8,
                      **quiet)]
    for i in range(16):
        steps.append(dyn_step(next(s), sta=1, rssi=90, bw=1, tx=150, rx=20, tf=400,
                              cfo=[(0, 100 - 13 * i)], fires=2, cck=500, ofdm=900))
    steps += [dyn_step(next(s), sta=1, rssi=92, bw=1, tx=40, rx=20, cfo=[(0, 70)], fires=2),
              dyn_step(next(s), sta=1, rssi=92, bw=1, tx=40, cfo=[(0, 70)])]
    cases.append((2, 0x7c, 0, 1, 0, 0, steps))
    # 5 GHz 20 MHz, several stations: equal and opposed averages, a station
    # silent, one MAC ID out of range, then one station.
    cases.append((1, 0x40, 1, 0, 0, 0, [
        dyn_step(next(s), sta=2, rssi=80, band=1, cfo=[(0, -40), (1, -40), (70, 5)]),
        dyn_step(next(s), sta=2, rssi=80, band=1, cfo=[(0, 80), (1, -80)]),
        dyn_step(next(s), sta=3, rssi=82, band=1, cfo=[(2, 60)]),
        dyn_step(next(s), sta=1, rssi=84, band=1, cfo=[(5, 30), (5, 34)]),
    ]))
    # 2 GHz: strong signal in noisy air until the PD diagnosis, suspend and
    # resume, a scan's end, the extremes of RSSI.
    noisy = dict(cck=9000, ofdm=9000)
    steps = [dyn_step(next(s), sta=1, rssi=160, **noisy) for _ in range(7)]
    steps += [dyn_step(next(s), sta=1, rssi=160, event=1, **noisy),
              dyn_step(next(s), sta=1, rssi=150, event=3, **noisy),
              dyn_step(next(s), sta=1, rssi=150, event=4, **quiet),
              dyn_step(next(s), sta=1, rssi=150, event=2, **quiet),
              dyn_step(next(s), sta=1, rssi=220, event=1, **quiet),
              dyn_step(next(s), sta=1, rssi=220, event=2, **quiet),
              dyn_step(next(s), sta=1, rssi=0, **quiet),
              dyn_step(next(s), sta=1, rssi=255, cck=0xffff, ofdm=0xffff)]
    cases.append((1, 0x30, 0, 0, 0, 0, steps))
    # XTAL SI never answering, linked with no CFO.
    cases.append((1, 0x2d, 0, 0, 0, 1, [dyn_step(next(s), sta=1, rssi=100, **quiet)]))
    # Monitor mode's bitmaps on 5 GHz 40 MHz; then unlinked on 5 GHz 80 MHz
    # and first connected on 2 GHz.
    cases.append((1, 0x2d, 1, 1, 1, 0, [
        dyn_step(next(s), band=1, bw=1, **quiet),
        dyn_step(next(s), sta=1, rssi=120, band=1, bw=1, cck=700, ofdm=200),
    ]))
    cases.append((1, 0x55, 1, 2, 0, 0, [
        dyn_step(next(s), band=1, bw=2, cck=400, ofdm=4000),
        dyn_step(next(s), sta=1, rssi=96, cck=400, ofdm=4000),
        dyn_step(next(s), sta=1, rssi=96, cck=40, ofdm=40, cfo=[(0, -9), (0, -10)]),
    ]))
    return cases


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

    # The tracking rtw89_track_work runs (dig_cfo_trace.bin): a second
    # program, so the one above and its trace stay as they are.
    def statics(file, names):
        """File-scope static const definitions of one line holding the names."""
        text = source(file)
        found_lines = []
        for name in names:
            found = re.findall(r'^static const [^\n]*\b' + re.escape(name) + r'\b[^\n]*;$',
                               text, re.M)
            if len(found) != 1:
                raise ValueError(f'{file}: static {name} appears {len(found)} times')
            if found[0] not in found_lines:
                found_lines.append(found[0])
        return record(file, f'static {" ".join(names)}', '\n'.join(found_lines))

    chip_dyn = check('rtw8852b_chip_info (tracking)', fields(
        'rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
        ['dig_table', 'dig_regs', 'support_noise', 'cfo_src_fd', 'cfo_hw_comp', 'dcfo_comp',
         'dcfo_comp_sft', 'xtal_info']), {
        'dig_table': 'NULL', 'dig_regs': '&rtw8852b_dig_regs', 'support_noise': 'false',
        'cfo_src_fd': 'true', 'cfo_hw_comp': 'true', 'dcfo_comp': '&rtw8852b_dcfo_comp',
        'dcfo_comp_sft': '10', 'xtal_info': 'NULL'})
    phy_gen_dyn = check('rtw89_phy_gen_ax (tracking)', fields(
        'phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax',
        ['physt_bmp_start', 'physt_bmp_eht', 'physt_gen', 'ccx', 'physts', 'cfo']), {
        'physt_bmp_start': 'R_PHY_STS_BITMAP_ADDR_START', 'physt_bmp_eht': '0xfc',
        'physt_gen': '0', 'ccx': '&rtw89_ccx_regs_ax', 'physts': '&rtw89_physts_regs_ax',
        'cfo': '&rtw89_cfo_regs_ax'})
    calls_in_order('phy.c', 'rtw89_phy_dm_init', [
        'rtw89_phy_env_monitor_init(rtwdev);', 'rtw89_phy_nhm_setting_init(rtwdev);',
        'rtw89_physts_parsing_init(rtwdev);', 'rtw89_phy_dig_init(rtwdev);',
        'rtw89_phy_cfo_init(rtwdev);', 'rtw89_phy_init_rf_nctl(rtwdev);'])
    calls_in_order('core.c', 'rtw89_track_work', [
        'if (rtwdev->scanning)', 'rtw89_phy_stat_track(rtwdev);',
        'rtw89_phy_env_monitor_track(rtwdev);', 'rtw89_phy_dig(rtwdev);',
        'rtw89_core_rfk_track(rtwdev);', 'rtw89_phy_cfo_track(rtwdev);'])
    phycap = ('\trtwdev->hal.support_cckpd =\n'
              '\t\t!(rtwdev->chip->chip_id == RTL8852A && rtwdev->hal.cv <= CHIP_CBV) &&\n'
              '\t\t!(rtwdev->chip->chip_id == RTL8852B && rtwdev->hal.cv <= CHIP_CAV);\n'
              '\trtwdev->hal.support_igi =\n'
              '\t\trtwdev->chip->chip_id == RTL8852A && rtwdev->hal.cv <= CHIP_CBV;\n')
    if phycap not in locate('core.c', 'rtw89_core_setup_phycap')[1]:
        raise ValueError('rtw89_core_setup_phycap no longer sets support_cckpd and '
                         'support_igi as the harness does')
    if '\t\tbb->dig.bypass_dig = true;\n' not in locate('core.c', 'rtw89_core_scan_complete')[1]:
        raise ValueError('rtw89_core_scan_complete no longer sets bypass_dig')

    dyn_head = '\n'.join([
        defines('core.h', ['MASKDWORD', 'RF_PATH_MAX', 'CFO_TRACK_MAX_USER', 'IGI_RSSI_TH_NUM',
                           'FA_TH_NUM', 'LNA_GAIN_NUM', 'TIA_GAIN_NUM', 'RTW89_NHM_TH_NUM',
                           'RTW89_NHM_RPT_NUM', 'RTW89_IFS_CLM_NUM']),
        macro('core.h', 'RTW89_REGS_DEF'),
        defines('phy.h', [
            'phy_div', 'CFO_TRK_ENABLE_TH', 'CFO_TRK_STOP_TH_4', 'CFO_TRK_STOP_TH_3',
            'CFO_TRK_STOP_TH_2', 'CFO_TRK_STOP_TH_1', 'CFO_TRK_STOP_TH',
            'CFO_SW_COMP_FINE_TUNE', 'CFO_PERIOD_CNT', 'CFO_BOUND', 'CFO_TP_UPPER',
            'CFO_TP_LOWER', 'CFO_COMP_PERIOD', 'CFO_TF_CNT_TH', 'CCX_MAX_PERIOD',
            'CCX_MAX_PERIOD_UNIT', 'MS_TO_4US_RATIO', 'ENV_MNTR_FAIL_DWORD',
            'ENV_MNTR_IFSCLM_HIS_MAX', 'PERMIL', 'PERCENT', 'IFS_CLM_TH0_UPPER',
            'IFS_CLM_TH_MUL', 'IFS_CLM_TH_START_IDX', 'TIA0_GAIN_A', 'TIA0_GAIN_G', 'LNA0_GAIN',
            'U4_MAX_BIT', 'U8_MAX_BIT', 'DIG_GAIN_SHIFT', 'DIG_GAIN', 'LNA_IDX_MAX',
            'LNA_IDX_MIN', 'TIA_IDX_MAX', 'TIA_IDX_MIN', 'RXB_IDX_MAX', 'RXB_IDX_MIN',
            'IGI_RSSI_MAX', 'PD_TH_MAX_RSSI', 'PD_TH_MIN_RSSI', 'CCKPD_TH_MIN_RSSI',
            'PD_TH_BW160_CMP_VAL', 'PD_TH_BW80_CMP_VAL', 'PD_TH_BW40_CMP_VAL',
            'PD_TH_BW20_CMP_VAL', 'PD_TH_SB_FLTR_CMP_VAL', 'CCX_US_BASE_RATIO']),
        macro('core.h', 'rtw89_for_each_active_bb'),
        macro('core.h', 'rtw89_for_each_capab_bb'),
    ])
    dyn_decls = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_core_chip_id', 'rtw89_chip_gen', 'rtw89_cv', 'rtw89_band', 'rtw89_bandwidth',
            'rtw89_phy_idx', 'rtw89_flags', 'rtw89_dig_noisy_level', 'rtw89_dm_type',
            'rtw89_entity_mode', 'rtw89_multi_cfo_mode', 'rtw89_phy_cfo_status',
            'rtw89_phy_cfo_ul_ofdma_acc_mode', 'rtw89_ifs_clm_application',
            'rtw89_env_racing_lv', 'rtw89_ccx_edcca_opt_bw_idx', 'rtw89_diag_bb_type']]
        + [declaration('mac.h', 'enum', 'rtw89_mac_xtal_si_offset')]
        + [declaration('phy.h', 'enum', name) for name in [
            'rtw89_env_monitor_result_level', 'rtw89_ccx_unit', 'rtw89_phy_status_ie_type',
            'rtw89_phy_status_bitmap', 'rtw89_dig_gain_type', 'rtw89_dig_gain_lna_idx',
            'rtw89_dig_gain_tia_idx']]
        + [declaration('core.h', 'struct', name) for name in [
            'rtw89_reg_def', 'rtw89_regs_def', 'rtw89_xtal_info', 'rtw89_dig_regs',
            'rtw89_phy_ch_info', 'rtw89_diag_bb', 'rtw89_agc_gaincode_set', 'rtw89_dig_info',
            'rtw89_cfo_tracking_info', 'rtw89_ccx_para_info', 'rtw89_nhm_report',
            'rtw89_env_monitor_info']]
        + [declaration('phy.h', 'struct', name) for name in [
            'rtw89_phy_dig_gain_cfg', 'rtw89_phy_dig_gain_table', 'rtw89_ccx_regs',
            'rtw89_physts_regs', 'rtw89_cfo_regs']])
    dyn_tables = '\n\n'.join([
        definition('phy.c', 'static const struct rtw89_ccx_regs rtw89_ccx_regs_ax'),
        definition('phy.c', 'static const u32 rtw89_txinfo_reg_ax[]'),
        definition('phy.c', 'static const u32 rtw89_tx_common_ctrl_reg_ax[]'),
        definition('phy.c', 'static const struct rtw89_reg_def rtw89_txpwr_ax[]'),
        definition('phy.c', 'static const struct rtw89_physts_regs rtw89_physts_regs_ax'),
        definition('phy.c', 'static const struct rtw89_cfo_regs rtw89_cfo_regs_ax'),
        definition('rtw8852b.c', 'static const struct rtw89_reg_def rtw8852b_dcfo_comp'),
        definition('rtw8852b.c', 'static const struct rtw89_dig_regs rtw8852b_dig_regs'),
        statics('phy.c', ['rssi_nolink', 'igi_rssi_th', 'fa_th_2g', 'fa_th_5g', 'fa_th_nolink',
                          'pd_low_th_offset', 'dynamic_igi_min', 'igi_max_performance_mode',
                          'dynamic_pd_threshold_max']),
    ])
    dyn_core_h = in_order('core.h', [
        'rtw89_read32_mask', 'rtw89_write32_mask', 'rtw89_write32_set', 'rtw89_write32_clr'])
    dyn_phy_h = in_order('phy.h', [
        'rtw89_phy_write32_set', 'rtw89_phy_write32_clr', 'rtw89_phy_write32_mask',
        'rtw89_phy_read32_mask'])
    dyn_mac = '\n\n'.join([
        in_order('mac.h', ['rtw89_mac_write_xtal_si', 'rtw89_mac_read_xtal_si']),
        in_order('mac.c', ['rtw89_mac_write_xtal_si_ax', 'rtw89_mac_read_xtal_si_ax'])])
    dyn_phy_c = in_order('phy.c', [
        'rtw89_phy_write32_idx', 'rtw89_phy_write32_idx_set', 'rtw89_phy_write32_idx_clr',
        'rtw89_phy_read32_idx', 'rtw89_phy_set_phy_regs',
        'rtw89_phy_cfo_get_xcap_reg', 'rtw89_phy_cfo_set_xcap_reg',
        'rtw89_phy_cfo_set_crystal_cap', 'rtw89_phy_cfo_reset', 'rtw89_dcfo_comp',
        'rtw89_dcfo_comp_init', 'rtw89_phy_cfo_init', 'rtw89_phy_cfo_crystal_cap_adjust',
        'rtw89_phy_average_cfo_calc', 'rtw89_phy_multi_sta_cfo_calc',
        'rtw89_phy_cfo_statistics_reset', 'rtw89_phy_cfo_dm', 'rtw89_phy_cfo_track_work',
        'rtw89_phy_cfo_start_work', 'rtw89_phy_cfo_track', 'rtw89_phy_cfo_parse',
        'rtw89_phy_ccx_us_to_idx', 'rtw89_phy_ccx_idx_to_us', 'rtw89_phy_ccx_top_setting_init',
        'rtw89_phy_ccx_get_report', 'rtw89_phy_ccx_ms_to_period_unit',
        'rtw89_phy_ccx_racing_release', 'rtw89_phy_ifs_clm_th_update_check',
        'rtw89_phy_ifs_clm_set_th_reg', '__rtw89_phy_nhm_setting_init',
        'rtw89_phy_nhm_setting_init', 'rtw89_phy_ifs_clm_setting_init',
        'rtw89_phy_ccx_racing_ctrl', 'rtw89_phy_ccx_trigger', 'rtw89_phy_ifs_clm_get_utility',
        'rtw89_phy_ifs_clm_get_result', 'rtw89_phy_edcca_clm_get_result',
        'rtw89_phy_ifs_clm_set', '__rtw89_phy_env_monitor_track',
        'rtw89_phy_env_monitor_track', 'rtw89_physts_ie_page_valid',
        'rtw89_phy_get_ie_bitmap_addr', 'rtw89_physts_get_ie_bitmap',
        'rtw89_physts_set_ie_bitmap', 'rtw89_physts_enable_fail_report',
        'rtw89_physts_enable_hdr_2', '__rtw89_physts_parsing_init', 'rtw89_physts_parsing_init',
        'rtw89_phy_dig_read_gain_table', 'rtw89_phy_dig_update_gain_para',
        'rtw89_phy_dig_update_rssi_info', 'rtw89_phy_dig_update_para',
        'rtw89_phy_dig_para_reset', '__rtw89_phy_dig_init', 'rtw89_phy_dig_init',
        'rtw89_phy_dig_lna_idx_by_rssi', 'rtw89_phy_dig_tia_idx_by_rssi',
        'rtw89_phy_dig_rxb_idx_by_rssi', 'rtw89_phy_dig_gaincode_by_rssi',
        'rtw89_phy_dig_igi_offset_by_env', 'rtw89_phy_dig_set_lna_idx',
        'rtw89_phy_dig_set_tia_idx', 'rtw89_phy_dig_set_rxb_idx', 'rtw89_phy_dig_set_igi_cr',
        'rtw89_phy_dig_sdagc_follow_pagc_config', 'rtw89_phy_dig_config_igi',
        'rtw89_phy_dig_cal_under_region', '__rtw89_phy_dig_dyn_pd_th',
        'rtw89_phy_dig_dyn_pd_th', 'rtw89_phy_dig_reset', 'rtw89_phy_dig_diag',
        'rtw89_phy_cal_igi_fa_rssi', 'rtw89_phy_dig_ctrl', 'rtw89_phy_dig_suspend',
        'rtw89_phy_dig_resume', '__rtw89_phy_dig', 'rtw89_phy_dig',
        '__rtw89_phy_env_monitor_init', 'rtw89_phy_env_monitor_init'])
    for text in DYN_WARNINGS:
        if '"' + text + '"' not in dyn_phy_c + dyn_mac:
            raise ValueError(f'no rtw89 format "{text}" in the extracted tracking code')

    dyn_preamble = r'''
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define test_bit(nr, addr) ((int)(((addr)[(nr) / 64] >> ((nr) % 64)) & 1))
#define unlikely(x) (x)
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
#define fallthrough __attribute__((__fallthrough__))
#define lockdep_assert_wiphy(w) ((void)(w))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define msecs_to_jiffies(ms) (ms)
#define ilog2(n) (31 - __builtin_clz(n))
#define abs(x) ({ __typeof__(x) __x = (x); __x < 0 ? -__x : __x; })
#define min(a, b) ({ __typeof__(a) __a = (a); __typeof__(b) __b = (b); __a < __b ? __a : __b; })
#define max(a, b) ({ __typeof__(a) __a = (a); __typeof__(b) __b = (b); __a > __b ? __a : __b; })
#define clamp(v, lo, hi) min(max(v, lo), hi)
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define clamp_t(t, v, lo, hi) min_t(t, max_t(t, v, lo), hi)
static inline s32 sign_extend32(u32 value, int index)
{
	u8 shift = 31 - index;
	return (s32)(value << shift) >> shift;
}
#define RTW89_DBG_DIG BIT(1)
#define RTW89_DBG_PHY_TRACK BIT(2)
#define RTW89_DBG_CFO BIT(3)
#define IEEE80211_CONF_MONITOR BIT(0)
static void sink(const char *format, ...) { (void)format; }
static void logged(const char *format, ...);
#define rtw89_warn(d, ...) ((void)(d), logged(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), logged(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
static void model_delay(u64 us);
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
struct list_head { struct list_head *next, *prev; };
struct ieee80211_channel;
struct wiphy { int unused; };
struct wiphy_work { int unused; };
struct wiphy_delayed_work { struct wiphy_work work; };
struct rtw89_dev;
'''
    dyn_harness = r'''
struct rtw89_mac_gen_def {
	int (*write_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 val, u8 mask);
	int (*read_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 *val);
};
struct rtw89_phy_gen_def {
	u32 cr_base;
	u32 physt_bmp_start;
	u32 physt_bmp_eht;
	u8 physt_gen;
	const struct rtw89_ccx_regs *ccx;
	const struct rtw89_physts_regs *physts;
	const struct rtw89_cfo_regs *cfo;
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_mac_gen_def *mac_def;
	const struct rtw89_phy_gen_def *phy_def;
	const struct rtw89_phy_dig_gain_table *dig_table;
	const struct rtw89_dig_regs *dig_regs;
	bool support_noise;
	bool cfo_hw_comp;
	const struct rtw89_reg_def *dcfo_comp;
	u8 dcfo_comp_sft;
	const struct rtw89_xtal_info *xtal_info;
};
struct rtw89_hal {
	u8 cv;
	bool support_cckpd;
	bool support_igi;
	u32 disabled_dm_bitmap;
	u8 fixed_dig_pd_th;
	s8 fixed_dig_cck_pd_th;
};
struct rtw89_efuse { u8 xtal_cap; };
struct rtw89_traffic_stats { u32 tx_throughput, rx_throughput, rx_tf_periodic; };
struct ewma_thermal { unsigned long internal; };
struct rtw89_phy_stat { struct ewma_thermal avg_thermal[RF_PATH_MAX]; };
struct rtw89_bb_ctx {
	enum rtw89_phy_idx phy_idx;
	struct rtw89_env_monitor_info env_monitor;
	struct rtw89_dig_info dig;
	struct rtw89_phy_ch_info ch_info;
	struct rtw89_diag_bb diag;
};
struct ieee80211_conf { u32 flags; };
struct ieee80211_hw { struct wiphy *wiphy; struct ieee80211_conf conf; };
struct rtw89_chan { enum rtw89_band band_type; enum rtw89_bandwidth band_width; };
struct rtw89_rx_phy_ppdu { u8 mac_id; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	struct rtw89_hal hal;
	struct rtw89_efuse efuse;
	struct rtw89_cfo_tracking_info cfo_tracking;
	struct rtw89_traffic_stats stats;
	struct rtw89_phy_stat phystat;
	struct rtw89_bb_ctx bbs[RTW89_PHY_NUM];
	struct ieee80211_hw *hw;
	struct wiphy_delayed_work cfo_track_work;
	struct rtw89_chan chan;
	u8 total_sta_assoc;
	bool dbcc_en;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
};
/* rtw89_core_setup_phycap's two lines, as checked. */
static void setup_phycap(struct rtw89_dev *rtwdev)
{
''' + phycap + r'''}
/* One channel context and PHY 0 alone. */
struct rtw89_entity_conf { const struct rtw89_chan *chans[RTW89_PHY_NUM]; };
static void rtw89_entity_get_conf(struct rtw89_dev *d, struct rtw89_entity_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->chans[RTW89_PHY_0] = &d->chan;
}
static enum rtw89_entity_mode rtw89_get_entity_mode(struct rtw89_dev *d)
{
	(void)d;
	return RTW89_ENTITY_MODE_SCC_OR_SMLD;
}
static u8 rtw89_get_active_phy_bitmap(struct rtw89_dev *d) { (void)d; return BIT(RTW89_PHY_0); }
static bool rtw89_is_mlo_1_1(struct rtw89_dev *d) { (void)d; return false; }
static unsigned long ewma_thermal_read(struct ewma_thermal *e) { return e->internal >> 4; }
/* Reached only with DBCC or in MCC: neither is. */
static u32 rtw89_phy0_phy1_offset(struct rtw89_dev *d, u32 a) { (void)d; (void)a; abort(); }
static void rtw89_phy_dig_mcc(struct rtw89_dev *d, struct rtw89_bb_ctx *bb)
{ (void)d; (void)bb; abort(); }
void rtw89_phy_dig_reset(struct rtw89_dev *rtwdev, struct rtw89_bb_ctx *bb);

/* The register model: BAR2 as bytes, behaving per aligned word, and the
 * XTAL SI file behind WLAN_XTAL_SI_CTRL. */
#define HARNESS_CR_BASE 0x10000u
static u8 memory[0x20000];
static u8 xtal[256];
static int xtal_stuck, logging, queued;
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
static u32 model_read(u32 r, u32 n)
{
	check(r, n);
	u32 v = get(r & ~3u, 4) >> ((r & 3) * 8);
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
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* Warnings by format, held until the step ends. */
static const char *const formats[] = {
''' + ',\n'.join('\t"' + text + '"' for text in DYN_WARNINGS) + r'''
};
static u32 warns[1 << 12];
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
/* The work queue and power save: the delay a work is queued with (80), and
 * leaving power save (81). */
static void wiphy_delayed_work_queue(struct wiphy *w, struct wiphy_delayed_work *dw,
				     unsigned long delay)
{
	(void)w;
	(void)dw;
	queued = 1;
	record(80, (u32)delay, 0);
}
static void rtw89_leave_ps_mode(struct rtw89_dev *d) { (void)d; record(81, 0, 0); }
'''
    words_c = ', '.join('0x%x' % r for r in DYN_WORD_REGS)
    dcases = dyn_cases()
    step_rows, case_rows = [], []
    for case in dcases:
        cv, cap, band, bw, monitor, stuck, steps = case
        case_rows.append('\t{%d, 0x%x, %d, %d, %d, %d, %d, %d}' % (
            cv, cap, band, bw, monitor, stuck, len(step_rows), len(steps)))
        for st in steps:
            if len(st['cfo']) > 4:
                raise ValueError('a step parses at most four CFOs')
            macids = [m for m, _ in st['cfo']] + [0] * (4 - len(st['cfo']))
            cfos = [c for _, c in st['cfo']] + [0] * (4 - len(st['cfo']))
            step_rows.append('\t{%d, %d, %d, %d, %d, %d, %d, {%s}, %d, %d, %d, {%s}, {%s}}' % (
                st['sta'], st['rssi'], st['band'], st['bw'], st['tx'], st['rx'], st['tf'],
                ', '.join('0x%x' % w for w in st['words']), st['fires'], st['event'],
                len(st['cfo']), ', '.join(map(str, macids)), ', '.join(map(str, cfos))))
    dyn_main = r'''
static const struct rtw89_mac_gen_def mac_gen_ax = {
	.write_xtal_si = rtw89_mac_write_xtal_si_ax,
	.read_xtal_si = rtw89_mac_read_xtal_si_ax,
};
static const struct rtw89_phy_gen_def phy_gen_ax = {
	.cr_base = 0x10000,
	.physt_bmp_start = R_PHY_STS_BITMAP_ADDR_START,
	.physt_bmp_eht = 0xfc,
	.physt_gen = 0,
	.ccx = &rtw89_ccx_regs_ax,
	.physts = &rtw89_physts_regs_ax,
	.cfo = &rtw89_cfo_regs_ax,
};
static const struct rtw89_chip_info chip = {
	.chip_id = RTL8852B,
	.chip_gen = RTW89_CHIP_AX,
	.mac_def = &mac_gen_ax,
	.phy_def = &phy_gen_ax,
	.dig_table = NULL,
	.dig_regs = &rtw8852b_dig_regs,
	.support_noise = false,
	.cfo_hw_comp = true,
	.dcfo_comp = &rtw8852b_dcfo_comp,
	.dcfo_comp_sft = 10,
	.xtal_info = NULL,
};
static const u32 word_regs[] = {''' + words_c + r'''};
struct step {
	u8 sta, rssi, band, bw;
	u32 tx, rx, tf;
	u32 words[ARRAY_SIZE(word_regs)];
	u8 fires, event, ncfo;
	u8 macid[4];
	s16 cfo[4];
};
static const struct step steps[] = {
''' + ',\n'.join(step_rows) + r'''
};
struct kase { u32 cv, cap, band, bw, monitor, stuck, first, n; };
static const struct kase cases[] = {
''' + ',\n'.join(case_rows) + r'''
};
static void record_state(const struct rtw89_dev *d)
{
	const struct rtw89_bb_ctx *bb = &d->bbs[RTW89_PHY_0];
	const struct rtw89_env_monitor_info *e = &bb->env_monitor;
	const struct rtw89_dig_info *g = &bb->dig;
	const struct rtw89_cfo_tracking_info *c = &d->cfo_tracking;

	record(90, e->ccx_watchdog_result | (u32)e->ccx_ongoing << 8 | (u32)e->ccx_rac_lv << 16 |
		   (u32)e->ccx_unit_idx << 24, e->ifs_clm_mntr_time | (u32)e->ccx_period << 16);
	record(91, (u32)e->ifs_clm_app | (u32)e->edcca_clm_ratio << 8 |
		   (u32)e->ifs_clm_tx_ratio << 16 | (u32)e->ifs_clm_edcca_excl_cca_ratio << 24,
	       e->ifs_clm_cck_fa_ratio | (u32)e->ifs_clm_ofdm_fa_ratio << 8 |
		   (u32)e->ifs_clm_cck_cca_excl_fa_ratio << 16 |
		   (u32)e->ifs_clm_ofdm_cca_excl_fa_ratio << 24);
	record(92, e->ifs_clm_cck_fa_permil | (u32)e->ifs_clm_ofdm_fa_permil << 16,
	       e->ifs_clm_total_ifs | (u32)e->ifs_clm_tx << 16);
	record(93, e->ifs_clm_cckfa | (u32)e->ifs_clm_ofdmfa << 16,
	       e->ifs_clm_cckcca_excl_fa | (u32)e->ifs_clm_ofdmcca_excl_fa << 16);
	record(94, e->ifs_clm_edcca_excl_cca, 0);
	for (u32 i = 0; i < RTW89_IFS_CLM_NUM; i++) {
		record(95, i | (u32)e->ifs_clm_th_l[i] << 16,
		       e->ifs_clm_th_h[i] | (u32)e->ifs_clm_his[i] << 16);
		record(96, e->ifs_clm_avg[i] | (u32)e->ifs_clm_cca[i] << 16, e->ifs_clm_ifs_avg[i]);
		record(97, i, e->ifs_clm_cca_avg[i]);
	}
	record(100, g->igi_rssi | (u32)g->igi_fa_rssi << 8 | (u32)g->fa_rssi_ofst << 16 |
		    (u32)g->dyn_igi_max << 24,
	       g->dyn_igi_min | (u32)g->dyn_pd_th_max << 8 | (u32)g->dyn_pd_max_cnt << 16 |
		   (u32)g->pd_low_th_ofst << 24);
	record(101, (u8)g->noisy_lv | (u32)g->dyn_pd_th_en << 8 | (u32)g->is_linked_pre << 9 |
		    (u32)g->bypass_dig << 10 | (u32)g->pause_dig << 11, g->bak_dig);
	record(102, g->fa_th[0] | (u32)g->fa_th[1] << 16, g->fa_th[2] | (u32)g->fa_th[3] << 16);
	record(103, g->igi_rssi_th[0] | (u32)g->igi_rssi_th[1] << 8 |
		    (u32)g->igi_rssi_th[2] << 16 | (u32)g->igi_rssi_th[3] << 24, g->igi_rssi_th[4]);
	record(104, bb->diag.diag_bb_bitmap, bb->diag.diag_bb_cnt[RTW89_DIAG_BB_PD]);
	record(110, c->cfo_timer_ms | (u32)c->cfo_trig_by_timer_en << 16 |
		    (u32)c->phy_cfo_status << 20 | (u32)c->is_adjust << 24 |
		    (u32)c->divergence_lock_en << 25,
	       c->phy_cfo_trk_cnt | (u32)c->crystal_cap << 8 | (u32)c->crystal_cap_default << 16 |
		   (u32)c->def_x_cap << 24);
	record(111, (u8)c->x_cap_ofst | (u32)c->x_cap_lb << 8 | (u32)c->x_cap_ub << 16 |
		    (u32)c->lock_cnt << 24, c->packet_count);
	record(112, (u32)c->cfo_avg_pre, (u32)c->dcfo_avg);
	record(113, (u32)c->dcfo_avg_pre, c->packet_count_pre);
	for (u32 i = 0; i < CFO_TRACK_MAX_USER; i++) {
		if (!c->cfo_tail[i] && !c->cfo_cnt[i] && !c->cfo_avg[i] && !c->pre_cfo_avg[i])
			continue;
		record(114, i | (u32)c->cfo_cnt[i] << 16, (u32)c->cfo_tail[i]);
		record(115, (u32)c->cfo_avg[i], (u32)c->pre_cfo_avg[i]);
	}
}
static void out32(FILE *o, u32 v)
{
	if (fwrite(&v, 4, 1, o) != 1)
		abort();
}
int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	static struct wiphy wiphy;
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		const struct kase *k = &cases[c];
		static struct rtw89_dev dev;
		static struct ieee80211_hw hw;
		for (u32 i = 0; i < sizeof(memory); i++)
			memory[i] = (u8)(i * 37 + 11);
		for (u32 i = 0; i < sizeof(xtal); i++)
			xtal[i] = (u8)(i * 29 + 0x47);
		xtal_stuck = k->stuck;
		segment_bytes = 0;
		n_warns = 0;
		queued = 0;
		logging = 1;
		memset(&dev, 0, sizeof(dev));
		memset(&hw, 0, sizeof(hw));
		hw.wiphy = &wiphy;
		hw.conf.flags = k->monitor ? IEEE80211_CONF_MONITOR : 0;
		dev.chip = &chip;
		dev.hw = &hw;
		dev.hal.cv = (u8)k->cv;
		dev.efuse.xtal_cap = (u8)k->cap;
		dev.chan.band_type = k->band;
		dev.chan.band_width = k->bw;
		for (u32 p = 0; p < RTW89_PHY_NUM; p++)
			dev.bbs[p].phy_idx = p;
		setup_phycap(&dev);
		record(58, k->cv | k->cap << 8 | k->band << 16 | k->bw << 24,
		       k->monitor | k->stuck << 8);
		/* rtw89_phy_dm_init's tracking part, in its order. */
		record(50, 0, 0);
		rtw89_phy_env_monitor_init(&dev);
		rtw89_phy_nhm_setting_init(&dev);
		rtw89_physts_parsing_init(&dev);
		rtw89_phy_dig_init(&dev);
		rtw89_phy_cfo_init(&dev);
		flush();
		record_state(&dev);
		for (u32 n = 0; n < k->n; n++) {
			const struct step *s = &steps[k->first + n];
			struct rtw89_bb_ctx *bb = &dev.bbs[RTW89_PHY_0];

			record(60, n, s->sta | (u32)s->rssi << 8 | (u32)s->band << 16 |
				      (u32)s->bw << 24);
			record(61, s->tx, s->rx);
			record(62, s->tf, s->fires | (u32)s->event << 8 | (u32)s->ncfo << 16);
			for (u32 i = 0; i < ARRAY_SIZE(word_regs); i++) {
				set(HARNESS_CR_BASE + word_regs[i], 4, s->words[i]);
				record(63, word_regs[i], s->words[i]);
			}
			for (u32 i = 0; i < s->ncfo; i++)
				record(64, s->macid[i], (u16)s->cfo[i]);
			dev.total_sta_assoc = s->sta;
			bb->ch_info.rssi_min = s->rssi;
			dev.chan.band_type = s->band;
			dev.chan.band_width = s->bw;
			dev.stats.tx_throughput = s->tx;
			dev.stats.rx_throughput = s->rx;
			dev.stats.rx_tf_periodic = s->tf;
			if (s->event) {
				record(50, 10, s->event);
				switch (s->event) {
				case 1:
					rtw89_phy_dig_suspend(&dev);
					break;
				case 2:
					rtw89_phy_dig_resume(&dev, false);
					break;
				case 3:
					rtw89_phy_dig_resume(&dev, true);
					break;
				case 4:
					bb->dig.bypass_dig = true;
					break;
				}
				flush();
			}
			record(50, 11, 0);
			for (u32 i = 0; i < s->ncfo; i++) {
				struct rtw89_rx_phy_ppdu ppdu = {.mac_id = s->macid[i]};
				rtw89_phy_cfo_parse(&dev, s->cfo[i], &ppdu);
			}
			flush();
			record(50, 1, 0);
			rtw89_phy_env_monitor_track(&dev);
			flush();
			record(50, 2, 0);
			rtw89_phy_dig(&dev);
			flush();
			record(50, 3, 0);
			rtw89_phy_cfo_track(&dev);
			flush();
			for (u32 f = 0; f < s->fires; f++) {
				if (!queued)
					continue;
				queued = 0;
				record(50, 4, f);
				rtw89_phy_cfo_track_work(&wiphy, &dev.cfo_track_work.work);
				flush();
			}
			record_state(&dev);
		}
		out32(out, (u32)segment_bytes);
		if (segment_bytes && fwrite(segment, segment_bytes, 1, out) != 1)
			abort();
	}
	if (fclose(out))
		abort();
	free(segment);
	printf("{\"cases\": %zu, \"steps\": %zu}\n", ARRAY_SIZE(cases), ARRAY_SIZE(steps));
	return 0;
}
'''
    dyn_program = '\n\n'.join([
        dyn_preamble, reg_h, dyn_head, dyn_decls, dyn_harness, dyn_tables, dyn_core_h, dyn_phy_h,
        dyn_mac, dyn_phy_c, dyn_main])
    dyn_generated = out / 'dig_cfo_oracle.c'
    dyn_generated.write_text(dyn_program, newline='\n')
    dyn_exe = out / 'dig_cfo_oracle'
    # A negative CFO sum is shifted left by dcfo_comp_sft, which the kernel's
    # -fno-strict-overflow leaves defined; the shift base check is off.
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-fno-sanitize=shift-base', '-fwrapv',
                    '-Wno-unused-function', '-Wno-unused-const-variable',
                    '-Wno-unused-but-set-variable', '-Wno-gnu-variable-sized-type-not-at-end',
                    str(dyn_generated), '-o', str(dyn_exe)], check=True)
    dyn_trace_path = out / 'dig_cfo_trace.bin'
    run = subprocess.run([str(dyn_exe), str(dyn_trace_path)], check=True, capture_output=True,
                         text=True)
    dyn_result = json.loads(run.stdout)
    if dyn_result['cases'] != len(dcases):
        raise ValueError(dyn_result)
    dyn_trace = dyn_trace_path.read_bytes()
    offset = 0
    dyn_outcomes = []
    for case in dcases:
        length = struct.unpack_from('<I', dyn_trace, offset)[0]
        body = dyn_trace[offset + 4:offset + 4 + length]
        offset += 4 + length
        tags = [struct.unpack_from('<III', body, i) for i in range(0, len(body), 12)]
        cfo_state = [t for t in tags if t[0] == 110]
        dyn_outcomes.append(dict(
            cut=case[0], crystal_cap=case[1], steps=len(case[6]), bytes=length,
            warnings=[DYN_WARNINGS[t[1]] for t in tags if t[0] == 70],
            queued=[t[1] for t in tags if t[0] == 80],
            crystal_caps=[t[2] >> 8 & 0xff for t in cfo_state],
            pd_floors=[t[2] for t in tags if t[0] == 101]))
    if offset != len(dyn_trace):
        raise ValueError('the tracking trace has trailing bytes')

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
        dig_cfo=dict(
            cases=len(dcases), steps=dyn_result['steps'], outcomes=dyn_outcomes,
            dispatch=dict(rtw8852b_chip_info=chip_dyn, rtw89_phy_gen_ax=phy_gen_dyn),
            trace_bytes=len(dyn_trace), trace_sha256=hashlib.sha256(dyn_trace).hexdigest(),
            generated_source_sha256=hashlib.sha256(dyn_generated.read_bytes()).hexdigest(),
            oracle_limit=[
                'the statistics are scripted words put in BAR2 before each period, not '
                'measured; the PPDU CFOs are handed to rtw89_phy_cfo_parse as scripted',
                'one BB context (PHY 0) and one channel context; rtw89_get_entity_mode is '
                'never MCC and rtw89_is_mlo_1_1 is false',
                'wiphy_delayed_work_queue records the delay and the harness runs the queued '
                'CFO work as many times as the step says, standing for its timer; '
                'rtw89_leave_ps_mode records that it was reached',
                'rtw89_core_setup_phycap\'s support_cckpd and support_igi lines are run as '
                'checked; rtw89_core_scan_complete\'s bypass_dig is set by the harness',
                'compiled -fwrapv with the shift base check off, as the kernel\'s '
                '-fno-strict-overflow leaves a negative CFO sum\'s left shift',
            ]),
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
    print(json.dumps(dict({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']},
                          dig_cfo={k: receipt['dig_cfo'][k] for k in [
                              'cases', 'steps', 'trace_bytes', 'trace_sha256']})))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
