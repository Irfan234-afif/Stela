#!/usr/bin/env python3
"""Unchanged pinned rtw89 RF calibrations for an RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. rtw8852b.c's rtw8852b_rfk_init and the
rtw8852b_rfk.c functions it reaches (rtw8852b_dpk_init with
_set_dpd_backoff, rtw8852b_rck with _rck, rtw8852b_dack with _dac_cal and
every DACK helper, rtw8852b_rx_dck with _wait_rx_mode, _rx_dck and
_set_rx_dck), rtw8852b_iqk with _iqk_init, _iqk and every helper _doiqk
reaches (the BB and RF backups, the LOK, TXK and RXK by group and
narrowband, _iqk_one_shot, _iqk_check_cal, the restores), the file's
leading defines, enums and tables, every table of
rtw8852b_rfk_table.c, rtw89_rfk_parser with its handlers, rtw89_phy_read_rf_v1
and rtw89_phy_write_rf_v1 with the direct and SWSI paths below them, the BB
and MMIO helpers of phy.h and core.h, reg.h, and the declarations they read
are extracted unchanged, each with its SHA-256 in manifest.json. They are
compiled with clang under ASan and UBSan against a harness that models BAR2
as bytes and each RF path's registers as 20-bit words reached through SWSI.

The model answers every poll from a script derived from the code, since no
Linux capture exists: SWSI never reads busy, and a read request leaves
R_SWSI_V1 holding the done bit and the RF word; R_DRCK_RS reads its done
bit, R_ADDCKR0 and R_ADDCKR1 bit 0, R_DACK_S0P0/S0P1 and R_DACK_S1P0/S1P1
bit 31, R_DACK_S0P2/S0P3, R_DACK10S and R_DACK11S bit 2, and RF RR_RCKS bit
3, each set unless the case keeps it clear. RF RR_MOD reads as written, or
with mode 2 (TX) when the case says so. For IQK, each write to R_NCTL_CFG
starts a one-shot: 0xbff8's low byte reads 0x55 unless the case names that
one-shot as never reporting, and R_NCTL_RPT reads B_NCTL_RPT_FLG only for
the one-shots the case fails; RF RR_TXMO reads LO leakage core codes 0x10
and 0x0f (0x1f, out of range, for I when the case fails LOK) and RR_LOKVB
buffer codes 0x20 and 0x1f. Every other read, the ones that
feed DACK's and RX DCK's computations among them (R_DRCK_RS's code,
R_ADDCKR*, the MSBK, bias and DADCK results, R_DBG32_D, R_DPD_BF, RF 0x05
and RR_DCK), reads what the patterned, all-ones or zeroed memory holds or
what was written. rtw89_chip_stop_sch_tx and rtw89_chip_resume_sch_tx are
stubs that record tags 12 (sel, mac_idx), giving tx_en 0xa5c3, and 13
(tx_en, mac_idx); the coex notifications are no-ops.

rfk_trace.bin holds eleven cases, each one segment prefixed by its byte
length: rtw8852b_rfk_init over patterned memory with R_DPD_BF's backoff and
scale adding up below 44 and to 44 or more, over all-ones and zeroed memory,
with RCK, the D-die RCK, ADDCK, S0's DACK and S1's DACK never done and with
RR_MOD reading TX mode; then rtw8852b_rx_dck(PHY 0) alone with both paths in
TSSI mode. A segment is records of three little-endian u32 (tag, a, b):
reads tagged by width, writes by 4 plus width, delays 9 (0, us), then
rtwdev->dack (14: flags, dack_cnt; 15 per path and I/Q: index and DADCK,
ADDCK and bias; 16 per path, I/Q and word: MSBK bytes), dpk_gs, the MCC
table index and is_tssi_mode (17).

iqk_trace.bin holds thirteen cases in the same form, each over patterned
memory: rtw8852b_iqk(PHY 0) on 2 GHz 20 MHz channel 1, 2 GHz 40 MHz channel
6, 5 GHz 20 MHz channel 36, 5 GHz 40 MHz channel 149 and 5 GHz 80 MHz
channels 36 and 149; channel 36 at 80 MHz with LOK failing; channel 1 with
one-shots 1, 6, 11, 13 and 20 failing; channel 6 with one-shot 7 never
reporting; channel 36 under MCC table 1; channel 1 then channel 149 at 80
MHz on one state; and channel 149 at 40 MHz narrowband, passing and with
every one-shot failing. After the state's records, rtwdev->iqk follows (20:
fail count and flags, times, version; 21 to 24 per path: channel, flags and
table, the narrowband CFIRs, the TX and RX results, the enable and syn1to2;
25 and 26 per table and path: MCC channel and LOK codes).

tssi_dpk_trace.bin holds TSSI_DPK_ORDER's cases, in the same form,
over patterned memory with dpk_gs 0x5b, cut CBV, the efuse's TSSI values,
thermal values 0x20 and 0x21 and a TX power tracking element patterned as
TRK_ROWS, bitmap 0xfff0. They run rtw8852b_tssi(PHY 0, hwtx_en),
rtw8852b_dpk(PHY 0), rtw8852b_rfk_channel, rtw8852b_rfk_band_changed
(rtw8852b_tssi_scan) and rtw8852b_rfk_scan (rtw8852b_wifi_scan_notify),
unchanged, with rtw8852b_mcc_get_ch_info, rtw89_rfk_chan_lookup,
rtw89_fw_h2c_rf_ntfy_mcc and the rtw8852b_common.c BB helpers TSSI's
alignment reaches through rtw8852bx_info. The model adds: R_RPT_COM's low
word reads 0x8000 while R_KIP_RPT1 selects report 3 (the DPK one-shot's),
unless the case keeps it clear, and otherwise reads the case's script of
words in turn, cycling, or memory without one; the TSSI CW reports at 0x1c18
and 0x3c18 read their ready bit unless the case keeps it clear. Each H2C is
two records: 30 (cat, class and func; type, rack, dack and length) and 31
per payload word. After the state's and IQK's records come rfk_mcc (40),
the DPK flags (43), per path and table the DPK result (41) and sync (42),
per path, band and word the TSSI alignment (44), and per path, channel
index and word the alignment kept by channel (45), for the channels kept.

dpk_track_trace.bin holds dpk_track_cases(), each over patterned memory:
rtw8852b.c's rtw8852b_rfk_track (rtw8852b_dpk_track with _dpk_track), run
every two seconds after phy.c's rtw89_phy_stat_thermal_update with
rtw8852b_common.c's __rtw8852bx_get_thermal, all unchanged; rtw8852b_chip_ops'
rfk_track and get_thermal and rtw8852bx_info's get_thermal are checked, and
rtw89_chip_get_thermal stands for the dispatch. The kernel's EWMA
(DECLARE_EWMA(thermal, 4, 4), include/linux/average.h, which the reference
tree lacks) is written in the harness. Each case scripts the DPK results in
use (per path and table: channel, band, thermal and power scaling factor;
the table in use) and the TSSI mode of each path; each period puts words in
BAR2 (per path R_TXAGC_BB, R_TXAGC_TP, R_DPD_COM, R_P0_TXDPD and the TSSI
thermal report at 0x1c10, then R_DPK_TRK) and RF RR_TM's word per path. A
segment records the inputs (58 the modes and tables in use, 59 per path and
table the result; per period 60, 63 per word, 65 per path's RR_TM), then,
in the form above, the thermal update (marker 50, 1), the averages read and
the highest reading (66), and the tracking (marker 50, 2).
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
TSSI_DPK_ORDER = (
    'rtw8852b_tssi(PHY 0, true) on 2 GHz 20 MHz channel 1, 2 GHz 40 MHz channel 6, 5 GHz 20 MHz '
    'channel 36, 5 GHz 40 MHz channel 149, 5 GHz 80 MHz channels 36, 149 and 42, 5 GHz 20 MHz '
    'channel 100; channel 36 with thermal values 0xff; channel 1 with the CW reports never '
    'ready; channel 6 with valid efuse gains; channel 1 twice on one state; '
    'rtw8852b_dpk(PHY 0) on the six channels of the IQK cases with the passing script; '
    'channel 1 with the sync failing; channels 36 and 36 at 80 MHz with the digital gain low; '
    'channel 6 with gain loss 9; channel 149 with gain loss 0 and the PA samples over and not '
    'over 8/5; channel 1 with both paths in TSSI mode; channels 36 and 1 with a 5 GHz '
    'external PA; channel 36 with dpk_gs 0x7f on cut CAV; channel 6 with the KIP report and '
    'one-shot 3 never ready; channel 1 with no script; rtw8852b_rfk_channel on channel 1, on '
    'channel 149 at 80 MHz, on channel 6 then 36, and on channel 36 with MCC table 1 already '
    'holding it; rtw8852b_rfk_band_changed on channel 36, alone and after rtw8852b_tssi; '
    'rtw8852b_rfk_scan start on channel 1; rtw8852b_tssi then scan start and end on channel 1')
TRK_ROWS = ('row r, delta i: (r * 13 + i * 7) % 61 - 30; types 4 to 7 at rows 0, 3, 6 and 9, '
            '8 to 15 at 12 to 19')
# The BB words each DPK tracking period puts in BAR2: per path R_TXAGC_BB,
# R_TXAGC_TP, R_DPD_COM, R_P0_TXDPD and the TSSI thermal report, then
# R_DPK_TRK.
TRACK_REGS = [0x1c60, 0x1c04, 0x81c8, 0x58d4, 0x1c10,
              0x3c60, 0x3c04, 0x82c8, 0x78d4, 0x3c10, 0x80f0]


def track_period(seed, tm, rf=(0x12, 0x15), bb=(0x10, 0x0e), ofst=(0, 0), tp=(2, 3), of=(0, 0),
                 txdpd=(1, 1), th=(0, 0), dis=0):
    """One period: RR_TM's thermal per path, then per path the TX AGC
    (R_TXAGC_BB's RF index, BB byte and offset byte), R_TXAGC_TP's target,
    the HW TX AGC offset mode, R_P0_TXDPD and the TSSI thermal report, and
    DPK tracking disabled or not."""
    def h(k):
        return (seed * 0x9e3779b1 + k * 0x7f4a7c15 + 0x2468ace) & 0xffffffff
    words = []
    for p in range(2):
        words += [
            (ofst[p] & 0xff) << 24 | (bb[p] & 0xff) << 16 | (h(p * 8) & 0xffc0) | rf[p],
            (h(p * 8 + 1) & ~0x7) & 0xffffffff | tp[p],
            (h(p * 8 + 2) & ~0x8000) & 0xffffffff | of[p] << 15,
            (h(p * 8 + 3) & 0x0fffffff) | txdpd[p] << 28,
            (h(p * 8 + 4) & ~0x3f000000) & 0xffffffff | th[p] << 24,
        ]
    words.append((h(20) & 0x7fffffff) | dis << 31)
    rr_tm = [(h(21 + p) & 0xfff80) | tm[p] << 1 for p in range(2)]
    return dict(words=words, rr_tm=rr_tm)


def dpk_track_cases():
    """(TSSI mode per path, table in use per path, per path and table
    (channel, band, thermal, pwsf), periods)."""
    s = iter(range(1, 1000))
    cases = []
    # 2 GHz, no TSSI: the thermal meter drifting either way, a period read
    # 0 (left out of the average), tracking disabled, a path's TX AGC 0.
    cases.append(((0, 0), (0, 0), (((1, 0, 0x20, 0x1f0), (36, 1, 0x10, 0x033)),
                                   ((1, 0, 0x22, 0x005), (36, 1, 0x11, 0x044))), [
        track_period(next(s), (0x20, 0x22)),
        track_period(next(s), (0x24, 0x26)),
        track_period(next(s), (0x2c, 0x30)),
        track_period(next(s), (0x18, 0x10)),
        track_period(next(s), (0, 0)),
        track_period(next(s), (0x22, 0x24), dis=1),
        track_period(next(s), (0x22, 0x24), rf=(0x12, 0)),
    ]))
    # 5 GHz, no TSSI, table 1 on path A; path B's result has no channel; a
    # drift past what an s8 holds.
    cases.append(((0, 0), (1, 0), (((1, 0, 0x20, 0x010), (36, 1, 0x30, 0x0c0)),
                                   ((0, 1, 0x30, 0x050), (149, 1, 0x3f, 0x1ff))), [
        track_period(next(s), (0x28, 0x30)),
        track_period(next(s), (0x38, 0x2e)),
        track_period(next(s), (0x01, 0x01)),
        track_period(next(s), (0x01, 0x01)),
    ]))
    # 5 GHz, both paths in TSSI mode: the thermal from the TSSI report, the
    # HW offset mode, R_P0_TXDPD 0 bringing in the BB TX AGC against its
    # target, negative AGC bytes, then path A's TX AGC 0.
    cases.append(((1, 1), (0, 1), (((149, 1, 0x25, 0x100), (36, 1, 0x20, 0x080)),
                                   ((36, 1, 0x1a, 0x070), (149, 1, 0x27, 0x0fe))), [
        track_period(next(s), (0x05, 0x06), th=(0x25, 0x27), ofst=(0xfd, 0x02)),
        track_period(next(s), (0x05, 0x06), th=(0x2a, 0x21), ofst=(0xfd, 0x02), of=(1, 0)),
        track_period(next(s), (0x05, 0x06), th=(0x2a, 0x21), ofst=(0x04, 0xf0), txdpd=(0, 0),
                     bb=(0xf0, 0x12), tp=(7, 0)),
        track_period(next(s), (0x05, 0x06), th=(0x30, 0x1c), ofst=(0x7f, 0x80), txdpd=(0, 9),
                     bb=(0x80, 0x7f), tp=(5, 1), rf=(0, 0x20)),
    ]))
    # 2 GHz, both in TSSI mode, path B's thermal report always 0: path B
    # takes the offset path A computed.
    cases.append(((1, 1), (0, 0), (((6, 0, 0x1e, 0x120), (1, 0, 0x10, 0x010)),
                                   ((6, 0, 0x1f, 0x0f0), (1, 0, 0x10, 0x010))), [
        track_period(next(s), (0x05, 0x06), th=(0x1e, 0), ofst=(0x06, 0x30)),
        track_period(next(s), (0x05, 0x06), th=(0x26, 0), ofst=(0xfa, 0x30), txdpd=(0, 1)),
        track_period(next(s), (0x05, 0x06), th=(0x16, 0), ofst=(0x01, 0x30), rf=(0, 0x15)),
    ]))
    # Path A in TSSI mode, path B not, 2 GHz.
    cases.append(((1, 0), (1, 1), (((1, 0, 0x20, 0x010), (11, 0, 0x22, 0x0aa)),
                                   ((1, 0, 0x20, 0x010), (11, 0, 0x23, 0x1fe))), [
        track_period(next(s), (0x30, 0x20), th=(0x22, 0x3f), ofst=(0x10, 0)),
        track_period(next(s), (0x30, 0x27), th=(0x1d, 0x3f), ofst=(0xf8, 0), of=(1, 1)),
    ]))
    return cases


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

    def functions(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        return '\n\n'.join(body for _, body in sorted(locate(file, name) for name in names))

    def declaration(file, kind, name):
        """An enum or struct declaration, through its semicolon."""
        text = source(file)
        m = re.search(r'^' + kind + r' ' + re.escape(name) + r' \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {kind} {name}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, f'{kind} {name}', text[m.start():end])

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

    def block(file, first, last):
        """The lines from the one starting `first` through the #define `last`,
        continuation lines included."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n', text.index('\n#define ' + last, start - 1) + 1)
        while text[end - 1] == '\\':
            end = text.index('\n', end + 1)
        return record(file, f'{first} .. {last}', text[start:end])

    def span(file, first, last):
        """Everything from the line starting `first` through the initialized
        definition `last`."""
        text = source(file)
        m = re.search(r'^' + re.escape(first), text, re.M)
        n = re.search(r'^' + re.escape(last) + r' = \{', text, re.M)
        if not m or not n or n.start() < m.start():
            raise ValueError(f'{file}: no span {first} .. {last}')
        end = text.index(';', closing(text, text.index('{', n.start()))) + 1
        return record(file, f'{first} .. {last}', text[m.start():end])

    def lines_from(file, first, last):
        """The lines from the one starting `first` through the function `last`."""
        text = source(file)
        start = text.index('\n' + first) + 1
        _, body = locate(file, last)
        end = text.index(body) + len(body)
        return record(file, f'{first.split()[-1]} .. {last}', text[start:end])

    def members(file, head, names):
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
    core_defines = defines('core.h', [
        'MASKBYTE0', 'MASKLWORD', 'MASKDWORD', 'RFREG_MASK', 'INV_RF_DATA', 'RF_PATH_MAX',
        'RTW89_DACK_PATH_NR', 'RTW89_DACK_IDX_NR', 'RTW89_DACK_MSBK_NR', 'RTW89_IQK_CHS_NR',
        'RTW89_IQK_PATH_NR'])
    phy_defines = defines('phy.h', ['RTW89_RF_ADDR_ADSEL_MASK'])
    chip_defines = defines('rtw8852b.h', ['RF_PATH_NUM_8852B'])
    rfk_macros = block('phy.h', '#define RTW89_DECLARE_RFK_TBL', 'RTW89_DECL_RFK_DELAY')
    by_cond = block('phy.h', '#define rtw89_rfk_parser_by_cond', 'rtw89_rfk_parser_by_cond')
    declarations = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_sch_tx_sel', 'rtw89_band', 'rtw89_phy_idx', 'rtw89_chanctx_idx',
            'rtw89_rf_path', 'rtw89_rf_path_bit', 'rtw89_bandwidth', 'rtw89_flags',
            'rtw89_rfk_chs_nrs']]
        + [declaration('core.h', 'struct', name) for name in [
            'rtw89_reg3_def', 'rtw89_reg5_def', 'rtw89_dack_info', 'rtw89_rfk_mcc_info_data',
            'rtw89_rfk_mcc_info', 'rtw89_iqk_info']]
        + [declaration('phy.h', 'enum', 'rtw89_rfk_flag'),
           declaration('phy.h', 'struct', 'rtw89_rfk_tbl')])
    core_helpers = functions('core.h', [
        'rtw89_write32_set', 'rtw89_write32_clr', 'rtw89_read32_mask', 'rtw89_write32_mask'])
    phy_helpers = functions('phy.h', [
        'rtw89_phy_write32_set', 'rtw89_phy_write32_clr', 'rtw89_phy_write32_mask',
        'rtw89_phy_read32_mask'])
    rf_access = functions('phy.c', [
        'rtw89_phy_check_swsi_busy', 'rtw89_phy_read_rf', 'rtw89_phy_read_rf_a',
        'rtw89_phy_read_rf_v1', 'rtw89_phy_write_rf', 'rtw89_phy_write_rf_a',
        'rtw89_phy_write_rf_v1'])
    parser = lines_from('phy.c', 'static void\n_rfk_write_rf', 'rtw89_rfk_parser')
    table_c = source('rtw8852b_rfk_table.c')
    if table_c.count('#include') != 1:
        raise ValueError('rtw8852b_rfk_table.c includes more than its header')
    tables = record('rtw8852b_rfk_table.c', 'rtw8852b_rfk_table.c',
                    re.sub(r'^#include [^\n]*\n', '', table_c, flags=re.M))
    rfk_head = span('rtw8852b_rfk.c', '#define RTW8852B_RXDCK_VER',
                    'static const struct rtw89_reg3_def rtw8852b_restore_nondbcc_path01[]')
    rfk = functions('rtw8852b_rfk.c', [
        '_kpath', '_set_rx_dck', '_rx_dck', '_rck', '_afe_init', '_drck', '_addck_backup',
        '_addck_reload', '_dack_backup_s0', '_dack_backup_s1', '_check_addc', '_addck',
        '_check_dadc', '_dack_s0_check_done', '_dack_s0', '_dack_s1_check_done', '_dack_s1',
        '_dack', '_dack_dump', '_dac_cal', '_wait_rx_mode', '_set_dpd_backoff',
        'rtw8852b_dpk_init', 'rtw8852b_rck', 'rtw8852b_dack', 'rtw8852b_rx_dck',
        '_rfk_backup_bb_reg', '_rfk_backup_rf_reg', '_rfk_restore_bb_reg', '_rfk_restore_rf_reg',
        '_iqk_check_cal', '_iqk_rxk_setting', '_iqk_one_shot', '_rxk_group_sel', '_iqk_nbrxk',
        '_iqk_rxclk_setting', '_txk_group_sel', '_iqk_nbtxk', '_lok_res_table',
        '_lok_finetune_check', '_iqk_lok', '_iqk_txk_setting', '_iqk_txclk_setting',
        '_iqk_info_iqk', '_iqk_by_path', '_iqk_get_ch_info', '_iqk_start_iqk', '_iqk_restore',
        '_iqk_afebb_restore', '_iqk_preset', '_iqk_macbb_setting', '_iqk_init', '_doiqk', '_iqk',
        'rtw8852b_iqk'])
    rfk_init = functions('rtw8852b.c', ['rtw8852b_rfk_init'])

    # TSSI, DPK, rtw8852b_rfk_channel and RF_NTFY_MCC.
    defines38 = '\n'.join([
        defines('core.h', ['MASKBYTE2', 'MASKBYTE3', 'MASKHWORD', 'DELTA_SWINGIDX_SIZE',
                           'RTW89_DPK_RF_PATH', 'RTW89_DPK_BKUP_NUM']),
        block('core.h', '#define TSSI_TRIM_CH_GROUP_NUM ', 'TSSI_ALIMK_VALUE_NUM'),
        defines('phy.h', ['phy_div']),
        defines('rtw8852b_common.h', ['BB_PATH_NUM_8852BX']),
        defines('fw.h', ['FWCMD_TYPE_H2C', 'H2C_CAT_OUTSRC', 'H2C_CL_OUTSRC_RF_FW_NOTIFY',
                         'H2C_FUNC_OUTSRC_RF_GET_MCCCH'])])
    declarations38 = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_cv', 'rtw89_subband', 'rtw89_gain_offset', 'rtw89_tssi_alimk_band',
            'rtw89_core_chip_id']]
        + [declaration('core.h', 'struct', name) for name in [
            'rtw89_dpk_bkup_para', 'rtw89_dpk_info', 'rtw89_fem_info', 'rtw89_tssi_info',
            'rtw89_phy_efuse_gain']]
        + [declaration('fw.h', 'enum', 'rtw89_fw_txpwr_trk_type')]
        + [declaration('fw.h', 'struct', name) for name in [
            'rtw89_fw_txpwr_track_cfg', 'rtw89_fw_h2c_rf_get_mccch',
            'rtw89_fw_h2c_rf_get_mccch_v0']]
        + [declaration('phy.h', 'struct', 'rtw89_rfk_chan_desc'),
           declaration('rtw8852b_common.h', 'enum', 'rtw8852bx_pmac_mode')]
        + [declaration('rtw8852b_common.h', 'struct', name) for name in [
            'rtw8852bx_bb_pmac_info', 'rtw8852bx_bb_tssi_bak']])
    phy_h38 = functions('phy.h', ['rtw89_raw_phy_write32', 'rtw89_phy_write32',
                                  'rtw89_subband_to_gain_offset_band_of_ofdm'])
    phy38 = '\n\n'.join([
        functions('phy.c', ['rtw89_phy_write32_idx', 'rtw89_phy_read32_idx']),
        lines_from('phy.c', 'static bool rfk_chan_validate_desc', 'rtw89_rfk_chan_lookup')])
    chan38 = functions('chan.c', ['rtw89_get_subband_type'])
    common_h38 = functions('rtw8852b_common.h', [
        'rtw8852bx_bb_cfg_tx_path', 'rtw8852bx_bb_ctrl_rx_path', 'rtw8852bx_bb_set_plcp_tx',
        'rtw8852bx_bb_set_power', 'rtw8852bx_bb_set_pmac_pkt_tx', 'rtw8852bx_bb_backup_tssi',
        'rtw8852bx_bb_restore_tssi', 'rtw8852bx_bb_tx_mode_switch', 'rtw8852bx_ctrl_btg_bt_rx'])
    common38 = '\n\n'.join([
        span('rtw8852b_common.c',
             'static const struct rtw89_reg3_def rtw8852bx_pmac_ht20_mcs7_tbl[]',
             'static const struct rtw89_reg3_def rtw8852bx_pmac_ht20_mcs7_tbl[]'),
        functions('rtw8852b_common.c', [
            'rtw8852bx_set_gain_offset', '__rtw8852bx_bb_set_plcp_tx', 'rtw8852bx_stop_pmac_tx',
            'rtw8852bx_start_pmac_tx', 'rtw8852bx_bb_set_pmac_tx',
            '__rtw8852bx_bb_set_pmac_pkt_tx', '__rtw8852bx_bb_set_power',
            '__rtw8852bx_bb_cfg_tx_path', '__rtw8852bx_bb_tx_mode_switch',
            '__rtw8852bx_bb_backup_tssi', '__rtw8852bx_bb_restore_tssi',
            '__rtw8852bx_ctrl_btg_bt_rx', '__rtw8852bx_bb_ctrl_rx_path'])])
    extra_group = block('rtw8852b_rfk.c', '#define TSSI_EXTRA_GROUP_BIT',
                        'TSSI_EXTRA_GET_GROUP_IDX2')
    rfk38 = functions('rtw8852b_rfk.c', [
        '_rfk_rf_direct_cntrl', '_rfk_drf_direct_cntrl', '_tmac_tx_pause',
        '_dpk_bkup_kip', '_dpk_reload_kip', '_dpk_order_convert', '_dpk_onoff', '_dpk_one_shot',
        '_dpk_rx_dck', '_dpk_information', '_dpk_bb_afe_setting', '_dpk_bb_afe_restore',
        '_dpk_tssi_pause', '_dpk_kip_restore', '_dpk_lbk_rxiqk', '_dpk_get_thermal',
        '_dpk_rf_setting', '_dpk_bypass_rxcfir', '_dpk_tpg_sel', '_dpk_table_select',
        '_dpk_sync_check', '_dpk_sync', '_dpk_dgain_read', '_dpk_dgain_mapping',
        '_dpk_gainloss_read', '_dpk_gainloss', '_dpk_kip_preset', '_dpk_kip_pwr_clk_on',
        '_dpk_kip_set_txagc', '_dpk_kip_set_rxagc', '_dpk_set_offset', '_dpk_pas_read',
        '_dpk_agc', '_dpk_set_mdpd_para', '_dpk_idl_mpa', '_dpk_fill_result',
        '_dpk_reload_check', '_dpk_main', '_dpk_cal_select', '_dpk_bypass_check',
        '_dpk_force_bypass', '_dpk', '_tssi_rf_setting', '_tssi_set_sys',
        '_tssi_ini_txpwr_ctrl_bb', '_tssi_ini_txpwr_ctrl_bb_he_tb', '_tssi_set_dck',
        '_tssi_set_tmeter_tbl', '_tssi_set_dac_gain_tbl', '_tssi_slope_cal_org',
        '_tssi_alignment_default', '_tssi_set_tssi_slope', '_tssi_set_tssi_track',
        '_tssi_set_txagc_offset_mv_avg', '_tssi_enable', '_tssi_disable',
        '_tssi_get_cck_group', '_tssi_get_ofdm_group', '_tssi_get_trim_group',
        '_tssi_get_ofdm_de', '_tssi_get_ofdm_trim_de', '_tssi_set_efuse_to_de',
        '_tssi_alimentk_dump_result', '_tssi_alimentk_done', '_tssi_hw_tx',
        '_tssi_backup_bb_registers', '_tssi_reload_bb_registers', '_tssi_ch_to_idx',
        '_tssi_get_cw_report', '_tssi_alimentk', 'rtw8852b_dpk', 'rtw8852b_tssi',
        'rtw8852b_tssi_scan', 'rtw8852b_tssi_default_txagc', 'rtw8852b_wifi_scan_notify',
        'rtw8852b_mcc_get_ch_info'])
    fw38 = functions('fw.c', ['rtw89_fw_h2c_rf_ntfy_mcc'])
    chip38 = functions('rtw8852b.c', ['rtw8852b_rfk_channel', 'rtw8852b_rfk_band_changed',
                                      'rtw8852b_rfk_scan'])
    chip_ops38 = members('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                         ['rfk_channel', 'rfk_band_changed', 'rfk_scan'])
    if chip_ops38 != {'rfk_channel': 'rtw8852b_rfk_channel',
                      'rfk_band_changed': 'rtw8852b_rfk_band_changed',
                      'rfk_scan': 'rtw8852b_rfk_scan'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops38}')

    # DPK tracking (dpk_track_trace.bin).
    chip_ops55 = members('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                         ['rfk_track', 'get_thermal'])
    if chip_ops55 != {'rfk_track': 'rtw8852b_rfk_track', 'get_thermal': 'rtw8852bx_get_thermal'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops55}')
    bx55 = members('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info',
                   ['get_thermal'])
    if bx55 != {'get_thermal': '__rtw8852bx_get_thermal'}:
        raise ValueError(f'rtw8852bx_info is {bx55}')
    if '\treturn rtw8852bx_info.get_thermal(rtwdev, rf_path);\n' not in \
            locate('rtw8852b_common.h', 'rtw8852bx_get_thermal')[1] or \
            '\treturn chip->ops->get_thermal(rtwdev, rf_path);\n' not in \
            locate('core.h', 'rtw89_chip_get_thermal')[1] or \
            '\t\tchip->ops->rfk_track(rtwdev);\n' not in \
            locate('core.h', 'rtw89_chip_rfk_track')[1]:
        raise ValueError('rtw89_chip_get_thermal or rtw89_chip_rfk_track no longer dispatch '
                         'as the harness does')
    track55 = '\n\n'.join([
        functions('rtw8852b_common.c', ['__rtw8852bx_get_thermal']),
        '/* rtw89_chip_get_thermal through rtw8852b_chip_ops and rtw8852bx_info. */\n'
        'static u8 rtw89_chip_get_thermal(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path)\n'
        '{\n\treturn __rtw8852bx_get_thermal(rtwdev, rf_path);\n}',
        functions('phy.c', ['rtw89_phy_stat_thermal_update']),
        functions('rtw8852b_rfk.c', ['_dpk_track', 'rtw8852b_dpk_track']),
        functions('rtw8852b.c', ['rtw8852b_rfk_track'])])
    harness55 = r'''
#define RTW89_DBG_RFK_TRACK 4
#define fsleep(us) model_delay(us)
#ifndef max
#define max(a, b) ({ __typeof__(a) __a = (a); __typeof__(b) __b = (b); __a > __b ? __a : __b; })
#endif
'''
    tcases55 = dpk_track_cases()
    case_rows, bp_rows, period_rows = [], [], []
    for tssi, cur, bps, periods in tcases55:
        case_rows.append('\t{{%d, %d}, {%d, %d}, %d, %d}' % (
            tssi[0], tssi[1], cur[0], cur[1], len(period_rows), len(periods)))
        bp_rows.append('\t{' + ', '.join('{' + ', '.join('{%d, %d, 0x%x, 0x%x}' % b for b in path)
                                         + '}' for path in bps) + '}')
        for period in periods:
            period_rows.append('\t{{%s}, {0x%x, 0x%x}}' % (
                ', '.join('0x%x' % w for w in period['words']), *period['rr_tm']))
    track_c = r'''
static const u32 track_regs[] = {''' + ', '.join('0x%x' % r for r in TRACK_REGS) + r'''};
struct track_period { u32 words[ARRAY_SIZE(track_regs)]; u32 rr_tm[2]; };
static const struct track_period track_periods[] = {
''' + ',\n'.join(period_rows) + r'''
};
static const struct { u8 ch, band, ther; u16 pwsf; } track_bps[][2][2] = {
''' + ',\n'.join(bp_rows) + r'''
};
static const struct { u8 tssi[2], cur[2]; u32 first, n; } track_cases[] = {
''' + ',\n'.join(case_rows) + r'''
};
static size_t run_track(const char *path)
{
	FILE *out = open_trace(path);
	for (size_t c = 0; c < ARRAY_SIZE(track_cases); c++) {
		static struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip_info;
		fill(PATTERN);
		record(58, track_cases[c].tssi[0] | (u32)track_cases[c].tssi[1] << 1 |
			   (u32)track_cases[c].cur[0] << 8 | (u32)track_cases[c].cur[1] << 16, 0);
		for (u32 p = 0; p < RF_PATH_NUM_8852B; p++) {
			dev.is_tssi_mode[p] = track_cases[c].tssi[p];
			dev.dpk.cur_idx[p] = track_cases[c].cur[p];
			for (u32 k = 0; k < RTW89_DPK_BKUP_NUM; k++) {
				struct rtw89_dpk_bkup_para *b = &dev.dpk.bp[p][k];

				b->ch = track_bps[c][p][k].ch;
				b->band = track_bps[c][p][k].band;
				b->ther_dpk = track_bps[c][p][k].ther;
				b->pwsf = track_bps[c][p][k].pwsf;
				record(59, p << 8 | k | (u32)b->band << 16 | (u32)b->ch << 24,
				       b->ther_dpk | (u32)b->pwsf << 16);
			}
		}
		for (u32 n = 0; n < track_cases[c].n; n++) {
			const struct track_period *t = &track_periods[track_cases[c].first + n];

			record(60, n, 0);
			for (u32 i = 0; i < ARRAY_SIZE(track_regs); i++) {
				set(CR_BASE + track_regs[i], 4, t->words[i]);
				record(63, track_regs[i], t->words[i]);
			}
			for (u32 p = 0; p < 2; p++) {
				rf[p][RR_TM] = t->rr_tm[p];
				record(65, p, t->rr_tm[p]);
			}
			record(50, 1, n);
			rtw89_phy_stat_thermal_update(&dev);
			record(66, (u32)ewma_thermal_read(&dev.phystat.avg_thermal[0]) |
				   (u32)ewma_thermal_read(&dev.phystat.avg_thermal[1]) << 8 |
				   (u32)dev.phystat.last_thermal_max << 16, 0);
			record(50, 2, n);
			rtw8852b_rfk_track(&dev);
		}
		flush(out);
	}
	close_trace(out);
	return ARRAY_SIZE(track_cases);
}
'''
    bx_names = ['bb_cfg_tx_path', 'bb_ctrl_rx_path', 'bb_set_plcp_tx', 'bb_set_power',
                'bb_set_pmac_pkt_tx', 'bb_backup_tssi', 'bb_restore_tssi', 'bb_tx_mode_switch',
                'ctrl_btg_bt_rx']
    bx = members('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info', bx_names)
    if bx != {name: '__rtw8852bx_' + name for name in bx_names}:
        raise ValueError(f'rtw8852bx_info is {bx}')
    chip_id = members('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                      ['chip_id'])
    if chip_id != {'chip_id': 'RTL8852B'}:
        raise ValueError(f'rtw8852b_chip_info is {chip_id}')
    fw_c = source('fw.c')
    if fw_c.count('RFK_NTFY_MCC_V0') != 2 or \
            '\t__CFG_FW_FEAT(RTL8852C, ge, 0, 0, 0, 0, RFK_NTFY_MCC_V0),\n' not in fw_c:
        raise ValueError('fw.c: RFK_NTFY_MCC_V0 is no longer RTL8852C\'s alone')

    chip_ops = members('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                       ['read_rf', 'write_rf', 'rfk_init', 'stop_sch_tx', 'resume_sch_tx'])
    if chip_ops != {'read_rf': 'rtw89_phy_read_rf_v1', 'write_rf': 'rtw89_phy_write_rf_v1',
                    'rfk_init': 'rtw8852b_rfk_init', 'stop_sch_tx': 'rtw89_mac_stop_sch_tx',
                    'resume_sch_tx': 'rtw89_mac_resume_sch_tx'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops}')
    info = members('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                   ['phy_def', 'rf_base_addr', 'rf_path_num'])
    if info['phy_def'] != '&rtw89_phy_gen_ax':
        raise ValueError(f"rtw8852b_chip_info.phy_def is {info['phy_def']}")
    phy_gen = members('phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax', ['cr_base'])
    raw_io = members('fw.c', 'static const struct rtw89_io_ops rtw89_raw_io', ['write_rf'])
    if raw_io != {'write_rf': 'rtw89_raw_write_rf'}:
        raise ValueError(f'rtw89_raw_io is {raw_io}')
    if '\trtwdev->chip->ops->write_rf(rtwdev, rf_path, addr, mask, data);\n' not in \
            source('core.h') or \
            '\treturn rtwdev->chip->ops->read_rf(rtwdev, rf_path, addr, mask);\n' not in \
            source('core.h'):
        raise ValueError('core.h: rtw89_read_rf or rtw89_raw_write_rf no longer use chip ops')

    preamble = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t s32;
typedef int8_t s8; typedef int16_t s16; typedef int64_t s64;
typedef u32 __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define FIELD_GET_SIGNED(m, v) \
	((s32)((u32)(v) << __builtin_clz(m)) >> (__builtin_clz(m) + __ffs(m)))
#define u32_replace_bits(old, v, m) ((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, v))
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
/* rtw89's log helpers are calls in the kernel: their arguments, register
 * reads among them, are evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
enum { RTW89_DBG_RFK = 1, RTW89_DBG_TSSI = 2 };
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound. The atomic form is the same in the
 * model. */
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
#define test_bit(nr, addr) ((int)(((addr)[(nr) / 64] >> ((nr) % 64)) & 1))
'''
    harness = r'''
struct rtw89_dev;
struct rtw89_phy_gen_def { u32 cr_base; };
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	const struct rtw89_phy_gen_def *phy_def;
	u32 rf_base_addr[2];
	u8 rf_path_num;
};
struct rtw89_hal { u8 cv; u8 antenna_rx; };
struct rtw89_chan {
	u8 channel;
	enum rtw89_band band_type;
	enum rtw89_bandwidth band_width;
	enum rtw89_subband subband_type;
};
struct rtw89_fw_elm_info { const struct rtw89_fw_txpwr_track_cfg *txpwr_trk; };
struct rtw89_fw_info { struct rtw89_fw_elm_info elm_info; };
struct rtw89_io_ops { void (*phy_write32)(struct rtw89_dev *rtwdev, u32 addr, u32 data); };
/* The kernel's DECLARE_EWMA(thermal, 4, 4) as include/linux/average.h
 * expands it, written here: the reference tree has no include/. */
struct ewma_thermal { unsigned long internal; };
static inline void ewma_thermal_init(struct ewma_thermal *e) { e->internal = 0; }
static inline unsigned long ewma_thermal_read(struct ewma_thermal *e) { return e->internal >> 4; }
static inline void ewma_thermal_add(struct ewma_thermal *e, unsigned long val)
{
	unsigned long internal = e->internal;

	e->internal = internal ? (((internal << 2) - internal) + (val << 4)) >> 2 : (val << 4);
}
struct rtw89_phy_stat { struct ewma_thermal avg_thermal[RF_PATH_MAX]; u8 last_thermal_max; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_io_ops *io;
	bool dbcc_en;
	struct rtw89_hal hal;
	struct rtw89_dack_info dack;
	struct rtw89_dpk_info dpk;
	struct rtw89_rfk_mcc_info rfk_mcc;
	bool is_tssi_mode[RF_PATH_MAX];
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
	struct rtw89_iqk_info iqk;
	struct rtw89_chan chan;
	struct rtw89_tssi_info tssi;
	struct rtw89_fem_info fem;
	struct rtw89_phy_efuse_gain efuse_gain;
	struct rtw89_fw_info fw;
	struct rtw89_phy_stat phystat;
};
static const struct rtw89_chan *rtw89_chan_get(struct rtw89_dev *d, enum rtw89_chanctx_idx i)
{
	(void)i;
	return &d->chan;
}

/* The coex notifications are no-ops; the PHY map they take is not computed. */
#define rtw89_btc_phymap(d, phy, paths, chanctx) ((void)(d), (u8)0)
#define rtw89_btc_ntfy_wl_rfk(d, map, type, state) ((void)(d), (void)(map))

/* The register model: BAR2 as bytes, behaving per aligned word, and each RF
 * path's registers as 20-bit words behind SWSI. */
#define CR_BASE 0x10000
static u8 memory[0x20000];
static u32 rf[2][256];
static struct {
	int rck_stuck, drck_stuck, addck_stuck, s0_stuck, s1_stuck, rx_stuck;
	int lok_fail;
	u64 nctl_fail;
	u32 nctl_stuck;
	int kip_stuck, cwrpt_stuck;
	const u32 *rpt;
	u32 rpt_len;
} fault;
/* The NCTL one-shots started: writes to R_NCTL_CFG. */
static u32 oneshots;
/* The reads of R_RPT_COM's script so far. */
static u32 rpt_reads;
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
static u32 get(u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)memory[r + i] << (8 * i); return v; }
static void set(u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) memory[r + i] = v >> (8 * i); }
static void check(u32 r, u32 n)
{
	if (r + n > sizeof(memory) || r % n)
		abort();
}
static u32 forced(u32 v, u32 bits, int stuck) { return stuck ? v & ~bits : v | bits; }
/* What RF register addr of path reads as. */
static u32 rf_view(u32 path, u32 addr)
{
	u32 v = rf[path][addr];
	switch (addr) {
	case RR_RCKS:
		return forced(v, BIT(3), fault.rck_stuck);
	case RR_MOD:
		return fault.rx_stuck ? u32_replace_bits(v, 2, RR_MOD_MASK) : v;
	case RR_TXMO:
		return u32_replace_bits(u32_replace_bits(v, fault.lok_fail ? 0x1f : 0x10, RR_TXMO_COI),
					0x0f, RR_TXMO_COQ);
	case RR_LOKVB:
		return u32_replace_bits(u32_replace_bits(v, 0x20, RR_LOKVB_COI), 0x1f, RR_LOKVB_COQ);
	}
	return v;
}
/* What the aligned word at w reads as. */
static u32 view(u32 w)
{
	u32 v = get(w, 4);
	if (w < CR_BASE)
		return v;
	switch (w - CR_BASE) {
	case R_SWSI_V1:
		return v & ~(B_SWSI_W_BUSY_V1 | B_SWSI_R_BUSY_V1);
	case R_DRCK_RS:
		return forced(v, B_DRCK_RS_DONE, fault.drck_stuck);
	case R_ADDCKR0:
	case R_ADDCKR1:
		return forced(v, BIT(0), fault.addck_stuck);
	case R_DACK_S0P0:
	case R_DACK_S0P1:
		return forced(v, B_DACK_S0P0_OK, fault.s0_stuck);
	case R_DACK_S0P2:
	case R_DACK_S0P3:
		return forced(v, B_DACK_S0P2_OK, fault.s0_stuck);
	case R_DACK_S1P0:
	case R_DACK_S1P1:
		return forced(v, B_DACK_S1P0_OK, fault.s1_stuck);
	case R_DACK10S:
	case R_DACK11S:
		return forced(v, B_DACK_S1P2_OK, fault.s1_stuck);
	case 0xbff8:
		return (v & ~0xffu) | (oneshots && oneshots == fault.nctl_stuck ? 0 : 0x55);
	case R_NCTL_RPT:
		return forced(v, B_NCTL_RPT_FLG,
			      !oneshots || oneshots > 64 || !((fault.nctl_fail >> (oneshots - 1)) & 1));
	case R_RPT_COM:
		if (FIELD_GET(B_KIP_RPT1_SEL, get(CR_BASE + R_KIP_RPT1, 4)) == 3)
			return (v & 0xffff0000u) | (fault.kip_stuck ? 0 : 0x8000);
		return fault.rpt_len ? fault.rpt[rpt_reads++ % fault.rpt_len] : v;
	case 0x1c18:
	case 0x3c18:
		return forced(v, B_TSSI_CWRPT_RDY, fault.cwrpt_stuck);
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
	set(r, n, v);
	u32 w = r & ~3u, s = get(w, 4);
	if (w == CR_BASE + R_SWSI_READ_ADDR_V1) {
		u32 path = FIELD_GET(B_SWSI_READ_ADDR_PATH_V1, s);
		u32 addr = FIELD_GET(B_SWSI_READ_ADDR_ADDR_V1, s);
		if (path >= 2)
			abort();
		set(CR_BASE + R_SWSI_V1, 4, B_SWSI_R_DATA_DONE_V1 | rf_view(path, addr));
	}
	if (w == CR_BASE + R_NCTL_CFG)
		oneshots++;
	if (w == CR_BASE + R_SWSI_DATA_V1) {
		u32 path = FIELD_GET(B_SWSI_DATA_PATH_V1, s);
		u32 addr = FIELD_GET(B_SWSI_DATA_ADDR_V1, s);
		u32 data = FIELD_GET(B_SWSI_DATA_VAL_V1, s);
		if (path >= 2)
			abort();
		if (s & B_SWSI_DATA_BIT_MASK_EN_V1) {
			u32 m = get(CR_BASE + R_SWSI_BIT_MASK_V1, 4) & RFREG_MASK;
			rf[path][addr] = (rf[path][addr] & ~m) | (data & m);
		} else {
			rf[path][addr] = data;
		}
	}
}
/* PCIe reaches the registers through rtw89_raw_io and rtw89_pci_ops; these
 * stand for both. */
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* The MAC scheduler is the MAC oracle's: these note that it was reached. */
static int rtw89_chip_stop_sch_tx(struct rtw89_dev *d, u8 mac_idx, u32 *tx_en,
				  enum rtw89_sch_tx_sel sel)
{
	(void)d;
	record(12, sel, mac_idx);
	*tx_en = 0xa5c3;
	return 0;
}
static int rtw89_chip_resume_sch_tx(struct rtw89_dev *d, u8 mac_idx, u32 tx_en)
{
	(void)d;
	record(13, tx_en, mac_idx);
	return 0;
}
'''
    dispatch = r'''
/* rtw89_read_rf and rtw89_write_rf through rtw8852b_chip_ops and rtw89_raw_io. */
static u32 rtw89_read_rf(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr, u32 mask)
{
	return rtw89_phy_read_rf_v1(rtwdev, rf_path, addr, mask);
}
static void rtw89_write_rf(struct rtw89_dev *rtwdev, enum rtw89_rf_path rf_path, u32 addr,
			   u32 mask, u32 data)
{
	rtw89_phy_write_rf_v1(rtwdev, rf_path, addr, mask, data);
}
'''
    chip = (
        'static const struct rtw89_phy_gen_def phy_gen_ax = {\n'
        f"\t.cr_base = {phy_gen['cr_base']},\n}};\n"
        'static const struct rtw89_chip_info chip_info = {\n'
        f"\t.chip_id = {chip_id['chip_id']},\n"
        '\t.phy_def = &phy_gen_ax,\n'
        f"\t.rf_base_addr = {info['rf_base_addr']},\n"
        f"\t.rf_path_num = {info['rf_path_num']},\n}};\n")
    harness38 = r'''
/* The coex notifications rtw8852b_rfk_channel adds are no-ops too. */
#define rtw89_btc_ntfy_conn_rfk(d, state) ((void)(d))
#define rtw89_btc_ntfy_preserve_bt_time(d, ms) ((void)(d))
#define str_on_off(v) ((v) ? "on" : "off")
#define str_enable_disable(v) ((v) ? "enable" : "disable")
#define S8_MIN (-128)
#define S8_MAX 127
#define clamp_t(t, v, lo, hi) ({ t __v = (v), __lo = (lo), __hi = (hi); \
	__v < __lo ? __lo : __v > __hi ? __hi : __v; })
static inline s32 sign_extend32(u32 value, int index)
{
	u8 shift = 31 - index;
	return (s32)(value << shift) >> shift;
}
/* The alignment's time account is not modeled. */
typedef s64 ktime_t;
static ktime_t ktime_get(void) { return 0; }
#define ktime_us_delta(a, b) ((s64)((a) - (b)))
/* RTL8852B's firmware has no RFK_NTFY_MCC_V0, which fw.c gives RTL8852C alone. */
#define RTW89_CHK_FW_FEATURE(feat, fw) ((void)(fw), false)
#define U8_MAX 0xff
#define cpu_to_le32(v) ((u32)(v))
/* The H2C path: the header's fields and the payload are what is recorded. */
struct sk_buff { u8 *data; u32 len; u8 buf[64]; };
static struct sk_buff h2c_skb;
static struct sk_buff *rtw89_fw_h2c_alloc_skb_with_hdr(struct rtw89_dev *d, u32 len)
{
	(void)d;
	if (len > sizeof(h2c_skb.buf))
		abort();
	memset(&h2c_skb, 0, sizeof(h2c_skb));
	h2c_skb.data = h2c_skb.buf;
	return &h2c_skb;
}
static void *skb_put(struct sk_buff *skb, u32 len)
{
	void *tail = skb->data + skb->len;
	skb->len += len;
	return tail;
}
static void rtw89_h2c_pkt_set_hdr(struct rtw89_dev *d, struct sk_buff *skb, u8 type, u8 cat,
				  u8 class, u8 func, bool rack, bool dack, u32 len)
{
	(void)d;
	(void)skb;
	record(30, cat | (u32)class << 8 | (u32)func << 16,
	       type | (u32)rack << 8 | (u32)dack << 9 | len << 16);
}
static u32 get_unaligned_le32(const u8 *p)
{
	return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}
static int rtw89_h2c_tx(struct rtw89_dev *d, struct sk_buff *skb, bool fwdl)
{
	(void)d;
	(void)fwdl;
	for (u32 i = 0; i < skb->len / 4; i++)
		record(31, i, get_unaligned_le32(skb->data + 4 * i));
	return 0;
}
static void dev_kfree_skb_any(struct sk_buff *skb) { (void)skb; }
struct rtw89_vif_link { enum rtw89_chanctx_idx chanctx_idx; enum rtw89_phy_idx phy_idx; };
/* One channel context: the entity's channel is the case's. */
struct rtw89_entity_conf { const struct rtw89_chan *chans[NUM_OF_RTW89_CHANCTX]; };
static void rtw89_entity_get_conf(struct rtw89_dev *d, struct rtw89_entity_conf *conf)
{
	memset(conf, 0, sizeof(*conf));
	conf->chans[0] = &d->chan;
}
static int rtw89_iterate_entity_chan(struct rtw89_dev *d,
				     int (*iterator)(const struct rtw89_chan *chan, void *data),
				     void *data)
{
	return iterator(&d->chan, data);
}
/* Reached only with DBCC or on an RTL8852BT: neither is. */
static u32 rtw89_phy0_phy1_offset(struct rtw89_dev *d, u32 a) { (void)d; (void)a; abort(); }
static void rtw8852bt_ext_loss_avg_update(struct rtw89_dev *d, s8 a, s8 b)
{ (void)d; (void)a; (void)b; abort(); }
/* Every case gives the TX power tracking element, as an RTL8852B's firmware must. */
static const struct rtw89_fw_txpwr_track_cfg rtw89_8852b_trk_cfg;
struct rtw8852bx_info {
	void (*bb_cfg_tx_path)(struct rtw89_dev *rtwdev, u8 tx_path);
	void (*bb_ctrl_rx_path)(struct rtw89_dev *rtwdev, enum rtw89_rf_path_bit rx_path,
				const struct rtw89_chan *chan);
	void (*bb_set_plcp_tx)(struct rtw89_dev *rtwdev);
	void (*bb_set_power)(struct rtw89_dev *rtwdev, s16 pwr_dbm, enum rtw89_phy_idx idx);
	void (*bb_set_pmac_pkt_tx)(struct rtw89_dev *rtwdev, u8 enable, u16 tx_cnt, u16 period,
				   u16 tx_time, enum rtw89_phy_idx idx,
				   const struct rtw89_chan *chan);
	void (*bb_backup_tssi)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx idx,
			       struct rtw8852bx_bb_tssi_bak *bak);
	void (*bb_restore_tssi)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx idx,
				const struct rtw8852bx_bb_tssi_bak *bak);
	void (*bb_tx_mode_switch)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx idx, u8 mode);
	void (*ctrl_btg_bt_rx)(struct rtw89_dev *rtwdev, bool en, enum rtw89_phy_idx phy_idx);
};
static const struct rtw8852bx_info rtw8852bx_info;
'''
    raw_io38 = members('fw.c', 'static const struct rtw89_io_ops rtw89_raw_io', ['phy_write32'])
    if raw_io38 != {'phy_write32': 'rtw89_raw_phy_write32'}:
        raise ValueError(f'rtw89_raw_io is {raw_io38}')
    io_table = ('static const struct rtw89_io_ops rtw89_raw_io = {\n'
                f"\t.phy_write32 = {raw_io38['phy_write32']},\n}};\n")
    bx_table = ('static const struct rtw8852bx_info rtw8852bx_info = {\n'
                + ''.join(f'\t.{name} = {value},\n' for name, value in bx.items()) + '};\n')
    main_c = r'''
static void flush(FILE *out)
{
	u32 n = segment_bytes;
	u8 length[4] = {n, n >> 8, n >> 16, n >> 24};
	if (fwrite(length, 1, 4, out) != 4 || fwrite(segment, 1, n, out) != n)
		abort();
	segment_bytes = 0;
}
static void record_state(const struct rtw89_dev *dev)
{
	const struct rtw89_dack_info *k = &dev->dack;
	record(14, (u32)k->dack_done | (u32)k->addck_timeout[0] << 1 |
		   (u32)k->addck_timeout[1] << 2 | (u32)k->dadck_timeout[0] << 3 |
		   (u32)k->dadck_timeout[1] << 4 | (u32)k->msbk_timeout[0] << 5 |
		   (u32)k->msbk_timeout[1] << 6, k->dack_cnt);
	for (u32 p = 0; p < RTW89_DACK_PATH_NR; p++)
		for (u32 i = 0; i < RTW89_DACK_IDX_NR; i++) {
			record(15, p << 8 | i | (u32)k->dadck_d[p][i] << 16,
			       k->addck_d[p][i] | (u32)k->biask_d[p][i] << 16);
			for (u32 w = 0; w < RTW89_DACK_MSBK_NR / 4; w++) {
				const u8 *b = &k->msbk_d[p][i][4 * w];
				record(16, p << 16 | i << 8 | w,
				       b[0] | (u32)b[1] << 8 | (u32)b[2] << 16 | (u32)b[3] << 24);
			}
		}
	record(17, dev->dpk.dpk_gs[0] | (u32)dev->dpk.dpk_gs[1] << 8,
	       dev->rfk_mcc.data[0].table_idx | (u32)dev->is_tssi_mode[0] << 8 |
	       (u32)dev->is_tssi_mode[1] << 9);
}
static void record_iqk(const struct rtw89_dev *dev)
{
	const struct rtw89_iqk_info *q = &dev->iqk;
	record(20, q->iqk_fail_cnt, (u32)q->is_iqk_init | (u32)q->is_nbiqk << 1 |
				    (u32)q->iqk_times << 8 | (u32)q->version << 16);
	for (u32 p = 0; p < RTW8852B_IQK_SS; p++) {
		record(21, p | (u32)q->iqk_band[p] << 8 | (u32)q->iqk_bw[p] << 16 |
			   (u32)q->iqk_ch[p] << 24,
		       (u32)q->lok_cor_fail[0][p] | (u32)q->lok_fin_fail[0][p] << 1 |
		       (u32)q->iqk_tx_fail[0][p] << 2 | (u32)q->iqk_rx_fail[0][p] << 3 |
		       (u32)q->is_wb_txiqk[p] << 4 | (u32)q->is_wb_rxiqk[p] << 5 |
		       (u32)q->iqk_table_idx[p] << 8);
		record(22, q->nb_txcfir[p], q->nb_rxcfir[p]);
		record(23, q->bp_txkresult[p], q->bp_rxkresult[p]);
		record(24, q->bp_iqkenable[p], q->syn1to2);
	}
	for (u32 i = 0; i < RTW89_IQK_CHS_NR; i++)
		for (u32 p = 0; p < RTW8852B_IQK_SS; p++) {
			record(25, i << 8 | p | (u32)q->iqk_mcc_ch[i][p] << 16, q->lok_idac[i][p]);
			record(26, i << 8 | p, q->lok_vbuf[i][p]);
		}
}
enum kind { INIT, RX_DCK };
enum fill { PATTERN, ONES, ZEROS };
static void fill(enum fill f)
{
	for (u32 i = 0; i < sizeof(memory); i++)
		memory[i] = f == PATTERN ? (u8)(i * 37 + 11) : f == ONES ? 0xff : 0;
	for (u32 p = 0; p < 2; p++)
		for (u32 a = 0; a < 256; a++)
			rf[p][a] = f == PATTERN ? (a * 0x9e37 + p * 0x3c1 + 0x1234) & RFREG_MASK :
				   f == ONES ? RFREG_MASK : 0;
	memset(&fault, 0, sizeof(fault));
	oneshots = 0;
	rpt_reads = 0;
}
static void record_tssi_dpk(const struct rtw89_dev *dev)
{
	const struct rtw89_rfk_mcc_info_data *m = &dev->rfk_mcc.data[0];
	const struct rtw89_dpk_info *d = &dev->dpk;
	const struct rtw89_tssi_info *t = &dev->tssi;

	record(40, m->ch[0] | (u32)m->ch[1] << 8 | (u32)m->ch[2] << 16,
	       m->band[0] | (u32)m->band[1] << 8 | (u32)m->band[2] << 16);
	record(43, (u32)d->is_dpk_enable | (u32)d->is_dpk_reload_en << 1 |
		   (u32)d->cur_idx[0] << 8 | (u32)d->cur_idx[1] << 16, 0);
	for (u32 p = 0; p < RTW89_DPK_RF_PATH; p++)
		for (u32 k = 0; k < RTW89_DPK_BKUP_NUM; k++) {
			const struct rtw89_dpk_bkup_para *b = &d->bp[p][k];

			record(41, p << 8 | k | (u32)b->band << 16 | (u32)b->bw << 20 |
				   (u32)b->ch << 24,
			       (u32)b->path_ok | (u32)b->txagc_dpk << 8 | (u32)b->ther_dpk << 16 |
			       (u32)b->gs << 24);
			record(42, b->pwsf | (u32)d->corr_val[p][k] << 16 | (u32)d->corr_idx[p][k] << 24,
			       d->dc_i[p][k] | (u32)d->dc_q[p][k] << 16);
		}
	for (u32 p = 0; p < RF_PATH_NUM_8852B; p++) {
		for (u32 b = 0; b < TSSI_ALIMK_MAX; b++)
			for (u32 v = 0; v < 4; v++)
				record(44, p << 16 | b << 8 | v | (u32)t->alignment_done[p][b] << 24,
				       t->alignment_value[p][b][v]);
		for (u32 c = 0; c < TSSI_MAX_CH_NUM; c++)
			if (t->check_backup_aligmk[p][c])
				for (u32 v = 0; v < 4; v++)
					record(45, p << 16 | c << 8 | v,
					       t->alignment_backup_by_ch[p][c][v]);
	}
}
/* The TX power tracking element's rows, bitmap 0xfff0: types 4 to 7 three rows
 * each, types 8 to 15 one. */
static s8 trk_rows[20][DELTA_SWINGIDX_SIZE];
static struct rtw89_fw_txpwr_track_cfg trk;
static void fill_trk(void)
{
	for (u32 r = 0; r < 20; r++)
		for (u32 i = 0; i < DELTA_SWINGIDX_SIZE; i++)
			trk_rows[r][i] = (s8)((int)((r * 13 + i * 7) % 61) - 30);
	for (u32 type = 4; type < 16; type++)
		trk.delta[type] = (const s8 (*)[DELTA_SWINGIDX_SIZE])
				  &trk_rows[type < 8 ? (type - 4) * 3 : type + 4];
}
enum op { OP_TSSI, OP_DPK, OP_CHANNEL, OP_BAND_CHANGED, OP_SCAN_START, OP_SCAN_END };
static const u32 rpt_ok[] = {0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b,
			     0x05000000, 0x00000030};
static const u32 rpt_sync_fail[] = {0x00000005, 0x00000012, 0x00006400, 0x000a0000,
				    0x0000000b, 0x05000000, 0x00000030};
static const u32 rpt_dgain_low[] = {0x00000005, 0x00000012, 0x0000c800, 0x000a0000,
				    0x0000000b, 0x01000000, 0x00000030};
static const u32 rpt_gl_high[] = {0x00000005, 0x00000012, 0x0000c800, 0x000a0000,
				  0x0000000b, 0x05000000, 0x00000090};
static const u32 rpt_gl_pas[] = {0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b,
				 0x05000000, 0x00000000, 0x04000400, 0x04000400, 0x00100010,
				 0x00100010};
static const u32 rpt_gl_lt[] = {0x00000005, 0x00000012, 0x0000c800, 0x000a0000, 0x0000000b,
				0x05000000, 0x00000000, 0x04000400, 0x04000400, 0x04000400,
				0x04000400};
static FILE *open_trace(const char *path)
{
	FILE *out = fopen(path, "wb");
	if (!out)
		abort();
	return out;
}
static void close_trace(FILE *out)
{
	if (fclose(out))
		abort();
}
struct chan { enum rtw89_band band; enum rtw89_bandwidth bw; u8 ch; };
static size_t run_track(const char *path);
int main(int argc, char **argv)
{
	static const struct {
		enum kind kind;
		enum fill fill;
		int has_dpd_bf;
		u32 dpd_bf;
		int rck_stuck, drck_stuck, addck_stuck, s0_stuck, s1_stuck, rx_stuck;
		int tssi;
	} cases[] = {
		{INIT, PATTERN, 1, 0x00000000},
		{INIT, PATTERN, 1, 0x0001f07f},
		{INIT, ONES},
		{INIT, ZEROS},
		{INIT, PATTERN, .rck_stuck = 1},
		{INIT, PATTERN, .drck_stuck = 1},
		{INIT, PATTERN, .addck_stuck = 1},
		{INIT, PATTERN, .s0_stuck = 1},
		{INIT, PATTERN, .s1_stuck = 1},
		{INIT, PATTERN, .rx_stuck = 1},
		{RX_DCK, PATTERN, .tssi = 1},
	};
	static const struct chan g1 = {RTW89_BAND_2G, RTW89_CHANNEL_WIDTH_20, 1};
	static const struct chan g6 = {RTW89_BAND_2G, RTW89_CHANNEL_WIDTH_40, 6};
	static const struct chan a36 = {RTW89_BAND_5G, RTW89_CHANNEL_WIDTH_20, 36};
	static const struct chan a149 = {RTW89_BAND_5G, RTW89_CHANNEL_WIDTH_40, 149};
	static const struct chan a36_80 = {RTW89_BAND_5G, RTW89_CHANNEL_WIDTH_80, 36};
	static const struct chan a149_80 = {RTW89_BAND_5G, RTW89_CHANNEL_WIDTH_80, 149};
	static const struct {
		const struct chan *chan, *then;
		u8 table_idx;
		int lok_fail;
		u64 nctl_fail;
		u32 nctl_stuck;
		int nbiqk;
	} iqk_cases[] = {
		{&g1},
		{&g6},
		{&a36},
		{&a149},
		{&a36_80},
		{&a149_80},
		{&a36_80, .lok_fail = 1},
		{&g1, .nctl_fail = BIT(0) | BIT(5) | BIT(10) | BIT(12) | BIT(13 + 6)},
		{&g6, .nctl_stuck = 7},
		{&a36, .table_idx = 1},
		{&g1, .then = &a149_80},
		{&a149, .nbiqk = 1},
		{&a149, .nbiqk = 1, .nctl_fail = ~0ULL},
	};
	static const struct chan a42_80 = {RTW89_BAND_5G, RTW89_CHANNEL_WIDTH_80, 42};
	static const struct chan a100 = {RTW89_BAND_5G, RTW89_CHANNEL_WIDTH_20, 100};
	struct top { enum op op; const struct chan *chan; };
#define RPT(a) .rpt = a, .rpt_len = ARRAY_SIZE(a)
	static const struct {
		int n;
		struct top ops[3];
		int thermal_ff, cwrpt_stuck, kip_stuck, gain, tssi_mode, epa_5g, gs7f, cav, mcc1;
		u32 nctl_stuck;
		const u32 *rpt;
		u32 rpt_len;
	} tcases[] = {
		{1, {{OP_TSSI, &g1}}},
		{1, {{OP_TSSI, &g6}}},
		{1, {{OP_TSSI, &a36}}},
		{1, {{OP_TSSI, &a149}}},
		{1, {{OP_TSSI, &a36_80}}},
		{1, {{OP_TSSI, &a149_80}}},
		{1, {{OP_TSSI, &a42_80}}},
		{1, {{OP_TSSI, &a100}}},
		{1, {{OP_TSSI, &a36}}, .thermal_ff = 1},
		{1, {{OP_TSSI, &g1}}, .cwrpt_stuck = 1},
		{1, {{OP_TSSI, &g6}}, .gain = 1},
		{2, {{OP_TSSI, &g1}, {OP_TSSI, &g1}}},
		{1, {{OP_DPK, &g1}}, RPT(rpt_ok)},
		{1, {{OP_DPK, &g6}}, RPT(rpt_ok)},
		{1, {{OP_DPK, &a36}}, RPT(rpt_ok)},
		{1, {{OP_DPK, &a149}}, RPT(rpt_ok)},
		{1, {{OP_DPK, &a36_80}}, RPT(rpt_ok)},
		{1, {{OP_DPK, &a149_80}}, RPT(rpt_ok)},
		{1, {{OP_DPK, &g1}}, RPT(rpt_sync_fail)},
		{1, {{OP_DPK, &a36}}, RPT(rpt_dgain_low)},
		{1, {{OP_DPK, &a36_80}}, RPT(rpt_dgain_low)},
		{1, {{OP_DPK, &g6}}, RPT(rpt_gl_high)},
		{1, {{OP_DPK, &a149}}, RPT(rpt_gl_pas)},
		{1, {{OP_DPK, &a149}}, RPT(rpt_gl_lt)},
		{1, {{OP_DPK, &g1}}, .tssi_mode = 1, RPT(rpt_ok)},
		{1, {{OP_DPK, &a36}}, .epa_5g = 1, RPT(rpt_ok)},
		{1, {{OP_DPK, &g1}}, .epa_5g = 1, RPT(rpt_ok)},
		{1, {{OP_DPK, &a36}}, .gs7f = 1, .cav = 1, RPT(rpt_ok)},
		{1, {{OP_DPK, &g6}}, .kip_stuck = 1, .nctl_stuck = 3, RPT(rpt_ok)},
		{1, {{OP_DPK, &g1}}},
		{1, {{OP_CHANNEL, &g1}}, RPT(rpt_ok)},
		{1, {{OP_CHANNEL, &a149_80}}, RPT(rpt_ok)},
		{2, {{OP_CHANNEL, &g6}, {OP_CHANNEL, &a36}}, RPT(rpt_ok)},
		{1, {{OP_CHANNEL, &a36}}, .mcc1 = 1, RPT(rpt_ok)},
		{1, {{OP_BAND_CHANGED, &a36}}},
		{2, {{OP_TSSI, &a36}, {OP_BAND_CHANGED, &a36}}},
		{1, {{OP_SCAN_START, &g1}}},
		{3, {{OP_TSSI, &g1}, {OP_SCAN_START, &g1}, {OP_SCAN_END, &g1}}},
	};
	if (argc != 5)
		return 2;
	FILE *out = open_trace(argv[1]);
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		static struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip_info;
		fill(cases[c].fill);
		if (cases[c].has_dpd_bf)
			set(CR_BASE + R_DPD_BF, 4, cases[c].dpd_bf);
		fault.rck_stuck = cases[c].rck_stuck;
		fault.drck_stuck = cases[c].drck_stuck;
		fault.addck_stuck = cases[c].addck_stuck;
		fault.s0_stuck = cases[c].s0_stuck;
		fault.s1_stuck = cases[c].s1_stuck;
		fault.rx_stuck = cases[c].rx_stuck;
		if (cases[c].kind == INIT) {
			rtw8852b_rfk_init(&dev);
		} else {
			dev.is_tssi_mode[RF_PATH_A] = cases[c].tssi;
			dev.is_tssi_mode[RF_PATH_B] = cases[c].tssi;
			rtw8852b_rx_dck(&dev, RTW89_PHY_0, RTW89_CHANCTX_0);
		}
		record_state(&dev);
		flush(out);
	}
	close_trace(out);
	out = open_trace(argv[2]);
	for (size_t c = 0; c < ARRAY_SIZE(iqk_cases); c++) {
		static struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip_info;
		fill(PATTERN);
		fault.lok_fail = iqk_cases[c].lok_fail;
		fault.nctl_fail = iqk_cases[c].nctl_fail;
		fault.nctl_stuck = iqk_cases[c].nctl_stuck;
		dev.rfk_mcc.data[0].table_idx = iqk_cases[c].table_idx;
		if (iqk_cases[c].nbiqk) {
			dev.iqk.is_iqk_init = true;
			dev.iqk.is_nbiqk = true;
		}
		for (const struct chan *ch = iqk_cases[c].chan; ch;
		     ch = ch == iqk_cases[c].then ? NULL : iqk_cases[c].then) {
			dev.chan.channel = ch->ch;
			dev.chan.band_type = ch->band;
			dev.chan.band_width = ch->bw;
			rtw8852b_iqk(&dev, RTW89_PHY_0, RTW89_CHANCTX_0);
		}
		record_state(&dev);
		record_iqk(&dev);
		flush(out);
	}
	close_trace(out);
	out = open_trace(argv[3]);
	fill_trk();
	for (size_t c = 0; c < ARRAY_SIZE(tcases); c++) {
		static struct rtw89_dev dev;
		struct rtw89_vif_link link = {RTW89_CHANCTX_0, RTW89_PHY_0};
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip_info;
		fill(PATTERN);
		fault.cwrpt_stuck = tcases[c].cwrpt_stuck;
		fault.kip_stuck = tcases[c].kip_stuck;
		fault.nctl_stuck = tcases[c].nctl_stuck;
		fault.rpt = tcases[c].rpt;
		fault.rpt_len = tcases[c].rpt_len;
		dev.dpk.dpk_gs[RTW89_PHY_0] = tcases[c].gs7f ? 0x7f : 0x5b;
		dev.hal.cv = tcases[c].cav ? CHIP_CAV : CHIP_CBV;
		dev.fw.elm_info.txpwr_trk = &trk;
		dev.io = &rtw89_raw_io;
		dev.fem.epa_5g = tcases[c].epa_5g;
		for (u32 p = 0; p < RF_PATH_NUM_8852B; p++) {
			dev.tssi.thermal[p] = tcases[c].thermal_ff ? 0xff : 0x20 + p;
			for (u32 g = 0; g < TSSI_TRIM_CH_GROUP_NUM; g++)
				dev.tssi.tssi_trim[p][g] = (s8)((int)((p * 7 + g * 3) % 9) - 4);
			for (u32 g = 0; g < TSSI_CCK_CH_GROUP_NUM; g++)
				dev.tssi.tssi_cck[p][g] = (s8)(0x10 + p * 3 + g);
			for (u32 g = 0; g < TSSI_MCS_CH_GROUP_NUM; g++)
				dev.tssi.tssi_mcs[p][g] = (s8)((int)((p * 5 + g * 11) % 31) - 15);
			if (tcases[c].gain) {
				for (u32 k = 0; k < 5; k++)
					dev.efuse_gain.offset[p][k] = (s8)((int)((p * 3 + k * 5) % 13) - 6);
				for (u32 s = 0; s < 5; s++)
					dev.efuse_gain.comp[p][s] = (s8)((int)((p * 7 + s * 2) % 11) - 5);
			}
		}
		if (tcases[c].gain) {
			dev.efuse_gain.offset_valid = true;
			dev.efuse_gain.comp_valid = true;
			dev.efuse_gain.offset_base[RTW89_PHY_0] = 3;
			dev.efuse_gain.rssi_base[RTW89_PHY_0] = -2;
		}
		if (tcases[c].tssi_mode) {
			dev.is_tssi_mode[RF_PATH_A] = true;
			dev.is_tssi_mode[RF_PATH_B] = true;
		}
		if (tcases[c].mcc1) {
			dev.rfk_mcc.data[0].ch[1] = tcases[c].ops[0].chan->ch;
			dev.rfk_mcc.data[0].band[1] = tcases[c].ops[0].chan->band;
		}
		for (int i = 0; i < tcases[c].n; i++) {
			const struct chan *ch = tcases[c].ops[i].chan;

			dev.chan.channel = ch->ch;
			dev.chan.band_type = ch->band;
			dev.chan.band_width = ch->bw;
			dev.chan.subband_type = rtw89_get_subband_type(ch->band, ch->ch);
			switch (tcases[c].ops[i].op) {
			case OP_TSSI:
				rtw8852b_tssi(&dev, RTW89_PHY_0, true, RTW89_CHANCTX_0);
				break;
			case OP_DPK:
				rtw8852b_dpk(&dev, RTW89_PHY_0, RTW89_CHANCTX_0);
				break;
			case OP_CHANNEL:
				rtw8852b_rfk_channel(&dev, &link);
				break;
			case OP_BAND_CHANGED:
				rtw8852b_rfk_band_changed(&dev, RTW89_PHY_0, &dev.chan);
				break;
			case OP_SCAN_START:
			case OP_SCAN_END:
				rtw8852b_rfk_scan(&dev, &link, tcases[c].ops[i].op == OP_SCAN_START);
				break;
			}
		}
		record_state(&dev);
		record_iqk(&dev);
		record_tssi_dpk(&dev);
		flush(out);
	}
	close_trace(out);
	size_t track_n = run_track(argv[4]);
	free(segment);
	printf("%zu %zu %zu %zu\n", ARRAY_SIZE(cases), ARRAY_SIZE(iqk_cases), ARRAY_SIZE(tcases),
	       track_n);
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, core_defines, defines38, phy_defines, chip_defines, declarations,
        declarations38, rfk_macros, by_cond, harness, harness38, core_helpers, phy_helpers,
        phy_h38, io_table, rf_access, phy38, dispatch, parser, tables, chip, chan38,
        common_h38, common38, bx_table, rfk_head, rfk, extra_group, rfk38, rfk_init, fw38, chip38, harness55, track55,
        main_c, track_c])
    generated = out / 'rfk_oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'rfk_oracle'
    # RTW8852B_TSSI_GET_VAL shifts a promoted u8 into int's sign bit, which the
    # kernel's -fno-strict-overflow leaves defined; the shift base check is off.
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-fno-sanitize=shift-base', '-fwrapv',
                    '-Wno-unused-function', '-Wno-unused-const-variable',
                    '-Wno-unused-variable', '-Wno-unused-but-set-variable',
                    '-Wno-c23-extensions', str(generated), '-o', str(exe)], check=True)
    trace = out / 'rfk_trace.bin'
    iqk_trace = out / 'iqk_trace.bin'
    tssi_dpk_trace = out / 'tssi_dpk_trace.bin'
    dpk_track_trace = out / 'dpk_track_trace.bin'
    run = subprocess.run([str(exe), str(trace), str(iqk_trace), str(tssi_dpk_trace),
                          str(dpk_track_trace)], check=True, capture_output=True, text=True)
    cases, iqk_cases, tssi_dpk_cases, dpk_track_cases_n = map(int, run.stdout.split())
    if dpk_track_cases_n != len(tcases55):
        raise ValueError(f'{dpk_track_cases_n} DPK tracking cases ran')
    dpk_track_data = dpk_track_trace.read_bytes()
    data = trace.read_bytes()
    iqk_data = iqk_trace.read_bytes()
    tssi_dpk_data = tssi_dpk_trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=cases,
        case_order='rtw8852b_rfk_init over patterned memory with R_DPD_BF 0x00000000 and '
                   '0x0001f07f, over all-ones and zeroed memory, with RCK, DRCK, ADDCK, S0 '
                   'DACK and S1 DACK never done, and with RR_MOD reading TX mode; '
                   'rtw8852b_rx_dck(PHY 0) with both paths in TSSI mode',
        dispatch=dict(rtw8852b_chip_ops=dict(chip_ops, **chip_ops38),
                      rtw8852b_chip_info=dict(info, **chip_id), rtw8852bx_info=bx,
                      rtw89_phy_gen_ax=phy_gen, rtw89_raw_io=dict(raw_io, **raw_io38)),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        iqk_cases=iqk_cases,
        iqk_case_order='rtw8852b_iqk(PHY 0) on 2 GHz 20 MHz channel 1, 2 GHz 40 MHz channel 6, '
                       '5 GHz 20 MHz channel 36, 5 GHz 40 MHz channel 149, 5 GHz 80 MHz '
                       'channels 36 and 149; 5 GHz 80 MHz channel 36 with the LO leakage '
                       'core code out of range; channel 1 with one-shots 1, 6, 11, 13 and 20 '
                       'failing; channel 6 with one-shot 7 never reporting; channel 36 under '
                       'MCC table 1; channel 1 then 5 GHz 80 MHz channel 149 on one state; '
                       '5 GHz 40 MHz channel 149 narrowband, passing and with every one-shot '
                       'failing',
        iqk_trace_bytes=len(iqk_data), iqk_trace_sha256=hashlib.sha256(iqk_data).hexdigest(),
        tssi_dpk_cases=tssi_dpk_cases, tssi_dpk_case_order=TSSI_DPK_ORDER, trk_rows=TRK_ROWS,
        tssi_dpk_trace_bytes=len(tssi_dpk_data),
        tssi_dpk_trace_sha256=hashlib.sha256(tssi_dpk_data).hexdigest(),
        dpk_track_cases=dpk_track_cases_n,
        dpk_track_periods=sum(len(case[3]) for case in tcases55),
        dpk_track_dispatch=dict(rtw8852b_chip_ops=chip_ops55, rtw8852bx_info=bx55),
        dpk_track_trace_bytes=len(dpk_track_data),
        dpk_track_trace_sha256=hashlib.sha256(dpk_track_data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays and the chip answers are a model derived from the code; no Linux '
            'capture and no physical evidence',
            'read_poll_timeout_atomic is modeled counted in steps, not by Linux timekeeping',
            'SWSI never reads busy; an RF read rtw89 would answer with INV_RF_DATA is not run',
            'rtw89_chip_stop_sch_tx and rtw89_chip_resume_sch_tx are stubs that note they were '
            'reached; the MAC oracle covers the scheduler',
            'rtw89_btc_ntfy_wl_rfk and rtw89_btc_phymap are no-ops',
            'rtw89_chan_get gives the case\'s channel, and the MCC table index is the '
            'case\'s, not rtw8852b_mcc_get_ch_info\'s',
            'the narrowband IQK cases set is_iqk_init and is_nbiqk beforehand, which nothing '
            'in rtw89 does',
            'register reads go straight to the model, below rtw89_pci_ops\' CMAC read retry',
            'the TSSI and DPK cases\' report words are scripted from the code, not measured; '
            'R_RPT_COM reads them in turn whatever the report selected',
            'rtw89_btc_ntfy_conn_rfk and rtw89_btc_ntfy_preserve_bt_time are no-ops',
            'one channel context: rtw89_entity_get_conf and rtw89_iterate_entity_chan give the '
            'case\'s channel alone',
            'the H2C is recorded as rtw89_h2c_pkt_set_hdr\'s arguments and the payload; the '
            'header bytes, sequence and forced ack are the H2C oracle\'s',
            'RTW89_CHK_FW_FEATURE(RFK_NTFY_MCC_V0) is false, as fw.c\'s table has it for '
            'RTL8852C alone',
            'ktime_get is 0: the alignment\'s time account is not modeled',
            'RTW8852B_TSSI_GET_VAL\'s shifts into int\'s sign bit are compiled -fwrapv with '
            'the shift base check off, as the kernel\'s -fno-strict-overflow leaves them',
            'the DPK tracking cases script the DPK results in use, the thermal readings and '
            'the TX AGC words instead of running rtw8852b_dpk first; DECLARE_EWMA(thermal, 4, '
            '4) is written in the harness as include/linux/average.h expands it',
            'rtw89_chip_get_thermal and rtw89_chip_rfk_track are stood for by direct calls '
            'to __rtw8852bx_get_thermal and rtw8852b_rfk_track, as the checked dispatch '
            'reaches them',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in [
        'cases', 'trace_bytes', 'trace_sha256', 'iqk_cases', 'iqk_trace_bytes',
        'iqk_trace_sha256', 'tssi_dpk_cases', 'tssi_dpk_trace_bytes',
        'tssi_dpk_trace_sha256', 'dpk_track_cases', 'dpk_track_trace_bytes',
        'dpk_track_trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
