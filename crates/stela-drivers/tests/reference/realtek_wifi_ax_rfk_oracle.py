#!/usr/bin/env python3
"""Unchanged pinned rtw89 RF calibrations for an RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. rtw8852b.c's rtw8852b_rfk_init and the
rtw8852b_rfk.c functions it reaches (rtw8852b_dpk_init with
_set_dpd_backoff, rtw8852b_rck with _rck, rtw8852b_dack with _dac_cal and
every DACK helper, rtw8852b_rx_dck with _wait_rx_mode, _rx_dck and
_set_rx_dck), the file's leading defines, enums and tables, every table of
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
with mode 2 (TX) when the case says so. Every other read, the ones that
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
        'RTW89_DACK_PATH_NR', 'RTW89_DACK_IDX_NR', 'RTW89_DACK_MSBK_NR'])
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
            'rtw89_rfk_mcc_info']]
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
        'rtw8852b_dpk_init', 'rtw8852b_rck', 'rtw8852b_dack', 'rtw8852b_rx_dck'])
    rfk_init = functions('rtw8852b.c', ['rtw8852b_rfk_init'])

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
enum { RTW89_DBG_RFK = 1 };
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
	const struct rtw89_phy_gen_def *phy_def;
	u32 rf_base_addr[2];
	u8 rf_path_num;
};
struct rtw89_hal { u8 cv; };
struct rtw89_dpk_info { u8 dpk_gs[RTW89_PHY_NUM]; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	bool dbcc_en;
	struct rtw89_hal hal;
	struct rtw89_dack_info dack;
	struct rtw89_dpk_info dpk;
	struct rtw89_rfk_mcc_info rfk_mcc;
	bool is_tssi_mode[RF_PATH_MAX];
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
};

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
} fault;
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
        '\t.phy_def = &phy_gen_ax,\n'
        f"\t.rf_base_addr = {info['rf_base_addr']},\n"
        f"\t.rf_path_num = {info['rf_path_num']},\n}};\n")
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
}
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
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
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
	if (fclose(out))
		abort();
	free(segment);
	printf("%zu\n", ARRAY_SIZE(cases));
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, core_defines, phy_defines, chip_defines, declarations, rfk_macros,
        by_cond, harness, core_helpers, phy_helpers, rf_access, dispatch, parser, tables, chip,
        rfk_head, rfk, rfk_init, main_c])
    generated = out / 'rfk_oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'rfk_oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-unused-const-variable', '-Wno-unused-variable',
                    '-Wno-unused-but-set-variable', '-Wno-c23-extensions',
                    str(generated), '-o', str(exe)], check=True)
    trace = out / 'rfk_trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=int(run.stdout.strip()),
        case_order='rtw8852b_rfk_init over patterned memory with R_DPD_BF 0x00000000 and '
                   '0x0001f07f, over all-ones and zeroed memory, with RCK, DRCK, ADDCK, S0 '
                   'DACK and S1 DACK never done, and with RR_MOD reading TX mode; '
                   'rtw8852b_rx_dck(PHY 0) with both paths in TSSI mode',
        dispatch=dict(rtw8852b_chip_ops=chip_ops, rtw8852b_chip_info=info,
                      rtw89_phy_gen_ax=phy_gen, rtw89_raw_io=raw_io),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays and the chip answers are a model derived from the code; no Linux '
            'capture and no physical evidence',
            'read_poll_timeout_atomic is modeled counted in steps, not by Linux timekeeping',
            'SWSI never reads busy; an RF read rtw89 would answer with INV_RF_DATA is not run',
            'rtw89_chip_stop_sch_tx and rtw89_chip_resume_sch_tx are stubs that note they were '
            'reached; the MAC oracle covers the scheduler',
            'rtw89_btc_ntfy_wl_rfk and rtw89_btc_phymap are no-ops',
            'register reads go straight to the model, below rtw89_pci_ops\' CMAC read retry',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
