#!/usr/bin/env python3
"""Unchanged pinned rtw89 power on and off for a PCIe RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. rtw89_mac_pwr_on and rtw89_mac_pwr_off,
rtw89_mac_power_switch, RTL8852B's power functions, the AX generation's
reset_pwr_state and XTAL SI, the physical efuse read the first power-on makes,
the rtw89 MMIO helpers of core.h, and the enums and dispatch values they read
are extracted unchanged, each with its SHA-256 in manifest.json. They are
compiled with clang under ASan and UBSan against a harness that models MAC
registers as bytes: SYS_PW_CTRL reads RDY_SYSPWR and clears the ON/OFF MAC
requests it completes, IC_PWR_STATE says whether the WL MAC is on, XTAL SI
completes every request, and the efuse answers every read. Every access and
delay is recorded in trace.bin for 72 cases: cut CAV, CBV and CCV; RFE 0 and
5; efuse invalid, valid without power calibration, and valid with it; a cold
or a left-on WL MAC; probe done or not. Each case is a power-on segment and a
power-off segment, each prefixed by its byte length. A segment is records of
three little-endian u32 (tag, register, value): reads are tagged by width,
writes by 4 plus width, delays 9. The power-on segment ends with tag 10
(whether rtw89 handed the secure-boot efuse bytes to its MSS recognizers, and
the two bytes) and tag 11 (rtw89_mac_pwr_on's return).
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
    efuse_text = source('efuse.c')
    efuse_defines = record('efuse.c', 'EFUSE_* defines', '\n'.join(
        line for line in efuse_text.splitlines() if line.startswith('#define EFUSE_')))
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_hci_type'),
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_cv'),
        declaration('core.h', 'enum', 'rtw89_phy_idx'),
        declaration('core.h', 'enum', 'rtw89_flags'),
        declaration('core.h', 'struct', 'rtw89_sb_regs'),
        declaration('core.h', 'struct', 'rtw89_fw_secure'),
        declaration('mac.h', 'enum', 'rtw89_mac_xtal_si_offset'),
        declaration('efuse.c', 'enum', 'rtw89_efuse_bank'),
    ])
    helpers = '\n\n'.join(function('core.h', name) for name in [
        'rtw89_write8_set', 'rtw89_write16_set', 'rtw89_write32_set',
        'rtw89_write8_clr', 'rtw89_write16_clr', 'rtw89_write32_clr',
        'rtw89_read32_mask', 'rtw89_write32_mask', 'rtw89_write16_mask'])
    inlines = '\n\n'.join([
        function('chan.h', 'rtw89_set_entity_state'),
        function('mac.h', 'rtw89_mac_clr_aon_intr'),
        function('mac.h', 'rtw89_mac_set_vcore_cfg'),
        function('mac.h', 'rtw89_mac_set_vcore_reset'),
        function('mac.h', 'rtw89_mac_write_xtal_si'),
        function('mac.h', 'rtw89_mac_read_xtal_si'),
        function('mac.h', 'rtw89_mac_efuse_read_ecv'),
        function('mac.h', 'rtw89_mac_efuse_read_thermal_k'),
        function('mac.h', 'rtw89_mac_efuse_read_pwr_data'),
    ])
    xtal_si = '\n\n'.join(function('mac.c', name) for name in [
        'rtw89_mac_write_xtal_si_ax', 'rtw89_mac_read_xtal_si_ax'])
    efuse = '\n\n'.join(function('efuse.c', name) for name in [
        'rtw89_switch_efuse_bank', 'rtw89_enable_otp_burst_mode',
        'rtw89_enable_efuse_pwr_cut_ddv', 'rtw89_disable_efuse_pwr_cut_ddv',
        'rtw89_dump_physical_efuse_map_ddv', 'rtw89_dump_physical_efuse_map_dav',
        '__rtw89_dump_physical_efuse_map', 'rtw89_dump_physical_efuse_map',
        'rtw89_efuse_read_fw_secure_ax'])
    chip = '\n\n'.join(function('rtw8852b.c', name) for name in [
        'rtw8852b_pwr_sps_ana', 'rtw8852b_pwr_sps_dig_off',
        'rtw8852b_pwr_on_func', 'rtw8852b_pwr_off_func'])
    power = '\n\n'.join(function('mac.c', name) for name in [
        'rtw89_mac_reset_pwr_state_ax', 'rtw89_mac_power_switch_boot_mode',
        'rtw89_mac_pwr_off_func_for_unplugged', 'rtw89_mac_update_scoreboard',
        'rtw89_mac_power_switch', 'rtw89_mac_pwr_on', 'rtw89_mac_pwr_off'])
    mac_fields = ['reset_pwr_state', 'efuse_read_fw_secure', 'efuse_read_ecv',
                  'efuse_read_thermal_k', 'efuse_read_pwr_data', 'clr_aon_intr',
                  'set_vcore_cfg', 'write_xtal_si', 'read_xtal_si']
    mac_def = members('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax', mac_fields)
    ops = members('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                  ['pwr_on_func', 'pwr_off_func'])
    info = members('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                   ['chip_id', 'pwr_on_seq', 'pwr_off_seq', 'btc_sb'])

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u8_get_bits(v, m) ((u8)u32_get_bits(v, m))
#define WRITE_ONCE(x, v) ((x) = (v))
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
#define rtw89_warn(d, ...) ((void)(d))
#define rtw89_err(d, ...) ((void)(d))
#define rtw89_debug(d, m, ...) ((void)(d))
#define test_bit(n, a) ((((const unsigned long *)(a))[(n) / 64] >> ((n) % 64)) & 1UL)
#define set_bit(n, a) (((unsigned long *)(a))[(n) / 64] |= 1UL << ((n) % 64))
#define clear_bit(n, a) (((unsigned long *)(a))[(n) / 64] &= ~(1UL << ((n) % 64)))
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
struct rtw89_pwr_cfg;
struct rtw89_mac_gen_def {
	int (*reset_pwr_state)(struct rtw89_dev *rtwdev);
	int (*efuse_read_fw_secure)(struct rtw89_dev *rtwdev);
	int (*efuse_read_ecv)(struct rtw89_dev *rtwdev);
	int (*efuse_read_thermal_k)(struct rtw89_dev *rtwdev);
	int (*efuse_read_pwr_data)(struct rtw89_dev *rtwdev);
	void (*clr_aon_intr)(struct rtw89_dev *rtwdev);
	void (*set_vcore_cfg)(struct rtw89_dev *rtwdev, u8 vlv);
	int (*write_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 val, u8 mask);
	int (*read_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 *val);
};
struct rtw89_chip_ops {
	int (*pwr_on_func)(struct rtw89_dev *rtwdev);
	int (*pwr_off_func)(struct rtw89_dev *rtwdev);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	const struct rtw89_pwr_cfg * const *pwr_on_seq;
	const struct rtw89_pwr_cfg * const *pwr_off_seq;
	struct rtw89_sb_regs btc_sb;
};
struct rtw89_efuse { bool valid; bool power_k_valid; u8 rfe_type; };
struct rtw89_hal { u8 cv; u8 thermal_prot_vlv; bool entity_active[RTW89_PHY_NUM]; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	struct { enum rtw89_hci_type type; } hci;
	struct rtw89_efuse efuse;
	struct rtw89_hal hal;
	struct { struct rtw89_fw_secure sec; } fw;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
};

/* The register model. */
static u8 memory[0x10000];
static u8 xtal[256];
static int powered;
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
static u8 efuse_byte(u32 addr) { return (u8)(addr * 7 + 3); }
static int special(u32 r)
{
	static const u32 at[] = {R_AX_SYS_PW_CTRL, R_AX_EFUSE_CTRL, R_AX_WLAN_XTAL_SI_CTRL, R_AX_IC_PWR_STATE};
	for (size_t i = 0; i < ARRAY_SIZE(at); i++)
		if (r >= at[i] && r < at[i] + 4)
			return 1;
	return 0;
}
static void check(u32 r, u32 n)
{
	if (r + n > sizeof(memory) || (special(r) && (n != 4 || (r & 3))))
		abort();
}
static u32 model_read(u32 r, u32 n)
{
	check(r, n);
	u32 v = get(r, n);
	if (r == R_AX_SYS_PW_CTRL)
		v |= B_AX_RDY_SYSPWR;
	if (r == R_AX_IC_PWR_STATE)
		v = (v & ~B_AX_WLMAC_PWR_STE_MASK) |
		    FIELD_PREP(B_AX_WLMAC_PWR_STE_MASK, powered ? MAC_AX_MAC_ON : MAC_AX_MAC_OFF);
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	check(r, n);
	record(4 + n, r, v);
	u32 stored = v;
	if (r == R_AX_SYS_PW_CTRL) {
		if (v & B_AX_APFN_ONMAC) { stored &= ~B_AX_APFN_ONMAC; powered = 1; }
		if (v & B_AX_APFM_OFFMAC) { stored &= ~B_AX_APFM_OFFMAC; powered = 0; }
	} else if (r == R_AX_WLAN_XTAL_SI_CTRL) {
		u32 offset = u32_get_bits(v, B_AX_WL_XTAL_SI_ADDR_MASK);
		u8 data = u32_get_bits(v, B_AX_WL_XTAL_SI_DATA_MASK);
		u8 mask = u32_get_bits(v, B_AX_WL_XTAL_SI_BITMASK_MASK);
		stored = v & ~B_AX_WL_XTAL_SI_CMD_POLL;
		if (u32_get_bits(v, B_AX_WL_XTAL_SI_MODE_MASK) == XTAL_SI_NORMAL_WRITE)
			xtal[offset] = (xtal[offset] & ~mask) | (data & mask);
		else
			stored = (stored & ~B_AX_WL_XTAL_SI_DATA_MASK) |
				 FIELD_PREP(B_AX_WL_XTAL_SI_DATA_MASK, xtal[offset]);
	} else if (r == R_AX_EFUSE_CTRL) {
		stored = (v & ~B_AX_EF_DATA_MASK) | B_AX_EF_RDY |
			 efuse_byte(u32_get_bits(v, B_AX_EF_ADDR_MASK));
	}
	set(r, n, stored);
}
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* Callees outside this slice: none is reached on a PCIe RTL8852B with no
 * firmware running, except the MSS recognizers, which only note the bytes. */
static int rtw89_mac_pwr_seq(struct rtw89_dev *d, const struct rtw89_pwr_cfg * const *s) { (void)d; (void)s; abort(); }
static void __rtw89_leave_ps_mode(struct rtw89_dev *d) { (void)d; abort(); }
static int secure_seen;
static u32 secure_bytes;
static int rtw89_efuse_recognize_mss_index_v0(struct rtw89_dev *d, u8 b1, u8 b2)
{
	(void)d;
	secure_seen = 1;
	secure_bytes = (u32)b1 << 8 | b2;
	return -ENOENT;
}
static int rtw89_efuse_recognize_mss_info_v1(struct rtw89_dev *d, u8 b1, u8 b2) { (void)d; (void)b1; (void)b2; return -ENOENT; }
'''
    tables = (
        'static const struct rtw89_mac_gen_def mac_gen_ax = {\n'
        + ''.join(f'\t.{field} = {mac_def[field]},\n' for field in mac_fields)
        + '};\nstatic const struct rtw89_chip_ops chip_ops = {\n'
        + f"\t.pwr_on_func = {ops['pwr_on_func']},\n\t.pwr_off_func = {ops['pwr_off_func']},\n"
        + '};\nstatic const struct rtw89_chip_info chip_info = {\n'
        + f"\t.chip_id = {info['chip_id']},\n\t.ops = &chip_ops,\n\t.mac_def = &mac_gen_ax,\n"
        + f"\t.pwr_on_seq = {info['pwr_on_seq']},\n\t.pwr_off_seq = {info['pwr_off_seq']},\n"
        + f"\t.btc_sb = {info['btc_sb']},\n"
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
int main(int argc, char **argv)
{
	static const u8 cuts[] = {CHIP_CAV, CHIP_CBV, CHIP_CCV};
	static const u8 rfes[] = {0, 5};
	static const bool efuses[][2] = {{false, false}, {true, false}, {true, true}};
	unsigned cases = 0;
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	for (size_t c = 0; c < ARRAY_SIZE(cuts); c++)
	for (size_t r = 0; r < ARRAY_SIZE(rfes); r++)
	for (size_t e = 0; e < ARRAY_SIZE(efuses); e++)
	for (int warm = 0; warm < 2; warm++)
	for (int probe_done = 0; probe_done < 2; probe_done++) {
		struct rtw89_dev dev = {0};
		for (size_t i = 0; i < sizeof(memory); i++)
			memory[i] = i * 37 + 11;
		memset(xtal, 0, sizeof(xtal));
		powered = warm;
		secure_seen = 0;
		secure_bytes = 0;
		dev.chip = &chip_info;
		dev.hci.type = RTW89_HCI_TYPE_PCIE;
		dev.hal.cv = cuts[c];
		dev.efuse.rfe_type = rfes[r];
		dev.efuse.valid = efuses[e][0];
		dev.efuse.power_k_valid = efuses[e][1];
		if (probe_done)
			set_bit(RTW89_FLAG_PROBE_DONE, dev.flags);
		int ret = rtw89_mac_pwr_on(&dev);
		record(10, secure_seen, secure_bytes);
		record(11, 0, (u32)ret);
		flush(out);
		rtw89_mac_pwr_off(&dev);
		flush(out);
		cases++;
	}
	if (fclose(out))
		abort();
	printf("%u\n", cases);
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, efuse_defines, declarations, harness,
        helpers, inlines, xtal_si, efuse, power, chip, tables, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    str(generated), '-o', str(exe)], check=True)
    trace = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    cases = int(run.stdout.strip())
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=cases,
        case_order='cut CAV/CBV/CCV, RFE 0/5, efuse invalid/valid/valid with power_k, '
                   'cold/left on, probe not done/done',
        dispatch=dict(rtw89_mac_gen_ax=mac_def, rtw8852b_chip_ops=ops, rtw8852b_chip_info=info),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays and the chip answers are a model; no physical evidence',
            'every polled bit answers at once; timeouts and retries are tested in Rust',
            'read_poll_timeout is modeled counted in steps, not by Linux timekeeping',
            'PCIe only: USB/SDIO branches run with hci.type PCIE and are not exercised',
            'firmware never ready: __rtw89_leave_ps_mode and rtw89_mac_pwr_seq abort if reached',
            'the MSS recognizers are stubs that note the efuse bytes; interpreting them is not checked',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
