#!/usr/bin/env python3
"""Unchanged pinned rtw89 DMAC pre-init for a PCIe RTL8852B, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. rtw89_mac_partial_init,
rtw89_mac_dmac_pre_init, the AX generation's hci_func_en and dmac_func_pre_en,
rtw89_mac_dle_init with every DLE callee, rtw89_mac_hfc_init with every HFC
callee, rtw89_mac_size, the RTL8852B HFC and DLE tables its chip info names
(PCIe and USB), its page registers, the rtw89 MMIO helpers and inlines of
core.h and mac.h, and the declarations and dispatch values they read are
extracted unchanged, each with its SHA-256 in manifest.json. They are compiled
with clang under ASan and UBSan against a harness that models MAC registers as
bytes: WDE_INI_STATUS and PLE_INI_STATUS read both ready bits, or the queue's
bit alone when stuck, and DMAC_FUNC_EN reads as written, as RTW89_R32_DEAD, as
RTW89_R32_EA, or never keeps B_AX_DMAC_FUNC_EN. rtwdev->hci.ops->mac_pre_init
(the PCIe pre-init) and rtw89_fw_download are stubs that record a marker.

Ten cases, each one segment prefixed by its byte length: the unchanged
rtw89_mac_partial_init(rtwdev, false, false) with mac.qta_mode SCC, as
rtw89_core_init leaves an AX chip, over patterned, all-ones and zeroed
memory, a WDE and a PLE that never read ready, and the three DMAC_FUNC_EN
faults; then rtw89_mac_dle_init(rtwdev, RTW89_QTA_SCC, RTW89_QTA_INVALID)
over patterned and all-ones memory. A segment is records of three
little-endian u32 (tag, register, value): reads are tagged by width, writes
by 4 plus width, delays 9, the PCIe pre-init's marker 12, the download's 13
(type, include_bb), and the return 11. A case that returns 0 then records
rtwdev->mac.dle_info (tags 14 and 15) and, for rtw89_mac_partial_init,
rtwdev->mac.hfc_param (tags 16 to 19, then 20 per channel when ch_cfg is set).
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

    def lines_between(file, first, last):
        """The lines from the one starting with first through the one starting with last."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n', text.index('\n' + last, start) + 1)
        return record(file, f'{first.split()[1]} block', text[start:end])

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
            values[name] = body[start:end].strip()
        return values

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    core_defines = defines('core.h', ['RTW89_R32_EA', 'RTW89_R32_DEAD'])
    mac_defines = defines('mac.h', [
        'DLE_BOUND_UNIT', 'RTW89_WDE_PG_64', 'RTW89_WDE_PG_128', 'RTW89_WDE_PG_256',
        'S_AX_WDE_PAGE_SEL_64', 'S_AX_WDE_PAGE_SEL_128', 'S_AX_WDE_PAGE_SEL_256',
        'RTW89_PLE_PG_64', 'RTW89_PLE_PG_128', 'RTW89_PLE_PG_256',
        'S_AX_PLE_PAGE_SEL_64', 'S_AX_PLE_PAGE_SEL_128', 'S_AX_PLE_PAGE_SEL_256'])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_hci_type'),
        declaration('core.h', 'enum', 'rtw89_hci_dle_type'),
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_qta_mode'),
        declaration('core.h', 'enum', 'rtw89_hcifc_mode'),
        declaration('core.h', 'enum', 'rtw89_dma_ch'),
        declaration('core.h', 'enum', 'rtw89_mac_idx'),
        declaration('core.h', 'enum', 'rtw89_fw_type'),
        declaration('mac.h', 'enum', 'rtw89_mac_hwmod_sel'),
        declaration('core.h', 'struct', 'rtw89_hfc_ch_cfg'),
        declaration('core.h', 'struct', 'rtw89_hfc_ch_info'),
        declaration('core.h', 'struct', 'rtw89_hfc_pub_cfg'),
        declaration('core.h', 'struct', 'rtw89_hfc_pub_info'),
        declaration('core.h', 'struct', 'rtw89_hfc_prec_cfg'),
        declaration('core.h', 'struct', 'rtw89_hfc_param'),
        declaration('core.h', 'struct', 'rtw89_hfc_param_ini'),
        declaration('core.h', 'struct', 'rtw89_dle_size'),
        declaration('core.h', 'struct', 'rtw89_wde_quota'),
        declaration('core.h', 'struct', 'rtw89_ple_quota'),
        declaration('core.h', 'struct', 'rtw89_rsvd_quota'),
        declaration('core.h', 'struct', 'rtw89_dle_rsvd_size'),
        declaration('core.h', 'struct', 'rtw89_dle_input'),
        declaration('core.h', 'struct', 'rtw89_dle_mem'),
        declaration('core.h', 'struct', 'rtw89_qta_def'),
        declaration('core.h', 'struct', 'rtw89_page_regs'),
        declaration('core.h', 'struct', 'rtw89_dle_info'),
        declaration('mac.h', 'struct', 'rtw89_mac_size_set'),
    ])
    helpers = '\n\n'.join(
        [function('core.h', name) for name in [
            'rtw89_write32_set', 'rtw89_write32_clr', 'rtw89_write32_mask',
            'rtw89_chip_get_qta_def']]
        + [function('mac.h', name) for name in [
            'rtw89_mac_check_mac_en', 'rtw89_mac_ctrl_hci_dma_trx',
            'rtw89_mac_fwdl_preconfig']])
    hfc = '\n\n'.join(function('mac.c', name) for name in [
        'rtw89_mac_check_mac_en_ax', 'hfc_reset_param', 'hfc_ch_cfg_chk',
        'hfc_pub_info_chk', 'hfc_pub_cfg_chk', 'hfc_ch_ctrl', 'hfc_upd_ch_info',
        'hfc_pub_ctrl', 'hfc_get_mix_info_ax', 'hfc_upd_mix_info', 'hfc_h2c_cfg_ax',
        'hfc_mix_cfg_ax', 'hfc_func_en_ax', 'rtw89_mac_hfc_init'])
    dle = '\n\n'.join(
        [function('mac.c', name) for name in [
            'get_dle_mem_cfg', 'dle_used_size', 'dle_expected_used_size',
            'dle_func_en_ax', 'dle_clk_en_ax', 'dle_mix_cfg_ax', 'chk_dle_rdy_ax']]
        + [lines_between('mac.c', '#define INVALID_QT_WCPU',
                         '\tSET_QUOTA_VAL(min_cfg->_x, max_cfg->_x, _module, _idx)')]
        + [function('mac.c', name) for name in [
            'wde_quota_cfg_ax', 'ple_quota_cfg_ax', 'dle_quota_cfg', 'rtw89_mac_dle_init']])
    pre_init = '\n\n'.join(function('mac.c', name) for name in [
        'rtw89_mac_hci_func_en_ax', 'rtw89_mac_dmac_func_pre_en_ax',
        'rtw89_mac_dmac_pre_init', 'rtw89_mac_partial_init'])
    mac_size = definition('mac.c', 'const struct rtw89_mac_size_set rtw89_mac_size')
    chip_tables = '\n\n'.join(definition('rtw8852b.c', head) for head in [
        'static const struct rtw89_hfc_ch_cfg rtw8852b_hfc_chcfg_pcie[]',
        'static const struct rtw89_hfc_pub_cfg rtw8852b_hfc_pubcfg_pcie',
        'static const struct rtw89_hfc_param_ini rtw8852b_hfc_param_ini_pcie[]',
        'static const struct rtw89_hfc_ch_cfg rtw8852b_hfc_chcfg_usb[]',
        'static const struct rtw89_hfc_pub_cfg rtw8852b_hfc_pubcfg_usb',
        'static const struct rtw89_hfc_prec_cfg rtw8852b_hfc_preccfg_usb',
        'static const struct rtw89_hfc_param_ini rtw8852b_hfc_param_ini_usb[]',
        'static const struct rtw89_dle_mem rtw8852b_dle_mem_pcie[]',
        'static const struct rtw89_dle_mem rtw8852b_dle_mem_usb3[]',
        'static const struct rtw89_page_regs rtw8852b_page_regs'])
    mac_fields = ['check_mac_en', 'hci_func_en', 'dmac_func_pre_en', 'dle_func_en',
                  'dle_clk_en', 'dle_mix_cfg', 'chk_dle_rdy', 'hfc_func_en', 'hfc_h2c_cfg',
                  'hfc_mix_cfg', 'hfc_get_mix_info', 'wde_quota_cfg', 'ple_quota_cfg',
                  'fwdl_preconfig']
    mac_def = fields('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax', mac_fields)
    info_fields = ['chip_id', 'fifo_size', 'dle_scc_rsvd_size', 'qta_def',
                   'hci_func_en_addr', 'page_regs', 'dma_ch_mask']
    info = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  info_fields + ['mac_def'])
    if info['mac_def'] != '&rtw89_mac_gen_ax':
        raise ValueError(f"rtw8852b_chip_info.mac_def is {info['mac_def']}")
    pci_ops = fields('pci.c', 'static const struct rtw89_hci_ops rtw89_pci_ops',
                     ['mac_pre_init'])
    pci_gen = fields('pci.c', 'const struct rtw89_pci_gen_def rtw89_pci_gen_ax',
                     ['mac_pre_init'])
    core_init = source('core.c')
    if '\trtwdev->mac.qta_mode = RTW89_QTA_SCC;\n' not in core_init:
        raise ValueError('core.c: rtw89_core_init no longer sets mac.qta_mode to SCC')
    dle_type = source('pci.c')
    if '\trtwdev->hci.dle_type = RTW89_HCI_DLE_TYPE_PCIE;\n' not in dle_type:
        raise ValueError('pci.c: the PCIe probe no longer sets hci.dle_type to PCIE')

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define U16_MAX 0xffff
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_replace_bits(old, v, m) ((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, v))
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
/* rtw89's log helpers are calls in the kernel: their arguments, register
 * reads among them, are evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound; a sleep before the first read counts
 * toward the bound. */
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
#define udelay(us) model_delay(us)
'''
    harness = r'''
struct rtw89_dev;
struct rtw89_mac_gen_def {
	int (*check_mac_en)(struct rtw89_dev *rtwdev, u8 band,
			    enum rtw89_mac_hwmod_sel sel);
	void (*hci_func_en)(struct rtw89_dev *rtwdev);
	void (*dmac_func_pre_en)(struct rtw89_dev *rtwdev);
	void (*dle_func_en)(struct rtw89_dev *rtwdev, bool enable);
	void (*dle_clk_en)(struct rtw89_dev *rtwdev, bool enable);
	int (*dle_mix_cfg)(struct rtw89_dev *rtwdev, const struct rtw89_dle_mem *cfg);
	int (*chk_dle_rdy)(struct rtw89_dev *rtwdev, bool wde_or_ple);
	void (*hfc_func_en)(struct rtw89_dev *rtwdev, bool en, bool h2c_en);
	void (*hfc_h2c_cfg)(struct rtw89_dev *rtwdev);
	void (*hfc_mix_cfg)(struct rtw89_dev *rtwdev);
	void (*hfc_get_mix_info)(struct rtw89_dev *rtwdev);
	void (*wde_quota_cfg)(struct rtw89_dev *rtwdev,
			      const struct rtw89_wde_quota *min_cfg,
			      const struct rtw89_wde_quota *max_cfg,
			      u16 ext_wde_min_qt_wcpu);
	void (*ple_quota_cfg)(struct rtw89_dev *rtwdev,
			      const struct rtw89_ple_quota *min_cfg,
			      const struct rtw89_ple_quota *max_cfg);
	void (*fwdl_preconfig)(struct rtw89_dev *rtwdev);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	const struct rtw89_mac_gen_def *mac_def;
	u32 fifo_size;
	u32 dle_scc_rsvd_size;
	struct rtw89_qta_def qta_def;
	u32 hci_func_en_addr;
	const struct rtw89_page_regs *page_regs;
	u32 dma_ch_mask;
};
struct rtw89_chip_variant { const struct rtw89_qta_def *qta_def_override; };
struct rtw89_hci_ops { int (*mac_pre_init)(struct rtw89_dev *rtwdev); };
struct rtw89_mac_info {
	struct rtw89_dle_info dle_info;
	struct rtw89_hfc_param hfc_param;
	enum rtw89_qta_mode qta_mode;
};
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_chip_variant *variant;
	struct {
		enum rtw89_hci_type type;
		enum rtw89_hci_dle_type dle_type;
		const struct rtw89_hci_ops *ops;
	} hci;
	struct rtw89_mac_info mac;
	bool dbcc_en;
};

/* The register model. */
static u8 memory[0x10000];
static int wde_stuck, ple_stuck;
enum dmac_fault { DMAC_ANSWERS, DMAC_READS_DEAD, DMAC_READS_EA, DMAC_DROPS_FUNC_EN };
static enum dmac_fault dmac;
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
static int special(u32 r)
{
	static const u32 at[] = {R_AX_DMAC_FUNC_EN, R_AX_WDE_INI_STATUS, R_AX_PLE_INI_STATUS};
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
	if (r == R_AX_WDE_INI_STATUS)
		v = wde_stuck ? (v | B_AX_WDE_Q_MGN_INI_RDY) & ~B_AX_WDE_BUF_MGN_INI_RDY
			      : v | WDE_MGN_INI_RDY;
	if (r == R_AX_PLE_INI_STATUS)
		v = ple_stuck ? (v | B_AX_PLE_Q_MGN_INI_RDY) & ~B_AX_PLE_BUF_MGN_INI_RDY
			      : v | PLE_MGN_INI_RDY;
	if (r == R_AX_DMAC_FUNC_EN && dmac == DMAC_READS_DEAD)
		v = RTW89_R32_DEAD;
	if (r == R_AX_DMAC_FUNC_EN && dmac == DMAC_READS_EA)
		v = RTW89_R32_EA;
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	check(r, n);
	record(4 + n, r, v);
	u32 stored = v;
	if (r == R_AX_DMAC_FUNC_EN && dmac == DMAC_DROPS_FUNC_EN)
		stored &= ~B_AX_DMAC_FUNC_EN;
	set(r, n, stored);
}
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* Callees outside this slice. rtw89_chip_bb_preinit is not reached with
 * include_bb and bb_preinit false; the PCIe pre-init and the firmware
 * download note that they were reached and succeed. */
static void rtw89_chip_bb_preinit(struct rtw89_dev *d) { (void)d; abort(); }
static int harness_mac_pre_init(struct rtw89_dev *d) { (void)d; record(12, 0, 0); return 0; }
static const struct rtw89_hci_ops hci_ops = { .mac_pre_init = harness_mac_pre_init };
static int rtw89_fw_download(struct rtw89_dev *d, enum rtw89_fw_type type, bool include_bb)
{
	(void)d;
	record(13, type, include_bb);
	return 0;
}
'''
    tables = (
        'static const struct rtw89_mac_gen_def mac_gen_ax = {\n'
        + ''.join(f'\t.{field} = {mac_def[field]},\n' for field in mac_fields)
        + '};\nstatic const struct rtw89_chip_info chip_info = {\n'
        + '\t.mac_def = &mac_gen_ax,\n'
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
static void record_dle_info(const struct rtw89_dev *dev)
{
	const struct rtw89_dle_info *i = &dev->mac.dle_info;
	record(14, i->qta_mode, i->ple_pg_size | (u32)i->ple_free_pg << 16);
	record(15, i->c0_rx_qta, i->c1_rx_qta);
}
static void record_hfc_param(const struct rtw89_dev *dev)
{
	const struct rtw89_hfc_param *p = &dev->mac.hfc_param;
	const struct rtw89_hfc_pub_cfg *pub = &p->pub_cfg;
	const struct rtw89_hfc_prec_cfg *prec = &p->prec_cfg;
	record(16, (u32)p->en | (u32)p->h2c_en << 1 | (u32)p->mode << 8, p->ch_cfg != NULL);
	record(17, pub->grp0 | (u32)pub->grp1 << 16, pub->pub_max | (u32)pub->wp_thrd << 16);
	record(18, prec->ch011_prec | (u32)prec->h2c_prec << 16,
	       prec->wp_ch07_prec | (u32)prec->wp_ch811_prec << 16);
	record(19, 0, prec->ch011_full_cond | (u32)prec->h2c_full_cond << 8 |
		      (u32)prec->wp_ch07_full_cond << 16 | (u32)prec->wp_ch811_full_cond << 24);
	if (p->ch_cfg)
		for (u32 ch = 0; ch < RTW89_DMA_CH_NUM; ch++)
			record(20, ch | (u32)p->ch_cfg[ch].grp << 8,
			       p->ch_cfg[ch].min | (u32)p->ch_cfg[ch].max << 16);
}
enum kind { PARTIAL_INIT, DLE_SCC };
enum fill { PATTERN, ONES, ZEROS };
int main(int argc, char **argv)
{
	static const struct {
		enum kind kind;
		enum fill fill;
		int wde_stuck, ple_stuck;
		enum dmac_fault dmac;
	} cases[] = {
		{PARTIAL_INIT, PATTERN, 0, 0, DMAC_ANSWERS},
		{PARTIAL_INIT, ONES, 0, 0, DMAC_ANSWERS},
		{PARTIAL_INIT, ZEROS, 0, 0, DMAC_ANSWERS},
		{PARTIAL_INIT, PATTERN, 1, 0, DMAC_ANSWERS},
		{PARTIAL_INIT, PATTERN, 0, 1, DMAC_ANSWERS},
		{PARTIAL_INIT, PATTERN, 0, 0, DMAC_READS_DEAD},
		{PARTIAL_INIT, PATTERN, 0, 0, DMAC_READS_EA},
		{PARTIAL_INIT, PATTERN, 0, 0, DMAC_DROPS_FUNC_EN},
		{DLE_SCC, PATTERN, 0, 0, DMAC_ANSWERS},
		{DLE_SCC, ONES, 0, 0, DMAC_ANSWERS},
	};
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		for (size_t i = 0; i < sizeof(memory); i++)
			memory[i] = cases[c].fill == PATTERN ? (u8)(i * 37 + 11) :
				    cases[c].fill == ONES ? 0xff : 0;
		wde_stuck = cases[c].wde_stuck;
		ple_stuck = cases[c].ple_stuck;
		dmac = cases[c].dmac;
		dev.chip = &chip_info;
		dev.variant = NULL;
		dev.hci.type = RTW89_HCI_TYPE_PCIE;
		dev.hci.dle_type = RTW89_HCI_DLE_TYPE_PCIE;
		dev.hci.ops = &hci_ops;
		dev.mac.qta_mode = RTW89_QTA_SCC;
		int ret;
		if (cases[c].kind == PARTIAL_INIT)
			ret = rtw89_mac_partial_init(&dev, false, false);
		else
			ret = rtw89_mac_dle_init(&dev, RTW89_QTA_SCC, RTW89_QTA_INVALID);
		record(11, 0, (u32)ret);
		if (!ret) {
			record_dle_info(&dev);
			if (cases[c].kind == PARTIAL_INIT)
				record_hfc_param(&dev);
		}
		flush(out);
	}
	if (fclose(out))
		abort();
	printf("%zu\n", ARRAY_SIZE(cases));
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, core_defines, mac_defines, declarations, harness, helpers,
        hfc, dle, pre_init, mac_size, chip_tables, tables, main_c])
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
        case_order='rtw89_mac_partial_init(false, false) over patterned/all-ones/zeroed memory, '
                   'WDE stuck, PLE stuck, DMAC_FUNC_EN dead/EA/without B_AX_DMAC_FUNC_EN; '
                   'rtw89_mac_dle_init(SCC, INVALID) over patterned/all-ones memory',
        dispatch=dict(rtw89_mac_gen_ax=mac_def, rtw8852b_chip_info=info,
                      rtw89_pci_ops=pci_ops, rtw89_pci_gen_ax=pci_gen,
                      rtw89_core_init='mac.qta_mode = RTW89_QTA_SCC',
                      rtw89_pci_probe='hci.dle_type = RTW89_HCI_DLE_TYPE_PCIE'),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays and the chip answers are a model; no physical evidence',
            'read_poll_timeout is modeled counted in steps, not by Linux timekeeping',
            'PCIe only: hci.dle_type PCIE; the USB tables are compiled but not read',
            'hci.ops->mac_pre_init and rtw89_fw_download are stubs that note they were reached '
            'and succeed; rtw89_chip_bb_preinit aborts if reached',
            'rtw89_mac_dle_init\'s error label is unreachable with RTL8852B\'s tables; '
            'it is tested in Rust with altered tables',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
