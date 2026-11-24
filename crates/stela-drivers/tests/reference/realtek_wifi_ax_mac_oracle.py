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

A second program, init_oracle.c, writes init_trace.bin: the unchanged
rtw89_mac_init for a PCIe RTL8852B, from its rtw89_mac_partial_init through
__rtw8852bx_mac_enable_bb_rf, sys_init_ax, trx_init_ax (dmac_init_ax with the
SCC quota and the full flow control, cmac_init_ax, the interrupt masks and the
release report), rtw89_mac_feat_init, rtw89_pci_ops_mac_post_init_ax with
rtw89_pci_ltr_set, rtw89_fw_send_all_early_h2c and rtw89_fw_h2c_set_ofld_cfg,
and rtw89_mac_stop_sch_tx and rtw89_mac_resume_sch_tx with the register mailbox
(rtw89_fw_msg_reg). Its symbols are listed under "init" in manifest.json with
their own SHA-256. Its model adds, per aligned word: SS_CTRL reading
SS_INIT_DONE_1, PUB_PAGE_INFO1 reading no public page used and PUB_PAGE_INFO2
the maximum PUB_PAGE_CTRL2 holds as available; WLAN_XTAL_SI_CTRL, the address
CAM and the BA CAM clearing their poll, clear and reset bits once written;
CMAC_FUNC_EN reading RTW89_R32_DEAD as a fault; and a trigger written to
H2CREG_CTRL leaving it 0 and, when the firmware answers, its four words in
C2HREG_DATA0..3 with 1 in C2HREG_CTRL. Each fault keeps its bit instead.
rtw89_h2c_tx records the skb's length and the sequence after it (40) and its
bytes as little-endian words (41). The PCIe pre-init, the download and the
power-off record 12, 13 and 30. Twenty-two cases, each a segment: an
rtw89_mac_init returns (11), then on success dle_info (14, 15), hfc_param (16
to 20), each channel's ch_info (21) and pub_info (22, 23), then h2c_seq (24);
a scheduler case returns (11), then for a stop that returned 0 the tx_en it
read (25), then the mailbox counters (26).
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
    # The second program's extractions are recorded in its own list; this
    # receipt keeps the first program's.
    receipt['symbols'] = list(manifest)
    receipt['init'] = full_init(source, closing, function, declaration, definition,
                                defines, lines_between, fields, out)
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    summary = {k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}
    summary['init'] = {k: receipt['init'][k] for k in ['cases', 'trace_bytes', 'trace_sha256']}
    print(json.dumps(summary))
    return 0


def full_init(source, closing, function, declaration, definition, defines,
              lines_between, fields, out):
    """The second program: the unchanged rtw89_mac_init and the scheduler TX helpers,
    written to init_trace.bin; returns its receipt, whose symbols are its own."""
    manifest = []

    def mark(body, file, name):
        manifest.append(dict(path='rtw89/' + file, symbol=name,
                             sha256=hashlib.sha256(body.encode()).hexdigest()))
        return body

    def own(file, name, body):
        return mark(body, file, name)

    def fn(file, name):
        return own(file, name, function(file, name))

    def locate(file, name):
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
            return m.start(), fn(file, name)
        raise ValueError(f'{file}: no definition of {name}')

    def in_order(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        return '\n\n'.join(body for _, body in sorted(locate(file, name) for name in names))

    def decl(file, kind, name):
        return own(file, f'{kind} {name}', declaration(file, kind, name))

    def defn(file, head):
        return own(file, head, definition(file, head))

    def defs(file, names):
        return own(file, f'#define {" ".join(names)}', defines(file, names))

    def span(file, first, last):
        """Everything from the line starting `first` through the declaration `last`."""
        text = source(file)
        m = re.search(r'^' + re.escape(first), text, re.M)
        n = re.search(r'^' + re.escape(last) + r' \{', text, re.M)
        if not m or not n or n.start() < m.start():
            raise ValueError(f'{file}: no span {first} .. {last}')
        end = text.index(';', closing(text, text.index('{', n.start()))) + 1
        return own(file, f'{first} .. {last}', text[m.start():end])

    def block(file, first, last):
        """The lines from the one starting `first` through the #define `last`,
        continuation lines included."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n', text.index('\n#define ' + last, start) + 1)
        while text[end - 1] == '\\':
            end = text.index('\n', end + 1)
        return own(file, f'{first} .. {last}', text[start:end])

    def table(file, head):
        """An array definition, through its semicolon."""
        text = source(file)
        m = re.search(re.escape(head) + r'\[[^\]]*\] = \{', text)
        if not m:
            raise ValueError(f'{file}: no {head}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return own(file, head, text[m.start():end])

    def members(file, head, names):
        """Members of a designated initializer by name; the initializer is recorded."""
        text = source(file)
        m = re.search(r'^' + re.escape(head) + r' = \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {head}')
        mark(text[m.start():closing(text, text.index('{', m.start()))], file, head)
        return fields(file, head, names)

    reg_h = own('reg.h', 'reg.h', source('reg.h'))
    core_defines = defs('core.h', ['RTW89_R32_EA', 'RTW89_R32_DEAD'])
    mac_defines = defs('mac.h', [
        'DLE_BOUND_UNIT', 'RTW89_WDE_PG_64', 'RTW89_WDE_PG_128', 'RTW89_WDE_PG_256',
        'S_AX_WDE_PAGE_SEL_64', 'S_AX_WDE_PAGE_SEL_128', 'S_AX_WDE_PAGE_SEL_256',
        'RTW89_PLE_PG_64', 'RTW89_PLE_PG_128', 'RTW89_PLE_PG_256',
        'S_AX_PLE_PAGE_SEL_64', 'S_AX_PLE_PAGE_SEL_128', 'S_AX_PLE_PAGE_SEL_256',
        'TRXCFG_WAIT_CNT', 'RTW89_MAC_AX_BAND_REG_OFFSET', 'FULL_BIT_MASK'])
    fw_defines = defs('fw.h', [
        'H2C_HEADER_LEN', 'H2C_HDR_CAT', 'H2C_HDR_CLASS', 'H2C_HDR_FUNC', 'H2C_HDR_DEL_TYPE',
        'H2C_HDR_H2C_SEQ', 'H2C_HDR_TOTAL_LEN', 'H2C_HDR_REC_ACK', 'H2C_HDR_DONE_ACK',
        'FWCMD_TYPE_H2C', 'H2C_CAT_MAC', 'H2C_CL_MAC_FW_OFLD'])
    pci_defines = block('pci.h', '#define R_AX_PCIE_DMA_STOP1', 'B_AX_TX_STOP1_MASK_V1')
    declarations = '\n\n'.join(
        [decl('core.h', 'enum', name) for name in [
            'rtw89_hci_type', 'rtw89_hci_dle_type', 'rtw89_core_chip_id', 'rtw89_chip_gen',
            'rtw89_cv', 'rtw89_bacam_ver', 'rtw89_sch_tx_sel', 'rtw89_qta_mode',
            'rtw89_hcifc_mode', 'rtw89_host_rpr_mode', 'rtw89_dma_ch', 'rtw89_mac_idx',
            'rtw89_fw_type', 'rtw89_flags']]
        + [decl('mac.h', 'enum', name) for name in [
            'rtw89_mac_hwmod_sel', 'rtw89_mac_fwd_target', 'rtw89_machdr_frame_type',
            'rtw89_mac_xtal_si_offset']]
        + [decl('core.h', 'struct', name) for name in [
            'rtw89_txwd_body', 'rtw89_hfc_ch_cfg', 'rtw89_hfc_ch_info', 'rtw89_hfc_pub_cfg',
            'rtw89_hfc_pub_info', 'rtw89_hfc_prec_cfg', 'rtw89_hfc_param',
            'rtw89_hfc_param_ini', 'rtw89_dle_size', 'rtw89_wde_quota', 'rtw89_ple_quota',
            'rtw89_rsvd_quota', 'rtw89_dle_rsvd_size', 'rtw89_dle_input', 'rtw89_dle_mem',
            'rtw89_qta_def', 'rtw89_page_regs', 'rtw89_dle_info', 'rtw89_reg_def',
            'rtw89_reg3_def', 'rtw89_imr_info', 'rtw89_rrsr_cfgs', 'rtw89_early_h2c']]
        + [decl('mac.h', 'struct', 'rtw89_mac_size_set'),
           span('fw.h', 'struct rtw89_c2hreg_hdr {', 'enum rtw89_mac_c2h_type'),
           decl('fw.h', 'struct', 'fwcmd_hdr'),
           decl('fw.h', 'enum', 'rtw89_fw_ofld_h2c_func')])
    helpers = '\n\n'.join(
        [fn('core.h', name) for name in [
            'rtw89_io_pack', 'rtw89_io_unpack', 'rtw89_write8_set', 'rtw89_write16_set',
            'rtw89_write32_set', 'rtw89_write8_clr', 'rtw89_write16_clr', 'rtw89_write32_clr',
            'rtw89_read32_mask', 'rtw89_write32_mask', 'rtw89_write16_mask',
            'rtw89_write8_mask', 'rtw89_chip_get_qta_def', 'rtw89_is_rtl885xb']]
        + [fn('mac.h', name) for name in [
            'rtw89_mac_check_mac_en', 'rtw89_mac_ctrl_hci_dma_trx', 'rtw89_mac_fwdl_preconfig',
            'rtw89_mac_reg_by_idx', 'rtw89_chip_enable_bb_rf', 'rtw89_mac_write_xtal_si']]
        + [fn('pci.h', name) for name in [
            'rtw89_pci_ltr_is_err_reg_val', 'rtw89_pci_ops_mac_post_init']])
    fw = in_order('fw.c', [
        'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr', 'rtw89_h2c_pkt_set_hdr',
        'rtw89_fw_h2c_set_ofld_cfg', 'rtw89_fw_send_all_early_h2c', 'rtw89_fw_write_h2c_reg',
        'rtw89_fw_read_c2h_reg', 'rtw89_fw_msg_reg'])
    mac = '\n\n'.join(
        [in_order('mac.c', [
            'rtw89_mac_check_mac_en_ax', 'hfc_reset_param', 'hfc_ch_cfg_chk',
            'hfc_pub_info_chk', 'hfc_pub_cfg_chk', 'hfc_ch_ctrl', 'hfc_upd_ch_info',
            'hfc_pub_ctrl', 'hfc_get_mix_info_ax', 'hfc_upd_mix_info', 'hfc_h2c_cfg_ax',
            'hfc_mix_cfg_ax', 'hfc_func_en_ax', 'rtw89_mac_hfc_init', 'cmac_func_en_ax',
            'dmac_func_en_ax', 'chip_func_en_ax', 'sys_init_ax', 'get_dle_mem_cfg',
            'dle_used_size', 'dle_expected_used_size', 'dle_func_en_ax', 'dle_clk_en_ax',
            'dle_mix_cfg_ax', 'chk_dle_rdy_ax'])]
        + [own('mac.c', 'INVALID_QT_WCPU block', lines_between(
            'mac.c', '#define INVALID_QT_WCPU',
            '\tSET_QUOTA_VAL(min_cfg->_x, max_cfg->_x, _module, _idx)'))]
        + [in_order('mac.c', [
            'wde_quota_cfg_ax', 'ple_quota_cfg_ax', 'dle_quota_cfg', 'rtw89_mac_dle_init',
            'is_qta_poh', 'rtw89_mac_preload_init', '_patch_ss2f_path', 'sta_sch_init_ax',
            'mpdu_proc_init_ax', 'sec_eng_init_ax', 'dmac_init_ax', 'addr_cam_init_ax',
            'scheduler_init_ax', 'rtw89_mac_typ_fltr_opt_ax', 'rx_fltr_init_ax',
            '_patch_dis_resp_chk', 'cca_ctrl_init_ax', 'nav_ctrl_init_ax',
            'spatial_reuse_init_ax', 'tmac_init_ax', 'trxptcl_init_ax', 'rst_bacam',
            'rmac_init_ax', 'cmac_com_init_ax', 'rtw89_mac_is_qta_dbcc', 'ptcl_init_ax',
            'cmac_dma_init_ax', 'cmac_init_ax', 'rtw89_hw_sch_tx_en_h2c',
            'rtw89_set_hw_sch_tx_en', 'rtw89_mac_stop_sch_tx', 'rtw89_mac_resume_sch_tx',
            'rtw89_wdrls_imr_enable', 'rtw89_wsec_imr_enable', 'rtw89_mpdu_trx_imr_enable',
            'rtw89_sta_sch_imr_enable', 'rtw89_txpktctl_imr_enable', 'rtw89_wde_imr_enable',
            'rtw89_ple_imr_enable', 'rtw89_pktin_imr_enable', 'rtw89_dispatcher_imr_enable',
            'rtw89_cpuio_imr_enable', 'rtw89_bbrpt_imr_enable', 'rtw89_scheduler_imr_enable',
            'rtw89_ptcl_imr_enable', 'rtw89_cdma_imr_enable', 'rtw89_phy_intf_imr_enable',
            'rtw89_rmac_imr_enable', 'rtw89_tmac_imr_enable', 'enable_imr_ax',
            'err_imr_ctrl_ax', 'set_host_rpr_ax', 'trx_init_ax', 'rtw89_mac_feat_init',
            'rtw89_mac_hci_func_en_ax', 'rtw89_mac_dmac_func_pre_en_ax',
            'rtw89_mac_dmac_pre_init', 'rtw89_mac_partial_init', 'rtw89_mac_init',
            'rtw89_mac_write_xtal_si_ax'])])
    bb_rf = fn('rtw8852b_common.c', '__rtw8852bx_mac_enable_bb_rf')
    bb_rf_inline = fn('rtw8852b_common.h', 'rtw8852bx_mac_enable_bb_rf')
    pci = in_order('pci.c', [
        'rtw89_pci_ctrl_txdma_ch_ax', 'rtw89_pci_ltr_set', 'rtw89_pci_ops_mac_post_init_ax'])
    mac_size = defn('mac.c', 'const struct rtw89_mac_size_set rtw89_mac_size')
    chip_tables = '\n\n'.join(
        [defn('rtw8852b.c', head) for head in [
            'static const struct rtw89_hfc_ch_cfg rtw8852b_hfc_chcfg_pcie[]',
            'static const struct rtw89_hfc_pub_cfg rtw8852b_hfc_pubcfg_pcie',
            'static const struct rtw89_hfc_param_ini rtw8852b_hfc_param_ini_pcie[]',
            'static const struct rtw89_hfc_ch_cfg rtw8852b_hfc_chcfg_usb[]',
            'static const struct rtw89_hfc_pub_cfg rtw8852b_hfc_pubcfg_usb',
            'static const struct rtw89_hfc_prec_cfg rtw8852b_hfc_preccfg_usb',
            'static const struct rtw89_hfc_param_ini rtw8852b_hfc_param_ini_usb[]',
            'static const struct rtw89_dle_mem rtw8852b_dle_mem_pcie[]',
            'static const struct rtw89_dle_mem rtw8852b_dle_mem_usb3[]',
            'static const struct rtw89_page_regs rtw8852b_page_regs',
            'static const struct rtw89_imr_info rtw8852b_imr_info',
            'static const struct rtw89_rrsr_cfgs rtw8852b_rrsr_cfgs']]
        + [table('rtw8852b.c', 'static const u32 rtw8852b_h2c_regs'),
           table('rtw8852b.c', 'static const u32 rtw8852b_c2h_regs')])

    mac_fields = ['band1_offset', 'default_rx_fltr', 'check_mac_en', 'sys_init', 'trx_init',
                  'hci_func_en', 'dmac_func_pre_en', 'dle_func_en', 'dle_clk_en',
                  'dle_mix_cfg', 'chk_dle_rdy', 'hfc_func_en', 'hfc_h2c_cfg', 'hfc_mix_cfg',
                  'hfc_get_mix_info', 'wde_quota_cfg', 'ple_quota_cfg', 'fwdl_preconfig',
                  'write_xtal_si']
    mac_def = members('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax',
                      mac_fields + ['preload_init'])
    if mac_def['preload_init'] != 'preload_init_set_ax':
        raise ValueError(f"rtw89_mac_gen_ax.preload_init is {mac_def['preload_init']}")
    info_fields = ['chip_id', 'chip_gen', 'bbmcu_nr', 'fifo_size', 'dle_scc_rsvd_size',
                   'qta_def', 'hci_func_en_addr', 'page_regs', 'dma_ch_mask', 'h2c_desc_size',
                   'imr_info', 'rrsr_cfgs', 'bacam_ver', 'h2c_ctrl_reg', 'h2c_counter_reg',
                   'h2c_regs', 'c2h_ctrl_reg', 'c2h_counter_reg', 'c2h_regs']
    info = members('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                   info_fields + ['mac_def', 'ops'])
    if info['mac_def'] != '&rtw89_mac_gen_ax' or info['ops'] != '&rtw8852b_chip_ops':
        raise ValueError(f"rtw8852b_chip_info.mac_def/ops are {info['mac_def']}/{info['ops']}")
    chip_ops = members('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                       ['enable_bb_rf', 'stop_sch_tx', 'resume_sch_tx'])
    if chip_ops != {'enable_bb_rf': 'rtw8852bx_mac_enable_bb_rf',
                    'stop_sch_tx': 'rtw89_mac_stop_sch_tx',
                    'resume_sch_tx': 'rtw89_mac_resume_sch_tx'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops}')
    bx = members('rtw8852b_common.c', 'const struct rtw8852bx_info rtw8852bx_info',
                 ['mac_enable_bb_rf'])
    if bx['mac_enable_bb_rf'] != '__rtw8852bx_mac_enable_bb_rf':
        raise ValueError(f'rtw8852bx_info is {bx}')
    pci_info = members('rtw8852be.c', 'static const struct rtw89_pci_info rtw8852b_pci_info',
                       ['gen_def', 'dma_stop1', 'dma_stop2', 'ltr_set'])
    if pci_info['gen_def'] != '&rtw89_pci_gen_ax':
        raise ValueError(f"rtw8852b_pci_info.gen_def is {pci_info['gen_def']}")
    pci_gen = members('pci.c', 'const struct rtw89_pci_gen_def rtw89_pci_gen_ax',
                      ['mac_pre_init', 'mac_post_init'])
    hci_ops = members('pci.c', 'static const struct rtw89_hci_ops rtw89_pci_ops',
                      ['mac_pre_init', 'mac_post_init'])
    if hci_ops != {'mac_pre_init': 'rtw89_pci_ops_mac_pre_init',
                   'mac_post_init': 'rtw89_pci_ops_mac_post_init'}:
        raise ValueError(f'rtw89_pci_ops is {hci_ops}')
    raw_io = members('fw.c', 'static const struct rtw89_io_ops rtw89_raw_io', ['pack', 'unpack'])
    if raw_io != {'pack': 'NULL', 'unpack': 'NULL'}:
        raise ValueError(f'rtw89_raw_io is {raw_io}')
    core = source('core.c')
    for line in ['\trtwdev->mac.qta_mode = RTW89_QTA_SCC;\n',
                 '\trtwdev->hal.rx_fltr = mac->default_rx_fltr;\n',
                 '\tINIT_LIST_HEAD(&rtwdev->early_h2c_list);\n',
                 '\trtwdev->io = rtw89_fw_cmd_ofld_alloc_and_get_io_ops(rtwdev);\n']:
        if line not in core:
            raise ValueError(f'core.c: rtw89_core_init no longer has {line.strip()}')
    if '\tif (!(rtwdev->hci.type == RTW89_HCI_TYPE_USB && chip->support_fw_cmd_ofld))\n' \
            '\t\treturn &rtw89_raw_io;\n' not in source('fw.c'):
        raise ValueError('fw.c: PCIe no longer takes rtw89_raw_io')

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define U16_MAX 0xffff
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_PREP_CONST(m, v) FIELD_PREP(m, v)
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_replace_bits(old, v, m) ((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, v))
#define u16_replace_bits(old, v, m) ((u16)u32_replace_bits(old, v, m))
#define u32p_replace_bits(p, v, m) (*(p) = u32_replace_bits(*(p), v, m))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define cpu_to_le32(v) ((__le32)(v))
#define WARN(c, ...) ((void)(c))
#define EXPORT_SYMBOL(...)
#define lockdep_assert_wiphy(w) ((void)0)
/* rtw89's log helpers are calls in the kernel: their arguments, register
 * reads among them, are evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound; a sleep before the first read counts
 * toward the bound. The atomic form is the same in the model. */
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
struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(l) ((l)->next = (l)->prev = (l))
#define list_for_each_entry(pos, head, member) \
	for (pos = (__typeof__(pos))((char *)(head)->next - offsetof(__typeof__(*pos), member)); \
	     &pos->member != (head); \
	     pos = (__typeof__(pos))((char *)pos->member.next - offsetof(__typeof__(*pos), member)))
#define test_bit(nr, addr) ((int)(((addr)[(nr) / 64] >> ((nr) % 64)) & 1))
'''
    harness = r'''
struct rtw89_dev;
struct sk_buff { u8 *head, *data; u32 len, size; };
struct rtw89_mac_gen_def {
	u32 band1_offset;
	u32 default_rx_fltr;
	int (*check_mac_en)(struct rtw89_dev *rtwdev, u8 band, enum rtw89_mac_hwmod_sel sel);
	int (*sys_init)(struct rtw89_dev *rtwdev);
	int (*trx_init)(struct rtw89_dev *rtwdev);
	int (*preload_init)(struct rtw89_dev *rtwdev, u8 mac_idx, enum rtw89_qta_mode mode);
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
	void (*wde_quota_cfg)(struct rtw89_dev *rtwdev, const struct rtw89_wde_quota *min_cfg,
			      const struct rtw89_wde_quota *max_cfg, u16 ext_wde_min_qt_wcpu);
	void (*ple_quota_cfg)(struct rtw89_dev *rtwdev, const struct rtw89_ple_quota *min_cfg,
			      const struct rtw89_ple_quota *max_cfg);
	void (*fwdl_preconfig)(struct rtw89_dev *rtwdev);
	int (*write_xtal_si)(struct rtw89_dev *rtwdev, u8 offset, u8 val, u8 mask);
};
struct rtw89_chip_ops { int (*enable_bb_rf)(struct rtw89_dev *rtwdev); };
struct rtw8852bx_info { int (*mac_enable_bb_rf)(struct rtw89_dev *rtwdev); };
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	u8 bbmcu_nr;
	u32 fifo_size;
	u32 dle_scc_rsvd_size;
	struct rtw89_qta_def qta_def;
	u32 hci_func_en_addr;
	const struct rtw89_page_regs *page_regs;
	u32 dma_ch_mask;
	u32 h2c_desc_size;
	const struct rtw89_imr_info *imr_info;
	const struct rtw89_rrsr_cfgs *rrsr_cfgs;
	enum rtw89_bacam_ver bacam_ver;
	u32 h2c_ctrl_reg;
	struct rtw89_reg_def h2c_counter_reg;
	const u32 *h2c_regs;
	u32 c2h_ctrl_reg;
	struct rtw89_reg_def c2h_counter_reg;
	const u32 *c2h_regs;
};
struct rtw89_chip_variant { const struct rtw89_qta_def *qta_def_override; };
struct rtw89_hci_ops {
	int (*mac_pre_init)(struct rtw89_dev *rtwdev);
	int (*mac_post_init)(struct rtw89_dev *rtwdev);
};
struct rtw89_io_ops {
	int (*pack)(struct rtw89_dev *rtwdev);
	int (*unpack)(struct rtw89_dev *rtwdev);
};
struct rtw89_pci_gen_def { int (*mac_post_init)(struct rtw89_dev *rtwdev); };
struct rtw89_pci_info {
	const struct rtw89_pci_gen_def *gen_def;
	struct rtw89_reg_def dma_stop1;
	struct rtw89_reg_def dma_stop2;
	int (*ltr_set)(struct rtw89_dev *rtwdev, bool en);
};
struct rtw89_mac_info {
	struct rtw89_dle_info dle_info;
	struct rtw89_hfc_param hfc_param;
	enum rtw89_qta_mode qta_mode;
};
struct rtw89_hal { u8 cv; u32 rx_fltr; };
struct rtw89_fw_info { u8 h2c_seq; u8 h2c_counter; u8 c2h_counter; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_chip_variant *variant;
	const struct rtw89_pci_info *pci_info;
	const struct rtw89_io_ops *io;
	struct {
		enum rtw89_hci_type type;
		enum rtw89_hci_dle_type dle_type;
		const struct rtw89_hci_ops *ops;
	} hci;
	struct rtw89_mac_info mac;
	struct rtw89_hal hal;
	struct rtw89_fw_info fw;
	struct list_head early_h2c_list;
	unsigned long flags[(NUM_OF_RTW89_FLAGS + 63) / 64];
	bool dbcc_en;
};

/* The register model: MAC space as bytes, behaving per aligned word. */
static u8 memory[0x10000];
static struct {
	int dmac_dead, cmac_dead, xtal_stuck, ss_stuck, cam_stuck, bacam_stuck, pub_short;
} fault;
static int reply;
static u32 reply_words[4];
static int h2c_refuse;
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
/* What the aligned word at w reads as. */
static u32 view(u32 w)
{
	u32 v = get(w, 4);
	switch (w) {
	case R_AX_WDE_INI_STATUS:
		return v | WDE_MGN_INI_RDY;
	case R_AX_PLE_INI_STATUS:
		return v | PLE_MGN_INI_RDY;
	case R_AX_DMAC_FUNC_EN:
		return fault.dmac_dead ? RTW89_R32_DEAD : v;
	case R_AX_CMAC_FUNC_EN:
		return fault.cmac_dead ? RTW89_R32_DEAD : v;
	case R_AX_SS_CTRL:
		return fault.ss_stuck ? v & ~B_AX_SS_INIT_DONE_1 : v | B_AX_SS_INIT_DONE_1;
	case R_AX_PUB_PAGE_INFO1:
		return v & ~(B_AX_G0_USE_PG_MASK | B_AX_G1_USE_PG_MASK);
	case R_AX_PUB_PAGE_INFO2: {
		u32 avail = u32_get_bits(get(R_AX_PUB_PAGE_CTRL2, 4), B_AX_PUBPG_ALL_MASK) -
			    (u32)fault.pub_short;
		return (v & ~B_AX_PUB_AVAL_PG_MASK) | FIELD_PREP(B_AX_PUB_AVAL_PG_MASK, avail);
	}
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
	if (w == R_AX_WLAN_XTAL_SI_CTRL && !fault.xtal_stuck)
		set(w, 4, s & ~B_AX_WL_XTAL_SI_CMD_POLL);
	if (w == R_AX_ADDR_CAM_CTRL && !fault.cam_stuck)
		set(w, 4, s & ~B_AX_ADDR_CAM_CLR);
	if (w == R_AX_RESPBA_CAM_CTRL && !fault.bacam_stuck)
		set(w, 4, s & ~B_AX_BACAM_RST_MASK);
	if (r == R_AX_H2CREG_CTRL && (v & B_AX_H2CREG_TRIGGER)) {
		set(R_AX_H2CREG_CTRL, n, 0);
		if (reply) {
			for (u32 i = 0; i < 4; i++)
				set(R_AX_C2HREG_DATA0 + 4 * i, 4, reply_words[i]);
			set(R_AX_C2HREG_CTRL, 1, 1);
		}
	}
}
/* PCIe reaches the registers through rtw89_raw_io and rtw89_pci_ops; these
 * stand for both, below the CMAC read retry. */
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

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

/* rtw89_h2c_tx, the boundary to the PCIe rings the H2C oracle covers: the
 * skb's bytes and the sequence after its header (40, then 41 per word),
 * then taken or refused with -ENOSPC as the case says. */
static int rtw89_h2c_tx(struct rtw89_dev *d, struct sk_buff *skb, bool fwdl)
{
	record(40, skb->len, d->fw.h2c_seq | (u32)fwdl << 8);
	for (u32 k = 0; k < (skb->len + 3) / 4; k++) {
		u32 v = 0;
		for (u32 b = 0; b < 4 && 4 * k + b < skb->len; b++)
			v |= (u32)skb->data[4 * k + b] << (8 * b);
		record(41, k, v);
	}
	if (h2c_refuse)
		return -ENOSPC;
	dev_kfree_skb_any(skb);
	return 0;
}

/* Callees outside this slice. The PCIe pre-init, the firmware download and
 * the power-off note that they were reached (12, 13, 30); the rest abort if
 * reached: no BB preinit without BB MCU, no preload on an RTL885xB, no DBCC
 * with the SCC quota, no BA CAM users with RTW89_BACAM_V0, no early H2C. The
 * platform left LTR disabled in DEVCTL2. */
static void rtw89_chip_bb_preinit(struct rtw89_dev *d) { (void)d; abort(); }
static int harness_mac_pre_init(struct rtw89_dev *d) { (void)d; record(12, 0, 0); return 0; }
static int rtw89_fw_download(struct rtw89_dev *d, enum rtw89_fw_type type, bool include_bb)
{
	(void)d;
	record(13, type, include_bb);
	return 0;
}
static void rtw89_mac_pwr_off(struct rtw89_dev *d) { (void)d; record(30, 0, 0); }
static int harness_preload_init(struct rtw89_dev *d, u8 mac_idx, enum rtw89_qta_mode mode)
{
	(void)d; (void)mac_idx; (void)mode;
	abort();
}
static int dbcc_enable_ax(struct rtw89_dev *d, bool enable) { (void)d; (void)enable; abort(); }
static int rtw89_fw_h2c_init_ba_cam_users(struct rtw89_dev *d, u8 users, u8 offset, u8 mac_idx)
{
	(void)d; (void)users; (void)offset; (void)mac_idx;
	abort();
}
static int rtw89_fw_h2c_raw(struct rtw89_dev *d, const u8 *buf, u16 len)
{
	(void)d; (void)buf; (void)len;
	abort();
}
static bool rtw89_pci_dev_ltr_enabled(struct rtw89_dev *d) { (void)d; return false; }
'''
    tables = (
        'static const struct rtw89_mac_gen_def mac_gen_ax = {\n'
        + ''.join(f'\t.{name} = {mac_def[name]},\n' for name in mac_fields)
        + '\t.preload_init = harness_preload_init,\n};\n'
        + bb_rf + '\n\n'
        + 'static const struct rtw8852bx_info rtw8852bx_info = {\n'
        + f"\t.mac_enable_bb_rf = {bx['mac_enable_bb_rf']},\n}};\n\n"
        + bb_rf_inline + '\n\n'
        + 'static const struct rtw89_chip_ops chip_ops = {\n'
        + f"\t.enable_bb_rf = {chip_ops['enable_bb_rf']},\n}};\n"
        + 'static const struct rtw89_chip_info chip_info = {\n'
        + '\t.mac_def = &mac_gen_ax,\n\t.ops = &chip_ops,\n'
        + ''.join(f'\t.{name} = {info[name]},\n' for name in info_fields)
        + '};\nstatic const struct rtw89_pci_gen_def pci_gen_ax = {\n'
        + f"\t.mac_post_init = {pci_gen['mac_post_init']},\n}};\n"
        + 'static const struct rtw89_pci_info pci_info = {\n\t.gen_def = &pci_gen_ax,\n'
        + ''.join(f'\t.{name} = {pci_info[name]},\n' for name in ['dma_stop1', 'dma_stop2', 'ltr_set'])
        + '};\nstatic const struct rtw89_hci_ops hci_ops = {\n'
        + '\t.mac_pre_init = harness_mac_pre_init,\n'
        + f"\t.mac_post_init = {hci_ops['mac_post_init']},\n}};\n"
        + 'static const struct rtw89_io_ops raw_io = {\n'
        + f"\t.pack = {raw_io['pack']},\n\t.unpack = {raw_io['unpack']},\n}};\n")
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
	const struct rtw89_dle_info *i = &dev->mac.dle_info;
	record(14, i->qta_mode, i->ple_pg_size | (u32)i->ple_free_pg << 16);
	record(15, i->c0_rx_qta, i->c1_rx_qta);
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
	for (u32 ch = 0; ch < RTW89_DMA_CH_NUM; ch++)
		record(21, ch, p->ch_info[ch].aval | (u32)p->ch_info[ch].used << 16);
	const struct rtw89_hfc_pub_info *pi = &p->pub_info;
	record(22, pi->g0_used | (u32)pi->g1_used << 16, pi->g0_aval | (u32)pi->g1_aval << 16);
	record(23, pi->pub_aval | (u32)pi->wp_aval << 16, 0);
}
enum kind { MAC_INIT, STOP_SCH, RESUME_SCH };
enum fill { PATTERN, ONES, ZEROS };
int main(int argc, char **argv)
{
	static const struct {
		enum kind kind;
		enum fill fill;
		int dmac_dead, cmac_dead, xtal_stuck, ss_stuck, cam_stuck, bacam_stuck, pub_short;
		int h2c_refuse;
		int fw_rdy;
		u8 reply_id;
		int cmac_on;
		enum rtw89_sch_tx_sel sel;
		u16 tx_en;
	} cases[] = {
		{MAC_INIT, PATTERN},
		{MAC_INIT, ONES},
		{MAC_INIT, ZEROS},
		{MAC_INIT, PATTERN, .xtal_stuck = 1},
		{MAC_INIT, PATTERN, .ss_stuck = 1},
		{MAC_INIT, PATTERN, .cam_stuck = 1},
		{MAC_INIT, PATTERN, .bacam_stuck = 1},
		{MAC_INIT, PATTERN, .pub_short = 1},
		{MAC_INIT, PATTERN, .cmac_dead = 1},
		{MAC_INIT, PATTERN, .h2c_refuse = 1},
		{MAC_INIT, PATTERN, .dmac_dead = 1},
		{STOP_SCH, PATTERN, .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_ALL},
		{STOP_SCH, PATTERN, .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_HIQ},
		{STOP_SCH, PATTERN, .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_MG0},
		{STOP_SCH, PATTERN, .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_MACID},
		{STOP_SCH, ONES, .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_ALL},
		{RESUME_SCH, PATTERN, .cmac_on = 1, .tx_en = 0x1234},
		{STOP_SCH, PATTERN, .fw_rdy = 1, .reply_id = RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT,
		 .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_ALL},
		{STOP_SCH, ONES, .fw_rdy = 1, .reply_id = RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT,
		 .cmac_on = 1, .sel = RTW89_SCH_TX_SEL_MG0},
		{RESUME_SCH, PATTERN, .fw_rdy = 1, .reply_id = RTW89_FWCMD_C2HREG_FUNC_TX_PAUSE_RPT,
		 .cmac_on = 1, .tx_en = 0xbeef},
		{STOP_SCH, PATTERN, .fw_rdy = 1, .reply_id = 0, .cmac_on = 1,
		 .sel = RTW89_SCH_TX_SEL_HIQ},
		{STOP_SCH, PATTERN, .cmac_on = 0, .sel = RTW89_SCH_TX_SEL_ALL},
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
		fault.dmac_dead = cases[c].dmac_dead;
		fault.cmac_dead = cases[c].cmac_dead;
		fault.xtal_stuck = cases[c].xtal_stuck;
		fault.ss_stuck = cases[c].ss_stuck;
		fault.cam_stuck = cases[c].cam_stuck;
		fault.bacam_stuck = cases[c].bacam_stuck;
		fault.pub_short = cases[c].pub_short;
		h2c_refuse = cases[c].h2c_refuse;
		reply = 0;
		dev.chip = &chip_info;
		dev.variant = NULL;
		dev.pci_info = &pci_info;
		dev.io = &raw_io;
		dev.hci.type = RTW89_HCI_TYPE_PCIE;
		dev.hci.dle_type = RTW89_HCI_DLE_TYPE_PCIE;
		dev.hci.ops = &hci_ops;
		dev.mac.qta_mode = RTW89_QTA_SCC;
		dev.hal.rx_fltr = mac_gen_ax.default_rx_fltr;
		INIT_LIST_HEAD(&dev.early_h2c_list);
		int ret;
		if (cases[c].kind == MAC_INIT) {
			ret = rtw89_mac_init(&dev);
			record(11, 0, (u32)ret);
			if (!ret)
				record_state(&dev);
			record(24, dev.fw.h2c_seq, 0);
		} else {
			memory[R_AX_H2CREG_CTRL] = 0;
			memory[R_AX_C2HREG_CTRL] = 0;
			u32 cmac = get(R_AX_CMAC_FUNC_EN, 4);
			set(R_AX_CMAC_FUNC_EN, 4, cases[c].cmac_on ? cmac | B_AX_CMAC_EN :
								    cmac & ~B_AX_CMAC_EN);
			if (cases[c].fw_rdy) {
				dev.flags[RTW89_FLAG_FW_RDY / 64] |= 1UL << (RTW89_FLAG_FW_RDY % 64);
				reply = 1;
				reply_words[0] = FIELD_PREP(RTW89_C2HREG_HDR_FUNC_MASK, cases[c].reply_id) |
						 FIELD_PREP(RTW89_C2HREG_HDR_LEN_MASK, 2);
				reply_words[1] = 0x11112222;
				reply_words[2] = 0x33334444;
				reply_words[3] = 0x55556666;
			}
			u32 tx_en = 0;
			if (cases[c].kind == STOP_SCH)
				ret = rtw89_mac_stop_sch_tx(&dev, RTW89_MAC_0, &tx_en, cases[c].sel);
			else
				ret = rtw89_mac_resume_sch_tx(&dev, RTW89_MAC_0, cases[c].tx_en);
			record(11, 0, (u32)ret);
			if (!ret && cases[c].kind == STOP_SCH)
				record(25, tx_en, 0);
			record(26, dev.fw.h2c_counter, dev.fw.c2h_counter);
		}
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
        preamble, reg_h, core_defines, mac_defines, fw_defines, pci_defines, declarations,
        harness,
        helpers, fw, mac, pci, mac_size, chip_tables, tables, main_c])
    generated = out / 'init_oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'init_oracle'
    # rtw89 fills the packed H2CREG words through u32p_replace_bits, whose
    # pointer clang warns may be unaligned; the harness's are aligned.
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member',
                    str(generated), '-o', str(exe)], check=True)
    trace = out / 'init_trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    data = trace.read_bytes()
    return dict(
        symbols=manifest, cases=int(run.stdout.strip()),
        case_order='rtw89_mac_init over patterned/all-ones/zeroed memory, XTAL SI stuck, '
                   'STA scheduler stuck, address CAM stuck, BA CAM stuck, one public page '
                   'short, CMAC_FUNC_EN dead, rtw89_h2c_tx refused, DMAC_FUNC_EN dead; '
                   'rtw89_mac_stop_sch_tx without firmware for ALL/HIQ/MG0/MACID over '
                   'patterned memory and ALL over all-ones; rtw89_mac_resume_sch_tx(0x1234) '
                   'without firmware; with FW_RDY and TX_PAUSE_RPT: stop ALL, stop MG0 over '
                   'all-ones, resume 0xbeef; stop HIQ answered by function 0; stop ALL with '
                   'CMAC_EN clear',
        dispatch=dict(rtw89_mac_gen_ax=mac_def, rtw8852b_chip_info=info,
                      rtw8852b_chip_ops=chip_ops, rtw8852bx_info=bx,
                      rtw8852b_pci_info=pci_info, rtw89_pci_gen_ax=pci_gen,
                      rtw89_pci_ops=hci_ops, rtw89_raw_io=raw_io,
                      rtw89_core_init='mac.qta_mode = RTW89_QTA_SCC; '
                                      'hal.rx_fltr = mac->default_rx_fltr; empty early_h2c_list'),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, delays and the chip answers are a model; no physical evidence',
            'read_poll_timeout and its atomic form are modeled counted in steps',
            'register reads go straight to the model, below rtw89_pci_ops\' CMAC read retry',
            'rtw89_h2c_tx is a stub recording the skb; the CH12 path is the H2C oracle\'s',
            'hci.ops->mac_pre_init, rtw89_fw_download and rtw89_mac_pwr_off are stubs that '
            'note they were reached; DEVCTL2 reads LTR disabled, so rtw89_pci_ltr_set '
            'returns at once; BB preinit, preload, DBCC, BA CAM users and early H2C abort '
            'if reached',
            'one firmware answer per mailbox exchange; a C2H that never comes is not run '
            '(its poll is 10^6 steps)',
        ])


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
