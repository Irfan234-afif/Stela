#!/usr/bin/env python3
"""Unchanged pinned rtw89 PCIe pre-init and rings for an RTL8852BE, with a register model.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. rtw89_pci_ops_mac_pre_init_ax with every
callee it reaches (the MDIO, DBI and configuration helpers, the PCIe settings,
rtw89_pci_ctrl_dma_all, the idle polls, rtw89_pci_mode_op, rtw89_pci_ops_reset
with rtw89_pci_reset_trx_rings, the BD RAM reset and the TX channel stops),
rtw89_pci_alloc_trx_rings with every allocation callee and the matching frees,
the RX info and tag functions, the BD index arithmetic,
rtw89_pci_fwcmd_submit and rtw89_pci_release_fwcmd, the pci.h inlines and
declarations they use, the register and enum definitions of pci.h, reg.h,
core.h and txrx.h, rtw89_pci_ch_dma_addr_set and rtw89_bd_ram_table_single are
extracted unchanged, each with its SHA-256 in manifest.json. rtw8852b_pci_info
(rtw8852be.c), rtw8852b_chip_info and rtw89_pci_gen_ax give the values the
harness's tables take, member by member. Everything is compiled with clang
under ASan and UBSan against a harness that models:

- MAC registers as bytes. MDIO_CFG performs a set RFLAG or WFLAG on the PHY
  register file (four pages of 32 16-bit registers) and clears it, unless
  MDIO is stuck for every address or for one; the DBI flag byte copies a
  dword of configuration space to DBI_RDATA or writes the enabled bytes of
  DBI_WDATA into it and clears, unless DBI is stuck; PCIE_DMA_BUSY1 reads
  idle unless a TX or RX channel is held busy; INIT_CFG1 drops RST_BDRAM as
  it is written unless the BD RAM reset is stuck.
- Configuration space as 4096 bytes behind pci_read_config_byte and
  pci_write_config_byte, which can fail every access.
- DMA with fixed addresses: the TX BD pool at 0xfffe0000, the RX BD pool at
  0xfffd0000, WD pages from 0x40000000 (never programmed), and the RX buffers
  from 0x80000000, 0x3000 apart in allocation order.

rtw89_pci_release_tx_ring, which releases the data channels' WD pages, is a
stub that checks their busy list is empty; rtw89_chip_fill_txdesc_fwcmd is a
stub that leaves the TXWD body zeroed; RTW89_PCI_TX_SKB_CB is the harness's,
the skb's control buffer.

Segments, each prefixed by its byte length, of records of three
little-endian u32 (tag, register, value): reads are tagged by width, writes
by 4 plus width, delays 9, configuration reads 21 (23 refused) and writes 22
(24 refused), the return 11. Cases:

- 17 times rtw89_pci_alloc_trx_rings then hci.ops->mac_pre_init (dispatched
  through rtw89_pci_gen_ax) over the register, configuration and PHY models
  of the case; a case that returns 0 then records every ring (tags 30 to 36,
  TX channels then RX) and the command queues' lengths (37).
- rtw89_pci_alloc_trx_rings alone: every ring, then every RX BD (40, 41).
- rtw89_pci_sync_skb_for_device_and_validate_rx_info over eight info dwords
  and targets, with check_rx_tag as rtw8852b_pci_info has it and true: the
  return and new target (50), the decoded info (51), the syncs (52).
- rtw89_pci_txbd_recalc and rtw89_pci_rxbd_recalc: the index read, then the
  count and new rp (53).
- rtw89_pci_get_avail_txbd_num, rtw89_pci_tx_bd_ring_update and
  rtw89_pci_rxbd_increase (54 to 56).
- rtw89_pci_fwcmd_submit on CH12: the return and wp (70), the BD (71), the
  skb's length and the queue's (72).
- rtw89_pci_release_fwcmd: each unmap (60), then both queues' lengths (61).
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

    def function(file, name):
        return locate(file, name)[1]

    def in_order(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        found = sorted(locate(file, name) for name in names)
        return '\n\n'.join(body for _, body in found)

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

    def macro(file, name):
        """A #define with its continuation lines."""
        text = source(file)
        found = list(re.finditer(r'^#define ' + re.escape(name) + r'\(', text, re.M))
        if len(found) != 1:
            raise ValueError(f'{file}: #define {name}( appears {len(found)} times')
        start = end = found[0].start()
        while True:
            line_end = text.index('\n', end)
            if not text[line_end - 1] == '\\':
                break
            end = line_end + 1
        return record(file, f'#define {name}', text[start:line_end])

    def lines_from_to(file, first, before):
        """The lines from the one starting with first up to the one starting with before."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n' + before, start) + 1
        return record(file, f'{first.split()[1]} to {before}', text[start:end])

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
    pci_h_defines = lines_from_to('pci.h', '#define MDIO_PG0_G1', 'struct rtw89_pci_isrs;')
    core_defines = defines('core.h', ['MASKBYTE0', 'MASKBYTE1', 'MASKBYTE2', 'MASKBYTE3'])
    rxbd_defines = defines('pci.h', ['RTW89_PCI_RXBD_FS', 'RTW89_PCI_RXBD_LS',
                                     'RTW89_PCI_RXBD_WRITE_SIZE', 'RTW89_PCI_RXBD_TAG'])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_cv'),
        declaration('core.h', 'enum', 'rtw89_quirks'),
        declaration('core.h', 'struct', 'rtw89_reg_def'),
        declaration('core.h', 'struct', 'rtw89_txwd_body'),
        declaration('txrx.h', 'enum', 'rtw89_tx_channel'),
        declaration('txrx.h', 'enum', 'rtw89_rx_channel'),
        declaration('pci.h', 'struct', 'rtw89_pci_ch_dma_addr'),
        declaration('pci.h', 'struct', 'rtw89_pci_ch_dma_addr_set'),
        declaration('pci.h', 'struct', 'rtw89_pci_bd_ram'),
        declaration('pci.h', 'struct', 'rtw89_pci_gen_def'),
        declaration('pci.h', 'struct', 'rtw89_pci_info'),
        declaration('pci.h', 'struct', 'rtw89_pci_tx_data'),
        declaration('pci.h', 'struct', 'rtw89_pci_rx_info'),
        declaration('pci.h', 'struct', 'rtw89_pci_tx_bd_32'),
        declaration('pci.h', 'struct', 'rtw89_pci_rx_bd_32'),
        declaration('pci.h', 'struct', 'rtw89_pci_rxbd_info'),
        declaration('pci.h', 'struct', 'rtw89_pci_tx_wd'),
        declaration('pci.h', 'struct', 'rtw89_pci_dma_ring'),
        declaration('pci.h', 'struct', 'rtw89_pci_dma_pool'),
        declaration('pci.h', 'struct', 'rtw89_pci_tx_wd_ring'),
        declaration('pci.h', 'struct', 'rtw89_pci_tx_ring'),
        declaration('pci.h', 'struct', 'rtw89_pci_tx_rings'),
        declaration('pci.h', 'struct', 'rtw89_pci_rx_ring'),
        declaration('pci.h', 'struct', 'rtw89_pci_rx_rings'),
        declaration('pci.h', 'struct', 'rtw89_pci'),
    ])
    core_helpers = '\n\n'.join(function('core.h', name) for name in [
        'rtw89_write16_set', 'rtw89_write16_clr', 'rtw89_write32_set', 'rtw89_write32_clr',
        'rtw89_write32_mask', 'rtw89_is_rtl885xb'])
    pci_h_inlines = in_order('pci.h', [
        'rtw89_pci_rxbd_increase', 'RTW89_PCI_RX_SKB_CB', 'RTW89_PCI_RX_BD',
        'rtw89_pci_get_next_txbd', 'rtw89_pci_enqueue_txwd', 'rtw89_pci_ops_mac_pre_init',
        'rtw89_pci_clr_idx_all'])
    dma_addr_set = '\n\n'.join(
        [macro('pci.c', name) for name in ['DEF_TXCHADDRS_TYPE1', 'DEF_TXCHADDRS', 'DEF_RXCHADDRS']]
        + [definition('pci.c', head) for head in [
            'const struct rtw89_pci_ch_dma_addr_set rtw89_pci_ch_dma_addr_set',
            'const struct rtw89_pci_bd_ram rtw89_bd_ram_table_single[RTW89_TXCH_NUM]']])
    pci_c = in_order('pci.c', [
        'rtw89_pci_rst_bdram_ax', 'rtw89_pci_dma_recalc', 'rtw89_pci_txbd_recalc',
        'rtw89_pci_release_fwcmd', 'rtw89_pci_rxbd_recalc', 'rtw89_pci_sync_skb_for_cpu',
        'rtw89_pci_rxbd_info_update', 'rtw89_pci_validate_rx_tag',
        'rtw89_pci_sync_skb_for_device_and_validate_rx_info', 'rtw89_pci_ctrl_txdma_ch_ax',
        'rtw89_pci_ctrl_txdma_fw_ch_ax', 'rtw89_pci_get_txch_addrs', 'rtw89_pci_get_rxch_addrs',
        'rtw89_pci_get_avail_txbd_num', 'rtw89_pci_tx_bd_ring_update', 'rtw89_pci_fwcmd_submit',
        'rtw89_pci_init_wp_16sel', 'rtw89_pci_enc_bd_cfg', 'rtw89_pci_reset_trx_rings',
        'rtw89_pci_ops_reset', 'rtw89_pci_ctrl_dma_trx', 'rtw89_pci_ctrl_dma_io',
        'rtw89_pci_ctrl_dma_all', 'rtw89_pci_check_mdio', 'rtw89_read16_mdio', 'rtw89_write16_mdio',
        'rtw89_write16_mdio_mask', 'rtw89_write16_mdio_set', 'rtw89_write16_mdio_clr',
        'rtw89_dbi_write8', 'rtw89_dbi_read8', 'rtw89_pci_write_config_byte',
        'rtw89_pci_read_config_byte', '__get_target', 'rtw89_pci_autok_x',
        'rtw89_pci_auto_refclk_cal', 'rtw89_pci_deglitch_setting', 'rtw89_pci_ber',
        'rtw89_pci_rxdma_prefth', 'rtw89_pci_l1off_pwroff', 'rtw89_pci_l2_rxen_lat',
        'rtw89_pci_aphy_pwrcut', 'rtw89_pci_hci_ldo', 'rtw89_pci_dphy_delay',
        'rtw89_pci_power_wake_ax', 'rtw89_pci_autoload_hang', 'rtw89_pci_l12_vmain',
        'rtw89_pci_gen2_force_ib', 'rtw89_pci_l1_ent_lat', 'rtw89_pci_wd_exit_l1',
        'rtw89_pci_set_sic', 'rtw89_pci_set_lbc', 'rtw89_pci_set_io_rcy', 'rtw89_pci_set_dbg',
        'rtw89_pci_set_keep_reg', 'rtw89_pci_clr_idx_all_ax', 'rtw89_pci_poll_txdma_ch_idle_ax',
        'rtw89_pci_poll_rxdma_ch_idle_ax', 'rtw89_pci_poll_dma_all_idle', 'rtw89_pci_mode_op',
        'rtw89_pci_ops_mac_pre_init_ax', 'rtw89_pci_free_tx_wd_ring', 'rtw89_pci_free_tx_ring',
        'rtw89_pci_free_tx_rings', 'rtw89_pci_free_rx_ring', 'rtw89_pci_free_rx_rings',
        'rtw89_pci_free_trx_rings', 'rtw89_pci_init_rx_bd', 'rtw89_pci_alloc_tx_wd_ring',
        'rtw89_pci_alloc_tx_ring', 'rtw89_pci_alloc_tx_rings', 'rtw89_pci_alloc_rx_ring',
        'rtw89_pci_alloc_rx_rings', 'rtw89_pci_alloc_trx_rings'])

    gen_fields = ['mac_pre_init', 'clr_idx_all', 'rst_bdram', 'ctrl_txdma_ch',
                  'ctrl_txdma_fw_ch', 'poll_txdma_ch_idle', 'power_wake']
    gen_def = fields('pci.c', 'const struct rtw89_pci_gen_def rtw89_pci_gen_ax', gen_fields)
    pci_fields = ['gen_def', 'txbd_trunc_mode', 'rxbd_trunc_mode', 'rxbd_mode', 'tag_mode',
                  'tx_burst', 'rx_burst', 'wd_dma_idle_intvl', 'wd_dma_act_intvl',
                  'multi_tag_num', 'lbc_en', 'lbc_tmr', 'autok_en', 'io_rcy_en', 'io_rcy_tmr',
                  'rx_ring_eq_is_full', 'check_rx_tag', 'no_rxbd_fs', 'group_bd_addr',
                  'init_cfg_reg', 'txhci_en_bit', 'rxhci_en_bit', 'rxbd_mode_bit',
                  'exp_ctrl_reg', 'max_tag_num_mask', 'rxbd_rwptr_clr_reg',
                  'txbd_rwptr_clr2_reg', 'dma_io_stop', 'dma_stop1', 'dma_stop2', 'dma_busy1',
                  'dma_busy2_reg', 'dma_busy3_reg', 'rpwm_addr', 'cpwm_addr', 'mit_addr',
                  'wp_sel_addr', 'tx_dma_ch_mask', 'dma_addr_set', 'bd_ram_table',
                  'ssid_quirks']
    pci_info = fields('rtw8852be.c', 'static const struct rtw89_pci_info rtw8852b_pci_info',
                      pci_fields)
    for name, expected in [('gen_def', '&rtw89_pci_gen_ax'),
                           ('dma_addr_set', '&rtw89_pci_ch_dma_addr_set'),
                           ('bd_ram_table', '&rtw89_bd_ram_table_single'),
                           ('ssid_quirks', 'NULL')]:
        if pci_info[name] != expected:
            raise ValueError(f'rtw8852b_pci_info.{name} is {pci_info[name]}')
    driver = fields('rtw8852be.c', 'static const struct rtw89_driver_info rtw89_8852be_info',
                    ['chip', 'quirks', 'dev_id_quirks'])
    if driver != {'chip': '&rtw8852b_chip_info', 'quirks': 'NULL', 'dev_id_quirks': '0'}:
        raise ValueError(f'rtw89_8852be_info is {driver}')
    chip_fields = ['chip_id', 'h2c_desc_size', 'default_quirks']
    chip = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info', chip_fields)
    if chip['default_quirks'] != '0':
        raise ValueError(f"rtw8852b_chip_info.default_quirks is {chip['default_quirks']}")
    pci_ops = fields('pci.c', 'static const struct rtw89_hci_ops rtw89_pci_ops',
                     ['mac_pre_init', 'reset'])
    if pci_ops != {'mac_pre_init': 'rtw89_pci_ops_mac_pre_init', 'reset': 'rtw89_pci_ops_reset'}:
        raise ValueError(f'rtw89_pci_ops is {pci_ops}')

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t dma_addr_t;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __packed __attribute__((packed))
#define __iomem
#define __maybe_unused __attribute__((unused))
#define unlikely(x) (x)
#define EXPORT_SYMBOL(...)
#define WARN(c, ...) ((void)(c))
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_replace_bits(old, v, m) ((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, v))
#define u16_encode_bits(v, m) ((u16)FIELD_PREP(m, (u16)(v)))
#define u16_replace_bits(old, v, m) ((u16)((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, (u16)(v))))
#define le16_encode_bits(v, m) ((__le16)FIELD_PREP(m, (u16)(v)))
#define le32_get_bits(v, m) u32_get_bits(v, m)
#define cpu_to_le16(v) ((__le16)(v))
#define cpu_to_le32(v) ((__le32)(v))
#define upper_32_bits(n) ((u32)(((u64)(n)) >> 32))
#define ilog2(n) (31 - __builtin_clz(n))
#define hweight16(x) __builtin_popcount((u16)(x))
#define hweight32(x) __builtin_popcount((u32)(x))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define RTW89_DBG_HCI BIT(6)
#define RTW89_DBG_UNEXP BIT(31)
/* rtw89's log helpers are calls in the kernel: their arguments, register
 * reads among them, are evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
static void model_delay(u64 us);
/* read_poll_timeout counted in steps: a read every step until the condition
 * holds, and one read past the bound; a sleep before the first read counts
 * toward the bound. The atomic form only busy-waits instead. */
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

/* Kernel types the declarations name. */
struct list_head { struct list_head *next, *prev; };
static void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static int list_empty(const struct list_head *l) { return l->next == l; }
static void list_add_tail(struct list_head *n, struct list_head *h)
{
	n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n;
}
struct sk_buff {
	struct sk_buff *next, *prev;
	u8 *head, *data;
	u32 len;
	u8 cb[48] __attribute__((aligned(8)));
};
struct sk_buff_head { struct sk_buff *next, *prev; u32 qlen; };
typedef struct { int unused; } spinlock_t;
#define spin_lock_bh(l) ((void)(l))
#define spin_unlock_bh(l) ((void)(l))
struct device { int unused; };
struct pci_dev { struct device dev; };
/* Only the member rtw89_pci_reset_trx_rings and the allocation clear. */
struct rtw89_rx_desc_info { bool ready; };
struct rtw89_dev;
struct rtw89_pci;
struct rtw89_pci_isrs;
struct rtw89_pci_rpp_info;
struct rtw89_pci_isr_def;
struct rtw89_pci_ssid_quirk;
struct rtw89_pci_bd_idx_addr;
'''
    harness = r'''
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	u32 h2c_desc_size;
	unsigned long default_quirks;
};
struct rtw89_hal { u8 cv; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_pci_info *pci_info;
	struct rtw89_hal hal;
	unsigned long quirks[1];
	struct device *dev;
	u8 priv[] __attribute__((aligned(8)));
};
struct rtw89_tx_desc_info { int unused; };
struct rtw89_core_tx_request { struct sk_buff *skb; struct rtw89_tx_desc_info desc_info; };
static int test_bit(int nr, const unsigned long *map) { return (map[nr / 64] >> (nr % 64)) & 1; }

/* The trace. */
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

/* The register model. */
static u8 memory[0x10000];
static u8 config[0x1000];
static u16 mdio[4][32];
static int config_fails, dbi_stuck, mdio_stuck, tx_busy, rx_busy, bdram_stuck;
static u32 get(u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)memory[r + i] << (8 * i); return v; }
static void set(u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) memory[r + i] = v >> (8 * i); }
static int overlaps(u32 r, u32 n, u32 at, u32 bytes) { return r < at + bytes && at < r + n; }
static void check(u32 r, u32 n)
{
	if (r + n > sizeof(memory))
		abort();
	if ((overlaps(r, n, R_AX_PCIE_INIT_CFG1, 4) || overlaps(r, n, R_AX_PCIE_DMA_BUSY1, 4)) &&
	    (n != 4 || (r & 3)))
		abort();
}
static void mdio_update(void)
{
	u32 cfg = get(R_AX_MDIO_CFG, 2);
	u32 addr = cfg & 0x1f, page = (cfg >> 12) & 3;
	if (mdio_stuck == 0x20 || mdio_stuck == (int)addr)
		return;
	if (cfg & B_AX_MDIO_RFLAG) {
		set(R_AX_MDIO_RDATA, 2, mdio[page][addr]);
		cfg &= ~B_AX_MDIO_RFLAG;
	}
	if (cfg & B_AX_MDIO_WFLAG) {
		mdio[page][addr] = get(R_AX_MDIO_WDATA, 2);
		cfg &= ~B_AX_MDIO_WFLAG;
	}
	set(R_AX_MDIO_CFG, 2, cfg);
}
static void dbi_update(void)
{
	u32 flag = memory[R_AX_DBI_FLAG + 2];
	u32 ctrl = get(R_AX_DBI_FLAG, 2);
	u32 at = ctrl & B_AX_DBI_ADDR_MSK;
	if (dbi_stuck || !(flag & 3))
		return;
	if (flag & (B_AX_DBI_RFLAG >> 16))
		for (u32 i = 0; i < 4; i++)
			memory[R_AX_DBI_RDATA + i] = config[at + i];
	if (flag & (B_AX_DBI_WFLAG >> 16))
		for (u32 i = 0; i < 4; i++)
			if (ctrl & (BIT(i) << 12))
				config[at + i] = memory[R_AX_DBI_WDATA + i];
	memory[R_AX_DBI_FLAG + 2] = 0;
}
static u32 model_read(u32 r, u32 n)
{
	check(r, n);
	u32 v = get(r, n);
	if (r == R_AX_PCIE_DMA_BUSY1) {
		v &= ~(DMA_BUSY1_CHECK_V1 | B_AX_RXQ_BUSY | B_AX_RPQ_BUSY);
		if (tx_busy)
			v |= B_AX_ACH0_BUSY;
		if (rx_busy)
			v |= B_AX_RXQ_BUSY;
	}
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	check(r, n);
	record(4 + n, r, v);
	if (r == R_AX_PCIE_INIT_CFG1 && !bdram_stuck)
		v &= ~B_AX_RST_BDRAM;
	set(r, n, v);
	if (overlaps(r, n, R_AX_MDIO_CFG, 2))
		mdio_update();
	if (overlaps(r, n, R_AX_DBI_FLAG + 2, 1))
		dbi_update();
}
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }

/* Configuration space: Linux leaves all ones and returns a PCIBIOS code on
 * a failed access. */
static int pci_read_config_byte(const struct pci_dev *p, int where, u8 *val)
{
	(void)p;
	if (where < 0 || where >= (int)sizeof(config))
		abort();
	if (config_fails) {
		record(23, where, 0);
		*val = 0xff;
		return 0x86;
	}
	*val = config[where];
	record(21, where, *val);
	return 0;
}
static int pci_write_config_byte(const struct pci_dev *p, int where, u8 val)
{
	(void)p;
	if (where < 0 || where >= (int)sizeof(config))
		abort();
	if (config_fails) {
		record(24, where, val);
		return 0x86;
	}
	config[where] = val;
	record(22, where, val);
	return 0;
}

/* DMA with fixed addresses. */
#define GFP_KERNEL 0
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define TX_POOL_DMA 0xfffe0000ULL
#define RX_POOL_DMA 0xfffd0000ULL
#define WD_DMA 0x40000000ULL
#define RX_BUF_DMA 0x80000000ULL
static u32 wd_allocations, maps, syncs_for_cpu;
static dma_addr_t map_override;
static int record_unmaps;
static void *dma_alloc_coherent(struct device *d, size_t size, dma_addr_t *dma, int gfp)
{
	(void)d; (void)gfp;
	void *head = calloc(1, size);
	if (!head)
		abort();
	if (size == 7 * RTW89_PCI_TXBD_NUM_MAX * sizeof(struct rtw89_pci_tx_bd_32))
		*dma = TX_POOL_DMA;
	else if (size == RTW89_RXCH_NUM * RTW89_PCI_RXBD_NUM_MAX * sizeof(struct rtw89_pci_rx_bd_32))
		*dma = RX_POOL_DMA;
	else
		*dma = WD_DMA + 0x10000ULL * wd_allocations++;
	return head;
}
static void dma_free_coherent(struct device *d, size_t size, void *head, dma_addr_t dma)
{
	(void)d; (void)size; (void)dma;
	free(head);
}
static dma_addr_t dma_map_single(struct device *d, void *p, size_t size, int dir)
{
	(void)d; (void)p; (void)size; (void)dir;
	return map_override ? map_override : RX_BUF_DMA + 0x3000ULL * maps++;
}
static int dma_mapping_error(struct device *d, dma_addr_t a) { (void)d; (void)a; return 0; }
static void dma_unmap_single(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d; (void)dir;
	if (record_unmaps)
		record(60, (u32)a, (u32)size);
}
static void dma_sync_single_for_cpu(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d; (void)a; (void)size; (void)dir;
	syncs_for_cpu++;
}
static void dma_sync_single_for_device(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d; (void)a; (void)size; (void)dir;
}

/* sk_buff queues. */
static void skb_queue_head_init(struct sk_buff_head *l)
{
	l->next = l->prev = (struct sk_buff *)l;
	l->qlen = 0;
}
static u32 skb_queue_len(const struct sk_buff_head *l) { return l->qlen; }
static void skb_queue_tail(struct sk_buff_head *l, struct sk_buff *s)
{
	s->next = (struct sk_buff *)l;
	s->prev = l->prev;
	l->prev->next = s;
	l->prev = s;
	l->qlen++;
}
static struct sk_buff *skb_dequeue(struct sk_buff_head *l)
{
	if (!l->qlen)
		return NULL;
	struct sk_buff *s = l->next;
	l->next = s->next;
	s->next->prev = (struct sk_buff *)l;
	l->qlen--;
	return s;
}
#define SKB_HEADROOM 64
static struct sk_buff *dev_alloc_skb(unsigned int length)
{
	struct sk_buff *s = calloc(1, sizeof(*s));
	if (!s)
		abort();
	s->head = calloc(1, SKB_HEADROOM + length);
	if (!s->head)
		abort();
	s->data = s->head + SKB_HEADROOM;
	return s;
}
static void dev_kfree_skb_any(struct sk_buff *s) { free(s->head); free(s); }
#define dev_kfree_skb dev_kfree_skb_any
static void *skb_push(struct sk_buff *s, unsigned int n)
{
	if (s->data - n < s->head)
		abort();
	s->data -= n;
	s->len += n;
	return s->data;
}

/* Callees outside this slice. */
static struct rtw89_pci_tx_data *RTW89_PCI_TX_SKB_CB(struct sk_buff *skb)
{
	return (struct rtw89_pci_tx_data *)skb->cb;
}
static void rtw89_chip_fill_txdesc_fwcmd(struct rtw89_dev *d, struct rtw89_tx_desc_info *i, void *t)
{
	(void)d; (void)i; (void)t;
}
static void rtw89_pci_release_tx_ring(struct rtw89_dev *d, struct rtw89_pci_tx_ring *tx_ring)
{
	(void)d;
	if (!list_empty(&tx_ring->busy_pages))
		abort();
}
'''
    tables = (
        'static const struct rtw89_pci_gen_def rtw89_pci_gen_ax = {\n'
        + ''.join(f'\t.{field} = {gen_def[field]},\n' for field in gen_fields)
        + '};\nstatic const struct rtw89_pci_info rtw8852b_pci_info = {\n'
        + ''.join(f'\t.{field} = {pci_info[field]},\n' for field in pci_fields)
        + '};\nstatic const struct rtw89_chip_info rtw8852b_chip_info = {\n'
        + ''.join(f'\t.{field} = {chip[field]},\n' for field in chip_fields)
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
static struct rtw89_pci *pci_of(struct rtw89_dev *dev) { return (struct rtw89_pci *)dev->priv; }
static void record_ring(u32 channel, const struct rtw89_pci_dma_ring *r)
{
	record(30, channel, r->len);
	record(31, r->desc_size, (u32)r->dma);
	record(32, r->wp, r->rp);
	record(33, r->addr.num, r->addr.idx);
	record(34, r->addr.bdram, r->addr.desa_l);
	record(35, r->addr.desa_h, upper_32_bits(r->dma));
}
static void record_rings(struct rtw89_dev *dev)
{
	struct rtw89_pci *p = pci_of(dev);
	for (u32 ch = 0; ch < RTW89_TXCH_NUM; ch++)
		if (!(dev->pci_info->tx_dma_ch_mask & BIT(ch)))
			record_ring(ch, &p->tx.rings[ch].bd_ring);
	for (u32 ch = 0; ch < RTW89_RXCH_NUM; ch++) {
		struct rtw89_pci_rx_ring *r = &p->rx.rings[ch];
		record_ring(0x100 | ch, &r->bd_ring);
		record(36, r->target_rx_tag, r->diliver_desc.ready | (r->diliver_skb != NULL) << 1);
	}
	record(37, skb_queue_len(&p->h2c_queue), skb_queue_len(&p->h2c_release_queue));
}
static struct pci_dev pdev;
static struct device device;
static struct rtw89_dev *new_dev(void)
{
	struct rtw89_dev *dev = calloc(1, sizeof(*dev) + sizeof(struct rtw89_pci));
	if (!dev)
		abort();
	dev->chip = &rtw8852b_chip_info;
	dev->pci_info = &rtw8852b_pci_info;
	dev->hal.cv = CHIP_CBV;
	dev->quirks[0] = rtw8852b_chip_info.default_quirks;
	dev->dev = &device;
	struct rtw89_pci *p = pci_of(dev);
	p->pdev = &pdev;
	skb_queue_head_init(&p->h2c_queue);
	skb_queue_head_init(&p->h2c_release_queue);
	return dev;
}
static void free_queue(struct sk_buff_head *l)
{
	struct sk_buff *s;
	while ((s = skb_dequeue(l)))
		dev_kfree_skb_any(s);
}
static void free_dev(struct rtw89_dev *dev)
{
	free_queue(&pci_of(dev)->h2c_queue);
	free_queue(&pci_of(dev)->h2c_release_queue);
	free(dev);
}
static void allocate(struct rtw89_dev *dev)
{
	wd_allocations = maps = 0;
	map_override = 0;
	if (rtw89_pci_alloc_trx_rings(dev, &pdev))
		abort();
}
enum fill { PATTERN, ONES, ZEROS };
static void fill(enum fill f, u8 phy_rate, u8 l1_ctrl, int calib)
{
	for (size_t i = 0; i < sizeof(memory); i++)
		memory[i] = f == PATTERN ? (u8)(i * 37 + 11) : f == ONES ? 0xff : 0;
	for (size_t i = 0; i < sizeof(config); i++)
		config[i] = (u8)(i * 13 + 7);
	config[RTW89_PCIE_PHY_RATE] = phy_rate;
	config[RTW89_PCIE_L1_CTRL] = l1_ctrl;
	for (u32 p = 0; p < 4; p++)
		for (u32 a = 0; a < 32; a++)
			mdio[p][a] = f == PATTERN ? (u16)((p * 32 + a) * 0x0b0b + 0x1234) :
				     f == ONES ? 0xffff : 0;
	for (u32 p = 1; p < 4; p += 2) {
		u16 *ppr = &mdio[p][RAC_CTRL_PPR_V1 & 0x1f];
		*ppr = calib ? *ppr | B_AX_CALIB_EN : *ppr & ~B_AX_CALIB_EN;
	}
}
static void pre_init(FILE *out)
{
	static const struct {
		enum fill fill;
		u8 phy_rate, l1_ctrl;
		int calib, config_fails, dbi_stuck, mdio_stuck, tx_busy, rx_busy, bdram_stuck;
	} cases[] = {
		{PATTERN, 0x11, 0x0f, 1, 0, 0, -1, 0, 0, 0},
		{ONES, 0x12, 0x08, 1, 0, 0, -1, 0, 0, 0},
		{ZEROS, 0x11, 0x00, 0, 0, 0, -1, 0, 0, 0},
		{PATTERN, 0x42, 0x37, 1, 0, 0, -1, 0, 0, 0},
		{PATTERN, 0x13, 0x08, 1, 0, 0, -1, 0, 0, 0},
		{PATTERN, 0x10, 0x08, 1, 0, 0, -1, 0, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 1, 0, -1, 0, 0, 0},
		{PATTERN, 0x12, 0x00, 0, 1, 0, -1, 0, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 1, 1, -1, 0, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 0, 0, 0x20, 0, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 0, 0, 0x10, 0, 0, 0},
		{PATTERN, 0x11, 0x00, 1, 0, 0, 0x10, 0, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 0, 0, 0x1b, 0, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 0, 0, -1, 1, 0, 0},
		{PATTERN, 0x11, 0x08, 1, 0, 0, -1, 0, 1, 0},
		{PATTERN, 0x11, 0x08, 1, 0, 0, -1, 0, 0, 1},
		{ONES, 0x11, 0x08, 1, 1, 0, -1, 0, 0, 0},
	};
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		fill(cases[c].fill, cases[c].phy_rate, cases[c].l1_ctrl, cases[c].calib);
		config_fails = cases[c].config_fails;
		dbi_stuck = cases[c].dbi_stuck;
		mdio_stuck = cases[c].mdio_stuck;
		tx_busy = cases[c].tx_busy;
		rx_busy = cases[c].rx_busy;
		bdram_stuck = cases[c].bdram_stuck;
		struct rtw89_dev *dev = new_dev();
		allocate(dev);
		if (segment_bytes)
			abort();
		int ret = rtw89_pci_ops_mac_pre_init(dev);
		record(11, 0, (u32)ret);
		if (!ret)
			record_rings(dev);
		flush(out);
		rtw89_pci_free_trx_rings(dev, &pdev);
		free_dev(dev);
	}
}
static void alloc_only(FILE *out)
{
	struct rtw89_dev *dev = new_dev();
	allocate(dev);
	record_rings(dev);
	struct rtw89_pci *p = pci_of(dev);
	for (u32 ch = 0; ch < RTW89_RXCH_NUM; ch++) {
		struct rtw89_pci_rx_ring *r = &p->rx.rings[ch];
		for (u32 i = 0; i < r->bd_ring.len; i++) {
			struct rtw89_pci_rx_bd_32 *bd = RTW89_PCI_RX_BD(r, i);
			record(40, ch << 16 | i, bd->buf_size | (u32)bd->opt << 16);
			record(41, ch << 16 | i, bd->dma);
		}
	}
	flush(out);
	rtw89_pci_free_trx_rings(dev, &pdev);
	free_dev(dev);
}
static void rx_info(FILE *out)
{
	static const struct { u32 dword; u32 target; int check; } entries[] = {
		{RTW89_PCI_RXBD_FS | RTW89_PCI_RXBD_LS | 100 | 5 << 16, 0, 0},
		{RTW89_PCI_RXBD_FS | RTW89_PCI_RXBD_LS | 64 | 1 << 16, 0, 1},
		{RTW89_PCI_RXBD_FS | 2000 | 7 << 16, 7, 1},
		{RTW89_PCI_RXBD_LS | 24 | 6 << 16, 7, 1},
		{RTW89_PCI_RXBD_FS | RTW89_PCI_RXBD_LS | 11498 | 0x1fffU << 16, 0x1fff, 1},
		{RTW89_PCI_RXBD_FS | RTW89_PCI_RXBD_LS | 8, 0, 1},
		{0xffffffff, 3, 0},
		{0, 0x1234, 0},
	};
	static struct rtw89_pci_info checking;
	checking = rtw8852b_pci_info;
	checking.check_rx_tag = true;
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci_rx_ring *ring = &pci_of(dev)->rx.rings[RTW89_RXCH_RXQ];
	for (size_t e = 0; e < ARRAY_SIZE(entries); e++) {
		struct sk_buff *skb = dev_alloc_skb(RTW89_PCI_RX_BUF_SIZE);
		memcpy(skb->data, &entries[e].dword, 4);
		dev->pci_info = entries[e].check ? &checking : &rtw8852b_pci_info;
		ring->target_rx_tag = entries[e].target;
		syncs_for_cpu = 0;
		int ret = rtw89_pci_sync_skb_for_device_and_validate_rx_info(dev, ring, skb);
		struct rtw89_pci_rx_info *info = RTW89_PCI_RX_SKB_CB(skb);
		record(50, (u32)ret, ring->target_rx_tag);
		record(51, info->fs | info->ls << 1, info->len | (u32)info->tag << 16);
		record(52, syncs_for_cpu, 0);
		dev_kfree_skb_any(skb);
	}
	flush(out);
	free_dev(dev);
}
static void recalc(FILE *out)
{
	static const struct { int tx; u32 len, wp, rp, idx; } entries[] = {
		{1, 256, 5, 0, 3 << 16 | 5},
		{1, 256, 4, 250, 4 << 16 | 4},
		{1, 256, 7, 7, 7 << 16 | 7},
		{1, 256, 9, 2, 0xf123ffff},
		{0, 256, 10, 0, 12 << 16},
		{0, 256, 250, 0, 3 << 16 | 0xfff},
		{0, 256, 0, 0, 0},
		{0, 256, 17, 9, 0x0fff0000},
	};
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci *p = pci_of(dev);
	memset(memory, 0, sizeof(memory));
	for (size_t e = 0; e < ARRAY_SIZE(entries); e++) {
		struct rtw89_pci_dma_ring *r;
		u32 cnt;
		if (entries[e].tx) {
			r = &p->tx.rings[RTW89_TXCH_CH12].bd_ring;
			r->addr = rtw89_pci_ch_dma_addr_set.tx[RTW89_TXCH_CH12];
		} else {
			r = &p->rx.rings[RTW89_RXCH_RXQ].bd_ring;
			r->addr = rtw89_pci_ch_dma_addr_set.rx[RTW89_RXCH_RXQ];
		}
		r->len = entries[e].len;
		r->wp = entries[e].wp;
		r->rp = entries[e].rp;
		set(r->addr.idx, 4, entries[e].idx);
		if (entries[e].tx)
			cnt = rtw89_pci_txbd_recalc(dev, &p->tx.rings[RTW89_TXCH_CH12]);
		else
			cnt = rtw89_pci_rxbd_recalc(dev, &p->rx.rings[RTW89_RXCH_RXQ]);
		record(53, cnt, r->rp);
	}
	flush(out);
	free_dev(dev);
}
static void tx_index(FILE *out)
{
	static const struct { u32 len, wp, rp, n; } entries[] = {
		{256, 0, 0, 1}, {256, 255, 0, 1}, {256, 254, 0, 1}, {256, 10, 11, 1},
		{256, 3, 200, 5}, {256, 200, 3, 100}, {256, 0, 1, 0},
	};
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci *p = pci_of(dev);
	struct rtw89_pci_tx_ring *tx = &p->tx.rings[RTW89_TXCH_CH12];
	struct rtw89_pci_rx_ring *rx = &p->rx.rings[RTW89_RXCH_RXQ];
	for (size_t e = 0; e < ARRAY_SIZE(entries); e++) {
		tx->bd_ring.len = entries[e].len;
		tx->bd_ring.wp = entries[e].wp;
		tx->bd_ring.rp = entries[e].rp;
		record(54, rtw89_pci_get_avail_txbd_num(tx), 0);
		rtw89_pci_tx_bd_ring_update(dev, tx, entries[e].n);
		record(55, tx->bd_ring.wp, rtw89_pci_get_avail_txbd_num(tx));
		rx->bd_ring.len = entries[e].len;
		rx->bd_ring.wp = entries[e].wp;
		rtw89_pci_rxbd_increase(rx, entries[e].n);
		record(56, rx->bd_ring.wp, 0);
	}
	flush(out);
	free_dev(dev);
}
static void fwcmd_submit(FILE *out)
{
	static const struct { u32 length; u64 dma; u32 wp; } entries[] = {
		{100, 0x12345000, 0}, {2020, 0xfffff000, 255}, {0, 0x80000000, 17},
		{8, 0x987654000ULL, 3},
	};
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci *p = pci_of(dev);
	struct rtw89_pci_tx_ring *tx = &p->tx.rings[RTW89_TXCH_CH12];
	tx->bd_ring.head = calloc(RTW89_PCI_TXBD_NUM_MAX, sizeof(struct rtw89_pci_tx_bd_32));
	if (!tx->bd_ring.head)
		abort();
	tx->bd_ring.len = RTW89_PCI_TXBD_NUM_MAX;
	tx->txch = RTW89_TXCH_CH12;
	for (size_t e = 0; e < ARRAY_SIZE(entries); e++) {
		struct rtw89_core_tx_request req = {0};
		req.skb = dev_alloc_skb(entries[e].length);
		req.skb->len = entries[e].length;
		tx->bd_ring.wp = entries[e].wp;
		tx->bd_ring.rp = entries[e].wp;
		map_override = entries[e].dma;
		struct rtw89_pci_tx_bd_32 *txbd = rtw89_pci_get_next_txbd(tx);
		int ret = rtw89_pci_fwcmd_submit(dev, tx, txbd, &req);
		record(70, (u32)ret, tx->bd_ring.wp);
		record(71, txbd->length | (u32)txbd->opt << 16, txbd->dma);
		record(72, req.skb->len, skb_queue_len(&p->h2c_queue));
	}
	map_override = 0;
	flush(out);
	free(tx->bd_ring.head);
	free_dev(dev);
}
static void queue(struct rtw89_pci *p, u32 count, u32 dma, u32 len)
{
	for (u32 i = 0; i < count; i++) {
		struct sk_buff *s = dev_alloc_skb(0);
		s->len = len + i;
		RTW89_PCI_TX_SKB_CB(s)->dma = dma + 0x1000 * i;
		skb_queue_tail(&p->h2c_queue, s);
	}
}
static void release_fwcmd(FILE *out)
{
	static const struct { u32 kept, queued, cnt; int all; } entries[] = {
		{0, 3, 3, 0}, {8, 4, 2, 0}, {5, 10, 10, 0}, {3, 4, 6, 0}, {6, 5, 0, 1}, {2, 7, 7, 1},
	};
	for (size_t e = 0; e < ARRAY_SIZE(entries); e++) {
		struct rtw89_dev *dev = new_dev();
		struct rtw89_pci *p = pci_of(dev);
		queue(p, entries[e].kept, 0x100000, 0x40);
		rtw89_pci_release_fwcmd(dev, p, entries[e].kept, false);
		queue(p, entries[e].queued, 0x200000, 0x80);
		record_unmaps = 1;
		rtw89_pci_release_fwcmd(dev, p, entries[e].cnt, entries[e].all);
		record_unmaps = 0;
		record(61, skb_queue_len(&p->h2c_queue), skb_queue_len(&p->h2c_release_queue));
		free_dev(dev);
	}
	flush(out);
}
int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	pre_init(out);
	alloc_only(out);
	rx_info(out);
	recalc(out);
	tx_index(out);
	fwcmd_submit(out);
	release_fwcmd(out);
	if (fclose(out))
		abort();
	free(segment);
	printf("%d\n", 23);
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, pci_h_defines, core_defines, declarations, rxbd_defines, harness,
        core_helpers,
        pci_h_inlines, dma_addr_set, pci_c, tables, main_c])
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
        case_order='17 x rtw89_pci_alloc_trx_rings then hci.ops->mac_pre_init; '
                   'rtw89_pci_alloc_trx_rings alone with every RX BD; RX info and tag; '
                   'TX and RX recalc; TX BD availability, ring update and RX increase; '
                   'rtw89_pci_fwcmd_submit; rtw89_pci_release_fwcmd',
        dispatch=dict(rtw89_pci_gen_ax=gen_def, rtw8852b_pci_info=pci_info,
                      rtw8852b_chip_info=chip, rtw89_8852be_info=driver, rtw89_pci_ops=pci_ops),
        dma=dict(tx_bd_pool='0xfffe0000', rx_bd_pool='0xfffd0000',
                 rx_buffers='0x80000000 + 0x3000 * n', wd_pages='0x40000000 + 0x10000 * n'),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, configuration space, the PCIe PHY, DMA addresses and the chip answers are a '
            'model; no physical evidence',
            'read_poll_timeout and read_poll_timeout_atomic are modeled counted in steps, not by '
            'Linux timekeeping',
            'PCIe RTL8852BE only: rtw8852b_pci_info with chip_id RTL8852B and no quirk',
            'the data channels\' WD pages are allocated but never programmed; their release is a '
            'stub that checks nothing is busy',
            'rtw89_chip_fill_txdesc_fwcmd leaves the TXWD body zeroed; RTW89_PCI_TX_SKB_CB is the '
            'skb control buffer',
            'the RX tag is also checked with check_rx_tag true, which rtw8852b_pci_info does not '
            'set',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
