#!/usr/bin/env python3
"""Unchanged pinned rtw89 H2C and C2H for an RTL8852BE: headers, TXWD body, CH12 and RXQ.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. Extracted unchanged, each with its SHA-256
in manifest.json:

- fw.c: rtw89_h2c_pkt_set_hdr and rtw89_h2c_pkt_set_hdr_fwdl, the H2C skb
  allocation (rtw89_fw_h2c_alloc_skb with its _with_hdr and _no_hdr forms),
  and the C2H entry: rtw89_fw_c2h_parse_attr, rtw89_fw_c2h_chk_atomic,
  rtw89_fw_c2h_irqsafe and rtw89_fw_c2h_cmd_handle;
- core.c: rtw89_h2c_tx with rtw89_core_tx_update_desc_info and
  rtw89_core_tx_update_h2c_info, rtw89_core_fill_txdesc with its TXWD body
  and info builders, rtw89_core_query_rxdesc and
  rtw89_core_rx_process_report;
- pci.c: rtw89_pci_ops' check_and_reclaim_tx_resource, tx_write and
  tx_kick_off on CH12 down to rtw89_pci_fwcmd_submit and
  rtw89_pci_release_fwcmd, and rtw89_pci_rxbd_deliver_skbs with every callee
  of its single-buffer path (the RX info and tag, rtw89_skb_put_rx_data);
- mac.c: rtw89_mac_c2h_chk_atomic, rtw89_mac_c2h_handle, its eight handler
  tables, rtw89_mac_c2h_rec_ack and rtw89_mac_c2h_done_ack;
- the core.h, pci.h, fw.h, mac.h, phy.h, coex.h and txrx.h declarations,
  inlines and definitions they use, reg.h, and rtw89_pci_ch_dma_addr_set.

rtw8852b_chip_info, rtw8852b_chip_ops, rtw8852b_pci_info and rtw89_pci_ops
give the values the harness's tables take, member by member. Everything is
compiled with clang under ASan and UBSan against a harness that models MAC
registers as bytes (CH12's hardware index is the upper half of its index
register), DMA with fixed addresses (command buffers from 0x80600000,
0x3000 apart, where the Rust test's domain places them), and skbs whose
headroom and tailroom are exactly what was reserved and allocated, so a
push or put past them aborts.

Harness stand-ins, each outside what an H2C or C2H reaches:
RTW89_PCI_TX_SKB_CB is the skb control buffer; the data path's callees of
rtw89_core_tx_update_desc_info, the WD-page and paused-HCI paths of the PCI
ops, rtw89_core_rx's 802.11 path, rtw89_mac_c2h_scanofld_rsp_atomic, the
PHY and BTC C2H entries, rtw89_complete_cond and every handler in the MAC
tables but the two acks are stubs; the acks' decoded fields are read from
the arguments of their rtw89_debug calls, which the kernel evaluates
whatever it prints.

Segments, each prefixed by its byte length, of records of three
little-endian u32 (tag, a, b):

- 600 headers from rtw89_h2c_pkt_set_hdr or rtw89_h2c_pkt_set_hdr_fwdl,
  from h2c_seq 0: the sequence before and hdr0 (100), hdr1 and the sequence
  after (101).
- TXWD bodies: rtw89_core_tx_update_desc_info for ten firmware commands,
  then rtw89_chip_fill_txdesc_fwcmd: the members it set (110) and the six
  dwords (111); rtw89_core_fill_txdesc over eight sets of body members
  (112).
- rtw89_h2c_tx over a script of commands, firmware header and parts on an
  empty CH12 ring, with the hardware index moved between them, CH12 filled
  until -ENOSPC and drained: each register access (tagged by width, writes
  by 4 plus width), the unmaps (60), the return (11), then for a sent
  packet the BD (122, 123) and the mapped bytes as words (124), the queue
  lengths (126) and the sequence (127); each index move (125).
- rtw89_pci_rxbd_deliver_skbs over 25 single-buffer packets on RXQ: the
  descriptor (130, 131); a packet of another type (132); a C2H's length
  (133), bytes (134) and attribute (137), then its REC_ACK (135) or
  DONE_ACK (136) as the handler decoded it, or neither (138).
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

    def table(file, name):
        """A handler table, from the blank line before it through its semicolon."""
        text = source(file)
        found = [m for m in re.finditer(re.escape(name) + r'\[\]\)', text)]
        if len(found) != 1:
            raise ValueError(f'{file}: {name}[] appears {len(found)} times')
        start = text.rfind('\n\n', 0, found[0].start()) + 2
        brace = text.index('= {', found[0].start()) + 2
        end = text.index(';', closing(text, brace)) + 1
        return record(file, name, text[start:end])

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

    def block(file, first, before, name):
        """The lines from the first one starting with first up to the next one starting with before."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n' + before, start) + 1
        return record(file, name, text[start:end])

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
    pci_h_defines = block('pci.h', '#define MDIO_PG0_G1','struct rtw89_pci_isrs;',
                          'MDIO_PG0_G1 to struct rtw89_pci_isrs;')
    rxbd_defines = defines('pci.h', ['RTW89_PCI_RXBD_FS', 'RTW89_PCI_RXBD_LS',
                                     'RTW89_PCI_RXBD_WRITE_SIZE', 'RTW89_PCI_RXBD_TAG'])
    txwd_defines = block('txrx.h', '/* TX WD BODY DWORD 0 */', '/* TX WD INFO DWORD 5 */',
                         'TX WD BODY DWORD 0 to TX WD INFO DWORD 5')
    rxd_defines = block('txrx.h', '/* RX WD dword0 */', 'struct rtw89_rxinfo_user {',
                        'RX WD dword0 to struct rtw89_rxinfo_user')
    h2c_defines = block('fw.h', '#define H2C_HEADER_LEN',
                        '/* CLASS 10 - Security CAM */', 'H2C_HEADER_LEN to CLASS 10')
    c2h_defines = block('fw.h', '#define RTW89_C2H_HEADER_LEN',
                        'struct rtw89_fw_c2h_log_fmt {',
                        'RTW89_C2H_HEADER_LEN to struct rtw89_fw_c2h_log_fmt')
    core_defines = defines('core.h', ['RTW89_COMPLETION_BUF_SIZE'])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_chip_gen'),
        declaration('core.h', 'enum', 'rtw89_core_tx_type'),
        declaration('core.h', 'enum', 'rtw89_core_rx_type'),
        declaration('core.h', 'enum', 'rtw89_flags'),
        declaration('core.h', 'enum', 'rtw89_dma_ch'),
        declaration('core.h', 'struct', 'rtw89_reg_def'),
        declaration('core.h', 'struct', 'rtw89_txwd_body'),
        declaration('core.h', 'struct', 'rtw89_txwd_info'),
        declaration('core.h', 'struct', 'rtw89_rx_desc_info'),
        declaration('core.h', 'struct', 'rtw89_rxdesc_short'),
        declaration('core.h', 'struct', 'rtw89_rxdesc_long'),
        declaration('core.h', 'struct', 'rtw89_tx_desc_info'),
        declaration('core.h', 'struct', 'rtw89_core_tx_request'),
        declaration('core.h', 'struct', 'rtw89_completion_data'),
        declaration('coex.h', 'enum', 'btc_pkt_type'),
        declaration('txrx.h', 'enum', 'rtw89_tx_channel'),
        declaration('txrx.h', 'enum', 'rtw89_rx_channel'),
        declaration('fw.h', 'struct', 'fwcmd_hdr'),
        declaration('fw.h', 'enum', 'rtw89_fw_c2h_category'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_ofld_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_info_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_mcc_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_misc_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_mlo_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_mrc_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_wow_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_ap_func'),
        declaration('mac.h', 'enum', 'rtw89_mac_c2h_class'),
        declaration('phy.h', 'enum', 'rtw89_phy_c2h_class'),
    ])
    pci_declarations = '\n\n'.join([
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
    core_h_inlines = '\n\n'.join(function('core.h', name) for name in [
        'rtw89_hci_tx_write', 'rtw89_hci_check_and_reclaim_tx_resource',
        'rtw89_hci_tx_kick_off', 'rtw89_chip_query_rxdesc', 'rtw89_chip_fill_txdesc_fwcmd',
        'rtw89_alloc_skb_for_rx'])
    pci_h_inlines = in_order('pci.h', [
        'rtw89_pci_rxbd_increase', 'RTW89_PCI_RX_SKB_CB', 'rtw89_pci_get_next_txbd',
        'rtw89_pci_enqueue_txwd'])
    dma_addr_set = '\n\n'.join(
        [macro('pci.c', name) for name in ['DEF_TXCHADDRS_TYPE1', 'DEF_TXCHADDRS', 'DEF_RXCHADDRS']]
        + [definition('pci.c', 'const struct rtw89_pci_ch_dma_addr_set rtw89_pci_ch_dma_addr_set')])
    core_c = in_order('core.c', [
        'rtw89_core_tx_update_h2c_info', 'rtw89_core_tx_update_desc_info', 'rtw89_h2c_tx',
        'rtw89_build_txwd_body0', 'rtw89_build_txwd_body2', 'rtw89_build_txwd_body3',
        'rtw89_build_txwd_info0', 'rtw89_build_txwd_info1', 'rtw89_build_txwd_info2',
        'rtw89_build_txwd_info3', 'rtw89_build_txwd_info4', 'rtw89_core_fill_txdesc',
        'rtw89_core_rx_process_report', 'rtw89_core_query_rxdesc'])
    pci_c = in_order('pci.c', [
        'rtw89_pci_dma_recalc', 'rtw89_pci_txbd_recalc', 'rtw89_pci_release_fwcmd',
        'rtw89_pci_reclaim_tx_fwcmd', 'rtw89_pci_sync_skb_for_cpu',
        'rtw89_pci_sync_skb_for_device', 'rtw89_pci_rxbd_info_update',
        'rtw89_pci_validate_rx_tag', 'rtw89_pci_sync_skb_for_device_and_validate_rx_info',
        'rtw89_skb_put_rx_data', 'rtw89_pci_get_rx_skb_idx', 'rtw89_pci_rxbd_deliver_skbs',
        'rtw89_pci_get_avail_txbd_num', '__rtw89_pci_check_and_reclaim_tx_fwcmd_resource',
        'rtw89_pci_check_and_reclaim_tx_resource', '__rtw89_pci_tx_kick_off',
        'rtw89_pci_tx_bd_ring_update', 'rtw89_pci_ops_tx_kick_off', 'rtw89_pci_fwcmd_submit',
        'rtw89_pci_txbd_submit', 'rtw89_pci_tx_write', 'rtw89_pci_ops_tx_write'])
    mac_acks = in_order('mac.c', ['rtw89_mac_c2h_rec_ack', 'rtw89_mac_c2h_done_ack'])
    table_names = ['rtw89_mac_c2h_ofld_handler', 'rtw89_mac_c2h_info_handler',
                   'rtw89_mac_c2h_mcc_handler', 'rtw89_mac_c2h_misc_handler',
                   'rtw89_mac_c2h_mlo_handler', 'rtw89_mac_c2h_mrc_handler',
                   'rtw89_mac_c2h_wow_handler', 'rtw89_mac_c2h_ap_handler']
    tables_c = [table('mac.c', name) for name in table_names]
    handlers = []
    for body in tables_c:
        for name in re.findall(r'\]\s*=\s*(\w+),', body):
            if name not in ('NULL', 'rtw89_mac_c2h_rec_ack', 'rtw89_mac_c2h_done_ack') \
                    and name not in handlers:
                handlers.append(name)
    handler_stubs = '\n'.join(
        f'static void {name}(struct rtw89_dev *rtwdev, struct sk_buff *c2h, u32 len)\n'
        f'{{ (void)rtwdev; (void)c2h; (void)len; other_handlers++; }}' for name in handlers)
    mac_c = in_order('mac.c', ['rtw89_mac_c2h_chk_atomic', 'rtw89_mac_c2h_handle'])
    fw_c = in_order('fw.c', [
        'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr',
        'rtw89_fw_h2c_alloc_skb_no_hdr', 'rtw89_h2c_pkt_set_hdr', 'rtw89_h2c_pkt_set_hdr_fwdl',
        'rtw89_fw_c2h_parse_attr', 'rtw89_fw_c2h_chk_atomic', 'rtw89_fw_c2h_irqsafe',
        'rtw89_fw_c2h_cmd_handle'])

    chip_fields = ['chip_id', 'chip_gen', 'ops', 'h2c_desc_size']
    chip = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info', chip_fields)
    if chip['ops'] != '&rtw8852b_chip_ops':
        raise ValueError(f"rtw8852b_chip_info.ops is {chip['ops']}")
    ops_fields = ['query_rxdesc', 'fill_txdesc_fwcmd']
    chip_ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                      ops_fields)
    if chip_ops != {'query_rxdesc': 'rtw89_core_query_rxdesc',
                    'fill_txdesc_fwcmd': 'rtw89_core_fill_txdesc'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops}')
    pci_fields = ['rx_ring_eq_is_full', 'check_rx_tag', 'no_rxbd_fs']
    pci_info = fields('rtw8852be.c', 'static const struct rtw89_pci_info rtw8852b_pci_info',
                      pci_fields)
    hci_fields = ['tx_write', 'tx_kick_off', 'check_and_reclaim_tx_resource']
    hci_ops = fields('pci.c', 'static const struct rtw89_hci_ops rtw89_pci_ops', hci_fields)
    if hci_ops != {'tx_write': 'rtw89_pci_ops_tx_write',
                   'tx_kick_off': 'rtw89_pci_ops_tx_kick_off',
                   'check_and_reclaim_tx_resource': 'rtw89_pci_check_and_reclaim_tx_resource'}:
        raise ValueError(f'rtw89_pci_ops is {hci_ops}')

    preamble = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
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
#define __rcu
#define __maybe_unused __attribute__((unused))
#define unlikely(x) (x)
#define likely(x) (x)
#define EXPORT_SYMBOL(...)
#define WARN(c, ...) ((void)(c))
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define le16_encode_bits(v, m) ((__le16)FIELD_PREP(m, (u16)(v)))
#define le32_get_bits(v, m) u32_get_bits(v, m)
#define cpu_to_le16(v) ((__le16)(v))
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define upper_32_bits(n) ((u32)(((u64)(n)) >> 32))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define RTW89_DBG_TXRX BIT(0)
#define RTW89_DBG_HCI BIT(6)
#define RTW89_DBG_FW BIT(12)
#define RTW89_DBG_UNEXP BIT(31)
/* rtw89's log helpers are calls in the kernel: their arguments are
 * evaluated whatever is printed. The acks' decoded fields are read from
 * theirs. */
static void sink(const char *format, ...) { (void)format; }
static void debug_sink(const char *format, ...);
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info_once(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), debug_sink(__VA_ARGS__))
struct rtw89_dev;
static void rtw89_hex_dump(struct rtw89_dev *d, u32 mask, const char *prefix,
			   const void *buf, size_t len)
{
	(void)d; (void)mask; (void)prefix; (void)buf; (void)len;
}

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
	u32 len, size;
	u8 cb[48] __attribute__((aligned(8)));
};
struct sk_buff_head { struct sk_buff *next, *prev; u32 qlen; };
typedef struct { int unused; } spinlock_t;
#define spin_lock_bh(l) ((void)(l))
#define spin_unlock_bh(l) ((void)(l))
struct device { int unused; };
struct pci_dev { struct device dev; };
struct rtw89_pci;
struct rtw89_pci_isrs;
struct rtw89_pci_rpp_info;
struct rtw89_pci_isr_def;
struct rtw89_pci_ssid_quirk;
struct rtw89_pci_bd_idx_addr;
struct ieee80211_vif;
struct ieee80211_sta { bool mlo; };
struct rtw89_vif_link;
struct rtw89_sta_link;
'''
    harness = r'''
/* The members of rtw89's device the extracted functions reach. */
struct rtw89_chip_ops {
	void (*query_rxdesc)(struct rtw89_dev *rtwdev, struct rtw89_rx_desc_info *desc_info,
			     u8 *data, u32 data_offset);
	void (*fill_txdesc_fwcmd)(struct rtw89_dev *rtwdev, struct rtw89_tx_desc_info *desc_info,
				  void *txdesc);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_chip_ops *ops;
	u32 h2c_desc_size;
};
struct rtw89_hci_ops {
	int (*tx_write)(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req);
	void (*tx_kick_off)(struct rtw89_dev *rtwdev, u8 txch);
	u32 (*check_and_reclaim_tx_resource)(struct rtw89_dev *rtwdev, u8 txch);
};
struct rtw89_hci_info { const struct rtw89_hci_ops *ops; bool paused; };
struct rtw89_fw_info { u8 h2c_seq; u8 rec_seq; };
struct rtw89_wait_info { int unused; };
struct rtw89_mac_info { struct rtw89_wait_info fw_ofld_wait, ps_wait; };
struct rtw89_hw_scan_info { u8 seq; };
struct ieee80211_conf { u32 flags; };
struct ieee80211_hw { void *wiphy; struct ieee80211_conf conf; };
#define IEEE80211_CONF_MONITOR BIT(0)
/* Only rtw89_alloc_skb_for_rx's monitor branch, never taken, names it. */
#define RTW89_RADIOTAP_ROOM 64
struct wiphy_work { int unused; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_pci_info *pci_info;
	struct rtw89_hci_info hci;
	struct rtw89_fw_info fw;
	struct rtw89_mac_info mac;
	struct rtw89_hw_scan_info scan_info;
	struct ieee80211_hw *hw;
	struct sk_buff_head c2h_queue;
	struct wiphy_work c2h_work;
	DECLARE_BITMAP(flags, NUM_OF_RTW89_FLAGS);
	struct device *dev;
	u8 priv[] __attribute__((aligned(8)));
};
static int test_bit(int nr, const unsigned long *map) { return (map[nr / 64] >> (nr % 64)) & 1; }
static void set_bit(int nr, unsigned long *map) { map[nr / 64] |= 1UL << (nr % 64); }

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
static void record(u32 tag, u32 a, u32 b) { word(tag); word(a); word(b); }
static u32 le32_at(const u8 *p) { u32 v; memcpy(&v, p, 4); return v; }

/* The acks' decoded fields, from the arguments of their debug calls. */
static u32 acks, other_handlers;
static void debug_sink(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	if (!strncmp(format, "C2H rev ack recv", 16)) {
		int cat = va_arg(ap, int), class = va_arg(ap, int);
		int func = va_arg(ap, int), seq = va_arg(ap, int);
		record(135, cat | class << 8 | func << 16, seq);
		acks++;
	} else if (!strncmp(format, "C2H done ack recv", 17)) {
		int cat = va_arg(ap, int), class = va_arg(ap, int), func = va_arg(ap, int);
		int ret = va_arg(ap, int), seq = va_arg(ap, int);
		record(136, cat | class << 8 | func << 16, ret | seq << 8);
		acks++;
	}
	va_end(ap);
}

/* The register model: MAC space as bytes. */
static u8 memory[0x10000];
static u32 get(u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)memory[r + i] << (8 * i); return v; }
static void set(u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) memory[r + i] = v >> (8 * i); }
static u32 model_read(u32 r, u32 n)
{
	if (r + n > sizeof(memory))
		abort();
	u32 v = get(r, n);
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	if (r + n > sizeof(memory))
		abort();
	record(4 + n, r, v);
	set(r, n, v);
}
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }

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
#define dev_kfree_skb dev_kfree_skb_any
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
static void wiphy_work_queue(void *wiphy, struct wiphy_work *work) { (void)wiphy; (void)work; }

/* DMA: command buffers from 0x80600000, 0x3000 apart; unmaps kept for the
 * record that follows the call. */
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define CMD_DMA 0x80600000ULL
static u32 maps, unmaps, unmap_log[2][512];
static dma_addr_t dma_map_single(struct device *d, void *p, size_t size, int dir)
{
	(void)d; (void)p; (void)size;
	if (dir != DMA_TO_DEVICE)
		abort();
	return CMD_DMA + 0x3000ULL * maps++;
}
static int dma_mapping_error(struct device *d, dma_addr_t a) { (void)d; (void)a; return 0; }
static void dma_unmap_single(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d;
	if (dir != DMA_TO_DEVICE || unmaps >= 512)
		abort();
	unmap_log[0][unmaps] = (u32)a;
	unmap_log[1][unmaps++] = (u32)size;
}
static void dma_sync_single_for_cpu(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d; (void)a; (void)size; (void)dir;
}
static void dma_sync_single_for_device(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d; (void)a; (void)size; (void)dir;
}

/* Stand-ins outside what an H2C or C2H reaches. */
static struct rtw89_pci_tx_data *RTW89_PCI_TX_SKB_CB(struct sk_buff *skb)
{
	return (struct rtw89_pci_tx_data *)skb->cb;
}
struct ieee80211_tx_info { u32 flags; };
#define IEEE80211_SKB_CB(skb) ((struct ieee80211_tx_info *)(skb)->cb)
struct ieee80211_hdr { __le16 frame_control, duration_id; u8 addr1[6], addr2[6], addr3[6]; __le16 seq_ctrl; };
#define IEEE80211_SCTL_SEQ 0xfff0
#define IEEE80211_TX_CTL_REQ_TX_STATUS BIT(0)
#define IEEE80211_TX_CTL_SEND_AFTER_DTIM BIT(1)
#define IEEE80211_TX_CTL_INJECTED BIT(2)
struct rtw89_addr_cam_entry { bool valid; };
static bool ieee80211_vif_is_mld(const struct ieee80211_vif *v) { (void)v; abort(); }
static struct rtw89_addr_cam_entry *rtw89_get_addr_cam_of(struct rtw89_vif_link *v,
							   struct rtw89_sta_link *s)
{
	(void)v; (void)s; abort();
}
static void rtw89_tx_rpt_init(struct rtw89_dev *d, struct rtw89_core_tx_request *r) { (void)d; (void)r; abort(); }
static bool is_broadcast_ether_addr(const u8 *a) { (void)a; abort(); }
static bool is_multicast_ether_addr(const u8 *a) { (void)a; abort(); }
static enum rtw89_core_tx_type rtw89_core_get_tx_type(struct rtw89_dev *d, struct sk_buff *s)
{
	(void)d; (void)s; abort();
}
static void rtw89_core_tx_update_mgmt_info(struct rtw89_dev *d, struct rtw89_core_tx_request *r) { (void)d; (void)r; abort(); }
static void rtw89_core_tx_update_data_info(struct rtw89_dev *d, struct rtw89_core_tx_request *r) { (void)d; (void)r; abort(); }
static enum btc_pkt_type rtw89_core_tx_btc_spec_pkt_notify(struct rtw89_dev *d,
							   struct rtw89_core_tx_request *r)
{
	(void)d; (void)r; abort();
}
static void rtw89_core_tx_update_he_qos_htc(struct rtw89_dev *d, struct rtw89_core_tx_request *r,
					    enum btc_pkt_type t) { (void)d; (void)r; (void)t; abort(); }
static void rtw89_core_tx_update_ampdu_info(struct rtw89_dev *d, struct rtw89_core_tx_request *r,
					    enum btc_pkt_type t) { (void)d; (void)r; (void)t; abort(); }
static void rtw89_core_tx_update_llc_hdr(struct rtw89_dev *d, struct rtw89_tx_desc_info *i,
					 struct sk_buff *s) { (void)d; (void)i; (void)s; abort(); }
static void rtw89_core_tx_update_injection(struct rtw89_dev *d, struct rtw89_core_tx_request *r,
					   struct ieee80211_tx_info *i) { (void)d; (void)r; (void)i; abort(); }
static u32 __rtw89_pci_check_and_reclaim_tx_resource_noio(struct rtw89_dev *d, u8 txch)
{
	(void)d; (void)txch; abort();
}
static u32 __rtw89_pci_check_and_reclaim_tx_resource(struct rtw89_dev *d, u8 txch)
{
	(void)d; (void)txch; abort();
}
static struct rtw89_pci_tx_wd *rtw89_pci_dequeue_txwd(struct rtw89_pci_tx_ring *t) { (void)t; abort(); }
static int rtw89_pci_txwd_submit(struct rtw89_dev *d, struct rtw89_pci_tx_ring *t,
				 struct rtw89_pci_tx_wd *w, struct rtw89_core_tx_request *r)
{
	(void)d; (void)t; (void)w; (void)r; abort();
}
static void rtw89_core_rx_process_ppdu_sts(struct rtw89_dev *d, struct rtw89_rx_desc_info *i,
					   struct sk_buff *s)
{
	(void)d; (void)i;
	dev_kfree_skb_any(s);
}
static void rtw89_mac_c2h_scanofld_rsp_atomic(struct rtw89_dev *d, struct sk_buff *s) { (void)d; (void)s; }
static bool rtw89_phy_c2h_chk_atomic(struct rtw89_dev *d, u8 class, u8 func)
{
	(void)d; (void)class; (void)func;
	return false;
}
static void rtw89_phy_c2h_handle(struct rtw89_dev *d, struct sk_buff *s, u32 len, u8 class, u8 func)
{
	(void)d; (void)s; (void)len; (void)class; (void)func; other_handlers++;
}
static void rtw89_btc_c2h_handle(struct rtw89_dev *d, struct sk_buff *s, u32 len, u8 class, u8 func)
{
	(void)d; (void)s; (void)len; (void)class; (void)func; other_handlers++;
}
static void rtw89_complete_cond(struct rtw89_wait_info *w, unsigned int cond,
				const struct rtw89_completion_data *data)
{
	(void)w; (void)cond; (void)data;
}
void rtw89_core_rx(struct rtw89_dev *rtwdev, struct rtw89_rx_desc_info *desc_info,
		   struct sk_buff *skb);
void rtw89_fw_c2h_irqsafe(struct rtw89_dev *rtwdev, struct sk_buff *c2h);
static void rtw89_fw_c2h_cmd_handle(struct rtw89_dev *rtwdev, struct sk_buff *skb);
'''
    tables = (
        'static const struct rtw89_chip_ops rtw8852b_chip_ops = {\n'
        + ''.join(f'\t.{name} = {chip_ops[name]},\n' for name in ops_fields)
        + '};\nstatic const struct rtw89_chip_info rtw8852b_chip_info = {\n'
        + ''.join(f'\t.{name} = {chip[name]},\n' for name in chip_fields)
        + '};\nstatic const struct rtw89_pci_info rtw8852b_pci_info = {\n'
        + ''.join(f'\t.{name} = {pci_info[name]},\n' for name in pci_fields)
        + '};\nstatic const struct rtw89_hci_ops rtw89_pci_ops = {\n'
        + ''.join(f'\t.{name} = {hci_ops[name]},\n' for name in hci_fields)
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
static struct pci_dev pdev;
static struct device device;
static struct ieee80211_hw hw;
static struct rtw89_pci *pci_of(struct rtw89_dev *dev) { return (struct rtw89_pci *)dev->priv; }
static struct rtw89_dev *new_dev(void)
{
	struct rtw89_dev *dev = calloc(1, sizeof(*dev) + sizeof(struct rtw89_pci));
	if (!dev)
		abort();
	dev->chip = &rtw8852b_chip_info;
	dev->pci_info = &rtw8852b_pci_info;
	dev->hci.ops = &rtw89_pci_ops;
	dev->hw = &hw;
	dev->dev = &device;
	set_bit(RTW89_FLAG_POWERON, dev->flags);
	set_bit(RTW89_FLAG_RUNNING, dev->flags);
	skb_queue_head_init(&dev->c2h_queue);
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
	free_queue(&dev->c2h_queue);
	free(dev);
}
static const u32 lens[10] = {0, 4, 8, 12, 2020, 2028, 0x3ff7, 0x3ff8, 0x4000, 0xfffffffc};
static void headers(FILE *out)
{
	struct rtw89_dev *dev = new_dev();
	for (u32 i = 0; i < 600; i++) {
		struct sk_buff *skb = dev_alloc_skb(H2C_HEADER_LEN);
		skb_reserve(skb, H2C_HEADER_LEN);
		u8 type = (i * 5) & 0x1f, cat = i % 6, class = (i * 7) & 0x7f;
		u8 func = (i * 13 + 1) & 0xff, before = dev->fw.h2c_seq;
		if (i % 7 == 3)
			rtw89_h2c_pkt_set_hdr_fwdl(dev, skb, type, cat, class, func, lens[i % 10]);
		else
			rtw89_h2c_pkt_set_hdr(dev, skb, type, cat, class, func, i % 3 == 0, i % 5 == 1,
					      lens[i % 10]);
		if (skb->len != H2C_HEADER_LEN || skb->data != skb->head)
			abort();
		struct fwcmd_hdr *hdr = (struct fwcmd_hdr *)skb->data;
		record(100, before, hdr->hdr0);
		record(101, hdr->hdr1, dev->fw.h2c_seq);
		dev_kfree_skb_any(skb);
	}
	flush(out);
	free_dev(dev);
}
static void txwd(FILE *out)
{
	static const u32 skb_lens[10] = {0, 8, 12, 32, 2020, 2028, 0x3fff, 0x4000, 0x10007, 0xffffffff};
	static u8 data[64];
	struct rtw89_dev *dev = new_dev();
	for (u32 e = 0; e < 10; e++) {
		struct sk_buff skb = {.head = data, .data = data, .len = skb_lens[e], .size = sizeof(data)};
		struct rtw89_core_tx_request tx_req = {0};
		u8 txdesc[sizeof(struct rtw89_txwd_body)] __attribute__((aligned(4)));
		tx_req.skb = &skb;
		tx_req.tx_type = RTW89_CORE_TX_TYPE_FWCMD;
		if (e % 3 == 2)
			tx_req.desc_info.fw_dl = true;
		rtw89_core_tx_update_desc_info(dev, &tx_req);
		memset(txdesc, 0, sizeof(txdesc));
		rtw89_chip_fill_txdesc_fwcmd(dev, &tx_req.desc_info, txdesc);
		struct rtw89_tx_desc_info *d = &tx_req.desc_info;
		record(110, d->pkt_size, d->ch_dma | d->wd_page << 8 | d->is_bmc << 9 |
					 d->fw_dl << 10 | d->en_wd_info << 11);
		for (u32 k = 0; k < 6; k++)
			record(111, k, le32_at(txdesc + 4 * k));
	}
	for (u32 j = 0; j < 8; j++) {
		struct rtw89_tx_desc_info d = {0};
		u8 txdesc[sizeof(struct rtw89_txwd_body)] __attribute__((aligned(4)));
		d.wp_offset = j * 37 + 3;
		d.ch_dma = j * 5 + 1;
		d.hdr_llc_len = j * 11;
		d.wd_page = j & 1;
		d.fw_dl = (j >> 1) & 1;
		d.hw_ssn_sel = j * 3;
		d.hw_seq_mode = j * 7;
		d.tid_indicate = (j >> 2) & 1;
		d.qsel = j * 9 + 2;
		d.pkt_size = j * 0x1357 + 0x89;
		d.mac_id = j * 29 + 5;
		d.seq = j * 0x321 + 7;
		d.agg_en = j % 3 == 0;
		d.bk = j % 3 == 1;
		memset(txdesc, 0, sizeof(txdesc));
		rtw89_core_fill_txdesc(dev, &d, txdesc);
		for (u32 k = 0; k < 6; k++)
			record(112, k, le32_at(txdesc + 4 * k));
	}
	flush(out);
	free_dev(dev);
}
enum op { CMD, FWHDR, PART, HW, HW_ALL, FILL };
static const struct { enum op op; u8 class, func; bool rack, dack; u32 len; } script[] = {
	{CMD, 0x01, 0x10, 0, 0, 16},
	{CMD, 0x02, 0x03, 0, 1, 7},
	{FWHDR, 0, 0, 0, 0, 64},
	{PART, 0, 0, 0, 0, 2020},
	{PART, 0, 0, 0, 0, 2020},
	{PART, 0, 0, 0, 0, 333},
	{HW, 0, 0, 0, 0, 3},
	{CMD, 0x3f, 0xff, 1, 1, 0},
	{HW, 0, 0, 0, 0, 7},
	{CMD, 0x05, 0x01, 0, 0, 4},
	{CMD, 0x05, 0x02, 0, 0, 1},
	{HW, 0, 0, 0, 0, 9},
	{FILL, 0x08, 0, 0, 0, 0},
	{HW_ALL, 0, 0, 0, 0, 0},
	{CMD, 0x01, 0x02, 0, 0, 12},
	{CMD, 0x0c, 0x20, 0, 0, 8},
};
static void send_one(struct rtw89_dev *dev, u32 sent, enum op op, u8 class, u8 func,
		     bool rack, bool dack, u32 len, int *ret_out)
{
	struct rtw89_pci *p = pci_of(dev);
	struct rtw89_pci_tx_ring *tx = &p->tx.rings[RTW89_TXCH_CH12];
	struct sk_buff *skb = op == PART ? rtw89_fw_h2c_alloc_skb_no_hdr(dev, len) :
					   rtw89_fw_h2c_alloc_skb_with_hdr(dev, len);
	for (u32 k = 0; k < len; k++) {
		u8 byte = (k * 7 + sent * 13 + 1) & 0xff;
		skb_put_data(skb, &byte, 1);
	}
	if (op == CMD)
		rtw89_h2c_pkt_set_hdr(dev, skb, FWCMD_TYPE_H2C, H2C_CAT_MAC, class, func, rack, dack, len);
	else if (op == FWHDR)
		rtw89_h2c_pkt_set_hdr_fwdl(dev, skb, FWCMD_TYPE_H2C, H2C_CAT_MAC, H2C_CL_MAC_FWDL,
					   H2C_FUNC_MAC_FWHDR_DL, len);
	u32 wp = tx->bd_ring.wp;
	unmaps = 0;
	int ret = rtw89_h2c_tx(dev, skb, op == PART);
	for (u32 u = 0; u < unmaps; u++)
		record(60, unmap_log[0][u], unmap_log[1][u]);
	record(11, 0, (u32)ret);
	if (!ret) {
		struct rtw89_pci_tx_bd_32 *bd = (struct rtw89_pci_tx_bd_32 *)tx->bd_ring.head + wp;
		struct sk_buff *queued = p->h2c_queue.prev;
		if (queued != skb)
			abort();
		record(122, wp, bd->length | (u32)bd->opt << 16);
		record(123, bd->dma, skb->len);
		for (u32 k = 0; k < (skb->len + 3) / 4; k++) {
			u32 v = 0;
			for (u32 b = 0; b < 4 && 4 * k + b < skb->len; b++)
				v |= (u32)skb->data[4 * k + b] << (8 * b);
			record(124, k, v);
		}
	} else {
		dev_kfree_skb_any(skb);
	}
	record(126, skb_queue_len(&p->h2c_queue), skb_queue_len(&p->h2c_release_queue));
	record(127, dev->fw.h2c_seq, 0);
	*ret_out = ret;
}
static void send(FILE *out)
{
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci *p = pci_of(dev);
	struct rtw89_pci_tx_ring *tx = &p->tx.rings[RTW89_TXCH_CH12];
	tx->bd_ring.head = calloc(RTW89_PCI_TXBD_NUM_MAX, sizeof(struct rtw89_pci_tx_bd_32));
	if (!tx->bd_ring.head)
		abort();
	tx->bd_ring.len = RTW89_PCI_TXBD_NUM_MAX;
	tx->bd_ring.addr = rtw89_pci_ch_dma_addr_set.tx[RTW89_TXCH_CH12];
	tx->txch = RTW89_TXCH_CH12;
	memset(memory, 0, sizeof(memory));
	maps = 0;
	u32 sent = 0;
	for (size_t s = 0; s < ARRAY_SIZE(script); s++) {
		int ret;
		switch (script[s].op) {
		case HW:
		case HW_ALL: {
			u32 idx = script[s].op == HW ? script[s].len : tx->bd_ring.wp;
			set(tx->bd_ring.addr.idx + 2, 2, idx);
			record(125, idx, 0);
			break;
		}
		case FILL:
			for (u32 n = 0;; n++) {
				if (n > RTW89_PCI_TXBD_NUM_MAX)
					abort();
				send_one(dev, sent++, CMD, script[s].class, n & 0xff, 0, 0, 0, &ret);
				if (ret)
					break;
			}
			break;
		default:
			send_one(dev, sent++, script[s].op, script[s].class, script[s].func,
				 script[s].rack, script[s].dack, script[s].len, &ret);
			if (ret)
				abort();
		}
	}
	flush(out);
	free(tx->bd_ring.head);
	free_dev(dev);
}
static const struct {
	u8 pkt_type, long_rxd, drv_info, shift, mac_info, pad;
	u32 w0, w1, w2;
	u16 pkt_size;
} c2h_cases[] = {
	{10, 0, 0, 0, 0, 0, 0x001, 12, 0x002a000d, 12},
	{10, 0, 0, 0, 0, 0, 0x101, 12, 0x55000309, 12},
	{10, 0, 0, 0, 0, 4, 0x101, 12, 0xff7f1725, 16},
	{10, 1, 2, 0, 1, 0, 0xab000001, 0xc00c, 0xff80ffff, 12},
	{10, 0, 7, 3, 0, 3, 0x001, 20, 0x00ff0705, 20},
	{10, 0, 0, 0, 0, 0, 0x201, 40, 0x01020304, 40},
	{10, 0, 0, 0, 0, 0, 0x401, 16, 0x0000000d, 16},
	{10, 0, 0, 0, 0, 0, 0x701, 12, 0x0000000d, 12},
	{10, 0, 0, 0, 0, 0, 0x205, 24, 0x0000000d, 24},
	{10, 0, 0, 0, 0, 0, 0x905, 32, 0x00000000, 32},
	{10, 0, 0, 0, 0, 0, 0x015, 12, 0x0011000d, 12},
	{10, 0, 0, 0, 0, 0, 0x0fd, 12, 0x0011000d, 12},
	{10, 0, 0, 0, 0, 0, 0x000, 12, 0x0011000d, 12},
	{10, 0, 0, 0, 0, 0, 0x002, 12, 0x0011000d, 12},
	{10, 0, 0, 0, 0, 0, 0x142, 12, 0x0011000d, 12},
	{10, 0, 0, 0, 0, 0, 0x003, 12, 0x0011000d, 12},
	{10, 0, 0, 0, 0, 0, 0x001, 0, 0x0042000d, 12},
	{10, 0, 0, 0, 0, 0, 0x06d, 12, 0x0011000d, 12},
	{0, 0, 0, 0, 0, 0, 0x001, 12, 0x0011000d, 64},
	{1, 0, 0, 0, 1, 0, 0x001, 12, 0x0011000d, 48},
	{6, 0, 1, 0, 0, 0, 0x001, 12, 0x0011000d, 16},
	{15, 1, 0, 0, 0, 2, 0x001, 12, 0x0011000d, 20},
	{10, 0, 0, 0, 0, 9, 0x001, 12, 0x0001080d, 12},
	{10, 0, 0, 0, 0, 0, 0xffff0101, 0xffffc00c, 0xffffffff, 12},
	{10, 1, 1, 0, 0, 0, 0x201, 2000, 0x00000000, 2000},
};
static u32 build(size_t c, u8 *buffer, u32 *info)
{
	u32 rxd_len = c2h_cases[c].long_rxd ? 32 : 16, at = 4;
	u32 dword0 = c2h_cases[c].pkt_size | (u32)c2h_cases[c].shift << 14 |
		     (u32)c2h_cases[c].mac_info << 23 | (u32)c2h_cases[c].pkt_type << 24 |
		     (u32)c2h_cases[c].drv_info << 28 | (u32)c2h_cases[c].long_rxd << 31;
	memcpy(buffer + at, &dword0, 4);
	for (u32 k = 1; k < rxd_len / 4; k++) {
		u32 v = 0xa5a50000 | k;
		memcpy(buffer + at + 4 * k, &v, 4);
	}
	at += rxd_len;
	for (u32 k = 0; k < 8u * c2h_cases[c].drv_info; k++)
		buffer[at++] = (k * 17 + 3) & 0xff;
	u32 words[3] = {c2h_cases[c].w0, c2h_cases[c].w1, c2h_cases[c].w2};
	for (u32 k = 0; k < c2h_cases[c].pkt_size; k++)
		buffer[at++] = k < 12 ? (words[k / 4] >> (8 * (k % 4))) & 0xff : (k * 31 + 5) & 0xff;
	for (u32 k = 0; k < c2h_cases[c].pad; k++)
		buffer[at++] = 0xee;
	*info = RTW89_PCI_RXBD_FS | RTW89_PCI_RXBD_LS | at | (u32)(c + 1) << 16;
	memcpy(buffer, info, 4);
	return at;
}
void rtw89_core_rx(struct rtw89_dev *rtwdev, struct rtw89_rx_desc_info *desc_info,
		   struct sk_buff *skb)
{
	record(130, desc_info->pkt_type, desc_info->pkt_size);
	record(131, desc_info->drv_info_size | desc_info->long_rxdesc << 8 |
		    desc_info->mac_info_valid << 9, desc_info->offset | (u32)desc_info->rxd_len << 16);
	if (desc_info->pkt_type != RTW89_CORE_RX_TYPE_C2H) {
		record(132, desc_info->pkt_type, 0);
		if (desc_info->pkt_type == RTW89_CORE_RX_TYPE_WIFI)
			dev_kfree_skb_any(skb);
		else
			rtw89_core_rx_process_report(rtwdev, desc_info, skb);
		return;
	}
	record(133, skb->len, 0);
	for (u32 k = 0; k < (skb->len + 3) / 4; k++) {
		u32 v = 0;
		for (u32 b = 0; b < 4 && 4 * k + b < skb->len; b++)
			v |= (u32)skb->data[4 * k + b] << (8 * b);
		record(134, k, v);
	}
	rtw89_fw_c2h_parse_attr(skb);
	struct rtw89_fw_c2h_attr *attr = RTW89_SKB_C2H_CB(skb);
	record(137, attr->category | attr->class << 8 | attr->func << 16, attr->len);
	u32 before = acks;
	rtw89_core_rx_process_report(rtwdev, desc_info, skb);
	struct sk_buff *queued;
	while ((queued = skb_dequeue(&rtwdev->c2h_queue))) {
		rtw89_fw_c2h_cmd_handle(rtwdev, queued);
		dev_kfree_skb_any(queued);
	}
	if (acks == before)
		record(138, 0, 0);
}
static void c2h(FILE *out)
{
	struct rtw89_dev *dev = new_dev();
	struct rtw89_pci_rx_ring *ring = &pci_of(dev)->rx.rings[RTW89_RXCH_RXQ];
	ring->bd_ring.len = RTW89_PCI_RXBD_NUM_MAX;
	for (size_t c = 0; c < ARRAY_SIZE(c2h_cases); c++) {
		struct sk_buff *rx = dev_alloc_skb(RTW89_PCI_RX_BUF_SIZE);
		u32 info;
		build(c, rx->data, &info);
		RTW89_PCI_RX_SKB_CB(rx)->dma = 0x90000000;
		ring->buf[0] = rx;
		ring->bd_ring.wp = 0;
		if (rtw89_pci_rxbd_deliver_skbs(dev, ring) != 1 || ring->diliver_skb ||
		    ring->diliver_desc.ready)
			abort();
		dev_kfree_skb_any(rx);
	}
	flush(out);
	free_dev(dev);
}
int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();
	headers(out);
	txwd(out);
	send(out);
	c2h(out);
	if (fclose(out))
		abort();
	free(segment);
	printf("%zu\n", 600 + 18 + ARRAY_SIZE(script) + ARRAY_SIZE(c2h_cases));
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, pci_h_defines, rxbd_defines, txwd_defines, rxd_defines, h2c_defines,
        c2h_defines, core_defines, declarations, pci_declarations, harness, core_h_inlines,
        pci_h_inlines, dma_addr_set, core_c, pci_c, handler_stubs, mac_acks, '\n\n'.join(tables_c),
        mac_c, fw_c, tables, main_c])
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
        case_order='600 rtw89_h2c_pkt_set_hdr / rtw89_h2c_pkt_set_hdr_fwdl headers; '
                   '10 firmware-command TXWD bodies then 8 rtw89_core_fill_txdesc bodies; '
                   'rtw89_h2c_tx over a 16-step CH12 script; '
                   '25 rtw89_pci_rxbd_deliver_skbs packets on RXQ',
        dispatch=dict(rtw8852b_chip_info=chip, rtw8852b_chip_ops=chip_ops,
                      rtw8852b_pci_info=pci_info, rtw89_pci_ops=hci_ops,
                      mac_c2h_handler_stubs=handlers),
        dma=dict(command_buffers='0x80600000 + 0x3000 * n', rx_buffer='0x90000000'),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, DMA addresses, skbs and every packet are a model; no physical evidence and '
            'no firmware answered anything',
            'PCIe RTL8852BE only: rtw8852b_chip_info and rtw8852b_pci_info',
            'the data path behind rtw89_core_tx_update_desc_info, the WD-page and paused-HCI '
            'paths, and rtw89_core_rx\'s 802.11 path are stubs an H2C or C2H never reaches',
            'RTW89_PCI_TX_SKB_CB is the skb control buffer',
            'every MAC C2H handler but REC_ACK and DONE_ACK, the PHY and BTC C2H entries, '
            'rtw89_mac_c2h_scanofld_rsp_atomic and rtw89_complete_cond are stubs; the acks\' '
            'decoded fields are their rtw89_debug arguments',
            'skbs have exactly the room reserved and allocated, so rtw89_skb_put_rx_data copies '
            'RPKT_LEN bytes when more were written',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
