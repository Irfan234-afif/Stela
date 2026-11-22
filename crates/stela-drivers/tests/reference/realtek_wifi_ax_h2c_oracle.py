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

station.bin and station.json are a second trace and its receipt: a station's
role, join, address CAM, CMAC table, MAC ID pause and security CAM H2C, and
its port registers, as station_oracle below describes. trace.bin and
manifest.json do not change with them.
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
    station_oracle(reference, out)
    return 0


def station_oracle(reference, out):
    """Unchanged pinned rtw89 for a PCIe RTL8852B station's H2C and port.

    Extracted unchanged, each with its SHA-256 in station.json:

    - mac.c: rtw89_mac_vif_init and rtw89_mac_vif_deinit,
      rtw89_mac_port_update with every rtw89_mac_port_cfg_* step and
      rtw89_port_base_ax, rtw89_mac_dmac_tbl_init, rtw89_mac_cmac_tbl_init,
      rtw89_mac_set_macid_pause and rtw89_mac_check_mac_en_ax;
    - fw.c: rtw89_fw_h2c_role_maintain, rtw89_fw_h2c_join_info,
      rtw89_fw_h2c_cam, rtw89_fw_h2c_default_cmac_tbl with
      __rtw89_fw_h2c_set_tx_path, rtw89_fw_h2c_assoc_cmac_tbl with
      __get_sta_he_pkt_padding, rtw89_fw_h2c_txtime_cmac_tbl,
      rtw89_fw_h2c_macid_pause, rtw89_h2c_pkt_set_hdr and the H2C skb
      allocation;
    - cam.c: the address, BSSID and security CAM paths a station reaches,
      from rtw89_cam_sec_key_add and rtw89_cam_sec_key_del down to
      rtw89_cam_send_sec_key_cmd and rtw89_cam_fill_addr_cam_info;
    - core.c: rtw89_vif_type_mapping, rtw89_core_sta_link_assoc with
      rtw89_sta_link_can_er, and rtw89_core_sta_link_disconnect;
    - the reg.h, core.h, mac.h, fw.h and cam.h declarations, inlines and
      definitions they use.

    rtw8852b_chip_info, rtw8852b_chip_ops and rtw89_mac_gen_ax give the
    members the harness's tables take, and RTL8852B's firmware feature rows
    are checked to name neither ADDR_CAM_V0 nor MACID_PAUSE_SLEEP. Compiled
    with clang under ASan and UBSan against a harness that models MAC
    registers as bytes and skbs with exactly the room reserved.

    Harness stand-ins: the mac80211 and rtw89 structures as the members the
    functions reach (one station link and its AP, whose MAC ID is the
    link's); the include/linux/ieee80211.h constants; rtw89_h2c_tx, which
    records the skb's length and the sequence (40) and its bytes as
    little-endian words (41), then takes it or refuses it with -ENOSPC;
    msleep and fsleep (9, microseconds); rtw89_mac_port_tsf_resync_all,
    which with no AP link touches nothing; and stubs for what a station's
    association reaches beyond these H2C, of which rtw89_phy_ra_assoc (70),
    rtw89_mac_bf_assoc (71), rtw89_fw_h2c_general_pkt (72),
    rtw89_fw_h2c_set_bcn_fltr_cfg (73) and rtw89_mac_bf_disassoc (74)
    leave a mark. The harness's steps stand where mac80211.c's callers
    would: BSS_CHANGED_BSSID as rtw89_ops_link_info_changed handles it, and
    __rtw89_ops_bss_link_assoc's rtw89_mac_port_update.

    Four segments, each prefixed by its byte length, of records of three
    little-endian u32 (tag, a, b): register reads by width, writes by 4
    plus width, delays, H2C and marks as above, each step's return (50) and
    each key's hw_key_idx (61):

    1. zeroed registers, CMAC0 on, MAC ID 0 on port 0 from sequence 0:
       interface up, BSSID set, association to an HE AP on 5 GHz with its
       port update, a CCMP pairwise key, a CCMP group key, a TKIP group key
       (refused), a second CCMP group key, the first group key, the
       pairwise key and the second group key deleted, the disconnect, the
       BSSID cleared and the interface down;
    2. all-ones registers, MAC ID 37 on port 1 from sequence 0xfe:
       interface up over a port already on, two TX-time tables, MAC ID 37
       paused, association to a non-HE AP on 2.4 GHz, a pairwise key
       refused by rtw89_h2c_tx then taken, and the interface down refused;
    3. CMAC0 reading RTW89_R32_DEAD: interface up;
    4. association CMAC tables for nine HE capabilities and none.
    """
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

    def in_order(file, names):
        return '\n\n'.join(body for _, body in sorted(locate(file, n) for n in names))

    def prototype(file, name):
        """A declaration ending in ');', from the start of its line."""
        text = source(file)
        for m in re.finditer(r'\b' + re.escape(name) + r'\(', text):
            end, depth = m.end(), 1
            while depth:
                depth += (text[end] == '(') - (text[end] == ')')
                end += 1
            if text[end] == ';':
                start = text.rfind('\n', 0, m.start()) + 1
                return record(file, 'declaration ' + name, text[start:end + 1])
        raise ValueError(f'{file}: no declaration of {name}')

    def declaration(file, kind, name):
        text = source(file)
        m = re.search(r'^' + kind + r' ' + re.escape(name) + r' \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {kind} {name}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, f'{kind} {name}', text[m.start():end])

    def definition(file, head):
        text = source(file)
        m = re.search(r'^' + re.escape(head) + r' = \{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {head}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, head, text[m.start():end])

    def defines(file, names):
        text = source(file)
        lines = []
        for name in names:
            found = re.findall(r'^#define\s+' + re.escape(name) + r'\b[^\n]*$', text, re.M)
            if len(found) != 1:
                raise ValueError(f'{file}: #define {name} appears {len(found)} times')
            lines.append(found[0])
        return record(file, f'#define {" ".join(names)}', '\n'.join(lines))

    def block(file, first, before, name):
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n' + before, start) + 1
        return record(file, name, text[start:end])

    def fields(file, head, names):
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

    features = [line for line in source('fw.c').splitlines()
                if line.strip().startswith('__CFG_FW_FEAT(RTL8852B,')]
    if not features or any('ADDR_CAM_V0' in f or 'MACID_PAUSE_SLEEP' in f for f in features):
        raise ValueError(f'RTL8852B firmware features: {features}')
    record('fw.c', 'RTL8852B feature rows', '\n'.join(features))

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    enums = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_core_chip_id', 'rtw89_chip_gen', 'rtw89_net_type', 'rtw89_wifi_role',
            'rtw89_upd_mode', 'rtw89_self_role', 'rtw89_msk_sO_el', 'rtw89_add_cam_sec_mode',
            'rtw89_sec_key_type', 'rtw89_port', 'rtw89_band', 'rtw89_hw_rate', 'rtw89_mac_idx',
            'rtw89_phy_idx', 'rtw89_chanctx_idx', 'rtw89_rf_path_bit', 'rtw89_bandwidth',
            'rtw89_pe_duration', 'rtw89_flags']]
        + [declaration('mac.h', 'enum', 'rtw89_mac_hwmod_sel')])
    core_defines = defines('core.h', [
        'RTW89_R32_EA', 'RTW89_R32_DEAD', 'RTW89_SEC_CAM_IN_ADDR_CAM', 'RTW89_MAX_ADDR_CAM_NUM',
        'RTW89_MAX_BSSID_CAM_NUM', 'RTW89_MAX_SEC_CAM_NUM', 'RTW89_PPE_BW_NUM'])
    mac_defines = defines('mac.h', [
        'ADDR_CAM_ENT_SIZE', 'ADDR_CAM_ENT_SHORT_SIZE', 'BSSID_CAM_ENT_SIZE',
        'R_AX_INDIR_ACCESS_ENTRY', 'DMAC_TBL_BASE_ADDR', 'CMAC_TBL_BASE_ADDR', 'CCTL_INFO_SIZE',
        'RTW89_MAC_AX_BAND_REG_OFFSET'])
    mac_c_defines = defines('mac.c', [
        'BCN_INTERVAL', 'BCN_ERLY_DEF', 'BCN_SETUP_DEF', 'BCN_HOLD_DEF', 'BCN_MASK_DEF',
        'TBTT_ERLY_DEF', 'TBTT_AGG_DEF', 'BCN_ERLY_SET_DLY'])
    h2c_defines = block('fw.h', '#define H2C_HEADER_LEN', '/* CLASS 10 - Security CAM */',
                        'H2C_HEADER_LEN to CLASS 10')
    sec_defines = defines('fw.h', ['H2C_SEC_CAM_LEN', 'H2C_CL_MAC_SEC_CAM',
                                   'H2C_FUNC_MAC_SEC_UPD'])
    fw_c_defines = defines('fw.c', ['H2C_CMC_TBL_LEN'])
    structs = '\n\n'.join([
        declaration('core.h', 'struct', 'rtw89_txwd_body'),
        declaration('core.h', 'struct', 'rtw89_port_reg'),
        declaration('core.h', 'struct', 'rtw89_addr_cam_entry'),
        declaration('core.h', 'struct', 'rtw89_bssid_cam_entry'),
        declaration('core.h', 'struct', 'rtw89_sec_cam_entry'),
        declaration('fw.h', 'struct', 'fwcmd_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_macid_pause_grp'),
        declaration('fw.h', 'struct', 'rtw89_fw_macid_pause_sleep_grp'),
        block('fw.h', 'struct rtw89_h2c_role_maintain {', 'struct rtw89_h2c_notify_dbcc {',
              'struct rtw89_h2c_role_maintain to struct rtw89_h2c_notify_dbcc'),
        block('cam.h', '#define RTW89_SEC_CAM_LEN', 'struct rtw89_h2c_dctlinfo_ud_v1 {',
              'RTW89_SEC_CAM_LEN to struct rtw89_h2c_dctlinfo_ud_v1'),
    ])
    prototypes = '\n'.join(
        [prototype('fw.h', name) for name in [
            'rtw89_fw_h2c_alloc_skb_with_hdr', 'rtw89_h2c_pkt_set_hdr', 'rtw89_fw_h2c_cam',
            'rtw89_fw_h2c_role_maintain', 'rtw89_fw_h2c_join_info',
            'rtw89_fw_h2c_default_cmac_tbl', 'rtw89_fw_h2c_assoc_cmac_tbl',
            'rtw89_fw_h2c_txtime_cmac_tbl', 'rtw89_fw_h2c_macid_pause']]
        + [prototype('cam.h', name) for name in [
            'rtw89_cam_init', 'rtw89_cam_deinit', 'rtw89_cam_fill_addr_cam_info',
            'rtw89_cam_fill_bssid_cam_info']]
        + [prototype('mac.h', name) for name in [
            'rtw89_mac_port_update', 'rtw89_mac_set_macid_pause']])
    core_h_inlines = '\n\n'.join(locate('core.h', name)[1] for name in [
        'rtw89_read32_mask', 'rtw89_write32_mask', 'rtw89_write16_mask', 'rtw89_write32_set',
        'rtw89_write32_clr', 'rtw89_write8_set', 'rtw89_write16_clr', 'rtw89_get_addr_cam_of',
        'rtw89_get_bssid_cam_of', 'rtw89_chip_h2c_dctl_sec_cam'])
    mac_h_inlines = '\n\n'.join(locate('mac.h', name)[1] for name in [
        'rtw89_mac_reg_by_idx', 'rtw89_mac_reg_by_port', 'rtw89_read32_port',
        'rtw89_read32_port_mask', 'rtw89_write32_port', 'rtw89_write32_port_mask',
        'rtw89_write16_port_mask', 'rtw89_write32_port_clr', 'rtw89_write16_port_clr',
        'rtw89_write32_port_set', 'rtw89_mac_check_mac_en'])
    fw_h_inlines = '\n\n'.join([
        block('fw.h', 'static inline void SET_CTRL_INFO_MACID', '#define SET_CMC_TBL_MASK_CSI_BW',
              'SET_CTRL_INFO_MACID to SET_CMC_TBL_MASK_CSI_BW'),
        block('fw.h', 'static inline void RTW89_SET_FWCMD_SEC_IDX',
              'static inline void RTW89_SET_EDCA_SEL',
              'RTW89_SET_FWCMD_SEC_IDX to RTW89_SET_EDCA_SEL'),
        '\n\n'.join(locate('fw.h', name)[1] for name in [
            'rtw89_chip_h2c_default_cmac_tbl', 'rtw89_chip_h2c_default_dmac_tbl',
            'rtw89_chip_h2c_assoc_cmac_tbl'])])
    port_base = definition('mac.c', 'static const struct rtw89_port_reg rtw89_port_base_ax')
    mac_c = in_order('mac.c', [
        'rtw89_mac_check_mac_en_ax', 'rtw89_mac_dmac_tbl_init', 'rtw89_mac_cmac_tbl_init',
        'rtw89_mac_port_cfg_func_sw', 'rtw89_mac_port_cfg_tx_rpt', 'rtw89_mac_port_cfg_rx_rpt',
        'rtw89_mac_port_cfg_net_type', 'rtw89_mac_port_cfg_bcn_prct', 'rtw89_mac_port_cfg_rx_sw',
        'rtw89_mac_port_cfg_rx_sync', 'rtw89_mac_port_cfg_rx_sync_by_nettype',
        'rtw89_mac_port_cfg_tx_sw', 'rtw89_mac_port_cfg_tx_sw_by_nettype',
        'rtw89_mac_port_cfg_bcn_intv', 'rtw89_mac_port_cfg_hiq_win',
        'rtw89_mac_port_cfg_hiq_dtim', 'rtw89_mac_port_cfg_bcn_setup_time',
        'rtw89_mac_port_cfg_bcn_hold_time', 'rtw89_mac_port_cfg_bcn_mask_area',
        'rtw89_mac_port_cfg_tbtt_early', 'rtw89_mac_port_cfg_tbtt_agg',
        'rtw89_mac_port_cfg_bss_color', 'rtw89_mac_port_cfg_mbssid',
        'rtw89_mac_port_cfg_hiq_drop', 'rtw89_mac_port_cfg_func_en',
        'rtw89_mac_port_cfg_bcn_early', 'rtw89_mac_port_cfg_bcn_psr_rpt',
        'rtw89_mac_port_update', 'rtw89_mac_vif_init', 'rtw89_mac_vif_deinit',
        'rtw89_mac_set_macid_pause'])
    fw_c = in_order('fw.c', [
        'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr', 'rtw89_h2c_pkt_set_hdr',
        'rtw89_fw_h2c_cam', '__rtw89_fw_h2c_set_tx_path', 'rtw89_fw_h2c_default_cmac_tbl',
        '__get_sta_he_pkt_padding', 'rtw89_fw_h2c_assoc_cmac_tbl',
        'rtw89_fw_h2c_txtime_cmac_tbl', 'rtw89_fw_h2c_role_maintain', 'rtw89_fw_h2c_join_info',
        'rtw89_fw_h2c_macid_pause'])
    cam_c = in_order('cam.c', [
        'rtw89_cam_get_sec_key_cmd', 'rtw89_cam_send_sec_key_cmd', 'rtw89_cam_get_avail_sec_cam',
        'rtw89_cam_get_addr_cam_key_idx', '__rtw89_cam_detach_sec_cam',
        '__rtw89_cam_attach_sec_cam', 'rtw89_cam_detach_sec_cam', 'rtw89_cam_attach_sec_cam',
        'rtw89_cam_sec_key_install', 'rtw89_cam_sec_key_add', 'rtw89_cam_sec_key_del',
        'rtw89_cam_deinit_addr_cam', 'rtw89_cam_deinit_bssid_cam', 'rtw89_cam_deinit',
        'rtw89_cam_get_avail_addr_cam', 'rtw89_get_addr_cam_entry_size',
        'rtw89_cam_init_addr_cam', 'rtw89_cam_get_avail_bssid_cam', 'rtw89_cam_init_bssid_cam',
        'rtw89_cam_bssid_changed', 'rtw89_cam_init', 'rtw89_cam_fill_bssid_cam_info',
        'rtw89_cam_addr_hash', 'rtw89_cam_fill_addr_cam_info'])
    core_c = in_order('core.c', [
        'rtw89_vif_type_mapping', 'rtw89_core_sta_link_disconnect', 'rtw89_sta_link_can_er',
        'rtw89_core_sta_link_assoc'])

    chip_names = ['chip_id', 'chip_gen', 'ops', 'mac_def', 'h2c_desc_size', 'rf_path_num',
                  'acam_num', 'bcam_num', 'scam_num', 'addrcam_ver', 'h2c_cctl_func_id',
                  'hw_sec_hdr', 'hw_mgmt_tx_encrypt', 'hw_tkip_crypto', 'hw_mlo_bmc_crypto']
    chip = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info', chip_names)
    if chip['ops'] != '&rtw8852b_chip_ops' or chip['mac_def'] != '&rtw89_mac_gen_ax':
        raise ValueError(f'rtw8852b_chip_info is {chip}')
    ops_names = ['h2c_dctl_sec_cam', 'h2c_default_cmac_tbl', 'h2c_assoc_cmac_tbl',
                 'h2c_txtime_cmac_tbl', 'h2c_default_dmac_tbl']
    chip_ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                      ops_names)
    if chip_ops != {'h2c_dctl_sec_cam': 'NULL',
                    'h2c_default_cmac_tbl': 'rtw89_fw_h2c_default_cmac_tbl',
                    'h2c_assoc_cmac_tbl': 'rtw89_fw_h2c_assoc_cmac_tbl',
                    'h2c_txtime_cmac_tbl': 'rtw89_fw_h2c_txtime_cmac_tbl',
                    'h2c_default_dmac_tbl': 'NULL'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops}')
    gen = fields('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax',
                 ['band1_offset', 'port_base', 'check_mac_en'])
    if gen['port_base'] != '&rtw89_port_base_ax' or \
            gen['check_mac_en'] != 'rtw89_mac_check_mac_en_ax':
        raise ValueError(f'rtw89_mac_gen_ax is {gen}')
    chip_init = ',\n'.join(f'\t.{k} = {chip[k]}' for k in chip_names)
    ops_init = ',\n'.join(f'\t.{k} = {chip_ops[k]}' for k in ops_names)
    gen_init = ',\n'.join(f'\t.{k} = {gen[k]}' for k in ['band1_offset', 'port_base',
                                                         'check_mac_en'])

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
typedef int8_t s8; typedef uint16_t __le16; typedef uint32_t __le32;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __packed __attribute__((packed))
#define unlikely(x) (x)
#define EXPORT_SYMBOL(...)
#define WARN(c, ...) ((void)(c))
#define WARN_ON(c) ((void)(c))
#define __ffs(m) ((u32)__builtin_ctzl(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define le32_encode_bits(v, m) ((__le32)FIELD_PREP(m, v))
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
static inline void le32p_replace_bits(__le32 *p, u32 v, u32 m) { *p = (*p & ~m) | FIELD_PREP(m, v); }
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define hweight8(v) ((u8)__builtin_popcount((u8)(v)))
#define ETH_ALEN 6
#define U8_MAX 0xff
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define kzalloc_obj(x) calloc(1, sizeof(x))
#define kfree free
static void ether_addr_copy(u8 *d, const u8 *s) { memcpy(d, s, ETH_ALEN); }
static int test_bit(unsigned long nr, const unsigned long *map) { return (map[nr / 64] >> (nr % 64)) & 1; }
static void set_bit(unsigned long nr, unsigned long *map) { map[nr / 64] |= 1UL << (nr % 64); }
static void clear_bit(unsigned long nr, unsigned long *map) { map[nr / 64] &= ~(1UL << (nr % 64)); }
static unsigned long find_next_zero_bit(const unsigned long *map, unsigned long size,
					unsigned long offset)
{
	for (; offset < size; offset++)
		if (!test_bit(offset, map))
			return offset;
	return size;
}
#define find_first_zero_bit(map, size) find_next_zero_bit(map, size, 0)
static unsigned long find_next_bit(const unsigned long *map, unsigned long size,
				   unsigned long offset)
{
	for (; offset < size; offset++)
		if (test_bit(offset, map))
			return offset;
	return size;
}
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), 0); (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
static void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
	memset(dst, 0, (nbits + 63) / 64 * sizeof(unsigned long));
}
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), sink(__VA_ARGS__))
#define RTW89_DBG_FW BIT(12)
/* RTL8852B's firmware rows name neither feature the station H2C ask about
 * (checked by the script). */
#define RTW89_CHK_FW_FEATURE(feature, fw) false
'''
    harness = r'''
/* include/linux/ieee80211.h, include/uapi/linux/nl80211.h. */
#define IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT 0x80
#define IEEE80211_HE_PHY_CAP9_NOMINAL_PKT_PADDING_MASK 0xc0
#define IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK 0x78
#define IEEE80211_PPE_THRES_INFO_PPET_SIZE 3
#define IEEE80211_PPE_THRES_NSS_MASK 7
#define IEEE80211_HE_PPE_THRES_MAX_LEN 25
#define IEEE80211_HE_OPERATION_ER_SU_DISABLE 0x00010000
#define IEEE80211_EML_CAP_EML_PADDING_DELAY_256US 4
#define IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY_256US 5
#define WLAN_CIPHER_SUITE_WEP40 0x000FAC01
#define WLAN_CIPHER_SUITE_TKIP 0x000FAC02
#define WLAN_CIPHER_SUITE_CCMP 0x000FAC04
#define WLAN_CIPHER_SUITE_WEP104 0x000FAC05
#define WLAN_CIPHER_SUITE_AES_CMAC 0x000FAC06
#define WLAN_CIPHER_SUITE_GCMP 0x000FAC08
#define WLAN_CIPHER_SUITE_GCMP_256 0x000FAC09
#define WLAN_CIPHER_SUITE_CCMP_256 0x000FAC0A
#define IEEE80211_KEY_FLAG_GENERATE_IV BIT(1)
#define IEEE80211_KEY_FLAG_GENERATE_MMIC BIT(2)
#define IEEE80211_KEY_FLAG_PAIRWISE BIT(3)
#define IEEE80211_KEY_FLAG_SW_MGMT_TX BIT(4)
enum nl80211_iftype {
	NL80211_IFTYPE_UNSPECIFIED, NL80211_IFTYPE_ADHOC, NL80211_IFTYPE_STATION,
	NL80211_IFTYPE_AP, NL80211_IFTYPE_AP_VLAN, NL80211_IFTYPE_WDS, NL80211_IFTYPE_MONITOR,
	NL80211_IFTYPE_MESH_POINT,
};
struct ieee80211_he_cap_elem { u8 mac_cap_info[6]; u8 phy_cap_info[11]; };
struct ieee80211_sta_he_cap {
	bool has_he;
	struct ieee80211_he_cap_elem he_cap_elem;
	u8 ppe_thres[IEEE80211_HE_PPE_THRES_MAX_LEN];
};
struct ieee80211_link_sta {
	u8 addr[ETH_ALEN];
	u8 rx_nss;
	struct ieee80211_sta_he_cap he_cap;
	struct { bool vht_supported; } vht_cap;
	struct { bool has_eht; } eht_cap;
};
struct ieee80211_sta { u16 aid; bool tdls; void *drv_priv; };
struct ieee80211_bss_conf {
	u8 addr[ETH_ALEN];
	u16 beacon_int;
	u8 dtim_period;
	struct { u8 color; } he_bss_color;
	bool nontransmitted;
	u8 bssid_index;
	bool he_support;
	struct { u32 params; } he_oper;
};
struct ieee80211_vif {
	enum nl80211_iftype type;
	bool p2p;
	struct { u16 aid; } cfg;
	void *drv_priv;
};
struct ieee80211_key_conf {
	u32 cipher;
	u8 hw_key_idx;
	u16 flags;
	int link_id;
	s8 keyidx;
	u8 keylen;
	u8 key[32];
};

/* The members of rtw89's structures the extracted functions reach. */
struct rtw89_dev;
struct rtw89_vif;
struct rtw89_sta;
struct rtw89_vif_link {
	struct rtw89_vif *rtwvif;
	u8 mac_id;
	u8 port;
	u8 mac_addr[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	u8 phy_idx;
	u8 mac_idx;
	u8 net_type;
	u8 wifi_role;
	u8 self_role;
	u8 wmm;
	u8 bcn_hit_cond;
	u8 hit_rule;
	bool trigger;
	bool lsig_txop;
	u8 tgt_ind;
	u8 frm_tgt_ind;
	bool wowlan_pattern;
	bool wowlan_uc;
	bool wowlan_magic;
	enum rtw89_chanctx_idx chanctx_idx;
	struct rtw89_addr_cam_entry addr_cam;
	struct rtw89_bssid_cam_entry bssid_cam;
};
struct rtw89_sta_link {
	struct rtw89_sta *rtwsta;
	struct rtw89_vif_link *rtwvif_link;
	u8 mac_id;
	bool er_cap;
	u32 htc_template;
	u8 tx_retry;
	bool cctl_tx_time;
	u32 ampdu_max_time : 4;
	bool cctl_tx_retry_limit;
	u32 data_tx_cnt_lmt : 6;
	struct rtw89_addr_cam_entry addr_cam;
	struct rtw89_bssid_cam_entry bssid_cam;
};
struct rtw89_vif {
	struct rtw89_vif_link *links[1];
	struct ieee80211_vif *vif;
	struct ieee80211_bss_conf *bss_conf;
};
struct rtw89_sta {
	struct rtw89_sta_link *links[1];
	struct ieee80211_sta *sta;
	struct ieee80211_link_sta *link_sta;
	DECLARE_BITMAP(pairwise_sec_cam_map, RTW89_MAX_SEC_CAM_NUM);
};
#define vif_to_rtwvif(v) ((struct rtw89_vif *)(v)->drv_priv)
#define sta_to_rtwsta_safe(s) ((s) ? (struct rtw89_sta *)(s)->drv_priv : NULL)
#define rtwsta_link_to_sta(l) ((l)->rtwsta->sta)
#define rtwsta_link_to_sta_safe(l) ((l) ? (l)->rtwsta->sta : NULL)
#define rtw89_sta_rcu_dereference_link(l, protect) ((l)->rtwsta->link_sta)
#define rtw89_vif_rcu_dereference_link(l, protect) ((l)->rtwvif->bss_conf)
#define rtw89_vif_for_each_link(rtwvif, link, link_id) \
	for ((link_id) = 0; (link_id) < 1; (link_id)++) \
		if (!((link) = (rtwvif)->links[link_id])) {} else
#define rtw89_sta_for_each_link(rtwsta, link, link_id) \
	for ((link_id) = 0; (link_id) < 1; (link_id)++) \
		if (!((link) = (rtwsta)->links[link_id])) {} else
static struct ieee80211_vif *rtwvif_link_to_vif(const struct rtw89_vif_link *l)
{
	return l->rtwvif->vif;
}
static bool ieee80211_vif_is_mld(const struct ieee80211_vif *vif) { (void)vif; return false; }
struct rtw89_chip_ops {
	int (*h2c_dctl_sec_cam)(struct rtw89_dev *rtwdev, struct rtw89_vif_link *rtwvif_link,
				struct rtw89_sta_link *rtwsta_link);
	int (*h2c_default_cmac_tbl)(struct rtw89_dev *rtwdev, struct rtw89_vif_link *rtwvif_link,
				    struct rtw89_sta_link *rtwsta_link);
	int (*h2c_assoc_cmac_tbl)(struct rtw89_dev *rtwdev, struct rtw89_vif_link *rtwvif_link,
				  struct rtw89_sta_link *rtwsta_link);
	int (*h2c_txtime_cmac_tbl)(struct rtw89_dev *rtwdev, struct rtw89_sta_link *rtwsta_link);
	int (*h2c_default_dmac_tbl)(struct rtw89_dev *rtwdev, struct rtw89_vif_link *rtwvif_link,
				    struct rtw89_sta_link *rtwsta_link);
};
struct rtw89_mac_gen_def {
	u32 band1_offset;
	const struct rtw89_port_reg *port_base;
	int (*check_mac_en)(struct rtw89_dev *rtwdev, u8 band, enum rtw89_mac_hwmod_sel sel);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	u32 h2c_desc_size;
	u8 rf_path_num;
	u8 acam_num;
	u8 bcam_num;
	u8 scam_num;
	u8 addrcam_ver;
	u8 h2c_cctl_func_id;
	bool hw_sec_hdr;
	bool hw_mgmt_tx_encrypt;
	bool hw_tkip_crypto;
	bool hw_mlo_bmc_crypto;
};
struct rtw89_hal { u8 antenna_tx; u8 tx_nss; };
struct rtw89_fw_secure { bool secure_boot; };
struct rtw89_cam_info {
	DECLARE_BITMAP(addr_cam_map, RTW89_MAX_ADDR_CAM_NUM);
	DECLARE_BITMAP(bssid_cam_map, RTW89_MAX_BSSID_CAM_NUM);
	DECLARE_BITMAP(sec_cam_map, RTW89_MAX_SEC_CAM_NUM);
	struct rtw89_sec_cam_entry *sec_entries[RTW89_MAX_SEC_CAM_NUM];
};
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	struct rtw89_hal hal;
	struct { bool tx_rpt_enabled; } hci;
	struct { u8 h2c_seq; struct rtw89_fw_secure sec; } fw;
	struct rtw89_cam_info cam_info;
	DECLARE_BITMAP(flags, NUM_OF_RTW89_FLAGS);
};
struct rtw89_chan { enum rtw89_band band_type; };
struct rtw89_bb_ctx { struct { u8 link_mode; } path_diff; };
static struct rtw89_chan chan;
static struct rtw89_bb_ctx bb;
static const struct rtw89_chan *rtw89_chan_get(struct rtw89_dev *d, enum rtw89_chanctx_idx i)
{
	(void)d; (void)i;
	return &chan;
}
static struct rtw89_bb_ctx *rtw89_get_bb_ctx(struct rtw89_dev *d, enum rtw89_phy_idx i)
{
	(void)d; (void)i;
	return &bb;
}

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
static void trace(u32 tag, u32 a, u32 b) { word(tag); word(a); word(b); }
static void flush(FILE *out)
{
	u32 n = segment_bytes;
	u8 length[4] = {n, n >> 8, n >> 16, n >> 24};
	if (fwrite(length, 1, 4, out) != 4 || fwrite(segment, 1, n, out) != n)
		abort();
	segment_bytes = 0;
}

/* The register model: MAC space, the indirect window included, as bytes. */
static u8 memory[0x40100];
static u32 get(u32 r, u32 n)
{
	u32 v = 0;
	if (r + n > sizeof(memory))
		abort();
	for (u32 i = 0; i < n; i++)
		v |= (u32)memory[r + i] << (8 * i);
	return v;
}
static void set(u32 r, u32 n, u32 v)
{
	if (r + n > sizeof(memory))
		abort();
	for (u32 i = 0; i < n; i++)
		memory[r + i] = v >> (8 * i);
}
static u32 model_read(u32 r, u32 n) { u32 v = get(r, n); trace(n, r, v); return v; }
static void model_write(u32 r, u32 n, u32 v) { trace(4 + n, r, v); set(r, n, v); }
static u8 rtw89_read8(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 1); }
static u16 rtw89_read16(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 2); }
static u32 rtw89_read32(struct rtw89_dev *d, u32 r) { (void)d; return model_read(r, 4); }
static void rtw89_write8(struct rtw89_dev *d, u32 r, u8 v) { (void)d; model_write(r, 1, v); }
static void rtw89_write16(struct rtw89_dev *d, u32 r, u16 v) { (void)d; model_write(r, 2, v); }
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v) { (void)d; model_write(r, 4, v); }
static void msleep(unsigned int ms) { trace(9, ms * 1000, 0); }
static void fsleep(unsigned long us) { trace(9, us, 0); }

/* skbs: headroom and tailroom exactly what was reserved and allocated. */
struct sk_buff { u8 *head, *data; u32 len, size; };
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
static void *skb_put(struct sk_buff *s, unsigned int n)
{
	if (n > skb_tailroom(s))
		abort();
	s->len += n;
	return s->data + s->len - n;
}
static void *skb_put_zero(struct sk_buff *s, unsigned int n)
{
	void *p = skb_put(s, n);
	memset(p, 0, n);
	return p;
}

/* rtw89_h2c_tx: the H2C recorded, then taken or refused. */
static int refuse;
int rtw89_h2c_tx(struct rtw89_dev *rtwdev, struct sk_buff *skb, bool fwdl)
{
	(void)fwdl;
	trace(40, skb->len, rtwdev->fw.h2c_seq);
	for (u32 i = 0; i < skb->len; i += 4) {
		u32 w = 0;
		memcpy(&w, skb->data + i, skb->len - i < 4 ? skb->len - i : 4);
		trace(41, i / 4, w);
	}
	if (refuse)
		return -ENOSPC;
	dev_kfree_skb_any(skb);
	return 0;
}

/* What a station's association reaches beyond its H2C. */
static void rtw89_phy_ra_assoc(struct rtw89_dev *d, struct rtw89_sta_link *l)
{
	(void)d; (void)l;
	trace(70, 0, 0);
}
static void rtw89_mac_bf_assoc(struct rtw89_dev *d, struct rtw89_vif_link *v,
			       struct rtw89_sta_link *l)
{
	(void)d; (void)v; (void)l;
	trace(71, 0, 0);
}
static int rtw89_fw_h2c_general_pkt(struct rtw89_dev *d, struct rtw89_vif_link *v, u8 macid)
{
	(void)d; (void)v;
	trace(72, macid, 0);
	return 0;
}
static int rtw89_fw_h2c_set_bcn_fltr_cfg(struct rtw89_dev *d, struct rtw89_vif_link *v,
					 bool connect)
{
	(void)d; (void)v;
	trace(73, connect, 0);
	return 0;
}
static void rtw89_mac_bf_disassoc(struct rtw89_dev *d, struct rtw89_vif_link *v,
				  struct rtw89_sta_link *l)
{
	(void)d; (void)v; (void)l;
	trace(74, 0, 0);
}
#define rtw89_mac_bf_monitor_calc(...) ((void)0)
#define rtw89_btc_ntfy_role_info(...) ((void)0)
#define rtw89_core_get_no_ul_ofdma_htc(...) ((void)0)
#define rtw89_phy_ul_tb_assoc(...) ((void)0)
#define rtw89_core_bcn_track_assoc(...) ((void)0)
#define rtw89_mac_set_tx_retry_limit(...) ((void)0)
#define rtw89_phy_dig_resume(...) ((void)0)
#define rtw89_assoc_link_set(...) ((void)0)
#define rtw89_fw_release_general_pkt_list_vif(...) ((void)0)
#define rtw89_leave_ips_by_hwflags(...) ((void)0)
/* Reached only by an AP's port, RTL8852C's ER check or BE chips. */
static void rtw89_mac_bcn_drop(struct rtw89_dev *d, struct rtw89_vif_link *l)
{
	(void)d; (void)l;
	abort();
}
static bool rtw89_sta_link_has_su_mu_4xhe08(struct ieee80211_link_sta *s) { (void)s; abort(); }
static bool rtw89_sta_link_has_er_su_4xhe08(struct ieee80211_link_sta *s) { (void)s; abort(); }
static int rtw89_fw_get_sta_type(struct rtw89_dev *d, struct rtw89_vif_link *v,
				 struct rtw89_sta_link *l)
{
	(void)d; (void)v; (void)l;
	abort();
}
static struct rtw89_vif_link *rtw89_get_designated_link(struct rtw89_vif *v) { (void)v; abort(); }
static u8 rtw89_sta_get_main_macid(struct rtw89_sta *s) { (void)s; abort(); }
static u8 rtw89_vif_get_main_macid(struct rtw89_vif *v) { (void)v; abort(); }
/* With no AP link it returns before touching a register. */
static void rtw89_mac_port_tsf_resync_all(struct rtw89_dev *d) { (void)d; }
'''
    main_c = r'''
static const struct rtw89_mac_gen_def rtw89_mac_gen_ax = {
@GEN@
};
static const struct rtw89_chip_ops rtw8852b_chip_ops = {
@OPS@
};
static const struct rtw89_chip_info rtw8852b_chip_info = {
@CHIP@
};

static const u8 own[ETH_ALEN] = {0x00, 0xe0, 0x4c, 0x88, 0x52, 0xbe};
static const u8 ap[ETH_ALEN] = {0x9c, 0x53, 0x22, 0x5b, 0x7a, 0x31};

struct world {
	struct rtw89_dev dev;
	struct ieee80211_vif vif;
	struct ieee80211_bss_conf bss;
	struct rtw89_vif rtwvif;
	struct rtw89_vif_link link;
	struct ieee80211_sta sta;
	struct ieee80211_link_sta link_sta;
	struct rtw89_sta rtwsta;
	struct rtw89_sta_link sta_link;
};

/* rtw89_ops_add_interface and __rtw89_ops_add_iface_link up to
 * rtw89_mac_add_vif, then __rtw89_ops_sta_add's AP for a station. */
static void setup(struct world *w, u8 mac_id, u8 port, u8 seq)
{
	memset(w, 0, sizeof(*w));
	w->dev.chip = &rtw8852b_chip_info;
	w->dev.hal.tx_nss = 2;
	w->dev.fw.h2c_seq = seq;
	w->vif.type = NL80211_IFTYPE_STATION;
	w->vif.drv_priv = &w->rtwvif;
	w->rtwvif.links[0] = &w->link;
	w->rtwvif.vif = &w->vif;
	w->rtwvif.bss_conf = &w->bss;
	memcpy(w->bss.addr, own, ETH_ALEN);
	w->link.rtwvif = &w->rtwvif;
	w->link.mac_id = mac_id;
	w->link.port = port;
	w->link.mac_idx = RTW89_MAC_0;
	w->link.phy_idx = RTW89_PHY_0;
	rtw89_vif_type_mapping(&w->link, false);
	w->link.hit_rule = 0;
	w->link.bcn_hit_cond = 0;
	w->link.chanctx_idx = RTW89_CHANCTX_0;
	ether_addr_copy(w->link.mac_addr, w->bss.addr);
	w->sta.drv_priv = &w->rtwsta;
	w->rtwsta.sta = &w->sta;
	w->rtwsta.links[0] = &w->sta_link;
	w->rtwsta.link_sta = &w->link_sta;
	w->sta_link.rtwsta = &w->rtwsta;
	w->sta_link.rtwvif_link = &w->link;
	w->sta_link.mac_id = mac_id;
	memcpy(w->link_sta.addr, ap, ETH_ALEN);
}

static void step(u32 id, int ret) { trace(50, id, (u32)ret); }

/* BSS_CHANGED_BSSID as rtw89_ops_link_info_changed handles it. */
static int bssid_changed(struct world *w, const u8 *bssid)
{
	ether_addr_copy(w->link.bssid, bssid);
	rtw89_cam_bssid_changed(&w->dev, &w->link);
	return rtw89_fw_h2c_cam(&w->dev, &w->link, NULL, NULL, RTW89_ROLE_INFO_CHANGE);
}

/* rtw89_station_mode_sta_assoc's __rtw89_ops_sta_assoc, then
 * __rtw89_ops_bss_link_assoc's port update. */
static void assoc(struct world *w, u32 id)
{
	rtw89_vif_type_mapping(&w->link, true);
	step(id, rtw89_core_sta_link_assoc(&w->dev, &w->link, &w->sta_link));
	step(id + 1, rtw89_mac_port_update(&w->dev, &w->link));
}

static void key(struct ieee80211_key_conf *k, u32 cipher, bool pairwise, s8 keyidx, u8 seed)
{
	memset(k, 0, sizeof(*k));
	k->cipher = cipher;
	k->flags = pairwise ? IEEE80211_KEY_FLAG_PAIRWISE : 0;
	k->keyidx = keyidx;
	k->keylen = cipher == WLAN_CIPHER_SUITE_TKIP ? 32 : 16;
	for (int i = 0; i < k->keylen; i++)
		k->key[i] = seed + i;
}

static void add(struct world *w, u32 id, struct ieee80211_key_conf *k, bool pairwise)
{
	step(id, rtw89_cam_sec_key_add(&w->dev, &w->vif, pairwise ? &w->sta : NULL, k));
	trace(61, k->hw_key_idx, 0);
}

static void he(struct ieee80211_link_sta *s, u8 rx_nss, u8 phy6, u8 phy9, u8 hdr, u8 seed)
{
	memset(&s->he_cap, 0, sizeof(s->he_cap));
	s->rx_nss = rx_nss;
	s->he_cap.has_he = true;
	s->he_cap.he_cap_elem.phy_cap_info[6] = phy6;
	s->he_cap.he_cap_elem.phy_cap_info[9] = phy9;
	s->he_cap.ppe_thres[0] = hdr;
	for (int i = 1; i < IEEE80211_HE_PPE_THRES_MAX_LEN; i++)
		s->he_cap.ppe_thres[i] = (u8)(seed * i + 0x31 * (i & 3));
}

static void free_keys(struct world *w)
{
	for (int i = 0; i < RTW89_MAX_SEC_CAM_NUM; i++)
		free(w->dev.cam_info.sec_entries[i]);
}

int main(int argc, char **argv)
{
	static struct world w;
	struct ieee80211_key_conf k1, k2, k3, k4;
	u32 cases = 0;
	if (argc != 2)
		return 2;
	FILE *out = fopen(argv[1], "wb");
	if (!out)
		abort();

	/* 1. The user's join, over zeroed registers. */
	memset(memory, 0, sizeof(memory));
	set(R_AX_CMAC_FUNC_EN, 4, B_AX_CMAC_EN);
	setup(&w, 0, 0, 0);
	chan.band_type = RTW89_BAND_5G;
	step(1, rtw89_mac_vif_init(&w.dev, &w.link));
	step(2, bssid_changed(&w, ap));
	w.bss.beacon_int = 100;
	w.bss.dtim_period = 2;
	w.bss.he_support = true;
	w.bss.he_bss_color.color = 0x2b;
	w.vif.cfg.aid = 0x1003;
	he(&w.link_sta, 2, IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT, 0, 0x39, 0x1d);
	assoc(&w, 3);
	key(&k1, WLAN_CIPHER_SUITE_CCMP, true, 0, 0x10);
	add(&w, 5, &k1, true);
	key(&k2, WLAN_CIPHER_SUITE_CCMP, false, 1, 0x20);
	add(&w, 6, &k2, false);
	key(&k3, WLAN_CIPHER_SUITE_TKIP, false, 2, 0x30);
	add(&w, 7, &k3, false);
	key(&k4, WLAN_CIPHER_SUITE_CCMP, false, 2, 0x40);
	add(&w, 8, &k4, false);
	step(9, rtw89_cam_sec_key_del(&w.dev, &w.vif, NULL, &k2, true));
	step(10, rtw89_cam_sec_key_del(&w.dev, &w.vif, &w.sta, &k1, true));
	step(11, rtw89_cam_sec_key_del(&w.dev, &w.vif, NULL, &k4, true));
	step(12, rtw89_core_sta_link_disconnect(&w.dev, &w.link, &w.sta_link));
	static const u8 zero[ETH_ALEN];
	step(13, bssid_changed(&w, zero));
	step(14, rtw89_mac_vif_deinit(&w.dev, &w.link));
	free_keys(&w);
	flush(out);
	cases++;

	/* 2. All-ones registers, MAC ID 37 on port 1. */
	memset(memory, 0xff, sizeof(memory));
	setup(&w, 37, 1, 0xfe);
	chan.band_type = RTW89_BAND_2G;
	step(1, rtw89_mac_vif_init(&w.dev, &w.link));
	w.sta_link.cctl_tx_time = true;
	w.sta_link.ampdu_max_time = 0xa;
	w.sta_link.cctl_tx_retry_limit = true;
	w.sta_link.data_tx_cnt_lmt = 0x2a;
	step(2, rtw89_fw_h2c_txtime_cmac_tbl(&w.dev, &w.sta_link));
	w.sta_link.cctl_tx_time = false;
	w.sta_link.cctl_tx_retry_limit = false;
	step(3, rtw89_fw_h2c_txtime_cmac_tbl(&w.dev, &w.sta_link));
	step(4, rtw89_mac_set_macid_pause(&w.dev, 37, true));
	step(5, bssid_changed(&w, ap));
	w.bss.beacon_int = 200;
	w.bss.dtim_period = 3;
	w.vif.cfg.aid = 0x7ff;
	w.link_sta.rx_nss = 1;
	assoc(&w, 6);
	refuse = 1;
	key(&k1, WLAN_CIPHER_SUITE_CCMP, true, 0, 0x50);
	add(&w, 8, &k1, true);
	refuse = 0;
	add(&w, 9, &k1, true);
	refuse = 1;
	step(10, rtw89_mac_vif_deinit(&w.dev, &w.link));
	refuse = 0;
	free_keys(&w);
	flush(out);
	cases++;

	/* 3. CMAC0 off. */
	memset(memory, 0, sizeof(memory));
	set(R_AX_CMAC_FUNC_EN, 4, RTW89_R32_DEAD);
	setup(&w, 0, 0, 0);
	step(1, rtw89_mac_vif_init(&w.dev, &w.link));
	flush(out);
	cases++;

	/* 4. Association CMAC tables over HE capabilities. */
	memset(memory, 0, sizeof(memory));
	setup(&w, 5, 0, 0x10);
	chan.band_type = RTW89_BAND_5G;
	rtw89_vif_type_mapping(&w.link, true);
	static const u8 caps[][5] = {
		/* rx_nss, phy_cap_info[6], phy_cap_info[9], ppe_thres[0], seed */
		{2, 0x00, 0x80, 0x00, 0x00},
		{1, 0x00, 0x40, 0x00, 0x00},
		{2, 0x00, 0xc0, 0x00, 0x00},
		{2, 0x80, 0x00, 0x39, 0x1d},
		{1, 0x80, 0x00, 0x78, 0x07},
		{4, 0x80, 0x00, 0x7b, 0x55},
		{1, 0x80, 0x00, 0x08, 0xff},
		{2, 0x80, 0x00, 0x11, 0x00},
		{3, 0xbf, 0x3f, 0x29, 0xe3},
	};
	for (u32 i = 0; i < ARRAY_SIZE(caps); i++) {
		he(&w.link_sta, caps[i][0], caps[i][1], caps[i][2], caps[i][3], caps[i][4]);
		step(i, rtw89_fw_h2c_assoc_cmac_tbl(&w.dev, &w.link, &w.sta_link));
	}
	w.link_sta.he_cap.has_he = false;
	step(100, rtw89_fw_h2c_assoc_cmac_tbl(&w.dev, &w.link, &w.sta_link));
	step(101, rtw89_fw_h2c_assoc_cmac_tbl(&w.dev, &w.link, NULL));
	flush(out);
	cases++;

	if (fclose(out))
		abort();
	free(segment);
	printf("%u\n", cases);
	return 0;
}
'''.replace('@GEN@', gen_init).replace('@OPS@', ops_init).replace('@CHIP@', chip_init)
    program = '\n\n'.join([
        preamble, reg_h, enums, core_defines, mac_defines, mac_c_defines, h2c_defines,
        sec_defines, fw_c_defines, structs, harness, prototypes, core_h_inlines, mac_h_inlines,
        fw_h_inlines, port_base, mac_c, fw_c, cam_c, core_c, main_c])
    generated = out / 'station.c'
    generated.write_text(program, newline='\n')
    exe = out / 'station'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    str(generated), '-o', str(exe)], check=True)
    trace = out / 'station.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    cases = int(run.stdout.strip())
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=cases,
        case_order='1: interface up, BSSID, HE association on 5 GHz, keys, disconnect, down; '
                   '2: all-ones registers, MAC ID 37 on port 1, TX-time tables, pause, '
                   'non-HE association on 2.4 GHz, refused H2C; 3: CMAC0 off; '
                   '4: association CMAC tables over HE capabilities',
        dispatch=dict(rtw8852b_chip_info=chip, rtw8852b_chip_ops=chip_ops,
                      rtw89_mac_gen_ax=gen),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO and skbs are a model; no physical evidence and no firmware answered anything',
            'PCIe RTL8852B only: rtw8852b_chip_info, one station link and its AP',
            'the mac80211 and rtw89 structures are stand-ins holding the members reached',
            'the harness, not mac80211.c, orders the steps as mac80211 and rtw89 call them',
            'rate adaptation, beamforming, general packets, the beacon filter, BTC, DIG and '
            'UL TB are stubs; five leave a mark where rtw89 reaches them',
        ])
    (out / 'station.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
