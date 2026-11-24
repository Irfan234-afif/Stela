#!/usr/bin/env python3
"""Unchanged pinned rtw89 firmware download for an RTL8852BE, over a register and DMA model.

Usage: script REFERENCE_DIRECTORY RTL8852B_IMAGE OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks; RTL8852B_IMAGE is the pinned
rtw89/rtw8852b_fw-2.bin. Extracted unchanged, each with its SHA-256 in
manifest.json:

- fw.c: rtw89_fw_download and everything it reaches on an AX chip:
  __rtw89_fw_download, rtw89_fw_download_suit, rtw89_fw_hdr_parser with its
  v0 and v1 parsers, __parse_security_section and __check_secure_blacklist,
  rtw89_fw_download_hdr and __rtw89_fw_download_hdr with both header tweaks,
  rtw89_fw_download_main and __rtw89_fw_download_main,
  rtw89_fw_check_rdy, rtw89_fw_dl_fail_dump and rtw89_fw_prog_cnt_dump,
  rtw89_h2c_pkt_set_hdr_fwdl and the H2C skb allocation; the suit's
  recognition (__rtw89_fw_recognize, rtw89_mfw_recognize and its helpers,
  rtw89_fw_update_ver with v0 and v1); the feature table from
  __DEF_FW_FEAT_COND through fw_feat_tbl, rtw89_fw_iterate_feature_cfg and
  rtw89_fw_recognize_features; rtw89_fw_blacklist_default;
- mac.c: rtw89_mac_disable_cpu_ax with rtw89_disable_fw_watchdog,
  rtw89_mac_enable_cpu_ax, rtw89_fw_get_rdy_ax,
  rtw89_fwdl_check_path_ready_ax and rtw89_fwdl_secure_idmem_share_mode_ax;
  mac.h's rtw89_mac_fwdl_preconfig and rtw89_fwdl_secure_idmem_share_mode;
- core.c: rtw89_h2c_tx with rtw89_core_tx_update_desc_info,
  rtw89_core_tx_update_h2c_info and rtw89_core_fill_txdesc with its TXWD
  builders; pci.c: rtw89_pci_ops' check_and_reclaim_tx_resource, tx_write
  and tx_kick_off on CH12 down to rtw89_pci_fwcmd_submit and
  rtw89_pci_release_fwcmd, and rtw89_pci_ch_dma_addr_set;
- efuse.c: rtw89_efuse_read_fw_secure_ax with both MSS recognizers,
  get_mss_dev_type_idx, the OTP key tables and the EFUSE_* defines;
- the core.h, pci.h, fw.h, mac.h and txrx.h declarations, inlines and
  definitions they use, and reg.h.

rtw8852b_chip_info, rtw8852b_chip_ops, rtw89_mac_gen_ax and rtw89_pci_ops
give the values the harness's tables take, member by member, each checked.
Everything is compiled with clang under ASan and UBSan.

The model: MAC space as bytes, byte i holding i * 37 + 11 and CH12's index
register 0 before each download. PLATFORM_ENABLE's WCPU_EN going from 0 to
1 starts an attempt, which takes its behavior from the case's script (the
last entry repeating): reads of WCPU_FW_CTRL while the WCPU runs show
H2C_PATH_RDY from the third read on, or at once after a kick; FWDL_PATH_RDY
from the third read after the first kick, or at once after a later one;
and, from the third read after the kick that completes the packets the
parsed suit needs, the script's status in place of the stored one. A
behavior may withhold either ready bit, and may leave CH12's hardware index
where it is (otherwise a kick moves it to the host index). A sticky case
keeps WCPU_EN set once set. Command buffers are mapped from 0x80600000,
0x3000 apart, where the Rust test's domain places them. Polls are
read_poll_timeout counted in steps, as in the other AX oracles.

Segments, each prefixed by its byte length, of records of three
little-endian u32 (tag, a, b):

1. rtw89_efuse_read_fw_secure_ax over every pair of efuse bytes, b1 the
   high byte of the index, 32 pairs per record: secure_boot (140),
   can_mss_v0 (141) and can_mss_v1 (142) bits; then a failed read: its
   return and the three flags (143).
2. Features: rtw89_fw_iterate_feature_cfg for RTL8852B over an empty map
   for each version code, the thirteen RTL8852B features as bits in the
   Rust enum's order and the map's population count from bit 16 (150);
   then rtw89_fw_recognize_features over the pinned image's normal suit for
   cuts 1 and 2 (151).
3. Per download case, two segments. The first: every register access
   (tagged by width, writes by 4 plus width), delay (9), unmap (60), and per
   BD a kick hands over, its index, length and option (122) and DMA address
   (123); then rtw89_fw_download's return (11), h2c_seq (127) and
   RTW89_FLAG_FW_RDY (128). A pair of records repeated back to back is
   kept once, followed by (12, further repeats, 0). The second: each BD's
   mapped bytes, a u32 length then the bytes, zero-padded to four.

Cases: synthetic images A (four sections: 4041 bytes, 2012 with checksum,
none, and a 100-byte security section with checksum and one MSS signature,
behind a 16-byte dynamic header) and B (2013 bytes with checksum, then 1),
both legacy single images; the pinned image for cuts 1 and 2.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'


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

    def block(file, first, before, name):
        """The lines from the first one starting with first up to the next one starting with before."""
        text = source(file)
        start = text.index('\n' + first) + 1
        end = text.index('\n' + before, start) + 1
        return record(file, name, text[start:end])

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
            values[name] = body[start:end].strip()
        return values

    reg_h = record('reg.h', 'reg.h', source('reg.h'))
    pci_h_defines = block('pci.h', '#define MDIO_PG0_G1', 'struct rtw89_pci_isrs;',
                          'MDIO_PG0_G1 to struct rtw89_pci_isrs;')
    txwd_defines = block('txrx.h', '/* TX WD BODY DWORD 0 */', '/* TX WD INFO DWORD 5 */',
                         'TX WD BODY DWORD 0 to TX WD INFO DWORD 5')
    h2c_defines = block('fw.h', '#define H2C_HEADER_LEN',
                        '/* CLASS 10 - Security CAM */', 'H2C_HEADER_LEN to CLASS 10')
    fw_defines = '\n'.join([
        defines('fw.h', ['FWDL_SECTION_MAX_NUM', 'FWDL_SECTION_CHKSUM_LEN',
                         'FWDL_SECTION_PER_PKT_LEN', 'FWDL_SECURITY_SECTION_TYPE',
                         'FWDL_SECURITY_SIGLEN', 'FWDL_SECURITY_CHKSUM_LEN', 'FORMATTED_MSSC',
                         'FORMATTED_MSSC_MASK', 'RTW89_MFW_SIG', 'FWDL_WAIT_CNT',
                         'FWDL_WAIT_CNT_USB']),
        lines('fw.h', '#define FWSECTION_HDR_', 'FWSECTION_HDR_* defines'),
        lines('fw.h', '#define FW_HDR_', 'FW_HDR_* defines'),
    ])
    core_macros = '\n'.join([
        macro('core.h', 'RTW89_FW_VER_CODE'), macro('core.h', 'RTW89_FW_SUIT_VER_CODE'),
        macro('core.h', 'RTW89_FW_FEATURE_GROUP'), macro('core.h', 'RTW89_CHK_FW_FEATURE'),
        macro('core.h', 'RTW89_SET_FW_FEATURE'), macro('core.h', 'RTW89_CLR_FW_FEATURE'),
    ])
    mac_defines = defines('mac.h', ['FW_PROG_CNTR_DBG_SEL', 'MAC_DBG_SEL'])
    efuse_text = source('efuse.c')
    efuse_defines = record('efuse.c', 'EFUSE_* and OTP_KEY_INFO_NUM defines', '\n'.join(
        line for line in efuse_text.splitlines()
        if line.startswith(('#define EFUSE_', '#define OTP_KEY_INFO_NUM'))))
    otp_tables = record('efuse.c', 'otp_key_info tables', '\n'.join(
        line for line in efuse_text.splitlines() if line.startswith('static const u8 otp_key_info_')))
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_hci_type'),
        declaration('core.h', 'enum', 'rtw89_core_chip_id'),
        declaration('core.h', 'enum', 'rtw89_chip_gen'),
        declaration('core.h', 'enum', 'rtw89_core_tx_type'),
        declaration('core.h', 'enum', 'rtw89_flags'),
        declaration('core.h', 'enum', 'rtw89_dma_ch'),
        declaration('core.h', 'enum', 'rtw89_fwdl_check_type'),
        declaration('core.h', 'enum', 'rtw89_fw_type'),
        declaration('core.h', 'enum', 'rtw89_fw_feature'),
        declaration('core.h', 'enum', 'rtw89_fw_mss_dev_type'),
        declaration('core.h', 'struct', 'rtw89_fw_suit'),
        declaration('core.h', 'struct', 'rtw89_fw_secure'),
        declaration('core.h', 'struct', 'rtw89_reg_def'),
        declaration('core.h', 'struct', 'rtw89_txwd_body'),
        declaration('core.h', 'struct', 'rtw89_txwd_info'),
        declaration('core.h', 'struct', 'rtw89_tx_desc_info'),
        declaration('core.h', 'struct', 'rtw89_rx_desc_info'),
        declaration('core.h', 'struct', 'rtw89_core_tx_request'),
        declaration('coex.h', 'enum', 'btc_pkt_type'),
        declaration('txrx.h', 'enum', 'rtw89_tx_channel'),
        declaration('txrx.h', 'enum', 'rtw89_rx_channel'),
        declaration('mac.h', 'enum', 'rtw89_mac_mem_sel'),
        declaration('fw.h', 'enum', 'rtw89_fw_dl_status'),
        declaration('fw.h', 'struct', 'fwcmd_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_section_info'),
        declaration('fw.h', 'struct', 'rtw89_fw_bin_info'),
        declaration('fw.h', 'struct', 'rtw89_fw_dynhdr_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_section'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_section_v1'),
        declaration('fw.h', 'struct', 'rtw89_fw_hdr_v1'),
        declaration('fw.h', 'union', 'rtw89_fw_section_mssc_content'),
        declaration('fw.h', 'struct', 'rtw89_fw_blacklist'),
        declaration('fw.h', 'struct', 'rtw89_mfw_info'),
        declaration('fw.h', 'struct', 'rtw89_mfw_hdr'),
        declaration('efuse.c', 'enum', 'rtw89_efuse_mss_dev_type'),
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
    core_h_inlines = in_order('core.h', [
        'rtw89_write16_mask', 'rtw89_write32_set', 'rtw89_write32_clr', 'rtw89_write32_mask',
        'rtw89_hci_tx_write', 'rtw89_hci_check_and_reclaim_tx_resource', 'rtw89_hci_tx_kick_off',
        'rtw89_chip_fill_txdesc_fwcmd', 'rtw89_fw_suit_get', 'rtw89_is_rtl885xb'])
    mac_h_inlines = in_order('mac.h', [
        'rtw89_mac_fwdl_preconfig', 'rtw89_fwdl_secure_idmem_share_mode'])
    pci_h_inlines = in_order('pci.h', ['rtw89_pci_get_next_txbd', 'rtw89_pci_enqueue_txwd'])
    dma_addr_set = '\n\n'.join(
        [macro('pci.c', name) for name in ['DEF_TXCHADDRS_TYPE1', 'DEF_TXCHADDRS', 'DEF_RXCHADDRS']]
        + [definition('pci.c', 'const struct rtw89_pci_ch_dma_addr_set rtw89_pci_ch_dma_addr_set')])
    core_c = in_order('core.c', [
        'rtw89_core_tx_update_h2c_info', 'rtw89_core_tx_update_desc_info', 'rtw89_h2c_tx',
        'rtw89_build_txwd_body0', 'rtw89_build_txwd_body2', 'rtw89_build_txwd_body3',
        'rtw89_build_txwd_info0', 'rtw89_build_txwd_info1', 'rtw89_build_txwd_info2',
        'rtw89_build_txwd_info3', 'rtw89_build_txwd_info4', 'rtw89_core_fill_txdesc'])
    pci_c = in_order('pci.c', [
        'rtw89_pci_dma_recalc', 'rtw89_pci_txbd_recalc', 'rtw89_pci_release_fwcmd',
        'rtw89_pci_reclaim_tx_fwcmd', 'rtw89_pci_get_avail_txbd_num',
        '__rtw89_pci_check_and_reclaim_tx_fwcmd_resource',
        'rtw89_pci_check_and_reclaim_tx_resource', '__rtw89_pci_tx_kick_off',
        'rtw89_pci_tx_bd_ring_update', 'rtw89_pci_ops_tx_kick_off', 'rtw89_pci_fwcmd_submit',
        'rtw89_pci_txbd_submit', 'rtw89_pci_tx_write', 'rtw89_pci_ops_tx_write'])
    mac_c = in_order('mac.c', [
        'rtw89_disable_fw_watchdog', 'rtw89_mac_disable_cpu_ax', 'rtw89_mac_enable_cpu_ax',
        'rtw89_fw_get_rdy_ax', 'rtw89_fwdl_check_path_ready_ax',
        'rtw89_fwdl_secure_idmem_share_mode_ax'])
    efuse_c = in_order('efuse.c', [
        'get_mss_dev_type_idx', 'rtw89_efuse_recognize_mss_info_v1',
        'rtw89_efuse_recognize_mss_index_v0', 'rtw89_efuse_read_fw_secure_ax'])
    blacklist = definition('fw.c', 'const struct rtw89_fw_blacklist rtw89_fw_blacklist_default')
    feature_table = block('fw.c', '#define __DEF_FW_FEAT_COND',
                          'static void rtw89_fw_iterate_feature_cfg',
                          '__DEF_FW_FEAT_COND to fw_feat_tbl')
    fw_c = in_order('fw.c', [
        'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr',
        'rtw89_fw_h2c_alloc_skb_no_hdr', 'rtw89_fw_check_rdy', 'rtw89_fw_hdr_parser_v0',
        '__check_secure_blacklist', '__parse_security_section', 'rtw89_fw_hdr_parser_v1',
        'rtw89_fw_hdr_parser', 'rtw89_mfw_get_hdr_ptr', 'rtw89_mfw_validate_hdr',
        'rtw89_mfw_recognize', 'rtw89_fw_update_ver_v0', 'rtw89_fw_update_ver_v1',
        'rtw89_fw_update_ver', '__rtw89_fw_recognize', 'rtw89_fw_iterate_feature_cfg',
        'rtw89_fw_recognize_features', 'rtw89_h2c_pkt_set_hdr_fwdl',
        '__rtw89_fw_download_tweak_hdr_v0', '__rtw89_fw_download_tweak_hdr_v1',
        '__rtw89_fw_download_hdr', 'rtw89_fw_download_hdr', '__rtw89_fw_download_main',
        'rtw89_fw_get_fwdl_chk_type_from_suit', 'rtw89_fw_download_main',
        'rtw89_fw_prog_cnt_dump', 'rtw89_fw_dl_fail_dump', 'rtw89_fw_download_suit',
        '__rtw89_fw_download', 'rtw89_fw_download'])
    # The feature table must sit before rtw89_fw_iterate_feature_cfg.
    split = fw_c.index('static void rtw89_fw_iterate_feature_cfg')
    fw_c = fw_c[:split] + feature_table + '\n' + fw_c[split:]

    mac_fields = ['boot_dbg', 'disable_cpu', 'fwdl_preconfig', 'fwdl_enable_wcpu',
                  'fwdl_get_status', 'fwdl_check_path_ready', 'fwdl_secure_idmem_share_mode']
    mac_def = fields('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax', mac_fields)
    expected_mac = {'boot_dbg': 'R_AX_BOOT_DBG', 'disable_cpu': 'rtw89_mac_disable_cpu_ax',
                    'fwdl_preconfig': 'NULL', 'fwdl_enable_wcpu': 'rtw89_mac_enable_cpu_ax',
                    'fwdl_get_status': 'rtw89_fw_get_rdy_ax',
                    'fwdl_check_path_ready': 'rtw89_fwdl_check_path_ready_ax',
                    'fwdl_secure_idmem_share_mode': 'rtw89_fwdl_secure_idmem_share_mode_ax'}
    if mac_def != expected_mac:
        raise ValueError(f'rtw89_mac_gen_ax is {mac_def}')
    chip_fields = ['chip_id', 'chip_gen', 'ops', 'mac_def', 'try_ce_fw', 'bbmcu_nr',
                   'fw_blacklist', 'h2c_desc_size']
    chip = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info', chip_fields)
    if (chip['ops'], chip['mac_def'], chip['try_ce_fw'], chip['bbmcu_nr']) != \
            ('&rtw8852b_chip_ops', '&rtw89_mac_gen_ax', 'true', '0'):
        raise ValueError(f'rtw8852b_chip_info is {chip}')
    ops_fields = ['fill_txdesc_fwcmd']
    chip_ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                      ops_fields)
    if chip_ops != {'fill_txdesc_fwcmd': 'rtw89_core_fill_txdesc'}:
        raise ValueError(f'rtw8852b_chip_ops is {chip_ops}')
    pci_fields = ['rx_ring_eq_is_full']
    pci_info = fields('rtw8852be.c', 'static const struct rtw89_pci_info rtw8852b_pci_info',
                      pci_fields)
    hci_fields = ['tx_write', 'tx_kick_off', 'check_and_reclaim_tx_resource']
    hci_ops = fields('pci.c', 'static const struct rtw89_hci_ops rtw89_pci_ops', hci_fields)
    if hci_ops != {'tx_write': 'rtw89_pci_ops_tx_write',
                   'tx_kick_off': 'rtw89_pci_ops_tx_kick_off',
                   'check_and_reclaim_tx_resource': 'rtw89_pci_check_and_reclaim_tx_resource'}:
        raise ValueError(f'rtw89_pci_ops is {hci_ops}')

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
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t dma_addr_t;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define __packed __attribute__((packed))
#define __iomem
#define __rcu
#define __maybe_unused __attribute__((unused))
#define unlikely(x) (x)
#define likely(x) (x)
#define EXPORT_SYMBOL(...)
#define WARN(c, ...) ((void)(c))
#define WARN_ONCE(c, ...) ((void)(c))
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
#define u32_encode_bits(v, m) FIELD_PREP(m, v)
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u8_get_bits(v, m) ((u8)u32_get_bits(v, m))
#define u32_replace_bits(old, v, m) ((((u32)(old)) & ~(u32)(m)) | FIELD_PREP(m, v))
#define le16_encode_bits(v, m) ((__le16)FIELD_PREP(m, (u16)(v)))
#define le32_encode_bits(v, m) ((__le32)FIELD_PREP(m, (v)))
#define le32_get_bits(v, m) u32_get_bits(v, m)
#define le32p_replace_bits(p, v, m) (*(p) = u32_replace_bits(*(p), v, m))
#define cpu_to_le16(v) ((__le16)(v))
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define upper_32_bits(n) ((u32)(((u64)(n)) >> 32))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define RTW89_DBG_TXRX BIT(0)
#define RTW89_DBG_HCI BIT(6)
#define RTW89_DBG_FW BIT(12)
#define RTW89_DBG_UNEXP BIT(31)
/* rtw89's log helpers are calls in the kernel: their arguments are
 * evaluated whatever is printed. */
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
struct rtw89_dev;
static void rtw89_hex_dump(struct rtw89_dev *d, u32 mask, const char *prefix,
			   const void *buf, size_t len)
{
	(void)d; (void)mask; (void)prefix; (void)buf; (void)len;
}
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
#define mdelay(ms) model_delay((u64)(ms) * 1000)

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
struct firmware { const u8 *data; size_t size; };
struct wiphy { char fw_version[32]; };
struct ieee80211_hw { struct wiphy *wiphy; };
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
	void (*fill_txdesc_fwcmd)(struct rtw89_dev *rtwdev, struct rtw89_tx_desc_info *desc_info,
				  void *txdesc);
};
struct rtw89_mac_gen_def {
	u32 boot_dbg;
	void (*disable_cpu)(struct rtw89_dev *rtwdev);
	void (*fwdl_preconfig)(struct rtw89_dev *rtwdev);
	int (*fwdl_enable_wcpu)(struct rtw89_dev *rtwdev, u8 boot_reason, bool dlfw,
				bool include_bb);
	u8 (*fwdl_get_status)(struct rtw89_dev *rtwdev, enum rtw89_fwdl_check_type type);
	int (*fwdl_check_path_ready)(struct rtw89_dev *rtwdev, bool h2c_or_fwdl);
	void (*fwdl_secure_idmem_share_mode)(struct rtw89_dev *rtwdev, u8 mode);
};
struct rtw89_chip_info {
	enum rtw89_core_chip_id chip_id;
	enum rtw89_chip_gen chip_gen;
	const struct rtw89_chip_ops *ops;
	const struct rtw89_mac_gen_def *mac_def;
	bool try_ce_fw;
	u8 bbmcu_nr;
	const struct rtw89_fw_blacklist *fw_blacklist;
	u32 h2c_desc_size;
};
struct rtw89_hci_ops {
	int (*tx_write)(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req);
	void (*tx_kick_off)(struct rtw89_dev *rtwdev, u8 txch);
	u32 (*check_and_reclaim_tx_resource)(struct rtw89_dev *rtwdev, u8 txch);
};
struct rtw89_hci_info { const struct rtw89_hci_ops *ops; enum rtw89_hci_type type; bool paused; };
struct rtw89_fw_info {
	struct { const struct firmware *firmware; } req;
	u8 h2c_seq;
	u8 rec_seq;
	u8 h2c_counter;
	u8 c2h_counter;
	struct rtw89_fw_suit normal;
	struct rtw89_fw_suit wowlan;
	struct rtw89_fw_suit bbmcu0;
	struct rtw89_fw_suit bbmcu1;
	struct { struct rtw89_fw_suit suit; } log;
	struct rtw89_fw_secure sec;
	DECLARE_BITMAP(feature_map, NUM_OF_RTW89_FW_FEATURES);
};
struct rtw89_mac_info { u8 rpwm_seq_num; u8 cpwm_seq_num; };
struct rtw89_hal { u8 cv; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	const struct rtw89_pci_info *pci_info;
	struct rtw89_hci_info hci;
	struct rtw89_fw_info fw;
	struct rtw89_mac_info mac;
	struct rtw89_hal hal;
	struct ieee80211_hw *hw;
	DECLARE_BITMAP(flags, NUM_OF_RTW89_FLAGS);
	struct device *dev;
	u8 priv[] __attribute__((aligned(8)));
};
static int test_bit(int nr, const unsigned long *map) { return (map[nr / 64] >> (nr % 64)) & 1; }
static void set_bit(int nr, unsigned long *map) { map[nr / 64] |= 1UL << (nr % 64); }
static void clear_bit(int nr, unsigned long *map) { map[nr / 64] &= ~(1UL << (nr % 64)); }
static int hweight8(u8 v) { return __builtin_popcount(v); }

/* The trace: records, and the bytes of every BD a kick hands over. */
static u32 *records;
static size_t nrecords, record_capacity;
static u8 *packets;
static size_t packet_bytes, packet_capacity;
static void record(u32 tag, u32 a, u32 b)
{
	if (nrecords + 1 > record_capacity) {
		record_capacity = record_capacity ? 2 * record_capacity : 4096;
		records = realloc(records, record_capacity * 12);
		if (!records)
			abort();
	}
	records[3 * nrecords] = tag;
	records[3 * nrecords + 1] = a;
	records[3 * nrecords + 2] = b;
	nrecords++;
}
static void packet(const u8 *p, u32 n)
{
	u32 padded = (n + 3) & ~3U;
	if (packet_bytes + 4 + padded > packet_capacity) {
		packet_capacity = 2 * (packet_capacity + 4 + padded);
		packets = realloc(packets, packet_capacity);
		if (!packets)
			abort();
	}
	memcpy(packets + packet_bytes, &n, 4);
	memcpy(packets + packet_bytes + 4, p, n);
	memset(packets + packet_bytes + 4 + n, 0, padded - n);
	packet_bytes += 4 + padded;
}
static void model_delay(u64 us) { if (us > UINT32_MAX) abort(); record(9, 0, (u32)us); }

/* The model's state. */
#define LAG 2
struct behavior { bool consume, h2c, fwdl; u8 status; };
static u8 memory[0x10000];
static const struct behavior *script;
static u32 script_len, attempt, kicks, reads, host, expected;
static bool sticky;
static struct rtw89_dev *current;
static u32 get(u32 r, u32 n) { u32 v = 0; for (u32 i = 0; i < n; i++) v |= (u32)memory[r + i] << (8 * i); return v; }
static void set(u32 r, u32 n, u32 v) { for (u32 i = 0; i < n; i++) memory[r + i] = v >> (8 * i); }
static const struct behavior *behavior(void)
{
	u32 i = attempt ? attempt : 1;
	if (i > script_len)
		i = script_len;
	return &script[i - 1];
}
static bool cpu_on(void) { return memory[R_AX_PLATFORM_ENABLE] & B_AX_WCPU_EN; }

/* DMA: command buffers from 0x80600000, 0x3000 apart. */
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define CMD_DMA 0x80600000ULL
#define MAX_MAPS 4096
static u32 maps;
static struct { dma_addr_t dma; const u8 *data; size_t size; } map_table[MAX_MAPS];
static dma_addr_t dma_map_single(struct device *d, void *p, size_t size, int dir)
{
	(void)d;
	if (dir != DMA_TO_DEVICE || maps >= MAX_MAPS)
		abort();
	map_table[maps].dma = CMD_DMA + 0x3000ULL * maps;
	map_table[maps].data = p;
	map_table[maps].size = size;
	return map_table[maps++].dma;
}
static int dma_mapping_error(struct device *d, dma_addr_t a) { (void)d; (void)a; return 0; }
static void dma_unmap_single(struct device *d, dma_addr_t a, size_t size, int dir)
{
	(void)d;
	if (dir != DMA_TO_DEVICE)
		abort();
	record(60, (u32)a, (u32)size);
}
static const u8 *mapped(dma_addr_t dma, size_t length)
{
	for (u32 i = 0; i < maps; i++)
		if (map_table[i].dma == dma && map_table[i].size >= length)
			return map_table[i].data;
	abort();
}

/* The device: a kick hands over every BD up to the new host index. */
extern const struct rtw89_pci_ch_dma_addr_set rtw89_pci_ch_dma_addr_set;
struct rtw89_pci;
static struct rtw89_pci *pci_of(struct rtw89_dev *dev) { return (struct rtw89_pci *)dev->priv; }
static void kick(u32 r, u32 to);
static u32 model_read(u32 r, u32 n)
{
	if (r + n > sizeof(memory))
		abort();
	u32 v = get(r, n);
	if (r == R_AX_WCPU_FW_CTRL && cpu_on()) {
		const struct behavior *b = behavior();
		reads++;
		if (b->h2c && (kicks > 0 || reads > LAG))
			v |= B_AX_H2C_PATH_RDY;
		if (b->fwdl && kicks > 0 && (kicks > 1 || reads > LAG))
			v |= B_AX_FWDL_PATH_RDY;
		if (kicks >= expected && reads > LAG)
			v = (v & ~B_AX_WCPU_FWDL_STS_MASK) | FIELD_PREP(B_AX_WCPU_FWDL_STS_MASK, b->status);
	}
	record(n, r, v);
	return v;
}
static void model_write(u32 r, u32 n, u32 v)
{
	if (r + n > sizeof(memory))
		abort();
	record(4 + n, r, v);
	if (r <= R_AX_PLATFORM_ENABLE && R_AX_PLATFORM_ENABLE < r + n) {
		bool was = cpu_on();
		set(r, n, v);
		if (sticky && was)
			memory[R_AX_PLATFORM_ENABLE] |= B_AX_WCPU_EN;
		if (!was && cpu_on()) {
			attempt++;
			kicks = 0;
			reads = 0;
		}
	} else if (r == rtw89_pci_ch_dma_addr_set.tx[RTW89_TXCH_CH12].idx && n == 2) {
		set(r, n, v);
		kick(r, v);
	} else {
		set(r, n, v);
	}
}
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
static void skb_trim(struct sk_buff *s, unsigned int n)
{
	if (n < s->len)
		s->len = n;
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

/* Stand-ins outside what the download reaches. */
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
/* rtw89_disable_fw_watchdog's path for chips other than RTL885xB. */
static void rtw89_mac_mem_write(struct rtw89_dev *d, u32 offset, u32 val, enum rtw89_mac_mem_sel sel)
{
	(void)d; (void)offset; (void)val; (void)sel; abort();
}
static u32 rtw89_mac_mem_read(struct rtw89_dev *d, u32 offset, enum rtw89_mac_mem_sel sel)
{
	(void)d; (void)offset; (void)sel; abort();
}
/* Only formatted MSSC reaches it; no image here has one. */
static int __parse_formatted_mssc(struct rtw89_dev *d, struct rtw89_fw_bin_info *i,
				  struct rtw89_fw_hdr_section_info *s, const void *c, u32 *l)
{
	(void)d; (void)i; (void)s; (void)c; (void)l; abort();
}
/* The physical efuse read rtw89_efuse_read_fw_secure_ax makes: the bytes
 * the secure segment names, or a failure. */
static u8 efuse_bytes[2];
static int efuse_fails;
static int rtw89_dump_physical_efuse_map(struct rtw89_dev *d, u8 *map, u32 dump_addr,
					 u32 dump_size, bool dav)
{
	(void)d;
	if (dump_addr != EFUSE_EXTERNALPN_ADDR_AX || dump_size != 2 || dav)
		abort();
	if (efuse_fails)
		return -ETIMEDOUT;
	map[0] = efuse_bytes[0];
	map[1] = efuse_bytes[1];
	return 0;
}
/* Forward declarations, as fw.c and fw.h make them. */
int rtw89_fw_check_rdy(struct rtw89_dev *rtwdev, enum rtw89_fwdl_check_type type);
static int __parse_security_section(struct rtw89_dev *rtwdev,
				    struct rtw89_fw_bin_info *info,
				    struct rtw89_fw_hdr_section_info *section_info,
				    const void *content,
				    u32 *mssc_len);
int rtw89_h2c_tx(struct rtw89_dev *rtwdev, struct sk_buff *skb, bool fwdl);
'''
    feature_names = ['NO_LPS_PG', 'TX_WAKE', 'CRASH_TRIGGER_TYPE_0', 'SCAN_OFFLOAD',
                     'BEACON_FILTER', 'BEACON_LOSS_COUNT_V1', 'NO_WOW_CPU_IO_RX',
                     'LPS_DACK_BY_C2H_REG', 'SER_L1_BY_EVENT', 'CRASH_TRIGGER_TYPE_1',
                     'SCAN_OFFLOAD_EXTRA_OP', 'BEACON_TRACKING', 'SIM_SER_L0L1_BY_HALT_H2C']
    tables = (
        'static const struct rtw89_chip_ops rtw8852b_chip_ops = {\n'
        + ''.join(f'\t.{name} = {chip_ops[name]},\n' for name in ops_fields)
        + '};\nstatic const struct rtw89_mac_gen_def rtw89_mac_gen_ax = {\n'
        + ''.join(f'\t.{name} = {mac_def[name]},\n' for name in mac_fields)
        + '};\nstatic const struct rtw89_chip_info rtw8852b_chip_info = {\n'
        + ''.join(f'\t.{name} = {chip[name]},\n' for name in chip_fields)
        + '};\nstatic const struct rtw89_pci_info rtw8852b_pci_info = {\n'
        + ''.join(f'\t.{name} = {pci_info[name]},\n' for name in pci_fields)
        + '};\nstatic const struct rtw89_hci_ops rtw89_pci_ops = {\n'
        + ''.join(f'\t.{name} = {hci_ops[name]},\n' for name in hci_fields)
        + '};\nstatic const int feature_bits[] = {\n'
        + ''.join(f'\tRTW89_FW_FEATURE_{name},\n' for name in feature_names)
        + '};\n')
    main_c = r'''
static void kick(u32 r, u32 to)
{
	struct rtw89_pci_tx_ring *tx = &pci_of(current)->tx.rings[RTW89_TXCH_CH12];
	while (host != to) {
		struct rtw89_pci_tx_bd_32 *bd = (struct rtw89_pci_tx_bd_32 *)tx->bd_ring.head + host;
		record(122, host, bd->length | (u32)bd->opt << 16);
		record(123, bd->dma, 0);
		packet(mapped(bd->dma, bd->length), bd->length);
		host = (host + 1) % RTW89_PCI_TXBD_NUM_MAX;
	}
	kicks++;
	reads = 0;
	if (behavior()->consume)
		set(r + 2, 2, to);
}
static void flush(FILE *out, bool compress)
{
	u32 *o = malloc((3 * nrecords + 3) * 4);
	size_t n = 0, i = 0;
	if (!o)
		abort();
#define SAME(x, y) (!memcmp(records + 3 * (x), records + 3 * (y), 12))
	while (i < nrecords) {
		if (compress && i + 3 < nrecords && SAME(i, i + 2) && SAME(i + 1, i + 3)) {
			size_t j = i + 2;
			u32 k = 0;
			while (j + 1 < nrecords && SAME(j, i) && SAME(j + 1, i + 1)) {
				k++;
				j += 2;
			}
			memcpy(o + n, records + 3 * i, 24);
			n += 6;
			o[n++] = 12;
			o[n++] = k;
			o[n++] = 0;
			i = j;
		} else {
			memcpy(o + n, records + 3 * i, 12);
			n += 3;
			i++;
		}
	}
	u32 bytes = n * 4;
	if (fwrite(&bytes, 4, 1, out) != 1 || fwrite(o, 4, n, out) != n)
		abort();
	free(o);
	nrecords = 0;
}
static void flush_packets(FILE *out)
{
	u32 bytes = packet_bytes;
	if (fwrite(&bytes, 4, 1, out) != 1 || fwrite(packets, 1, bytes, out) != bytes)
		abort();
	packet_bytes = 0;
}
static struct pci_dev pdev;
static struct device device;
static struct wiphy wiphy;
static struct ieee80211_hw hw = {.wiphy = &wiphy};
static struct rtw89_dev *new_dev(void)
{
	struct rtw89_dev *dev = calloc(1, sizeof(*dev) + sizeof(struct rtw89_pci));
	if (!dev)
		abort();
	dev->chip = &rtw8852b_chip_info;
	dev->pci_info = &rtw8852b_pci_info;
	dev->hci.ops = &rtw89_pci_ops;
	dev->hci.type = RTW89_HCI_TYPE_PCIE;
	dev->hw = &hw;
	dev->dev = &device;
	set_bit(RTW89_FLAG_POWERON, dev->flags);
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

static void secure(FILE *out)
{
	for (u32 base = 0; base < 0x10000; base += 32) {
		u32 sb = 0, v0 = 0, v1 = 0;
		for (u32 k = 0; k < 32; k++) {
			struct rtw89_dev *dev = new_dev();
			efuse_bytes[0] = (base + k) >> 8;
			efuse_bytes[1] = (base + k) & 0xff;
			if (rtw89_efuse_read_fw_secure_ax(dev))
				abort();
			sb |= (u32)dev->fw.sec.secure_boot << k;
			v0 |= (u32)dev->fw.sec.can_mss_v0 << k;
			v1 |= (u32)dev->fw.sec.can_mss_v1 << k;
			free_dev(dev);
		}
		record(140, base, sb);
		record(141, base, v0);
		record(142, base, v1);
	}
	efuse_fails = 1;
	struct rtw89_dev *dev = new_dev();
	int ret = rtw89_efuse_read_fw_secure_ax(dev);
	record(143, (u32)ret, dev->fw.sec.secure_boot | dev->fw.sec.can_mss_v0 << 1 |
			      dev->fw.sec.can_mss_v1 << 2);
	free_dev(dev);
	efuse_fails = 0;
	flush(out, false);
}
static u32 feature_word(const struct rtw89_dev *dev)
{
	u32 bits = 0, count = 0;
	for (u32 i = 0; i < ARRAY_SIZE(feature_bits); i++)
		bits |= (u32)test_bit(feature_bits[i], dev->fw.feature_map) << i;
	for (int i = 0; i < NUM_OF_RTW89_FW_FEATURES; i++)
		count += test_bit(i, dev->fw.feature_map);
	return bits | count << 16;
}
/* rtw89_fw_recognize's normal suit: the CE image first, as try_ce_fw asks. */
static void recognize(struct rtw89_dev *dev, const struct firmware *fw, u8 cut)
{
	dev->hal.cv = cut;
	dev->fw.req.firmware = fw;
	if (dev->chip->try_ce_fw && !__rtw89_fw_recognize(dev, RTW89_FW_NORMAL_CE, true))
		return;
	if (__rtw89_fw_recognize(dev, RTW89_FW_NORMAL, false))
		abort();
}
#define VER(a, b, c, d) RTW89_FW_VER_CODE(a, b, c, d)
static const u32 versions[] = {
	0, VER(0, 29, 25, 255), VER(0, 29, 26, 0), VER(0, 29, 28, 255), VER(0, 29, 29, 0),
	VER(0, 29, 29, 6), VER(0, 29, 29, 7), VER(0, 29, 29, 14), VER(0, 29, 29, 15),
	VER(0, 29, 29, 18), VER(0, 29, 29, 255), VER(0, 29, 30, 0), VER(0, 29, 126, 255),
	VER(0, 29, 127, 0), VER(0, 29, 127, 255), VER(0, 29, 128, 0), VER(0, 29, 129, 0),
	VER(0, 29, 130, 0), VER(0, 29, 255, 255), VER(0, 30, 0, 0), VER(1, 0, 0, 0), 0xffffffff,
};
static void features(FILE *out, const struct firmware *fw)
{
	for (u32 i = 0; i < ARRAY_SIZE(versions); i++) {
		struct rtw89_dev *dev = new_dev();
		rtw89_fw_iterate_feature_cfg(&dev->fw, dev->chip, versions[i]);
		record(150, versions[i], feature_word(dev));
		free_dev(dev);
	}
	for (u8 cut = 1; cut <= 2; cut++) {
		struct rtw89_dev *dev = new_dev();
		recognize(dev, fw, cut);
		rtw89_fw_recognize_features(dev);
		record(151, cut, feature_word(dev));
		free_dev(dev);
	}
	flush(out, false);
}

struct section { u8 kind; u32 size; bool checksum; u32 mssc; };
static const struct section syn_a[] = {{2, 4041, false, 0}, {1, 2012, true, 0}, {3, 0, false, 0},
				       {9, 100, true, 1}};
static const struct section syn_b[] = {{1, 2013, true, 0}, {2, 1, false, 0}};
static void put32(u8 *b, size_t at, u32 v) { memcpy(b + at, &v, 4); }
/* A legacy single image of header version 0: what the Rust test builds. */
static u8 *synthetic(u8 seed, const struct section *s, u32 n, u32 dynamic, size_t *len)
{
	u32 base = 32 + 16 * n, hdr = base + dynamic;
	size_t total = hdr;
	for (u32 i = 0; i < n; i++)
		total += s[i].size + (s[i].checksum ? 8 : 0) + s[i].mssc * 512;
	u8 *b = calloc(1, total);
	if (!b)
		abort();
	put32(b, 0, 0x00008852);
	put32(b, 4, 0x121d1d00);
	put32(b, 8, 0x12345678 ^ seed);
	put32(b, 12, dynamic ? hdr << 16 : 0);
	put32(b, 16, 0x2a0b0c0d);
	put32(b, 20, 2024);
	put32(b, 24, n << 8 | 0x11);
	put32(b, 28, 0x5a000000 | (dynamic ? 1U << 16 : 0) | 0x1234);
	for (u32 i = 0; i < n; i++) {
		size_t at = 32 + 16 * i;
		put32(b, at, 0xb8000000 + i * 0x100000);
		put32(b, at + 4, s[i].size | (u32)s[i].kind << 24 | (u32)s[i].checksum << 28);
		put32(b, at + 8, s[i].mssc);
		put32(b, at + 12, 0);
	}
	if (dynamic) {
		put32(b, base, dynamic);
		for (u32 k = 4; k < dynamic; k++)
			b[base + k] = k * 5 + seed;
	}
	size_t at = hdr;
	for (u32 i = 0; i < n; i++) {
		u32 length = s[i].size + (s[i].checksum ? 8 : 0);
		for (u32 k = 0; k < length; k++)
			b[at + k] = k * 31 + i * 17 + seed;
		at += length;
		for (u32 k = 0; k < s[i].mssc * 512; k++)
			b[at + k] = k * 13 + 0x5a;
		at += s[i].mssc * 512;
	}
	*len = total;
	return b;
}

enum image { SYN_A, SYN_B, PINNED };
#define OK {true, true, true, RTW89_FWDL_WCPU_FW_INIT_RDY}
#define STATUS(s) {true, true, true, s}
#define NO_H2C {true, false, true, RTW89_FWDL_WCPU_FW_INIT_RDY}
#define NO_FWDL {true, true, false, RTW89_FWDL_WCPU_FW_INIT_RDY}
#define HOLD(s) {false, true, true, s}
static const struct {
	enum image image;
	u8 cut;
	bool sticky;
	u32 n;
	struct behavior script[5];
} cases[] = {
	{SYN_A, 2, false, 1, {OK}},
	{SYN_B, 2, false, 1, {OK}},
	{PINNED, 1, false, 1, {OK}},
	{PINNED, 2, false, 1, {OK}},
	{SYN_A, 2, false, 2, {NO_H2C, OK}},
	{SYN_A, 2, false, 5, {NO_FWDL, STATUS(2), STATUS(3), STATUS(4), OK}},
	{SYN_B, 2, false, 1, {STATUS(1)}},
	{SYN_B, 2, false, 5, {STATUS(0), STATUS(5), STATUS(6), STATUS(2), STATUS(4)}},
	{SYN_B, 2, true, 1, {OK}},
	{PINNED, 2, false, 2, {HOLD(0), HOLD(RTW89_FWDL_WCPU_FW_INIT_RDY)}},
};
static u32 download(FILE *out, size_t c, const u8 *pinned, size_t pinned_len)
{
	size_t len = pinned_len;
	u8 *syn = NULL;
	if (cases[c].image == SYN_A)
		syn = synthetic(1, syn_a, ARRAY_SIZE(syn_a), 16, &len);
	else if (cases[c].image == SYN_B)
		syn = synthetic(2, syn_b, ARRAY_SIZE(syn_b), 0, &len);
	struct firmware fw = {syn ? syn : pinned, len};
	struct rtw89_dev *dev = new_dev();
	recognize(dev, &fw, cases[c].cut);
	/* rtw89_fw_recognize then recognizes the features, before the download. */
	rtw89_fw_recognize_features(dev);
	struct rtw89_fw_bin_info info = {0};
	if (rtw89_fw_hdr_parser(dev, &dev->fw.normal, &info))
		abort();
	expected = 1;
	for (u32 i = 0; i < info.section_num; i++)
		expected += DIV_ROUND_UP(info.section_info[i].len, info.part_size);

	struct rtw89_pci_tx_ring *tx = &pci_of(dev)->tx.rings[RTW89_TXCH_CH12];
	tx->bd_ring.head = calloc(RTW89_PCI_TXBD_NUM_MAX, sizeof(struct rtw89_pci_tx_bd_32));
	if (!tx->bd_ring.head)
		abort();
	tx->bd_ring.len = RTW89_PCI_TXBD_NUM_MAX;
	tx->bd_ring.addr = rtw89_pci_ch_dma_addr_set.tx[RTW89_TXCH_CH12];
	tx->txch = RTW89_TXCH_CH12;
	for (size_t i = 0; i < sizeof(memory); i++)
		memory[i] = i * 37 + 11;
	set(tx->bd_ring.addr.idx, 4, 0);
	script = cases[c].script;
	script_len = cases[c].n;
	sticky = cases[c].sticky;
	attempt = kicks = reads = host = 0;
	maps = 0;
	current = dev;

	/* rtw89_mac_partial_init's last two steps. */
	rtw89_mac_fwdl_preconfig(dev);
	int ret = rtw89_fw_download(dev, RTW89_FW_NORMAL, false);
	record(11, 0, (u32)ret);
	record(127, dev->fw.h2c_seq, 0);
	record(128, test_bit(RTW89_FLAG_FW_RDY, dev->flags), 0);
	flush(out, true);
	flush_packets(out);

	free(tx->bd_ring.head);
	free_dev(dev);
	free(syn);
	return expected;
}
int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	FILE *in = fopen(argv[1], "rb");
	if (!in)
		abort();
	static u8 pinned[16 << 20];
	size_t pinned_len = fread(pinned, 1, sizeof(pinned), in);
	if (!pinned_len || !feof(in))
		abort();
	fclose(in);
	FILE *out = fopen(argv[2], "wb");
	if (!out)
		abort();
	struct firmware fw = {pinned, pinned_len};
	secure(out);
	features(out, &fw);
	printf("{\"cases\": %zu, \"packets\": [", ARRAY_SIZE(cases));
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++)
		printf("%s%u", c ? ", " : "", download(out, c, pinned, pinned_len));
	printf("]}\n");
	if (fclose(out))
		abort();
	free(records);
	free(packets);
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, reg_h, pci_h_defines, txwd_defines, h2c_defines, fw_defines, core_macros,
        mac_defines, efuse_defines, declarations, pci_declarations, otp_tables, harness,
        core_h_inlines, mac_h_inlines, pci_h_inlines, dma_addr_set, blacklist, core_c, pci_c,
        mac_c, efuse_c, tables, fw_c, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function', '-Wno-address-of-packed-member',
                    str(generated), '-o', str(exe)], check=True)
    trace = out / 'trace.bin'
    run = subprocess.run([str(exe), str(image), str(trace)], check=True, capture_output=True,
                         text=True)
    result = json.loads(run.stdout)
    data = trace.read_bytes()
    pinned = image.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, cases=result['cases'],
        packets_per_attempt=result['packets'],
        case_order='secure-boot decision over all 65536 efuse pairs and a failed read; '
                   'features for 22 version codes and the pinned image at cuts 1 and 2; '
                   'downloads: A ok, B ok, pinned cut 1 ok, pinned cut 2 ok, '
                   'A H2C path stuck then ok, A FWDL path stuck then status 2, 3, 4 then ok, '
                   'B status 1 five times, B status 0, 5, 6, 2, 4, B WCPU_EN sticky, '
                   'pinned cut 2 with CH12 never read: status 0 then ok',
        image=dict(path=str(image.resolve()), bytes=len(pinned),
                   sha256=hashlib.sha256(pinned).hexdigest()),
        dispatch=dict(rtw8852b_chip_info=chip, rtw8852b_chip_ops=chip_ops,
                      rtw8852b_pci_info=pci_info,
                      rtw89_mac_gen_ax=mac_def, rtw89_pci_ops=hci_ops),
        dma=dict(command_buffers='0x80600000 + 0x3000 * n, per case'),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'MMIO, DMA addresses, skbs and the WCPU are a model; no ROM read any packet and no '
            'firmware ran, so FREERTOS_DONE is the model\'s answer',
            'PCIe RTL8852BE only; secure boot is off in every download, and the secure-boot '
            'decision is checked on its own',
            'read_poll_timeout is modeled counted in steps, not by Linux timekeeping',
            'the data path behind rtw89_core_tx_update_desc_info and the WD-page paths are '
            'stubs a firmware command never reaches; __parse_formatted_mssc is a stub no '
            'image here reaches',
            'the MSS recognizers run unchanged, but only the flags they set are recorded',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'packets_per_attempt', 'trace_bytes',
                                              'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
