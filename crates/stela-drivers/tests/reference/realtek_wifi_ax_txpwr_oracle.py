#!/usr/bin/env python3
"""Unchanged pinned rtw89 TX power and regulation for an RTL8852B.

Usage: script REFERENCE_DIRECTORY RTL8852B_IMAGE OUTPUT_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks; RTL8852B_IMAGE is the pinned
rtw89/rtw8852b_fw-2.bin. Extracted unchanged, each with its SHA-256 in
manifest.json:

- fw.c: rtw89_fw_recognize_elements with __fw_element_handlers,
  rtw89_mfw_get_size and its helpers, rtw89_fw_recognize_txpwr_from_elm,
  rtw89_recognize_regd_from_elm with rtw89_regd_entcpy and
  rtw89_for_each_in_regd_element, every fw_*_entry_valid check and
  rtw89_fw_load_txpwr_* / rtw89_fw_load_tx_shape_* loader with
  __fw_txpwr_entry_zero_ext and __fw_txpwr_entry_acceptable,
  rtw89_fw_has_da_txpwr_table and rtw89_load_rfe_data_from_fw;
- phy.c: rtw89_phy_raw_byr_seek, rtw89_phy_read_txpwr_byrate,
  rtw89_phy_read_txpwr_limit and _limit_ru with their channel indexing,
  bandwidth check and TPE constraint, every rtw89_phy_fill_txpwr_limit*_ax,
  rtw89_phy_set_txpwr_byrate_ax, _offset_ax, _limit_ax and _limit_ru_ax,
  the antenna gain gates (rtw89_can_apply_ant_gain, rtw89_phy_ant_gain_offset,
  rtw89_phy_ant_gain_pwr_offset), rtw89_phy_write32_idx and
  rtw89_phy0_phy1_offset;
- rtw8852b_common.c: __rtw8852bx_set_txpwr, __rtw8852bx_set_txpwr_ctrl,
  rtw8852bx_set_txpwr_ref, rtw8852bx_bb_cal_txpwr_ref,
  rtw8852bx_set_tx_shape, rtw8852bx_bb_set_tx_shape_dfir,
  rtw8852bx_set_txpwr_diff and rtw8852bx_get_txpwr_sar_diff;
- mac.c: rtw89_mac_get_txpwr_cr_ax; mac.h: rtw89_mac_reg_by_idx and
  rtw89_mac_txpwr_write32 with its mask variant;
- regd.c: rtw89_ww_regd, rtw89_regd_map with COUNTRY_REGD,
  rtw89_regd_find_reg_by_name, rtw89_regd_is_ww, rtw89_regd_get_index(_by_name),
  rtw89_regd_setup, rtw89_regd_setup_unii4, rtw89_regd_setup_reg_rules,
  rtw89_regd_init_hint, rtw89_regd_apply_policy_unii4 and
  rtw89_regd_notifier_apply;
- core.h, phy.h, fw.h, sar.h, reg.h, rtw8852b_common.h: the enums, structs,
  defines and inline helpers those name (rtw89_regd_get,
  rtw89_get_tx_shape_idx, rtw89_load_txpwr_table, rtw89_txpwr_entcpy,
  rtw89_for_each_in_txpwr_conf, rtw89_write32_mask, rtw89_phy_write32_mask,
  the rtw89_phy_txpwr_* conversions and the rtw89_phy_set_txpwr_* dispatch).

rtw8852b_chip_info's rf_path_num, txpwr factors, support_bands,
support_unii4, support_ant_gain and rfe_parms_conf, rtw89_phy_gen_ax's
cr_base and set_txpwr_* and rtw89_mac_gen_ax's band1_offset and
get_txpwr_cr are checked and used.

The harness's: rtw89_read32/rtw89_write32 over a 128 KiB BAR whose byte i
starts as i * 37 + 11, every access recorded; rtw89_dev with the members
reached; __fw_element_handlers' other handlers defined to ignore their
elements and needed_fw_elms 0, so the unchanged walk runs the TX power and
REGD handlers alone; rtw8852b's dflt_parms as an empty rtw89_rfe_parms, the
Rust port carrying no compiled tables, each table RTL8852B reads checked
filled from the firmware; rtw89_acpi_evaluate_dsm failing (Stela evaluates
no ACPI DSM); rtw89_regd_setup_6ghz doing nothing, as the real one does
without a 6 GHz band; rtw89_regd_notifier as the real one's programmed
check, rtw89_regd_notifier_apply and rtw89_regd_apply_policy_unii4, without
its lock, power save exit, 6 GHz, TAS and antenna gain policies and the
set_txpwr it ends with; rtw89_query_sar returning the case's cap by NTX
(63, RTW89_SAR_TXPWR_MAC_MAX, when uncapped): where Stela puts regulatory.db's
EIRP; rtw89_phy_ant_gain_query aborting (no case reaches it, antenna gain
being off without ACPI). cfg80211 is two notifier calls, each after the
channels' flags are set back to their original ones as cfg80211's updates
set them: "00" from the core when ieee80211_register_hw registers the
wiphy, between rtw89_regd_setup and rtw89_regd_init_hint, then the stack's
alpha2 as a user request.

Cases, in the trace's order: the TX power tables of RFE 1; regulations for
the element's map and rtw89_regd_map, efuse country blank, ID, US or XX,
the stack's ID, US, GB, CA, 00 or XX; set_txpwr for RFE 1, then the tables
and set_txpwr for RFE 0; rtw8852bx_set_txpwr_ref at several offsets;
__rtw8852bx_set_txpwr_ctrl.

trace.bin: segments, each prefixed by its byte length, of little-endian u32
unless stated:
- kind 1, a regulation: 1, map (0 element, 1 rtw89_regd_map), efuse
  country and stack alpha2 (two bytes as a u16), the chosen regd's alpha2,
  txpwr_regd[0..3] and func_bitmap, rtw89_regd_get for 2.4 and 5 GHz,
  programmed, rtw89_regd_is_ww, the UNII-4 channels left disabled (bit i
  for rtw89_channels_5ghz[25 + i]) and the map's size;
- kind 2, the tables: 2, RFE, has_da, each struct rtw89_rfe_data conf's
  rfe_type in its order (0xffffffff when invalid), then the bytes of byr,
  lmt_2ghz.v, lmt_5ghz.v, lmt_ru_2ghz.v, lmt_ru_5ghz.v, tx_shape_lmt.v and
  tx_shape_lmt_ru.v as loaded;
- kind 3, set_txpwr: 3, RFE, map, stack alpha2, band, channel, primary
  channel, bandwidth, the cap at 1TX and 2TX (s8 as u32), then per access
  its tag (reads 4, writes 8), register and value;
- kind 4, a reference: 4, pwr_ofst (s16 as u32), then the accesses;
- kind 5, set_txpwr_ctrl: 5, then the accesses.
"""
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
RFES = [1, 0]
EFUSES = [b'\xff\xff', b'ID', b'US', b'XX']
STACKS = [b'ID', b'US', b'GB', b'CA', b'00', b'XX']
COUNTRIES = [b'ID', b'US']
# band, channel, primary, bandwidth
CHANNELS = [
    (0, 1, 1, 0), (0, 3, 1, 1), (0, 6, 6, 0), (0, 4, 6, 1), (0, 8, 6, 1),
    (0, 13, 13, 0), (0, 11, 13, 1),
    (1, 36, 36, 0), (1, 38, 36, 1), (1, 42, 36, 2),
    (1, 100, 100, 0), (1, 102, 100, 1), (1, 106, 100, 2),
    (1, 149, 149, 0), (1, 151, 149, 1), (1, 155, 149, 2),
]
OFFSETS = [0, 8, -8, 100, -100, 300, -300, 32767, -32768]


def cap(eirp_mbm):
    """Stela's cap for an EIRP: less 6 dBi, and 3.01 dB more for 2TX, in
    half dB floored, held to -64..63."""
    return tuple(max(-64, min(63, (eirp_mbm - less) // 50)) for less in (600, 901))


UNCAPPED = (63, 63)


def u16(alpha2):
    return alpha2[0] | alpha2[1] << 8


def txpwr_cases():
    cases = []
    for rfe in RFES:
        for country in COUNTRIES:
            for chan in CHANNELS:
                cases.append((rfe, 0, country) + chan + UNCAPPED)
        if rfe != 1:
            continue
        cases += [
            (1, 1, b'ID', 0, 6, 6, 0) + UNCAPPED,
            (1, 1, b'ID', 1, 42, 36, 2) + UNCAPPED,
            (1, 0, b'ID', 0, 1, 1, 0) + cap(2000),
            (1, 0, b'ID', 1, 38, 36, 1) + cap(2300),
            (1, 0, b'ID', 1, 155, 149, 2) + cap(600),
            (1, 0, b'US', 1, 169, 169, 0) + UNCAPPED,
            (1, 0, b'US', 1, 171, 165, 2) + UNCAPPED,
            (1, 0, b'JP', 0, 14, 14, 0) + UNCAPPED,
        ]
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

    def in_order(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        found = sorted(locate(file, name) for name in names)
        return '\n\n'.join(body for _, body in found)

    def functions(file, names):
        return '\n\n'.join(locate(file, name)[1] for name in names)

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
        m = re.search(r'^' + re.escape(head) + r' =\s*\{', text, re.M)
        if not m:
            raise ValueError(f'{file}: no {head}')
        end = text.index(';', closing(text, text.index('{', m.start()))) + 1
        return record(file, head, text[m.start():end])

    def statement(file, head):
        """A declaration from its head through its semicolon."""
        text = source(file)
        start = text.find(head)
        if start < 0 or text.find(head, start + 1) >= 0:
            raise ValueError(f'{file}: {head} is not unique')
        return record(file, head, text[start:text.index(';', start) + 1])

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
        """Members of a designated initializer by name."""
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

    chip = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  ['support_bands', 'support_unii4', 'support_ant_gain', 'rf_path_num',
                   'txpwr_factor_bb', 'txpwr_factor_rf', 'txpwr_factor_mac', 'rfe_parms_conf',
                   'dflt_parms'])
    expected_chip = {
        'support_bands': 'BIT(NL80211_BAND_2GHZ) | BIT(NL80211_BAND_5GHZ)',
        'support_unii4': 'true', 'support_ant_gain': 'true', 'rf_path_num': '2',
        'txpwr_factor_bb': '3', 'txpwr_factor_rf': '2', 'txpwr_factor_mac': '1',
        'rfe_parms_conf': 'NULL', 'dflt_parms': '&rtw89_8852b_dflt_parms',
    }
    if chip != expected_chip:
        raise ValueError(f'rtw8852b_chip_info is {chip}')
    phy_gen = fields('phy.c', 'const struct rtw89_phy_gen_def rtw89_phy_gen_ax',
                     ['cr_base', 'set_txpwr_byrate', 'set_txpwr_offset', 'set_txpwr_limit',
                      'set_txpwr_limit_ru'])
    expected_phy = {
        'cr_base': '0x10000', 'set_txpwr_byrate': 'rtw89_phy_set_txpwr_byrate_ax',
        'set_txpwr_offset': 'rtw89_phy_set_txpwr_offset_ax',
        'set_txpwr_limit': 'rtw89_phy_set_txpwr_limit_ax',
        'set_txpwr_limit_ru': 'rtw89_phy_set_txpwr_limit_ru_ax',
    }
    if phy_gen != expected_phy:
        raise ValueError(f'rtw89_phy_gen_ax is {phy_gen}')
    mac_gen = fields('mac.c', 'const struct rtw89_mac_gen_def rtw89_mac_gen_ax',
                     ['band1_offset', 'get_txpwr_cr'])
    if mac_gen != {'band1_offset': 'RTW89_MAC_AX_BAND_REG_OFFSET',
                   'get_txpwr_cr': 'rtw89_mac_get_txpwr_cr_ax'}:
        raise ValueError(f'rtw89_mac_gen_ax is {mac_gen}')
    ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                 ['set_txpwr', 'set_txpwr_ctrl'])
    if ops != {'set_txpwr': 'rtw8852bx_set_txpwr', 'set_txpwr_ctrl': 'rtw8852bx_set_txpwr_ctrl'}:
        raise ValueError(f'rtw8852b_chip_ops is {ops}')
    common_ops = fields('rtw8852b_common.c',
                        'const struct rtw8852bx_info rtw8852bx_info',
                        ['set_txpwr', 'set_txpwr_ctrl'])
    if common_ops != {'set_txpwr': '__rtw8852bx_set_txpwr',
                      'set_txpwr_ctrl': '__rtw8852bx_set_txpwr_ctrl'}:
        raise ValueError(f'rtw8852bx_info is {common_ops}')

    constants = '\n'.join([
        defines('core.h', ['RTW89_2G_CH_NUM', 'RTW89_5G_CH_NUM', 'RTW89_6G_CH_NUM',
                           'RTW89_2G_BW_NUM', 'RTW89_5G_BW_NUM', 'RTW89_6G_BW_NUM',
                           'RTW89_BYR_BW_NUM', 'RTW89_TXPWR_CONF_DFLT_RFE_TYPE',
                           'RTW89_REGD_MAX_COUNTRY_NUM', 'RTW89_5GHZ_UNII4_CHANNEL_NUM',
                           'RTW89_5GHZ_UNII4_START_INDEX', 'RF_PATH_MAX',
                           'DELTA_SWINGIDX_SIZE']),
        defines('phy.h', ['RTW89_TXPWR_LMT_PAGE_SIZE_AX', 'RTW89_RU_SEC_NUM_AX',
                          'RTW89_TXPWR_LMT_RU_PAGE_SIZE_AX']),
        defines('sar.h', ['RTW89_SAR_TXPWR_MAC_MAX']),
        defines('mac.h', ['RTW89_MAC_AX_BAND_REG_OFFSET']),
        defines('rtw8852b_common.h', ['RF_PATH_NUM_8852BX']),
        defines('reg.h', ['R_AX_PWR_RATE_CTRL', 'B_AX_PWR_REF', 'R_AX_PWR_RATE_OFST_CTRL',
                          'R_AX_PWR_BY_RATE_TABLE0', 'R_AX_PWR_BY_RATE', 'R_AX_PWR_LMT_TABLE0',
                          'R_AX_PWR_LMT', 'R_AX_PWR_RU_LMT_TABLE0', 'R_AX_PWR_RU_LMT',
                          'CMAC1_START_ADDR_AX', 'CMAC1_END_ADDR_AX', 'R_TXFIR0', 'R_DCFO_OPT',
                          'B_TXSHAPE_TRIANGULAR_CFG', 'B_DPD_TSSI_CW', 'B_DPD_PWR_CW',
                          'B_DPD_REF']),
        defines('fw.h', ['RTW89_MFW_SIG', 'RTW89_FW_ELEMENT_ALIGN']),
        lines('fw.h', '#define FW_HDR_', 'FW_HDR_* defines'),
        macro('core.h', 'rtw89_txpwr_conf_valid'),
    ])
    declarations = '\n\n'.join([
        declaration('core.h', 'enum', 'rtw89_rf_path'),
        declaration('core.h', 'enum', 'rtw89_band'),
        declaration('core.h', 'enum', 'rtw89_subband'),
        declaration('core.h', 'enum', 'rtw89_tx_comp_band'),
        declaration('core.h', 'enum', 'rtw89_rate_section'),
        declaration('core.h', 'enum', 'rtw89_rate_offset_indexes'),
        declaration('core.h', 'enum', 'rtw89_rate_num'),
        declaration('core.h', 'enum', 'rtw89_nss'),
        declaration('core.h', 'enum', 'rtw89_ntx'),
        declaration('core.h', 'enum', 'rtw89_beamforming_type'),
        declaration('core.h', 'enum', 'rtw89_ofdma_type'),
        declaration('core.h', 'enum', 'rtw89_regulation_type'),
        declaration('core.h', 'enum', 'rtw89_reg_6ghz_power'),
        declaration('core.h', 'struct', 'rtw89_reg_6ghz_tpe'),
        declaration('core.h', 'struct', 'rtw89_txpwr_byrate'),
        declaration('core.h', 'struct', 'rtw89_rate_desc'),
        declaration('core.h', 'enum', 'rtw89_phy_idx'),
        declaration('core.h', 'enum', 'rtw89_bandwidth'),
        declaration('core.h', 'enum', 'rtw89_ru_bandwidth'),
        declaration('core.h', 'enum', 'rtw89_sc_offset'),
        declaration('core.h', 'enum', 'rtw89_rfsi_ctrl_band'),
        declaration('core.h', 'struct', 'rtw89_chan'),
        declaration('core.h', 'enum', 'rtw89_hci_type'),
        declaration('core.h', 'enum', 'rtw89_qta_mode'),
        declaration('core.h', 'enum', 'rtw89_fw_type'),
        declaration('core.h', 'struct', 'rtw89_reg2_def'),
        declaration('core.h', 'struct', 'rtw89_phy_table'),
        declaration('core.h', 'struct', 'rtw89_txpwr_table'),
        declaration('core.h', 'struct', 'rtw89_txpwr_rule_2ghz'),
        declaration('core.h', 'struct', 'rtw89_txpwr_rule_5ghz'),
        declaration('core.h', 'struct', 'rtw89_txpwr_rule_6ghz'),
        declaration('core.h', 'struct', 'rtw89_tx_shape'),
        declaration('core.h', 'struct', 'rtw89_rfe_parms'),
        declaration('core.h', 'struct', 'rtw89_txpwr_conf'),
        declaration('core.h', 'struct', 'rtw89_txpwr_byrate_data'),
        declaration('core.h', 'struct', 'rtw89_txpwr_lmt_2ghz_data'),
        declaration('core.h', 'struct', 'rtw89_txpwr_lmt_5ghz_data'),
        declaration('core.h', 'struct', 'rtw89_txpwr_lmt_6ghz_data'),
        declaration('core.h', 'struct', 'rtw89_txpwr_lmt_ru_2ghz_data'),
        declaration('core.h', 'struct', 'rtw89_txpwr_lmt_ru_5ghz_data'),
        declaration('core.h', 'struct', 'rtw89_txpwr_lmt_ru_6ghz_data'),
        declaration('core.h', 'struct', 'rtw89_tx_shape_lmt_data'),
        declaration('core.h', 'struct', 'rtw89_tx_shape_lmt_ru_data'),
        declaration('core.h', 'struct', 'rtw89_rfe_data'),
        declaration('core.h', 'enum', 'rtw89_regd_func'),
        declaration('core.h', 'struct', 'rtw89_regd'),
        declaration('core.h', 'struct', 'rtw89_regd_data'),
        declaration('core.h', 'struct', 'rtw89_regd_ctrl'),
        declaration('core.h', 'struct', 'rtw89_regulatory_info'),
        declaration('phy.h', 'enum', 'rtw89_phy_c2h_rfk_log_func'),
        declaration('phy.h', 'enum', 'rtw89_bandwidth_section_num_ax'),
        declaration('phy.h', 'struct', 'rtw89_txpwr_limit_ax'),
        declaration('phy.h', 'struct', 'rtw89_txpwr_limit_ru_ax'),
        declaration('sar.h', 'struct', 'rtw89_sar_parm'),
        declaration('fw.h', 'struct', 'rtw89_mfw_info'),
        declaration('fw.h', 'struct', 'rtw89_mfw_hdr'),
        declaration('fw.h', 'enum', 'rtw89_fw_element_id'),
        declaration('fw.h', 'struct', '__rtw89_fw_txpwr_element'),
        declaration('fw.h', 'struct', '__rtw89_fw_regd_element'),
        declaration('fw.h', 'enum', 'rtw89_fw_txpwr_trk_type'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_track_cfg'),
        declaration('fw.h', 'struct', 'rtw89_fw_element_hdr'),
        declaration('fw.h', 'struct', 'rtw89_fw_regd_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_byrate_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_lmt_2ghz_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_lmt_5ghz_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_lmt_6ghz_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_lmt_ru_2ghz_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_lmt_ru_5ghz_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_txpwr_lmt_ru_6ghz_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_tx_shape_lmt_entry'),
        declaration('fw.h', 'struct', 'rtw89_fw_tx_shape_lmt_ru_entry'),
        declaration('phy.h', 'struct', 'rtw89_phy_rfk_log_fmt'),
        declaration('core.h', 'struct', 'rtw89_fw_elm_info'),
        declaration('fw.c', 'union', 'rtw89_fw_element_arg'),
        declaration('fw.c', 'struct', 'rtw89_fw_element_handler'),
    ])
    inline_core = '\n\n'.join([
        functions('core.h', ['rtw89_write32_mask', 'rtw89_hw_to_nl80211_band',
                             'rtw89_regd_get', 'rtw89_get_tx_shape_idx',
                             'rtw89_load_txpwr_table', 'rtw89_txpwr_entcpy']),
        macro('core.h', 'rtw89_for_each_in_txpwr_conf'),
        functions('mac.h', ['rtw89_mac_reg_by_idx', 'rtw89_mac_txpwr_write32',
                            'rtw89_mac_txpwr_write32_mask']),
        functions('phy.h', ['rtw89_phy_write32_mask', 'rtw89_phy_set_txpwr_byrate',
                            'rtw89_phy_set_txpwr_offset', 'rtw89_phy_set_txpwr_limit',
                            'rtw89_phy_set_txpwr_limit_ru', 'rtw89_phy_txpwr_rf_to_bb',
                            'rtw89_phy_txpwr_rf_to_mac', 'rtw89_phy_txpwr_dbm_to_mac',
                            'rtw89_phy_txpwr_mac_to_bb']),
    ])
    phy_c = '\n\n'.join([
        definition('phy.c', 'static const u8 rtw89_rs_idx_num_ax[]'),
        definition('phy.c', 'static const u8 rtw89_rs_nss_num_ax[]'),
        macro('phy.c', '__fill_txpwr_limit_nonbf_bf'),
        in_order('phy.c', [
            'rtw89_phy0_phy1_offset', 'rtw89_phy_write32_idx', 'rtw89_phy_ant_gain_offset',
            'rtw89_can_apply_ant_gain', 'rtw89_phy_ant_gain_pwr_offset',
            'rtw89_phy_raw_byr_seek', 'rtw89_phy_txpwr_dbm_without_tolerance',
            'rtw89_phy_get_tpe_constraint', 'rtw89_phy_read_txpwr_byrate',
            'rtw89_channel_6g_to_idx', 'rtw89_channel_to_idx',
            'rtw89_phy_validate_txpwr_limit_bw', 'rtw89_phy_read_txpwr_limit',
            'rtw89_phy_fill_txpwr_limit_20m_ax', 'rtw89_phy_fill_txpwr_limit_40m_ax',
            'rtw89_phy_fill_txpwr_limit_80m_ax', 'rtw89_phy_fill_txpwr_limit_160m_ax',
            'rtw89_phy_fill_txpwr_limit_ax', 'rtw89_phy_read_txpwr_limit_ru',
            'rtw89_phy_fill_txpwr_limit_ru_20m_ax', 'rtw89_phy_fill_txpwr_limit_ru_40m_ax',
            'rtw89_phy_fill_txpwr_limit_ru_80m_ax', 'rtw89_phy_fill_txpwr_limit_ru_160m_ax',
            'rtw89_phy_fill_txpwr_limit_ru_ax', 'rtw89_phy_set_txpwr_byrate_ax',
            'rtw89_phy_set_txpwr_offset_ax', 'rtw89_phy_set_txpwr_limit_ax',
            'rtw89_phy_set_txpwr_limit_ru_ax']),
    ])
    skipped = ['__rtw89_fw_recognize_from_elm', 'rtw89_build_phy_tbl_from_elm',
               'rtw89_build_txpwr_trk_tbl_from_elm', 'rtw89_build_rfk_log_fmt_from_elm',
               'rtw89_build_afe_pwr_seq_from_elm', 'rtw89_recognize_diag_mac_from_elm',
               'rtw89_build_tx_comp_from_elm']
    loaders = [
        'rtw89_fw_load_txpwr_byrate', 'rtw89_fw_load_txpwr_lmt_2ghz',
        'rtw89_fw_load_txpwr_lmt_5ghz', 'rtw89_fw_load_txpwr_lmt_6ghz',
        'rtw89_fw_load_txpwr_lmt_ru_2ghz', 'rtw89_fw_load_txpwr_lmt_ru_5ghz',
        'rtw89_fw_load_txpwr_lmt_ru_6ghz', 'rtw89_fw_load_tx_shape_lmt',
        'rtw89_fw_load_tx_shape_lmt_ru']
    checks = [
        'fw_txpwr_byrate_entry_valid', 'fw_txpwr_lmt_2ghz_entry_valid',
        'fw_txpwr_lmt_5ghz_entry_valid', 'fw_txpwr_lmt_6ghz_entry_valid',
        'fw_txpwr_lmt_ru_2ghz_entry_valid', 'fw_txpwr_lmt_ru_5ghz_entry_valid',
        'fw_txpwr_lmt_ru_6ghz_entry_valid', 'fw_tx_shape_lmt_entry_valid',
        'fw_tx_shape_lmt_ru_entry_valid']
    fw_c = '\n\n'.join([
        in_order('fw.c', ['rtw89_mfw_get_hdr_ptr', 'rtw89_mfw_validate_hdr',
                          'rtw89_mfw_get_size', 'rtw89_fw_recognize_txpwr_from_elm',
                          'rtw89_regd_entcpy']),
        macro('fw.c', 'rtw89_for_each_in_regd_element'),
        locate('fw.c', 'rtw89_recognize_regd_from_elm')[1],
        '\n'.join(f'#define {name} skip_element' for name in skipped),
        definition('fw.c', 'static const struct rtw89_fw_element_handler __fw_element_handlers[]'),
        '\n'.join(f'#undef {name}' for name in skipped),
        locate('fw.c', 'rtw89_fw_recognize_elements')[1],
        macro('fw.c', '__fw_txpwr_entry_acceptable'),
        in_order('fw.c', ['__fw_txpwr_entry_zero_ext'] + checks + loaders
                 + ['rtw89_fw_has_da_txpwr_table', 'rtw89_load_rfe_data_from_fw']),
    ])
    mac_c = locate('mac.c', 'rtw89_mac_get_txpwr_cr_ax')[1]
    common_c = in_order('rtw8852b_common.c', [
        'rtw8852bx_bb_cal_txpwr_ref', 'rtw8852bx_set_txpwr_ref',
        'rtw8852bx_bb_set_tx_shape_dfir', 'rtw8852bx_set_tx_shape',
        'rtw8852bx_get_txpwr_sar_diff', 'rtw8852bx_set_txpwr_diff', '__rtw8852bx_set_txpwr',
        '__rtw8852bx_set_txpwr_ctrl'])
    regd_c = '\n\n'.join([
        macro('regd.c', 'COUNTRY_REGD'),
        statement('regd.c', 'static const struct rtw89_regd rtw89_ww_regd ='),
        definition('regd.c', 'static const struct rtw89_regd rtw89_regd_map[]'),
        macro('regd.c', 'rtw89_debug_regd'),
        in_order('regd.c', [
            'rtw89_regd_find_reg_by_name', 'rtw89_regd_is_ww', 'rtw89_regd_get_index',
            'rtw89_regd_get_index_by_name', 'rtw89_regd_setup_unii4',
            'rtw89_regd_setup_reg_rules', 'rtw89_regd_setup', 'rtw89_regd_init_hint',
            'rtw89_regd_apply_policy_unii4', 'rtw89_regd_notifier_apply']),
    ])

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
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32;
typedef uint16_t __le16; typedef uint32_t __le32;
#define BIT(n) (1U << (n))
#define U8_MAX 255
#define S8_MAX 127
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a) (((x) + ((__typeof__(x))(a) - 1)) & ~((__typeof__(x))(a) - 1))
#define min(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b; })
#define max(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a > _b ? _a : _b; })
#define min3(a, b, c) min(min(a, b), c)
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define clamp_t(t, v, lo, hi) min_t(t, max((t)(v), (t)(lo)), (t)(hi))
#define abs(x) ({ __typeof__(x) _x = (x); _x < 0 ? -_x : _x; })
#define __packed __attribute__((packed))
#define __counted_by(m)
#define __force
#define BUILD_BUG_ON(c) ((void)sizeof(char[1 - 2 * !!(c)]))
#define __ffs(m) ((u32)__builtin_ctz(m))
#define __bf_shf(m) (__builtin_ffsll(m) - 1)
#define FIELD_PREP(m, v) (((__typeof__(m))(v) << __bf_shf(m)) & (m))
#define u32_get_bits(v, m) ((((u32)(v)) & (m)) >> __ffs(m))
#define u16_get_bits(v, m) ((u16)((((u16)(v)) & (m)) >> __ffs(m)))
#define u8_get_bits(v, m) ((u8)((((u8)(v)) & (m)) >> __ffs(m)))
#define u32_encode_bits(v, m) ((((u32)(v)) << __ffs(m)) & (m))
#define u8_encode_bits(v, m) ((u8)((((u32)(v)) << __ffs(m)) & (m)))
#define le32_get_bits(v, m) u32_get_bits(v, m)
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define typecheck(t, x) 1
#define BITS_PER_LONG 64
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
static void set_bit(long nr, unsigned long *addr) { addr[nr / 64] |= 1UL << (nr % 64); }
static void clear_bit(long nr, unsigned long *addr) { addr[nr / 64] &= ~(1UL << (nr % 64)); }
static bool test_bit(long nr, const unsigned long *addr) { return addr[nr / 64] >> (nr % 64) & 1; }
static void bitmap_fill(unsigned long *addr, unsigned int bits)
{
	for (unsigned int i = 0; i < bits; i++)
		set_bit(i, addr);
}
#define GFP_KERNEL 0
#define kzalloc_obj(x, ...) ((__typeof__(&(x)))calloc(1, sizeof(x)))
#define kfree(p) free((void *)(p))
#define devm_kzalloc(d, size, gfp) calloc(1, (size))
#define devm_kfree(d, p) free((void *)(p))
#define RTW89_DBG_TXPWR BIT(0)
#define RTW89_DBG_REGD BIT(8)
#define RTW89_DBG_FW BIT(12)
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_info(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), (void)(m), sink(__VA_ARGS__))
/* RTW89_CHK_FW_FEATURE is reached only with antenna gain on, which no
 * case has. */
#define RTW89_CHK_FW_FEATURE(f, fw) (abort(), 0)
#define EXPORT_SYMBOL(s)
#define unlikely(x) (x)
#define static_assert(e, ...) _Static_assert(e, #e)
/* rtw89_write32_mask warns on a misaligned register: no case makes one. */
#define WARN(c, ...) ({ bool _w = !!(c); if (_w) abort(); _w; })
enum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_60GHZ,
		    NL80211_BAND_6GHZ, NUM_NL80211_BANDS };
enum nl80211_reg_initiator { NL80211_REGDOM_SET_BY_CORE, NL80211_REGDOM_SET_BY_USER };
#define REGULATORY_STRICT_REG BIT(1)
#define REGULATORY_COUNTRY_IE_IGNORE BIT(4)
#define IEEE80211_CHAN_DISABLED BIT(0)
struct ieee80211_channel { u32 flags; u16 hw_value; };
struct ieee80211_supported_band { struct ieee80211_channel *channels; int n_channels; };
struct regulatory_request { char alpha2[3]; enum nl80211_reg_initiator initiator; };
struct wiphy {
	struct ieee80211_supported_band *bands[NUM_NL80211_BANDS];
	u32 regulatory_flags;
	void (*reg_notifier)(struct wiphy *wiphy, struct regulatory_request *request);
};
struct ieee80211_hw { struct wiphy *wiphy; };
struct device { int unused; };
struct firmware { const u8 *data; size_t size; };
static u32 ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	if (band == NL80211_BAND_2GHZ)
		return chan == 14 ? 2484 : 2407 + chan * 5;
	return 5000 + chan * 5;
}
static int regulatory_hint(struct wiphy *wiphy, const char *alpha2)
{
	(void)wiphy; (void)alpha2;
	return 0;
}
enum rtw89_acpi_dsm_func { RTW89_ACPI_DSM_FUNC_UNII4_SUP = 6,
			   RTW89_ACPI_DSM_FUNC_REG_RULES_EN = 10 };
enum rtw89_acpi_conf_unii4 { RTW89_ACPI_CONF_UNII4_US = BIT(0), RTW89_ACPI_CONF_UNII4_CA = BIT(1) };
enum rtw89_acpi_conf_reg_rules { RTW89_ACPI_CONF_REG_RULE_REGD_UK = BIT(0) };
struct rtw89_acpi_policy_reg_rules { u8 signature[4]; u8 revision; u8 conf; u8 rsvd[3]; } __packed;
struct rtw89_acpi_dsm_result {
	union { u8 value; struct rtw89_acpi_policy_reg_rules *policy_reg_rules; } u;
};
struct rtw89_dev;
'''
    harness = r'''
struct rtw89_phy_gen_def {
	u32 cr_base;
	u32 (*phy0_phy1_offset)(struct rtw89_dev *rtwdev, u32 addr);
	void (*set_txpwr_byrate)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				 enum rtw89_phy_idx phy_idx);
	void (*set_txpwr_offset)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				 enum rtw89_phy_idx phy_idx);
	void (*set_txpwr_limit)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				enum rtw89_phy_idx phy_idx);
	void (*set_txpwr_limit_ru)(struct rtw89_dev *rtwdev, const struct rtw89_chan *chan,
				   enum rtw89_phy_idx phy_idx);
};
struct rtw89_mac_gen_def {
	u32 band1_offset;
	bool (*get_txpwr_cr)(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy_idx,
			     u32 reg_base, u32 *cr);
};
struct rtw89_chip_info {
	const struct rtw89_phy_gen_def *phy_def;
	const struct rtw89_mac_gen_def *mac_def;
	u32 needed_fw_elms;
	u32 support_bands;
	bool support_unii4;
	bool support_ant_gain;
	u8 rf_path_num;
	u8 txpwr_factor_bb, txpwr_factor_rf, txpwr_factor_mac;
};
struct rtw89_hal { u8 cv; u16 aid; };
struct rtw89_efuse { u8 rfe_type; char country_code[2]; };
struct rtw89_fw_req_info { const struct firmware *firmware; };
struct rtw89_fw_info { struct rtw89_fw_req_info req; struct rtw89_fw_elm_info elm_info; };
struct rtw89_ant_gain_info { u32 regd_enabled; bool block_country; };
struct rtw89_mac_info { enum rtw89_qta_mode qta_mode; };
struct rtw89_hci_info { enum rtw89_hci_type type; };
struct rtw89_dev {
	const struct rtw89_chip_info *chip;
	struct rtw89_hal hal;
	struct rtw89_efuse efuse;
	struct rtw89_fw_info fw;
	struct rtw89_rfe_data *rfe_data;
	const struct rtw89_rfe_parms *rfe_parms;
	struct rtw89_txpwr_byrate byr[RTW89_BAND_NUM][RTW89_BYR_BW_NUM];
	struct rtw89_regulatory_info regulatory;
	struct rtw89_ant_gain_info ant_gain;
	struct rtw89_mac_info mac;
	struct rtw89_hci_info hci;
	bool dbcc_en;
	struct device *dev;
	struct ieee80211_hw *hw;
};
/* BAR2: byte i starts as i * 37 + 11; every access is recorded. */
static u8 memory[0x20000];
static u8 *seg;
static size_t seg_len, seg_cap;
static void putb(const void *p, size_t n)
{
	if (seg_len + n > seg_cap) {
		seg_cap = (seg_len + n) * 2;
		seg = realloc(seg, seg_cap);
		if (!seg)
			abort();
	}
	memcpy(seg + seg_len, p, n);
	seg_len += n;
}
static void put32(u32 v) { putb(&v, 4); }
static void access(u32 tag, u32 r, u32 v) { put32(tag); put32(r); put32(v); }
static void reset_memory(void)
{
	for (size_t i = 0; i < sizeof(memory); i++)
		memory[i] = (u8)(i * 37 + 11);
}
static u32 rtw89_read32(struct rtw89_dev *d, u32 r)
{
	(void)d;
	if (r & 3 || r + 4 > sizeof(memory))
		abort();
	u32 v;
	memcpy(&v, memory + r, 4);
	access(4, r, v);
	return v;
}
static void rtw89_write32(struct rtw89_dev *d, u32 r, u32 v)
{
	(void)d;
	if (r & 3 || r + 4 > sizeof(memory))
		abort();
	access(8, r, v);
	memcpy(memory + r, &v, 4);
}
/* What stands where rtw89 asks SAR: the case's cap by NTX. */
static s8 harness_cap[RTW89_NTX_NUM] = {RTW89_SAR_TXPWR_MAC_MAX, RTW89_SAR_TXPWR_MAC_MAX};
static s8 rtw89_query_sar(struct rtw89_dev *d, const struct rtw89_sar_parm *p)
{
	(void)d;
	if (p->ntx >= RTW89_NTX_NUM)
		abort();
	return harness_cap[p->ntx];
}
static s8 rtw89_phy_ant_gain_query(struct rtw89_dev *d, enum rtw89_rf_path path, u32 freq)
{
	(void)d; (void)path; (void)freq;
	abort();
}
static int rtw89_acpi_evaluate_dsm(struct rtw89_dev *d, enum rtw89_acpi_dsm_func func,
				   struct rtw89_acpi_dsm_result *res)
{
	(void)d; (void)func; (void)res;
	return -ENODEV;
}
static int skip_element(struct rtw89_dev *d, const struct rtw89_fw_element_hdr *e,
			const union rtw89_fw_element_arg a)
{
	(void)d; (void)e; (void)a;
	return 1;
}
'''
    regd_harness = r'''
/* An RTL8852B has no 6 GHz band: the real one finds no sband and returns. */
static void rtw89_regd_setup_6ghz(struct rtw89_dev *rtwdev, struct wiphy *wiphy)
{
	(void)rtwdev;
	if (wiphy->bands[NL80211_BAND_6GHZ])
		abort();
}
void rtw89_regd_notifier(struct wiphy *wiphy, struct regulatory_request *request);
'''
    notifier = r'''
static struct rtw89_dev *notified;
static struct ieee80211_channel channels_5ghz[28];
/* rtw89_regd_notifier's regulation steps, after cfg80211 has set the
 * channels' flags back to their original ones as each update does. */
void rtw89_regd_notifier(struct wiphy *wiphy, struct regulatory_request *request)
{
	struct rtw89_dev *rtwdev = notified;

	for (size_t i = 0; i < ARRAY_SIZE(channels_5ghz); i++)
		channels_5ghz[i].flags = 0;

	if (rtwdev->regulatory.programmed)
		goto policy;
	rtw89_regd_notifier_apply(rtwdev, wiphy, request);
policy:
	rtw89_regd_apply_policy_unii4(rtwdev, wiphy);
}
'''
    regd_cases = []
    for map_kind in (0, 1):
        for efuse in EFUSES:
            for stack in STACKS:
                regd_cases.append((map_kind, u16(efuse), u16(stack)))
    tx_cases = txpwr_cases()
    regd_table = ',\n'.join('\t{%d, 0x%04x, 0x%04x}' % c for c in regd_cases)
    tx_table = ',\n'.join(
        '\t{%d, %d, 0x%04x, %d, %d, %d, %d, %d, %d}' % ((c[0], c[1], u16(c[2])) + c[3:])
        for c in tx_cases)
    offsets = ', '.join(str(o) for o in OFFSETS)
    main_c = r'''
static const struct rtw89_phy_gen_def phy_gen = {
	.cr_base = PHY_CR_BASE,
	.phy0_phy1_offset = NULL,
	.set_txpwr_byrate = rtw89_phy_set_txpwr_byrate_ax,
	.set_txpwr_offset = rtw89_phy_set_txpwr_offset_ax,
	.set_txpwr_limit = rtw89_phy_set_txpwr_limit_ax,
	.set_txpwr_limit_ru = rtw89_phy_set_txpwr_limit_ru_ax,
};
static const struct rtw89_mac_gen_def mac_gen = {
	.band1_offset = RTW89_MAC_AX_BAND_REG_OFFSET,
	.get_txpwr_cr = rtw89_mac_get_txpwr_cr_ax,
};
static const struct rtw89_chip_info chip = {
	.phy_def = &phy_gen,
	.mac_def = &mac_gen,
	.needed_fw_elms = 0,
	.support_bands = SUPPORT_BANDS,
	.support_unii4 = SUPPORT_UNII4,
	.support_ant_gain = SUPPORT_ANT_GAIN,
	.rf_path_num = RF_PATH_NUM,
	.txpwr_factor_bb = TXPWR_FACTOR_BB,
	.txpwr_factor_rf = TXPWR_FACTOR_RF,
	.txpwr_factor_mac = TXPWR_FACTOR_MAC,
};
struct regd_case { u32 map, efuse, stack; };
static const struct regd_case regd_cases[] = {
''' + regd_table + r'''
};
struct tx_case { u32 rfe, map, stack, band, ch, pri, bw; s32 cap0, cap1; };
static const struct tx_case tx_cases[] = {
''' + tx_table + r'''
};
static const s16 offsets[] = {''' + offsets + r'''};
static FILE *out;
static void flush(void)
{
	u32 n = (u32)seg_len;
	if (fwrite(&n, 4, 1, out) != 1 || (n && fwrite(seg, n, 1, out) != 1))
		abort();
	seg_len = 0;
}
static struct ieee80211_supported_band sband_5ghz = {channels_5ghz, 28};
static struct wiphy wiphy;
static struct ieee80211_hw hw = {&wiphy};
static struct device device;
static void regulate(struct rtw89_dev *dev, u32 map, u32 efuse, u32 stack)
{
	const struct rtw89_regd_data *regd = dev->fw.elm_info.regd;
	memset(&dev->regulatory, 0, sizeof(dev->regulatory));
	memset(channels_5ghz, 0, sizeof(channels_5ghz));
	memset(&wiphy, 0, sizeof(wiphy));
	wiphy.bands[NL80211_BAND_5GHZ] = &sband_5ghz;
	if (map)
		dev->fw.elm_info.regd = NULL;
	dev->efuse.country_code[0] = (char)(efuse & 0xff);
	dev->efuse.country_code[1] = (char)(efuse >> 8);
	notified = dev;
	if (rtw89_regd_setup(dev))
		abort();
	/* ieee80211_register_hw: cfg80211 notifies the world regulation. */
	struct regulatory_request world = {"00", NL80211_REGDOM_SET_BY_CORE};
	wiphy.reg_notifier(&wiphy, &world);
	if (rtw89_regd_init_hint(dev))
		abort();
	struct regulatory_request request = {
		{(char)(stack & 0xff), (char)(stack >> 8), 0}, NL80211_REGDOM_SET_BY_USER};
	wiphy.reg_notifier(&wiphy, &request);
	dev->fw.elm_info.regd = regd;
}
static const size_t conf_offsets[] = {
	offsetof(struct rtw89_rfe_data, byrate.conf),
	offsetof(struct rtw89_rfe_data, lmt_2ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_5ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_6ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_2ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_5ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_6ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_ru_2ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_ru_5ghz.conf),
	offsetof(struct rtw89_rfe_data, lmt_ru_6ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_ru_2ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_ru_5ghz.conf),
	offsetof(struct rtw89_rfe_data, da_lmt_ru_6ghz.conf),
	offsetof(struct rtw89_rfe_data, tx_shape_lmt.conf),
	offsetof(struct rtw89_rfe_data, tx_shape_lmt_ru.conf),
};
int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	FILE *in = fopen(argv[2], "rb");
	if (!in || fseek(in, 0, SEEK_END))
		abort();
	long size = ftell(in);
	if (size <= 0 || fseek(in, 0, SEEK_SET))
		abort();
	u8 *image = malloc((size_t)size);
	if (!image || fread(image, 1, (size_t)size, in) != (size_t)size)
		abort();
	fclose(in);
	struct firmware fw = {image, (size_t)size};
	out = fopen(argv[1], "wb");
	if (!out)
		abort();
	static const struct rtw89_rfe_parms dflt_parms;
	u32 counts[6] = {0};
	for (u32 r = 0; r < ARRAY_SIZE(rfes); r++) {
		static struct rtw89_dev dev;
		memset(&dev, 0, sizeof(dev));
		dev.chip = &chip;
		dev.hal.cv = 1;
		dev.efuse.rfe_type = (u8)rfes[r];
		dev.fw.req.firmware = &fw;
		dev.dev = &device;
		dev.hw = &hw;
		dev.hci.type = RTW89_HCI_TYPE_PCIE;
		dev.mac.qta_mode = RTW89_QTA_SCC;
		if (rtw89_fw_recognize_elements(&dev))
			abort();
		/* rtw89_core_setup_rfe_parms with rfe_parms_conf NULL. */
		dev.rfe_parms = rtw89_load_rfe_data_from_fw(&dev, &dflt_parms);
		const struct rtw89_rfe_parms *p = dev.rfe_parms;
		if (!p->byr_tbl || !p->rule_2ghz.lmt || !p->rule_2ghz.lmt_ru || !p->rule_5ghz.lmt ||
		    !p->rule_5ghz.lmt_ru || !p->tx_shape.lmt || !p->tx_shape.lmt_ru)
			abort();
		rtw89_load_txpwr_table(&dev, p->byr_tbl);
		put32(2);
		put32(rfes[r]);
		put32(p->has_da);
		for (u32 i = 0; i < ARRAY_SIZE(conf_offsets); i++) {
			const struct rtw89_txpwr_conf *conf =
				(const void *)((const u8 *)dev.rfe_data + conf_offsets[i]);
			put32(rtw89_txpwr_conf_valid(conf) ? conf->rfe_type : 0xffffffff);
		}
		putb(dev.byr, sizeof(dev.byr));
		putb(p->rule_2ghz.lmt, sizeof(*p->rule_2ghz.lmt));
		putb(p->rule_5ghz.lmt, sizeof(*p->rule_5ghz.lmt));
		putb(p->rule_2ghz.lmt_ru, sizeof(*p->rule_2ghz.lmt_ru));
		putb(p->rule_5ghz.lmt_ru, sizeof(*p->rule_5ghz.lmt_ru));
		putb(p->tx_shape.lmt, sizeof(*p->tx_shape.lmt));
		putb(p->tx_shape.lmt_ru, sizeof(*p->tx_shape.lmt_ru));
		flush();
		counts[2]++;
		if (r == 0) {
			for (u32 i = 0; i < ARRAY_SIZE(regd_cases); i++) {
				const struct regd_case *k = &regd_cases[i];
				regulate(&dev, k->map, k->efuse, k->stack);
				const struct rtw89_regulatory_info *g = &dev.regulatory;
				u32 disabled = 0;
				for (u32 c = 0; c < RTW89_5GHZ_UNII4_CHANNEL_NUM; c++)
					if (channels_5ghz[RTW89_5GHZ_UNII4_START_INDEX + c].flags &
					    IEEE80211_CHAN_DISABLED)
						disabled |= 1U << c;
				put32(1);
				put32(k->map);
				put32(k->efuse);
				put32(k->stack);
				put32((u8)g->regd->alpha2[0] | (u32)(u8)g->regd->alpha2[1] << 8);
				for (u32 b = 0; b < RTW89_BAND_NUM; b++)
					put32(g->regd->txpwr_regd[b]);
				put32((u32)g->regd->func_bitmap[0]);
				put32(rtw89_regd_get(&dev, RTW89_BAND_2G));
				put32(rtw89_regd_get(&dev, RTW89_BAND_5G));
				put32(g->programmed);
				put32(rtw89_regd_is_ww(g->regd));
				put32(disabled);
				put32(k->map ? ARRAY_SIZE(rtw89_regd_map) : g->ctrl.nr);
				flush();
				counts[1]++;
			}
		}
		for (u32 i = 0; i < ARRAY_SIZE(tx_cases); i++) {
			const struct tx_case *k = &tx_cases[i];
			if (k->rfe != rfes[r])
				continue;
			regulate(&dev, k->map, 0xffff, k->stack);
			harness_cap[0] = (s8)k->cap0;
			harness_cap[1] = (s8)k->cap1;
			reset_memory();
			put32(3);
			put32(k->rfe);
			put32(k->map);
			put32(k->stack);
			put32(k->band);
			put32(k->ch);
			put32(k->pri);
			put32(k->bw);
			put32((u32)k->cap0);
			put32((u32)k->cap1);
			struct rtw89_chan chan = {
				.channel = (u8)k->ch,
				.primary_channel = (u8)k->pri,
				.band_type = (enum rtw89_band)k->band,
				.band_width = (enum rtw89_bandwidth)k->bw,
				.freq = ieee80211_channel_to_frequency(
					k->ch, rtw89_hw_to_nl80211_band((enum rtw89_band)k->band)),
			};
			__rtw8852bx_set_txpwr(&dev, &chan, RTW89_PHY_0);
			flush();
			counts[3]++;
		}
		harness_cap[0] = harness_cap[1] = RTW89_SAR_TXPWR_MAC_MAX;
		if (r == ARRAY_SIZE(rfes) - 1) {
			for (u32 i = 0; i < ARRAY_SIZE(offsets); i++) {
				reset_memory();
				put32(4);
				put32((u32)(s32)offsets[i]);
				rtw8852bx_set_txpwr_ref(&dev, RTW89_PHY_0, offsets[i]);
				flush();
				counts[4]++;
			}
			reset_memory();
			put32(5);
			__rtw8852bx_set_txpwr_ctrl(&dev, RTW89_PHY_0);
			flush();
			counts[5]++;
		}
		free((void *)dev.fw.elm_info.regd);
		free(dev.rfe_data);
	}
	if (fclose(out))
		abort();
	free(image);
	free(seg);
	printf("{\"counts\": [%u, %u, %u, %u, %u, %u]}\n", counts[0], counts[1], counts[2],
	       counts[3], counts[4], counts[5]);
	return 0;
}
'''
    chip_c = '\n'.join([
        f'#define SUPPORT_BANDS ({chip["support_bands"]})',
        f'#define SUPPORT_UNII4 {chip["support_unii4"]}',
        f'#define SUPPORT_ANT_GAIN {chip["support_ant_gain"]}',
        f'#define RF_PATH_NUM {chip["rf_path_num"]}',
        f'#define TXPWR_FACTOR_BB {chip["txpwr_factor_bb"]}',
        f'#define TXPWR_FACTOR_RF {chip["txpwr_factor_rf"]}',
        f'#define TXPWR_FACTOR_MAC {chip["txpwr_factor_mac"]}',
        f'#define PHY_CR_BASE {phy_gen["cr_base"]}',
        'static const u32 rfes[] = {%s};' % ', '.join(str(r) for r in RFES),
    ])
    program = '\n\n'.join([
        preamble, constants, declarations, harness, inline_core, phy_c, fw_c, mac_c,
        common_c, regd_harness, regd_c, notifier, chip_c, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member', '-Wno-gnu-variable-sized-type-not-at-end',
                    str(generated), '-o', str(exe)], check=True)
    trace_path = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace_path), str(image)], check=True,
                         capture_output=True, text=True)
    counts = json.loads(run.stdout)['counts']
    expected = [0, len(regd_cases), len(RFES), len(tx_cases), len(OFFSETS), 1]
    if counts != expected:
        raise ValueError(f'counts {counts}, expected {expected}')
    trace = trace_path.read_bytes()

    # A summary of what the trace holds, for the receipt.
    offset = 0
    regulations, tables, chosen = [], {}, {}
    while offset < len(trace):
        (length,) = struct.unpack_from('<I', trace, offset)
        body = trace[offset + 4:offset + 4 + length]
        offset += 4 + length
        kind = struct.unpack_from('<I', body, 0)[0]
        if kind == 1:
            w = struct.unpack_from('<15I', body, 0)
            regulations.append(dict(
                map=['element', 'rtw89_regd_map'][w[1]],
                efuse=w[2].to_bytes(2, 'little').hex(),
                stack=w[3].to_bytes(2, 'little').decode('latin-1'),
                regd=w[4].to_bytes(2, 'little').decode('latin-1'), txpwr_regd=list(w[5:8]),
                regd_get=[w[9], w[10]], programmed=w[11], ww=w[12], unii4_disabled=w[13],
                map_size=w[14]))
        elif kind == 2:
            w = struct.unpack_from('<18I', body, 0)
            tables[w[1]] = dict(has_da=w[2], conf_rfe_types=[
                None if v == 0xffffffff else v for v in w[3:18]],
                bytes=len(body) - 72, sha256=hashlib.sha256(body[72:]).hexdigest())
        elif kind == 3:
            w = struct.unpack_from('<10I', body, 0)
            if w[1] == 1 and w[2] == 0 and w[3] == u16(b'ID') and w[8] == 63:
                writes = [struct.unpack_from('<3I', body, 40 + 12 * i)
                          for i in range((len(body) - 40) // 12)]
                chosen[f'{w[5]}/{20 << w[7]}'] = dict(
                    by_rate=['%08x' % v for t, r, v in writes if t == 8 and 0xd2c0 <= r < 0xd2ec],
                    limit_1tx=['%08x' % v for t, r, v in writes
                               if t == 8 and 0xd2ec <= r < 0xd314],
                    limit_2tx=['%08x' % v for t, r, v in writes
                               if t == 8 and 0xd314 <= r < 0xd33c])
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest, counts=counts,
        image=dict(path=str(image.resolve()), bytes=image.stat().st_size,
                   sha256=hashlib.sha256(image.read_bytes()).hexdigest()),
        dispatch=dict(rtw8852b_chip_info=chip, rtw89_phy_gen_ax=phy_gen,
                      rtw89_mac_gen_ax=mac_gen, rtw8852b_chip_ops=ops,
                      rtw8852bx_info=common_ops),
        tables=tables, regulations=regulations, rfe1_id_pages=chosen,
        trace_bytes=len(trace), trace_sha256=hashlib.sha256(trace).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'the walk runs the TX power and REGD handlers alone, the other handlers '
            'ignoring their elements and needed_fw_elms 0; the elements oracle proves the rest',
            'dflt_parms is empty, so a table the firmware lacks would stop the run where '
            'rtw89 would read its compiled one',
            'no ACPI: the DSM fails, antenna gain and TAS stay off; rtw89_query_sar stands '
            'for Stela\'s cap; rtw89_regd_notifier is its regulation steps alone',
            'cfg80211 is two notifier calls, the world regulation at registration and the '
            'stack\'s alpha2 as a user request, each after the channel flags are reset',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['counts', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
