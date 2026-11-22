#!/usr/bin/env python3
"""Unchanged pinned rtw89 rate adaptation, BA CAM and RA report for an RTL8852B.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY [HEADER_CACHE]

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. The IEEE 802.11 constants and wire
structs rtw89 reads come from include/linux/ieee80211-{ht,vht,he,eht}.h of
the same commit, kept in HEADER_CACHE (OUTPUT_DIRECTORY/linux when not
given) and fetched from the pinned commit when missing; each must match its
SHA-256 below.

The program runs, unchanged, with every rtw89 callee it reaches:

- rtw89_phy_ra_assoc (rtw89_phy_ra_sta_update with get_mcs_ra_mask,
  get_he_ra_mask, rtw89_phy_ra_mask_rssi, rtw89_phy_ra_mask_recover,
  rtw89_phy_ra_mask_cfg and rtw89_phy_ra_gi_ltf; rtw89_sta_has_beamformer_cap)
  and then rtw89_phy_ra_update_sta_link, each ending in rtw89_fw_h2c_ra,
  over fourteen peers: legacy 5 GHz, b/g and b-only 2.4 GHz, HT 2SS 40 and
  1SS 20, VHT 2SS 80 (a beamformer) and 2SS 20, HE 2SS 80 (the user's AP's
  kind, a beamformer with ER), HE 2SS 40 on 2.4 GHz, a 4SS HE AP at low
  RSSI, HE at 160 MHz over the 80+80 map, an HT peer whose mask the RSSI
  empties and recovery restores, an RSSI past every level, and one TX
  stream;
- rtw89_fw_h2c_ba_cam (RTW89_BACAM_V0) with rtw89_core_acquire_sta_ba_entry
  and rtw89_core_release_sta_ba_entry over a sequence of RX Block Ack starts
  and stops that fills both static entries, replaces one for TID 5, and
  misses;
- __rtw89_phy_c2h_ra_rpt_iter with rtw89_legacy_rate_to_bitrate,
  rtw89_hw_to_rate_info_bw and get_max_amsdu_len over legacy, HT, VHT and
  HE reports and a report for another MAC ID.

The changed pieces are the seams: rtw89_h2c_tx records the skb;
cfg80211_calculate_bitrate is a stub returning each case's bit rate (the
cfg80211 formula is not rtw89's, and Stela derives HE rates from IEEE
802.11ax instead), so get_max_amsdu_len is exercised at chosen rates;
rtw89_chan_get, rtw89_sta_rcu_dereference_link and rtwvif_link_to_vif
return the harness's channel, peer and vif; RTW89_CHK_FW_FEATURE is false,
checked against fw.c naming OLD_HT_RA_FORMAT for RTL8852A alone. The
cfg80211, nl80211 and mac80211 enums and structs rtw89 reads are declared
by the harness with Linux's values.

The trace (trace.bin, little-endian): the RA case count, then per case its
22 input words, the 24 bytes of the assoc H2C and the 24 of the update H2C;
the BA operation count, then per operation five input words, the return,
whether an H2C went, the map and entries' TIDs, and 16 H2C bytes (zero
when none); the report count, then per report five input words and
thirteen output words. Every H2C takes the next sequence number from 0.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from urllib.request import urlopen

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
HEADERS = {
    'ieee80211-ht.h': '0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b',
    'ieee80211-vht.h': 'eaae1e52bcaed0ecb9bbcf1c87a65e03a7ac5ea29733111a90e92bb993741775',
    'ieee80211-he.h': 'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e',
    'ieee80211-eht.h': '3301a09629b7efafe791abcbc9346c7b20a515dc1e254826f03e71c602052f5e',
}


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    reference, out = map(pathlib.Path, argv[:2])
    out.mkdir(parents=True, exist_ok=True)
    cache = pathlib.Path(argv[2]) if len(argv) == 3 else out / 'linux'
    cache.mkdir(parents=True, exist_ok=True)
    manifest = []
    texts = {}

    for name, expected in HEADERS.items():
        path = cache / name
        if not path.exists():
            url = f'https://raw.githubusercontent.com/torvalds/linux/{COMMIT}/include/linux/{name}'
            path.write_bytes(urlopen(url).read())
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'{name}: SHA-256 differs from the pinned header')
        texts['include/linux/' + name] = data.decode()

    def source(file):
        if file not in texts:
            texts[file] = (reference / 'rtw89' / file).read_text()
        return texts[file]

    def label(file):
        return file if file.startswith('include/') else 'rtw89/' + file

    def closing(text, brace):
        end, depth = brace + 1, 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        return end

    def record(file, name, body):
        manifest.append(dict(path=label(file), symbol=name,
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
            return m.start(), record(file, name, text[start:closing(text, end)])
        raise ValueError(f'{file}: no definition of {name}')

    def functions(file, names):
        """Definitions in their file's order, so each precedes its callers."""
        return '\n\n'.join(body for _, body in sorted(locate(file, name) for name in names))

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
        found_lines = []
        for name in names:
            found = re.findall(r'^#define ' + re.escape(name) + r'\b[^\n]*$', text, re.M)
            if len(found) != 1:
                raise ValueError(f'{file}: #define {name} appears {len(found)} times')
            found_lines.append(found[0])
        return record(file, f'#define {" ".join(names)}', '\n'.join(found_lines))

    def prefixed(file, prefixes):
        """Every #define whose name starts with one of `prefixes`, with its
        continuation lines, in file order."""
        text = source(file)
        pattern = r'^#define (?:' + '|'.join(map(re.escape, prefixes)) + r')\w*\b(?:[^\n]*\\\n)*[^\n]*$'
        found = [m.group(0) for m in re.finditer(pattern, text, re.M)]
        if not found:
            raise ValueError(f'{file}: no #define starting {prefixes}')
        return record(file, f'#define {"|".join(prefixes)}*', '\n'.join(found))

    def fields(file, head, names):
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

    ht_h, vht_h = 'include/linux/ieee80211-ht.h', 'include/linux/ieee80211-vht.h'
    he_h, eht_h = 'include/linux/ieee80211-he.h', 'include/linux/ieee80211-eht.h'
    ieee = '\n\n'.join(
        [prefixed(h, ['IEEE80211_']) for h in [ht_h, vht_h, he_h, eht_h]]
        + [declaration(ht_h, 'enum', 'ieee80211_max_ampdu_length_exp'),
           declaration(ht_h, 'enum', 'ieee80211_min_mpdu_spacing'),
           declaration(ht_h, 'struct', 'ieee80211_mcs_info'),
           declaration(vht_h, 'enum', 'ieee80211_vht_max_ampdu_length_exp'),
           declaration(vht_h, 'enum', 'ieee80211_vht_mcs_support'),
           declaration(vht_h, 'struct', 'ieee80211_vht_mcs_info'),
           declaration(he_h, 'struct', 'ieee80211_he_cap_elem'),
           declaration(he_h, 'enum', 'ieee80211_he_mcs_support'),
           declaration(he_h, 'struct', 'ieee80211_he_mcs_nss_supp'),
           declaration(he_h, 'struct', 'ieee80211_he_6ghz_capa'),
           declaration(eht_h, 'struct', 'ieee80211_eht_mcs_nss_supp_20mhz_only'),
           declaration(eht_h, 'struct', 'ieee80211_eht_mcs_nss_supp_bw'),
           declaration(eht_h, 'struct', 'ieee80211_eht_cap_elem_fixed')])

    core_defines = defines('core.h', ['MAX_RSSI', 'RSSI_FACTOR', 'RTW89_MAX_BA_CAM_NUM'])
    phy_defines = prefixed('phy.h', ['RA_MASK_'])
    phy_c_defines = defines('phy.c', ['RA_FLOOR_TABLE_SIZE', 'RA_FLOOR_UP_GAP'])
    fw_defines = '\n\n'.join([
        defines('fw.h', ['H2C_HEADER_LEN', 'H2C_HDR_CAT', 'H2C_HDR_CLASS', 'H2C_HDR_FUNC',
                         'H2C_HDR_DEL_TYPE', 'H2C_HDR_H2C_SEQ', 'H2C_HDR_TOTAL_LEN',
                         'H2C_HDR_REC_ACK', 'H2C_HDR_DONE_ACK', 'FWCMD_TYPE_H2C',
                         'H2C_CAT_MAC', 'H2C_CAT_OUTSRC', 'H2C_CL_BA_CAM',
                         'H2C_FUNC_MAC_BA_CAM', 'H2C_CL_OUTSRC_RA',
                         'H2C_FUNC_OUTSRC_RA_MACIDCFG']),
        prefixed('fw.h', ['RTW89_H2C_RA_', 'RTW89_H2C_BA_CAM_', 'RTW89_C2H_RA_RPT_',
                          'RTW89_RA_RATE_MASK_', 'RTW89_MK_HT_RATE'])])
    declarations = '\n\n'.join(
        [declaration('core.h', 'enum', name) for name in [
            'rtw89_core_chip_id', 'rtw89_chip_gen', 'rtw89_cv', 'rtw89_bacam_ver', 'rtw89_band',
            'rtw89_hw_rate', 'rtw89_mac_idx', 'rtw89_phy_idx', 'rtw89_rf_path', 'rtw89_bandwidth',
            'rtw89_ra_mode', 'rtw89_ra_report_mode', 'rtw89_gi_ltf']]
        + [declaration('core.h', 'struct', name) for name in [
            'rtw89_ra_info', 'rtw89_ra_report', 'rtw89_ba_cam_entry', 'rtw89_phy_rate_pattern']]
        + [declaration('fw.h', 'struct', name) for name in [
            'fwcmd_hdr', 'rtw89_h2c_ra', 'rtw89_h2c_ra_v1', 'rtw89_h2c_ba_cam', 'rtw89_c2h_hdr',
            'rtw89_c2h_ra_rpt']])
    core_inlines = '\n\n'.join(locate('core.h', name)[1] for name in [
        'rtw89_hw_to_rate_info_bw', 'rtw89_hw_to_nl80211_band', 'rtw89_sta_has_beamformer_cap',
        'rtw89_sta_link_has_su_mu_4xhe08'])
    bitrates = definition('core.c', 'static struct ieee80211_rate rtw89_bitrates[]')
    core = functions('core.c', [
        'rtw89_legacy_rate_to_bitrate', 'rtw89_core_acquire_bit_map', 'rtw89_core_release_bit_map',
        'rtw89_core_acquire_sta_ba_entry', 'rtw89_core_release_sta_ba_entry'])
    fw = functions('fw.c', [
        'rtw89_fw_h2c_alloc_skb', 'rtw89_fw_h2c_alloc_skb_with_hdr', 'rtw89_h2c_pkt_set_hdr',
        'rtw89_fw_h2c_ba_cam', 'rtw89_fw_h2c_ra'])
    phy_tables = '\n'.join(definition('phy.c', f'static const u64\nrtw89_ra_mask_{kind}[4]')
                           for kind in ['ht_rates', 'vht_rates', 'he_rates', 'eht_rates',
                                        'eht_mcs0_11'])
    phy_iter = declaration('phy.c', 'struct', 'rtw89_phy_iter_ra_data')
    phy_first = functions('phy.c', [
        'get_max_amsdu_len', 'get_mcs_ra_mask', 'get_he_ra_mask', 'get_eht_mcs_ra_mask',
        'get_eht_ra_mask', 'rtw89_phy_ra_mask_rssi', 'rtw89_phy_ra_mask_recover',
        'rtw89_phy_ra_mask_cfg'])
    phy_second = functions('phy.c', [
        'rtw89_phy_ra_gi_ltf', 'rtw89_phy_ra_sta_update', 'rtw89_phy_ra_update_sta_link',
        'rtw89_phy_ra_assoc'])
    phy_report = locate('phy.c', '__rtw89_phy_c2h_ra_rpt_iter')[1]

    info = fields('rtw8852b.c', 'const struct rtw89_chip_info rtw8852b_chip_info',
                  ['chip_id', 'chip_gen', 'max_amsdu_limit', 'bacam_num', 'bacam_dynamic_num',
                   'bacam_ver', 'tx_nss', 'rx_nss', 'ops'])
    if info['ops'] != '&rtw8852b_chip_ops':
        raise ValueError(f'rtw8852b_chip_info.ops is {info["ops"]}')
    ops = fields('rtw8852b.c', 'static const struct rtw89_chip_ops rtw8852b_chip_ops',
                 ['h2c_ba_cam'])
    if ops != {'h2c_ba_cam': 'rtw89_fw_h2c_ba_cam'}:
        raise ValueError(f'rtw8852b_chip_ops is {ops}')
    feats = re.findall(r'__CFG_FW_FEAT\(([^,]+),[^\n]*OLD_HT_RA_FORMAT\)', source('fw.c'))
    if feats != ['RTL8852A']:
        raise ValueError(f'OLD_HT_RA_FORMAT is set for {feats}')
    core_c = source('core.c')
    if '\trtw89_phy_ra_assoc(rtwdev, rtwsta_link);\n' not in core_c:
        raise ValueError('rtw89_core_sta_link_assoc no longer calls rtw89_phy_ra_assoc')

    preamble = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;
typedef uint16_t __le16; typedef uint32_t __le32; typedef uint64_t __le64;
typedef uint8_t __u8; typedef uint16_t __u16;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define __counted_by(m)
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) ((~0U >> (31 - (h))) & (~0U << (l)))
#define GENMASK_ULL(h, l) ((~0ULL >> (63 - (h))) & (~0ULL << (l)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define U8_MAX 0xff
#define ETH_ALEN 6
#define __ffs(m) ((u32)__builtin_ctz(m))
#define FIELD_PREP(m, v) ((((u32)(v)) << __ffs(m)) & (m))
#define FIELD_GET(m, v) ((((u32)(v)) & (m)) >> __ffs(m))
static inline u8 u8_encode_bits(u8 v, u8 m) { return (u8)((v << __builtin_ctz(m)) & m); }
static inline u8 u8_get_bits(u8 v, u8 m) { return (u8)((v & m) >> __builtin_ctz(m)); }
static inline u16 u16_encode_bits(u16 v, u16 m) { return (u16)((v << __builtin_ctz(m)) & m); }
static inline u64 u64_encode_bits(u64 v, u64 m) { return (v << __builtin_ctzll(m)) & m; }
static inline __le32 le32_encode_bits(u32 v, u32 m) { return (v << __builtin_ctz(m)) & m; }
static inline u32 le32_get_bits(__le32 v, u32 m) { return (v & m) >> __builtin_ctz(m); }
static inline __le16 le16_encode_bits(u16 v, u16 m) { return (u16)((v << __builtin_ctz(m)) & m); }
#define cpu_to_le16(v) ((__le16)(v))
#define cpu_to_le32(v) ((__le32)(v))
#define le16_to_cpu(v) ((u16)(v))
#define le32_to_cpu(v) ((u32)(v))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define EXPORT_SYMBOL(...)
#define unlikely(c) (c)
#define fallthrough __attribute__((fallthrough))
#define lockdep_assert_wiphy(w) ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
static void sink(const char *format, ...) { (void)format; }
#define rtw89_warn(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_err(d, ...) ((void)(d), sink(__VA_ARGS__))
#define rtw89_debug(d, m, ...) ((void)(d), sink(__VA_ARGS__))
struct list_head { struct list_head *next, *prev; };
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{
	n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n;
}
static inline void list_del(struct list_head *e)
{
	e->prev->next = e->next; e->next->prev = e->prev; e->next = e->prev = NULL;
}
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
#define list_entry(p, type, member) container_of(p, type, member)
#define list_next_entry(pos, member) list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member), \
	     n = list_next_entry(pos, member); \
	     &pos->member != (head); pos = n, n = list_next_entry(n, member))
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
static unsigned long find_next_bit(const unsigned long *a, unsigned long size, unsigned long at)
{
	for (; at < size; at++)
		if ((a[at / 64] >> (at % 64)) & 1)
			return at;
	return size;
}
static unsigned long find_first_zero_bit(const unsigned long *a, unsigned long size)
{
	for (unsigned long at = 0; at < size; at++)
		if (!((a[at / 64] >> (at % 64)) & 1))
			return at;
	return size;
}
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), 0); (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
static void set_bit(long nr, unsigned long *a) { a[nr / 64] |= 1UL << (nr % 64); }
static void clear_bit(long nr, unsigned long *a) { a[nr / 64] &= ~(1UL << (nr % 64)); }
struct sk_buff { u8 *head, *data; u32 len, size; };
'''
    harness_types = r'''
/* nl80211, cfg80211 and mac80211 as far as these rtw89 functions read them,
 * with Linux's values. */
enum nl80211_band { NL80211_BAND_2GHZ, NL80211_BAND_5GHZ, NL80211_BAND_60GHZ,
	NL80211_BAND_6GHZ, NL80211_BAND_S1GHZ, NL80211_BAND_LC, NUM_NL80211_BANDS };
enum nl80211_iftype { NL80211_IFTYPE_UNSPECIFIED, NL80211_IFTYPE_ADHOC,
	NL80211_IFTYPE_STATION, NL80211_IFTYPE_AP };
enum nl80211_chan_width { NL80211_CHAN_WIDTH_20_NOHT, NL80211_CHAN_WIDTH_20,
	NL80211_CHAN_WIDTH_40, NL80211_CHAN_WIDTH_80, NL80211_CHAN_WIDTH_80P80,
	NL80211_CHAN_WIDTH_160 };
enum nl80211_he_gi { NL80211_RATE_INFO_HE_GI_0_8, NL80211_RATE_INFO_HE_GI_1_6,
	NL80211_RATE_INFO_HE_GI_3_2 };
enum nl80211_eht_gi { NL80211_RATE_INFO_EHT_GI_0_8, NL80211_RATE_INFO_EHT_GI_1_6,
	NL80211_RATE_INFO_EHT_GI_3_2 };
enum ieee80211_sta_rx_bandwidth { IEEE80211_STA_RX_BW_20 = 0, IEEE80211_STA_RX_BW_40,
	IEEE80211_STA_RX_BW_80, IEEE80211_STA_RX_BW_160, IEEE80211_STA_RX_BW_320 };
enum ieee80211_rate_control_changed { IEEE80211_RC_BW_CHANGED = BIT(0),
	IEEE80211_RC_SMPS_CHANGED = BIT(1), IEEE80211_RC_SUPP_RATES_CHANGED = BIT(2),
	IEEE80211_RC_NSS_CHANGED = BIT(3) };
enum rate_info_flags { RATE_INFO_FLAGS_MCS = BIT(0), RATE_INFO_FLAGS_VHT_MCS = BIT(1),
	RATE_INFO_FLAGS_SHORT_GI = BIT(2), RATE_INFO_FLAGS_DMG = BIT(3),
	RATE_INFO_FLAGS_HE_MCS = BIT(4), RATE_INFO_FLAGS_EDMG = BIT(5),
	RATE_INFO_FLAGS_EXTENDED_SC_DMG = BIT(6), RATE_INFO_FLAGS_EHT_MCS = BIT(7) };
enum rate_info_bw { RATE_INFO_BW_20 = 0, RATE_INFO_BW_5, RATE_INFO_BW_10, RATE_INFO_BW_40,
	RATE_INFO_BW_80, RATE_INFO_BW_160, RATE_INFO_BW_HE_RU, RATE_INFO_BW_320,
	RATE_INFO_BW_EHT_RU };
struct rate_info { u16 flags; u16 legacy; u8 mcs; u8 nss; u8 bw; u8 he_gi; u8 he_dcm;
	u8 he_ru_alloc; u8 n_bonded_ch; u8 eht_gi; u8 eht_ru_alloc; };
struct ieee80211_rate { u32 flags; u16 bitrate; u16 hw_value, hw_value_short; };
struct ieee80211_sta_ht_cap { u16 cap; bool ht_supported; u8 ampdu_factor;
	u8 ampdu_density; struct ieee80211_mcs_info mcs; };
struct ieee80211_sta_vht_cap { bool vht_supported; u32 cap;
	struct ieee80211_vht_mcs_info vht_mcs; };
struct ieee80211_sta_he_cap { bool has_he; struct ieee80211_he_cap_elem he_cap_elem;
	struct ieee80211_he_mcs_nss_supp he_mcs_nss_supp; u8 ppe_thres[25]; };
struct ieee80211_eht_mcs_nss_supp {
	union {
		struct ieee80211_eht_mcs_nss_supp_20mhz_only only_20mhz;
		struct {
			struct ieee80211_eht_mcs_nss_supp_bw _80;
			struct ieee80211_eht_mcs_nss_supp_bw _160;
			struct ieee80211_eht_mcs_nss_supp_bw _320;
		} __packed bw;
	} __packed;
} __packed;
struct ieee80211_sta_eht_cap { bool has_eht; struct ieee80211_eht_cap_elem_fixed eht_cap_elem;
	struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp; u8 eht_ppe_thres[32]; };
struct ieee80211_sband_iftype_data { u16 types_mask; struct ieee80211_sta_he_cap he_cap;
	struct ieee80211_he_6ghz_capa he_6ghz_capa; struct ieee80211_sta_eht_cap eht_cap; };
struct ieee80211_sta_aggregates { u16 max_amsdu_len; u16 max_rc_amsdu_len;
	u16 max_tid_amsdu_len[16]; };
struct ieee80211_link_sta { u32 supp_rates[NUM_NL80211_BANDS];
	struct ieee80211_sta_ht_cap ht_cap; struct ieee80211_sta_vht_cap vht_cap;
	struct ieee80211_sta_he_cap he_cap; struct ieee80211_sta_eht_cap eht_cap;
	struct ieee80211_sta_aggregates agg; u8 rx_nss;
	enum ieee80211_sta_rx_bandwidth bandwidth; };
struct cfg80211_bitrate_mask { struct { u32 legacy; u8 ht_mcs[IEEE80211_HT_MCS_MASK_LEN];
	u16 vht_mcs[8]; u16 he_mcs[8]; u16 eht_mcs[8]; int gi; u8 he_gi; u8 he_ltf;
	u8 eht_gi; u8 eht_ltf; } control[NUM_NL80211_BANDS]; };
struct ieee80211_vif { enum nl80211_iftype type; bool p2p; };
struct ieee80211_hw { void *wiphy; };
struct ieee80211_ampdu_params { u16 tid; u16 ssn; u16 buf_size; };
#define ieee80211_hw_check(hw, flag) ((void)(hw), 0)
'''
    harness = r'''
struct ewma_rssi { unsigned long internal; };
static unsigned long ewma_rssi_read(struct ewma_rssi *e) { return e->internal; }
struct rtw89_chan { enum rtw89_band band_type; enum rtw89_bandwidth band_width; };
struct rtw89_vif_link { struct rtw89_phy_rate_pattern rate_pattern; u8 chanctx_idx;
	u8 phy_idx; u8 mac_idx; };
struct rtw89_sta_link { struct rtw89_vif_link *rtwvif_link; u8 mac_id; bool er_cap;
	bool use_cfg_mask; struct cfg80211_bitrate_mask mask; struct rtw89_ra_info ra;
	struct rtw89_ra_report ra_report; struct ewma_rssi avg_rssi;
	struct list_head ba_cam_list; int max_agg_wait; };
struct rtw89_cam_info { DECLARE_BITMAP(ba_cam_map, RTW89_MAX_BA_CAM_NUM);
	struct rtw89_ba_cam_entry ba_cam_entry[RTW89_MAX_BA_CAM_NUM]; };
struct rtw89_chip_info { enum rtw89_core_chip_id chip_id; enum rtw89_chip_gen chip_gen;
	u16 max_amsdu_limit; u8 bacam_num; u8 bacam_dynamic_num;
	enum rtw89_bacam_ver bacam_ver; u8 tx_nss, rx_nss; u32 h2c_desc_size; };
struct rtw89_hal { u8 tx_nss, rx_nss; bool no_mcs_12_13; u8 cv; };
struct rtw89_dev { const struct rtw89_chip_info *chip; struct rtw89_hal hal;
	struct { u8 h2c_seq; } fw; struct rtw89_cam_info cam_info; struct ieee80211_hw *hw; };
#define RTW89_CHK_FW_FEATURE(feat, fw) ((void)(fw), 0)

static struct ieee80211_link_sta harness_sta;
static struct ieee80211_vif harness_vif;
static struct rtw89_chan chan;
static const struct rtw89_chan *rtw89_chan_get(struct rtw89_dev *d, u8 idx)
{
	(void)d; (void)idx; return &chan;
}
#define rtw89_sta_rcu_dereference_link(s, h) ((void)(s), (void)(h), &harness_sta)
#define rtwvif_link_to_vif(v) ((void)(v), &harness_vif)

static u32 stub_bitrate;
static u32 cfg80211_calculate_bitrate(struct rate_info *r) { (void)r; return stub_bitrate; }

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
static void *skb_put(struct sk_buff *s, unsigned int n)
{
	if (n > skb_tailroom(s))
		abort();
	void *p = s->data + s->len;
	s->len += n;
	return p;
}

/* rtw89_h2c_tx: the H2C's bytes, header included, kept for the trace. */
static u8 h2c_bytes[64];
static u32 h2c_len, h2c_count;
static int rtw89_h2c_tx(struct rtw89_dev *d, struct sk_buff *skb, bool fwdl)
{
	(void)d;
	if (fwdl || skb->len > sizeof(h2c_bytes))
		abort();
	memcpy(h2c_bytes, skb->data, skb->len);
	h2c_len = skb->len;
	h2c_count++;
	dev_kfree_skb_any(skb);
	return 0;
}

static u8 *trace;
static size_t trace_len, trace_cap;
static void put(const void *p, size_t n)
{
	if (trace_len + n > trace_cap) {
		trace_cap = trace_cap ? 2 * trace_cap + n : 65536;
		trace = realloc(trace, trace_cap);
		if (!trace)
			abort();
	}
	memcpy(trace + trace_len, p, n);
	trace_len += n;
}
static void word(u32 v)
{
	u8 b[4] = {(u8)v, (u8)(v >> 8), (u8)(v >> 16), (u8)(v >> 24)};
	put(b, 4);
}
'''
    chip = f'''
static const struct rtw89_chip_info chip_info = {{
	.chip_id = {info["chip_id"]},
	.chip_gen = {info["chip_gen"]},
	.max_amsdu_limit = {info["max_amsdu_limit"]},
	.bacam_num = {info["bacam_num"]},
	.bacam_dynamic_num = {info["bacam_dynamic_num"]},
	.bacam_ver = {info["bacam_ver"]},
	.tx_nss = {info["tx_nss"]},
	.rx_nss = {info["rx_nss"]},
	.h2c_desc_size = 24,
}};
'''
    main_c = r'''
struct ra_case {
	u8 band, bw, rssi, er, macid, tx_nss, rx_nss;
	u32 supp;
	bool has_ht; u16 ht_cap; u8 rx_mask[4];
	bool has_vht; u32 vht_cap; u16 vht_map;
	bool has_he; u8 phy[11]; u16 mcs80, mcs160, mcs80p80;
	u32 changed;
};
/* HT: SGI 20/40, LDPC, one RX STBC stream; VHT: SGI 80, RX LDPC, RX STBC 1;
 * HE PHY: LDPC, STBC RX under 80 MHz, DCM RX 16-QAM, SU beamformer. */
#define HT_CAP 0x0161
#define VHT_CAP 0x0130
static const struct ra_case ra_cases[] = {
	/* legacy, 5 GHz */
	{1, 0, 120, 0, 0, 2, 1, 0xff, 0},
	/* b/g, 2.4 GHz */
	{0, 0, 90, 0, 1, 2, 1, 0xfff, 0, .changed = 4},
	/* b only: CCK, no RSSI cut */
	{0, 0, 40, 0, 2, 2, 1, 0x00f, 0, .changed = 1},
	/* HT 2SS 40 MHz, 5 GHz */
	{1, 1, 110, 0, 3, 2, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, .changed = 8},
	/* HT 1SS 20 MHz, 2.4 GHz */
	{0, 0, 70, 0, 4, 2, 1, 0xff0, 1, 0x0020, {0xff}, .changed = 13},
	/* VHT 2SS 80 MHz, a SU beamformer */
	{1, 2, 130, 0, 5, 2, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, 1, VHT_CAP | 0x800, 0xfffa,
	 .changed = 4},
	/* VHT 2SS 20 MHz, MCS 0-8 in the mask, MCS 0-7 on stream 2 */
	{1, 0, 100, 0, 6, 2, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, 1, VHT_CAP, 0xfff6},
	/* HE 2SS 80 MHz: the user's AP's kind, a beamformer with ER */
	{1, 2, 140, 1, 7, 2, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, 1, VHT_CAP | 0x80800, 0xfffa,
	 1, {0x04, 0x20, 0x08, 0x98, 0x00, 0, 0x20}, 0xfffa, 0, 0, .changed = 12},
	/* HE 2SS 40 MHz, 2.4 GHz, no beamformer */
	{0, 1, 110, 0, 8, 2, 2, 0xfff, 1, HT_CAP, {0xff, 0xff}, 0, 0, 0,
	 1, {0x02, 0x20, 0x00, 0x00}, 0xfffa, 0, 0, .changed = 4},
	/* a 4SS HE AP at low RSSI, MU beamformer */
	{1, 2, 66, 1, 9, 2, 4, 0xff, 1, HT_CAP, {0xff, 0xff, 0xff, 0xff}, 1, VHT_CAP, 0xffaa,
	 1, {0x04, 0x00, 0x08, 0x00, 0x02}, 0xff55, 0, 0, .changed = 1},
	/* HE at 160 MHz over the 80+80 map */
	{1, 3, 120, 0, 10, 2, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, 1, VHT_CAP | 0x40, 0xfffa,
	 1, {0x1c, 0x20}, 0xfffa, 0xfffe, 0xfff0, .changed = 15},
	/* HT 1SS with MCS 0-3 only: the RSSI cut empties it, recovery restores it */
	{1, 0, 200, 0, 11, 2, 1, 0xff, 1, 0, {0x0f}},
	/* an RSSI past every level keeps every rate */
	{1, 1, 220, 0, 12, 2, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, .changed = 2},
	/* one TX stream */
	{1, 2, 140, 0, 13, 1, 2, 0xff, 1, HT_CAP, {0xff, 0xff}, 1, VHT_CAP, 0xfffa,
	 1, {0x04, 0x20, 0x08}, 0xfffa, 0, 0},
};

struct ba_case { u8 macid; bool valid; u16 tid, ssn, buf_size; };
static const struct ba_case ba_cases[] = {
	{0, true, 0, 100, 64}, {0, true, 3, 2000, 256}, {0, true, 6, 7, 64},
	{0, true, 5, 4095, 32}, {0, false, 3, 0, 0}, {0, false, 0, 0, 0},
	{0, true, 2, 1, 65}, {0, false, 5, 0, 0}, {0, false, 2, 0, 0}, {0, false, 2, 0, 0},
	{7, true, 7, 300, 64}, {7, false, 7, 0, 0},
};

struct rpt_case { u16 macid; u32 w2, w3, bitrate; u16 amsdu; };
#define W3(rate, mode, giltf, bw) ((rate) | (mode) << 8 | (giltf) << 10 | (bw) << 13)
static const struct rpt_case rpt_cases[] = {
	{0, 0, W3(11, 0, 0, 0), 540, 0},
	{0, 0, W3(12, 0, 0, 0), 600, 0},
	{0, 0, W3(4, 0, 0, 1), 7000, 1},
	{0, 0, W3(0x0f, 1, 1, 1), 3000, 0},
	{0, 0, W3(0x2a, 1, 0, 0), 1799, 1200},
	{0, 0, W3(0x02, 1, 0, 0), 4000, 0},
	{0, 0, W3(0x19, 2, 0, 2), 7800, 0},
	{0, 0, W3(0x01, 2, 1, 2), 1800, 0},
	{0, 0, W3(0x1b, 3, 3, 2), 12009, 5000},
	{0, 0, W3(0x07, 3, 2, 1), 3999, 0},
	{0, 0, W3(0x0b, 3, 1, 2), 6999, 0},
	{0, 0, W3(0x1a, 3, 5, 3), 549, 0},
	{0, 0, W3(0x13, 3, 4, 0), 550, 0},
	{0, 0, W3(0x03, 3, 0, 2), 2600, 0},
	{0, 0x80ff0000, W3(0x1b, 3, 3, 2) | 0x18000, 12009, 0},
	{5, 0x0000ffff, W3(0x1b, 3, 3, 2), 12009, 0},
	{0x1234, 0x1234, W3(0x09, 2, 0, 2), 3900, 0},
};

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	static struct rtw89_dev dev;
	static struct ieee80211_hw hw;
	static struct rtw89_vif_link vif_link;
	static struct rtw89_sta_link sta_link;
	dev.chip = &chip_info;
	dev.hw = &hw;
	harness_vif.type = NL80211_IFTYPE_STATION;
	sta_link.rtwvif_link = &vif_link;
	INIT_LIST_HEAD(&sta_link.ba_cam_list);

	word(ARRAY_SIZE(ra_cases));
	for (size_t i = 0; i < ARRAY_SIZE(ra_cases); i++) {
		const struct ra_case *c = &ra_cases[i];
		memset(&harness_sta, 0, sizeof(harness_sta));
		harness_sta.supp_rates[c->band ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ] = c->supp;
		harness_sta.ht_cap.ht_supported = c->has_ht;
		harness_sta.ht_cap.cap = c->ht_cap;
		memcpy(harness_sta.ht_cap.mcs.rx_mask, c->rx_mask, 4);
		harness_sta.vht_cap.vht_supported = c->has_vht;
		harness_sta.vht_cap.cap = c->vht_cap;
		harness_sta.vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(c->vht_map);
		harness_sta.he_cap.has_he = c->has_he;
		memcpy(harness_sta.he_cap.he_cap_elem.phy_cap_info, c->phy, 11);
		harness_sta.he_cap.he_mcs_nss_supp.rx_mcs_80 = cpu_to_le16(c->mcs80);
		harness_sta.he_cap.he_mcs_nss_supp.rx_mcs_160 = cpu_to_le16(c->mcs160);
		harness_sta.he_cap.he_mcs_nss_supp.rx_mcs_80p80 = cpu_to_le16(c->mcs80p80);
		harness_sta.rx_nss = c->rx_nss;
		harness_sta.bandwidth = c->bw;
		chan.band_type = c->band ? RTW89_BAND_5G : RTW89_BAND_2G;
		chan.band_width = RTW89_CHANNEL_WIDTH_80;
		dev.hal.tx_nss = c->tx_nss;
		dev.hal.rx_nss = 2;
		sta_link.mac_id = c->macid;
		sta_link.er_cap = c->er;
		sta_link.avg_rssi.internal = c->rssi;
		u32 in[22] = {c->band, c->bw, c->rssi, c->er, c->macid, c->tx_nss, c->rx_nss, c->supp,
			      c->has_ht, c->ht_cap,
			      c->rx_mask[0] | c->rx_mask[1] << 8 | c->rx_mask[2] << 16 |
				      (u32)c->rx_mask[3] << 24,
			      c->has_vht, c->vht_cap, c->vht_map, c->has_he,
			      c->phy[0] | c->phy[1] << 8 | c->phy[2] << 16 | (u32)c->phy[3] << 24,
			      c->phy[4] | c->phy[5] << 8 | c->phy[6] << 16 | (u32)c->phy[7] << 24,
			      c->phy[8] | c->phy[9] << 8 | c->phy[10] << 16,
			      c->mcs80, c->mcs160, c->mcs80p80, c->changed};
		for (size_t k = 0; k < 22; k++)
			word(in[k]);
		u32 before = h2c_count;
		rtw89_phy_ra_assoc(&dev, &sta_link);
		if (h2c_count != before + 1 || h2c_len != 24)
			abort();
		put(h2c_bytes, 24);
		rtw89_phy_ra_update_sta_link(&dev, &sta_link, c->changed);
		if (h2c_count != before + 2 || h2c_len != 24)
			abort();
		put(h2c_bytes, 24);
	}

	word(ARRAY_SIZE(ba_cases));
	for (size_t i = 0; i < ARRAY_SIZE(ba_cases); i++) {
		const struct ba_case *c = &ba_cases[i];
		struct ieee80211_ampdu_params params = {c->tid, c->ssn, c->buf_size};
		sta_link.mac_id = c->macid;
		word(c->macid); word(c->valid); word(c->tid); word(c->ssn); word(c->buf_size);
		u32 before = h2c_count;
		int ret = rtw89_fw_h2c_ba_cam(&dev, &vif_link, &sta_link, c->valid, &params);
		word((u32)ret);
		bool sent = h2c_count != before;
		word(sent);
		u32 map = dev.cam_info.ba_cam_map[0];
		u32 state = map & 3;
		for (int e = 0; e < 2; e++)
			state |= (u32)((map >> e) & 1 ? dev.cam_info.ba_cam_entry[e].tid : 0xff) << (8 + 8 * e);
		word(state);
		u8 bytes[16] = {0};
		if (sent) {
			if (h2c_len != 16)
				abort();
			memcpy(bytes, h2c_bytes, 16);
		}
		put(bytes, 16);
	}

	word(ARRAY_SIZE(rpt_cases));
	for (size_t i = 0; i < ARRAY_SIZE(rpt_cases); i++) {
		const struct rpt_case *c = &rpt_cases[i];
		struct { struct rtw89_c2h_hdr hdr; __le32 w2, w3; } __packed c2h = {
			{ 2 | 1 << 2, 16 }, cpu_to_le32(c->w2), cpu_to_le32(c->w3) };
		struct sk_buff skb = { (u8 *)&c2h, (u8 *)&c2h, sizeof(c2h), sizeof(c2h) };
		struct rtw89_phy_iter_ra_data data = { &dev, &skb };
		bool changed = false;
		sta_link.mac_id = (u8)c->macid;
		memset(&sta_link.ra_report, 0xa5, sizeof(sta_link.ra_report));
		struct rtw89_ra_report untouched = sta_link.ra_report;
		sta_link.max_agg_wait = -77;
		memset(&harness_sta, 0, sizeof(harness_sta));
		harness_sta.agg.max_rc_amsdu_len = c->amsdu;
		stub_bitrate = c->bitrate;
		__rtw89_phy_c2h_ra_rpt_iter(&sta_link, &harness_sta, &data, &changed);
		word(c->macid); word(c->w2); word(c->w3); word(c->bitrate); word(c->amsdu);
		const struct rtw89_ra_report *r = &sta_link.ra_report;
		bool updated = memcmp(r, &untouched, sizeof(*r)) != 0;
		u32 o[13] = {0};
		if (updated) {
			u32 kind = r->txrate.flags & RATE_INFO_FLAGS_HE_MCS ? 3 :
				   r->txrate.flags & RATE_INFO_FLAGS_VHT_MCS ? 2 :
				   r->txrate.flags & RATE_INFO_FLAGS_MCS ? 1 : 0;
			u32 bw = r->txrate.bw == RATE_INFO_BW_160 ? 3 :
				 r->txrate.bw == RATE_INFO_BW_80 ? 2 :
				 r->txrate.bw == RATE_INFO_BW_40 ? 1 : 0;
			if (r->bit_rate != c->bitrate)
				abort();
			u32 v[13] = {updated,
				     kind | !!(r->txrate.flags & RATE_INFO_FLAGS_SHORT_GI) << 8,
				     r->txrate.mcs, r->txrate.nss, r->txrate.he_gi, bw,
				     r->txrate.legacy, r->hw_rate, r->might_fallback_legacy,
				     r->retry_ratio, harness_sta.agg.max_rc_amsdu_len, changed,
				     (u32)sta_link.max_agg_wait};
			memcpy(o, v, sizeof(o));
		} else if (changed || harness_sta.agg.max_rc_amsdu_len != c->amsdu ||
			   sta_link.max_agg_wait != -77) {
			abort();
		}
		for (size_t k = 0; k < 13; k++)
			word(o[k]);
	}

	FILE *f = fopen(argv[1], "wb");
	if (!f || fwrite(trace, 1, trace_len, f) != trace_len || fclose(f))
		abort();
	printf("%zu %zu %zu\n", ARRAY_SIZE(ra_cases), ARRAY_SIZE(ba_cases), ARRAY_SIZE(rpt_cases));
	return 0;
}
'''
    program = '\n\n'.join([
        preamble, ieee, harness_types, core_defines, phy_defines, phy_c_defines, fw_defines,
        declarations, harness, chip, core_inlines, bitrates, core, fw, phy_tables, phy_iter,
        phy_first, phy_second, phy_report, main_c])
    generated = out / 'oracle.c'
    generated.write_text(program, newline='\n')
    exe = out / 'oracle'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wno-unused-function',
                    '-Wno-address-of-packed-member', str(generated), '-o', str(exe)],
                   check=True)
    trace = out / 'trace.bin'
    run = subprocess.run([str(exe), str(trace)], check=True, capture_output=True, text=True)
    ra_count, ba_count, rpt_count = map(int, run.stdout.split())
    data = trace.read_bytes()
    receipt = dict(
        linux_commit=COMMIT, symbols=manifest,
        cases=dict(ra=ra_count, ba_cam=ba_count, ra_report=rpt_count),
        dispatch=dict(rtw8852b_chip_info=info, rtw8852b_chip_ops=ops,
                      old_ht_ra_format=feats),
        trace_bytes=len(data), trace_sha256=hashlib.sha256(data).hexdigest(),
        generated_source_sha256=hashlib.sha256(generated.read_bytes()).hexdigest(),
        oracle_limit=[
            'the peers are the harness\'s ieee80211_link_sta, not mac80211\'s parse of an AP',
            'cfg80211_calculate_bitrate is a stub returning each case\'s bit rate',
            'cfg80211, nl80211 and mac80211 declarations are the harness\'s, with Linux\'s values',
            'rtw89_h2c_tx is a stub recording the skb; the CH12 path is the H2C oracle\'s',
        ])
    (out / 'manifest.json').write_text(json.dumps(receipt, indent=2) + '\n', newline='\n')
    print(json.dumps({k: receipt[k] for k in ['cases', 'trace_bytes', 'trace_sha256']}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
