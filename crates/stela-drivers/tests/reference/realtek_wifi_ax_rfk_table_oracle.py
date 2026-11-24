#!/usr/bin/env python3
"""Export RTL8852B's RF calibration tables from pinned rtw8852b_rfk_table.c.

Usage: script REFERENCE_DIRECTORY OUTPUT_DIRECTORY [--write]

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of the tree
realtek_wifi_reference.py checks. Every `static const struct rtw89_reg5_def`
array becomes a Rust table of `rfk::Entry` with its declaration's SHA-256,
each array's RTW89_DECLARE_RFK_TBL is required, and the rustfmt-formatted
result must equal the committed ax/rtw8852b/rfk/table.rs byte for byte;
`--write` replaces the committed file instead. Arguments are evaluated by a
small parser that knows integer literals, BIT(), GENMASK() and RF_PATH_A/B,
and refuses anything else. No calibration behavior is proved here.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
SOURCE = 'rtw89/rtw8852b_rfk_table.c'
TARGET = pathlib.Path(__file__).resolve().parents[3] / (
    'stela-driver-net/src/wifi/realtek/ax/rtw8852b/rfk/table.rs')
CONSTANTS = {'RF_PATH_A': 0, 'RF_PATH_B': 1}
ARITY = {'WRF': 4, 'WM': 3, 'WS': 2, 'WC': 2, 'DELAY': 1}


def value(text):
    """An argument: a literal, BIT(n), GENMASK(h, l) or a known constant."""
    text = text.strip()
    if re.fullmatch(r'0[xX][0-9a-fA-F]+|[0-9]+', text):
        number = int(text, 0)
    elif text in CONSTANTS:
        number = CONSTANTS[text]
    elif m := re.fullmatch(r'BIT\((\d+)\)', text):
        number = 1 << int(m.group(1))
    elif m := re.fullmatch(r'GENMASK\((\d+),\s*(\d+)\)', text):
        high, low = int(m.group(1)), int(m.group(2))
        number = ((1 << (high + 1)) - 1) & ~((1 << low) - 1)
    else:
        raise ValueError(f'unknown argument {text!r}')
    if not 0 <= number <= 0xffffffff:
        raise ValueError(f'argument {text!r} is not a u32')
    return number


def arguments(text):
    """Split a macro's arguments at the commas outside parentheses."""
    parts, depth, start = [], 0, 0
    for at, char in enumerate(text):
        depth += (char == '(') - (char == ')')
        if char == ',' and depth == 0:
            parts.append(text[start:at])
            start = at + 1
    parts.append(text[start:])
    return [value(part) for part in parts]


def rust_name(name):
    words = [word for word in name.removeprefix('rtw8852b_').split('_') if word != 'defs']
    return '_'.join(words).upper()


def entry(kind, args):
    if kind == 'WRF':
        path, address, mask, data = args
        return f'RfWrite {{ path: {path}, address: {address:#010x}, mask: {mask:#010x}, data: {data:#010x} }}'
    if kind == 'WM':
        address, mask, data = args
        return f'Mask {{ address: {address:#010x}, mask: {mask:#010x}, data: {data:#010x} }}'
    if kind in ('WS', 'WC'):
        address, bits = args
        variant = 'Set' if kind == 'WS' else 'Clear'
        return f'{variant} {{ address: {address:#010x}, bits: {bits:#010x} }}'
    (microseconds,) = args
    return f'Delay {{ microseconds: {microseconds} }}'


def main(argv):
    write = '--write' in argv
    args = [arg for arg in argv if arg != '--write']
    if len(args) != 2:
        print(__doc__)
        return 2
    reference, out = map(pathlib.Path, args)
    out.mkdir(parents=True, exist_ok=True)
    source = (reference / SOURCE).read_bytes()
    text = source.decode()
    tables, manifest, counts = [], [], dict.fromkeys(ARITY, 0)
    declaration = re.compile(
        r'static const struct rtw89_reg5_def (\w+)\[\] = \{(.*?)\n\};', re.S)
    for m in declaration.finditer(text):
        name, body = m.group(1), m.group(2)
        if f'RTW89_DECLARE_RFK_TBL({name});' not in text[m.end():m.end() + 200]:
            raise ValueError(f'{name} has no RTW89_DECLARE_RFK_TBL')
        entries = []
        for call in re.finditer(r'RTW89_DECL_RFK_(\w+)\(((?:[^()]|\([^()]*\))*)\)', body):
            kind, args = call.group(1), arguments(call.group(2))
            if len(args) != ARITY[kind]:
                raise ValueError(f'{name}: {kind} takes {ARITY[kind]} arguments')
            counts[kind] += 1
            entries.append(entry(kind, args))
        leftover = re.sub(r'RTW89_DECL_RFK_\w+\((?:[^()]|\([^()]*\))*\),?', '', body)
        if leftover.strip():
            raise ValueError(f'{name}: unparsed text {leftover.strip()[:40]!r}')
        digest = hashlib.sha256(m.group(0).encode()).hexdigest()
        manifest.append({'symbol': name, 'entries': len(entries), 'sha256': digest})
        tables.append((name, rust_name(name), digest, entries))
    if len({rust for _, rust, _, _ in tables}) != len(tables):
        raise ValueError('two tables share a Rust name')
    if text.count('RTW89_DECLARE_RFK_TBL(') != len(tables):
        raise ValueError('a declared table was not exported')
    full = hashlib.sha256(source).hexdigest()
    lines = [
        '// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause',
        '// Copyright(c) 2019-2020 Realtek Corporation',
        '// RTL8852B RF calibration tables from the licensed driver source.',
        f'// Source: Linux {COMMIT} {SOURCE}.',
        f'// Full donor SHA256 {full}.',
        '//! RTL8852B\'s RF calibration tables, as rtw8852b_rfk_table.c declares',
        '//! them, generated by realtek_wifi_ax_rfk_table_oracle.py.',
        'use super::Entry::{self, *};',
    ]
    for name, rust, digest, entries in tables:
        lines += ['', f'// {name}: {len(entries)} entries; source declaration SHA256 {digest}.',
                  f'pub static {rust}: &[Entry] = &[']
        lines += [f'    {item},' for item in entries]
        lines.append('];')
    lines += ['', '/// Every table by its rtw89 name, in the source\'s order.',
              'pub static TABLES: &[(&str, &[Entry])] = &[']
    lines += [f'    ("{name}", {rust}),' for name, rust, _, _ in tables]
    lines.append('];')
    generated = out / 'table.rs'
    generated.write_text('\n'.join(lines) + '\n', newline='\n')
    subprocess.run(['rustfmt', '--edition', '2024', str(generated)], check=True)
    if write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(generated.read_bytes())
    elif generated.read_bytes() != TARGET.read_bytes():
        raise SystemExit('committed RFK tables differ from the pinned source export')
    summary = {'linux_commit': COMMIT, 'source': SOURCE, 'source_sha256': full,
               'tables': len(tables), 'counts': counts, 'declarations': manifest}
    (out / 'manifest.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(f'{len(tables)} tables, entries {counts}, source SHA256 {full}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
