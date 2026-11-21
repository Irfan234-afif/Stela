#!/usr/bin/env python3
"""Check the pinned Linux tree the Realtek Wi-Fi oracles read.

Usage: script REFERENCE_DIRECTORY
       script --record REFERENCE_DIRECTORY

REFERENCE_DIRECTORY is drivers/net/wireless/realtek of a Linux checkout at the
commit realtek_wifi_reference.json names. Every rtw88/ and rtw89/ file must
have its recorded git blob id and SHA-256, and none may be missing or extra:
a tree from another commit, or one checked out with CRLF line ends, fails.
`--record` rewrites the manifest from a tree known to be that commit.

One way to make the tree, kept out of third_party/linux:

    git init linux && cd linux && git config core.autocrlf false
    git remote add origin https://github.com/torvalds/linux.git
    git sparse-checkout set --no-cone /drivers/net/wireless/realtek/
    git fetch --depth 1 --filter=blob:none origin COMMIT
    git checkout --detach FETCH_HEAD

The source pins in stela-c-build's linux_radio policy describe another tree
(its core.c, fw.c and pci.c differ from this commit's) and are not used here.
"""
import hashlib
import json
import pathlib
import sys

MANIFEST = pathlib.Path(__file__).with_name('realtek_wifi_reference.json')
COMMIT = 'a804c5742bff224d4cb4d25dd383554d598be32b'
FAMILIES = ('rtw88', 'rtw89')


def files(root):
    for family in FAMILIES:
        for path in sorted((root / family).rglob('*')):
            if path.is_file():
                yield path.relative_to(root).as_posix(), path.read_bytes()


def entry(data):
    blob = hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()
    return {'blob': blob, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main(argv):
    record = argv[:1] == ['--record']
    args = argv[1:] if record else argv
    if len(args) != 1:
        print(__doc__)
        return 2
    root = pathlib.Path(args[0])
    found = {path: entry(data) for path, data in files(root)}
    if record:
        pinned = {
            'directory': 'drivers/net/wireless/realtek',
            'files': found,
            'linux_commit': COMMIT,
        }
        with MANIFEST.open('w', newline='\n') as out:
            json.dump(pinned, out, indent=1, sort_keys=True)
            out.write('\n')
        print(f'recorded {len(found)} files of Linux {COMMIT}')
        return 0
    pinned = json.loads(MANIFEST.read_text())
    expected = pinned['files']
    problems = [f'missing {path}' for path in expected if path not in found]
    problems += [f'not pinned {path}' for path in found if path not in expected]
    problems += [
        f'differs {path}: blob {found[path]["blob"]}, pinned {pin["blob"]}'
        for path, pin in expected.items()
        if path in found and found[path] != pin
    ]
    for problem in problems:
        print(problem)
    if problems:
        print(f'{len(problems)} of {len(expected)} files do not match Linux {pinned["linux_commit"]}')
        return 1
    print(f'{len(expected)} files match Linux {pinned["linux_commit"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
