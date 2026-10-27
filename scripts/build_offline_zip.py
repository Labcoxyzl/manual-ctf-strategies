#!/usr/bin/env python3
"""Build the tracked offline ZIP from the validated public export."""

import argparse
import os
from pathlib import Path
import stat
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from package_toolkit import ROOT, collect


ARCHIVE = ROOT / 'manual-ctf-strategies-offline-2026-10-27.zip'
TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def build(out=ARCHIVE):
    files = collect(ROOT)
    with tempfile.NamedTemporaryFile(dir=out.parent, prefix='.offline-kit-', delete=False) as temp:
        temporary = Path(temp.name)
    try:
        with ZipFile(temporary, 'w', compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                info = ZipInfo(name, TIMESTAMP)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data, compress_type=ZIP_DEFLATED, compresslevel=9)
        temporary.chmod(0o644)
        os.replace(temporary, out)
    finally:
        temporary.unlink(missing_ok=True)
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ARCHIVE,
                        help='ZIP destination (default: tracked root-level offline kit)')
    args = parser.parse_args()
    print(f'Packed {build(args.out)} allowlisted files into {args.out}')


if __name__ == '__main__':
    main()
