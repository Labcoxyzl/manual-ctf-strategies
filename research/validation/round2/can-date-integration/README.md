# Integrated local asc2log date repair

The validated local build is active through the project launcher. It fixes the uninitialized DST field and recognizes AM headers, with the exact `de_DE` and `en_US` locales required by this can-utils version. The original distro executable remains unchanged at `/usr/bin/asc2log`; PATH selects `/usr/local/bin/asc2log`.

| State | Image ID |
| --- | --- |
| Preserved `cyber-sea-game-2026-tools:before-can-date-fix` | `sha256:0e138ff37dfe13044aebf35f93e60d801ff04c6775c265509f6a2bc618c3f3b3` |
| Validated `cyber-sea-game-2026-tools:can-date-fix` and active `:local` | `sha256:50f47857aaa355668b2c8271c9f51e7e21250df4991b8ba49f4de8b6a9cc1658` |

The new image is 6,169,410,296 bytes, adding 863,313 bytes across its source and build layers. All original layers remain. The package database is byte-for-byte unchanged. The original `asc2log`, other checked tool hashes, and default Nmap/LibreOffice version output are unchanged (`package-and-layer-diff.json`). No host installation, package upgrade, prune, deletion or publication occurred.

The pinned sources, full original license notices and reviewed two-line patch are in `tools/distro/can-utils-date-fix/`, also installed under `/usr/local/share/can-utils-date-fix`. Build-time checks verify the source/patch hashes and the patched source hash before compiling a fresh binary. Its SHA-256 is `8aa7cdb285a713b483b17f52822ba0f9345d4f6eb871151ae56510bf6288506e`. This is a **local patched build**, not the distro package's exact binary. Original upstream unused-parameter warnings are retained in `build.log`; no diagnostics were suppressed.

`candidate/summary.json` records 70 required checks, including 56 date conversions across 14 cases, each checking all five absolute timestamps, relative offsets and full frame records (standard/extended IDs, channels, DLC/data, RTR and zero-length data). Coverage includes UTC, Berlin winter/summer, AM/PM, noon/midnight, milliseconds, relative ASC mode, and lowercase/mixed-case markers. The authored compact-to-ASC-to-compact roundtrip is exact. Zsteg scan/extraction, qpdf file validation, pngcheck, and Nmap/LibreOffice startup also passed.

After promotion, `promoted/summary.json` records 28 required checks through the actual `tools/distro/run-container` launcher, including all 14 date cases and the roundtrip/smokes. No expected timestamp or frame check was relaxed.

Known parser failures are recorded separately in each run's `known-limitations.json`, **not counted as readiness passes**: malformed DLC still drops one of five records with exit zero and empty stderr; invalid dates still substitute current time with a warning. Zsteg still strips trailing NULs. ASC lacks a timezone field; use the supplied log's timezone. DST transition ambiguity, CAN FD, hardware and live network frames were not tested.

The canonical Dockerfile appends the same COPY/build instructions used by the tested derivative, and `.dockerignore` allows only the additional source directory. The complete canonical image was not rebuilt; the derivative preserved its existing base and ran only the new instructions offline:

```bash
docker build --progress=plain --pull=false --network=none -f research/validation/round2/can-date-integration/Dockerfile.derivative -t cyber-sea-game-2026-tools:can-date-fix tools/distro
```

Recheck into a new output directory:

```bash
/opt/ctf-tools/py312/bin/python research/validation/round2/can-date-integration/verify.py --image cyber-sea-game-2026-tools:local --launcher --repeat 1 research/validation/round2/can-date-integration/recheck-1
```

Runtime rollback:

```bash
docker tag cyber-sea-game-2026-tools:before-can-date-fix cyber-sea-game-2026-tools:local
cp research/validation/round2/can-date-integration/image-id.txt.before tools/distro/image-id.txt
```

Source/build inputs, command logs, image IDs and hashes are retained here. Independent causal diagnosis and patch review remain in `../can-repair-review/`; the rejected locale-only candidate and all 24 inconsistent timestamp outcomes remain in `../can-locale-repair/`.
