# Recipe fixture validation

Run: 2026-10-23T03:05:43.204460+00:00
Routes SHA-256: `2193bde7bcdad6c53f16cb92ebe5be042880a64faf8c31998397d7f89a26a712`

Commands ran in a temporary directory on generated benign files, without network requests or package installation.
Only the listed command steps were exercised; this is not validation of whole routes or organiser machines.

| Route | Exact command | Result | Local version |
|---|---|---|---|
| artifact-identification | `file artifact.bin` | PASS | file-5.45 |
| artifact-identification | `7z l artifact.bin` | PASS | 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20 |
| artifact-identification | `7z x artifact.bin -oextracted-artifact` | PASS | 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20 |
| artifact-identification | `7z l invalid.bin` | PASS (failure control) | 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20 |
| focused-extraction | `rg -n -F "needle" evidence-dir` | PASS | ripgrep 15.2.0 (rev e89fff89ac) |
| focused-extraction | `jq . data.json` | PASS | jq-1.7 |
| focused-extraction | `jq -r .key data.json` | PASS | jq-1.7 |
| focused-extraction | `jq . invalid.json` | PASS (failure control) | jq-1.7 |
| focused-extraction | `python3 -c 'import struct; data = open("record.bin", "rb").read(4); print(struct.unpack("<I", data)[0])'` | PASS | Python 3.12.3 |
| media-inspection | `exiftool -a -u -g1 image.png` | PASS | 12.76 |
| media-inspection | `pngcheck -v image.png` | SKIP: executable unavailable |  |

Untested routes: android-validation, bundle-extraction, decode-bytes, disk-file, document-code, dotnet-validation, endpoint-discovery, executable-triage, http-baseline, jwt-verification, memory-process, metadata-corroboration, native-checker, password-recovery, pcap-stream, public-domain, public-source, rsa-weakness, service-interaction, source-view, targeted-web-test.

Skipped: GUI workflows, exploit execution, real challenge inputs, online services, and platform/version parity. Source-reviewed labels remain appropriate; local fixture success does not establish competition-host availability.
