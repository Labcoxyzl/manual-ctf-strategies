# Local asc2log date repair

This directory builds a locally patched `asc2log` from can-utils v2023.03, pinned to upstream commit `cfe41963f3425e9adb01a70cfaddedf5e5982720`. `sources.json` records the three original source URLs and hashes. Original dual-license notices (`GPL-2.0-only OR BSD-3-Clause`) remain in each source file and `LICENSE`.

`date-fix.patch` contains the two independently reviewed changes: initialize `struct tm` with `tm_isdst=-1`, and recognize AM as well as PM before selecting the English 12-hour parser. The image generates the exact `de_DE` and `en_US` locale names requested by this version. The build verifies both the original files and patched source against recorded SHA-256 values before compilation.

The resulting override is `/usr/local/bin/asc2log`; the original distro executable stays at `/usr/bin/asc2log`. Sources, patch, hashes and this notice stay in `/usr/local/share/can-utils-date-fix`. The default project launcher uses the local override through PATH. `dpkg-query` still reports the original distro package, not this derivative's exact build identity. No package or libc upgrade is part of this repair.

ASC headers do not carry a timezone; set `TZ` from the supplied log's context. This repair does not make the parser strict: malformed rows may be silently omitted with exit zero, and invalid dates may fall back to the current time with a warning. Validate timestamps, record counts and frame contents. DST transition ambiguity, CAN FD and live CAN interfaces are outside the validation scope.

Independent review: `research/validation/round2/can-repair-review/REPORT.md`. Final image and launcher evidence: `research/validation/round2/can-date-integration/`.
