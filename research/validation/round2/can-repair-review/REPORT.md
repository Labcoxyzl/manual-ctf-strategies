# Independent CAN repair review — 2026-10-25

A reversible local candidate is justified. The missing locales and the uninitialized DST flag are separate defects. Keep the generated `de_DE` and `en_US` locales, and initialize the timestamp structure with `struct tm tms = { .tm_isdst = -1 };`. No image, canonical source, launcher, or current tag was changed by this review. All compilations and outputs are confined to this directory.

The installed binary was tested directly using a temporary `LD_PRELOAD` interposer that records the incoming `tm_isdst` and optionally changes only that field. For 12 unchanged UTC runs, seven nonpositive values produced the expected epoch and five positive values produced an epoch exactly 3,600 seconds early. Forcing `-1` or `0` produced the correct epoch in all 24 controls; forcing `1` produced the one-hour error in all 12 controls. Every run returned zero. This links the installed failure to the field passed to `mktime`, independently of the source-only hypothesis. The interposer is diagnostic and must not be installed as a repair. See [results.json](results.json), [summary.json](summary.json), and the complete inputs/stdout/stderr under [runs](runs/).

The [pinned upstream source](https://github.com/linux-can/can-utils/blob/cfe41963f3425e9adb01a70cfaddedf5e5982720/asc2log.c#L370) declares `struct tm tms;`, parses calendar fields, and calls `mktime` without setting `tm_isdst`. The freshly fetched source SHA-256 matches the earlier evidence. A disposable build of the unchanged source reproduces the failure. Changing only the initializer passes all 25 repeated supported controls: UTC, millisecond date, PM, noon, Berlin winter, Berlin summer, and relative offsets. Exact epoch, each offset, all five IDs/channels/data/RTR outputs, status and stderr are checked. The two extra summer controls establish that `tm_isdst=0` alone is wrong: it is 3,600 seconds late, while `-1` is correct.

There is also an independently reproduced AM defect. The source detects only ` pm ` before choosing the English 12-hour parser. AM and midnight inputs take the German 24-hour branch, fail parsing, and fall back to current time. This persists after the DST initializer repair. A second disposable variant adds `|| strcasestr(date, " am ") != NULL`; all five AM/midnight/AM-millisecond/PM/noon controls pass. If the parent wants AM/PM supported, this second line belongs in the candidate. Otherwise document AM as unsupported. Do not claim the initializer alone fixes AM/PM generally. See [additional-results.json](additional-results.json). Four further lowercase/mixed-case AM/PM inputs also pass; `strcasestr` retains case-insensitive branch selection, and the English locale parser accepts the tested casing. See [am-case-results.json](am-case-results.json).

| Option | Assessment |
|---|---|
| Locale generation and `TZ` alone | Insufficient: the UTC one-hour error still occurs. `LC_ALL` cannot replace locales explicitly requested by the program. |
| Locale generation plus initialized `tm_isdst=-1` | Recommended minimum timestamp repair. One changed source line; no package upgrade or new dependency. |
| Above plus AM-branch recognition | Recommended if AM input is part of the supported workflow; independently tested as a distinct repair. |
| Detect-only guard | Useful mitigation for a bounded input grammar: reject fallback warnings, verify expected timestamps and record preservation. Status or stderr alone cannot detect the one-hour error or missing malformed rows. A general ASC validator is a larger task. |
| Omit reverse conversion | Smallest operational alternative if only compact-log inspection/export is required. It leaves ASC input unsupported rather than repairing it. |

Malformed DLC remains unchanged: a five-row file with only three bytes supplied for a DLC-eight row produces four rows, status zero and empty stderr in both the installed and initializer-patched binaries. An invalid date produces five rows, status zero and the current-time fallback warning. Preserve those failing controls; this patch does not make `asc2log` a strict validator. Other malformed syntax, DST transition ambiguity, CAN FD, hardware, transmission and live tunnelling were not tested.

Build provenance is recorded in [sources.json](sources.json), [tag-provenance.json](tag-provenance.json), [runtime-provenance.txt](runtime-provenance.txt), and [image-id.txt](image-id.txt). Upstream tag `v2023.03` resolves to commit `cfe41963f3425e9adb01a70cfaddedf5e5982720`. Inputs are that commit's `asc2log.c`, `lib.c`, and `lib.h`, plus the candidate image's system headers and libc. The image has distro `can-utils 2023.03-1`, GCC binary 16.2.0 (`gcc-16 16.2.0-3`; the GCC metapackage version differs), glibc/development headers 2.43-6 and Linux userspace headers 7.1.5-1kali1. The build command was:

```sh
gcc -O2 -Wall -Wextra -D_GNU_SOURCE asc2log-tm-fixed.c lib.c -o asc2log-tm-fixed
```

This follows upstream's `asc2log.o + lib.o` link relationship, but uses installed headers and is not a byte-for-byte reconstruction of the distro build. Both controls used identical inputs/flags except the patch. Only existing upstream unused-parameter warnings were emitted. Label any installed derivative as a local patched build, retain its source/patch/hash and the original distro binary, and test the actual launcher before promotion. Package metadata must not be presented as the patched binary's exact build identity.

The three source inputs carry `GPL-2.0-only OR BSD-3-Clause` notices; full notices remain in each copied and patched file, and the distro copyright record is retained. For a distributed derivative, include the selected license's notice materials with the binary. No legal conclusion beyond these source notices is asserted.

Reproduce from the repository root, after running [build.sh](build.sh) inside the same mounted image:

```sh
docker run --rm --network none --read-only \
  -v "$PWD/research/validation/round2/can-repair-review:/review" \
  --tmpfs /tmp --entrypoint python3 \
  cyber-sea-game-2026-tools:can-locale-fix /review/repro.py
```

`repro.py` ran 149 conversion invocations; `additional-controls.py` ran seven more; `am-case-controls.py` ran four, for 160 total. Assertions passed while preserving the expected failing original/AM/malformed results. The final candidate image and launcher require their own checks after the parent implements the selected repair. No promotion or full toolkit retest was attempted here.
