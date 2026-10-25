# Round 2: existing-runtime and offline portability validation

The helpers run on the existing **CPython 3.11.11 Linux/WSL interpreter**, including from a freshly extracted offline ZIP. The standard-library helpers also work with third-party imports disabled and no external tools on `PATH`. A missing-dependency usability defect and a container-launcher directory defect were repaired and independently rechecked. This establishes an additional tested interpreter; it does not establish Python 3.10, Kali, native Windows, or competition-laptop support.

## Environment and evidence

- CPython 3.11.11, built with Clang 18.1.8, at `tools/distro/uv-python/cpython-3.11.11-linux-x86_64-gnu/bin/python3.11`. No pwntools package is installed in this interpreter.
- Existing CPython 3.12.3, built with GCC 13.3.0, at `/opt/ctf-tools/py312/bin/python`; pwntools 4.15.0 and the build-only renderer markdown-it-py 4.2.0 are installed there.
- Host kernel: Linux 6.6.87.2-microsoft-standard-WSL2, x86_64, glibc 2.39. Exact OS release is in [host.json](host.json).
- Host `file` 5.45 and ExifTool 12.76. Project `pngcheck` launcher reaches PNGcheck 4.0.1 in the existing `cyber-sea-game-2026-tools:local` Docker image, ID `sha256:804df10b7a628b28cc0ea0143111851c9668de3c706a7e71f5a98fa4ece68954`.
- Full argv, working directory, exit status, controlled `PATH`, and log paths are recorded in [commands.json](commands.json). Tool outputs are under [logs](logs/). No software was downloaded or installed.
- [source-hashes-before.json](source-hashes-before.json), [source-hashes-after.json](source-hashes-after.json), and [source-change-status.json](source-change-status.json) tie the initial checks to stable source bytes. Any repair recheck is recorded separately below.

## Executed checks

| Check | Actual result |
| --- | --- |
| Python 3.11 `test_toolkit.py` | 28 passed |
| Python 3.11 `test_toolkit_acceptance.py` | 22 passed |
| Python 3.11 `test_templates.py` | 3 standard-library tests passed; 7 pwntools tests skipped because the package is absent |
| Python 3.11 `test_math_client.py` | 6 tests skipped because the package is absent; not a math-client pass |
| Python 3.11 export/distribution tests | Build dependency absent: `markdown_it` import fails before distribution tests run; see distinction below |
| Python 3.11 and 3.12 `-I -S`, empty tool directory on `PATH` | Byte readiness, binary-text decoding, XOR, binary parser, and file preview passed; inspect readiness correctly reports unavailable capabilities |
| Quoted, Unicode, space-containing, dash-leading file names | Exact `AB` bytes and `6162` XOR preview; pre-existing output preserved and rejected with exit 2 |
| WSL `/mnt/c/...` mounted-drive output on both interpreters | Exact bytes, overwrite refusal, and staging-file cleanup passed; synthetic temporary directory removed afterward |
| Windows `C:\...` path supplied to Linux Python | `invalid_input` / exit 2, no traceback; documented interpreter-path rule applies |
| PNG inspection with neither `file` nor ExifTool available | `partial` / exit 3; both missing capabilities identified |
| Python 3.12 `-I -S` template suite with no tools on `PATH` | 3 standard-library tests passed, including loopback HTTP success/failure cases; 7 optional pwntools cases skipped |
| `source tools/activate.sh`, then Python 3.11 inspect readiness | Complete: real `file` and ExifTool feature probes succeeded |
| Existing `pngcheck` project launcher | Parsed a freshly generated 69-byte, 1×1 RGB PNG with 3 valid chunks and no errors; actual file action, not only help/version output |

The first `pngcheck -V` probe returned usage/2 because this version does not support that switch; its output identifies version 4.0.1. The subsequent `pngcheck -v <synthetic-image>` succeeded. The raw command record retains this distinction.

## Fresh offline ZIP

The existing Python 3.12 build environment exported 41 explicitly allowlisted files. These were archived with the standard library, extracted into a new quoted/Unicode directory outside the repository, and checked for exact per-file SHA-256 equality. The pre-archive staging directory was removed before runtime checks. [offline-zip.json](offline-zip.json) records the archive hash, extraction path, and every extracted file hash.

- Extracted Python 3.11 toolkit suite: **50 passed**.
- Extracted Python 3.11 templates: **3 standard-library tests passed, 7 optional pwntools tests skipped**.
- A real unprivileged network namespace with no network access ran extracted Python 3.11 binary-text conversion successfully.
- A separate child-only mount/network namespace hid the development tree with tmpfs and ran the extracted Python 3.12 `-I -S` byte doctor and conversion successfully. The host tree was never mounted over in the host namespace.

The Python 3.11 executable itself lives inside the development tree, so the source-hiding smoke used the external Python 3.12 interpreter. No claim is made that the source-hidden namespace check used Python 3.11. Python 3.11 did run the fresh extraction and the real no-network check.

## Failures and smallest repair

**Confirmed usability defect before repair:** on a clean interpreter, both optional pwntools templates fail even for `--help` with `ModuleNotFoundError: No module named 'pwn'`, without saying which dependency or interpreter to use. The failure is expected when execution needs pwntools; the unexplained traceback and inaccessible help are avoidable. Evidence: [starter stderr](logs/py311-missing-dependency-pwntools_starter.stderr) and [math-client stderr](logs/py311-missing-dependency-math_client.stderr).

Smallest repair, implemented by the coordinator: parse arguments before importing optional pwntools, and handle its absence with one concise dependency/interpreter message. No automatic installation or new dependency was added. `--help` and the pure arithmetic function now work without pwntools.

The changed paths were rechecked with **Python 3.11.11 `-I -S` and an empty tool directory on `PATH`**:

- Both scripts' `--help` returned 0 and usage text.
- Both actual-run attempts returned 2 with `pwntools is unavailable`, the exact selected interpreter path, and no traceback. Import failure occurred before any connection attempt.
- The new optional-dependency regression test passed, checking help and actual-run failure for both scripts.
- The arithmetic whitelist/limits test passed without pwntools, including valid arithmetic and rejected expressions.
- A newly generated, ZIP-transferred, freshly extracted 41-file export passed the same two regression tests on Python 3.11. The changed scripts and tests exactly match source hashes.

See [repair.log](repair.log), [repair-source-hashes.json](repair-source-hashes.json), and [repair-offline-zip.json](repair-offline-zip.json). The repair source was unchanged during these checks. The original byte and standard-library helper suites were not repeated because their files remain unchanged; the hash record explicitly lists those reusable checks. No unresolved material runtime defect remains from this lane.

**Confirmed launcher directory defect, repaired after integration:** the project container runner used to silently replace a working directory outside the project with the project root. A command using a relative file name could therefore return a different, same-named project file. The integration reproduction is retained in [launcher-boundary-before.json](launcher-boundary-before.json).

The repaired runner rejects outside working directories with exit 2 and an explicit message to run inside the project or use a native installed tool. It does not broaden the project bind mount. This lane independently checked it using different synthetic paths and a different quoted/Unicode collision filename:

- Outside-directory `cat <relative-path>` returned 2, with no stdout and an actionable project/native-tool diagnostic; it did not return the colliding project file.
- A real inside-project container call returned the exact intended synthetic file bytes.
- The existing `pngcheck` wrapper's `--help` call from outside also rejected clearly with 2.
- An authored Docker argument recorder proved an outside call never reaches Docker. An inside call retained exactly the existing project bind mount, existing read-only WSLg/X11 volumes, `--cap-drop ALL`, and `no-new-privileges`. The outside directory was not mounted or passed to Docker.
- Both synthetic inputs retained their SHA-256 hashes. The outside temporary directory was removed afterward. Runner SHA-256 stayed `cea44332ee214dbc00b26251682fad8c2be02d9b96fa667341d66d9eb58cf128` throughout the checks.

Full independent evidence is in [launcher-boundary-after.json](launcher-boundary-after.json), [launcher_boundary.py](launcher_boundary.py), and the `boundary-*` command logs. The first harness assertion mistakenly required the literal word “outside”; it was corrected to check the actual actionable diagnostic, and the original assertion failure remains in [launcher-boundary.log](launcher-boundary.log). The command already had the correct exit status and empty stdout in that first check.

**Build boundary, not helper runtime failure:** running `package_toolkit.py` and its distribution tests under bare Python 3.11 fails importing `markdown_it` from `build_notes.py`. Export generation uses the declared build-only renderer; exported helpers do not import it. Building with the already-equipped Python 3.12 environment succeeded. The README already documents this build dependency, so no runtime dependency should be added to the exported helpers.

The first evidence-driver attempt incorrectly continued after that failed build and then stopped trying to remove the nonexistent staging directory. The driver was repaired to require a successful build and a nonempty matching manifest. The original failure logs remain; the subsequent `--finish` run completed the actual ZIP checks. Also, the first driver expected the activated inspect doctor to be partial; actual probes succeeded, because the ExifTool launcher uses the host binary. This was an incorrect test expectation, not a product failure.

## Untested limits

Python 3.10 is absent and was not installed. Native Windows discovery found only the Microsoft Store `python.exe` alias, which was not executed; native Windows remains unsupported by the toolkit contract. Kali and organiser machines were not available. No unknown challenge binary was run, no desktop focus was taken, no host settings were changed, and no broad Docker maintenance was performed. This lane did not rerun the pwntools transport/math suites on Python 3.12; the coordinator owns validation of those repaired transport paths in the dependency-equipped environment.
