# Optional local toolkit

Use these prewritten helpers for repeatable byte conversion and bounded file inspection. They supplement the [approved tools](../index.html#tools); they are not additional organiser-approved applications or solvers for every category. Keep challenge files local and follow the [competition rules](../RULES.html).

<a id="setup"></a>
## Start here

For an editable local/remote connection scaffold, see [Python challenge templates](templates/README.md). That optional starter requires pwntools; the byte and inspection helpers below do not.

For broader competition preparation, install the [no-AI Python requirements](../requirements.txt) in a fresh **Linux/WSL or Kali** CPython 3.11/3.12 virtual environment. For a new checkout, use a GitHub account with access to this private repository:

```sh
git clone https://github.com/Labcoxyzl/manual-ctf-strategies.git
cd manual-ctf-strategies
python3 --version  # Confirm 3.11.x or 3.12.x before continuing.
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=:all: -r requirements.txt
python -m pip check
python scripts/ctf.py doctor --workflow bytes
python scripts/templates/math_client.py --local python scripts/templates/math_demo.py
```

If you already have a checkout or the offline export, skip the first two commands and start from its root. This optional set includes pwntools, crypto/math, packet/web, file-analysis and approved forensic libraries; it does not install AI/LLM extras. Keep [constraints.txt](../constraints.txt) beside the requirements file: it pins the reviewed dependencies. `--only-binary` rejects a package without a compatible wheel instead of building unreviewed source on the competition machine. The helpers in this guide still run without this set.

Run commands from the folder containing `index.html` and `scripts/`. The entry point is [scripts/ctf.py](ctf.py); there is no installation step, network access or Python package dependency. Keep this folder structure when copying the toolkit offline.

The declared runtime is **CPython 3.10 or newer on Linux, including WSL**. Check the interpreter before relying on the script:

```sh
python --version
python scripts/ctf.py doctor --workflow bytes
python scripts/ctf.py --help
```

If your Linux launcher is `python3`, substitute it in every example. If Python is missing, the shell fails before the toolkit can diagnose anything. The standard-library helpers were tested on Python 3.11.11 and 3.12.3 in Linux/WSL, including a fresh offline export. Python 3.10, Kali and competition-machine checks remain pending. Native Windows execution is unsupported. From Windows, open WSL, change to the copied folder (for example `cd "/mnt/c/Users/YourName/CTF toolkit"`), and use its Linux Python. A Windows Python installation does not establish that WSL tools are available.

Quote paths containing spaces. Use paths understood by the running interpreter, such as `/mnt/c/...` in WSL, rather than `C:\...`. Unicode paths are supported. For a filename beginning with a dash use `--file=-sample.bin` or `--file="./-sample.bin"`. Inputs must be regular local files; there is no implicit stdin or directory traversal.

Choose `bits` for explicitly binary text, `xor` for raw bytes and a known hex key, or `inspect` to gather initial evidence. `doctor --workflow bytes` checks the Python-only transforms; `doctor --workflow inspect` checks Python, `file` and ExifTool readiness. A partial doctor result names the unavailable capability and the remaining usable branches. It does not install anything.

<a id="bits"></a>
## Binary text → bytes

Approved baseline: local [CyberChef](../index.html#tool-windows-1), **From Binary**, or approved [Python](../index.html#tool-windows-7). Prefer CyberChef for a short interactive conversion. This helper makes selected payload lines, bit significance and validation repeatable.

```sh
python scripts/ctf.py bits --text "01000001 01000010"
```

Expected: two output bytes, hex `4142`, with width 8 and `msb` bit significance. Printable bytes alone do not establish successful decryption. No output file is created without `--out`.

For a file with a header followed by two binary payload rows:

```sh
python scripts/ctf.py bits --file "rows.txt" --lines 2:3 --width 8 --order msb --out "decoded.bin"
```

`--file` and `--text` are mutually exclusive. Only `0`, `1` and ASCII whitespace are accepted in the selected text; headers containing digits are never harvested automatically. `--lines START:END` is one-based and inclusive. Selected rows are concatenated for conversion; their boundaries are not output-byte boundaries. Widths 1–8 create one zero-extended output byte per group. `--order msb|lsb` changes bit significance within each group, not byte order or the order of the stream. The report states selected lines, bit count, group count and parameters.

Failure example: `python scripts/ctf.py bits --text "0100000"` returns `invalid_input`/2 for an incomplete 8-bit group and writes nothing. Empty selections and nonbinary characters are invalid. Inspect the reported position and original rows; do not pad, truncate or discard text merely to obtain output.

Manual alternative: select the same payload rows, paste into local CyberChef's From Binary operation, and deliberately configure the same grouping and bit significance. With approved Python, split validated bits into groups and use `int(group, 2)` for MSB, or `int(group[::-1], 2)` for LSB. Check expected bytes before trusting the result.

<a id="xor"></a>
## Known-key file XOR

Approved baseline: local [CyberChef XOR](../index.html#tool-windows-1) or approved [Python](../index.html#tool-windows-7). Use the CLI when repeating a file transform or protecting an output from accidental replacement. It performs no key search or scoring.

```sh
python scripts/ctf.py xor --file "research/learning/practice/match.txt" --key-hex "20" --out "xor-result.bin"
```

Expected: output has exactly the input byte length; each byte is XORed with `0x20`. XORing that output with the same key into another new file restores the original bytes. Compare to a known expected result as well as testing the round trip.

A key is nonempty hexadecimal, with ASCII whitespace allowed between digits. It cycles from file offset zero. Other characters, odd digit counts and keys over 64 KiB decoded are rejected. Raw file bytes are used unchanged; there is no text encoding choice. Empty files yield a valid empty result. Keys are not included in result reports.

Failure example: `python scripts/ctf.py xor --file "research/learning/practice/match.txt" --key-hex "f"` returns `invalid_input`/2 for odd-length hex. An existing `--out` path is also refused, including on a second run of the example. Choose a new output name.

Manual alternative: load the file into local CyberChef, choose XOR with a hex key and repetition from offset zero, and save to a new filename. In approved Python, compute `bytes(value ^ key[index % len(key)] for index, value in enumerate(data))` after explicitly validating the key. Preserve the original and compare bytes independently.

<a id="inspect"></a>
## Gather initial file evidence

Approved baseline: [file on Kali](../index.html#tool-kali-42), [ExifTool on Windows](../index.html#tool-windows-14), [7-Zip on Kali](../index.html#tool-kali-2), and approved [Python](../index.html#tool-windows-7). The wrapper requires Linux executables in its own environment; an approved Windows installation does not imply an available WSL executable.

```sh
python scripts/ctf.py inspect --file "research/learning/practice/match.txt"
```

Expected: size, bounded format evidence and check coverage. This plain-text fixture does not need image metadata. Missing `file` leaves classification unknown and returns `partial`/3. `--sha256` requests a whole-file SHA-256 and costs a complete read; a prefix is never labeled a whole-file digest.

For JPEG/PNG evidence, inspection asks ExifTool for selected tags. No GPS means only that the queried GPS tags were not found. For classic ZIP evidence, it checks bounded directory metadata and reports encrypted entries separately from malformed structure. It shows at most 100 members; a complete report may summarize a fully checked directory beyond those displayed rows. It never extracts, runs an artifact, or proves safe extraction.

Failure example: `python scripts/ctf.py inspect --file "missing-file.bin"` returns `invalid_input`/2. Missing ExifTool affects the image branch, not non-image inspection. Unsupported ZIP64, multidisk, self-extracting or unrecognized directory structures return a partial report with the archive-tool alternative. A malformed ordinary ZIP is invalid input. Other formats can have complete basic inspection while their contents remain unexamined.

Manual alternative: on the matching approved platform, run `file -- "./artifact.bin"`, open image metadata in ExifTool, or list an archive with `7z l "./archive.zip"`. Use absolute or `./`-prefixed paths so filenames are not options. On Windows invoke the approved ExifTool executable with a full Windows path. For PDF/audio contents and executable analysis, follow the [format-specific routes](../index.html#forensics). Do not execute a file to identify it.

<a id="results"></a>
## Interpret results and preserve files

Every command supports `--json` for the same facts in one structured stdout result after argument parsing. Default output is a compact text report; diagnostics use stderr. Help and argument-parser usage errors use normal argparse output. Reports describe sources, scope and limits, with at most two next actions; they do not announce flags or confidence percentages.

| Status / exit | Meaning and next step |
| --- | --- |
| `complete` / 0 | All requested applicable checks finished, including valid empty XOR output. Read the stated scope; complete classification is not complete content analysis. |
| `invalid_input` / 2 | Invalid arguments, selected data, key or input type. Correct the named issue without modifying the original. |
| `unsupported` / 3 | Runtime or required capability is unsupported. Use the matching approved manual workflow. |
| `partial` / 3 | Useful facts remain, but an applicable capability is unavailable or unsupported. Read which check was skipped. |
| `partial` or `failed` / 1 | I/O, changed input, timeout or a work/output limit prevented completion. No partial transform is published. |
| Interrupted / 130 | Ctrl-C cancels the operation and removes task-owned incomplete output. |

When both missing capabilities and operational limits occur, exit 1 takes precedence. `doctor --workflow inspect` requires both `file` and ExifTool probes for full readiness even if your next input is not an image; 7-Zip is a manual alternative, not a hidden dependency.

Without `--out`, transforms show a bounded preview and byte count, never raw binary terminal output. Any estimated or unvalidated scope must be labeled; a complete bits result validates all selected text. With `--out`, the destination must be new: existing files, same-file aliases, symlinks and nonregular destinations are rejected. There is no force-overwrite option. Output is staged privately beside its destination and published only after validation and an input identity/size/mtime recheck; failures remove task-owned staging output.

| Work limit | First-release boundary |
| --- | --- |
| Source bytes per command | 256 MiB, including skipped lines and optional hashing |
| Overall command deadline | 30 seconds, including probes and hashing |
| Classification prefix / transform chunks | 64 KiB |
| Rendered preview | 64 bytes |
| Each external tool | 10 seconds; 1 MiB captured output |
| ZIP metadata | 8 MiB central directory; 10,000 members; 100 displayed rows |
| Decoded XOR key | 64 KiB |

Limits and truncation are reported. No unbounded override is provided; use the approved manual route for larger inputs. The toolkit makes no network calls, uploads, automatic dependency installations or recursive decoding attempts. Keep the preparation pages offline; external technical links still require internet.
