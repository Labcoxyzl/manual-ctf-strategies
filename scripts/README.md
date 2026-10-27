# Optional local toolkit

Use these prewritten helpers for repeatable byte conversion and bounded file inspection. They supplement the [approved tools](../index.html#tools); they are not additional organiser-approved applications or solvers for every category. Keep challenge files local and follow the [competition rules](../RULES.html).

<a id="setup"></a>
## Start here

For an editable local/remote connection scaffold, see [Python challenge templates](templates/README.md). That optional starter requires pwntools; the byte and inspection helpers below do not.

`autosolve.py` is the developing local artifact runner. It handles bounded
encoding/classical-cipher and XOR candidates, declared RSA/AES/hash checks,
ZIP/TAR, MIME, PDF, Office/RTF, image metadata/steganography/QR, media views,
offline packet and CAN inspection, SQLite, and static ELF leads. `setup`
uses uv to install the hash pinned Python core into `.autosolve/envs/core/`
with CPython 3.12, without changing the active Python or `/opt/ctf-tools`.
It needs internet on a fresh checkout and never installs native engines.
`doctor` probes the interpreter used to run it; missing native engines remain
partial. Reports are private under `.autosolve/runs/` and mark remaining
families as partial or not implemented. A candidate string does not mean the
challenge accepted an answer.

```sh
python3 scripts/autosolve.py setup --profiles all
.autosolve/envs/core/bin/python scripts/autosolve.py doctor --profiles all --self-test
.autosolve/envs/core/bin/python scripts/autosolve.py analyze ./challenge.zip --category auto --budget 300
.autosolve/envs/core/bin/python scripts/autosolve.py resume .autosolve/runs/RUN_ID --budget 300
```

For an assigned service, `service --host HOST --port PORT --protocol private.json`
runs only the protocol's explicit hex writes and delimiter, length, or exact
byte reads. A protocol can contain `{"steps":[{"read":{"delimiter_hex":"0a"}},
{"write_hex":"4869"}]}` and optional TLS settings; the endpoint comes from
the command. `service --host HOST --ports 80,443 --enumerate` checks only those
TCP ports. An optional private protocol can declare per-port hex probes as
`{"probes":{"80":"48454144202f20485454502f312e300d0a0d0a"}}`.
Transcripts and inventory bytes stay in private run files. Resume renders the
saved result without sending requests again; neither mode claims exploitation
or challenge acceptance.

For scoped WEB02 discovery, supply a raw HTTP GET request and a small private
wordlist: `python3 scripts/autosolve.py web --request-file ./request.http
--scope-origin https://assigned.example --wordlist ./small-words.txt --kind path
--budget 30`. The origin is authoritative. Redirects are recorded without
following them, and omitting the wordlist sends no requests.

<a id="web-sql"></a>
For one suspected SQL input, supply the saved request and opt in with
`--sql-test --sql-parameter NAME`. A selected value comparison additionally
needs `--sql-table TABLE --sql-column COLUMN` and one to four repeated
`--sql-candidate VALUE` arguments. A differential response is a lead, not
proof of a query or an accepted challenge result.

<a id="web-leads"></a>
For one suspected path traversal or template input, use
`--lead-kind traversal|template` with an existing `--parameter` and explicit
probe/expected value or syntax. WEB03 and WEB05 checks stay within the
declared origin, budget and rate and are not replayed on resume.

<a id="web-workflows"></a>
WEB08 compares two supplied workflows against a declared response invariant.
Put roles, ordered steps and the invariant in a private JSON fixture. Mark a
step `safe_to_replay: true` only when sending it is intended; then run
`python3 scripts/autosolve.py web --scope-origin https://assigned.example
--workflow-file ./private.json --workflow-test --budget 30`. The transcript stays private, and resume reads
it without sending the requests again. An explicit `Cookie` header seeds
only that role's host-scoped session, and later `Set-Cookie` responses update
it; a raw header cannot recover the cookie's original path scope. A difference
is an observation, not proof of an authorization flaw. Replace the synthetic
paths and role header
in this fixture with two permitted principals and a known object:

```json
{"expected_invariant":{"left":{"role":"owner","step":"read"},
 "right":{"role":"guest","step":"read"},"relation":"different_status"},
 "workflows":[{"role":"owner","steps":[{"id":"read","method":"GET",
 "path":"/object/1","headers":{"X-Role":"owner"},"safe_to_replay":true}]},
 {"role":"guest","steps":[{"id":"read","method":"GET",
 "path":"/object/1","headers":{"X-Role":"guest"},"safe_to_replay":true}]}]}
```

Setup uses only wheels and verifies hashes from
[`core.lock.txt`](autosolve_requirements/core.lock.txt). It stops with a
partial result if CPython 3.12, a compatible wheel, or uv is unavailable.
It does not delete an unexpected pre-existing `.autosolve/envs/core` directory.

For an encrypted ZIP, put candidate passwords in a private file, one exact
byte line each (at most eight; LF or CRLF separators), and pass a JSON hints file containing `{"password_file":
"/path/to/private-passwords.txt"}` with `--hints`. The local `analyze` command never sends
challenge data over the network. ZIP and TAR extraction keep originals
unchanged; files larger than 8 MiB are recorded but not passed to the
encoding decoder. Runs remain partial while baseline families are unavailable.

Candidate patterns scan raw bytes in bounded 1 MiB chunks with 4,095 bytes of
overlap. Matches are limited to 4,096 bytes and retain byte offsets. At most
64 MiB is scanned per artifact; a report states if that or a work limit leaves
bytes unchecked. UTF-16 and other text encodings are not decoded by this scan.

For bounded textbook RSA checks, pass `--hints` with
`{"rsa_parameters":{"records":[{"n":"0x...","e":3,"c":"0x..."}]}}`.
Records can also use `public_key_pem`, `public_key_der_hex`, or a
`key_file_index` into private `key_files`, together with `c`. The selected
methods verify a raw modular preimage; padding and the original byte width
remain unknown. A reported preimage is not an accepted flag.

Declared AES-GCM, CBC and CTR checks accept a `symmetric_parameters` list in
the private hints JSON. Each record names `algorithm: "AES"`, `mode`, and hex
`key`/`ciphertext`, plus the mode's required nonce or IV and GCM tag. GCM must
authenticate before a transform is validated; CBC/CTR plaintext remains a
candidate. Verified GCM plaintext enters the artifact queue for further
scanning. Keys are excluded from ordinary run reports.

For bounded password hash checks, provide `hash_parameters` and a separate
`hash_wordlist_file` in the private hints JSON. For example:
`{"hash_parameters":[{"algorithm":"sha256","digest":"HEX_DIGEST","salt_hex":"00ff","salt_position":"prefix"}],"hash_wordlist_file":"/path/to/words.txt"}`.
Supported declared algorithms are MD5, SHA-1, SHA-256 and SHA-512; `salt_hex`
is optional and `salt_position` is `prefix` or `suffix` when supplied. A bare
hex digest has only length-compatible format leads, never a format claim.
The wordlist uses exact byte lines (LF separators), at most 4,096 entries of
128 bytes. Spaces and CR bytes remain part of a password. Recovered bytes are
hex in private findings; ordinary reports state only the verified index.

Recorded candump and ASC CAN text logs produce bounded, line-linked frame
records. Timing bases remain explicit; payload semantics require a supplied
DBC or protocol schema and are not inferred from the raw bytes.

Offline PCAP/PCAPNG inspection uses local TShark to report frame-linked DNS,
HTTP, endpoints, and TCP stream IDs. Capture gaps and output limits remain
visible. Selected HTTP object bodies and TCP direction payloads can be exported with frame references; incomplete or encrypted captures remain partial without matching evidence or keys.

SQLite inspection copies the supplied database and its WAL/SHM companions
privately before read-only schema and row queries. Missing companions and
changed snapshots are reported; source files are never opened for writing.

<a id="aichatbot-challenges"></a>
## AI/chatbot challenges

The [strategy guide](chatbot_strategies.md) lists selected live playbooks,
direct API plans, a context bloating check, and an offline model helper.

`chatbot` requires an explicitly authorized origin and finite limits. It reads the
page, same-origin scripts and source maps first. A single unambiguous HTML form
can supply the chat request shape. For a JavaScript app or a nested response,
provide a private JSON protocol file:

```json
{
  "chat": {
    "path": "/api/ask",
    "encoding": "json",
    "message_field": "query",
    "response_field": "data.reply",
    "conversation_field": "thread",
    "conversation_response_field": "thread_id"
  },
  "lanes": ["capability", "rag"],
  "history_path": "/api/history"
}
```

```sh
python3 scripts/autosolve.py chatbot --origin https://AUTHORIZED_ORIGIN --protocol ./private-chat.json --budget 60 --max-requests 12 --max-prompts 3 --dry-run
python3 scripts/autosolve.py chatbot --origin https://AUTHORIZED_ORIGIN --protocol ./private-chat.json --budget 60 --max-requests 12 --max-prompts 3
python3 scripts/autosolve.py resume .autosolve/runs/RUN_ID --budget 60 --max-requests 20
python3 scripts/autosolve.py report .autosolve/runs/RUN_ID
```

The protocol can also set `headers` for auth, `csrf_cookie`/`csrf_header` inside
`chat`, `client_id_field`, one explicit `bootstrap` login or tab-claim, and a
declared serial `heartbeat` before chat when the frontend requires it.
Put secrets in the private protocol file, not
command arguments. `verification` requires an explicit same-origin path,
`success_field`, and `success_value`; a POST checker also needs
`candidate_field`. A JSON/form `injection` requires an exposed writable `path`,
`field`, `payload`, `marker`, and `trigger_prompt`; multipart upload uses an
explicit regular file, file field, filename, and content type instead. The
client writes once, then tests the later chat response. A repeated marker is
only a candidate. The private run directory
contains raw responses and cookies. Stop reasons, transcript line numbers,
untested probes, and exact request counts appear in `report.md`. The `report`
command prints its private file path for chatbot runs. A timeout,
lock, rate limit, ambiguous reply, or unverified route leaves the run partial.

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

Run commands from the folder containing `index.html` and `scripts/`. The byte and file helpers in [scripts/ctf.py](ctf.py) need no network access or Python package installation. The chatbot command contacts only its explicit origin, and the callback receiver listens only when started. Keep this folder structure when copying the toolkit offline.

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

Limits and truncation are reported. No unbounded override is provided; use the approved manual route for larger inputs. The `ctf.py` byte and file helpers make no network calls, uploads, automatic dependency installations or recursive decoding attempts. Keep the preparation pages offline; external technical links still require internet.
