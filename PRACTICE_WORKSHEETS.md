# Offline practice and answer checks

These small exercises are authored for this refresher, not organiser challenges. The bundled files are synthetic and contain no captured user traffic or malware. Use a copy of the files. Commands assume the repository root as your working directory; installed tools on your travel laptop may differ from this research environment.

Each block has a no-setup paper route. That route tests interpretation and recall, **not practical proficiency with the application**. If a lab will not start, complete the paper route and record the missing setup; do not count it as tool execution. Answers are below each exercise so you can cover them while attempting it.

<a id="block-1"></a>
## 1. Identify before decoding

**Diagnostic:** Explain the difference between Base64, encryption, metadata and a file signature. If you can also explain why an apparent stego signature needs validation, skim the introductory reading.

**Exercise:** In a prepared local CyberChef copy, decode `Q1RGLXJlZnJlc2hlcg==`, then encode the result back to Base64. Open [http-demo.pcap](research/learning/practice/http-demo.pcap) as bytes in HxD or with `xxd -l 16 research/learning/practice/http-demo.pcap`. Record the first four bytes. Do not rename it based on a text fragment or assume that binwalk finding a signature proves an embedded file is valid. Read one zsteg extraction example and explain what channel/bit-order selection adds beyond a bulk scan.

**Paper route:** Decode the Base64 using the selected guide's alphabet/process, or explain the recipe and verify against the answer. Given leading bytes `d4 c3 b2 a1`, distinguish the container identification from an embedded HTTP payload. State what independent check you would perform on extracted bytes.

**Check:** The decoded text is `CTF-refresher`, with no newline; round-trip encoding reproduces the input. The capture begins `d4 c3 b2 a1` (classic little-endian PCAP). A valid embedded object should also parse as its claimed format or produce coherent content; a signature alone is a lead. This exercise does not prove that you can solve image steganography. Optional depth: create a tiny steghide carrier on your own machine and recover your own payload, checking byte equality.

<a id="block-2"></a>
## 2. Reconstruct a network conversation

**Diagnostic:** Explain capture filters versus display filters and what Follow TCP Stream reconstructs. Correct answers let you skim the introductory reading.

**Input:** [http-demo.pcap](research/learning/practice/http-demo.pcap), a 541-byte synthetic Ethernet/IPv4/TCP capture containing five packets. The addresses are documentation addresses, not live targets.

**Exercise:** Open the file in Wireshark; apply `http.request`. Record client/server addresses, method and URI. Follow the TCP stream and recover the response body. Then compare with:

```sh
tshark -r research/learning/practice/http-demo.pcap -Y http.request -T fields -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e tcp.stream
tshark -r research/learning/practice/http-demo.pcap -q -z follow,tcp,ascii,0
```

**Deliverable:** A five-field request row, the body, and an explanation of which direction supplied it. For depth, compare packet bytes with reassembled content; then read the Zeek quickstart's expected logs and explain how a UID joins records. Executing Zeek is optional and needs its prepared binary.

**Paper route:** Analyze this supplied transcript: client `192.0.2.10:40000` → server `192.0.2.20:80`; request `GET /clue.txt HTTP/1.1`; response `HTTP/1.1 200 OK`, body `CTF-refresher` followed by a newline. Identify the same fields and explain why a hostname in the Host header does not change the observed IP endpoints.

**Check:** One HTTP request; source `192.0.2.10`, destination `192.0.2.20`, method `GET`, URI `/clue.txt`, stream `0`. The server returns `CTF-refresher\n` (14 bytes). These TShark results were executed and checked locally; Wireshark GUI and Zeek execution were not tested.

<a id="block-3"></a>
## 3. Keep forensic coordinate systems separate

**Diagnostic:** Distinguish an image byte offset, partition sector offset, filesystem block number and inode/file metadata address. If any distinction is unclear, do the reading before trying recovery commands.

**Paper exercise:** A synthetic partition begins at sector 2048, sectors are 512 bytes, filesystem blocks are 4096 bytes, and a described data block has zero-based index 3 relative to the filesystem. Calculate its absolute byte offset. Separately, suppose `fls` reports a deleted file with metadata address 128; explain why 128 is not the block index and which input `icat` expects. Explain what the partition offset option must represent. Consult the selected official manuals rather than the superseded walkthrough.

**Artifact interpretation:** A hypothetical file record contains a name and timestamps. List two facts the record supports and two claims it cannot establish alone (for example, who deliberately deleted the file). Read the selected MFTECmd documentation's export example; identify the input artifact and output format. Do not treat a historical video as current evidence of `$LogFile` support.

**Optional execution:** Only if you already have a benign local disk image, use Autopsy to add it as a data source, locate a known file and export it to a new folder. Compare a hash of the export with your known original. Do not use a raw system disk as a training input. No disk image is bundled, so this is not a ready-to-run disk-recovery lab.

**Check:** `2048 × 512 + 3 × 4096 = 1,060,864` bytes. `icat` uses a metadata address to retrieve file content; partition-offset units must match its documented sector convention. Deleted status does not guarantee recoverable content. File records need corroboration for attribution. The arithmetic is checked; Autopsy, MFTECmd and TSK execution are unperformed.

**Practice caps (80 minutes total):** Allow up to 15 minutes for the original coordinate exercise, 15 for the command pass below, 25 for journal interpretation, 15 for a closed-note retry, and 10 to check answers and record corrections. These are planning caps, not measured completion times; finish early when the checks are met.

**Second case — supplied inputs:** Everything in these tables is synthetic, normalized teaching data, not captured output from TSK or MFTECmd. Assume a single NTFS volume in `disk.dd`, starting at sector 4096 with 512-byte sectors. No such image is bundled. Metadata addresses in the file table are the addresses to use for this paper exercise; journal identity is the separate `(entry, sequence)` pair on this volume.

| Metadata address | Entry | Sequence | Name | Listing status |
| --- | --- | --- | --- | --- |
| 42-128-1 | 42 | 7 | final.txt | Deleted |
| 43-128-1 | 43 | 2 | draft.txt | Allocated |

The journal rows below are deliberately out of order. Order by event number, which represents journal order in this teaching case. Do not join records by filename alone.

| Event | Entry | Sequence | Reason | Name |
| --- | --- | --- | --- | --- |
| 106 | 42 | 7 | Delete | final.txt |
| 103 | 42 | 7 | RenameOldName | draft.txt |
| 101 | 42 | 7 | Create | draft.txt |
| 108 | 42 | 8 | Create | unrelated.txt |
| 104 | 42 | 7 | RenameNewName | final.txt |
| 102 | 43 | 2 | Create | draft.txt |
| 105 | 43 | 2 | DataExtend | draft.txt |

**Command pass:** Without running anything, write commands to list the image partitions, recursively list the selected filesystem, and attempt recovery of deleted `final.txt` to a new file outside the evidence. Convert the partition start to bytes, then identify which number belongs in `-o`. State what you would check before trusting an export. For the earlier MFTECmd reading, name a valid source artifact and the requested tabular export format.

**Journal pass:** Start from the deleted listing row. Write its complete identity and ordered event numbers; give the name transition and last supplied event for that identity. Identify the two traps in filtering only on `draft.txt` or only on entry 42. State whether the rows prove who deleted the file, whether its bytes survive, and what evidence would address each question. Close the answers and repeat the grouping, command and limitations before checking.

**Second-case answer key:**

- Commands: `mmls disk.dd`; `fls -r -o 4096 disk.dd`; `icat -r -o 4096 disk.dd 42-128-1 > recovered-final.txt`. Assume the destination is a new file in a separate working folder; shell redirection can overwrite an existing file. The partition starts at `4096 × 512 = 2,097,152` bytes, but `-o` takes `4096` sectors here. Recovery may fail or return incomplete/overwritten bytes; inspect content/format and compare with a known original hash if available. No known hash is supplied in this case.
- Target `(42, 7)` has events `101 → 103 → 104 → 106`: create `draft.txt`, rename it to `final.txt`, then delete `final.txt`. The two rename rows describe one rename, not two. Events `102, 105` belong to `(43, 2)`; event `108` belongs to `(42, 8)`, a different identity after entry reuse. The filename filter mixes distinct files and misses the target's renamed/deleted rows; entry-only grouping wrongly includes event 108.
- The supplied rows record a deletion event, not an actor or intention. Correlated audit/logon evidence would be needed for attribution; surviving file content and a checked extraction would address recovery. Neither conclusion follows from a name or deletion row alone. For MFTECmd, `$MFT` or `$UsnJrnl:$J` is a valid source artifact for the selected workflow, and CSV is the tabular export to inspect in Timeline Explorer; these normalized rows are not a claimed MFTECmd export.

Award one check each for the three command shapes, offset units, full-key grouping, rename/delete order, separation of the other two identities, attribution limits, recovery limits, and MFTECmd input/output (10 checks). Rework any missing check with the answer covered. This remains a paper exercise; no forensic tool execution is claimed.

<a id="block-4"></a>
## 4. Read memory evidence without overclaiming

**Diagnostic:** Explain the difference between a process list and a parent/child tree, and why Volatility 2 profiles cannot simply be substituted into Volatility 3 instructions.

**Paper input:** Synthetic process rows: `PID 100 / PPID 4 / services.exe`; `PID 220 / PPID 100 / helper.exe`; `PID 330 / PPID 220 / cmd.exe`. There are no timestamps, command lines or signatures in this dataset.

**Exercise:** Draw the parent chain for PID 330. Write the next two questions you would ask and name the evidence needed (for example command line, executable path, file signature or surrounding timeline). Explain why the chain alone neither proves compromise nor establishes that the name matches a legitimate executable. Read the official Volatility 3 `pslist`/`pstree` examples and compare their output structure with your drawing.

**Setup failure drill:** A plugin reports unsatisfied symbol requirements before producing output. Is that a negative forensic finding? Describe the online preflight step needed for a Windows image and why a fully cached page is not enough.

**Optional execution:** With an independently obtained benign memory image, resolve symbols while online, then run the tutorial's `windows.pslist` and `windows.pstree` operations offline. Compare the same PID/PPID pair in both outputs. No memory image or symbol set is bundled; this route has not been executed.

**Check:** `4 → 100 → 220 → 330` is the chain represented by the rows, though PID 4 has no supplied row. Names and ancestry are leads, not malware verdicts. A symbol error is a failed analysis, not evidence of absence. A local image, working Volatility and matching cached symbols are separate prerequisites.

**Practice caps (50 minutes total):** Allow up to 10 minutes for the original chain and setup drill, 15 for the contrasting views below, 10 for hypotheses and command selection, 10 for a closed-note retry, and 5 for answer checks. These are planning caps, not measured durations; do not pad a completed attempt.

**Second case — contrasting views:** Both tables are synthetic, normalized teaching data for one snapshot, not actual Volatility output. View A is a flat `pslist`-style listing. View B is a `pstree`-style rendering of the same supplied PID/PPID relationships; it is not independent corroboration. Neither view supplies process start times, command lines, paths or signatures.

| View A: PID | PPID | Name |
| --- | --- | --- |
| 500 | 4 | services.exe |
| 620 | 500 | helper.exe |
| 710 | 620 | cmd.exe |
| 850 | 799 | helper.exe |
| 910 | 850 | cmd.exe |

| View B: represented chain | Gap in supplied rows |
| --- | --- |
| 500 services.exe → 620 helper.exe → 710 cmd.exe | PID 4 has no row |
| 850 helper.exe → 910 cmd.exe | PID 799 has no row |

**Independent pass:** Reconstruct PID 910's reported ancestry from View A before checking View B. List every missing parent row. Decide whether either `helper.exe` name lets you merge the branches or assign PID 910 to PID 500. Write two hypotheses for missing PID 799 and a distinguishing evidence request for each. State what remains unknown even when both views agree.

**Command-selection pass:** Assume the official tutorial's source checkout with `vol.py` and a prepared benign image called `memory.raw`. Write the help/discovery command, flat-list command and tree command in that order. Choose which process view makes ancestry easiest to inspect and which evidence you need to investigate a misleading executable name. Explain how a symbol failure changes the interpretation. Do not execute these placeholders; no image is supplied.

**Second-case answer key:**

- The reported chain is `799 → 850 → 910`, with no supplied row for 799; PID 4 is also missing. The separate represented branch is `4 → 500 → 620 → 710`. There are five supplied processes and two missing parent identifiers. Identical names do not identify the same process; there is no supplied edge from 500 or 620 to 850 or 910.
- One hypothesis is that parent 799 exited before capture: seek process creation/termination records and start/exit times to test the chronology. Another is incomplete collection or enumeration: check capture/parser diagnostics and compare with additional process evidence, such as a pool-scan result. Neither hypothesis is established here, and a discrepancy alone would not prove a hidden malicious process. PID reuse also requires time-aware identity checks before treating a matching PID in another source as the historical parent.
- Commands: `python3 vol.py -h`; `python3 vol.py -f memory.raw windows.pslist`; `python3 vol.py -f memory.raw windows.pstree`. These follow the selected tutorial's CLI form; confirm the prepared installation's help before a real run. `pstree` makes relationships easier to see; it does not independently validate them. Investigating a name requires executable path/content and signature or hash checks, with command-line and timeline context. Agreement between these views establishes no actor, intent or malware verdict. A symbol failure means analysis did not complete, not that the snapshot contains no processes.

Award one check each for the 910 chain, both missing parents, keeping same-named processes separate, rejecting unsupported ancestry to 500, each of the two hypotheses paired with evidence, the three-command sequence, choosing the tree view, requesting evidence beyond names, and interpreting a symbol failure (10 checks). Cover the key for the retry and correct each missed check. This checks paper interpretation and command recall only; no Volatility execution is claimed.

<a id="block-5"></a>
## 5. Recover and verify a program's branch logic

**Diagnostic:** Explain `strcmp`'s zero result and distinguish a function's return value from a conditional jump's sense. If fluent, skip one or both introductory videos and start with the executable.

**Input:** [check_input.c](research/learning/practice/check_input.c), a small benign program. To avoid spoiling the answer, compile it before studying its source. On a prepared Linux/WSL toolchain:

```sh
gcc -O0 -g research/learning/practice/check_input.c -o /tmp/ctf-refresher-check
/tmp/ctf-refresher-check wrong
gdb /tmp/ctf-refresher-check
```

In GDB use `break main`, `run wrong`, `disassemble main`, and `next` to relate the condition to the branch. `print argc` checks the argument count. Import the same executable into Ghidra, locate `main`, inspect the comparison, rename the input and write pseudocode. Do not patch the program before explaining it. Finally compare with the source.

**Deliverable:** A three-case table: no user argument, wrong word, accepted word; include printed text and exit status. Explain which comparison decides success. Addresses and generated assembly vary by compiler and architecture; do not copy an address from the video.

**Paper route:** Keep the bundled [check_input.c](research/learning/practice/check_input.c), and save the separate LiveOverflow [gdb_disassembly](https://raw.githubusercontent.com/LiveOverflow/liveoverflow_youtube/master/0x05_simple_crackme_intro_assembler/gdb_disassembly) and [license_1.c](https://raw.githubusercontent.com/LiveOverflow/liveoverflow_youtube/master/0x05_simple_crackme_intro_assembler/license_1.c) individually before boarding; saving only the repository directory page is insufficient. Draw the three branches from the C source, then trace one comparison/jump in the published disassembly. These are separate examples; do not assume identical addresses or passwords.

**Check:** No argument → `usage: check_input WORD`, status 2. `wrong` → `rejected`, status 1. `harbor` → `accepted`, status 0. The comparison is `strcmp(argv[1], "harbor") == 0`. All three compiled cases and basic GDB execution were locally tested; Ghidra GUI was not. Delete `/tmp/ctf-refresher-check` after practice if desired.

<a id="block-6"></a>
## 6. Turn static indicators into testable statements

**Diagnostic:** Explain how FLOSS differs from ordinary strings, and why a capa match is a lead rather than a complete behavioral trace. If fluent, spend the reading time on the YARA conditions section.

**Exercise:** Write a YARA rule requiring both `training-marker` and the full word `harbor`. Test against [match.txt](research/learning/practice/match.txt) and [near-miss.txt](research/learning/practice/near-miss.txt). Only then compare with [training.yar](research/learning/practice/training.yar).

```sh
yara research/learning/practice/training.yar research/learning/practice/match.txt
yara research/learning/practice/training.yar research/learning/practice/near-miss.txt
```

**Check:** The first should print the rule name and file; the second should produce no match. Adding `harbor` without the marker should still fail. Paper route: evaluate those three cases by hand from the rule's condition. Read one capa verbose-output example and state the location you would inspect next; read one FLOSS decoded-string example and explain what an extracted URL does **not** prove about execution.

**Full-word contrast (paper input):** Evaluate the exact text `training-marker harbors`. Expected: **no match**. The marker is present, but `harbor` is followed by the letter `s`, so it is not a full word. Compare `training-marker harbor`, which should match. This pair distinguishes a `fullword` check from a substring-only rule; the missing-marker case alone cannot do that. These are supplied text cases, not YARA CLI results; no YARA CLI run is claimed.

**Format-routing check:** Choose dnSpyEx for a .NET assembly, JADX for APK/DEX Java-like output, and pyinstxtractor-ng for extracting a PyInstaller package before considering bytecode decompilation. Decompilation is not guaranteed to recover original source.

**Execution status:** YARA CLI was not available on the research PATH and was not installed. The text fixtures and rule logic were reviewed; actual YARA matching and capa/FLOSS execution remain untested. This exercise uses no malware.

<a id="block-7"></a>
## 7. Change one HTTP request and explain the response

**Diagnostic:** Write a minimal HTTP GET request with a Host header. Explain why changing a header is not the same as changing the URL path. If fluent, skip the introductory Repeater video.

**Local target:** In a spare terminal from the repository root:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory research/learning/practice/http
```

Then in another terminal:

```sh
curl -i http://127.0.0.1:8765/clue.txt
curl -i http://127.0.0.1:8765/missing.txt
```

**Exercise:** Record each status and body. With a prepared Burp Community installation, open its browser, visit the first URL, send its request from HTTP history to Repeater, change only the path to `/missing.txt`, and compare the responses. Keep this exercise scoped to `127.0.0.1:8765`. Stop the server with Ctrl-C afterward.

**Check:** `/clue.txt` returns 200 and `CTF-refresher\n`; `/missing.txt` returns 404. One controlled path change is sufficient to explain the difference. The Python server/curl pair was locally tested. Burp capture/replay was not; if your browser bypasses the proxy for loopback, use Burp's configured browser or the paper route rather than debugging during the flight. No Pro feature is required.

**Paper route:** Rewrite `GET /clue.txt HTTP/1.1` with `Host: 127.0.0.1:8765` into the missing-path request. Predict the two responses above and explain which fields you held constant. For ffuf, explain where `FUZZ` belongs in a path and why a wildcard 200 response can require filtering by content/size rather than status alone. Reading Academy instructions is free; executing its hosted labs still requires registration/connectivity.

<a id="block-8"></a>
## 8. Check an attack's assumptions before running it

**Diagnostic:** Distinguish encoding, hashing and encryption. Explain the RSA roles of `n`, `e`, `d` and why a ZIP header does not automatically imply an AES attack is possible.

**RSA exercise:** Use toy inputs `p=61`, `q=53`, `e=17`, plaintext integer `m=42`. Calculate `n`, Euler's totient, the modular inverse `d`, then encrypt and decrypt. Ordinary Python 3 suffices for these toy values:

```python
p, q, e, m = 61, 53, 17, 42
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
c = pow(m, e, n)
print(n, phi, d, c, pow(c, d, n))
```

**Check:** `3233 3120 2753 2557 42`. Confirm `17 × 2753 mod 3120 = 1`. This is a deliberately weak toy key with known primes, not a general factoring method. Read the RsaCtfTool attack prerequisites and name one reason a selected attack might not apply. Sage is useful for broader number theory but is not required for this exercise.

**Password exercise:** Given MD5 `d077f244def8a70e5ea758bd8352fcd8` and candidates `dog`, `cat`, `bird`, compare each candidate's hash using Python's `hashlib.md5(candidate.encode()).hexdigest()`. Explain why the 32 hex characters alone do not prove the algorithm. Then read either hashcat's dictionary guide **or** John's wordlist example, and map the candidate process to that tool; do not run both introductions unless comparing syntax is useful.

**Check:** `cat` matches. MD5 is explicitly supplied for this exercise. The Python arithmetic and hashes were tested; hashcat/John backend execution was not.

**Optional archive branch:** Use the selected version-pinned bkcrack tutorial and its public `secrets.zip` only after downloading the exact example while online. Explain the ZipCrypto/known-plaintext conditions and verify the recovered plaintext against the tutorial. Neither that archive nor bkcrack is bundled or executed. The paper alternative is to state why AES ZIP or insufficient plaintext invalidates this attack route.

<a id="block-9"></a>
## 9. Close one specific gap

Choose **one**, not all three. Use the remaining tools' reference index for a different specialty only if you can name an input and a checkable outcome.

- **Audio:** Read Audacity Spectrogram View, especially window-size tradeoffs. Given two nearby tones that blur together, choose a larger analysis window; explain the loss in time resolution. Given very brief clicks, explain why the opposite choice may help. Optional execution requires a local audio sample; none is bundled.
- **Managed code:** Read the dnSpyEx/JADX/PyInstaller routing references. Given `.NET assembly`, `APK/DEX`, and `PyInstaller executable`, select the respective entry tool and explain why extraction and decompilation are separate operations. Check against block 6's answer.
- **Structured artifacts:** Read SQLite CLI `.tables` and `.schema`. Given table `visits(url TEXT, ts INTEGER)` and rows `('a',10), ('b',20)`, write `SELECT url, ts FROM visits ORDER BY ts DESC;`. Expected order is `b` then `a`; the schema alone does not tell you the timestamp epoch. Optional execution uses a new toy database, never original evidence.

**Diagnostic:** Before reading, explain your chosen task in two sentences. **Deliverable:** A tiny procedure, its expected output and one failure mode. If you cannot assess the result from the supplied answers or official example, record the unresolved question rather than marking mastery.

<a id="block-10"></a>
## 10. Closed-note transfer check

**Diagnostic:** Without looking, list three inputs you can now route to a tool and state the first non-destructive action. Use any hesitation to choose the two exercises to repeat.

Repeat one interpretation exercise (blocks 3, 4 or 9) and one executable exercise (blocks 1, 2, 5, 7 or 8) without reading the procedure. If no tools are prepared, repeat its paper route and mark the result **paper only**. Timebox each attempt to 20 minutes. Compare with the supplied answer, then write the smallest correction to your notes.

**Assessment rubric:** For each attempt, award one check each for selecting an appropriate approved tool, preserving the original input, giving the right command/action or accurate paper explanation, and interpreting the result without an unsupported claim. Any missing check means that workflow needs another pass; this is a study heuristic, not a validated proficiency score. Do not count reading an answer as a successful independent attempt.

**Final note:** Record two things you can now do, two unresolved questions, and any untested setup needed before competition. Actual learning gains depend on your attempts and feedback; this pack has not measured them.
