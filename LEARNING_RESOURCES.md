# Approved tools: a practical 24-hour refresher

Ten practice blocks for returning CTF participants. Start with each diagnostic; spend time saved on familiar topics repeating exercises without instructions.

Some Windows-list tools run in WSL; Kali availability is best effort. Tutorials may mention unapproved applications, paid features or uploads: follow the [event rules](EVENT_SOURCES.md). [All 200 approved tools](APPROVED_TOOL_REFERENCES.md).

[Study blocks](#study-blocks) · [Worksheets](PRACTICE_WORKSHEETS.md) · [Offline preparation](#offline-prep)

<details>
<summary>Plan your study time</summary>

1. Follow the 10 blocks below. Their allocations total **1,440 minutes (24 hours)**, including practice and assessment; do not add resource estimates to that total. Break time is outside this study budget.
2. Choose **reading or its video alternative**, not both by default. Every video has a free reading/practice replacement. No subscription, trial, account creation or organiser portal launch is needed for the core path.
3. Open the [practice worksheets](PRACTICE_WORKSHEETS.md). They contain exact inputs, commands or paper tasks, and answer checks. Small local fixtures are bundled; forensic disk/memory images and public archives are not.
4. A paper route keeps a block usable when a lab is unavailable. Mark it **paper only**: interpretation practice does not prove that you can operate the application.

</details>

<a id="study-blocks"></a>

## The 24-hour sequence

Diagnostic/study/exercise/check are minute budgets, not video runtimes.

| Block | Total | Diagnostic / study / exercise / check | Outcome |
| --- | --- | --- | --- |
| [1. Identify and decode files](#block-1) | 120 min | 10 / 40 / 50 / 20 | Choose a first inspection operation and validate decoded output. |
| [2. Reconstruct network evidence](#block-2) | 180 min | 10 / 50 / 90 / 30 | Follow a complete conversation and reproduce selected fields. |
| [3. Interpret filesystem and Windows artifacts](#block-3) | 180 min | 10 / 60 / 80 / 30 | Keep recovery coordinates straight and avoid unsupported attribution. |
| [4. Reason from memory artifacts](#block-4) | 120 min | 10 / 40 / 50 / 20 | Read pslist/pstree and distinguish missing prerequisites from negative findings. |
| [5. Recover a native input check](#block-5) | 240 min | 15 / 75 / 120 / 30 | Relate source, disassembly and decompiler output, then verify a hypothesis. |
| [6. Test static-analysis claims](#block-6) | 120 min | 10 / 40 / 50 / 20 | Write a specific rule and treat extraction/capability labels as evidence leads. |
| [7. Replay controlled HTTP changes](#block-7) | 180 min | 10 / 50 / 90 / 30 | Change one request field, compare responses and avoid false discovery conclusions. |
| [8. Check crypto and password assumptions](#block-8) | 180 min | 10 / 60 / 80 / 30 | Derive a toy RSA result and map candidate testing to the right tool. |
| [9. Close one specialist gap](#block-9) | 60 min | 5 / 15 / 30 / 10 | Apply one narrowly scoped unfamiliar workflow. |
| [10. Transfer without instructions](#block-10) | 60 min | 5 / 0 / 40 / 15 | Repeat two workflows independently and record remaining gaps.  |

<a id="block-1"></a>

### 1. Identify and decode files — 120 minutes

**Prerequisites:** Basic byte/text and shell familiarity. **Diagnostic:** Explain encoding versus encryption and why a signature is only a lead.

**Selection:** Read CyberChef recipe order, three ExifTool reading examples, Binwalk scan/extract and zsteg channel-selection examples. The CyberChef video is an alternative, not extra work.

[CyberChef: how recipes work and worked examples](#crypto-foundations-1) · [ExifTool: application documentation and reading examples](#media-3) · [Binwalk: file analysis and extraction](#media-2) · [zsteg: detection and extraction examples](#media-1)

**Prepare:** Local CyberChef and HxD/xxd only for execution; all paper inputs and the tiny PCAP are bundled.

**Do and check:** [Worksheet 1](PRACTICE_WORKSHEETS.md#block-1). Round-trip Base64, identify the capture header, and state an independent validation check. Optional: [bytes and PDF stream practice](research/learning/video-coverage/practice/TRIAGE_PRACTICE.md).

<a id="block-2"></a>

### 2. Reconstruct network evidence — 180 minutes

**Prerequisites:** Block 1; basic IP/port and request/response concepts. **Diagnostic:** Explain display versus capture filters and stream reassembly.

**Selection:** Read official display filters/Follow Stream and TShark -r/-Y/-T fields. Use the same tiny capture for GUI/CLI; Zeek quickstart is optional depth within the block.

[Wireshark: display filters and following protocol streams](#web-network-5) · [TShark manual: saved captures and display filters](#web-network-6) · [Zeek quick start: turn a PCAP into correlated logs](#web-network-7)

**Prepare:** Bundled http-demo.pcap; Wireshark/TShark for execution. Zeek needs a separately working install.

**Do and check:** [Worksheet 2](PRACTICE_WORKSHEETS.md#block-2). Match the supplied endpoint/URI/body answer key; explain client versus server direction.

<a id="block-3"></a>

### 3. Interpret filesystem and Windows artifacts — 180 minutes

**Prerequisites:** Blocks 1–2; sectors/bytes and file metadata are distinct concepts. **Diagnostic:** Distinguish sector offset, block index and metadata address.

**Selection:** Read TSK fls/mmls/icat arguments, Autopsy case→source→ingest→export, and MFTECmd author documentation or selected video chapters. Use SQLite schema sections if time remains.

[Sleuth Kit: list files and recover by metadata address](#forensics-1) · [Autopsy Quick Start Guide](#forensics-2) · [Introduction to MFTECmd - NTFS MFT and Journal Forensics](#forensics-5) · [SQLite command-line shell: inspect schema and records](#forensics-8)

**Prepare:** Both paper cases are bundled: coordinates, file listing and normalized journal rows. Optional Autopsy execution needs a prepared benign image or logical-file folder.

**Do and check:** [Worksheet 3](PRACTICE_WORKSHEETS.md#block-3). Compute both offsets; write the recovery commands; group journal rows by full identity and explain rename/deletion and attribution limits.

<a id="block-4"></a>

### 4. Reason from memory artifacts — 120 minutes

**Prerequisites:** Block 3; process IDs and parent relationships. **Diagnostic:** Explain Volatility 2 profiles versus Volatility 3 symbols.

**Selection:** Read official process tutorial; video is optional instead of repeated introduction. Compare plugin output structure with the supplied process table.

[Volatility 3: Windows Tutorial](#forensics-3) · [Introduction to Memory Forensics with Volatility 3](#forensics-4)

**Prepare:** Both synthetic process cases are bundled. Tool execution separately requires an image, working Volatility and pre-cached matching symbols.

**Do and check:** [Worksheet 4](PRACTICE_WORKSHEETS.md#block-4). Reconstruct both process cases, identify missing parents, distinguish same-named processes, pair hypotheses with evidence and write the tutorial command sequence.

<a id="block-5"></a>

### 5. Recover a native input check — 240 minutes

**Prerequisites:** Basic C branches, arguments and strings; skim source syntax first if rusty. **Diagnostic:** Explain strcmp returning zero and how a branch uses the result.

**Selection:** Use Ghidra import/decompiler/references/function graph and the benign companion. Choose at most one video for orientation; spend the rest on the included C program.

[Introduction to Ghidra — student guide](#reverse-1) · [bin 0x05 companion: license-check source and GDB disassembly](#reverse-4) · [Ghidra quickstart & tutorial: Solving a simple crackme](#reverse-2) · [Reversing and Cracking first simple Program — bin 0x05](#reverse-3)

**Prepare:** Bundled C source; GCC/GDB for executed route, Ghidra optional. Save the published companion source/disassembly for the paper transfer exercise.

**Do and check:** [Worksheet 5](PRACTICE_WORKSHEETS.md#block-5). Predict all three output/status cases; compare your recovered condition with source.

<a id="block-6"></a>

### 6. Test static-analysis claims — 120 minutes

**Prerequisites:** Block 5; strings, conditions and basic file formats. **Diagnostic:** Distinguish decoded strings from executed behavior.

**Selection:** Read capa default/verbose output, FLOSS string types and YARA strings/conditions/fullword. Format-routing references are short optional lookups.

[capa 9.4.0 usage: interpret capability matches](#reverse-5) · [FLOSS usage: static, stack, tight and decoded strings](#reverse-6) · [Writing YARA rules](#reverse-7)

**Prepare:** Bundled harmless text files and rule; YARA only for execution. No malware samples needed.

**Do and check:** [Worksheet 6](PRACTICE_WORKSHEETS.md#block-6). Distinguish full-word and substring matches, check the missing-marker case, and name a justified next check for a capa/FLOSS finding.

<a id="block-7"></a>

### 7. Replay controlled HTTP changes — 180 minutes

**Prerequisites:** Block 2; HTTP method/path/header/body. **Diagnostic:** Write a GET and explain path versus header changes.

**Selection:** Read Repeater steps, curl headers/cookies/POST and ffuf FUZZ/filter examples. Video substitutes for the first orientation; no hosted lab required.

[Burp: reissue requests and investigate unexpected input](#web-network-1) · [Everything curl: Command line HTTP](#web-network-3) · [ffuf upstream examples: discovery, filters and bounded runs](#web-network-4) · [How to resend individual requests with Burp Repeater](#web-network-2)

**Prepare:** Bundled static target served by Python on loopback; curl/Burp Community for execution. Paper requests need no server or account.

**Do and check:** [Worksheet 7](PRACTICE_WORKSHEETS.md#block-7). Show 200 versus 404 after one path change; explain wildcard-response filtering.

<a id="block-8"></a>

### 8. Check crypto and password assumptions — 180 minutes

**Prerequisites:** Integer arithmetic and encoding/hash/encryption distinction. **Diagnostic:** Explain n/e/d, hash candidates and ZipCrypto versus AES.

**Selection:** Read RSA prerequisites and initial Sage arithmetic; do hashcat dictionary OR John wordlist introduction. Use bkcrack metadata/conditions as a separate optional branch.

[RsaCtfTool: usage and attack prerequisites](#crypto-foundations-4) · [SageMath tutorial: number theory](#crypto-foundations-5) · [hashcat: dictionary attacks with a tiny wordlist](#crypto-foundations-6) · [John the Ripper: usage examples](#crypto-foundations-7) · [bkcrack 1.8.1: stored-plaintext ZIP recovery](#crypto-foundations-8) · [CTFlearn: RSA Beginner](#crypto-foundations-3)

**Prepare:** Included Python 3 toy inputs need no Sage or network. Optional bkcrack execution needs its exact public archive and installed binary.

**Do and check:** [Worksheet 8](PRACTICE_WORKSHEETS.md#block-8). Recover 42, identify cat, and state when RSA/ZIP attacks do not apply.

<a id="block-9"></a>

### 9. Close one specialist gap — 60 minutes

**Prerequisites:** Choose based on a failed diagnostic, not novelty. **Diagnostic:** Explain the chosen task in two sentences before reading.

**Selection:** Choose exactly one worksheet branch: audio-window tradeoff, managed-format routing, or SQLite schema/query. Other niche families remain indexed references.

[Audacity: Spectrogram View](#media-5) · [dnSpyEx: managed assembly navigation and debugging capabilities](#reverse-8) · [JADX: APK/DEX reading and decompiler limits](#reverse-9) · [pyinstxtractor-ng: inspect and extract a PyInstaller executable](#reverse-10) · [SQLite command-line shell: inspect schema and records](#forensics-8)

**Prepare:** All three paper branches have inputs and answers; actual audio/decompiler use requires a separately prepared file/tool.

**Do and check:** [Worksheet 9](PRACTICE_WORKSHEETS.md#block-9). Check the specified tradeoff, format routing, or query order; record one failure mode. For an executable audio exercise, try [resolving nearby tones](research/learning/video-coverage/practice/AUDIO_PRACTICE.md).

<a id="block-10"></a>

### 10. Transfer without instructions — 60 minutes

**Prerequisites:** Completed or diagnosed earlier blocks. **Diagnostic:** Name three inputs, approved tools and first non-destructive actions.

**Selection:** No new resource; close the notes and repeat one interpretation task and one executable task.

**Prepare:** Use included exercises; mark paper-only attempts honestly.

**Do and check:** [Worksheet 10](PRACTICE_WORKSHEETS.md#block-10). Assess tool choice, input preservation, correct operation and justified interpretation; record corrections.

<a id="offline-prep"></a>

## Prepare for the flight

- Save the specific lesson sections and figures as PDF or complete pages; saving an index does not save its children. Verify those saved files on the device with networking disabled. This pack contains links and worksheets, **not cached copies of every lesson**.
- Public video viewing is distinct from free offline viewing. YouTube’s documented computer-download route requires a signed-in Premium account and availability varies. Do not buy it for this plan: use each video’s free reading alternative. [Official offline-viewing terms](https://support.google.com/youtube/answer/11977233?hl=en).
- The [bundled practice files](research/learning/practice/README.md) are tiny, synthetic inputs. Reading them needs no additional account. Executing needs the listed local tools; prepare dependencies before departure.
- For optional disk/memory work, bring a suitable benign image and required symbols. For optional public ZIP or PCAP transfer exercises, save the exact named artifact first. Do not download entire collections for this pack.
- Burp Community manual Proxy/Repeater is sufficient; scanner, Collaborator and full Intruder are not part of this plan. PortSwigger articles are free to read; its hosted labs require a free account and connectivity. The included loopback target avoids that requirement.
- Preserve original evidence and avoid sending event challenge material to public services. The AI/online-service rules in the organiser guide still apply.

## Focused resource menu

Choose the resources for your block. “Study cap” includes practice pauses and differs from video runtime. Reading is free; save pages and figures before going offline.

### File triage and media

<a id="media-1"></a>

**[zsteg: detection and extraction examples](https://github.com/zed-0xff/zsteg)** — zed-0xff · read · core · study cap ~20 min.

**Focus:** Usage: -a, -E and PARAMS SHORTCUT; Simple LSB and Multi-result file examples. Skip wbStego internals unless encountered.

**Prerequisites:** Basic shell, redirects and binary-versus-text distinction; PNG/BMP carrier awareness.

<a id="media-2"></a>

**[Binwalk: file analysis and extraction](https://github.com/ReFirmLabs/binwalk/wiki/File-Analysis-and-Extraction)** — ReFirmLabs · read · core · study cap ~15 min.

**Focus:** Scan versus -e extraction versus -Me recursive extraction; read green/yellow/red confidence definitions. Keep --carve note as version lookup.

**Prerequisites:** Basic shell; understand that a signature is evidence rather than proof of a valid embedded file.

**Offline:** Extraction also depends on locally installed helper programs.

<a id="media-3"></a>

**[ExifTool: application documentation and reading examples](https://exiftool.org/exiftool_pod.html#READING-EXAMPLES)** — Phil Harvey / ExifTool · read · core · study cap ~15 min.

**Focus:** Only -a -u -g1, -s with named tags, and -b -ThumbnailImage. Read caveat that ordinary extraction omits some embedded/expensive metadata. Do not read format tables or writing reference end-to-end.

**Prerequisites:** Shell redirection and basic metadata concepts; perform any later extraction in a scratch directory.

<a id="media-4"></a>

**[Stegseek: wordlist mode, seed mode and steghide compatibility](https://github.com/RickdeJager/stegseek)** — Rick de Jager · read · core · study cap ~20 min.

**Focus:** Using Stegseek, Detection and passwordless extraction, and Steghide compatibility; skip benchmark tables and install variants.

**Prerequisites:** Existing steghide/stegseek, a sufficiently large local JPEG/BMP/WAV carrier and a small plain-text wordlist for execution. Reading does not need these.

**Offline:** Save any intended wordlist beforehand; prepare the local Stegseek binary.

<a id="media-5"></a>

**[Audacity: Spectrogram View](https://manual.audacityteam.org/man/spectrogram_view.html)** — Audacity · read · core · study cap ~20 min.

**Focus:** Selecting view, frequency limits, gain/range and Time Smearing/Frequency Smearing. Skip spectral editing and window-function catalog.

**Prerequisites:** Know waveform versus frequency plot; working Audacity needed only for GUI practice.

<a id="media-6"></a>

**[FFmpeg: stream selection and streamcopy](https://ffmpeg.org/ffmpeg.html)** — FFmpeg project · read · next · study cap ~20 min.

**Focus:** Section 3.1 Streamcopy plus section 4.1 automatic/manual selection. Retain option-order and per-output scoping rules; skip loopback and complex filtergraphs.

**Prerequisites:** Basic shell and the difference between a container and audio/video streams.

**Offline:** Check available codecs and installed help before departure.

<a id="media-7"></a>

**[AperiSolve: local deployment and analyzer overview](https://github.com/Zeecka/AperiSolve)** — Zeecka · read · reference · study cap ~5 min.

**Focus:** Key features and localhost deployment prerequisite only. No Docker setup exercise.

**Prerequisites:** No prerequisite for reading. Execution requires a fully prepared local service stack, not just the approved repository checkout.

**Offline:** Save README. Offline use requires an already working local deployment and dependencies; a git checkout alone is insufficient. Never upload event challenge files to the public service.

<a id="media-8"></a>

**[MORSE CODE Steganography (2/2) BsidesCT CTF 2018](https://www.youtube.com/watch?v=pJYyyz6HPbQ)** — John Hammond · watch · next · study cap ~15 min.

**Focus:** Opening audio/metadata investigation; skip decoding-site interaction and sponsorship. Alternative: Sonic Visualiser reference sections 1.1–1.4, 6.1, 6.3 and 8.

**Prerequisites:** Understand waveform versus spectrogram; encoding basics for the latter half. No portal or event files needed.

**Video runtime:** 09:29

**Free offline route:** [Read/practice instead](https://www.sonicvisualiser.org/doc/reference/5.2.1/en/); save before going offline.

**Caution:** This 2018 walkthrough uses historical interfaces and online upload steps. Use local tools for event files.

### Web and network evidence

<a id="web-network-1"></a>

**[Burp: reissue requests and investigate unexpected input](https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests)** — PortSwigger · read · core · study cap ~30 min.

**Focus:** Proxy history → Repeater; baseline valid input, another valid ID, invalid input; explain response changes. Skip the mixed-edition scanner continuation.

**Prerequisites:** HTTP request/response basics; for execution, Burp Community, prepared browser proxy and reachable Academy lab.

Hosted Academy exercise requires a free account. **Offline:** Save this page and linked Proxy/scope steps before flying. Academy execution requires an account and reachable lab server; saved HTML does not preserve the lab.

<a id="web-network-2"></a>

**[How to resend individual requests with Burp Repeater](https://www.youtube.com/watch?v=_Wifm2g9ugg)** — PortSwigger · watch · core · study cap ~10 min.

**Focus:** Watch only if moving a request between Proxy and Repeater is unfamiliar; recall redirect/history behavior.

**Prerequisites:** Basic HTTP; reading resource 1 is sufficient without playback.

**Video runtime:** 06:30

**Free offline route:** [Read/practice instead](https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests); save before going offline.

<a id="web-network-3"></a>

**[Everything curl: Command line HTTP](https://everything.curl.dev/http/)** — Daniel Stenberg and curl contributors · read · core · study cap ~30 min.

**Focus:** Customize headers; writing cookies; Simple POST; response codes. Explain why a successful transfer can still return HTTP 404.

**Prerequisites:** Know method, URL, headers and body; execution requires curl and a prepared target.

**Offline:** Save [Customize headers](https://everything.curl.dev/http/modify/headers.html), [Writing cookies](https://everything.curl.dev/http/cookies/writing.html), [Simple POST](https://everything.curl.dev/http/post/simple.html) and [Responses](https://everything.curl.dev/http/response.html) before departure. Reading works offline; HTTP execution needs a previously prepared local service.

<a id="web-network-4"></a>

**[ffuf upstream examples: discovery, filters and bounded runs](https://github.com/ffuf/ffuf)** — ffuf maintainers · read · next · study cap ~35 min.

**Focus:** One wordlist, one FUZZ position, baseline response, -fs/-fc filtering, -maxtime. Validate an interesting result manually with Burp/curl.

**Prerequisites:** Complete manual-request work first; local wordlist and reachable target for execution.

**Offline:** Save README and a small selected wordlist. Optional home practice: https://github.com/adamtlangley/ffufme offers a local Docker target; build and verify before travel. The hosted ffuf.me requires internet; prepare the local lab separately.

<a id="web-network-5"></a>

**[Wireshark: display filters and following protocol streams](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)** — Wireshark Foundation · read · core · study cap ~25 min.

**Focus:** Protocol/field presence, ip.addr equality, and/or; Analyze → Follow → TCP Stream, direction selection, and the filter left by closing the dialog. Avoid advanced/new filter syntax.

**Prerequisites:** Basic TCP/client-server concepts; saved capture and Wireshark for hands-on work.

**Offline:** Save display-filter guide and https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html with figures. Free text; no account. Saved-PCAP practice requires an installed Wireshark and downloaded sample.

<a id="web-network-6"></a>

**[TShark manual: saved captures and display filters](https://www.wireshark.org/docs/man-pages/tshark.html)** — Wireshark Foundation · read · next · study cap ~15 min.

**Focus:** -r input, -Y display filter, -T fields and repeated -e, -E header=y; distinguish -f capture filters.

**Prerequisites:** Complete Wireshark filtering exercise; TShark installed and same saved PCAP.

**Offline:** Save manual and sample PCAP; run locally after checking TShark is installed. No live network needed for saved-capture analysis.

<a id="web-network-7"></a>

**[Zeek quick start: turn a PCAP into correlated logs](https://docs.zeek.org/en/current/quickstart.html)** — Zeek project · practice · next · study cap ~30 min.

**Focus:** Run saved quickstart.pcap; join conn/http/weird records by uid, identify the unusual method.

**Prerequisites:** Zeek installed in WSL or Unix; save the PCAP and guide before travel.

**Offline:** Save the guide and linked quickstart.pcap in advance; verify Zeek in WSL and local analysis before departure. The live-traffic exercise uses external HTTP and is not flight practice.

<a id="web-network-8"></a>

**[Wireshark http.cap: match one HTTP request to its response](https://wiki.wireshark.org/SampleCaptures#hypertext-transport-protocol-http)** — Wireshark community wiki · practice · next · study cap ~30 min.

**Focus:** Use http.cap; compare GUI-selected fields with TShark output, explain what following a stream adds beyond one packet.

**Prerequisites:** Wireshark and TShark available; artifact downloaded before travel.

**Offline:** Save http.cap from https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap plus official filter/stream pages before travel. No account or lab server is required.

<a id="web-network-9"></a>

**[Nmap reference: interpret ports, services and saved results](https://nmap.org/book/man.html)** — Nmap project / Gordon Lyon · read · next · study cap ~15 min.

**Focus:** Distinguish open/closed/filtered; port-number label versus -sV identification; -oN and -oX output.

**Prerequisites:** Basic TCP ports; actual scanning requires a prepared authorized local target.

**Offline:** Save the reference for reading. Actual scanning needs a prepared local target or a reachable authorized lab; the online example target is not available without network.

### Filesystem, memory and artifact analysis

<a id="forensics-1"></a>

**[Sleuth Kit: list files and recover by metadata address](https://www.sleuthkit.org/sleuthkit/man/fls.html)** — The Sleuth Kit · read · core · study cap ~20 min.

**Focus:** Read fls -o/-r/-d/-p and Examples; mmls description and sector-size option; icat -o/-r and stdout behavior. Skip timeline and split-image options on the first pass.

**Prerequisites:** Basic shell syntax and redirection; know disk image versus filesystem image.

**Offline:** Save fls plus https://www.sleuthkit.org/sleuthkit/man/mmls.html and https://www.sleuthkit.org/sleuthkit/man/icat.html . The supplied paper drill needs no disk image. Executing requires an installed Sleuth Kit and a separately staged compatible image.

<a id="forensics-2"></a>

**[Autopsy Quick Start Guide](https://www.sleuthkit.org/autopsy/docs/user-docs/4.22.0/quick_start_guide.html)** — The Sleuth Kit / Autopsy · read · core · study cap ~20 min.

**Focus:** Cases and Data Sources; File Type Identification and Keyword Search; Analysis Basics; Web Artifacts. Skip multi-user setup, hash-set downloads and reporting formats.

**Prerequisites:** Recognize a case as a results container; execution requires installed Windows Autopsy, but reading/recall does not.

**Offline:** Save the 4.22.0 guide with screenshots. The required recall exercise uses no image; optional hands-on work can use a newly created folder of harmless text files as a logical data source. Installed Autopsy and sufficient local case storage are required for execution.

<a id="forensics-3"></a>

**[Volatility 3: Windows Tutorial](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html)** — Volatility Foundation · read · core · study cap ~20 min.

**Focus:** Plugin discovery, CLI shape, pslist, pstree and the symbol-download note; reconstruct relationships from the displayed PID/PPID columns.

**Prerequisites:** Understand PID/PPID and memory snapshot; hands-on requires a compatible local dump, installed Volatility 3 and resolved symbols.

**Offline:** Save the page. Stage the memory image and resolve its symbols while online, then test the chosen commands offline: Windows symbol files may otherwise require Microsoft downloads. Volatility does not acquire memory.

<a id="forensics-4"></a>

**[Introduction to Memory Forensics with Volatility 3](https://www.youtube.com/watch?v=Uk3DEgY5Ue8)** — DFIRScience / Joshua I. James · watch · next · study cap ~20 min.

**Focus:** If the official process exercise is easy, skip this item. Otherwise use the creator explanation to connect processes with handles and extracted files; consult installed help for plugin names. Do not copy windows.registay or windows.dumpfile from the notes.

**Prerequisites:** Volatility 3 core process lesson; distinguish PowerShell Select-String from WSL shell commands.

**Video runtime:** Not verified; the study cap is not a runtime.

**Free offline route:** [Read/practice instead](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html); save before going offline.

<a id="forensics-5"></a>

**[Introduction to MFTECmd - NTFS MFT and Journal Forensics](https://www.youtube.com/watch?v=_qElVZJqlGY)** — 13Cubed · watch · core · study cap ~25 min.

**Focus:** 00:00–06:00 artifact concepts and 10:33–20:36 MFTECmd/Timeline Explorer analysis; skip KAPE at 06:00–10:33. Concentrate on UpdateReasons and file-entry filtering, not treating timestamp anomalies alone as proof.

**Prerequisites:** NTFS basics; understand current metadata versus change journal. Execution needs supplied $MFT/$J, applicable Zimmerman executables/runtime and a CSV viewer; no KAPE requirement.

**Video runtime:** 22:01; selected chapters approximately 16:03, study estimate 25 minutes including recall.

**Free offline route:** [Read/practice instead](https://github.com/EricZimmerman/MFTECmd); save before going offline.

**Compatibility:** The video describes a historical `$LogFile` limitation; check the current MFTECmd README for support.

<a id="forensics-6"></a>

**[qpdf: PDF inspection options](https://qpdf.readthedocs.io/en/stable/cli.html#pdf-inspection)** — qpdf project · read · next · study cap ~15 min.

**Focus:** Basic Invocation inspection-mode exception; PDF Inspection: show-pages, show-object, raw-stream-data, filtered-stream-data, list-attachments and show-attachment.

**Prerequisites:** Know that a PDF contains numbered objects and streams; no PDF sample needed for recall. Execution requires local qpdf and a harmless PDF copy.

**Offline:** Save the PDF Inspection section. Hands-on use needs installed qpdf and local sample PDFs; retain original files and use inspection operations. Unsupported stream filters may prevent decoding.

<a id="forensics-7"></a>

**[Chainsaw: searching and hunting Windows event logs](https://github.com/WithSecureOpenSource/chainsaw#examples)** — WithSecure Countercept · read · next · study cap ~20 min.

**Focus:** Examples → Searching, then one Hunting command and its output. Explain the separate log input, rules and mapping; use 4104 in the example command despite the prose typo 4014.

**Prerequisites:** Understand EVTX event fields; execution needs local logs. Rule-based hunting additionally needs matching Sigma/Chainsaw rule files and mapping.

**Offline:** Save README examples and, for a local exercise, stage a small EVTX set plus matching rules and mapping files. Check the installed 2.16.5 help against the current README. No hosted backend is needed for the documented local-file workflow.

<a id="forensics-8"></a>

**[SQLite command-line shell: inspect schema and records](https://sqlite.org/cli.html)** — SQLite project · read · next · study cap ~20 min.

**Focus:** Opening Database Files (--readonly/--ifexists), .tables, .schema, .mode list and basic SELECT examples; distinguish dot-commands from SQL statements.

**Prerequisites:** Basic SQL SELECT/WHERE/ORDER BY; no sample database required for the included in-memory exercise.

**Offline:** Save these sections, not the whole manual as a study assignment. Use a local copy of a database and preserve any supplied WAL/SHM companions. This is SQLite CLI instruction, not deleted-record recovery or SQLCipher decryption.

### Reversing and static triage

<a id="reverse-1"></a>

**[Introduction to Ghidra — student guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)** — Ghidra project / NSA · read · core · study cap ~25 min.

**Focus:** Import/auto-analysis, decompiler, references, rename/type correction, function graph. Skip installation, server and window customization unless blocked.

**Prerequisites:** Basic C control flow and recognition of executable formats; running Ghidra only for optional lab.

**Offline:** Save the guide with images before travel; confirm it opens offline. The exercises accept a program of your choice, so use the benign [GDB source and disassembly](#reverse-4).

<a id="reverse-2"></a>

**[Ghidra quickstart & tutorial: Solving a simple crackme](https://www.youtube.com/watch?v=fTGTnrgjuGA)** — stacksmashing · watch · core · study cap ~15 min.

**Focus:** Choose this OR the basic Ghidra guide if navigation is rusty; focus on correcting main signature and deriving the three input conditions.

**Prerequisites:** Basic C expressions, argv and zero-based indexing.

**Video runtime:** Not verified; the study cap is not a runtime.

**Free offline route:** [Read/practice instead](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html); save before going offline.

**Compatibility:** This 2019 video uses an older interface. Skip its scrolling-patch suggestion.

<a id="reverse-3"></a>

**[Reversing and Cracking first simple Program — bin 0x05](https://www.youtube.com/watch?v=VroEiMOJPm8)** — LiveOverflow · watch · core · study cap ~15 min.

**Focus:** Use alongside the [GDB source and disassembly](#reverse-4); attempt its branch exercise. Review disassemble main and connect conditional jumps to the source.

**Prerequisites:** Basic x86-64 registers, cmp/test and conditional branches; use guide notes if rusty.

**Video runtime:** Not verified; the study cap is not a runtime.

**Free offline route:** [Read/practice instead](https://github.com/LiveOverflow/liveoverflow_youtube/tree/master/0x05_simple_crackme_intro_assembler); save before going offline.

<a id="reverse-4"></a>

**[bin 0x05 companion: license-check source and GDB disassembly](https://github.com/LiveOverflow/liveoverflow_youtube/tree/master/0x05_simple_crackme_intro_assembler)** — LiveOverflow · practice · next · study cap ~35 min.

**Focus:** Reconstruct branch graph and output cases from disassembly before opening license_1.c. Then verify one dynamic hypothesis if a local lab is already prepared.

**Prerequisites:** C argv/argc and strcmp; x86-64 argument registers and zero/nonzero return reasoning.

**Offline:** Save [gdb_disassembly](https://raw.githubusercontent.com/LiveOverflow/liveoverflow_youtube/master/0x05_simple_crackme_intro_assembler/gdb_disassembly) and [license_1.c](https://raw.githubusercontent.com/LiveOverflow/liveoverflow_youtube/master/0x05_simple_crackme_intro_assembler/license_1.c) before departure. Optional hands-on work requires a prepared local GDB/Ghidra environment; use the readable benign source, and check your compiled output because addresses will differ.

<a id="reverse-5"></a>

**[capa 9.4.0 usage: interpret capability matches](https://github.com/mandiant/capa/blob/v9.4.0/doc/usage.md)** — Mandiant / FLARE · read · core · study cap ~15 min.

**Focus:** Default versus -v/-vv, nested matches and -t filtering; ignore alternate commercial/cloud backends.

**Prerequisites:** Know what strings, disassembly and an address are; no malware execution needed.

**Offline:** Save the usage page; inspect its printed examples on the plane. CLI reading needs no live malware. Skip cloud uploads, IDA/Binary Ninja backends and sandbox integration for this study path.

<a id="reverse-6"></a>

**[FLOSS usage: static, stack, tight and decoded strings](https://github.com/mandiant/flare-floss/blob/master/doc/usage.md)** — Mandiant / FLARE · read · core · study cap ~15 min.

**Focus:** Default extraction plus static/stack/tight/decoded distinctions; one string-type selection example. Skip tag databases, HTML viewer and new filtering controls.

**Prerequisites:** Know why a plain-text string scan can miss runtime-constructed values.

**Offline:** Save the Markdown page before travel. Read the examples without executing sample malware; newer filtering/summary options need a local version check.

<a id="reverse-7"></a>

**[Writing YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html)** — YARA project · read · next · study cap ~25 min.

**Focus:** strings/condition, ASCII case sensitivity, nocase, hex wildcards and all-of logic. Skip exotic modifiers/modules on first pass.

**Prerequisites:** Boolean AND/OR and elementary byte/hex representation.

**Offline:** Save the relevant sections as HTML/PDF; the benign text-file drill is local once YARA is available. No malware collection or network service is required.

<a id="reverse-8"></a>

**[dnSpyEx: managed assembly navigation and debugging capabilities](https://github.com/dnSpyEx/dnSpy)** — dnSpyEx maintainers · read · reference · study cap ~5 min.

**Focus:** Entry point, string search, find callers, IL versus C# and breakpoint/locals capabilities.

**Prerequisites:** Recognize .NET assemblies; basic C# syntax helps.

**Offline:** Save README and relevant screenshots before travel. Practical debugging requires a prepared Windows environment and a benign assembly; no additional Unity setup is needed for this reading path.

<a id="reverse-9"></a>

**[JADX: APK/DEX reading and decompiler limits](https://github.com/skylot/jadx)** — JADX maintainers · read · reference · study cap ~10 min.

**Focus:** APK/DEX input; decoded manifest/resources; search, go-to-declaration, find usage; decompilation can be incomplete.

**Prerequisites:** Recognize APK/DEX and simple Java syntax; prepared Java/JADX only for execution.

**Offline:** Save README before departure; prepare any benign APK locally. GUI/CLI use can be offline once Java and JADX are working. Do not assume cloud deobfuscation is permitted.

<a id="reverse-10"></a>

**[pyinstxtractor-ng: inspect and extract a PyInstaller executable](https://github.com/pyinstxtractor/pyinstxtractor-ng)** — pyinstxtractor-ng maintainers · read · reference · study cap ~10 min.

**Focus:** Extract locally; distinguish extraction from recovered source; identify bytecode version before choosing decompiler. Avoid the README example that immediately executes extracted code.

**Prerequisites:** Understand executable container versus Python bytecode; simple Python familiarity.

**Offline:** Save README before travel. Read its examples without executing extracted code; prepare a benign sample only if you want an offline drill. Do not use the linked web service for event files.

### Encodings, crypto and passwords

<a id="crypto-foundations-1"></a>

**[CyberChef: how recipes work and worked examples](https://github.com/gchq/CyberChef)** — GCHQ · read · core · study cap ~10 min.

**Focus:** Read How it works, breakpoints, save/load recipes, and the Base64/hexdump examples. In Worksheet 1, decode the single Base64 layer Q1RGLXJlZnJlc2hlcg== to CTF-refresher (no newline), encode it back to the original input, and save the recipe.

**Prerequisites:** Comfort with encodings versus encryption; local CyberChef needed only for interactive practice.

**Offline:** Save the README and prepare a working local CyberChef build before departure; a bookmark alone is not an offline copy. Test it with networking disabled.

<a id="crypto-foundations-2"></a>

**[Cryptography Lab 5: Cooking with the Cyberchef](https://www.youtube.com/watch?v=UtqmiI7k9lU)** — Level Effect · watch · core · study cap ~10 min.

**Focus:** Optional 7:17 watch or skim first recipe construction and inversion; use the typed-text example or the embedded known-answer recipe instead of course assets.

**Prerequisites:** None beyond the CyberChef basics; later course lab file not supplied.

**Video runtime:** 07:17

**Free offline route:** [Read/practice instead](https://github.com/gchq/CyberChef); save before going offline.

<a id="crypto-foundations-3"></a>

**[CTFlearn: RSA Beginner](https://www.youtube.com/watch?v=20K1ctFzu2Y)** — Almond Force · watch · core · study cap ~10 min.

**Focus:** Optional 5:44 walkthrough of factorization, phi, inverse and modular decryption. For local practice, use Worksheet 8’s separate toy inputs p=61, q=53, e=17, m=42: derive n=3233, phi=3120, d=2753, encrypt to c=2557 and decrypt to 42. Skip the portal submission and online converter.

**Prerequisites:** Integer arithmetic and Python pow; Sage optional for the tiny fixture.

**Video runtime:** 05:44

**Free offline route:** [Read/practice instead](https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html); save before going offline.

**Limit:** This example demonstrates weak textbook RSA, not a general RSA attack.

<a id="crypto-foundations-4"></a>

**[RsaCtfTool: usage and attack prerequisites](https://github.com/RsaCtfTool/RsaCtfTool)** — RsaCtfTool maintainers · read · core · study cap ~20 min.

**Focus:** Read key creation/inspection and named-attack examples; choose attacks from observed weaknesses. Know why arbitrary RSA keys are not automatically recoverable. Avoid FactorDB and sendtofdb in offline/event workflows.

**Prerequisites:** Basic RSA n/e/c/p/q/phi/d; local Python 3.9+ and tool dependencies if executing; Sage only for supported attacks that need it.

**Offline:** Save README and help output. Prepare dependencies beforehand; Sage is optional for some attacks but needed for others. Avoid network-backed attacks such as FactorDB offline.

<a id="crypto-foundations-5"></a>

**[SageMath tutorial: number theory](https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html)** — SageMath documentation team · read · next · study cap ~15 min.

**Focus:** Read gcd/factor, inverse_mod, extended Euclid and CRT; skip p-adics, number fields and unrelated sequences. Check CRT gives 11 for residues 2 mod 3 and 1 mod 5.

**Prerequisites:** Modular arithmetic; local Sage for Sage commands. Python pow(...,-1,...) can cover the small RSA exercise without Sage.

**Offline:** Save this chapter and test local Sage first. The workbook records no Sage installation information; ordinary Python alone does not provide sage.all.

<a id="crypto-foundations-6"></a>

**[hashcat: dictionary attacks with a tiny wordlist](https://hashcat.net/wiki/doku.php?id=dictionary_attack)** — hashcat project · read · core · study cap ~15 min.

**Focus:** Read dictionary Description and the first command. Use -m 0 (raw MD5) with -a 0 and a three-word list; compare with -a 3 and a constrained mask. Use local help for installed-version flags; skip page suggestions for newer modes.

**Prerequisites:** Hash format identification; working hashcat backend for execution, otherwise use the Python known-answer fallback.

**Offline:** Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.

<a id="crypto-foundations-7"></a>

**[John the Ripper: usage examples](https://www.openwall.com/john/doc/EXAMPLES.shtml)** — Openwall · read · core · study cap ~10 min.

**Focus:** Read --wordlist, --rules, --show and session/restore examples; skip password-file acquisition, account filters and exhaustive incremental demonstrations. Compare John --format=raw-md5 with hashcat -m 0 on the same toy file.

**Prerequisites:** John Jumbo for raw-md5; no real account files needed. Verify the local format is present before flight.

**Offline:** Save the examples and prepare a tiny synthetic hash file and wordlist. The page teaches general John behavior; Jumbo-specific formats and extractors need the installed build’s help.

<a id="crypto-foundations-8"></a>

**[bkcrack 1.8.1: stored-plaintext ZIP recovery](https://github.com/kimci86/bkcrack/blob/v1.8.1/example/tutorial.md)** — kimci86 / bkcrack project · practice · next · study cap ~25 min.

**Focus:** Read archive metadata, stored-file known plaintext, internal-key recovery and password removal. Work from the printed metadata if the sample archive was not prepared.

**Prerequisites:** ZipCrypto versus AES; stored versus deflated members; local bkcrack 1.8.1 plus public example only if executing.

**Offline:** Save selected text before departure. Reading a saved page is free; running examples also requires a working local tool and dependencies.

## Compatibility and coverage limits

The exact inventory versions and locations remain in the [all-tool index](APPROVED_TOOL_REFERENCES.md). Consult its specialist references when the core exercises do not cover your input.

- capa and bkcrack instructions are pinned to recorded versions 9.4.0 and 1.8.1. Autopsy documentation is 4.22.0; the installed version still needs checking. Moving docs for tools listed as “Latest” or unspecified are not guarantees of installed flags.
- Binwalk major versions differ. SSTV is listed as a decoder but its installation note names the PySSTV encoder. Sage has no installation information recorded. Neither is an execution prerequisite for the included exercises.
- The MFTECmd video is historical: use the current author README for `$LogFile` support. DFIRScience companion command notes have typos; use the official Volatility tutorial for syntax.
- Specialized lattice attacks are outside this schedule; `crypto-attacks` remains approved and referenced. Alternative debuggers, mobile artifacts, OSINT, CAN/wireless and vulnerability-specific utilities remain available as targeted lookups, not implicitly mastered by the core path.
