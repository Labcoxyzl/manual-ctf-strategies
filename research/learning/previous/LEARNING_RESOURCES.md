# Approved tools: a 24-hour CTF refresher

For someone who knows CTFs but wants to regain fluency without an assistant. Skim familiar tools; spend the saved time repeating an unfamiliar workflow without looking at the instructions. This is a study menu, not a claim that 24 hours covers every tool deeply.

The approval boundary is the organiser's `AJCCBC_CTF2026_Tool_Review_List_261015r11.xlsx`: **39 Windows rows and 161 Kali rows**, checked against the original workbook on 22 October 2026. Some Windows entries run in WSL. Kali tools are installed on a best-effort basis; an approved name does not establish a working installation. See [source notes](EVENT_SOURCES.md).

## How to use this list

Start with the schedule below. Each block should leave you able to recognize an input, choose an approved tool, run one useful operation, and interpret its output. Read or watch first, repeat on a local training artifact, then write a few lines of your own notes: **when to use it, minimum command or clicks, what output matters, and one failure mode**.

The curated resources below are the learning path. The separate [all-tool index](APPROVED_TOOL_REFERENCES.md) keeps a documentation reference for every approved row, including specialist tools, runtimes, editors, and overlapping utilities. “Reference” means look it up when needed, not spend equal time studying it.

## Suggested 24-hour path

These are recommended study allocations, including practice and notes, **not video runtimes**. Break them across the trip; skip ahead whenever you can already perform the stated task.

| Block | Time | Focus | Finish when you can… |
| --- | --- | --- | --- |
| 1 | 2 h | [CyberChef](#crypto-foundations-1), [ExifTool](#media-3), [binwalk](#media-2), [zsteg](#media-1) | Explain why you chose CyberChef, ExifTool, binwalk, or a format-specific stego tool; distinguish decoding from decryption. |
| 2 | 3 h | [Wireshark video](#web-network-5), [sample captures](#web-network-8), [TShark](#web-network-6) | Filter a saved capture, follow a conversation, and identify the bytes or object that answer a question. |
| 3 | 3 h | [Autopsy](#forensics-2), [Sleuth Kit](#forensics-1), [MFTECmd video](#forensics-5) | Navigate supplied evidence, recover a file or timeline, and relate an artifact to a user action. |
| 4 | 2 h | [Volatility 3 tutorial](#forensics-3) and [video](#forensics-4) | Choose Volatility 3 plugins, inspect process relationships, and recognize a missing-symbol or version problem. |
| 5 | 4 h | [Ghidra guide](#reverse-1), [Ghidra video](#reverse-2), [GDB video](#reverse-3) and [exercise](#reverse-4) | Find a program's input check, rename important values, and verify one hypothesis in a debugger. |
| 6 | 2 h | [capa](#reverse-5), [FLOSS](#reverse-6), [YARA](#reverse-7), [managed-code options](#reverse-8) | Use strings/FLOSS/capa/YARA appropriately and choose a decompiler for the binary's format. |
| 7 | 3 h | [Burp tutorial](#web-network-1) and [video](#web-network-2), [curl](#web-network-3), [ffuf](#web-network-4) | Capture, modify, and replay a request; recognize where a hosted lab needs connectivity. |
| 8 | 3 h | [RSA video](#crypto-foundations-3), [RsaCtfTool](#crypto-foundations-4), [hashcat](#crypto-foundations-6), [John](#crypto-foundations-7), [bkcrack](#crypto-foundations-8) | Recognize an applicable RSA or archive weakness, distinguish hash identification from recovery, and explain the assumptions of an attack. |
| 9 | 1 h | Your weakest specialist area | Use the all-tool index to study one unfamiliar family: Android, audio/SSTV, CAN, registry, or another likely gap. |
| 10 | 1 h | Recall and consolidation | Reproduce two useful workflows from your own short notes and record what still requires checking. |

## Before the flight

1. Save the selected reading pages as PDFs or complete offline pages, including any figures you need. Open them with networking disabled before leaving. Saving a landing page does not save its linked chapters.
2. Prepare videos through an available platform download option and test playback on the device you will carry. YouTube documents offline downloads through Premium, subject to availability, account and periodic reconnection requirements; a bookmark alone will not work offline. See [YouTube's offline-viewing instructions](https://support.google.com/youtube/answer/11977233?hl=en).
3. Put chosen training files, worksheets and solutions in separate local folders. Read the task first and keep the solution closed until you have made an attempt. Use small, benign artifacts for the plane; do not assume a remotely hosted lab can be saved as a page.
4. Launch the tools you plan to practice with while still online. Resolve dependencies, symbols, plugins and sample-file requirements then. For Ghidra, the [official beginner guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html) says its exercises can use a program of your choice; a small benign program you already understand makes a useful starting point.
5. Keep web-lab reading separate from hands-on work that needs a server. Offline practice requires a previously prepared local target; a cloud portal or PortSwigger lab still needs its service.

This research pass produces a resource list, not a downloaded offline bundle. No organiser portal has been opened, and no practice launch has been consumed. Resources are preparation material; the competition's restrictions on AI assistance and uploading challenge files still apply.

## Small practice options

These are public learning materials, not organiser portal challenges. Nothing has been downloaded or run.

| Exercise | Preparation before flying | Offline task |
| --- | --- | --- |
| [Wireshark sample capture](https://wiki.wireshark.org/SampleCaptures) | Save one small HTTP or Telnet PCAP and its description. | Find endpoints and one conversation; compare the stream with raw packets. |
| [Zeek quick start](https://docs.zeek.org/en/current/quickstart.html) | Save `quickstart.pcap`; confirm local Zeek works. | Generate logs and correlate one connection by `uid`. |
| [LiveOverflow branch exercise](https://github.com/LiveOverflow/liveoverflow_youtube/tree/master/0x05_simple_crackme_intro_assembler) | Save `gdb_disassembly` and `license_1.c`. | Predict branches on paper before reading the source; optionally verify in GDB. |
| [bkcrack ZIP exercise](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md) | Save `example/secrets.zip` and the tutorial; test the binary. | Explain the known-plaintext assumption, then follow the key-recovery exercise. |
| [YARA rule exercise](https://yara.readthedocs.io/en/stable/writingrules.html) | Save the relevant rule syntax; prepare two harmless text files. | Write a rule that matches one file but not the other, then explain why. This is a suggested drill, not a published challenge. |

## Curated resources

### File triage, steganography and media

<a id="media-1"></a>

**[zsteg: detection and extraction examples](https://github.com/zed-0xff/zsteg)** — zed-0xff · read · core · about 25 min.

**Tools:** zsteg. Refresh PNG/BMP LSB scanning, channel/bit-order selection, and extracting a specific candidate with -E. Read Usage and Examples; distinguish candidate signatures from validated payloads.

**For the flight:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

<a id="media-2"></a>

**[Binwalk v3: embedded-file identification](https://github.com/ReFirmLabs/binwalk)** — ReFirmLabs · read · core · about 15 min.

**Tools:** binwalk. Refresh what signature scanning, extraction and entropy can tell you. Read the short README, then use installed --help for extraction options; avoid copying v2 recipes blindly.

**For the flight:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Extraction also depends on locally installed helper programs.

<a id="media-3"></a>

**[ExifTool: application documentation and reading examples](https://exiftool.org/exiftool_pod.html#READING-EXAMPLES)** — Phil Harvey / ExifTool · read · core · about 20 min.

**Tools:** ExifTool. Refresh metadata reading syntax and the distinction between reading and assignment-based writing; skim Reading Examples and retain a local copy for tag lookup.

**For the flight:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

<a id="media-4"></a>

**[Stegseek: wordlist mode, seed mode and steghide compatibility](https://github.com/RickdeJager/stegseek)** — Rick de Jager · read · core · about 20 min.

**Tools:** stegseek, steghide. Refresh wordlist extraction versus seed detection. Seed mode can recover an unencrypted payload; it does not generally bypass encryption. Compare steghide command syntax with stegseek --command syntax.

**For the flight:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Save any intended wordlist beforehand; no wordlist or binaries downloaded here.

<a id="media-5"></a>

**[Audacity: Spectrogram View](https://manual.audacityteam.org/man/spectrogram_view.html)** — Audacity · read · core · about 25 min.

**Tools:** Audacity. Refresh switching from waveform to spectrogram, frequency limits, gain/range, and window size. Understand the time-versus-frequency resolution tradeoff before interpreting a blank or blurred image.

**For the flight:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available.

<a id="media-6"></a>

**[FFmpeg: stream selection and streamcopy](https://ffmpeg.org/ffmpeg.html)** — FFmpeg project · read · next · about 30 min.

**Tools:** FFmpeg. Skim Description, Streamcopy and Stream selection. Refresh input/output option ordering and explicit -map selection so an audio or secondary stream is not missed during media extraction.

**For the flight:** Save the page with images or print to PDF before flying; local tools and any practice files must already be available. Check available codecs and installed help before departure.

<a id="media-7"></a>

**[AperiSolve: local deployment and analyzer overview](https://github.com/Zeecka/AperiSolve)** — Zeecka · read · reference · about 15 min.

**Tools:** AperiSolve. Recognize which individual tools and bit-layer views the platform combines. Read Key features and Quick start to understand local operation; direct tools remain useful when a deployment is unavailable.

**For the flight:** Save README. Offline use requires an already working local deployment and dependencies; a git checkout alone is insufficient. Never upload event challenge files to the public service.

<a id="media-8"></a>

**[MORSE CODE Steganography (2/2) BsidesCT CTF 2018](https://www.youtube.com/watch?v=pJYyyz6HPbQ)** — John Hammond · watch · next · about 20 min.

**Tools:** Sonic Visualiser, ExifTool. Watch an audio investigation using Sonic Visualiser and ExifTool to distinguish tone timing from other encodings; note how metadata redirects the investigation. Skim the later encoding detour if familiar.

**For the flight:** Use YouTube-supported offline saving where available and test playback before flying. The walkthrough uses online decoders: retain the reasoning, but do not copy challenge-file uploads at this event.

**Video check:** 2026-10-22: Inspected creator video metadata and full retrieved transcript via Exa, not playback. Transcript explicitly names Sonic Visualiser and ExifTool and includes online upload steps. Published 2018-11-06; historical UI.

### Web requests and network evidence

<a id="web-network-1"></a>

**[Burp: reissue requests and investigate unexpected input](https://portswigger.net/burp/documentation/desktop/getting-started/reissuing-http-requests)** — PortSwigger · read · core · about 30 min.

**Tools:** Burp Suite Community Edition. Move a request from Proxy history into Repeater; change one parameter, compare responses and recognize useful error disclosure. Follow the linked Proxy/scope prerequisites first.

**For the flight:** Save this page and linked Proxy/scope steps before flying. Academy execution requires an account and reachable lab server; saved HTML does not preserve the lab.

<a id="web-network-2"></a>

**[How to resend individual requests with Burp Repeater](https://www.youtube.com/watch?v=_Wifm2g9ugg)** — PortSwigger · watch · core · about 15 min.

**Tools:** Burp Suite Community Edition. Short demonstration of the manual request-edit-send-compare loop, history, redirects and tabs. Pair with the current written tutorial because the 2020 interface differs.

**For the flight:** Use YouTube offline viewing where supported and verify playback before departure; otherwise save personal notes. A running target is needed to repeat the actions.

**Video check:** 2026-10-22: Inspected creator metadata, description and transcript; did not watch the video.

<a id="web-network-3"></a>

**[Everything curl: Command line HTTP](https://everything.curl.dev/http/)** — Daniel Stenberg and curl contributors · read · core · about 30 min.

**Tools:** curl. Read the Customize headers and Cookies subsections: reproduce HTTP requests, replace headers and retain session state with a cookie jar. Useful when a browser hides request details.

**For the flight:** Save the selected child pages as well as the chapter index. Header examples: https://everything.curl.dev/http/modify/headers.html ; cookie jar: https://everything.curl.dev/http/cookies/writing.html . Sending requests needs a local prepared server or connectivity.

<a id="web-network-4"></a>

**[ffuf upstream examples: discovery, filters and bounded runs](https://github.com/ffuf/ffuf)** — ffuf maintainers · read · next · about 35 min.

**Tools:** ffuf, SecLists. Place FUZZ in a path, Host header or parameter; filter uninteresting sizes/statuses and bound runs. SecLists supplies candidate input, but learning response comparison matters more than collecting more wordlists.

**For the flight:** Save README and a small selected wordlist. Optional home practice: https://github.com/adamtlangley/ffufme offers a local Docker target; build and verify before travel. The hosted ffuf.me requires internet; no local lab was prepared.

<a id="web-network-5"></a>

**[How to Use Wireshark's Follow TCP Stream Feature](https://www.youtube.com/watch?v=ixVXfUBEciU)** — Learning Tree International · watch · core · about 15 min.

**Tools:** Wireshark. Recover the complete two-way conversation instead of reading one packet at a time; distinguish client and server directions using a Telnet sample.

**For the flight:** Arrange permitted offline video playback and save the sample capture in advance. The 2017 UI is old; TCP reconstruction remains the useful lesson.

**Video check:** 2026-10-22: Fetched original creator description and transcript, including the sample-capture source and stream-direction demonstration; did not watch.

<a id="web-network-6"></a>

**[TShark manual: saved captures and display filters](https://www.wireshark.org/docs/man-pages/tshark.html)** — Wireshark Foundation · read · next · about 25 min.

**Tools:** tshark. Focus on -r to read a PCAP, -Y for Wireshark display filters and -T fields/-e for repeatable field extraction. Distinguish display filters from capture filters.

**For the flight:** Save manual and sample PCAP; run locally after checking TShark is installed. No live network needed for saved-capture analysis.

<a id="web-network-7"></a>

**[Zeek quick start: turn a PCAP into correlated logs](https://docs.zeek.org/en/current/quickstart.html)** — Zeek project · practice · next · about 30 min.

**Tools:** zeek. Use the supplied quickstart.pcap to produce conn.log, http.log and weird.log, then correlate them by uid. Stop before the live-traffic section for airplane practice.

**For the flight:** Save the guide and linked quickstart.pcap in advance; verify Zeek in WSL and local analysis before departure. The live-traffic exercise uses external HTTP and is not flight practice.

<a id="web-network-8"></a>

**[Wireshark Sample Captures: a small offline packet-analysis exercise](https://wiki.wireshark.org/SampleCaptures)** — Wireshark community wiki · practice · core · about 30 min.

**Tools:** Wireshark, tshark. Pick a small HTTP or Telnet capture. Identify endpoints, filter one conversation, reconstruct its stream, then extract matching fields with TShark. These are self-directed exercises, not scored challenges.

**For the flight:** Download one selected capture and its description before departure. Static saved files work offline; viewing the index alone is insufficient. No sample was downloaded or tested here.

<a id="web-network-9"></a>

**[Nmap reference: interpret ports, services and saved results](https://nmap.org/book/man.html)** — Nmap project / Gordon Lyon · read · next · about 25 min.

**Tools:** Nmap (with Ncat / Nping). Read port states, service/version detection and output sections. Learn what open, closed and filtered do and do not establish before selecting a service-specific tool.

**For the flight:** Save the reference for reading. Actual scanning needs a prepared local target or a reachable authorized lab; the online example target is not available without network.

### Disk, memory and artifact forensics

<a id="forensics-1"></a>

**[Sleuth Kit: filesystem analysis scenarios](https://wiki.sleuthkit.org/FS-Analysis/)** — The Sleuth Kit · read · core · about 25 min.

**Tools:** The Sleuth Kit, strings. Follow a string hit from unallocated space to its original disk block, inode and deleted filename; learn why byte offsets and filesystem units differ. Read Search first; treat the historic filesystem examples as concepts to adapt.

**For the flight:** Save the page before departure. Reading needs no image; repeating commands needs a local disk image and installed Sleuth Kit. Example image names are illustrative, not bundled downloads.

<a id="forensics-2"></a>

**[Autopsy Quick Start Guide](https://www.sleuthkit.org/autopsy/docs/user-docs/4.20.0/quick_start_guide.html)** — The Sleuth Kit / Autopsy · read · core · about 20 min.

**Tools:** Autopsy. Create a single-user case, add a raw/E01 image, choose ingest modules, search keywords, inspect extracted browser activity and export an interesting file.

**For the flight:** Save the guide including images. For hands-on work, stage a small local image and let ingest finish before boarding; avoid modules that need network services. Documentation is for 4.20.0, not a verified installed version.

<a id="forensics-3"></a>

**[Volatility 3: Windows Tutorial](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html)** — Volatility Foundation · read · core · about 20 min.

**Tools:** volatility3. Understand plugin syntax and compare pslist with pstree to reconstruct processes and parent-child relationships in a Windows memory dump.

**For the flight:** Save the page. Stage the memory image and resolve its symbols while online, then test the chosen commands offline: Windows symbol files may otherwise require Microsoft downloads. Volatility does not acquire memory.

<a id="forensics-4"></a>

**[Introduction to Memory Forensics with Volatility 3](https://www.youtube.com/watch?v=Uk3DEgY5Ue8)** — DFIRScience / Joshua I. James · watch · next · about 40 min.

**Tools:** volatility3. See the workflow from memory information to processes, handles, connections, extracted files and registry artifacts; use the official Windows tutorial for current command spelling.

**For the flight:** Save using a permitted platform offline feature and confirm playback before departure; availability can depend on account and region. Save the companion notes at https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3 . Its practice-image link is optional and was not downloaded or tested.

**Video check:** 2026-10-22: Read the creator companion page and inspected its HTML embedding this exact YouTube ID; YouTube fetch confirmed title and 2022 publication date but provided no transcript. Not watched. Companion command notes contain apparent typos including windows.registay and windows.dumpfile, so do not use them as a verbatim command sheet.

<a id="forensics-5"></a>

**[Introduction to MFTECmd - NTFS MFT and Journal Forensics](https://www.youtube.com/watch?v=_qElVZJqlGY)** — 13Cubed · watch · core · about 30 min.

**Tools:** Eric Zimmerman's Tools. Learn what $MFT and $UsnJrnl can reveal about file creation, deletion and renaming; follow MFTECmd CSV parsing at 10:33 and Timeline Explorer analysis at 13:00.

**For the flight:** Save through a permitted platform offline feature and check playback. For practice, bring already extracted $MFT/$J files and the required Zimmerman tools/runtime. Skip the 06:00 KAPE acquisition chapter unless that separate tool is independently confirmed approved.

**Video check:** 2026-10-22: Fetched title, channel, description, chapter markers and transcript excerpts. The video demonstrates MFTECmd and Timeline Explorer and discusses a historical $LogFile limitation; no claim of current installed support. Not watched.

<a id="forensics-6"></a>

**[qpdf: PDF inspection options](https://qpdf.readthedocs.io/en/stable/cli.html#pdf-inspection)** — qpdf project · read · next · about 20 min.

**Tools:** qpdf. Move beyond visible page text: inspect PDF objects and attachments, distinguish compressed stream bytes from decoded stream data, and recognize the inspection-mode invocation.

**For the flight:** Save the PDF Inspection section. Hands-on use needs installed qpdf and local sample PDFs; retain original files and use inspection operations. Unsupported stream filters may prevent decoding.

<a id="forensics-7"></a>

**[Chainsaw: searching and hunting Windows event logs](https://github.com/WithSecureOpenSource/chainsaw#examples)** — WithSecure Countercept · read · next · about 25 min.

**Tools:** Chainsaw. Search EVTX files by string or event field, then compare those results with Sigma-based hunting using a mapping file and time filters. Start with search before loading a large ruleset.

**For the flight:** Save README examples and, for a local exercise, stage a small EVTX set plus matching rules and mapping files. Check the installed 2.16.5 help against the current README. No hosted backend is needed for the documented local-file workflow.

<a id="forensics-8"></a>

**[SQLite command-line shell: inspect schema and records](https://sqlite.org/cli.html)** — SQLite project · read · next · about 20 min.

**Tools:** sqlite3. Read Getting Started, dot-commands, output formats and Querying the database schema; use .tables and .schema before querying an unfamiliar artifact database.

**For the flight:** Save these sections, not the whole manual as a study assignment. Use a local copy of a database and preserve any supplied WAL/SHM companions. This is SQLite CLI instruction, not deleted-record recovery or SQLCipher decryption.

### Reversing and static malware analysis

<a id="reverse-1"></a>

**[Introduction to Ghidra — student guide](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)** — Ghidra project / NSA · read · core · about 45 min.

**Tools:** Ghidra. Import a binary, analyze it, navigate functions and references, rename findings, and compare decompiler output with disassembly. Read the basic analysis, navigation and decompiler sections first.

**For the flight:** Save the guide with images before travel; confirm it opens offline. The exercises accept a program of your choice, so use the benign reverse-4 companion.

<a id="reverse-2"></a>

**[Ghidra quickstart & tutorial: Solving a simple crackme](https://www.youtube.com/watch?v=fTGTnrgjuGA)** — stacksmashing · watch · core · about 25 min.

**Tools:** Ghidra. See a complete small password-check investigation: import, analysis, decompiler, function signatures and window navigation.

**For the flight:** Use an authorized YouTube offline download if available and check playback before boarding. Watch as a walkthrough; a third-party crackme download is optional, not needed for reading.

**Video check:** 2026-10-22: Exa retrieved the original video title, creator and transcript covering import, analysis and decompiler navigation. Published 2019; skip the historical scrolling-patch suggestion and expect changed UI. Not watched or executed; study_minutes is a planning estimate, not video runtime.

<a id="reverse-3"></a>

**[Reversing and Cracking first simple Program — bin 0x05](https://www.youtube.com/watch?v=VroEiMOJPm8)** — LiveOverflow · watch · core · about 25 min.

**Tools:** gdb. Connect C control flow to GDB disassembly using a tiny license-check example; pair the video with its source and annotated disassembly in reverse-4.

**For the flight:** Prepare authorized offline video playback and save the companion source/disassembly. GDB is approved in WSL; historical tool comparisons do not require installing Hopper or IDA.

**Video check:** 2026-10-22: Exa fetched the original YouTube title/date; full primary-page transcript was unavailable, and web fallback failed. Inspected the creator repository and raw C/disassembly to verify the exercise and plain-GDB basis. Video content itself was not fully independently inspected. Not watched or executed; study_minutes is a planning estimate, not video runtime.

<a id="reverse-4"></a>

**[bin 0x05 companion: license-check source and GDB disassembly](https://github.com/LiveOverflow/liveoverflow_youtube/tree/master/0x05_simple_crackme_intro_assembler)** — LiveOverflow · practice · next · about 25 min.

**Tools:** gdb, Ghidra. Draw the branch graph on paper from gdb_disassembly, predict which branch each input takes, then compare with license_1.c. This works as a reading exercise without executing a downloaded binary.

**For the flight:** Save gdb_disassembly and license_1.c before departure. Optional hands-on work requires a prepared local GDB/Ghidra environment; use the readable benign source, and check your compiled output because addresses will differ.

<a id="reverse-5"></a>

**[capa usage: understand capability matches](https://github.com/mandiant/capa/blob/master/doc/usage.md)** — Mandiant / FLARE · read · core · about 20 min.

**Tools:** capa. Read default versus verbose output and rule filtering; use match locations as leads for investigation rather than treating a capability label as a complete explanation.

**For the flight:** Save the usage page; inspect its printed examples on the plane. CLI reading needs no live malware. Skip cloud uploads, IDA/Binary Ninja backends and sandbox integration for this study path.

<a id="reverse-6"></a>

**[FLOSS usage: static, stack, tight and decoded strings](https://github.com/mandiant/flare-floss/blob/master/doc/usage.md)** — Mandiant / FLARE · read · core · about 20 min.

**Tools:** FLOSS (FLARE Obfuscated String Solver). Learn why ordinary strings can miss useful values and how FLOSS groups extracted string types. Concentrate on default extraction and string-type selection.

**For the flight:** Save the Markdown page before travel. Read the examples without executing sample malware; newer filtering/summary options need a local version check.

<a id="reverse-7"></a>

**[Writing YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html)** — YARA project · read · next · about 30 min.

**Tools:** YARA. Learn strings and conditions, text versus hex patterns, wildcards and boolean combinations. Optional benign drill: draft a rule to distinguish two small text files you create.

**For the flight:** Save the relevant sections as HTML/PDF; the benign text-file drill is local once YARA is available. No malware collection or network service is required.

<a id="reverse-8"></a>

**[dnSpyEx: managed assembly navigation and debugging capabilities](https://github.com/dnSpyEx/dnSpy)** — dnSpyEx maintainers · read · next · about 20 min.

**Tools:** dnSpyEx (dnSpy). Identify the .NET workflow: find entry points, search strings/classes, follow callers, inspect IL, then use breakpoints and locals when appropriate. Start with navigation before editing assemblies.

**For the flight:** Save README and relevant screenshots before travel. Practical debugging requires a prepared Windows environment and a benign assembly; no additional Unity setup is needed for this reading path.

<a id="reverse-9"></a>

**[JADX: APK/DEX reading and decompiler limits](https://github.com/skylot/jadx)** — JADX maintainers · read · next · about 20 min.

**Tools:** jadx (jadx-gui). Learn the Android entry workflow: load APK/DEX, search Java-like output and resources, and treat failed or suspicious decompilation as a reason to inspect bytecode with the approved companion tools.

**For the flight:** Save README before departure; prepare any benign APK locally. GUI/CLI use can be offline once Java and JADX are working. Do not assume cloud deobfuscation is permitted.

<a id="reverse-10"></a>

**[pyinstxtractor-ng: inspect and extract a PyInstaller executable](https://github.com/pyinstxtractor/pyinstxtractor-ng)** — pyinstxtractor-ng maintainers · read · next · about 20 min.

**Tools:** pyinstxtractor-ng. Separate packaging from bytecode recovery: extract a PyInstaller archive first, then identify bytecode version before selecting pycdc, uncompyle6 or unpyc3. Extraction alone does not recover Python source.

**For the flight:** Save README before travel. Read its examples without executing extracted code; prepare a benign sample only if you want an offline drill. Do not use the linked web service for event files.

### Encodings, crypto and password recovery

<a id="crypto-foundations-1"></a>

**[CyberChef: how recipes work and worked examples](https://github.com/gchq/CyberChef)** — GCHQ · read · core · about 20 min.

**Tools:** CyberChef. Learn the input/recipe/output workflow; follow Base64, hexdump, compression and nested-encoding examples. Start here before trying random operations.

**For the flight:** Save the README and prepare a working local CyberChef build before departure; a bookmark alone is not an offline copy. Test it with networking disabled.

<a id="crypto-foundations-2"></a>

**[Cryptography Lab 5: Cooking with the Cyberchef](https://www.youtube.com/watch?v=UtqmiI7k9lU)** — Level Effect · watch · core · about 15 min.

**Tools:** CyberChef. A short visual introduction to reversible recipes, Base64, octal and a multi-step obfuscation exercise. The simple typed-text example can be recreated without the course.

**For the flight:** Use the platform’s permitted offline option before flying. Later lab material references a course-provided obfuscated-code file; that file was not obtained.

**Video check:** 2026-10-22: Inspected creator video metadata and transcript covering the interface and layered encoding through Exa; not watched. Listed runtime is 7:17; study estimate includes pausing.

<a id="crypto-foundations-3"></a>

**[CTFlearn: RSA Beginner](https://www.youtube.com/watch?v=20K1ctFzu2Y)** — Almond Force · watch · core · about 20 min.

**Tools:** Python 3, Python 3.11 (via uv), SageMath. Follow n, e and c through factorization, totient, modular inverse and Python byte conversion. This explains the prerequisites behind automated RSA tools.

**For the flight:** Save using a permitted video offline option. The demo uses online SageCell: replace that step with an already-tested local Sage installation for public toy inputs; do not copy the online submission workflow with event challenge material.

**Video check:** 2026-10-22: Inspected creator metadata and full retrieved transcript through Exa; not watched. Listed runtime is 5:44. This demonstrates textbook weak RSA, not general RSA breaking.

<a id="crypto-foundations-4"></a>

**[RsaCtfTool: usage and attack prerequisites](https://github.com/RsaCtfTool/RsaCtfTool)** — RsaCtfTool maintainers · read · core · about 25 min.

**Tools:** RsaCtfTool. Learn public-key inspection, selected attacks and decryption inputs; distinguish close-prime, small-exponent and shared-factor situations from unfactorable keys.

**For the flight:** Save README and help output. Prepare dependencies beforehand; Sage is optional for some attacks but needed for others. Avoid network-backed attacks such as FactorDB offline.

<a id="crypto-foundations-5"></a>

**[SageMath tutorial: number theory](https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html)** — SageMath documentation team · read · next · about 35 min.

**Tools:** SageMath. Work through modular rings, gcd, factor, inverse_mod and CRT examples. Compare Sage syntax with the provided Python equivalents.

**For the flight:** Save this chapter and test local Sage first. The workbook records no Sage installation information; ordinary Python alone does not provide sage.all.

<a id="crypto-foundations-6"></a>

**[hashcat: attack modes, options and status output](https://hashcat.net/wiki/doku.php?id=hashcat)** — hashcat project · read · core · about 25 min.

**Tools:** hashcat, rockyou.txt (Kali 'wordlists' package). Focus on choosing hash type versus attack mode, supplying a wordlist or mask, and interpreting progress, rejected candidates and recovered hashes. Consult local help before copying flags.

**For the flight:** Save the page and prepare a tiny self-created hash/wordlist exercise before flying. Device backend and drivers must already work; long GPU searches are poor battery exercises.

<a id="crypto-foundations-7"></a>

**[John the Ripper: usage examples](https://www.openwall.com/john/doc/EXAMPLES.shtml)** — Openwall · read · core · about 25 min.

**Tools:** John the Ripper (jumbo), rockyou.txt (Kali 'wordlists' package). Learn single mode, wordlist rules and --show; understand why selecting candidates matters more than immediately running exhaustive incremental search.

**For the flight:** Save the examples and prepare a tiny synthetic hash file and wordlist. The page teaches general John behavior; Jumbo-specific formats and extractors need the installed build’s help.

<a id="crypto-foundations-8"></a>

**[bkcrack: official encrypted-ZIP tutorial](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)** — kimci86 / bkcrack project · practice · next · about 40 min.

**Tools:** bkcrack. Inspect ZipCrypto versus compression, identify known plaintext, recover internal keys and decrypt the provided public example. Keys can recover data without first recovering the original password.

**For the flight:** Before departure, obtain the public repository’s example/secrets.zip and tutorial plus a working bkcrack binary; test on your own device. Nothing downloaded here. Targets ZipCrypto, not AES ZIP; at least 12 known bytes are needed, including 8 contiguous bytes.

<a id="crypto-foundations-9"></a>

**[crypto-attacks: requirements and worked Boneh–Durfee example](https://github.com/jvdsn/crypto-attacks)** — jvdsn / crypto-attacks contributors · read · next · about 35 min.

**Tools:** crypto-attacks, SageMath. See how an attack implementation consumes mathematical parameters and how its test data provides a reproducible starting point. Advanced follow-up after basic RSA and Sage, not a universal one-command solver.

**For the flight:** Save the repository and its test data beforehand if pursuing this optional exercise. README requires Sage with Python 3.9 and PyCryptodome; test compatibility with the actual environment before travel.

### Important version and tutorial notes

- The Sleuth Kit filesystem scenario is old and mixes offset coordinate systems in one `dd` example. Use its `blkcalc`/`blkcat` explanation; do not copy the `dd` line blindly.
- The DFIRScience companion notes contain apparent command typos. Use the linked official Volatility 3 tutorial for command spelling; Volatility 2 uses different profiles and plugins.
- Burp Community is the approved edition. Stay with Proxy/Repeater and manual testing; scanner, Collaborator and full Intruder workflows need a different edition. See [PortSwigger’s edition comparison](https://portswigger.net/burp/communitydownload).
- The workbook names an SSTV decoder but records `PySSTV`, an encoder, as its installation. SageMath has no installation information recorded. Treat both as unresolved until checked locally.
- Binwalk major versions differ; the workbook says “Latest.” Current upstream tutorials do not prove which build is installed.
- OSINT has no dedicated course in this shortlist. Subfinder is in the approved index, but its data sources need connectivity; metadata inspection is covered by ExifTool.


## Evidence and limits

The shortlist contains **44 resources: 31 readings, 9 videos, and 4 practice resources**. Their individual study estimates total 1095 minutes; the 24-hour path leaves the balance for repetition, notes and your chosen specialist gaps. Do not add the schedule and resource estimates together.

The five research lanes inspected selected primary documentation and creator material on 22 October. Videos were checked through metadata, descriptions and available transcripts, not watched end to end. The all-tool index preserves earlier per-tool documentation and link-check evidence from 19 October; those references were not all re-researched today. A metadata-only, redundant steghide video was removed during curation.

Detailed source checks, approval-row mappings and limitations are in [the research data](research/learning-resources.json). Independent review and resulting changes are recorded in [the review](research/learning/review.md). No installed tool behavior, video offline playback, or practice exercise completion is claimed.
