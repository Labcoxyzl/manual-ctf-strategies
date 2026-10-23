# Approved-tool learning collection: depth beyond the starter videos

**The old video pack is 1:43:34, not twelve hours.** Its six first-pass recommendations total 1:28:21. The earlier 24-hour plan included reading, practice and assessment. The full caption audit finds **4 workflow mappings, 7 introductory mappings, 4 incidental mentions and 185 rows without direct video instruction**. There is **no deep-video coverage** in that original set. These counts are inventory rows, not unique tools or proof that every row needs a video.

This collection adds **nine substantively inspected video candidates/lessons** with verified metadata: full new runtime **6:57:20**. All 17 linked videos total **8:40:54**, still under 12 hours. Recommended sections of the new videos total **4:41:38**; retained MFTECmd/Volatility workflow sections add **39:12**. Full runtimes include explicitly skipped material; reading/practice estimates are never added to video time.

## What to do first

Use the original short clips only when you fail a quick tool-orientation check. For depth, work by capability below: read the focused source, predict a result before the demonstration, then reproduce a small example or explain the provided answer. Choose tracks by the files and skills you expect to handle, not by a desire to fill twelve hours.

All 200 exact organiser rows remain in the [coverage matrix](TOOL_COVERAGE_MATRIX.md). The audit assigns 48 high-priority rows, 47 specialist, 32 alternative and 73 supporting rows as **preparation judgments**. The organiser approved availability, not this priority ranking. No unseen challenge is predicted. [Original source notes](EVENT_SOURCES.md).

This is an expanded depth menu, not a promise to finish every branch during one flight. The [earlier 24-hour refresher](LEARNING_RESOURCES.md) and [keyed worksheets](PRACTICE_WORKSHEETS.md) remain a starter route. Reading/practice ranges below are planning estimates, not measured completion times.

## Prioritized capability tracks

### 1. Binary triage: identify and validate

[Binwalk: file analysis and extraction](TOOL_RESOURCE_CATALOG.md#media-2) · [ExifTool: application documentation and reading examples](TOOL_RESOURCE_CATALOG.md#media-3) · [Strings, encodings and raw byte offsets](TOOL_RESOURCE_CATALOG.md#practice:triage)

**Outcome/check:** Known bytes → file identity/metadata → candidate embedded objects. Verify an offset/encoding or extracted format instead of trusting a signature.

**Planning estimate:** 25–40 min reading;20–30 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 2. Images and audio

[zsteg: detection and extraction examples](TOOL_RESOURCE_CATALOG.md#media-1) · [Stegseek: wordlist mode, seed mode and steghide compatibility](TOOL_RESOURCE_CATALOG.md#media-4) · [Audacity: Spectrogram View](TOOL_RESOURCE_CATALOG.md#media-5) · [Resolve nearby tones in a known WAV](TOOL_RESOURCE_CATALOG.md#practice:audio)

**Outcome/check:** Choose PNG/BMP LSB versus steghide carrier processing; validate candidates. Compare time/frequency windows on the bundled known-tone WAV.

**Planning estimate:** 35–50 min reading;30–45 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 3. Packets and network evidence

[SF19US - 22 Analyzing Windows malware traffic w/ Wireshark Part 1](TOOL_RESOURCE_CATALOG.md#forensics-deeper-video-1) · [Wireshark: display filters and following protocol streams](TOOL_RESOURCE_CATALOG.md#web-network-5) · [TShark manual: saved captures and display filters](TOOL_RESOURCE_CATALOG.md#web-network-6) · [Zeek quick start: turn a PCAP into correlated logs](TOOL_RESOURCE_CATALOG.md#web-network-7)

**Outcome/check:** Identify hosts/users, follow conversations, recognize malicious requests even with HTTP404, then extract fields with TShark or correlate Zeek UID logs.

**Planning estimate:** 20–30 min reading;45–60 min practice, plus selected video. Stop when you can explain the result and a failure mode without copying the answer.

### 4. Disk and filesystems

[Sleuth Kit: list files and recover by metadata address](TOOL_RESOURCE_CATALOG.md#forensics-1) · [TSK partition layout and sector units](TOOL_RESOURCE_CATALOG.md#forensics-mmls) · [Autopsy Quick Start Guide](TOOL_RESOURCE_CATALOG.md#forensics-2) · [Local closed-note forensic and packet cases](TOOL_RESOURCE_CATALOG.md#forensics-current-worksheets)

**Outcome/check:** Find a partition, keep sector/byte/metadata units separate, recover a chosen file and assess recovery limits. In Autopsy, trace a result back to its source.

**Planning estimate:** 45–60 min reading;45–60 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 5. Windows artifact correlation

[Introduction to Windows Forensics](TOOL_RESOURCE_CATALOG.md#forensics-deeper-video-2) · [LNK Files and Jump Lists](TOOL_RESOURCE_CATALOG.md#forensics-deeper-video-3) · [PECmd input selection and exports](TOOL_RESOURCE_CATALOG.md#forensics-pecmd) · [JLECmd current options companion](TOOL_RESOURCE_CATALOG.md#forensics-jlecmd) · [Chainsaw: searching and hunting Windows event logs](TOOL_RESOURCE_CATALOG.md#forensics-7) · [Microsoft Incident Response: artifact facts, pitfalls and applications](TOOL_RESOURCE_CATALOG.md#forensics-artifact-interpretation)

**Outcome/check:** Follow registry/USB/LNK/JumpList/Prefetch/EVTX evidence across artifacts. Distinguish presence, access, execution, timestamp meaning and file-entry reuse.

**Planning estimate:** 45–60 min targeted reading;60–90 min practice, plus selected videos. Stop when you can explain the result and a failure mode without copying the answer.

### 6. Memory analysis

[Volatility 3: Windows Tutorial](TOOL_RESOURCE_CATALOG.md#forensics-3) · [Introduction to Memory Forensics with Volatility 3](TOOL_RESOURCE_CATALOG.md#forensics-4) · [Local closed-note forensic and packet cases](TOOL_RESOURCE_CATALOG.md#forensics-current-worksheets) · [Volatility: diagnose layer and symbol requirements](TOOL_RESOURCE_CATALOG.md#capability:volatility-symbols)

**Outcome/check:** Select process/handle/network/registry evidence; extract a particular file; diagnose layer/symbol requirements, correct known prerequisites and corroborate names/ancestry without promising every input is recoverable.

**Planning estimate:** 30–45 min reading;45–60 min practice, plus retained video. Stop when you can explain the result and a failure mode without copying the answer.

### 7. HTTP requests, sessions and discovery

[Everything curl: Command line HTTP](TOOL_RESOURCE_CATALOG.md#web-network-3) · [ffuf upstream examples: discovery, filters and bounded runs](TOOL_RESOURCE_CATALOG.md#web-network-4) · [Nmap reference: interpret ports, services and saved results](TOOL_RESOURCE_CATALOG.md#web-network-9) · [Nmap suite: discovery, Ncat byte streams and Nping probes](TOOL_RESOURCE_CATALOG.md#capability:nmap-bundle)

**Outcome/check:** Preserve requests and cookies, compare baselines, select/filter discovery candidates, interpret service states and distinguish Ncat byte streams from conditional Nping probes.

**Planning estimate:** 30–45 min reading;45–60 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 8. Web vulnerability workflows

[Broken Access Control \| Complete Guide](TOOL_RESOURCE_CATALOG.md#video:_jz5qFWhLcg) · [Access control: concepts and request-level failure cases](TOOL_RESOURCE_CATALOG.md#web-depth-access) · [Burp lab: controlled ID parameter](TOOL_RESOURCE_CATALOG.md#web-depth-idor) · [Burp lab: password reset broken logic](TOOL_RESOURCE_CATALOG.md#web-depth-reset) · [sqlmap request preservation and result comparison](TOOL_RESOURCE_CATALOG.md#web-depth-sqlmap) · [JWT testing methodology with jwt_tool and Burp](TOOL_RESOURCE_CATALOG.md#web-depth-jwt)

**Outcome/check:** Use authorized-user controls, distinguish authentication from authorization, test one parameter/state change, interpret dynamic responses and preserve sessions.

**Planning estimate:** 45–75 min reading;60–90 min practice, plus selected video. Stop when you can explain the result and a failure mode without copying the answer.

### 9. Native reversing and debugging

[Ghidra training: reconstruct types and program structure](TOOL_RESOURCE_CATALOG.md#ghidra-training) · [HackadayU: Reverse Engineering with Ghidra Class 3](TOOL_RESOURCE_CATALOG.md#reverse-depth-video-1) · [HackadayU: Reverse Engineering with Ghidra Class 4](TOOL_RESOURCE_CATALOG.md#reverse-depth-video-2) · [GDB memory examination and watchpoint exercises](TOOL_RESOURCE_CATALOG.md#reverse-depth-gdb) · [Unpacking Redaman Malware & Basics of Self-Injection Packers - ft. OALabs](TOOL_RESOURCE_CATALOG.md#reverse-depth-video-3)

**Outcome/check:** Recover structures/pointers, reconcile decompilation with assembly, repair memory maps and use breakpoints/watchpoints to test a decoding hypothesis.

**Planning estimate:** 60–90 min reading;60–90 min practice, plus selected videos. Stop when you can explain the result and a failure mode without copying the answer.

### 10. Managed code, APKs and Python packages

[AsyncRAT: trace settings and reconstruct configuration decoding](TOOL_RESOURCE_CATALOG.md#reverse-depth-dotnet) · [Malware Analysis - Unpacking NetWiredRC With DnSpy](TOOL_RESOURCE_CATALOG.md#reverse-depth-dotnet-dynamic) · [dnSpy module view and module-load breakpoints](TOOL_RESOURCE_CATALOG.md#reverse-depth-dotnet-modules) · [Android App RE: JADX entry points, DEX logic and JNI](TOOL_RESOURCE_CATALOG.md#reverse-depth-android) · [Apktool 2.x: choose resource and DEX decoding modes](TOOL_RESOURCE_CATALOG.md#reverse-depth-apktool) · [PyInstaller extraction to version-aware bytecode analysis](TOOL_RESOURCE_CATALOG.md#reverse-depth-python)

**Outcome/check:** Route by format; trace.NET settings or an already-extracted stage, inspect DEX/JNI boundaries, and choose a Python decompiler by bytecode version.

**Planning estimate:** 60–90 min selected reading;45–90 min practice, plus selected.NET clip. Stop when you can explain the result and a failure mode without copying the answer.

### 11. Malware triage and detection

[Detect It Easy CLI: file identity, entropy and heuristic comparison](TOOL_RESOURCE_CATALOG.md#reverse-depth-die) · [capa: interpret matches and test the evidence](TOOL_RESOURCE_CATALOG.md#reverse-depth-capa) · [FLOSS: string categories, offsets and targeted decoding](TOOL_RESOURCE_CATALOG.md#reverse-depth-floss) · [YARA rule semantics and positive/negative checks](TOOL_RESOURCE_CATALOG.md#reverse-depth-yara) · [UPX list, test and decompress boundaries](TOOL_RESOURCE_CATALOG.md#reverse-depth-upx)

**Outcome/check:** Treat packer/signature/capability matches as leads. Inspect evidence addresses, recover decoded strings and test rules against positive/negative controls.

**Planning estimate:** 45–60 min reading;45–60 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 12. PDF and Office objects

[qpdf dictionary, raw stream and decoded stream](TOOL_RESOURCE_CATALOG.md#practice:qpdf) · [qpdf: PDF inspection options](TOOL_RESOURCE_CATALOG.md#forensics-6) · [Nested PDF→Office payload analysis](TOOL_RESOURCE_CATALOG.md#reverse-depth-documents) · [olevba: extraction, decoded strings and triage interpretation](TOOL_RESOURCE_CATALOG.md#reverse-depth-olevba) · [oletools suite: extract objects and choose the right parser](TOOL_RESOURCE_CATALOG.md#capability:oletools-suite)

**Outcome/check:** Choose dictionaries versus decoded streams, inspect nested payloads/macros without opening active content, and retain extraction/interpretation limits.

**Planning estimate:** 30–45 min reading;30–45 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 13. RSA, symmetric crypto and encrypted archives

[RsaCtfTool: usage and attack prerequisites](TOOL_RESOURCE_CATALOG.md#crypto-foundations-4) · [SageMath tutorial: number theory](TOOL_RESOURCE_CATALOG.md#crypto-foundations-5) · [RSA common-modulus prerequisites and derivation](TOOL_RESOURCE_CATALOG.md#crypto-depth-common-modulus) · [RSA modulus recovery: gcd and ambiguity](TOOL_RESOURCE_CATALOG.md#crypto-depth-recover-modulus) · [OpenSSL 3 decryption parameters and validation](TOOL_RESOURCE_CATALOG.md#crypto-depth-openssl) · [bkcrack 1.8.1: stored-plaintext ZIP recovery](TOOL_RESOURCE_CATALOG.md#crypto-foundations-8)

**Outcome/check:** Check assumptions before selecting an attack. Derive modular operations, validate output, preserve IV/salt/KDF details and distinguish ZipCrypto from AES.

**Planning estimate:** 60–90 min reading;45–75 min practice. Stop when you can explain the result and a failure mode without copying the answer.

### 14. Password recovery

[Password Cracking with Hashcat](TOOL_RESOURCE_CATALOG.md#video:XkLCEhEJuSI) · [hashcat: dictionary attacks with a tiny wordlist](TOOL_RESOURCE_CATALOG.md#crypto-foundations-6) · [Hashcat rule transformations and controlled candidate generation](TOOL_RESOURCE_CATALOG.md#crypto-depth-rules) · [John the Ripper: usage examples](TOOL_RESOURCE_CATALOG.md#crypto-foundations-7)

**Outcome/check:** Identify the supplied hash context, control wordlist/rule/mask candidates, preserve potfiles and compare failures against a known toy input.

**Planning estimate:** 25–40 min reading;30–45 min practice, plus selected video. Stop when you can explain the result and a failure mode without copying the answer.

### 15. Data handling helpers

[Python 3.11 binary files and JSON](TOOL_RESOURCE_CATALOG.md#utility-depth-python-io) · [jq applied JSON filtering tutorial](TOOL_RESOURCE_CATALOG.md#utility-depth-jq) · [ripgrep (rg): focused reference](TOOL_RESOURCE_CATALOG.md#ref:kali-119)

**Outcome/check:** Read binary versus text, process JSON safely and diagnose why recursive search omitted hidden, ignored or binary input.

**Planning estimate:** 25–40 min reading;20–30 min practice. Stop when you can explain the result and a failure mode without copying the answer.

## Deeper video selections

All runtimes below were obtained directly from YouTube metadata; original-English captions are retained with hashes. Selection is supported by substantive captions, creator worked content or both. Videos were not watched end to end. Follow the selected sections, not unapproved tools elsewhere in the recording.

| Video | Full runtime | Selected sections / total | Why it adds depth |
| --- | --- | --- | --- |
| [SF19US - 22 Analyzing Windows malware traffic w/ Wireshark (Part 1)(Brad Duncan)](https://www.youtube.com/watch?v=eQItiKZpuSc) | 1:28:53 | 5:11–12:36, 25:11–30:59, 36:21–1:06:12, 1:09:46–1:28:53 / **1:02:11** | [SF19US - 22 Analyzing Windows malware traffic w/ Wireshark Part 1](TOOL_RESOURCE_CATALOG.md#forensics-deeper-video-1) |
| [Introduction to Windows Forensics](https://www.youtube.com/watch?v=VYROU-ZwZX8) | 1:04:33 | 2:55–3:30, 3:40–22:46, 23:28–53:29 / **49:42** | [Introduction to Windows Forensics](TOOL_RESOURCE_CATALOG.md#forensics-deeper-video-2) |
| [LNK Files and Jump Lists](https://www.youtube.com/watch?v=wu4-nREmzGM) | 26:59 | 1:04–26:59 / **25:55** | [LNK Files and Jump Lists](TOOL_RESOURCE_CATALOG.md#forensics-deeper-video-3) |
| [HackadayU: Reverse Engineering with Ghidra Class 3](https://www.youtube.com/watch?v=RFG5FuqY0CE) | 1:00:39 | 8:03–51:02 / **42:59** | [HackadayU: Reverse Engineering with Ghidra Class 3](TOOL_RESOURCE_CATALOG.md#reverse-depth-video-1) |
| [HackadayU: Reverse Engineering with Ghidra Class 4](https://www.youtube.com/watch?v=5QBXNF7FKxM) | 52:42 | 3:14–25:39, 45:00–52:42 / **30:07** | [HackadayU: Reverse Engineering with Ghidra Class 4](TOOL_RESOURCE_CATALOG.md#reverse-depth-video-2) |
| [Unpacking Redaman Malware & Basics of Self-Injection Packers - ft. OALabs](https://www.youtube.com/watch?v=YXnNO3TipvM) | 26:18 | 1:25–4:55, 5:45–10:02, 19:33–21:53 / **10:07** | [Unpacking Redaman Malware & Basics of Self-Injection Packers - ft. OALabs](TOOL_RESOURCE_CATALOG.md#reverse-depth-video-3) |
| [Malware Analysis - Unpacking NetWiredRC With DnSpy](https://www.youtube.com/watch?v=dLIbkg_8O68) | 27:05 | 13:00–16:30 / **3:30** | [Malware Analysis - Unpacking NetWiredRC With DnSpy](TOOL_RESOURCE_CATALOG.md#reverse-depth-dotnet-dynamic) |
| [Broken Access Control \| Complete Guide](https://www.youtube.com/watch?v=_jz5qFWhLcg) | 39:32 | 2:25–34:40 / **32:15** | [Broken Access Control \| Complete Guide](TOOL_RESOURCE_CATALOG.md#video:_jz5qFWhLcg) |
| [Password Cracking with Hashcat](https://www.youtube.com/watch?v=XkLCEhEJuSI) | 30:39 | 3:00–27:52 / **24:52** | [Password Cracking with Hashcat](TOOL_RESOURCE_CATALOG.md#video:XkLCEhEJuSI) |

Skip IDA/PE-Bear portions in the Redaman lesson; use only the selected x64dbg operations. The .NET clip begins with an already-extracted stage and stops before de4dot. The Windows lesson omits FTK acquisition: start with supplied/pre-extracted hives. It also omits NirSoft Prefetch demonstration; use the approved PECmd guide. Historical UI/API simplifications are called out in the catalog.

## Free access and offline preparation

The required study routes can be completed without purchases. Public guide reading is distinct from product licensing: Sublime continued-use licensing and BinDiff’s excluded paid-build/disassembler paths are disclosed in the matrix and access records. Approved free editors and Ghidra routes keep those purchases optional. Guides and public worked solutions are free to read. Hosted Academy execution requires a free account and network; saved solutions do not preserve the server. No account is required for the local paper and synthetic-file routes. YouTube documents computer downloads through a **signed-in paid Premium account**, subject to availability and reconnection limits ([official guidance](https://support.google.com/youtube/answer/11977233?hl=en)). No subscription is required for this collection’s reading routes. Public video streaming is distinct from free offline downloading; each video has a useful free reading alternative in the [catalog](TOOL_RESOURCE_CATALOG.md), which may teach the same skill without reproducing the entire case.

The eight previously saved local MP4s can be played without buying YouTube Premium; that download-button policy does not add a fee to existing files. The nine added videos remain public streaming/reading routes, not locally downloaded videos.

Only needed metadata and captions were fetched in this goal. The eight existing MP4s are reused; no extra videos, malware collections or portal challenges were downloaded/launched, and no revised material was sent automatically. Save selected text/figures and test your chosen applications before departure.

## Evidence and limits

[Complete data and source observations](research/learning/video-coverage/collection.json) · [full matrix CSV](research/learning/video-coverage/coverage.csv) · [review](research/learning/video-coverage/review.md) · [per-source access audit](research/learning/video-coverage/access-audit.md) · [checks](research/learning/video-coverage/validation.json).

Important capabilities now have focused instruction plus worked examples or explicit checks. Specialist/support/alternative rows keep exact references and input-triggered dispositions; those references do not claim deep proficiency. Untested playback, GUI and malware/image execution remain untested. Source inspection and synthetic checks are not measured learning gains.
