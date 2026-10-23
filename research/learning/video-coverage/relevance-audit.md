# Independent relevance and duplication audit

Reviewed 2026-10-23 against the supplied comprehensive-learning-collection goal. Scope: all 79 non-reference instruction records and 17 video selections in the candidate, their actual claimed skills, prerequisites, approval restrictions and overlap. This is an independent review, not a new course-selection exercise. The integration owner owns repairs.

## Findings — resolved in focused recheck

The descriptions below preserve the initial findings. Both are closed by the focused repair recheck at the end of this report.

### R1 — merge duplicate Autopsy quick-start assignments (low)

**Locations:** `forensics-2`, `forensics-autopsy-workflow`, and `windows-34.learning_resource_ids` in collection.json; both corresponding catalog entries.

The row assigns two selected lessons based on the same Quick Start Guide, at versions 4.22.0 and 4.20.0. The first is labeled targeted and the second workflow, but both assign case creation, source selection, ingest, result navigation and export. The older entry adds timeline/partial-ingest interpretation that is also present in the newer source. Fresh primary reads confirm identical relevant instruction. No version-specific learning distinction or choose-one instruction justifies two records. This is unnecessary duplication under the explicit goal, not a reason to discard Autopsy instruction.

**Minimal repair:** consolidate the richer scope and evidence into `forensics-2` using the already selected 4.22.0 guide; retain an alias if old IDs need compatibility, and map the row to one assignment. Preserve the original organiser reference separately. No replacement course is needed.

Primary sources: [4.20 guide](https://www.sleuthkit.org/autopsy/docs/user-docs/4.20.0/quick_start_guide.html), [4.22 guide](https://www.sleuthkit.org/autopsy/docs/user-docs/4.22.0/quick_start_guide.html). Freshly inspected case/data-source, ingest, analysis, other interfaces and example-case sections.

### R2 — memory track overstates symbol-error diagnosis (low)

**Locations:** `TOOL_LEARNING_COLLECTION.md`, track 6 outcome “resolve symbol failure”; `windows-31` maps `forensics-3`, `forensics-4`, `forensics-current-worksheets`.

These are relevant memory-analysis resources, but the advertised troubleshooting outcome is not demonstrated. The [official Windows tutorial](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html), freshly read, explains automatic Microsoft PDB acquisition and gives pslist/pstree/hashdump output. It does not diagnose unsatisfied symbol/layer requirements. The local worksheet, lines 93–97 and 118–126, teaches online preflight and recognizing that failed analysis is not a negative finding. Fresh caption search of `Uk3DEgY5Ue8` finds a symbol-path/download mention at 05:21–05:29, outside its selected start of 05:50, and no symbol-failure investigation. Going online again does not itself distinguish a missing symbol from an invalid/incompatible image.

**Minimal repair:** either add a focused, inspected primary troubleshooting/symbol companion and a small diagnostic check, or narrow the outcome to staging/caching prerequisites and recognizing failed analysis. Do not imply that the existing lesson resolves arbitrary layer/symbol failures. No replacement video is needed, and this finding does not deny the substantial process/handle/network/registry workflow already taught.

## Relevance and overlap conclusions

The remaining selections have concrete approved-tool applications. Reused valid substantive observations are adequate evidence for undisputed sources; I did not treat a prior reviewer verdict or a role label as proof. Important distinctions checked:

- zsteg channel/order extraction, Stegseek seed limitations, Audacity time/frequency tradeoffs and FFmpeg stream selection are distinct operations. Sonic Visualiser's optional video shows timing/metadata reasoning; its later online decoding is explicitly excluded from event use.
- Wireshark's multi-PCAP workshop adds host/user attribution and malware traffic interpretation; filter/stream references, TShark fields and Zeek UID logs teach distinct operations. The optional HTTP sample is transfer practice, not a mandatory repeated lesson.
- TSK offsets/metadata recovery, Autopsy GUI ingest, memory investigation and Windows artifacts are not interchangeable. PECmd/JLECmd references supply current parsing options; the Microsoft interpretation guide supplies presence-versus-execution limits. R1 is the actual redundant pair.
- Ghidra classes 3/4 add type reconstruction, linked-library analysis, version tracking and memory/API concepts beyond the optional crackme. The written Ghidra source is an offline alternative and source-exercise companion. Fresh class-4 caption inspection confirms concrete import paths, missing symbols, correlation settings, address objects and API examples, not merely a feature list. Eclipse is mentioned near 45:00, but the selected useful scripting passage uses Ghidra's built-in Python interface; no mandatory Eclipse installation is assigned.
- The x64dbg and dnSpy clips isolate approved debugging operations. Already-extracted input and prepared-lab prerequisites remain explicit. The dnSpy module-view guide is correctly not claimed to reproduce byte-array dumping. Android's static DEX/JNI workshop and Apktool's bounded decode options teach different operations. Python extraction and decompiler compatibility have direct companion links.
- capa/FLOSS/YARA/Detect It Easy/UPX cover different triage questions and preserve false-positive/version limits. The Didier Stevens PDF-to-Office case teaches its own suite; qpdf has its own object/stream practice. olevba adds a separate macro-triage interface.
- Burp basics, authorization controls, reset logic, sqlmap response comparison and JWT control tests are distinct. The access-control video is expressly conceptual; actual request mutation is supplied by public written lab solutions. Community-compatible operations and account/network execution requirements are visible.
- RSA parameter recovery/common-modulus reasoning, OpenSSL parameter selection, ZipCrypto known plaintext and password candidate generation are different capabilities. Hashcat's guide/video overlap serves the stated optional orientation/offline roles; rule and mask cases add substance. No duration quota justifies extra lessons.
- jq, Python IO and ripgrep are applied supporting skills, with concrete JSON, byte/text and omitted-hit behavior. They do not need broad programming courses.

## Video content and dependency checks

All 17 video records were considered alongside their resource claims and existing substantive caption assessments. Fresh local caption passages were checked for Sonic Visualiser, CyberChef, Ghidra class 4, Hashcat and Volatility uncertainties. Existing timestamped content evidence was reused for other videos; this is not a claim of fresh full-transcript rereading or playback of all 17.

CyberChef `UtqmiI7k9lU` at 01:38–03:22 provides a self-created reverse/Base64/octal example. At 03:24 it switches to the course file, then demonstrates ROT13/Base64/gzip/binary/hex reasoning through 06:25. The collection explicitly says that later file is not supplied and offers a self-created first example; the absent course input is therefore not a hidden paid prerequisite. The NetWiredRC/Redaman/Windows-artifact restrictions remain explicit. Free-reading alternatives need not duplicate the complete video case; they must support the stated skill and remain described with their limits, as they are here.

No additional unapproved mandatory dependency, paid-content prerequisite, unrelated selected subject or material duplicate was established beyond R1. This review does not certify every current upstream option or organiser installation.

## Selected-record audit ledger

Each listed record was checked against its skills, prerequisite/limit text and substantive source observation. “Retain” means no material relevance/duplication defect established within this scope; it does not claim playback, execution or advanced mastery.

| Resource | Result |
| --- | --- |
| `media-1` | Retain |
| `media-2` | Retain |
| `media-3` | Retain |
| `media-4` | Retain |
| `media-5` | Retain |
| `media-6` | Retain |
| `media-7` | Retain |
| `media-8` | Retain |
| `web-network-5` | Retain |
| `web-network-6` | Retain |
| `web-network-7` | Retain |
| `web-network-8` | Retain |
| `forensics-1` | Retain |
| `forensics-2` | R1: merge duplicate source |
| `forensics-3` | Retain; track-level outcome subject to R2 |
| `forensics-4` | Retain; track-level outcome subject to R2 |
| `forensics-5` | Retain |
| `forensics-6` | Retain |
| `forensics-7` | Retain |
| `forensics-8` | Retain |
| `forensics-autopsy-workflow` | R1: merge duplicate source |
| `forensics-mmls` | Retain |
| `forensics-pecmd` | Retain |
| `forensics-jlecmd` | Retain |
| `forensics-current-worksheets` | Retain; track-level outcome subject to R2 |
| `forensics-deeper-video-1` | Retain |
| `forensics-deeper-video-2` | Retain |
| `forensics-deeper-video-3` | Retain |
| `forensics-artifact-interpretation` | Retain |
| `reverse-depth-video-1` | Retain |
| `reverse-depth-video-2` | Retain |
| `reverse-depth-video-3` | Retain |
| `reverse-depth-gdb` | Retain |
| `reverse-depth-android` | Retain |
| `reverse-depth-apktool` | Retain |
| `reverse-depth-dotnet` | Retain |
| `reverse-depth-python` | Retain |
| `reverse-depth-capa` | Retain |
| `reverse-depth-floss` | Retain |
| `reverse-depth-yara` | Retain |
| `reverse-depth-documents` | Retain |
| `reverse-depth-olevba` | Retain |
| `reverse-depth-upx` | Retain |
| `reverse-depth-die` | Retain |
| `reverse-depth-dotnet-dynamic` | Retain |
| `reverse-depth-dotnet-modules` | Retain |
| `web-network-1` | Retain |
| `web-network-2` | Retain |
| `web-network-3` | Retain |
| `web-network-4` | Retain |
| `web-network-9` | Retain |
| `crypto-foundations-1` | Retain |
| `crypto-foundations-2` | Retain |
| `crypto-foundations-3` | Retain |
| `crypto-foundations-4` | Retain |
| `crypto-foundations-5` | Retain |
| `crypto-foundations-6` | Retain |
| `crypto-foundations-7` | Retain |
| `crypto-foundations-8` | Retain |
| `web-depth-access` | Retain |
| `web-depth-idor` | Retain |
| `web-depth-reset` | Retain |
| `web-depth-sqlmap` | Retain |
| `web-depth-jwt` | Retain |
| `crypto-depth-openssl` | Retain |
| `crypto-depth-rules` | Retain |
| `crypto-depth-common-modulus` | Retain |
| `crypto-depth-recover-modulus` | Retain |
| `utility-depth-jq` | Retain |
| `utility-depth-python-io` | Retain |
| `ref:kali-119` | Retain |
| `reverse-2` | Retain |
| `reverse-3` | Retain |
| `video:_jz5qFWhLcg` | Retain |
| `video:XkLCEhEJuSI` | Retain |
| `practice:audio` | Retain |
| `practice:triage` | Retain |
| `practice:qpdf` | Retain |
| `ghidra-training` | Retain |

## Candidate identity and limits

- `5877ebe362ec36ea05969d3b2cc29e9d4a7d69d9ef272f3dde13c7292dde849c` — `TOOL_LEARNING_COLLECTION.md`
- `5fafa1399f9dfad492a5aba9e1e618d365dc8634359f7cecf550d153d52414f6` — `TOOL_RESOURCE_CATALOG.md`
- `17e6e9a89510b7be8d1bd3ec02d493534f5d3a22a741401671fcd8c940e8215e` — `research/learning/video-coverage/collection.json`

No accounts, downloads, installs, tool execution, full video playback or hosted labs were performed. Link/access/runtime arithmetic is owned by the other review lanes; this report does not replace those checks. Only this report was written.

## Focused repair recheck — R1 and R2 resolved

Rechecked only the accepted findings and their changed scope on 2026-10-23. R1 is resolved: `forensics-autopsy-workflow` is absent from selected resources, its alias resolves to `forensics-2`, and `windows-34` assigns only the consolidated 4.22.0 guide. Its richer ingest, source-pivot, timeline and partial-result skills are retained. The original 79-record ledger above is the initial review snapshot, not the current selected-record count.

R2 is resolved: track 6 and `windows-31` now link `capability:volatility-symbols`, whose local route distinguishes input/layer failure from symbol identity and discovery, supplies ordered decisions and known-answer checks, and preserves unresolved outcomes. Fresh primary reads of the [symbol-table guide](https://volatility3.readthedocs.io/en/latest/symbol-tables.html) and [CLI requirement/error handling](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/cli.html) support the route: Windows PDB identity and exact Linux/macOS banners; input existence/readability/acquisition checks before symbols; and incomplete analysis when requirements fail. The revised outcome promises diagnosis and correction of known prerequisites rather than universal recovery. The route does not require executing the linked symbol-generation build steps.

No new material relevance/duplication issue was established in these repairs. Unrelated new capability routes belong to their assigned reviewers; this focused recheck does not certify them. No GUI, memory-image, symbol-download or Volatility execution was performed.

Current candidate hashes:

- `c7e1fe5001a0347fea6834612bc269218f55d85fb3912d4cd8f7c585dbe7114c` — `TOOL_LEARNING_COLLECTION.md`
- `2baab8e8e666be37f970533bdaeb6363b281e1736e742e9fe075923131541d5b` — `TOOL_RESOURCE_CATALOG.md`
- `d97b95ed626e65dd46ca9132955d11c1ab1ba1bc735f655f6f63d93d0447c417` — `research/learning/video-coverage/collection.json`
- `ca98fe9242496d953c70571b3f51740f97e1c3cac5b9a8515aea01517a91cace` — `research/learning/video-coverage/practice/CAPABILITY_ROUTES.md`
