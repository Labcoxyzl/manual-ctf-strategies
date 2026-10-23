# Competition utility review

Reviewed the five frozen resource JSON files and `guide-template.html` on 2026-10-22. This is an editorial ranking from the recorded task fit and evidence, not a measured speed benchmark or an independent revalidation of the linked pages. The 200 catalog entries should remain searchable; “core” does not mean every entry deserves a starter recipe.

Selection order: (1) observable input selects the route, (2) one default gets an interpretable result, (3) a direct worked example beats a broad reference for the first click, (4) an alternative earns space only through a distinct input, limitation or workflow. Known platform and version caveats override these preferences. Within each category below, rows are recommended display order, not predicted challenge frequency.

## Recommended starter routes

Use 24 routes total, with one short procedure and expected result per route. These are editorial proposals; the JSON candidates are not execution-tested instructions.

### Digital Forensics — four routes

1. **PCAP → conversation → recovered content.** Default `windows-2` Wireshark and its [Follow Stream guide](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html). `windows-36` tshark only for repeatable field extraction; `windows-18` Zeek for a broad connection/protocol summary before choosing a stream. Do not display three coequal starting tools. Encrypted or incomplete captures may yield no recoverable object.
2. **Disk image → partition → named file.** Default `windows-23` Sleuth Kit [fls reference](https://www.sleuthkit.org/sleuthkit/man/fls.html); preserve the partition-offset prerequisite in the authored recipe. `windows-34` Autopsy is the GUI alternative; `kali-143` PhotoRec is conditional on unusable filesystem metadata. Carving loses names/context and is not the default.
3. **Memory image → process/network lead.** Default `windows-31` Volatility 3 [Windows tutorial](https://volatility3.readthedocs.io/en/latest/getting-started-windows-tutorial.html). `kali-151` Volatility 2 only for a supported legacy image and matching profile; community plugins and `kali-32` dwarf2json belong in prerequisites/fallbacks, not parallel starters.
4. **Image/audio/PDF → format-specific inspection.** A compact format selector, not one combined command chain: PNG/BMP: `windows-14` ExifTool → `kali-108` pngcheck if PNG → `windows-12` [zsteg examples](https://github.com/zed-0xff/zsteg); audio: `kali-10` [Audacity spectrogram](https://manual.audacityteam.org/man/spectrogram_view.html); PDF: `windows-26` [qpdf inspection](https://qpdf.readthedocs.io/en/stable/cli.html). Conditional links: `kali-40` FFmpeg to isolate a stream; `kali-134` steghide with a supplied password or `kali-135` stegseek for an evidenced steghide carrier. Do not run every stego tool on every image.

The fourth route is broad because the four-route limit otherwise hides an entire artifact family. SQLite, registry and EVTX should be immediately visible in the expanded forensic artifact index, with `kali-131`, `kali-118`, `kali-20` respectively; avoid relocating EVTX exclusively to Malware.

### Malware Analysis — three routes

1. **Unknown executable → format and useful functions.** `kali-27` [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) identifies likely format/packer, then `kali-19` [capa](https://github.com/mandiant/capa) supplies capability evidence. `kali-43` FLOSS is conditional when useful strings are obscured. Cross-link native reversing rather than repeat Ghidra instructions. Packer guesses and capability matches are leads, not proof.
2. **Office/PDF document → macro or embedded object.** Office: `kali-98` [olevba guide](https://github.com/decalage2/oletools/wiki/olevba); PDF: `kali-30` [Didier Stevens PDF tools](https://blog.didierstevens.com/programs/pdf-tools/). `kali-105` peepdf only when interactive object-graph inspection adds value; `kali-29` onedump only for OneNote. Generic qpdf belongs in the forensic route and can be linked here.
3. **Identified bundle → extract before analysis.** `kali-111` [pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng) for PyInstaller; `kali-9` asar for Electron; `kali-149` UPX only when the evidence matches. State format selection before showing tools. Python bytecode version selects the decompiler; do not promise pycdc/uncompyle6 support for arbitrary versions.

Demote YARA (`kali-157`) from universal first-pass triage: writing a rule is useful for finding related samples, but usually adds work for a single unknown executable. Retain a compact corpus-matching entry and Python bindings (`kali-158`) only as a programmatic alternative. FakeNet-NG (`kali-37`) is a deliberate dynamic-analysis fallback, not a starter.

### Web Security — four routes

1. **Request → reproducible baseline → one controlled change.** Default `windows-20` [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater). Chrome (`windows-5`) captures/inspects; curl (`kali-23`) is the reproducible terminal alternative. Their roles are complementary, not three tutorials.
2. **Missing endpoint → bounded discovery.** Default `kali-41` [ffuf examples](https://github.com/ffuf/ffuf), after measuring a nonexistent-path baseline. `kali-126` SecLists is an input, not another workflow. `kali-39` Feroxbuster only when recursion is needed; `kali-54` Gobuster for an existing familiar dir/vhost workflow; `kali-78` Katana when linked/JavaScript endpoints are the actual clue.
3. **Observed vulnerability class → targeted test.** Default `kali-103` [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), linked to a relevant local class when available. `kali-132` [sqlmap saved-request usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage) only for an identified parameter and suspected SQL injection. Remove sqlmap from the generic hidden-path tool list: it addresses a different question.
4. **JWT → claims/algorithm → server verification.** `kali-77` [jwt_tool wiki](https://github.com/ticarpi/jwt_tool/wiki), paired with the recorded [PortSwigger JWT explanation](https://portswigger.net/web-security/jwt). Decoded claims do not prove trust; retain server-response comparison. Link `kali-64` hlextend and `kali-101` padding-oracle-attacker from crypto only when their distinct prerequisites are observed.

### Reverse Engineering — four routes

1. **Native checker → validation logic.** Default `windows-22` [Ghidra guided exercises](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html). Runtime confirmation: `windows-9` GDB for the matching native environment, `windows-33` x64dbg for Windows PE. `kali-109` pwndbg is an installed GDB enhancement, not a separate solving method. Cutter/radare2 are compact alternatives, not duplicate recipes.
2. **APK/DEX → validation method.** Default `kali-72` [jadx](https://github.com/skylot/jadx); `kali-8` Apktool for manifest/resources/smali or a failed decompilation. Frida (`kali-46`) and Android Studio (`kali-5`) only after identifying a runtime question. Do not imply all of these require installing/running an APK.
3. **.NET assembly → C#/IL.** Default `windows-38` [dnSpyEx](https://github.com/dnSpyEx/dnSpy). Give it its own row instead of hiding .NET under an APK-only resource. The current template supplies no .NET starting link.
4. **Python/Java/JavaScript → matching source view.** Small format selector: Python bundle links the Malware extraction route; supported PYC uses `kali-110` pycdc with version caveat; JAR uses `kali-38` [Fernflower](https://github.com/JetBrains/fernflower/blob/master/README.md); JavaScript starts with `kali-75` js-beautify. `kali-76`/`kali-96` deobfuscators are conditional on matching obfuscation. `kali-6` angr is an escalation for a modeled checker, not a default before reading the validation code.

### OSINT — three routes

1. **Image/date → metadata clue → corroboration.** `windows-14` [ExifTool read examples](https://exiftool.org/exiftool_pod2.html#READING-EXAMPLES), shared with Forensics. Preserve time-zone and provenance uncertainty. Repeated GPS/date fields can conflict.
2. **Public phrase/page → source and date.** `windows-5` Chrome, using the current template's [Google search-operator help](https://support.google.com/websearch/answer/2466433?gl=us&hl=en). Keep this as a research method, not a newly approved tool entry. The lane's Chrome DevTools network source is useful for Web but insufficient as an OSINT methodology reference.
3. **Given public domain → candidate hostnames.** `kali-139` [Subfinder usage](https://docs.projectdiscovery.io/opensource/subfinder/usage). Conditional, because public passive sources may require configured keys and coverage can be empty. Retain provenance and corroboration, not an implied complete asset inventory.

Do not manufacture extra OSINT software coverage: only these approved mappings have relevant evidence. Reverse image searching/geolocation procedures are not substantiated by the frozen lane files.

### Cryptography — three routes

1. **Encoded bytes → reversible transform.** Default `windows-1` [CyberChef](https://github.com/gchq/CyberChef); its [Magic explanation](https://github.com/gchq/CyberChef/wiki/Automatic-detection-of-encoded-data-using-CyberChef-Magic) is a caveat/advanced link. `windows-24` OpenSSL is conditional on known encryption parameters, not a coequal generic decoding starter. Verify bytes or format after every layer.
2. **Password/hash → confirmed format → bounded candidates.** Default `kali-59` [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) for format selection; `kali-73` [John examples](https://www.openwall.com/john/doc/EXAMPLES.shtml) when its bundled file converter is the relevant path. `kali-60` hashid proposes candidates, not certainty; `kali-120` rockyou is an input. `kali-13` [bkcrack worked tutorial](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md) is a distinct ZIP known-plaintext branch, not generic password cracking.
3. **RSA/algebra → evidenced weakness → checked result.** Default `windows-30` [RsaCtfTool usage](https://github.com/RsaCtfTool/RsaCtfTool); `kali-125` SageMath or `kali-22` crypto-attacks only when custom algebra/attack prerequisites justify them. Retain local mathematical validation. `kali-36` FactorDB is not a default competition path because it submits an integer externally.

Hash recovery is the material missing starter in the existing two-row crypto section. No evidence supports foregrounding every specialized attack library.

### Miscellaneous — three routes

1. **Unknown artifact/container → identify → list/extract.** `kali-42` file then `kali-2` 7-Zip for a supported archive; `windows-13` binwalk only when embedded signatures are relevant. Keep all compressor-specific entries in one catalog group. The existing template labels 7-Zip but links Python zipfile; replace that mismatched first link with the approved tool's reference or explicitly label the Python alternative.
2. **Structured text/bytes → focused extraction.** `kali-119` [ripgrep guide](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md) for search; `windows-21` [jq manual](https://jqlang.org/manual/) for JSON; `windows-7` [Python struct](https://docs.python.org/3/library/struct.html) for binary fields. These are a format selector, not a required sequence. QR gets a compact `windows-19` ZBar link; audio links back to Forensics.
3. **Challenge endpoint → protocol → interaction.** `kali-94` [Nmap reference](https://nmap.org/book/man.html), then its [Ncat usage](https://nmap.org/ncat/guide/ncat-usage.html) for the applicable text protocol. `kali-68` Impacket only for an observed SMB need; `kali-127` socat for a concrete transport requirement; `kali-124` RustScan is optional rather than a second mandatory scan.

## Consolidation and cuts

- Keep all 200 approved IDs in a compact catalog with platform, one-line purpose, one best link, and necessary caveats. Multiple approval rows must not disappear when descriptions are deduplicated. Shared tool explanations should have one canonical destination and cross-category links.
- Preserve official category names in navigation or accessible labels. The coordinator reports category aliases have now been normalized; preserve that normalization when grouping, so category matching does not silently drop content.
- Collapse editor/compiler/environment entries into setup/reference material: WSL, uv, conda, language SDKs, IDE extensions, Obsidian, VPN, Docker. No standalone synthetic “hello world” recipe per tool. Keep necessary Python library restrictions visible at the shared Python entry.
- Collapse overlapping families: pwndbg/GEF/PEDA; Ghidra/Cutter/radare2; ffuf/Feroxbuster/Gobuster; SQLite CLI/DB Browser/DBeaver; Audacity/Sonic Visualiser/SoX; compressor utilities; Volatility plugins. The alternatives remain discoverable with a clear trigger.
- Keep broad HackTricks, Exploit-DB and GTFOBins in the catalog. They are useful lookups after identifying a primitive/product/context, but displace actionable starter links when presented as general reading.
- Demote universal Google-search rows. A verified direct task link should be the first click; preserve one category search affordance if wanted. Remove the repeated Google-blocking/AI-Overview-testing history from the competition page and retain it only in internal evidence notes. Preserve the actual competition AI/data restrictions once.
- Do not turn inherited generic candidate descriptions into authored scripts. There is currently no execution evidence supporting the recipes; links to upstream code are references, not tested local PoCs.
- Hold `kali-133` SSTV instructions until decoder identity is resolved; hold `kali-70` internet_detector instructions because the INetSim link does not establish identity. Keep those approved catalog entries with explicit uncertainty. SoX_ng syntax, binwalk version, and local-only AperiSolve availability also need confirmation before executable guidance.

## Remaining evidence and acceptance

No installed-tool timings, participant trials, recipe executions, or independent link reopening were performed in this review. Thus defaults are justified by direct task fit and fewer branching choices, not claims that one tool is objectively faster. The coordinator reports category aliases and inventory/platform metadata normalized after this review began. The generic/structured mixture in `recipe_candidate` still needs an integration check. Run exact ID-coverage and rendered narrow-layout/keyboard checks after implementation; this document does not validate those outcomes.

A useful second bloat pass asks of each prominent element: does it choose the next action, show the action, or interpret its result? Move everything else to the catalog/evidence records. Stop when concrete duplicate or misleading material is resolved; do not repeatedly trim essential format, platform, or verification caveats to hit an arbitrary word count.
