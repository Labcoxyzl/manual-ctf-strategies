# Independent accuracy review — 2026-10-22

The five research lanes are suitable for consolidation as **candidate references**, not as tested competition recipes. No substantive blocker was found in the reviewed claims. Preserve their compatibility and identity caveats when shortening the content.

## Ranked findings

1. **AR-01 — low: Zui migration wording confuses an organisation with a product rename.** `web-network.json`, `kali-161`, says “Repository renamed to superdb.” The primary repository is still named `zui`; `brimdata/zui` redirects to `superdb/zui`. Change this to “Repository moved to the superdb organisation; installed version and PCAP import prerequisites are unverified.” This is a small factual correction before publishing, not a runtime blocker. Evidence: [current Zui repository](https://github.com/superdb/zui), [old URL redirect](https://github.com/brimdata/zui).

No high- or medium-severity accuracy findings. Category-name and caveat-type normalization are already owned by the coordinator; this review does not duplicate those integration findings.

## Keep these decisions

- **Highest value:** retain task-led defaults and their failure conditions: Wireshark/TShark for captures; file/strings then the matching parser; Ghidra or JADX by executable type; CyberChef for evidenced encodings; bounded John/hashcat attempts only after identifying the input format. These are clear routes rather than lists of interchangeable tools.
- **Keep identity blocks visible:** `kali-133` must not become a decoder recipe. The workbook names a decoder but records PySSTV, whose [package documentation](https://pypi.org/project/pySSTV/) explicitly converts images to audio. The separate [sstv decoder](https://github.com/colaclanth/sstv) is not established as the installed or separately approved application. The research correctly blocks the recipe.
- **Keep reference-only or conditional:** unresolved `internet_detector`/INetSim identity, local AperiSolve deployment, SoX_ng option compatibility, legacy decompilers, and GUI prerequisites. An approval row is not a successful execution check.
- **Keep version boundaries:** Volatility 2 profiles versus Volatility 3 symbols; Bash checksec versus the newer Go CLI; ImageMagick 7 syntax; Frida 17 bridge packaging; older Python bytecode support. Do not collapse these caveats into a generic “latest docs” note.
- **Keep cross-category links, not duplicated recipes:** PDF analysis spans forensics and malware; PCAP analysis spans forensics and web; password recovery spans crypto and wireless. Join every tool by its inventory ID and display actual installation location, particularly Windows-list entries installed in WSL.
- **Keep local-only challenge-data handling:** Factordb, public AperiSolve, hosted deobfuscators and other upload services must not become default competition actions. Approved offline reference collections do not approve every program they mention. Existing caveats align with `EVENT_SOURCES.md`.

## Checks actually performed

- Parsed all five JSON files and compared IDs and names to `research/inventory.json`: **200 records, 200 distinct IDs, no missing inventory rows, no name mismatches**. Lane counts: forensics 40, web/network 31, reverse 51, media 23, crypto/foundations 55.
- Read `EVENT_SOURCES.md`; compared candidate actions, approval assumptions and platform/version caveats with the inventory. Reviewed extracted recipe/caveat summaries across all 200 rows and selected full resource records.
- Reopened primary sources for material identity/platform questions: [OpenSSH recovery](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) confirms a Linux Volatility 3 plugin and architecture-specific symbols; [js-deobfuscator](https://github.com/ben-sb/javascript-deobfuscator) confirms the npm identity and local CLI; [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) documents Linux support and privileged operation, supporting its contained-lab caveat; SSTV and Zui sources are linked above. An exploratory guessed `ben-sb/js-deobfuscator` URL returned 404; the actual research link is the correct `javascript-deobfuscator` repository.

## Before recipes claim validation

Use synthetic fixtures and the available runtime to verify each selected short procedure, its expected observation and its failure path. Installed interpreter/plugin versions, event-machine GUI availability, symbol caches, GPU backends and local service deployment remain runtime checks. Such checks are necessary before marking a recipe tested, but are not prerequisites for keeping a clearly labelled reference in the catalog.

Not checked: every external URL, complete upstream source code, the original private workbook/PDF, or any organiser-provided runtime. No challenge tool was executed and no website/JSON was edited. The remaining risk is shortening away prerequisites and accidentally presenting researched candidates as verified commands.
