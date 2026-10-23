# Consolidated guide direction

Research covers all **200 approved workbook entries**, with **216 selected resource URLs**. Keep the full catalog, but lead with task routes rather than 200 equally prominent tutorials. These are source-backed editorial choices, not measured speed rankings or tested recipes.

## Category structure

The [utility review](utility-review.md) ranks 24 routes and supplies their tool IDs, source links, prerequisites, and conditional alternatives. Use that as the implementation content specification:

| Category | Starting routes | Default selection |
| --- | --- | --- |
| Digital Forensics | PCAP; disk; memory; image/audio/PDF selector | Wireshark; Sleuth Kit; Volatility 3; format-specific inspection |
| Malware Analysis | Executable triage; documents; identified bundles | Detect It Easy/capa; oletools or PDF tools; matching extractor |
| Web Security | HTTP replay; endpoint discovery; vulnerability-specific test; JWT | Burp Repeater; ffuf; relevant reference/test; jwt_tool |
| Reverse Engineering | Native; APK; .NET; Python/Java/JavaScript selector | Ghidra; JADX; dnSpyEx; matching source viewer |
| OSINT | Metadata; public phrase/page; supplied public domain | ExifTool; browser/search operators; conditional Subfinder |
| Cryptography | Encodings; password/hash recovery; RSA/algebra | CyberChef; hashcat/John by input; RsaCtfTool with justified escalation |
| Miscellaneous | Unknown container; structured text/bytes; challenge endpoint | file/archive tool; matching text parser; protocol-specific tools |

Each route should show a recognizable input, a short first action, the expected observation, and a next step if that observation is absent. Shared tools have one explanation, linked across categories. Format selectors are alternatives, not instructions to run every listed tool.

## Keep the page short

Give each route one default and show another tool only when its distinct use is relevant. Put specialist tools, editors, runtimes, SDKs and setup material in the expandable catalog. Keep one direct task reference first; secondary references must answer a different question. Retain all platform-specific approval IDs when merging descriptions.

Remove repeated search prompts and old Google AI Overview experiment history from the eventual competition interface; retain research history in its existing files. Keep the competition restrictions once. Add the currently missing password/hash and distinct .NET starting routes. Separate SQL injection testing from endpoint discovery. Replace the existing 7-Zip/Python-link mismatch with an accurately labeled reference.

## Accuracy decisions

The [accuracy review](accuracy-review.md) found one factual correction: Zui's repository moved to the `superdb` organisation; the product was not renamed. This is corrected in the research data. Category names, caveat lists and inventory platform/version/location fields are now normalized across all five files.

Preserve the unresolved SSTV decoder and `internet_detector` identities. Keep version-specific requirements for decompilers, Volatility, Frida and other specialist tools. External submission services do not become default challenge-data workflows. Approval-list presence does not prove the installed tool works.

## Next implementation stage

Use the existing template and generator. Turn selected candidate procedures into short instructions, test any executable recipes or local PoCs with synthetic fixtures, then inspect the rendered interface and its affected interactions. Keep every untested item labeled accordingly. Use the project's existing checks after changes; this research does not validate a changed website.

The initial research stage did not change the website or execute recipes. The subsequent authorized implementation is now complete locally: all 24 routes and 200 catalog entries are rendered, exact-tool filtering and canonical links work offline, and the original preparation guide remains linked. Static and five-viewport browser checks passed. Eight published command steps and two malformed-input controls passed on benign local fixtures; pngcheck was unavailable and explicitly skipped. See [fixture evidence](recipe-validation.md), `research/testing-static.json`, and `research/testing-browser.json`.

Independent content and rendered-UI reviews found no remaining blockers after the input-code formatting correction and final regeneration. Organiser-machine parity, remaining recipe execution, external-link availability, and public hosting are not established by those checks. Nothing was published or pushed.

## Local interface cleanup — 23 October 2026

Completed against HTML SHA-256 `f4b6fda34dfc293f3472ea63da759c48c736dfa9cdb0709f64950339f6ea4c89`. The catalog and search now precede the 24 task routes, and Tools is the first navigation item. Search moved from about 3,805 px to 311 px from the top on a 390 px viewport. All 200 approved entries and canonical tool anchors remain; visible inventory IDs and source-verification prose were removed. Windows/WSL distinctions, installation limits, instructions, expected results, fallbacks and references remain available. The main HTML is 225,605 bytes, down from 281,323, with no new dependencies.

Preparation pages were regenerated from current sources. Study navigation and expandable setup instructions replace the long opening setup block. Tool-reference labels use names, with exact inventory identity retained in anchors. Bytes/PDF and audio exercises are linked selectively; research ledgers and review reports remain local evidence rather than study navigation. Existing report files and unrelated toolkit planning were preserved.

Current checks passed: static guide coverage, seven published notes and local anchors, learning-pack fixtures (TShark, GCC/GDB, curl), tool-collection checks, whitespace, and browser coverage at 320×900, 390×900, 768×900, 1440×900 and 667×375. Browser checks include initial search visibility, keyboard access, rules expansion, search/reset/empty results, 24 offline procedures, deep links, no page overflow, note tables, no-JavaScript reading and hidden print navigation. Desktop/mobile screenshots and final prep changes received independent rendered acceptance review with no remaining blockers. A representative Wireshark reference opened successfully; external links were not exhaustively rechecked.

Changes are verified locally, not deployed. Competition-machine compatibility, qpdf/Audacity GUI execution and full printed layout remain outside these checks.
