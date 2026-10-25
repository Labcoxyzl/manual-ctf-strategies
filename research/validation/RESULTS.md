# Challenge-driven validation results

This pass tested the current helpers against the supplied practice collection and public past-event artifacts, repaired demonstrated failures, and rechecked the integrated guide. It does not establish a numerical confidence level or universal solver coverage.

## Supplied practice challenges

| Challenge | Result | Evidence and limit |
| --- | --- | --- |
| 28: Ramen | unresolved | Exact JSAC 2023 speaker/avatar established; two independent restaurant searches found no corroborated restaurant code. |
| 29: Guess the geolocation | corroborated candidate | No GPS; public matching photographs and mapped viewpoint support a signed rounded coordinate candidate. Not GPS-measured or organiser-accepted. |
| 30: Matryoshka | locally derived | 64 static layers decoded; independent replay matched every layer hash. PHP was never executed. |
| 31: Reversing & Packet Analysis | blocked: missing inputs | Saved portal lists no attachment; required process dump and PCAP not supplied. Historical captures were not substituted. |
| 32: Decode the RFID Tag | qualified candidate | Seven repeated fields and independent extraction agree, but row/column parity fail. Public method consulted after independent first attempt; no standards-valid or accepted claim. |
| 33: ReverseMe | locally derived | John recovery, six-byte section-name repair in a copy, UPX validation, static checker and clean reproduction agree. No native execution or organiser acceptance. |
| 34: Plato | locally recovered | Appended encrypted archive, twelve CRC-valid images, seventeen pixel-adjacency checks and cipher roundtrip reproduced from original. |
| 35: Analyze the forgotten password | locally verified key | Unencrypted ZIP/HTA; recovered all three permuted MD5 pieces, passed source-faithful checker and wrong-key control. |
| 57: Welcome | blocked: live resource | Requires assigned organiser PX Kali user profile. Zero launches or submissions; no local substitute flag. |

Original files remain unchanged. Raw flags, passwords, precise OSINT answers and extracted payloads remain only in ignored challenge-local validation directories. `challenge-results.json` binds each private report to its hash.

## Improvement cycles

1. Independent sample attempts compared existing helpers with approved tools. Existing inspection correctly separated encrypted and unencrypted archives, caught the JPEG/SFX boundary, and retained RFID/bitstream limits. Tool discovery, password-length coverage, static script bounds and visual OSINT fallback became guide improvements.
2. Public 2019/2021/2022/2025 sources supplied held-out packet, web, encoding and static unpacking cases. The HTTP template omitted useful headers; a harmless loopback comparison established the gap and an independent retest confirmed the repair. See [historical evidence](history/REPORT.md).
3. Independent adversarial tests found short HTTP bodies falsely succeeding, impossible ZIP local-header offsets accepted, and binary parsing hanging on a FIFO. All three were repaired. Original reproductions, 34 distinct boundary checks, eight new HTTP cases and two demo controls passed on the final helper hashes. See [script review](review-scripts/REPORT.md).
4. A separate reviewer checked all 200 source-guided recipes and seven category playbooks, including version-sensitive commands and all helper links. The exported Markdown initially referenced unavailable raw notes; helper links now target the packaged HTML and the nine distribution checks pass. See [recipe review](review-recipes/REVIEW.md).

## Deliverables

- `CTF_CHEATSHEET.md` and generated HTML: seven category playbooks and dedicated sections for each of the 200 exact approved platform entries; 96 command blocks are syntax-checked, not claimed universally executed.
- `HASHCAT.md`: structural identification with existing Hashcat/hashid, ambiguity, candidate coverage, performance limits, sessions and recovery.
- Python templates remain small: file preview, byte helpers, binary parser, HTTP experiment, pwntools transport, timed arithmetic client and local demo. No new dependencies or auto-execution of challenge payloads.
- Core inspection now supplies PE/ELF follow-up actions and bounded lexical PHP markers with offsets; these are clues, not execution or complete source analysis.

## Remaining limits

- Ramen restaurant mapping remains unresolved after two independent search lanes. RFID parity failures remain explicit.
- Challenge 31 needs its missing dump and PCAP. Challenge 57 needs the assigned live PX environment; no launches were consumed.
- No organiser acceptance, native Windows/Kali/CPython 3.10 verification or 200-tool execution claim. Static/public-source-guided recipes are distinguished from executed local cases.
- Historical participant copies were pinned and independently parsed where noted, but their hashes are not organiser authenticity checks. The historical packer used published parameters; incomplete five-bit input retains its unexplained suffix.
- Changes are local. No git push or deployment was performed.


## Final integrated checks

- 75 unit tests passed. After the export README wording correction, all nine affected distribution tests passed again.
- All 66 script tests included in the clean 41-file export passed from that export directory. The ZIP was created before test caches and its entries/CRC/hashes verified.
- Ten recipe fixture checks passed; pngcheck was unavailable and explicitly skipped.
- Static guide and 13-note source/link checks passed. Browser checks passed five viewports, keyboard navigation, offline behavior, empty/reset states and local links; new cheatsheet desktop/320px screenshots were inspected.
- `final-checks.json` binds checks to final files; `offline-export.json` records the 317,627-byte archive and all 41 entry hashes.
- Early integration failure: the generated Markdown initially linked raw notes absent from the export. This was repaired by linking packaged HTML; no allowlist or missing-link check was weakened. A later evidence-file write used the export working directory accidentally; no private file was added, and archive verification/evidence recording was rerun from the project directory.
