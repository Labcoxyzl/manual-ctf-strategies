# Approved-tool learning resource research

Objective: curate guides and videos for a participant who knows CTFs but is rusty solving without assistance. Build a skimmable 24-hour flight-study path, with references for all explicitly approved inventory rows. Portal practice is secondary and has not been opened.

Source: `AJCCBC_CTF2026_Tool_Review_List_261015r11.xlsx`, supplied 19 October. On 22 October, re-extraction matched `research/inventory.json` exactly: 39 Windows and 161 Kali approved rows; SHA-256 `a7de8719aae3c344c1158e3489eb59543378bb34b1ba16661caef36b332eedaf`. Approval is platform-specific; Kali operation is best effort.

Ownership: parent owns integration and final guide. Five workers own their respective JSON outputs under this directory: forensics (40 rows), media (23), reverse (51), web-network (31), crypto-foundations (55). The input manifests partition all 200 rows. Existing per-tool documentation references are carried forward distinctly from fresh curated research.

Acceptance: concrete reading/video links with source evidence; practical learning outcomes; offline preparation and limits; approval/edition/version caveats; no requirement for a separate tutorial for each utility; all 200 rows accounted for. A separate reviewer checks the integrated result for factual scope, breadth, duplication, and flight feasibility, followed by supported repairs.

No portal access, large downloads, package installations, live challenge solving, or edits to the existing website were performed. Study-time allocations are recommendations, separate from verified video runtimes.

Status: revised goal complete. The prior pack is retained in `previous/`. Five category investigators evaluated all 44 original resources; parent integrated 43 retained/replaced selections with eight optional videos, each with a free reading route. `RESOURCE_EVALUATION.md` records the decisions. `LEARNING_RESOURCES.md` has ten blocks totaling 1,440 minutes, with diagnostics, prerequisites, focused selections and assessed exercises linked to `PRACTICE_WORKSHEETS.md`. All 200 approval rows and original per-tool reference URLs remain intact.

Independent final review found no unresolved material findings. It independently checked substantive replacements, approval metadata, worksheet answers and local fixture behavior. Stale worksheet wording and the old validation report were corrected and rechecked. `review.md` records this pass; `validation.json` contains current hashes, exact coverage checks and execution results. All research/review workers have completed.

`python tests/check_learning_pack.py` passed. TShark, GCC/basic GDB, Python/curl loopback and Python arithmetic/SQLite checks ran against benign bundled inputs. Forty-five selected/alternative URLs resolved; one HEAD 404 was investigated with a successful GET and substantive content, preserving both results in `link-probes.json`.

Remaining optional work: save and test chosen external readings/videos on the travel device, prepare GUI or image-based labs if desired, and inspect organiser practice in a separate portal pass. No video playback, YARA CLI, forensic image or GUI execution is claimed. The paper routes keep every required study block usable without those optional setups; they are explicitly not evidence of hands-on proficiency or measured learning gains.

## Plan-to-implementation audit pass

The new active goal is a current-state implementation audit, not a rebuild. Initial inspection found no drift in any artifact hash recorded by the previous validation. Prior fixture execution and source checks therefore remain evidence for that exact baseline, subject to focused reviewer challenges.

Plan and ownership:

1. A read-only topology assessor checks the task and recommends independent lanes. Parent retains integration and the requirement audit.
2. Fan out three distinct review lanes: curriculum and plan fidelity; technical exercises, approval mappings and evidence correctness; access, free alternatives and offline practicality. Reviewers own only their review report files and may return no findings.
3. Adjudicate findings against the attachment and current artifacts. Assign actual independent gaps to implementation workers with file ownership; do not create changes merely to exercise the swarm. Parent coordinates shared document/data changes.
4. Recheck affected behavior and `tests/check_learning_pack.py` after relevant edits. Reuse unchanged source/link evidence, preserve inconclusive checks, and refresh final hashes/reports.
5. Audit each original requirement against the integrated result and resolve material findings before completing this goal. Keep video playback, GUI/image execution and travel-device readiness outside completion claims.

Review findings and implementation ownership:

- Curriculum reviewer found one material learning-value gap: the disk/memory exercise timeboxes lacked a bounded independent second case. `repair_practice` owns worksheet blocks 3/4, adding synthetic listings/process views and keyed interpretation/command tasks. The same owner adds a YARA `harbors` negative case so the full-word requirement is assessable.
- Parent/access inspection found stale exercise references: the CyberChef focus mentions an absent second layer and the RSA focus uses ciphertext 2790 instead of worksheet 8's 2557. `repair_resource_coherence` owns the guide and combined JSON to align those instructions. It also exposes exact companion/curl page save links and labels historical lane caveats separately from current execution limits.
- Technical reviewer found no material command, mapping or fixture defect. Access reviewer found no material paid/account/offline blocker; its precise-link suggestions are included in the small coherence repair.
- Parent owns integration, a mirrored companion link in worksheet 5 after its owner releases the file, the requirement audit, validation and reports. The original workbook was re-extracted during this pass and still matches the full inventory exactly.

Current phase: this goal is complete. Both implementation workers finished; all three reviewers rechecked their affected sections with no unresolved findings. The focused check passed, including the added synthetic-table assertions, and final validation hashes were refreshed. The prior goal completion above describes the starting candidate; this section records the completed new pass.

Requirement-to-artifact audit (integrated candidate verified):

| Requirement | Authoritative evidence / check |
| --- | --- |
| Exact organiser scope and all 200 references | Original workbook re-extraction equals `research/inventory.json`; technical review compares every rendered index row to data; focused check compares each original reference URL. |
| Substantive teaching value and retain/replace/shorten/remove rationale | All 44 original evaluations in combined JSON and `RESOURCE_EVALUATION.md`; curriculum review of the 43 retained selections and original attachment. |
| Free-first access, registration and offline alternatives | Per-resource access records; eight video alternatives; access reviewer traced all block dependencies and inspected disputed primary sources. |
| Practical 24-hour sequence | Ten schedule entries sum to 1,440 minutes with per-block sub-budgets; guide and worksheets provide outcomes, diagnostics, preparation and keyed exercises. Forensic second cases are the accepted repair. |
| Breadth without duplicate courses | All-tool reference-family rationales plus curriculum review; no resource-count expansion in this pass. |
| Correct actionable exercises and honest execution claims | Bundled fixtures, independently recomputed answers, focused local test and technical review; paper versus tool execution explicitly separated. Parent identified and is repairing two stale local-exercise references and the full-word negative case. |
| Independent implementation and review | Three distinct review reports, two workers with disjoint file ownership, parent integration, then targeted reviewer rechecks. |
| Current evidence rather than stale success | Final focused check, current artifact hashes, resolved finding dispositions and this audit; unchanged external evidence reused with its original limits. |
| Scope limits | No publishing, push, purchases, accounts, large collections or portal launches; no unperformed playback/GUI/image execution or measured learning gain claimed. |

## Comprehensive tool-depth collection (active goal, 23 October)

The user corrected the video-depth expectation. The eight downloaded videos total 6,214 seconds (1:43:34), not twelve hours. Their six first-pass recommendations total 5,301 seconds (1:28:21); the earlier 24-hour schedule includes reading and practice. The new active goal is the attachment at `/home/ubuntu/.codex/attachments/823478b8-46cd-4dd0-b5d5-331dcbe4611f/pasted-text-1.txt`.

Scope now includes closing consequential instructional gaps, not merely reporting them. Preserve all 200 exact approval rows; classify priorities as preparation judgments and actual instructional depth as incidental/introductory/workflow/deeper. References may serve support/alternative tools, but must not conceal missing instruction for important capabilities. Use substantive free videos, guides and worked practice, with honest access limits and verified runtime arithmetic. Do not pad twelve hours or infer unseen challenges.

Existing work was reconciled before expanding assignments. Three researchers own separate files under `video-coverage/`: forensics/media/packet evidence (71 rows), reversing/malware (51), web/crypto/support (78). These manifests partition all 200 rows. Parent owns integration, direct caption/metadata retrieval, runtime evidence, the final matrix and review. Already downloaded videos are reused. No revised messages, additional video downloads, purchases, accounts or portal launches are authorized by this goal.

Current phase: comprehensive collection complete; final requirement audit, selected-link repair and focused reviewer rechecks passed. All 200 rows are mapped; inferred priorities are 48 essential, 47 specialist, 32 alternative and 73 support rows. The original videos contain four workflow mappings, seven introductory mappings, four incidental mappings and 185 rows with no direct video instruction; none was graded deep. These are row-level judgments, not a requirement for 200 videos.

Deliverables: `TOOL_LEARNING_COLLECTION.md` (15 prioritized capability tracks), `TOOL_RESOURCE_CATALOG.md` (79 selected instructional entries), `TOOL_COVERAGE_MATRIX.md` and `video-coverage/coverage.csv` (all 200 rows with exact references and full skills/prerequisites/limits), and `video-coverage/collection.json` (canonical evidence and mappings). The remaining records in the 259-record data catalog are concise exact references, not extra courses.

Nine additional video lessons have direct metadata and original-English captions, totaling 25,040 seconds full length. Together with the original eight, full linked runtime is 31,254 seconds (8:40:54), not twelve hours. New selected sections total 16,898 seconds (4:41:38), plus 2,352 seconds (39:12) of retained MFTECmd/Volatility workflow sections. Full lengths include skipped content; reading/practice estimates remain separate. No additional video files were downloaded or material sent.

The owner added tiny known-answer audio, strings and PDF inputs to close concrete practice gaps. Frequencies and file structure were checked; GNU strings ran; pypdf validated the PDF. Audacity/qpdf/forensic GUI execution was not performed. Selected PDF workflow uses qpdf directly; the Didier Stevens document case is complementary and is not falsely mapped as qpdf instruction.

Independent depth and runtime/access reviews found companion-link delivery gaps, an FTK acquisition segment, missing collection-wide Premium disclosure and stale pending-runtime language. Repairs expose the needed primary guides, use pre-extracted hives, cut the FTK intervals, distinguish paid offline video from free reading, and label historical evidence. Focused reviewers marked these resolved. Final link probes also found an obsolete Apktool decoding URL; it was replaced with live version2.x official CLI instructions, qualified against the organiser's2.7.0-dirty build. Original reference URLs remain unchanged.

Current checks: `python tests/check_tool_collection.py` passes all 200 mappings, exact metadata/references, source/caption hashes, 17 unique-video arithmetic, selected/excluded interval boundaries, local links/anchors, CSV and known-answer input integrity. Final link results and prior failed probes are preserved in `video-coverage/link-checks.json`. Final requirement-to-evidence audit and current artifact hashes are recorded in `video-coverage/review.md` and `video-coverage/validation.json`. All material review findings are resolved; no required instructional coverage is left marked incomplete.

## Recursive free-access, relevance and goal-alignment audit

The user requested another review/repair loop against the same goal. Three independent lanes audited every source's access claims, practical relevance/duplication, and exact requirement alignment. The initial 259-record baseline was unchanged when review began; successful prior checks were reused with that scope. Fresh primary checks targeted ambiguous prices, weak prior evidence, blocked sources and hidden paid/unapproved prerequisites.

Six findings were repaired: explicit Ncat/Nping and nine-component oletools routes; merging the duplicate Autopsy Quick Start; a bounded Volatility layer/symbol troubleshooting route; verified free alternatives for three inconclusive GNU endpoints; Sublime evaluation-versus-continued-use licensing with approved editor alternatives; and a BinDiff/Ghidra route excluding paid disassemblers and commercial GUI source-build requirements. Eight previously saved MP4s are explicitly separated from the paid YouTube download-button policy. No additional video files or messages were sent.

Two authored benign OLE/RTF inputs were extracted with the installed oleobj/rtfobj and checked against the known17-byte payload. A loopback Ncat exchange also passed. Nping, memory-image troubleshooting, GUI operation and target-machine compatibility remain unexecuted; paper decisions and limits are explicit.

All originating reviewers rechecked affected claims and closed their findings. The current collection has 261 source records: 81 instructional entries and180 concise references. The per-record access ledger has19 fresh verifications and242 reused-evidence assessments, with no unresolved required learning route; the original GNU endpoint failures remain recorded rather than called paywalls. The exact200 rows and17-video runtime totals are unchanged.

`tests/check_tool_collection.py` now also checks named bundled components, the exact access-audit record identities, Autopsy deduplication, and preserved benign extraction/loopback evidence. It passes. Final reports: `access-audit.md/.json`, `relevance-audit.md`, `goal-alignment-audit.md`, and the integration record in `review.md`. This pass does not claim every source was freshly fetched or every application is free to execute.
