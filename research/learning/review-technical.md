# Independent technical review — 2026-10-22

What this change does: The pack supplies ten assessed study blocks, benign local fixtures, and an index preserving the organiser’s 200 approved rows. It separates executed command checks from paper exercises and optional unexecuted applications.

No material findings in this review lane. The fixture contents, worksheet commands and answer keys agree with the recorded local execution evidence. The optional forensic, GUI, YARA and archive routes explicitly disclose missing assets or unperformed execution; they are not presented as completed labs.

## Evidence checked

- Read the supplied goal attachment, applicable `/home/ubuntu/sgco/AGENTS.md`, worksheets, fixture sources, test implementation, inventory, resource JSON and recorded validation. Applied concrete-defect review criteria from Ponytail review.
- Independently compared all 200 rendered index rows with resource coverage: names, original reference URLs, version/location/remarks, and linked resource IDs agree. This supplements the existing test, which checks JSON metadata and rendered row count but does not itself compare every rendered value.
- Independently recomputed all 13 recorded input SHA-256 values; all match validation. Reused the recorded successful fixture execution against those unchanged inputs rather than rerunning it. The recorded command results cover TShark fields/stream, GCC’s three requested branches, basic GDB, loopback Python/curl 200 and 404, and toy arithmetic/hash/SQLite checks.
- Independently parsed the capture’s little-endian header and packet-record bounds: five records, 541 bytes, correct stated magic. No new network traffic was captured.
- Reviewed the YARA rule and two text fixtures: both marker and full-word `harbor` are required; the supplied `harbour` near miss fails by inspection. No YARA execution claimed.
- Compared version pins with inventory: capa 9.4.0 and bkcrack 1.8.1 agree. The guide discloses Binwalk major-version differences, moving documentation, historical examples, Autopsy documentation version and unverified organiser/local installations.
- Read assertions in `tests/check_learning_pack.py`: exact coverage/metadata/reference preservation, 1,440-minute arithmetic, local links/anchors, required resource/access fields, substantive fixture results. Test scope is suitable for these static documents and small fixtures; it does not establish video playback, GUI usability, comprehensive remote-link content or actual learning gains.

## Focused integrated-candidate recheck

Reviewed the revised worksheet 3/4 synthetic cases, worksheet 6 full-word contrast, and guide/JSON crypto focus corrections. No unresolved technical finding in these changes.

- Independently extracted worksheet journal table entries and checked `(42, 7)` → `101, 103, 104, 106`, `(43, 2)` → `102, 105`, and `(42, 8)` → `108`. The listing metadata addresses are explicitly supplied separately from journal identity. TSK command shapes agree with the retained official-manual evidence: `mmls`, `fls -r -o 4096`, and deleted recovery `icat -r -o 4096 ... 42-128-1`; 4096 sectors × 512 = 2,097,152 bytes. The new-file redirection requirement and overwrite risk are stated.
- Independently extracted the five process rows: missing parent identifiers are exactly 4 and 799; PID 910 reports 850 then 799. Volatility command shapes follow the selected tutorial’s source-checkout CLI. Synthetic views are explicitly not independent corroboration; missing evidence and failed symbols are not negative findings.
- The `training-marker harbors` case correctly fails the rule’s `fullword` condition and distinguishes it from substring matching. This is a reviewed paper result, not YARA execution.
- Recomputed Base64 and RSA answers. The current guide and JSON focus agree with worksheet 1’s single-layer decode and worksheet 8’s ciphertext 2557; stale two-layer/2790 focus text has been corrected by the integration owner.
- Reviewed the final added test assertions: they parse the actual journal/process Markdown tables, check row counts, full-key event grouping, both process chains and missing parents, recompute the offset, and check the two ASCII word-boundary examples. Their expectations agree with the supplied cases. The regular-expression check is narrowly labeled paper matching; it does not claim to execute or comprehensively emulate YARA. The parent reran the updated test successfully, and the saved `check-results.json` records its new synthetic journal/process and ASCII paper-match checks alongside the existing executed fixture checks, with no skips. This reviewer inspected that result and the additions without rerunning the suite or claiming forensic/YARA execution. The test hash below was refreshed after this addition; the integration owner is refreshing validation separately.

## Candidate hashes

- `LEARNING_RESOURCES.md`: `5e869b28a6fb6d21d76796472906369c6c9d4f8319de9fb12f20542fd063b15c`
- `APPROVED_TOOL_REFERENCES.md`: `a667298c6c5bb0043fd51c8d7b01b7d868c101fb36d079437b6570acfa547eb4`
- `PRACTICE_WORKSHEETS.md`: `4f1c67e2737aeda41cdff3858ce820daaa69463569e5e80e1b7c8fba989464a6`
- `RESOURCE_EVALUATION.md`: `b522fa37836a429d93d9ebfa00a710fa8c33c1f67332641172f18d5df0675100`
- `research/learning-resources.json`: `0bbdb9ba9868a37db49fe8702a7370c17d724681921b32344057ce0a5772b31d`
- `tests/check_learning_pack.py`: `82ddbe272b123a1d4ada2178ff2ff659bca34165ba0e0c20a515a80e90eb52ae`
- `research/learning/practice/training.yar`: `5818923604e11bf21a48beb33fde989326968b20aefd53d513b70d0f11795906`
- `research/learning/practice/near-miss.txt`: `fa267f147266e353d94f61707af00384dadd188e5c441dad23d4933717e7d151`
- `research/learning/practice/README.md`: `c45d11cdc2e399bbc97e1f2bb1da3d60cd8920cd92cc0c6e9ce74fcf0919d363`
- `research/learning/practice/match.txt`: `4f3559253150d54c60d2ce4b34594b5745acfae9014e2f01b3b42eeb0ccb28d1`
- `research/learning/practice/check_input.c`: `545705c463250b4806864909a961c3f97a0579f1cf87fbc66f5d102b02831f3c`
- `research/learning/practice/http-demo.pcap`: `926aa19af4dc25f31dceaad717eee584f55ae37b958cc942b11c73fdf828fc6c`
- `research/learning/practice/http/clue.txt`: `fd6ae5ab05585609b101acc6830600ff4c94c1a9d0bc7ed8e2cbcb27a172a176`

Verdict: No technical repair required on this candidate.

Not checked anew: organiser/travel-machine installations, external source retrieval, video playback, GUI tools, forensic images, YARA execution, optional archive execution or original-workbook extraction. Prior command checks were reused only after matching input hashes; broader evidence and learning-value review remain the integration owner’s responsibility.
