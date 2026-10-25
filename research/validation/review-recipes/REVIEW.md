# Independent recipe review

What this change does: The cheatsheet gives every approved inventory entry a dedicated Markdown section with a first action, expected result, fallback, availability and references. Seven category playbooks connect the entries to a challenge-solving workflow.

Looks good. No confirmed blocking findings in the reviewed state.

The review covered all 200 recipe bodies, the 200 resource descriptions and caveats used by the renderer, all seven category playbooks, `build_cheatsheet.py`, and the generated Markdown structure. The generated file exactly matched `render_cheatsheet()`. It contained 200 unique approved-entry anchors matching the inventory and all seven category anchors. Every recipe used the honest `source-guided` verification label; the introduction clearly distinguishes these workflows from local runtime checks.

The review checked output destinations and source preservation, version-specific syntax, tool identity, platform assumptions, expected-result claims and fallbacks. No recipe requires treating an encoding transform as a full protocol parser. The ambiguous `internet_detector` and `sstv` entries require identity confirmation and do not promise unavailable behavior. The latter correctly distinguishes [PySSTV's image-to-audio generator](https://pypi.org/project/pySSTV/) from [colaclanth/sstv's audio decoder](https://github.com/colaclanth/sstv).

Eight bounded local invocations completed successfully. Full stdout, stderr and command arguments are beside this report and recorded in `independent-checks.json`:

- qpdf help recognizes the attachment and page inspection options.
- stegsnow help recognizes its positional input and optional compression/password arguments. The recipe's basic extraction invocation is consistent with the [Kali package help](https://www.kali.org/tools/stegsnow/).
- hashid help recognizes `-m` for Hashcat mode candidates.
- Subfinder help recognizes `-oJ`, `-cs` and `-o`. These also agree with the [maintainer usage reference](https://docs.projectdiscovery.io/opensource/subfinder/usage).
- John reports its local build successfully. Its local upstream `doc/OPTIONS` documents `--wordlist`, `--max-run-time` and `--show`.
- LZ4 help recognizes integrity testing and explicit-output decompression; force-overwrite is a separate flag absent from the recipe.
- uv's `python find` help recognizes `--offline`, `--no-python-downloads` and the positional version request.
- RsaCtfTool successfully dumped `n: 3233` and `e: 17` from a fixed, harmless public-key fixture using the recipe's `--dumpkey --key` combination. The help's description of `--key` as a private-key input is narrower than actual behavior; the local implementation imports either key type and checks for private components before printing them. This is not a defect in the recipe.

The exact [checksec 2.6.0 source](https://raw.githubusercontent.com/slimm609/checksec/2.6.0/checksec) was independently read. Its help declares `--file={file}`, matching the pinned Bash-era recipe. A current pwntools or Go command with the same name would not establish that version's syntax.

Verdict: Ship this reviewed recipe state. No shared source edits were made.

Not checked: End-to-end execution of all 200 tools, Windows/GUI workflows, organiser-machine availability, live network targets, or untrusted challenge binaries. Help and source checks establish the selected interfaces, not full tool functionality. The exact reviewed hashes and invocation results are in `independent-checks.json`.

## Focused final-state follow-up

The seven appended category steps and helper-link conversion were reviewed separately after the initial full review. They preserve the relevant distinctions: layered decoding is bounded static analysis; HTTP banners are leads; UPX repair requires matching evidence, a copy and validation; missing GPS calls for independent viewpoint evidence; hashes remain ambiguous; frame parity and partial five-bit groups must not be ignored. These are workflow recommendations, not new claims that every example or tool has been executed. No new finding was identified.

The renderer now maps helper links through the existing `NOTE_OUTPUTS` table. All 55 helper occurrences mapped correctly, fragments and query strings were retained, and the existing local-page validator found no broken target or anchor in the cheatsheet. Markdown and HTML matched their renderers and retained exactly 200 approved-tool anchors and all seven category anchors. Moving repeated availability caveats to the introduction retained the source-guided and best-effort limits.

`independent-checks.json` now binds the verdict to the final input hashes and retains the initial hashes separately. Earlier tool checks were reused because all 200 tool recipes are byte-for-byte unchanged; no new tool-runtime claim is made. `followup-checks.json` records the narrow renderer/link checks.
