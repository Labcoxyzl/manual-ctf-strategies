# Independent runtime, approval-boundary and access review

Reviewed 2026-10-23 against the active comprehensive-collection task attachment, `TOOL_LEARNING_COLLECTION.md`, `TOOL_RESOURCE_CATALOG.md`, `collection.json`, original video-pack README and saved metadata/captions. This reviewer owns only this report. Findings were sent to the integration owner for repair.

## Findings and focused-recheck status

1. **Resolved: Windows-forensics selection retained an unapproved acquisition step.** The selected 2:55–53:29 range of `VYROU-ZwZX8` includes FTK Imager: the captions at 3:35–3:39 suggest it for protected live hives, and 22:49–23:28 discuss its “obtain protected files” control and missing USRCLASS.DAT. FTK is absent from `research/inventory.json`. The catalog's `forensics-deeper-video-2` warning excludes only the later NirSoft demonstration, while its prerequisites do not require pre-extracted hives. This can lead a learner following the selected workflow to an unapproved acquisition tool. Minimal repair: require already-extracted hives, explicitly exclude FTK acquisition, and preferably omit the operational 22:46–23:28 interval from selected time. Recalculate selected totals if ranges change. No need to discard the substantive Registry Explorer/USB correlation lesson.

2. **Resolved: new-video download cost was insufficiently explicit.** Most new video entries say “Free public resource” or “Free streaming,” then “No additional video downloaded” and distinguish streaming from offline availability. The collection's common access section does not identify paid Premium/sign-in requirements. Some inherited video cards do, but a learner following only a new track will not see those cards. The task explicitly requires distinguishing paid downloads and account requirements. Minimal repair: add a clear policy applying to every video that YouTube's documented computer-download route requires signed-in paid Premium where available, exact eligibility/playback is untested, and free saved reading is the default alternative. Reuse the already-inspected [official computer-download instructions](https://support.google.com/youtube/answer/11977233?hl=en); no purchase/account is needed.

3. **Resolved: several current catalog caveats contradicted completed verification.** `reverse-depth-video-1` still says “Runtime needs metadata verification”; the access-control and Hashcat cards say the parent is checking captions/runtime. The saved direct metadata now verifies all these durations. The JSON also carries older evidence statements such as “indexed duration not fresh metadata verification” next to current direct-verification fields. Label earlier research statements historical or replace pending-work language with the current direct-metadata status while preserving untested playback. This is evidence reconciliation, not a reason to repeat retrieval.

### Focused recheck

The Windows ranges are now `[175,210]`, `[220,1366]`, `[1408,3209]`, excluding both the initial FTK mention and its acquisition segment. The resource explicitly requires supplied/pre-extracted hives in its limitations and excludes FTK and NirSoft. All 17 video access records now disclose signed-in paid Premium for the documented computer-download route and retain free alternatives; the collection has the same policy with the official help link. These two findings are closed.

The Ghidra and Hashcat pending-runtime wording is repaired. Hashcat now states direct metadata verification and retrieved captions without claiming playback. The earlier Windows/LNK timing evidence and GDB unknown-runtime evidence now have explicit historical labels and stage notes directing readers to current video records. The Wireshark source observation describes its earlier indexed retrieval; the adjacent current runtime-verification field and video metadata record establish the later direct check. No unresolved material finding remains in this lane. No external retrieval was repeated.

## Runtime checks passed

Independent assertions loaded each video's actual `info.json`, checked its ID and duration, verified all 34 metadata/caption SHA-256 values, and checked every selected interval is positive, within full duration, sorted and nonoverlapping. Each stored selected subtotal equals the sum of its intervals. There are 17 distinct YouTube IDs; no duplicate video is counted twice.

| Quantity | Independently calculated seconds | Duration |
| --- | ---: | --- |
| Original eight full videos | 6,214 | 1:43:34 |
| Nine new full videos | 25,040 | 6:57:20 |
| All 17 full videos | 31,254 | 8:40:54 |
| New selected sections, repaired candidate | 16,898 | 4:41:38 |
| Retained MFTECmd/Volatility sections | 2,352 | 39:12 |
| All selected sections including optional refreshers | 21,285 | 5:54:45 |

The collection correctly separates full lengths from selected lengths and reading/practice estimates. It does not claim twelve hours. The new selected subtotal plus retained workflow subtotal is not the all-video selected total because the latter also includes six optional refreshers; this distinction is intentional, not missing runtime.

## Focused boundary and alternative checks

- **Redaman:** Read selected and adjacent local caption passages. The first interval supplies self-injection context; the second covers x64dbg allocation/protection breakpoints and dump/map inspection. PE-Bear operation begins around 10:07, after the 10:02 cutoff. The IDA analysis around 12:57 onward lies outside the selections. The 19:33–21:53 interval returns to x64dbg and LoadLibrary path interception; a spoken reference to prior IDA findings is incidental. Its already-prepared-stage prerequisite avoids requiring the excluded IDA workflow. The catalog explicitly rejects the broad A/W-wrapper and packer-frequency generalizations. No additional approval defect found in these ranges.
- **dnSpy:** Read local 13:00–16:30 captions through breakpoint placement, Locals, Show in Memory and saving selected bytes. The presenter stops rather than running the recovered stage at 16:23. de4dot begins around 16:54, outside the selected interval; PEStudio/PortEx/Visual Studio are also excluded. The entry requires a supplied/pre-extracted managed stage. The free module-view guide teaches related dnSpy inspection; the catalog honestly says it does not reproduce byte-array dumping and excludes BepInEx/Mono setup.
- **Windows forensics:** The 53:29 cutoff excludes the later Prefetch segment: captions start Prefetch discussion around 58:50 and name the NirSoft viewer around 61:00. The repaired split ranges now also exclude the earlier FTK issue.
- **Hashcat:** Caption inspection confirms 3:00–5:29 is synthetic MD5/wordlist creation and hash-mode ambiguity, not installation. The selected range therefore does not contradict its instruction to skip installation. The potfile-preservation caveat remains useful.
- **Free alternatives:** All 17 video resources contain a free-reading-alternative URL. They map to relevant official manuals, creator worked guides or focused public documentation: Sonic Visualiser; Volatility; MFTECmd; Wireshark; Microsoft artifact interpretation; JLECmd; Ghidra training; the creator x64dbg walkthrough; dnSpy module inspection; Burp Repeater; CyberChef; Sage arithmetic; the basic Ghidra guide; LiveOverflow source/disassembly; access-control concepts; and Hashcat rule examples. Existing substantive inspection evidence is reused. Related-skill replacements are not represented as exact reproductions of every video case.
- **Hosted/offline limits:** The collection explicitly separates Academy server execution from saved text, makes paper/synthetic paths account-free, and retains playback/GUI/malware execution limits. No saved-HTML claim turns a hosted lab into an offline lab.

## Focused-recheck candidate hashes

```text
e6965f84f0afd6ba4fc4b1276e5de07bcd3ff461afdc9852d836b381f92dce3f  TOOL_LEARNING_COLLECTION.md
76b6d24e523dd63dbb002a70272bf900c603335e8d237caefe11b4a65e745f6a  TOOL_RESOURCE_CATALOG.md
154205d41614b2883e33c539af5504c2aa65c77a87ccdb1ed77740b12f2583a5  research/learning/video-coverage/collection.json
```

No videos played, accounts created, downloads made, messages sent externally or portal launches consumed. Stable external sources were not refetched. Caption inspection cannot verify visual transitions to the frame or actual application behavior; automatic captions can mistranscribe names/commands. This review does not claim measured learning gains or completeness of every tool-family workflow.
