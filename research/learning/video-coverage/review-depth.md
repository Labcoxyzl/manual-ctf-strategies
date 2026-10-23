# Independent instructional-depth review

Reviewed 2026-10-23 against the comprehensive-collection goal attachment. This review concerns the expanded collection, not the earlier 24-hour plan. No implementation files were edited.

## Resolved finding D1 — expose the inspected companion sources needed by assigned workflows

**Priority:** Medium. **Requirement:** Directly usable learning collection with genuine source-to-tool mappings and adequate instruction for important capabilities.

**Locations:** `TOOL_RESOURCE_CATALOG.md#reverse-depth-python`, `#reverse-depth-gdb`, and the matching `collection.json` resources. Related dangling prerequisite: `#reverse-depth-dotnet` mentions `reverse-8`, which is neither a catalog anchor nor a collection resource alias.

**Evidence and reachable failure:**

- Python extraction maps both essential pycdc (`kali-110`) and alternative uncompyle6 (`kali-145`) to the combined extraction/decompilation lesson, but its only learner-facing resource link is the [pyinstxtractor-ng README](https://github.com/pyinstxtractor/pyinstxtractor-ng). A fresh substantive read confirms that it teaches archive extraction/info/one-directory options, not pycdc/pycdas invocation, stderr versus recovered source, or uncompyle6 bytecode-version limits. The research observation explicitly says those separate READMEs and the classic extractor's worked output were inspected. Their URLs are not exposed as supporting sources for this lesson. Original tool links elsewhere remain useful, but the selected route does not tell the learner which companion sections deliver the claimed workflow. Saving the selected page alone leaves the decompilation stage unsupported offline.
- The GDB lesson assigns a dereferenced watchpoint exercise but links only [Examining Memory](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory.html). A fresh substantive read confirms that this page teaches `x` and related memory display; it does not teach `watch`, expression/address semantics, hardware limits or scope. Its research evidence says `Set-Watchpoints.html` was separately read, but the lesson does not link that required companion.
- The .NET practice tells the participant to pair the lesson with `reverse-8` for navigation. That identifier exists in the old refresher, not in this catalog; the new entry provides neither that cross-file link nor the upstream equivalent.

**Smallest repair:** Keep the combined lessons and existing selections. Add explicit companion links and bounded focus to the Python and GDB entries and their machine-readable evidence: classic extractor worked output (as explanatory context only), pycdc/pycdas usage and failure handling, uncompyle6 bytecode support, and GDB Set Watchpoints. Resolve `reverse-8` to its actual old-guide anchor or directly link the current dnSpyEx navigation reference. Do not add videos or duplicate courses. Recheck that the generated catalog carries these companion links, so the save-before-flight route preserves all required content.

## Focused D1 repair recheck — resolved

D1 is resolved. Exact named GDB and Python companion links and bounded focus appear in canonical JSON and rendered catalog. The extraction-tool distinction and decompiler version/error limits remain intact. The final .NET practice text now points to the linked dnSpyEx navigation reference and selected managed-memory scope; the stale “Pair with reverse-8” instruction is absent. Verified the canonical practice text is present verbatim in the catalog. No further finding remains within this focused recheck.

Current candidate hashes at final focused recheck:

```text
e6965f84f0afd6ba4fc4b1276e5de07bcd3ff461afdc9852d836b381f92dce3f  TOOL_LEARNING_COLLECTION.md
76b6d24e523dd63dbb002a70272bf900c603335e8d237caefe11b4a65e745f6a  TOOL_RESOURCE_CATALOG.md
92c371762dfeaaaebe56d6e81b33eaceef041fdc9d67fa4f9837755f7c1626a3  TOOL_COVERAGE_MATRIX.md
154205d41614b2883e33c539af5504c2aa65c77a87ccdb1ed77740b12f2583a5  research/learning/video-coverage/collection.json
```

## Other conclusions

- All 200 row identifiers are unique in the candidate; 48 rows carry the explicitly judgment-based essential priority. Essential rows have plausible targeted/workflow instruction rather than a blanket reference-only escape. Small utilities do not need a separate course.
- Resource sharing is generally bounded correctly: qpdf has its own concrete object/stream exercise, while the Didier Stevens investigation is credited to its actual tools; same-name/platform/version distinctions remain visible. The new audio and byte/offset exercises provide known-answer practice appropriate to their scope.
- The deeper tracks address real options, output interpretation, assumptions and limits. Their reading/practice estimates are explicitly planning estimates. Optional original introductory videos and selected portions of longer videos avoid a requirement to watch overlapping material twice.
- Restricted selections and limitations separate approved x64dbg/dnSpy/Zimmerman operations from unapproved setup and paid/online paths. Practice using already-owned inputs or paper analysis is permissible; absence of a bundled malware/image lab is not itself a finding.
- Recorded runtime arithmetic is coherent: existing 6,214 s, new 25,040 s, total 31,254 s; new selected portions 16,950 s. This review did not independently replay videos or redo the runtime audit. No demand to reach twelve hours is justified.

## Candidate identity

SHA-256 at initial review:

```text
a69dbd5f2e5df8ff7562bb87f3824d6b7f9a9e610b78b24da8cbfa6f9acd7dd6  TOOL_LEARNING_COLLECTION.md
3f76a4738f41672d9da6b0ef9a9885ec3be7607cf6e0335338f11bf69ed53754  TOOL_RESOURCE_CATALOG.md
206cf71dad08f7486924eda1e7cec7d8f14f23dbc8365cbf28194e62a1c2315b  TOOL_COVERAGE_MATRIX.md
f0b5e3e56adc0355710fed3fe928014809b695b0104c5965183114cec5be991f  research/learning/video-coverage/collection.json
```

## Limits

Reused existing substantive observations and captions evidence for undisputed sources. Independently opened only the two disputed primary pages above. Did not execute GUI/image/malware labs, replay videos, create accounts, install dependencies, download collections or revalidate every external link. Parent owns implementation and final validation. No other material instructional-depth finding was established.

## Post-review delta: Apktool source repair

Narrowly reviewed the replacement `reverse-depth-apktool` entry and rendered catalog. No finding: the versioned 2.x primary option page provides an appropriately targeted decoding lesson when paired with the already-selected AndroidAppRE workflow. The practice distinguishes DEX disassembly from resource decoding, calls out destructive `-f` output handling, and avoids claiming Java source recovery or rebuild proficiency. The approved 2.7.0-dirty version is preserved and newer 2.x flags are explicitly outside the assigned scope. Reused the parent's recorded direct-200/substantive-content evidence; no new fetch or APK execution was needed. D1 remains resolved.

Current hashes after this delta:

```text
998ef6b692dae766782c1671f34ed1a92b9ae7c17be223004dbde1216fe5a51c  TOOL_LEARNING_COLLECTION.md
5fafa1399f9dfad492a5aba9e1e618d365dc8634359f7cecf550d153d52414f6  TOOL_RESOURCE_CATALOG.md
53e52b54bc14159986e929cf8275c9cd6b9dc1f4ce5ac9d0ac7834753b0dc464  TOOL_COVERAGE_MATRIX.md
17e6e9a89510b7be8d1bd3ec02d493534f5d3a22a741401671fcd8c940e8215e  research/learning/video-coverage/collection.json
```
