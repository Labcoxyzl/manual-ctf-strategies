# Independent curriculum review

Reviewed 2026-10-22 against the goal attachment, inherited working agreements and `/home/ubuntu/sgco/AGENTS.md`. Review only; no curriculum implementation edits. Scope: learning value, actionable practice/assessment, time allocation, and breadth rationale. Existing content evidence was reused; no disputed external factual claim required new browsing.

## Resolved finding: add a bounded independent interpretation pass to the two forensic practice slots

**Priority:** Medium, curriculum-quality repair. This does not require a disk or memory image, tool installation, video playback, or proof of measured learning gains.

**Requirement:** A practical 24-hour refresher for a rusty CTF participant, with each block earning its allocated study time through concrete skills and assessable practice.

**Locations:** `LEARNING_RESOURCES.md`, sequence blocks 3–4; `research/learning-resources.json`, corresponding schedule entries; `PRACTICE_WORKSHEETS.md:43–64`.

**Evidence:** Block 3 allocates 80 exercise minutes, but supplies one offset calculation, one metadata-address distinction, and generic questions about an unspecified record. The artifact exercise gives no actual name/timestamp/journal rows to investigate. Its answer omits a concrete recovery-command example and the expected MFTECmd input/output answer. Block 4 allocates 50 exercise minutes but supplies a single three-process chain, two open-ended evidence questions, and one setup-error explanation. The successful draw and symbol-failure explanation are already effectively disclosed in the prompt. Comparing the official tutorial is useful reading, but there is no second supplied case or explicit independent command/result interpretation pass. Optional real-image work cannot be assumed to fill the remaining practice budget because neither input is supplied or required.

**Learner impact:** Both routes are usable and accurately disclose their limits, but a rusty participant who completes the small recall task must invent further practice to use the advertised slot. The general instruction to repeat exercises does not provide a new forensic case after the first answer is known. The weakness is directed practice depth, not the absence of a large executable lab. No empirical completion-time claim is made here.

**Smallest repair:** Retain the paper routes and add one bounded second pass per block with supplied inputs and answer checks. Disk: provide a small partition/file listing, ask for the exact recovery command, and give a few synthetic same-file journal rows from which to order rename/deletion events. Memory: provide two small process-output views with one missing parent or name ambiguity, ask the learner to reconcile the evidence and write the tutorial command sequence, then grade specific supported versus unsupported conclusions. Assign rough sub-budgets to these passes and close notes for the final pass. Alternatively shorten these slots and explicitly assign the recovered minutes to other named independent drills; do not merely pad reading or require unspecified images.

## Focused repair recheck — resolved

Re-read only worksheet blocks 3–4 and the corresponding guide/schedule entries after integration. The finding is resolved; no unresolved finding remains in this review scope.

- Disk now supplies a second listing and deliberately unordered journal rows. The command pass distinguishes sector and byte offsets; the keyed interpretation separates `(42, 7)`, `(43, 2)` and reused entry `(42, 8)`, correctly orders create/rename/delete, and checks attribution and recoverability separately. MFTECmd source/export answers are explicit.
- Memory now supplies a second process case with same-named processes and missing parents. The key reconstructs both chains, keeps process identity distinct, pairs two hypotheses with evidence requests, and supplies the tutorial command sequence. It correctly labels the tree as another rendering of the same evidence, not independent corroboration.
- Both cases include bounded sub-budgets, a closed-note retry and ten explicit assessment checks. The caps sum to 80 and 50 minutes. The guide and JSON preparation/assessment text now point to those supplied cases. No real image or executed GUI session is required to complete the paper route.
- The existing 1,440-minute schedule remains intact. These are planning caps, not measured learner timings; the text tells learners to finish early when checks are met. This is sufficient directed practice for the stated refresher without expanding the resource list.

Current relevant candidate SHA-256 values at focused recheck:

```text
5e869b28a6fb6d21d76796472906369c6c9d4f8319de9fb12f20542fd063b15c  LEARNING_RESOURCES.md
4f1c67e2737aeda41cdff3858ce820daaa69463569e5e80e1b7c8fba989464a6  PRACTICE_WORKSHEETS.md
b522fa37836a429d93d9ebfa00a710fa8c33c1f67332641172f18d5df0675100  RESOURCE_EVALUATION.md
0bbdb9ba9868a37db49fe8702a7370c17d724681921b32344057ce0a5772b31d  research/learning-resources.json
```

## Other conclusions

- The selected resources have bounded focus, prerequisites and access/offline notes. Video substitutes and free reading alternatives are clear. No material breadth finding: reference-only rationales identify concrete triggers and distinguish related interfaces from actual proficiency.
- Paper exercises are a legitimate option under the request's exercise-or-recall-check requirement. Their existence alone is not a defect, and unperformed optional GUI/image execution is honestly disclosed.
- All ten blocks have diagnostics, outcomes, preparation, exercises and checks. A focused local JSON check found 43 retained resources, 200 coverage entries, 1,440 total scheduled minutes, and no per-block allocation mismatch.
- No new subscriptions, accounts, downloads, portal interactions or dependencies were used.

## Original candidate identity (before repair)

SHA-256 at review time:

```text
e88d2254a7c6cf509f1a21144c6edf703228029ffdfc1cd50366f3f9289da227  LEARNING_RESOURCES.md
41397ad0bd4be062d9d057bf605f73a9bc09c5ba7414fb05b10fc3510cdb1da8  PRACTICE_WORKSHEETS.md
b522fa37836a429d93d9ebfa00a710fa8c33c1f67332641172f18d5df0675100  RESOURCE_EVALUATION.md
8ee127ac9de71ece09cf5ee47c0498abc412f69faaf01c35893b25a62bcbe11b  research/learning-resources.json
```

This review does not independently revalidate all external links or every inventory mapping, execute tools/GUI labs, or measure learner completion times. Parent integration owns the repair and final-state verification.
