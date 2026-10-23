# Resource consolidation plan

The competition reference should help a participant move from an observed artifact or task to an approved tool, a short procedure, and an interpretable result. Preserve the existing dependency-free guide and all 200 approved workbook row identities. This phase researches and ranks content; website implementation follows the consolidated recommendations.

## Research ownership

Five agents own separate JSON outputs, using the existing `research/learning/*-input.json` partitions: forensics (40 rows), web/network (31), reverse/malware (51), media (23), and crypto/foundations (55). Root owns integration and review records. Existing input files, catalog records, and website files remain under their existing ownership.

Each tool record contains its approved ID, challenge use, category mappings, one to three useful resources, source-verification status, priority, caveats, and a recipe candidate where justified. Reuse prior references; label inherited evidence separately from sources inspected during this pass. Generic utilities do not need fabricated challenge recipes. Agents may request a spare slot for a specific independent investigation.

## Ranking and consolidation

After the research files are complete, separate reviewers assess technical accuracy and competition utility. Prefer a source that directly answers the task, matches the relevant version, explains inputs and outputs, and is easy to scan. Keep an alternative only when it adds a distinct capability or resolves a limitation. Source authority alone does not make a lengthy manual the best starting page.

Organize the website under the seven official categories: Digital Forensics, Malware Analysis, Web Security, Reverse Engineering, OSINT, Cryptography, and Miscellaneous. Give shared tools one canonical explanation with links from relevant tasks. Keep platform-specific approval rows and caveats even when descriptions are deduplicated. Lead with short routes; place supporting references and specialist alternatives in expandable material.

Recipe candidates become published instructions only after source review and appropriate fixture checks. A linked upstream script is not automatically an approved standalone application or a verified local script. Record dependencies, expected input/output, version limits, and execution evidence before labeling a script tested.

## Implementation and acceptance

Load frontend-design before changing the interface. Extend the current template and generator rather than introduce a framework. Preserve offline access to locally authored instructions; external references require connectivity. Check exact approved-ID coverage, seven-category navigation, source links, keyboard access, narrow layouts, and affected interactions. Run the existing relevant checks after implementation; prior browser evidence does not validate changed HTML.

A separate bloat review removes duplicated explanations, low-value alternatives, and material that does not help choose a tool, perform a task, or interpret a result. Repeat review for concrete unresolved findings, not indefinitely. Retain necessary safety, approval, platform, and accuracy caveats. Keep internal source documents, credentials, and raw session logs out of public artifacts. Do not publish or push as part of research.

Paul's earlier remarks were not found in the project notes. This plan reflects the user's current description. The historical Google AI Overview comparison blocker does not block primary-source resource research.

## Implementation contract after plan review (22 October)

Inventory remains the approval and platform-metadata authority. The catalog generator will read the five reviewed resource JSON files instead of displaying the older query records. The mixed `recipe_candidate` proposals are research only; author a separate `research/routes.json` containing 24 explicit task routes. Preserve the existing category fragment IDs and both generated HTML entry points.

Route records have `id`, `category` (existing slug), `title`, `input`, `tool_ids`, `steps` (short text list), `expected`, `fallback`, `caveat`, `verification` (source-reviewed, not runtime-tested unless supported), and `references` (objects with `title` and `url`). Keep reference URLs grounded in the research; do not invent commands or silently claim generic recipes were executed. A route may provide GUI actions or short commands; a new standalone script is justified only by a specific unmet workflow and must have a synthetic test. Link existing upstream examples where sufficient.

Use one canonical catalog entry per approved ID, grouped by its first official category. Each entry preserves purpose, curated references, material caveats, and inventory version/location/remarks. Cross-category route links target this entry and must open its containing details element and scroll below sticky navigation. Link the existing preparation guide once; do not reproduce its schedule or videos.

Keep the current palette, typography and dense layout. Add a labelled local tool filter by name, ID, purpose and category, with a result count, no-results message and clear/reset behavior. Filtering opens matching catalogs and clearing restores the ordinary browsable view. No network request or third-party runtime is needed. With JavaScript unavailable, categories and native details still expose all instructions and entries.

Tests must follow the new contract: remove assertions requiring obsolete Google prompts, retaining the archival query-data check when explicitly requested. Require exact 200-ID coverage, selected resource links and material caveats, seven categories, 24 complete routes, unique anchors, valid local links and inventory metadata. Browser checks cover keyboard details, local filter success/empty/reset, cross-category tool links revealing hidden targets, route instructions offline, mobile/landscape overflow, navigation and console errors. Test representative locally available commands on benign fixtures; label other procedures as source-reviewed only. Do not weaken checks to hide a failure.

Implementation owners: one route-content writer, one template/interaction writer, one generator writer, one checks writer, and root integration/documentation. Only root regenerates final HTML after compatible source changes are ready. Independent final reviewers assess content and rendered UI; repairs reopen only affected checks. No package installation, portal use, public hosting or git push is needed for this implementation.

Plan review disposition: accepted the data-source/test-contract mismatch, exact-tool discovery gap, closed-details link behavior, and missing explicit offline procedure fields. The separate learning guide remains intact. No evidence currently justifies a new standalone script collection. Proceed after a bounded independent gate check verifies these corrections against the task; further review requires a concrete unresolved defect.

## Implementation result

The independent gate accepted the revised contract. Separate owners implemented route content, generator, template, checks and benign recipe fixtures; root integrated both HTML outputs and README. Final independent content/UI reviews returned no unresolved blocking findings. The two content findings (literal backticks in input summaries and generated-page drift after a final command edit) were fixed and the final artifact rechecked.

- Final HTML SHA-256: `6711c5177ebd3a97c550b7fa520e5d370777cee1cc9890459af5658f70f9002b`; both entry points are identical.
- `python tests/check_guide.py --catalog`: passed exact 200 IDs, 24 routes, source links/caveats/metadata, anchors and alias equality.
- `node tests/check_browser.cjs` with installed Playwright/Chromium paths: passed 320×900, 390×900, 768×900, 1440×900, 667×375; offline routes, keyboard controls, filter success/empty/reset, canonical and direct-fragment links, overflow, navigation, no-JavaScript fallback and print-navigation behavior. Screenshots were inspected independently.
- `python tests/check_recipes.py --report`: 10 passed (eight published commands plus two malformed-input controls), one unavailable pngcheck step skipped. Evidence ties the checked commands to route SHA-256 `2193bde7bcdad6c53f16cb92ebe5be042880a64faf8c31998397d7f89a26a712`.
- The first browser run failed because an immediate visibility assertion preceded asynchronous hash navigation. A diagnostic confirmed eventual correct product state; the test now waits for observable visibility and scroll completion while retaining its assertions. Final checks passed on the rebuilt artifact.

No new production dependency or standalone script collection was introduced. Source-reviewed instructions remain labeled; these checks do not verify every route, external URL or competition-host installation. No portal sessions, public hosting, package installation or git push occurred. The recursive review stopped after supported findings were repaired and relevant checks passed.

## Follow-up review and repair

A further independent cycle checked keyboard continuation, repeated/invalid hashes, Back navigation, local document navigation and build validation. Keyboard/hash behaviors passed. Platform filtering and printing closed route instructions were identified as optional extensions outside the existing contract, not manufactured into required repairs.

Finding C3 was reproduced: the preparation link opened raw Markdown in local Chromium, with no clickable study links. The repair renders seven explicitly linked notes to local HTML, rewrites their note links, preserves authored anchors and practice-file paths, and leaves every Markdown source untouched. `build_notes.py` reuses the already-installed markdown-it-py 4.2.0 as a build-time dependency; generated pages remain standalone. The source footer deliberately offers raw Markdown separately.

Independent content and UI rechecks confirmed C3 resolved with no new defects. The final guide hash is `442551737219d2d364e856b2d78388ab7a031b44fa0a0a855c80204a9dc0d4be`. Static catalog checks, the seven-document notes/link/fragment checker, and the expanded five-viewport browser suite passed. Browser coverage now follows guide → preparation → worksheet block 2 → guide and tests all seven notes at 320px, including keyboard-scrolling tables. A new immediate keyboard-navigation assertion initially raced page loading; explicit expected-URL waits resolved the test race without removing its assertion. Evidence is in `research/testing-static.json`, `research/testing-notes.json`, and `research/testing-browser.json`; reviewed notes screenshots use `research/ui-review-notes-*.png`.

Recipe inputs are unchanged, so valid earlier fixture results were retained rather than rerun. No external-link sweep, organiser-machine check, publication or package installation was performed. This cycle stops with no unresolved required finding; new evidence should determine the next review question.
