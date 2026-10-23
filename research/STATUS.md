# Keyword research and testing status

Owner: goal thread `01a152b0-847e-7613-8840-bd600a158a3d`.

The swarm completed `inventory.json`, `queries-a.json` (Windows 1–39, Kali 1–27), `queries-b.json` (Kali 28–94), `queries-c.json` (Kali 95–161), and `categories.json`. Query records contain inventory ID, category, primary and alternate queries, a usage reference, purpose, and evidence note. Independent review reconciled all 200 source IDs and checked tool identities. Installation uncertainty, particularly PySSTV versus the named SSTV decoder, is retained explicitly.

Google redirected the first live query to its unusual-traffic challenge. See `google-results.md` and `google-results.json`. Actual AI Overview comparisons remain incomplete; no winning queries have been established.

Another concurrent session was modifying `index.html` and `scripts/build_tool_index.py`. This thread has **not modified the page** and is awaiting the user's decision on integration ownership. `build_catalog.py` generates the separate [keyword preview](../keyword-preview.html) from the current page and research data; it never writes `index.html`. The preview includes all 200 approved entries and seven category queries with a visible unverified-AI-Overview notice.

The final preview SHA-256 is `5552d18c1f32473981b296d6201c0a7d6c5f7326dda700772cd34087a8f6dc11`. `testing-preview-static.json` and `testing-preview-browser.json` establish exact ID/query/reference coverage, all seven category searches, keyboard expansion, offline local loading, navigation, no document overflow, and query-label consistency at 320×900, 390×900, 768×900, 1440×900, and 667×375. Desktop and mobile screenshots were inspected. Print navigation hiding was checked; complete printed-document layout was not audited.

`testing-query-links.json` records 203 unique documentation URLs: 202 reachable and one Adobe page blocked with HTTP 403, with no remaining observed 404s. This is availability evidence, not proof of every documentation statement. Research notes retain fetch limitations. No approved binaries were executed on organiser machines.

Reproduce the preview with `python build_catalog.py`, then check it with `python tests/check_guide.py --html keyword-preview.html --catalog`. `python tests/check_guide.py --query-network` checks research links using cached successful observations. `tests/check_browser.cjs` uses the preinstalled Playwright package/browser and records the tested page hash. Rebuilding from a changed `index.html` invalidates prior rendered evidence.

Remaining requirements: decide which session integrates the preview into the main page; then validate the final main page. Once normal Google access is available, run the pending comparisons in `google-results.json` for all 200 tools and seven categories. All scores remain null; the goal is active and not complete.

Continuation audit: the first goal turn produced the complete researched preview and tests. On the second goal turn, all saved preview, test-input, link-report, and Google-candidate hashes were revalidated against current files. The competing `01a152b0-81a6` session has a terminal completion event, while the originating `01a15295` session has started a further turn; ownership has not been resolved by a user reply. No main-page write or Google challenge retry was performed. The same two remaining dependencies persist for a second consecutive goal turn; completion remains unproven. Do not launch another research swarm or repeat passing checks without a changed input or concrete remaining defect.

Existing browser evidence applies to the page state it observed and must be checked against its recorded hash before reuse. Historical tests of the lost application do not validate this static guide.

## Third-turn reconciliation

The other session integrated the catalog: current `index.html` and `keyword-preview.html` both have SHA-256 `ec96aaa993ba8cbc5b5f008bb52495533b3c80ba1929d22a10922b742ca8a83e`. `build_catalog.py` now reads `guide-template.html` and writes both pages; the earlier preview-only description above is historical. Main-page `testing-static.json` and `testing-browser.json` match the current HTML and research inputs. Their checks establish all 200 tool records, seven category searches, and the five recorded viewport/interaction cases. Integration no longer requires an ownership decision.

The previous turn was a revalidation with no new implementation progress. This turn found completed integration and reconciled its current evidence. Google access remains blocked for the third consecutive goal turn, with all 207 tool/category comparisons unmeasured. There is no remaining local repair that can establish AI Overview quality. The goal is being marked blocked, not complete; resume once normal Google access permits the pending comparisons. Do not repeat the passed local checks unless their inputs change.
