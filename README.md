# Cyber SEA Game 2026 field guide

Open [index.html](index.html) directly in a browser. The guide provides **24 task routes across seven categories** and a searchable catalog of all **200 approved workbook entries**. Routes include local instructions, expected observations and fallback steps; tool entries retain curated references and platform/version caveats. The earlier `keyword-preview.html` link opens the same guide.

The tool filter runs locally. Instructions remain readable offline; external references need internet. Source review is not proof that an installed competition tool works. Use the [preparation guide](LEARNING_RESOURCES.md) for longer reading and study, and the [consolidated research](research/resources/CONSOLIDATED.md) for selection decisions.

To update the page, edit `guide-template.html`, `research/routes.json`, or the five reviewed collections in `research/resources/` (`forensics`, `web-network`, `reverse`, `media`, `crypto-foundations`). The approval authority is `research/inventory.json`, extracted from the canonical workbook by `extract_inventory.py`. Run `python build_catalog.py`, then `python tests/check_guide.py --catalog` and `python tests/check_recipes.py`. Run `node tests/check_browser.cjs` with the installed Playwright package/browser paths supplied through `PLAYWRIGHT_MODULE` and `CHROMIUM_PATH` when needed. No dependencies or server are needed to open the finished HTML.

Both HTML entry points and the linked preparation HTML pages are generated; edit their inputs instead. `build_notes.py` renders the existing Markdown documents with the already-installed `markdown-it-py` package (4.2.0 here); rebuilding those pages requires that build-time package. Opening the generated pages needs no Python packages or network. Run `python tests/check_notes.py` to verify the linked notes and their local anchors.

The old `research/queries-*.json` remains archival search research and is no longer the rendered catalog source. This directory also contains private recovery/source notes: building the local guide does not publish or approve publishing the whole directory.

The original project directory disappeared between 14 and 18 October 2026. This directory contains a new, standalone [field guide](index.html), recovery notes, and a session index. It does not contain the former site's source or build. Start with [RECOVERY_CONTEXT.md](RECOVERY_CONTEXT.md) before attempting to reconstruct that larger site.

The original work was a local, offline CTF reference site with search, a category start guide, approved-tool recipes, and challenge description/file intake. The last verified build in the session record was `d54992b4da12d2ca` on 14 October. Those checks apply to the lost build, not this directory. Read [EVENT_SOURCES.md](EVENT_SOURCES.md) for the newer tool review list and practice/competition guide supplied on 19 October; they supersede the old tool and category assumptions.

The source of record for recovery is the retained Codex session history under `/home/ubuntu/.codex/sessions/2026/` and the project session index at [recovery/sessions.tsv](recovery/sessions.tsv). The raw JSONL files have not been copied here because they contain account-related and credential-like material. Preserve them locally and review/redact them before publishing any part of them.
