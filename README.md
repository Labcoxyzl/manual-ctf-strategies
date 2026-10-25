# Manual CTF Strategies

[Open the guide](https://labcoxyzl.github.io/manual-ctf-strategies/) for 24 challenge routes, an offline search, and 200 tool entries from the Cyber SEA Game 2026 approved workbook. Tool approval and competition rules are specific to that event.

- **Start solving:** [Core workflows](CORE_WORKFLOWS.md) and [practice worksheets](PRACTICE_WORKSHEETS.md).
- **Find a tool:** [All-tool cheatsheet](CTF_CHEATSHEET.md) and [approved-tool references](APPROVED_TOOL_REFERENCES.md).
- **Crack hashes:** [Hashcat cheatsheet](HASHCAT.md).
- **Try the examples:** [Synthetic practice files](examples/core/README.md).
- **Use a script:** [Python helpers](scripts/README.md), [challenge templates](scripts/templates/README.md), and [no-AI Python requirements](requirements.txt).
- **Prepare for the event:** [Learning resources](LEARNING_RESOURCES.md), [rules](docs/public-rules.md), and [source notes](EVENT_SOURCES.md).

From the repository root, run `python3 scripts/ctf.py doctor --workflow bytes` to check the dependency-free helpers. The script guides explain setup, limits, and manual alternatives.

To update the site and generated cheatsheet, edit [the guide template](guide-template.html) or [task routes](research/routes.json), then run `python build_catalog.py`. Run `python tests/check_guide.py --catalog`, `python tests/check_notes.py`, and the relevant tests before publishing.
