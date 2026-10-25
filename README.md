# Manual CTF Strategies

[Open the guide](https://labcoxyzl.github.io/manual-ctf-strategies/) for 24 challenge routes, an offline search, and 200 tool entries from the Cyber SEA Game 2026 approved workbook. Tool approval and competition rules are specific to that event.

- **Start solving:** [Core workflows](CORE_WORKFLOWS.md) and [practice worksheets](PRACTICE_WORKSHEETS.md).
- **Find a tool:** [All-tool cheatsheet](CTF_CHEATSHEET.md) and [approved-tool references](APPROVED_TOOL_REFERENCES.md).
- **Crack hashes:** [Hashcat cheatsheet](HASHCAT.md).
- **Try the examples:** [Synthetic practice files](examples/core/README.md).
- **Use a script:** [Python helpers](scripts/README.md), [challenge templates](scripts/templates/README.md), and [no-AI Python requirements](requirements.txt).
- **Prepare for the event:** [Learning resources](LEARNING_RESOURCES.md), [rules](docs/public-rules.md), and [source notes](EVENT_SOURCES.md).

## Install

Use Linux, Kali, or WSL with Git and CPython 3.11 or 3.12. The repository is private, so clone with a GitHub account that has access. For a new checkout, run:

```sh
git clone https://github.com/Labcoxyzl/manual-ctf-strategies.git
cd manual-ctf-strategies
python3 --version  # Confirm 3.11.x or 3.12.x before continuing.
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --only-binary=:all: -r requirements.txt
python -m pip check
python scripts/ctf.py doctor --workflow bytes
python scripts/templates/math_client.py --local python scripts/templates/math_demo.py
```

If you already have a checkout, start at `python3 --version` in its root. The install uses both [requirements.txt](requirements.txt) and [constraints.txt](constraints.txt). The byte helpers work without these packages; [setup and limits](scripts/README.md#setup) explain the optional stack.

To update the site and generated cheatsheet, edit [the guide template](guide-template.html) or [task routes](research/routes.json), then run `python build_catalog.py`. Run `python tests/check_guide.py --catalog`, `python tests/check_notes.py`, and the relevant tests before publishing.
