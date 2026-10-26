# Coverage status — 27 October 2026

The current [route data](../../research/routes.json) has 33 task routes across all seven event categories. They use 70 distinct approved entries; the [catalog](../../README.md) still lists all 200. Route count and tool count are navigation measures, not proof that an unseen challenge is solvable from the guide.

The guide added supplied-wireless-capture, EVTX, native-crash-triage, ZipCrypto, registry-hive, SQLite/WAL, SQL-condition, server-fetch, and object-authorization routes. Each has a local [specialist workflow](../../SPECIALIST_WORKFLOWS.md) and primary source references. The guide/export checks, 9 distribution tests, five browser sizes, and 12 benign recipe checks passed; `pngcheck` was unavailable for one recipe. The native route's checksec, ROPgadget, and cyclic commands ran on a benign local ELF. The SQLite check read a committed row from a copied database/WAL/SHM set. Wireless conversion, EVTX parsing, registry parsing, bkcrack recovery, and the new web routes remain source-reviewed only and have not run on competition machines or live challenge services.

Next useful coverage questions, chosen from approved tools and routes:

1. Cryptography: add a branch guide for XOR/stream reuse, symmetric mode prerequisites, and oracle evidence. Reuse CyberChef, Python, OpenSSL, and the existing bounded helpers where they fit; do not treat candidate decoder output as validation.
2. Forensics: map mobile artifacts and browser-profile parsers beyond direct SQLite to source-backed procedures and representative benign fixtures. Keep missing parsers, sidecars, and time-zone ambiguity explicit.
3. Web: cover context-specific browser output and cross-site request flows only where an offline procedure can distinguish a real effect from reflection, cache, or session behavior. The new SQL, fetch, and authorization routes are starting checks, not proof for every web flaw.
4. Native exploitation: the crash route establishes control and mitigations, not a working exploit. Only add a specific exploit workflow when a safe synthetic target and independent success check justify it.

For each new route, require an approved-tool baseline, input preconditions, a checkable result, one failure path, a bundled local guide, and an offline-export check. Competition-machine availability and arbitrary unseen challenge coverage remain unverified. No live challenge content or secrets belong in this record.
