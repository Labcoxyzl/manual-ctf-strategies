# Independent helper review

Status: complete; all three findings repaired and independently rechecked. No unresolved material defect was found within this scope. This review uses synthetic files and loopback services only. It never executes challenge binaries, extracts challenge archives, contacts assigned targets or installs tools. Shared scripts were read-only for the reviewer.

## Initial findings

1. **Short HTTP bodies reported success.** `http_probe.py` read the response with `read(65537)`. CPython deliberately does not raise `IncompleteRead` for this bounded-read form. A loopback response advertising 100 bytes and closing after `abc` printed that body and returned 0. The smallest repair must check response-body completeness while retaining the preview bound and respecting bodyless status codes and chunked framing.
2. **Impossible ZIP member offsets reported complete metadata.** A 115-byte ordinary ZIP whose central-directory local-header offset was changed from 0 to 215 returned `complete`/0 and claimed validated directory metadata. `7z l` on the identical bytes returned 2 with `Headers Error`. Validate that a classic member's minimum local header fits before the central directory; no extraction is needed.
3. **The binary parser blocked opening a FIFO.** A named pipe without a writer remained stuck in `open()` until the review harness killed it at 0.7 seconds. The other two file helpers promptly rejected the same pipe. Reject nonregular input without a blocking open.

Initial evidence: `before-repair-results.json`, `before-fixtures.json`, and `before-fixtures/`. All seven shared helper hashes were unchanged across the initial run. Original reproducer: `review_helpers.py`.

## Initial controls

- 100 arithmetic questions with split tokens, coalesced questions, signed exact division, negative floor division/remainder, and a split completion marker all passed. The server independently checked every answer. This local run took 0.233 seconds including interpreter startup; it does not establish performance on a remote challenge.
- Nonintegral division, division by zero, unexpected banners, non-ASCII expressions, oversized lines and early EOF returned explicit nonzero failures without guessed answers. A CRLF question received the right answer; the intentionally absent completion marker still caused failure.
- A math slow-drip service hit the total protocol budget. HTTP body stalls failed at the socket timeout. HTTP slow-drip exceeded the numeric timeout and completed, matching its explicitly documented per-socket-operation contract.
- HTTP chunked truncation, oversized bodies and redirects failed. Header count and value truncation were labeled. The redirect was not followed.
- File preview escaped control bytes, printed offsets and preserved input files. Basic inspection attributed its classification to `file`, agreed with the direct baseline, and explicitly said unhandled content was not examined.

## Repair verification

The parent repaired the three shared helpers. The original HTTP fixture now returns 1 with `expected 100 bytes, received 3`; the impossible ZIP offset returns `invalid_input`/2; the FIFO returns 1 in 0.017 seconds. All 37 original command observations have the expected exit status after repair. Their complete stdout/stderr remains in `independent-results.json`; the pre-repair results remain separate.

All 34 checks in `heldout_boundaries.py` passed. They cover valid HTTP 204/chunked/close-delimited bodies, zero and exact 64 KiB size boundaries, truncated bodies, ZIP offsets at and beyond the directory/EOF, binary records at offsets 0/1/4097, fragmented transport delimiters and raw bytes, slow-drip replies, failed late-bit output, source preservation and opaque-file classification. Direct `file` agreed with the opaque-file classification. Python's full-body HTTP reader independently rejected the original short body with `IncompleteRead`. `heldout-results.json` records the checks and command outputs.

Eight additional checks exercised the newly introduced HTTP validation: matching/conflicting duplicate lengths, negative/signed/nondecimal lengths, an oversized decimal length, unsupported transfer coding and too many headers. All produced the intended success/failure statuses. See `new-header-branches.json`.

The math demo completed all 100 questions through the client in local process mode. Its independent explicit `wrong\n` input returned 1 without a completion marker. See `demo-results.json`.

`verification-summary.json` binds the outcomes to the exact seven helper hashes. Those hashes were stable across every post-repair run and matched the current shared files at review closure. Reproduction commands:

```sh
/opt/ctf-tools/py312/bin/python research/validation/review-scripts/review_helpers.py
/opt/ctf-tools/py312/bin/python research/validation/review-scripts/heldout_boundaries.py
```

The helper benefit established here is bounded, repeatable handling with explicit failure and preservation behavior. The arithmetic benchmark is a local protocol test, not proof of remote challenge speed. The core inspection helper still reports a bounded classification and selected metadata; it does not decode opaque files or establish archive extraction safety.

Not checked: remote challenge protocols, unknown executable behavior, native Windows, Kali, and Python 3.10. No completion or performance claim extends to those environments.
