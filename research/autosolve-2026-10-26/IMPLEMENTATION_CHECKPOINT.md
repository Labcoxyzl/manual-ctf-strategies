# Autosolve implementation checkpoint — 2026-10-27

The implementation goal is **active**. The broad acceptance target remains the
proposal's 55 original baseline families across eleven domains, plus two AI
baselines, with row-specific
positive, two held-out and negative cases, an all-domain gate, clean rootless
setup, preservation, and report/resume checks. A working partial profile is
not a completed baseline family or a challenge solve-rate claim.

## Integrated runner

`scripts/autosolve.py` has private manifests, source hashes, job fingerprints,
bounded workers, derived artifacts, candidate states, a family ledger, a run
lock, and resume. Implemented paths now include finite encoding/classical
ciphers, single/repeating XOR, declared RSA/AES/hash checks, ZIP/TAR/MIME/PDF/
Office extraction, PNG tails, image metadata/views, zsteg, Stegseek, QR,
FFmpeg media views/frames/subtitles, SSTV, offline CAN/DBC, TShark packet
inventory, HTTP objects, TCP stream evidence and keylog-backed TLS, SQLite/WAL,
read-only TSK disk inventory/recovery, selected OS artifacts, Volatility memory
triage, static ELF/PE intelligence, local web snapshots, bounded live path
discovery, scoped service transport/inventory, and the separately contributed
chatbot command. Missing engines and unsupported operations remain explicit.

Review/fix loops repaired stale shared-child lineage, invalid RSA/AES hint
findings, old private hint ingestion after a replacement hints file, wrong
ZIP-password retirement of a child with a valid Base64 parent, unfair initial
scheduling under heavy RSA hints, transformed passwords with surrounding
spaces, source-reversion intelligence, and false operation labels on reused
shared artifacts, a POST-only upload mislabeled as a response object, and
stale source locators on shared artifacts. The frozen publication worktree
passed 501 autosolve tests
(17 optional skips), nine copied-export tests, Python compilation and
`git diff --check`. The runner is still a partial implementation under the
proposal's broader acceptance gate.

## Independent end-to-end evidence

- A local ret2win ELF/service has an independently replayed exploit oracle.
  Autosolve's PWN02 static pass now reports NX, no PIE/canary, partial RELRO,
  `win` at `0x401196`, and bounded gadget leads. PWN01 captured the exact
  loopback exploit transcript and PWN07 recorded open/closed ports and an
  explicit probe. Neither claimed challenge acceptance; resume made no second
  connection. Evidence:
  `/tmp/autosolve-pwn-e2e-KlkbeB/EVIDENCE.md`.
- Independent single-byte XOR and AES-GCM cases matched exact oracle bytes.
  An AES finding initially failed to enter the artifact scanner; verified GCM
  plaintext now becomes a source-linked private artifact and its pattern
  candidate retires on wrong-tag resume. Evidence:
  `/tmp/autosolve-crypto-e2e-mbrbrjvn/`.
- A real RFID bitstream and Matryoshka ZIP were exercised earlier. The
  runner recovered exact expected bytes but did not claim accepted flags.

## Remaining order

1. Complete group-two acceptance on real held-out CAN, memory, audio and packet
   cases. The new rootless Python core environment works in a clean source
   copy; native multimon-ng and several approved engines remain missing or
   unprobed. A compatible Windows memory image/symbol set is still needed.
2. Continue group-three reversing, web and OSINT baselines. Local static and
   scoped transport paths exist; deeper rule, packer, checker, web workflow
   and source-attribution cases remain.
3. Run every baseline acceptance row, cross-category chains, packaged fresh
   setup, report/resume and preservation gates. Keep release status partial
   until these pass.

The repository has concurrent unrelated guide edits. At this checkpoint,
`package_toolkit.py` expects 36 public task routes while `index.html` contains
35, so the distribution gate stops before autosolve export smoke tests. Git's
local `core.bare` was also changed concurrently to `true`; use an explicit
`--git-dir=.git --work-tree=.` for read-only diff checks. Neither unrelated
state was changed here. The user subsequently authorized remote checkpoint
pushes; the verified checkpoint is prepared on the isolated
`autosolve-progress-2026-10-27` branch for publication after review.
