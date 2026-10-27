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
shared artifacts. The first isolated publication checkpoint passed nine
copied-export tests and the repository's full pre-push gate (575 passed, 22
optional skipped); commit `b8aca2c` is on the remote
`autosolve-progress-2026-10-27` branch. Subsequent group-three work adds
PyInstaller, Java/Android, PowerShell, a bounded angr checker with explicit
local-execution and replay gates, selected WEB03/WEB08 checks, and a declared
arithmetic service. All 57 baseline IDs have source-visible code paths, but
the row-specific transfer gate is still incomplete.

The second isolated snapshot passed 630 CPython 3.12 autosolve tests (17
optional skipped), nine copied-export distribution tests and the repository's
full pre-push gate (695 passed, 35 optional skipped). Commit `f34b805` is on
the same remote progress branch.

The reviewed NET02 wire-completeness repair passed its isolated copied-export
gate and the repository's pre-push gate (699 passed, 35 optional skipped).
Commit `35020b4` is published. The next snapshot adds reviewed encrypted 7z,
IMG02 bit-plane, IMG05 DataMatrix readiness, JWT optional-engine identity,
AV06 frame timing and Java no-perfdata changes; its full gate is pending.

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
- The official ROP Emporium ret2win handout produced the correct static ELF
  mitigations, target and gadget. A separate synthetic-marker replay proved a
  manual exploit, while autosolve made no exploit or acceptance claim.
  Evidence: `/tmp/autosolve-e2e-pwn-public-20261027/EVIDENCE.md`.
- Two official Wireshark captures yielded HTTP objects byte-for-byte equal to
  independent TCP/HTTP reconstruction. Damaging a response withheld the
  incomplete object; resume reused the exact artifacts. Evidence:
  `/tmp/autosolve-e2e-group2-20261027/EVIDENCE.md`.
- Independent loopback WEB03, WEB08 and MISC01 controls exercised positive and
  negative behavior and made no requests on resume. Real rootless engine
  probes covered DTMF, Morse, AFSK, SSTV, CAN/DBC, capa, YARA and UPX.
  Evidence: `/tmp/autosolve-e2e-web-service-20261027/EVIDENCE.md` and
  `/tmp/autosolve-engine-probe-20261027/EVIDENCE.md`.
- Frozen encoding, document, image and reversing cases found routing,
  provenance and privacy defects, then checked fixes against new unseen
  inputs. A public Cridex memory image exposed empty process triage; a bounded
  `psscan` fallback now recovers its independently documented process but
  leaves command/file coverage partial. Evidence is under
  `/tmp/autosolve-heldout-{encoding,documents,reversing}-20261027/` and
  `/tmp/autosolve-memory-e2e-20261027/`.

The later frozen case ledgers report 12/12 scoped PWN01/02/07 checks,
12/12 WEB03/WEB08/MISC01 checks, 17/17 ENC06/07/08/10 checks, and exact
first-use transfers for ENC01/02/05, DOC01, IMG01 and a second Windows-memory
dump. A separate WEB01 oracle expected `same_origin` for unresolved relative
URLs; the original strict result remains 3/4 and a newly frozen correctly
scoped case passed. The first NET01/02/03 and CAN01/02 ledger met 19 of 20
row/case slots. A later reviewed NET02 repair passed two freshly sealed
out-of-order and chunked/gzip transfers with byte-exact, wire-verified bodies;
missing and conflicting TCP data stayed withheld. NET01 still labels the
reordered capture `truncated`.
These are local/public-corpus observations, not the complete 57-row acceptance
gate or a competition solve-rate measurement.

Further frozen evidence includes 17/17 AV01–AV04 checks, AV06 QR/frame/subtitle
transfers, exact IMG02 bit-plane and DataMatrix results, exact encrypted 7z
with wrong-password controls, 157/157 OSINT checks, and 71/71 checks on four
cross-category chains. A copied export installed the 24 hash-pinned core
packages; direct Java launcher flags removed all six observed outside-task
perfdata writes in a fresh trace. Its untraced all-profile doctor remains
partial: 40 of 53 operations ready. Evidence stays in the corresponding
`/tmp/autosolve-heldout-*`, `/tmp/autosolve-cross-chain-20261027/` and
`/tmp/autosolve-java-writecheck-20261027/` directories.

## Remaining order

1. Freeze and verify the next 7z/image/media/JWT/Java snapshot in the isolated
   branch, then publish it after copied-export and repository gates. Finish
   the raw-ext4 DF02 and OSINT report repairs found by independent cases.
2. Freeze and execute each baseline row's positive, two independent held-out
   variations and negative controls. The source audit found no complete
   57-row transfer ledger; local tests alone do not satisfy this gate.
3. Complete the cross-category and failure cases, approved-engine discovery
   in a clean copied export, and the three-publisher diversity requirement.
   Keep release status partial until all required evidence passes.

The repository has concurrent unrelated guide edits. At this checkpoint,
`package_toolkit.py` expects 36 public task routes while `index.html` contains
35, so the distribution gate stops before autosolve export smoke tests. Git's
local `core.bare` was also changed concurrently to `true`; use an explicit
`--git-dir=.git --work-tree=.` for read-only diff checks. Neither unrelated
state was changed here. The user subsequently authorized remote checkpoint
pushes; three tested commits are published and the next repair set is under
its isolated gate.
