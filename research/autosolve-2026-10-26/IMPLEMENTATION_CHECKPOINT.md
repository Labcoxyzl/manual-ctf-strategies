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
Commit `35020b4` is published. The fourth snapshot added reviewed encrypted
7z, IMG02 bit-plane, IMG05 DataMatrix readiness, JWT optional-engine identity,
AV06 frame timing and Java no-perfdata changes. It passed 652 CPython 3.12
autosolve tests (20 optional skipped), nine copied-export tests and the full
pre-push gate (711 passed, 37 optional skipped); commit `82190b4` is published.
The fifth snapshot covers raw-ext4 routing, OS01 interpretation, bounded report
locators and the encrypted-7z doctor probe. Its focused Python 3.12 run passed
142 tests (five optional skips), the copied-export gate passed nine tests, and
the repository pre-push gate passed 724 tests (37 optional skips, 348 subtests).
Commit `11d4168` is published and its remote hash was verified. A concurrent
full Python 3.12 run had two 15-second CLI timeouts and one process-group
timing assertion; all three passed on a focused rerun. This remains a
load-sensitive test observation, not a clean full Python 3.12 pass.

The sixth isolated snapshot adds the reviewed OS02 deadline distinction,
SSTV-to-OCR clue chain, bounded answer schema, explicit browser-to-snapshot
relation, compressed/raw TAR lineage, non-English Caesar hypotheses, and
YARA source offsets. Its focused Python 3.12 integration run passed 187 tests
(three optional skips), the copied-export gate passed nine tests, and the full
Python 3.12 autosolve suite passed 695 tests (20 optional skips). A further
22 OS artifact/snapshot tests passed after the long-browser-URL comparison
guard. The repository pre-push gate passed 755 tests (37 optional skips,
359 subtests); commit `3334179` is published and its remote hash was verified.

The seventh isolated snapshot adds Firefox visit provenance, 32-frame bounded
AV06 inspection with old-run invalidation, and truthful REV07 failed-replay
coverage. Its focused checks passed 112 core/OS/media tests and then 50
checker/media/OS tests after the replay repair; nine copied-export tests also
passed. Its full Python 3.12 autosolve suite passed 703 tests (20 optional
skips), and its pre-push gate passed 760 tests (39 optional skips, 363
subtests). Commit `8a4bbd3` is published and its remote hash was verified.

The eighth snapshot integrates declared chatbot checkers, bounded route
and CSRF handling, and score-controls with redirect provenance. The isolated
prep passed 69 chatbot/scorer tests and nine copied-export tests. An integrated
fixed archive passed 18 frozen AIC01 local cases, and a separate first-use
scorer transfer passed seven high-precision, overlap and redirect controls.
Its full Python 3.12 autosolve suite passed 727 tests (20 optional skips), and
its pre-push gate passed 786 tests (39 optional skips, 424 subtests). Commit
`5fc5584` is published and its remote hash was verified. No publisher
acceptance is inferred from local toy services.

The ninth isolated snapshot addresses nullable hash deadlines and unverified
cache reuse across adapters, adds EVTX truncation and header/XML provenance,
and retains short flag-shaped XOR candidates. Its Python 3.12 autosolve suite
passed 745 tests (20 optional skipped), the copied-export gate passed nine,
and the repository pre-push gate passed 805 tests (39 optional skipped,
448 subtests). Commit `2407b36` is published and its remote hash was verified.
A timed-out cache check may rerun the affected job on later resume; it does not
reuse unverified bytes or stop unrelated ready work.

On that pinned ninth candidate, 20 of 22 frozen two-family all-domain cases
passed; IMG01 explicit-image ZIP routing and DOC05 resume provenance failed.
The strict X01–X08/F01–F12 replay passed 19 of 20 rows; F10 exposed a started
encoding job whose family coverage still said `not scheduled`. A separate
15-case measurement run passed its frozen oracles but is not a release-wide
solve-rate sample. CryptoHack's short-XOR handout recovered an independently
verified candidate, without platform submission. A public XP memory transfer
exposed missing late-row report sampling and stale rows after switching symbol
paths back. Each failure remains in a preserved local evidence ledger.

The tenth checkpoint repairs independent memory-triage warnings, bounded job
coverage, cross-archive DOC02 status, PyInstaller metadata inventory, IMG01
image-tail ZIP routing, DOC05 resume provenance, REV02 supported decoder loops,
and DF05 symbol-path resume and late-row sampling. Independent review cleared
the repairs. Its Python 3.12 autosolve suite passed 766 tests (20 optional
skipped); its repository pre-push gate passed 825 tests (39 optional skipped,
483 subtests). Commit `559448a` is published and its remote hash was verified.
On that exact candidate, the frozen two-family all-domain gate passed 22/22,
the X01–X08/F01–F12 gate passed 20/20, and clean copied rootless setup and
seven adverse controls passed. These are narrow gates, not 57-row acceptance.

The eleventh checkpoint integrates AIC01 partial-stream reporting, AIC02
model parity, recurrent traces, calibrated search and exact live scorer
numbers, an opt-in supplied-offset local PWN04 ret2win path, bounded
PyInstaller 5 encrypted PYZ recovery, the locked AIC02/REV05 Python backends,
and AV04 routing that avoids probing OCR bytes as SSTV audio. Independent
review cleared the changes. Its Python 3.12 autosolve suite passed 795 tests
(22 optional skipped) on a quiet full rerun after one cooldown timing error;
the repository pre-push gate passed 872 tests (41 optional skipped,
498 subtests). Commit `60feabc` is published and its remote hash was verified.
On that exact candidate, the frozen all-domain gate passed 22/22 with AV04
`ran`, X01–X08/F01–F12 passed 20/20, and clean copied rootless setup passed
with 28 locked packages, 126 changed-path tests (four optional Torch skips),
seven adverse controls and zero outside-task writes. Local AIC01/AIC02,
encrypted PyInstaller and two public ret2win transfers matched independent
oracles without claiming platform acceptance. PWN03 autonomous offset
discovery, broader PWN04 ROP, foreign PyInstaller bytecode and unsupported
REV02 compiler layouts remain partial.

The twelfth checkpoint bundles a functional authored SSTV doctor recording,
rootless pefile/Capstone parsers, and a refreshed deterministic README-linked
Offline kit with 237 validated members. Its Python 3.12 autosolve suite passed
800 tests (23 optional skipped), and the pre-push gate passed 877 tests
(42 optional skipped, 498 subtests). Commit `dc8aa70` is published and remote
verified. The exact pinned all-domain and X/F gates passed 22/22 and 20/20;
copied rootless directory and ZIP setup installed 30 locked packages, with
44 ready, 10 partial and one unavailable doctor operation. Write tracing had
zero outside-task ordinary-file targets.

The thirteenth checkpoint validates copied SQLite WAL integrity before
treating missing `-shm` as informational and refreshes the Offline kit to
match. Corrupt WAL remains truncated, and ambiguous reused WAL stays partial.
Its Python 3.12 suite passed 802 tests (23 optional skipped); the pre-push gate
passed 879 tests (42 optional skipped, 509 subtests). Commit `4680795` is
published and remote verified. On that exact candidate the all-domain gate
passed 22/22 with all selected families `ran`; X/F passed 20/20; clean
directory and ZIP rootless gates and 15 representative measurements passed.

Four published-tenth row batches replayed 82 frozen cases: 80 narrow passes,
with ENC01 Base85 and ENC05 no-crib H2 excluded. A fifth batch on the
thirteenth commit passed 20/20 more narrow cases. IMG01, ENC02, DOC01 and
CAN02 passed their complete named row contracts on pinned published commits.
AV03 later passed its eight-case named row, including Morse, AFSK and negative
controls; IMG02 passed its nine-case named row under its explicitly partial
contract, with four truncated runs and 873 unverified candidates on one public
image. DOC02 then passed 11/11 on the published fifteenth commit, and AV01
passed 6/6 on the same hash. DOC04 passed 10/10 on the published sixteenth
commit, including encrypted PDF, incremental, Unicode and unsafe-name cases.
IMG03 later passed 9/9 with conservative no-seed, possible-seed and timeout
outcomes; AV02 passed 7/7 DTMF cases, and IMG05 passed 8/8 with the pinned
rootless DataMatrix decoder. Those twelve named rows are proved on earlier
published commits. NET01 then passed 8/8 on the published eighteenth hash,
including reordered complete traffic and true gap, clipped and unsupported
link negatives. That brought the count to thirteen named rows on pinned
published commits. AV04, NET03, IMG04, NET02, ENC05, DOC05, AV06 and DF04
later passed their named rows on that same published hash. DF01 and NET05 then
passed their named rows on that published hash, including shifted filesystem,
TLS 1.2 and 1.3, resumption, and negative controls. Twenty-three named rows
are now proved on pinned published commits; the other 34 remain unproved at
named-row depth. DF04's stationary exclusive-lock control recovered only its
committed row but did not test concurrent writes; DOC05 proved static VBA
source extraction, not desktop Office execution.

The fourteenth checkpoint adds an authored AV03 Morse/AFSK doctor probe, an
opt-in hash-locked AI CPU environment, a separate wheel-only angr checker
environment and encrypted-ZIP corruption classification before decrypted
children are published. Two tiny source-only checker dependencies were reviewed
and vendored as hash-verified wheels so user setup does not run their build code.
The deterministic README-linked Offline kit contains 248 verified files. Its
quiet Python 3.12 suite passed 817 tests (24 optional skipped) after an initial
15-second JPEG timeout; the timed-out case passed in isolation. The repository
pre-push gate passed 893 tests (44 optional skipped, 513
subtests). Commit `1858634` is published and its remote hash was verified.
On that exact candidate, the all-domain gate passed 22/22 with all selected
families `ran`, X/F passed 20/20, and 15 representative measurements passed
with zero validated false solutions in two classified negatives. Fresh copied
directory and ZIP setup passed core 30/30; opt-in AI CPU 39/39 and checker
65/65 passed functional probes. Traced optional installs made zero outside-task
writes, and eleven adverse controls behaved as expected. AIC01/AIC02,
CryptoHack RSA/XOR, encrypted PyInstaller and two official ret2win handouts
matched independent local oracles without platform acceptance claims.

The fifteenth checkpoint repairs DOC02 leading-signature corruption, reports
how many unverified findings exceed the report display limit, and adds opt-in
PWN03 local crash-offset discovery from GDB evidence with controlled replay.
Both pinned ROP Emporium and pwn.college handouts yielded independently known
offset 40 with negative controls; this is local replay, not platform
acceptance. The deterministic Offline kit contains 250 verified files. Its
Python 3.12 suite passed 831 tests (24 optional skipped); the repository
pre-push gate passed 907 tests (44 optional skipped, 517 subtests). Commit
`4f6dad8` is published and remote verified. On that exact candidate, the
all-domain gate passed 22/22, X/F passed 20/20, 21 changed-path DOC02/PWN03/
IMG02 checks passed, and 15 representative measurements passed with zero
validated false solutions in two classified negatives. Clean directory and
ZIP core setup passed 30/30 locked packages with 250/250 file parity, seven
adverse controls, and zero outside ordinary-file writes. PWN03 copied-export
controls passed 5/5. Doctor still lacks a dedicated GDB/PWN03 readiness row;
the next candidate adds that distinction.

The sixteenth checkpoint adds supplied-password PDF extraction and a dedicated
GDB/PWN03 doctor self-test. Both isolated changes passed focused tests and
independent review. Its first integrated hash `2d0cc8c` passed 838 Python
3.12 tests (24 optional skipped), all-domain 22/22, 18 changed-path checks
and 15 representative measurements. The strict X/F gate stayed 19/20: one F10
0.3-second run exhausted its wall-clock budget during preflight/host delay;
six quiet controls passed, and an injected pause reproduced the failure.
No scheduler defect or truthful fix that guarantees work after an arbitrary
pause was established. Rootless tracing then found 22 denied GDB Python
bytecode-cache directory attempts outside the task root in both setup and
doctor. A reviewed hotfix suppresses bytecode generation; focused PWN03/setup
tests and direct file-syscall traces passed with zero outside ordinary-file
write attempts. The repaired commit `ba86d98` passed 838 Python 3.12 tests
(24 optional skipped), all-domain 22/22 and X/F 20/20; the earlier F10 failure
remains a timing risk. Fresh copied directory/ZIP setup matched 250 files and
30 locked packages, with GDB/PWN03 and PDF doctor probes ready and zero
outside ordinary-file or directory write attempts in setup and doctor traces.
The first pre-push run failed one 15-second PNG test timeout; that exact test
passed in isolation in 7.97 seconds. The quiet pre-push rerun passed 914 tests
(44 optional skipped, 517 subtests), and the remote hash was verified as
`ba86d98`. DOC04's full named row passed 10/10 on that hash. These checks
do not establish the other 48 named rows or platform challenge acceptance.

The seventeenth checkpoint distinguishes PWN03 debugger startup failures
from genuine noncrashing program exits and adds an opt-in bounded StegSeek
seed probe for IMG03's negative-classification clause. The isolated
PWN03 suite passed 15 tests; StegSeek passed 12 focused tests and three
independently frozen real-carrier controls with stable resume and no published
seed output. A two-carrier regression repaired an aggregate IMG03 report note
that had implied no seed globally after a positive carrier; aggregate seed
warnings now identify their source artifact and path. The final commit
`615d966` passed 846 Python 3.12 tests (24 optional skipped), all-domain
22/22, X/F 20/20, nine changed-path cases and 15 representative measurements.
The earlier F10 host-pause failure remains a timing risk. Fresh directory and
ZIP setup matched 250 files and 30 locked core packages; StegSeek seed
controls passed 8/8, PWN03 startup controls 3/3, seven adverse controls passed,
and setup/doctor traces made zero outside ordinary-file or directory write
attempts. The first pre-push run failed a chatbot cooldown test that passed
alone in 1.80 seconds. The quiet pre-push rerun passed 922 tests (44 optional
skipped, 517 subtests), and the remote hash was verified as `615d966`.
IMG03, AV02 and IMG05 then passed their full named rows on that published hash.
This does not establish the other 45 named rows or platform acceptance.

The eighteenth checkpoint repairs NET01's reordered-capture truncation:
a gap-free reassembled stream can coexist with a transient TShark lost-segment
warning. The repair clears that provisional warning only when both matching
TCP directions are complete and gap-free. Independent review then found ACK
evidence of uncaptured bytes and mixed clipped/clean directories could falsely
mark NET01 `ran`; a follow-up retains ACK-loss warnings and aggregates status
across current sources. Genuine gaps, conflicts and stale packet jobs remain
truncated. Isolated focused and frozen reordered, missing-frame, conflict,
ACK, mixed-source and source-removal transfers passed; full named NET01 row
acceptance was then proved 8/8 on the published commit. An initial integrated
Python 3.12 suite failed one chatbot bootstrap test with a 50 ms inspection
timeout; that test passed alone. The first pre-push gate then failed a
recurring 429 test
whose fixed 1.05-second sleep could return before the recorded cooldown
expired. A reviewed test-only repair now waits to that expiry, gives
pre-bootstrap inspection its own adequate timeout while still forcing the
delayed claim to time out, and reports a sanitized CLI reason on failure.
Controlled red-to-green checks and three focused tests passed on Python 3.12
and 3.13. The final commit `a611072` passed 848 Python 3.12 tests (24
optional skipped), all-domain 22/22, X/F 20/20, exact NET01 changed-path
controls and 15 representative measurements on byte-identical production
source. The earlier F10 host-pause failure remains a timing risk. Fresh ZIP
core setup installed 30 locked packages from 250 verified files, three
packaged chatbot reliability tests passed, and setup/doctor traces made zero
outside ordinary-file or directory write attempts. The final pre-push hook
passed 924 tests (44 optional skipped, 520 subtests); remote hash `a611072`
was verified. This does not establish the other 44 named rows or platform
challenge acceptance.

The nineteenth candidate adds bounded binary BLF support to CAN01 using the
pinned python-can environment, with conservative corrupt/truncated handling
and a functional doctor probe. A separate OS01 repair interprets
`XMP-exif:DateTimeOriginal` time basis and conflicts. Both isolated changes
passed focused tests, independent review and frozen local transfers. The first
integrated suite reproduced a CAN source-reversion failure: BLF jobs and the
current-adapter registry used different fingerprints. Review also found a
valid non-CAN BLF marker wrongly marked truncated and malformed-then-valid
directories wrongly marked complete. A reviewed follow-up aligns fingerprints,
keeps informational marker notices without data-loss status, and aggregates
coverage across current sources. Two existing chatbot 50 ms tests also timed
out during preliminary inspection instead of their intended chat request;
controlled delayed-GET checks supported a test-only timing repair without
weakening the chat-timeout assertions. One deep-JSON helper exceeded its 12 s
subprocess cap under the slower diagnostic suite; its cause remains unproved,
so only sanitized failure diagnostics were added. A later default-environment
trace found OCR output and setup/doctor scratch attempts outside the task root.
Reviewed repairs use anonymous OCR output, private toolkit scratch for setup,
doctor and their child tools, and per-run scratch for actual zsteg and checker
jobs. An isolated combined copied-export setup and all-profile doctor trace
found zero outside ordinary-file or directory write attempts, with PTY devices
excluded; no-trace doctor passed its zsteg and GDB probes. This is not yet a
same-hash release gate for the integrated candidate. Integrated review then
found generic text could overwrite valid CAN01 coverage, display-only CAN01 and
CAN02 row limits could mark complete work partial, and a later clean image could
overwrite an earlier OS01 warning or failure. Focused red-to-green repairs and
independent review passed. Combined release gates and publication remain
pending. Full CAN01, OS01 and PWN03 named-row credit awaits
integrated published-hash replay. PDF metadata remains outside OS01 routing
and is a separate breadth gap.

Integrated core tests then exposed a forked CAN worker whose 256 MiB virtual
memory limit failed after the parent imported Pillow. A reviewed fresh-process
worker retains the limit, bounds private request and result pipes under one
deadline, reaps timed-out process groups, and works for direct Python callers.
The stable core/CAN focused suite passed 135 tests with one optional skip;
final combined release checks and publication remain pending.

The first fresh rootless default-environment product trace with the full tool
PATH then found REV03 rule version probes writing disposable scratch under
`/tmp` even for unrelated CAN and OSINT inputs. A reviewed repair routes rule
version and supplied-rule sample scratch under each active run, validates the
chosen directory, and scopes child tool cache and temp variables. Its isolated
24-test rule suite and CAN/supplied-rule reversing traces passed with zero
outside ordinary-file or directory write attempts. The earlier failed trace
remains evidence; final integrated rootless and release gates are pending.
The first integrated full Python 3.12 run after that repair passed 893 tests
with 35 optional skips but failed one chatbot test whose fixed sleep could end
before the recorded Retry-After deadline. An independently reviewed test-only
repair now waits for that deadline; the final full-suite rerun is pending.
The repaired Python 3.12 autosolve suite then passed 894 tests (35 optional
skips), with X/F 20/20, all-domain 22/22, changed-path CAN/OS 11/11 and a
separate 4/4 mixed/default-environment supplement. Fifteen measured cases
passed with zero timeouts and zero validated false solutions in two classified
negatives. Fresh copied directory/ZIP setup and doctor passed core 30/30;
default-environment setup, doctor and four product traces on byte-identical
production source made zero outside ordinary-file or directory write attempts.
The repository pre-push hook then failed 11 Python 3.13 cases: ten OCR cases
because this Python build omits `os.memfd_create`, and one hidden-workspace
toolkit case exposed same-size source edits that preserved metadata. Reviewed
repairs use libc anonymous memfd when Python omits its binding and bounded
content revalidation before toolkit output publication. Focused Python 3.12
and 3.13 OCR/toolkit/hidden-workspace checks passed; final combined release
gates and remote publication remain pending.

The final nineteenth commit `6e873aa` is published on the remote progress
branch and its hash was verified. Its deterministic Offline kit has 252
byte-verified members. The Python 3.12 autosolve suite passed 895 tests (35
optional skips); the repository pre-push gate passed 962 tests (56 skips, 532
subtests). On that exact hash, frozen X/F passed 20/20, all-domain passed
22/22 with every selected family `ran`, changed-path CAN/OS passed 11/11 plus
4/4 separate mixed/default-environment controls, and 15 representative
measurements passed with zero timeouts and zero validated false solutions in
two classified negatives. Fresh copied directory and ZIP setup installed the
30 pinned core packages; doctor reported 46 ready, nine partial and one
unavailable operation. Python 3.13 copied OCR fallback and toolkit integrity
controls passed. Default-environment setup/doctor/CAN/OSINT/zsteg/checker
traces made zero outside ordinary-file or directory write attempts on
production-byte-identical source; the changed OCR path was separately traced
on the exact final source. The earlier F10 host-pause timing failure and a
toolkit source-write race between final validation and publication remain
documented limits.

Published-hash full named-row replay then passed CAN01 10/10, OS01's six-image
scope 196/196 plus 54 extended checks, PWN03 4/4, ENC07 six independent cases,
and OS03 4/4. These five raise the full named-row count from 23 to **28 of
57**; 29 remain unproved at named-row depth. Local replay and independent
oracles do not establish challenge-platform acceptance. PDF metadata remains
outside OS01 routing and is a separate breadth gap.

The twentieth candidate repairs WEB01 URL scope classification when a caller
supplies an HTTP(S) origin: relative form and link references resolve against
that origin, while protocol-relative, external-base and browser backslash
network paths remain cross-origin or conservative. The unchanged frozen WEB01
oracle moved from 3/4 to 4/4 in isolation; sibling WEB02/04/05 cases stayed
4/4 each. Focused tests, exact public CLI offsets and a zero-network trace
passed, with independent review. Integrated release gates and published-hash
WEB01 row acceptance remain pending.

The twentieth commit `bf18be0` is published on the remote progress branch and
its hash was verified. Its Python 3.12 autosolve suite passed 898 tests (35
optional skips); the repository pre-push gate passed 965 tests (56 skips, 532
subtests). On that exact hash, frozen X/F passed 20/20, all-domain passed
22/22 with every selected family `ran`, the unchanged WEB01 oracle passed
4/4 from its previous 3/4, and 15 representative measurements passed with
zero timeouts and zero validated false solutions in two classified negatives.
The 252-member copied kit passed WEB01 tests 11/11 and an eight-URL public CLI
trace with exact scopes, zero network calls and zero outside ordinary-file or
directory write attempts. The core environment was relocated and verified
against all 30 pins; fresh installation and unaffected path traces were
covered by byte-identical earlier source. Published-hash WEB01 replay then
passed its full four-case named contract with the original oracle unchanged.
This raises local full named-row proof to **30 of 57**; 27 remain unproved.
The strict F10 0.3-second gate passed but one repeat scheduled only two of
three eligible families; the historical host-pause timing risk remains.

Subsequent published-twentieth named-row replay passed REV01 10/10 with
independent ELF/PE structural oracles and no target execution, OS02 ten exact
source-byte clues across UTF-8, UTF-16BE and derived ZIP controls with zero
network calls, and ENC01 7/7 layered-decoding cases with exact parent chains
and no silent repair. These three raise full named-row proof to **33 of 57**;
24 remain unproved. ENC01's positive runs recovered their target chains but
reached the 256-artifact cap, so they remained honestly partial rather than
exhaustive. OS02 testing separately found a generic runner defect: deleting a
direct input before resume returns invalid input while leaving the manifest
marked `running`; a focused repair is pending.
An official pwn.college babyrop handout was independently downloaded and hash
matched, then exercised on the published twentieth build: PWN02 static facts,
PWN03 offset 40 and PWN04's 56-byte payload matched independent local
oracles, with a local win marker and wrong-offset negative. This was local
replay, not platform acceptance. The current workflow still needs a person
to copy the verified PWN03 offset into PWN04 and supply the channel, symbol,
prompt and marker; a source-hash-checked run handoff is the smallest next
orchestration improvement identified by that transfer.
PWN02 then passed its published-hash full named row in eight cases: independent
x86-32 and x86-64 ELF samples, PIE, stripped and different-compiler held-outs,
unsupported/malformed negatives, exact mitigation and instruction/VA locators,
and source retirement. This raises local full named-row proof to **34 of 57**;
23 remain unproved. The x86-32 case used hand assembly because 32-bit C
startup libraries were unavailable; compiler variation was exercised on x86-64.
Published-twentieth DOC06 then passed five independently authored MIME cases
with nine exact decoded part bytes/paths, malformed-boundary and misleading-name
negatives, private derived paths and zero network. ENC08 passed 13 independent
AES-CBC/GCM fixtures across all four clauses: exact binary/empty plaintext,
held-out nonce/tag/length settings, wrong-input negatives and no plaintext on
GCM authentication failure. CBC remained candidate-only. These two raise
full named-row proof to **36 of 57**; 21 remain unproved. No platform result
is inferred from either local oracle.
PWN01 then passed nine independent loopback transport cases on the published
twentieth hash: newline, delimiter, length and fragmented/TLS framing, EOF,
timeout and oversized negatives, exact server/CLI byte transcripts, and no
second connection on resume. This raises full named-row proof to **37 of 57**;
20 remain unproved. No live CTF service or platform flag was attempted.
REV03 then passed seven independent named-row cases on that same published hash
with genuine YARA 4.5.0: a benign capability rule matched exact ELF bytes and
offsets after code relocation, rule revision retired old current evidence,
and near-match, missing-pack and unchanged-resume controls had the required
distinct outcomes. This raises local named-row proof to **38 of 57**; 19 remain
unproved. The selected YARA fallback was exercised; genuine capa was not.
Separately, nine frozen ENC04 local cases found no implemented Vigenere or
rail-fence transform or accepted classical-key hint: 0/7 keyed positive
plaintexts were recovered, while two negatives yielded no validated solution.
ENC04 remains unproved and is the next explicit-key implementation target.

The twenty-first candidate repairs direct-input resume after source removal:
it retires stale current evidence, clears running state and memory routing,
keeps unsafe symlink/FIFO replacements rejected, and can resume if the source
is restored. It also adds an explicit `setup --floss` path for the official
hash-verified FLOSS 3.2.0 standalone executable under private toolkit state,
without changing default core setup. A shared verified resolver, private
FLOSS child scratch and a genuine compiled stack-string doctor probe let REV02
use that optional backend; isolated doctor/analyze and tamper/reversion tests
passed. A frozen nine-case real-backend transfer recovered seven of eight
independent stack/XOR positives and rejected its negative. GCC `-O2` with a
frame-pointer-free tail-call decoder remained unrecovered by both upstream
FLOSS and the conservative static fallback. A proposed broader static entry
rule produced false plaintext on adversarial direct and indirect bypasses, so
it was withheld; full A-REV02 named-row credit remains pending. Finally,
`pwn-ret2win --offset-run` can consume a verified stdin PWN03 run after exact
source and all library identities are rechecked; local replay remains explicit.
The official babyrop handout passed this handoff locally, without platform
acceptance or full PWN04 row credit. Combined release gates, copied rootless
setup and remote publication remain pending.

The final twenty-first commit `d663ae9193b9bf391e4a3a5e712dbab31b7be741`
was pushed to the [remote progress branch](https://github.com/Labcoxyzl/manual-ctf-strategies/tree/autosolve-progress-2026-10-27),
and the remote SHA was independently verified. Its 253-member Offline kit had
exact source/ZIP byte parity. The Python 3.12 autosolve suite passed 923 tests
(35 optional skips); the repository pre-push Python 3.13 gate passed 990 tests
(56 skips, 554 subtests). Exact-hash frozen X/F passed 20/20, including three
additional 0.3-second F10 repeats with all three families scheduled; the
all-domain gate passed 22/22 with every selected family `ran`; 15 representative
measurements passed with zero timeouts and zero validated false solutions in
two classified negatives. Fresh copied directory and ZIP setup retained all
30 core pins and doctor reported 46 ready, 9 partial, 1 unavailable without
an unprobed ready entry. The genuine pinned FLOSS opt-in install, offline
reuse, doctor and compiled ELF analysis passed, with two exact source-linked
candidate strings and no target execution. Packaged missing-source resume
passed 5/5, PWN offset handoff 19/19, and setup adverse controls 25/25.
Non-install FLOSS phases made no internet connections and no outside ordinary
content-file writes; its bundled Python created and removed `/dev/shm/sem.*`
POSIX semaphore IPC objects, so a literal zero outside-root mutation claim is
not made. A-REV02 remains at 7/8 positive local cases and is not counted among
the 38 proved named rows. Local replay is not platform acceptance.

Another published-nineteenth replay passed ENC03's five exact classical-cipher
recoveries and two negative controls, with candidate-only output and stable
report/resume behavior. This raises full named-row proof to **29 of 57**;
28 remain unproved. REV02 separately passed four independently compiled
static stack/XOR fallback cases with exact file offsets and no target execution,
but its full named row remains pending: FLOSS-dependent coverage was unavailable
and each run truthfully remained `truncated`.

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

Later fresh transfers recovered a second OS01/OS03 conflict case with bounded
readable provenance and a raw-ext4 deleted file byte-for-byte after routing
repair. NET05 TLS-keylog cases, DF01 targeted files and DF04 WAL rows also
matched independent oracles. Firefox visits are covered in the seventh
snapshot; real EVTX/registry CLI validation remains pending. The
X04/X05/X07/X08 and F01–F12 frozen ledgers are recorded. AIC02 selected
offline cases and scorer controls passed local independent oracles. Published
AIC01 checker repairs passed local GET/POST, route and CSRF transfers.
A separate official
pwn.college babyrop handout matched static `win`/gadget/mitigation observations
and bounded service replay; autosolve did not synthesize the exploit or claim
challenge acceptance. Detailed publisher exploit notes remain local.

The eighth published evidence matrix credits 52 of 57 rows with four observed
narrow case slots and 107 of 114 first-use held-out slots. Later first-use
IMG02/DOC02 transfers and REV11's four-slot run raise the local postpublication
evidence to 53/57 and 110/114; REV02 still awaits a code checkpoint. These
counts do not establish
family-wide or release acceptance. Fresh X04 and X08 transfers recovered
exact sourced outputs; X05
joined a recovered browser visit to a supplied snapshot by exact URL/time,
with mismatched and stale sources withheld and zero network requests.
Independent CAN02 bit-level oracles matched multiplexed, signed, endian and
CAN FD cases. Four pinned public REV07 checkers validated only after explicit
native replay; unsat, unsupported syscall, timeout and failed-replay controls
stayed distinct. AV06's first-use 20-frame QR miss became a development
regression; a fresh 27-frame transfer recovered its exact QR and subtitle
under the new 32-frame bound. DF05 post-repair public memory cases and the
REV05 encrypted bundle recovered their frozen facts/resources, but retained
explicit command/file and archive/decryption limits. The AIC02 model transfer
passed artifact, gradient and recurrent checks; scorer controls now have exact
high-precision and redirect-provenance oracles. CryptoHack's official attached
RSA handout became the third distinct executed publisher; exact plaintext was
recovered with public-parameter hints, without platform submission. A fresh
rootless export matched all 232 authored files; setup and doctor had zero writes
outside assigned targets. Doctor found 42/55 operations ready and kept missing
prerequisites explicit. F05 rule/tool invalidation passed, while F10 exposed a separate ZIP
hash-deadline bug now included in the ninth repair set.

## Remaining order

1. Publish the next reviewed checkpoint through the repository gate, then
   rerun affected frozen challenge transfers and rootless checks on its exact
   remote hash. Keep unsupported branches explicitly partial.
2. Complete the baseline row matrix: each of 57 rows needs its positive, two
   independently held-out variations and negative controls with named clause
   coverage and exact source/oracle fingerprints. Current broad gates and
   mixed-commit row examples do not prove that matrix.
3. Extend portable rootless readiness and classified false-positive/limit
   measurements across the accepted row corpus. Keep release status partial
   until all required checks and provenance pass on one candidate.

Unrelated guide edits remain in the shared worktree; checkpoint publication
uses an isolated worktree. Remote pushes are authorized for this autosolve
progress branch and each published hash is verified after the repository gate.
