# Round 2: adapting the Python templates

The four templates were useful foundations for a second, independently authored
local protocol. Each required explicit protocol work. After adaptation, all 108
checks passed across 28 subprocess runs, including expected failures. The shared
templates remained unchanged. These results establish local protocol handling,
not success against an unknown challenge or a measure of human solving speed.

The [specification](PROTOCOL.md) and [server fixture](fixtures/protocols.py) were
written before the adapted copies. The arithmetic service uses a menu, alternating
question wording, CRLF, and prompts without newlines; it never sends the original
`Q` or `DONE` format. Its ten manually checked expression/answer pairs repeat over
100 numbered rounds. The binary and HTTP exercises use separately specified
records and session rules. Direct sockets and `http.client` provide baselines
without importing the templates.

| Template | What transferred unchanged | Meaningful edit groups | Result |
|---|---|---:|---|
| `math_client.py` | Arithmetic evaluator, magnitude/AST limits, one connection, whole-session budget, target validation and error handling | 5: question grammar; menu selection; delimiter reader; answer-prompt synchronization; terminal count/token validation | All 100 answers and token verified |
| `pwntools_starter.py` | Transport selection, bounded prompt receiver, byte-oriented I/O and exception handling | 4: prompt/payload constants; menu selection; raw send; bounded length-prefix receive/output | Exact 35-byte frame captured; embedded LF was sent as one of four raw bytes |
| `binary_parser.py` | Regular-file/offset checks, read-only opening, explicit byte order and error handling | 4: record layout/magic; variable-length body checks/read; version validation; field output | Counter 270544960 and synthetic token verified, also at offset 7 |
| `http_probe.py` | URL checks, certificate behavior, no redirects, response/body limits, header display and incomplete-body rejection | 6: cookie opener; two-stage flow; nonce parsing; form submission; completion validation; removal of the single-body CLI option | Cookie and nonce preserved over GET/POST; terminal token verified |

These counts group behavior changes by responsibility; they are not keystroke
counts or time estimates. The [individual diffs](results/) and
[line counts](results/diff-stats.json) make the boundaries inspectable. The HTTP
diff includes indentation of the retained response validation inside the
two-stage loop. No reusable framework, dependency, or new shared helper was added.

The unmodified math client rejected the banner before answering. The unmodified
transport starter timed out waiting for its different prompt. The original binary
parser rejected the new magic/layout. The original HTTP probe completed its GET,
then its separate POST lacked the required cookie and form content type. These
are expected outcomes under the documented contracts, not newly discovered bugs.
CRLF alone was not established as a defect in the original math client.

Five adapted math runs took 0.203–0.227 seconds including Python/pwntools startup;
the median was 0.217 seconds. The server measured 0.073–0.092 seconds from its
accepted connection through sending completion. With a 2 ms server pause before
each of 100 questions, the measured subprocess time was 0.437 seconds and server
time was 0.308 seconds. The 3-second client budget included connection and all
rounds. These are loopback measurements with TCP_NODELAY on the fixture server;
they do not establish remote network latency or event performance.

Failure controls checked the states that matter for these adaptations:

- A deliberately wrong math answer was rejected without a token. Client runs
  failed on rejection at round 3, disconnect during round 17, a fake completion
  after one answer, and expiry of a 0.1-second total budget. None printed a token.
- Wrong raw bytes were rejected. A truncated binary reply and a 65535-byte
  advertised length failed without a captured-frame success message. The file
  parser rejected truncation, mismatched lengths, bad magic and version 2; all
  tested files remained unchanged.
- The independent HTTP baseline received 403 without the cookie or with a wrong
  nonce, then succeeded with both. The adapted client rejected a redirect, a
  denied POST, and a short final body. It did not follow the redirect, send a
  subsequent POST after it, or claim a completed session on any of these failures.

The main documentation gap is the math edit checklist. Changing the question
regex, completion marker, and answer formatting is insufficient when a service
has menu state or prompts without newlines. Show those adaptation points next to
the existing example. A bounded length-prefix snippet and a small cookie-opener
snippet would also help readers apply the existing primitives. Those are proposed
in [guide-proposal.md](guide-proposal.md). Each has one demonstrated second-protocol
use here; that is insufficient evidence for adding configurable shared features.

Source hashes and command outputs are in
[exercises.json](results/exercises.json). The first passing run and its quoted
timings are retained in [exercises-original-origin.json](results/exercises-original-origin.json).
The fixture-first hashes are preserved
in [fixture-first-sha256.json](fixture-first-sha256.json). The first fixture import
caught a manual token length error in the independent specification: the token
has 23 bytes, not 22. That made the payload/frame 33/35 bytes, not 32/34. The
[correction record](fixture-correction.json) and initial failure output are
retained. A related negative-control mutation initially wrote the newly correct
length and was corrected to a genuinely inconsistent length. No adapted client
change was needed for either fixture correction. The subsequent complete run
passed all 108 checks.

After that run, the coordinator moved optional pwntools imports into each shared
CLI so `--help` works without the package. The origins of the four adapted copies
remain the original hashes. [baseline-refresh.json](baseline-refresh.json)
records the current shared hashes and verifies that the reused `solve`,
`remaining`, and `receive_until` functions are AST-identical. The full 108-check
suite also passed against those refreshed baseline files; no adaptation change
was needed.

For toolkit integration, promote the complete
[arithmetic replacement block](promotion/math_menu_block.py) and the binary/HTTP
blocks in [guide-proposal.md](guide-proposal.md) into the user-facing template
guide. The arithmetic block reuses the existing evaluator, line reader, bounded
prompt reader and CLI, rather than shipping four duplicate scripts. Its exact
generated candidate passed [31 further checks](promotion/results.json) against
the current optional-import sources. The copy requirements and export paths are
specified in the guide proposal. Shared documentation remains the coordinator's
integration responsibility.

Reproduce from the repository root with the installed environment:

```sh
/opt/ctf-tools/py312/bin/python research/validation/round2/template-exercises/run_exercises.py
```

The harness accepts one connection per TCP fixture, uses ephemeral loopback
ports, enforces socket and subprocess bounds, and writes only inside this folder.
It uses Python 3.12.3 and pwntools 4.15.0. No installs, scans, external requests,
unknown executables, challenge attachments or shared-script changes were needed.

Not checked: remote services, TLS challenge behavior, Windows/Kali, other Python
versions, a live CTF terminal condition, or an unmeasured human adaptation time.
HTTP retains a socket timeout rather than a total exchange deadline, and the
transport's prefix/body receives each retain their own timeout.
