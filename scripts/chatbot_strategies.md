# AI/chatbot challenge scripts

Choose a strategy after inspecting the challenge page and its JavaScript. The
scripts provide bounded transport, session handling, and evidence collection;
they do not infer an unknown endpoint, tool grammar, model wrapper, or win
condition. All live commands require an authorized origin and finite budgets.

## Live chat playbooks

List the built-in plans and their required parameters:

```sh
python3 scripts/autosolve.py --json chatbot-strategies
```

Copy a [protocol example](chatbot_recipes/context_bloat.json), set the actual
chat path, fields, cookies or headers from the frontend, and run a dry run first:

```sh
python3 scripts/autosolve.py chatbot --origin https://AUTHORIZED_ORIGIN \
  --protocol ./private-chat.json --strategy context_bloat \
  --budget 60 --max-requests 12 --max-prompts 6 --dry-run
python3 scripts/autosolve.py chatbot --origin https://AUTHORIZED_ORIGIN \
  --protocol ./private-chat.json --strategy context_bloat \
  --budget 60 --max-requests 12 --max-prompts 6
```

`context_bloat` sends an anchor and then 512, 2,048 and 8,192 characters of
neutral filler by default in one conversation. It records the first size at
which the target stops returning the original marker. Set `strategy_params.sizes`
to one to four increasing sizes, each 128–65,536 characters; `filler`,
`anchor_prompt`, and `check_prompt` are optional. A lost marker is a behavior
observation, never a validated challenge solve. The generated marker and queue
survive resume. The client will not resend a POST whose outcome is uncertain.
For a stateless chat API that expects the full conversation on every request,
copy the [messages-array recipe](chatbot_recipes/messages_array.json) and set
`chat.history_field` to its top-level JSON array field. The client sends prior
confirmed user/assistant turns as `{role, content}` objects plus the new user
prompt. It stores those turns in the private run for resume and stops before a
POST if the accumulated body exceeds 128 KiB. This adapter assumes standard
`user` and `assistant` roles; custom message shapes need a target adapter.

The bounded local end-to-end fixture runs the real CLI against an independent
loopback chat service:

```sh
pytest -q tests/test_autosolve_chatbot.py -k context_bloat_is_bounded_and_records_marker_loss
```

Observed on 2026-10-27: `1 passed, 57 deselected`. Its dry run sent 0 requests; the
live run sent exactly 8 HTTP requests and 5 prompts. The earlier marker was
retained at 512 and 2,048 filler characters and lost at 8,192. The run was
partial with 0 validated outcomes, and resume sent no further prompt.

If the frontend sends fixed body fields with each chat message, declare them
under `chat.static_fields` as in the
[static-fields recipe](chatbot_recipes/chat_static_fields.json). JSON fields
may contain JSON values; form fields must be strings. The message, conversation
ID, client ID, and captured bootstrap token remain dynamic fields. Static
values are sent with each serial chat request but redacted in logged request
bodies and reports; raw chatbot responses remain in the private transcript,
including any value the target echoes. The private protocol is part of the
resume identity. Bracketed form names such as `settings[mode]` are supported.
Static JSON fields have an 8 KiB and 64-level nesting limit.

If the frontend supplies a CSRF token in an HTML `<meta name="..." content="...">`
tag, copy the [CSRF meta recipe](chatbot_recipes/csrf_meta_chat.json). Set the
actual `page_path`, `chat.csrf_meta` name, and `chat.csrf_header`. The client
requires one unique printable token on that page, stores it privately, and
sends it only on same-origin state-changing requests. Missing tags, duplicate
tags or attributes, and invalid values stop before chat. A target that rotates
its token during a run needs a target-specific refresh plan.

For a `text/event-stream` chat route that emits JSON `data:` events and a
`data: [DONE]` terminator, copy the [SSE recipe](chatbot_recipes/sse_chat.json).
Set `chat.response_format` to `sse` and `chat.response_field` to the event
field containing each text delta. The client joins string deltas, ignores
missing or null deltas, retains raw stream bytes and parsed events privately,
and stops reading at `[DONE]` even if the server keeps the connection open.
It can carry a declared conversation ID from an event into the next serial
request. A missing terminator, invalid event, or timeout leaves the POST
unresolved; inspect history/status before releasing the origin. Other stream
framing or terminal markers need a target-specific adapter. If a route emits
`text/event-stream` without the declared SSE fields, the client stops after
one POST and keeps the raw bytes for inspection.
An `application/x-ndjson` or `application/json-seq` reply is held for a
target-specific adapter; the client records a bounded initial chunk and does
not send another prompt.

When a chat POST times out, the run sends at most one configured history/status
GET. If that read-only check is incomplete, `resume` can repeat only the GET
within the raised request ceiling. It never replays the timed-out chat POST or
turns a status response into an accepted challenge result. Bytes received
before a non-stream response stalls remain in the private transcript
as `raw_b64`; the timeout still leaves the POST unresolved.
Malformed or excessively nested declared JSON keeps exact consumed bytes in
the private transcript and stops as `malformed_json`; a body shorter than its
declared length or a broken chunked stream stops as `partial_response`. Neither
sends another prompt. A broken 409 or 429 body keeps its lock or rate-limit
signal and records the incomplete body.
A 429 keeps its rate-limit signal. This applies to JSON and `+json` content
types even when the body resembles ordinary chat text. A valid JSON `null`
also stops as ambiguous. Plain `text/plain` replies remain usable.

| Strategy | Required protocol fields | What the script does |
| --- | --- | --- |
| `instruction_leak` | none | Ask for a hidden instruction quote and a short prefix. |
| `rag_sources` | `topic` | Ask for source IDs, metadata and one exact quote. |
| `rag_aliases` | `topic` | Ask for labels and their backend field names. |
| `tool_schema` | none | Ask for callable names and argument schemas. |
| `tool_audit` | `audit_path` in the protocol when exposed | Ask for the tool call lifecycle; read the audit route once if supplied. |
| `tool_filter` | `tool_name`, `filter_value` | Ask for one exact filter argument; inspect real tool evidence before using the web workflow. |
| `fetch_tool`, `fetch_blocklist` | `fetch_url`; its origin in `authorized_destinations` | Send one explicit fetch request through the chatbot; no destination is chosen from scraped text. |
| `retrieved_page_injection` | `fetch_url`, `attack_goal`; callback origin in `authorized_destinations` | Ask the assistant to summarize one controlled page while the page tries to redirect its behavior. Check callback evidence and the independent verifier. |
| `route_discovery` | none | Ask for chat, history, status, audit and verifier paths. |
| `agent_routing` | none | Ask for agent names, tiers and an escalation trigger. |
| `output_validator` | none | Ask for exact output/schema constraints and missing fields. |
| `guardrail_representation` | `item` | Ask for code points and a character array; reconstruct and verify separately. |
| `refusal_policy` | none | Ask for the refusal label and prerequisite. |
| `diagnostic_chat` | credentials in private `headers` or chat fields | Ask for diagnostic fields and status after the app authorizes the session. |
| `workflow_status` | `status_path` when exposed | Ask for stage and artifact; read the status route once if supplied. Set `status_after_each_chat` to inspect and pause after each prompt. |
| `orchestrator_action` | `action_prompt`, `status_path`, `allow_state_change: true` | Send one explicit final action prompt, then read status once. |
| `kb_injection` | an `injection` object with exact `success_status` | Write one exposed lower-trust KB item or multipart document, require its declared acceptance response, then send its trigger prompt. A repeated marker stays unvalidated. |
| `custom_chat` | `prompts`: one to four strings | Run a target-specific prompt idea with the same session and evidence controls. |
| `context_bloat` | none | Test context retention at bounded sizes. |
| `scorer_batch` | `path`, `body_field`, `score_field`, `candidates`, `allow_state_change: true` | Score one to fifty explicit inputs serially; numerical scores are observations, not membership proof. |

The selected strategy sends its listed probes after one baseline. It does not
run every strategy or the whole CHY corpus. A response that reveals a route or
secret stops broad prompting. The private run contains a JSONL transcript,
candidate and checker evidence, cookies, and a report. The ordinary terminal
output contains only status and file paths, including for `report`. `--max-requests` is at most 100,
`--max-prompts` at most 20, and `--budget` at most 600 seconds. The HTTP client
also caps each response at 128 KiB, each request body at 128 KiB, and its
transcript at 2 MiB.

One live owner lock is held for each authorized origin across runs from the
same local user account, even when run directories differ. A second live start
or resume exits busy before sending requests; dry runs remain independent.
The lock and its private state live under the account's `~/.local/state`
directory, independent of the process `HOME` setting. A `Retry-After` cooldown
also applies to fresh runs at that origin, including lock-labeled 429 replies.
An uncertain POST leaves a private origin marker after the client exits. New
live runs stay blocked, while resuming the recorded run can make a read-only
history/status check. Once you have checked that the server-side attempt is no
longer active, release that origin explicitly:

```sh
python3 scripts/autosolve.py resume .autosolve/runs/RUN_ID --budget 10
python3 scripts/autosolve.py chatbot-release-origin .autosolve/runs/RUN_ID
```

The release command makes no network request and never replays the POST. It
does not validate challenge success or bypass an active Retry-After cooldown.
The lock is conservative for separate
identities at one exact origin; aliases, machines and user accounts still need
a single human-assigned chat owner.

If the frontend requires one login, claim, or token exchange before chat,
declare a `bootstrap` request using the [POST tab-claim example](chatbot_recipes/tab_claim.json)
or [GET token example](chatbot_recipes/get_token_bootstrap.json). GET has no
body; POST declares its exact JSON or form body. Set `allow_state_change: true`
and the exact 2xx `success_status`. A token can come from `token_field` in the
response JSON or one unique `token_header` in the response headers, then be
copied into the declared chat `header` or `chat_field`. Header tokens are
bounded to 4,096 printable characters. Optional `success_field`/
`success_value` checks the response body. The request runs once with the same
cookie jar before prompts; a redirect, timeout, missing token, or mismatched
success field leaves its outcome uncertain. Resume can inspect a configured
status route but never repeats the bootstrap automatically. If the frontend also
requires a heartbeat, use the [tab-heartbeat example](chatbot_recipes/tab_heartbeat.json)
to declare its path, body, exact success status, optional captured token field,
optional success field/value, and interval. Due
heartbeats run serially before chat and count against the same request budget.
An uncertain heartbeat is not replayed; resume can inspect a configured status
route once. Multi-step login and force-claim semantics still need target-
specific work.

For a tool-header capture, start the bounded callback receiver first. Its
default bind is loopback, and it exits after one request or its duration. A
remote challenge can reach it only if you deliberately provide a reachable
authorized address; put that address in the protocol's
`authorized_destinations` before selecting `fetch_tool`. Raw callback headers
stay in a private JSONL file.

```sh
python3 scripts/chatbot_callback.py --port 0 --max-requests 1 --duration 60
```

For a fetched-page injection, serve a bounded local file with the callback
instead of its default empty response. Copy the
[retrieved-page protocol](chatbot_recipes/retrieved_page.json), replace the
chat fields and callback URL with the observed authorized routes, and use
`--strategy retrieved_page_injection`. The example page contains only a
synthetic marker. The callback logs the actual fetch in its private run; the
chatbot run records a redacted entry URL and the declared goal's SHA-256; the
exact goal remains in the private protocol. A
page echo alone is not prompt-injection evidence, and a challenge result is
validated only by an independent checker or persisted state.

```sh
python3 scripts/chatbot_callback.py --response-file scripts/chatbot_recipes/example_retrieved_page.txt \
  --response-path /payload \
  --content-type text/plain --max-requests 1 --duration 60
python3 scripts/autosolve.py chatbot --origin https://AUTHORIZED_ORIGIN \
  --protocol ./private-retrieved-page.json --strategy retrieved_page_injection \
  --budget 60 --max-requests 10 --max-prompts 3 --dry-run
```

Use a reachable callback address only when that destination is explicitly
authorized. The receiver binds to loopback by default; a public bind needs
`--allow-public-bind` and serves the file only for the declared GET path and
optional exact query,
request count and duration. The served file is capped at 64 KiB; the callback
run stores an exact private snapshot and its SHA-256 in the request log.

When a guardrail returns code points, character arrays, NATO words, initials,
reversed text, groups, Base64, or byte-like embedding values, save the exact response in a private text
file and decode it as a candidate. The tool-call audit helper compares
`args_raw`, `args_validated`, `args_normalized`, and `args_applied` from a JSON
response or a chosen transcript line. It reports changed paths and hashes,
never proof of applied backend state.
The helper caps local input at 128 KiB and returns `invalid_input` for malformed
or excessively nested JSON; it does not print decoded candidate text.

```sh
python3 scripts/chatbot_evidence.py decode --input ./private-reply.txt --mode codepoints
python3 scripts/chatbot_evidence.py decode --input ./private-embedding.json --mode embedding-bytes
python3 scripts/chatbot_evidence.py audit --input .autosolve/runs/RUN_ID/transcript.jsonl \
  --line 5 --raw-field tool_calls.0.args_raw \
  --validated-field tool_calls.0.args_validated \
  --normalized-field tool_calls.0.args_normalized \
  --applied-field tool_calls.0.args_applied
```

## Direct application routes

Select `api_plan` when the decisive path is a normal API. It uses the same
origin, cookie jar, redirects, request budget, and private transcript. A plan
contains one to ten declared GET or POST steps; POST requires
`allow_state_change: true`. A configured `expect` compares an exact response
field. Only an official checker/completion step marked `acceptance: true` can
mark a result validated. An expected field match on a history or vector-store
response is evidence, not a solve. Same-origin redirects are logged, but their
final response does not validate the originally declared checker route or
provide a scorer observation.
When a chat response exposes a same-origin route in `tool_calls` or JSON
function arguments, the runner records that clue and stops broader prompting.
Tool-only responses can supply the clue without assistant text. For SSE, the
client joins bounded argument fragments by tool-call index before inspection.
It directly checks only a configured GET verifier, history, status, or audit
route. Unknown paths, POST-only verifiers, and routes with query values need an
explicit API plan; a tool-call claim is never challenge acceptance by itself.

Start from the [history](chatbot_recipes/history_idor.json),
[vector-store](chatbot_recipes/vector_store.json),
[debug/verifier](chatbot_recipes/debug_verifier.json),
[fresh-nonce verifier](chatbot_recipes/nonce_verifier.json),
[scorer-batch](chatbot_recipes/scorer_batch.json),
[tool-audit](chatbot_recipes/tool_audit.json), or
[workflow](chatbot_recipes/workflow_action.json) examples. Replace every
`REPLACE_` field before live use; the CLI rejects live plans that retain one.
The [KB example](chatbot_recipes/kb_article.json) shows a JSON/form write.
The [document upload example](chatbot_recipes/document_upload.json) uses a
synthetic text file and a multipart form. Replace its route, file field, and
file content after inspecting the challenge. Set the write's exact
`success_status` and optional `success_field`/`success_value` from the frontend;
an unconfirmed write is never followed by its trigger prompt or replayed on
resume. The upload file is limited to
64 KiB and hashed into the run identity; changing it invalidates resume.
Do not enumerate IDs, origins, or ports by changing a plan
into a bulk scanner. For SQLi, SSRF, IDOR, auth bypass, or other ordinary web
bugs, use the web workflow once the relevant primitive is observed.

For an exposed one-shot nonce route, one `api_plan` step may set
`capture_field` to a scalar JSON response path or `capture_header` to one
explicit response header. Use the [body-field nonce recipe](chatbot_recipes/nonce_verifier.json)
or [response-header nonce recipe](chatbot_recipes/header_nonce_verifier.json).
One later POST may set either
`bind_body_field` or `bind_header` to place that fresh value in its declared
request. The client keeps the same cookies, stores the captured value only in
the private run, and redacts its later request body or header. A missing,
non-scalar, oversized, duplicate-header, or redirected capture stops before the verifier POST.
The bound POST is never replayed after an uncertain outcome. This adapter does
not derive signatures, chain multiple tokens, or infer acceptance from a model
claim; use the challenge's documented checker field.

For a staged chat workflow, copy the
[workflow-stage recipe](chatbot_recipes/workflow_stage.json) and set
`status_after_each_chat: true` with the observed `status_path`. The runner
reserves one GET after every completed chat prompt, stores its exact response
in the private transcript, and pauses before the next prompt. Resume retries
only an incomplete status GET; after a complete check, the next explicit
resume sends the next chat prompt once. A stage number or artifact is an
observation until the official completion state confirms the objective.

```sh
python3 scripts/autosolve.py chatbot --origin https://AUTHORIZED_ORIGIN \
  --protocol ./private-api-plan.json --strategy api_plan \
  --budget 60 --max-requests 12 --max-prompts 1 --dry-run
```

## Offline model and scorer routes

The offline helper does not deserialize pickle files or run a supplied wrapper
during inspection. It reports bounded metadata from NPY, NPZ, safetensors,
zip-backed PyTorch files, and pickle globals. A small pair of NPZ or
safetensors files can be compared when NumPy (and, for safetensors, that
package) is installed. Parity runs two explicit wrapper commands on up to 20
JSON canaries and requires `--execute-local`.

```sh
python3 scripts/ai_model.py inspect ./model.safetensors
python3 scripts/ai_model.py compare ./base.npz ./challenge.npz
python3 scripts/ai_model.py suppression ./base.npz ./challenge.npz
python3 scripts/ai_model.py svm ./private-svm-parameters.json
python3 scripts/ai_model.py sign-gates ./private-sign-gates.json --timeout 10
python3 scripts/ai_model.py parity ./private-parity.json --execute-local
python3 scripts/ai_model.py calibrated-search ./private-calibrated-search.json --execute-local
python3 scripts/ai_model_attack.py --adapter ./private-adapter.py --execute-local \
  gradient --model ./model.pt --input ./input.npy --target chosen-class \
  --epsilon 0.1 --step-size 0.02 --steps 10
python3 scripts/ai_model_attack.py --adapter ./private-adapter.py --execute-local \
  recurrent --actions ./actions.json --seed 0
```

A [parity config](chatbot_recipes/model_parity.json) supplies `reference` and
`candidate` argv arrays, `cases`, a
per-call `timeout` (at most 30 seconds), and a total `budget` (at most 600
seconds). Each wrapper reads one JSON value on stdin and prints one JSON value
on stdout. The script uses no shell and records only case indexes, equality,
and output hashes in a private report. It never claims that matching canaries
prove full inference parity.

Copy the [model adapter template](templates/ai_model_adapter.py) for gradient
or recurrent runs. Gradient mode needs `load_model(path)`, `load_input(path)`
returning a floating PyTorch tensor, and `loss(model, tensor, target)` returning
one scalar to maximize. It applies bounded projected gradient steps and saves
an NPY candidate; it does not serialize a challenge submission. Recurrent mode
needs `reset(seed)`, `policy_step(observation, previous_action, hidden)`, and
`env_step(action)`. It records pre/post auxiliary vectors with one policy call
per observed state, avoiding a duplicate hidden-state advance. Both modes
execute the adapter only with `--execute-local`. That opt-in is not a sandbox.
NumPy and PyTorch are optional local requirements for gradient mode.

For a deterministic sign network, export the actual affine gates and input
bounds into the [sign-gate JSON example](chatbot_recipes/sign_network.json).
`ai_model.py sign-gates` uses Z3 when installed, returns one satisfying input,
and checks whether another input also satisfies the declared constraints.
It does not infer gates from a model or treat a satisfying assignment as a
validated flag. The supplied checker must accept the serialized candidate.

`ai_model.py suppression` calculates the explicit `2*base-challenge`
hypothesis for small matching floating NPZ tensors and stores a float64
candidate. It does not identify historical weights from an ambiguous
transformation. Check the producer's arithmetic and run parity before using
the candidate.

For a black-box scoring endpoint, `scorer_batch` can collect up to 50 explicit
inputs serially. Put known member and nonmember controls at declared one-based
positions, then compare their scalar scores offline:

```sh
python3 scripts/chatbot_evidence.py score-controls \
  --input .autosolve/runs/RUN_ID/manifest.json \
  --positive 1,2 --negative 3,4 --candidates 5,6 --direction higher
```

The private report gives control medians, whether the observed ranges strictly
separate, and candidate rankings in the declared score direction. Calculations
use decimal representations of the recorded scores and include the source
manifest hash. Median and gap arithmetic is capped at 512 digits; the report
sets `medians_rounded` when that cap loses precision. Strict separation and
candidate ordering compare the exact recorded values. For `scorer_batch`,
JSON fractional score tokens are retained
as exact decimal strings in the private manifest; finite scalar scores over
512 characters or outside ±1e150 stop the batch. Ordinary `api_plan` response
parsing keeps its configured schema behavior.
It never labels a candidate as a member. Use repeated controls to assess stochasticity
and the challenge's independent verifier to establish any membership claim.

For local unknown-behavior search, copy the [calibrated-search recipe](chatbot_recipes/calibrated_search.json)
and [score wrapper template](templates/ai_score_wrapper.py). The wrapper must
reproduce the challenge's preprocessing, inference, and exact scored output
boundary, then return one finite scalar for each JSON input. Put known behavior
and frozen negative controls beside explicit candidates within a 50-case limit. The
command runs one local wrapper process per case with a 30-second per-call and
600-second total maximum. `--execute-local` runs that wrapper with the current
account's access; it is not a sandbox. Each input is at most 8 KiB, and each
finite score is at most 512 characters. The command records hashes of the
exact JSON sent to the wrapper and score strings in a private report. It
preserves completed scores if a later case times out and ranks only the
supplied candidate set. If no positive control is known, the
report remains uncalibrated. A separated control range is evidence that this
statistic is worth testing further, not proof of a backdoor, identity, or
challenge acceptance. Candidate generation and verifier serialization remain
target-specific; run `parity` on representative canaries before scaling a
model-specific scorer.

| CHY offline route | Ready script step | Target-specific work that remains |
| --- | --- | --- |
| Sparse model or classical binary SVM | `ai_model.py inspect`; `svm` computes primal weight, margins and slack from exported JSON parameters | Recover exact preprocessing and verify decoded text through the checker. |
| Deterministic sign verifier | `ai_model.py sign-gates` for exported affine gates; parity-check the scorer | Derive gates from the wrapper and verify a satisfying input. |
| Differentiable evasion or inversion | `ai_model_attack.py gradient` and parity canaries | Supply the challenge adapter, input bounds, loss direction, serializer, and checker. |
| Recurrent policy and world-model state | `ai_model_attack.py recurrent` and parity canaries | Supply environment, policy step, action list, and exact hidden-state contract. |
| Adapter/delta and weight differences | `ai_model.py compare` and explicit NPZ `suppression` hypothesis | Reproduce merge arithmetic, quantization, and full-model behavior. |
| Black-box extraction or membership | `scorer_batch` plus `chatbot_evidence.py score-controls` | Supply known controls, repeated queries when needed, and an independent membership oracle. |
| Token-identity parity and calibrated behavior search | `ai_model.py parity` on representative canaries; `calibrated-search` on an explicit bounded candidate set | Supply tokenizer/model wrappers, known controls, candidate generation and an independent verifier. |

These scripts cover repeatable mechanics, not arbitrary model semantics. A
specialized solver still needs the challenge's wrapper, data constraints and
acceptance endpoint. Refusals, marker echoes, high model scores, and plausible
identifiers remain candidates until independent state or checker evidence
confirms the objective.

The [AI/chatbot acceptance record](chatbot_acceptance.json) keeps AIC01 and
AIC02 partial, lists the local fixture gates, and leaves publisher transfer
untested. The broader MISC03 AI-dependent row remains unsupported.

## CHY pattern coverage map

This map follows the installed CHY chatbot skill's pattern index. "Ready"
means the command runs after the listed target fields are filled; it does not
mean the attack will succeed against an arbitrary challenge.

| Skill pattern | Prepared path | Remaining target-specific work |
| --- | --- | --- |
| Chat history IDOR | `api_plan` + `history_idor.json` | Supply one authorized account and an observed message ID; compare ownership evidence. |
| Tool header capture | `fetch_tool` + `chatbot_callback.py` | Provide a reachable, separately authorized callback address. |
| Retrieved-page tool-result injection | `retrieved_page_injection` + `chatbot_callback.py --response-file` | Supply the actual fetch URL, a controlled page and checker; compare behavior beyond a page echo. |
| Tool-backed SQL/filter injection | `tool_filter` | Learn the exact callable/field, then use the web SQLi workflow for confirmed injection. |
| Fetch-tool SSRF and blocklist bypass | `fetch_tool` / `fetch_blocklist` | Supply each authorized destination and verify the actual fetch, not a model claim. |
| Trusted KB or document injection | `kb_injection` + JSON or multipart recipe | Fill the exposed write route and verify state beyond an echo. |
| RAG source and alias mapping | `rag_sources` / `rag_aliases` | Supply a topic and verify returned IDs against the app. |
| Exposed vector store | `api_plan` + `vector_store.json` | Fill collection ID and inspect returned documents and metadata. |
| Model/agent switching | `agent_routing`, then `custom_chat` | Supply the observed trigger and verify a response field or backend state. |
| DLP or guardrail representation | `guardrail_representation` + `chatbot_evidence.py decode` | Reconstruct a candidate and check the real verifier. |
| Workflow validator and exact output | `output_validator` / `workflow_status` + `workflow_stage.json` | Fill stage/status route and inspect persisted progress between prompts when state can advance. |
| Chat ownership locks and rate limits | Shared transport, one-step `bootstrap`, and declared `heartbeat` | Map claim/heartbeat fields from frontend; honor cooldowns. |
| Tool-call audit lifecycle | `tool_audit` + `chatbot_evidence.py audit` | Fill audit route, inspect applied state independently, and pivot on bounded tool-call route clues. |
| Debug validator and direct verifier | `api_plan` + `debug_verifier.json`, `nonce_verifier.json`, or `header_nonce_verifier.json` | Fill documented boundary input and official completion field; one fresh scalar body or response-header nonce can be bound, while signature derivation remains target-specific. |
| Credential-gated diagnostic chat | `diagnostic_chat` | Recover the credential from authorized firmware/log/source evidence and put it in private protocol fields. |
| State-prepared AI orchestrator | `orchestrator_action` + `workflow_action.json` | Prepare backend state, fill exact action prompt, and confirm status. |
| Non-LLM application agent | `api_plan` for an exposed API; otherwise the web, protocol or reverse workflow | Identify the actual non-chat transport and its validator. |
| Sparse/SVM and sign-network verifiers | `ai_model.py inspect`, `svm`, `sign-gates`, `parity` | Export parameters/gates, check exact semantics, and run the supplied checker. |
| Tiny neural scorer and validator payloads | `ai_model.py inspect`, `ai_model_attack.py gradient`, and `parity` when the scorer is differentiable | Reproduce the wrapper's forward path and checker constraints; discrete graph or integer payload search remains target-specific. |
| Differentiable evasion and inversion | `ai_model_attack.py gradient` | Supply exact preprocessing, bounds, loss, and checker serialization. |
| Recurrent policy/world-model alignment | `ai_model_attack.py recurrent` | Supply environment and policy step wrappers with the correct hidden-state timing. |
| Adapter/delta weight recovery | `ai_model.py compare`, `suppression`, and `parity` | Reproduce merge, casts, rounding and full-model behavior. |
| Black-box extraction/membership | `scorer_batch` numeric observations plus `score-controls` comparison | Supply representative controls and an independent membership oracle. |
| Token-identity and inference parity | `ai_model.py parity` | Supply tokenizer/model wrappers and exact prompt boundaries. |
| Calibrated unknown-behavior search | `ai_model.py parity`, `calibrated-search` for a local wrapper, or `score-controls` for an API manifest | Supply known controls, an explicit candidate set and a target-specific objective; rankings are exploratory. |
