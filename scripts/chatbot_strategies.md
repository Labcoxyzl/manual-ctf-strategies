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

| Strategy | Required protocol fields | What the script does |
| --- | --- | --- |
| `instruction_leak` | none | Ask for a hidden instruction quote and a short prefix. |
| `rag_sources` | `topic` | Ask for source IDs, metadata and one exact quote. |
| `rag_aliases` | `topic` | Ask for labels and their backend field names. |
| `tool_schema` | none | Ask for callable names and argument schemas. |
| `tool_audit` | `audit_path` in the protocol when exposed | Ask for the tool call lifecycle; read the audit route once if supplied. |
| `tool_filter` | `tool_name`, `filter_value` | Ask for one exact filter argument; inspect real tool evidence before using the web workflow. |
| `fetch_tool`, `fetch_blocklist` | `fetch_url`; its origin in `authorized_destinations` | Send one explicit fetch request through the chatbot; no destination is chosen from scraped text. |
| `route_discovery` | none | Ask for chat, history, status, audit and verifier paths. |
| `agent_routing` | none | Ask for agent names, tiers and an escalation trigger. |
| `output_validator` | none | Ask for exact output/schema constraints and missing fields. |
| `guardrail_representation` | `item` | Ask for code points and a character array; reconstruct and verify separately. |
| `refusal_policy` | none | Ask for the refusal label and prerequisite. |
| `diagnostic_chat` | credentials in private `headers` or chat fields | Ask for diagnostic fields and status after the app authorizes the session. |
| `workflow_status` | `status_path` when exposed | Ask for stage and artifact; read the status route once if supplied. |
| `orchestrator_action` | `action_prompt`, `status_path`, `allow_state_change: true` | Send one explicit final action prompt, then read status once. |
| `kb_injection` | an `injection` object | Write one exposed lower-trust KB item or multipart document and send its trigger prompt. A repeated marker stays unvalidated. |
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

If the frontend requires one login, claim, or token-exchange POST before chat,
add a `bootstrap` object like the [tab-claim example](chatbot_recipes/tab_claim.json).
It declares the exact path/body and, when needed, the response token field to
copy into a chat field or header. Set `allow_state_change: true`. The request
runs once in the same cookie jar before prompts; a timeout leaves its outcome
uncertain and resume will not replay it automatically. If the frontend also
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

For an authorized fetch tool that retrieves a page you control, serve one
bounded file on an exact GET path instead of the receiver's default empty
response. The synthetic example below contains no challenge data:

```sh
python3 scripts/chatbot_callback.py \
  --response-file scripts/chatbot_recipes/example_injection.txt \
  --response-path '/payload?nonce=1' --content-type text/plain \
  --max-requests 1 --duration 60
```

Use a regular response file without symlinked path components. It is capped at 64 KiB and copied into a private callback run. Only the
exact path and query receive its bytes; other requests do not consume the
one-request limit. Loopback is the default. A reachable bind needs an
explicitly authorized destination and `--allow-public-bind`; use a private,
unpredictable path and query because anyone who knows them can fetch the page
and consume a request slot. The fetch log shows what was requested, while a
page echo alone does not establish that the chatbot followed an instruction
or that a checker accepted it.

When a guardrail returns code points, character arrays, NATO words, initials,
reversed text, groups, Base64, or byte-like embedding values, save the exact response in a private text
file and decode it as a candidate. The tool-call audit helper compares
`args_raw`, `args_validated`, `args_normalized`, and `args_applied` from a JSON
response or a chosen transcript line. It reports changed paths and hashes,
never proof of applied backend state.

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
response is evidence, not a solve.

Start from the [history](chatbot_recipes/history_idor.json),
[vector-store](chatbot_recipes/vector_store.json),
[debug/verifier](chatbot_recipes/debug_verifier.json),
[scorer-batch](chatbot_recipes/scorer_batch.json),
[tool-audit](chatbot_recipes/tool_audit.json), or
[workflow](chatbot_recipes/workflow_action.json) examples. Replace every
`REPLACE_` field before live use; the CLI rejects live plans that retain one.
The [KB example](chatbot_recipes/kb_article.json) shows a JSON/form write.
The [document upload example](chatbot_recipes/document_upload.json) uses a
synthetic text file and a multipart form. Replace its route, file field, and
file content after inspecting the challenge. The upload file is limited to
64 KiB and hashed into the run identity; changing it invalidates resume.
Do not enumerate IDs, origins, or ports by changing a plan
into a bulk scanner. For SQLi, SSRF, IDOR, auth bypass, or other ordinary web
bugs, use the web workflow once the relevant primitive is observed.

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

**Competition restriction:** The approved-tool workbook forbids adding AI/ML
libraries to Python or uv on competition systems. The PyTorch gradient command
below is for permitted local preparation outside the competition. Do not add
PyTorch on a competition machine; if an ML runtime is already provided there,
confirm its use with the organiser first. See the [competition rules](../RULES.html).

```sh
python3 scripts/ai_model.py inspect ./model.safetensors
python3 scripts/ai_model.py compare ./base.npz ./challenge.npz
python3 scripts/ai_model.py suppression ./base.npz ./challenge.npz
python3 scripts/ai_model.py svm ./private-svm-parameters.json
python3 scripts/ai_model.py sign-gates ./private-sign-gates.json --timeout 10
python3 scripts/ai_model.py parity ./private-parity.json --execute-local
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
Gradient mode needs NumPy and PyTorch in the **same Python environment** that
runs the script. These packages are not bundled in the offline kit or core
requirements. For permitted preparation elsewhere, use the
[NumPy install guide](https://numpy.org/install/)
and [PyTorch's platform selector](https://pytorch.org/get-started/locally/),
then check the exported script with:

```sh
python3 -c 'import numpy, torch; print(numpy.__version__, torch.__version__)'
python3 -B -m unittest discover -s tests -p test_ai_model_attack.py
```

Without either package, gradient mode reports `invalid_input` with a dependency
reason; recurrent mode only needs packages imported by your own adapter.

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

| CHY offline route | Ready script step | Target-specific work that remains |
| --- | --- | --- |
| Sparse model or classical binary SVM | `ai_model.py inspect`; `svm` computes primal weight, margins and slack from exported JSON parameters | Recover exact preprocessing and verify decoded text through the checker. |
| Deterministic sign verifier | `ai_model.py sign-gates` for exported affine gates; parity-check the scorer | Derive gates from the wrapper and verify a satisfying input. |
| Differentiable evasion or inversion | `ai_model_attack.py gradient` (permitted preparation only) and parity canaries | Supply the challenge adapter, input bounds, loss direction, serializer, and checker. |
| Recurrent policy and world-model state | `ai_model_attack.py recurrent` and parity canaries | Supply environment, policy step, action list, and exact hidden-state contract. |
| Adapter/delta and weight differences | `ai_model.py compare` and explicit NPZ `suppression` hypothesis | Reproduce merge arithmetic, quantization, and full-model behavior. |
| Black-box extraction or membership | `scorer_batch` for bounded, explicit scorer inputs | Design controls, statistics, and independent membership oracle. |
| Token-identity parity and calibrated behavior search | `ai_model.py parity` on representative canaries | Supply tokenizer/model wrappers and calibrated controls. |

These scripts cover repeatable mechanics, not arbitrary model semantics. A
specialized solver still needs the challenge's wrapper, data constraints and
acceptance endpoint. Refusals, marker echoes, high model scores, and plausible
identifiers remain candidates until independent state or checker evidence
confirms the objective.

## CHY pattern coverage map

This map follows the installed CHY chatbot skill's pattern index. "Ready"
means the command runs after the listed target fields are filled; it does not
mean the attack will succeed against an arbitrary challenge.

| Skill pattern | Prepared path | Remaining target-specific work |
| --- | --- | --- |
| Chat history IDOR | `api_plan` + `history_idor.json` | Supply one authorized account and an observed message ID; compare ownership evidence. |
| Tool header capture | `fetch_tool` + `chatbot_callback.py` | Provide a reachable, separately authorized callback address. |
| Tool-backed SQL/filter injection | `tool_filter` | Learn the exact callable/field, then use the web SQLi workflow for confirmed injection. |
| Fetch-tool SSRF and blocklist bypass | `fetch_tool` / `fetch_blocklist` | Supply each authorized destination and verify the actual fetch, not a model claim. |
| Trusted KB or document injection | `kb_injection` + JSON or multipart recipe | Fill the exposed write route and verify state beyond an echo. |
| RAG source and alias mapping | `rag_sources` / `rag_aliases` | Supply a topic and verify returned IDs against the app. |
| Exposed vector store | `api_plan` + `vector_store.json` | Fill collection ID and inspect returned documents and metadata. |
| Model/agent switching | `agent_routing`, then `custom_chat` | Supply the observed trigger and verify a response field or backend state. |
| DLP or guardrail representation | `guardrail_representation` + `chatbot_evidence.py decode` | Reconstruct a candidate and check the real verifier. |
| Workflow validator and exact output | `output_validator` / `workflow_status` | Fill stage/status route and check persisted progress. |
| Chat ownership locks and rate limits | Shared transport, one-step `bootstrap`, and declared `heartbeat` | Map claim/heartbeat fields from frontend; honor cooldowns. |
| Tool-call audit lifecycle | `tool_audit` + `chatbot_evidence.py audit` | Fill audit route and check applied state independently. |
| Debug validator and direct verifier | `api_plan` + `debug_verifier.json` | Fill documented boundary input, nonce/signature rules, and official completion field. |
| Credential-gated diagnostic chat | `diagnostic_chat` | Recover the credential from authorized firmware/log/source evidence and put it in private protocol fields. |
| State-prepared AI orchestrator | `orchestrator_action` + `workflow_action.json` | Prepare backend state, fill exact action prompt, and confirm status. |
| Non-LLM application agent | `api_plan` for an exposed API; otherwise the web, protocol or reverse workflow | Identify the actual non-chat transport and its validator. |
| Sparse/SVM and sign-network verifiers | `ai_model.py inspect`, `svm`, `sign-gates`, `parity` | Export parameters/gates, check exact semantics, and run the supplied checker. |
| Differentiable evasion and inversion | `ai_model_attack.py gradient` (permitted preparation only) | Supply exact preprocessing, bounds, loss, and checker serialization. |
| Recurrent policy/world-model alignment | `ai_model_attack.py recurrent` | Supply environment and policy step wrappers with the correct hidden-state timing. |
| Adapter/delta weight recovery | `ai_model.py compare`, `suppression`, and `parity` | Reproduce merge, casts, rounding and full-model behavior. |
| Black-box extraction/membership | `scorer_batch` numeric observations | Supply representative inputs, statistics and an independent membership oracle. |
| Token-identity and inference parity | `ai_model.py parity` | Supply tokenizer/model wrappers and exact prompt boundaries. |
| Calibrated unknown-behavior search | `ai_model.py parity` | Supply positive/negative controls and a target-specific bounded search objective. |
