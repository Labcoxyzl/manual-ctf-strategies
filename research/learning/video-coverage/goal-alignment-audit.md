# Goal-alignment audit

Reviewed 2026-10-23 against the exact completed goal in `/home/ubuntu/.codex/attachments/823478b8-46cd-4dd0-b5d5-331dcbe4611f/pasted-text-1.txt`. Scope: requirements, canonical mapping, evidence claims, capability dispositions and verification breadth. Independent reviewers own current network access and substantive instructional quality. This audit changes only this report.

## Material finding G1: bundled capabilities disappear behind a row-level workflow label

**Status: resolved on focused recheck after integration repair.** Initial evidence is retained below; closure evidence follows.

- `collection.json` row `kali-94`, Nmap (with Ncat / Nping), explicitly states that Ncat/Nping need separate command lookup and includes Ncat connections in missing skills. Its sole learning resource, `web-network-9`, covers Nmap port states, service/version detection and output. The catalog has no Ncat or Nping instruction or disposition. A general `workflow_instruction` label does not close those identified capabilities.
- Row `kali-98` names the full oletools suite, including oleobj, rtfobj and msodde. Its sole resource, `reverse-depth-olevba`, covers VBA triage and decoded strings and explicitly says not every subcommand is covered. The catalog supplies no embedded-object/RTF/DDE routing or disposition, although the row identifies embedded payload extraction as a missing capability. This is narrower than the goal's audit of distinct challenge-solving capabilities.

Minimal repair: add inspected, bounded primary companions and concrete input/output checks for Ncat connections and oleobj/rtfobj extraction, then explicitly route Nping and other suite components as conditional, overlapping, or supporting capabilities. One concise suite routing reference can suffice; no separate video course is required. Update row dispositions and dependent CSV/catalog/matrix. Do not silently infer suite-wide coverage from the existing row-level labels.

## Requirement trace

| Goal requirement | Evidence and conclusion |
| --- | --- |
| Start from original workbook, inventory, event notes and prior pack | Source workbook at the path in EVENT_SOURCES.md exists and its freshly computed SHA-256 equals inventory source_sha256. Existing workbook extraction validation is reusable. The workbook basename in inventory is not a workspace-relative copy. |
| Preserve all 200 exact rows and distinctions | Fresh comparison of all JSON names, platforms, versions, locations and remarks against inventory matches; all CSV canonical name/platform/version/location/priority/family fields match JSON. Existing checker covers row membership and original references. Rendered matrix explicitly links complete CSV. |
| Prioritize using categories and evidence, as judgments | Collection explicitly labels 48 essential, 47 specialist, 32 alternative and 73 support rows as preparation judgments. These counts match data; event notes identify the announced categories and do not mandate these priorities. |
| Distinguish incidental, introductory, workflow and deep instruction | Original-video assessment is clearly separated from added resources: 185 none, 4 incidental, 7 intro, 4 workflow, no deep. New resource depth has a defined legend. Six old clips are optional refreshers; two retain narrow workflows. |
| Audit distinct capabilities and avoid token row coverage | G1 was the identified exception and is now closed by explicit component routes and bounded checks. A row with one non-reference resource alone is not evidence that all important capabilities named in that row were assessed. Other substantive-quality judgments belong to the parallel review. |
| Resources, skills, depth, prerequisites and limits | Every CSV row has nonempty skills/depth/prerequisite/limit fields and resource mappings. Catalog makes selected resources directly usable. Generic fields in references do not establish demonstrated mastery, which the collection correctly disclaims. |
| Free material and approval boundaries | Access records separate reading, streaming, paid offline downloads, hosted-account execution and local practice. Explicit selected-video exclusions exist for FTK, NirSoft and unapproved reverse-engineering continuations. Fresh access/content assurance is owned by parallel reviewers. |
| Correct, individually verified runtime without padding | Existing metadata/caption hash checks remain valid on unchanged artifacts. Recorded sums: old full 6214s, new full 25040s, combined full 31254s (8:40:54), new selected 16898s (4:41:38), retained selected 2352s (39:12). Estimates are separate; no claim exceeds 12 hours. |
| Practical and nonredundant learning routes | Fifteen capability tracks give outcomes/checks and bounded planning estimates; reference records are not extra courses. Existing synthetic checks establish fixture facts, not proficiency or organiser-machine execution. |
| Independent review and supported repair | Prior research lanes and review reports exist. Current recursive lanes retain separate ownership. Supported G1 was integrated and its affected mappings, routes and fixture evidence were rechecked. |
| Scope and execution limits | Artifacts explicitly retain untested playback/GUI/forensic/malware execution. This audit did not launch portals, download videos, create accounts, send material, or mutate the collection. |

## Check interpretation

All hashes listed in the existing `validation.json` matched when checked, so the valid recorded checker execution was reused instead of repeated. Fresh targeted comparisons above supplement it. `check_tool_collection.py` establishes structural integrity, resource presence, runtime arithmetic, selected intervals and local link/fixture integrity. It deliberately does not prove teaching quality: its essential-row predicate accepts any mapped non-reference depth. Its CSV checks primarily establish IDs and original references; this audit separately compared canonical CSV fields. No presently mismatched CSV fields were found, so this is a scope statement, not a speculative repair request.

## Initial reviewed SHA-256 values

- `TOOL_LEARNING_COLLECTION.md`: `5877ebe362ec36ea05969d3b2cc29e9d4a7d69d9ef272f3dde13c7292dde849c`
- `TOOL_RESOURCE_CATALOG.md`: `5fafa1399f9dfad492a5aba9e1e618d365dc8634359f7cecf550d153d52414f6`
- `TOOL_COVERAGE_MATRIX.md`: `53e52b54bc14159986e929cf8275c9cd6b9dc1f4ce5ac9d0ac7834753b0dc464`
- `research/learning/video-coverage/collection.json`: `17e6e9a89510b7be8d1bd3ec02d493534f5d3a22a741401671fcd8c940e8215e`
- `research/learning/video-coverage/coverage.csv`: `befb2d7a35f312123723505c19956e62ed43ac0d482baa9d7d74296f44a2b2a8`
- `tests/check_tool_collection.py`: `b57c7c07bcd80a58467b183735847f810f379ce98ba6614908d7d8b81555c0e1`
- `research/inventory.json`: `d4e8f647ffc71eac3ca307f9b542bf553fa3385c70d95fde8e90ebab41bb4f0f`
- `EVENT_SOURCES.md`: `872b7d4f9623390b05581ac9c0ce7dbc62532fe2955fbab0d3f3e04ce4f46e12`

## Focused G1 closure recheck

The repaired JSON enumerates Nmap, Ncat and Nping separately and all nine named oletools components. Each component maps to the appropriate retained or new route. Ncat now has an explicit loopback client/listener example, expected bytes, protocol-aware follow-up and failure interpretation; Nping has a bounded conditional probe reference with execution/privilege limits. The oletools route distinguishes VBA, OLE/RTF extraction, DDE, indicators, metadata, timestamps and SWF; it supplies selected-object extraction syntax, benign fixtures, expected payload and version-specific return-code interpretation. The primary references are directly linked and the route records what was inspected. This meets the requested capability disposition without inventing nine separate courses.

The two repaired matrix rows link their new catalog resources; CSV dispositions match JSON and include both new resource IDs. Catalog entries link the local route. Read both recorded execution-result files; freshly verified the OLE/RTF input hashes and the expected seventeen-byte payload SHA-256. Reused the parent's bounded execution evidence rather than rerunning unchanged checks. Nping, HTTP variation and the conditional suite tools remain explicitly unexecuted. No additional material G1 issue was found. Other concurrent findings and final checker updates remain the integration owner's responsibility.

### Rechecked artifact hashes

- `TOOL_LEARNING_COLLECTION.md`: `c7e1fe5001a0347fea6834612bc269218f55d85fb3912d4cd8f7c585dbe7114c`
- `TOOL_RESOURCE_CATALOG.md`: `2baab8e8e666be37f970533bdaeb6363b281e1736e742e9fe075923131541d5b`
- `TOOL_COVERAGE_MATRIX.md`: `dbead02295dd0788dd0e9505a268c4ed0de0bed5b75b3cd467c99fe18065b610`
- `research/learning/video-coverage/collection.json`: `d97b95ed626e65dd46ca9132955d11c1ab1ba1bc735f655f6f63d93d0447c417`
- `research/learning/video-coverage/coverage.csv`: `81d1a9b82249a6245ff1e276854c1161a53251cc2b10e813493eca18b43d1d79`
- `tests/check_tool_collection.py`: `b57c7c07bcd80a58467b183735847f810f379ce98ba6614908d7d8b81555c0e1`
- `research/learning/video-coverage/practice/CAPABILITY_ROUTES.md`: `ca98fe9242496d953c70571b3f51740f97e1c3cac5b9a8515aea01517a91cace`
- `research/learning/video-coverage/practice/ncat-check.json`: `a481ddf9f1cd969e78961985f317c10bc96de6ef96bf0069da27ecea240845a5`
- `research/learning/video-coverage/practice/bundle-extraction-check.json`: `597be1f9b0b1442a3f4d002ef7c4935e6a74d04a38589f599d297d1c86c5e4b7`
