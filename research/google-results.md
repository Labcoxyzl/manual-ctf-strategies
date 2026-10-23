# Google AI Overview comparison: blocked, candidates unranked

On 19 October 2026 at 05:46:21 UTC, the first controlled Google search (`CyberChef decode base64 recipe example`) redirected to `https://www.google.com/sorry/index`. The page reported unusual traffic from this network and requested a human check. No search results or AI Overview were observed. No CAPTCHA was attempted, and further Google requests stopped.

Before that request, Playwright MCP could not reuse its profile because a live Chrome process held it. Inspection confirmed Chrome PID 767578 belonged to playwright-mcp PID 753852 and used a debugging pipe. That existing browser was preserved. The one Google navigation used a separate ephemeral Chrome context through the already installed Playwright package, without copied cookies or account state. The JSON stores a sanitized page-text excerpt; redirect challenge tokens and the network IP are omitted.

This result does **not** mean the query lacks an AI Overview. It means visibility and answer quality could not be measured. Ordinary web-search tool results are not Google AI Overviews and cannot establish a winning query.

[Google's AI Overview help](https://support.google.com/websearch/answer/14901683?hl=en) says Google decides when an overview is useful, acknowledges possible mistakes, and recommends verifying sources and trying different versions of a question. No keyword wording guarantees an overview. The [AI features documentation](https://developers.google.com/search/docs/appearance/ai-features) also does not provide a user-query ranking benchmark.

The proposed queries use exact tool identity, relevant format or platform, one task, and an example or workflow term. This is a documented-functionality design choice, not an observed superiority claim. Ambiguous names particularly need qualifiers: `file Linux command`, `Mandiant FLOSS`, `Mandiant capa`, `WithSecure Chainsaw EVTX`, `Yamato Security Hayabusa EVTX`, and `ZBar zbarimg QR` distinguish the intended projects. Direct documentation remains the fallback.

## Remaining comparison coverage

The companion JSON records all 15 original route queries, all seven category pairs, and all 200 approved tool rows by stable inventory ID. Every unexecuted comparison is marked `not_run_after_network_block`, with null scores. Category queries and alternatives are in `categories.json`; all 200 tool primary/alternate candidates have been joined from `queries-a.json`, `queries-b.json`, and `queries-c.json` by ID and are recorded explicitly in the comparison matrix. Duplicate names on different platforms retain separate rows because version and platform context may change the useful answer. The matrix records SHA-256 hashes for all four candidate input files under `candidate_input_sha256`, so later changes can be detected.

After Google access works normally, compare each tool's generic baseline (`tool name tutorial`), primary task query and alternate under the same language, country, signed-in state and device conditions. Compare each category's generic baseline, workflow query and focused alternate. Record time, full public query, visible Overview presence, answer excerpt and cited source URLs. Stop on another unusual-traffic page. Repeat promising comparisons in a later session before describing any query as consistently better; a single response only supports that observation.

Score **visible AI Overviews only**, using 0–2 for each of correct identity/version/platform, useful first action, correct syntax or GUI steps, and supporting authoritative sources. Syntax can be null when not applicable. Reject a candidate with an incorrect identity or wrong first action regardless of total. For absence or blocking, retain null quality scores rather than assigning zero quality. Keep ordinary result relevance as a separate observation. Never put actual challenge text, artifacts, credentials or flags in these queries.

No AI Overview winner has been established. The live comparison requirement remains incomplete because of the observed network challenge.
