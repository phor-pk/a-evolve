# audit-ledger

A Claude Code mod (function-hook plugin, built and checked against Claude Code 2.1.296) that records what happens in a session as a tamper-evident ledger and audits whether each claim of completion is backed by a check that actually ran.

## What it records

Every entry is one line of canonical JSON in an append-only, SHA-256 hash-chained segment file. Each entry carries `seq`, `ts`, `session`, `kind`, `origin` (for capability calls), `data`, `prev` (the hash of the entry before it) and `hash` (SHA-256 over the entry's canonical encoding, RFC 8785 key ordering). The chain head (`seq`, `hash`, `segment`) is anchored separately in the mod's `$.store`, so truncating the tail of a segment is detectable, not only editing it.

| Kind | Source event | Notable fields |
| --- | --- | --- |
| `session.start`, `session.end` | session lifecycle | version, surface, mode, end reason |
| `prompt.submit`, `prompt.drop` | `prompt.submit` | origin kind, text payload |
| `turn.start`, `turn.complete` | turn lifecycle | turnId, agentId, reason, durationMs, usage, answer payload |
| `tool.intent` (enforce mode only), `tool.call` | `tool.call` | tool, id, agentId, input payload, outcome (`ok`, `error`, `denied`), deny reason, `isCheck`, ms, output digest |
| `agent.spawn` | `agent.spawn` | subagent type, requested and resolved model, agentId, background, fork, prompt payload |
| `op.*` | other mods' `$` calls: `fs.write`, `process.run`, `http.fetch`, `env.set`, `model.complete`, `model.fork`, `mcp.call`, `tool.register`, `agent.register`, `session.authorize` | the calling mod as `origin`, a summary of the call, deny |
| `supervisor.verdict`, `supervisor.invalid`, `supervisor.error` | the completion supervisor | verdict, fork usage |
| `ledger.verify` | `/audit verify` | result and problems |

A payload is `{ digest, bytes, excerpt? }`: the SHA-256 digest and size of the full text, plus a 500-character excerpt with common secrets (`Authorization`, `Bearer`, `api_key=`, `sk-…`, `ghp_…`, `AKIA…`, `xox?-…`) replaced by `[REDACTED]`. Set `capture` to `digest` to keep no excerpts at all. A successful tool's output is always kept as a digest alone; a failed one keeps an excerpt, since the error is the evidence. Environment values, HTTP query strings and headers, and `fs.write` contents are never recorded.

Segments live at `<ledgerDir>/<session id>/000001.jsonl` and roll over at about 1 MB, under the 4 MiB limit of `$.fs.read`. The ledger directory defaults to `.claude/audit` under the project root; add it to `.gitignore` unless the team intends to commit it.

## The completion supervisor

When a main-loop turn ends with an answer that claims completion (`done`, `fixed`, `tests pass`, `ready for review` and similar), the mod forks the session once with `$.model.fork`. The fork reuses the main thread's prompt cache, so its marginal cost is the auditor's instruction and the reply. The fork receives the answer and the turn's tool calls from the ledger, each check command (`pytest`, `tsc`, `ruff`, `claude plugin validate` and peers) marked, and a deterministic flag `claim_without_check`, which is true when the answer claims completion and no check ran and passed this turn. It must reply with one JSON object:

```json
{"state":"verified|unverified|partial|blocked|no-claim","claims":[],"checks":[{"name":"","result":"pass|fail|not-run"}],"open_items":[],"confidence":0.0,"next_action":""}
```

The 2.1.296 `ModelForkRequest` has no schema parameter, so the mod validates the reply itself. A reply that is not exactly this contract is rejected, recorded as `supervisor.invalid`, and raised as a toast; it is never coerced into a verdict. The verdict draws in a band above the prompt (press `d` to dismiss), an `UNVERIFIED` verdict also raises a toast, and the fork's token usage accumulates in `/audit status`, so the supervisor is metered rather than assumed free.

## Commands

| Command | Result |
| --- | --- |
| `/audit` or `/audit status` | mode, ledger path, head, entry and failure counts, supervisor token meter, last review |
| `/audit verify` | walks every segment from genesis, recomputes each hash, checks `seq` and `prev` continuity and the anchored head; prints `PASS` or `FAIL` with the first break, and exits 1 on `FAIL` in a headless run |
| `/audit tail [n]` | the last `n` entries (default 20, at most 200) |

## Options

| Option | Values | Default | Effect |
| --- | --- | --- | --- |
| `ledgerDir` | path | `.claude/audit` | relative to the project root, or absolute |
| `mode` | `observe`, `enforce` | `observe` | `observe` records after each tool call and never blocks one. `enforce` writes a `tool.intent` entry before the tool runs and refuses the call when that write fails or the hook fails before it, so no tool runs unrecorded. |
| `supervise` | `claims`, `always`, `off` | `claims` | when to fork the completion supervisor |
| `capture` | `excerpt`, `digest` | `excerpt` | whether payloads keep a redacted excerpt |

## Install

```
/plugin install audit-ledger --marketplace phor-pk/a-evolve
```

Answer `y` to add the marketplace, then choose a scope. To run it from a working copy for one session instead: `claude --plugin-dir mods/audit-ledger`. `--safe-mode` disables it, as it does every installed mod.

## Checks

```
claude plugin validate mods/audit-ledger --strict
claude plugin test mods/audit-ledger
```

The tests drive the real hook chain under the engine's test kit, with an in-memory filesystem, store, clock and model fork beneath the mod. They cover the chain proof, detection of an edited entry, enforce-mode refusal, observe-mode fail-open, supervisor verdicts and rejected replies, `claims`-mode gating, capability-call attribution to the calling mod, and the band on the terminal and desktop surfaces. The pure core (`hooks/ledger.ts`) has its own tests for canonical encoding, truncation and deletion detection, redaction, and verdict parsing.

## Limits

The ledger is tamper-evident, not tamper-proof. The mod runs with the user's authority, and anyone with that authority can rewrite both the segments and the store head together. Copy segments and heads somewhere the session cannot write when the record must survive a hostile user. `$.fs.write` is not atomic, so a crash mid-write can leave a damaged segment; `/audit verify` reports it as a break rather than passing over it. Observational hooks fail open by design: if the ledger cannot write in `observe` mode, the action proceeds and the failure shows on the status line, in the band, and in `/audit status`. Use `enforce` when an unrecorded tool call is unacceptable.
