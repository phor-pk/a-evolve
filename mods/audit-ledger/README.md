# audit-ledger

A Claude Code mod (function-hook plugin, built and checked against Claude Code 2.1.296) that records what happens in a session as a tamper-evident ledger and audits whether each claim of completion is backed by a check that actually ran.

## What it records

Every entry is one line of canonical JSON in an append-only, SHA-256 hash-chained segment file. Each entry carries `seq`, `ts`, `session`, `kind`, `origin` (for capability calls), `data`, `prev` (the hash of the entry before it) and `hash` (SHA-256 over the entry's canonical encoding, RFC 8785 key ordering). The chain head (`seq`, `hash`, `segment`) is anchored separately in the mod's `$.store`, so truncating the tail of a segment is detectable, not only editing it.

| Kind | Source event | Notable fields |
| --- | --- | --- |
| `session.start`, `session.end` | session lifecycle | version, surface, mode, end reason |
| `prompt.submit`, `prompt.drop` | `prompt.submit` | origin kind, text payload |
| `turn.start`, `turn.complete` | turn lifecycle | turnId, agentId, reason, durationMs, usage, answer payload |
| `tool.intent` (enforce mode only), `tool.call` | `tool.call` | tool, id, agentId, input payload, outcome (`ok`, `error`, `denied`), deny reason, `isCheck`, ms, output digest; `origin` names the mod when a mod made the call through `$.tool.call` |
| `agent.spawn` | `agent.spawn` | subagent type, requested and resolved model, agentId, background, fork, prompt payload; `origin` as above |
| `op.*` | other mods' `$` calls: `fs.write`, `process.run`, `process.spawn` (a `start` entry, then an `end` entry saying `ended`, `closed-early` or `threw`), `http.fetch`, `env.set`, `model.complete`, `model.fork`, `mcp.call`, `tool.register`, `agent.register`, `session.authorize` | the calling mod as `origin`, a summary of the call, deny |
| `op.config.set` | any `/config` change, by the person or a mod | key, and for this mod's own keys the old and new value |
| `session.send` | messages sent to other sessions | recipient, digest of the text |
| `supervisor.verdict`, `supervisor.invalid`, `supervisor.error` | the completion supervisor | verdict, whether the deterministic floor overrode it, fork usage |
| `ledger.reanchor` | opening a chain whose stored head disagrees with the segments on disk | the reasons (`head-missing`, `head-behind`, `head-mismatch`, `truncated`, `segments-missing`, `damaged-tail`), the stored head, the disk tail |
| `ledger.verify` | `/audit verify` | result and problems |

A payload is `{ digest, bytes, excerpt?, isRedacted? }`. The digest is an HMAC-SHA256 (RFC 2104) of the original text under a random per-machine key that the mod keeps in its own store, never in the ledger. Equal payloads therefore match across this machine's ledgers, while a reader holding only the ledger cannot test a guessed secret against any digest. Digests do not match across machines.

Under `capture: excerpt` the mod also keeps a 500-character excerpt, masked before encoding. Every string leaf passes through the redaction patterns (over a bounded window, so long inputs stay fast), and the whole value of any key that names a secret becomes `[REDACTED]`. A name names a secret when one of its words, split on `_ . -` and camelCase, is `password`, `passwd`, `pass`, `secret`, `token`, `credential`, `authorization` or `cookie`, or its joined words contain `apikey`, `accesskey`, `privatekey`, `secretkey`, `clientsecret`, `authtoken` or `sessionkey`; so `SMTP_PASS` and `DJANGO_SECRET_KEY` are masked while `max_tokens`, `passed` and `PWD` are not. The patterns cover `NAME=value`, `name: value`, `"name":"value"` and shell-escaped `\"name\":\"value\"`, `--password value` flags, URL userinfo, `curl`/`wget -u` and `--user=`, `mysql -p…`, `redis-cli -a`, `Bearer` tokens, PEM private keys, and the `sk-`, `sk_live_`/`rk_test_`, `gh?_`, `AKIA` and `xox?-` key formats. Redaction is pattern-based and best effort; choose `digest` where no excerpt may ever hold a secret. A successful tool's output is kept as a digest alone; a failed one keeps an excerpt, since the error is the evidence. Environment values, HTTP headers, `fs.write` contents, and HTTP paths and query strings (which can carry webhook and bot tokens) are never recorded in the clear: an `op.http.fetch` entry keeps the URL's origin and a digest of the rest.

Segments live at `<ledgerDir>/<session id>/000001.jsonl` and roll over at about 1 MB, under the 4 MiB limit of `$.fs.read`. The chain follows the live session id, so `/clear` and `/resume` continue in the right session's directory. Every write runs through one queue. `/audit verify` and `tail` take the head once the queue drains (from memory when this load wrote it) and read the segments outside the queue, cutting any entry appended after that head, so they see a consistent snapshot without holding the queue across a call another mod may hook. Records of other mods' capability calls are queued without blocking the call they describe, so a mod that hooks the ledger's own reads or writes cannot wedge it.

The segments on disk, not the store, are where a chain continues. When the mod opens a session's chain, it takes the last intact entry on disk; if the stored head disagrees with it, or is missing, it seals a `ledger.reanchor` entry recording both before anything else. It never writes over an existing segment, and it never appends after a damaged line: a damaged tail sends the chain on into a fresh segment. A missing or lagging head (`head-missing`, `head-behind`) is only bookkeeping. A `truncated`, `head-mismatch`, `segments-missing` or `damaged-tail` reanchor is tamper evidence: once sealed into the chain, it fails every later `/audit verify`, so reopening a damaged ledger can never launder it. A head that fails to anchor after its entry landed on disk counts as a write failure (and, in `enforce` mode, refuses the tool call); the next write retries it. The ledger directory defaults to `.claude/audit` under the project root; add it to `.gitignore` unless the team intends to commit it.

## The completion supervisor

When a main-loop turn ends with an answer that claims completion (`done`, `fixed`, `tests pass`, `ready for review` and similar), the mod forks the session once with `$.model.fork`. The fork reuses the main thread's prompt cache, so its marginal cost is the auditor's instruction and the reply. The fork receives the answer and the turn's tool calls from the ledger, each check command (`pytest`, `tsc`, `ruff`, `claude plugin validate` and peers) marked, and a deterministic flag `claim_without_check`, which is true when the answer claims completion and no check ran and passed this turn. It must reply with one JSON object:

```json
{"state":"verified|unverified|partial|blocked|no-claim","claims":[],"checks":[{"name":"","result":"pass|fail|not-run"}],"open_items":[],"confidence":0.0,"next_action":""}
```

The answer and the call summaries reach the fork as JSON string literals, so model output cannot add lines to the prompt, close a fence, or forge a check row. The ledger also sets a floor: whenever no check passed this turn, a `verified` reply is recorded as `unverified` with `isOverridden: true`, and the band says `[floor applied]`. A check is a command whose executable position runs a test, lint, type or validation tool (after `cd`, `&&`, pipes and leading environment assignments); a runner named anywhere else, as in `echo "npm test"` or `grep pytest`, is not a check. A passing check run by a subagent counts only for the turn that spawned that subagent; a call another mod made through `$.tool.call` never counts. When several verdicts are in flight, the band and `/audit status` keep the newest turn's review, and every verdict still goes into the ledger.

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
| `mode` | `observe`, `enforce` | `observe` | `observe` records after each tool call and never blocks one. `enforce` writes a `tool.intent` entry before the tool runs and refuses the call when that write fails or the hook fails before it, so no tool runs unrecorded. It also refuses any other mod's attempt to change this mod's settings (only the person may), and records the attempt. |
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

The tests drive the real hook chain under the engine's test kit, with an in-memory filesystem, store, clock and model fork beneath the mod. They cover the chain proof and edit detection; recovery with no stored head, with a damaged tail, and with a head that failed to anchor; the chain following a resumed session id; tamper evidence that survives a reopen; `/audit verify` beside concurrent appends and beside a mod that writes on every read; enforce-mode refusal of tool calls and of another mod's settings change; observe-mode fail-open; supervisor verdicts, the floor (also under `supervise: always`), subagent evidence bound to its spawning turn, forged check commands, rejected replies and stale verdicts; `claims`-mode gating; attribution of `http.fetch` and `process.spawn` to the calling mod, including a spawn its reader abandons; enforce-mode refusal when a head cannot anchor; and the band on the terminal and desktop surfaces. The pure core (`hooks/ledger.ts`) has its own tests for canonical encoding, truncation and deletion detection, seventeen secret spellings and the ordinary text that must survive, linear-time redaction, HMAC-SHA256 against the RFC 4231 vector, keyed digest semantics, check detection, prompt injection, the floor, and segment tails.

## Limits

The ledger is tamper-evident, not tamper-proof. The mod runs with the user's authority, and anyone with that authority can rewrite both the segments and the store head together. Copy segments and heads somewhere the session cannot write when the record must survive a hostile user. `$.fs.write` is not atomic, so a crash mid-write can leave a damaged segment; `/audit verify` reports it as a break rather than passing over it. Observational hooks fail open by design: if the ledger cannot write in `observe` mode, the action proceeds and the failure shows on the status line, in the band, and in `/audit status`. Use `enforce` when an unrecorded tool call is unacceptable.
