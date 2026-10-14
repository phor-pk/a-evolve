// Pure core of the audit ledger: canonical encoding, sealing, redaction,
// chain verification and supervisor verdict parsing. Nothing here touches $.

import type { AuditCheck, AuditVerdict, AuditVerdictState } from '../types'

export const SCHEMA = 1
export const GENESIS = '0'.repeat(64)
export const SEGMENT_BYTES = 1_000_000
export const EXCERPT_CHARS = 500
export const SEGMENT_NAME = /^\d{6}\.jsonl$/

export type Capture = 'excerpt' | 'digest'

export type Payload = { digest: string; bytes: number; excerpt?: string }

export type EntryBody = {
  v: number
  seq: number
  ts: number
  session: string
  kind: string
  origin?: string
  data: unknown
  prev: string
}

export type Entry = EntryBody & { hash: string }

export type Head = { seq: number; hash: string; segment: number }

export type ChainReport = {
  isIntact: boolean
  entries: number
  lastSeq: number
  lastHash: string
  problems: string[]
}

const encoder = new TextEncoder()

export const byteLength = (text: string): number => encoder.encode(text).length

export const segmentName = (segment: number): string => `${String(segment).padStart(6, '0')}.jsonl`

// RFC 8785 (JCS) restricted to what the ledger stores: sorted object keys,
// undefined members dropped, JSON.stringify for every scalar.
export const canonical = (value: unknown): string => {
  if (value === null || typeof value !== 'object') {
    return value === undefined ? 'null' : JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map(item => (item === undefined ? 'null' : canonical(item))).join(',')}]`
  }
  const record = value as Record<string, unknown>
  const members = Object.keys(record)
    .filter(key => record[key] !== undefined)
    .sort()
    .map(key => `${JSON.stringify(key)}:${canonical(record[key])}`)
  return `{${members.join(',')}}`
}

export const sha256Hex = async (text: string): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text))
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
}

export const seal = async (body: EntryBody): Promise<Entry> => ({
  ...body,
  hash: await sha256Hex(canonical(body)),
})

const SECRET_PATTERNS: readonly RegExp[] = [
  /\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|authorization)(["']?\s*[:=]\s*["']?)(?:(?:Bearer|Basic|Token)\s+)?[^\s"',;]+/gi,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g,
  /\bsk-[A-Za-z0-9_-]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
]

export const redact = (text: string): string =>
  SECRET_PATTERNS.reduce(
    (out, pattern) =>
      out.replace(pattern, (match, name: unknown, separator: unknown) =>
        typeof name === 'string' && typeof separator === 'string'
          ? `${name}${separator}[REDACTED]`
          : '[REDACTED]',
      ),
    text,
  )

export const payload = async (
  value: unknown,
  capture: Capture,
  limit = EXCERPT_CHARS,
): Promise<Payload> => {
  const text = typeof value === 'string' ? value : canonical(value)
  const base = { digest: await sha256Hex(text), bytes: byteLength(text) }
  if (capture === 'digest') return base
  const clean = redact(text)
  return { ...base, excerpt: clean.length > limit ? `${clean.slice(0, limit)}…` : clean }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const isEntry = (value: unknown): value is Entry =>
  isRecord(value) &&
  typeof value.seq === 'number' &&
  typeof value.hash === 'string' &&
  typeof value.prev === 'string' &&
  typeof value.kind === 'string'

// Walks every line of every segment in order and proves the chain: seq
// contiguous from 1, each prev naming the hash before it, each hash
// recomputed from its body, and the last entry matching the anchored head.
export const verifyChain = async (
  lines: readonly string[],
  head: Head | null,
): Promise<ChainReport> => {
  const problems: string[] = []
  let expectedSeq = 1
  let prev = GENESIS
  let entries = 0
  for (const [index, line] of lines.entries()) {
    if (line.trim() === '') continue
    let parsed: unknown
    try {
      parsed = JSON.parse(line)
    } catch {
      problems.push(`line ${index + 1}: not JSON`)
      break
    }
    if (!isEntry(parsed)) {
      problems.push(`line ${index + 1}: not a ledger entry`)
      break
    }
    const { hash, ...body } = parsed
    if (body.seq !== expectedSeq) problems.push(`seq ${body.seq}: expected seq ${expectedSeq}`)
    if (body.prev !== prev) problems.push(`seq ${body.seq}: prev does not name the entry before it`)
    const recomputed = await sha256Hex(canonical(body))
    if (recomputed !== hash) problems.push(`seq ${body.seq}: hash mismatch (content altered)`)
    if (problems.length > 0) break
    prev = hash
    expectedSeq = body.seq + 1
    entries += 1
  }
  const lastSeq = expectedSeq - 1
  if (problems.length === 0 && head !== null) {
    if (head.seq > lastSeq) problems.push(`head anchors seq ${head.seq} but the ledger ends at seq ${lastSeq} (truncated)`)
    else if (head.seq < lastSeq) problems.push(`ledger runs to seq ${lastSeq} past the anchored head seq ${head.seq} (unanchored tail)`)
    else if (head.hash !== prev) problems.push(`head hash does not match seq ${lastSeq}`)
  }
  if (problems.length === 0 && head === null && entries > 0) {
    problems.push('no anchored head for this session')
  }
  return { isIntact: problems.length === 0, entries, lastSeq, lastHash: prev, problems }
}

// Completion language in an answer: the trigger for supervise: 'claims'.
const CLAIM =
  /\b(done|completed?|finished|fixed|resolved|implemented|shipped|verified|ready (?:to|for) (?:merge|review|ship)|works now|all (?:tests|checks) (?:pass|passed|passing)|tests? (?:pass|passed|passing)|passes|PASS)\b/i

export const claimsCompletion = (answer: string): boolean => CLAIM.test(answer)

const CHECK =
  /\b(pytest|unittest|jest|vitest|mocha|go test|cargo (?:test|check|clippy)|(?:npm|pnpm|yarn|bun)(?: run)? (?:test|lint|check|typecheck)|make (?:test|check|lint)|ruff|eslint|tsc|mypy|pyright|claude plugin (?:validate|test)|ctest|gradle(?:w)? test|mvn test|rspec|phpunit|dotnet test)\b/

export const looksLikeCheck = (command: string): boolean => CHECK.test(command)

export type CallNote = { tool: string; outcome: string; isCheck: boolean; summary: string }

export type SupervisorSnapshot = {
  turnId: string
  answer: string
  calls: readonly CallNote[]
  subagentCalls: number
  claimWithoutCheck: boolean
}

export const supervisorPrompt = (snap: SupervisorSnapshot): string => {
  const calls =
    snap.calls.length === 0
      ? '(none)'
      : snap.calls
          .slice(-40)
          .map(
            (call, index) =>
              `${index + 1}. ${call.tool} ${call.outcome}${call.isCheck ? ' [check]' : ''}: ${call.summary}`,
          )
          .join('\n')
  const answer = snap.answer.length > 4000 ? `${snap.answer.slice(0, 4000)}…` : snap.answer
  return [
    'You are the completion auditor for the turn that just ended. Do not continue the task and do not call tools.',
    'Judge one thing: whether each completion claim in the final answer is backed by a check that actually ran in this session and passed, with its output visible in the transcript.',
    '',
    'FINAL ANSWER (excerpt):',
    '<<<',
    answer,
    '>>>',
    '',
    'TOOL CALLS THIS TURN, from the audit ledger (oldest first; [check] marks a test, lint or validation command):',
    calls,
    `Subagent tool calls this turn: ${snap.subagentCalls}`,
    `Deterministic flag claim_without_check: ${snap.claimWithoutCheck}`,
    '',
    'States: verified = every claim is backed by a passing check; unverified = some claim lacks a passing check; partial = the answer itself reports remaining work; blocked = the answer reports a blocker; no-claim = the answer claims no completion.',
    'Reply with exactly one JSON object and nothing else:',
    '{"state":"verified|unverified|partial|blocked|no-claim","claims":["..."],"checks":[{"name":"...","result":"pass|fail|not-run"}],"open_items":["..."],"confidence":0.0,"next_action":"..."}',
  ].join('\n')
}

const STATES: readonly AuditVerdictState[] = ['verified', 'unverified', 'partial', 'blocked', 'no-claim']
const RESULTS: readonly AuditCheck['result'][] = ['pass', 'fail', 'not-run']

const clip = (text: string, limit = 200): string =>
  text.length > limit ? `${text.slice(0, limit)}…` : text

const strings = (value: unknown): string[] | null =>
  Array.isArray(value) && value.every(item => typeof item === 'string')
    ? value.slice(0, 8).map(item => clip(item))
    : null

export type VerdictParse = { verdict: AuditVerdict } | { error: string }

export const parseVerdict = (text: string): VerdictParse => {
  const start = text.indexOf('{')
  const end = text.lastIndexOf('}')
  if (start === -1 || end <= start) return { error: 'no JSON object in the reply' }
  let raw: unknown
  try {
    raw = JSON.parse(text.slice(start, end + 1))
  } catch {
    return { error: 'reply JSON does not parse' }
  }
  if (!isRecord(raw)) return { error: 'reply is not a JSON object' }
  const state = STATES.find(one => one === raw.state)
  if (state === undefined) return { error: `unknown state ${JSON.stringify(raw.state)}` }
  const claims = strings(raw.claims)
  const openItems = strings(raw.open_items)
  if (claims === null) return { error: 'claims is not a list of strings' }
  if (openItems === null) return { error: 'open_items is not a list of strings' }
  if (!Array.isArray(raw.checks)) return { error: 'checks is not a list' }
  const checks: AuditCheck[] = []
  for (const check of raw.checks.slice(0, 12)) {
    if (!isRecord(check) || typeof check.name !== 'string') return { error: 'a check has no name' }
    const result = RESULTS.find(one => one === check.result)
    if (result === undefined) return { error: `check ${JSON.stringify(check.name)} has an unknown result` }
    checks.push({ name: clip(check.name), result })
  }
  const confidence = raw.confidence
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return { error: 'confidence is not a number in [0, 1]' }
  }
  const nextAction = typeof raw.next_action === 'string' ? clip(raw.next_action) : ''
  return { verdict: { state, claims, checks, openItems, confidence, nextAction } }
}
