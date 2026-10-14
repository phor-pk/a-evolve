import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { AuditHealth, AuditMeter, AuditReview } from '../types'
import {
  GENESIS,
  SCHEMA,
  SEGMENT_BYTES,
  SEGMENT_NAME,
  applyFloor,
  byteLength,
  canonical,
  claimsCompletion,
  looksLikeCheck,
  parseVerdict,
  payload,
  seal,
  segmentName,
  supervisorPrompt,
  tailOf,
  verifyChain,
} from './ledger'
import type { CallNote, Capture, ChainReport, Head, SupervisorSnapshot } from './ledger'

const review = atom({ plugin: 'audit-ledger', key: 'review' } as const, null)
const isDismissed = atom({ plugin: 'audit-ledger', key: 'isDismissed' } as const, false)
const meter = atom({ plugin: 'audit-ledger', key: 'meter' } as const, {
  forks: 0,
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheCreationTokens: 0,
})
const health = atom({ plugin: 'audit-ledger', key: 'health' } as const, {
  entries: 0,
  failures: 0,
  lastError: null,
})

type Mode = 'observe' | 'enforce'
type Supervise = 'claims' | 'always' | 'off'
type Config = { mode: Mode; supervise: Supervise; capture: Capture; ledgerDir: string }

type Cursor = { session: string; dir: string; seq: number; hash: string; segment: number; text: string }

type Reanchor = {
  reasons: string[]
  head: Head | null
  disk: { seq: number; hash: string; segment: number }
}

type Turn = { id: string; calls: CallNote[]; subagentCalls: number }

const HEADS_KEPT = 5000

const pick = <T extends string>(value: unknown, allowed: readonly T[], fallback: T): T =>
  allowed.find(one => one === value) ?? fallback

const isAbsolute = (path: string): boolean => path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path)

const headKey = (session: string): string => `head:${session}`

const isHead = (value: unknown): value is Head =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as Head).seq === 'number' &&
  typeof (value as Head).hash === 'string' &&
  typeof (value as Head).segment === 'number'

const errorText = (error: unknown): string => (error instanceof Error ? error.message : String(error))

const clip = (text: string, limit = 160): string => (text.length > limit ? `${text.slice(0, limit)}…` : text)

const toolInput = (e: object): Record<string, unknown> => {
  const { tool, tool_use_id, consent, agentId, requestMeta, ...rest } = e as Record<string, unknown>
  void tool, tool_use_id, consent, agentId, requestMeta
  return rest
}

let config: Config = { mode: 'observe', supervise: 'claims', capture: 'excerpt', ledgerDir: '.claude/audit' }
let cursor: Cursor | null = null
let queue: Promise<unknown> = Promise.resolve()
let turn: Turn | null = null

// Every ledger read and write runs here, one at a time, in the order asked.
function exclusive<T>(task: () => Promise<T>): Promise<T> {
  const run = queue.then(task)
  queue = run.catch(() => undefined)
  return run
}

async function dirOf($: EngineInterface, session: string): Promise<string> {
  const base = isAbsolute(config.ledgerDir) ? config.ledgerDir : `${await $.session.root()}/${config.ledgerDir}`
  return `${base.replace(/[\\/]+$/, '')}/${session}`
}

async function listSegments($: EngineInterface, dir: string): Promise<number[]> {
  if (!(await $.fs.exists(dir))) return []
  return (await $.fs.list(dir))
    .filter(entry => entry.kind === 'file' && SEGMENT_NAME.test(entry.name))
    .map(entry => Number.parseInt(entry.name, 10))
    .sort((a, b) => a - b)
}

// Opens the session's chain from the segments on disk, never from the store
// alone: the last intact entry on disk is where the chain continues. A head
// that disagrees with it is not trusted and not hidden; the caller seals the
// disagreement into the chain as a ledger.reanchor entry.
async function open($: EngineInterface, session: string): Promise<{ at: Cursor; notice: Reanchor | null }> {
  const dir = await dirOf($, session)
  const stored = await $.store.get(headKey(session))
  const head = isHead(stored) ? stored : null
  if (head === null) {
    const heads = (await $.store.keys()).filter(key => key.startsWith('head:'))
    for (const stale of heads.slice(0, Math.max(0, heads.length - HEADS_KEPT + 1))) {
      await $.store.delete(stale)
    }
  }
  const segments = await listSegments($, dir)
  const highest = segments.at(-1)
  if (highest === undefined) {
    const at = { session, dir, seq: 0, hash: GENESIS, segment: 1, text: '' }
    return { at, notice: head === null ? null : { reasons: ['segments-missing'], head, disk: { seq: 0, hash: GENESIS, segment: 0 } } }
  }
  const text = await $.fs.read(`${dir}/${segmentName(highest)}`)
  const top = tailOf(text)
  let last = top.last
  for (let index = segments.length - 2; last === null && index >= 0; index -= 1) {
    last = tailOf(await $.fs.read(`${dir}/${segmentName(segments[index] ?? 0)}`)).last
  }
  const seq = last?.seq ?? 0
  const hash = last?.hash ?? GENESIS
  // Never append after damage: continue the chain in a fresh segment.
  const isFresh = top.isDamaged || top.last === null
  const at = { session, dir, seq, hash, segment: isFresh ? highest + 1 : highest, text: isFresh ? '' : text }
  const reasons: string[] = []
  if (head === null) reasons.push('head-missing')
  else if (head.seq > seq) reasons.push('truncated')
  else if (head.seq < seq) reasons.push('head-behind')
  else if (head.hash !== hash) reasons.push('head-mismatch')
  if (top.isDamaged) reasons.push('damaged-tail')
  return { at, notice: reasons.length === 0 ? null : { reasons, head, disk: { seq, hash, segment: highest } } }
}

async function put($: EngineInterface, at: Cursor, kind: string, data: unknown, origin?: string): Promise<Cursor> {
  const entry = await seal({
    v: SCHEMA,
    seq: at.seq + 1,
    ts: await $.clock.now(),
    session: at.session,
    kind,
    origin,
    data,
    prev: at.hash,
  })
  const line = `${canonical(entry)}\n`
  const isFull = at.text !== '' && byteLength(at.text) + byteLength(line) > SEGMENT_BYTES
  const segment = isFull ? at.segment + 1 : at.segment
  const text = (isFull ? '' : at.text) + line
  try {
    await $.fs.write(`${at.dir}/${segmentName(segment)}`, text)
  } catch (error) {
    // The write may have landed in part: reopen from disk next time.
    cursor = null
    throw error
  }
  const next = { ...at, seq: entry.seq, hash: entry.hash, segment, text }
  cursor = next
  // The entry is durable on disk; a head that fails to anchor is reconciled
  // (and sealed as head-behind) by the next open.
  try {
    await $.store.set(headKey(at.session), { seq: entry.seq, hash: entry.hash, segment })
  } catch (error) {
    $.ui.status(`audit-ledger: head anchor failing: ${clip(errorText(error), 80)}`)
  }
  return next
}

async function write($: EngineInterface, kind: string, data: unknown, origin?: string): Promise<number> {
  const session = await $.session.id()
  let at = cursor
  if (at === null || at.session !== session) {
    const opened = await open($, session)
    at = opened.at
    cursor = at
    if (opened.notice !== null) at = await put($, at, 'ledger.reanchor', opened.notice)
  }
  return (await put($, at, kind, data, origin)).seq
}

async function append($: EngineInterface, kind: string, data: unknown, origin?: string): Promise<number> {
  try {
    const seq = await exclusive(() => write($, kind, data, origin))
    await update($, health, now => ({ ...now, entries: now.entries + 1 }))
    return seq
  } catch (error) {
    const message = errorText(error)
    await update($, health, now => ({ entries: now.entries, failures: now.failures + 1, lastError: message }))
    $.ui.status(`audit-ledger: ledger write failing: ${clip(message, 80)}`)
    throw error
  }
}

// Observational appends never break the action they describe.
async function record($: EngineInterface, kind: string, data: unknown, origin?: string): Promise<void> {
  try {
    await append($, kind, data, origin)
  } catch {
    // append already raised the failure on the status line and in health
  }
}

async function superviseTurn($: EngineInterface, snap: SupervisorSnapshot): Promise<void> {
  const base: AuditReview = {
    turnId: snap.turnId,
    status: 'pending',
    verdict: null,
    reason: null,
    claimWithoutCheck: snap.claimWithoutCheck,
    isOverridden: false,
    checksRun: snap.calls.filter(call => call.isCheck).length,
    checksFailed: snap.calls.filter(call => call.isCheck && call.outcome !== 'ok').length,
  }
  await update($, isDismissed, () => false)
  await update($, review, () => base)
  const result = await $.model.fork({ prompt: supervisorPrompt(snap) })
  const usage = 'usage' in result ? result.usage : null
  if (usage !== null) {
    await update($, meter, (now: AuditMeter) => ({
      forks: now.forks + 1,
      inputTokens: now.inputTokens + usage.input_tokens,
      outputTokens: now.outputTokens + usage.output_tokens,
      cacheReadTokens: now.cacheReadTokens + usage.cache_read_input_tokens,
      cacheCreationTokens: now.cacheCreationTokens + usage.cache_creation_input_tokens,
    }))
  }
  // A later turn's review owns the band; this one only writes the ledger.
  const isCurrent = (await read($, review))?.turnId === snap.turnId
  const settle = (change: AuditReview): Promise<AuditReview | null> =>
    update($, review, (now): AuditReview | null => (now !== null && now.turnId === snap.turnId ? change : now))
  if (!result.isAnswered) {
    await settle({ ...base, status: 'error', reason: result.reason })
    await record($, 'supervisor.error', { turnId: snap.turnId, reason: result.reason, usage })
    if (isCurrent) $.ui.toast(`audit-ledger: supervisor did not answer (${result.reason})`)
    return
  }
  const parsed = parseVerdict(result.text)
  if ('error' in parsed) {
    await settle({ ...base, status: 'invalid', reason: parsed.error })
    await record($, 'supervisor.invalid', {
      turnId: snap.turnId,
      reason: parsed.error,
      reply: await payload(result.text, config.capture),
      usage,
    })
    if (isCurrent) $.ui.toast(`audit-ledger: supervisor reply rejected: ${parsed.error}`)
    return
  }
  const { verdict, isOverridden } = applyFloor(parsed.verdict, snap.claimWithoutCheck)
  await settle({ ...base, status: 'done', verdict, isOverridden })
  await record($, 'supervisor.verdict', {
    turnId: snap.turnId,
    verdict,
    claimWithoutCheck: snap.claimWithoutCheck,
    isOverridden,
    usage,
  })
  if (isCurrent && verdict.state === 'unverified') {
    $.ui.toast(`audit-ledger: completion claim UNVERIFIED. ${verdict.nextAction}`)
  }
}

async function status($: EngineInterface): Promise<string> {
  await queue
  const now = await read($, health)
  const spent = await read($, meter)
  const last = await read($, review)
  const at = cursor
  return [
    `audit-ledger: ${config.mode} mode, supervisor ${config.supervise}, capture ${config.capture}`,
    at === null
      ? 'ledger: nothing written yet this load'
      : `ledger: ${at.dir}  seq ${at.seq}  head ${at.hash.slice(0, 12)}  segment ${segmentName(at.segment)}`,
    `entries this session: ${now.entries}  write failures: ${now.failures}${now.lastError === null ? '' : `  last error: ${now.lastError}`}`,
    `supervisor: ${spent.forks} forks  input ${spent.inputTokens}  output ${spent.outputTokens}  cache read ${spent.cacheReadTokens}  cache write ${spent.cacheCreationTokens}`,
    last === null
      ? 'last review: none'
      : `last review: turn ${last.turnId} ${last.status}${last.verdict === null ? '' : ` ${last.verdict.state.toUpperCase()} (${last.verdict.confidence})`}${last.isOverridden ? ' floor applied' : ''}${last.reason === null ? '' : ` ${last.reason}`}`,
  ].join('\n')
}

async function readSegments($: EngineInterface, dir: string): Promise<string[]> {
  const lines: string[] = []
  for (const segment of await listSegments($, dir)) {
    lines.push(...(await $.fs.read(`${dir}/${segmentName(segment)}`)).split('\n'))
  }
  return lines
}

// A consistent snapshot: no append can land between reading the head and
// reading the segments.
async function snapshot($: EngineInterface): Promise<{ dir: string; head: Head | null; lines: string[] }> {
  const session = await $.session.id()
  const dir = await dirOf($, session)
  const stored = await $.store.get(headKey(session))
  return { dir, head: isHead(stored) ? stored : null, lines: await readSegments($, dir) }
}

async function verify($: EngineInterface): Promise<string> {
  const { dir, report } = await exclusive(async (): Promise<{ dir: string; report: ChainReport }> => {
    const snap = await snapshot($)
    return { dir: snap.dir, report: await verifyChain(snap.lines, snap.head) }
  })
  await record($, 'ledger.verify', {
    isIntact: report.isIntact,
    entries: report.entries,
    lastSeq: report.lastSeq,
    problems: report.problems,
  })
  return report.isIntact
    ? `PASS: ${report.entries} entries chained from genesis to head ${report.lastHash.slice(0, 12)} (seq ${report.lastSeq}) in ${dir}`
    : `FAIL: ${report.problems.join('; ')} (${report.entries} entries verified before the first break, in ${dir})`
}

async function tail($: EngineInterface, count: number): Promise<string> {
  const { lines } = await exclusive(() => snapshot($))
  const kept = lines.filter(line => line.trim() !== '').slice(-count)
  if (kept.length === 0) return 'The ledger is empty.'
  return kept
    .map(line => {
      try {
        const entry = JSON.parse(line) as { seq: number; kind: string; origin?: string; data: unknown }
        return `#${entry.seq} ${entry.kind}${entry.origin === undefined ? '' : ` <${entry.origin}>`} ${clip(canonical(entry.data))}`
      } catch {
        return `(unparseable line) ${clip(line, 80)}`
      }
    })
    .join('\n')
}

export const register: Register = (on, options) => {
  config = {
    mode: pick<Mode>(options.mode, ['observe', 'enforce'], 'observe'),
    supervise: pick<Supervise>(options.supervise, ['claims', 'always', 'off'], 'claims'),
    capture: pick<Capture>(options.capture, ['excerpt', 'digest'], 'excerpt'),
    ledgerDir: typeof options.ledgerDir === 'string' && options.ledgerDir !== '' ? options.ledgerDir : '.claude/audit',
  }
  cursor = null
  queue = Promise.resolve()
  turn = null

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'audit',
      description: 'Audit ledger: status, verify (prove the hash chain), tail [n]',
      argumentHint: 'status | verify | tail [n]',
      immediate: true,
    })
    const version = await $.session.version()
    await record($, 'session.start', {
      cwd: e.cwd,
      surface: e.surface,
      isInteractive: e.isInteractive,
      version: version.version,
      mode: config.mode,
      supervise: config.supervise,
    })
    return next(e)
  })

  // The chain follows the live session id, so /clear and /resume need no
  // cursor reset here; only the turn in progress is dropped.
  on('session.end', async ($, e, next) => {
    await record($, 'session.end', { reason: e.reason, sessionId: e.sessionId })
    if (e.reason === 'clear' || e.reason === 'resume') turn = null
    return next(e)
  })

  on('prompt.submit', async ($, e, next) => {
    const result = await next(e)
    if (result.drop !== undefined) {
      await record($, 'prompt.drop', { origin: e.origin?.kind, reason: result.drop })
    } else {
      await record($, 'prompt.submit', { origin: e.origin?.kind, text: await payload(result.text, config.capture) })
    }
    return result
  })

  on('turn.start', async ($, e, next) => {
    turn = { id: e.turnId, calls: [], subagentCalls: 0 }
    await record($, 'turn.start', { turnId: e.turnId, isContinuation: e.text === '' })
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    const tool = String(e.tool)
    const input = toolInput(e)
    // A call another mod made through $.tool.call is attributed to it and is
    // never evidence for the model's own claims.
    const by = next.origin.plugin === 'engine' ? undefined : next.origin.plugin
    const started = await $.clock.now()
    if (config.mode === 'enforce') {
      await append($, 'tool.intent', { tool, id: e.tool_use_id, agentId: e.agentId, input: await payload(input, config.capture) }, by)
    }
    const result = await next(e)
    const outcome = result.deny !== undefined ? 'denied' : result.isError === true ? 'error' : 'ok'
    const command = tool === 'Bash' && typeof input.command === 'string' ? input.command : ''
    const isCheck = command !== '' && looksLikeCheck(command)
    await record(
      $,
      'tool.call',
      {
        tool,
        id: e.tool_use_id,
        agentId: e.agentId,
        input: await payload(input, config.capture),
        outcome,
        deny: result.deny,
        isCheck,
        ms: (await $.clock.now()) - started,
        output: typeof result.text === 'string' ? await payload(result.text, outcome === 'ok' ? 'digest' : config.capture) : undefined,
      },
      by,
    )
    if (turn !== null && by === undefined) {
      const summary = clip(command !== '' ? command : canonical(input))
      if (e.agentId === undefined) turn.calls.push({ tool, outcome, isCheck, summary })
      else if (isCheck) turn.calls.push({ tool, outcome, isCheck, summary: `[subagent ${e.agentId}] ${summary}` })
      else turn.subagentCalls += 1
    }
    return result
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    if (config.mode === 'enforce') {
      return { deny: `audit-ledger: this call could not be recorded, and enforce mode refuses any call it cannot record (${next.error.kind}).` }
    }
    return next(e)
  })

  on('agent.spawn', async ($, e, next) => {
    const result = await next(e)
    await record(
      $,
      'agent.spawn',
      {
        id: e.tool_use_id,
        subagentType: e.subagentType,
        description: await payload(e.description, config.capture),
        prompt: await payload(e.prompt, config.capture),
        requestedModel: e.model,
        model: result.model,
        agentId: result.agentId,
        parentAgentId: e.parentAgentId,
        background: e.background,
        fork: e.fork,
        deny: result.deny,
      },
      next.origin.plugin === 'engine' ? undefined : next.origin.plugin,
    )
    return result
  })

  on('turn.complete', async ($, e, next) => {
    const result = await next(e)
    const seq = await append($, 'turn.complete', {
      turnId: e.turnId,
      agentId: e.agentId,
      reason: e.reason,
      durationMs: e.durationMs,
      usage: e.usage,
      answer: await payload(e.answer, config.capture),
    }).catch(() => null)
    const ended = turn
    if (e.agentId === undefined) turn = null
    const isMain = e.agentId === undefined && e.reason === 'answer' && e.answer !== ''
    const isClaim = claimsCompletion(e.answer)
    const shouldReview = isMain && (config.supervise === 'always' || (config.supervise === 'claims' && isClaim))
    if (shouldReview) {
      const calls = ended !== null && ended.id === e.turnId ? ended.calls : []
      const snap: SupervisorSnapshot = {
        turnId: e.turnId,
        answer: e.answer,
        calls,
        subagentCalls: ended?.subagentCalls ?? 0,
        claimWithoutCheck: isClaim && !calls.some(call => call.isCheck && call.outcome === 'ok'),
      }
      if (seq !== null) $.ui.log(`audit-ledger: reviewing turn ${e.turnId} (ledger seq ${seq})`, { to: 'debug' })
      $.clock.after(0, () => {
        void superviseTurn($, snap).catch(async (error: unknown) => {
          const message = errorText(error)
          await update($, review, (now): AuditReview | null =>
            now !== null && now.turnId === snap.turnId ? { ...now, status: 'error', reason: message } : now,
          )
          $.ui.toast(`audit-ledger: supervisor failed: ${clip(message, 120)}`)
        })
      })
    }
    return result
  })

  // Capability calls other mods make through $: the seam where one mod is
  // audited by another. The ledger's own calls are passed through unrecorded.
  on('fs.write', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record($, 'op.fs.write', { path: e.path, text: await payload(e.text, 'digest'), deny: result.deny }, next.origin.plugin)
    return result
  })

  on('process.run', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record(
      $,
      'op.process.run',
      { argv: await payload(e.argv.join(' '), config.capture), cwd: e.init?.cwd, exitCode: result.value?.exitCode, deny: result.deny },
      next.origin.plugin,
    )
    return result
  })

  on('process.spawn', async function* ($, e, next) {
    if (next.origin.plugin === $.plugin.name) return yield* next(e)
    const result = yield* next(e)
    await record(
      $,
      'op.process.spawn',
      {
        argv: await payload(e.argv.join(' '), config.capture),
        cwd: e.cwd,
        code: result?.value?.code,
        signal: result?.value?.signal,
        deny: result?.deny,
      },
      next.origin.plugin,
    )
    return result
  })

  // A URL path can carry the credential itself (webhook and bot tokens), so
  // only the origin is kept in the clear.
  on('http.fetch', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    const url = URL.canParse(e.url) ? new URL(e.url) : null
    await record(
      $,
      'op.http.fetch',
      {
        method: e.init?.method ?? 'GET',
        origin: url === null ? '(unparseable)' : url.origin,
        path: await payload(url === null ? e.url : `${url.pathname}${url.search}`, 'digest'),
        status: result.value?.status,
        deny: result.deny,
      },
      next.origin.plugin,
    )
    return result
  })

  on('env.set', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record($, 'op.env.set', { name: e.name, isUnset: e.value === undefined, deny: result.deny }, next.origin.plugin)
    return result
  })

  on('model.complete', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    const value = result.value
    await record(
      $,
      'op.model.complete',
      {
        model: e.model,
        prompt: await payload(e.prompt, 'digest'),
        isAnswered: value?.isAnswered,
        usage: value === undefined ? undefined : value.usage,
        deny: result.deny,
      },
      next.origin.plugin,
    )
    return result
  })

  on('model.fork', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    const value = result.value
    await record(
      $,
      'op.model.fork',
      {
        prompt: await payload(e.prompt, 'digest'),
        isAnswered: value?.isAnswered,
        usage: value !== undefined && 'usage' in value ? value.usage : undefined,
        deny: result.deny,
      },
      next.origin.plugin,
    )
    return result
  })

  on('mcp.call', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record(
      $,
      'op.mcp.call',
      { server: e.server, tool: e.tool, args: await payload(e.args, config.capture), deny: result.deny },
      next.origin.plugin,
    )
    return result
  })

  on('tool.register', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record($, 'op.tool.register', { name: e.name, isDeferred: e.isDeferred, deny: result.deny }, next.origin.plugin)
    return result
  })

  on('agent.register', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record($, 'op.agent.register', { spec: await payload(e, 'digest'), deny: result.deny }, next.origin.plugin)
    return result
  })

  on('session.authorize', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    await record($, 'op.session.authorize', { deny: result.deny }, next.origin.plugin)
    return result
  })

  on('session.send', async ($, e, next) => {
    const result = await next(e)
    await record(
      $,
      'session.send',
      { to: e.to, agentId: e.agentId, text: await payload(e.text, 'digest') },
      next.origin.plugin === 'engine' ? undefined : next.origin.plugin,
    )
    return result
  })

  // A setting change is recorded whoever makes it. In enforce mode another
  // mod may not change this mod's own settings: only the person may. The
  // caller is read from next.origin, which the host stamps and no plugin can
  // write.
  on('config.set', async ($, e, next) => {
    const caller = next.origin.plugin
    const isForeign = caller !== 'engine' && caller !== 'client' && caller !== $.plugin.name
    const by = caller === 'engine' ? undefined : caller
    const isOwn = e.key.includes('audit-ledger')
    const shown = (value: unknown): unknown => (isOwn ? value : undefined)
    if (config.mode === 'enforce' && isOwn && isForeign) {
      const deny = 'audit-ledger: in enforce mode only the person may change audit-ledger settings.'
      await record($, 'op.config.set', { key: e.key, value: shown(e.value), previous: shown(e.previous), deny }, by)
      return { deny }
    }
    const result = await next(e)
    await record($, 'op.config.set', { key: e.key, value: shown(e.value), previous: shown(e.previous), deny: result.deny }, by)
    return result
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    const caller = next.origin.plugin
    const isGuarded = config.mode === 'enforce' && e.key.includes('audit-ledger') && caller !== 'engine' && caller !== 'client'
    return isGuarded ? { deny: 'audit-ledger: its settings guard failed; the change is refused.' } : next(e)
  })

  on('command.run', { command: 'audit' }, async ($, e) => {
    const [verb = 'status', count = ''] = e.args.trim().split(/\s+/).filter(word => word !== '')
    if (verb === 'status') return { text: await status($) }
    if (verb === 'verify') {
      const text = await verify($)
      return { text, exitCode: text.startsWith('PASS') ? 0 : 1 }
    }
    if (verb === 'tail') {
      const n = Number.parseInt(count, 10)
      return { text: await tail($, Number.isFinite(n) && n > 0 ? Math.min(n, 200) : 20) }
    }
    return { text: `Unknown subcommand "${verb}". Use: /audit status | verify | tail [n]`, exitCode: 2 }
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const last = await read($, review)
    const now: AuditHealth = await read($, health)
    const isHidden = await read($, isDismissed)
    const hasFailure = now.failures > 0
    if (e.props.hasSurvey || isHidden || (last === null && !hasFailure)) return next(e)
    const { Box, Button, Text } = $.ui.resolve(e)
    const verdict = last?.verdict ?? null
    const color =
      verdict === null ? undefined : verdict.state === 'verified' ? 'success' : verdict.state === 'unverified' ? 'error' : 'warning'
    const headline =
      last === null
        ? null
        : last.status === 'pending'
          ? `auditing turn ${last.turnId}…`
          : last.status === 'error'
            ? `supervisor did not answer: ${last.reason ?? 'unknown'}`
            : last.status === 'invalid'
              ? `supervisor reply rejected: ${last.reason ?? 'unknown'}`
              : verdict === null
                ? null
                : `${verdict.state.toUpperCase()} (${Math.round(verdict.confidence * 100)}%)  checks ${last.checksRun} run, ${last.checksFailed} failed${verdict.openItems.length > 0 ? `  open: ${verdict.openItems.length}` : ''}`
    return (
      <Box flexDirection="column">
        {headline !== null && (
          <Text color={color}>
            audit: {headline}
            {last?.claimWithoutCheck === true ? '  [claim without a passing check]' : ''}
            {last?.isOverridden === true ? '  [floor applied]' : ''}
          </Text>
        )}
        {verdict !== null && verdict.nextAction !== '' && <Text dimColor>next: {verdict.nextAction}</Text>}
        {hasFailure && (
          <Text color="error">
            audit ledger: {now.failures} write failures; last: {now.lastError ?? 'unknown'}
          </Text>
        )}
        <Button key="dismiss" label="Dismiss" hotkey="d" plain onPress={() => update($, isDismissed, () => true)} />
      </Box>
    )
  })
}
