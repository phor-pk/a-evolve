import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { AuditHealth, AuditMeter, AuditReview } from '../types'
import {
  GENESIS,
  SCHEMA,
  SEGMENT_BYTES,
  SEGMENT_NAME,
  byteLength,
  canonical,
  claimsCompletion,
  looksLikeCheck,
  parseVerdict,
  payload,
  seal,
  segmentName,
  supervisorPrompt,
  verifyChain,
} from './ledger'
import type { CallNote, Capture, Head, SupervisorSnapshot } from './ledger'

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

type Cursor = { session: string; dir: string; seq: number; hash: string; segment: number; text: string }

type Turn = { id: string; calls: CallNote[]; subagentCalls: number }

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

const toolInput = (e: object): Record<string, unknown> => {
  const { tool, tool_use_id, consent, agentId, requestMeta, ...rest } = e as Record<string, unknown>
  void tool, tool_use_id, consent, agentId, requestMeta
  return rest
}

const HEADS_KEPT = 200

type Config = { mode: Mode; supervise: Supervise; capture: Capture; ledgerDir: string }

let config: Config = { mode: 'observe', supervise: 'claims', capture: 'excerpt', ledgerDir: '.claude/audit' }

let cursor: Cursor | null = null
let queue: Promise<unknown> = Promise.resolve()
let turn: Turn | null = null

async function open($: EngineInterface): Promise<Cursor> {
  const session = await $.session.id()
  const base = isAbsolute(config.ledgerDir) ? config.ledgerDir : `${await $.session.root()}/${config.ledgerDir}`
  const dir = `${base.replace(/[\\/]+$/, '')}/${session}`
  const head = await $.store.get(headKey(session))
  if (!isHead(head)) {
    const keys = (await $.store.keys()).filter(key => key.startsWith('head:'))
    for (const stale of keys.slice(0, Math.max(0, keys.length - HEADS_KEPT + 1))) {
      await $.store.delete(stale)
    }
    return { session, dir, seq: 0, hash: GENESIS, segment: 1, text: '' }
  }
  const path = `${dir}/${segmentName(head.segment)}`
  const text = (await $.fs.exists(path)) ? await $.fs.read(path) : ''
  return { session, dir, seq: head.seq, hash: head.hash, segment: head.segment, text }
}

async function write($: EngineInterface, kind: string, data: unknown, origin?: string): Promise<number> {
  const at = cursor ?? (await open($))
  cursor = at
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
  await $.fs.write(`${at.dir}/${segmentName(segment)}`, text)
  cursor = { ...at, seq: entry.seq, hash: entry.hash, segment, text }
  await $.store.set(headKey(at.session), { seq: entry.seq, hash: entry.hash, segment })
  return entry.seq
}

// Appends run strictly one after another, in the order hooks asked.
function append($: EngineInterface, kind: string, data: unknown, origin?: string): Promise<number> {
  const run = queue.then(() => write($, kind, data, origin))
  queue = run.catch(() => undefined)
  return run.then(
    async seq => {
      await update($, health, now => ({ ...now, entries: now.entries + 1 }))
      return seq
    },
    async (error: unknown) => {
      cursor = null
      const message = errorText(error)
      await update($, health, now => ({ entries: now.entries, failures: now.failures + 1, lastError: message }))
      $.ui.status(`audit-ledger: ledger write failing: ${message.slice(0, 80)}`)
      throw error
    },
  )
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
    checksRun: snap.calls.filter(call => call.isCheck).length,
    checksFailed: snap.calls.filter(call => call.isCheck && call.outcome !== 'ok').length,
  }
  await update($, isDismissed, () => false)
  await update($, review, () => base)
  const result = await $.model.fork({ prompt: supervisorPrompt(snap) })
  if ('usage' in result) {
    const usage = result.usage
    await update($, meter, (now: AuditMeter) => ({
      forks: now.forks + 1,
      inputTokens: now.inputTokens + usage.input_tokens,
      outputTokens: now.outputTokens + usage.output_tokens,
      cacheReadTokens: now.cacheReadTokens + usage.cache_read_input_tokens,
      cacheCreationTokens: now.cacheCreationTokens + usage.cache_creation_input_tokens,
    }))
  }
  const usage = 'usage' in result ? result.usage : null
  if (!result.isAnswered) {
    await update($, review, (): AuditReview => ({ ...base, status: 'error', reason: result.reason }))
    await record($, 'supervisor.error', { turnId: snap.turnId, reason: result.reason, usage })
    $.ui.toast(`audit-ledger: supervisor did not answer (${result.reason})`)
    return
  }
  const parsed = parseVerdict(result.text)
  if ('error' in parsed) {
    await update($, review, (): AuditReview => ({ ...base, status: 'invalid', reason: parsed.error }))
    await record($, 'supervisor.invalid', {
      turnId: snap.turnId,
      reason: parsed.error,
      reply: await payload(result.text, config.capture),
      usage,
    })
    $.ui.toast(`audit-ledger: supervisor reply rejected: ${parsed.error}`)
    return
  }
  await update($, review, (): AuditReview => ({ ...base, status: 'done', verdict: parsed.verdict }))
  await record($, 'supervisor.verdict', {
    turnId: snap.turnId,
    verdict: parsed.verdict,
    claimWithoutCheck: snap.claimWithoutCheck,
    usage,
  })
  if (parsed.verdict.state === 'unverified') {
    $.ui.toast(`audit-ledger: completion claim UNVERIFIED. ${parsed.verdict.nextAction}`)
  }
}

async function status($: EngineInterface): Promise<string> {
  await queue
  const now = await read($, health)
  const spent = await read($, meter)
  const last = await read($, review)
  const at = cursor
  const lines = [
    `audit-ledger: ${config.mode} mode, supervisor ${config.supervise}, capture ${config.capture}`,
    at === null
      ? 'ledger: nothing written yet this load'
      : `ledger: ${at.dir}  seq ${at.seq}  head ${at.hash.slice(0, 12)}  segment ${segmentName(at.segment)}`,
    `entries this session: ${now.entries}  write failures: ${now.failures}${now.lastError === null ? '' : `  last error: ${now.lastError}`}`,
    `supervisor: ${spent.forks} forks  input ${spent.inputTokens}  output ${spent.outputTokens}  cache read ${spent.cacheReadTokens}  cache write ${spent.cacheCreationTokens}`,
    last === null
      ? 'last review: none'
      : `last review: turn ${last.turnId} ${last.status}${last.verdict === null ? '' : ` ${last.verdict.state.toUpperCase()} (${last.verdict.confidence})`}${last.reason === null ? '' : ` ${last.reason}`}`,
  ]
  return lines.join('\n')
}

async function readSegments($: EngineInterface, dir: string): Promise<string[]> {
  if (!(await $.fs.exists(dir))) return []
  const names = (await $.fs.list(dir))
    .filter(entry => entry.kind === 'file' && SEGMENT_NAME.test(entry.name))
    .map(entry => entry.name)
    .sort()
  const lines: string[] = []
  for (const name of names) {
    lines.push(...(await $.fs.read(`${dir}/${name}`)).split('\n'))
  }
  return lines
}

async function verify($: EngineInterface): Promise<string> {
  await queue
  const at = cursor ?? (await open($))
  cursor = at
  const stored = await $.store.get(headKey(at.session))
  const head = isHead(stored) ? stored : null
  const report = await verifyChain(await readSegments($, at.dir), head)
  await record($, 'ledger.verify', {
    isIntact: report.isIntact,
    entries: report.entries,
    lastSeq: report.lastSeq,
    problems: report.problems,
  })
  return report.isIntact
    ? `PASS: ${report.entries} entries chained from genesis to head ${report.lastHash.slice(0, 12)} (seq ${report.lastSeq}) in ${at.dir}`
    : `FAIL: ${report.problems.join('; ')} (${report.entries} entries verified before the first break, in ${at.dir})`
}

async function tail($: EngineInterface, count: number): Promise<string> {
  await queue
  const at = cursor ?? (await open($))
  cursor = at
  const lines = (await readSegments($, at.dir)).filter(line => line.trim() !== '').slice(-count)
  if (lines.length === 0) return 'The ledger is empty.'
  return lines
    .map(line => {
      try {
        const entry = JSON.parse(line) as { seq: number; kind: string; origin?: string; data: unknown }
        const data = canonical(entry.data)
        return `#${entry.seq} ${entry.kind}${entry.origin === undefined ? '' : ` <${entry.origin}>`} ${data.length > 160 ? `${data.slice(0, 160)}…` : data}`
      } catch {
        return `(unparseable line) ${line.slice(0, 80)}`
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

  on('session.end', async ($, e, next) => {
    await record($, 'session.end', { reason: e.reason, sessionId: e.sessionId })
    if (e.reason === 'clear') {
      cursor = null
      turn = null
    }
    return next(e)
  })

  on('prompt.submit', async ($, e, next) => {
    const result = await next(e)
    if (result.drop !== undefined) {
      await record($, 'prompt.drop', { origin: e.origin.kind, reason: result.drop })
    } else {
      await record($, 'prompt.submit', { origin: e.origin.kind, text: await payload(result.text, config.capture) })
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
    const started = await $.clock.now()
    if (config.mode === 'enforce') {
      await append($, 'tool.intent', {
        tool,
        id: e.tool_use_id,
        agentId: e.agentId,
        input: await payload(input, config.capture),
      })
    }
    const result = await next(e)
    const outcome = result.deny !== undefined ? 'denied' : result.isError === true ? 'error' : 'ok'
    const command = tool === 'Bash' && typeof input.command === 'string' ? input.command : ''
    const isCheck = command !== '' && looksLikeCheck(command)
    await record($, 'tool.call', {
      tool,
      id: e.tool_use_id,
      agentId: e.agentId,
      input: await payload(input, config.capture),
      outcome,
      deny: result.deny,
      isCheck,
      ms: (await $.clock.now()) - started,
      output: typeof result.text === 'string' ? await payload(result.text, outcome === 'ok' ? 'digest' : config.capture) : undefined,
    })
    if (turn !== null) {
      if (e.agentId === undefined) {
        const summary = command !== '' ? command : canonical(input)
        turn.calls.push({ tool, outcome, isCheck, summary: summary.length > 160 ? `${summary.slice(0, 160)}…` : summary })
      } else {
        turn.subagentCalls += 1
      }
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
    await record($, 'agent.spawn', {
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
    })
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
          await update($, review, (now): AuditReview | null => (now === null ? now : { ...now, status: 'error', reason: message }))
          $.ui.toast(`audit-ledger: supervisor failed: ${message.slice(0, 120)}`)
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

  on('http.fetch', async ($, e, next) => {
    if (next.origin.plugin === $.plugin.name) return next(e)
    const result = await next(e)
    const url = URL.canParse(e.url) ? new URL(e.url) : null
    await record(
      $,
      'op.http.fetch',
      {
        method: e.init?.method ?? 'GET',
        url: url === null ? '(unparseable)' : `${url.origin}${url.pathname}`,
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
