import { expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On, RenderElement } from 'claude-code'

import { GENESIS, canonical, seal } from './ledger'

const ROOT = '/proj'
const SESSION = 'sess-1'
const DIR = `${ROOT}/.claude/audit/${SESSION}`
const SEGMENT = `${DIR}/000001.jsonl`

type Files = Map<string, string>
type Clock = ReturnType<typeof mock.clock>

// The sinks a session would draw: status line, toasts and log lines.
const surface = (on: On, said: string[]): void => {
  on('ui.status', ($, e) => {
    if (e.text !== undefined) said.push(e.text)
    return { value: undefined }
  })
  on('ui.toast', ($, e) => {
    said.push(e.text)
    return { value: undefined }
  })
  on('ui.log', ($, e) => {
    said.push(e.text)
    return { value: undefined }
  })
}

// The engine beneath the plugin: an in-memory filesystem, a session, a
// mocked clock, and the bottoms a session would supply for these events.
type World = { session: string; failStoreSetAt?: number; storeSets: number }

type Fork = string | null | ((prompt: string, clock: Clock) => Promise<string>)

const USAGE = { input_tokens: 40, output_tokens: 60, cache_read_input_tokens: 9000, cache_creation_input_tokens: 0 }

const engine = (
  on: On,
  files: Files,
  fork?: Fork,
  said: string[] = [],
  world: World = { session: SESSION, storeSets: 0 },
): Clock => {
  const clock = mock.clock(on, { now: 1_000 })
  // An in-memory store whose set can be made to fail once.
  const store = new Map<string, unknown>()
  on('store.get', ($, e) => ({ value: store.get(e.key) }))
  on('store.keys', () => ({ value: [...store.keys()] }))
  on('store.delete', ($, e) => {
    store.delete(e.key)
    return { value: undefined }
  })
  on('store.set', ($, e) => {
    world.storeSets += 1
    if (world.storeSets === world.failStoreSetAt) return { deny: 'store is unavailable' }
    store.set(e.key, e.value)
    return { value: undefined }
  })
  surface(on, said)
  on('fs.write', ($, e) => {
    files.set(e.path, e.text)
    return { value: undefined }
  })
  on('fs.read', ($, e) => {
    const text = files.get(e.path)
    return text === undefined ? { deny: `ENOENT ${e.path}` } : { value: text }
  })
  on('fs.exists', ($, e) => ({
    value: files.has(e.path) || [...files.keys()].some(path => path.startsWith(`${e.path}/`)),
  }))
  on('fs.list', ($, e) => ({
    value: [...files.keys()]
      .filter(path => path.startsWith(`${e.path}/`) && !path.slice(e.path.length + 1).includes('/'))
      .map(path => ({
        name: path.slice(e.path.length + 1),
        kind: 'file' as const,
        size: files.get(path)?.length ?? 0,
        mtimeMs: 0,
        isLink: false,
      })),
  }))
  on('session.id', () => ({ value: world.session }))
  on('session.root', () => ({ value: ROOT }))
  on('session.version', () => ({ value: { version: '2.1.296' } }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  on('tool.call', () => ({ result: { stdout: 'ok', stderr: '', interrupted: false } }) as never)
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('turn.complete', ($, e) => ({ text: e.answer }))
  on('model.fork', async ($, e) => {
    if (fork === null || fork === undefined) return { value: { isAnswered: false, reason: 'nothing-to-fork' } as const }
    const text = typeof fork === 'string' ? fork : await fork(e.prompt, clock)
    return { value: { isAnswered: true, text, usage: USAGE } as const }
  })
  on('http.fetch', () => ({ value: { status: 200, ok: true, headers: {}, text: '' } }))
  return clock
}

type Row = { seq: number; kind: string; origin?: string; prev: string; hash: string; data: Record<string, unknown> }

const entries = (files: Files, path = SEGMENT): Row[] =>
  (files.get(path) ?? '')
    .split('\n')
    .filter(line => line !== '')
    .map(line => JSON.parse(line))

const audit = async ($: Engine, args: string): Promise<string> =>
  (
    await $.command.run({
      command: 'audit',
      args,
      origin: { kind: 'person' } as never,
      presentation: { isFullscreen: false, columns: 100 },
    })
  ).text ?? ''

const verify = ($: Engine): Promise<string> => audit($, 'verify')

test('a tool call lands in a hash chain that /audit verify proves intact', async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  await $.tool.call({ tool: 'Bash', command: 'pytest -q' })
  await $.tool.call({ tool: 'Bash', command: 'echo API_KEY=sk-0123456789abcdefghij' })
  const kept = entries(files)
  expect(kept.map(entry => entry.kind)).toEqual(['tool.call', 'tool.call'])
  expect(kept[0]?.data.isCheck).toBe(true)
  expect(JSON.stringify(kept[1]?.data)).not.toContain('sk-0123456789abcdefghij')
  expect(await verify($)).toStartWith('PASS: 2 entries')
})

test('an edited ledger line fails /audit verify', async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  await $.tool.call({ tool: 'Bash', command: 'pwd' })
  files.set(SEGMENT, (files.get(SEGMENT) ?? '').replace('"outcome":"ok"', '"outcome":"error"'))
  const text = await verify($)
  expect(text).toStartWith('FAIL:')
  expect(text).toMatch(/hash mismatch/)
})

test('enforce mode refuses a tool call it cannot record', { options: { mode: 'enforce' } }, async ($, on) => {
  let isRun = false
  const said: string[] = []
  mock.clock(on)
  mock.store(on)
  surface(on, said)
  on('session.id', () => ({ value: SESSION }))
  on('session.root', () => ({ value: ROOT }))
  on('fs.exists', () => ({ value: false }))
  on('fs.write', () => ({ deny: 'disk is read-only' }))
  on('tool.call', () => {
    isRun = true
    return { result: { stdout: '', stderr: '', interrupted: false } } as never
  })
  const result = await $.tool.call({ tool: 'Bash', command: 'rm -rf build' })
  expect(isRun).toBe(false)
  expect(result.deny ?? result.text ?? '').toMatch(/could not be recorded/)
})

test('observe mode lets the call run when the ledger cannot write', async ($, on) => {
  let isRun = false
  const said: string[] = []
  mock.clock(on)
  mock.store(on)
  surface(on, said)
  on('session.id', () => ({ value: SESSION }))
  on('session.root', () => ({ value: ROOT }))
  on('fs.exists', () => ({ value: false }))
  on('fs.write', () => ({ deny: 'disk is read-only' }))
  on('tool.call', () => {
    isRun = true
    return { result: { stdout: '', stderr: '', interrupted: false } } as never
  })
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(isRun).toBe(true)
  expect(said.join('\n')).toMatch(/ledger write failing: .*read-only/)
  expect(await audit($, 'status')).toMatch(/write failures: 1 /)
})

const UNVERIFIED =
  '{"state":"unverified","claims":["all tests pass"],"checks":[{"name":"pytest","result":"not-run"}],"open_items":["run pytest"],"confidence":0.9,"next_action":"Run pytest and show the output."}'

// The supervisor runs on a timer after the turn: let it fire, then wait for
// its verdict to land in the ledger.
const settle = async (clock: Clock, files: Files, kind: RegExp): Promise<void> => {
  for (let round = 0; round < 50; round += 1) {
    await clock.settle()
    if (entries(files).some(entry => kind.test(entry.kind))) return
  }
}

test('a completion claim with no passing check is forked to the supervisor and judged', async ($, on) => {
  const files: Files = new Map()
  const said: string[] = []
  const clock = engine(on, files, UNVERIFIED, said)
  await $.turn.start({ text: 'fix the bug', turnId: 't1' })
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  await $.turn.complete({ answer: 'Done. All tests pass.', durationMs: 5, isAborted: false, turnId: 't1', reason: 'answer' })
  await settle(clock, files, /^supervisor\./)
  const verdict = entries(files).find(entry => entry.kind === 'supervisor.verdict')
  expect(verdict?.data.claimWithoutCheck).toBe(true)
  expect(verdict?.data.verdict).toMatchObject({ state: 'unverified', openItems: ['run pytest'] })
  expect(said.join('\n')).toMatch(/completion claim UNVERIFIED/)
  const status = await audit($, 'status')
  expect(status).toMatch(/last review: turn t1 done UNVERIFIED \(0\.9\)/)
  expect(status).toMatch(/supervisor: 1 forks .* cache read 9000/)
  expect(entries(files).map(entry => entry.kind)).toEqual([
    'turn.start',
    'tool.call',
    'turn.complete',
    'supervisor.verdict',
  ])
  expect(await verify($)).toStartWith('PASS')
})

test('an answer that claims nothing is not forked in claims mode', async ($, on) => {
  const files: Files = new Map()
  const clock = engine(on, files, UNVERIFIED)
  await $.turn.start({ text: 'plan it', turnId: 't2' })
  await $.turn.complete({ answer: 'Here is a plan for tomorrow.', durationMs: 5, isAborted: false, turnId: 't2', reason: 'answer' })
  await clock.settle()
  expect(await audit($, 'status')).toMatch(/last review: none/)
  expect(entries(files).map(entry => entry.kind)).toEqual(['turn.start', 'turn.complete'])
})

test('a supervisor reply that is not the contract is rejected loudly', { options: { supervise: 'always' } }, async ($, on) => {
  const files: Files = new Map()
  const clock = engine(on, files, 'Looks fine to me!')
  await $.turn.start({ text: 'go', turnId: 't3' })
  await $.turn.complete({ answer: 'Summary of the change.', durationMs: 5, isAborted: false, turnId: 't3', reason: 'answer' })
  await settle(clock, files, /^supervisor\./)
  const rejected = entries(files).at(-1)
  expect(rejected?.kind).toBe('supervisor.invalid')
  expect(rejected?.data.reason).toBe('no JSON object in the reply')
  expect(await audit($, 'status')).toMatch(/turn t3 invalid no JSON object in the reply/)
})

const FETCHER = {
  name: 'fetcher',
  register: (on: On) => {
    on('session.start', async ($, e, next) => {
      await $.http.fetch('https://api.example.com/v1/items?token=abc123')
      return next(e)
    })
  },
}

test('a capability call another mod makes through $ is recorded with its origin', { plugins: [FETCHER] }, async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  const op = entries(files).find(entry => entry.kind === 'op.http.fetch')
  expect(op?.origin).toBe('fetcher')
  expect(op?.data.origin).toBe('https://api.example.com')
  expect(JSON.stringify(op?.data)).not.toContain('abc123')
  expect(JSON.stringify(op?.data)).not.toContain('/v1/items')
  expect(op?.data.status).toBe(200)
  expect(entries(files).some(entry => entry.kind === 'session.start')).toBe(true)
})

const BAND = {
  component: 'AbovePrompt',
  props: {
    hasSurvey: false,
    isWorking: false,
    maxRows: 8,
    bodyColumns: 100,
    scroll: { offset: 0, bodyRows: 8 },
    view: {},
  },
} as const

test('the band shows the verdict on every surface that draws it, and Dismiss hides it', async ($, on) => {
  const files: Files = new Map()
  const clock = engine(on, files, UNVERIFIED)
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return h(Text, { key: 'engine' }, 'engine band') as RenderElement
  })
  await $.turn.start({ text: 'fix', turnId: 't4' })
  await $.turn.complete({ answer: 'Fixed and verified.', durationMs: 5, isAborted: false, turnId: 't4', reason: 'answer' })
  await settle(clock, files, /^supervisor\./)
  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ plugin: 'audit-ledger', surface, ...BAND })
    expect((await ui.find({ type: 'Text', text: /UNVERIFIED \(90%\)/ }))?.text).toMatch(/claim without a passing check/)
    expect(await ui.find({ type: 'Text', text: /next: Run pytest/ })).toBeDefined()
    await ui.unmount()
  }
  const ui = await $.ui.mount({ plugin: 'audit-ledger', surface: 'terminal', ...BAND })
  await ui.press({ key: 'dismiss' })
  expect(await ui.find({ type: 'Text', text: /UNVERIFIED/ })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: 'engine band' })).toBeDefined()
  await ui.unmount()
})

test('a model tool call carries no origin and counts as the turn\'s own evidence', async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(entries(files)[0]?.origin).toBeUndefined()
})

// A chain already on disk, as an earlier load of the mod left it.
const seed = async (files: Files, count: number, path = SEGMENT): Promise<string> => {
  let prev = GENESIS
  let text = ''
  for (let seq = 1; seq <= count; seq += 1) {
    const entry = await seal({ v: 1, seq, ts: seq, session: SESSION, kind: 'seeded', data: { n: seq }, prev })
    text += `${canonical(entry)}\n`
    prev = entry.hash
  }
  files.set(path, text)
  return text
}

test('with no anchored head the chain continues from disk, sealing the gap, and no segment is overwritten', async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  const before = await seed(files, 3)
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  const after = files.get(SEGMENT) ?? ''
  expect(after.startsWith(before)).toBe(true)
  const kept = entries(files)
  expect(kept.map(entry => entry.kind)).toEqual(['seeded', 'seeded', 'seeded', 'ledger.reanchor', 'tool.call'])
  expect(kept[3]?.data.reasons).toEqual(['head-missing'])
  expect(await verify($)).toStartWith('PASS: 5 entries')
})

test('a damaged segment tail is never appended to: the chain continues in a fresh segment', async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  await seed(files, 2)
  files.set(SEGMENT, `${files.get(SEGMENT) ?? ''}{"seq":3,"ha`)
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(files.get(SEGMENT)?.endsWith('{"seq":3,"ha')).toBe(true)
  const fresh = entries(files, `${DIR}/000002.jsonl`)
  expect(fresh.map(entry => entry.kind)).toEqual(['ledger.reanchor', 'tool.call'])
  expect(fresh[0]?.data.reasons).toEqual(['head-missing', 'damaged-tail'])
  expect(await verify($)).toMatch(/^FAIL: line 3: not JSON/)
})

test('a head anchor that fails after the segment landed leaves no duplicate seq', async ($, on) => {
  const files: Files = new Map()
  const said: string[] = []
  engine(on, files, undefined, said, { session: SESSION, storeSets: 0, failStoreSetAt: 2 })
  await $.tool.call({ tool: 'Bash', command: 'one' })
  await $.tool.call({ tool: 'Bash', command: 'two' })
  await $.tool.call({ tool: 'Bash', command: 'three' })
  expect(entries(files).map(entry => entry.seq)).toEqual([1, 2, 3])
  expect(said.join('\n')).toMatch(/head anchor failing/)
  expect(await verify($)).toStartWith('PASS: 3 entries')
})

test('after a resume the chain follows the live session id', async ($, on) => {
  const files: Files = new Map()
  const world: World = { session: SESSION, storeSets: 0 }
  engine(on, files, undefined, [], world)
  on('session.end', ($, e) => ({ sessionId: e.sessionId }))
  await $.tool.call({ tool: 'Bash', command: 'before' })
  await $.session.end({ reason: 'resume', sessionId: SESSION, resume: {} as never })
  world.session = 'sess-2'
  await $.tool.call({ tool: 'Bash', command: 'after' })
  expect(entries(files).map(entry => entry.kind)).toEqual(['tool.call', 'session.end'])
  const moved = entries(files, `${ROOT}/.claude/audit/sess-2/000001.jsonl`)
  expect(moved.map(entry => [entry.seq, entry.kind])).toEqual([[1, 'tool.call']])
})

test('/audit verify running beside appends sees one consistent snapshot', async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  await $.tool.call({ tool: 'Bash', command: 'warm' })
  const [, verdict] = await Promise.all([
    $.tool.call({ tool: 'Bash', command: 'a' }),
    verify($),
    $.tool.call({ tool: 'Bash', command: 'b' }),
    $.tool.call({ tool: 'Bash', command: 'c' }),
  ])
  expect(verdict).toStartWith('PASS')
  expect(await verify($)).toStartWith('PASS')
  expect(entries(files).filter(entry => entry.kind === 'ledger.verify').every(entry => entry.data.isIntact === true)).toBe(true)
})

const VERIFIED =
  '{"state":"verified","claims":["all tests pass"],"checks":[{"name":"pytest","result":"pass"}],"open_items":[],"confidence":0.95,"next_action":""}'

test('a verified verdict cannot stand when the ledger shows no passing check', async ($, on) => {
  const files: Files = new Map()
  const clock = engine(on, files, VERIFIED)
  await $.turn.start({ text: 'fix', turnId: 't5' })
  await $.tool.call({ tool: 'Bash', command: 'ls' })
  await $.turn.complete({ answer: 'All tests pass.', durationMs: 5, isAborted: false, turnId: 't5', reason: 'answer' })
  await settle(clock, files, /^supervisor\./)
  const verdict = entries(files).find(entry => entry.kind === 'supervisor.verdict')
  expect(verdict?.data.isOverridden).toBe(true)
  expect(verdict?.data.verdict).toMatchObject({ state: 'unverified' })
  expect(await audit($, 'status')).toMatch(/UNVERIFIED \(0\.95\) floor applied/)
})

test('a passing check run by a subagent backs the main answer', async ($, on) => {
  const files: Files = new Map()
  const clock = engine(on, files, VERIFIED)
  await $.turn.start({ text: 'fix', turnId: 't6' })
  await $.tool.call({ tool: 'Bash', command: 'npm test', agentId: 'agent-1' } as never)
  await $.turn.complete({ answer: 'All tests pass.', durationMs: 5, isAborted: false, turnId: 't6', reason: 'answer' })
  await settle(clock, files, /^supervisor\./)
  const verdict = entries(files).find(entry => entry.kind === 'supervisor.verdict')
  expect(verdict?.data.claimWithoutCheck).toBe(false)
  expect(verdict?.data.verdict).toMatchObject({ state: 'verified' })
})

test('a slow verdict for an older turn never replaces the newer turn\'s review', async ($, on) => {
  const files: Files = new Map()
  const clock = engine(on, files, async (prompt, late) => {
    if (prompt.includes('Done with the first')) {
      await late.sleep(5_000)
      return UNVERIFIED
    }
    return VERIFIED
  })
  await $.turn.start({ text: 'one', turnId: 'old' })
  await $.turn.complete({ answer: 'Done with the first.', durationMs: 5, isAborted: false, turnId: 'old', reason: 'answer' })
  await clock.settle()
  await $.turn.start({ text: 'two', turnId: 'new' })
  await $.tool.call({ tool: 'Bash', command: 'pytest -q' })
  await $.turn.complete({ answer: 'Fixed; tests pass.', durationMs: 5, isAborted: false, turnId: 'new', reason: 'answer' })
  await settle(clock, files, /^supervisor\./)
  await clock.advance(5_000)
  for (let round = 0; round < 50 && entries(files).filter(entry => entry.kind === 'supervisor.verdict').length < 2; round += 1) {
    await clock.settle()
  }
  expect(entries(files).filter(entry => entry.kind === 'supervisor.verdict')).toHaveLength(2)
  expect(await audit($, 'status')).toMatch(/last review: turn new done VERIFIED/)
})

const RECONFIGURER = {
  name: 'reconfigurer',
  register: (on: On) => {
    on('session.start', async ($, e, next) => {
      await $.config.set({ key: 'audit-ledger.mode', value: 'observe' })
      return next(e)
    })
  },
}

test('in enforce mode another mod cannot change the audit settings, and the attempt is recorded', { options: { mode: 'enforce' }, plugins: [RECONFIGURER] }, async ($, on) => {
  const files: Files = new Map()
  let isChanged = false
  engine(on, files)
  on('config.set', ($, e) => {
    isChanged = true
    return { value: e.value }
  })
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true }).catch(() => undefined)
  expect(isChanged).toBe(false)
  const attempt = entries(files).find(entry => entry.kind === 'op.config.set')
  expect(attempt?.origin).toBe('reconfigurer')
  expect(attempt?.data.deny).toMatch(/only the person may change/)
})

const SPAWNER = {
  name: 'spawner',
  register: (on: On) => {
    on('session.start', async ($, e, next) => {
      for await (const chunk of $.process.spawn({ argv: ['sh', '-c', 'echo hi'] })) void chunk
      return next(e)
    })
  },
}

test('a streamed host process another mod starts is recorded', { plugins: [SPAWNER] }, async ($, on) => {
  const files: Files = new Map()
  engine(on, files)
  on('process.spawn', async function* () {
    yield { stream: 'stdout' as const, text: 'hi\n' }
    return { value: { code: 0, signal: null } }
  })
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  await $.session.start({ cwd: ROOT, surface: 'terminal', isInteractive: true })
  const spawned = entries(files).find(entry => entry.kind === 'op.process.spawn')
  expect(spawned?.origin).toBe('spawner')
  expect(spawned?.data.code).toBe(0)
})
