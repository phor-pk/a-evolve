import { expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On, RenderElement } from 'claude-code'

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
const engine = (on: On, files: Files, fork?: string | null, said: string[] = []): Clock => {
  const clock = mock.clock(on, { now: 1_000 })
  mock.store(on)
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
  on('session.id', () => ({ value: SESSION }))
  on('session.root', () => ({ value: ROOT }))
  on('session.version', () => ({ value: { version: '2.1.296' } }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  on('tool.call', () => ({ result: { stdout: 'ok', stderr: '', interrupted: false } }) as never)
  on('turn.start', ($, e) => ({ turnId: e.turnId }))
  on('turn.complete', ($, e) => ({ text: e.answer }))
  on('model.fork', () =>
    fork === null || fork === undefined
      ? { value: { isAnswered: false, reason: 'nothing-to-fork' } as const }
      : {
          value: {
            isAnswered: true,
            text: fork,
            usage: { input_tokens: 40, output_tokens: 60, cache_read_input_tokens: 9000, cache_creation_input_tokens: 0 },
          } as const,
        },
  )
  on('http.fetch', () => ({ value: { status: 200, ok: true, headers: {}, text: '' } }))
  return clock
}

const entries = (files: Files): Array<{ seq: number; kind: string; origin?: string; data: Record<string, unknown> }> =>
  (files.get(SEGMENT) ?? '')
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
  expect(op?.data.url).toBe('https://api.example.com/v1/items')
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
