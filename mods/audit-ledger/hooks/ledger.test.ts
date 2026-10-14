import { describe, expect, test } from 'claude-code/testing'

import {
  GENESIS,
  canonical,
  claimsCompletion,
  looksLikeCheck,
  parseVerdict,
  payload,
  redact,
  seal,
  verifyChain,
} from './ledger'
import type { Entry } from './ledger'

const chain = async (count: number): Promise<Entry[]> => {
  const entries: Entry[] = []
  let prev = GENESIS
  for (let seq = 1; seq <= count; seq += 1) {
    const entry = await seal({ v: 1, seq, ts: seq, session: 's', kind: 'k', data: { n: seq }, prev })
    entries.push(entry)
    prev = entry.hash
  }
  return entries
}

const lines = (entries: readonly Entry[]): string[] => entries.map(entry => canonical(entry))

describe('canonical encoding', () => {
  test('sorts keys and drops undefined members at every depth', () => {
    expect(canonical({ b: 1, a: { d: undefined, c: [2, 'x'] } })).toBe('{"a":{"c":[2,"x"]},"b":1}')
  })
})

describe('chain verification', () => {
  test('an untouched chain anchored at its head passes', async () => {
    const entries = await chain(5)
    const last = entries[4]!
    const report = await verifyChain(lines(entries), { seq: 5, hash: last.hash, segment: 1 })
    expect(report.isIntact).toBe(true)
    expect(report.entries).toBe(5)
  })

  test('an edited entry fails with a hash mismatch', async () => {
    const entries = await chain(4)
    const text = lines(entries)
    text[2] = text[2]!.replace('"n":3', '"n":33')
    const report = await verifyChain(text, { seq: 4, hash: entries[3]!.hash, segment: 1 })
    expect(report.isIntact).toBe(false)
    expect(report.problems[0]).toMatch(/seq 3: hash mismatch/)
  })

  test('a deleted middle entry fails on sequence and link', async () => {
    const entries = await chain(4)
    const text = lines(entries)
    text.splice(1, 1)
    const report = await verifyChain(text, { seq: 4, hash: entries[3]!.hash, segment: 1 })
    expect(report.isIntact).toBe(false)
    expect(report.problems.join(' ')).toMatch(/seq 3: expected seq 2/)
  })

  test('a truncated tail fails against the anchored head', async () => {
    const entries = await chain(4)
    const report = await verifyChain(lines(entries.slice(0, 3)), { seq: 4, hash: entries[3]!.hash, segment: 1 })
    expect(report.isIntact).toBe(false)
    expect(report.problems[0]).toMatch(/truncated/)
  })

  test('a chain with no anchored head fails', async () => {
    const report = await verifyChain(lines(await chain(2)), null)
    expect(report.isIntact).toBe(false)
    expect(report.problems[0]).toMatch(/no anchored head/)
  })
})

describe('redaction and payloads', () => {
  test('secrets are masked while the digest covers the original', async () => {
    const raw = 'curl -H "Authorization: Bearer abcdefghijklmnop" API_KEY=sk-0123456789abcdefghij'
    expect(redact(raw)).not.toContain('abcdefghijklmnop')
    expect(redact(raw)).not.toContain('sk-0123456789abcdefghij')
    const kept = await payload(raw, 'excerpt')
    expect(kept.excerpt).toContain('[REDACTED]')
    expect(kept.digest).toHaveLength(64)
    const bare = await payload(raw, 'digest')
    expect(bare.excerpt).toBeUndefined()
    expect(bare.digest).toBe(kept.digest)
  })
})

describe('claim and check detection', () => {
  test('completion language and check commands are recognized', () => {
    expect(claimsCompletion('All tests pass and the fix is done.')).toBe(true)
    expect(claimsCompletion('Here is the plan for tomorrow.')).toBe(false)
    expect(looksLikeCheck('cd mods && claude plugin validate . --strict')).toBe(true)
    expect(looksLikeCheck('python -m pytest -q tests/')).toBe(true)
    expect(looksLikeCheck('ls -la')).toBe(false)
  })
})

describe('verdict parsing', () => {
  test('a well-formed reply parses, fenced or not', () => {
    const reply =
      '```json\n{"state":"unverified","claims":["tests pass"],"checks":[{"name":"pytest","result":"not-run"}],"open_items":["run pytest"],"confidence":0.8,"next_action":"Run pytest."}\n```'
    const parsed = parseVerdict(reply)
    expect('verdict' in parsed).toBe(true)
    if ('verdict' in parsed) {
      expect(parsed.verdict.state).toBe('unverified')
      expect(parsed.verdict.checks[0]).toEqual({ name: 'pytest', result: 'not-run' })
      expect(parsed.verdict.openItems).toEqual(['run pytest'])
    }
  })

  test('malformed replies are rejected with a reason', () => {
    expect(parseVerdict('no json here')).toEqual({ error: 'no JSON object in the reply' })
    expect(parseVerdict('{"state":"great"}')).toEqual({ error: 'unknown state "great"' })
    const badConfidence = parseVerdict('{"state":"verified","claims":[],"checks":[],"open_items":[],"confidence":7}')
    expect(badConfidence).toEqual({ error: 'confidence is not a number in [0, 1]' })
  })
})
