// The audit-ledger contract: the values it keeps in $.state and the shapes
// its ledger entries and supervisor verdicts take.

export type AuditVerdictState = 'verified' | 'unverified' | 'partial' | 'blocked' | 'no-claim'

export type AuditCheck = { name: string; result: 'pass' | 'fail' | 'not-run' }

export type AuditVerdict = {
  state: AuditVerdictState
  claims: string[]
  checks: AuditCheck[]
  openItems: string[]
  confidence: number
  nextAction: string
}

export type AuditReviewStatus = 'pending' | 'done' | 'error' | 'invalid'

export type AuditReview = {
  turnId: string
  status: AuditReviewStatus
  verdict: AuditVerdict | null
  reason: string | null
  claimWithoutCheck: boolean
  checksRun: number
  checksFailed: number
}

export type AuditMeter = {
  forks: number
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  cacheCreationTokens: number
}

export type AuditHealth = { entries: number; failures: number; lastError: string | null }

declare module 'claude-code' {
  interface PluginState {
    'audit-ledger': {
      review: AuditReview | null
      isDismissed: boolean
      meter: AuditMeter
      health: AuditHealth
    }
  }
}
