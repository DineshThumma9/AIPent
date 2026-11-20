import { describe, expect, it } from 'vitest'
import { explainReply } from './chat'
import { actionLabel, type MissionView } from './mission'
import type { AssessmentDetail, Approval } from './schemas'

function approval(argv: string[]): Approval {
  return {
    id: 1,
    assessment_id: 1,
    step_id: 1,
    action: 'curl_request',
    argv,
    detail: {
      role: 'validation',
      rationale: 'Probe independent endpoints',
      plan: [
        {
          action: 'curl_request',
          target: '127.0.0.1',
          rationale: 'Probe independent endpoints',
        },
      ],
    },
    decision: 'pending',
    actor: null,
    reason: null,
    requested_at: '2026-11-20T10:00:00Z',
    decided_at: null,
    executed_at: null,
    outcome: null,
  }
}

function missionFor(pending: Approval): MissionView {
  return {
    pendingApproval: pending,
    runId: 'run-1',
    running: false,
    counts: { confirmed: 0, suspected: 0, falsePositive: 0, total: 0 },
  } as MissionView
}

const detail = {
  targets: ['127.0.0.1'],
  ports: [3000],
} as AssessmentDetail

describe('batched curl explanations', () => {
  it('describes the requests instead of pasting the batch argv', () => {
    const pending = approval([
      'mcp',
      'curl_request',
      JSON.stringify({
        batch: [
          { method: 'GET', url: 'http://127.0.0.1:3000/login' },
          { method: 'HEAD', url: 'http://127.0.0.1:3000/admin' },
        ],
      }),
    ])

    const text = explainReply(detail, missionFor(pending))

    expect(text).toContain('2 independent read-only requests')
    expect(text).toContain('GET /login')
    expect(text).toContain('HEAD /admin')
    expect(text).not.toContain('"batch"')
  })

  it('keeps the exact command for a single request', () => {
    const pending = approval([
      'mcp',
      'curl_request',
      JSON.stringify({ method: 'GET', url: 'http://127.0.0.1:3000/login' }),
    ])

    expect(explainReply(detail, missionFor(pending))).toContain(
      'It will run exactly: mcp curl_request',
    )
  })

  it('labels the current curl action', () => {
    expect(actionLabel('curl_request')).toBe('HTTP request (curl)')
  })
})
