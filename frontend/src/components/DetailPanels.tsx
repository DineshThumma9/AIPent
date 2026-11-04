import { summarizeEvent, type StreamEvent } from '../lib/events'
import { formatClock, pad, shortHash } from '../lib/format'
import { reportUrl } from '../lib/api'
import type { Approval, AssessmentDetail, PlanStep } from '../lib/schemas'
import { StatusMark } from './StatusMark'

export function ScopePanel({ detail }: { detail: AssessmentDetail }) {
  return (
    <section className="panel" aria-labelledby="scope-title">
      <div className="panel-head">
        <h2 id="scope-title">Authorized scope</h2>
        <span className="panel-meta">{detail.targets.length} target(s)</span>
      </div>

      <ul className="scope-targets">
        {detail.targets.map((target) => (
          <li key={target}>
            <span className="scope-mark" aria-hidden="true" />
            <span className="mono">{target}</span>
          </li>
        ))}
      </ul>

      <dl className="scope-facts">
        <div>
          <dt>ports</dt>
          <dd className="mono">
            {detail.ports.length ? detail.ports.join(', ') : 'tool default'}
          </dd>
        </div>
        <div>
          <dt>exclusions</dt>
          <dd className="mono">
            {detail.exclusions.length ? detail.exclusions.join(', ') : 'none'}
          </dd>
        </div>
      </dl>
    </section>
  )
}

function planFrom(approval: Approval): PlanStep[] {
  const raw = approval.detail.plan
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item) => {
    if (typeof item !== 'object' || item === null) return []
    const record = item as Record<string, unknown>
    if (
      typeof record.action !== 'string' ||
      typeof record.target !== 'string' ||
      typeof record.rationale !== 'string'
    ) {
      return []
    }
    return [
      {
        action: record.action,
        target: record.target,
        rationale: record.rationale,
      },
    ]
  })
}

function gateLabel(action: string) {
  if (action === 'plan_review') return 'assessment plan'
  if (action === 'final_review') return 'final findings review'
  return action.replaceAll('_', ' ')
}

function ApprovalRow({
  approval,
  busy,
  onDecision,
}: {
  approval: Approval
  busy: boolean
  onDecision?: (decision: 'approved' | 'rejected') => void
}) {
  const plan = planFrom(approval)
  const pending = approval.decision === 'pending'

  return (
    <li className="approval" data-decision={approval.decision}>
      <div className="approval-line">
        <span className="approval-action">{gateLabel(approval.action)}</span>
        <span className="approval-decision">{approval.decision}</span>
      </div>

      {plan.length > 0 && (
        <ol className="plan-list">
          {plan.map((step) => (
            <li key={`${step.action}-${step.target}`}>
              <span className="plan-action mono">{step.action.replaceAll('_', ' ')}</span>
              <span className="plan-target mono">{step.target}</span>
              <span className="plan-rationale">{step.rationale}</span>
            </li>
          ))}
        </ol>
      )}

      {approval.argv.length > 0 && (
        <pre className="mini-argv">{approval.argv.join(' ')}</pre>
      )}

      <div className="approval-meta">
        <span>requested {formatClock(approval.requested_at)}</span>
        {approval.actor && <span>by {approval.actor}</span>}
        {approval.reason && <span>{approval.reason}</span>}
      </div>

      {pending && onDecision && (
        <div className="approval-actions">
          <button
            type="button"
            className="btn btn-primary btn-small"
            onClick={() => onDecision('approved')}
            disabled={busy}
          >
            {busy ? 'Submitting…' : 'Approve'}
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-small"
            onClick={() => onDecision('rejected')}
            disabled={busy}
          >
            Reject
          </button>
        </div>
      )}
    </li>
  )
}

export function ApprovalPanel({
  approvals,
  busy = false,
  onDecision,
}: {
  approvals: Approval[]
  busy?: boolean
  onDecision?: (decision: 'approved' | 'rejected') => void
}) {
  const pending = approvals.filter((approval) => approval.decision === 'pending')

  return (
    <section className="panel" aria-labelledby="approval-title">
      <div className="panel-head">
        <h2 id="approval-title">Approval gates</h2>
        <span className="panel-meta">
          {pending.length ? `${pending.length} pending` : 'clear'}
        </span>
      </div>

      {approvals.length === 0 ? (
        <p className="empty small">
          No gate has been raised. The agent pauses here before its plan, before an
          active web probe, and before the report.
        </p>
      ) : (
        <ul className="approval-list">
          {approvals.map((approval) => (
            <ApprovalRow
              key={approval.id}
              approval={approval}
              busy={busy}
              onDecision={approval.decision === 'pending' ? onDecision : undefined}
            />
          ))}
        </ul>
      )}
    </section>
  )
}

export function ReportPanel({ detail }: { detail: AssessmentDetail }) {
  const ready = Boolean(detail.report_path)

  return (
    <section className="panel" aria-labelledby="report-title">
      <div className="panel-head">
        <h2 id="report-title">Report</h2>
        <span className="panel-meta">
          {ready ? (
            <StatusMark status="completed" />
          ) : (
            'not generated'
          )}
        </span>
      </div>

      {ready ? (
        <>
          <dl className="report-facts">
            <div>
              <dt>file</dt>
              <dd className="mono">{detail.report_path}</dd>
            </div>
            <div>
              <dt>sha256</dt>
              <dd className="mono" title={detail.report_sha256 ?? undefined}>
                {shortHash(detail.report_sha256, 20)}
              </dd>
            </div>
            {detail.finished_at && (
              <div>
                <dt>finished</dt>
                <dd className="mono">{formatClock(detail.finished_at)}</dd>
              </div>
            )}
          </dl>
          <a className="report-link" href={reportUrl(detail.id)} download>
            Download report
          </a>
        </>
      ) : (
        <p className="empty small">
          The Typst report is written after review. Its path and hash will replace this
          note.
        </p>
      )}
    </section>
  )
}

function auditSummary(eventType: string, payload: Record<string, unknown>) {
  const step = payload.step_id
  switch (eventType) {
    case 'assessment.created':
      return 'scope opened'
    case 'step.started':
      return `step ${typeof step === 'number' ? pad(step) : '—'} started`
    case 'step.succeeded':
      return `step ${typeof step === 'number' ? pad(step) : '—'} succeeded · ${String(
        payload.findings_added ?? 0,
      )} new`
    case 'step.failed':
      return `step ${typeof step === 'number' ? pad(step) : '—'} failed`
    case 'step.timeout':
      return `step ${typeof step === 'number' ? pad(step) : '—'} timed out`
    default:
      return eventType
  }
}

export function SignalsPanel({
  audit,
  recent,
}: {
  audit: AssessmentDetail['audit']
  recent: StreamEvent[]
}) {
  const streamRows = recent.filter((event) => event.type !== 'heartbeat').slice(0, 6)

  return (
    <section className="panel" aria-labelledby="signals-title">
      <div className="panel-head">
        <h2 id="signals-title">Signals</h2>
        <span className="panel-meta">live + recorded</span>
      </div>

      <div className="signal-group">
        <h3>Stream</h3>
        {streamRows.length === 0 ? (
          <p className="empty small">Waiting for the next event.</p>
        ) : (
          <ol className="signal-list">
            {streamRows.map((event) => (
              <li key={`${event.type}-${event.ts}-${event.id}`} data-type={event.type}>
                <span className="signal-time mono">{formatClock(event.ts)}</span>
                <span className="signal-type">{event.type}</span>
                <span className="signal-text">{summarizeEvent(event)}</span>
              </li>
            ))}
          </ol>
        )}
      </div>

      <div className="signal-group">
        <h3>Audit trail</h3>
        {audit.length === 0 ? (
          <p className="empty small">No audit rows yet.</p>
        ) : (
          <ol className="signal-list">
            {audit.slice(0, 8).map((row) => (
              <li key={row.id}>
                <span className="signal-time mono">{formatClock(row.ts)}</span>
                <span className="signal-type">{auditSummary(row.event_type, row.payload)}</span>
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  )
}
