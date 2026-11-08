import { formatDate, pad } from '../lib/format'
import type { AssessmentDetail } from '../lib/schemas'
import { StatusMark } from './StatusMark'

export function AssessmentHeader({
  detail,
  scanning,
  agentBusy,
  gatePending,
  onScan,
  onRunAgent,
}: {
  detail: AssessmentDetail
  scanning: boolean
  agentBusy: boolean
  gatePending: boolean
  onScan: () => void
  onRunAgent: () => void
}) {
  const active = ['planning', 'running', 'reporting'].includes(detail.status)
  const busy = scanning || agentBusy || active
  const runDisabled = busy || gatePending

  return (
    <header className="assessment-head">
      <div className="kicker">
        <span>Assessment</span>
        <span className="mono">#{pad(detail.id)}</span>
        <StatusMark status={detail.status} />
      </div>

      <h1>{detail.title}</h1>
      <p className="request">
        {detail.request || 'Scoped service discovery against an authorized lab target.'}
      </p>

      <dl className="meta">
        <div>
          <dt>Created</dt>
          <dd>{formatDate(detail.created_at)}</dd>
        </div>
        <div>
          <dt>Targets</dt>
          <dd className="mono">{detail.targets.join(' · ')}</dd>
        </div>
        <div>
          <dt>Ports</dt>
          <dd className="mono">
            {detail.ports.length ? detail.ports.join(', ') : 'tool default'}
          </dd>
        </div>
        <div>
          <dt>Risk</dt>
          <dd className="mono">
            {detail.risk_score === null ? 'not scored' : `${detail.risk_score.toFixed(1)} / 10`}
          </dd>
        </div>
      </dl>

      <div className="head-actions">
        <button
          type="button"
          className="btn btn-primary"
          onClick={onRunAgent}
          disabled={runDisabled}
          aria-busy={agentBusy || active}
        >
          {agentBusy || active ? 'Agent working…' : 'Run agent'}
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={onScan}
          disabled={busy}
          aria-busy={scanning}
        >
          {scanning ? 'nmap running…' : 'Manual nmap'}
        </button>
        <span className="head-hint">
          {gatePending
            ? 'An approval is pending. Decide there to continue.'
            : 'Plan approval, active-scan approval, final review. Exact argv is audited before it runs.'}
        </span>
      </div>
    </header>
  )
}
