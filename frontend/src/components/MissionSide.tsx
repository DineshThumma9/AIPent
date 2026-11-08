import { formatClock, pad, shortHash } from '../lib/format'
import type { AssessmentDetail } from '../lib/schemas'
import {
  actionLabel,
  approvalRole,
  roleLabel,
  type MissionView,
} from '../lib/mission'
import { SeverityMark, StatusMark } from './StatusMark'
import { ReasoningPanel } from './ReasoningPanel'

function ScopeSide({ detail }: { detail: AssessmentDetail }) {
  return (
    <section className="side-panel" aria-labelledby="scope-title">
      <div className="side-head">
        <h2 id="scope-title">Authorized scope</h2>
        <span className="side-meta mono">
          {detail.targets.length} target{detail.targets.length === 1 ? '' : 's'}
        </span>
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
        <div>
          <dt>risk</dt>
          <dd className="mono">
            {detail.risk_score === null
              ? 'not scored'
              : `${detail.risk_score.toFixed(1)} / 10`}
          </dd>
        </div>
      </dl>
    </section>
  )
}

function RoleLane({ mission }: { mission: MissionView }) {
  return (
    <section className="side-panel" aria-labelledby="roles-title">
      <div className="side-head">
        <h2 id="roles-title">Roles</h2>
        <span className="side-meta mono">
          {mission.activeRole
            ? `${mission.activeRole} working`
            : mission.runId
              ? 'run closed'
              : 'idle'}
        </span>
      </div>

      <ol className="role-lane">
        {mission.roles.map((role) => {
          const state =
            role.status === 'active'
              ? 'working'
              : role.status === 'done'
                ? role.handoff
                  ? 'handed off'
                  : 'closed'
                : 'queued'

          return (
            <li key={role.name} data-status={role.status}>
              <span className="role-pip" aria-hidden="true" />
              <div className="role-body">
                <div className="role-line">
                  <span className="role-name">{role.label}</span>
                  <span className="role-state mono">{state}</span>
                </div>
                <p className="role-mission">{role.mission}</p>
                {role.turns > 0 && (
                  <p className="role-turns mono">
                    {role.turns} turn{role.turns === 1 ? '' : 's'}
                  </p>
                )}
                {role.handoff?.summary && (
                  <p className="role-handoff">{role.handoff.summary}</p>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function FindingsSide({ mission }: { mission: MissionView }) {
  const confirmed = mission.confirmed.slice(0, 4)
  const suspected = mission.findings
    .filter((finding) => finding.status === 'suspected')
    .slice(0, 3)

  return (
    <section className="side-panel" aria-labelledby="side-findings-title">
      <div className="side-head">
        <h2 id="side-findings-title">Findings</h2>
        <span className="side-meta mono">
          {mission.counts.confirmed} confirmed
        </span>
      </div>

      {mission.counts.total === 0 ? (
        <p className="side-empty">
          No findings recorded. Recon services and scanner candidates land here
          with their evidence.
        </p>
      ) : (
        <>
          {confirmed.length > 0 ? (
            <ul className="side-findings">
              {confirmed.map((finding) => (
                <li key={finding.id} data-status={finding.status}>
                  <SeverityMark severity={finding.severity} />
                  <div>
                    <p>{finding.title}</p>
                    <span className="mono">
                      {finding.endpoint ?? finding.asset}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="side-empty">
              Nothing is confirmed yet. {mission.counts.suspected} candidate
              {mission.counts.suspected === 1 ? '' : 's'} await probe evidence.
            </p>
          )}

          {suspected.length > 0 && (
            <details className="side-details">
              <summary>
                Suspected candidates{' '}
                <span className="mono">{mission.counts.suspected}</span>
              </summary>
              <ul className="side-findings">
                {suspected.map((finding) => (
                  <li key={finding.id} data-status={finding.status}>
                    <SeverityMark severity={finding.severity} />
                    <div>
                      <p>{finding.title}</p>
                      <span className="mono">
                        {finding.endpoint ?? finding.asset}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </section>
  )
}

function GatesSide({ detail }: { detail: AssessmentDetail }) {
  const recent = [...detail.approvals]
    .sort((a, b) => b.id - a.id)
    .slice(0, 4)

  return (
    <section className="side-panel" aria-labelledby="gates-title">
      <div className="side-head">
        <h2 id="gates-title">Gates</h2>
        <span className="side-meta mono">
          {detail.approvals.some((approval) => approval.decision === 'pending')
            ? 'open'
            : 'clear'}
        </span>
      </div>

      {recent.length === 0 ? (
        <p className="side-empty">
          No gate has opened. Every action pauses here before it runs.
        </p>
      ) : (
        <ol className="gate-history">
          {recent.map((approval) => {
            const role = approvalRole(approval)
            return (
              <li key={approval.id} data-decision={approval.decision}>
                <div className="gate-history-line">
                  <span>{actionLabel(approval.action)}</span>
                  <span className="mono">{approval.decision}</span>
                </div>
                <p className="mono">
                  {role ? roleLabel(role) : 'review'} ·{' '}
                  {formatClock(approval.requested_at)}
                </p>
              </li>
            )
          })}
        </ol>
      )}
    </section>
  )
}

function ReportSide({ detail }: { detail: AssessmentDetail }) {
  return (
    <section className="side-panel" aria-labelledby="report-title">
      <div className="side-head">
        <h2 id="report-title">Report</h2>
        <span className="side-meta mono">
          {detail.report_path ? (
            <StatusMark status="completed" />
          ) : (
            'not generated'
          )}
        </span>
      </div>

      {detail.report_path ? (
        <>
          <dl className="scope-facts">
            <div>
              <dt>file</dt>
              <dd className="mono" title={detail.report_path}>
                {detail.report_path.split('/').pop()}
              </dd>
            </div>
            <div>
              <dt>sha256</dt>
              <dd className="mono" title={detail.report_sha256 ?? undefined}>
                {shortHash(detail.report_sha256, 16)}
              </dd>
            </div>
          </dl>
          <a
            className="report-link"
            href={`/api/assessments/${detail.id}/report`}
            download
          >
            Download report
          </a>
        </>
      ) : (
        <p className="side-empty">
          The report is written after final review. Its path and hash will
          replace this note.
        </p>
      )}
    </section>
  )
}

function ActionRecord({ detail }: { detail: AssessmentDetail }) {
  return (
    <details className="side-details side-record">
      <summary>
        Action record <span className="mono">{detail.steps.length}</span>
      </summary>

      {detail.steps.length === 0 ? (
        <p className="side-empty">No action has been recorded.</p>
      ) : (
        <ol className="action-log">
          {detail.steps.map((step) => (
            <li key={step.id} data-status={step.status}>
              <div className="action-line">
                <span className="action-seq mono">{pad(step.seq)}</span>
                <span className="action-name">{actionLabel(step.action)}</span>
                <StatusMark status={step.status} />
              </div>
              <p className="action-meta mono">
                {step.target ?? 'no target'} · {formatClock(step.created_at)}
              </p>
              {step.argv.length > 0 && (
                <details className="action-command">
                  <summary>Command</summary>
                  <pre>{step.argv.join(' ')}</pre>
                </details>
              )}
              {step.error && <p className="action-error">{step.error}</p>}
            </li>
          ))}
        </ol>
      )}
    </details>
  )
}

function AuditRecord({ detail }: { detail: AssessmentDetail }) {
  const rows = detail.audit.slice(0, 10)

  return (
    <details className="side-details side-record">
      <summary>
        Audit trail <span className="mono">{detail.audit.length}</span>
      </summary>

      {rows.length === 0 ? (
        <p className="side-empty">No audit rows recorded.</p>
      ) : (
        <ol className="audit-log">
          {rows.map((row) => (
            <li key={row.id}>
              <span className="mono">{formatClock(row.ts)}</span>
              <span>{row.event_type.replaceAll('.', ' ')}</span>
            </li>
          ))}
        </ol>
      )}
    </details>
  )
}

export function MissionSide({
  detail,
  mission,
}: {
  detail: AssessmentDetail
  mission: MissionView
}) {
  return (
    <aside className="mission-side" aria-label="Mission record">
      <ScopeSide detail={detail} />
      <RoleLane mission={mission} />
      <FindingsSide mission={mission} />
      <ReasoningPanel board={mission.reasoning} />
      <GatesSide detail={detail} />
      <ReportSide detail={detail} />
      <ActionRecord detail={detail} />
      <AuditRecord detail={detail} />
    </aside>
  )
}
