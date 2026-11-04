import { useState } from 'react'
import { formatClock, pad, shortHash } from '../lib/format'
import type { Evidence, Finding } from '../lib/schemas'
import { SeverityMark } from './StatusMark'

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

function EvidenceBlock({ evidence }: { evidence: Evidence }) {
  return (
    <figure className="evidence">
      <figcaption>
        <span>evidence #{pad(evidence.id)}</span>
        {evidence.step_id !== null && <span>step {pad(evidence.step_id)}</span>}
      </figcaption>
      {evidence.excerpt && <blockquote>{evidence.excerpt}</blockquote>}
      <pre>{JSON.stringify(evidence.locator, null, 2)}</pre>
    </figure>
  )
}

function FindingRow({
  finding,
  evidence,
}: {
  finding: Finding
  evidence: Evidence[]
}) {
  const [open, setOpen] = useState(false)

  return (
    <li className="finding" data-open={open}>
      <button
        type="button"
        className="finding-row"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={`finding-${finding.id}`}
      >
        <SeverityMark severity={finding.severity} />
        <span className="finding-title">{finding.title}</span>
        <span className="finding-asset mono">
          {finding.asset}
          {finding.endpoint ? finding.endpoint : ''}
        </span>
        <span className="finding-confidence mono">
          {finding.confidence.toFixed(2)} conf.
        </span>
        <span className="finding-caret" aria-hidden="true">
          {open ? '−' : '+'}
        </span>
      </button>

      {open && (
        <div className="finding-detail" id={`finding-${finding.id}`}>
          {finding.description && <p>{finding.description}</p>}

          <dl className="finding-facts">
            <div>
              <dt>status</dt>
              <dd>{finding.status.replaceAll('_', ' ')}</dd>
            </div>
            <div>
              <dt>origin</dt>
              <dd>{finding.origin}</dd>
            </div>
            <div>
              <dt>key</dt>
              <dd className="mono" title={finding.canonical_key}>
                {shortHash(finding.canonical_key, 18)}
              </dd>
            </div>
            {finding.cvss !== null && (
              <div>
                <dt>cvss</dt>
                <dd className="mono">{finding.cvss.toFixed(1)}</dd>
              </div>
            )}
            {finding.cwe.length > 0 && (
              <div>
                <dt>cwe</dt>
                <dd className="mono">{finding.cwe.join(', ')}</dd>
              </div>
            )}
            <div>
              <dt>seen</dt>
              <dd className="mono">{formatClock(finding.updated_at)}</dd>
            </div>
          </dl>

          {finding.impact && (
            <p className="finding-note">
              <span>Impact.</span> {finding.impact}
            </p>
          )}
          {finding.remediation && (
            <p className="finding-note">
              <span>Remediation.</span> {finding.remediation}
            </p>
          )}

          {evidence.length === 0 ? (
            <p className="empty small">No evidence attached to this finding.</p>
          ) : (
            <div className="evidence-list">
              {evidence.map((row) => (
                <EvidenceBlock key={row.id} evidence={row} />
              ))}
            </div>
          )}
        </div>
      )}
    </li>
  )
}

export function FindingLedger({
  findings,
  evidence,
}: {
  findings: Finding[]
  evidence: Evidence[]
}) {
  const sorted = [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      b.id - a.id,
  )

  return (
    <section className="panel panel-findings" aria-labelledby="findings-title">
      <div className="panel-head">
        <h2 id="findings-title">Findings</h2>
        <span className="panel-meta">
          {sorted.length === 0
            ? 'none recorded'
            : `${sorted.length} total · ${sorted[0].severity}`}
        </span>
      </div>

      {sorted.length === 0 ? (
        <p className="empty">
          No findings recorded yet. Service detections and web checks land here with
          their evidence.
        </p>
      ) : (
        <ul className="finding-list">
          {sorted.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              evidence={evidence.filter((row) => row.finding_id === finding.id)}
            />
          ))}
        </ul>
      )}
    </section>
  )
}
