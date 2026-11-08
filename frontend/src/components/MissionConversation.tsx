import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from 'react'
import { ArrowUp, Copy } from 'lucide-react'
import { formatClock, formatDate, pad, shortHash } from '../lib/format'
import type {
  Approval,
  AssessmentDetail,
  Evidence,
  Finding,
} from '../lib/schemas'
import type { LocalMessage } from '../lib/chatStorage'
import {
  ROLE_INFO,
  actionLabel,
  approvalRationale,
  approvalRole,
  approvalTarget,
  approvalPlan,
  buildThread,
  roleLabel,
  type HandoffView,
  type MissionView,
  type RoleName,
  type ThreadEntry,
} from '../lib/mission'
import { SeverityMark, StatusMark } from './StatusMark'

function RoleTag({ role }: { role: RoleName }) {
  return (
    <span className="role-tag">
      <span className="role-square" aria-hidden="true" />
      {ROLE_INFO[role].label}
    </span>
  )
}

function OperatorTurn({
  entry,
}: {
  entry: Extract<ThreadEntry, { kind: 'operator' }>
}) {
  return (
    <article className="turn turn-operator">
      <header className="turn-head">
        <span className="turn-square turn-square-oxide" aria-hidden="true" />
        <span className="turn-who">Operator</span>
        <time className="turn-time mono" dateTime={entry.at}>
          {formatClock(entry.at)}
        </time>
      </header>
      <p className="turn-text">{entry.text}</p>
    </article>
  )
}

function AssistantTurn({
  entry,
}: {
  entry: Extract<ThreadEntry, { kind: 'assistant' }>
}) {
  return (
    <article className="turn turn-assistant">
      <header className="turn-head">
        <span className="turn-square" aria-hidden="true" />
        <span className="turn-who">AIPENT</span>
        <time className="turn-time mono" dateTime={entry.at}>
          {formatClock(entry.at)}
        </time>
      </header>
      <p className="turn-text">{entry.text}</p>
    </article>
  )
}

function RoleTurn({
  entry,
}: {
  entry: Extract<ThreadEntry, { kind: 'role' }>
}) {
  return (
    <div className="role-divider">
      <span className="role-divider-square" aria-hidden="true" />
      <span className="role-divider-name">{ROLE_INFO[entry.role].label}</span>
      <span className="role-divider-note">{entry.note}</span>
      <time className="turn-time mono" dateTime={entry.at}>
        {formatClock(entry.at)}
      </time>
    </div>
  )
}

function decisionLine(decision: Record<string, unknown>): string {
  const what =
    typeof decision.what === 'string'
      ? decision.what
      : typeof decision.decision === 'string'
        ? decision.decision
        : null
  const why =
    typeof decision.why === 'string'
      ? decision.why
      : typeof decision.reason === 'string'
        ? decision.reason
        : null

  if (what && why) return `${what} — ${why}`
  if (what) return what
  if (why) return why

  const pairs = Object.entries(decision).map(([key, value]) => {
    const text = Array.isArray(value)
      ? value.map(String).join(', ')
      : String(value)
    return `${key.replaceAll('_', ' ')}: ${text}`
  })
  return pairs.join(' · ')
}

function HandoffTurn({ handoff }: { handoff: HandoffView }) {
  return (
    <article className="turn turn-assistant turn-handoff">
      <header className="turn-head">
        <span className="turn-square" aria-hidden="true" />
        <RoleTag role={handoff.role} />
        <span className="turn-kicker">handoff</span>
        <time className="turn-time mono" dateTime={handoff.at}>
          {formatClock(handoff.at)}
        </time>
      </header>

      <p className="turn-text">{handoff.summary}</p>

      {handoff.decisions.length > 0 && (
        <details className="turn-details">
          <summary>
            {handoff.decisions.length} decision
            {handoff.decisions.length === 1 ? '' : 's'}
          </summary>
          <ul className="decision-list">
            {handoff.decisions.map((decision, index) => (
              <li key={index}>{decisionLine(decision)}</li>
            ))}
          </ul>
        </details>
      )}

      {handoff.openQuestions.length > 0 && (
        <details className="turn-details">
          <summary>Open questions</summary>
          <ul className="decision-list">
            {handoff.openQuestions.map((question) => (
              <li key={question}>{question}</li>
            ))}
          </ul>
        </details>
      )}

      <p className="handoff-next">
        <span className="mono">next</span>{' '}
        {handoff.next === 'review'
          ? 'final review'
          : roleLabel(handoff.next)}
      </p>

      {handoff.needsInput && handoff.question && (
        <p className="handoff-question">{handoff.question}</p>
      )}
    </article>
  )
}

function finalReviewFacts(approval: Approval): string[] {
  const facts: string[] = []
  const risk = approval.detail.risk_score
  if (typeof risk === 'number') facts.push(`risk ${risk.toFixed(1)} / 10`)

  const counts = approval.detail.counts
  if (typeof counts === 'object' && counts !== null) {
    for (const [key, value] of Object.entries(counts)) {
      if (typeof value === 'number' && value > 0) {
        facts.push(`${key.replaceAll('_', ' ')} ${value}`)
      }
    }
  }

  const findings = approval.detail.findings
  if (typeof findings === 'number') {
    facts.push(`${findings} finding${findings === 1 ? '' : 's'}`)
  }

  return facts
}

function ApprovalCard({
  approval,
  busy,
  gateOpen,
  settled,
  onDecision,
}: {
  approval: Approval
  busy: boolean
  gateOpen: boolean
  settled: boolean
  onDecision: (decision: 'approved' | 'rejected', reason?: string) => void
}) {
  const [reason, setReason] = useState('')
  const pending = approval.decision === 'pending'
  const role = approvalRole(approval)
  const plan = approvalPlan(approval)
  const target = approvalTarget(approval)
  const rationale = approvalRationale(approval)
  const review = approval.action === 'final_review'
  const facts = review ? finalReviewFacts(approval) : []
  const detail = approval.detail as Record<string, unknown>
  const hypothesisId: string | undefined =
    typeof detail.hypothesis_id === 'string' ? detail.hypothesis_id : undefined
  const expectedObservation: string | undefined =
    typeof detail.expected_observation === 'string'
      ? detail.expected_observation
      : undefined
  const wouldFalsify: string | undefined =
    typeof detail.would_falsify === 'string' ? detail.would_falsify : undefined
  const evidenceIds: number[] = Array.isArray(detail.evidence_ids)
    ? detail.evidence_ids.filter((id): id is number => typeof id === 'number')
    : []
  const canDecide = pending && gateOpen && !settled && !busy

  const copyArgv = () => {
    navigator.clipboard.writeText(approval.argv.join(' '))
  }

  return (
    <article
      className="gate-card"
      data-decision={approval.decision}
      aria-label={`${actionLabel(approval.action)} gate`}
    >
      <header className="gate-head">
        <div className="gate-heading">
          <span className="gate-stamp" aria-hidden="true" />
          <div>
            <p className="gate-kind">
              {pending ? 'Action gate' : 'Gate record'}
            </p>
            <h3>{actionLabel(approval.action)}</h3>
          </div>
        </div>
        <span className="gate-decision mono">{approval.decision}</span>
      </header>

      <div className="gate-meta">
        {role && <RoleTag role={role} />}
        {target && <span className="mono">{target}</span>}
        <time className="mono" dateTime={approval.requested_at}>
          {formatClock(approval.requested_at)}
        </time>
      </div>

      {review ? (
        <p className="gate-why">
          {facts.length
            ? facts.join(' · ')
            : 'The final digest is recorded on the approval.'}
        </p>
      ) : (
        rationale && <p className="gate-why">{rationale}</p>
      )}

      {hypothesisId && (
        <p className="gate-meta-line">
          <span className="mono gate-meta-label">Hypothesis</span>{' '}
          <span className="mono">{String(hypothesisId)}</span>
        </p>
      )}

      {expectedObservation && (
        <p className="gate-meta-line">
          <span className="mono gate-meta-label">Expected observation</span>{' '}
          <span>{String(expectedObservation)}</span>
        </p>
      )}

      {wouldFalsify && (
        <p className="gate-meta-line">
          <span className="mono gate-meta-label">Would falsify</span>{' '}
          <span>{String(wouldFalsify)}</span>
        </p>
      )}

      {evidenceIds.length > 0 && (
        <div className="gate-meta-line">
          <span className="mono gate-meta-label">Evidence</span>
          {evidenceIds.map((id) => (
            <span
              key={id}
              className="evidence-chip"
              onClick={() => {}}
              title={`Evidence #${id}`}
            >
              #{id}
            </span>
          ))}
        </div>
      )}

      {plan.length > 1 && (
        <ol className="gate-plan">
          {plan.map((step) => (
            <li key={`${step.action}-${step.target}`}>
              <span className="mono">{actionLabel(step.action)}</span>
              <span className="mono">{step.target}</span>
              {step.rationale && <p>{step.rationale}</p>}
            </li>
          ))}
        </ol>
      )}

      {approval.argv.length > 0 && (
        <div className="gate-argv-wrap">
          <pre className="gate-argv" aria-label="Exact command">
            <span className="gate-prompt">$</span>{' '}
            <span className="gate-verb">{approval.argv[0]}</span>{' '}
            {approval.argv.slice(1).join(' ')}
          </pre>
          <button
            type="button"
            className="copy-argv"
            onClick={copyArgv}
            aria-label="Copy command"
            disabled={busy}
          >
            <Copy size={18} strokeWidth={1.5} aria-hidden="true" />
          </button>
        </div>
      )}

      {!pending && (
        <p className="gate-outcome">
          {approval.decision === 'approved' ? 'Approved' : 'Rejected'}
          {approval.actor ? ` by ${approval.actor}` : ''}
          {approval.reason ? ` — ${approval.reason}` : ''}
        </p>
      )}

      {pending && !gateOpen && (
        <p className="gate-hint">
          The role is still working. This gate opens when its turn ends.
        </p>
      )}

      {pending && gateOpen && (
        <div className="gate-actions">
          <button
            type="button"
            className="btn btn-primary btn-small"
            onClick={() => onDecision('approved', reason)}
            disabled={!canDecide}
          >
            {busy ? 'Submitting…' : 'Approve'}
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-small"
            onClick={() => onDecision('rejected', reason)}
            disabled={!canDecide}
          >
            Reject
          </button>
          <span className="gate-hint">
            Approving runs this exact command once.
          </span>
        </div>
      )}

      {pending && gateOpen && !settled && !busy && (
        <div className="gate-reason">
          <label className="sr-only" htmlFor={`approval-reason-${approval.id}`}>
            Reason for decision
          </label>
          <textarea
            id={`approval-reason-${approval.id}`}
            className="gate-reason-input"
            rows={2}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason for your decision (e.g. why rejected or guidance)…"
            maxLength={500}
          />
        </div>
      )}
    </article>
  )
}

function FindingCard({
  finding,
  evidence,
}: {
  finding: Finding
  evidence: Evidence[]
}) {
  const first = evidence[0]

  return (
    <article className="finding-card">
      <header className="finding-card-head">
        <SeverityMark severity={finding.severity} />
        <span className="finding-card-status mono">{finding.status}</span>
      </header>

      <h3>{finding.title}</h3>
      <p className="finding-card-where mono">
        {finding.asset}
        {finding.endpoint ?? ''} · {finding.confidence.toFixed(2)} confidence
      </p>

      {first?.excerpt ? (
        <blockquote className="finding-card-excerpt">
          {first.excerpt.length > 280
            ? `${first.excerpt.slice(0, 280)}…`
            : first.excerpt}
        </blockquote>
      ) : (
        <p className="finding-card-empty">
          No evidence excerpt is attached to this finding.
        </p>
      )}

      {evidence.length > 1 && (
        <details className="turn-details">
          <summary>
            {evidence.length} evidence row{evidence.length === 1 ? '' : 's'}
          </summary>
          <ul className="evidence-locators">
            {evidence.map((row) => (
              <li key={row.id}>
                <span className="mono">
                  {String(row.locator.tool ?? 'evidence')} · #{row.id}
                </span>
                <pre>{JSON.stringify(row.locator, null, 2)}</pre>
              </li>
            ))}
          </ul>
        </details>
      )}
    </article>
  )
}

function ReportTurn({ detail }: { detail: AssessmentDetail }) {
  return (
    <article className="report-card">
      <header>
        <span className="turn-square" aria-hidden="true" />
        <h3>Report written</h3>
        <StatusMark status={detail.status} />
      </header>
      <p className="report-card-path mono">{detail.report_path}</p>
      <p className="report-card-hash mono">
        sha256 {shortHash(detail.report_sha256, 20)}
      </p>
      <a
        className="report-link"
        href={`/api/assessments/${detail.id}/report`}
        download
      >
        Download report
      </a>
    </article>
  )
}

function NoteTurn({
  entry,
}: {
  entry: Extract<ThreadEntry, { kind: 'note' }>
}) {
  return (
    <p className="turn-note" data-error={entry.error}>
      <time className="mono" dateTime={entry.at}>
        {formatClock(entry.at)}
      </time>
      <span>{entry.text}</span>
    </p>
  )
}

function suggestionsFor(mission: MissionView): string[] {
  if (mission.pendingApproval) {
    return ['Explain this gate', 'What is left?', 'What happens if I reject?']
  }
  if (mission.running) {
    return ['What is the status?', 'Why this step?', 'Stop after this step']
  }
  if (mission.counts.total > 0) {
    return [
      'Summarize the findings',
      'What should I fix first?',
      'What is still unverified?',
    ]
  }
  return [
    'Pick one Juice Shop challenge and make it happen',
    'Map the target before choosing a challenge',
    'What will you do first?',
  ]
}

export function MissionConversation({
  detail,
  mission,
  messages,
  busy,
  gateOpen,
  settledApprovalId,
  scanning,
  onSend,
  onDecision,
  onRun,
  onStop,
  onScan,
}: {
  detail: AssessmentDetail
  mission: MissionView
  messages: LocalMessage[]
  busy: boolean
  gateOpen: boolean
  settledApprovalId: number | null
  scanning: boolean
  onSend: (text: string) => void
  onDecision: (decision: 'approved' | 'rejected', reason?: string) => void
  onRun: () => void
  onStop?: () => void
  onScan: () => void
}) {
  const [draft, setDraft] = useState('')
  const threadRef = useRef<HTMLDivElement>(null)

  const entries = useMemo(() => {
    const localOperator = new Set(
      messages
        .filter((message) => message.role === 'operator')
        .map((message) => message.text.trim()),
    )
    const localEntries: ThreadEntry[] = messages.map((message) =>
      message.role === 'operator'
        ? {
            kind: 'operator',
            id: message.id,
            at: message.at,
            text: message.text,
          }
        : {
            kind: 'assistant',
            id: message.id,
            at: message.at,
            text: message.text,
          },
    )
    const server = buildThread(detail, mission).filter(
      (entry) =>
        entry.kind !== 'operator' || !localOperator.has(entry.text.trim()),
    )
    return [...server, ...localEntries].sort((a, b) => {
      const left = Date.parse(a.at)
      const right = Date.parse(b.at)
      return (
        (Number.isFinite(left) ? left : 0) -
        (Number.isFinite(right) ? right : 0)
      )
    })
  }, [detail, mission, messages])

  const scrollToBottom = () => {
    const node = threadRef.current
    if (node) node.scrollTop = node.scrollHeight
  }

  // New message arrived (optimistic or via SSE): follow the thread to the bottom.
  useEffect(() => {
    scrollToBottom()
  }, [entries.length, messages.length, detail.status, mission.pendingApproval?.id])

  // Keep the thread scrolled while the run is actively submitting.
  useEffect(() => {
    if (busy) scrollToBottom()
  }, [busy])

  function submit(event?: FormEvent) {
    event?.preventDefault()
    const text = draft.trim()
    if (!text || busy) return
    onSend(text)
    setDraft('')
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (
      event.key === 'Enter' &&
      !event.shiftKey &&
      !event.nativeEvent.isComposing
    ) {
      event.preventDefault()
      submit()
    }
  }

  const suggestions = suggestionsFor(mission)
  const placeholder = mission.pendingApproval
    ? 'Ask about the open gate'
    : mission.running
      ? 'Ask for status or explain a step'
      : mission.runId
        ? 'Ask for a summary or start again'
        : 'Set the goal for this run'

  return (
    <section className="conversation" aria-label="Mission conversation">
      <header className="conversation-head">
        <div className="conversation-title-row">
          <h1>{detail.title}</h1>
          <StatusMark status={detail.status} />
        </div>

        <p className="conversation-objective">
          {detail.request || 'No objective recorded for this mission.'}
        </p>

        <dl className="conversation-meta">
          <div>
            <dt>Mission</dt>
            <dd className="mono">#{pad(detail.id)}</dd>
          </div>
          <div>
            <dt>Target</dt>
            <dd className="mono">{detail.targets.join(' · ') || 'none'}</dd>
          </div>
          <div>
            <dt>Ports</dt>
            <dd className="mono">
              {detail.ports.length ? detail.ports.join(', ') : 'default'}
            </dd>
          </div>
          <div>
            <dt>Risk</dt>
            <dd className="mono">
              {detail.risk_score === null
                ? 'not scored'
                : `${detail.risk_score.toFixed(1)} / 10`}
            </dd>
          </div>
          <div>
            <dt>Opened</dt>
            <dd className="mono">{formatDate(detail.created_at)}</dd>
          </div>
        </dl>

        <div className="conversation-actions">
          <div className="conversation-buttons">
            <button
              type="button"
              className="btn btn-primary btn-small"
              onClick={onRun}
              disabled={mission.running || busy}
            >
              {mission.running
                ? 'Run in progress'
                : mission.runId
                  ? 'Run again'
                  : 'Begin recon'}
            </button>
            {mission.running && (
              <button
                type="button"
                className="btn btn-oxide btn-small"
                onClick={onStop}
                disabled={busy}
              >
                Stop run
              </button>
            )}
            <button
              type="button"
              className="btn btn-ghost btn-small"
              onClick={onScan}
              disabled={busy || mission.running}
            >
              {scanning ? 'nmap running…' : 'Manual nmap'}
            </button>
          </div>
          <p className="conversation-hint">
            {mission.pendingApproval
              ? 'Gate open below. Nothing runs until you decide.'
              : mission.running
                ? 'Roles are working. The next gate appears in the thread.'
                : mission.runId
                  ? 'Run closed. Start again to re-open the service surface.'
                  : 'Recon starts with nmap, then hands the surface to discovery.'}
          </p>
        </div>
      </header>

      <div
        className="thread-scroll"
        ref={threadRef}
        role="log"
        aria-label="Mission messages and evidence"
      >
        {entries.map((entry) => {
          switch (entry.kind) {
            case 'operator':
              return <OperatorTurn key={entry.id} entry={entry} />
            case 'assistant':
              return <AssistantTurn key={entry.id} entry={entry} />
            case 'role':
              return <RoleTurn key={entry.id} entry={entry} />
            case 'handoff':
              return <HandoffTurn key={entry.id} handoff={entry.handoff} />
            case 'approval':
              return (
                <div className="gate-wrap" key={entry.id}>
                  <ApprovalCard
                    approval={entry.approval}
                    busy={busy}
                    gateOpen={
                      gateOpen && mission.pendingApproval?.id === entry.approval.id
                    }
                    settled={
                      settledApprovalId !== null &&
                      settledApprovalId === entry.approval.id
                    }
                    onDecision={onDecision}
                  />
                </div>
              )
            case 'finding':
              return (
                <div className="finding-wrap" key={entry.id}>
                  <FindingCard
                    finding={entry.finding}
                    evidence={entry.evidence}
                  />
                </div>
              )
            case 'report':
              return <ReportTurn key={entry.id} detail={entry.detail} />
            case 'note':
              return <NoteTurn key={entry.id} entry={entry} />
          }
        })}

        {busy && (
          <p className="desk-working" role="status">
            <span className="desk-working-mark" aria-hidden="true" />
            Submitting to the desk…
          </p>
        )}
      </div>

      <div className="composer">
        <div className="suggestions" aria-label="Suggested prompts">
          {suggestions.map((suggestion) => (
            <button
              key={suggestion}
              type="button"
              className="suggestion"
              onClick={() => onSend(suggestion)}
              disabled={busy}
            >
              {suggestion}
            </button>
          ))}
        </div>

        <form className="composer-form" onSubmit={submit}>
          <label className="sr-only" htmlFor="composer-input">
            Message the desk
          </label>
          <textarea
            id="composer-input"
            rows={1}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            spellCheck={false}
          />
          <button
            type="submit"
            className="composer-send"
            disabled={busy || !draft.trim()}
            aria-label="Send message"
            title="Send message"
          >
            <ArrowUp size={18} strokeWidth={1.5} aria-hidden="true" />
          </button>
        </form>

        <div className="composer-foot">
          <span>Enter to send · Shift+Enter for a new line</span>
          <span>
            {mission.pendingApproval
              ? 'Decision required'
              : mission.running
                ? 'Run active'
                : 'Desk ready'}
          </span>
        </div>
      </div>
    </section>
  )
}
