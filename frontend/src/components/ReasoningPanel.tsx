import type { EvidenceBoard } from '../lib/schemas'
import { MarkdownText } from './MarkdownText'

export function ReasoningPanel({
  board,
}: {
  board: EvidenceBoard
}) {
  return (
    <section className="side-panel" aria-labelledby="reasoning-title">
      <div className="side-head">
        <h2 id="reasoning-title">Reasoning</h2>
        <span className="side-meta mono">
          {board.hypotheses.length} hypotheses
        </span>
      </div>

      {board.hypotheses.length === 0 ? (
        <p className="side-empty">
          No hypothesis yet. Recon records one when a service fact needs testing.
        </p>
      ) : (
        <ol className="hypothesis-list">
          {board.hypotheses.map((h) => (
            <li key={h.id} data-status={h.status}>
              <div className="hypothesis-head">
                <span className="mono">{h.id}</span>
                <span className="hypothesis-status">{h.status}</span>
                <span className="mono">{Math.round(h.confidence * 100)}%</span>
              </div>
              <p><MarkdownText text={h.statement} inline /></p>
              <p className="hypothesis-falsifier">
                <span className="mono">falsifier</span> <MarkdownText text={h.falsifier} inline />
              </p>
              {h.evidence_ids.length > 0 && (
                <p className="hypothesis-evidence mono">
                  evidence {h.evidence_ids.join(', ')}
                </p>
              )}
            </li>
          ))}
        </ol>
      )}

      {board.decisions.length > 0 && (
        <details className="side-details">
          <summary>
            Decision trail <span className="mono">{board.decisions.length}</span>
          </summary>
          <ol className="decision-trail">
            {board.decisions.slice(-8).reverse().map((d) => (
              <li key={d.id}>
                <div className="mono">{d.id} · {d.action} · {d.target}</div>
                <p><MarkdownText text={d.observation || d.expected_observation || d.outcome || ''} inline /></p>
                {d.would_falsify && (
                  <p className="mono">would falsify: {d.would_falsify}</p>
                )}
              </li>
            ))}
          </ol>
        </details>
      )}

      {board.open_questions.length > 0 && (
        <details className="side-details">
          <summary>Open questions</summary>
          <ul className="decision-list">
            {board.open_questions.map((q) => <li key={q}>{q}</li>)}
          </ul>
        </details>
      )}
    </section>
  )
}
