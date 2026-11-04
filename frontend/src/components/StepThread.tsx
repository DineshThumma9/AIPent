import {
  basename,
  formatClock,
  formatDuration,
  pad,
  shortHash,
} from '../lib/format'
import type { Step } from '../lib/schemas'
import { StatusMark } from './StatusMark'

function Ticks({ count = 14 }: { count?: number }) {
  return (
    <span className="ticks" aria-hidden="true">
      {Array.from({ length: count }, (_, index) => (
        <i key={index} />
      ))}
    </span>
  )
}

function StepNode({ step }: { step: Step }) {
  const duration = formatDuration(step.created_at, step.ended_at)

  return (
    <li className="thread-node" data-status={step.status}>
      <div className="thread-body">
        <div className="step-head">
          <span className="step-seq">{pad(step.seq)}</span>
          <h3>{step.action.replaceAll('_', ' ')}</h3>
          <StatusMark status={step.status} />
        </div>

        {step.rationale && <p className="step-why">{step.rationale}</p>}

        <pre className="argv" aria-label="Command executed">
          <span className="argv-prompt">$</span>{' '}
          <span className="argv-verb">{step.argv[0]}</span>{' '}
          {step.argv.slice(1).join(' ')}
        </pre>

        <div className="step-meta">
          <span>
            started <span className="mono">{formatClock(step.created_at)}</span>
          </span>
          {duration && (
            <span>
              took <span className="mono">{duration}</span>
            </span>
          )}
          {step.exit_code !== null && (
            <span>
              exit <span className="mono">{step.exit_code}</span>
            </span>
          )}
          <Ticks />
        </div>

        {step.output_sha256 && (
          <div className="artifact">
            <span className="artifact-label">artifact</span>
            <span className="mono">{basename(step.output_path)}</span>
            <span className="artifact-sep" aria-hidden="true">
              /
            </span>
            <span className="artifact-label">sha256</span>
            <code title={step.output_sha256}>{shortHash(step.output_sha256)}</code>
          </div>
        )}

        {step.error && <p className="step-error">{step.error}</p>}
      </div>
    </li>
  )
}

export function StepThread({ steps }: { steps: Step[] }) {
  return (
    <section className="panel panel-thread" aria-labelledby="thread-title">
      <div className="panel-head">
        <h2 id="thread-title">Run thread</h2>
        <span className="panel-meta">
          {steps.length} {steps.length === 1 ? 'step' : 'steps'}
        </span>
      </div>

      {steps.length === 0 ? (
        <p className="empty">
          No steps yet. Run the scan to open the evidence thread.
        </p>
      ) : (
        <ol className="thread">
          {steps.map((step) => (
            <StepNode key={step.id} step={step} />
          ))}
        </ol>
      )}
    </section>
  )
}
