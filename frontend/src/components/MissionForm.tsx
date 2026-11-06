import { useState, type FormEvent } from 'react'
import { cx } from '../lib/format'
import type { AssessmentInput } from '../lib/schemas'

const DEFAULT_GOAL = 'Pick one Juice Shop challenge and make it happen'

export function MissionForm({
  onCreate,
  compact = false,
  autoFocus = false,
}: {
  onCreate: (input: AssessmentInput) => Promise<void>
  compact?: boolean
  autoFocus?: boolean
}) {
  const [goal, setGoal] = useState(DEFAULT_GOAL)
  const [target, setTarget] = useState('127.0.0.1')
  const [ports, setPorts] = useState('3000')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    const objective = goal.trim()
    if (!objective) {
      setError('Name the objective for this mission.')
      return
    }

    const parsedPorts = ports
      .split(',')
      .map((port) => port.trim())
      .filter(Boolean)
      .map(Number)

    if (
      parsedPorts.some(
        (port) => !Number.isInteger(port) || port < 1 || port > 65535,
      )
    ) {
      setError('Ports must be whole numbers between 1 and 65535.')
      return
    }

    setSaving(true)
    try {
      await onCreate({
        title: objective.replace(/\s+/g, ' ').slice(0, 72),
        request: objective,
        targets: [target.trim()],
        ports: parsedPorts,
      })
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setSaving(false)
    }
  }

  return (
    <form
      className={cx('mission-form', compact && 'mission-form-compact')}
      onSubmit={submit}
    >
      <label className="field">
        <span>Objective</span>
        <textarea
          required
          rows={compact ? 2 : 3}
          value={goal}
          onChange={(event) => setGoal(event.target.value)}
          placeholder={DEFAULT_GOAL}
          autoFocus={autoFocus}
        />
      </label>

      <div className="field-row">
        <label className="field">
          <span>Target</span>
          <input
            required
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="127.0.0.1"
            spellCheck={false}
          />
        </label>
        <label className="field field-ports">
          <span>Ports</span>
          <input
            value={ports}
            onChange={(event) => setPorts(event.target.value)}
            placeholder="3000, 8080"
            inputMode="numeric"
            spellCheck={false}
          />
        </label>
      </div>

      <div className="form-foot">
        <button type="submit" className="btn btn-primary" disabled={saving}>
          {saving ? 'Opening…' : 'Open mission'}
        </button>
        <p className="form-note">
          The objective is the operator’s first message. Scope bounds every
          action.
        </p>
      </div>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </form>
  )
}
