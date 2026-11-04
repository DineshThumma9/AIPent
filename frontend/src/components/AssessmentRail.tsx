import { useState, type FormEvent } from 'react'
import { pad } from '../lib/format'
import type { Assessment, AssessmentInput } from '../lib/schemas'
import { StatusMark } from './StatusMark'

export function AssessmentRail({
  items,
  selectedId,
  onSelect,
  onCreate,
}: {
  items: Assessment[]
  selectedId: number | null
  onSelect: (id: number) => void
  onCreate: (input: AssessmentInput) => Promise<void>
}) {
  const [title, setTitle] = useState('Juice Shop local VAPT')
  const [target, setTarget] = useState('127.0.0.1')
  const [ports, setPorts] = useState('3000')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    const parsedPorts = ports
      .split(',')
      .map((port) => Number(port.trim()))
      .filter((port) => Number.isInteger(port))

    if (parsedPorts.some((port) => port < 1 || port > 65535)) {
      setError('Ports must be 1–65535.')
      return
    }

    setSaving(true)
    try {
      await onCreate({
        title: title.trim(),
        request: '',
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
    <aside className="rail" aria-label="Assessments">
      <div className="rail-head">
        <h2>Assessments</h2>
        <span className="rail-count">{pad(items.length)}</span>
      </div>

      {items.length === 0 ? (
        <p className="rail-empty">No assessments yet.</p>
      ) : (
        <ol className="rail-list">
          {items.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                className="rail-item"
                onClick={() => onSelect(item.id)}
                aria-current={item.id === selectedId ? 'true' : undefined}
              >
                <span className="rail-id">#{pad(item.id)}</span>
                <span className="rail-title">{item.title}</span>
                <StatusMark status={item.status} />
              </button>
            </li>
          ))}
        </ol>
      )}

      <details className="new-assessment" open={items.length === 0}>
        <summary>New assessment</summary>
        <form onSubmit={submit}>
          <label>
            <span>Title</span>
            <input
              required
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Lab assessment"
            />
          </label>

          <div className="field-row">
            <label>
              <span>Target</span>
              <input
                required
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="127.0.0.1"
                spellCheck={false}
              />
            </label>
            <label className="field-ports">
              <span>Ports</span>
              <input
                value={ports}
                onChange={(event) => setPorts(event.target.value)}
                placeholder="3000,8080"
                inputMode="numeric"
                spellCheck={false}
              />
            </label>
          </div>

          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? 'Opening…' : 'Open assessment'}
          </button>
          {error && <p className="form-error">{error}</p>}
        </form>
      </details>

      <p className="rail-note">
        Only listed targets are contacted. Scans are recorded with command, artifact and
        SHA-256.
      </p>
    </aside>
  )
}
