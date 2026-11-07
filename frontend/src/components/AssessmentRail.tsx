import { PanelLeftClose, PanelLeftOpen, Plus } from 'lucide-react'
import { pad } from '../lib/format'
import type { Assessment, AssessmentInput } from '../lib/schemas'
import { MissionForm } from './MissionForm'
import { StatusMark } from './StatusMark'

export function AssessmentRail({
  items,
  selectedId,
  collapsed = false,
  onToggleCollapse,
  onSelect,
  onCreate,
}: {
  items: Assessment[]
  selectedId: number | null
  collapsed?: boolean
  onToggleCollapse?: () => void
  onSelect: (id: number) => void
  onCreate: (input: AssessmentInput) => Promise<void>
}) {
  if (collapsed) {
    return (
      <aside className="rail rail-collapsed" aria-label="Missions">
        <div className="rail-collapsed-content">
          <button
            type="button"
            className="rail-toggle-btn"
            onClick={onToggleCollapse}
            title="Expand mission rail"
            aria-label="Expand mission rail"
          >
            <PanelLeftOpen size={16} strokeWidth={1.5} />
          </button>

          <span
            className="rail-collapsed-count mono"
            title={`${items.length} missions`}
          >
            {pad(items.length)}
          </span>

          <div className="rail-collapsed-list">
            {items.map((item) => (
              <button
                key={item.id}
                type="button"
                className="rail-collapsed-item"
                onClick={() => onSelect(item.id)}
                aria-current={item.id === selectedId ? 'true' : undefined}
                title={`#${pad(item.id)}: ${item.title} (${item.status})`}
              >
                <span className="mono">#{pad(item.id)}</span>
                <span className={`status-dot status-dot-${item.status}`} aria-hidden="true" />
              </button>
            ))}
          </div>

          <button
            type="button"
            className="rail-collapsed-new"
            onClick={onToggleCollapse}
            title="New mission (expand rail)"
            aria-label="New mission"
          >
            <Plus size={14} strokeWidth={1.5} />
          </button>
        </div>
      </aside>
    )
  }

  return (
    <aside className="rail" aria-label="Missions">
      <div className="rail-head">
        <div className="rail-head-left">
          <h2>Missions</h2>
          <span className="rail-count mono">{pad(items.length)}</span>
        </div>
        {onToggleCollapse && (
          <button
            type="button"
            className="rail-toggle-btn"
            onClick={onToggleCollapse}
            title="Collapse mission rail"
            aria-label="Collapse mission rail"
          >
            <PanelLeftClose size={15} strokeWidth={1.5} />
          </button>
        )}
      </div>

      {/* New mission at the top */}
      <details className="new-assessment" open={items.length === 0}>
        <summary>New mission</summary>
        <MissionForm compact onCreate={onCreate} />
      </details>

      {items.length === 0 ? (
        <p className="rail-empty">No missions yet.</p>
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

      <p className="rail-note">
        Only listed targets are contacted. Every queued action waits for
        approval and is recorded with its command, artifact and SHA-256.
      </p>
    </aside>
  )
}
