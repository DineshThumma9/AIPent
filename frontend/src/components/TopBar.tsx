import { Sun, Moon } from 'lucide-react'
import type { StreamConnection } from '../lib/events'
import { formatClock } from '../lib/format'
import { applyTheme, resolvedTheme } from '../lib/theme'

const CONNECTION_LABEL: Record<StreamConnection, string> = {
  idle: 'stream idle',
  connecting: 'stream connecting',
  live: 'stream live',
  reconnecting: 'stream reconnecting',
  error: 'stream offline',
}

export function TopBar({
  connection,
  lastEventAt,
  rejected,
  theme,
  setTheme,
}: {
  connection: StreamConnection
  lastEventAt: number | null
  rejected: number
  theme: 'light' | 'dark' | 'system'
  setTheme: (theme: 'light' | 'dark' | 'system') => void
}) {
  const resolved = resolvedTheme(theme)
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true" />
        <span className="brand-name">AIPENT</span>
        <span className="brand-note">scoped VAPT · authorized lab</span>
      </div>

      <div className="stream" role="status" aria-live="polite">
        <span className="stream-dot" data-connection={connection} aria-hidden="true" />
        <span>{CONNECTION_LABEL[connection]}</span>
        {lastEventAt !== null && (
          <span className="stream-time">
            last event {formatClock(new Date(lastEventAt).toISOString())}
          </span>
        )}
        {rejected > 0 && (
          <span className="stream-rejected" title="Events rejected by the Zod schema">
            {rejected} rejected
          </span>
        )}
      </div>

      <button
        type="button"
        className="btn btn-ghost btn-small"
        onClick={() => {
          const next = resolved === 'dark' ? 'light' : 'dark'
          setTheme(next)
          applyTheme(next)
        }}
        aria-label="Toggle dark mode"
        aria-pressed={resolved === 'dark'}
      >
        {resolved === 'dark' ? (
          <Sun size={18} strokeWidth={1.5} aria-hidden="true" />
        ) : (
          <Moon size={18} strokeWidth={1.5} aria-hidden="true" />
        )}
      </button>
    </header>
  )
}
