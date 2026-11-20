import { useEffect, useState } from 'react'
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

const STALL_MS = 45_000

function formatAge(ms: number): string {
  const seconds = Math.max(1, Math.round(ms / 1000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  if (minutes < 60) return rest ? `${minutes}m ${rest}s` : `${minutes}m`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ${minutes % 60}m`
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
  const [now, setNow] = useState(() => Date.now())

  // Heartbeats update lastEventAt, but a wedged backend stops producing them.
  // Tick locally so the badge can age without waiting for a stream event.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5000)
    return () => window.clearInterval(timer)
  }, [])

  const age = lastEventAt === null ? null : now - lastEventAt
  const stalled =
    connection === 'live' && age !== null && age > STALL_MS
  const label = stalled ? 'stream stalled' : CONNECTION_LABEL[connection]

  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true" />
        <span className="brand-name">AIPENT</span>
        <span className="brand-note">scoped VAPT · authorized lab</span>
      </div>

      <div className="stream" role="status" aria-live="polite">
        <span
          className="stream-dot"
          data-connection={stalled ? 'stalled' : connection}
          aria-hidden="true"
        />
        <span>{label}</span>
        {lastEventAt !== null && (
          <span className="stream-time">
            last event {formatClock(new Date(lastEventAt).toISOString())}
            {stalled && age !== null && ` · ${formatAge(age)} ago`}
          </span>
        )}
        {rejected > 0 && (
          <span
            className="stream-rejected"
            title={`${rejected} events rejected by schema validation; details are logged in the browser console`}
          >
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
