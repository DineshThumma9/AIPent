import type { StreamConnection } from '../lib/events'
import { formatClock } from '../lib/format'

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
}: {
  connection: StreamConnection
  lastEventAt: number | null
  rejected: number
}) {
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
    </header>
  )
}
