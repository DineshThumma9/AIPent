import { cx } from '../lib/format'

export function StatusMark({
  status,
  className,
}: {
  status: string
  className?: string
}) {
  return (
    <span className={cx('status', className)} data-status={status}>
      <span className="status-dot" aria-hidden="true" />
      {status.replaceAll('_', ' ')}
    </span>
  )
}

export function SeverityMark({ severity }: { severity: string }) {
  return (
    <span className="severity" data-severity={severity}>
      <span className="severity-dot" aria-hidden="true" />
      {severity}
    </span>
  )
}
