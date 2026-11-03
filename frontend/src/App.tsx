import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  createAssessment,
  getAssessment,
  listAssessments,
  runScan,
  type Assessment,
  type AssessmentDetail,
} from './lib/api'
import { useSelected } from './store'

const STATUS_STYLES: Record<string, string> = {
  draft: 'bg-slate-700 text-slate-200',
  planning: 'bg-amber-500/20 text-amber-300',
  awaiting_plan: 'bg-amber-500/20 text-amber-300',
  running: 'bg-sky-500/20 text-sky-300',
  awaiting_approval: 'bg-amber-500/20 text-amber-300',
  completed: 'bg-emerald-500/20 text-emerald-300',
  failed: 'bg-rose-500/20 text-rose-300',
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'text-rose-400',
  high: 'text-orange-400',
  medium: 'text-amber-300',
  low: 'text-sky-300',
  info: 'text-slate-400',
}

function Pill({ label, styles }: { label: string; styles: string }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${styles}`}>
      {label}
    </span>
  )
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <h2 className="mb-3 text-xs font-semibold tracking-widest text-slate-400 uppercase">
        {title}
      </h2>
      {children}
    </section>
  )
}

export default function App() {
  const selectedId = useSelected((state) => state.selectedId)
  const select = useSelected((state) => state.select)

  const [items, setItems] = useState<Assessment[]>([])
  const [detail, setDetail] = useState<AssessmentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [scanning, setScanning] = useState(false)

  const [title, setTitle] = useState('Local lab VAPT')
  const [target, setTarget] = useState('127.0.0.1')
  const [ports, setPorts] = useState('3000,8080')

  const refresh = useCallback(async () => {
    try {
      setItems(await listAssessments())
    } catch (cause) {
      setError(String(cause))
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    if (selectedId === null) {
      setDetail(null)
      return
    }
    getAssessment(selectedId)
      .then(setDetail)
      .catch(() => {
        select(null)
        setDetail(null)
      })
  }, [selectedId, select])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSaving(true)
    try {
      const created = await createAssessment({
        title,
        request: '',
        targets: [target],
        ports: ports
          .split(',')
          .map((port) => Number(port.trim()))
          .filter((port) => Number.isInteger(port)),
      })
      select(created.id)
      await refresh()
    } catch (cause) {
      setError(String(cause))
    } finally {
      setSaving(false)
    }
  }

  async function scanNow() {
    if (detail === null) return
    setError(null)
    setScanning(true)
    try {
      await runScan(detail.id)
      setDetail(await getAssessment(detail.id))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setScanning(false)
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 px-4 py-8 text-slate-100">
      <div className="mx-auto max-w-6xl">
        <header className="mb-6 flex items-baseline justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">AIPENT</h1>
            <p className="text-sm text-slate-400">Authorized local lab assessments only</p>
          </div>
          <span className="text-xs text-slate-500">{items.length} assessment(s)</span>
        </header>

        {error && (
          <p className="mb-4 rounded-lg border border-rose-800 bg-rose-950/50 px-3 py-2 text-sm text-rose-300">
            {error}
          </p>
        )}

        <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
          <div className="space-y-4">
            <Card title="New assessment">
              <form onSubmit={submit} className="space-y-3">
                <label className="block text-sm">
                  <span className="mb-1 block text-slate-400">Title</span>
                  <input
                    required
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
                  />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-slate-400">Target</span>
                  <input
                    required
                    value={target}
                    onChange={(event) => setTarget(event.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
                  />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-slate-400">Ports</span>
                  <input
                    value={ports}
                    onChange={(event) => setPorts(event.target.value)}
                    placeholder="3000,8080"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
                  />
                </label>
                <button
                  type="submit"
                  disabled={saving}
                  className="w-full rounded-lg bg-sky-600 px-3 py-2 text-sm font-semibold hover:bg-sky-500 disabled:opacity-50"
                >
                  {saving ? 'Creating…' : 'Create assessment'}
                </button>
              </form>
            </Card>

            <Card title="Assessments">
              {items.length === 0 ? (
                <p className="text-sm text-slate-500">Nothing yet.</p>
              ) : (
                <ul className="space-y-1">
                  {items.map((item) => (
                    <li key={item.id}>
                      <button
                        onClick={() => select(item.id)}
                        className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm hover:bg-slate-800 ${
                          item.id === selectedId ? 'bg-slate-800' : ''
                        }`}
                      >
                        <span className="truncate">
                          #{item.id} {item.title}
                        </span>
                        <Pill
                          label={item.status}
                          styles={STATUS_STYLES[item.status] ?? 'bg-slate-700 text-slate-200'}
                        />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <div className="space-y-4">
            {detail === null ? (
              <Card title="Detail">
                <p className="text-sm text-slate-500">Select an assessment.</p>
              </Card>
            ) : (
              <>
                <Card title="Assessment">
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="text-lg font-semibold">
                      #{detail.id} {detail.title}
                    </h3>
                    <Pill
                      label={detail.status}
                      styles={STATUS_STYLES[detail.status] ?? 'bg-slate-700 text-slate-200'}
                    />
                  </div>
                  <p className="mt-2 text-sm text-slate-400">
                    {detail.targets.join(', ')} · ports{' '}
                    {detail.ports.length ? detail.ports.join(', ') : 'all'}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    created {new Date(detail.created_at).toLocaleString()}
                  </p>
                  <button
                    onClick={scanNow}
                    disabled={scanning}
                    className="mt-3 rounded-lg border border-sky-700 bg-sky-600/20 px-3 py-1.5 text-sm font-medium text-sky-300 hover:bg-sky-600/30 disabled:opacity-50"
                  >
                    {scanning ? 'Scanning…' : 'Run nmap'}
                  </button>
                </Card>

                <Card title={`Steps (${detail.steps.length})`}>
                  {detail.steps.length === 0 ? (
                    <p className="text-sm text-slate-500">No steps planned yet.</p>
                  ) : (
                    <table className="w-full text-left text-sm">
                      <thead className="text-xs text-slate-500 uppercase">
                        <tr>
                          <th className="pb-2">#</th>
                          <th className="pb-2">Action</th>
                          <th className="pb-2">Status</th>
                          <th className="pb-2">Command</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {detail.steps.map((step) => (
                          <tr key={step.id}>
                            <td className="py-2 text-slate-500">{step.seq}</td>
                            <td className="py-2">{step.action}</td>
                            <td className="py-2">
                              <Pill label={step.status} styles="bg-slate-800 text-slate-300" />
                            </td>
                            <td className="truncate py-2 font-mono text-xs text-slate-400">
                              {step.argv.join(' ')}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </Card>

                <Card title={`Findings (${detail.findings.length})`}>
                  {detail.findings.length === 0 ? (
                    <p className="text-sm text-slate-500">No findings recorded.</p>
                  ) : (
                    <ul className="divide-y divide-slate-800">
                      {detail.findings.map((finding) => (
                        <li key={finding.id} className="flex items-center justify-between py-2 text-sm">
                          <span>
                            <span className={SEVERITY_STYLES[finding.severity] ?? 'text-slate-300'}>
                              {finding.severity.toUpperCase()}
                            </span>{' '}
                            {finding.title}
                            <span className="ml-2 text-xs text-slate-500">
                              {finding.asset}
                              {finding.endpoint ? ` ${finding.endpoint}` : ''}
                            </span>
                          </span>
                          <span className="text-xs text-slate-500">{finding.status}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>

                <Card title="Audit">
                  {detail.audit.length === 0 ? (
                    <p className="text-sm text-slate-500">No events.</p>
                  ) : (
                    <ul className="space-y-1 font-mono text-xs text-slate-400">
                      {detail.audit.slice(0, 8).map((event) => (
                        <li key={event.id}>
                          {new Date(event.ts).toLocaleTimeString()} {event.event_type}{' '}
                          <span className="text-slate-600">
                            {JSON.stringify(event.payload)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
              </>
            )}
          </div>
        </div>
      </div>
    </main>
  )
}
