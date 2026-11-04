import { useEffect, useState } from 'react'
import { AssessmentHeader } from './components/AssessmentHeader'
import { AssessmentRail } from './components/AssessmentRail'
import { ApprovalPanel, ReportPanel, ScopePanel, SignalsPanel } from './components/DetailPanels'
import { FindingLedger } from './components/FindingLedger'
import { StepThread } from './components/StepThread'
import { TopBar } from './components/TopBar'
import { useAssessmentStream } from './hooks/useAssessmentStream'
import {
  createAssessment,
  getAssessment,
  listAssessments,
  resumeAgent,
  runAgent,
  runScan,
} from './lib/api'
import type { Assessment, AssessmentInput } from './lib/schemas'
import { useSelected } from './store'

function EmptyWorkspace() {
  return (
    <div className="empty-workspace">
      <p className="empty-index mono">00</p>
      <h1>Open an assessment.</h1>
      <p className="empty-lead">
        AIPENT plans and runs an authorized VAPT, keeps every command and artifact, and
        streams the run to this desk as it happens.
      </p>
      <dl className="empty-facts">
        <div>
          <dt>Tool trio</dt>
          <dd>nmap, Nikto, OWASP ZAP</dd>
        </div>
        <div>
          <dt>Control</dt>
          <dd>hard scope bounds and human gates</dd>
        </div>
        <div>
          <dt>Record</dt>
          <dd>evidence, SHA-256, audit trail</dd>
        </div>
      </dl>
    </div>
  )
}

function LoadingWorkspace() {
  return (
    <div className="loading-workspace" role="status">
      <p className="mono">Opening stream</p>
      <span className="loading-rule" aria-hidden="true" />
    </div>
  )
}

export default function App() {
  const selectedId = useSelected((state) => state.selectedId)
  const select = useSelected((state) => state.select)

  const [items, setItems] = useState<Assessment[]>([])
  const [listError, setListError] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [agentBusy, setAgentBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const stream = useAssessmentStream(selectedId)
  const detail = stream.detail
  const pendingGate = Boolean(
    detail?.approvals.some((approval) => approval.decision === 'pending'),
  )

  useEffect(() => {
    listAssessments()
      .then(setItems)
      .catch((cause: unknown) => {
        setListError(cause instanceof Error ? cause.message : String(cause))
      })
  }, [])

  useEffect(() => {
    if (items.length === 0) return
    if (selectedId === null || !items.some((item) => item.id === selectedId)) {
      select(items[0].id)
    }
  }, [items, selectedId, select])

  useEffect(() => {
    if (!detail) return
    setItems((current) =>
      current.map((item) =>
        item.id === detail.id
          ? { ...item, status: detail.status, finished_at: detail.finished_at }
          : item,
      ),
    )
  }, [detail?.id, detail?.status, detail?.finished_at])

  async function handleCreate(input: AssessmentInput) {
    setActionError(null)
    const created = await createAssessment(input)
    setItems(await listAssessments())
    select(created.id)
  }

  async function handleScan() {
    if (!detail) return
    setActionError(null)
    setScanning(true)
    try {
      const updated = await runScan(detail.id)
      stream.replace(updated)
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setScanning(false)
    }
  }

  async function handleRunAgent() {
    if (!detail) return
    setActionError(null)
    setAgentBusy(true)
    try {
      await runAgent(detail.id)
      stream.replace(await getAssessment(detail.id))
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setAgentBusy(false)
    }
  }

  async function handleDecision(decision: 'approved' | 'rejected') {
    if (!detail) return
    setActionError(null)
    setAgentBusy(true)
    try {
      await resumeAgent(detail.id, {
        decision,
        actor: 'analyst',
        reason: decision === 'approved' ? 'Approved from the dashboard' : 'Rejected from the dashboard',
      })
      stream.replace(await getAssessment(detail.id))
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setAgentBusy(false)
    }
  }

  const error = actionError ?? stream.error ?? listError

  return (
    <div className="app">
      <TopBar
        connection={stream.connection}
        lastEventAt={stream.lastEventAt}
        rejected={stream.rejected}
      />

      <div className="frame">
        <AssessmentRail
          items={items}
          selectedId={selectedId}
          onSelect={select}
          onCreate={handleCreate}
        />

        <main className="workspace">
          {error && (
            <p className="banner" role="alert">
              {error}
            </p>
          )}

          {selectedId === null ? (
            <EmptyWorkspace />
          ) : !detail ? (
            <LoadingWorkspace />
          ) : (
            <>
              <AssessmentHeader
                detail={detail}
                scanning={scanning}
                agentBusy={agentBusy}
                gatePending={pendingGate}
                onScan={handleScan}
                onRunAgent={handleRunAgent}
              />

              <StepThread steps={detail.steps} />

              <div className="workspace-grid">
                <div className="column-main">
                  <FindingLedger
                    findings={detail.findings}
                    evidence={detail.evidence}
                  />
                </div>

                <aside className="column-side" aria-label="Assessment record">
                  <ScopePanel detail={detail} />
                  <ApprovalPanel
                    approvals={detail.approvals}
                    busy={agentBusy}
                    onDecision={handleDecision}
                  />
                  <ReportPanel detail={detail} />
                  <SignalsPanel audit={detail.audit} recent={stream.recent} />
                </aside>
              </div>

              <footer className="workspace-foot">
                <span>AIPENT · local lab</span>
                <span>streamed from the evidence of record</span>
              </footer>
            </>
          )}
        </main>
      </div>
    </div>
  )
}
