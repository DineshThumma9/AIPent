import { useEffect, useMemo, useRef, useState } from 'react'
import { AssessmentRail } from './components/AssessmentRail'
import { BriefWorkspace } from './components/BriefWorkspace'
import { MissionConversation } from './components/MissionConversation'
import { MissionSide } from './components/MissionSide'
import { TopBar } from './components/TopBar'
import { useAssessmentStream } from './hooks/useAssessmentStream'
import {
  createAssessment,
  createMessage,
  getAssessment,
  listAssessments,
  listMessages,
  resumeAgent,
  runAgent,
  runScan,
  stopAgent,
  updateAssessmentRequest,
} from './lib/api'
import {
  classifyIntent,
  explainReply,
  findingsReply,
  statusReply,
  steeringReply,
  stopReply,
} from './lib/chat'
import type { LocalMessage } from './lib/chatStorage'
import { actionLabel, deriveMission } from './lib/mission'
import type { Assessment, AssessmentInput, Message } from './lib/schemas'
import { useSelected } from './store'

function LoadingWorkspace() {
  return (
    <div className="loading-workspace" role="status">
      <p className="mono">Opening mission</p>
      <span className="loading-rule" aria-hidden="true" />
    </div>
  )
}

function causeText(cause: unknown): string {
  if (cause instanceof Error) {
    try {
      const parsed = JSON.parse(cause.message)
      if (parsed && typeof parsed.detail === 'string') {
        return parsed.detail
      }
      if (parsed && typeof parsed.message === 'string') {
        return parsed.message
      }
    } catch {
      // Not JSON, fall through to raw message
    }
    return cause.message
  }
  return String(cause)
}

function toLocalMessage(message: Message): LocalMessage {
  return {
    id: String(message.id),
    role: message.role as LocalMessage['role'],
    text: message.text,
    at: message.created_at,
  }
}

export default function App() {
  const selectedId = useSelected((state) => state.selectedId)
  const select = useSelected((state) => state.select)

  const [items, setItems] = useState<Assessment[]>([])
  const [listError, setListError] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [agentBusy, setAgentBusy] = useState(false)
  const [chatBusy, setChatBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [chats, setChats] = useState<Record<number, LocalMessage[]>>(() =>
    selectedId !== null ? { [selectedId]: [] } : {},
  )
  const [railCollapsed, setRailCollapsed] = useState(() => {
    try {
      return localStorage.getItem('aipent-rail-collapsed') === 'true'
    } catch {
      return false
    }
  })

  function handleToggleRail() {
    setRailCollapsed((prev) => {
      const next = !prev
      try {
        localStorage.setItem('aipent-rail-collapsed', String(next))
      } catch {}
      return next
    })
  }

  const stream = useAssessmentStream(selectedId)
  const detail = stream.detail
  const mission = useMemo(
    () => (detail ? deriveMission(detail) : null),
    [detail],
  )

  async function loadChatMessages(assessmentId: number): Promise<LocalMessage[]> {
    try {
      const messages = await listMessages(assessmentId)
      return messages.map(toLocalMessage)
    } catch {
      return []
    }
  }

  function messagesFor(id: number): LocalMessage[] {
    return chats[id] ?? []
  }

  async function pushMessage(
    assessmentId: number,
    role: LocalMessage['role'],
    text: string,
  ) {
    try {
      const created = await createMessage(assessmentId, { role, text })
      const local = toLocalMessage(created)
      setChats((prev) => {
        const current = prev[assessmentId] ?? []
        const next = [...current, local].slice(-120)
        return { ...prev, [assessmentId]: next }
      })
    } catch (cause) {
      const message = causeText(cause)
      setActionError(message)
    }
  }

  useEffect(() => {
    listAssessments()
      .then(setItems)
      .catch((cause: unknown) => setListError(causeText(cause)))
  }, [])

  useEffect(() => {
    if (items.length === 0) return
    if (selectedId === null || !items.some((item) => item.id === selectedId)) {
      select(items[0].id)
    }
  }, [items, selectedId, select])

  useEffect(() => {
    if (selectedId === null) return
    loadChatMessages(selectedId).then((messages) => {
      setChats((prev) => ({ ...prev, [selectedId]: messages }))
    })
  }, [selectedId])

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
      setActionError(causeText(cause))
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
      // Do not fetch the assessment here. The graph starts in a background
      // task and the first gate may not be reached yet. Let the SSE stream
      // push the updated state as it happens.
      await pushMessage(
        detail.id,
        'assistant',
        `Recon is opening the service surface on ${
          detail.targets.join(', ') || 'the scoped target'
        }. The first queued action will appear here for approval.`,
      )
    } catch (cause) {
      const message = causeText(cause)
      setActionError(message)
      await pushMessage(
        detail.id,
        'assistant',
        `I could not start the run: ${message}. Check that the backend is running, then try again.`,
      )
    } finally {
      setAgentBusy(false)
    }
  }

  async function handleStopAgent() {
    if (!detail) return
    setActionError(null)
    setAgentBusy(true)
    try {
      await stopAgent(detail.id)
      // Do not fetch the assessment here. Let the SSE stream push the
      // updated state as the stop is processed.
      await pushMessage(
        detail.id,
        'assistant',
        'The run was stopped by the operator. No further actions will execute.',
      )
    } catch (cause) {
      const message = causeText(cause)
      setActionError(message)
      await pushMessage(
        detail.id,
        'assistant',
        `I could not stop the run: ${message}.`,
      )
    } finally {
      setAgentBusy(false)
    }
  }

  const resumeRef = useRef(false)

  async function handleDecision(decision: 'approved' | 'rejected') {
    if (!detail || resumeRef.current) return
    const pending = mission?.pendingApproval ?? null
    setActionError(null)
    setAgentBusy(true)
    resumeRef.current = true
    try {
      await resumeAgent(detail.id, {
        decision,
        actor: 'analyst',
        reason:
          decision === 'approved'
            ? 'Approved from the mission desk'
            : 'Rejected from the mission desk',
        // The backend enforces approval.argv == step.argv integrity when the
        // gate executes, so the human approves exactly what runs. The IDs are
        // echoed for audit traceability; the gate resolves the pending step
        // itself (oldest planned step wins).
        approval_id: pending?.id ?? undefined,
        step_id: pending?.step_id ?? undefined,
      })
      // Do not fetch the assessment here. The graph resumes in a background
      // task and the DB may not reflect the new state yet. Let the SSE
      // stream push the updated state (gate, step, report, status) as it
      // happens. Fetching immediately returns stale data and can cause
      // double-submit errors if the user clicks again.
      await pushMessage(
        detail.id,
        'assistant',
        pending
          ? decision === 'approved'
            ? `Approved ${actionLabel(pending.action)}. The role will read the observation and continue.`
            : `Rejected ${actionLabel(pending.action)}. The command will not run; the role will adapt from the refusal.`
          : decision === 'approved'
            ? 'Decision approved. The run will continue.'
            : 'Decision rejected. The run will stop at this gate.',
      )
    } catch (cause) {
      const message = causeText(cause)
      setActionError(message)
      await pushMessage(
        detail.id,
        'assistant',
        `I could not submit that decision: ${message}. Check the stream, then try again.`,
      )
    } finally {
      resumeRef.current = false
      setAgentBusy(false)
    }
  }

  async function handleChat(text: string) {
    if (!detail || !mission) return
    const current = mission
    await pushMessage(detail.id, 'operator', text)

    const intent = classifyIntent(text)

    if (intent === 'stop') {
      await pushMessage(detail.id, 'assistant', stopReply(current))
      return
    }

    if (intent === 'status') {
      await pushMessage(detail.id, 'assistant', statusReply(detail, current))
      return
    }

    if (intent === 'summary') {
      await pushMessage(detail.id, 'assistant', findingsReply(current))
      return
    }

    if (intent === 'explain') {
      await pushMessage(detail.id, 'assistant', explainReply(detail, current))
      return
    }

    if (current.running) {
      await pushMessage(detail.id, 'assistant', steeringReply(current))
      return
    }

    if (intent !== 'start') {
      await pushMessage(detail.id, 'assistant', steeringReply(current))
      return
    }

    setChatBusy(true)
    setActionError(null)
    try {
      await updateAssessmentRequest(detail.id, text)
      const refreshed = await getAssessment(detail.id)
      stream.replace(refreshed)
      await runAgent(detail.id)
      // Do not fetch the assessment here. The graph starts in a background
      // task and the first gate may not be reached yet. Let the SSE stream
      // push the updated state as it happens.
      await pushMessage(
        detail.id,
        'assistant',
        `Recon is opening the service surface on ${
          detail.targets.join(', ') || 'the scoped target'
        }. The first queued action will appear here for approval.`,
      )
    } catch (cause) {
      const message = causeText(cause)
      setActionError(message)
      await pushMessage(
        detail.id,
        'assistant',
        `I could not start the run: ${message}. Check that the backend is running, then try again.`,
      )
    } finally {
      setChatBusy(false)
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

      <div className="frame" data-collapsed={railCollapsed}>
        <AssessmentRail
          items={items}
          selectedId={selectedId}
          collapsed={railCollapsed}
          onToggleCollapse={handleToggleRail}
          onSelect={select}
          onCreate={handleCreate}
        />

        <main className="desk">
          {error && (
            <p className="banner" role="alert">
              {error}
            </p>
          )}

          {selectedId === null ? (
            <BriefWorkspace onCreate={handleCreate} />
          ) : !detail || !mission ? (
            <LoadingWorkspace />
          ) : (
            <div className="desk-grid">
              <MissionConversation
                key={detail.id}
                detail={detail}
                mission={mission}
                messages={messagesFor(detail.id)}
                busy={agentBusy || chatBusy}
                scanning={scanning}
                onSend={handleChat}
                onDecision={handleDecision}
                onRun={handleRunAgent}
                onStop={handleStopAgent}
                onScan={handleScan}
              />
              <MissionSide detail={detail} mission={mission} />
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
