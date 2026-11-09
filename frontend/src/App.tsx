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
  listAssessments,
  listMessages,
  resumeAgent,
  runAgent,
  runScan,
  sendChat,
  stopAgent,
} from './lib/api'
import type { LocalMessage } from './lib/chatStorage'
import { applyTheme, readTheme } from './lib/theme'
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
      if (
        parsed &&
        typeof parsed.detail === 'object' &&
        parsed.detail?.message
      ) {
        return String(parsed.detail.message)
      }
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

/**
 * Reconcile optimistic turns with server rows by client_message_id, then add
 * any server rows this tab has not seen. Used both by the SSE message effect
 * and the REST fallback so both paths are idempotent.
 */
function mergeMessages(
  local: LocalMessage[],
  server: Message[],
): LocalMessage[] {
  const byClient = new Map(
    server
      .filter((m) => m.client_message_id)
      .map((m) => [m.client_message_id as string, m]),
  )
  const next = local
    .filter(
      (m) =>
        !m.id.startsWith('local-') ||
        !byClient.has(m.id.replace('local-', '')),
    )
    .map((m) => {
      if (!m.id.startsWith('local-')) return m
      const match = byClient.get(m.id.replace('local-', ''))
      return match ? toLocalMessage(match) : m
    })
  for (const message of server) {
    if (!next.some((m) => m.id === String(message.id)))
      next.push(toLocalMessage(message))
  }
  return next.sort((a, b) => Date.parse(a.at) - Date.parse(b.at)).slice(-120)
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
  const [settledApprovalId, setSettledApprovalId] = useState<number | null>(null)
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

  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>(() =>
    readTheme(),
  )

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

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

  async function loadChatMessages(assessmentId: number): Promise<Message[]> {
    try {
      return await listMessages(assessmentId)
    } catch {
      return []
    }
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

  // Approval ids are global rows, so a settled id from the previous
  // assessment must not lock a coincidentally matching gate card here.
  useEffect(() => {
    setSettledApprovalId(null)
    setActionError(null)
  }, [selectedId])

  useEffect(() => {
    if (selectedId === null) return
    let cancelled = false
    loadChatMessages(selectedId).then((messages) => {
      if (cancelled) return
      // The SSE stream may already have delivered rows while this request was
      // in flight. Merge instead of replacing so those turns are not lost.
      setChats((prev) => ({
        ...prev,
        [selectedId]: mergeMessages(prev[selectedId] ?? [], messages),
      }))
    })
    return () => {
      cancelled = true
    }
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

  // The stream carries messages from every client. Reconcile optimistic turns
  // and add anything this tab has not seen yet, without waiting for the REST
  // fallback, so a message never appears twice with different ids.
  useEffect(() => {
    if (!detail) return
    setChats((prev) => ({
      ...prev,
      [detail.id]: mergeMessages(prev[detail.id] ?? [], detail.messages),
    }))
  }, [detail?.id, detail?.messages])

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
        }. The first action will appear here for approval.`,
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

  async function handleDecision(
    decision: 'approved' | 'rejected',
    customReason?: string,
  ) {
    if (!detail || resumeRef.current) return
    const pending = mission?.pendingApproval ?? null
    const finalReason =
      customReason?.trim() ||
      (decision === 'approved'
        ? 'Approved from the mission desk'
        : 'Rejected from the mission desk')
    setActionError(null)
    setAgentBusy(true)
    resumeRef.current = true
    try {
      await resumeAgent(detail.id, {
        decision,
        actor: 'analyst',
        reason: finalReason,
        // The backend enforces approval.argv == step.argv integrity when the
        // gate executes, so the human approves exactly what runs. The IDs are
        // echoed for audit traceability; the gate resolves the pending step
        // itself (oldest planned step wins).
        // A synthesized review card has no database row (id 0); the backend
        // resolves the review interrupt without an approval id.
        approval_id: pending && pending.id > 0 ? pending.id : undefined,
        step_id: pending?.step_id ?? undefined,
      })
      if (pending) {
        // The card is settled even if the poll-driven status has not caught up
        // yet. Prevent a second click from racing the resumed graph.
        setSettledApprovalId(pending.id)
      }
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
            ? `Approved ${actionLabel(pending.action)}.${customReason?.trim() ? ` Note: ${customReason.trim()}` : ''} The role will read the observation and continue.`
            : `Rejected ${actionLabel(pending.action)}${customReason?.trim() ? ` (${customReason.trim()})` : ''}. The command will not run; the role will adapt from the refusal.`
          : decision === 'approved'
            ? 'Decision approved. The run will continue.'
            : `Decision rejected${customReason?.trim() ? ` (${customReason.trim()})` : ''}. The run will stop at this gate.`,
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
    if (!detail) return
    const clientId = crypto.randomUUID()
    setChatBusy(true)
    setActionError(null)

    // Optimistic operator turn. The server row replaces it by client_message_id.
    const optimistic: LocalMessage = {
      id: `local-${clientId}`,
      role: 'operator',
      text,
      at: new Date().toISOString(),
    }
    setChats((prev) => ({
      ...prev,
      [detail.id]: [...(prev[detail.id] ?? []), optimistic],
    }))

    try {
      await sendChat(detail.id, { text, client_message_id: clientId })
      // The assistant reply arrives through SSE. Fallback: one fetch after a
      // short delay in case the stream is reconnecting.
      setTimeout(() => {
        listMessages(detail.id)
          .then((messages) => {
            setChats((prev) => ({
              ...prev,
              [detail.id]: mergeMessages(prev[detail.id] ?? [], messages),
            }))
          })
          .catch(() => {})
      }, 1500)
    } catch (cause) {
      setActionError(causeText(cause))
      setChats((prev) => ({
        ...prev,
        [detail.id]: (prev[detail.id] ?? []).filter(
          (m) => m.id !== optimistic.id,
        ),
      }))
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
        theme={theme}
        setTheme={setTheme}
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
                messages={chats[detail.id] ?? []}
                busy={agentBusy || chatBusy}
                gateOpen={
                  mission.gateOpen &&
                  mission.pendingApproval?.id !== settledApprovalId
                }
                settledApprovalId={settledApprovalId}
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
