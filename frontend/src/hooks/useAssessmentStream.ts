import { useCallback, useEffect, useReducer } from 'react'
import { getAssessment } from '../lib/api'
import {
  STREAM_EVENT_TYPES,
  StreamEventSchema,
  applyEvent,
  type StreamConnection,
  type StreamEvent,
} from '../lib/events'
import type { AssessmentDetail } from '../lib/schemas'

type State = {
  detail: AssessmentDetail | null
  connection: StreamConnection
  lastEventAt: number | null
  recent: StreamEvent[]
  rejected: number
  error: string | null
}

type Action =
  | { kind: 'reset' }
  | { kind: 'restore'; detail: AssessmentDetail }
  | { kind: 'replace'; detail: AssessmentDetail }
  | { kind: 'connection'; connection: StreamConnection }
  | { kind: 'event'; event: StreamEvent }
  | { kind: 'rejected'; reason: string }
  | { kind: 'error'; message: string }

const initialState: State = {
  detail: null,
  connection: 'idle',
  lastEventAt: null,
  recent: [],
  rejected: 0,
  error: null,
}

function reducer(state: State, action: Action): State {
  switch (action.kind) {
    case 'reset':
      return initialState

    // The first paint can come from REST; a late response must not overwrite
    // state that the stream has already advanced.
    case 'restore':
      return state.detail ? state : { ...state, detail: action.detail, error: null }

    case 'replace':
      return { ...state, detail: action.detail, error: null }

    case 'connection':
      return { ...state, connection: action.connection }

    case 'event': {
      const event = action.event
      if (event.type === 'heartbeat') {
        return {
          ...state,
          connection: 'live',
          lastEventAt: Date.now(),
        }
      }

      const detail = applyEvent(state.detail, event)
      return {
        ...state,
        detail,
        connection: 'live',
        lastEventAt: Date.now(),
        recent: [
          event,
          ...state.recent.filter((item) => item.type !== 'heartbeat'),
        ].slice(0, 8),
      }
    }

    case 'rejected':
      console.warn('Rejected stream event:', action.reason)
      return { ...state, rejected: state.rejected + 1 }

    case 'error':
      return { ...state, error: action.message, connection: 'error' }
  }
}

/**
 * Opens the replayable event stream for one assessment.
 *
 * EventSource reconnects on its own. Because every connection replays a
 * snapshot first, a reconnect cannot leave the UI with a stale partial view.
 */
export function useAssessmentStream(assessmentId: number | null) {
  const [state, dispatch] = useReducer(reducer, initialState)
  const replace = useCallback(
    (detail: AssessmentDetail) => dispatch({ kind: 'replace', detail }),
    [],
  )

  useEffect(() => {
    dispatch({ kind: 'reset' })
    if (assessmentId === null) return

    let disposed = false
    dispatch({ kind: 'connection', connection: 'connecting' })

    const source = new EventSource(`/api/assessments/${assessmentId}/events`)

    getAssessment(assessmentId)
      .then((detail) => {
        if (!disposed) dispatch({ kind: 'restore', detail })
      })
      .catch((cause: unknown) => {
        if (disposed) return
        const message = cause instanceof Error ? cause.message : String(cause)
        dispatch({ kind: 'error', message })
        source.close()
      })

    const handleNamed = (name: string, raw: MessageEvent) => {
      let json: unknown
      try {
        json = JSON.parse(raw.data)
      } catch {
        dispatch({ kind: 'rejected', reason: `${name}: invalid JSON` })
        return
      }

      const parsed = StreamEventSchema.safeParse(json)
      if (!parsed.success) {
        dispatch({
          kind: 'rejected',
          reason: `${name}: ${parsed.error.issues[0]?.message ?? 'schema mismatch'}`,
        })
        return
      }

      if (parsed.data.type !== name) {
        dispatch({
          kind: 'rejected',
          reason: `${name}: envelope says ${parsed.data.type}`,
        })
        return
      }

      dispatch({ kind: 'event', event: parsed.data })
    }

    const listeners = STREAM_EVENT_TYPES.filter((name) => name !== 'error').map((name) => {
      const listener = (event: Event) => {
        if (event instanceof MessageEvent) handleNamed(name, event)
      }
      source.addEventListener(name, listener)
      return [name, listener] as const
    })

    const onOpen = () => dispatch({ kind: 'connection', connection: 'live' })

    // An SSE event named "error" also lands here; only a non-message event is
    // a transport failure.
    const onError = (event: Event) => {
      if (event instanceof MessageEvent && typeof event.data === 'string') {
        handleNamed('error', event)
        return
      }
      dispatch({
        kind: 'connection',
        connection: source.readyState === EventSource.CLOSED ? 'error' : 'reconnecting',
      })
    }

    source.addEventListener('open', onOpen)
    source.addEventListener('error', onError)

    return () => {
      disposed = true
      for (const [name, listener] of listeners) source.removeEventListener(name, listener)
      source.removeEventListener('open', onOpen)
      source.removeEventListener('error', onError)
      source.close()
    }
  }, [assessmentId])

  return { ...state, replace }
}
