import { describe, it, expect } from 'vitest'
import { mergeMessages, toLocalMessage } from './messages'
import type { Message } from './schemas'
import type { LocalMessage } from './chatStorage'

describe('mergeMessages', () => {
  it('converts a Message to LocalMessage', () => {
    const serverMsg: Message = {
      id: 144,
      assessment_id: 20,
      role: 'assistant',
      text: 'Approved curl request.',
      client_message_id: null,
      created_at: '2026-11-19T12:41:56.912Z',
    }
    const local = toLocalMessage(serverMsg)
    expect(local).toEqual({
      id: '144',
      role: 'assistant',
      text: 'Approved curl request.',
      at: '2026-11-19T12:41:56.912Z',
    })
  })

  it('deduplicates duplicate items in local state (self-healing)', () => {
    const dupLocal: LocalMessage[] = [
      { id: '144', role: 'assistant', text: 'Approved curl request.', at: '2026-11-19T12:41:56.912Z' },
      { id: '144', role: 'assistant', text: 'Approved curl request.', at: '2026-11-19T12:41:56.912Z' },
      { id: '144', role: 'assistant', text: 'Approved curl request.', at: '2026-11-19T12:41:56.912Z' },
    ]
    const merged = mergeMessages(dupLocal, [])
    expect(merged).toHaveLength(1)
    expect(merged[0].id).toBe('144')
  })

  it('prevents duplicate when REST pushMessage and SSE push the same message', () => {
    const existing: LocalMessage[] = [
      { id: '144', role: 'assistant', text: 'Approved curl request.', at: '2026-11-19T12:41:56.912Z' },
    ]
    const sseMessage: Message = {
      id: 144,
      assessment_id: 20,
      role: 'assistant',
      text: 'Approved curl request.',
      client_message_id: null,
      created_at: '2026-11-19T12:41:56.912Z',
    }
    const merged = mergeMessages(existing, [sseMessage])
    expect(merged).toHaveLength(1)
    expect(merged[0].id).toBe('144')
  })

  it('replaces optimistic local message when server message arrives with client_message_id', () => {
    const clientId = 'uuid-1234'
    const optimistic: LocalMessage = {
      id: `local-${clientId}`,
      role: 'operator',
      text: 'Hello assistant',
      at: '2026-11-19T12:40:00.000Z',
    }
    const serverMsg: Message = {
      id: 200,
      assessment_id: 20,
      role: 'operator',
      text: 'Hello assistant',
      client_message_id: clientId,
      created_at: '2026-11-19T12:40:01.000Z',
    }
    const merged = mergeMessages([optimistic], [serverMsg])
    expect(merged).toHaveLength(1)
    expect(merged[0].id).toBe('200')
    expect(merged[0].text).toBe('Hello assistant')
  })

  it('sorts messages chronologically and caps at 120 items', () => {
    const local: LocalMessage[] = [
      { id: '2', role: 'assistant', text: 'Second', at: '2026-11-19T12:00:02.000Z' },
      { id: '1', role: 'operator', text: 'First', at: '2026-11-19T12:00:01.000Z' },
    ]
    const server: Message[] = [
      {
        id: 3,
        assessment_id: 1,
        role: 'assistant',
        text: 'Third',
        client_message_id: null,
        created_at: '2026-11-19T12:00:03.000Z',
      },
    ]
    const merged = mergeMessages(local, server)
    expect(merged.map((m) => m.id)).toEqual(['1', '2', '3'])
  })

  it('keeps ordering deterministic when a timestamp is invalid', () => {
    const local: LocalMessage[] = [
      { id: '2', role: 'assistant', text: 'Second', at: 'not-a-date' },
      { id: '1', role: 'operator', text: 'First', at: '2026-11-19T12:00:01.000Z' },
    ]
    const merged = mergeMessages(local, [])
    expect(merged.map((m) => m.id)).toEqual(['2', '1'])
  })
})
