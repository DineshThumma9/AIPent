import type { Message } from './schemas'
import type { LocalMessage } from './chatStorage'

export function toLocalMessage(message: Message): LocalMessage {
  return {
    id: String(message.id),
    role: message.role as LocalMessage['role'],
    text: message.text,
    at: message.created_at,
  }
}

/**
 * Reconcile optimistic turns with server rows by client_message_id, deduplicate
 * any redundant local turns, and add any server rows this tab has not seen.
 * Used both by the SSE message effect, pushMessage, and the REST fallback
 * so all paths are idempotent and duplicate-free.
 */
export function mergeMessages(
  local: LocalMessage[],
  server: Message[],
): LocalMessage[] {
  const byClient = new Map(
    server
      .filter((m) => m.client_message_id)
      .map((m) => [m.client_message_id as string, m]),
  )
  const seenIds = new Set<string>()
  const next: LocalMessage[] = []

  for (const m of local) {
    if (m.id.startsWith('local-')) {
      const clientId = m.id.replace('local-', '')
      if (!byClient.has(clientId) && !seenIds.has(m.id)) {
        seenIds.add(m.id)
        next.push(m)
      }
    } else if (!seenIds.has(m.id)) {
      seenIds.add(m.id)
      next.push(m)
    }
  }

  for (const message of server) {
    const idStr = String(message.id)
    if (!seenIds.has(idStr)) {
      seenIds.add(idStr)
      next.push(toLocalMessage(message))
    }
  }

  return next.sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0)).slice(-120)
}
