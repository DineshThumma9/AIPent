export type LocalMessage = {
  id: string
  role: 'operator' | 'assistant'
  text: string
  at: string
}

const KEY_PREFIX = 'aipent.chat.v1.'

function storageKey(assessmentId: number): string {
  return `${KEY_PREFIX}${assessmentId}`
}

function isMessage(value: unknown): value is LocalMessage {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return (
    typeof record.id === 'string' &&
    (record.role === 'operator' || record.role === 'assistant') &&
    typeof record.text === 'string' &&
    typeof record.at === 'string'
  )
}

export function loadMessages(assessmentId: number): LocalMessage[] {
  try {
    const raw = localStorage.getItem(storageKey(assessmentId))
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter(isMessage).slice(-120)
  } catch {
    return []
  }
}

export function saveMessages(
  assessmentId: number,
  messages: LocalMessage[],
): void {
  try {
    localStorage.setItem(storageKey(assessmentId), JSON.stringify(messages.slice(-120)))
  } catch {
    // Private browsing or a full quota should not break the desk.
  }
}

export function makeMessage(
  role: LocalMessage['role'],
  text: string,
): LocalMessage {
  const id =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `msg-${Date.now()}-${Math.random().toString(16).slice(2)}`
  return { id, role, text, at: new Date().toISOString() }
}
