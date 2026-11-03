const BASE = '/api'

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
  return res.json() as Promise<T>
}

export type Assessment = {
  id: number
  title: string
  request: string
  targets: string[]
  ports: number[]
  exclusions: string[]
  status: string
  created_at: string
  finished_at: string | null
  report_path: string | null
  report_sha256: string | null
}

export type Step = {
  id: number
  seq: number
  action: string
  argv: string[]
  rationale: string
  status: string
  error: string | null
  created_at: string
  ended_at: string | null
}

export type Finding = {
  id: number
  canonical_key: string
  asset: string
  endpoint: string | null
  title: string
  severity: string
  cvss: number | null
  confidence: number
  status: string
  origin: string
}

export type Approval = {
  id: number
  action: string
  argv: string[]
  decision: string
  actor: string | null
  reason: string | null
  requested_at: string
}

export type AuditEvent = {
  id: number
  ts: string
  actor: string
  event_type: string
  payload: Record<string, unknown>
}

export type AssessmentDetail = Assessment & {
  steps: Step[]
  findings: Finding[]
  approvals: Approval[]
  audit: AuditEvent[]
}

export type AssessmentInput = {
  title: string
  request: string
  targets: string[]
  ports: number[]
}

export const listAssessments = () => req<Assessment[]>('/assessments')

export const getAssessment = (id: number) => req<AssessmentDetail>(`/assessments/${id}`)

export const createAssessment = (body: AssessmentInput) =>
  req<Assessment>('/assessments', { method: 'POST', body: JSON.stringify(body) })

export const runScan = (id: number) =>
  req<Step>(`/assessments/${id}/scan`, { method: 'POST' })
