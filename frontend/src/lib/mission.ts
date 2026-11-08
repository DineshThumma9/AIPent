import type {
  Approval,
  AssessmentDetail,
  Evidence,
  EvidenceBoard,
  Finding,
  PlanStep,
} from './schemas'

export const ROLE_ORDER = ['recon', 'discovery', 'validation'] as const

export type RoleName = (typeof ROLE_ORDER)[number]
export type RoleStatus = 'queued' | 'active' | 'done'

export const ROLE_INFO: Record<RoleName, { label: string; mission: string }> = {
  recon: {
    label: 'Recon',
    mission: 'Ports and service facts',
  },
  discovery: {
    label: 'Discovery',
    mission: 'Scanner hypotheses',
  },
  validation: {
    label: 'Validation',
    mission: 'Probes and verdicts',
  },
}

export type HandoffView = {
  role: RoleName
  at: string
  summary: string
  next: string
  needsInput: boolean
  question: string | null
  openQuestions: string[]
  decisions: Record<string, unknown>[]
  findingIds: number[]
  stepIds: number[]
  // next_role is the canonical field; next_recommendation is the legacy alias.
  nextRole?: string | null
}

export type RoleView = {
  name: RoleName
  label: string
  mission: string
  status: RoleStatus
  turns: number
  handoff: HandoffView | null
}

export type MissionView = {
  runId: string | null
  startedAt: string | null
  running: boolean
  gateOpen: boolean
  activeRole: RoleName | null
  reasoning: EvidenceBoard
  roles: RoleView[]
  handoffs: HandoffView[]
  pendingApproval: Approval | null
  finalReview: Approval | null
  findings: Finding[]
  confirmed: Finding[]
  counts: {
    confirmed: number
    suspected: number
    falsePositive: number
    total: number
  }
  severity: Record<string, number>
}

export type ThreadEntry =
  | { kind: 'operator'; id: string; at: string; text: string }
  | { kind: 'assistant'; id: string; at: string; text: string }
  | { kind: 'role'; id: string; at: string; role: RoleName; note: string }
  | { kind: 'handoff'; id: string; at: string; handoff: HandoffView }
  | { kind: 'approval'; id: string; at: string; approval: Approval }
  | {
      kind: 'finding'
      id: string
      at: string
      finding: Finding
      evidence: Evidence[]
    }
  | { kind: 'report'; id: string; at: string; detail: AssessmentDetail }
  | { kind: 'note'; id: string; at: string; text: string; error: boolean }

const ACTIVE_STATUSES = new Set([
  'planning',
  'running',
  'reporting',
])
const TERMINAL_STATUSES = new Set([
  'completed',
  'cancelled',
  'failed',
  'draft',
])

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

function asText(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function asRole(value: unknown): RoleName | null {
  return typeof value === 'string' && ROLE_ORDER.includes(value as RoleName)
    ? (value as RoleName)
    : null
}

function asNumbers(value: unknown): number[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is number => typeof item === 'number')
}

function asRecords(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return []
  return value.filter(
    (item): item is Record<string, unknown> =>
      typeof item === 'object' && item !== null,
  )
}

export function actionLabel(action: string): string {
  const labels: Record<string, string> = {
    final_review: 'Final findings review',
    recon_services: 'Service and port scan',
    nmap_scan: 'Nmap scan',
    nmap_nse: 'Nmap NSE script scan',
    whatweb: 'Technology detection (WhatWeb)',
    sslscan: 'TLS/SSL configuration scan (sslscan)',
    nikto_scan: 'Nikto web scan',
    sqlmap_scan: 'sqlmap scan',
    dirb_scan: 'Directory scan',
    zap_baseline: 'ZAP baseline scan',
    curl_tool: 'HTTP request (curl)',
    hashcat_crack: 'Credential recovery (hashcat)',
    hash_identify: 'Hash format identification',
  }
  return labels[action] ?? action.replaceAll('_', ' ')
}

export function roleLabel(role: string | null | undefined): string {
  if (role === 'review') return 'Final review'
  return role && ROLE_ORDER.includes(role as RoleName)
    ? ROLE_INFO[role as RoleName].label
    : 'AIPENT'
}

export function approvalRole(approval: Approval): RoleName | null {
  return asRole(approval.detail.role) ?? asRole(approval.detail.phase)
}

export function approvalPlan(approval: Approval): PlanStep[] {
  const raw = approval.detail.plan
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item) => {
    if (typeof item !== 'object' || item === null) return []
    const record = item as Record<string, unknown>
    const action = asText(record.action)
    const target = asText(record.target)
    if (!action || !target) return []
    return [
      {
        action,
        target,
        rationale: asText(record.rationale) ?? '',
      },
    ]
  })
}

export function approvalTarget(approval: Approval): string | null {
  return approvalPlan(approval)[0]?.target ?? null
}

export function approvalRationale(approval: Approval): string {
  return (
    asText(approval.detail.rationale) ??
    approvalPlan(approval)[0]?.rationale ??
    ''
  )
}

export function briefText(detail: AssessmentDetail): string {
  const targets = detail.targets.length
    ? detail.targets.join(', ')
    : 'no target yet'
  const ports = detail.ports.length
    ? ` on ${detail.ports.join(', ')}`
    : ' on the catalogue default ports'
  return `Scope is locked to ${targets}${ports}. Recon maps the service surface, discovery turns it into candidate findings, and validation tests each hypothesis with safe probes. Every consequential action stops here for approval before it runs.`
}

function runAudit(detail: AssessmentDetail) {
  const audit = [...detail.audit].sort((a, b) => a.id - b.id)
  let start = [...audit]
    .reverse()
    .find(
      (event) =>
        event.event_type === 'agent.started' &&
        asText(event.payload.run_id) !== null,
    )

  if (!start) {
    start = [...audit]
      .reverse()
      .find((event) => asText(event.payload.run_id) !== null)
  }

  const runId = start ? asText(start.payload.run_id) : null
  const events = runId
    ? audit.filter((event) => asText(event.payload.run_id) === runId)
    : []

  return {
    runId,
    startedAt: events[0]?.ts ?? start?.ts ?? null,
    events,
  }
}

function handoffsFrom(events: AssessmentDetail['audit']): HandoffView[] {
  return events
    .filter((event) => event.event_type === 'handoff.created')
    .flatMap((event) => {
      const role = asRole(event.payload.role)
      if (!role) return []
      return [
        {
          role,
          at: event.ts,
          summary: asText(event.payload.summary) ?? '',
          next:
            asText(event.payload.next_role) ??
            asText(event.payload.next_recommendation) ??
            'review',
          nextRole:
            asText(event.payload.next_role) ??
            asText(event.payload.next_recommendation) ??
            null,
          needsInput: event.payload.needs_input === true,
          question: asText(event.payload.question),
          openQuestions:
            Array.isArray(event.payload.open_questions)
              ? event.payload.open_questions.filter(
                  (item): item is string => typeof item === 'string',
                )
              : [],
          decisions: asRecords(event.payload.decisions),
          findingIds: asNumbers(event.payload.finding_ids),
          stepIds: asNumbers(event.payload.step_ids),
        },
      ]
    })
}

export function deriveMission(detail: AssessmentDetail): MissionView {
  const { runId, startedAt, events } = runAudit(detail)
  // The gate always executes the oldest planned step (lowest seq), and
  // approvals are created in that same order. Show that approval, not the
  // newest one, so the card never describes a different command than the one
  // the next resume will run.
  const pendingApproval =
    [...detail.approvals]
      .sort((a, b) => a.id - b.id)
      .find((approval) => approval.decision === 'pending') ?? null
  const finalReview =
    pendingApproval?.action === 'final_review' ? pendingApproval : null
  const handoffs = handoffsFrom(events)

  const startedRoles: RoleName[] = []
  for (const event of events) {
    if (event.event_type !== 'role.started') continue
    const role = asRole(event.payload.role) ?? asRole(event.payload.to)
    if (role && !startedRoles.includes(role)) startedRoles.push(role)
  }

  const turns: Partial<Record<RoleName, number>> = {}
  for (const event of events) {
    if (event.event_type !== 'role.turn') continue
    const role = asRole(event.payload.role)
    const turn = asNumber(event.payload.turn)
    if (role && turn !== null) turns[role] = turn
  }

  const lastStarted = startedRoles.at(-1) ?? null
  const pendingRole = pendingApproval
    ? asRole(pendingApproval.detail.role) ??
      asRole(pendingApproval.detail.phase)
    : null
  const running =
    ACTIVE_STATUSES.has(detail.status) || pendingApproval !== null
  const activeRole =
    running && !finalReview ? pendingRole ?? lastStarted : null
  const lastIndex = lastStarted ? ROLE_ORDER.indexOf(lastStarted) : -1

  const roles = ROLE_ORDER.map((name, index): RoleView => {
    const handoff = handoffs.find((item) => item.role === name) ?? null
    const started = startedRoles.includes(name)
    let status: RoleStatus = 'queued'

    if (handoff) {
      status = 'done'
    } else if (activeRole === name) {
      status = 'active'
    } else if (
      started &&
      (lastIndex > index ||
        finalReview !== null ||
        TERMINAL_STATUSES.has(detail.status))
    ) {
      status = 'done'
    }

    return {
      name,
      label: ROLE_INFO[name].label,
      mission: ROLE_INFO[name].mission,
      status,
      turns: turns[name] ?? 0,
      handoff,
    }
  })

  const findings = [...detail.findings].sort(
    (a, b) =>
      (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
      Date.parse(b.updated_at) - Date.parse(a.updated_at),
  )
  const confirmed = findings.filter((finding) => finding.status === 'confirmed')
  const suspected = findings.filter((finding) => finding.status === 'suspected')
  const falsePositive = findings.filter(
    (finding) => finding.status === 'false_positive',
  )
  const severity: Record<string, number> = {}
  for (const finding of findings) {
    if (finding.status === 'false_positive') continue
    severity[finding.severity] = (severity[finding.severity] ?? 0) + 1
  }

  return {
    runId,
    startedAt,
    running,
    gateOpen:
      detail.gate_open &&
      (pendingApproval?.detail.requires_approval ?? true) !== false,
    activeRole,
    reasoning: detail.reasoning ?? {
      hypotheses: [],
      decisions: [],
      open_questions: [],
      coverage: {},
    },
    roles,
    handoffs,
    pendingApproval,
    finalReview,
    findings,
    confirmed,
    counts: {
      confirmed: confirmed.length,
      suspected: suspected.length,
      falsePositive: falsePositive.length,
      total: findings.length,
    },
    severity,
  }
}

export function evidenceFor(
  detail: AssessmentDetail,
  findingId: number,
): Evidence[] {
  return detail.evidence.filter((row) => row.finding_id === findingId)
}

export function buildThread(
  detail: AssessmentDetail,
  mission: MissionView,
): ThreadEntry[] {
  const entries: ThreadEntry[] = []
  const request = detail.request.trim()

  if (request) {
    entries.push({
      kind: 'operator',
      id: `operator-goal-${detail.id}`,
      at: detail.created_at,
      text: request,
    })
  }

  entries.push({
    kind: 'assistant',
    id: `assistant-brief-${detail.id}`,
    at: detail.created_at,
    text: briefText(detail),
  })

  if (!mission.runId) return entries

  const startMs = mission.startedAt ? Date.parse(mission.startedAt) : null
  const inRun = (at: string | null) => {
    if (!at || startMs === null) return false
    const value = Date.parse(at)
    return Number.isFinite(value) && value >= startMs - 1000
  }
  const runEvents = detail.audit.filter(
    (event) => event.payload.run_id === mission.runId,
  )
  const seenRoles = new Set<RoleName>()

  for (const event of runEvents) {
    if (event.event_type === 'role.started') {
      const role = asRole(event.payload.role) ?? asRole(event.payload.to)
      if (!role || seenRoles.has(role)) continue
      seenRoles.add(role)
      entries.push({
        kind: 'role',
        id: `role-${mission.runId}-${role}`,
        at: event.ts,
        role,
        note: ROLE_INFO[role].mission,
      })
      continue
    }

    if (event.event_type === 'role.budget_exhausted') {
      const role = asRole(event.payload.role)
      entries.push({
        kind: 'note',
        id: `budget-${event.id}`,
        at: event.ts,
        text: `${roleLabel(role)} reached its turn cap and handed to review.`,
        error: false,
      })
      continue
    }

    if (event.event_type === 'report.failed') {
      entries.push({
        kind: 'note',
        id: `report-failed-${event.id}`,
        at: event.ts,
        text: `Report failed: ${asText(event.payload.error) ?? 'unknown error'}`,
        error: true,
      })
    }
  }

  for (const handoff of mission.handoffs) {
    entries.push({
      kind: 'handoff',
      id: `handoff-${mission.runId}-${handoff.role}-${handoff.at}`,
      at: handoff.at,
      handoff,
    })
  }

  for (const approval of detail.approvals) {
    if (approval.decision === 'pending' || inRun(approval.requested_at)) {
      entries.push({
        kind: 'approval',
        id: `approval-${approval.id}`,
        at: approval.requested_at,
        approval,
      })
    }
  }

  const confirmed = mission.confirmed
    .filter((finding) => inRun(finding.updated_at))
    .slice(0, 8)
  for (const finding of confirmed) {
    entries.push({
      kind: 'finding',
      id: `finding-${finding.id}-${finding.updated_at}`,
      at: finding.updated_at,
      finding,
      evidence: evidenceFor(detail, finding.id),
    })
  }

  if (detail.report_path) {
    const lastAt = runEvents.at(-1)?.ts ?? mission.startedAt ?? detail.created_at
    entries.push({
      kind: 'report',
      id: `report-${detail.id}-${detail.report_path}`,
      at: detail.finished_at ?? lastAt,
      detail,
    })
  }

  return entries.sort((a, b) => {
    const left = Date.parse(a.at)
    const right = Date.parse(b.at)
    return (Number.isFinite(left) ? left : 0) - (Number.isFinite(right) ? right : 0)
  })
}
