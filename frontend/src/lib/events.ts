import { z } from 'zod'
import {
  AssessmentDetailSchema,
  ApprovalSchema,
  AuditEventSchema,
  EvidenceSchema,
  FindingSchema,
  StepSchema,
  type AssessmentDetail,
} from './schemas'

export const STREAM_EVENT_TYPES = [
  'snapshot',
  'status',
  'step',
  'finding',
  'approval',
  'audit',
  'report',
  'error',
  'heartbeat',
] as const

export type StreamConnection =
  | 'idle'
  | 'connecting'
  | 'live'
  | 'reconnecting'
  | 'error'

function envelope<T extends (typeof STREAM_EVENT_TYPES)[number], D extends z.ZodType>(
  type: T,
  data: D,
) {
  return z.object({
    id: z.number().int(),
    type: z.literal(type),
    assessment_id: z.number().int(),
    ts: z.string(),
    data,
  })
}

export const StreamEventSchema = z.discriminatedUnion('type', [
  envelope('snapshot', z.object({ assessment: AssessmentDetailSchema })),
  envelope(
    'status',
    z.object({
      status: z.string(),
      finished_at: z.string().nullable(),
    }),
  ),
  envelope('step', z.object({ step: StepSchema })),
  envelope(
    'finding',
    z.object({
      finding: FindingSchema,
      evidence: z.array(EvidenceSchema),
    }),
  ),
  envelope('approval', z.object({ approval: ApprovalSchema })),
  envelope('audit', z.object({ event: AuditEventSchema })),
  envelope(
    'report',
    z.object({
      report_path: z.string().nullable(),
      report_sha256: z.string().nullable(),
      finished_at: z.string().nullable(),
      status: z.string(),
    }),
  ),
  envelope(
    'error',
    z
      .object({
        message: z.string().optional(),
        step_id: z.number().int().nullable().optional(),
      })
      .catchall(z.unknown()),
  ),
  envelope('heartbeat', z.object({ ts: z.string() })),
])

export type StreamEvent = z.infer<typeof StreamEventSchema>

function upsert<T extends { id: number }>(rows: T[], row: T): T[] {
  const index = rows.findIndex((candidate) => candidate.id === row.id)
  if (index === -1) return [...rows, row]
  const next = rows.slice()
  next[index] = row
  return next
}

/** Fold one validated event into the current detail. Never mutates. */
export function applyEvent(
  detail: AssessmentDetail | null,
  event: StreamEvent,
): AssessmentDetail | null {
  switch (event.type) {
    case 'snapshot':
      return event.data.assessment

    case 'status':
      return detail
        ? { ...detail, status: event.data.status, finished_at: event.data.finished_at }
        : detail

    case 'step':
      return detail
        ? {
            ...detail,
            steps: upsert(detail.steps, event.data.step).sort((a, b) => a.seq - b.seq),
          }
        : detail

    case 'finding': {
      if (!detail) return detail
      let evidence = detail.evidence
      for (const row of event.data.evidence) evidence = upsert(evidence, row)
      return {
        ...detail,
        findings: upsert(detail.findings, event.data.finding),
        evidence,
      }
    }

    case 'approval':
      return detail
        ? {
            ...detail,
            approvals: upsert(detail.approvals, event.data.approval).sort(
              (a, b) => b.id - a.id,
            ),
          }
        : detail

    case 'audit': {
      if (!detail) return detail
      if (detail.audit.some((row) => row.id === event.data.event.id)) return detail
      return {
        ...detail,
        audit: [event.data.event, ...detail.audit].slice(0, 100),
      }
    }

    case 'report':
      return detail
        ? {
            ...detail,
            report_path: event.data.report_path,
            report_sha256: event.data.report_sha256,
            finished_at: event.data.finished_at,
            status: event.data.status,
          }
        : detail

    case 'error':
    case 'heartbeat':
      return detail
  }
}

export function summarizeEvent(event: StreamEvent): string {
  switch (event.type) {
    case 'snapshot':
      return `snapshot restored · ${event.data.assessment.steps.length} ${
        event.data.assessment.steps.length === 1 ? 'step' : 'steps'
      }`
    case 'status':
      return `status → ${event.data.status}`
    case 'step':
      return `step ${String(event.data.step.seq).padStart(2, '0')} ${event.data.step.status}`
    case 'finding':
      return `${event.data.finding.severity} · ${event.data.finding.title}`
    case 'approval':
      return `approval ${event.data.approval.decision}`
    case 'audit':
      return event.data.event.event_type
    case 'report':
      return 'report updated'
    case 'error':
      return String(event.data.message ?? 'stream error')
    case 'heartbeat':
      return 'heartbeat'
  }
}
