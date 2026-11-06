import { z } from 'zod'

/**
 * Domain schemas. The REST API and the SSE stream both parse through these, so
 * the dashboard never trusts an unvalidated payload.
 */

export const AssessmentSchema = z.object({
  id: z.number().int(),
  title: z.string(),
  request: z.string(),
  targets: z.array(z.string()),
  ports: z.array(z.number().int()),
  exclusions: z.array(z.string()),
  status: z.string(),
  risk_score: z.number().nullable().default(null),
  created_at: z.string(),
  finished_at: z.string().nullable(),
  report_path: z.string().nullable(),
  report_sha256: z.string().nullable(),
})

export const StepSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  seq: z.number().int(),
  action: z.string(),
  target: z.string().nullable().default(null),
  argv: z.array(z.string()),
  rationale: z.string(),
  status: z.string(),
  output_path: z.string().nullable(),
  output_sha256: z.string().nullable(),
  exit_code: z.number().int().nullable(),
  error: z.string().nullable(),
  created_at: z.string(),
  ended_at: z.string().nullable(),
})

export const FindingSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  canonical_key: z.string(),
  asset: z.string(),
  endpoint: z.string().nullable(),
  title: z.string(),
  description: z.string(),
  severity: z.string(),
  cvss: z.number().nullable(),
  cve: z.array(z.string()),
  cwe: z.array(z.string()),
  confidence: z.number(),
  status: z.string(),
  origin: z.string(),
  impact: z.string(),
  remediation: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
})

export const EvidenceSchema = z.object({
  id: z.number().int(),
  finding_id: z.number().int(),
  step_id: z.number().int().nullable(),
  locator: z.record(z.string(), z.unknown()),
  excerpt: z.string(),
  created_at: z.string(),
})

export const ApprovalSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  step_id: z.number().int().nullable(),
  action: z.string(),
  argv: z.array(z.string()),
  detail: z.record(z.string(), z.unknown()).default({}),
  decision: z.string(),
  actor: z.string().nullable(),
  reason: z.string().nullable(),
  requested_at: z.string(),
  decided_at: z.string().nullable(),
  executed_at: z.string().nullable(),
  outcome: z.string().nullable(),
})

export const AuditEventSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  ts: z.string(),
  actor: z.string(),
  event_type: z.string(),
  payload: z.record(z.string(), z.unknown()),
})

export const AssessmentDetailSchema = AssessmentSchema.extend({
  steps: z.array(StepSchema),
  findings: z.array(FindingSchema),
  evidence: z.array(EvidenceSchema),
  approvals: z.array(ApprovalSchema),
  audit: z.array(AuditEventSchema),
})

export const PlanStepSchema = z.object({
  action: z.string(),
  target: z.string(),
  rationale: z.string(),
})

export const AgentViewSchema = z.object({
  assessment_id: z.number().int(),
  status: z.string(),
  running: z.boolean(),
  paused: z.boolean(),
  next: z.array(z.string()),
  plan: z.array(PlanStepSchema),
  plan_source: z.string(),
  pending: z.record(z.string(), z.unknown()).nullable(),
  steps: z.number().int(),
  last_message: z.string().nullable(),
  risk_score: z.number().nullable(),
})

export const AgentAcceptedSchema = z.object({
  assessment_id: z.number().int(),
  accepted: z.boolean(),
  message: z.string(),
})

export const DecisionInputSchema = z.object({
  decision: z.enum(['approved', 'rejected']),
  actor: z.string().min(1),
  reason: z.string(),
})

export const MessageSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  role: z.string(),
  text: z.string(),
  created_at: z.string(),
})

export const AssessmentInputSchema = z.object({
  title: z.string().min(1),
  request: z.string().default(''),
  targets: z.array(z.string().min(1)).min(1),
  ports: z.array(z.number().int().min(1).max(65535)),
})

export const AssessmentRequestSchema = z.object({
  request: z.string().min(1).max(4000),
})

export type Assessment = z.infer<typeof AssessmentSchema>
export type AssessmentDetail = z.infer<typeof AssessmentDetailSchema>
export type AssessmentInput = z.infer<typeof AssessmentInputSchema>
export type Step = z.infer<typeof StepSchema>
export type Finding = z.infer<typeof FindingSchema>
export type Evidence = z.infer<typeof EvidenceSchema>
export type Approval = z.infer<typeof ApprovalSchema>
export type AuditEvent = z.infer<typeof AuditEventSchema>
export type AgentView = z.infer<typeof AgentViewSchema>
export type DecisionInput = z.infer<typeof DecisionInputSchema>
export type Message = z.infer<typeof MessageSchema>
export type PlanStep = z.infer<typeof PlanStepSchema>
