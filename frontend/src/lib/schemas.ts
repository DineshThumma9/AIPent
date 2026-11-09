import { z } from 'zod'

/**
 * Domain schemas. The REST API and the SSE stream both parse through these, so
 * the dashboard never trusts an unvalidated payload.
 *
 * JSON columns can be NULL in SQLite even when the Python default is `[]` or
 * `{}`. Zod's `.default()` only covers `undefined`, so every list/record is
 * normalised explicitly to keep one bad row from dropping an entire event.
 */

const stringList = () =>
  z
    .array(z.string())
    .nullish()
    .transform((value) => value ?? [])

const intList = () =>
  z
    .array(z.number().int())
    .nullish()
    .transform((value) => value ?? [])

const dataRecord = () =>
  z
    .record(z.string(), z.unknown())
    .nullish()
    .transform((value) => value ?? {})

const emptyBoard = () => ({
  hypotheses: [],
  decisions: [],
  open_questions: [],
  coverage: {},
})

export const AssessmentSchema = z.object({
  id: z.number().int(),
  title: z.string(),
  request: z.string(),
  targets: stringList(),
  ports: intList(),
  exclusions: stringList(),
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
  argv: stringList(),
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
  cvss: z.number().nullable().default(null),
  cve: stringList(),
  cwe: stringList(),
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
  locator: dataRecord(),
  excerpt: z.string(),
  created_at: z.string(),
})

export const ApprovalSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  step_id: z.number().int().nullable(),
  action: z.string(),
  argv: stringList(),
  detail: dataRecord(),
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
  payload: dataRecord(),
})

export const MessageSchema = z.object({
  id: z.number().int(),
  assessment_id: z.number().int(),
  role: z.string(),
  text: z.string(),
  client_message_id: z.string().nullable().default(null),
  created_at: z.string(),
})

export const HypothesisSchema = z.object({
  id: z.string(),
  statement: z.string(),
  asset: z.string(),
  endpoint: z.string().nullable().default(null),
  status: z.enum(['open', 'supported', 'refuted', 'inconclusive']),
  confidence: z.number(),
  evidence_ids: intList(),
  falsifier: z.string(),
  created_by: z.string(),
  updated_at: z.string(),
})

export const DecisionRecordSchema = z.object({
  id: z.string(),
  role: z.string(),
  action: z.string(),
  target: z.string(),
  hypothesis_id: z.string().nullable().default(null),
  evidence_ids: intList(),
  observation: z.string(),
  expected_observation: z.string().nullable().default(null),
  would_falsify: z.string().nullable().default(null),
  confidence: z.number(),
  outcome: z.string(),
  created_at: z.string(),
})

export const EvidenceBoardSchema = z.object({
  hypotheses: z
    .array(HypothesisSchema)
    .nullish()
    .transform((value) => value ?? []),
  decisions: z
    .array(DecisionRecordSchema)
    .nullish()
    .transform((value) => value ?? []),
  open_questions: stringList(),
  coverage: dataRecord(),
})

export const ChatAcceptedSchema = z.object({
  assessment_id: z.number().int(),
  operator_message_id: z.number().int(),
  accepted: z.boolean(),
  steering: z.boolean(),
  message: z.string(),
})

const listOf = <T extends z.ZodType>(schema: T) =>
  z
    .array(schema)
    .nullish()
    .transform((value) => value ?? [])

export const AssessmentDetailSchema = AssessmentSchema.extend({
  steps: listOf(StepSchema),
  findings: listOf(FindingSchema),
  evidence: listOf(EvidenceSchema),
  approvals: listOf(ApprovalSchema),
  audit: listOf(AuditEventSchema),
  messages: listOf(MessageSchema),
  reasoning: EvidenceBoardSchema.nullish().transform(
    (value) => value ?? emptyBoard(),
  ),
  gate_open: z
    .boolean()
    .nullish()
    .transform((value) => value ?? false),
  active_role: z.string().nullable().default(null),
  run_id: z.string().nullable().default(null),
})

export const PlanStepSchema = z.object({
  action: z.string(),
  target: z.string(),
  rationale: z.string(),
})

export const AgentViewSchema = z.object({
  assessment_id: z.number().int(),
  run_id: z.string().nullable().default(null),
  status: z.string(),
  running: z.boolean(),
  paused: z.boolean(),
  next: stringList(),
  plan: listOf(PlanStepSchema),
  plan_source: z.string(),
  pending: z.record(z.string(), z.unknown()).nullable(),
  steps: z.number().int(),
  last_message: z.string().nullable(),
  risk_score: z.number().nullable(),
  gate_open: z.boolean().default(false),
  active_role: z.string().nullable().default(null),
  phase: z.string().default(''),
  reasoning_summary: z.string().default(''),
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
  // Bind the decision to the specific gate card the analyst saw, so the
  // backend can reject stale approval cards (approval.argv must match step.argv).
  approval_id: z.number().int().optional(),
  step_id: z.number().int().optional(),
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
export type Hypothesis = z.infer<typeof HypothesisSchema>
export type DecisionRecord = z.infer<typeof DecisionRecordSchema>
export type EvidenceBoard = z.infer<typeof EvidenceBoardSchema>
export type ChatAccepted = z.infer<typeof ChatAcceptedSchema>
