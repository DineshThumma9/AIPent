import type { z } from 'zod'
import {
  AgentAcceptedSchema,
  AssessmentDetailSchema,
  AssessmentInputSchema,
  AssessmentSchema,
  DecisionInputSchema,
  type Assessment,
  type AssessmentDetail,
  type AssessmentInput,
  type DecisionInput,
} from './schemas'

const BASE = '/api'

async function req<S extends z.ZodType>(
  path: string,
  schema: S,
  init?: RequestInit,
): Promise<z.infer<S>> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

  if (!res.ok) {
    const body = await res.text()
    throw new Error(body || `${res.status} ${res.statusText}`)
  }

  const parsed = schema.safeParse(await res.json())
  if (!parsed.success) {
    console.error('API schema mismatch', path, parsed.error.issues)
    throw new Error(`Unexpected response shape from ${path}`)
  }
  return parsed.data
}

const listSchema = AssessmentSchema.array()

export const listAssessments = () =>
  req('/assessments', listSchema) as Promise<Assessment[]>

export const getAssessment = (id: number) =>
  req(`/assessments/${id}`, AssessmentDetailSchema) as Promise<AssessmentDetail>

export const createAssessment = (body: AssessmentInput) =>
  req('/assessments', AssessmentSchema, {
    method: 'POST',
    body: JSON.stringify(AssessmentInputSchema.parse(body)),
  }) as Promise<Assessment>

export const runScan = (id: number) =>
  req(`/assessments/${id}/scan`, AssessmentDetailSchema, {
    method: 'POST',
  }) as Promise<AssessmentDetail>

export const runAgent = (id: number) =>
  req(`/assessments/${id}/run`, AgentAcceptedSchema, {
    method: 'POST',
  }) as Promise<z.infer<typeof AgentAcceptedSchema>>

export const resumeAgent = (id: number, decision: DecisionInput) =>
  req(`/assessments/${id}/resume`, AgentAcceptedSchema, {
    method: 'POST',
    body: JSON.stringify(DecisionInputSchema.parse(decision)),
  }) as Promise<z.infer<typeof AgentAcceptedSchema>>

export const reportUrl = (id: number) => `${BASE}/assessments/${id}/report`
