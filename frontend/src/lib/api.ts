import type { z } from 'zod'
import {
  AgentAcceptedSchema,
  AssessmentDetailSchema,
  AssessmentInputSchema,
  AssessmentSchema,
  ChatAcceptedSchema,
  DecisionInputSchema,
  MessageSchema,
  type Assessment,
  type AssessmentDetail,
  type AssessmentInput,
  type ChatAccepted,
  type DecisionInput,
  type Message,
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

export const updateAssessmentRequest = (id: number, request: string) =>
  req(`/assessments/${id}/request`, AssessmentSchema, {
    method: 'PATCH',
    body: JSON.stringify({ request }),
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

export const stopAgent = (id: number) =>
  req(`/assessments/${id}/stop`, AgentAcceptedSchema, {
    method: 'POST',
  }) as Promise<z.infer<typeof AgentAcceptedSchema>>

export const listMessages = (id: number) =>
  req(`/assessments/${id}/messages`, MessageSchema.array()) as Promise<Message[]>

export const createMessage = (id: number, payload: { role: 'operator' | 'assistant'; text: string }) =>
  req(`/assessments/${id}/messages`, MessageSchema, {
    method: 'POST',
    body: JSON.stringify(payload),
  }) as Promise<Message>

export const sendChat = (
  id: number,
  body: { text: string; client_message_id?: string },
) =>
  req(`/assessments/${id}/chat`, ChatAcceptedSchema, {
    method: 'POST',
    body: JSON.stringify(body),
  }) as Promise<ChatAccepted>

export const reportUrl = (id: number) => `${BASE}/assessments/${id}/report`
