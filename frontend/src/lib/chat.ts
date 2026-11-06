import type { AssessmentDetail } from './schemas'
import {
  ROLE_INFO,
  actionLabel,
  approvalRationale,
  approvalRole,
  approvalTarget,
  roleLabel,
  type MissionView,
} from './mission'

export type ChatIntent =
  | 'status'
  | 'stop'
  | 'explain'
  | 'summary'
  | 'start'
  | 'other'

export function classifyIntent(input: string): ChatIntent {
  const text = input.trim()
  if (!text) return 'other'

  if (/\b(stop|halt|cancel|abort)\b/i.test(text)) return 'stop'

  if (
    /\b(status|progress|update|where are we|what(?:'s| is) happening|what(?:'s| is) left)\b/i.test(
      text,
    )
  ) {
    return 'status'
  }

  if (/\b(summar\w*|findings|results|fix first|unverified|report)\b/i.test(text)) {
    return 'summary'
  }

  if (
    /\b(why|explain|argv|command|gate|this action|that action)\b/i.test(text) ||
    /\bwhat (?:will|would|do) you\b/i.test(text) ||
    /\bwhat is .* doing\b/i.test(text)
  ) {
    return 'explain'
  }

  if (
    /\b(start|run|begin|go|pick|challenge|make it happen|map|scan|recon)\b/i.test(
      text,
    )
  ) {
    return 'start'
  }

  return 'other'
}

function scopeLine(detail: AssessmentDetail): string {
  const targets = detail.targets.length
    ? detail.targets.join(', ')
    : 'no target'
  const ports = detail.ports.length
    ? ` on ${detail.ports.join(', ')}`
    : ' on the catalogue default ports'
  return `${targets}${ports}`
}

export function statusReply(
  detail: AssessmentDetail,
  mission: MissionView,
): string {
  if (!mission.runId) {
    return `No run has started. Scope is ${scopeLine(detail)}. Say "start recon" when you want the service surface mapped; the first action will pause for approval.`
  }

  const parts: string[] = []

  if (mission.pendingApproval) {
    const role = roleLabel(
      approvalRole(mission.pendingApproval) ??
        String(mission.pendingApproval.detail.role ?? ''),
    )
    parts.push(
      `The run is paused at ${actionLabel(
        mission.pendingApproval.action,
      )} for ${role}. Nothing executes until you approve or reject it.`,
    )
  } else if (mission.finalReview) {
    parts.push('The run is paused at final review and needs your decision.')
  } else if (mission.running) {
    const active = mission.activeRole
      ? ROLE_INFO[mission.activeRole].label
      : 'A role'
    parts.push(`${active} is working. No gate is open right now.`)
  } else {
    parts.push(`The run is ${detail.status.replaceAll('_', ' ')}.`)
  }

  parts.push(
    `${mission.counts.confirmed} confirmed, ${mission.counts.suspected} suspected, ${mission.counts.falsePositive} false positive.`,
  )

  if (detail.risk_score !== null) {
    parts.push(`Recorded risk is ${detail.risk_score.toFixed(1)} / 10.`)
  }

  return parts.join(' ')
}

export function findingsReply(mission: MissionView): string {
  if (mission.counts.total === 0) {
    return 'No findings are recorded yet. Recon and discovery have not produced candidate evidence for validation.'
  }

  if (mission.confirmed.length === 0) {
    return `No finding is confirmed yet. ${mission.counts.suspected} candidate${
      mission.counts.suspected === 1 ? ' is' : 's are'
    } still suspected, so there is not enough executed probe evidence for a verdict.`
  }

  const top = mission.confirmed.slice(0, 3)
  const lines = top.map((finding) => {
    const where = finding.endpoint ?? finding.asset
    return `${finding.title} (${finding.severity}, ${where})`
  })

  const head = `${mission.confirmed.length} confirmed finding${
    mission.confirmed.length === 1 ? '' : 's'
  }.`
  const tail =
    mission.confirmed.length > 1
      ? ' By recorded severity, start with the first.'
      : ''

  return `${head} ${lines.join('; ')}.${tail}`
}

export function explainReply(
  detail: AssessmentDetail,
  mission: MissionView,
): string {
  const pending = mission.pendingApproval

  if (pending?.action === 'final_review') {
    const findings = pending.detail.findings
    const risk = pending.detail.risk_score
    return `This is the final findings review. The run recorded ${
      typeof findings === 'number' ? findings : mission.counts.total
    } finding${findings === 1 ? '' : 's'}${
      typeof risk === 'number' ? ` at risk ${risk.toFixed(1)} / 10` : ''
    }. Approving writes the report and closes the run; rejecting closes it without a report.`
  }

  if (pending) {
    const role =
      roleLabel(approvalRole(pending)) ||
      roleLabel(String(pending.detail.role ?? ''))
    const target = approvalTarget(pending) ?? 'the scoped target'
    const rationale = approvalRationale(pending)
    const command = pending.argv.length
      ? ` It will run exactly: ${pending.argv.join(' ')}.`
      : ''
    const reason = rationale ? ` The stated rationale is: ${rationale}.` : ''
    return `${role} queued ${actionLabel(
      pending.action,
    )} against ${target}.${reason}${command} Approving executes it once; rejecting records the refusal and the role adapts.`
  }

  if (!mission.runId) {
    return `Recon will begin with a service scan on ${scopeLine(
      detail,
    )}. If an HTTP service is open, discovery chooses a scanner for the service, and validation tests the resulting hypotheses with safe probes. Every action pauses for your approval before it runs.`
  }

  if (mission.running) {
    return 'No gate is open. The next action will pause here with its exact command and rationale before anything runs.'
  }

  return 'There is no open gate. The run is closed; ask for a summary or start a fresh run.'
}

export function stopReply(mission: MissionView): string {
  if (mission.pendingApproval) {
    const role = roleLabel(approvalRole(mission.pendingApproval))
    return `The run is paused at ${actionLabel(
      mission.pendingApproval.action,
    )} for ${role}. Nothing has executed. Reject that gate to stop it; I will not approve it for you.`
  }

  if (mission.running) {
    return 'No gate is open. AIPENT pauses before every action, so the next safe stop is the next gate — reject it there. No command runs without your approval.'
  }

  return 'There is nothing to stop. No run is active.'
}

export function steeringReply(mission: MissionView): string {
  if (mission.running) {
    return 'I recorded that on the desk. Steering a live role needs the message transport, which is not wired to this run yet. I can still report status, explain a gate, or stop at the next gate.'
  }

  return 'The desk is idle. Say "start recon" when you want the target mapped; I will pause at the first action gate.'
}
