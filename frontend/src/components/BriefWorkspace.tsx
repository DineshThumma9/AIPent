import type { AssessmentInput } from '../lib/schemas'
import { MissionForm } from './MissionForm'

export function BriefWorkspace({
  onCreate,
}: {
  onCreate: (input: AssessmentInput) => Promise<void>
}) {
  return (
    <div className="brief-workspace">
      <section className="brief-copy" aria-labelledby="brief-title">
        <h1 id="brief-title">Brief the desk</h1>
        <p className="brief-lead">
          AIPENT runs an authorized VAPT with three specialists. Recon maps the
          service surface, discovery turns it into candidate findings, and
          validation tests each hypothesis with safe probes. Every action waits
          for your approval.
        </p>

        <dl className="brief-roles">
          <div>
            <dt>Recon</dt>
            <dd>Live ports and service facts.</dd>
          </div>
          <div>
            <dt>Discovery</dt>
            <dd>Scanner candidates ranked for evidence value.</dd>
          </div>
          <div>
            <dt>Validation</dt>
            <dd>Executed probes and honest verdicts.</dd>
          </div>
        </dl>

        <p className="brief-note">
          Scope is enforced before every command. Exact argv, artifacts and
          SHA-256 stay in the record, and nothing irreversible runs without a
          human decision.
        </p>
      </section>

      <section className="brief-form-panel" aria-labelledby="new-mission-title">
        <h2 id="new-mission-title">New mission</h2>
        <MissionForm onCreate={onCreate} autoFocus />
      </section>
    </div>
  )
}
