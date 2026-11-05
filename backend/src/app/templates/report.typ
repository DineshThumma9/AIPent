#let data = json("report-data.json")
#set page(paper: "a4", margin: (x: 2cm, y: 2.2cm), numbering: "1")
#set text(font: ("DejaVu Sans", "Liberation Sans"), size: 9.5pt)
#set par(justify: true, leading: 0.65em)

#show heading.where(level: 1): it => {
  v(8pt)
  text(size: 15pt, weight: "bold", it.body)
  v(2pt)
  line(length: 100%, stroke: 0.6pt)
  v(4pt)
}

#align(center)[
  #text(size: 23pt, weight: "bold")[#data.assessment.title]
  #v(4pt)
  #text(size: 10pt, fill: luma(90))[Authorized vulnerability assessment report]
  #v(2pt)
  #text(size: 10pt, fill: luma(90))[AIPENT · assessment #data.assessment.id · #data.assessment.status]
]

#v(10pt)

= Scope and rules of engagement

#table(
  columns: (1fr, 2fr),
  inset: 5pt,
  stroke: 0.4pt + luma(200),
  [*Targets*], [#data.assessment.targets.join(", ")],
  [*Ports*], [#data.assessment.ports.map(str).join(", ")],
  [*Exclusions*], [#if data.assessment.exclusions.len() == 0 [none] else [#data.assessment.exclusions.join(", ")]],
  [*Requested by*], [#data.assessment.request],
  [*Opened*], [#data.assessment.created_at],
  [*Finished*], [#data.assessment.finished_at],
)

#v(6pt)
#text(size: 8.5pt, fill: luma(90))[
  Only the targets above were contacted. Active web probes required a human
  action approval; the plan and final report required human gates.
  #if data.mcp_only [
    Transport: Docker MCP Gateway. Scanner arguments were constructed and
    approved by the policy layer; the LLM did not supply argv.
  ] else if data.mcp [
    Transport: mixed local/Docker and Docker MCP Gateway steps.
  ] else [
    Every step is recorded with its exact argv, output artifact and SHA-256.
  ]
]

= Executive summary

#if data.findings.len() == 0 [
  No findings were recorded. This is a coverage statement for the actions below,
  not proof that the target is free of vulnerabilities.
] else [
  #data.findings.len() findings were recorded across #data.tool_count tool(s).
  The highest deterministic risk score is #data.risk.score / 10.
  #if data.risk.confirmed > 0 [ #data.risk.confirmed finding(s) are corroborated by more than one tool. ]
]

#v(6pt)
#table(
  columns: (1fr, 1fr, 1fr, 1fr),
  inset: 5pt,
  stroke: 0.4pt + luma(200),
  [*Critical*], [#data.risk.counts.critical],
  [*High*], [#data.risk.counts.high],
  [*Medium*], [#data.risk.counts.medium],
  [*Low / info*], [#(data.risk.counts.low + data.risk.counts.info)],
)

= Tool execution

#table(
  columns: (auto, 1fr, auto, auto, auto),
  inset: 5pt,
  stroke: 0.4pt + luma(200),
  [*No.*], [*Action*], [*Target*], [*Status*], [*Exit*],
  ..data.steps.map(s => (
    [#s.seq], [#s.action], [#s.target], [#s.status], [#s.exit_code],
  )).flatten(),
)

#v(4pt)
#text(size: 8.5pt, fill: luma(90))[
  Execution summary: #data.tool_count tool(s), #data.steps.len() step(s).
  Artifacts are listed in the evidence index below.
]

= Findings

#if data.findings.len() == 0 [
  None recorded.
] else [
  #for f in data.findings [
    == #f.id · #f.title

    #table(
      columns: (1fr, 1fr, 1fr, 1fr),
      inset: 5pt,
      stroke: 0.4pt + luma(200),
      [*Severity*], [#f.severity], [*Risk*], [#f.score / 10],
      [*Confidence*], [#f.confidence], [*Status*], [#f.status],
      [*Asset*], [#f.asset], [*Endpoint*], [#f.endpoint],
      [*CVE*], [#if f.cve.len() == 0 [none] else [#f.cve.join(", ")]], [*CWE*], [#if f.cwe.len() == 0 [none] else [#f.cwe.join(", ")]],
    )

    #v(4pt)
    #f.description

    #if f.remediation != "" [
      *Remediation.* #f.remediation
      #v(3pt)
    ]

    #if f.evidence.len() > 0 [
      *Evidence.*
      #for e in f.evidence [
        - #text(font: "DejaVu Sans Mono")[#e.tool] · #e.excerpt \
          #text(size: 8pt, fill: luma(90))[#e.locator]
      ]
    ]
  ]
]

= Approvals and audit

#table(
  columns: (1fr, auto, auto, 1fr),
  inset: 5pt,
  stroke: 0.4pt + luma(200),
  [*Gate / action*], [*Decision*], [*Actor*], [*Reason*],
  ..data.approvals.map(a => (
    [#a.action],
    [#a.decision],
    [#a.actor],
    [#a.reason],
  )).flatten(),
)

#v(6pt)
#text(size: 8.5pt, fill: luma(90))[
  Decisions are recorded at the time they were made. Approved commands are
  reproduced verbatim in the assessment database and audit trail.
]

= Limitations

- This is a time-boxed, non-exploiting assessment. It does not prove absence of
  vulnerabilities.
- Tool output can contain false positives; suspected findings are labelled.
- No credentials, destructive tests, denial of service, or out-of-scope targets
  were used.
- nmap, Nikto and OWASP ZAP baseline were the only live tools.

= Evidence index

#table(
  columns: (auto, 1fr, auto, 1fr),
  inset: 5pt,
  stroke: 0.4pt + luma(200),
  [*Step*], [*Artifact*], [*SHA-256*], [*Target*],
  ..data.artifacts.map(a => (
    [#a.seq],
    [#a.path],
    [#text(size: 7pt)[#a.sha]],
    [#a.target],
  )).flatten(),
)
