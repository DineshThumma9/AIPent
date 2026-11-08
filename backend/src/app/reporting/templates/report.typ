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
  #if "cve_snapshot" in data [
    \
    #text(size: 8pt, fill: luma(110))[CVE data snapshot: #data.cve_snapshot]
  ]
]

#if data.narrative.methodology != "" [
  = Methodology

  #data.narrative.methodology
]

#if data.narrative.risk_overview != "" [
  = Risk overview

  #data.narrative.risk_overview
]

= Executive summary

#if data.narrative.executive_summary != "" [
  #data.narrative.executive_summary
] else [
  #if data.findings.len() == 0 [
    No findings were recorded. This is a coverage statement for the actions below,
    not proof that the target is free of vulnerabilities.
  ] else [
    #data.findings.len() findings were recorded across #data.tool_count tool(s).
    The highest deterministic risk score is #data.risk.score / 10.
    #if data.risk.confirmed > 0 [ #data.risk.confirmed finding(s) are corroborated by more than one tool. ]
  ]
  #if data.narrative_source == "evidence-only" [
    #v(4pt)
    #text(size: 8.5pt, fill: luma(100))[_Narrative generation was unavailable; this report is evidence-only._]
  ]
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
  #for (idx, f) in data.findings.enumerate() [
    == Finding #(idx + 1): #f.title #text(size: 9pt, fill: luma(120), weight: "regular")[(ID: \##f.id)]

    #table(
      columns: (1fr, 1fr, 1fr, 1fr),
      inset: 5pt,
      stroke: 0.4pt + luma(200),
      [*Severity*], [#f.severity], [*Risk*], [#f.score / 10],
      [*Confidence*], [#f.confidence], [*Status*], [#f.status],
      [*Asset*], [#f.asset], [*Endpoint*], [#f.endpoint],
      [*CVE*], [#if f.cve.len() == 0 [-] else [#f.cve.join(", ")]], [*CWE*], [#if f.cwe.len() == 0 [-] else [#f.cwe.join(", ")]],
    )

    #v(4pt)
    #if f.narrative != none [
      *Technical analysis.* #f.narrative.technical_analysis

      #v(2pt)
      *Impact.* #f.narrative.impact

      #v(2pt)
      *Remediation.* #f.narrative.remediation

      #v(2pt)
      *Confidence.* #f.narrative.confidence_statement

      #v(2pt)
      *Observed vs inferred.* #f.narrative.observed_vs_inferred
    ] else [
      #f.description

      #if f.remediation != "" [
        #v(2pt)
        *Remediation.* #f.remediation
      ]
    ]

    #v(4pt)
    #if "finding_cves" in f and f.finding_cves.len() > 0 [
      *CVE Citations & Upstream Advisories.*
      #for fc in f.finding_cves [
        - #text(font: "DejaVu Sans Mono")[#fc.cve_id] (#fc.source, #fc.match_reason) #if fc.source_url != "" [ · #text(size: 7.5pt)[#fc.source_url] ]
      ]
      #v(2pt)
    ] else if f.cve.len() == 0 and f.endpoint.starts-with("tcp/") [
      #text(size: 8pt, fill: luma(120))[_CVE enrichment not possible; version not exposed._]
      #v(2pt)
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

#if data.narrative.limitations != "" [
  #data.narrative.limitations
  #v(4pt)
]

- This is a time-boxed, non-exploiting assessment. It does not prove absence of
  vulnerabilities.
- Tool output can contain false positives; suspected findings are labelled.
- No credentials, destructive tests, denial of service, or out-of-scope targets
  were used.

#let gaps = data.steps.filter(s => s.status == "rejected" or s.status == "failed" or s.status == "timeout")
#if gaps.len() > 0 [
  #v(4pt)
  *Coverage gaps and rejected actions:*
  #for g in gaps [
    - Step #g.seq (#g.action): status is #g.status#if g.target != "" [ on #g.target].
  ]
]

#let rejected_approvals = data.approvals.filter(a => a.decision == "rejected")
#if rejected_approvals.len() > 0 [
  #v(4pt)
  *Rejected approvals:*
  #for ra in rejected_approvals [
    - #ra.action was rejected by #ra.actor#if ra.reason != "" [ (#ra.reason)].
  ]
]

#if data.narrative.recommendations.len() > 0 [
  = Recommendations

  #for r in data.narrative.recommendations [
    - #r
  ]
]

#if data.narrative.conclusion != "" [
  = Conclusion

  #data.narrative.conclusion
]

= Evidence index

#if data.artifacts.len() == 0 [
  No artifact files recorded.
] else [
  #table(
    columns: (30pt, 1.4fr, 1.8fr, 1fr),
    inset: 4pt,
    stroke: 0.4pt + luma(200),
    [*Step*], [*Action & Evidence Artifact*], [*SHA-256 (Hash)*], [*Target*],
    ..data.artifacts.map(a => (
      align(center)[#a.seq],
      [
        #text(weight: "bold", size: 8pt)[#if "action_title" in a [#a.action_title] else [#a.action]] \
        #text(size: 7pt, fill: luma(110), font: "DejaVu Sans Mono")[#a.path]
      ],
      [#text(size: 6.5pt, font: "DejaVu Sans Mono")[
        #if a.sha.len() == 64 [
          #a.sha.slice(0, 32) \
          #a.sha.slice(32)
        ] else [
          #a.sha
        ]
      ]],
      [#text(size: 8pt)[#a.target]],
    )).flatten(),
  )
]

#v(14pt)
#align(center)[
  #text(size: 8pt, fill: luma(120))[Narrative source: #data.narrative_source]
]
