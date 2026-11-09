#let data = json("report-data.json")
#set page(
  paper: "a4",
  margin: (x: 2cm, top: 2.4cm, bottom: 2.2cm),
  header: context {
    if counter(page).get().first() > 1 [
      #grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8pt, fill: luma(110))[AIPENT · Vulnerability Assessment Report]],
        align(right)[#text(size: 8pt, fill: luma(110))[CONFIDENTIAL · Assessment \##data.assessment.id]]
      )
      #v(-2pt)
      #line(length: 100%, stroke: 0.3pt + luma(200))
    ]
  },
  footer: context [
    #line(length: 100%, stroke: 0.3pt + luma(200))
    #v(2pt)
    #grid(
      columns: (1fr, 1fr),
      align(left)[#text(size: 8pt, fill: luma(120))[#data.assessment.title · #data.narrative_source]],
      align(right)[#text(size: 8pt, fill: luma(120))[Page #counter(page).display() of #counter(page).final().first()]]
    )
  ]
)
#set text(font: ("IBM Plex Sans", "DejaVu Sans", "Liberation Sans"), size: 9.5pt)
#set par(justify: true, leading: 0.65em)

#show heading.where(level: 1): it => {
  v(8pt)
  text(size: 15pt, weight: "bold", it.body)
  v(2pt)
  line(length: 100%, stroke: 0.6pt)
  v(4pt)
}

#let severity-badge(s) = {
  let bg = luma(235)
  let fg = luma(30)
  let val = lower(str(s))
  if val == "critical" { bg = rgb("#fde8e8"); fg = rgb("#9c1c1c") }
  else if val == "high" { bg = rgb("#feecdc"); fg = rgb("#b43403") }
  else if val == "medium" { bg = rgb("#fdf6b2"); fg = rgb("#723b13") }
  else if val == "low" { bg = rgb("#e1effe"); fg = rgb("#1e429f") }
  else if val == "info" { bg = rgb("#edf2f7"); fg = rgb("#4a5568") }
  box(fill: bg, inset: (x: 5pt, y: 2.5pt), radius: 3pt)[#text(size: 7.5pt, weight: "bold", fill: fg)[#upper(val)]]
}

#let status-badge(st) = {
  let bg = luma(235)
  let fg = luma(40)
  let val = lower(str(st))
  if val == "confirmed" or val == "succeeded" or val == "approved" or val == "completed" { bg = rgb("#def7ec"); fg = rgb("#03543f") }
  else if val == "suspected" or val == "running" or val == "pending" or val == "reporting" { bg = rgb("#fef08a"); fg = rgb("#713f12") }
  else if val == "failed" or val == "rejected" { bg = rgb("#fee2e2"); fg = rgb("#991b1b") }
  else if val == "timeout" { bg = rgb("#ffedd5"); fg = rgb("#9a3412") }
  box(fill: bg, inset: (x: 4.5pt, y: 2pt), radius: 2.5pt)[#text(size: 7.5pt, weight: "bold", fill: fg)[#val]]
}

#align(center)[
  #text(size: 22pt, weight: "bold")[#data.assessment.title]
  #v(3pt)
  #text(size: 10pt, fill: luma(80), weight: "medium")[Authorized Vulnerability Assessment Report]
  #v(4pt)
  #box(fill: luma(248), radius: 4pt, inset: (x: 8pt, y: 3.5pt), stroke: 0.5pt + luma(220))[
    #text(size: 8.5pt, fill: luma(70))[
      *AIPENT* #h(5pt)·#h(5pt) Assessment \##data.assessment.id #h(5pt)·#h(5pt) #status-badge(data.assessment.status)
    ]
  ]
]

#v(8pt)

= Scope and rules of engagement

#table(
  columns: (1fr, 2.5fr),
  inset: 5.5pt,
  stroke: 0.4pt + luma(200),
  [*Targets*], [#data.assessment.targets.join(", ")],
  [*Ports*], [#data.assessment.ports.map(str).join(", ")],
  [*Exclusions*], [#if data.assessment.exclusions.len() == 0 [none] else [#data.assessment.exclusions.join(", ")]],
  [*Execution Mode*], [#if data.mcp_only [Docker MCP Gateway (Strict)] else if data.mcp [Mixed Local / Docker MCP] else [Standard Direct CLI]],
  [*Started*], [#if "created_at_human" in data.assessment and data.assessment.created_at_human != "" [#data.assessment.created_at_human] else [#data.assessment.created_at]],
  [*Finished*], [#if "finished_at_human" in data.assessment and data.assessment.finished_at_human != "" [#data.assessment.finished_at_human] else if data.assessment.finished_at != "" [#data.assessment.finished_at] else [In Progress]],
)

#if data.assessment.request != "" and data.assessment.request != "(no additional request text)" [
  #v(5pt)
  #rect(
    width: 100%,
    fill: rgb("#f8fafc"),
    stroke: (left: 3pt + rgb("#0284c7"), rest: 0.4pt + rgb("#e2e8f0")),
    radius: (right: 3pt),
    inset: (x: 9pt, y: 7pt),
  )[
    #text(size: 7.5pt, weight: "bold", fill: rgb("#0369a1"))[ENGAGEMENT OBJECTIVE & SCOPE DIRECTIVE]\
    #v(2.5pt)
    #text(size: 8.5pt, fill: rgb("#1e293b"))[#data.assessment.request]
  ]
]

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

  #if "methodology_blocks" in data.narrative and data.narrative.methodology_blocks.len() > 0 [
    #for b in data.narrative.methodology_blocks [
      #if b.kind == "item" [
        - #b.text
      ] else [
        #v(1.5pt)
        #b.text
        #v(1.5pt)
      ]
    ]
  ] else [
    #data.narrative.methodology
  ]
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

#v(8pt)
#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 6pt,
  rect(fill: rgb("#fde8e8"), inset: 6pt, radius: 3pt, width: 100%)[
    #align(center)[
      #text(size: 8pt, weight: "bold", fill: rgb("#9c1c1c"))[CRITICAL]\
      #text(size: 14pt, weight: "bold", fill: rgb("#9c1c1c"))[#data.risk.counts.critical]
    ]
  ],
  rect(fill: rgb("#feecdc"), inset: 6pt, radius: 3pt, width: 100%)[
    #align(center)[
      #text(size: 8pt, weight: "bold", fill: rgb("#b43403"))[HIGH]\
      #text(size: 14pt, weight: "bold", fill: rgb("#b43403"))[#data.risk.counts.high]
    ]
  ],
  rect(fill: rgb("#fdf6b2"), inset: 6pt, radius: 3pt, width: 100%)[
    #align(center)[
      #text(size: 8pt, weight: "bold", fill: rgb("#723b13"))[MEDIUM]\
      #text(size: 14pt, weight: "bold", fill: rgb("#723b13"))[#data.risk.counts.medium]
    ]
  ],
  rect(fill: rgb("#e1effe"), inset: 6pt, radius: 3pt, width: 100%)[
    #align(center)[
      #text(size: 8pt, weight: "bold", fill: rgb("#1e429f"))[LOW / INFO]\
      #text(size: 14pt, weight: "bold", fill: rgb("#1e429f"))[#(data.risk.counts.low + data.risk.counts.info)]
    ]
  ],
)

= Tool execution

#table(
  columns: (auto, 1fr, auto, auto, auto),
  inset: 5pt,
  stroke: 0.4pt + luma(200),
  [*No.*], [*Action*], [*Target*], [*Status*], [*Exit*],
  ..data.steps.map(s => (
    [#s.seq], [#s.action], [#s.target], [#status-badge(s.status)], [#s.exit_code],
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
      [*Severity*], [#severity-badge(f.severity)], [*Risk*], [#f.score / 10],
      [*Confidence*], [#f.confidence], [*Status*], [#status-badge(f.status)],
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
    [#status-badge(a.decision)],
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
