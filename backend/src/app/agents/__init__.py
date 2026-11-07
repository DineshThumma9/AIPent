"""Assessment agent package.

Modules here enforce policy and persist state:

- ``control``  role and handoff state recorded in the database
- ``execution`` security gate: scope, budget, policy, approval, execution
- ``graph``    LangGraph assessment loop (supervisor → specialists → gate → review → report)
- ``specialists`` self-contained recon/discovery/validation sub-graphs
"""
