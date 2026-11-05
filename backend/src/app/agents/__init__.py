"""Single-agent assessment loop.

The LLM chooses actions through the tools in ``agents.tools``; the modules here
only enforce policy and persist state:

- ``control``  phase/finish decisions recorded by the agent
- ``gate``     shared action queue + human approval gate + evidence
- ``graph``    one LangGraph loop (agent -> gate -> agent ... -> review -> report)
- ``tools``    the LLM-facing tool set
- ``prompts``  system prompt and context summarization prompt
"""
