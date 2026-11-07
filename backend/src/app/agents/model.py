"""Role-scoped LLM agent construction.

Each specialist gets its own LangChain agent with only its own tools and
prompt. The agent cannot call another role's tools.
"""

from __future__ import annotations
from app.agents.middleware import middleware_setup
from typing import Any

from langchain_groq import ChatGroq
from langchain_huggingface import ChatHuggingFace
from langchain_mistralai import ChatMistralAI
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from app.agents.prompts import ROLE_PROMPTS
from app.agents.tools import ROLE_TOOLS
from app.core.config import settings
from app.core.log import get_logger
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openrouter import ChatOpenRouter
from ..domain.models import ThinkingLevel
log = get_logger("agent.model")


models =   {

"groq": lambda model_name:ChatGroq(
    model=model_name,
    groq_api_key=settings.groq_api_key,
    timeout=settings.llm_timeout,
    max_tokens=settings.llm_max_tokens,
    ),

"ollama" : lambda model_name: ChatOllama(
    model=model_name or settings.ollama_model,
    base_url=settings.ollama_base_url,
    num_predict=settings.llm_max_tokens,
    timeout=settings.llm_timeout,
    client_kwargs={"headers": {"Authorization": f"Bearer {settings.ollama_api_key}"}} if settings.ollama_base_url and settings.ollama_api_key else {},
),

"mistral": lambda model_name: ChatMistralAI(
    model=model_name,
    mistral_api_key=settings.mistral_api_key,
    timeout=settings.llm_timeout,
    max_tokens=settings.llm_max_tokens,
),

"gemini": lambda model_name : ChatGoogleGenerativeAI(model=model_name),
"openrouter":lambda model_name: ChatOpenRouter(model=model_name),
"huggingface": lambda model_name:ChatHuggingFace(model_name=model_name)
}


thinkings_levels = {
    "supervisor":ThinkingLevel.HIGH,
    "recon":ThinkingLevel.MEDIUM,
    "validation":ThinkingLevel.MEDIUM,
    "discovery":ThinkingLevel.MEDIUM
}
def _build_model() -> BaseChatModel:
    provider = settings.llm_provider.lower()
    model_name = settings.llm_model

    if provider not in models:
        raise ValueError(f"{provider} not available")

    return models[provider](model_name)
def build_role_agent(role: str):
    """Build an LLM agent scoped to one role's tools and prompt."""
    if role not in ROLE_PROMPTS:
        raise ValueError(
            f"unknown role {role!r}; expected one of {tuple(ROLE_PROMPTS)}"
        )

    tools = ROLE_TOOLS.get(role, [])
    log.info(
        "building role agent role=%s tools=%s",
        role,
        [getattr(t, "name", str(t)) for t in tools],
    )

    return create_agent(
        model=_build_model(),
        tools=tools,
        middleware=middleware_setup(thinkings_levels[role]),
        system_prompt=ROLE_PROMPTS[role],
    )
