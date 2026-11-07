"""Role-scoped LLM agent construction.

Each specialist gets its own LangChain agent with only its own tools and
prompt. The agent cannot call another role's tools.
"""

from __future__ import annotations

from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel

from app.agents.prompts import ROLE_PROMPTS
from app.agents.tools import ROLE_TOOLS
from app.core.config import settings
from app.core.log import get_logger

log = get_logger("agent.model")


def _build_model() -> BaseChatModel:
    provider = settings.llm_provider.lower()
    model_name = settings.llm_model
    

    if provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=model_name,
            groq_api_key=settings.groq_api_key,
            timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens,
        )
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        kwargs: dict[str, Any] = {}
        if settings.llm_base_url:
            kwargs["base_url"] = settings.llm_base_url
        client_kwargs: dict[str, Any] = {"timeout": settings.llm_timeout}
        import os

        api_key = os.getenv("OLLAMA_API_KEY")
        if api_key:
            kwargs["client_kwargs"] = {
                "headers": {"Authorization": f"Bearer {api_key}"}
            }
        return ChatOllama(
            model=model_name or settings.ollama_model,
            num_predict=settings.llm_max_tokens,
            **kwargs,
        )
    if provider == "mistralai":
        from langchain_mistralai import ChatMistralAI
        return ChatMistralAI(
            model=model_name,
            mistral_api_key=settings.mistral_api_key,
            timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens,
        )
    if provider == "mistral":
        from langchain_mistralai import ChatMistralAI
        return ChatMistralAI(
            model=model_name,
            mistral_api_key=settings.mistral_api_key,
            timeout=settings.llm_timeout,
            max_tokens=settings.llm_max_tokens,
        )
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model=model_name)
    if provider == "openrouter":
        from langchain_openrouter import ChatOpenRouter
        return ChatOpenRouter(model=model_name)
    if provider in ("huggingface", "huggingface_model"):
        from langchain_huggingface import ChatHuggingFace
        return ChatHuggingFace(model_name=model_name)

    raise ValueError(f"Provider {provider!r} not available")


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
        system_prompt=ROLE_PROMPTS[role],
    )
