"""Role-scoped LLM agent construction.

Each specialist gets its own LangChain agent with only its own tools and
prompt. The agent cannot call another role's tools.
"""

from __future__ import annotations
from app.agents.middleware import middleware_setup
from typing import Any

import httpx
import socket
import types
import aiohttp
from langchain_cerebras import ChatCerebras
from langchain_cloudflare import ChatCloudflareWorkersAI
from langchain_groq import ChatGroq
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint
from langchain_mistralai import ChatMistralAI
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from app.agents.prompts import ROLE_PROMPTS
from app.agents.tool_specs import ROLE_TOOLS
from app.core.config import settings
from app.core.log import get_logger
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from ..domain.models import ThinkingLevel
log = get_logger("agent.model")


def _ollama_headers() -> dict[str, str]:
    if settings.ollama_api_key:
        return {"Authorization": f"Bearer {settings.ollama_api_key}"}
    return {}


_ORIG_GETADDRINFO = socket.getaddrinfo


def _ipv4_first(*args, **kwargs):
    infos = _ORIG_GETADDRINFO(*args, **kwargs)
    return sorted(infos, key=lambda info: info[0] != socket.AF_INET)


def _prefer_ipv4() -> None:
    if socket.getaddrinfo is _ORIG_GETADDRINFO:
        socket.getaddrinfo = _ipv4_first


def _nvidia_model(model_name: str) -> ChatNVIDIA:
    # NAT64 DNS returns IPv6 first; sort IPv4 first but keep IPv6 as fallback.
    _prefer_ipv4()
    model = ChatNVIDIA(
        model=model_name,
        api_key=settings.nvidia_api_key,
        max_completion_tokens=settings.llm_max_tokens,
        timeout=settings.llm_timeout,
    )
    # uvloop resolves through libuv, bypassing the getaddrinfo patch above.
    # Pinning the connector is the only family switch the SDK exposes.
    client = model._async_client

    def _ipv4_session(self):
        connector = aiohttp.TCPConnector(
            ssl=self._build_ssl_context(),
            family=socket.AF_INET,
        )
        timeout = aiohttp.ClientTimeout(
            connect=self.timeout,
            sock_connect=self.timeout,
            sock_read=self.timeout,
        )
        return aiohttp.ClientSession(connector=connector, timeout=timeout)

    client.get_async_session_fn = types.MethodType(_ipv4_session, client)
    return model


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
    sync_client_kwargs={
        "headers": _ollama_headers(),
        "transport": httpx.HTTPTransport(retries=3),
    },
    async_client_kwargs={
        "headers": _ollama_headers(),
        "transport": httpx.AsyncHTTPTransport(retries=3),
    },
),

"mistral": lambda model_name: ChatMistralAI(
    model=model_name,
    mistral_api_key=settings.mistral_api_key,
    timeout=settings.llm_timeout,
    max_tokens=settings.llm_max_tokens,
),

"gemini": lambda model_name : ChatGoogleGenerativeAI(model=model_name),
"openrouter": lambda model_name: ChatOpenAI(
    model=model_name,
    base_url="https://openrouter.ai/api/v1",
    api_key=settings.openrouter_api_key,
    timeout=settings.llm_timeout,
    max_tokens=settings.llm_max_tokens,
),
"nvidia": _nvidia_model,
"huggingface": lambda model_name: ChatHuggingFace(
    llm=HuggingFaceEndpoint(
        repo_id=model_name,
        task="text-generation",
        huggingfacehub_api_token=settings.huggingface_api_key,
        max_new_tokens=settings.llm_max_tokens,
        timeout=settings.llm_timeout,
    )
),
"cerebras": lambda model_name: ChatCerebras(
    model=model_name,
    cerebras_api_key=settings.cerebras_api_key,
    timeout=settings.llm_timeout,
    max_tokens=settings.llm_max_tokens,
),
"cloudflare": lambda model_name: ChatCloudflareWorkersAI(
    model=model_name,
    api_token=settings.cloudflare_api_key,
    account_id=settings.cloudflare_account_id,
    request_timeout=settings.llm_timeout,
    max_tokens=settings.llm_max_tokens,
),
}


thinkings_levels = {
    "supervisor": ThinkingLevel.HIGH,
    "recon": ThinkingLevel.MEDIUM,
    "validation": ThinkingLevel.MEDIUM,
    "discovery": ThinkingLevel.MEDIUM,
    "report": ThinkingLevel.HIGH,
    "coordinator": ThinkingLevel.LOW,
}


def _resolve_model(provider: str, override_model: str | None) -> str:
    """Role override first, then the provider's default model, then the global one."""
    if override_model:
        return override_model
    provider_default = getattr(settings, f"{provider}_model", None)
    return provider_default or settings.llm_model


def _build_model(
    override_model: str | None = None, override_provider: str | None = None
) -> BaseChatModel:
    provider = (override_provider or settings.llm_provider).lower()
    model_name = _resolve_model(provider, override_model)

    if provider not in models:
        raise ValueError(
            f"{provider} not available; expected one of {tuple(models)}"
        )

    return models[provider](model_name)


def build_role_model(role: str) -> BaseChatModel:
    """Return the configured chat model for a role, with per-role provider/model overrides."""
    override_model = getattr(settings, f"{role}_model", None)
    override_provider = getattr(settings, f"{role}_provider", None)
    return _build_model(override_model, override_provider)


ROLE_NAMES: tuple[str, ...] = tuple(thinkings_levels)


def role_model_config() -> dict[str, dict[str, str]]:
    """Resolve each role's provider/model without building clients.

    Mirrors :func:`build_role_model` so the run-start banner and audit record
    describe exactly what a run will use. Makes 429s and bad overrides
    self-diagnosing instead of inferred from error URLs.
    """
    config: dict[str, dict[str, str]] = {}
    for role in ROLE_NAMES:
        provider = (
            getattr(settings, f"{role}_provider", None) or settings.llm_provider
        ).lower()
        override_model = getattr(settings, f"{role}_model", None)
        config[role] = {
            "provider": provider,
            "model": _resolve_model(provider, override_model),
        }
    return config


def build_report_model() -> BaseChatModel:
    """Build the LLM for report narrative generation (strongest configured model)."""
    return build_role_model("report")


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
        model=build_role_model(role),
        tools=tools,
        middleware=middleware_setup(thinkings_levels[role]),
        system_prompt=ROLE_PROMPTS[role],
    )
