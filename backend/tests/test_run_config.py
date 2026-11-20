"""A run must say which provider/model every role will use before it starts."""

import asyncio

from sqlmodel import select

from app.agents.builder import prepare_run
from app.agents.model import role_model_config
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Audit

ROLES = {"supervisor", "coordinator", "recon", "discovery", "validation", "report"}


def test_role_model_config_uses_per_role_overrides(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "mistral")
    monkeypatch.setattr(settings, "llm_model", "base-model")
    monkeypatch.setattr(settings, "supervisor_provider", "cerebras")
    monkeypatch.setattr(settings, "supervisor_model", "gpt-oss-120b")
    monkeypatch.setattr(settings, "discovery_provider", None)
    monkeypatch.setattr(settings, "discovery_model", None)

    config = role_model_config()

    assert config["supervisor"] == {
        "provider": "cerebras",
        "model": "gpt-oss-120b",
    }
    assert config["discovery"] == {"provider": "mistral", "model": "base-model"}
    assert set(config) == ROLES


def test_nvidia_provider_uses_configured_model(monkeypatch):
    import socket

    from app.agents import model as model_module

    monkeypatch.setenv("NVIDIA_MODEL", "nvidia/test-model")
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    model = model_module._build_model(None, "nvidia")

    assert model.model == "nvidia/test-model"
    assert socket.getaddrinfo is model_module._ipv4_first
    assert (
        model._async_client.get_async_session_fn.__func__.__name__
        == "_ipv4_session"
    )


def test_prepare_run_audits_role_models(engine, monkeypatch):
    from app.integrations import juiceshop

    async def no_baseline(session, assessment_id):
        return None

    monkeypatch.setattr(juiceshop, "capture_baseline", no_baseline)

    async def run():
        async with get_async_session_ctx() as session:
            assessment = Assessment(
                title="Lab", targets=["127.0.0.1"], ports=[3000]
            )
            session.add(assessment)
            await session.commit()
            await session.refresh(assessment)

            await prepare_run(session, assessment.id)

            result = await session.execute(
                select(Audit).where(Audit.event_type == "run.requested")
            )
            return assessment.id, result.scalars().first()

    assessment_id, event = asyncio.run(run())

    assert event is not None
    assert event.assessment_id == assessment_id
    models = event.payload["models"]
    assert set(models) == ROLES
    assert models["supervisor"]["provider"]
    assert models["supervisor"]["model"]
