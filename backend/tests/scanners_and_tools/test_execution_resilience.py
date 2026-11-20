"""Tests for scanner execution resilience, timeout termination, exit code enforcement, and artifact hashing."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import pytest

from app.actions.catalogue import ARTIFACT_DIR, get_action
from app.actions.executor import (
    _run,
    execute_action,
    register_process,
    terminate_process,
)
from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, StepStatus
from app.persistence.step_repo import StepRepo


@pytest.mark.asyncio
async def test_subprocess_timeout_termination():
    # Execute a command that sleeps longer than timeout
    with pytest.raises(asyncio.TimeoutError):
        await _run(["sleep", "10"], timeout=0.1, assessment_id=999)


@pytest.mark.asyncio
async def test_active_process_registration_and_termination():
    # Start a live background process
    proc = await asyncio.create_subprocess_exec(
        "sleep", "10",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    register_process(888, proc)

    # Terminate via registry
    terminate_process(888)
    await proc.wait()

    assert proc.returncode is not None
    # Process returncode should reflect termination (e.g. -15 for SIGTERM)
    assert proc.returncode != 0


@pytest.mark.asyncio
async def test_nonzero_exit_code_rejection(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", False)
    monkeypatch.setattr("app.actions.catalogue.ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path / "artifacts")

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Non-Zero Exit Target",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Mock _run to return non-zero exit code
        async def mock_run(argv, timeout, assessment_id=None):
            return subprocess.CompletedProcess(
                argv,
                returncode=2,
                stdout="",
                stderr="Scanner fatal error: target unreachable",
            )

        monkeypatch.setattr("app.actions.executor._run", mock_run)

        # execute_action records failure on Step and returns it without raising
        step = await execute_action(
            session=session,
            assessment_id=assessment.id,
            action="nmap_scan",
            target="127.0.0.1",
        )
        assert step.status == StepStatus.FAILED.value
        assert "Scanner fatal error" in (step.error or "")


@pytest.mark.asyncio
async def test_artifact_sha256_calculation(engine, tmp_path, sample_nmap_xml, monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", False)
    monkeypatch.setattr("app.actions.catalogue.ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "artifacts_dir", tmp_path / "artifacts")

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Hashing Target",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        expected_content = sample_nmap_xml
        expected_hash = hashlib.sha256(expected_content.encode("utf-8")).hexdigest()

        async def mock_run(argv, timeout, assessment_id=None):
            return subprocess.CompletedProcess(
                argv,
                returncode=0,
                stdout=expected_content,
                stderr="",
            )

        monkeypatch.setattr("app.actions.executor._run", mock_run)

        # Run action
        step = await execute_action(
            session=session,
            assessment_id=assessment.id,
            action="nmap_scan",
            target="127.0.0.1",
        )

        assert step.status == StepStatus.SUCCEEDED.value
        assert step.exit_code == 0
        assert step.output_path is not None
        assert Path(step.output_path).exists()
        assert step.output_sha256 == expected_hash
