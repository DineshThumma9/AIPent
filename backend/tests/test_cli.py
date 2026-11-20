"""Unit and integration tests for AIPENT CLI interface."""

from typer.testing import CliRunner
import pytest

from app.cli import app, _normalize_args

runner = CliRunner()


def test_cli_main_help_exposes_flags_and_examples():
    """Verify that `aipent --help` surfaces key scan flags and practical examples."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    output = result.output

    # Check key flags visibility
    assert "--request" in output or "-r" in output
    assert "--query" in output or "-q" in output
    assert "--auto-approve" in output or "-y" in output
    assert "--ports" in output or "-p" in output
    assert "--exclude" in output or "-e" in output
    assert "--timeout" in output

    # Check that helpful examples are shown
    assert "Helpful Examples:" in output
    assert "aipent scan http://127.0.0.1:3000 -y" in output
    assert "-r" in output
    assert "aipent list" in output
    assert "aipent status" in output
    assert "aipent report" in output
    assert "aipent steer" in output


def test_cli_scan_help_exposes_aliases_and_examples():
    """Verify that `aipent scan --help` surfaces request, query, auto-approve, and examples."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    output = result.output

    # Check arguments & options
    assert "target" in output.lower()
    assert "--request" in output
    assert "--query" in output
    assert "--auto-approve" in output
    assert "--yes" in output
    assert "--ports" in output
    assert "--exclude" in output
    assert "--timeout" in output

    # Check scan epilog examples
    assert "Helpful Examples:" in output
    assert "aipent scan http://127.0.0.1:3000 -y" in output


def test_cli_help_command():
    """Verify that `aipent help` displays the main help without errors."""
    result = runner.invoke(app, ["help"])
    assert result.exit_code == 0
    output = result.output
    assert "AIPENT" in output
    assert "scan" in output
    assert "list" in output


def test_cli_help_scan_subcommand():
    """Verify that `aipent help scan` displays scan help documentation."""
    result = runner.invoke(app, ["help", "scan"])
    assert result.exit_code == 0
    output = result.output
    assert "Start an authorized security assessment" in output
    assert "--request" in output
    assert "--auto-approve" in output


def test_cli_help_unknown_command():
    """Verify that `aipent help <unknown>` exits cleanly with an error message."""
    result = runner.invoke(app, ["help", "nonexistent_command"])
    assert result.exit_code != 0
    assert "Unknown command" in result.output


def test_cli_other_commands_epilog():
    """Verify status, report, and steer commands have examples."""
    for cmd in ["status", "report", "steer", "list"]:
        res = runner.invoke(app, [cmd, "--help"])
        assert res.exit_code == 0
        assert "Helpful Example" in res.output or "Example:" in res.output


def test_cli_normalize_args():
    """Verify shorthand auto-routing to `scan`."""
    # Target directly -> prepend 'scan'
    assert _normalize_args(["http://127.0.0.1:3000", "-y"]) == ["scan", "http://127.0.0.1:3000", "-y"]
    assert _normalize_args(["127.0.0.1", "-p", "80"]) == ["scan", "127.0.0.1", "-p", "80"]
    assert _normalize_args(["-r", "find xss", "-y", "127.0.0.1"]) == ["scan", "-r", "find xss", "-y", "127.0.0.1"]

    # Known commands remain unchanged
    assert _normalize_args(["scan", "http://127.0.0.1:3000"]) == ["scan", "http://127.0.0.1:3000"]
    assert _normalize_args(["list"]) == ["list"]
    assert _normalize_args(["status", "1"]) == ["status", "1"]
    assert _normalize_args(["report", "1"]) == ["report", "1"]
    assert _normalize_args(["steer", "1", "instruction"]) == ["steer", "1", "instruction"]
    assert _normalize_args(["help"]) == ["help"]
    assert _normalize_args(["help", "scan"]) == ["help", "scan"]
    assert _normalize_args(["--help"]) == ["--help"]
    assert _normalize_args(["-h"]) == ["-h"]
    assert _normalize_args([]) == []
