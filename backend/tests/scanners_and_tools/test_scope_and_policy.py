"""Tests for IP/CIDR scope authorization, exclusion precedence, and action policy."""

from __future__ import annotations

import json
import pytest

from app.actions.catalogue import ScopeError, check_scope
from app.core.policy import (
    DEFAULT_ACTION_POLICIES,
    ActionPolicy,
    load_policies,
    load_policies_from_json,
    policy_for,
)
from app.domain.models import Assessment


def test_scope_authorization_ip_and_hostname():
    assessment = Assessment(
        id=1,
        title="Scope Test",
        targets=["192.168.1.10", "example.com", "localhost"],
        ports=[80],
    )

    # Valid targets
    check_scope(assessment, "192.168.1.10")
    check_scope(assessment, "http://192.168.1.10:8080/path")
    check_scope(assessment, "example.com")
    check_scope(assessment, "https://example.com/api")
    check_scope(assessment, "localhost")
    check_scope(assessment, "127.0.0.1")  # Loopback alias for localhost


def test_scope_authorization_cidr():
    assessment = Assessment(
        id=2,
        title="CIDR Scope Test",
        targets=["10.0.0.0/24"],
        ports=[80],
    )

    # In CIDR
    check_scope(assessment, "10.0.0.1")
    check_scope(assessment, "10.0.0.254")

    # Outside CIDR
    with pytest.raises(ScopeError):
        check_scope(assessment, "10.0.1.1")


def test_scope_exclusion_precedence():
    assessment = Assessment(
        id=3,
        title="Exclusion Scope Test",
        targets=["192.168.1.0/24"],
        exclusions=["192.168.1.100", "192.168.1.200/31"],
        ports=[80],
    )

    # Allowed in subnet
    check_scope(assessment, "192.168.1.50")

    # Excluded single IP
    with pytest.raises(ScopeError, match="not in scope"):
        check_scope(assessment, "192.168.1.100")

    # Excluded CIDR range
    with pytest.raises(ScopeError, match="not in scope"):
        check_scope(assessment, "192.168.1.201")


def test_scope_out_of_bounds_target():
    assessment = Assessment(
        id=4,
        title="Out of Bounds Test",
        targets=["127.0.0.1"],
        ports=[80],
    )

    with pytest.raises(ScopeError, match="not in scope"):
        check_scope(assessment, "192.168.1.1")

    with pytest.raises(ScopeError, match="not in scope"):
        check_scope(assessment, "evil-target.com")


def test_default_action_policies():
    assert DEFAULT_ACTION_POLICIES["nmap_scan"].risk == "low"
    assert DEFAULT_ACTION_POLICIES["nmap_scan"].approve is False

    assert DEFAULT_ACTION_POLICIES["nikto_scan"].risk == "low"
    assert DEFAULT_ACTION_POLICIES["nikto_scan"].approve is False

    assert DEFAULT_ACTION_POLICIES["dirb_scan"].risk == "low"
    assert DEFAULT_ACTION_POLICIES["dirb_scan"].approve is False

    assert DEFAULT_ACTION_POLICIES["curl_request"].risk == "medium"
    assert DEFAULT_ACTION_POLICIES["curl_request"].approve is True

    assert DEFAULT_ACTION_POLICIES["sqlmap_scan"].risk == "high"
    assert DEFAULT_ACTION_POLICIES["sqlmap_scan"].approve is True

    assert DEFAULT_ACTION_POLICIES["hashcat_crack"].risk == "high"
    assert DEFAULT_ACTION_POLICIES["hashcat_crack"].approve is True


def test_policy_overrides_dict_and_json():
    overrides = {
        "nmap_scan": {"approve": True, "risk": "medium"},
        "sqlmap_scan": {"approve": False},
    }
    loaded = load_policies(overrides)
    assert loaded["nmap_scan"].approve is True
    assert loaded["nmap_scan"].risk == "medium"
    assert loaded["sqlmap_scan"].approve is False
    assert loaded["sqlmap_scan"].risk == "high"  # preserved base

    # JSON loading
    json_str = json.dumps(overrides)
    loaded_json = load_policies_from_json(json_str)
    assert loaded_json["nmap_scan"].approve is True

    # Empty / invalid JSON fails gracefully to defaults
    assert load_policies_from_json(None) == DEFAULT_ACTION_POLICIES
    assert load_policies_from_json("invalid json") == DEFAULT_ACTION_POLICIES


def test_new_tools_policies():
    from app.core.policy import policy_for

    ffuf_policy = policy_for("ffuf_scan")
    assert ffuf_policy.risk == "low"
    assert ffuf_policy.approve is False

    katana_policy = policy_for("katana_crawl")
    assert katana_policy.risk == "low"
    assert katana_policy.approve is False

    nuclei_policy = policy_for("nuclei_scan")
    assert nuclei_policy.risk == "medium"
    assert nuclei_policy.approve is True

