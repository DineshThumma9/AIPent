"""OWASP ZAP baseline adapter: Docker argv, typed JSON parse."""

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.adapters.base import EvidenceDraft, FindingDraft, strip_html
from app.domain.models import FindingStatus, Severity

RiskCode = Literal["0", "1", "2", "3"]


class ZapInstance(BaseModel):
    uri: str = ""
    method: str = ""
    param: str = ""
    evidence: str = ""


class ZapAlert(BaseModel):
    pluginid: str
    alert: str = Field(min_length=1)
    riskcode: RiskCode = "0"
    confidence: str = "1"
    desc: str = ""
    solution: str = ""
    cweid: str = ""
    reference: str = ""
    instances: list[ZapInstance] = Field(default_factory=list)


class ZapSite(BaseModel):
    # ZAP's traditional JSON names this field "@name".
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(alias="@name")
    alerts: list[ZapAlert] = Field(default_factory=list)


class ZapReport(BaseModel):
    site: list[ZapSite] = Field(default_factory=list)


SEVERITY: dict[str, Severity] = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

CONFIDENCE: dict[str, float] = {"3": 0.9, "2": 0.7, "1": 0.5, "0": 0.4}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_CWE_RE = re.compile(r"CWE-\d+")


def _extract_cves(text: str) -> list[str]:
    return sorted(set(_CVE_RE.findall(text or "")))


def _extract_cwes(text: str) -> list[str]:
    return sorted(set(_CWE_RE.findall(text or "")))


def argv(
    target: str,
    port: int,
    output_path: str,
    artifact_dir: Path,
    image: str = "ghcr.io/zaproxy/zaproxy:stable",
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network=host",
        "-v",
        f"{artifact_dir}:/zap/wrk:rw",
        image,
        "zap-baseline.py",
        "-t",
        f"http://{target}:{port}",
        # Relative by design: the baseline automation plan combines this with
        # /zap/wrk. An absolute path is joined twice and the report is lost.
        "-J",
        Path(output_path).name,
        "-m",
        "2",
    ]


def parse(text: str) -> list[ZapAlert]:
    try:
        report = ZapReport.model_validate(json.loads(text))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(f"invalid ZAP report: {exc}") from exc
    return [alert for site in report.site for alert in site.alerts]


def to_drafts(host: str, port: int, alerts: list[ZapAlert]) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    for alert in alerts:
        desc = strip_html(alert.desc)
        solution = strip_html(alert.solution)
        evidence = [
            EvidenceDraft(
                locator={
                    "tool": "zap",
                    "plugin": alert.pluginid,
                    "uri": instance.uri,
                    "param": instance.param,
                },
                excerpt=strip_html(instance.evidence or desc)[:600],
            )
            for instance in alert.instances[:3]
        ]
        cve_list = _extract_cves(alert.reference or "")
        cwe_list = _extract_cwes(alert.cweid or "")
        if alert.cweid and not cwe_list:
            # Some ZAP versions put just "CWE-79" in cweid; capture it directly.
            m = re.match(r"CWE-(\d+)", alert.cweid.strip())
            if m:
                cwe_list = [f"CWE-{m.group(1)}"]
        drafts.append(
            FindingDraft(
                canonical_key=f"web:{alert.alert.lower()}:{host}:{port}",
                asset=host,
                endpoint=f"http://{host}:{port}",
                title=strip_html(alert.alert)[:160],
                description=desc,
                severity=SEVERITY[alert.riskcode],
                confidence=CONFIDENCE.get(alert.confidence, 0.5),
                status=FindingStatus.SUSPECTED,
                remediation=solution,
                cve=cve_list,
                cwe=cwe_list,
                evidence=evidence,
            )
        )
    return drafts


def scan(text: str, host: str, port: int) -> list[FindingDraft]:
    return to_drafts(host, port, parse(text))
