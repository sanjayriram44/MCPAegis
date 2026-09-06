"""Stage 6b: wrap pip-audit / npm audit / osv-scanner / cargo-audit (W5)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcpaegis.core.models import DependencyFinding

Severity = str


def scan(root: Path | str) -> list[DependencyFinding]:
    root = Path(root)
    findings: list[DependencyFinding] = []
    findings.extend(_pip_audit(root))
    findings.extend(_npm_audit(root))
    findings.extend(_osv_scanner(root))
    findings.extend(_cargo_audit(root))
    findings.extend(_npm_install_scripts(root))
    return _dedupe(findings)


def _run_json(cmd: list[str], *, cwd: Path, timeout: int = 120) -> Optional[Any]:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    stdout = completed.stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def _norm_severity(raw: object) -> Severity:
    text = str(raw or "MEDIUM").upper()
    mapping = {
        "MODERATE": "MEDIUM",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "UNKNOWN": "MEDIUM",
    }
    text = mapping.get(text, text)
    if text not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "MEDIUM"
    return text


def _pip_audit(root: Path) -> list[DependencyFinding]:
    if not ((root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file()):
        return []
    payload = _run_json(["pip-audit", "-f", "json"], cwd=root)
    if payload is None:
        return []
    findings: list[DependencyFinding] = []
    deps = payload if isinstance(payload, list) else payload.get("dependencies") or []
    for dep in deps:
        name = str(dep.get("name") or dep.get("package") or "")
        version = str(dep.get("version") or dep.get("installed_version") or "")
        vulns = dep.get("vulns") or dep.get("vulnerabilities") or []
        if not vulns and dep.get("id"):
            vulns = [dep]
        for vuln in vulns:
            findings.append(
                DependencyFinding(
                    weakness_id="W5",
                    package_name=name,
                    installed_version=version,
                    vulnerable_range=_join_ranges(vuln.get("fix_versions") or vuln.get("vulnerable_range")),
                    cve_id=_cve(vuln.get("id") or vuln.get("aliases")),
                    severity=_norm_severity(vuln.get("severity") or "MEDIUM"),
                    source_tool="pip-audit",
                )
            )
    return findings


def _npm_audit(root: Path) -> list[DependencyFinding]:
    if not (root / "package.json").is_file():
        return []
    payload = _run_json(["npm", "audit", "--json"], cwd=root)
    if not isinstance(payload, dict):
        return []
    findings: list[DependencyFinding] = []
    vulnerabilities = payload.get("vulnerabilities") or {}
    if isinstance(vulnerabilities, dict):
        for name, meta in vulnerabilities.items():
            if not isinstance(meta, dict):
                continue
            via = meta.get("via") or []
            cve = None
            if isinstance(via, list):
                for item in via:
                    if isinstance(item, dict):
                        cve = _cve(item.get("source") or item.get("cve") or item.get("url"))
                        if cve:
                            break
            findings.append(
                DependencyFinding(
                    weakness_id="W5",
                    package_name=str(name),
                    installed_version=str(meta.get("range") or meta.get("installed") or ""),
                    vulnerable_range=str(meta.get("range") or "") or None,
                    cve_id=cve,
                    severity=_norm_severity(meta.get("severity")),
                    source_tool="npm-audit",
                )
            )
    advisories = payload.get("advisories") or {}
    if isinstance(advisories, dict):
        for adv in advisories.values():
            if not isinstance(adv, dict):
                continue
            findings.append(
                DependencyFinding(
                    weakness_id="W5",
                    package_name=str(adv.get("module_name") or ""),
                    installed_version=str(adv.get("findings", [{}])[0].get("version") if adv.get("findings") else ""),
                    vulnerable_range=str(adv.get("vulnerable_versions") or "") or None,
                    cve_id=_cve(adv.get("cves") or adv.get("cve")),
                    severity=_norm_severity(adv.get("severity")),
                    source_tool="npm-audit",
                )
            )
    return findings


def _osv_scanner(root: Path) -> list[DependencyFinding]:
    payload = _run_json(["osv-scanner", "--format", "json", "-r", str(root)], cwd=root)
    if not isinstance(payload, dict):
        return []
    findings: list[DependencyFinding] = []
    for result in payload.get("results") or []:
        for pkg in result.get("packages") or []:
            package = pkg.get("package") or {}
            name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            for vuln in pkg.get("vulnerabilities") or []:
                findings.append(
                    DependencyFinding(
                        weakness_id="W5",
                        package_name=name,
                        installed_version=version,
                        vulnerable_range=_osv_range(vuln),
                        cve_id=_cve(vuln.get("aliases") or vuln.get("id")),
                        severity=_osv_severity(vuln),
                        source_tool="osv-scanner",
                    )
                )
    return findings


def _cargo_audit(root: Path) -> list[DependencyFinding]:
    if not (root / "Cargo.toml").is_file():
        return []
    payload = _run_json(["cargo", "audit", "--json"], cwd=root)
    if payload is None:
        return []
    findings: list[DependencyFinding] = []
    vulns = []
    if isinstance(payload, dict):
        vulns = (
            (payload.get("vulnerabilities") or {}).get("list")
            if isinstance(payload.get("vulnerabilities"), dict)
            else payload.get("vulnerabilities") or []
        )
    for vuln in vulns or []:
        advisory = vuln.get("advisory") or vuln
        package = vuln.get("package") or {}
        findings.append(
            DependencyFinding(
                weakness_id="W5",
                package_name=str(package.get("name") or advisory.get("package") or ""),
                installed_version=str(package.get("version") or ""),
                vulnerable_range=str((advisory.get("affected_functions") or "") or "") or None,
                cve_id=_cve(advisory.get("id") or advisory.get("aliases")),
                severity=_norm_severity(advisory.get("severity") or "MEDIUM"),
                source_tool="cargo-audit",
            )
        )
    return findings


def _npm_install_scripts(root: Path) -> list[DependencyFinding]:
    """Surface preinstall/postinstall scripts for manual review (no verdict)."""
    package_json = root / "package.json"
    if not package_json.is_file():
        return []
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    scripts = data.get("scripts") or {}
    findings: list[DependencyFinding] = []
    for hook in ("preinstall", "postinstall", "preuninstall", "install"):
        if hook in scripts and scripts[hook]:
            pkg = str(data.get("name") or package_json.parent.name)
            findings.append(
                DependencyFinding(
                    weakness_id="W5",
                    package_name=f"{pkg} ({hook})",
                    installed_version=str(data.get("version") or ""),
                    vulnerable_range=None,
                    cve_id=None,
                    severity="LOW",
                    source_tool="npm-audit",
                )
            )
    return findings


def _cve(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            found = _cve(item)
            if found:
                return found
        return None
    text = str(value)
    if text.startswith("CVE-"):
        return text
    return text if text else None


def _join_ranges(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(v) for v in value) or None
    text = str(value)
    return text or None


def _osv_range(vuln: dict[str, Any]) -> Optional[str]:
    affected = vuln.get("affected") or []
    ranges: list[str] = []
    for item in affected:
        for rng in item.get("ranges") or []:
            events = rng.get("events") or []
            parts = [f"{k}={v}" for ev in events for k, v in ev.items()]
            if parts:
                ranges.append(",".join(parts))
    return ";".join(ranges) or None


def _osv_severity(vuln: dict[str, Any]) -> Severity:
    sevs = vuln.get("severity") or []
    if isinstance(sevs, list) and sevs:
        score = sevs[0].get("score") if isinstance(sevs[0], dict) else sevs[0]
        return _norm_severity(score)
    return "MEDIUM"


def _dedupe(findings: list[DependencyFinding]) -> list[DependencyFinding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[DependencyFinding] = []
    for item in findings:
        key = (item.package_name, item.installed_version, item.cve_id or "", item.source_tool)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
