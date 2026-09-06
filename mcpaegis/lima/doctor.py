"""Host/guest readiness for Lima runtime (no side effects besides subprocess reads)."""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from typing import Any, Mapping

INSTANCE_NAME = "mcpaegis"


@dataclass(frozen=True)
class LimaInstance:
    name: str
    status: str = ""
    vm_type: str = ""
    arch: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.status.lower() == "running"


@dataclass(frozen=True)
class DoctorReport:
    system: str
    machine: str
    apple_silicon: bool
    limactl: str | None
    instance: LimaInstance | None
    guest_uname: str | None = None
    btf: bool | None = None
    cgroup_v2: bool | None = None
    guest_home: str | None = None
    venv_ok: bool | None = None
    bcc_ok: bool | None = None
    notes: tuple[str, ...] = ()

    @property
    def lima_ready(self) -> bool:
        return bool(self.limactl) and self.instance is not None and self.instance.running

    def header_line(self) -> str:
        if self.system == "Linux":
            bits = ["host: Linux (skip Lima)"]
            if self.btf:
                bits.append("BTF: ok")
            if self.cgroup_v2:
                bits.append("cgroup: ok")
            return " · ".join(bits)
        parts: list[str] = []
        if not self.apple_silicon:
            parts.append("need Apple Silicon")
        elif not self.limactl:
            parts.append("Lima: missing")
        elif self.instance is None:
            parts.append("Lima: no VM")
        elif not self.instance.running:
            parts.append(f"Lima: {self.instance.status or 'stopped'}")
        else:
            parts.append("Lima: running")
        if self.venv_ok is True:
            parts.append("venv: ok")
        elif self.venv_ok is False:
            parts.append("venv: missing")
        if self.bcc_ok is True:
            parts.append("BPF: ok")
        elif self.bcc_ok is False:
            parts.append("BPF: missing")
        return " · ".join(parts) if parts else "Lima: unknown"


def parse_limactl_list(stdout: str) -> list[LimaInstance]:
    """Parse ``limactl list --json`` (array or JSONL) or the default table."""
    text = (stdout or "").strip()
    if not text:
        return []
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        return _from_json(text)
    return _from_table(text)


def instance_named(instances: list[LimaInstance], name: str = INSTANCE_NAME) -> LimaInstance | None:
    for item in instances:
        if item.name == name:
            return item
    return None


def _from_json(text: str) -> list[LimaInstance]:
    stripped = text.strip()
    data: Any
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        rows: list[Any] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        data = rows
    if isinstance(data, dict):
        data = data.get("instances") or data.get("list") or [data]
    if not isinstance(data, list):
        return []
    out: list[LimaInstance] = []
    for row in data:
        if not isinstance(row, Mapping):
            continue
        name = str(row.get("name") or "")
        if not name:
            continue
        out.append(
            LimaInstance(
                name=name,
                status=str(row.get("status") or row.get("Status") or ""),
                vm_type=str(row.get("vmType") or row.get("vmTypeOverride") or row.get("VMType") or ""),
                arch=str(row.get("arch") or row.get("Arch") or ""),
                raw=dict(row),
            )
        )
    return out


def _from_table(text: str) -> list[LimaInstance]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []
    header = lines[0]
    keys = header.split()
    lower = [k.lower() for k in keys]
    try:
        name_i = lower.index("name")
    except ValueError:
        name_i = 0
    status_i = lower.index("status") if "status" in lower else 1
    vm_i = next((i for i, k in enumerate(lower) if k in {"vmtype", "vm_type"}), None)
    arch_i = lower.index("arch") if "arch" in lower else None
    out: list[LimaInstance] = []
    for line in lines[1:]:
        cols = line.split()
        if not cols:
            continue
        name = cols[name_i] if name_i < len(cols) else cols[0]
        status = cols[status_i] if status_i < len(cols) else ""
        vm_type = cols[vm_i] if vm_i is not None and vm_i < len(cols) else ""
        arch = cols[arch_i] if arch_i is not None and arch_i < len(cols) else ""
        out.append(LimaInstance(name=name, status=status, vm_type=vm_type, arch=arch))
    return out


def host_snapshot(*, limactl: str | None = None, list_stdout: str | None = None) -> DoctorReport:
    """Cheap Darwin/Linux snapshot. Pass ``list_stdout`` in tests to skip the binary."""
    system = platform.system()
    machine = platform.machine()
    apple = system == "Darwin" and machine in {"arm64", "aarch64"}
    if limactl is not None:
        binary = limactl
    else:
        from mcpaegis.lima.vm import find_limactl

        binary = find_limactl()
    instance = None
    notes: list[str] = []
    if system == "Darwin" and not apple:
        notes.append("Intel Macs cannot use the bundled aarch64 vz guest.")
    if binary and list_stdout is not None:
        instance = instance_named(parse_limactl_list(list_stdout))
    return DoctorReport(
        system=system,
        machine=machine,
        apple_silicon=apple,
        limactl=binary,
        instance=instance,
        notes=tuple(notes),
    )
