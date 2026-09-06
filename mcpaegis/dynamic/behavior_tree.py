"""Assemble one noise-filtered ToolBehaviorTree from a RuntimeEvent stream."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from mcpaegis.core.models import ProcessNode, RuntimeEvent, ToolBehaviorTree
from mcpaegis.core.taxonomy import RuntimeEventKind

DEFAULT_NOISE_SUFFIXES = (".so", ".so.", ".dll", ".dylib", ".pyc")
DEFAULT_NOISE_PATH_PARTS = (
    "/usr/lib/",
    "/lib/",
    "/lib64/",
    "/usr/lib64/",
    "site-packages/",
    "/etc/ld.so",
    "/dev/null",
    "/dev/urandom",
    "/proc/self/",
    "/usr/share/",
)
LOOPBACK_ADDRS = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}


def assemble(
    events: Sequence[RuntimeEvent],
    *,
    call_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    timestamp: float | None = None,
    seed_pids: Optional[Iterable[int]] = None,
    noise_path_parts: Sequence[str] | None = None,
) -> ToolBehaviorTree:
    """Filter loader/loopback noise, then build a single pid/ppid tree."""
    ts = timestamp if timestamp is not None else time.time()
    filtered = [evt for evt in events if not is_noise(evt, noise_path_parts=noise_path_parts)]
    nodes, dns = _build_nodes(filtered, seed_pids=list(seed_pids or []))
    return ToolBehaviorTree(
        call_id=call_id,
        tool_name=tool_name,
        arguments=dict(arguments),
        timestamp=ts,
        process_branch=nodes,
        dns_branch=dns,
    )


def is_noise(
    event: RuntimeEvent,
    *,
    noise_path_parts: Sequence[str] | None = None,
) -> bool:
    parts = tuple(noise_path_parts) if noise_path_parts is not None else DEFAULT_NOISE_PATH_PARTS
    if event.kind in {
        RuntimeEventKind.FILE_OPEN,
        RuntimeEventKind.FILE_READ,
        RuntimeEventKind.FILE_WRITE,
        RuntimeEventKind.FILE_UNLINK,
    }:
        path = str(event.details.get("path") or "")
        lowered = path.lower()
        if any(path.endswith(sfx) or sfx in lowered for sfx in DEFAULT_NOISE_SUFFIXES):
            return True
        if any(part in path for part in parts):
            return True
    if event.kind in {RuntimeEventKind.NET_CONNECT, RuntimeEventKind.DNS_RESPONSE}:
        dest = str(event.details.get("dest_ip") or "")
        if dest in LOOPBACK_ADDRS:
            return True
    return False


def _build_nodes(
    events: Sequence[RuntimeEvent],
    *,
    seed_pids: list[int],
) -> tuple[list[ProcessNode], list[RuntimeEvent]]:
    by_pid: dict[int, dict[str, Any]] = {}
    dns: list[RuntimeEvent] = []

    def ensure(pid: int, ppid: int | None, ts: float, details: Mapping[str, Any]) -> dict[str, Any]:
        node = by_pid.get(pid)
        if node is None:
            node = {
                "pid": pid,
                "ppid": ppid,
                "comm": str(details.get("comm") or ""),
                "argv": str(details.get("command_args") or details.get("path") or details.get("comm") or ""),
                "started_at": ts,
                "ended_at": None,
                "file_events": [],
                "net_events": [],
            }
            by_pid[pid] = node
        else:
            if ppid and not node["ppid"]:
                node["ppid"] = ppid
            if ts < node["started_at"]:
                node["started_at"] = ts
            comm = str(details.get("comm") or "")
            if comm and not node["comm"]:
                node["comm"] = comm
        return node

    for pid in seed_pids:
        ensure(pid, None, 0.0, {"comm": ""})

    for event in events:
        if event.kind == RuntimeEventKind.DNS_RESPONSE:
            dns.append(event)
            if event.pid:
                ensure(event.pid, event.ppid, event.timestamp, event.details)
            continue
        node = ensure(event.pid, event.ppid, event.timestamp, event.details)
        if event.kind == RuntimeEventKind.PROC_EXEC:
            path = str(event.details.get("path") or event.details.get("command_args") or "")
            if path:
                node["argv"] = path
                node["comm"] = Path(path).name or node["comm"]
        if event.kind == RuntimeEventKind.PROC_FORK:
            child = int(event.details.get("child_pid") or 0)
            if child:
                ensure(child, event.pid, event.timestamp, {"comm": event.details.get("comm", "")})
        if event.kind in {
            RuntimeEventKind.FILE_OPEN,
            RuntimeEventKind.FILE_READ,
            RuntimeEventKind.FILE_WRITE,
            RuntimeEventKind.FILE_UNLINK,
        }:
            node["file_events"].append(event)
        elif event.kind == RuntimeEventKind.NET_CONNECT:
            node["net_events"].append(event)

    models: dict[int, ProcessNode] = {}
    for pid, data in by_pid.items():
        models[pid] = ProcessNode(
            pid=data["pid"],
            ppid=data["ppid"],
            comm=data["comm"] or f"pid-{pid}",
            argv=data["argv"] or data["comm"] or f"pid-{pid}",
            started_at=data["started_at"],
            ended_at=data["ended_at"],
            file_events=list(data["file_events"]),
            net_events=list(data["net_events"]),
            children=[],
        )

    pids = set(models)
    roots: list[ProcessNode] = []
    for node in models.values():
        parent = node.ppid
        if parent and parent in pids and parent != node.pid:
            models[parent].children.append(node)
        else:
            roots.append(node)
    roots.sort(key=lambda item: item.pid)
    return roots, dns


def tree_to_dict(tree: ToolBehaviorTree) -> dict[str, Any]:
    return tree.model_dump(mode="json")


def clone_tree(tree: ToolBehaviorTree) -> ToolBehaviorTree:
    return tree.model_copy(deep=True)
