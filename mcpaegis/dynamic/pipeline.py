"""Orchestrates dynamic stages 0–6 and produces a DynamicReport."""

from __future__ import annotations

import json
import uuid
import warnings
from pathlib import Path
from typing import Any, Sequence

from mcpaegis.core.mcp_client import McpClient, McpClientError
from mcpaegis.core.models import (
    CanarySeed,
    DynamicReport,
    PostExecutionVerification,
    PreExecutionAuditResult,
    ServerMetadata,
    StaticReport,
    ToolBehaviorTree,
    ToolMetadata,
)
from mcpaegis.core.session import AuditSession
from mcpaegis.dynamic.behavior_tree import assemble as assemble_tree
from mcpaegis.dynamic.canary import FILE_CANARY_NAME, plant_env, plant_file
from mcpaegis.dynamic.ebpf.monitor import Monitor
from mcpaegis.dynamic.errors import DynamicPipelineError, RuntimeUnavailableError
from mcpaegis.dynamic.invocation_generator import PlannedInvocation, generate as generate_invocations
from mcpaegis.dynamic.post_execution_verifier import verify as verify_post
from mcpaegis.dynamic.pre_execution_auditor import audit as audit_pre
from mcpaegis.dynamic.report_builder import build as build_report
from mcpaegis.dynamic.sandbox import process_provider
from mcpaegis.dynamic.sink_inspector import inspect as inspect_sinks

STATIC_REPORT_NAME = "static-report.json"


def assert_runtime_available(*, sandbox: str = "process") -> None:
    """Raise ``RuntimeUnavailableError`` if this host cannot run the dynamic pipeline."""
    if sandbox not in {"process", "local"}:
        raise RuntimeUnavailableError(
            f"unsupported sandbox provider {sandbox!r}; only 'process' is implemented "
            "(local MCP server + nested cgroup, no Docker)."
        )
    process_provider.require_linux()
    from mcpaegis.dynamic.ebpf.monitor import _import_bcc

    _import_bcc()


def run(
    path: Path | str,
    *,
    session: AuditSession | None = None,
    test_script: Path | str | None = None,
    max_calls: int | None = None,
    timeout: float | int | None = None,
    sandbox: str = "process",
    static_report: StaticReport | Path | str | None = None,
    server: ServerMetadata | None = None,
) -> DynamicReport:
    """Run stages 0–6. Raises ``RuntimeUnavailableError`` if Linux/eBPF cannot run."""
    server_path = Path(path).resolve()
    session = session or AuditSession.from_cli()
    per_call_timeout = float(timeout) if timeout is not None else 30.0

    if sandbox == "docker":
        sandbox = "process"
    assert_runtime_available(sandbox=sandbox)

    static = _load_static_report(static_report, session.output_dir)
    if static is None:
        warnings.warn(
            "no static profile found — running without declared-vs-observed verification",
            UserWarning,
            stacklevel=2,
        )

    metadata = server or (static.server if static else None) or _fallback_metadata(server_path)
    profiles = list(static.expected_behavior_profiles) if static else []
    profile_by_tool = {p.tool_name: p for p in profiles}

    canary_dir = session.output_dir / "canaries"
    canary_dir.mkdir(parents=True, exist_ok=True)
    env_seed = plant_env("MCPAEGIS_CANARY_ENV")
    extra_env = {env_seed.key: env_seed.value}
    file_seed = plant_file(canary_dir / FILE_CANARY_NAME, key="MCPAEGIS_CANARY_FILE")

    handle = process_provider.launch(
        server_path,
        entrypoint=metadata.entrypoint,
        language=metadata.language,
        canary_dir=canary_dir,
        extra_env=extra_env,
        timeout=per_call_timeout,
    )
    monitor: Monitor | None = None
    client: McpClient | None = None
    try:
        seed_pids = process_provider.read_cgroup_procs(handle)
        monitor = Monitor(handle.cgroup_id, seed_pids=seed_pids)
        # Fail fast if BCC/eBPF cannot load, before dispatching tool calls.
        monitor.start()
        monitor.drain()

        client = McpClient(handle.proc, timeout=per_call_timeout)
        try:
            client.initialize()
            live_tools = client.list_tools()
        except McpClientError as exc:
            code = handle.proc.poll()
            tail = _sandbox_stderr_tail(handle)
            bits = [str(exc)]
            if code is not None:
                bits.append(f"server exited with code {code}")
            if tail:
                bits.append(f"--- sandbox stderr ---\n{tail}")
            else:
                bits.append(
                    "no stderr. If you installed mcp 2.x, FastMCP is gone — "
                    "pip install 'mcp>=1.2,<2' then retry."
                )
            raise DynamicPipelineError(
                "MCP handshake with local server failed: " + "\n".join(bits)
            ) from exc

        tools = _merge_tools(metadata.tools, live_tools)
        planned = generate_invocations(
            tools,
            profiles=profiles,
            test_script=test_script,
            max_calls=max_calls,
        )

        pre_audits: list[PreExecutionAuditResult] = []
        trees: list[ToolBehaviorTree] = []
        verifications: list[PostExecutionVerification] = []
        witnesses_all = []
        seeds: list[CanarySeed] = [env_seed, file_seed]

        for inv in planned:
            call_id = f"call_{uuid.uuid4().hex}"
            seeds.extend(inv.canaries)
            pre = audit_pre(
                inv.tool_name,
                inv.arguments,
                call_id=call_id,
                schema=inv.schema,
                session=session,
            )
            pre_audits.append(pre)
            if pre.decision == "deny":
                continue

            tree, response = _dispatch_call(
                client,
                monitor,
                inv,
                call_id=call_id,
                seed_pids=seed_pids,
            )
            trees.append(tree.raw)
            verifications.append(
                verify_post(
                    tree.raw,
                    profile_by_tool.get(inv.tool_name),
                    call_id=call_id,
                    simplified=tree.simplified,
                    session=session,
                    schema=inv.schema,
                )
            )
            witnesses_all.extend(inspect_sinks(response, seeds, call_id=call_id))

        return build_report(
            server_path=server_path,
            trees=trees,
            pre_audits=pre_audits,
            verifications=verifications,
            canary_seeds=seeds,
            sink_witnesses=witnesses_all,
            session=session,
            output_dir=session.output_dir,
            output_format=session.output_format,
        )
    finally:
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        process_provider.teardown(handle)


def _dispatch_call(
    client: McpClient,
    monitor: Monitor,
    inv: PlannedInvocation,
    *,
    call_id: str,
    seed_pids: Sequence[int],
):
    monitor.start()
    try:
        response = client.call_tool(inv.tool_name, inv.arguments)
    except McpClientError as exc:
        response = {"error": str(exc), "isError": True}
    events = monitor.drain()
    trees = assemble_tree(
        events,
        call_id=call_id,
        tool_name=inv.tool_name,
        arguments=inv.arguments,
        seed_pids=seed_pids,
    )
    return trees, response


def _load_static_report(
    static_report: StaticReport | Path | str | None,
    output_dir: Path,
) -> StaticReport | None:
    if isinstance(static_report, StaticReport):
        return static_report
    candidates: list[Path] = []
    if static_report is not None:
        candidates.append(Path(static_report))
    candidates.append(output_dir / STATIC_REPORT_NAME)
    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return StaticReport.model_validate(data)
            except Exception as exc:  # noqa: BLE001
                warnings.warn(f"failed to load static report {path}: {exc}", UserWarning, stacklevel=3)
    return None


def _sandbox_stderr_tail(handle: Any, *, limit: int = 4000) -> str:
    log = getattr(handle, "stderr_log", None)
    fh = getattr(handle, "_stderr_handle", None)
    if fh is not None:
        try:
            fh.flush()
        except OSError:
            pass
    if log is None:
        return ""
    path = Path(log)
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    text = text.strip()
    if len(text) > limit:
        return text[-limit:]
    return text


def _fallback_metadata(server_path: Path) -> ServerMetadata:
    from mcpaegis.static.discovery import detect_entrypoint, detect_language

    language, manifest = detect_language(server_path)
    entrypoint, _cmd = detect_entrypoint(server_path, language)
    if not entrypoint:
        entrypoint = "node index.js" if language in {"javascript", "typescript"} else "python3 server.py"
    return ServerMetadata(
        entrypoint=entrypoint,
        language=language,
        manifest_path=str(manifest) if manifest else None,
        tools=[],
        resources=[],
        prompts=[],
        source="static_fallback",
    )


def _merge_tools(
    existing: Sequence[ToolMetadata],
    live: Sequence[dict[str, Any]],
) -> list[ToolMetadata]:
    by_name = {t.name: t for t in existing}
    for item in live:
        name = str(item.get("name") or "")
        if not name:
            continue
        schema = item.get("inputSchema") or item.get("input_schema") or {}
        if not isinstance(schema, dict):
            schema = {}
        description = str(item.get("description") or "")
        if name in by_name:
            current = by_name[name]
            by_name[name] = current.model_copy(
                update={
                    "description": current.description or description,
                    "input_schema": current.input_schema or schema,
                }
            )
        else:
            by_name[name] = ToolMetadata(
                name=name,
                description=description,
                input_schema=schema,
            )
    return list(by_name.values())
