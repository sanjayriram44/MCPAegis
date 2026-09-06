"""Minimal MCP JSON-RPC client (stdio) for initialize / list / tools/call."""

from __future__ import annotations

import json
import os
import select
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from subprocess import Popen
from typing import Any, BinaryIO, Optional

PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "mcpaegis"
CLIENT_VERSION = "0.1.0"


class McpClientError(Exception):
    """MCP handshake or RPC failure."""


MCPClientError = McpClientError


@dataclass
class HandshakeResult:
    """Live MCP list payloads from initialize → tools/list → resources/list → prompts/list."""

    tools: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    prompts: list[dict[str, Any]]


def handshake(
    launch_cmd: Sequence[str],
    *,
    cwd: str | Path | None = None,
    timeout: float = 10.0,
) -> HandshakeResult:
    """Launch a local MCP server over stdio and return listed tools/resources/prompts."""
    proc = subprocess.Popen(
        list(launch_cmd),
        cwd=str(cwd) if cwd is not None else None,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    client = McpClient(proc, timeout=timeout)
    try:
        client.initialize()
        return HandshakeResult(
            tools=client.list_tools(),
            resources=client.list_resources(),
            prompts=client.list_prompts(),
        )
    finally:
        client.close()
        _stop_proc(proc)


class McpClient:
    """Speak MCP over a subprocess stdin/stdout pair (Content-Length or NDJSON)."""

    def __init__(
        self,
        proc: Popen[bytes],
        *,
        timeout: float = 30.0,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> None:
        self._proc = proc
        self._stdin: BinaryIO = stdin or proc.stdin  # type: ignore[assignment]
        self._stdout: BinaryIO = stdout or proc.stdout  # type: ignore[assignment]
        if self._stdin is None or self._stdout is None:
            raise McpClientError("MCP subprocess must be started with stdin/stdout pipes")
        self._timeout = timeout
        self._next_id = 1
        self._lock = threading.Lock()
        self._buf = bytearray()
        try:
            os.set_blocking(self._stdout.fileno(), False)
        except (OSError, ValueError, AttributeError):
            pass

    @property
    def proc(self) -> Popen[bytes]:
        return self._proc

    def initialize(self) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        )
        self.notify("notifications/initialized", {})
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list", {})
        tools = result.get("tools", [])
        if not isinstance(tools, list):
            return []
        return [t for t in tools if isinstance(t, dict)]

    def list_resources(self) -> list[dict[str, Any]]:
        try:
            result = self.request("resources/list", {})
        except McpClientError:
            return []
        resources = result.get("resources", [])
        return [r for r in resources if isinstance(r, dict)] if isinstance(resources, list) else []

    def list_prompts(self) -> list[dict[str, Any]]:
        try:
            result = self.request("prompts/list", {})
        except McpClientError:
            return []
        prompts = result.get("prompts", [])
        return [p for p in prompts if isinstance(p, dict)] if isinstance(prompts, list) else []

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.request(
            "tools/call",
            {"name": name, "arguments": dict(arguments or {})},
        )

    def request(self, method: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            msg_id = self._next_id
            self._next_id += 1
            payload: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = dict(params)
            self._write(payload)
            deadline = time.monotonic() + self._timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpClientError(f"timed out waiting for MCP response to {method!r}")
                message = self._read_message(remaining)
                if message is None:
                    raise McpClientError(f"MCP server closed the stream during {method!r}")
                if message.get("method") and "id" not in message:
                    continue
                if message.get("id") != msg_id:
                    continue
                if "error" in message:
                    raise McpClientError(f"MCP error for {method!r}: {message['error']}")
                result = message.get("result")
                return result if isinstance(result, dict) else {"value": result}

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        with self._lock:
            payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                payload["params"] = dict(params)
            self._write(payload)

    def close(self) -> None:
        try:
            self._stdin.close()
        except OSError:
            pass

    def _write(self, payload: dict[str, Any]) -> None:
        # Official MCP Python stdio transport is NDJSON (one JSON object per line).
        # Content-Length framing is still accepted on *read* for other servers.
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            self._stdin.write(body)
            self._stdin.flush()
        except OSError as exc:
            raise McpClientError(f"failed to write MCP message: {exc}") from exc

    def _read_message(self, timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpClientError("timed out reading MCP message")
            parsed = self._try_parse()
            if parsed is not None:
                return parsed
            got = self._fill(remaining)
            if got is None:
                parsed = self._try_parse(final=True)
                return parsed
            if got is False:
                parsed = self._try_parse(final=True)
                if parsed is not None:
                    return parsed
                continue

    def _fill(self, timeout: float) -> bool | None:
        """Read whatever is ready. ``True`` = bytes, ``False`` = wait, ``None`` = EOF.

        Uses ``os.read`` so we never block for a full buffer after ``select``.
        """
        fd = self._stdout.fileno()
        ready, _, _ = select.select([fd], [], [], max(timeout, 0.0))
        if not ready:
            return False
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            return False
        except OSError as exc:
            raise McpClientError(f"failed to read MCP stdout: {exc}") from exc
        if not chunk:
            return None
        self._buf.extend(chunk)
        return True

    def _try_parse(self, final: bool = False) -> dict[str, Any] | None:
        if not self._buf:
            return None

        # Content-Length framed
        header_end = self._buf.find(b"\r\n\r\n")
        sep_len = 4
        if header_end < 0:
            header_end = self._buf.find(b"\n\n")
            sep_len = 2
        if header_end >= 0:
            header = bytes(self._buf[:header_end]).decode("utf-8", errors="replace")
            length: Optional[int] = None
            for line in header.replace("\r\n", "\n").split("\n"):
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key.strip().lower() == "content-length":
                    try:
                        length = int(value.strip())
                    except ValueError as exc:
                        raise McpClientError(f"invalid Content-Length {value!r}") from exc
            if length is None:
                # Might be NDJSON that happened to contain blank lines; fall through
                pass
            else:
                start = header_end + sep_len
                if len(self._buf) < start + length:
                    return None
                body = bytes(self._buf[start : start + length])
                del self._buf[: start + length]
                return _loads_obj(body)

        # NDJSON fallback
        nl = self._buf.find(b"\n")
        if nl < 0:
            if final and self._buf.strip().startswith(b"{"):
                body = bytes(self._buf)
                self._buf.clear()
                return _loads_obj(body)
            return None
        line = bytes(self._buf[:nl]).strip()
        del self._buf[: nl + 1]
        if not line:
            return None if not final else None
        if line.startswith(b"{"):
            return _loads_obj(line)
        return None


def _stop_proc(proc: Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()
        try:
            proc.wait(timeout=1)
        except Exception:
            pass


def _loads_obj(body: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise McpClientError(f"invalid MCP JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise McpClientError("MCP message was not a JSON object")
    return parsed
