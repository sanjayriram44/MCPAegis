"""BCC wrapper: load bpf_programs.c, cgroup-filter, start/stop/drain RuntimeEvents."""

from __future__ import annotations

import platform
import socket
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from mcpaegis.core.models import RuntimeEvent
from mcpaegis.core.taxonomy import RuntimeEventKind
from mcpaegis.dynamic.errors import RuntimeUnavailableError

BPF_SOURCE = Path(__file__).resolve().parent / "bpf_programs.c"

KIND_MAP = {
    1: RuntimeEventKind.FILE_OPEN,
    2: RuntimeEventKind.FILE_READ,
    3: RuntimeEventKind.FILE_WRITE,
    4: RuntimeEventKind.FILE_UNLINK,
    5: RuntimeEventKind.NET_CONNECT,
    6: RuntimeEventKind.PROC_EXEC,
    7: RuntimeEventKind.PROC_FORK,
    8: RuntimeEventKind.DNS_RESPONSE,
}


class EbpfUnavailableError(RuntimeUnavailableError):
    """Linux kernel, BCC, or tracepoint attach is missing/unusable."""


def _require_linux() -> None:
    system = platform.system()
    if system != "Linux":
        raise EbpfUnavailableError(
            f"eBPF runtime monitor requires Linux; this host is {system}. "
            "Run `mcpaegis static` instead, or use a Lima Ubuntu VM with BCC "
            "(docs/lima-runtime.md)."
        )


def _raise_memlock() -> None:
    """BCC maps need RLIMIT_MEMLOCK; the default 64KiB yields EPERM on bpf()."""
    try:
        import resource
    except ImportError:
        return

    inf = resource.RLIM_INFINITY
    try:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (inf, inf))
        return
    except (ValueError, OSError):
        pass
    try:
        _soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    except (ValueError, OSError):
        return
    # PAM limits.d does not apply to `limactl shell`. A 64KiB hard cap cannot
    # be raised from userspace; sudo prlimit on this PID can.
    if hard != inf and hard < 256 * 1024 * 1024:
        raise EbpfUnavailableError(
            "RLIMIT_MEMLOCK is too low for BCC "
            f"(hard={hard} bytes). In the Lima guest run "
            "`sudo prlimit --pid $$ --memlock=unlimited` then retry "
            "`mcpaegis runtime` in the same shell (do not sudo mcpaegis)."
        )


def _import_bcc() -> Any:
    _require_linux()
    try:
        from bcc import BPF  # type: ignore[import-untyped]
    except ImportError as exc:
        raise EbpfUnavailableError(
            "eBPF runtime monitor requires BCC (`python3-bpfcc` / `bcc`). "
            "Install BCC matching the host kernel, then retry `mcpaegis runtime`."
        ) from exc
    return BPF


def _decode_cstr(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw.split("\x00", 1)[0]
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _ipv4(n: int) -> str:
    try:
        return socket.inet_ntoa(struct.pack("=I", n))
    except OSError:
        return "0.0.0.0"


class Monitor:
    """Host-side eBPF monitor filtered to a sandbox cgroup inode."""

    def __init__(
        self,
        cgroup_id: str | int,
        *,
        seed_pids: Optional[list[int]] = None,
        bpf_source: Path | None = None,
        bpf_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        try:
            self._cgroup_id = int(cgroup_id)
        except (TypeError, ValueError) as exc:
            raise EbpfUnavailableError(f"invalid cgroup inode {cgroup_id!r}") from exc
        self._seed_pids = list(seed_pids or [])
        self._bpf_source = Path(bpf_source) if bpf_source else BPF_SOURCE
        self._bpf_factory = bpf_factory
        self._bpf: Any = None
        self._lock = threading.Lock()
        self._buffer: list[RuntimeEvent] = []
        self._running = False
        self._open_at: float = 0.0

    def start(self) -> None:
        """Attach raw_tracepoint/sys_enter + kprobes and begin collecting."""
        with self._lock:
            if not self._running:
                self._attach()
            self._buffer.clear()
            self._open_at = time.time()
            self._running = True

    def stop(self) -> None:
        with self._lock:
            self._running = False
            bpf = self._bpf
            self._bpf = None
        if bpf is not None:
            try:
                bpf.cleanup()
            except Exception:
                pass

    def drain(self) -> list[RuntimeEvent]:
        """Return events captured since the last ``start()`` (or previous drain)."""
        self._poll()
        with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
        return events

    def _attach(self) -> None:
        if self._bpf is not None:
            return
        if not self._bpf_source.is_file():
            raise EbpfUnavailableError(f"BPF program missing at {self._bpf_source}")
        text = self._bpf_source.read_text(encoding="utf-8")
        factory = self._bpf_factory or _import_bcc()
        cflags = [f"-DTARGET_CGROUP_ID={self._cgroup_id}ULL"]
        _raise_memlock()
        try:
            self._bpf = factory(text=text, cflags=cflags)
        except EbpfUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise EbpfUnavailableError(
                f"failed to load eBPF programs: {exc}. "
                "raw_tracepoint/sys_enter and kprobes need root (CAP_SYS_ADMIN). "
                "In the Lima guest: "
                'sudo -E "$HOME/mcpaegis-venv/bin/mcpaegis" runtime … '
                "(use the venv binary; a bare `sudo mcpaegis` has no PATH)."
            ) from exc
        try:
            self._bpf["events"].open_perf_buffer(self._on_event, page_cnt=64)
        except Exception as exc:  # noqa: BLE001
            raise EbpfUnavailableError(
                f"failed to open eBPF perf buffer: {exc}"
            ) from exc

    def _poll(self, timeout_ms: int = 200) -> None:
        bpf = self._bpf
        if bpf is None:
            return
        deadline = time.monotonic() + max(timeout_ms, 1) / 1000.0
        while time.monotonic() < deadline:
            try:
                bpf.perf_buffer_poll(timeout=50)
            except Exception:
                break

    def _on_event(self, _cpu: int, data: Any, _size: int) -> None:
        if not self._running:
            return
        try:
            event = self._parse(data)
        except Exception:
            return
        if event is None:
            return
        with self._lock:
            self._buffer.append(event)

    def _parse(self, data: Any) -> RuntimeEvent | None:
        bpf = self._bpf
        raw = bpf["events"].event(data) if bpf is not None and hasattr(bpf, "__getitem__") else data
        kind_num = int(getattr(raw, "kind", 0))
        kind = KIND_MAP.get(kind_num)
        if kind is None:
            return None
        pid = int(getattr(raw, "pid", 0))
        ppid = int(getattr(raw, "ppid", 0)) or None
        cgroup_id = str(int(getattr(raw, "cgroup_id", self._cgroup_id)))
        ts_ns = int(getattr(raw, "timestamp", 0))
        timestamp = (ts_ns / 1e9) if ts_ns else time.time()
        comm = _decode_cstr(getattr(raw, "comm", b""))
        path = _decode_cstr(getattr(raw, "path", b""))
        details: dict[str, Any] = {"comm": comm}
        if kind in {
            RuntimeEventKind.FILE_OPEN,
            RuntimeEventKind.FILE_UNLINK,
            RuntimeEventKind.PROC_EXEC,
        }:
            details["path"] = path
            if kind == RuntimeEventKind.PROC_EXEC:
                details["command_args"] = path
        if kind in {RuntimeEventKind.FILE_READ, RuntimeEventKind.FILE_WRITE}:
            details["fd"] = int(getattr(raw, "fd", 0))
        if kind in {RuntimeEventKind.NET_CONNECT, RuntimeEventKind.DNS_RESPONSE}:
            dest_ip = _ipv4(int(getattr(raw, "dest_ip", 0)))
            dest_port = int(getattr(raw, "dest_port", 0))
            details["dest_ip"] = dest_ip
            details["dest_port"] = dest_port
        if kind == RuntimeEventKind.PROC_FORK:
            details["child_pid"] = int(getattr(raw, "child_pid", 0))
        return RuntimeEvent(
            id=f"evt_{uuid.uuid4().hex}",
            kind=kind,
            pid=pid,
            ppid=ppid,
            cgroup_id=cgroup_id,
            timestamp=timestamp,
            details=details,
        )

    @property
    def seed_pids(self) -> list[int]:
        return list(self._seed_pids)
