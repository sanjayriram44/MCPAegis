from mcpaegis.core.models import RuntimeEvent
from mcpaegis.core.taxonomy import RuntimeEventKind
from mcpaegis.dynamic.behavior_tree import assemble, is_noise


def _evt(kind: RuntimeEventKind, pid: int, **details) -> RuntimeEvent:
    return RuntimeEvent(
        id="e",
        kind=kind,
        pid=pid,
        ppid=1,
        cgroup_id="1",
        timestamp=1.0,
        details=details,
    )


def test_assemble_returns_one_filtered_tree():
    events = [
        _evt(RuntimeEventKind.FILE_OPEN, 2, path="/usr/lib/libc.so.6", comm="python"),
        _evt(RuntimeEventKind.PROC_EXEC, 3, path="/bin/sh", command_args="/bin/sh -c echo", comm="sh"),
        _evt(RuntimeEventKind.NET_CONNECT, 2, dest_ip="127.0.0.1", dest_port=53, comm="python"),
    ]
    tree = assemble(events, call_id="c1", tool_name="run_cmd", arguments={"command": "echo"}, seed_pids=[2])
    assert tree.call_id == "c1"
    assert not any(
        is_noise(evt) is False and str((evt.details or {}).get("path") or "").endswith(".so.6")
        for node in tree.process_branch
        for evt in node.file_events
    )
    comms = []

    def walk(nodes):
        for n in nodes:
            comms.append(n.comm)
            walk(n.children)

    walk(tree.process_branch)
    assert "sh" in comms
