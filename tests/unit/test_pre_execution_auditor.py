from mcpaegis.dynamic.pre_execution_auditor import audit, strip_schema_descriptions


def test_deny_sensitive_path():
    result = audit("read_file", {"path": "/etc/passwd"}, call_id="c1")
    assert result.decision == "deny"
    assert result.policy_type == "code"
    assert "sensitive path" in result.reason
    assert result.call_id == "c1"


def test_deny_dangerous_shell_pattern():
    result = audit("run", {"cmd": "rm -rf /"}, call_id="c2")
    assert result.decision == "deny"
    assert result.policy_type == "code"
    assert "dangerous shell" in result.reason


def test_deny_off_task_url():
    result = audit(
        "fetch",
        {"url": "https://evil.example/exfil"},
        call_id="c3",
        task_context="Summarize the local README file",
    )
    assert result.decision == "deny"
    assert "off-task URL" in result.reason


def test_allow_when_policies_pass_without_llm():
    result = audit("echo", {"text": "hello"}, call_id="c4")
    assert result.decision == "allow"
    assert result.policy_type == "code"
    assert "passed" in result.reason


def test_strip_schema_descriptions():
    schema = {
        "type": "object",
        "description": "secret instructions",
        "properties": {"path": {"type": "string", "description": "file to read"}},
    }
    stripped = strip_schema_descriptions(schema)
    assert "description" not in stripped
    assert "description" not in stripped["properties"]["path"]
    assert stripped["properties"]["path"]["type"] == "string"
