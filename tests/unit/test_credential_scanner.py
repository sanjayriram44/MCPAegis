from pathlib import Path

from mcpaegis.static.credential_scanner import redact_secret, scan

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
API_LINE = 'api_key = "mcp_demo_abcdefghijklmnopqrstuvwxyz0123"'
GITHUB = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


def test_redact_secret_never_returns_raw_value():
    raw = "supersecretvalue1234"
    redacted = redact_secret(raw)
    assert raw not in redacted
    assert "sha256=" in redacted
    assert redacted.startswith("supe") and "1234" in redacted


def test_short_secret_is_fully_redacted():
    raw = "abcd1234"
    redacted = redact_secret(raw)
    assert raw not in redacted
    assert redacted.startswith("[REDACTED")


def test_scan_redacts_aws_and_api_keys(tmp_path: Path):
    src = tmp_path / "config.py"
    src.write_text(
        "\n".join(
            [
                f"AWS_ACCESS_KEY_ID = '{AWS_KEY}'",
                API_LINE,
                f"token = '{GITHUB}'",
            ]
        ),
        encoding="utf-8",
    )
    findings = scan(tmp_path)
    assert findings
    blobs = " ".join(f.snippet for f in findings)
    assert AWS_KEY not in blobs
    assert "mcp_demo_abcdefghijklmnopqrstuvwxyz0123" not in blobs
    assert GITHUB not in blobs
    for finding in findings:
        assert finding.weakness_id == "W14"
        assert "sha256=" in finding.snippet or "REDACTED" in finding.snippet
        assert finding.pattern in {
            "aws_access_key_id",
            "generic_api_key",
            "github_token",
        }


def test_scan_skips_venv_and_does_not_persist_raw_secret(tmp_path: Path):
    hidden = tmp_path / ".venv" / "lib" / "secrets.py"
    hidden.parent.mkdir(parents=True)
    hidden.write_text(f"KEY = '{AWS_KEY}'\n", encoding="utf-8")
    visible = tmp_path / "app.py"
    visible.write_text("print('ok')\n", encoding="utf-8")
    findings = scan(tmp_path)
    assert findings == []
    # The on-disk fixture still contains the key; reports must not.
    assert AWS_KEY in hidden.read_text(encoding="utf-8")
