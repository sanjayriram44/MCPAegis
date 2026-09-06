# Rule authoring

This guide covers two extension points: **Semgrep sink rules** used by static taint analysis, and **taxonomy categories** (`Capability`, `Weakness`, `SinkType`).

## Semgrep rules

Packs live next to the runner:

- `mcpaegis/static/taint/rules/python.yaml` / `javascript.yaml` — **pattern** rules. Hits become `SinkFact.confidence="proximate"` (reachable / co-occurrence, not proven dataflow).
- `mcpaegis/static/taint/rules/taint/python-taint.yaml` / `javascript-taint.yaml` — **`mode: taint`**. Hits become `confidence="direct"` (tool-parameter source reached the sink). Lane B named W5/W6/W7 findings use only these.

The runner runs the pattern files, then the taint directory (plus generated YAML). Generated sources are **per handler file** (`paths.include` + `def <handler>(...)`) so a same-named function in another module is not a taint source. Generated taint rules copy **sink-type sanitizers** (e.g. `shlex.quote` for `shell_exec` only — quoting does not sanitize `open`/`eval`). Shared helpers emit one `SinkFact` per attributing tool; `direct` wins only for the tool whose parameter actually reached the sink.

Python `open($PATH, ...)` matches keyword arguments (`encoding=`) as well as a mode string. Prefer that over `open($PATH)` alone when adding file sinks.

### Required metadata

Every rule **must** set `metadata.sink_type` to a `SinkType` value:

| `sink_type` | Maps to capability | Typical APIs |
| --- | --- | --- |
| `shell_exec` | `SHELL_EXEC` (`C3`) | `subprocess.*`, `os.system`, `child_process.exec` |
| `file_read` | `FS_READ` (`C1`) | `open(..., "r")`, `Path.read_text`, `fs.readFile` |
| `file_write` | `FS_WRITE` (`C2`) | `open(..., "w")`, `Path.write_text`, `fs.writeFile` |
| `network_call` | `NET_OUTBOUND` (`C4`) | `requests.*`, `httpx.*`, `urllib.request.urlopen` |
| `db_query` | `DB_ACCESS` (`C6`) | `cursor.execute`, `sqlite3.connect` |
| `dynamic_code_load` | *(no capability map; flagged under W5)* | `eval`, `exec`, `importlib.import_module` |
| `credential_read` | `CREDENTIAL_HANDLING` (`C7`) | `os.environ`, `os.getenv`, `keyring.get_password` |

`SINK_TO_CAPABILITY` in `mcpaegis/core/taxonomy.py` is the source of truth for capability derivation. `dynamic_code_load` is intentionally absent from that map.

### Rule skeleton

```yaml
rules:
  - id: mcpaegis.python.shell_exec.os_system
    message: Process execution sink (os.system)
    languages: [python]
    severity: ERROR
    metadata:
      sink_type: shell_exec
    pattern-either:
      - pattern: os.system(...)
      - pattern: os.popen(...)
```

Conventions:

- **id** — `mcpaegis.<lang>.<sink_type>.<short-name>`. Copied into `SinkFact.rule_id`.
- **languages** — `python` or `javascript` / `typescript` to match the pack.
- **severity** — Semgrep’s own severity (`ERROR` / `WARNING`); MCPAegis weakness severity is assigned later (cross-check, merger, writers).
- Prefer `pattern-either` over a single overly-broad pattern.

After adding a **pattern** rule, run static analysis against `tests/fixtures/unrelated_cleanup` and expect a `proximate` sink (no W5). After adding a **taint** rule, use `tests/fixtures/command_injection` / `path_traversal` / `ssrf` / `eval_format` and expect a `direct` W5/W6/W7 (`eval_format` is `dynamic_code_load` → W5).

Package data includes `static/taint/rules/*.yaml` and `static/taint/rules/taint/*.yaml`.

## Taxonomy categories

Enums live in `mcpaegis/core/taxonomy.py`.

### Adding a capability

1. Add a member to `Capability` (`C13`, …) with a short comment.
2. If a sink produces it, add an entry to `SINK_TO_CAPABILITY`.
3. Teach `mcpaegis/static/capability_classifier.py` `KEYWORD_RULES` so tool names and **argument names** can *declare* the capability. Do not match free-text tool descriptions (negations and incidental words). Avoid generic tokens (`query`) unless they are unambiguous (`sql`, `database`).
4. Update writers if you want a human title (`mcpaegis/output/findings.py` already formats `NAME (Cn)` from the enum).

### Adding a weakness (finding)

1. Add `Wxx_NAME = "Wxx"` to `Weakness` and implement a stage that emits the matching model (`PoisoningFlag`, `CrossCheckFinding`, `RuntimeFinding`, …). Do not reserve unused IDs.
2. Add a title in `WEAKNESS_TITLES` and a default severity in `_DEFAULT_SEVERITY` inside `mcpaegis/output/findings.py`.
3. SARIF publishes every `Weakness` member as a rule even when a run has no results — new IDs appear automatically.
4. Wire `--categories Wxx` via the existing `Weakness` enum (`AuditSession.parse_categories`).

### Adding a sink type

1. Add `SinkType` and, if it should participate in W3 cross-check, map it in `SINK_TO_CAPABILITY`.
2. Add Semgrep rules with `metadata.sink_type` matching the enum **value** (snake_case string).
3. Privileged-sink heuristics:
   - W8 access control: `PRIVILEGED_SINKS` in `access_control_check.py`.
   - W1 LLM second pass: `PRIVILEGED_SINKS` in `metadata_classifier.py`.

### Combining pipelines

`mcpaegis/combine/merger.py` tags findings:

- `static_only` — present only in the static report.
- `runtime_confirmed` — same weakness id on a tool in static **and** a runtime finding with `status="confirmed"`.
- `runtime_only` — runtime finding with `status="runtime_only"` (or confirmed with no static counterpart).

New weakness IDs do not need merger changes if both pipelines use the same `weakness_id` string.

## Tests

Prefer unit tests that construct models by hand (see `tests/unit/`). Fixture servers under `tests/fixtures/` are small, vendored MCP apps — not an external submodule.
