# MCPAegis

CLI for **static** and **dynamic (sandboxed runtime)** security analysis of **local MCP (Model Context Protocol) servers** when source is available.

Package and command: `mcpaegis`. Requires **Python 3.11+**.

MCP servers expose **tools** (named functions with JSON Schema arguments) that an agent can call. MCPAegis does not sit in the agent loop. It audits a **local source tree**: what the server advertises, what the code can do, and (on Linux) what actually happens when a tool is invoked.

The **product** is one overall finding list (W1–W10). Static analysis and runtime analysis are **evidence sources**, not two scores. A planted bug counts if it appears in the combined report, whether Semgrep named it, eBPF confirmed it, or both. Combined rows still record the source (`static_only` / `runtime_confirmed` / `runtime_only`) so you can see *how* it was found.

```mermaid
flowchart LR
  Src["Local MCP server tree"] --> Static["mcpaegis static"]
  Src --> Dyn["mcpaegis runtime"]
  Static --> SJ["static-report.json"]
  Dyn --> RJ["runtime-report.json"]
  SJ --> Merge["combine/merger"]
  RJ --> Merge
  Merge --> CJ["combined-report.json / sarif / md"]
```

- **Static** never executes tool bodies. It reads metadata and source. It runs on macOS.
- **Dynamic** *does* call tools as a **local process** in the Lima VM, while eBPF watches that process tree (nested cgroup). It requires **Linux + BCC**. Darwin is the wrong kernel. On Apple Silicon, `mcpaegis` (no args) opens a TUI that starts Lima and runs runtime in the guest ([docs/lima-runtime.md](docs/lima-runtime.md)).

On Apple Silicon, `mcpaegis runtime` and `mcpaegis full` (CLI or TUI) start Lima automatically: static on the Mac, runtime in the guest, merge locally. On Linux they run in-process.

### Current status

- **Catalog is W1–W10.** Old W11 (runtime canary leak) is **W10 runtime evidence**, not a separate ID.
- **Overall result is the product.** Combined JSON/SARIF/MD is the score. Static and runtime reports are kept so you can see *how* an ID was named (`static_only` / `runtime_confirmed` / `runtime_only`).
- **Static** runs on macOS or Linux. After discovery, three lanes run in parallel: advertisement (W1 + declared caps), Semgrep (W5/W6/W7), inventory (W4 + static W10). W8 needs sinks only; W3 joins declared vs code.
- **Runtime** needs Linux + BCC + cgroup v2 (Lima Ubuntu ARM64 on Apple Silicon). No Docker. Pre-exec is a **code-only** dangerous-dispatch gate (no LLM). One **filtered** behavior tree per call (loader/loopback noise dropped; not a raw+simplified pair).
- **LLM (optional)** is Lane A advertisement (W1 + declared caps) and the runtime Stage 4 **emitter** (W3/W5/W6/W7/W9/W10). No key → regex/keyword fallback for static, code verifier for runtime. Static never fails closed.
- **W7** means caller-controlled URL reached a fetch, not “we proved there is no allowlist.”
- **Known overall gaps** (latest `out/full6` Linux + LLM run): Semgrep still emits HIGH W5 on `sanitized_shell` (`shlex.quote` + argv); leftover LOW W3 on stub names. Planted W1–W8/W10 and SSRF W7 otherwise land. Runtime canary W10 has no planted positive fixture yet.

---

## What it does

### Weaknesses (W1–W10)

There is one catalog. Every ID below is implemented. There are no reserved / deferred IDs.

| ID | Name | Evidence | What gets flagged |
| --- | --- | --- | --- |
| W1 | Tool poisoning | Static Lane A (LLM or regex) | Tool description/schema contains hidden instructions, jailbreak language, homoglyphs, base64 blobs, or cross-tool override text |
| W2 | Tool shadowing | Static code (not LLM) | Two tools have lookalike names after normalize/leet (different implementations) |
| W3 | Over-privileged / capability mismatch | Join declared vs code; runtime can confirm | Code sinks imply a capability the advertisement never declared (`under_declared`), or the reverse (`over_declared`, LOW). Runtime confirms when the process tree shows that undeclared shell/net |
| W4 | Supply chain | Lane C SCA | `pip-audit` / `npm audit` / `osv-scanner` / `cargo-audit` CVEs; npm install scripts surfaced for review |
| W5 | Command / SQL injection | Lane B taint `direct`; runtime if `/bin/sh` (etc.) | Tool parameter reaches `shell_exec` / `db_query` / `dynamic_code_load`. Runtime confirms only on a real shell interpreter child — not `/bin/echo` after quoting, not in-process `eval` |
| W6 | Path traversal | Lane B taint; runtime `FILE_OPEN`/`WRITE` | Untrusted path reaches `file_read` / `file_write`. Runtime needs a non-empty, non-loader path |
| W7 | SSRF | Lane B taint; runtime `NET_CONNECT`/`DNS` | Untrusted URL reaches `network_call`. Not an allowlist scanner: a real host (e.g. `http://example.com/`) is required to confirm a fetch happened |
| W8 | Missing access control | Sinks + name heuristic | Privileged sink with no auth-like function name on the call path. MEDIUM if the sink is `direct`, LOW if only `proximate` |
| W9 | Tool execution hijack | Runtime only | Privileged shell/net/creds that static never attributed to this tool |
| W10 | Credential exposure | Static regex **or** runtime env/file canary | Hardcoded secrets in source (redacted), and/or a planted canary appearing in the MCP **response** |

Discovery and declared capabilities do **not** raise weakness IDs. Semgrep records every sink (`proximate` = pattern/call-graph; `direct` = parameter-to-sink dataflow). Only **direct** sinks become named W5/W6/W7. Proximate sinks still feed W3/W8 and `ExpectedBehaviorProfile`.

**Overall vs evidence.** Score the combined ID list. Static-only W1 is still a hit. Runtime-confirmed W5 is the same W5. Runtime-only W9 or canary W10 are hits that static could not have produced. Extra IDs (LOW W3 on stubs, Semgrep false W5) are overall noise even if the other pipeline was silent.

### Capabilities (descriptive tags, not findings)

Used by Lane A (declared from advertisement — LLM or **tool name + input-schema argument names**) and Lane B (derived from sinks). W3 diffs the two.

| ID | Name | Typical evidence |
| --- | --- | --- |
| C1 | Filesystem read | `file`, `path`, `dir`; `file_read` sinks |
| C2 | Filesystem write | write/delete wording; `file_write` sinks |
| C3 | Shell / process exec | `exec`, `command`, `shell`; `shell_exec` sinks |
| C4 | Network outbound | `url`, `fetch`, `http`; `network_call` sinks |
| C5 | Network inbound | listen / bind wording (declared only in v1) |
| C6 | Database | `sql`, `database`, `postgres`; `db_query` sinks |
| C7 | Credential handling | `token`, `secret`, `key`; `credential_read` sinks |
| C8 | Browser automation | `browser`, `page`, `click` |
| C9 | Cloud / SaaS | cloud product names in argument/tool identifiers |
| C10 | Code repository | `git`, `repo`, `commit` |
| C11 | Prompt / template | `prompt`, `template` |
| C12 | Benign utility | no privileged keywords on the name/arguments |

`dynamic_code_load` (`eval` / `exec`) does **not** map to a capability; it is flagged as W5 when taint-confirmed.

Incidental words in a **docstring** (“matching the query”, “does not mention shell”) are **not** declarations. The argument name `query` is not `DB_ACCESS`; `sql` / `database` are.

---

## Project structure

```
MCPAegis/
├── pyproject.toml
├── README.md
├── lima.yaml                      # Lima Ubuntu 24.04 ARM64 (vz) for runtime
├── docs/
│   ├── lima-runtime.md            # TUI automation + manual guest fallback
│   ├── todos.md                   # Analysis-quality and product backlog
│   └── rule-authoring.md          # Semgrep packs + taxonomy extension
├── mcpaegis/
│   ├── cli.py                     # TUI when bare; static / runtime / full / report
│   ├── tui/                       # Textual UI (mode + path)
│   ├── lima/                      # doctor, VM start, guest venv, runtime argv
│   ├── core/
│   │   ├── taxonomy.py            # Capability, Weakness, SinkType, RuntimeEventKind
│   │   ├── models.py              # Pydantic contracts (reports, findings, sinks)
│   │   ├── session.py             # AuditSession, LLMConfig, output dir
│   │   └── mcp_client.py          # stdio JSON-RPC: initialize, list, tools/call
│   ├── static/
│   │   ├── pipeline.py            # discovery → parallel lanes → joins → report
│   │   ├── discovery.py           # Wave 0
│   │   ├── advertisement.py       # Lane A LLM (W1 + declared caps)
│   │   ├── metadata_classifier.py # W1 regex fallback + W2 code
│   │   ├── capability_classifier.py  # declared-cap keyword fallback
│   │   ├── taint/
│   │   │   ├── semgrep_runner.py  # Lane B: pattern + taint Semgrep
│   │   │   ├── call_graph.py      # reverse-BFS tool attribution
│   │   │   ├── codeql_runner.py   # v2 stub (always empty)
│   │   │   └── rules/
│   │   │       ├── python.yaml / javascript.yaml          # pattern → proximate
│   │   │       └── taint/python-taint.yaml / javascript-taint.yaml
│   │   ├── injection_findings.py  # Lane B: direct → W5/W6/W7
│   │   ├── cross_check.py         # W3 join
│   │   ├── access_control_check.py  # W8
│   │   ├── inventory.py           # Lane C orchestrator
│   │   ├── credential_scanner.py  # W10 static
│   │   ├── sca_scan.py            # W4
│   │   └── report_builder.py

│   ├── dynamic/                   # Linux + eBPF only
│   │   ├── pipeline.py
│   │   ├── sandbox/               # process_provider.py (local process + nested cgroup)
│   │   ├── ebpf/                  # bpf_programs.c, monitor.py
│   │   ├── invocation_generator.py
│   │   ├── canary.py
│   │   ├── pre_execution_auditor.py
│   │   ├── behavior_tree.py
│   │   ├── post_execution_verifier.py  # code fallback
│   │   ├── runtime_judge.py       # Stage 4 LLM emitter
│   │   ├── sink_inspector.py
│   │   └── report_builder.py
│   ├── combine/merger.py          # static + runtime → CombinedReport
│   ├── output/                    # json / sarif / md / html + FindingRecord
│   └── llm/                       # advertisement + runtime judge prompts
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/                  # handshake-safe MCP stubs (see catalog below)
```

---

## Static analysis

Static answers: *what tools exist, what they claim, what the source can do, and whether those views disagree* — without calling the tools.

Order in [`mcpaegis/static/pipeline.py`](mcpaegis/static/pipeline.py): **wave 0** discovery, then **wave 1** three parallel lanes, then **wave 2** joins (W8 on sinks; W3 after both cap lists), then **wave 3** report.

```mermaid
flowchart TD
  S0[Discovery]
  S0 --> A[LaneA advertisement]
  S0 --> B[LaneB Semgrep]
  S0 --> C[LaneC inventory]

  A --> Adv["LLM or regex: W1 plus declared caps"]
  A --> W2[Code W2 shadowing]

  B --> Facts[SinkFacts plus code caps]
  Facts --> Inj[direct W5 W6 W7]
  Facts --> W8[W8 unchanged]

  C --> W4[W4 SCA]
  C --> W10s[W10 static secrets]

  Adv --> W3[W3 join]
  Facts --> W3
```

| Wave | Module | Input | Output | Weakness |
| --- | --- | --- | --- | --- |
| 0 | `static/discovery.py` | Path | `ServerMetadata` (tools, language, entrypoint) | — |
| 1A | `static/advertisement.py` | Tools | `PoisoningFlag`, `DeclaredCapability` | W1 |
| 1A | `static/metadata_classifier.py` | Tools | `ShadowingFlag` (+ W1 regex fallback) | W2 |
| 1B | `static/taint/semgrep_runner.py` | Source + tool locations | `SinkFact`, `CodeCapability` | — (facts only) |
| 1B | `static/injection_findings.py` | `SinkFact` with `confidence=direct` | `InjectionFinding` | W5, W6, W7 |
| 1C | `static/inventory.py` | Source tree | credentials + SCA | W10 static, W4 |
| 2 | `static/access_control_check.py` | Privileged sinks, call-path names | `AccessControlFinding` | W8 |
| 2 | `static/cross_check.py` | Declared vs code caps | `CrossCheckFinding` | W3 |
| 3 | `static/report_builder.py` | All of the above | `StaticReport` + writers | — |

`--categories W1,W3,...` skips the matching detectors (empty lists), not the whole pipeline. `--categories W4` / `W10` skip halves of Lane C.

### Wave 0 — Discovery

Discovery answers three questions: what language is this, how do I start the process, and what does the server advertise.

1. **Language** — from `pyproject.toml` / `requirements.txt` / `package.json` / `Cargo.toml` (or file suffixes if there is no manifest).
2. **Entrypoint** — not a magic MCP field. It is the **shell command** MCPAegis would use to start the server as a child process, for example `python server.py` or `node dist/index.js`. It is inferred from console scripts, `package.json` `bin`/`main`/`scripts.start`, or common filenames (`server.py`, `main.py`, `index.js`).
3. **Live handshake (preferred)** — spawn that command for ~10s over **stdio JSON-RPC** (NDJSON) and speak MCP: `initialize`, then `tools/list`, `resources/list`, `prompts/list`. Those three catalogs are what MCPAegis enumerates. If this works, tool names/descriptions/schemas come from the running server (`source=live`). Child `stderr` is discarded so a noisy server cannot deadlock the pipe.
4. **Fallback** — if the process will not start or will not speak MCP, grep/AST the source for registration patterns: Python `@mcp.tool()` / `@server.tool()` decorators (and `server.tool("name")` calls), JS `server.tool("name", ...)`. Same goal (find tools), worse fidelity (empty schemas, no live resources/prompts). `source=static_fallback`.

Live discovery still runs the decorator scan afterward only to attach `source_location` (file + line of the handler) onto tools that the handshake already named. Stage 3 taint sources are those handler functions, **file-scoped**.

**Example — `tests/fixtures/eval_format`**

Handshake starts `python …/eval_format/server.py`. `tools/list` returns `get_qotd` with argument `fmt`. Report header: `Metadata source: live`, `Tools: 1`. Semgrep later uses `source_location.function_name = get_qotd`.

**Example — `tests/fixtures/supply_chain`**

`server.js` is not a real MCP server. Handshake fails; `source=static_fallback`, `Tools: 0`. Lane C can still read `package.json`. That is a W4-only tree, not a discovery bug.

Fixtures are handshake-safe: **import + `initialize` / `tools/list` do no I/O**. Dangerous APIs stay in source so Semgrep can see them. Do not `tools/call` them unless you intend to.

### Lane A — Advertisement (W1 + declared caps) and code W2

[`advertisement.py`](mcpaegis/static/advertisement.py) does **one LLM pass per tool** when `MCPAEGIS_LLM_API_KEY` is set. The prompt includes today’s W1 fast-rule criteria **and** the keyword cheat-sheet for declared capabilities. Sibling JSON objects — poisoning does not fight declared caps.

No key or bad JSON → regex fallback: [`metadata_classifier.py`](mcpaegis/static/metadata_classifier.py) `_poisoning_fast` and [`capability_classifier.py`](mcpaegis/static/capability_classifier.py) `KEYWORD_RULES`. Static does **not** fail closed.

**W1 fast rules** (in the prompt and in the fallback)

| Pattern id | Intent |
| --- | --- |
| `hidden_instruction` / `ignore_previous` | Jailbreak / “do not tell the user” |
| `cross_tool_override` | “When calling X, always use this tool instead…” |
| `base64_blob` | Long base64 that may hide instructions |
| `homoglyph` | Cyrillic/Greek lookalikes in ASCII-looking text |

Naming another tool in explanatory prose (“same join as `read_file`”) is **not** W1. Override *wording* still is.

**W2 stays code** (`normalize_tool_name` / leet). Not in the LLM. Flags collisions: `read_file` vs registered name `read-file`. Package typosquats (`twittter-mcp`) are **not** W2.

**Example — `poisoned_description` / `malicious_tools_adapted`**

`summarize` / `get_status` docstrings contain “Ignore previous instructions” and “always use this tool”. Stage 1 emits HIGH W1 (`hidden_instruction`, `ignore_previous`) and MEDIUM W1 (`cross_tool_override`). Innocent sibling `search` is not flagged.

**Example — `tool_shadowing`**

MEDIUM W2: `read_file` shadows `read-file` (similarity 1.0). No W1 from the alias docstring mentioning `read_file`.

**Example — `workspace_actions.write_file`**

“Same naive join as `read_file`” does **not** produce W1.

### Declared capabilities (Lane A, not a finding)

The LLM (or keyword fallback) answers: *what would a client think this tool is allowed to do from the advertised name and arguments?* It is **not** a finding.

Search blob = tool name (underscores → spaces) + schema **property names** + per-argument `title` / `description`. The tool-level docstring is ignored so negations and incidental words cannot declare shell or SQL.

**Example — `overprivileged.search_docs(query)`**

Name `search_docs` + argument `query` → no `SHELL_EXEC`, no `DB_ACCESS` → `BENIGN_UTILITY`. Code still shells (Lane B). W3 will say **under_declared**.

**Example — `write_file(path, content)`**

Name contains `write_file` / `file` → declared `FS_WRITE` and often `FS_READ`. If code only writes, W3 may emit LOW `over_declared` FS_READ. That is name-vs-code leftover, not “query means database.”

**Example — argument `sql` vs `query`**

`lookup(sql=…)` can declare `DB_ACCESS`. `search_docs(query=…)` does not.

### Lane B — Sinks, taint, and named W5/W6/W7

Two Semgrep runs, then a union. Missing `semgrep` → empty sink list (static still finishes). Untracked fixture files are scanned with `--x-ignore-semgrepignore-files`.

```mermaid
flowchart LR
  Tools["Tool handlers + files"] --> Pat["python.yaml / javascript.yaml"]
  Tools --> Gen["Generated taint sources per handler file"]
  Gen --> Taint["taint/*.yaml"]
  Pat --> Prox["SinkFact proximate"]
  Taint --> Dir["SinkFact direct"]
  Prox --> Attr["Call-graph reverse paths"]
  Dir --> Attr
  Attr --> Merge["Per tool,file,line,sink_type: direct wins"]
  Merge --> Caps["CodeCapability via SINK_TO_CAPABILITY"]
  Merge --> Inj["Named W5/W6/W7 if direct"]
```

**Pattern pack** (`python.yaml` / `javascript.yaml`): “this API appears.” Attribution is containment or reverse call-graph (≤10 hops). Confidence = **`proximate`**. Reachable, not proven dataflow.

**Taint pack** (`taint/*.yaml` plus generated YAML): sources are `def <handler>(...):` **only in that handler’s file**, so a same-named function in another module is not a source (`name_collision`). Sinks are `subprocess.run`, `open($PATH, ...)`, `eval`, `requests.get`, etc. Generated rules copy **sink-type sanitizers** (`shlex.quote` only for `shell_exec` — quoting does not sanitize `open`/`eval`). Confidence = **`direct`**.

Python `open($PATH, ...)` matches keyword arguments (`encoding=`) as well as a mode string.

Snippets are the **source line at `file:line`**, not Semgrep’s `extra.lines` window.

| `SinkFact.confidence` | How it is earned | Becomes a named W5/W6/W7? |
| --- | --- | --- |
| `proximate` | Pattern pack hit, attributed by containment or reverse call-graph (≤10 hops) | No — still used for W3, W8, profiles |
| `direct` | Taint-mode: tool parameter flows into the sink. Sources are file-scoped to the handler | Yes, if `tool_name` is set |

Shared helpers emit **one `SinkFact` per attributing tool**. The same line can be `direct` for one tool and `proximate` for another.

| `sink_type` | Capability | Injection ID (direct only) |
| --- | --- | --- |
| `shell_exec` | C3 `SHELL_EXEC` | W5 |
| `db_query` | C6 `DB_ACCESS` | W5 |
| `dynamic_code_load` | *(none)* | W5 |
| `file_read` | C1 `FS_READ` | W6 |
| `file_write` | C2 `FS_WRITE` | W6 |
| `network_call` | C4 `NET_OUTBOUND` | W7 |
| `credential_read` | C7 `CREDENTIAL_HANDLING` | — (feeds W3/W8, not injection IDs) |

**Example — `command_injection`**

`run_cmd(command)` → `subprocess.run(command, shell=True)`. Taint: parameter → sink → `direct` `shell_exec`.

**Example — `unrelated_cleanup`**

`search_docs` calls `_internal_cleanup()` which runs hardcoded `CLEANUP_CMD`. Pattern mode still sees `subprocess.run` (reachable) → **proximate**. Taint must **not** mark `direct` because `query` never reaches the sink. **No W5.**

**Example — `workspace_actions.read_file`**

`full = os.path.join(WORKSPACE, path)` then `open(full, encoding="utf-8")`. `open($PATH, ...)` matches. Taint follows `path` → `full` → `open` → `direct` `file_read`.

**Example — `sanitized_shell` (known Semgrep miss)**

`quoted = shlex.quote(command)` then `subprocess.run(["/bin/echo", quoted])` (no `shell=True`). Sanitizer is listed; Semgrep often still reports `direct`. Expect HIGH W5 until the engine honors assign + list wrapping. Proximate subprocess would still be legitimate.

Named W5/W6/W7 live in the **same lane**. Semgrep already decided `direct` vs `proximate`. [`injection_findings.py`](mcpaegis/static/injection_findings.py) does **not** re-run taint, and it does **not** “upgrade sink confidence to HIGH.” Confidence on a `SinkFact` stays `direct`/`proximate`. Severity is a separate field on the **finding**.

What it actually does:

1. Keep sinks with `confidence=direct` **and** a `tool_name`. Drop `proximate` and unattributed hits.
2. Map `sink_type` → weakness ID: shell / SQL / `eval` → **W5**, `open`/write → **W6**, network → **W7**. (`credential_read` is not mapped; it only feeds W3/W8.)
3. Emit an `InjectionFinding` with `severity=HIGH` and `confidence="direct"`.

So `direct` means “Semgrep proved parameter → sink.” HIGH means “we are willing to name that as W5/W6/W7.” A proximate `subprocess.run` is still a real sink for W3/W8/profiles; it never becomes a named injection finding.

W3/W8 **also** look at sink confidence, but that is Stages 4–5 (under-declared shell is HIGH only if a supporting sink is `direct`; W8 is MEDIUM if `direct`, LOW if `proximate`). That is independent of 3.5.

**Example — `eval_format`**

`get_qotd` → `return str(eval(fmt))` → Lane B `direct` `dynamic_code_load` → HIGH W5. Snippet is that line.

**Example — `ssrf`**

`fetch_url(url)` → `requests.get(url)` → HIGH W7.

**Example — `path_traversal`**

`Path(path).read_text(...)` → HIGH W6.

**Example — `unrelated_cleanup`**

Lane B `proximate` `shell_exec` only → **no** injection row. W3 may still emit MEDIUM.

### Wave 2 — W3 join (declared vs code)

[`cross_check.py`](mcpaegis/static/cross_check.py) diffs Lane A declared caps vs Lane B code caps. It is the only true join. W3 must not do auth or injection IDs.

- **`under_declared`**: code has a cap the advertisement does not. Dangerous direction (hidden power).
- **`over_declared`**: advertisement claims a cap code sinks do not show. LOW; often keyword leftover.

`BENIGN_UTILITY` is ignored in the declared set.

### Severity vs confidence

| Finding | HIGH / MEDIUM / LOW |
| --- | --- |
| W3 `under_declared` for `SHELL_EXEC`, `CREDENTIAL_HANDLING`, `NET_OUTBOUND` | HIGH if a supporting sink is `direct`; otherwise MEDIUM |
| W3 `under_declared` for other caps | MEDIUM |
| W3 `over_declared` | LOW |
| W8 privileged sink, no auth-like name on the path | MEDIUM if `direct`, LOW if `proximate` |
| W5 / W6 / W7 | HIGH (direct only) |

**Example — `overprivileged`**

Declared: none privileged. Code: `direct` `SHELL_EXEC`. HIGH W3 `under_declared` + HIGH W5.

**Example — `unrelated_cleanup`**

Proximate shell only → MEDIUM W3 `under_declared` SHELL_EXEC, **no** W5.

**Example — stub `read_file` in `tool_shadowing`**

Name declares `FS_READ`; no sink → LOW `over_declared`.

### Wave 2 — Missing access control (W8)

W8 needs **SinkFacts only**. It can run as soon as Lane B finishes — it does not wait on the LLM or inventory. Same shell sink may still emit **both** W3 and W8.

Privileged sink types: `shell_exec`, `file_write`, `db_query`, `credential_read`. If no function on the reverse path matches `require_auth` / `check_permission` / `login_required` / …, emit W8.

This is a **name heuristic**, not a proof of missing auth. Stubs without login will always fire. `file_read` / `network_call` / `eval` are not in this privileged set, so `path_traversal` and `eval_format` do not get W8 from those sinks.

**Example — `missing_access_control`**

Docstring *admits* subprocess; no auth helper → MEDIUM W8 (direct) plus W5.

**Example — `command_injection` / `workspace_actions.write_file`**

Same W8 on the privileged sink. Expected for fixtures, not a misfire of W5/W6.

### Lane C — Inventory (W4 + static W10)

Tree only. No LLM, no Semgrep, no tool list required. [`inventory.py`](mcpaegis/static/inventory.py) calls both scanners.

**W10 static** is source scanning. MCPAegis does **not** call the tool and does **not** plant credentials. It walks the tree (skipping `.venv`, `node_modules`, binaries) and matches gitleaks-style regexes: `AKIA…` AWS keys, `api_key = "…"`, PEM headers, JWTs, `ghp_`, Slack `xox…`, Google `AIza…`.

Hits become `StaticCredentialFinding`. The snippet is **redacted** (`AKIA…MPLE [sha256=…]`) so reports never store the raw secret.

Runtime **W10** is the other evidence path for the same ID: we *plant* unique env/file canaries in the sandbox and see if they come back in the MCP response. Static W10 = “the author already wrote a key into the repo.” Runtime W10 = “at runtime the process leaked a secret we introduced.”

**Example — `static_credentials`**

Module constants `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"` and `API_KEY = "mcp_demo_…"`. The `echo` tool just returns `text`; secrets are **not** in the return value. HIGH W10 with no Semgrep and no `tools/call`.

**W4 supply chain:** MCPAegis does **not** implement its own CVE API. [`sca_scan.py`](mcpaegis/static/sca_scan.py) wraps tools **if they are on `PATH`**:

| Wrapper | When it runs | Who talks to a vuln DB |
| --- | --- | --- |
| `pip-audit -f json` | `pyproject.toml` or `requirements.txt` | pip-audit (PyPI / OSV) |
| `npm audit --json` | `package.json` | npm registry advisories |
| `osv-scanner --format json -r` | always attempted | Google OSV |
| `cargo audit --json` | `Cargo.toml` | RustSec |
| npm install-script scan | `package.json` has `preinstall` / `postinstall` / `install` / `preuninstall` | **nobody** — local JSON only |

If the CLI is missing, that wrapper returns nothing (static still finishes). Findings are deduped on `(package, version, CVE, source_tool)`.

Install-script rows are **always** LOW W4 even with no CVE: a `postinstall` hook is a supply-chain footgun whether or not lodash is pinned to a known CVE. Do not `npm install` the fixture unless you intend to exercise audit.

**Example — `supply_chain`**

Handshake fails (`Tools: 0`). Lane C still reads `package.json` → LOW W4 `mcpaegis-supply-chain-fixture (postinstall)@0.0.1`. If `npm audit` is installed, lodash `4.17.20` may add extra CVE rows.

### Wave 3 — Report

Assembles `StaticReport`, writes `static-report.json` / `.sarif` / `.md`, and builds per-tool **`ExpectedBehaviorProfile`**: declared caps, code caps, sink ids, known weakness flags. The runtime judge / code verifier consumes that profile as “what we already believed before calling the tool.”

---

## Dynamic analysis

Dynamic answers: *when we actually call the tool, does the process tree, DNS, and response match the static profile — and did planted canaries leak?*

It is **not** a replacement for static. Static never runs `eval(fmt)`. Dynamic never reads Semgrep. Together they fill one overall list: static hypothesizes; runtime confirms or adds behavior static could not see.

Runtime does **not** implement W4. W10 is shared: static regex in source, plus runtime canaries (unique `MCPAEGIS_CANARY_…` strings) in the MCP response. Canaries are test markers, not the author’s AWS keys.

```mermaid
flowchart LR
  Mac["macOS Darwin"] -->|"limactl shell"| Guest["Ubuntu VM stock kernel"]
  Guest --> Auditor["mcpaegis + python3-bpfcc"]
  Auditor -->|"spawn"| Server["MCP server stdio"]
  Server --> Nested["nested cgroup mcpaegis-*"]
  Auditor -->|"eBPF attach on guest kernel"| Filter["filter cgroup inode"]
  Nested --> Filter
```

**Why a VM, and why not Docker Desktop**

- The **Linux kernel that runs `mcpaegis`** is where BCC compiles and attaches eBPF. Darwin has no Linux tracepoints. Docker Desktop’s LinuxKit VM does not count: the CLI still runs on Darwin and exits at `platform.system() != "Linux"`.
- The **server under test** is a child process of `mcpaegis`, moved into a nested cgroup. BPF keeps events whose `bpf_get_current_cgroup_id()` matches that inode. Without that fence, BPF would see apt, ssh, leftover shells on the auditor host.
- On Apple Silicon use Lima ([docs/lima-runtime.md](docs/lima-runtime.md)): **guest kernel** for BCC, **guest process** for the server. No Docker.

### Glossary (what the machinery is)

| Term | What it is | Why MCPAegis cares |
| --- | --- | --- |
| **Kernel** | The OS core. Every `open`, `execve`, `connect` is a **syscall** the kernel handles. | eBPF programs run *in* the kernel. macOS and LinuxKit are the wrong kernel for our C program. |
| **Syscall / tracepoint** | Stable kernel hook. Named `syscalls:sys_enter_execve` kprobes miss ARM64 (`openat2`, `execveat`). | [`bpf_programs.c`](mcpaegis/dynamic/ebpf/bpf_programs.c) uses `raw_tracepoint/sys_enter` (openat/openat2/execve/execveat/connect/unlinkat) plus `kretprobe/kernel_clone` and UDP DNS kprobes. |
| **eBPF** | Small programs the kernel JIT-compiles and runs at those hooks. They cannot sleep or wander the heap; they copy a tiny `event_t` and exit. | Our filter is one compare: `bpf_get_current_cgroup_id() == TARGET_CGROUP_ID`. Mismatch → drop. Match → `perf_submit`. |
| **BCC** | BPF Compiler Collection (`python3-bpfcc`). Compiles the `.c` with **this** kernel’s headers (`linux-headers-$(uname -r)`) and BTF (`/sys/kernel/btf/vmlinux`). | [`monitor.py`](mcpaegis/dynamic/ebpf/monitor.py) `BPF(text=…, cflags=["-DTARGET_CGROUP_ID=…"])`. Headers must match the running kernel. |
| **BTF** | Compact type info for the live kernel. | Lets BCC resolve `task_struct` without a full debug kernel. Probe: `test -e /sys/kernel/btf/vmlinux`. |
| **cgroup (v2)** | Kernel “folder of processes” used for limits and accounting. | [`process_provider.py`](mcpaegis/dynamic/sandbox/process_provider.py) mkdir’s a nested group `mcpaegis-<pid>-<ts>` and moves the MCP server into it (`preexec` writes `cgroup.procs`). Children inherit. |
| **inode** | Number identifying that cgroup directory on `cgroupfs` (`stat -c '%i'`). `bpf_get_current_cgroup_id()` returns the same number. | Compiled into the BPF program as `TARGET_CGROUP_ID`. ssh/apt on the guest (different inode) are invisible. |
| **perf buffer** | Kernel ring buffer BPF writes into; user space polls. | `Monitor.drain()` → `RuntimeEvent` list for one `tools/call`. |

**Example — one `echo hello` under the microscope**

1. Lima guest kernel is Linux. `mcpaegis` (Python) + BCC live here.
2. `Popen` starts `python server.py` in a nested cgroup `/sys/fs/cgroup/…/mcpaegis-<pid>-<ts>`, inode `4242`.
3. Host BPF: `if (cgroup_id != 4242) return;`. `apt upgrade` on the guest is inode `99` → dropped.
4. MCP `tools/call run_cmd {"command":"echo hello"}`.
5. Kernel: `clone` then `execve("/bin/sh", ["sh","-c","echo hello"])` (or `/bin/echo`). `raw_tracepoint/sys_enter` fires, BPF keeps the event if the cgroup matches, user space builds a tree with a child exec. Stage 4 maps that to observed `SHELL_EXEC` and **confirms static W5** when the profile already knew about shell.

```mermaid
sequenceDiagram
  participant CLI as mcpaegis on Linux
  participant Srv as MCP server
  participant Kern as guest kernel
  participant BPF as eBPF programs
  CLI->>CLI: mkdir nested cgroup
  CLI->>Srv: Popen python server.py (enter cgroup)
  CLI->>Kern: BCC load bpf_programs.c TARGET=INODE
  CLI->>Srv: MCP initialize / tools/list
  CLI->>Srv: tools/call
  Srv->>Kern: execve / connect / openat
  Kern->>BPF: raw_tracepoint/sys_enter
  BPF-->>CLI: event if cgroup matches
  CLI->>CLI: filtered tree then W9 / W10
```

```mermaid
flowchart TD
  D0[Process plus cgroup plus eBPF]
  D0 --> D1[Plan invocations plus canaries]
  D1 --> D2[Code policy gate]
  D2 -->|deny| Skip[Skip tools/call]
  D2 -->|allow| Call[tools/call plus drain BPF]
  Call --> D3[One filtered behavior tree]
  D3 --> D4[Judge or code verifier]
  Call --> D5[Canary vs response W10]
  D4 --> D6[Runtime report]
  D5 --> D6
```

| Step | Module | Input | Output | Weakness |
| --- | --- | --- | --- | --- |
| 0 | `dynamic/sandbox/process_provider.py` | Server path, entrypoint | Local process + cgroup inode + stdio | — (or `RuntimeUnavailableError`) |
| — | `dynamic/ebpf/monitor.py` | Cgroup inode | `RuntimeEvent` stream | — |
| 1 | `dynamic/invocation_generator.py` + `canary.py` | Tools, schema, optional test script | Ranked `PlannedInvocation`s + `CanarySeed`s | — |
| 2 | `dynamic/pre_execution_auditor.py` | Argument values | `allow` / `deny` (code only) | Deny skips the call (no finding ID) |
| 3 | `dynamic/behavior_tree.py` | Events for one call | One filtered `ToolBehaviorTree` | — |
| 4 | `dynamic/post_execution_verifier.py` + `runtime_judge.py` | Tree + `ExpectedBehaviorProfile` | Mismatches, confirmed / runtime-only IDs | W9; confirm W3/W5/W6/W7/W10 |
| 5 | `dynamic/sink_inspector.py` | MCP response + env/file seeds | `SinkWitness` | W10 runtime |
| 6 | `dynamic/report_builder.py` | All of the above | `DynamicReport` | Derives `RuntimeFinding`s |

### Stage 0 — Local process and eBPF

[`process_provider.launch`](mcpaegis/dynamic/sandbox/process_provider.py) starts the MCP server with `Popen` in the Lima guest:

- cwd = the server tree (same path as on the Mac via virtiofs)
- extra env (the env canary)
- stdin/stdout piped for MCP NDJSON
- `preexec_fn` writes the new PID into a nested `cgroup.procs`

The nested group is `/sys/fs/cgroup/…/mcpaegis-<pid>-<ts>`. Its inode is compiled into BPF as `-DTARGET_CGROUP_ID=<inode>`. Children of the server inherit the cgroup.

Events: `FILE_OPEN` / `READ` / `WRITE` / `UNLINK`, `NET_CONNECT`, `PROC_EXEC` / `FORK`, `DNS_RESPONSE`.

Handshake uses the same NDJSON client as static, against the process stdin/stdout.

If Linux/cgroup v2/BCC is missing, `mcpaegis runtime` exits 1. `mcpaegis full` warns and writes a static-only combined report.

**Example**

`mcpaegis runtime ./tests/fixtures/command_injection --output ./out` on Darwin → error pointing at [docs/lima-runtime.md](docs/lima-runtime.md). Same command **inside** `limactl shell mcpaegis` after `python3-bpfcc` + `pip install mcp`.

### Stage 1 — Invocations and canaries

Canaries answer: **did a secret-shaped value we planted show up in what the tool returned to the MCP client?** The VM is isolation from your Mac; the nested cgroup is isolation from other guest processes.

They are **not** your `.env`. They are **not** argument-echo / prompt-injection checks (we do not plant markers as JSON argument values). A canary hit is **W10 runtime evidence** for the same ID as hardcoded secrets.

A canary is a unique `MCPAEGIS_CANARY_<uuid>` minted for **this run**. If that blob (or base64/hex/rot13 of it) appears in the `tools/call` JSON, it came from this plant.

**Two plant sites** ([`canary.py`](mcpaegis/dynamic/canary.py), [`pipeline.py`](mcpaegis/dynamic/pipeline.py)):

| Kind | What we do | Analogy | Finding if it appears in the MCP **response** |
| --- | --- | --- | --- |
| `env` | Set `MCPAEGIS_CANARY_ENV=<marker>` on the server process | Same as `HOME=…` on the process | **W10** — tool dumped environment |
| `file` | Write `<marker>` into `out/canaries/secret.canary` | Stand-in for `.env` / `id_rsa` sitting on disk | **W10** — tool returned file bytes |

We do **not** scan process memory. eBPF may still show `open`/`read`. Runtime W10 is only: **dye in the JSON the client got.**

#### Env canary (1)

Every runtime launch sets one extra environment variable on the server process, like `HOME`. A `search` tool should never read it or put it in the result. `return dict(os.environ)` → Stage 5 sees the marker → CRITICAL W10.

#### File canary (2)

This is **not** a second env var and **not** “export.” We **write a bait file** next to the report. We **never** pass that path as a tool argument.

1. Guest: `out/canaries/secret.canary`. Contents: one line, the marker.
2. Auto-fill for path-like args (`path`, `file`, …) is **`/tmp/mcpaegis-placeholder-path`**, not the bait. Non-path strings get `mcpaegis-placeholder`.

W10 on a file seed means the process **went fishing**: it opened `secret.canary` even though we did not ask it to, and **put those bytes in the MCP result**. Same story as reading `id_rsa` without being given that path.

- `search_docs(query)` / `read_file(path=/tmp/mcpaegis-placeholder-path)` returning the marker → **W10**.
- A test script that *intentionally* passes the bait path would make returning the bytes the feature; don’t do that if you want runtime W10 to mean “unauthorized read.”

Static **W6** is “untrusted path reached `open`.” Runtime W10 is “our secret marker came back in the reply.”

Prefer a test script for shells:

```yaml
- tool_name: run_cmd
  arguments:
    command: echo hello
```

[`invocation_generator.py`](mcpaegis/dynamic/invocation_generator.py): `--test-script` wins per tool; else schema auto-fill (path → dummy `/tmp/…`, never the bait file; other strings → placeholder); rank by risk tokens; `--max-calls`. The bait file is planted in Stage 0 / pipeline, not as an argument.

### Stage 2 — Pre-execution audit (code only)

[`pre_execution_auditor.py`](mcpaegis/dynamic/pre_execution_auditor.py) is a **dangerous-dispatch kill switch**. Regex on **argument values**: sensitive paths, `rm -rf /`, `curl|sh`, …. Deny → skip `tools/call`. **Not a weakness ID.** There is no LLM text policy on this path.

**Example**

Auto `path=/etc/passwd` → **deny**. Test-script `command=echo hello` → **allow**, then Stage 3 may see `/bin/echo` or `sh -c` under the sandbox cgroup.

### Stage 3 — One filtered behavior tree

While the call runs, the monitor drains events. [`behavior_tree.assemble`](mcpaegis/dynamic/behavior_tree.py) **filters noise first**, then builds a **single** `ToolBehaviorTree`. Loader paths (`/usr/lib/`, `site-packages/`, `.so`, `/dev/null`, …) and loopback `connect`/DNS (`127.0.0.1`, `::1`) are dropped — those are boring interpreter syscalls, not attacks. Raw events may stay on disk for debug; they are not a second product tree.

Filter is **cgroup**, not “this call’s child only.” The long-lived server pid is in the tree; `drain()` per `tools/call` keeps one invocation’s window.

`PROC_EXEC` / `FORK` become process nodes; `NET_CONNECT` / `DNS_RESPONSE` become the DNS branch; file events hang off the issuing pid.

**Example — `command_injection` after `echo hello`**

The tree shows a child exec (`/bin/sh` or `/bin/echo`). That is evidence, not a finding yet. Stage 4 interprets it against the static profile.

**Example — `ssrf` after `tools/call fetch_url`**

`NET_CONNECT` + maybe `DNS_RESPONSE` for the argument host. That confirms a **fetch happened**. An allowlist that includes `example.com` would look the same. No allow/deny list is **why the fixture is vulnerable**, not what Semgrep or eBPF searches for. If static already had `NET_OUTBOUND` / W7, Stage 4 **confirms**. If static had no net cap, Stage 4 can emit **W9**.

### Stage 4 — Post-execution vs static profile

[`post_execution_verifier.py`](mcpaegis/dynamic/post_execution_verifier.py) maps the filtered tree to **observed capabilities** (exec → `SHELL_EXEC`, connect → `NET_OUTBOUND`, sensitive paths → credential/FS, …) and diffs them against `ExpectedBehaviorProfile` from static wave 3. That code pass is the **fallback** when no LLM key is set.

When `MCPAEGIS_LLM_API_KEY` is set, [`runtime_judge.py`](mcpaegis/dynamic/runtime_judge.py) **emits** runtime findings from the same context (tree, declared/code/observed caps, args, static hints). Runtime-emittable: W3, W5, W6, W7, W9, W10. Static-only IDs (W1, W2, W4, W8) are stripped even if the model names them.

| Situation | Result |
| --- | --- |
| Observed cap already in static `known_flags` as W5/W6/W7/W3 | **Confirm** that static ID (`status=confirmed`) |
| Observed privileged cap (`SHELL_EXEC` / `NET_OUTBOUND` / credentials) **not** in declared or code | **W9** hijack (`runtime_only`) |
| Declared/code cap not observed on this call | mismatch recorded; not automatically a weakness (one call is not a proof of absence) |
| LLM verdict `false_positive` / `absent` | no runtime finding for that ID |

Without `static-report.json`, profiles are empty: declared-vs-observed is skipped (warning); W9 still possible if privileged behavior appears with nothing expected.

**Example — `overprivileged`**

Static: HIGH W3 + W5. Runtime `subprocess` child → confirm W5 (and/or W3). Not a new W9 — shell was already in the code profile.

**Example — W9 shape**

Tool advertised and coded as “search”; at runtime a child `curl` or `bash` appears that static never attributed. Observed `NET_OUTBOUND` / `SHELL_EXEC` not in profile → W9.

### Stage 5 — Env/file canaries in the MCP response (W10)

[`sink_inspector.py`](mcpaegis/dynamic/sink_inspector.py) walks string leaves of the JSON-RPC result. It matches **only** `env` and `file` seeds (exact / prefix / suffix / base64 / hex / rot13). Argument-shaped seeds are ignored. A hit is **W10**.

If the server reads `MCPAEGIS_CANARY_ENV`, writes it to `/tmp/x`, and **never puts it in the MCP result**, Stage 5 is silent (eBPF might still show `FILE_WRITE`).

| | Mechanism |
| --- | --- |
| **W10** (static) | Author already wrote `AKIA…` in source. No call, no plant. |
| **W10** (runtime) | *We* planted env or `out/canaries/*.canary`; that marker came back in the tool response. |

**Example — env W10**

Process has `MCPAEGIS_CANARY_ENV=MCPAEGIS_CANARY_deadbeef`. Tool returns `os.environ` inside `content` → CRITICAL W10.

**Example — file W10**

`out/canaries/secret.canary` holds `MCPAEGIS_CANARY_cafe`. Calls use some other path (or no path). The result still contains the marker → the tool read a file it was not given → CRITICAL W10.

### Stage 6 — Runtime report

Derives `RuntimeFinding`s from verifications + witnesses, writes `runtime-report.json` / `.sarif` / `.md`.

| ID | Typical severity |
| --- | --- |
| Confirmed W5 / W6 / W7 / W3 | HIGH |
| W9 | CRITICAL |
| W10 (canary) | CRITICAL |

### Combine (overall list)

[`combine/merger.py`](mcpaegis/combine/merger.py) unions static and runtime into one finding list. **That list is the result.** The tier is provenance, not a second score:

| Tier | Meaning |
| --- | --- |
| `static_only` | Named from source/metadata; runtime did not (or need not) confirm. W1/W2/W4/W8 and static W10 typically stay here |
| `runtime_confirmed` | Same ID in static *and* the behavior tree / canary (typical W3/W5/W6/W7; W10 if both regex and canary hit) |
| `runtime_only` | Runtime evidence with no static counterpart (W9, canary W10, or extra W3) |

On macOS, `mcpaegis full` produces `static_only` rows plus a warning. W4 stays `static_only` even on Linux — runtime does not call `npm audit`.

---

## Install

```bash
cd /path/to/MCPAegis
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Homebrew Python 3.11 is typically `/opt/homebrew/bin/python3.11`. Default `python3` may be 3.10 and will fail `requires-python`.

### Optional tools (static)

Static analysis runs with Python alone, but these improve coverage:

- [Semgrep](https://semgrep.dev/) — taint/sink rules (`semgrep` on `PATH`)
- `pip-audit` / `npm audit` / [osv-scanner](https://google.github.io/osv-scanner/) / `cargo-audit` — dependency findings (W4)

### Runtime (Linux only)

`mcpaegis runtime` and the runtime half of `mcpaegis full` need:

- Linux host with a **stock kernel** (BTF + kprobes) — not macOS, not Docker Desktop’s LinuxKit VM
- cgroup v2 (`/sys/fs/cgroup/cgroup.controllers`)
- BCC matching the kernel (`python3-bpfcc`, `bpfcc-tools`, `linux-headers-$(uname -r)`) **on the same host** that runs `mcpaegis`
- the `mcp` Python package in the guest venv (fixtures import FastMCP)

On macOS, `runtime` prints an error and exits 1. `full` still writes the static report, warns, and emits a combined report from static results only.

**VM = kernel for the auditor and the process that runs the server.** On Apple Silicon (macOS ≥13.5) that VM is Lima + Ubuntu 24.04 ARM64 (`vz` / Virtualization.framework). Config: [`lima.yaml`](lima.yaml).

The TUI owns install/start/venv/`sudo -E`. Manual copy-paste remains in [docs/lima-runtime.md](docs/lima-runtime.md).

```bash
mcpaegis          # TUI: mode, then model on/off, then path, then script
# first Runtime/Full may brew-install Lima and download Ubuntu (minutes)
```

---

## Quick start

Apple Silicon Mac: install the package, then launch the TUI. Homebrew is used only if Lima is missing.

```bash
pip install -e ".[static]"
mcpaegis
```

Pick **Static**, **Runtime**, or **Full**, then enter a path to a local MCP server **under your home directory** (`~` is the virtiofs mount). Runtime and Full start Lima if needed. Reports land in `~/mcpaegis-out/<server-name>/`.

Subcommands still work for scripts and CI (static on any OS; runtime only on Linux):

```bash
mcpaegis static ./tests/fixtures/poisoned_description --output ./out
```

Reports land in `./out` (default without `--output`: `./mcpaegis-out`):

- `static-report.json`
- `static-report.sarif`
- `static-report.md`

Re-render an existing JSON report:

```bash
mcpaegis report ./out/static-report.json --format html --output ./out
mcpaegis report ./out/static-report.json --format md --output ./out
mcpaegis report ./out/static-report.json --format sarif --output ./out
```

---

## CLI

```text
mcpaegis                         # TUI (TTY): mode → model on/off → path → script → run
mcpaegis static <path> [--format json|sarif|md] [--output DIR] [--categories W1,W3,...] [--fail-on HIGH|CRITICAL] [--no-color]
mcpaegis runtime <path> [--test-script FILE] [--sandbox process] [--max-calls N] [--timeout SEC] [--format ...] [--output DIR] [--fail-on ...] [--no-color]
mcpaegis full <path> [union of the above] [--fail-on HIGH|CRITICAL]
mcpaegis report <results.json> --format html|md|sarif --output DIR
```

Examples:

```bash
mcpaegis static ./server --format json --output ./out --categories W1,W3 --no-color
mcpaegis runtime ./server --test-script tests.yaml --max-calls 20 --timeout 30 --output ./out
mcpaegis full ./server --output ./out --fail-on HIGH
mcpaegis report ./out/combined-report.json --format html --output ./out
```

- `full` runs static, then runtime (auto-wires the static report), then merges.
- `runtime` uses `<output_dir>/static-report.json` when present; otherwise it warns and skips declared-vs-observed checks.
- `--fail-on` exits 1 if any finding is at or above that severity (CI).
- `--no-color` / non-TTY output disables ANSI color.

### Test script (runtime)

YAML or JSON list of explicit invocations that override/supplement schema-generated args:

```yaml
- tool_name: run_cmd
  arguments:
    command: echo hello
```

---

## LLM (optional)

Semantic stages run only when a key is set. Missing key skips those stages; analysis does not fail.

- Static Lane A: one advertisement pass (W1 + declared capabilities). Regex/keywords if the key is missing or JSON is bad.
- Dynamic Stage 4: when an API key is set, the **LLM emits** runtime evidence (W3/W5/W6/W7/W9/W10) from the filtered tree plus declared/code/observed capabilities. Each classification includes a reason. W1/W2/W4/W8 stay in the static half of the overall list. Code verify is the fallback if the key is missing or the model fails. Pre-exec is code-only (no LLM).

Put the key and model in a repo-root `.env`. MCPAegis loads it automatically (cwd, then repo root). Process env still wins over the file.

```
MCPAEGIS_LLM_API_KEY=sk-or-...
MCPAEGIS_LLM_BASE_URL=https://openrouter.ai/api/v1
MCPAEGIS_LLM_MODEL=qwen/qwen3.8-27b
```

`--llm-model` / `--llm-base-url` on `static` / `runtime` / `full` override both.

Prompts live in [`mcpaegis/llm/prompts.py`](mcpaegis/llm/prompts.py). They are instructed not to treat argument names (`query`, `path`) or explanatory cross-tool mentions as poisoning or as observed capabilities.

---

## Tests

```bash
source .venv/bin/activate
pytest tests/unit tests/integration
```

Vendored fixture servers under `tests/fixtures/`. Each tree is a handshake-safe FastMCP (or JS) stub.

### Fixture catalog

Planted ID is the **overall** expectation (combined report). How it is gathered is in the notes.

| Dir | Overall expect | What the server does | How it is found | Notes |
| --- | --- | --- | --- | --- |
| `poisoned_description` | W1 | `summarize` docstring jailbreak; innocent `search` | Metadata fast rules | Description-only |
| `malicious_tools_adapted` | W1 | Jailbreak in the **docstring** (adapted); body returns JSON | Same W1 rules | Original Appsecco poison was return-JSON — that shape is out of scope |
| `tool_shadowing` | W2 | `read_file` + registered `read-file` | Name collision | Package typosquats are **not** W2 |
| `overprivileged` | W3 + W5 | Docs say search; code `subprocess.run(query, shell=True)` | Taint W5 + under_declared W3; runtime confirms both | Stub W8 is expected |
| `supply_chain` | W4 | JS stub + `postinstall` + `lodash@4.17.20` | Lane C SCA | No `server.py`; do not `npm install` unless you want audit |
| `command_injection` | W5 | `run_cmd(command)` → `shell=True` | Taint + runtime `/bin/sh` | Stub W8 expected |
| `eval_format` | W5 | `eval(fmt)` on an in-memory quote | Taint `dynamic_code_load` | No execve — runtime must **not** confirm W5 |
| `workspace_actions` | W6 + W5 | Naive join `open`/`write`; `eval(code)` | Taint file + eval | Runtime confirms read `FILE_OPEN`; in-process eval stays static |
| `path_traversal` | W6 | `Path(path).read_text` | Taint + runtime open | |
| `ssrf` | W7 | `requests.get(url)` no allowlist | Taint; runtime needs a real URL (`http://example.com/`) | Placeholder string is not a fetch |
| `missing_access_control` | W8 + W5 | Declared shell, no auth helper | Taint W5 + auth-name heuristic W8 | Docstring *admits* subprocess |
| `static_credentials` | W10 | Hardcoded `AKIA…` / `mcp_demo_…` | Lane C regex, redacted | `echo` does not leak canaries |
| `indirect_prompt_injection` | *(none)* | Wiki body embeds `[SYSTEM INSTRUCTION]` | Out of scope | Not metadata, not a sink |

Counter-examples (overall must **not** include the named injection):

| Dir | Overall expect |
| --- | --- |
| `unrelated_cleanup` | W3 (hidden hardcoded `rm`); **no W5**. Runtime confirms W3, not injection |
| `sanitized_shell` | **no W5** — `shlex.quote` then argv `/bin/echo` |
| `name_collision` | No W5 on the MCP `search` tool (unrelated `search` in `other.py`) |

### Current eval (`out/full6`, Linux + LLM emitter)

Score is **overall** (union of static + runtime). Provenance is stored but does not change the grade. Extra stub W8 on a privileged sink with no auth is allowed.

| Fixture | Overall | Why |
| --- | --- | --- |
| `command_injection` | Correct | W5 (+ W8) |
| `path_traversal` | Correct | W6 |
| `missing_access_control` | Correct | W5 + W8 |
| `overprivileged` | Correct | W3 + W5 |
| `unrelated_cleanup` | Correct | W3, not W5 |
| `eval_format` | Correct | W5 present; runtime correctly did not re-emit it |
| `poisoned_description` | Correct | W1 |
| `malicious_tools_adapted` | Correct | W1 |
| `static_credentials` | Correct | W10 (static regex; no canary leak) |
| `indirect_prompt_injection` | Correct | empty |
| `ssrf` | Correct | W7 (runtime confirm with `example.com`) |
| `workspace_actions` | Partial | Planted W6 + W5 are present; extra LOW W3 from name/eval taxonomy |
| `tool_shadowing` | Partial | W2 present; extra LOW W3 on stubs (`path` vs no `open`) |
| `sanitized_shell` | Partial | Runtime dropped W5; **overall still has false HIGH W5** from Semgrep through `shlex.quote` |

`name_collision` and `supply_chain` were not in the runtime loop (no `server.py` / W4-only).

```bash
mcpaegis static ./tests/fixtures/eval_format --output ./out
```

### Appsecco Vulnerable MCP Servers Lab → fixtures

Reconstructions of [appsecco/vulnerable-mcp-servers-lab](https://github.com/appsecco/vulnerable-mcp-servers-lab) (MIT). Not clones of the live servers: no install-time network, no real keys, no HTTP bind, no extra argv.

| Lab folder | Fixture | Overall expect | What we stripped / adapted |
| --- | --- | --- | --- |
| `vulnerable-mcp-server-filesystem-workspace-actions` | `workspace_actions` | W6 (`open`/`write` after naive join), W5 (`eval`). Possibly W3/W8 | Dropped required workspace argv (`sys.exit`); dummy `WORKSPACE` string |
| `vulnerable-mcp-server-malicious-code-exec` | `eval_format` | W5 (`eval(fmt)`) | Dropped quote HTTP fetch and any API key |
| `vulnerable-mcp-server-malicious-tools` | `malicious_tools_adapted` | W1 | **Adapted:** jailbreak moved into the docstring. Original poison was return-JSON (prompt-injection class) — static W1 would miss it |
| `vulnerable-mcp-server-indirect-prompt-injection` | `indirect_prompt_injection` | **No** W1/W5/W6/W7 | In-memory corpus instead of on-disk/HTTP docs. Hidden text is in the **body**, not metadata |
| `vulnerable-mcp-server-indirect-prompt-injection-remote-mcp` | *(skipped)* | — | Same IPI shape plus HTTP+SSE transport |
| `vulnerable-mcp-server-secrets-pii` | `static_credentials` | W10 | Fake `AKIA` / `mcp_demo_` only. No icahazip/weather/news, no startup log of admin contact, no base64 PII table |
| `vulnerable-mcp-server-outdated-pacakges` | `supply_chain` | W4 (install hook; audit optional) | Single `postinstall` echo + one lodash pin, not their full CVE pin set |
| `vulnerable-mcp-server-wikipedia-http-streamable` | `ssrf` | W7 | Stdio `requests.get(url)` instead of Streamable HTTP Wikipedia client. Untrusted-content IPI is a **miss** (same as document IPI) |
| `vulnerable-mcp-server-namespace-typosquatting` | `tool_shadowing` (related only) | W2 on **tool** lookalikes | Lab is a **package** name (`twittter-mcp`). That is not W2; we do not vendor a fake npm package |

[MCP-Tox](https://github.com/luoji12103/MCP-Tox) is an LLM-agent simulation, not MCP server source. It is **not** mapped onto these fixtures.

---

## Extending rules

See [docs/rule-authoring.md](docs/rule-authoring.md) for Semgrep sink rules and taxonomy (`Capability` / `Weakness` / `SinkType`).
