# MCPAegis backlog

Work that is **not** in the TUI / Lima automation stream. Do not treat this file as a commit checklist for that feature.

## Analysis quality (full7 fixture run)

- **SSRF W3 `runtime_confirmed` has the wrong polarity.** Static W3 on `fetch_url` was *over-declared C1* (advertises FS_READ; code only has C4). The runtime judge treated DNS / `NET_CONNECT` as confirming W3. **W7 is the real runtime finding.** Fix the judge so over-declared C1 is `static_only` (or `false_positive`) unless the tree shows the *missing-from-declared* capability, not an unrelated network event.
- **`write_file` W6 stays `static_only` because eBPF `FILE_WRITE` path is null.** `read_file` captured `/tmp/mcpaegis-placeholder-path`; write recorded `FILE_WRITE` with an empty path, so the judge would not confirm traversal. Fix path capture for write syscalls (likely `openat`/`openat2` write flags vs a dedicated write probe).
- **Recurring LOW W3 over-declared C1** on search/docs-style tools (`indirect_prompt_injection`, `overprivileged`, `unrelated_cleanup`, `tool_shadowing`). Lane A vs code-cap join: advertisement infers FS_READ from names like `search_docs` / `query` while Semgrep sees no `file_read` sink. Tighten declared-cap heuristics or drop LOW over-declared C1 when there is no FS evidence.
- **`tool_shadowing` W1 `cross_tool_override` on the hyphenated-name description.** W2 (lookalike `read_file` / `read-file`) is the intended finding. The LLM treated explanatory copy about the hyphenated MCP name as poisoning. Narrow the W1 prompt so naming/collision prose is not `cross_tool_override`.

## Product

- **TUI + Mac VM automation** — bare `mcpaegis` launches a Textual UI; static on the Mac; runtime/full drives Lima Ubuntu ARM64. Tracked as the TUI Lima plan, not here.
- **Intel Mac x86_64 guest** — current `lima.yaml` is `vz` + `aarch64` only. A native Ubuntu x86_64 image would be required; out of scope for Apple Silicon automation.
- **Mounts outside `$HOME`** — Lima virtiofs only shares `~`. Server paths and `--output` outside the Mac home are refused. Extra `mounts:` entries are a later change.
- **Runtime canary W10 positive fixture** — no planted fixture yet where an env/file canary appears in the MCP response.
