# Lima Ubuntu ARM64 runbook (`mcpaegis runtime`)

On an **Apple Silicon Mac**, install once (`pip install -e ".[static]"`), then run `mcpaegis` from **any cwd**:

```bash
mcpaegis          # TUI
# or
mcpaegis full ./tests/fixtures/command_injection --output ~/mcpaegis-out/ci
```

Both install Lima (Homebrew) if needed, start the shared Ubuntu ARM64 guest named `mcpaegis`, bootstrap the guest venv, and run runtime with `sudo -n -E`. After each Runtime/Full run the VM is **stopped** (`limactl stop -y mcpaegis`) so host RAM/CPU are freed; the disk and venv stay for the next start. Static stays on macOS so Semgrep is not lost under `sudo` `secure_path`. Any MCP server path is accepted: trees outside `~` are copied to `~/mcpaegis-servers/<name>/` (Lima only mounts home). The rest of this file is the fallback if you want to drive Lima yourself.

Do **not** `limactl shell` just to run analysis — the CLI/TUI do that.

This guest is a **stock Ubuntu 24.04 ARM64** VM via Lima’s `vz` driver (Apple Virtualization.framework, default since Lima v1.0 on macOS ≥13.5). The MCP server under test is a **local process** in a nested cgroup. There is no Docker.

Config: [`lima.yaml`](../lima.yaml) at the repo root (also packaged as `mcpaegis/lima/lima.yaml`).

## Requirements

- Apple Silicon Mac, macOS ≥13.5
- Homebrew (only if `limactl` is missing; first run may also prompt for Virtualization.framework)
- A local MCP server path (any location). Lima virtiofs mounts `~` writable. Servers already under home are used in place. Servers outside home are copied to `~/mcpaegis-servers/<name>/`. Static analysis still uses the original path.
- Guest sudo is passwordless `sudo -n -E` inside Ubuntu for eBPF. The Mac user does not type sudo for host Python.

Intel Macs cannot run an ARM guest with `vz`. Use a native `x86_64` Ubuntu image instead (not this file).

`mcpaegis runtime` / `mcpaegis full` on macOS now start Lima automatically. You only need this runbook if automation fails.

## 1. Install Lima (macOS)

```bash
brew install lima
limactl --version
```

Lima ≥1.0 uses `vz` by default on macOS ≥13.5. [`lima.yaml`](../lima.yaml) sets `vmType: vz` and `arch: aarch64` explicitly.

## 2. Create and start the VM

From the repo (first start downloads the Ubuntu cloud image; several minutes):

```bash
cd /Users/sanjaysriram/Documents/MCPAegis
limactl start --name=mcpaegis lima.yaml
limactl list
```

Expect `STATUS=Running`, `VMTYPE=vz`, `ARCH=aarch64`. Then:

```bash
limactl shell mcpaegis -- uname -a
```

You want `Linux … aarch64` and an Ubuntu kernel string (`…-generic` or similar), **not** `linuxkit`.

Open a guest shell:

```bash
limactl shell mcpaegis
```

If `lima.yaml` is unavailable, the equivalent image is `limactl start --name=mcpaegis template://ubuntu-24.04`, then install packages by hand (section 3).

## 3. Guest packages (if provision did not finish)

`lima.yaml` `provision` installs these on first boot. If `python3-bpfcc` is missing:

```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv \
  python3-bpfcc bpfcc-tools "linux-headers-$(uname -r)"
```

Sanity:

```bash
test -e /sys/kernel/btf/vmlinux && echo BTF=yes
uname -r
test -f /sys/fs/cgroup/cgroup.controllers && echo cgroupv2=yes
```

## 4. Install MCPAegis in the guest

The Mac checkout is the same path inside the VM:

```bash
cd /Users/sanjaysriram/Documents/MCPAegis
python3 -m venv --system-site-packages "$HOME/mcpaegis-venv"
source "$HOME/mcpaegis-venv/bin/activate"
pip install -e ".[dev]"
pip install "mcp>=1.2,<2"   # FastMCP; mcp 2.x renamed it to MCPServer
pip install semgrep   # optional; static taint still useful here
```

Use a **guest** venv under `$HOME` (Linux home, not the virtiofs Mac checkout). `--system-site-packages` is required so `import bcc` sees Ubuntu’s `python3-bpfcc`. Do not reuse a Darwin `.venv` from the Mac.

Existing VMs that already have Docker from an older `lima.yaml` can leave it installed; MCPAegis no longer uses it.

## 5. Run static + runtime **inside the guest**

Safer payload (auto-fill uses `mcpaegis-placeholder` for non-path strings; still prefer an explicit command):

```bash
cat > /tmp/mcpaegis-runtime.yaml <<'EOF'
- tool_name: run_cmd
  arguments:
    command: echo hello
EOF

source "$HOME/mcpaegis-venv/bin/activate"
# Static does not need root. sudo secure_path drops venv `semgrep` unless we
# resolve it next to the venv interpreter (already done in code).
mcpaegis static ./tests/fixtures/command_injection --output ./out

sudo sysctl -w kernel.unprivileged_bpf_disabled=0
# Nested cgroup + BCC kprobes need root. Use the venv binary (PATH is empty under sudo).
sudo -E "$HOME/mcpaegis-venv/bin/mcpaegis" runtime ./tests/fixtures/command_injection \
  --test-script /tmp/mcpaegis-runtime.yaml \
  --output ./out --max-calls 3 --timeout 30
```

Or one shot:

```bash
sudo -E "$HOME/mcpaegis-venv/bin/mcpaegis" full ./tests/fixtures/command_injection \
  --test-script /tmp/mcpaegis-runtime.yaml \
  --output ./out --max-calls 3 --timeout 30
```

Reports land in `./out` on the shared mount (visible on the Mac).

## 6. Stop and delete

The TUI/CLI already stop the VM after each Darwin Runtime/Full run (`limactl stop -y mcpaegis`) and never delete it. Manual equivalents on the **Mac**:

```bash
limactl stop mcpaegis      # keep disk; start later with limactl start mcpaegis
limactl start mcpaegis
limactl delete -f mcpaegis # destroy this instance’s disk
```

`limactl delete` does not uninstall Homebrew Lima. Do not delete between ordinary runs; the next start would re-download Ubuntu.

## Failure modes

| Symptom | Cause |
| --- | --- |
| `this host is Darwin` | You ran `mcpaegis runtime` on macOS. Use `limactl shell mcpaegis`. |
| `VMTYPE=qemu` | Lima <1.0 or macOS <13.5. Upgrade; this YAML requires `vz`. |
| BCC / headers mismatch | Reinstall `"linux-headers-$(uname -r)"` and `python3-bpfcc` after a guest kernel update. |
| `incomplete definition of type 'struct tracepoint__…'` | Old BPF used `TRACEPOINT_PROBE` (needs debugfs format files). Current `bpf_programs.c` uses `raw_tracepoint/sys_enter` plus `kernel_clone`. Pull latest and retry. |
| Runtime trees are python3 forks only, `file_events`/`net_events` empty, zero findings | Old `syscall__openat` kprobes miss ARM64 (`openat2` / `execveat`). Current BPF uses `raw_tracepoint/sys_enter`. Re-run runtime after pulling. Also Stage 4 now confirms W5/W6/W7 when the observed tree matches the static profile, not only when static missed the capability. |
| `Need super-user privileges to run` / `Failed to load program: Operation not permitted` | BCC kprobes and nested cgroups need root. `sudo -E "$HOME/mcpaegis-venv/bin/mcpaegis" runtime …` — not a bare `sudo mcpaegis`. |
| `MCP server exited immediately` / empty stderr / `FastMCP is missing` | `pip install mcp` pulled 2.x. Pin 1.x: `pip install 'mcp>=1.2,<2'`. See `./out/canaries/sandbox.stderr`. |
| Static `sink_facts` empty / LOW W3 over_declared on `run_cmd` | Semgrep not visible to the process. `sudo` uses `secure_path`. Current code looks next to `sys.executable`. Prefer `mcpaegis static` **without** sudo, then `sudo -E … runtime`. |
| `Broken pipe` / handshake failed | Server died after spawn. Same stderr file. |
| `cannot create a nested cgroup` | Not root, or cgroup v2 missing. `test -f /sys/fs/cgroup/cgroup.controllers`. |
| Intel Mac + this YAML | `vz` cannot run `aarch64` on Intel. Native x86_64 Ubuntu, not this file. |

Ubuntu **26.04**: only if `limactl start template://ubuntu-26.04` exists on your Lima. Prefer 24.04 for BCC/header packages.
