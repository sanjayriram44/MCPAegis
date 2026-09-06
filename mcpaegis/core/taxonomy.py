"""Capability, weakness, sink, and runtime-event taxonomies."""

from enum import Enum


class Capability(str, Enum):
    FS_READ = "C1"  # Filesystem Read
    FS_WRITE = "C2"  # Filesystem Write/Modify/Delete
    SHELL_EXEC = "C3"  # Shell/Process Execution
    NET_OUTBOUND = "C4"  # Network Outbound
    NET_INBOUND = "C5"  # Network Inbound
    DB_ACCESS = "C6"  # Database Access
    CREDENTIAL_HANDLING = "C7"  # Credential/Secret Handling
    BROWSER_AUTOMATION = "C8"  # Browser Automation
    CLOUD_SAAS = "C9"  # Cloud/SaaS Operation
    CODE_REPO = "C10"  # Code Repository Operation
    PROMPT_PROVIDING = "C11"  # Prompt/Template Providing
    BENIGN_UTILITY = "C12"  # Benign/Utility, no external effect


class Weakness(str, Enum):
    # v1 — implement detection for these
    W1_TOOL_POISONING = "W1"  # Layer A, static
    W2_TOOL_SHADOWING = "W2"  # Layer A, static
    W4_OVERPRIVILEGED = "W4"  # Layer A, static (cross-check)
    W5_SUPPLY_CHAIN = "W5"  # Layer A, static (delegated to SCA tools)
    W6_COMMAND_INJECTION = "W6"  # Layer B, static+dynamic (includes SQL sub-type)
    W7_PATH_TRAVERSAL = "W7"  # Layer B, static+dynamic
    W9_SSRF = "W9"  # Layer B, static+dynamic
    W11_ACCESS_CONTROL = "W11"  # Layer B, static
    W12_TOOL_EXEC_HIJACK = "W12"  # Layer D, dynamic only
    W14_STATIC_CRED_EXPOSURE = "W14"  # Layer C, static
    W15_RUNTIME_CRED_LEAKAGE = "W15"  # Layer C, dynamic (env/file canary in MCP response)

    # v2 — deferred, enum values reserved, no detection logic yet
    W3_RUG_PULL = "W3"
    W10_SCHEMA_BYPASS = "W10"
    W13_INDIRECT_PROMPT_INJECTION = "W13"  # argument-echo / corpus IPI — no detector
    W16_CONTEXT_OVERSHARING = "W16"
    W17_HOST_SIDE_ATTACKS = "W17"


class SinkType(str, Enum):
    SHELL_EXEC = "shell_exec"  # -> Capability.SHELL_EXEC
    FILE_READ = "file_read"  # -> Capability.FS_READ
    FILE_WRITE = "file_write"  # -> Capability.FS_WRITE
    NETWORK_CALL = "network_call"  # -> Capability.NET_OUTBOUND
    DB_QUERY = "db_query"  # -> Capability.DB_ACCESS
    DYNAMIC_CODE_LOAD = "dynamic_code_load"  # eval/exec/dynamic import — flag under W6
    CREDENTIAL_READ = "credential_read"  # os.environ, keyring, etc. -> Capability.CREDENTIAL_HANDLING


class RuntimeEventKind(str, Enum):
    FILE_OPEN = "FILE_OPEN"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_UNLINK = "FILE_UNLINK"
    NET_CONNECT = "NET_CONNECT"
    PROC_EXEC = "PROC_EXEC"
    PROC_FORK = "PROC_FORK"
    DNS_RESPONSE = "DNS_RESPONSE"


SINK_TO_CAPABILITY: dict[SinkType, Capability] = {
    SinkType.SHELL_EXEC: Capability.SHELL_EXEC,
    SinkType.FILE_READ: Capability.FS_READ,
    SinkType.FILE_WRITE: Capability.FS_WRITE,
    SinkType.NETWORK_CALL: Capability.NET_OUTBOUND,
    SinkType.DB_QUERY: Capability.DB_ACCESS,
    SinkType.CREDENTIAL_READ: Capability.CREDENTIAL_HANDLING,
}
