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
    W1_TOOL_POISONING = "W1"  # Layer A, static
    W2_TOOL_SHADOWING = "W2"  # Layer A, static
    W3_OVERPRIVILEGED = "W3"  # Layer A, static (cross-check)
    W4_SUPPLY_CHAIN = "W4"  # Layer A, static (delegated to SCA tools)
    W5_COMMAND_INJECTION = "W5"  # Layer B, static+dynamic (includes SQL sub-type)
    W6_PATH_TRAVERSAL = "W6"  # Layer B, static+dynamic
    W7_SSRF = "W7"  # Layer B, static+dynamic
    W8_ACCESS_CONTROL = "W8"  # Layer B, static
    W9_TOOL_EXEC_HIJACK = "W9"  # Layer D, dynamic only
    W10_CREDENTIAL_EXPOSURE = "W10"  # Layer C: static regex and/or runtime env/file canary
    W10_STATIC_CRED_EXPOSURE = "W10"  # alias of W10_CREDENTIAL_EXPOSURE


class SinkType(str, Enum):
    SHELL_EXEC = "shell_exec"  # -> Capability.SHELL_EXEC
    FILE_READ = "file_read"  # -> Capability.FS_READ
    FILE_WRITE = "file_write"  # -> Capability.FS_WRITE
    NETWORK_CALL = "network_call"  # -> Capability.NET_OUTBOUND
    DB_QUERY = "db_query"  # -> Capability.DB_ACCESS
    DYNAMIC_CODE_LOAD = "dynamic_code_load"  # eval/exec/dynamic import — flag under W5
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
