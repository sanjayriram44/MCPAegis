from mcpaegis.core.taxonomy import Capability
from mcpaegis.static.capability_classifier import classify
from tests.unit.helpers import tool


def _caps(name_desc_schema):
    name, desc, schema = name_desc_schema
    return {c.capability for c in classify([tool(name, desc, schema)])}


def test_shell_keywords_map_to_shell_exec():
    caps = classify(
        [tool("run_cmd", "Execute a shell command via subprocess", {"properties": {"command": {"type": "string"}}})]
    )
    by_cap = {c.capability: c for c in caps}
    assert Capability.SHELL_EXEC in by_cap
    assert by_cap[Capability.SHELL_EXEC].confidence >= 0.7
    assert by_cap[Capability.SHELL_EXEC].evidence


def test_file_read_and_write_are_multi_label():
    caps = {
        c.capability
        for c in classify([tool("write_file", "Overwrite a file path on disk", {"properties": {"path": {"type": "string"}}})])
    }
    assert Capability.FS_WRITE in caps
    assert Capability.FS_READ in caps


def test_network_db_and_credential_keywords():
    net = classify([tool("fetch_url", "HTTP GET a url endpoint")])
    db = classify(
        [
            tool(
                "lookup_users",
                "Run a SQL query against postgres",
                {"properties": {"sql": {"type": "string"}}},
            )
        ]
    )
    cred = classify([tool("store_token", "Save an API key credential")])
    assert Capability.NET_OUTBOUND in {c.capability for c in net}
    assert Capability.DB_ACCESS in {c.capability for c in db}
    assert Capability.CREDENTIAL_HANDLING in {c.capability for c in cred}


def test_no_keywords_is_benign_utility():
    caps = classify([tool("ping", "Return a friendly hello")])
    assert len(caps) == 1
    assert caps[0].capability == Capability.BENIGN_UTILITY
    assert caps[0].evidence == ["no privileged keywords matched"]


def test_tool_description_words_are_not_declarations():
    """Negations and incidental prose in the docstring are not advertised caps."""
    caps = classify(
        [
            tool(
                "search_docs",
                "Look up local documentation snippets matching the query. "
                "Does not mention shell, subprocess, or command execution. "
                "Filesystem-oriented helper.",
                {"properties": {"query": {"type": "string"}}},
            )
        ]
    )
    kinds = {c.capability for c in caps}
    assert Capability.SHELL_EXEC not in kinds
    assert Capability.DB_ACCESS not in kinds
    assert Capability.FS_READ not in kinds
    assert Capability.BENIGN_UTILITY in kinds


def test_argument_name_declares_capability_not_tool_prose():
    caps = classify(
        [
            tool(
                "lookup",
                "This paragraph talks about shells and databases but is not a claim.",
                {
                    "properties": {
                        "sql": {"type": "string", "description": "postgres statement"},
                    }
                },
            )
        ]
    )
    kinds = {c.capability for c in caps}
    assert Capability.DB_ACCESS in kinds
    assert Capability.SHELL_EXEC not in kinds


def test_schema_descriptions_are_searched():
    caps = classify(
        [
            tool(
                "do_thing",
                "utility helper",
                {
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "git repo to clone",
                        }
                    }
                },
            )
        ]
    )
    assert Capability.CODE_REPO in {c.capability for c in caps}
