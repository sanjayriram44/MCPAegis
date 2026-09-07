from pathlib import Path

from mcpaegis.core.models import ToolMetadata
from mcpaegis.dynamic.canary import GUEST_FILE_CANARY
from mcpaegis.dynamic.invocation_generator import PATH_PLACEHOLDER, fill_from_schema, generate, load_test_script


def test_path_args_are_dummy_not_bait_file():
    args, seeds = fill_from_schema(
        {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "query": {"type": "string"},
            },
            "required": ["path", "query"],
        }
    )
    assert args["path"] == PATH_PLACEHOLDER
    assert GUEST_FILE_CANARY not in args.values()
    assert args["query"] == "mcpaegis-placeholder"
    assert seeds == []


def test_auto_invocation_does_not_point_at_canary_file():
    tool = ToolMetadata(
        name="read_file",
        description="",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )
    planned = generate([tool])
    assert planned[0].arguments["path"] == PATH_PLACEHOLDER
    assert planned[0].canaries == []


def test_load_test_script_nested_yaml_arguments(tmp_path: Path):
    script = tmp_path / "runtime.yaml"
    script.write_text(
        "- tool_name: run_cmd\n  arguments:\n    command: echo hi\n",
        encoding="utf-8",
    )
    planned = load_test_script(script)
    assert planned[0].tool_name == "run_cmd"
    assert planned[0].arguments["command"] == "echo hi"
