from datetime import datetime, timezone

from mcpaegis.core.models import CanarySeed, SinkWitness
from mcpaegis.dynamic.sink_inspector import classify_witness, extract_sink_regions, inspect


def _seed(value: str, kind: str = "arg") -> CanarySeed:
    return CanarySeed(type=kind, key="marker", value=value, planted_at=datetime.now(timezone.utc))  # type: ignore[arg-type]


def test_inspect_matches_content_field():
    value = "MCPAEGIS_CANARY_sinkinspect01"
    response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": f"here is {value}"}]},
    }
    witnesses = inspect(response, [_seed(value, kind="file")], call_id="c1")
    assert witnesses
    assert witnesses[0].call_id == "c1"
    assert witnesses[0].canary_ref == value
    assert witnesses[0].match_type == "exact"
    assert "content" in witnesses[0].sink_location.lower() or "text" in witnesses[0].sink_location.lower()


def test_extract_skips_short_metadata():
    regions = extract_sink_regions({"id": "1", "jsonrpc": "2.0", "name": "x", "content": "hello world"})
    texts = [t for _, t in regions]
    assert "hello world" in texts
    assert "2.0" not in texts


def test_classify_env_file_canary_is_w15():
    seed = _seed("MCPAEGIS_CANARY_envleak", kind="env")
    witness = SinkWitness(
        call_id="c1",
        canary_ref=seed.value,
        sink_location="$.result.content[0].text",
        match_type="exact",
        confidence=1.0,
        matched_snippet=seed.value,
    )
    assert classify_witness(witness, [seed]) == "W15"


def test_inspect_ignores_argument_canaries():
    value = "MCPAEGIS_CANARY_promptarg"
    response = {"result": {"content": value}}
    assert inspect(response, [_seed(value, kind="arg")], call_id="c1") == []


def test_classify_arg_seed_is_not_a_finding():
    seed = _seed("MCPAEGIS_CANARY_promptarg", kind="arg")
    witness = SinkWitness(
        call_id="c1",
        canary_ref=seed.value,
        sink_location="$.result.messages[0].content",
        match_type="exact",
        confidence=1.0,
        matched_snippet=seed.value,
    )
    assert classify_witness(witness, [seed]) == ""


def test_inspect_empty_inputs():
    assert inspect(None, [_seed("x")], call_id="c") == []
    assert inspect({"result": "ok"}, [], call_id="c") == []
