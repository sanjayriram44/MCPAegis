import base64
import binascii
import codecs
from datetime import datetime, timezone

from mcpaegis.core.models import CanarySeed
from mcpaegis.core.session import CANARY_PREFIX
from mcpaegis.dynamic.canary import candidates, make_value, match_any, match_text, plant_arg


def _seed(value: str) -> CanarySeed:
    return CanarySeed(
        type="arg",
        key="token",
        value=value,
        planted_at=datetime.now(timezone.utc),
    )


def test_make_value_uses_product_prefix():
    value = make_value()
    assert value.startswith(CANARY_PREFIX)
    assert CANARY_PREFIX == "MCPAEGIS_CANARY_"


def test_exact_match():
    seed = plant_arg("input", value="MCPAEGIS_CANARY_abcdef0123456789")
    hit = match_text(f"echo {seed.value} done", seed)
    assert hit is not None
    match_type, snippet, confidence = hit
    assert match_type == "exact"
    assert confidence == 1.0
    assert seed.value in snippet


def test_prefix_and_suffix_match():
    value = "MCPAEGIS_CANARY_" + ("a" * 40)
    seed = _seed(value)
    prefix = value[:24]
    suffix = value[-24:]
    assert match_text(f"head {prefix} tail", seed)[0] == "prefix"
    assert match_text(f"head {suffix} tail", seed)[0] == "suffix"


def test_base64_hex_rot13_match():
    value = "MCPAEGIS_CANARY_deadbeefcafebabe"
    seed = _seed(value)
    b64 = base64.b64encode(value.encode()).decode("ascii")
    hx = binascii.hexlify(value.encode()).decode("ascii")
    rot = codecs.encode(value, "rot_13")
    assert match_text(f"payload={b64}", seed)[0] == "base64"
    assert match_text(f"hex:{hx}", seed)[0] == "hex"
    assert match_text(f"rot={rot}", seed)[0] == "rot13"


def test_separator_normalized_match():
    value = "MCPAEGIS_CANARY_aabbccdd"
    seed = _seed(value)
    spaced = "MCPAEGIS CANARY aabbccdd"
    hit = match_text(spaced, seed)
    assert hit is not None
    assert hit[0] == "separator_normalized"


def test_candidates_include_encodings():
    value = "MCPAEGIS_CANARY_xyz"
    forms = dict(candidates(value))
    assert forms["exact"] == value
    assert forms["base64"] == base64.b64encode(value.encode()).decode("ascii")
    assert forms["hex"] == binascii.hexlify(value.encode()).decode("ascii")
    assert forms["rot13"] == codecs.encode(value, "rot_13")


def test_match_any_and_no_match():
    seed = _seed("MCPAEGIS_CANARY_nomatchtoken")
    assert match_any("unrelated output", [seed]) == []
    hits = match_any(f"leak {seed.value}", [seed])
    assert len(hits) == 1
    assert hits[0][1] == "exact"
