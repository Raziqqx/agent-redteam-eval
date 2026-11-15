from collections import Counter

import pytest
import yaml
from pydantic import ValidationError

from redteam.cases import ATTACK_CATEGORIES, Case, Suite, dump_suite, load_suite


def test_suite_size_and_coverage(suite):
    counts = Counter(c.category for c in suite.cases)
    assert 40 <= sum(v for k, v in counts.items() if k != "benign") <= 60
    assert counts["benign"] == 15
    assert set(ATTACK_CATEGORIES) <= set(counts)
    assert all(c.version >= 1 for c in suite.cases)


def test_every_attack_targets_something_checkable(suite):
    for c in suite.cases:
        if c.is_attack:
            assert c.injection is not None, c.id


BASE = {
    "id": "DI-999",
    "version": 1,
    "category": "direct_injection",
    "title": "t",
    "task": "x",
    "injection": {"location": "prompt", "payload": "p"},
    "success": {"canaries": ["PWNED-X999"]},
}


@pytest.mark.parametrize(
    "patch",
    [
        {"success": {}},  # attack without criteria
        {"category": "benign"},  # benign with injection/criteria
        {"surprise": 1},  # unknown key
        {"id": "bad id"},
        {"injection": {"location": "prompt", "parts": ["[[1/2]] a", "[[2/2]] b"]}},  # split in prompt
        {"success": {"policy": ["not_a_policy"]}},
    ],
)
def test_schema_rejects(patch):
    with pytest.raises(ValidationError):
        Case.model_validate({**BASE, **patch})


def test_duplicate_ids_rejected():
    with pytest.raises(ValidationError):
        Suite.model_validate({"schema_version": 1, "suite": "s", "version": "1.0.0", "cases": [BASE, BASE]})


def test_dump_roundtrip(suite, tmp_path):
    p = tmp_path / "s.yaml"
    dump_suite(suite, p)
    assert yaml.safe_load(p.read_text())["schema_version"] == 1
    assert load_suite(p) == suite
