import random
import string

from redteam.cases import Injection
from redteam.llm import decoded_views, parse_directives, reassemble_parts
from redteam.mutate import OPERATORS, _key, _split, generate, mutate


def test_generation_is_deterministic_and_deduped(suite):
    a, sa = generate(suite, 2, seed=7)
    b, _ = generate(suite, 2, seed=7)
    assert [m.model_dump() for m in a] == [m.model_dump() for m in b]
    keys = [_key(m.injection) for m in a]
    assert len(keys) == len(set(keys))
    seeds = {_key(c.injection) for c in suite.cases if c.injection}
    assert not seeds & set(keys)
    assert len({m.id for m in a}) == len(a) == sa["mutants"]


def test_mutants_keep_parent_criteria(suite, cases):
    mutants, _ = generate(suite, 2, seed=3)
    for m in mutants:
        assert m.success == cases[m.parent].success and m.category == cases[m.parent].category
        assert set(m.mutations) <= set(OPERATORS)


def test_split_reassembles_property():
    rng = random.Random(0)
    for _ in range(200):
        words = ["".join(rng.choices(string.ascii_letters, k=rng.randint(1, 8))) for _ in range(rng.randint(2, 15))]
        p = " ".join(words)
        assert reassemble_parts(_split(p)) == [p]


def test_encoded_payloads_still_understood_by_the_mock(cases):
    rng = random.Random(1)
    for op in ("b64", "rot13"):
        m = mutate(cases["DI-002"], [op], rng)
        assert m.injection.payload != cases["DI-002"].injection.payload
        views = decoded_views(m.injection.payload)
        assert any(d.kind == "tool" and d.key == "run_shell" for v in views for d in parse_directives(v, "prompt"))


def test_split_moves_ioc_payload_to_logs(cases):
    m = mutate(cases["II-003"], ["split"], random.Random(0))
    assert m.injection == Injection(location="log", parts=m.injection.parts) and len(m.injection.parts) == 2
