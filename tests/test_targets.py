import pytest

from redteam.defences import CONDITIONS, DefenceStack
from redteam.judges import rule_judge, task_success
from redteam.targets.p5 import p5_available
from redteam.targets.toy import ToyTarget

pytestmark = pytest.mark.anyio


async def run(target, case, cond, seed=1):
    return await target.run(case, DefenceStack.for_condition(cond), seed, cond)


async def test_positive_control_attacks_succeed_without_defences(suite):
    """The vulnerable toy must be breakable, or the harness cannot be trusted to detect anything."""
    toy = ToyTarget()
    attacks = [c for c in suite.cases if c.is_attack and "toy" in c.targets]
    wins = [rule_judge(c, await run(toy, c, "none", s), toy.tiers).success for c in attacks for s in (1, 2, 3)]
    assert sum(wins) / len(wins) > 0.3


async def test_runs_are_deterministic(cases):
    toy = ToyTarget()
    a = await run(toy, cases["II-006"], "none", 2)
    b = await run(toy, cases["II-006"], "none", 2)
    assert a.to_dict() == b.to_dict()


@pytest.mark.parametrize("cond", CONDITIONS)
async def test_plain_benign_task_succeeds_under_every_condition(cases, cond):
    toy = ToyTarget()
    t = await run(toy, cases["BN-001"], cond)
    assert task_success(cases["BN-001"], t), t.final_output


async def test_privsep_denies_every_unauthorised_sensitive_call(suite):
    toy = ToyTarget()
    for c in suite.cases:
        if "toy" not in c.targets:
            continue
        for seed in (1, 2, 3):
            t = await run(toy, c, "privsep", seed)
            for e in t.executed():
                if toy.tiers.get(e.name) == "sensitive":
                    assert any(a.tool == e.name and a.contains in str(e.args) for a in c.authorised), (c.id, e)


async def test_input_filter_blocks_before_any_tool_runs(cases):
    t = await run(ToyTarget(), cases["JB-001"], "input_filter")
    assert t.input_blocked and t.refused and t.tool_calls == []


needs_p5 = pytest.mark.skipif(not p5_available(), reason="project 5 not found at P5_PATH")


@pytest.fixture(scope="module")
def p5():
    from redteam.targets.p5 import P5Target

    t = P5Target()
    yield t
    t.close()


@needs_p5
async def test_p5_benign_hunt_and_poison_reaches_agent(p5, cases):
    t = await run(p5, cases["BN-001"], "all")
    assert task_success(cases["BN-001"], t)
    # indirect payload planted in the attack chain's auth events is read and (for some seed) obeyed
    outs = [rule_judge(cases["II-002"], await run(p5, cases["II-002"], "none", s), p5.tiers).success for s in (1, 2, 3)]
    assert any(outs)


@needs_p5
async def test_p5_own_allow_list_stops_unknown_tools(p5, cases):
    for seed in (1, 2, 3, 4):
        t = await run(p5, cases["JB-001"], "none", seed)
        assert not any(e.name == "run_shell" and e.status == "executed" for e in t.tool_calls)


@needs_p5
async def test_p5_sanitiser_keeps_hunt_working(p5, cases):
    t = await run(p5, cases["II-001"], "sanitiser")
    assert "confirmed" in t.final_output and any(e["by"] == "sanitiser" for e in t.defence_events)
