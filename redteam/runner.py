"""Run the (target x case x defence condition x seed) matrix and judge every transcript."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .cases import Case
from .defences import DefenceStack
from .judges import mock_llm_judge, rule_judge, task_success
from .targets import make_target

BLOCKING_HOOKS = {"input", "tool_call", "output"}


def row_for(case: Case, t, tiers: dict) -> dict:
    rv = rule_judge(case, t, tiers)
    jv = mock_llm_judge(case, t)
    blocking = [e for e in t.defence_events if e["hook"] in BLOCKING_HOOKS]
    return {
        "target": t.target,
        "condition": t.condition,
        "seed": t.seed,
        "case_id": case.id,
        "parent": case.parent or case.id,
        "category": case.category,
        "mutated": case.parent is not None,
        "attack": case.is_attack,
        "rule_success": rv.success if case.is_attack else None,
        "rule_reasons": rv.reasons,
        "judge_success": jv.success if case.is_attack else None,
        "refused": t.refused,
        "input_blocked": t.input_blocked,
        "task_success": None if case.is_attack else task_success(case, t),
        "intervened": bool(blocking),
        "intervened_by": sorted({e["by"] for e in blocking}),
        "sanitised": any(e["hook"] == "tool_output" for e in t.defence_events),
        "attempted_calls": len(t.tool_calls),
        "denied_calls": sum(e.status == "denied" for e in t.tool_calls),
    }


async def run_matrix(
    targets: list[str],
    cases: list[Case],
    conditions: list[str],
    seeds: list[int],
    out: Path,
    provider: str = "mock",
    keep: tuple[str, ...] = ("none", "all"),
    log=print,
) -> list[dict]:
    """Writes out/runs.jsonl (one row per run) and out/transcripts.jsonl (conditions in `keep`, first seed)."""
    out.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    with (
        open(out / "runs.jsonl", "w", encoding="utf-8") as fr,
        open(out / "transcripts.jsonl", "w", encoding="utf-8") as ft,
    ):
        for name in targets:
            target = make_target(name, provider)
            mine = [c for c in cases if name in c.targets]
            t0 = time.monotonic()
            for case in mine:
                for cond in conditions:
                    for seed in seeds:
                        t = await target.run(case, DefenceStack.for_condition(cond), seed, cond)
                        row = row_for(case, t, target.tiers)
                        rows.append(row)
                        fr.write(json.dumps(row) + "\n")
                        if cond in keep and seed == seeds[0]:
                            ft.write(json.dumps(t.to_dict(), default=str) + "\n")
            if hasattr(target, "close"):
                target.close()
            log(
                f"{name}: {len(mine)} cases x {len(conditions)} conditions x {len(seeds)} seeds "
                f"in {time.monotonic() - t0:.1f}s"
            )
    return rows
