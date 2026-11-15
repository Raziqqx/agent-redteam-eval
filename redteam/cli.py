"""redteam CLI: generate | run | sample-labels | report.

redteam generate --suite cases/core-v1.yaml --out cases/generated-v1.yaml
redteam run --targets toy p5 --seeds 1 2 3 --out results
redteam report --out results
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import anyio

from .cases import Suite, dump_suite, load_suite
from .defences import CONDITIONS
from .judges import render_for_judge
from .mutate import generate
from .transcript import Transcript


def _cases(args) -> tuple[Suite, list]:
    suite = load_suite(args.suite)
    cases = list(suite.cases)
    if args.generated and Path(args.generated).exists():
        cases += load_suite(args.generated).cases
    return suite, cases


def _tiers(targets) -> dict[str, dict]:
    from .targets.toy import TIERS

    tiers = {"toy": TIERS}
    if "p5" in targets:
        from .targets.p5 import ACTION, _import_p5

        tiers["p5"] = {t: "read" for t in _import_p5().READ_ONLY_TOOLS} | {ACTION: "sensitive"}
    return tiers


def cmd_generate(args) -> None:
    suite = load_suite(args.suite)
    mutants, stats = generate(suite, args.per_case, args.seed)
    dump_suite(
        Suite(schema_version=1, suite=f"{suite.suite}-generated", version=suite.version, cases=mutants), args.out
    )
    print(json.dumps(stats))


def cmd_run(args) -> None:
    from .runner import run_matrix

    suite, cases = _cases(args)
    rows = anyio.run(lambda: run_matrix(args.targets, cases, args.conditions, args.seeds, args.out, args.provider))
    meta = {
        "suite": suite.suite,
        "suite_version": suite.version,
        "seed_cases": len(suite.cases),
        "mutants": len(cases) - len(suite.cases),
        "conditions": args.conditions,
        "seeds": args.seeds,
        "provider": args.provider,
        "targets": args.targets,
    }
    (args.out / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"{len(rows)} runs -> {args.out / 'runs.jsonl'}")


def cmd_sample(args) -> None:
    """Draw a stratified sample of attack transcripts to hand-label; writes sample.jsonl and a readable sample.md."""
    suite, cases = _cases(args)
    by_id = {c.id: c for c in cases}
    rng = random.Random(args.seed)
    pool = [json.loads(x) for x in args.transcripts.read_text().splitlines()]
    pool = [d for d in pool if by_id[d["case_id"]].is_attack]
    strata: dict[tuple, list] = {}
    for d in pool:
        strata.setdefault((d["target"], d["condition"]), []).append(d)
    per = max(1, args.n // len(strata))
    picked = []
    for k in sorted(strata):
        picked += rng.sample(strata[k], min(per, len(strata[k])))
    args.labels.mkdir(parents=True, exist_ok=True)
    with open(args.labels / "sample.jsonl", "w", encoding="utf-8") as f:
        for d in picked:
            f.write(json.dumps({"key": f"{d['target']}|{d['case_id']}|{d['condition']}|{d['seed']}", **d}) + "\n")
    md = ["# Hand-labelling sample (see DECISIONS.md, 'Labelling guide')", ""]
    for d in picked:
        t = Transcript.from_dict(d)
        md += [
            f"## {d['target']}|{d['case_id']}|{d['condition']}|{d['seed']}",
            "```",
            f"Task: {t.task}",
            render_for_judge(by_id[t.case_id], t),
            "```",
            "",
        ]
    (args.labels / "sample.md").write_text("\n".join(md), encoding="utf-8")
    print(f"{len(picked)} transcripts -> {args.labels / 'sample.jsonl'}")


def cmd_report(args) -> None:
    from .report import build

    suite, cases = _cases(args)
    rows = [json.loads(x) for x in (args.out / "runs.jsonl").read_text().splitlines()]
    meta = json.loads((args.out / "meta.json").read_text())
    summary = build(rows, {c.id: c for c in cases}, _tiers(meta["targets"]), args.out, meta, args.labels)
    for tg, v in summary["targets"].items():
        ab = v["ablation"]
        print(
            f"{tg}: ASR none={ab['none']['asr']:.3f} all={ab['all']['asr']:.3f} "
            f"benign FPR(all)={ab['all']['benign_fpr']:.3f} rule/judge kappa={v['judges']['kappa']:.3f}"
        )
    if summary["hand_labels"]:
        h = summary["hand_labels"]
        print(
            f"hand labels n={h['n']}: kappa rules={h['kappa_rules_vs_hand']:.3f} judge={h['kappa_judge_vs_hand']:.3f}"
        )
    print(f"-> {args.out / 'report.md'}, {args.out / 'report.html'}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        prog="redteam", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--suite", type=Path, default=Path("cases/core-v1.yaml"))
        p.add_argument("--generated", type=Path, default=Path("cases/generated-v1.yaml"))
        p.add_argument("--labels", type=Path, default=Path("labels"))

    g = sub.add_parser("generate", help="mutate seed attacks into a generated suite")
    g.add_argument("--suite", type=Path, default=Path("cases/core-v1.yaml"))
    g.add_argument("--out", type=Path, default=Path("cases/generated-v1.yaml"))
    g.add_argument("--per-case", type=int, default=2)
    g.add_argument("--seed", type=int, default=7)
    g.set_defaults(fn=cmd_generate)

    r = sub.add_parser("run", help="run the target x case x condition x seed matrix")
    common(r)
    r.add_argument("--targets", nargs="+", default=["toy", "p5"], choices=["toy", "p5"])
    r.add_argument("--conditions", nargs="+", default=CONDITIONS, choices=CONDITIONS)
    r.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3])
    r.add_argument(
        "--provider",
        default="mock",
        choices=["mock", "anthropic"],
        help="p5 only: 'anthropic' uses project 5's real provider (needs ANTHROPIC_API_KEY)",
    )
    r.add_argument("--out", type=Path, default=Path("results"))
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("sample-labels", help="export a stratified transcript sample for hand labelling")
    common(s)
    s.add_argument("--transcripts", type=Path, default=Path("results/transcripts.jsonl"))
    s.add_argument("--n", type=int, default=40)
    s.add_argument("--seed", type=int, default=11)
    s.set_defaults(fn=cmd_sample)

    p = sub.add_parser("report", help="write report.md/.html, ablation CSVs and summary.json")
    common(p)
    p.add_argument("--out", type=Path, default=Path("results"))
    p.set_defaults(fn=cmd_report)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
