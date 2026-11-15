"""Aggregate runs.jsonl (+ the hand-labelled sample) into Markdown, HTML, CSV and summary.json."""

from __future__ import annotations

import csv
import html
import json
import math
from collections import defaultdict
from pathlib import Path

import yaml

from .cases import ATTACK_CATEGORIES, Case
from .defences import CONDITIONS
from .judges import mock_llm_judge, rule_judge
from .metrics import cohen_kappa, confusion, wilson
from .transcript import Transcript

SHORT = {
    "direct_injection": "direct",
    "indirect_injection": "indirect",
    "jailbreak": "jailbreak",
    "tool_misuse": "tool misuse",
    "exfiltration": "exfil",
    "goal_hijack": "hijack",
}


def _rate(xs: list[bool]) -> float:
    return sum(xs) / len(xs) if xs else math.nan


def _fmt(x: float) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.3f}"


def ablation(rows: list[dict], target: str) -> tuple[list[str], list[list[str]], dict]:
    head = [
        "condition",
        *[SHORT[c] for c in ATTACK_CATEGORIES],
        "ASR all [95% CI]",
        "safe-refusal",
        "benign task success",
        "benign FPR",
        "over-refusal",
    ]
    body, raw = [], {}
    for cond in CONDITIONS:
        rs = [r for r in rows if r["target"] == target and r["condition"] == cond]
        if not rs:
            continue
        att = [r for r in rs if r["attack"]]
        ben = [r for r in rs if not r["attack"]]
        cats = [_rate([r["rule_success"] for r in att if r["category"] == c]) for c in ATTACK_CATEGORIES]
        k = sum(r["rule_success"] for r in att)
        lo, hi = wilson(k, len(att))
        asr = _rate([r["rule_success"] for r in att])
        safe = _rate([r["refused"] and not r["rule_success"] for r in att])
        task = _rate([r["task_success"] for r in ben])
        fpr = _rate([r["intervened"] for r in ben])
        over = _rate([r["refused"] for r in ben])
        raw[cond] = {
            "asr": asr,
            "asr_ci": [lo, hi],
            "n_attack": len(att),
            "n_benign": len(ben),
            "per_category": dict(zip(ATTACK_CATEGORIES, cats, strict=True)),
            "safe_refusal": safe,
            "benign_task_success": task,
            "benign_fpr": fpr,
            "over_refusal": over,
        }
        body.append(
            [
                cond,
                *map(_fmt, cats),
                f"{_fmt(asr)} [{_fmt(lo)}, {_fmt(hi)}]",
                _fmt(safe),
                _fmt(task),
                _fmt(fpr),
                _fmt(over),
            ]
        )
    return head, body, raw


def seeds_vs_mutants(rows: list[dict], target: str) -> tuple[list[str], list[list[str]]]:
    head = ["condition", "seed cases ASR", "n", "mutants ASR", "n"]
    body = []
    for cond in CONDITIONS:
        att = [r for r in rows if r["target"] == target and r["condition"] == cond and r["attack"]]
        if not att:
            continue
        s = [r["rule_success"] for r in att if not r["mutated"]]
        m = [r["rule_success"] for r in att if r["mutated"]]
        body.append([cond, _fmt(_rate(s)), str(len(s)), _fmt(_rate(m)), str(len(m))])
    return head, body


def mutation_ops(rows: list[dict], cases: dict[str, Case], target: str, cond: str = "all"):
    """ASR of mutants under `cond`, by mutation operator (a mutant counts once per operator it used)."""
    by = defaultdict(list)
    for r in rows:
        if r["target"] == target and r["condition"] == cond and r["mutated"] and r["case_id"] in cases:
            for op in cases[r["case_id"]].mutations:
                by[op].append(r["rule_success"])
    return ["operator", f"ASR under '{cond}'", "runs"], [
        [op, _fmt(_rate(v)), str(len(v))] for op, v in sorted(by.items())
    ]


def run_agreement(rows: list[dict]) -> dict:
    att = [r for r in rows if r["attack"]]
    a, b = [r["rule_success"] for r in att], [r["judge_success"] for r in att]
    return {"n": len(att), "kappa": cohen_kappa(a, b), "agreement": _rate([x == y for x, y in zip(a, b, strict=True)])}


def hand_label_agreement(sample: Path, labels: Path, cases: dict[str, Case], tiers: dict[str, dict]) -> dict:
    """Re-judge the frozen sample transcripts and compare both judges with the hand labels."""
    if not (sample.exists() and labels.exists()):
        return {}
    lab = {x["key"]: bool(x["success"]) for x in yaml.safe_load(labels.read_text(encoding="utf-8"))["labels"]}
    human, rule, judge = [], [], []
    for line in sample.read_text(encoding="utf-8").splitlines():
        d = json.loads(line)
        key = d.pop("key")
        if key not in lab:
            continue
        t = Transcript.from_dict(d)
        case = cases[t.case_id]
        human.append(lab[key])
        rule.append(rule_judge(case, t, tiers[t.target]).success)
        judge.append(mock_llm_judge(case, t).success)
    if not human:
        return {}
    return {
        "n": len(human),
        "positives_by_hand": sum(human),
        "kappa_rules_vs_hand": cohen_kappa(rule, human),
        "kappa_judge_vs_hand": cohen_kappa(judge, human),
        "rules_confusion": confusion(rule, human),
        "judge_confusion": confusion(judge, human),
    }


def md_table(head, body) -> str:
    return "\n".join(
        ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(r) + " |" for r in body]
    )


def html_table(head, body) -> str:
    th = "".join(f"<th>{html.escape(h)}</th>" for h in head)
    trs = "".join("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in r) + "</tr>" for r in body)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def build(
    rows: list[dict], cases: dict[str, Case], tiers: dict[str, dict], out: Path, meta: dict, labels_dir: Path
) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    targets = sorted({r["target"] for r in rows}, key=lambda t: (t != "toy", t))
    sections: list[tuple[str, str, list, list]] = []  # (title, note, head, body)
    summary: dict = {"meta": meta, "targets": {}}
    for tg in targets:
        head, body, raw = ablation(rows, tg)
        sections.append(
            (
                f"Ablation: {tg}",
                "Attack success rate (rule judge) per category; benign FPR = share of "
                "benign runs where any defence blocked an input, a tool call or redacted output.",
                head,
                body,
            )
        )
        with open(out / f"ablation_{tg}.csv", "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([head, *body])
        h2, b2 = seeds_vs_mutants(rows, tg)
        sections.append((f"Seed cases vs generated mutants: {tg}", "", h2, b2))
        h3, b3 = mutation_ops(rows, cases, tg)
        sections.append((f"Mutant ASR by operator under all defences: {tg}", "", h3, b3))
        summary["targets"][tg] = {"ablation": raw, "judges": run_agreement([r for r in rows if r["target"] == tg])}
    hl = hand_label_agreement(labels_dir / "sample.jsonl", labels_dir / "hand_labels.yaml", cases, tiers)
    summary["hand_labels"] = hl
    jh = ["target", "attack runs", "rule vs mock-judge agreement", "kappa"]
    jb = [
        [tg, str(v["judges"]["n"]), _fmt(v["judges"]["agreement"]), _fmt(v["judges"]["kappa"])]
        for tg, v in summary["targets"].items()
    ]
    sections.append(("Rule judge vs mock LLM judge (all attack runs)", "", jh, jb))
    if hl:
        hh = ["comparison", "n", "kappa", "tp", "fp", "fn", "tn"]
        hb = [
            [name, str(hl["n"]), _fmt(hl[k]), *(str(hl[c][x]) for x in ("tp", "fp", "fn", "tn"))]
            for name, k, c in (
                ("rules vs hand labels", "kappa_rules_vs_hand", "rules_confusion"),
                ("mock judge vs hand labels", "kappa_judge_vs_hand", "judge_confusion"),
            )
        ]
        sections.append(
            (
                "Agreement with hand labels",
                f"{hl['n']} hand-labelled transcripts ({hl['positives_by_hand']} labelled successful).",
                hh,
                hb,
            )
        )
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    intro = (
        f"Suite {meta['suite']} v{meta['suite_version']}: {meta['seed_cases']} seed cases + {meta['mutants']} "
        f"mutants; conditions {', '.join(meta['conditions'])}; seeds {meta['seeds']}; LLM: {meta['provider']} "
        "(susceptible mock: results show the harness and defence mechanics, not a real model's robustness)."
    )
    md = ["# agent-redteam-eval report", "", intro, ""]
    for title, note, head, body in sections:
        md += [f"## {title}", "", *([note, ""] if note else []), md_table(head, body), ""]
    (out / "report.md").write_text("\n".join(md), encoding="utf-8")
    style = (
        "body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 16px;"
        "background:#fff;color:#111}table{border-collapse:collapse;margin:1rem 0;font-size:14px}"
        "td,th{border:1px solid #ccc;padding:4px 8px;text-align:right}td:first-child,th:first-child"
        "{text-align:left}th{background:#f2f2f2}"
    )
    body_html = "".join(
        f"<h2>{html.escape(t)}</h2>" + (f"<p>{html.escape(n)}</p>" if n else "") + html_table(h, b)
        for t, n, h, b in sections
    )
    (out / "report.html").write_text(
        f"<!doctype html><html><head><meta charset='utf-8'><title>Red-team report</title><style>{style}</style>"
        f"</head><body><h1>agent-redteam-eval report</h1><p>{html.escape(intro)}</p>{body_html}</body></html>",
        encoding="utf-8",
    )
    return summary
