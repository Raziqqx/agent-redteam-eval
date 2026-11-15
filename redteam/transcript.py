"""Transcript record returned by every target adapter, plus the per-run context the defences see."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .cases import ArgMatch, Case


def args_json(args: dict) -> str:
    return json.dumps(args, sort_keys=True, default=str)


def matches(rule: ArgMatch, name: str, args: dict) -> bool:
    return rule.tool == name and (not rule.contains or rule.contains in args_json(args))


@dataclass
class ToolEvent:
    name: str
    args: dict
    status: str  # executed | error (target rejected / bad args) | denied (a defence blocked it)
    by: str = ""  # which defence or target control decided, when not executed
    result: str = ""  # excerpt of what the agent saw


@dataclass
class Transcript:
    case_id: str
    target: str
    condition: str
    seed: int
    task: str = ""
    input_blocked: bool = False
    refused: bool = False
    final_output: str = ""
    tool_calls: list[ToolEvent] = field(default_factory=list)
    defence_events: list[dict] = field(default_factory=list)
    llm_notes: list[str] = field(default_factory=list)
    steps: int = 0

    def executed(self) -> list[ToolEvent]:
        return [t for t in self.tool_calls if t.status == "executed"]

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> Transcript:
        d = dict(d)
        d["tool_calls"] = [ToolEvent(**t) for t in d.get("tool_calls", [])]
        return Transcript(**d)


@dataclass
class RunContext:
    """What the defences may consult during one run: the case's authorisations and the target's tool tiers."""

    case: Case
    tiers: dict[str, str]  # tool -> "read" | "sensitive"
    sensitive_calls: int = 0

    def authorised(self, name: str, args: dict) -> bool:
        return any(matches(a, name, args) for a in self.case.authorised)
