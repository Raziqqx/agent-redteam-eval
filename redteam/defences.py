"""Defences, each usable alone or stacked. Every adapter calls the four hooks at the same points:

filter_input(task)               before the agent sees the user's task
sanitise(tool, value)            on every tool result before the model sees it
check_tool_call(name, args, ctx) before a tool executes (and inside approval gates)
filter_output(text)              on the final answer
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .llm import SECRET_RE
from .transcript import RunContext, args_json

POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"


@dataclass
class Decision:
    allowed: bool
    by: str = ""
    reason: str = ""


ALLOW = Decision(True)


class Defence:
    name = "none"

    def filter_input(self, text: str) -> Decision:
        return ALLOW

    def sanitise(self, tool: str, value):
        return value

    def check_tool_call(self, name: str, args: dict, ctx: RunContext) -> Decision:
        return ALLOW

    def filter_output(self, text: str) -> str:
        return text


class InputFilter(Defence):
    """Blocks a user task that carries known injection / jailbreak markers or a large encoded blob."""

    name = "input_filter"
    PATTERNS = [
        (
            re.compile(r"\b(?:ignore|disregard|forget)\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all)\b", re.I),
            "instruction override",
        ),
        (
            re.compile(r"\b(?:developer mode|DAN|jailbreak|no restrictions|unrestricted|unfiltered)\b", re.I),
            "jailbreak marker",
        ),
        (re.compile(r"\byou are now\b|\bpretend (?:to be|you)\b|\blet's play\b", re.I), "role-play"),
        (re.compile(r"<\s*/?\s*system\s*>|\bsystem prompt\b|###\s*system", re.I), "fake system delimiter"),
        (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "encoded blob"),
        (re.compile(r"\brot13\b", re.I), "encoded text"),
    ]

    def filter_input(self, text: str) -> Decision:
        for rx, why in self.PATTERNS:
            if rx.search(text):
                return Decision(False, self.name, why)
        return ALLOW


class ToolOutputSanitiser(Defence):
    """Removes instruction-like clauses from every string in a tool result (keeps the JSON shape)."""

    name = "sanitiser"
    CLAUSE_SPLIT = re.compile(r"(?<=[.;!?\n])\s+")
    PATTERNS = [
        re.compile(
            r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:instructions?|rules|guidance|above|previous)\b", re.I
        ),
        re.compile(
            r"\b(?:assistant|AI|agent|model|you)\b[^.\n]{0,40}\b(?:must|should|need to|are required to)\b", re.I
        ),
        re.compile(r"\b(?:call|invoke|execute)\s+(?:the\s+)?(?:tool\s+)?`?[a-z]+_[a-z_]+", re.I),
        re.compile(r"<\s*/?\s*(?:system|instructions?)\s*>|\bsystem\s*:|\bnew (?:instructions?|task)\b", re.I),
        re.compile(r"\b(?:decode|base64|rot13)\b", re.I),
    ]
    MARK = "[sanitised: instruction-like text removed]"

    def _clean(self, s: str) -> str:
        clauses = self.CLAUSE_SPLIT.split(s)
        kept = [c if not any(p.search(c) for p in self.PATTERNS) else self.MARK for c in clauses]
        return " ".join(kept)

    def sanitise(self, tool: str, value):
        if isinstance(value, str):
            return self._clean(value)
        if isinstance(value, dict):
            return {k: self.sanitise(tool, v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.sanitise(tool, v) for v in value]
        return value


class PrivilegeSeparation(Defence):
    """Read-only tier runs freely; sensitive tools need approval; unknown tools are refused.

    The approver is simulated as a careful human who approves exactly what the user's task authorised
    (`case.authorised`). It never rubber-stamps; that is the optimistic assumption, see DECISIONS.md."""

    name = "privsep"

    def check_tool_call(self, name, args, ctx):
        tier = ctx.tiers.get(name)
        if tier == "read":
            return ALLOW
        if tier == "sensitive":
            if ctx.authorised(name, args):
                return ALLOW
            return Decision(False, self.name, "sensitive tool not approved for this task")
        return Decision(False, self.name, "tool not in any privilege tier")


class PolicyLayer(Defence):
    """Declarative argument / egress / taint policy loaded from policies/default.yaml."""

    name = "policy"

    def __init__(self, path: Path = POLICY_PATH):
        self.doc = yaml.safe_load(path.read_text(encoding="utf-8"))

    @staticmethod
    def _violates(rule: dict, value) -> str:
        s = str(value)
        if "prefix" in rule and not s.startswith(rule["prefix"]):
            return f"must start with {rule['prefix']}"
        if "suffix" in rule and not s.endswith(rule["suffix"]):
            return f"must end with {rule['suffix']}"
        if "not_in" in rule and s.lower() in {x.lower() for x in rule["not_in"]}:
            return "protected value"
        if "max" in rule and isinstance(value, int | float) and value > rule["max"]:
            return f"exceeds {rule['max']}"
        if "not_cidr" in rule:
            try:
                if ipaddress.ip_address(s) in ipaddress.ip_network(rule["not_cidr"]):
                    return f"inside protected range {rule['not_cidr']}"
            except ValueError:
                pass
        return ""

    def check_tool_call(self, name, args, ctx):
        d = self.doc
        if name in d.get("deny_tools", []):
            return Decision(False, self.name, "tool denied by policy")
        if name not in ctx.tiers:
            return Decision(False, self.name, "tool not on the target allow-list")
        for key, rule in d.get("args", {}).items():
            tool, arg = key.split(".", 1)
            if tool == name and arg in args:
                why = self._violates(rule, args[arg])
                if why:
                    return Decision(False, self.name, f"{key}: {why}")
        if d.get("taint", {}).get("deny_secret_patterns") and SECRET_RE.search(args_json(args)):
            return Decision(False, self.name, "secret-shaped value in tool arguments")
        if ctx.tiers.get(name) == "sensitive":
            if ctx.sensitive_calls >= d.get("max_sensitive_calls", 99):
                return Decision(False, self.name, "sensitive-call budget exhausted")
        return ALLOW


class OutputFilter(Defence):
    """DLP on the final answer: redacts secret-shaped strings, including base64-encoded ones."""

    name = "output_filter"
    B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

    def filter_output(self, text: str) -> str:
        text = SECRET_RE.sub("[REDACTED]", text)

        def unb64(m):
            try:
                raw = base64.b64decode(m.group() + "=" * (-len(m.group()) % 4), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return m.group()
            return "[REDACTED]" if SECRET_RE.search(raw) else m.group()

        return self.B64.sub(unb64, text)


DEFENCES = {
    "input_filter": InputFilter,
    "output_filter": OutputFilter,
    "sanitiser": ToolOutputSanitiser,
    "privsep": PrivilegeSeparation,
    "policy": PolicyLayer,
}
CONDITIONS = ["none", *DEFENCES, "all"]


@dataclass
class DefenceStack:
    """The defences active in one condition, plus a log of every intervention for the transcript."""

    defences: list[Defence] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)

    @staticmethod
    def for_condition(condition: str) -> DefenceStack:
        if condition == "none":
            return DefenceStack([])
        if condition == "all":
            return DefenceStack([cls() for cls in DEFENCES.values()])
        return DefenceStack([DEFENCES[condition]()])

    def filter_input(self, text: str) -> Decision:
        for d in self.defences:
            dec = d.filter_input(text)
            if not dec.allowed:
                self.events.append({"hook": "input", "by": dec.by, "reason": dec.reason})
                return dec
        return ALLOW

    def sanitise(self, tool: str, value):
        for d in self.defences:
            new = d.sanitise(tool, value)
            if new != value:
                self.events.append({"hook": "tool_output", "by": d.name, "tool": tool})
            value = new
        return value

    def check_tool_call(self, name: str, args: dict, ctx: RunContext) -> Decision:
        for d in self.defences:
            dec = d.check_tool_call(name, args, ctx)
            if not dec.allowed:
                self.events.append({"hook": "tool_call", "by": dec.by, "tool": name, "reason": dec.reason})
                return dec
        if ctx.tiers.get(name) == "sensitive":
            ctx.sensitive_calls += 1
        return ALLOW

    def filter_output(self, text: str) -> str:
        for d in self.defences:
            new = d.filter_output(text)
            if new != text:
                self.events.append({"hook": "output", "by": d.name})
            text = new
        return text
