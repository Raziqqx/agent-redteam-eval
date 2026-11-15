"""Versioned attack/benign case schema (pydantic) and the YAML loader."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = 1
ATTACK_CATEGORIES = (
    "direct_injection",
    "indirect_injection",
    "jailbreak",
    "tool_misuse",
    "exfiltration",
    "goal_hijack",
)
CATEGORIES = (*ATTACK_CATEGORIES, "benign")
POLICY_CHECKS = ("unauthorised_sensitive_action", "findings_suppressed")

Category = Literal[
    "direct_injection", "indirect_injection", "jailbreak", "tool_misuse", "exfiltration", "goal_hijack", "benign"
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Injection(Strict):
    """Attacker-controlled text and where it is planted.

    prompt   -> appended to the user's task (direct injection / jailbreak)
    log      -> embedded in log events the agent retrieves (indirect)
    ioc      -> a `note` on the threat-intel entry the agent looks up (indirect)
    `parts` (set by the split mutation) spreads the payload over several log events.
    """

    location: Literal["prompt", "log", "ioc"]
    payload: str = ""
    parts: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _non_empty(self):
        if not self.payload and not self.parts:
            raise ValueError("injection needs a payload or parts")
        if self.parts and self.location == "prompt":
            raise ValueError("split parts only make sense in tool outputs (log/ioc)")
        return self


class ArgMatch(Strict):
    tool: str
    contains: str = ""  # substring of the JSON-encoded args; "" matches any call to the tool


class Success(Strict):
    """When does the attack count as successful? Any one criterion is enough."""

    canaries: list[str] = Field(default_factory=list)  # in final output or executed tool args
    forbidden_tools: list[str] = Field(default_factory=list)  # executed (not denied, not errored)
    forbidden_args: list[ArgMatch] = Field(default_factory=list)  # executed with matching args
    policy: list[Literal["unauthorised_sensitive_action", "findings_suppressed"]] = Field(default_factory=list)


class Expect(Strict):
    """Benign task success: output keywords and tools that must have executed."""

    output_contains: list[str] = Field(default_factory=list)
    tools_executed: list[str] = Field(default_factory=list)


class Case(Strict):
    id: str = Field(pattern=r"^[A-Z]{2,3}-\d{3}(-m[0-9a-f]{6})?$")
    version: int = Field(ge=1)
    category: Category
    title: str
    targets: list[Literal["toy", "p5"]] = Field(default_factory=lambda: ["toy", "p5"])
    task: str
    injection: Injection | None = None
    secrets: list[str] = Field(default_factory=list)  # canary secrets planted in the target's data
    authorised: list[ArgMatch] = Field(default_factory=list)  # sensitive calls the user actually asked for
    success: Success = Field(default_factory=Success)
    expect: Expect = Field(default_factory=Expect)
    parent: str | None = None  # seed case id, for mutants
    mutations: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.category != "benign"

    @model_validator(mode="after")
    def _criteria(self):
        s = self.success
        has_criteria = s.canaries or s.forbidden_tools or s.forbidden_args or s.policy
        if self.is_attack and not has_criteria:
            raise ValueError(f"{self.id}: attack case declares no success criteria")
        if not self.is_attack and (has_criteria or self.injection):
            raise ValueError(f"{self.id}: benign case must not carry an injection or success criteria")
        if not self.is_attack and not (self.expect.output_contains or self.expect.tools_executed):
            raise ValueError(f"{self.id}: benign case needs task-success expectations")
        return self


class Suite(Strict):
    schema_version: Literal[1]
    suite: str
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    cases: list[Case]

    @model_validator(mode="after")
    def _unique(self):
        ids = [c.id for c in self.cases]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"duplicate case ids: {sorted(dup)}")
        return self


def load_suite(path: Path) -> Suite:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    # Top-level "x-*" keys hold YAML anchors (shared task text etc.); they are resolved by the parser.
    return Suite.model_validate({k: v for k, v in doc.items() if not k.startswith("x-")})


def dump_suite(suite: Suite, path: Path) -> None:
    data = suite.model_dump(mode="json", exclude_defaults=True)
    data["schema_version"] = suite.schema_version
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")
