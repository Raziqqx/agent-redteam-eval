"""Target adapter interface. Any agent can be tested by implementing `Target`:

    name: str                       short id used in results
    tiers: dict[str, str]           tool -> "read" | "sensitive" (used by privsep/policy and the rule judge)
    async run(case, stack, seed, condition) -> Transcript

`run` sends the case's task (plus any prompt injection), plants indirect payloads/secrets in the target's
data, calls the DefenceStack hooks at the four documented points, and returns the transcript: tool calls with
their status, final output, refusal flag and defence interventions.
"""

from __future__ import annotations

from typing import Protocol

from ..cases import Case
from ..defences import DefenceStack
from ..transcript import Transcript


class Target(Protocol):
    name: str
    tiers: dict[str, str]

    async def run(self, case: Case, stack: DefenceStack, seed: int, condition: str = "") -> Transcript: ...


def make_target(name: str, provider: str = "mock") -> Target:
    if name == "toy":
        from .toy import ToyTarget

        return ToyTarget()
    if name == "p5":
        from .p5 import P5Target

        return P5Target(provider)
    raise ValueError(f"unknown target {name!r}")
