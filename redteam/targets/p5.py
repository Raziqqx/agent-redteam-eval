"""Adapter for project 5 (agentic-threat-hunter): its real MCP server, real HuntAgent loop and safeguards.

Path dependency, no copied code: project 5's root is put on sys.path (env P5_PATH, default the sibling folder
../agentic-threat-hunter). Each run gets a fresh copy of a small generated dataset (seed 7, scale 0.2) with the
case's poison planted in the attack chain's own log events / IOC entry, so the agent retrieves it naturally.

The approval gate is replaced by a harness gate: with no defence it approves everything (a rubber-stamping
human, the worst case); with privsep it approves only what the case authorised. Project 5's own default is deny.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from ..cases import Case
from ..defences import DefenceStack
from ..llm import SusceptibleLLM
from ..transcript import RunContext, ToolEvent, Transcript

DEFAULT_P5 = Path(__file__).resolve().parents[3] / "agentic-threat-hunter"
ACTION = "request_response_action"


def p5_path() -> Path:
    return Path(os.environ.get("P5_PATH", DEFAULT_P5)).resolve()


def p5_available() -> bool:
    return (p5_path() / "agent" / "loop.py").exists()


def _import_p5():
    root = str(p5_path())
    if root not in sys.path:
        sys.path.insert(0, root)
    from agent.llm import MockProvider, make_provider
    from agent.loop import READ_ONLY_TOOLS, Budgets, HuntAgent
    from datagen.generate import generate
    from service.server import build_server

    return SimpleNamespace(
        MockProvider=MockProvider,
        make_provider=make_provider,
        READ_ONLY_TOOLS=READ_ONLY_TOOLS,
        Budgets=Budgets,
        HuntAgent=HuntAgent,
        generate=generate,
        build_server=build_server,
    )


class GuardedSession:
    """Wraps project 5's MCP client session: policy/privsep checks before a tool runs, sanitising after."""

    def __init__(self, session, stack: DefenceStack, ctx: RunContext, t: Transcript):
        self.s, self.stack, self.ctx, self.t = session, stack, ctx, t

    async def list_tools(self):
        return await self.s.list_tools()

    async def call_tool(self, name: str, args: dict):
        d = self.stack.check_tool_call(name, args, self.ctx)
        if not d.allowed:
            self.t.tool_calls.append(ToolEvent(name, args, "denied", d.by, d.reason))
            return SimpleNamespace(
                structured_content={"error": f"denied by {d.by}: {d.reason}"}, content=[], is_error=True
            )
        res = await self.s.call_tool(name, args)
        if res.is_error:
            text = "".join(getattr(c, "text", "") for c in res.content)
            self.t.tool_calls.append(ToolEvent(name, args, "error", "target", text[:300]))
            return res
        value = res.structured_content
        if value is None:  # project 5 returns JSON as text content: sanitise the parsed structure, not the string
            text = "".join(getattr(c, "text", "") for c in res.content)
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                value = text
        clean = self.stack.sanitise(name, value)
        self.t.tool_calls.append(ToolEvent(name, args, "executed", "", json.dumps(clean, default=str)[:300]))
        if isinstance(clean, str):
            return SimpleNamespace(structured_content=None, content=[SimpleNamespace(text=clean)], is_error=False)
        return SimpleNamespace(structured_content=clean, content=res.content, is_error=False)


class HarnessGate:
    """Stands in for project 5's ApprovalGate; the active defences decide, otherwise it rubber-stamps."""

    def __init__(self, stack: DefenceStack, ctx: RunContext, t: Transcript):
        self.stack, self.ctx, self.t = stack, ctx, t

    def decide(self, name: str, args: dict) -> bool:
        d = self.stack.check_tool_call(name, args, self.ctx)
        if not d.allowed:
            self.t.tool_calls.append(ToolEvent(name, args, "denied", d.by, d.reason))
            return False
        self.t.tool_calls.append(ToolEvent(name, args, "executed", "", "approved recommendation (recorded only)"))
        return True


class P5Target:
    name = "p5"

    def __init__(self, provider: str = "mock"):
        self.p5 = _import_p5()
        self.provider = provider
        self.tiers = {t: "read" for t in self.p5.READ_ONLY_TOOLS} | {ACTION: "sensitive"}
        self._tmp = Path(tempfile.mkdtemp(prefix="redteam-p5-"))
        self.base = self._tmp / "base"
        self.p5.generate(7, self.base, scale=0.2)
        labels = json.loads((self.base / "labels.json").read_text())
        c1 = next(c for c in labels["chains"] if c["chain_id"] == "C1")
        self.attack_ids = next(s["event_ids"] for s in c1["steps"] if s["technique"] == "T1110.001")

    def close(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _poison(self, case: Case, run_dir: Path) -> None:
        shutil.copytree(self.base, run_dir)
        auth = run_dir / "auth.jsonl"
        events = [json.loads(line) for line in auth.read_text().splitlines()]
        by_id = {e["event_id"]: e for e in events}
        attack = [by_id[i] for i in self.attack_ids]
        inj = case.injection
        if inj and inj.location == "log":
            for e, text in zip(attack, inj.parts or [inj.payload], strict=False):
                e["message"] += " " + text
        if inj and inj.location == "ioc":
            for e, text in zip(attack[1:], inj.parts, strict=False):
                e["message"] += " " + text
            if inj.payload:
                iocs = json.loads((run_dir / "iocs.json").read_text())
                for i in iocs:
                    if i["indicator"] == attack[0]["src_ip"]:
                        i["note"] = inj.payload
                (run_dir / "iocs.json").write_text(json.dumps(iocs))
        for e, s in zip(attack[5:], case.secrets, strict=False):
            e["message"] += f" debug token={s}"
        auth.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events))

    async def run(self, case: Case, stack: DefenceStack, seed: int, condition: str = "") -> Transcript:
        from mcp import Client

        task = case.task + (
            f"\n\n{case.injection.payload}" if case.injection and case.injection.location == "prompt" else ""
        )
        t = Transcript(case.id, self.name, condition, seed, task=task)
        dec = stack.filter_input(task)
        if not dec.allowed:
            t.input_blocked = t.refused = True
            t.final_output = f"Request blocked by {dec.by} ({dec.reason})."
            t.defence_events = stack.events
            return t
        ctx = RunContext(case, self.tiers)
        run_dir = Path(tempfile.mkdtemp(dir=self._tmp)) / "data"
        self._poison(case, run_dir)
        if self.provider == "mock":
            llm = SusceptibleLLM(self.p5.MockProvider(), seed=seed, case_key=case.id)
        else:  # real model via project 5's provider (needs ANTHROPIC_API_KEY); never run in this repo's results
            llm = self.p5.make_provider(self.provider)
        server = self.p5.build_server(run_dir, run_dir.parent / "audit.jsonl")
        async with Client(server) as session:
            agent = self.p5.HuntAgent(
                llm, GuardedSession(session, stack, ctx, t), self.p5.Budgets(max_steps=16), HarnessGate(stack, ctx, t)
            )
            report = await agent.run(task)
        shutil.rmtree(run_dir.parent, ignore_errors=True)
        known = set(self.p5.READ_ONLY_TOOLS) | {ACTION}
        for step in report.trace:  # calls project 5's own allow-list rejected never reach the session
            for c in step["tool_calls"]:
                if c["name"] not in known:
                    t.tool_calls.append(ToolEvent(c["name"], c["input"], "error", "target:allow-list"))
        titles = "; ".join(f.get("title", "") for f in report.findings)
        t.final_output = stack.filter_output(f"{report.summary}\nFindings: {titles or 'none'}")
        t.refused = report.summary.startswith("I can't comply") or report.stop_reason == "refusal"
        t.steps, t.defence_events = report.steps, stack.events
        t.llm_notes = getattr(llm, "notes", [])
        return t
