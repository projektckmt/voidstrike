"""OPPLAN — a structured, state-backed operations plan for the orchestrator.

The prompt-only OPPLAN (see prompts/_shared.py) asks the orchestrator to shape
its `write_todos` entries as phases. This middleware makes that structure
*enforced* instead of *asked*: a `write_opplan` tool whose arg schema requires
each phase to carry intent, a cheapest-confirm move, and a decision criterion
with a branch — the model can't emit a bare string. The plan is stored in agent
state (`opplan`), so it survives transcript summarization and the CLI can render
it.

Mirrors deepagents' TodoListMiddleware exactly: a StructuredTool that returns a
`Command` updating a dedicated state key, plus a `state_schema` declaring that
key. OPPLAN is orchestrator-only — subagents keep their flat tactical
`write_todos` lead-lists (a checklist is the right shape there).

Attach to the orchestrator's middleware list only. `write_opplan` coexists with
the `write_todos` deepagents binds automatically; the OPPLAN prompt fragment
points the orchestrator at `write_opplan`, leaving `write_todos` for subagents.

NB: this module deliberately does NOT use `from __future__ import annotations`.
The inner tool functions are defined inside `opplan_middleware()` and annotated
with `ToolRuntime`/`Command` (imported in that scope). With stringized
annotations, langgraph's `get_type_hints` re-evaluates them against the module
globals — where those names don't exist — and raises `NameError: ToolRuntime`
at ToolNode build time. Real (eagerly-evaluated) annotations resolve from the
closure and sidestep that.
"""

import json
from typing import Any, Literal

from typing_extensions import TypedDict


class OpplanPhase(TypedDict):
    """One phase of the operations plan. Every field is required so a phase can
    never collapse back into a bare task string."""

    phase: str
    """Ordered stage label, e.g. RECON, FOOTHOLD, PRIVESC, LOOT."""

    intent: str
    """What this phase is trying to establish (its objective in one line)."""

    confirm_move: str
    """The single cheapest action that confirms or kills this phase's key
    assumption before you commit to it."""

    decision: str
    """The observable that advances the phase, AND the branch if it doesn't
    appear: 'if precondition false, drop to <next-ranked move>'."""

    status: Literal["pending", "active", "done", "dead"]
    """pending = not started; active = in progress; done = objective met;
    dead = precondition disproven (don't keep torturing it)."""


def _opplan_update(mission: str, phases: list[OpplanPhase], tool_call_id: str) -> dict[str, Any]:
    """Build the langgraph state update for a write_opplan call. Pure — the tool
    wraps this in a Command and the __main__ self-check exercises it directly.

    The ToolMessage content is a parseable `Updated OPPLAN ... <json>` line so the
    CLI renderer can extract the structured plan (mirrors write_todos)."""
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    payload = {"mission": mission, "phases": phases}
    return {
        "opplan": payload,
        "messages": [
            ToolMessage(f"Updated OPPLAN to {json.dumps(payload)}", tool_call_id=tool_call_id)
        ],
    }


_WRITE_OPPLAN_DESCRIPTION = """Record or update your operations plan (OPPLAN). This is the orchestrator's plan of record — use it instead of write_todos.

An OPPLAN is NOT a flat checklist. It is an ordered set of phases, each of which must state:
- `phase`: the stage label (RECON, FOOTHOLD, PRIVESC, LOOT, ...). Phases gate each other — don't start a later phase until the earlier one produced what it consumes.
- `intent`: what this phase establishes (its objective).
- `confirm_move`: the single cheapest action that confirms or kills this phase's key assumption BEFORE you commit to it.
- `decision`: the observable that advances the phase, AND the branch if it doesn't appear ("if precondition false, drop to <next move>"). A phase with no branch is a guess, not a plan.
- `status`: pending | active | done | dead. Mark a phase `dead` the moment its precondition is disproven — do not leave it pending and torture the data.

Call this once per turn (it replaces the whole plan). Keep it current as evidence lands: flip statuses, re-rank remaining phases, add phases the findings reveal."""


def opplan_middleware():
    """Return middleware that binds `write_opplan` and tracks the OPPLAN in state.

    Orchestrator-only. Mirrors TodoListMiddleware's shape so deepagents registers
    the tool (via `self.tools`) and threads the `opplan` state key (via
    `state_schema`)."""
    from typing import (
        Annotated,  # noqa: PLC0415
        NotRequired,  # noqa: PLC0415
    )

    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain.agents.middleware.types import AgentState, OmitFromInput  # noqa: PLC0415
    from langchain.tools import ToolRuntime  # noqa: PLC0415
    from langchain_core.tools import StructuredTool  # noqa: PLC0415
    from langgraph.types import Command  # noqa: PLC0415
    from pydantic import BaseModel  # noqa: PLC0415

    class OpplanState(AgentState):
        opplan: Annotated[NotRequired[dict[str, Any]], OmitFromInput]

    class WriteOpplanInput(BaseModel):
        mission: str
        phases: list[OpplanPhase]

    def _write_opplan(runtime: ToolRuntime, mission: str, phases: list[OpplanPhase]) -> Command:
        return Command(update=_opplan_update(mission, phases, runtime.tool_call_id))

    async def _awrite_opplan(
        runtime: ToolRuntime, mission: str, phases: list[OpplanPhase]
    ) -> Command:
        return _write_opplan(runtime, mission, phases)

    class OpplanMiddleware(AgentMiddleware):
        state_schema = OpplanState  # type: ignore[assignment]

        def __init__(self) -> None:
            super().__init__()
            self.tools = [
                StructuredTool.from_function(
                    name="write_opplan",
                    description=_WRITE_OPPLAN_DESCRIPTION,
                    func=_write_opplan,
                    coroutine=_awrite_opplan,
                    args_schema=WriteOpplanInput,
                    infer_schema=False,
                )
            ]

    return OpplanMiddleware()


if __name__ == "__main__":
    # Self-check: the arg schema enforces full phases, and the state update is
    # shaped right (opplan payload + a parseable ToolMessage the CLI can read).
    from pydantic import BaseModel, ValidationError

    class _Input(BaseModel):  # standalone mirror of WriteOpplanInput for the test
        mission: str
        phases: list[OpplanPhase]

    good = {
        "mission": "foothold on 10.0.0.5",
        "phases": [
            {
                "phase": "RECON",
                "intent": "map exposed services + versions",
                "confirm_move": "nmap quick then web_intake on any HTTP",
                "decision": "advance on a service+version; if thin, escalate to full TCP",
                "status": "active",
            }
        ],
    }
    _Input(**good)  # valid

    # Missing the branch/decision field → rejected by the schema (the enforcement).
    try:
        _Input(mission="x", phases=[{"phase": "RECON", "intent": "i",
                                     "confirm_move": "c", "status": "pending"}])  # type: ignore[typeddict-item]
        raise SystemExit("FAIL: incomplete phase accepted")
    except ValidationError:
        pass

    upd = _opplan_update(good["mission"], good["phases"], "call_123")
    assert upd["opplan"] == {"mission": good["mission"], "phases": good["phases"]}
    msg = upd["messages"][0]
    assert msg.tool_call_id == "call_123"
    assert msg.content.startswith("Updated OPPLAN to ")
    # CLI renderer must be able to recover the structure from the message.
    recovered = json.loads(msg.content[len("Updated OPPLAN to "):])
    assert recovered["phases"][0]["phase"] == "RECON"

    print("opplan self-check OK")
