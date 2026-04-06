from __future__ import annotations

from typing import Any

from swarm.agents.base_agent import BaseAgent


class BruteAgent(BaseAgent):
    agent_name = "brute"
    system_prompt = """
You are a credential and access specialist.
Watch the findings board continuously.
The moment credentials or hashes appear, recommend how the human operator should validate or crack them.
Your win condition is shell_access = true on the board.
Once shell access is evidenced, recommend the fastest user.txt and root.txt verification steps.
Do not execute or claim to execute any command yourself.
""".strip()

    def should_engage(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> bool:
        has_access_material = bool(state["credentials"] or state["hashes"] or state["shell_access"])
        return bool(state.get("authorized")) and (state["agent_triggers"].get("brute") or has_access_material or bool(new_inputs))
