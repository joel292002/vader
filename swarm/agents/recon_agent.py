from __future__ import annotations

from typing import Any

from swarm.agents.base_agent import BaseAgent


class ReconAgent(BaseAgent):
    agent_name = "recon"
    system_prompt = """
You are a recon specialist agent in a security swarm.
Your only job is mapping the full attack surface.
Start from the evidence on the shared board and any newly dropped tool outputs.
Recommend what the human operator should run next, but do not claim to have executed it.
Add every supported port, service, banner, and version to the findings board.
Signal other agents by updating agent_triggers when the evidence justifies it.
Think like a senior pentester doing initial recon.
Only work on authorized targets.
""".strip()

    def should_engage(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> bool:
        return bool(state.get("authorized")) and (not state["open_ports"] or bool(new_inputs))
