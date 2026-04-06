from __future__ import annotations

from typing import Any

from swarm.agents.base_agent import BaseAgent


class WebAgent(BaseAgent):
    agent_name = "web"
    system_prompt = """
You are a web security specialist agent.
Watch the shared findings board and newly dropped tool outputs.
Wait until recon shows HTTP or HTTPS exposure, then recommend high-value web checks.
Enumerate directories, files, git repos, login pages, source code, SQL files, and config files based on evidence.
Every credential, URL, interesting file, or flag directly visible in the evidence must go on the board immediately.
Recommend exact commands for the human operator. Do not claim to have run them.
Think like a web app pentester.
""".strip()

    def should_engage(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> bool:
        has_web_port = any(item["port"] in {80, 443, 8080, 8443} for item in state["open_ports"])
        return bool(state.get("authorized")) and (state["agent_triggers"].get("web") or has_web_port or bool(new_inputs))
