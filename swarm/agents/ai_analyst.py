from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

from swarm.agents.base_agent import BaseAgent

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None


console = Console()

SYSTEM_PROMPT = """
You are the AI analyst for a defensive CTF coordination swarm.

You do not execute tools. You only interpret operator-supplied tool outputs and recommend next steps.

Return strict JSON with this schema:
{
  "what_i_found": ["short bullet", "..."],
  "next_actions": [
    {"priority": 1, "action": "exact command or check", "why": "brief reason"}
  ],
  "reasoning": "short paragraph",
  "memory_applied": "short paragraph",
  "visible_credentials": [
    {"username": "user", "password": "pass", "source": "where seen"}
  ],
  "visible_flags": [
    {"value": "flag", "location": "where seen"}
  ],
  "patterns_seen_before": ["short note"]
}

Focus on:
- what the finding means
- the highest priority next human action
- exact tool names and exact flags when recommending tools
- any credentials, hashes, URLs, or flags visible in the evidence
- whether prior memory suggests a proven follow-up
""".strip()


class AIAnalyst(BaseAgent):
    agent_name = "analyst"

    def __init__(
        self,
        findings_board,
        target: str,
        input_dir: Path,
        knowledge_path: Path,
        model: str = "gpt-4o",
        poll_interval: int = 5,
    ) -> None:
        super().__init__(findings_board, target)
        self.input_dir = input_dir
        self.knowledge_path = knowledge_path
        self.model = model
        self.poll_interval = poll_interval
        self.seen_files: dict[str, float] = {}
        self.client = OpenAI() if OpenAI is not None and os.getenv("OPENAI_API_KEY") else None

    def run(self) -> None:
        self.findings_board.mark_agent(self.agent_name, "watching")
        self.log("AI analyst is ready for orchestrator-triggered reviews")

    def analyze_pending_inputs(self) -> int:
        changed_files = self._scan_for_changes()
        if not changed_files:
            return 0
        self.findings_board.mark_agent(self.agent_name, "running")
        for file_path in changed_files:
            self._analyze_file(file_path)
        self.findings_board.mark_agent(self.agent_name, "watching")
        return len(changed_files)

    def _scan_for_changes(self) -> list[Path]:
        changed: list[Path] = []
        for path in sorted(self.input_dir.glob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            mtime = path.stat().st_mtime
            key = str(path)
            if self.seen_files.get(key) != mtime:
                self.seen_files[key] = mtime
                changed.append(path)
        return changed

    def _analyze_file(self, file_path: Path) -> None:
        self.log(f"Analyzing {file_path.name}")
        evidence = file_path.read_text(encoding="utf-8", errors="replace")
        board_state = self.findings_board.load()
        knowledge = self.knowledge_path.read_text(encoding="utf-8") if self.knowledge_path.exists() else ""

        analysis = self._generate_analysis(file_path.name, evidence, board_state, knowledge)
        recommendation = {
            "file": file_path.name,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            **analysis,
        }
        self.findings_board.add_analyst_recommendation(recommendation)
        self._apply_visible_artifacts(analysis, file_path.name)
        self.findings_board.add_log(self.agent_name, f"Assessment completed for {file_path.name}")
        console.print(self._render_panel(analysis))

    def _generate_analysis(
        self,
        file_name: str,
        evidence: str,
        board_state: dict[str, Any],
        knowledge: str,
    ) -> dict[str, Any]:
        extracted = self._extract_visible_artifacts(evidence, file_name)
        if self.client is None:
            return self._fallback_analysis(file_name, evidence, board_state, knowledge, extracted)

        payload = {
            "target": self.target,
            "file_name": file_name,
            "evidence": evidence[-12000:],
            "findings_board": board_state,
            "knowledge": knowledge[-12000:],
        }
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload)},
                ],
            )
            content = response.choices[0].message.content or "{}"
            parsed = json.loads(content)
        except Exception as exc:
            self.log(f"OpenAI analysis failed for {file_name}: {exc}")
            return self._fallback_analysis(file_name, evidence, board_state, knowledge, extracted)

        parsed.setdefault("what_i_found", [])
        parsed.setdefault("next_actions", [])
        parsed.setdefault("reasoning", "No reasoning returned.")
        parsed.setdefault("memory_applied", "No memory applied.")
        parsed.setdefault("visible_credentials", extracted["credentials"])
        parsed.setdefault("visible_flags", extracted["flags"])
        parsed.setdefault("patterns_seen_before", [])
        return parsed

    def _fallback_analysis(
        self,
        file_name: str,
        evidence: str,
        board_state: dict[str, Any],
        knowledge: str,
        extracted: dict[str, Any],
    ) -> dict[str, Any]:
        open_ports = board_state["findings"]["open_ports"]
        evidence_lines = [line.strip() for line in evidence.splitlines() if line.strip()]
        first_line = evidence_lines[0] if evidence_lines else f"No content in {file_name}"
        what_i_found = [f"Imported evidence from {file_name}", first_line[:120]]
        next_actions = []

        if any(item["port"] in {80, 443, 8080, 8443} for item in open_ports):
            next_actions.append(
                {
                    "priority": 1,
                    "action": "whatweb http://TARGET:PORT && nikto -h http://TARGET:PORT",
                    "why": "Web ports are present and should be fingerprinted and reviewed.",
                }
            )
        if "apache 2.4.49" in evidence.lower():
            next_actions.insert(
                0,
                {
                    "priority": 1,
                    "action": "curl -i http://TARGET/cgi-bin/ && searchsploit Apache 2.4.49",
                    "why": "Apache 2.4.49 warrants targeted review of known traversal-related exposure.",
                },
            )
        if not next_actions:
            next_actions.append(
                {
                    "priority": 1,
                    "action": "Review the imported output manually and decide the next enumeration step",
                    "why": "No stronger pattern was recognized locally.",
                }
            )

        memory_hits = []
        lowered_knowledge = knowledge.lower()
        for needle in ("git", "dbcreate.sql", "wordpress", "apache 2.4.49", "ftp", "ssh"):
            if needle in evidence.lower() and needle in lowered_knowledge:
                memory_hits.append(f"Previous notes mention {needle}")

        return {
            "what_i_found": what_i_found,
            "next_actions": next_actions,
            "reasoning": "Fallback reasoning was used because the OpenAI client was unavailable or returned an error.",
            "memory_applied": "; ".join(memory_hits) if memory_hits else "No direct prior pattern match found in memory.",
            "visible_credentials": extracted["credentials"],
            "visible_flags": extracted["flags"],
            "patterns_seen_before": memory_hits,
        }

    def _extract_visible_artifacts(self, evidence: str, file_name: str) -> dict[str, Any]:
        credentials = []
        for user, password in re.findall(r"([A-Za-z0-9_.-]{2,}):([^\s:]{2,})", evidence):
            credentials.append({"username": user, "password": password, "source": file_name})

        flags = []
        for flag in re.findall(r"(flag\{[^}]+\}|THM\{[^}]+\}|HTB\{[^}]+\}|user\.txt|root\.txt)", evidence, flags=re.IGNORECASE):
            flags.append({"value": flag, "location": file_name})

        return {"credentials": credentials[:20], "flags": flags[:20]}

    def _apply_visible_artifacts(self, analysis: dict[str, Any], file_name: str) -> None:
        for item in analysis.get("visible_credentials", []):
            self.findings_board.add_credential(
                item.get("username", ""),
                item.get("password", ""),
                item.get("source", file_name),
            )
        for item in analysis.get("visible_flags", []):
            self.findings_board.add_flag(item.get("value", ""), item.get("location", file_name))

    def _render_panel(self, analysis: dict[str, Any]) -> Panel:
        found = "\n".join(f"- {item}" for item in analysis.get("what_i_found", [])) or "- None"
        actions = "\n".join(
            f"{item.get('priority', index + 1)}. {item.get('action', '')}"
            for index, item in enumerate(analysis.get("next_actions", []))
        ) or "1. None"
        reasoning = analysis.get("reasoning", "No reasoning provided.")
        memory_applied = analysis.get("memory_applied", "No memory applied.")
        body = (
            "WHAT I FOUND:\n"
            f"{found}\n\n"
            "NEXT ACTIONS (priority order):\n"
            f"{actions}\n\n"
            "REASONING:\n"
            f"{reasoning}\n\n"
            "MEMORY APPLIED:\n"
            f"{memory_applied}"
        )
        return Panel(body, title="AI Analyst Assessment", border_style="cyan")
