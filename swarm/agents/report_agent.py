from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from swarm.agents.base_agent import BaseAgent


class ReportAgent(BaseAgent):
    agent_name = "report"
    system_prompt = """
You watch all agents and build the assessment story.
When the assessment is complete, write a full markdown report, update knowledge.md, soul.md, and patterns.json.
Base everything on the shared findings board and timeline.
Do not invent evidence. Summarize operator-provided outputs and agent recommendations.
""".strip()

    def __init__(
        self,
        findings_board,
        target: str,
        input_dir: Path,
        knowledge_path: Path,
        soul_path: Path,
        patterns_path: Path,
        output_dir: Path,
        model: str = "gpt-4o",
        poll_interval: int = 3,
    ) -> None:
        super().__init__(findings_board, target, input_dir, knowledge_path, model, poll_interval)
        self.soul_path = soul_path
        self.patterns_path = patterns_path
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_path = self.output_dir / "report.md"

    def should_engage(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> bool:
        statuses = state["agent_status"]
        non_report = [statuses[name] for name in ("recon", "web", "brute", "exploit")]
        all_flags_found = any(item["value"] == "root.txt" for item in state["flags"]) and any(
            item["value"] == "user.txt" for item in state["flags"]
        )
        return all(status in {"complete", "failed"} for status in non_report) or all_flags_found

    def _reason(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> dict[str, Any]:
        analysis = super()._reason(state, new_inputs)
        if self.client is None:
            analysis["report_markdown"] = self._fallback_report(state)
            analysis["knowledge_append"] = self._fallback_knowledge_update(state)
            analysis["soul_append"] = self._fallback_soul_update(state)
            analysis["patterns_update"] = self._fallback_patterns_update(state)
            analysis["done"] = True
            return analysis

        payload = {
            "findings_board": state,
            "report_path": str(self.report_path),
        }
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": self.system_prompt
                        + """

Return strict JSON:
{
  "reasoning": "...",
  "status": "complete",
  "next_command": "",
  "action_summary": "report generated",
  "done": true,
  "findings_to_add": {"open_ports": [], "credentials": [], "flags": [], "hashes": [], "urls": [], "interesting_files": [], "agent_triggers": {}},
  "report_markdown": "# Report...",
  "knowledge_append": "- lesson",
  "soul_append": "- assessment entry",
  "patterns_update": {"port_patterns": {}, "service_patterns": {}, "tool_wins": {}, "common_credentials": [], "ctf_patterns": {"tryhackme": [], "hackthebox": []}, "total_assessments": 0, "last_updated": "YYYY-MM-DD"}
}
""".strip(),
                    },
                    {"role": "user", "content": json.dumps(payload)},
                ],
            )
            parsed = json.loads(response.choices[0].message.content or "{}")
            normalized = self._normalize_analysis(parsed)
            normalized["report_markdown"] = parsed.get("report_markdown", self._fallback_report(state))
            normalized["knowledge_append"] = parsed.get("knowledge_append", self._fallback_knowledge_update(state))
            normalized["soul_append"] = parsed.get("soul_append", self._fallback_soul_update(state))
            normalized["patterns_update"] = parsed.get("patterns_update", self._fallback_patterns_update(state))
            normalized["done"] = True
            normalized["status"] = "complete"
            return normalized
        except Exception:
            analysis["report_markdown"] = self._fallback_report(state)
            analysis["knowledge_append"] = self._fallback_knowledge_update(state)
            analysis["soul_append"] = self._fallback_soul_update(state)
            analysis["patterns_update"] = self._fallback_patterns_update(state)
            analysis["done"] = True
            analysis["status"] = "complete"
            return analysis

    def _apply_analysis(self, analysis: dict[str, Any]) -> None:
        super()._apply_analysis(analysis)
        self.report_path.write_text(analysis["report_markdown"], encoding="utf-8")
        self._append_unique_line(self.knowledge_path, analysis["knowledge_append"])
        self._append_unique_line(self.soul_path, analysis["soul_append"])
        self.patterns_path.write_text(
            json.dumps(analysis["patterns_update"], indent=2),
            encoding="utf-8",
        )
        self.findings_board.update("status", "complete")

    def _append_unique_line(self, path: Path, line: str) -> None:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if line not in existing:
            separator = "" if not existing or existing.endswith("\n") else "\n"
            path.write_text(existing + separator + line + "\n", encoding="utf-8")

    def _fallback_report(self, state: dict[str, Any]) -> str:
        ports = ", ".join(f"{item['port']}/{item['service']}" for item in state["open_ports"]) or "None"
        creds = "\n".join(
            f"- `{item['username']}` / `{item['password']}` from {item['source']}"
            for item in state["credentials"]
        ) or "- None"
        flags = "\n".join(
            f"- `{item['value']}` at {item['location']} verified={item['verified']}"
            for item in state["flags"]
        ) or "- None"
        timeline = "\n".join(
            f"- {item['timestamp']} | {item['agent']} | {item['action']} | {item['finding']}"
            for item in state["timeline"][-50:]
        ) or "- None"
        return f"""# Swarm Report

## Scope
- Target: `{state['target']}`
- Platform: `{state['platform']}`
- Authorized: `{state['authorized']}`
- Started: `{state['started_at']}`

## Findings
- Open ports: {ports}
- Shell access: `{state['shell_access']}`
- Root access: `{state['root_access']}`

### Credentials
{creds}

### Flags
{flags}

## Timeline
{timeline}

## Notes
- This report summarizes operator-supplied tool output and AI agent recommendations.
- Commands were recommended, not executed autonomously by the swarm.
"""

    def _fallback_knowledge_update(self, state: dict[str, Any]) -> str:
        return (
            f"- {datetime.now().strftime('%Y-%m-%d')} | {state['target']} | "
            f"AI advisory swarm captured {len(state['open_ports'])} ports, "
            f"{len(state['credentials'])} credentials, {len(state['flags'])} flags"
        )

    def _fallback_soul_update(self, state: dict[str, Any]) -> str:
        return (
            f"- {datetime.now().strftime('%Y-%m-%d')}: advisory swarm session for "
            f"{state['target']} on {state['platform']}"
        )

    def _fallback_patterns_update(self, state: dict[str, Any]) -> dict[str, Any]:
        current = json.loads(self.patterns_path.read_text(encoding="utf-8")) if self.patterns_path.exists() else {}
        port_patterns = current.get("port_patterns", {})
        service_patterns = current.get("service_patterns", {})
        common_credentials = current.get("common_credentials", [])
        for port in state["open_ports"]:
            port_key = str(port["port"])
            port_patterns[port_key] = port_patterns.get(port_key, 0) + 1
            service_key = port.get("service", "")
            if service_key:
                service_patterns[service_key] = service_patterns.get(service_key, 0) + 1
        for cred in state["credentials"]:
            pair = f"{cred['username']}:{cred['password']}"
            if pair not in common_credentials:
                common_credentials.append(pair)
        return {
            "port_patterns": port_patterns,
            "service_patterns": service_patterns,
            "tool_wins": current.get("tool_wins", {}),
            "common_credentials": common_credentials,
            "ctf_patterns": current.get("ctf_patterns", {"tryhackme": [], "hackthebox": []}),
            "total_assessments": int(current.get("total_assessments", 0)) + 1,
            "last_updated": datetime.now().strftime("%Y-%m-%d"),
        }
