from __future__ import annotations

import hashlib
import json
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from swarm.findings_board import FindingsBoard
from swarm.utils.logger import get_logger

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None


class BaseAgent(ABC):
    agent_name = "base"
    system_prompt = ""

    def __init__(
        self,
        findings_board: FindingsBoard,
        target: str,
        input_dir: Path,
        knowledge_path: Path,
        model: str = "gpt-4o",
        poll_interval: int = 3,
    ) -> None:
        self.findings_board = findings_board
        self.target = target
        self.input_dir = input_dir
        self.knowledge_path = knowledge_path
        self.model = model
        self.poll_interval = poll_interval
        self.logger = get_logger(self.__class__.__name__)
        self.client = OpenAI() if OpenAI is not None and os.getenv("OPENAI_API_KEY") else None
        self.seen_files: dict[str, float] = {}
        self.last_fingerprint = ""
        self.last_analysis_at = 0.0

    def run(self) -> None:
        self.findings_board.mark_agent(self.agent_name, "starting")
        self.log("Agent thread started")
        try:
            while True:
                state = self.findings_board.load()
                if state["status"] == "complete":
                    self.findings_board.mark_agent(self.agent_name, "complete")
                    break
                new_inputs = self._collect_new_inputs()
                if not self.should_engage(state, new_inputs):
                    self.findings_board.mark_agent(self.agent_name, "waiting")
                    time.sleep(self.poll_interval)
                    continue

                fingerprint = self._build_fingerprint(state, new_inputs)
                if fingerprint == self.last_fingerprint and not new_inputs:
                    time.sleep(self.poll_interval)
                    continue

                self.findings_board.mark_agent(self.agent_name, "thinking")
                analysis = self._reason(state, new_inputs)
                self._apply_analysis(analysis)
                self.last_fingerprint = fingerprint
                self.last_analysis_at = time.monotonic()
                if analysis.get("done"):
                    self.findings_board.mark_agent(self.agent_name, "complete")
                    self.findings_board.add_timeline(
                        self.agent_name,
                        "marked complete",
                        analysis.get("reasoning", "")[:160],
                    )
                    break
                self.findings_board.mark_agent(
                    self.agent_name,
                    analysis.get("status", "waiting"),
                )
                time.sleep(self.poll_interval)
        except Exception as exc:
            self.findings_board.mark_agent(self.agent_name, "failed")
            self.findings_board.add_timeline(self.agent_name, "failed", str(exc))
            self.logger.error(f"{self.agent_name} failed: {exc}")

    @abstractmethod
    def should_engage(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> bool:
        raise NotImplementedError

    def log(self, message: str) -> None:
        self.logger.info(message)
        self.findings_board.add_timeline(self.agent_name, message, "")

    def _collect_new_inputs(self) -> list[dict[str, str]]:
        new_inputs: list[dict[str, str]] = []
        for path in sorted(self.input_dir.glob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            mtime = path.stat().st_mtime
            key = str(path)
            if self.seen_files.get(key) == mtime:
                continue
            self.seen_files[key] = mtime
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                content = f"Unable to read file: {exc}"
            new_inputs.append({"file": path.name, "content": content[-12000:]})
        return new_inputs

    def _build_fingerprint(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> str:
        payload = {
            "state": state,
            "new_inputs": new_inputs,
            "agent": self.agent_name,
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _reason(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> dict[str, Any]:
        knowledge = (
            self.knowledge_path.read_text(encoding="utf-8")[-12000:]
            if self.knowledge_path.exists()
            else ""
        )
        payload = {
            "target": self.target,
            "agent_name": self.agent_name,
            "findings_board": state,
            "memory": knowledge,
            "new_tool_output": new_inputs,
            "operator_model": (
                "Recommend exact commands for a human operator. Do not claim to have run them."
            ),
        }
        if self.client is None:
            return self._fallback_analysis(state, new_inputs)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": self.system_prompt + self._json_contract()},
                    {"role": "user", "content": json.dumps(payload)},
                ],
            )
            content = response.choices[0].message.content or "{}"
            parsed = json.loads(content)
        except Exception as exc:
            self.logger.warning(f"{self.agent_name} falling back after OpenAI error: {exc}")
            return self._fallback_analysis(state, new_inputs)

        return self._normalize_analysis(parsed)

    def _json_contract(self) -> str:
        return """

Return strict JSON with:
{
  "reasoning": "short explanation",
  "status": "waiting|thinking|running|complete",
  "next_command": "exact recommended command for the human operator, or empty string",
  "action_summary": "short operator-facing summary",
  "done": false,
  "findings_to_add": {
    "open_ports": [{"port": 80, "service": "http", "banner": "", "version": ""}],
    "credentials": [{"username": "user", "password": "pass", "source": "file", "tried_on": []}],
    "flags": [{"value": "flag", "location": "file", "verified": false}],
    "hashes": [{"value": "hash", "type": "md5", "cracked": false, "plaintext": ""}],
    "urls": ["http://target"],
    "interesting_files": ["/var/www/html/.env"],
    "shell_access": false,
    "root_access": false,
    "agent_triggers": {"web": false, "brute": false, "exploit": false}
  }
}
Only include findings directly supported by the provided inputs or board state.
""".strip()

    def _normalize_analysis(self, analysis: dict[str, Any]) -> dict[str, Any]:
        findings = analysis.get("findings_to_add", {})
        findings.setdefault("open_ports", [])
        findings.setdefault("credentials", [])
        findings.setdefault("flags", [])
        findings.setdefault("hashes", [])
        findings.setdefault("urls", [])
        findings.setdefault("interesting_files", [])
        findings.setdefault("agent_triggers", {})
        return {
            "reasoning": analysis.get("reasoning", ""),
            "status": analysis.get("status", "waiting"),
            "next_command": analysis.get("next_command", ""),
            "action_summary": analysis.get("action_summary", ""),
            "done": bool(analysis.get("done", False)),
            "findings_to_add": findings,
        }

    def _fallback_analysis(self, state: dict[str, Any], new_inputs: list[dict[str, str]]) -> dict[str, Any]:
        summary = (
            f"{len(new_inputs)} new input file(s) available for {self.agent_name} review"
            if new_inputs
            else f"{self.agent_name} is waiting for more evidence"
        )
        return {
            "reasoning": "OpenAI client unavailable. Manual operator review is required.",
            "status": "waiting",
            "next_command": "",
            "action_summary": summary,
            "done": False,
            "findings_to_add": {
                "open_ports": [],
                "credentials": [],
                "flags": [],
                "hashes": [],
                "urls": [],
                "interesting_files": [],
                "agent_triggers": {},
            },
        }

    def _apply_analysis(self, analysis: dict[str, Any]) -> None:
        reasoning = analysis.get("reasoning", "")
        next_command = analysis.get("next_command", "")
        self.findings_board.set_agent_reasoning(self.agent_name, reasoning)
        self.findings_board.set_agent_recommendation(
            self.agent_name,
            {
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "next_command": next_command,
                "action_summary": analysis.get("action_summary", ""),
                "status": analysis.get("status", "waiting"),
            },
        )
        findings = analysis.get("findings_to_add", {})
        for item in findings.get("open_ports", []):
            self.findings_board.add_port(
                int(item.get("port", 0)),
                str(item.get("service", "")),
                str(item.get("banner", "")),
                str(item.get("version", "")),
            )
        for item in findings.get("credentials", []):
            self.findings_board.add_credential(
                str(item.get("username", "")),
                str(item.get("password", "")),
                str(item.get("source", self.agent_name)),
                list(item.get("tried_on", [])),
            )
        for item in findings.get("flags", []):
            self.findings_board.add_flag(
                str(item.get("value", "")),
                str(item.get("location", self.agent_name)),
                bool(item.get("verified", False)),
            )
        for item in findings.get("hashes", []):
            self.findings_board.add_hash(
                str(item.get("value", "")),
                str(item.get("type", "")),
                bool(item.get("cracked", False)),
                str(item.get("plaintext", "")),
            )
        for url in findings.get("urls", []):
            self.findings_board.add_url(str(url))
        for path in findings.get("interesting_files", []):
            self.findings_board.add_interesting_file(str(path))
        if "shell_access" in findings:
            self.findings_board.update("shell_access", bool(findings["shell_access"]))
        if "root_access" in findings:
            self.findings_board.update("root_access", bool(findings["root_access"]))
        if findings.get("agent_triggers"):
            self.findings_board.merge_triggers(findings["agent_triggers"])
        action_summary = analysis.get("action_summary", "")
        timeline_finding = next_command or reasoning[:160]
        self.findings_board.add_timeline(
            self.agent_name,
            action_summary or "updated recommendation",
            timeline_finding,
        )
