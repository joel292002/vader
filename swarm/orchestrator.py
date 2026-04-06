from __future__ import annotations

import threading
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from rich.live import Live

from swarm.agents.brute_agent import BruteAgent
from swarm.agents.exploit_agent import ExploitAgent
from swarm.agents.recon_agent import ReconAgent
from swarm.agents.report_agent import ReportAgent
from swarm.agents.web_agent import WebAgent
from swarm.dashboard import build_dashboard
from swarm.findings_board import DEFAULT_STATE, FindingsBoard
from swarm.utils.logger import get_logger


class Orchestrator:
    def __init__(self, target: str, platform: str, authorization_confirmation: str) -> None:
        self.target = target
        self.platform = platform
        self.authorization_confirmation = authorization_confirmation
        self.logger = get_logger("Orchestrator")
        self.base_dir = Path(__file__).resolve().parent
        self.input_dir = self.base_dir / "input"
        self.output_dir = self.base_dir / "output"
        self.memory_dir = self.base_dir.parent / "memory"
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.board = FindingsBoard(self.base_dir / "findings.json")

    def start(self) -> Path:
        self._require_authorization()
        state = deepcopy(DEFAULT_STATE)
        state.update(
            {
                "target": self.target,
                "platform": self.platform,
                "authorized": True,
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "status": "running",
            }
        )
        self.board.save(state)

        agents = {
            "recon": ReconAgent(self.board, self.target, self.input_dir, self.memory_dir / "knowledge.md"),
            "web": WebAgent(self.board, self.target, self.input_dir, self.memory_dir / "knowledge.md"),
            "brute": BruteAgent(self.board, self.target, self.input_dir, self.memory_dir / "knowledge.md"),
            "exploit": ExploitAgent(self.board, self.target, self.input_dir, self.memory_dir / "knowledge.md"),
            "report": ReportAgent(
                self.board,
                self.target,
                self.input_dir,
                self.memory_dir / "knowledge.md",
                self.memory_dir / "soul.md",
                self.memory_dir / "patterns.json",
                self.output_dir,
            ),
        }

        threads = [
            threading.Thread(target=self._run_agent, args=(name, agent), daemon=True)
            for name, agent in agents.items()
        ]
        for thread in threads:
            thread.start()

        report_path = self.output_dir / "report.md"
        with Live(build_dashboard(self.board.load()), refresh_per_second=2, screen=False) as live:
            while True:
                state = self.board.load()
                live.update(build_dashboard(state))
                if state["status"] == "complete" and report_path.exists():
                    break
                time.sleep(2)

        for thread in threads:
            thread.join(timeout=1)
        return report_path

    def _run_agent(self, name: str, agent) -> None:
        try:
            agent.run()
        except Exception as exc:
            self.logger.error(f"{name} crashed: {exc}")
            self.board.mark_agent(name, "failed")
            self.board.add_timeline(name, "unhandled error", str(exc))

    def _require_authorization(self) -> None:
        if self.authorization_confirmation != "AUTHORIZED":
            self.board.update("status", "refused")
            raise PermissionError("Type AUTHORIZED to confirm permission to test")
