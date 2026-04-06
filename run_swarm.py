from __future__ import annotations

import threading
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel

from swarm.dashboard import build_dashboard
from swarm.findings_board import DEFAULT_STATE, FindingsBoard
from swarm.tool_runner import ToolRunner
from swarm.utils.logger import get_logger


console = Console()
logger = get_logger("RunSwarm")
BASE_DIR = Path(__file__).resolve().parent
SWARM_DIR = BASE_DIR / "swarm"
MEMORY_DIR = BASE_DIR / "memory"


def _memory_summary() -> str:
    soul_path = MEMORY_DIR / "soul.md"
    if not soul_path.exists():
        return "(missing)"
    lines = soul_path.read_text(encoding="utf-8").splitlines()
    return "\n".join(lines[:12]) or "(empty)"


def _initialize_state(target: str, platform: str) -> dict:
    state = deepcopy(DEFAULT_STATE)
    state.update(
        {
            "target": target,
            "platform": platform,
            "authorized": True,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "status": "running",
        }
    )
    return state


def main() -> None:
    console.print(Panel.fit(_memory_summary(), title="Soul Memory", border_style="cyan"))
    target = input("Target IP/host: ").strip()
    platform = input("Platform: ").strip() or "Other"
    authorization = input("Type AUTHORIZED to confirm permission to test: ").strip()

    if authorization != "AUTHORIZED":
        message = "Type AUTHORIZED to confirm permission to test"
        logger.error(message)
        console.print(Panel.fit(message, title="Authorization Required", border_style="red"))
        return

    findings_board = FindingsBoard(SWARM_DIR / "findings.json")
    findings_board.save(_initialize_state(target, platform))
    findings_board.add_timeline("run_swarm", "session initialized", target)

    tool_runner = ToolRunner(SWARM_DIR, findings_board)
    runner_thread = threading.Thread(target=tool_runner.run, daemon=True)
    runner_thread.start()

    instructions = "\n".join(
        [
            "=== CODEX YOUR TURN ===",
            "1. cat ~/vader/swarm/findings.json",
            "2. cat ~/vader/memory/knowledge.md",
            "3. Reason about the target",
            "4. Write first command to next_command.txt",
            "5. Read output from swarm/input/latest.txt",
            "6. Keep going until all flags found",
        ]
    )
    console.print(Panel.fit(instructions, title="Workflow", border_style="green"))

    with Live(build_dashboard(findings_board.load()), refresh_per_second=2, screen=False) as live:
        try:
            while True:
                state = findings_board.load()
                live.update(build_dashboard(state))
                report_path = SWARM_DIR / "output" / "report.md"
                if state["status"] == "complete" or report_path.exists():
                    break
                time.sleep(2)
        except KeyboardInterrupt:
            findings_board.update("status", "stopped")
            findings_board.add_timeline("run_swarm", "session stopped", "KeyboardInterrupt")

    runner_thread.join(timeout=1)
    console.print(Panel.fit("Swarm coordination stopped.", title="Complete", border_style="blue"))


if __name__ == "__main__":
    main()
