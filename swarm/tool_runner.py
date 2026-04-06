from __future__ import annotations

import time
from pathlib import Path

from swarm.findings_board import FindingsBoard
from swarm.utils.logger import get_logger


class ToolRunner:
    def __init__(self, base_dir: Path, findings_board: FindingsBoard, poll_interval: int = 2) -> None:
        self.base_dir = base_dir
        self.findings_board = findings_board
        self.poll_interval = poll_interval
        self.logger = get_logger("ToolRunner")
        self.next_command_path = self.base_dir / "next_command.txt"
        self.latest_output_path = self.base_dir / "input" / "latest.txt"
        self.next_command_path.parent.mkdir(parents=True, exist_ok=True)
        self.latest_output_path.parent.mkdir(parents=True, exist_ok=True)
        self.next_command_path.touch(exist_ok=True)
        self.latest_output_path.touch(exist_ok=True)
        self.last_command = ""
        self.last_command_mtime = 0.0
        self.last_output_mtime = 0.0

    def run(self) -> None:
        self.findings_board.add_timeline("tool_runner", "started", "Passive coordination mode")
        while True:
            state = self.findings_board.load()
            if state["status"] == "complete":
                self.findings_board.add_timeline("tool_runner", "stopped", "Session complete")
                return
            try:
                self._check_next_command()
                self._check_latest_output()
            except Exception as exc:
                self.logger.error(f"tool runner loop error: {exc}")
                self.findings_board.add_timeline("tool_runner", "error", str(exc))
            time.sleep(self.poll_interval)

    def _check_next_command(self) -> None:
        mtime = self.next_command_path.stat().st_mtime
        if mtime == self.last_command_mtime:
            return
        self.last_command_mtime = mtime
        command = self.next_command_path.read_text(encoding="utf-8").strip()
        if not command:
            return
        if command == self.last_command:
            self.findings_board.add_timeline("tool_runner", "duplicate command ignored", command)
            return
        self.last_command = command
        self.findings_board.update("next_command", command)
        self.findings_board.update("last_command_run", command)
        self.findings_board.append_raw_output(
            command=command,
            output="Pending operator execution. Paste tool output into swarm/input/latest.txt",
            source="next_command.txt",
        )
        self.findings_board.add_timeline(
            "tool_runner",
            "command queued",
            command,
        )
        self.logger.info(f"Queued command for operator execution: {command}")

    def _check_latest_output(self) -> None:
        mtime = self.latest_output_path.stat().st_mtime
        if mtime == self.last_output_mtime:
            return
        self.last_output_mtime = mtime
        output = self.latest_output_path.read_text(encoding="utf-8", errors="replace").strip()
        if not output:
            return
        command = self.findings_board.load().get("last_command_run", "")
        self.findings_board.append_raw_output(command=command, output=output, source="input/latest.txt")
        self.findings_board.add_timeline(
            "tool_runner",
            "output captured",
            output[:160],
        )
        self.logger.info("Captured updated operator-supplied output from swarm/input/latest.txt")
