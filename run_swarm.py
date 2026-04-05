from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from swarm.agents.ai_security_agent import AISecurityAgent, save_report
from swarm.tools.kali_tools import list_available_tools
from swarm.utils.logger import get_logger


console = Console()
logger = get_logger("RunSwarm")


def main() -> None:
    target = input("Target IP/host: ").strip()
    available_tools = list_available_tools()

    console.print(
        Panel.fit(
            "\n".join(available_tools) if available_tools else "No supported Kali tools found.",
            title="Available Kali Tools",
            border_style="cyan",
        )
    )

    if not available_tools:
        logger.error("Cannot start AI agent because no supported Kali tools are installed.")
        return

    agent = AISecurityAgent(model="gpt-4o")
    report_markdown = agent.run(target)
    report_path = save_report(target, report_markdown)

    logger.success(f"Final report saved to {report_path}")
    console.print(
        Panel.fit(
            f"Assessment complete.\nReport: {report_path}",
            title="ReconSwarm",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()
