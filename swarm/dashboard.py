from __future__ import annotations

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table


def _snippet(text: str, limit: int = 240) -> str:
    cleaned = " ".join((text or "").split())
    return cleaned[:limit] + ("..." if len(cleaned) > limit else "")


def build_dashboard(state: dict) -> Panel:
    layout = Layout()

    header = Panel(
        f"Target: {state['target']} | Platform: {state['platform']} | "
        f"Started: {state['started_at']} | Status: {state['status']}",
        title="Vader Swarm",
        border_style="cyan",
    )

    summary = Table.grid(expand=True)
    summary.add_row("Open ports", str(len(state["open_ports"])), "Credentials", str(len(state["credentials"])))
    summary.add_row("Flags", str(len(state["flags"])), "Hashes", str(len(state["hashes"])))
    summary.add_row("Shell", "yes" if state["shell_access"] else "no", "Root", "yes" if state["root_access"] else "no")

    command_panel = Panel(
        f"Next command:\n{state['next_command'] or '(waiting)'}\n\n"
        f"Last command seen:\n{state['last_command_run'] or '(none)'}",
        title="Command State",
        border_style="blue",
    )

    output_panel = Panel(
        _snippet(state.get("last_output", "")) or "(no output yet)",
        title="Last Output Snippet",
        border_style="green",
    )

    notes_panel = Panel(
        state.get("codex_notes", "") or "(no Codex notes yet)",
        title="Codex Notes",
        border_style="yellow",
    )

    flags_panel = Panel(
        "\n".join(f"- {item['value']} ({item['location']})" for item in state["flags"]) or "- None",
        title="Flags",
        border_style="red",
    )

    timeline = Table(show_header=True, expand=True)
    timeline.add_column("Latest Actions")
    for item in state["timeline"][-5:][::-1]:
        timeline.add_row(f"{item['timestamp']} | {item['agent']} | {item['action']} | {item['finding']}")
    if not state["timeline"]:
        timeline.add_row("No actions yet")

    layout.split_column(
        Layout(header, size=3),
        Layout(Panel(summary, title="Findings", border_style="magenta"), size=6),
        Layout(command_panel, size=7),
        Layout(output_panel, size=7),
        Layout(notes_panel, size=7),
        Layout(flags_panel, size=7),
        Layout(Panel(timeline, title="Timeline", border_style="white")),
    )
    return Panel(layout, border_style="white")
