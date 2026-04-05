from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
MEMORY_DIR = ROOT_DIR / "memory"
OUTPUT_DIR = ROOT_DIR / "swarm" / "output"
SOUL_PATH = MEMORY_DIR / "soul.md"
KNOWLEDGE_PATH = MEMORY_DIR / "knowledge.md"
PATTERNS_PATH = MEMORY_DIR / "patterns.json"


@dataclass
class ReportInsights:
    target: str
    open_ports: list[int]
    services: list[str]
    tools_used: list[str]
    vulnerabilities: list[str]
    credentials: list[str]
    dead_ends: list[str]
    winning_moves: list[str]


def _latest_report_path() -> Path:
    reports = sorted(OUTPUT_DIR.glob("report_*.md"), key=lambda path: path.stat().st_mtime)
    if not reports:
        raise FileNotFoundError("No report markdown files found in swarm/output/.")
    return reports[-1]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def _extract_target(report_text: str, report_path: Path) -> str:
    scope_match = re.search(r"- Target:\s*`?([^\n`]+)`?", report_text)
    if scope_match:
        return scope_match.group(1).strip()

    name_match = re.match(r"report_(.+)\.md$", report_path.name)
    return name_match.group(1) if name_match else "unknown"


def _extract_ports(report_text: str) -> list[int]:
    ports = {int(match) for match in re.findall(r"\b(\d{1,5})/tcp\b", report_text)}
    ports.update(int(match) for match in re.findall(r"\bport `?(\d{1,5})`?\b", report_text, flags=re.IGNORECASE))
    return sorted(port for port in ports if 0 < port <= 65535)


def _extract_services(report_text: str) -> list[str]:
    services = set(re.findall(r"\|\s+\d+/tcp\s+open\s+\S+\s+([A-Za-z0-9._ -]+)", report_text))
    services.update(re.findall(r"- Service:\s*`([^`]+)`", report_text))
    cleaned = {" ".join(service.split()) for service in services if service.strip()}
    return sorted(cleaned)


def _extract_tools(report_text: str) -> list[str]:
    tools = re.findall(r"`([a-z0-9_-]+)(?:\s+[^`]*)?`", report_text)
    known_tools = {
        "nmap",
        "nikto",
        "whatweb",
        "gobuster",
        "searchsploit",
        "sslscan",
        "dnsenum",
        "nuclei",
        "wpscan",
    }
    return sorted({tool for tool in tools if tool in known_tools})


def _extract_vulnerabilities(report_text: str) -> list[str]:
    cves = set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", report_text))
    vuln_lines = re.findall(r"###\s+\d+\.\s+([^\n]+)", report_text)
    for line in vuln_lines:
        if any(token in line.lower() for token in ("vulnerab", "exposed", "exploit", "ssh", "tls", "credential")):
            cves.add(line.strip())
    return sorted(cves)


def _extract_credentials(report_text: str) -> list[str]:
    creds = set()
    in_credentials_section = False
    for line in report_text.splitlines():
        stripped = line.strip("- ").strip()
        if not stripped:
            if in_credentials_section:
                continue
            continue

        if line.startswith("## "):
            in_credentials_section = False
        elif line.strip() == "Recovered credentials:" or line.strip() == "Historical credential from Git history:":
            in_credentials_section = True
            continue

        if in_credentials_section:
            if re.match(r"`?[^`\s]+`?\s*:\s*`?[^`\s]+`?$", stripped):
                creds.add(stripped.replace("`", ""))
            continue

        lower_line = stripped.lower()
        if not any(token in lower_line for token in ("credential", "creds", "password", "username")):
            continue
        if any(
            token in lower_line
            for token in (
                "no credentialed validation",
                "disable password authentication",
                "password attacks",
                "credential policy",
                "credentials that have worked",
            )
        ):
            continue

        if ":" in stripped and any(token in lower_line for token in ("username", "password", "credential", "creds")):
            creds.add(stripped)
        elif re.search(r"\b[a-z0-9._-]+:[^\s]+\b", stripped, flags=re.IGNORECASE):
            creds.add(stripped)
    return sorted(creds)


def _extract_dead_ends(report_text: str) -> list[str]:
    dead_ends = set()
    in_dead_end_section = False
    for line in report_text.splitlines():
        if line.startswith("## "):
            in_dead_end_section = False
        if line.strip().lower() == "### dead ends":
            in_dead_end_section = True
            continue

        if in_dead_end_section and re.match(r"\d+\.\s+", line.strip()):
            dead_ends.add(line.strip())
            continue

        lower_line = line.lower()
        if any(token in lower_line for token in ("no results", "no open", "no evidence", "dead end", "pointless", "no common")):
            stripped = line.strip("- ").strip()
            if stripped:
                dead_ends.add(stripped)
    return sorted(dead_ends)


def _extract_winning_moves(report_text: str) -> list[str]:
    winners = set()
    methodology_section = False
    in_effective_moves = False
    for line in report_text.splitlines():
        if line.startswith("## Methodology"):
            methodology_section = True
            continue
        if methodology_section and line.startswith("## "):
            methodology_section = False
        if methodology_section and re.match(r"\d+\.\s+", line.strip()):
            winners.add(line.strip())

        if line.startswith("## "):
            in_effective_moves = False
        if line.strip().lower() == "### effective moves":
            in_effective_moves = True
            continue
        if in_effective_moves and re.match(r"\d+\.\s+", line.strip()):
            winners.add(line.strip())

    for line in report_text.splitlines():
        lower_line = line.lower()
        if "highest-value" in lower_line or "best remaining gap" in lower_line or "smart move" in lower_line:
            winners.add(line.strip())

    return sorted(winners)


def extract_insights(report_text: str, report_path: Path) -> ReportInsights:
    return ReportInsights(
        target=_extract_target(report_text, report_path),
        open_ports=_extract_ports(report_text),
        services=_extract_services(report_text),
        tools_used=_extract_tools(report_text),
        vulnerabilities=_extract_vulnerabilities(report_text),
        credentials=_extract_credentials(report_text),
        dead_ends=_extract_dead_ends(report_text),
        winning_moves=_extract_winning_moves(report_text),
    )


def _update_section(content: str, section_name: str, bullet_lines: list[str]) -> str:
    pattern = rf"(## {re.escape(section_name)}\n)(.*?)(?=\n## |\Z)"
    replacement_body = "\n".join(bullet_lines).strip() if bullet_lines else ""

    match = re.search(pattern, content, flags=re.DOTALL)
    if not match:
        return content

    new_section = f"{match.group(1)}{replacement_body}\n"
    return content[: match.start()] + new_section + content[match.end() :]


def append_learnings_to_knowledge(knowledge_text: str, insights: ReportInsights, report_name: str) -> str:
    today = date.today().isoformat()

    port_lines = [
        f"- {today} | {insights.target} | Ports observed: {', '.join(map(str, insights.open_ports)) or 'none'}",
    ]
    if insights.open_ports:
        port_lines.extend(f"- Port {port}: seen on {insights.target}" for port in insights.open_ports)

    service_lines = [
        f"- {today} | {insights.target} | Services: {', '.join(insights.services) or 'none observed'}",
    ]

    tool_lines = [
        f"- {today} | {insights.target} | Useful tools: {', '.join(insights.tools_used) or 'none parsed'}",
    ]

    credential_lines = insights.credentials or ["- No working credentials captured yet"]
    dead_end_lines = insights.dead_ends or ["- No rabbit holes recorded from this report"]
    winning_lines = insights.winning_moves or [
        f"- {today} | {insights.target} | Best move: start with broad service discovery, then pivot from evidence",
    ]

    updated = knowledge_text
    updated = _update_section(updated, "Port Patterns", port_lines)
    updated = _update_section(updated, "Service Patterns", service_lines)
    updated = _update_section(updated, "Tool Effectiveness", tool_lines)
    updated = _update_section(updated, "Credentials That Have Worked", credential_lines)
    updated = _update_section(updated, "Rabbit Holes To Avoid", dead_end_lines)
    updated = _update_section(updated, "Winning Strategies", winning_lines)

    report_note = f"\n\n## Latest Assessment Snapshot\n- Source report: {report_name}\n"
    if insights.vulnerabilities:
        report_note += "- Findings: " + "; ".join(insights.vulnerabilities) + "\n"
    else:
        report_note += "- Findings: no named vulnerabilities extracted\n"

    if "## Latest Assessment Snapshot" in updated:
        updated = re.sub(
            r"\n\n## Latest Assessment Snapshot\n.*\Z",
            report_note.rstrip(),
            updated,
            flags=re.DOTALL,
        )
    else:
        updated = updated.rstrip() + report_note

    return updated


def update_patterns(patterns: dict, insights: ReportInsights) -> dict:
    patterns["total_assessments"] = int(patterns.get("total_assessments", 0)) + 1
    patterns["last_updated"] = date.today().isoformat()

    port_patterns = patterns.setdefault("port_patterns", {})
    for port in insights.open_ports:
        port_key = str(port)
        port_patterns[port_key] = int(port_patterns.get(port_key, 0)) + 1

    service_patterns = patterns.setdefault("service_patterns", {})
    for service in insights.services:
        service_patterns[service] = int(service_patterns.get(service, 0)) + 1

    tool_wins = patterns.setdefault("tool_wins", {})
    for tool in insights.tools_used:
        tool_wins[tool] = int(tool_wins.get(tool, 0)) + 1

    common_credentials = patterns.setdefault("common_credentials", [])
    for credential in insights.credentials:
        if credential not in common_credentials:
            common_credentials.append(credential)

    patterns.setdefault("ctf_patterns", {}).setdefault("tryhackme", [])
    patterns.setdefault("ctf_patterns", {}).setdefault("hackthebox", [])

    return patterns


def update_soul(soul_text: str, insights: ReportInsights) -> str:
    total_match = re.search(r"- Total:\s*(\d+)", soul_text)
    current_total = int(total_match.group(1)) if total_match else 0
    new_total = current_total + 1

    soul_text = re.sub(r"- Total:\s*\d+", f"- Total: {new_total}", soul_text)

    targets_line_match = re.search(r"- Targets assessed:\s*(.+)", soul_text)
    current_targets_raw = targets_line_match.group(1).strip() if targets_line_match else "none yet"
    current_targets = [] if current_targets_raw == "none yet" else [item.strip() for item in current_targets_raw.split(",")]
    if insights.target not in current_targets:
        current_targets.append(insights.target)
    target_line = ", ".join(current_targets) if current_targets else "none yet"
    soul_text = re.sub(r"- Targets assessed:\s*.+", f"- Targets assessed: {target_line}", soul_text)

    evolution_entry = (
        f"- {date.today().isoformat()}: Assessed {insights.target}; "
        f"observed ports {', '.join(map(str, insights.open_ports)) or 'none'}; "
        f"services {', '.join(insights.services) or 'none'}"
    )
    soul_text = soul_text.rstrip() + "\n" + evolution_entry + "\n"
    return soul_text


def print_summary(insights: ReportInsights, patterns: dict) -> None:
    summary = {
        "target": insights.target,
        "ports": insights.open_ports,
        "services": insights.services,
        "tools_used": insights.tools_used,
        "vulnerabilities": insights.vulnerabilities,
        "credentials": insights.credentials,
        "dead_ends": insights.dead_ends,
        "winning_moves": insights.winning_moves,
        "total_assessments": patterns.get("total_assessments", 0),
    }
    print(json.dumps(summary, indent=2))


def main() -> None:
    report_path = _latest_report_path()
    report_text = _read_text(report_path)
    soul_text = _read_text(SOUL_PATH)
    knowledge_text = _read_text(KNOWLEDGE_PATH)
    patterns = json.loads(_read_text(PATTERNS_PATH))

    insights = extract_insights(report_text, report_path)
    updated_knowledge = append_learnings_to_knowledge(knowledge_text, insights, report_path.name)
    updated_patterns = update_patterns(patterns, insights)
    updated_soul = update_soul(soul_text, insights)

    _write_text(KNOWLEDGE_PATH, updated_knowledge)
    _write_text(PATTERNS_PATH, json.dumps(updated_patterns, indent=2))
    _write_text(SOUL_PATH, updated_soul)

    print_summary(insights, updated_patterns)


if __name__ == "__main__":
    main()
