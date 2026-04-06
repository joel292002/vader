from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent.parent
MEMORY_DIR = ROOT_DIR / "memory"
OUTPUT_DIR = ROOT_DIR / "swarm" / "output"

SOUL_PATH = MEMORY_DIR / "soul.md"
KNOWLEDGE_PATH = MEMORY_DIR / "knowledge.md"
PATTERNS_PATH = MEMORY_DIR / "patterns.json"
AGENT_PROMPT_PATH = MEMORY_DIR / "agent_prompt.md"

ASSESSMENT_HOOK = (
    "When assessment is complete run:\n"
    " python3 ~/vader/memory/update_memory.py\n"
    " This updates all memory files automatically."
)

STATIC_OPERATING_TRAITS = [
    "Read memory before touching the target.",
    "Let evidence drive pivots.",
    "Explain reasoning before every action.",
    "Update memory after every completed assessment.",
]

DEFAULT_STRENGTHS = [
    "web enumeration",
    "git mining",
    "credential extraction",
]

DEFAULT_WEAKNESSES = [
    "FTP enumeration depth",
    "flag ordering assumptions",
]

TOOL_ALIASES = {
    "nmap": "nmap",
    "smbclient": "smbclient",
    "smbmap": "smbmap",
    "netexec": "netexec",
    "crackmapexec": "netexec",
    "rpcclient": "rpcclient",
    "ldapsearch": "ldapsearch",
    "john": "john",
    "hashcat": "hashcat",
    "curl": "curl",
    "gobuster": "gobuster",
    "hydra": "hydra",
    "searchsploit": "searchsploit",
    "impacket-lookupsid": "impacket-lookupsid",
    "lookupsid.py": "impacket-lookupsid",
    "lookupsid": "impacket-lookupsid",
    "impacket-getuserspns": "impacket-GetUserSPNs",
    "getuserspns.py": "impacket-GetUserSPNs",
    "impacket-getnpusers": "impacket-GetNPUsers",
    "getnpusers.py": "impacket-GetNPUsers",
    "evil-winrm": "evil-winrm",
    "bloodhound-python": "bloodhound-python",
    "enum4linux-ng": "enum4linux-ng",
    "enum4linux": "enum4linux",
}

TOOL_NOTES = {
    "nmap": "best first-pass network map.",
    "curl": "fast for validating exposed files and endpoints.",
    "gobuster": "useful for confirming hidden files and directory leaks.",
    "hydra": "useful only after strong credentials are recovered.",
    "netexec": "strong for SMB/LDAP validation, spraying, roasting, and pass-the-hash validation.",
    "smbclient": "simple and effective for targeted share looting after credential recovery.",
    "smbmap": "quick way to verify share permissions and recurse interesting paths.",
    "ldapsearch": "raw LDAP is high-value once a valid bind exists.",
    "rpcclient": "worth trying for Windows null session and RID-based discovery.",
    "john": "good offline cracker for small credential sets and Kerberoast tickets.",
    "hashcat": "fast offline cracking option when local GPU/session setup cooperates.",
    "impacket-lookupsid": "excellent when AD blocks normal anonymous enumeration but still leaks user RIDs.",
    "impacket-GetUserSPNs": "reliable Kerberoast collection once any domain user credential is available.",
    "impacket-GetNPUsers": "good for checking AS-REP roasting quickly.",
    "searchsploit": "useful for quick version-to-public-exploit triage, but not proof of exploitability.",
    "evil-winrm": "high-value WinRM shell path once valid Windows credentials exist.",
    "bloodhound-python": "good for graphing AD relationships after foothold.",
    "enum4linux-ng": "worth using when SMB/RPC exposure needs broader Linux-side enumeration.",
    "enum4linux": "older SMB enumeration helper with mixed value.",
}

SKILL_STRENGTH_MAP = {
    "git": "git mining",
    "web": "web enumeration",
    "credential": "credential extraction",
    "ftp": "FTP enumeration",
    "ad": "AD enumeration",
    "password spray": "password spraying",
    "kerberoast": "Kerberoasting",
    "smb": "SMB looting",
    "pass-the-hash": "pass-the-hash",
    "windows": "Windows enumeration",
}

WEAKNESS_HINTS = {
    "ftp": "FTP enumeration depth",
    "flag order": "flag ordering assumptions",
    "flag numbering": "flag ordering assumptions",
    "service account": "service-account bias during spraying",
    "anonymous ldap": "anonymous LDAP assumptions",
    "spray": "spray discipline",
    "dead end": "pivot selection under uncertainty",
}


@dataclass
class AssessmentData:
    report_path: Path
    report_id: str
    room: str
    platform: str
    target: str
    os_type: str
    ports: list[int]
    services: list[str]
    tools_worked: list[str]
    tools_wasted: list[str]
    attack_chain: list[str]
    flags_found: list[str]
    flags_found_count: int
    flags_total: int
    flags_missed: list[str]
    credentials: list[str]
    dead_ends: list[str]
    lessons: list[str]
    quick_wins: list[str]
    strengths: list[str]
    weaknesses: list[str]
    evolution_summary: str
    key_lesson: str


@dataclass
class SoulState:
    total_assessments: int
    strengths: list[str]
    weaknesses: list[str]
    evolution_log: list[str]
    recent_lessons: list[str]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def write_text(path: Path, content: str) -> None:
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def latest_report() -> Path:
    reports = sorted(OUTPUT_DIR.glob("*.md"), key=lambda item: item.stat().st_mtime)
    if not reports:
        raise FileNotFoundError(f"No markdown reports found in {OUTPUT_DIR}")
    return reports[-1]


def report_id_for(path: Path) -> str:
    return f"{path.resolve()}::{int(path.stat().st_mtime)}"


def section_body(text: str, heading: str) -> str:
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def subsection_body(text: str, heading: str) -> str:
    match = re.search(rf"^### {re.escape(heading)}\n(.*?)(?=^### |^## |\Z)", text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def bullet_lines(block: str) -> list[str]:
    items: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            items.append(line[2:].strip())
    return items


def extract_total_from_soul(text: str) -> int:
    match = re.search(r"^- Total:\s*(\d+)\s*$", text, flags=re.MULTILINE)
    return int(match.group(1)) if match else 0


def parse_soul_state(text: str) -> SoulState:
    return SoulState(
        total_assessments=extract_total_from_soul(text),
        strengths=dedupe(bullet_lines(section_body(text, "Strengths")) or DEFAULT_STRENGTHS),
        weaknesses=dedupe(bullet_lines(section_body(text, "Weaknesses")) or DEFAULT_WEAKNESSES),
        evolution_log=dedupe(bullet_lines(section_body(text, "Evolution Log"))),
        recent_lessons=dedupe(bullet_lines(section_body(text, "Confirmed Lessons From Recent Assessments"))),
    )


def numbered_lines(block: str) -> list[str]:
    items: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if re.match(r"^\d+\.\s+", line):
            items.append(re.sub(r"^\d+\.\s+", "", line))
    return items


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        cleaned = normalize_whitespace(item)
        if not cleaned:
            continue
        key = cleaned.casefold()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(cleaned)
    return ordered


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "assessment"


def extract_scope_value(text: str, label: str) -> str:
    match = re.search(rf"- {re.escape(label)}:\s*`?([^\n`]+)`?", text)
    if match:
        return normalize_whitespace(match.group(1))
    return ""


def extract_room(text: str, path: Path) -> str:
    room = extract_scope_value(text, "Room")
    if room:
        return room
    title_match = re.search(r"^#\s+(?:Security Assessment Report:\s+)?(.+?)(?:\s+Assessment)?$", text, flags=re.MULTILINE)
    if title_match:
        title = normalize_whitespace(title_match.group(1))
        if title and title.lower() not in {"security assessment report", "assessment"}:
            return title
    return path.stem


def infer_os_type(text: str, services: list[str], ports: list[int]) -> str:
    lowered = text.lower()
    service_blob = " ".join(services).lower()
    if any(port in ports for port in (88, 389, 445, 3268, 5985)) and (
        "active directory" in lowered
        or "domain controller" in lowered
        or "kerberoast" in lowered
        or "pass-the-hash" in lowered
        or "winrm" in lowered
        or "ldap" in lowered
    ):
        return "AD"
    if (
        "microsoft windows" in lowered
        or "windows server" in lowered
        or "terminal services" in service_blob
        or "msrpc" in service_blob
        or "winrm" in lowered
    ):
        return "Windows"
    return "Linux"


def extract_ports(text: str) -> list[int]:
    ports = {int(value) for value in re.findall(r"\b(\d{1,5})/tcp\b", text)}
    return sorted(port for port in ports if 0 < port <= 65535)


def extract_services(text: str) -> list[str]:
    services = re.findall(r"^\d{1,5}/tcp\s+open\s+\S+\s+(.+)$", text, flags=re.MULTILINE)
    return dedupe([normalize_whitespace(item) for item in services])


def extract_commands(text: str) -> list[str]:
    commands: list[str] = []
    methodology = section_body(text, "Methodology")
    for line in numbered_lines(methodology):
        commands.extend(re.findall(r"`([^`]+)`", line))
    tooling = section_body(text, "Tooling And Pivots")
    for block in (tooling, text):
        commands.extend(re.findall(r"`([a-zA-Z0-9_.-]+(?:\s+[^`\n]+)?)`", block))
    return dedupe(commands)


def first_command_token(command: str) -> str:
    token = command.strip().split()[0].lower()
    return TOOL_ALIASES.get(token, token)


def detect_tools(commands: list[str], lines: list[str]) -> list[str]:
    tools = [first_command_token(command) for command in commands]
    line_blob = " ".join(lines).lower()
    for alias, canonical in TOOL_ALIASES.items():
        if alias in line_blob:
            tools.append(canonical)
    return dedupe(tools)


def extract_credentials(text: str) -> list[str]:
    credentials: list[str] = []
    for user, password in re.findall(r"`([^`:\n]+)\s*:\s*([^`\n]+)`", text):
        credentials.append(f"{user.strip()}:{password.strip()}")
    for user, password in re.findall(r"-\s*`?([A-Za-z0-9_.$!@-]+)\s*:\s*([^`\n]+?)`?\s*$", text, flags=re.MULTILINE):
        if ":::" in password:
            continue
        credentials.append(f"{user.strip()}:{password.strip()}")
    for account, nthash in re.findall(
        r"([A-Za-z0-9_.-]+\$?):\d+:aad3b435b51404eeaad3b435b51404ee:([0-9a-fA-F]{32}):::",
        text,
    ):
        credentials.append(f"{account}:{nthash.lower()}")
    return dedupe(credentials)


def extract_flags(text: str) -> tuple[list[str], int, list[str]]:
    found = set(
        re.findall(
            r"(?:THM|HTB|flag|fla)\{[^}\n]+\}|(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])",
            text,
            flags=re.IGNORECASE,
        )
    )
    flags_section = section_body(text, "Flags")
    total = 0
    missed: list[str] = []
    if flags_section:
        for line in bullet_lines(flags_section):
            if ":" in line:
                total += 1
                label, value = [part.strip() for part in line.split(":", 1)]
                if re.search(r"\bnot found\b|\bmissed\b|\bunknown\b", value, flags=re.IGNORECASE):
                    missed.append(label)
    if total == 0 and found:
        total = len(found)
    total = max(total, len(found))
    return sorted(found), total, dedupe(missed)


def extract_dead_ends(text: str) -> list[str]:
    dead = numbered_lines(subsection_body(text, "Dead ends"))
    limits = bullet_lines(section_body(text, "Limits"))
    if limits:
        dead.extend([f"Assessment limit: {item}" for item in limits])
    return dedupe(dead)


def extract_effective_moves(text: str) -> list[str]:
    return dedupe(numbered_lines(subsection_body(text, "Effective moves")))


def derive_lessons(text: str, os_type: str, attack_chain: list[str]) -> list[str]:
    lowered = text.lower()
    lessons: list[str] = []
    if "lookupsid" in lowered or "rid leak" in lowered or "lsarpc" in lowered:
        lessons.append(
            "LSARPC SID bruteforcing can still leak a full domain user list even when anonymous LDAP subtree queries are blocked."
        )
    if "username-equals-password" in lowered or "username = password" in lowered:
        lessons.append("Username-equals-password can be the intended spray pattern for one low-priv domain user.")
    if "kerberoast" in lowered or "getuserspns" in lowered:
        lessons.append("Kerberoast all SPN accounts as soon as one valid domain user is recovered.")
    if "backup share" in lowered or "backup_extract.txt" in lowered:
        lessons.append("Readable backup shares may contain machine-account NTLM hashes that are directly useful for pass-the-hash.")
    if "pass-the-hash" in lowered or "pwn3d" in lowered:
        lessons.append("Machine-account hashes can be enough to read administrative SMB shares on the domain controller.")
    if os_type == "Linux" and ".git" in lowered and "dbcreate.sql" in lowered:
        lessons.append("Exposed Git over HTTP plus live SQL bootstrap files can leak both credentials and flags directly.")
    if not lessons and attack_chain:
        lessons.append(f"Confirmed chain: {' -> '.join(attack_chain)}")
    if not lessons:
        lessons.append("Let the service mix drive the next pivot instead of forcing a fixed checklist.")
    return dedupe(lessons)


def derive_attack_chain(text: str, effective_moves: list[str], credentials: list[str]) -> list[str]:
    lowered = text.lower()
    chain: list[str] = []
    if "lookupsid" in lowered or "rid leak" in lowered or "lsarpc" in lowered:
        chain.append("RID leak via lookupsid")
    if "username-equals-password" in lowered or "username = password" in lowered:
        chain.append("username-equals-password spray")
    if any(credential.split(":", 1)[0].casefold() == credential.split(":", 1)[1].casefold() for credential in credentials if ":" in credential):
        chain.append("weak user credential recovered")
    if "kerberoast" in lowered or "getuserspns" in lowered:
        chain.append("Kerberoast")
    if "backup share" in lowered or "backup_extract.txt" in lowered:
        chain.append("backup share loot")
    if "pass-the-hash" in lowered or "pwn3d" in lowered:
        chain.append("pass-the-hash")
    if "root.txt" in lowered or "administrator flag" in lowered:
        chain.append("admin flag recovery")
    if not chain:
        chain.extend(effective_moves[:4])
    return dedupe(chain)


def derive_quick_wins(text: str, effective_moves: list[str], os_type: str) -> list[str]:
    lowered = text.lower()
    quick_wins: list[str] = []
    if os_type == "AD" and ("lookupsid" in lowered or "rid leak" in lowered):
        quick_wins.append("Try `impacket-lookupsid -no-pass` when AD blocks anonymous LDAP but still leaks SIDs.")
    if os_type == "AD" and ("username-equals-password" in lowered or "username = password" in lowered):
        quick_wins.append("Spray `username = password` once across synthetic-looking AD user sets before burning broader guesses.")
    if "kerberoast" in lowered:
        quick_wins.append("Kerberoast SPN accounts immediately after the first valid domain user is found.")
    if "backup share" in lowered:
        quick_wins.append("Re-check custom SMB shares after each credential recovery; access often changes with service accounts.")
    if "pass-the-hash" in lowered:
        quick_wins.append("Validate recovered NTLM hashes over SMB immediately; machine accounts can still land admin access.")
    for move in effective_moves[:3]:
        quick_wins.append(move)
    return dedupe(quick_wins)


def derive_strengths(os_type: str, attack_chain: list[str]) -> list[str]:
    strengths: list[str] = []
    for item in attack_chain:
        lowered = item.lower()
        for hint, strength in SKILL_STRENGTH_MAP.items():
            if hint in lowered:
                strengths.append(strength)
    if os_type == "AD":
        strengths.append("AD enumeration")
    return dedupe(strengths)


def derive_weaknesses(flags_missed: list[str], dead_ends: list[str]) -> list[str]:
    weaknesses: list[str] = []
    if flags_missed:
        weaknesses.append("full-clear consistency")
    for item in dead_ends:
        lowered = item.lower()
        for hint, weakness in WEAKNESS_HINTS.items():
            if hint in lowered:
                weaknesses.append(weakness)
    return dedupe(weaknesses)


def summarize_evolution(room: str, attack_chain: list[str], flags_found_count: int, flags_total: int) -> str:
    if attack_chain:
        return f"{room}: {' -> '.join(attack_chain[:4])} ({flags_found_count}/{flags_total} flags)."
    return f"{room}: completed assessment with {flags_found_count}/{flags_total} flags."


def parse_report(report_path: Path) -> AssessmentData:
    text = read_text(report_path)
    room = extract_room(text, report_path)
    platform = extract_scope_value(text, "Platform") or extract_scope_value(text, "Assessment type") or "Unknown"
    target = extract_scope_value(text, "Target") or "unknown"
    ports = extract_ports(text)
    services = extract_services(text)
    os_type = infer_os_type(text, services, ports)
    commands = extract_commands(text)
    effective_moves = extract_effective_moves(text)
    dead_ends = extract_dead_ends(text)
    tools_worked = detect_tools(commands, effective_moves)
    tools_wasted = detect_tools(commands, dead_ends)
    credentials = extract_credentials(text)
    flags_found, flags_total, flags_missed = extract_flags(text)
    attack_chain = derive_attack_chain(text, effective_moves, credentials)
    lessons = derive_lessons(text, os_type, attack_chain)
    quick_wins = derive_quick_wins(text, effective_moves, os_type)
    strengths = derive_strengths(os_type, attack_chain)
    weaknesses = derive_weaknesses(flags_missed, dead_ends)
    return AssessmentData(
        report_path=report_path,
        report_id=report_id_for(report_path),
        room=room,
        platform=platform,
        target=target,
        os_type=os_type,
        ports=ports,
        services=services,
        tools_worked=tools_worked,
        tools_wasted=tools_wasted,
        attack_chain=attack_chain,
        flags_found=flags_found,
        flags_found_count=len(flags_found),
        flags_total=flags_total,
        flags_missed=flags_missed,
        credentials=credentials,
        dead_ends=dead_ends,
        lessons=lessons,
        quick_wins=quick_wins,
        strengths=strengths,
        weaknesses=weaknesses,
        evolution_summary=summarize_evolution(room, attack_chain, len(flags_found), flags_total),
        key_lesson=lessons[0],
    )


def normalize_patterns(payload: dict[str, Any], soul_state: SoulState | None = None) -> dict[str, Any]:
    identity = payload.get("identity") or {"name": "Vader", "role": "adaptive security agent"}
    soul_state = soul_state or SoulState(0, DEFAULT_STRENGTHS, DEFAULT_WEAKNESSES, [], [])
    total = int(payload.get("total_assessments") or payload.get("assessments_completed") or soul_state.total_assessments or 0)
    successful = int(payload.get("successful_assessments") or 0)
    processed_reports = payload.get("processed_reports") or []
    if isinstance(processed_reports, dict):
        processed_reports = list(processed_reports.keys())

    tools: dict[str, dict[str, Any]] = {}
    raw_tools = payload.get("tool_effectiveness", {})
    if isinstance(raw_tools, list):
        for index, item in enumerate(raw_tools):
            tool = item.get("tool")
            if not tool:
                continue
            score = int(item.get("rank") or max(1, 100 - index))
            tools[tool] = {
                "score": score,
                "wins": 0,
                "wastes": 0,
                "rooms": [],
                "notes": TOOL_NOTES.get(tool, ""),
            }
    elif isinstance(raw_tools, dict):
        for tool, meta in raw_tools.items():
            if isinstance(meta, dict):
                tools[tool] = {
                    "score": int(meta.get("score", 50)),
                    "wins": int(meta.get("wins", 0)),
                    "wastes": int(meta.get("wastes", 0)),
                    "rooms": dedupe(meta.get("rooms", [])),
                    "notes": meta.get("notes") or TOOL_NOTES.get(tool, ""),
                }

    os_patterns = payload.get("os_patterns") or {}
    if not isinstance(os_patterns, dict):
        os_patterns = {}

    quick_wins = dedupe(payload.get("quick_wins_confirmed") or payload.get("winning_strategies") or [])
    dead_ends = dedupe(payload.get("dead_ends_confirmed") or payload.get("dead_ends_to_avoid") or [])

    rooms = payload.get("rooms") or {}
    if not isinstance(rooms, dict):
        rooms = {}

    return {
        "identity": identity,
        "total_assessments": total,
        "assessments_completed": total,
        "successful_assessments": successful,
        "win_rate": round((successful / total) * 100, 1) if total else 0.0,
        "strengths": dedupe(payload.get("strengths") or soul_state.strengths or DEFAULT_STRENGTHS),
        "weaknesses": dedupe(payload.get("weaknesses") or soul_state.weaknesses or DEFAULT_WEAKNESSES),
        "confirmed_lessons": payload.get("confirmed_lessons") or [],
        "tool_effectiveness": tools,
        "os_patterns": os_patterns,
        "quick_wins_confirmed": quick_wins,
        "dead_ends_confirmed": dead_ends,
        "rooms": rooms,
        "processed_reports": dedupe(processed_reports),
        "last_updated": payload.get("last_updated") or date.today().isoformat(),
    }


def merge_assessment(patterns: dict[str, Any], assessment: AssessmentData) -> tuple[dict[str, Any], bool]:
    already_processed = assessment.report_id in patterns["processed_reports"]
    if not already_processed:
        patterns["total_assessments"] += 1
        patterns["assessments_completed"] = patterns["total_assessments"]
        if assessment.flags_total and assessment.flags_found_count >= assessment.flags_total:
            patterns["successful_assessments"] += 1
        patterns["processed_reports"].append(assessment.report_id)

    patterns["win_rate"] = round(
        (patterns["successful_assessments"] / patterns["total_assessments"]) * 100, 1
    ) if patterns["total_assessments"] else 0.0

    room_key = slugify(assessment.room)
    patterns["rooms"][room_key] = {
        "room": assessment.room,
        "platform": assessment.platform,
        "target": assessment.target,
        "os_type": assessment.os_type,
        "ports": assessment.ports,
        "services": assessment.services,
        "tools_worked": assessment.tools_worked,
        "tools_wasted": assessment.tools_wasted,
        "attack_chain": assessment.attack_chain,
        "credentials": assessment.credentials,
        "flags_found": assessment.flags_found,
        "flags_found_count": assessment.flags_found_count,
        "flags_total": assessment.flags_total,
        "flags_missed": assessment.flags_missed,
        "dead_ends": assessment.dead_ends,
        "lessons": assessment.lessons,
        "quick_wins": assessment.quick_wins,
        "report_path": str(assessment.report_path),
        "report_id": assessment.report_id,
        "updated": date.today().isoformat(),
    }

    for strength in assessment.strengths:
        patterns["strengths"] = dedupe(patterns["strengths"] + [strength])
    for weakness in assessment.weaknesses:
        patterns["weaknesses"] = dedupe(patterns["weaknesses"] + [weakness])

    existing_lessons = {(item.get("source"), item.get("lesson")) for item in patterns["confirmed_lessons"] if isinstance(item, dict)}
    for lesson in assessment.lessons:
        item = (assessment.room, lesson)
        if item not in existing_lessons:
            patterns["confirmed_lessons"].append({"source": assessment.room, "lesson": lesson})
            existing_lessons.add(item)

    for quick_win in assessment.quick_wins:
        patterns["quick_wins_confirmed"] = dedupe(patterns["quick_wins_confirmed"] + [quick_win])

    for dead_end in assessment.dead_ends:
        patterns["dead_ends_confirmed"] = dedupe(patterns["dead_ends_confirmed"] + [dead_end])

    bucket = patterns["os_patterns"].setdefault(
        assessment.os_type,
        {"count": 0, "rooms": [], "ports": [], "successful_chains": [], "lessons": []},
    )
    if not already_processed:
        bucket["count"] = int(bucket.get("count", 0)) + 1
    bucket["rooms"] = dedupe(bucket.get("rooms", []) + [assessment.room])
    bucket["ports"] = sorted({int(port) for port in bucket.get("ports", []) + assessment.ports})
    if assessment.attack_chain:
        bucket["successful_chains"] = dedupe(bucket.get("successful_chains", []) + [" -> ".join(assessment.attack_chain)])
    bucket["lessons"] = dedupe(bucket.get("lessons", []) + assessment.lessons)

    for tool in assessment.tools_worked:
        meta = patterns["tool_effectiveness"].setdefault(
            tool,
            {"score": 50, "wins": 0, "wastes": 0, "rooms": [], "notes": TOOL_NOTES.get(tool, "")},
        )
        if not already_processed:
            meta["score"] = int(meta.get("score", 50)) + 5
            meta["wins"] = int(meta.get("wins", 0)) + 1
        meta["rooms"] = dedupe(meta.get("rooms", []) + [assessment.room])
        if not meta.get("notes"):
            meta["notes"] = TOOL_NOTES.get(tool, "")

    for tool in assessment.tools_wasted:
        meta = patterns["tool_effectiveness"].setdefault(
            tool,
            {"score": 50, "wins": 0, "wastes": 0, "rooms": [], "notes": TOOL_NOTES.get(tool, "")},
        )
        if not already_processed:
            meta["score"] = max(1, int(meta.get("score", 50)) - 1)
            meta["wastes"] = int(meta.get("wastes", 0)) + 1
        meta["rooms"] = dedupe(meta.get("rooms", []) + [assessment.room])
        if not meta.get("notes"):
            meta["notes"] = TOOL_NOTES.get(tool, "")

    patterns["last_updated"] = date.today().isoformat()
    return patterns, already_processed


def build_knowledge(patterns: dict[str, Any]) -> str:
    port_lines: list[str] = []
    port_seen: set[tuple[int, str]] = set()
    for room in sorted(patterns["rooms"].values(), key=lambda item: item["room"].lower()):
        for port in room.get("ports", []):
            key = (int(port), room["room"])
            if key in port_seen:
                continue
            port_seen.add(key)
            port_lines.append(f"- `{port}/tcp`: observed on {room['room']}")

    service_lines: list[str] = []
    service_seen: set[tuple[str, str]] = set()
    for room in sorted(patterns["rooms"].values(), key=lambda item: item["room"].lower()):
        for service in room.get("services", []):
            key = (service.casefold(), room["room"])
            if key in service_seen:
                continue
            service_seen.add(key)
            service_lines.append(f"- {service}")

    ranking = sorted(
        patterns["tool_effectiveness"].items(),
        key=lambda item: (-int(item[1].get("score", 0)), item[0].casefold()),
    )[:10]
    tool_lines = []
    for index, (tool, meta) in enumerate(ranking, start=1):
        note = normalize_whitespace(meta.get("notes") or TOOL_NOTES.get(tool, "effective in observed assessments."))
        tool_lines.append(f"{index}. `{tool}`: {note}")

    platform_lines = [
        "- Hints often redirect from a minor service to the real weakness.",
        "- Naming themes can become usernames.",
    ]
    for os_type, meta in sorted(patterns["os_patterns"].items()):
        if meta.get("count"):
            platform_lines.append(
                f"- {os_type} patterns seen in {meta['count']} assessment(s): {', '.join(meta.get('rooms', [])[:5])}"
            )

    credential_lines = []
    for room in sorted(patterns["rooms"].values(), key=lambda item: item["room"].lower()):
        for credential in room.get("credentials", []):
            credential_lines.append(f"- `{credential}`")

    dead_end_lines = [f"- {item}" for item in patterns["dead_ends_confirmed"]]
    quick_win_lines = [f"- {item}" for item in patterns["quick_wins_confirmed"]]

    snapshot_sections: list[str] = []
    ordered_rooms = sorted(patterns["rooms"].values(), key=lambda item: item.get("updated", ""), reverse=True)
    for room in ordered_rooms:
        snapshot_sections.append(
            "\n".join(
                [
                    f"## {room['room']} Snapshot",
                    f"- Platform: {room.get('platform', 'Unknown')}",
                    f"- Target: {room.get('target', 'unknown')}",
                    f"- OS type: {room.get('os_type', 'Unknown')}",
                    f"- Confirmed path: {' -> '.join(room.get('attack_chain', [])) if room.get('attack_chain') else 'No attack chain captured'}",
                    f"- Confirmed flags: {', '.join(room.get('flags_found', [])) if room.get('flags_found') else 'none'}",
                ]
            )
        )

    return "\n".join(
        [
            "# Vader Knowledge Base",
            "",
            "## Port Patterns Learned",
            "\n".join(port_lines) or "- No port patterns recorded yet.",
            "",
            "## Service Patterns Learned",
            "\n".join(service_lines) or "- No service patterns recorded yet.",
            "",
            "## Tool Effectiveness Rankings",
            "\n".join(tool_lines) or "1. `nmap`: best first-pass network map.",
            "",
            "## CTF Platform Patterns For TryHackMe",
            "\n".join(dedupe(platform_lines)),
            "",
            "## Credential Patterns Seen",
            "\n".join(dedupe(credential_lines)) or "- No credentials captured yet.",
            "",
            "## Dead Ends To Avoid",
            "\n".join(dead_end_lines) or "- No dead ends recorded yet.",
            "",
            "## Winning Strategies Confirmed",
            "\n".join(quick_win_lines) or "- No winning strategies recorded yet.",
            "",
            "\n\n".join(snapshot_sections),
        ]
    )


def build_soul(patterns: dict[str, Any]) -> str:
    latest_room = ""
    latest_updated = ""
    for room in patterns["rooms"].values():
        updated = room.get("updated", "")
        if updated >= latest_updated:
            latest_updated = updated
            latest_room = room.get("room", "")

    lessons = [item["lesson"] for item in patterns["confirmed_lessons"][-8:] if isinstance(item, dict) and item.get("lesson")]
    evolution_lines: list[str] = []
    for room in sorted(patterns["rooms"].values(), key=lambda item: item.get("updated", "")):
        summary = room.get("attack_chain", [])
        flags_found = room.get("flags_found_count", 0)
        flags_total = room.get("flags_total", 0)
        os_type = room.get("os_type", "Unknown")
        lesson = normalize_whitespace((room.get("lessons") or ["Completed assessment"])[0])
        evolution_lines.append(
            f"- {room.get('updated', date.today().isoformat())} | {room.get('room', 'Unknown')} | "
            f"{os_type} | {flags_found}/{flags_total} flags | {lesson}"
        )

    return "\n".join(
        [
            "# Vader Soul",
            "",
            "## Identity",
            "I am Vader, adaptive security agent.",
            "",
            "## Assessments Completed",
            f"- Total: {patterns['total_assessments']}",
            f"- Successful full clears: {patterns['successful_assessments']}",
            f"- Win rate: {patterns['successful_assessments']}/{patterns['total_assessments']} ({patterns['win_rate']:.1f}%)",
            f"- Latest room memory: {latest_room or 'none'}",
            "",
            "## Confirmed Lessons From Recent Assessments",
            "\n".join(f"- {lesson}" for lesson in dedupe(lessons)) or "- No lessons recorded yet.",
            "",
            "## Strengths",
            "\n".join(f"- {item}" for item in patterns["strengths"]),
            "",
            "## Weaknesses",
            "\n".join(f"- {item}" for item in patterns["weaknesses"]),
            "",
            "## Operating Traits",
            "\n".join(f"- {item}" for item in STATIC_OPERATING_TRAITS),
            "",
            "## Evolution Log",
            "\n".join(evolution_lines) or f"- {date.today().isoformat()} | No assessments logged yet.",
        ]
    )


def build_agent_prompt(patterns: dict[str, Any]) -> str:
    quick_wins = patterns["quick_wins_confirmed"][:5]
    pattern_lines: list[str] = []
    for os_type, meta in sorted(patterns["os_patterns"].items(), key=lambda item: (-int(item[1].get("count", 0)), item[0])):
        if meta.get("count"):
            rooms = ", ".join(meta.get("rooms", [])[:3])
            pattern_lines.append(f"- {os_type}: seen in {meta['count']} assessment(s) ({rooms})")
    if not pattern_lines:
        pattern_lines = ["- Let observed services drive the next pivot."]
    latest_chains: list[str] = []
    ordered_rooms = sorted(patterns["rooms"].values(), key=lambda item: item.get("updated", ""), reverse=True)
    for room in ordered_rooms[:5]:
        chain = room.get("attack_chain", [])
        if chain:
            latest_chains.append(f"- {room.get('room', 'Unknown')}: {' -> '.join(chain)}")
    if not latest_chains:
        latest_chains = ["- No confirmed chains logged yet."]

    lines = [
        "Read `CLAUDE.md`, `soul.md`, `knowledge.md`, and `patterns.json`.",
        "Target: [TARGET]",
        "Platform: [PLATFORM]",
        "Authorization: Confirmed",
        "Find all flags. Show reasoning before each step. Update memory when done.",
        "",
        "## Quick Wins",
        *(quick_wins and [f"- {item}" for item in quick_wins] or ["- Start broad, then pivot into the richest artifact quickly."]),
        "",
        "## Pattern Recognition",
        *pattern_lines,
        "",
        "## Latest Confirmed Chains",
        *latest_chains,
        "",
        "## Strength Bias",
        *(patterns["strengths"][:5] and [f"- Lean on {item} when the evidence supports it." for item in patterns["strengths"][:5]] or ["- Use the right tool for the evidence you have."]),
        "",
        "## Avoid Repeating",
        *(patterns["weaknesses"][:5] and [f"- Watch for {item}." for item in patterns["weaknesses"][:5]] or ["- Do not repeat logged mistakes."]),
        "",
        ASSESSMENT_HOOK,
    ]
    return "\n".join(lines)


def summary_counts(before: dict[str, Any], after: dict[str, Any], room_key: str) -> tuple[int, int]:
    before_lessons = len(before.get("confirmed_lessons", []))
    after_lessons = len(after.get("confirmed_lessons", []))
    before_patterns = len(before.get("quick_wins_confirmed", [])) + len(before.get("dead_ends_confirmed", [])) + len(before.get("os_patterns", {}))
    after_patterns = len(after.get("quick_wins_confirmed", [])) + len(after.get("dead_ends_confirmed", [])) + len(after.get("os_patterns", {}))
    if room_key not in before.get("rooms", {}):
        after_patterns += 1
    return max(0, after_lessons - before_lessons), max(0, after_patterns - before_patterns)


def main() -> None:
    report_path = latest_report()
    assessment = parse_report(report_path)

    current_state = {
        "soul": read_text(SOUL_PATH),
        "knowledge": read_text(KNOWLEDGE_PATH),
        "patterns": read_json(PATTERNS_PATH),
        "agent_prompt": read_text(AGENT_PROMPT_PATH),
    }
    soul_state = parse_soul_state(current_state["soul"])

    patterns_before = normalize_patterns(current_state["patterns"], soul_state)
    patterns_after, already_processed = merge_assessment(normalize_patterns(current_state["patterns"], soul_state), assessment)

    knowledge_text = build_knowledge(patterns_after)
    soul_text = build_soul(patterns_after)
    agent_prompt_text = build_agent_prompt(patterns_after)

    write_text(KNOWLEDGE_PATH, knowledge_text)
    write_text(SOUL_PATH, soul_text)
    write_json(PATTERNS_PATH, patterns_after)
    write_text(AGENT_PROMPT_PATH, agent_prompt_text)

    room_key = slugify(assessment.room)
    lessons_added, patterns_updated = summary_counts(patterns_before, patterns_after, room_key)
    if already_processed:
        lessons_added = 0
        patterns_updated = 0

    print(f"Assessment: {assessment.room}")
    print(f"Flags: {assessment.flags_found_count} found / {assessment.flags_total} total")
    print(f"New lessons added: {lessons_added}")
    print(f"Patterns updated: {patterns_updated}")
    print(f"Soul evolution: {assessment.evolution_summary}")
    print("Memory is now current. Vader is smarter.")


if __name__ == "__main__":
    main()
