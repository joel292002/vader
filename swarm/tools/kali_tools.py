from __future__ import annotations

import shlex
import shutil
import subprocess


TOOL_COMMANDS = {
    "run_nmap": "nmap",
    "run_nikto": "nikto",
    "run_whatweb": "whatweb",
    "run_gobuster": "gobuster",
    "run_searchsploit": "searchsploit",
    "run_dnsenum": "dnsenum",
    "run_nuclei": "nuclei",
    "run_wpscan": "wpscan",
    "run_sslscan": "sslscan",
}


def _run_command(command_name: str, args: list[str]) -> str:
    binary = shutil.which(command_name)
    if not binary:
        return f"[tool unavailable] {command_name} is not installed on this system."

    try:
        completed = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return (
            f"[tool timeout] {' '.join([command_name, *args])}\n"
            f"{stdout}\n{stderr}".strip()
        )
    except Exception as exc:
        return f"[tool error] Failed to run {command_name}: {exc}"

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    pieces = []
    if stdout:
        pieces.append(stdout)
    if stderr:
        pieces.append(f"[stderr]\n{stderr}")
    if not pieces:
        pieces.append(f"[no output] {command_name} exited with code {completed.returncode}.")
    if completed.returncode != 0:
        pieces.append(f"[exit code] {completed.returncode}")
    return "\n\n".join(pieces)


def run_nmap(target: str, flags: str = "") -> str:
    effective_flags = flags or "-sV -sC --open -T4"
    args = [*shlex.split(effective_flags), target]
    return _run_command("nmap", args)


def run_nikto(target: str) -> str:
    return _run_command("nikto", ["-h", target, "-nointeractive"])


def run_whatweb(target: str) -> str:
    return _run_command("whatweb", ["--color=never", "-a", "3", target])


def run_gobuster(
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> str:
    return _run_command(
        "gobuster",
        ["dir", "-u", target, "-w", wordlist, "-q", "--no-error"],
    )


def run_searchsploit(query: str) -> str:
    return _run_command("searchsploit", [query, "--color=never"])


def run_dnsenum(target: str) -> str:
    return _run_command("dnsenum", ["--noreverse", "--nocolor", target])


def run_nuclei(target: str) -> str:
    return _run_command("nuclei", ["-u", target, "-silent"])


def run_wpscan(target: str) -> str:
    return _run_command("wpscan", ["--url", target, "--no-banner"])


def run_sslscan(target: str) -> str:
    return _run_command("sslscan", ["--no-colour", target])


def list_available_tools() -> list[str]:
    available = []
    for tool_name, command_name in TOOL_COMMANDS.items():
        if shutil.which(command_name):
            available.append(tool_name)
    return available
