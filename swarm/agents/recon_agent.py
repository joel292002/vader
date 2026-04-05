from __future__ import annotations

import asyncio
import socket
from datetime import datetime

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from swarm.utils.logger import get_logger
from swarm.utils.models import PortFinding, ReconResult


logger = get_logger("ReconAgent")
console = Console()

KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8834: "Nessus",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

RISK_MAP = {
    "Telnet": "critical",
    "FTP": "high",
    "SMB": "high",
    "RDP": "high",
    "VNC": "high",
    "Redis": "high",
    "MongoDB": "high",
    "Elasticsearch": "high",
    "MSSQL": "medium",
    "MySQL": "medium",
    "PostgreSQL": "medium",
    "NetBIOS": "medium",
    "RPC": "medium",
    "SSH": "low",
    "HTTP": "low",
    "SMTP": "low",
    "DNS": "low",
    "POP3": "low",
    "IMAP": "low",
    "HTTPS": "info",
    "Nessus": "info",
    "HTTP-Alt": "info",
    "HTTPS-Alt": "info",
    "Unknown": "info",
}

RICH_RISK_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _clean_banner(data: bytes) -> str:
    banner = data.decode("utf-8", errors="replace").strip()
    if not banner:
        return ""
    return " ".join(banner.split())


def _service_for_port(port: int) -> str:
    return KNOWN_SERVICES.get(port, "Unknown")


def _risk_for_service(service: str) -> str:
    return RISK_MAP.get(service, "info")


async def probe_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = 0.8,
) -> tuple[int, bool, str]:
    async with semaphore:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            try:
                banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
            except Exception:
                banner = b""

            return port, True, _clean_banner(banner)
        except Exception:
            return port, False, ""
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def scan(
    host: str,
    start_port: int,
    end_port: int,
    concurrency: int = 300,
) -> list[PortFinding]:
    semaphore = asyncio.Semaphore(concurrency)
    findings: list[PortFinding] = []
    total_ports = end_port - start_port + 1

    async def tracked_probe(progress: Progress, task_id: int, port: int) -> tuple[int, bool, str]:
        result = await probe_port(host, port, semaphore)
        _, is_open, banner = result

        if is_open:
            service = _service_for_port(port)
            risk = _risk_for_service(service)
            finding = PortFinding(
                port=port,
                service=service,
                banner=banner,
                risk=risk,
            )
            findings.append(finding)
            console.print(
                f"[{RICH_RISK_STYLES[risk]}]Open port {port}/tcp | {service} | "
                f"risk={risk.upper()} | banner={banner or 'No banner'}[/]"
            )

        progress.advance(task_id, 1)
        return result

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            f"Scanning {host} ports {start_port}-{end_port}",
            total=total_ports,
        )
        tasks = [
            tracked_probe(progress, task_id, port)
            for port in range(start_port, end_port + 1)
        ]
        await asyncio.gather(*tasks)

    return sorted(findings, key=lambda finding: finding.port)


def resolve_hostname(target: str) -> str:
    try:
        return socket.gethostbyaddr(target)[0]
    except Exception:
        try:
            return socket.getfqdn(target) if target != socket.getfqdn(target) else ""
        except Exception:
            return ""


async def run(target: str, start_port: int = 1, end_port: int = 65535) -> ReconResult:
    logger.log("AGENT_START", f"Starting recon scan against {target}")

    started_at = datetime.now()
    scan_start = started_at.isoformat(timespec="seconds")
    hostname = resolve_hostname(target)

    findings = await scan(target, start_port, end_port)

    finished_at = datetime.now()
    duration_seconds = (finished_at - started_at).total_seconds()
    result = ReconResult(
        target=target,
        hostname=hostname,
        scan_start=scan_start,
        scan_end=finished_at.isoformat(timespec="seconds"),
        duration_seconds=duration_seconds,
        open_ports=findings,
        total_ports_scanned=end_port - start_port + 1,
    )

    output_path = result.save_json()

    logger.log(
        "AGENT_DONE",
        f"Recon complete for {target}: {len(findings)} open ports found in {duration_seconds:.2f}s",
    )
    logger.log("HANDOFF", f"Recon findings saved for VulnAgent at {output_path}")

    return result


if __name__ == "__main__":
    target = input("Target IP: ").strip()
    asyncio.run(run(target))
