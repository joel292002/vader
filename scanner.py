import asyncio
import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Map of well-known ports to service names
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


async def scan_port(host, port, semaphore, timeout=1):
    """
    Async version of port scanning.
    'semaphore' controls how many ports we scan at the same time.
    Think of it like only allowing 200 people through a door at once.
    """
    async with semaphore:
        try:
            # asyncio.open_connection is the async way to make a TCP connection
            # If it connects = port is open
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            # Try to grab a banner (what the service says when you connect)
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                banner = banner.decode(errors="ignore").strip()
            except:
                banner = ""

            # Politely close the connection
            writer.close()
            await writer.wait_closed()

            return port, True, banner

        except:
            return port, False, ""


async def run_scan(host, start_port, end_port, concurrency=200):
    """
    Run all port scans concurrently.
    concurrency=200 means we check 200 ports at the same time.
    """
    # Semaphore = a limit on how many async tasks run simultaneously
    semaphore = asyncio.Semaphore(concurrency)

    # Build a list of scan tasks — one per port
    tasks = [
        scan_port(host, port, semaphore)
        for port in range(start_port, end_port + 1)
    ]

    open_ports = []
    total = len(tasks)

    console.print(f"\n[bold cyan]🔍 Target:[/bold cyan] {host}")
    console.print(f"[bold cyan]📡 Port range:[/bold cyan] {start_port} - {end_port}")
    console.print(f"[bold cyan]⚡ Concurrency:[/bold cyan] {concurrency} ports at a time")
    console.print(f"[bold cyan]🕐 Started:[/bold cyan] {datetime.now().strftime('%H:%M:%S')}\n")

    # Progress bar so we can see it working in real time
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task_bar = progress.add_task("Scanning ports...", total=total)

        # as_completed = process results as they come in, not waiting for all
        for coro in asyncio.as_completed(tasks):
            port, is_open, banner = await coro
            progress.advance(task_bar)

            if is_open:
                open_ports.append((port, banner))
                service = KNOWN_SERVICES.get(port, "Unknown")
                banner_display = f" → [italic]{banner[:40]}[/italic]" if banner else ""
                console.print(
                    f"[bold green]✅ Port {port:5d}[/bold green] | "
                    f"[yellow]{service:<12}[/yellow]{banner_display}"
                )

    return sorted(open_ports, key=lambda x: x[0])


def show_results(host, open_ports, start_time):
    """Show a final clean summary table"""
    elapsed = (datetime.now() - start_time).total_seconds()

    console.print("\n")
    table = Table(title=f"📋 Final Scan Report — {host}", show_lines=True)
    table.add_column("Port", style="cyan", justify="center", width=8)
    table.add_column("Service", style="yellow", justify="center", width=14)
    table.add_column("Banner / Info", style="white", width=45)

    for port, banner in open_ports:
        service = KNOWN_SERVICES.get(port, "Unknown")
        table.add_row(str(port), service, banner[:45] if banner else "—")

    console.print(table)
    console.print(f"\n[bold green]✅ Open ports found: {len(open_ports)}[/bold green]")
    console.print(f"[bold]⏱  Scan duration: {elapsed:.2f} seconds[/bold]")
    console.print(f"[dim]Completed at: {datetime.now().strftime('%H:%M:%S')}[/dim]\n")


# ── MAIN ─────────────────────────────────────────────────
if __name__ == "__main__":
    console.print("[bold yellow]⚡ Fast Async Port Scanner v2[/bold yellow]\n")

    host = input("Enter target IP or hostname: ").strip()
    start = int(input("Start port (e.g. 1): ").strip())
    end = int(input("End port (e.g. 65535): ").strip())

    start_time = datetime.now()

    # asyncio.run() is how you start an async program
    open_ports = asyncio.run(run_scan(host, start, end))

    if open_ports:
        show_results(host, open_ports, start_time)
    else:
        console.print("[bold red]❌ No open ports found.[/bold red]")
