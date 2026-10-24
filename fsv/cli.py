"""FSV Command-Line Interface"""

from __future__ import annotations
import asyncio
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

from fsv import __version__, BANNER
from fsv.config import MODULES_ENABLED
from fsv.core.models import ScanConfig
from fsv.core import engine, database as db
from fsv.core.report import generate_markdown, generate_json

console = Console()

SEV_COLOR = {
    "critical": "bold red",
    "high":     "orange3",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "grey70",
}


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="FSV")
@click.pass_context
def cli(ctx):
    """FSV — Web Vulnerability Scanner & MCP Security Toolkit."""
    if ctx.invoked_subcommand is None:
        console.print(f"[bold white]{BANNER}[/]")
        console.print(ctx.get_help())


@cli.command()
@click.argument("target")
@click.option("--authorize", is_flag=True,
              help="Confirm you own or are authorized to test this target (REQUIRED).")
@click.option("--profile", type=click.Choice(["passive","balanced","aggressive"]),
              default="balanced", help="Scan intensity profile.")
@click.option("--no-crawl", is_flag=True, help="Scan only the given URL, don't crawl.")
@click.option("--max-urls", default=50, help="Maximum URLs to scan.")
@click.option("--depth", default=2, help="Crawl depth.")
@click.option("--threads", default=10, help="Concurrency.")
@click.option("--timeout", default=10, help="Per-request timeout (seconds).")
@click.option("--modules", default="", help="Comma-separated module list (default: all).")
@click.option("-o", "--output", default="", help="Write report to file (.md or .json).")
@click.option("--quiet", is_flag=True, help="Suppress live progress.")
def scan(target, authorize, profile, no_crawl, max_urls, depth, threads, timeout, modules, output, quiet):
    """Run a vulnerability scan against TARGET."""
    if not authorize:
        console.print(Panel(
            "[bold red]Authorization required.[/]\n\n"
            "FSV may only be used against systems you own or are explicitly\n"
            "authorized to test. Re-run with [bold]--authorize[/] to confirm.",
            title="⚠  Authorization", border_style="red", box=box.ROUNDED,
        ))
        sys.exit(1)

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    mod_list = [m.strip() for m in modules.split(",") if m.strip()] if modules else []

    from fsv.core.models import ScanProfile
    config = ScanConfig(
        target=target, modules=mod_list, crawl=not no_crawl,
        max_urls=max_urls, depth=depth, timeout=timeout, threads=threads,
        profile=ScanProfile(profile),
    )

    console.print(f"\n[bold white]▶ Scanning[/] [cyan]{target}[/]\n")

    result = asyncio.run(_run_with_progress(config, quiet))

    _print_summary(result)
    _print_findings(result)

    if output:
        content = generate_json(result) if output.endswith(".json") else generate_markdown(result)
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[green]✓[/] Report written to [bold]{output}[/]")

    console.print(f"\n[grey70]scan_id:[/] [bold]{result.scan_id}[/]")


async def _run_with_progress(config, quiet):
    if quiet:
        return await engine.run_scan(config)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
        console=console, transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=100)

        def cb(p):
            progress.update(task, completed=p.pct, description=p.message[:50])

        return await engine.run_scan(config, progress_cb=cb)


def _print_summary(result):
    t = Table(box=box.ROUNDED, show_header=False, border_style="grey35")
    t.add_column(style="bold"); t.add_column()
    t.add_row("Target", result.target)
    t.add_row("Status", result.status.value)
    grade_color = {"A+":"green","A":"green","B":"yellow","C":"orange3","D":"orange3","F":"bold red"}.get(result.grade,"white")
    t.add_row("Risk", f"[{grade_color}]{result.grade}[/]  ({result.risk_score}/100)")
    t.add_row("Duration", f"{result.duration_s:.1f}s")
    t.add_row("URLs scanned", str(result.urls_scanned))
    if result.stats:
        s = result.stats
        t.add_row("Requests", f"{s.get('requests',0)} ({s.get('cache_hits',0)} cached, {s.get('errors',0)} err)")
    if result.tech_stack:
        t.add_row("Tech stack", ", ".join(result.tech_stack))
    console.print(t)

    counts = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    for s in ("critical","high","medium","low","info"):
        counts.add_column(s.upper(), justify="center")
    counts.add_row(
        f"[bold red]{result.critical_count}[/]",
        f"[orange3]{result.high_count}[/]",
        f"[yellow]{result.medium_count}[/]",
        f"[cyan]{result.low_count}[/]",
        f"[grey70]{result.info_count}[/]",
    )
    console.print(counts)


def _print_findings(result):
    if not result.findings:
        console.print("\n[green]✓ No findings.[/]\n")
        return
    console.print("\n[bold]Findings[/]\n")
    for i, f in enumerate(result.findings, 1):
        color = SEV_COLOR.get(f.severity.value, "white")
        head = f"[{color}]{f.severity.value.upper():>8}[/]  [bold]{f.title}[/]"
        meta = f"[grey50]{f.url}"
        if f.parameter:
            meta += f"  · param={f.parameter}"
        if f.cwe:
            meta += f"  · {f.cwe}"
        meta += "[/]"
        console.print(f"{i:>2}. {head}")
        console.print(f"    {meta}")


@cli.command("list")
@click.option("--limit", default=20)
def list_scans(limit):
    """List recent scans."""
    scans = asyncio.run(db.list_scans(limit=limit))
    if not scans:
        console.print("[grey70]No scans yet.[/]")
        return
    t = Table(box=box.ROUNDED, border_style="grey35")
    t.add_column("scan_id", style="dim"); t.add_column("target")
    t.add_column("C", justify="center"); t.add_column("H", justify="center")
    t.add_column("M", justify="center"); t.add_column("status")
    for s in scans:
        c = s["counts"]
        t.add_row(
            s["scan_id"][:8], s["target"],
            f"[red]{c['critical']}[/]", f"[orange3]{c['high']}[/]",
            f"[yellow]{c['medium']}[/]", s["status"],
        )
    console.print(t)


@cli.command()
@click.argument("scan_id")
@click.option("--json", "as_json", is_flag=True, help="Output JSON instead of Markdown.")
def report(scan_id, as_json):
    """Print the full report for a scan."""
    result = asyncio.run(db.get_scan(scan_id))
    if result is None:
        console.print("[red]Scan not found.[/]")
        sys.exit(1)
    content = generate_json(result) if as_json else generate_markdown(result)
    click.echo(content)


@cli.command()
def modules():
    """List available scan modules."""
    t = Table(box=box.ROUNDED, border_style="grey35")
    t.add_column("module", style="bold cyan"); t.add_column("enabled", justify="center")
    for m, enabled in MODULES_ENABLED.items():
        t.add_row(m, "[green]✓[/]" if enabled else "[grey50]✗[/]")
    console.print(t)


@cli.command()
def web():
    """Launch the web dashboard."""
    from fsv.web.app import run as run_web
    run_web()


@cli.command("mcp")
def mcp_cmd():
    """Run the MCP server (stdio)."""
    from fsv.mcp.server import run as run_mcp
    run_mcp()


if __name__ == "__main__":
    cli()
