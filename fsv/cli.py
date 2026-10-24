"""FSV Command-Line Interface"""

from __future__ import annotations
import asyncio
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

from fsv import __version__, BANNER
from fsv.config import MODULES_ENABLED
from fsv.core.models import ScanConfig, ScanProfile, FindingStatus, normalize_target
from fsv.core import engine, database as db, registry
from fsv.core import report as report_mod
from fsv.core.diff import compare

console = Console()

SEV_COLOR = {
    "critical": "bold red", "high": "orange3", "medium": "yellow",
    "low": "cyan", "info": "grey70",
}
GRADE_COLOR = {"A+": "green", "A": "green", "B": "yellow", "C": "orange3",
               "D": "orange3", "F": "bold red"}


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
@click.option("--profile", type=click.Choice(["passive", "balanced", "aggressive"]),
              default="balanced", help="Scan intensity profile.")
@click.option("--no-crawl", is_flag=True, help="Scan only the given URL, don't crawl.")
@click.option("--max-urls", default=50, help="Maximum URLs to scan.")
@click.option("--depth", default=2, help="Crawl depth.")
@click.option("--threads", default=10, help="Concurrency.")
@click.option("--timeout", default=10, help="Per-request timeout (seconds).")
@click.option("--rate", default=20.0, help="Max requests per second (politeness).")
@click.option("--modules", default="", help="Comma-separated module list (default: all).")
@click.option("--exclude", default="", help="Comma-separated path globs to skip, e.g. /admin/*.")
@click.option("--header", "headers", multiple=True, help="Extra request header 'Name: value' (repeatable).")
@click.option("--cookie", "cookies", multiple=True, help="Request cookie 'name=value' (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Label this scan (repeatable).")
@click.option("--robots", is_flag=True, help="Respect robots.txt disallow rules.")
@click.option("-o", "--output", default="", help="Write report to file (.md/.json/.html/.sarif/.csv).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default=None, help="Exit non-zero if a finding of this severity or worse exists (CI gate).")
@click.option("--quiet", is_flag=True, help="Suppress live progress.")
def scan(target, authorize, profile, no_crawl, max_urls, depth, threads, timeout, rate,
         modules, exclude, headers, cookies, tags, robots, output, fail_on, quiet):
    """Run a vulnerability scan against TARGET."""
    if not authorize:
        console.print(Panel(
            "[bold red]Authorization required.[/]\n\n"
            "FSV may only be used against systems you own or are explicitly\n"
            "authorized to test. Re-run with [bold]--authorize[/] to confirm.",
            title="⚠  Authorization", border_style="red", box=box.ROUNDED,
        ))
        sys.exit(2)

    try:
        target = normalize_target(target)
    except ValueError as exc:
        console.print(f"[red]Invalid target:[/] {exc}")
        sys.exit(2)

    config = ScanConfig(
        target=target,
        modules=[m.strip() for m in modules.split(",") if m.strip()],
        crawl=not no_crawl, max_urls=max_urls, depth=depth, timeout=timeout,
        threads=threads, rate_per_sec=rate, profile=ScanProfile(profile),
        exclude_paths=[p.strip() for p in exclude.split(",") if p.strip()],
        headers=_parse_kv(headers, ":"), cookies=_parse_kv(cookies, "="),
        tags=list(tags), respect_robots=robots,
    )

    console.print(f"\n[bold white]▶ Scanning[/] [cyan]{target}[/]  [grey50]({profile})[/]\n")
    result = asyncio.run(_run_with_progress(config, quiet))

    _print_summary(result)
    _print_findings(result)

    if output:
        fmt = report_mod.format_for_path(output)
        content, _ = report_mod.render(result, fmt)
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[green]✓[/] {fmt.upper()} report written to [bold]{output}[/]")

    console.print(f"\n[grey70]scan_id:[/] [bold]{result.scan_id}[/]")

    if fail_on:
        order = ["info", "low", "medium", "high", "critical"]
        threshold = order.index(fail_on)
        worst = max((order.index(f.severity.value) for f in result.active_findings),
                    default=-1)
        if worst >= threshold:
            console.print(f"\n[red]✗ Gate failed:[/] findings at or above '{fail_on}'.")
            sys.exit(1)


def _parse_kv(items, sep) -> dict[str, str]:
    out = {}
    for raw in items:
        if sep in raw:
            k, v = raw.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


async def _run_with_progress(config, quiet):
    if quiet:
        return await engine.run_scan(config)
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30), TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=100)
        progress.update(task, description="Starting…")
        return await engine.run_scan(
            config, progress_cb=lambda p: progress.update(
                task, completed=p.pct, description=p.message[:48]))


def _print_summary(result):
    t = Table(box=box.ROUNDED, show_header=False, border_style="grey35")
    t.add_column(style="bold"); t.add_column()
    t.add_row("Target", result.target)
    t.add_row("Status", result.status.value + (f"  [red]{result.error}[/]" if result.error else ""))
    gc = GRADE_COLOR.get(result.grade, "white")
    t.add_row("Risk", f"[{gc}]{result.grade}[/]  ({result.risk_score}/100)")
    t.add_row("Duration", f"{result.duration_s:.1f}s")
    t.add_row("URLs scanned", str(result.urls_scanned))
    if result.stats:
        s = result.stats
        t.add_row("Requests", f"{s.get('requests',0)} "
                  f"({s.get('cache_hits',0)} cached, {s.get('coalesced',0)} shared, "
                  f"{s.get('errors',0)} err, {s.get('avg_latency_ms',0)}ms avg)")
    if result.tech_stack:
        t.add_row("Tech stack", ", ".join(result.tech_stack))
    if result.module_errors:
        t.add_row("Module errors", ", ".join(f"{m}×{n}" for m, n in result.module_errors.items()))
    console.print(t)

    counts = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    for s in ("critical", "high", "medium", "low", "info"):
        counts.add_column(s.upper(), justify="center")
    c = result.counts()
    counts.add_row(
        f"[bold red]{c['critical']}[/]", f"[orange3]{c['high']}[/]",
        f"[yellow]{c['medium']}[/]", f"[cyan]{c['low']}[/]", f"[grey70]{c['info']}[/]")
    console.print(counts)
    if c["suppressed"]:
        console.print(f"[grey50]({c['suppressed']} finding(s) triaged out of the score)[/]")


def _print_findings(result):
    active = result.active_findings
    if not active:
        console.print("\n[green]✓ No findings that count toward risk.[/]\n")
        return
    console.print("\n[bold]Findings[/]\n")
    for i, f in enumerate(active, 1):
        color = SEV_COLOR.get(f.severity.value, "white")
        console.print(f"{i:>2}. [{color}]{f.severity.value.upper():>8}[/]  [bold]{f.title}[/]")
        meta = f"[grey50]{f.url}"
        if len(f.affected_urls) > 1:
            meta += f"  (+{len(f.affected_urls)-1} more)"
        if f.parameter:
            meta += f"  · param={f.parameter}"
        if f.cwe:
            meta += f"  · {f.cwe}"
        if f.owasp:
            meta += f"  · {f.owasp}"
        meta += f"  · {f.confidence.value}[/]"
        console.print(f"    {meta}")


@cli.command("list")
@click.option("--limit", default=20)
@click.option("--target", default=None, help="Filter by host substring.")
def list_scans(limit, target):
    """List recent scans."""
    scans = asyncio.run(db.list_scans(limit=limit, target=target))
    if not scans:
        console.print("[grey70]No scans yet.[/]")
        return
    t = Table(box=box.ROUNDED, border_style="grey35")
    t.add_column("scan_id", style="dim"); t.add_column("target")
    t.add_column("grade", justify="center")
    t.add_column("C", justify="center"); t.add_column("H", justify="center")
    t.add_column("M", justify="center"); t.add_column("status")
    t.add_column("when", style="grey50")
    for s in scans:
        c = s["counts"]; g = s["grade"]
        t.add_row(
            s["scan_id"][:8], s["target"],
            f"[{GRADE_COLOR.get(g,'white')}]{g}[/]",
            f"[red]{c['critical']}[/]", f"[orange3]{c['high']}[/]",
            f"[yellow]{c['medium']}[/]", s["status"], (s["started_at"] or "")[:19].replace("T", " "))
    console.print(t)


@cli.command()
@click.argument("scan_id")
@click.option("--format", "fmt", type=click.Choice(list(report_mod.FORMATS)), default="md")
@click.option("-o", "--output", default="", help="Write to file instead of stdout.")
def report(scan_id, fmt, output):
    """Print or write the report for a scan (md/json/html/sarif/csv)."""
    result = asyncio.run(db.get_scan(scan_id))
    if result is None:
        console.print("[red]Scan not found.[/]")
        sys.exit(1)
    content, _ = report_mod.render(result, fmt)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[green]✓[/] written to [bold]{output}[/]")
    else:
        click.echo(content)


@cli.command()
@click.argument("baseline_id")
@click.argument("current_id")
def diff(baseline_id, current_id):
    """Compare two scans (resolved / new / persisted findings)."""
    a = asyncio.run(db.get_scan(baseline_id))
    b = asyncio.run(db.get_scan(current_id))
    if a is None or b is None:
        console.print("[red]One or both scans not found.[/]")
        sys.exit(1)
    d = compare(a, b)
    vc = {"improved": "green", "regressed": "bold red", "unchanged": "yellow"}[d["verdict"]]
    console.print(Panel(
        f"[{vc}]{d['verdict'].upper()}[/]  risk {d['baseline']['risk_score']} → "
        f"{d['current']['risk_score']}  (Δ {d['risk_delta']:+d})\n"
        f"[green]{d['counts']['resolved']} resolved[/] · "
        f"[red]{d['counts']['new']} new[/] · "
        f"[grey70]{d['counts']['persisted']} persisted[/]",
        title="Scan diff", border_style="grey35", box=box.ROUNDED))
    for label, color, items in (("Resolved", "green", d["resolved"]),
                                ("New", "red", d["new"])):
        if items:
            console.print(f"\n[{color}]{label}:[/]")
            for f in items:
                console.print(f"  [{SEV_COLOR.get(f['severity'],'white')}]{f['severity']:>8}[/]  {f['title']}")


@cli.command()
@click.argument("scan_id")
@click.argument("finding_id")
@click.argument("status", type=click.Choice([s.value for s in FindingStatus]))
@click.option("--note", default="", help="Reason / context for this decision.")
def triage(scan_id, finding_id, status, note):
    """Mark a finding (confirmed / false_positive / accepted_risk / fixed / open).

    The decision is stored per host by fingerprint, so it carries to future scans.
    """
    result = asyncio.run(db.get_scan(scan_id))
    if result is None:
        console.print("[red]Scan not found.[/]"); sys.exit(1)
    match = [f for f in result.findings if f.id == finding_id or f.fingerprint == finding_id]
    if not match:
        console.print(f"[red]No finding '{finding_id}' in this scan.[/]"); sys.exit(1)
    f = match[0]
    asyncio.run(db.set_triage(db.host_of(result.target), f.fingerprint,
                              FindingStatus(status), note))
    console.print(f"[green]✓[/] '{f.title}' → [bold]{status}[/] for host "
                  f"[cyan]{db.host_of(result.target)}[/]")


@cli.command()
@click.argument("scan_id")
def findings(scan_id):
    """List findings with their IDs (for use with `fsv triage`)."""
    result = asyncio.run(db.get_scan(scan_id))
    if result is None:
        console.print("[red]Scan not found.[/]"); sys.exit(1)
    t = Table(box=box.ROUNDED, border_style="grey35")
    t.add_column("id", style="dim"); t.add_column("sev"); t.add_column("title")
    t.add_column("status", style="grey50")
    for f in result.findings:
        t.add_row(f.id, f"[{SEV_COLOR.get(f.severity.value,'white')}]{f.severity.value}[/]",
                  f.title, f.status.value)
    console.print(t)


@cli.command()
@click.option("--keep", default=None, type=int, help="Keep only the newest N scans.")
@click.option("--id", "scan_id", default=None, help="Delete one scan by id.")
@click.confirmation_option(prompt="Delete scans from the local database?")
def prune(keep, scan_id):
    """Delete scan history from the local database."""
    if scan_id:
        ok = asyncio.run(db.delete_scan(scan_id))
        console.print("[green]✓ deleted[/]" if ok else "[red]not found[/]")
    elif keep is not None:
        n = asyncio.run(db.prune_scans(keep))
        console.print(f"[green]✓[/] removed {n} scan(s), kept newest {keep}.")
    else:
        console.print("[yellow]Specify --keep N or --id <scan_id>.[/]")


@cli.command()
@click.option("--json", "as_json", is_flag=True)
def modules(as_json):
    """List available scan modules with category and scope."""
    mods = registry.describe()
    if as_json:
        import json as _j
        click.echo(_j.dumps(mods, indent=2)); return
    t = Table(box=box.ROUNDED, border_style="grey35")
    t.add_column("module", style="bold cyan"); t.add_column("scope")
    t.add_column("category"); t.add_column("on", justify="center")
    t.add_column("checks", style="grey70")
    for m in mods:
        cat_color = "yellow" if m["category"] == "active" else "green"
        t.add_row(m["name"], m["scope"], f"[{cat_color}]{m['category']}[/]",
                  "[green]✓[/]" if MODULES_ENABLED.get(m["name"], True) else "[grey50]✗[/]",
                  m["description"])
    console.print(t)
    console.print(f"\n[grey50]{len(mods)} modules · "
                  f"{sum(1 for m in mods if m['category']=='active')} active, "
                  f"{sum(1 for m in mods if m['category']=='passive')} passive[/]")


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
