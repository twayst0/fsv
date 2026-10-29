"""FSV Command-Line Interface"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

from fsv import __version__, BANNER
from fsv.config import MODULES_ENABLED, WEBHOOK_URL_ENV
from fsv.core.models import ScanConfig, ScanProfile, FindingStatus, normalize_target
from fsv.core import engine, database as db, registry
from fsv.core import report as report_mod
from fsv.core.diff import compare
from fsv.core import baseline as baseline_mod
from fsv.core import fixes as fixes_mod
from fsv.core import settings as settings_mod

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


_ORDER = ["info", "low", "medium", "high", "critical"]


@cli.command()
@click.argument("target")
@click.option("--authorize", is_flag=True,
              help="Confirm you own or are authorized to test this target (REQUIRED).")
@click.option("--config", "config_path", default=None, type=click.Path(dir_okay=False),
              help="Settings file (default: ./fsv.toml if present). Flags override it.")
@click.option("--profile", type=click.Choice(["passive", "balanced", "aggressive", "deep", "full"]),
              default="balanced",
              help="Scan intensity. deep = wider crawl, hidden-parameter discovery, larger file list, more payload shapes. "
                   "full = everything in deep, then exhaustive: 1000+ URLs, ~600 guessed paths, backup copies, boolean SQLi (slowest).")
@click.option("--no-crawl", is_flag=True, help="Scan only the given URL, don't crawl.")
@click.option("--max-urls", default=50, help="Maximum URLs to scan.")
@click.option("--depth", default=2, help="Crawl depth.")
@click.option("--threads", default=10, help="Concurrency.")
@click.option("--timeout", default=10, help="Per-request timeout (seconds).")
@click.option("--rate", default=20.0, help="Max requests per second (politeness).")
@click.option("--modules", default="", help="Comma-separated module list (default: all).")
@click.option("--exclude", default="", help="Comma-separated path globs to skip, e.g. /admin/*.")
@click.option("--seed", "seeds", multiple=True,
              help="Extra same-origin path or URL to start crawling from, e.g. /app/dashboard (repeatable).")
@click.option("--proxy", default="",
              help="Send requests through an HTTP(S) proxy: http://host:port, or 'env' for HTTPS_PROXY.")
@click.option("--header", "headers", multiple=True, help="Extra request header 'Name: value' (repeatable).")
@click.option("--cookie", "cookies", multiple=True, help="Request cookie 'name=value' (repeatable).")
@click.option("--tag", "tags", multiple=True, help="Label this scan (repeatable).")
@click.option("--robots", is_flag=True, help="Respect robots.txt disallow rules.")
@click.option("--max-time", default=0, help="Stop after N seconds and keep partial results (0 = no limit).")
@click.option("--ct-logs", is_flag=True,
              help="Also query Certificate Transparency logs (crt.sh) for subdomains. "
                   "Sends the domain name to a third party.")
@click.option("--no-external", is_flag=True,
              help="Skip modules that contact hosts other than the target (takeover, cloud storage).")
@click.option("--notify", "notify_url", default="", metavar="URL",
              help="POST a summary to this webhook (Slack/Discord/own endpoint) if the scan finds high+ issues. "
                   "Same as FSV_WEBHOOK_URL; severity floor via FSV_WEBHOOK_MIN_SEVERITY.")
@click.option("--baseline", "baseline_path", default=None, type=click.Path(dir_okay=False),
              help="Known-findings file; only NEW findings count for --fail-on.")
@click.option("--write-baseline", default=None, type=click.Path(dir_okay=False),
              help="Write this scan's findings as a baseline file.")
@click.option("-o", "--output", default="", help="Write report to file (.md/.json/.html/.sarif/.csv).")
@click.option("--fail-on", type=click.Choice(_ORDER), default=None,
              help="Exit 1 if a finding of this severity or worse exists (CI gate; with --baseline: new ones only).")
@click.option("--quiet", is_flag=True, help="Suppress live progress.")
@click.option("-v", "--verbose", is_flag=True, help="Log module errors and engine details to stderr.")
@click.pass_context
def scan(ctx, target, authorize, config_path, profile, no_crawl, max_urls, depth, threads, timeout, rate,
         modules, exclude, seeds, proxy, headers, cookies, tags, robots, max_time, ct_logs, no_external,
         notify_url, baseline_path, write_baseline, output, fail_on, quiet, verbose):
    """Run a vulnerability scan against TARGET."""
    # -v turns on FSV's own debug logging only — never the DEBUG firehose of third-party libraries
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    logging.getLogger("fsv").setLevel(logging.DEBUG if verbose else logging.WARNING)
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
    # settings file: applies only to options the user did NOT pass explicitly
    cfg_file = config_path or settings_mod.find_default()
    if cfg_file:
        try:
            file_cfg = settings_mod.load_scan_config(cfg_file)
        except (settings_mod.ConfigError, OSError) as exc:
            console.print(f"[red]Config error:[/] {exc}")
            sys.exit(2)

        def given(name: str) -> bool:
            return ctx.get_parameter_source(name).name != "DEFAULT"

        profile  = profile  if given("profile")  else file_cfg.get("profile", profile)
        max_urls = max_urls if given("max_urls") else file_cfg.get("max_urls", max_urls)
        depth    = depth    if given("depth")    else file_cfg.get("depth", depth)
        threads  = threads  if given("threads")  else file_cfg.get("threads", threads)
        timeout  = timeout  if given("timeout")  else file_cfg.get("timeout", timeout)
        rate     = rate     if given("rate")     else file_cfg.get("rate", rate)
        max_time = max_time if given("max_time") else file_cfg.get("max_time", max_time)
        fail_on  = fail_on  if given("fail_on")  else file_cfg.get("fail_on", fail_on)
        baseline_path = baseline_path if given("baseline_path") else file_cfg.get("baseline", baseline_path)
        no_crawl = no_crawl or (file_cfg.get("crawl") is False)
        robots   = robots   or bool(file_cfg.get("robots"))
        ct_logs  = ct_logs  or bool(file_cfg.get("ct_logs"))
        no_external = no_external or (file_cfg.get("external") is False)
        if not modules and file_cfg.get("modules"):
            modules = ",".join(file_cfg["modules"])
        if not exclude and file_cfg.get("exclude"):
            exclude = ",".join(file_cfg["exclude"])
        tags = tuple(tags) + tuple(file_cfg.get("tags", []))
        seeds = tuple(seeds) + tuple(file_cfg.get("seeds", []))
        proxy = proxy or file_cfg.get("proxy", "")
        notify_url = notify_url or file_cfg.get("notify", "")
        file_headers, file_cookies = file_cfg.get("headers", {}), file_cfg.get("cookies", {})
    else:
        file_headers, file_cookies = {}, {}

    baseline = None
    if baseline_path:
        try:
            baseline = baseline_mod.load_baseline(baseline_path)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Baseline error:[/] {exc}")
            sys.exit(2)

    if notify_url:
        os.environ[WEBHOOK_URL_ENV] = notify_url

    config = ScanConfig(
        target=target,
        modules=[m.strip() for m in modules.split(",") if m.strip()],
        crawl=not no_crawl, max_urls=max_urls, depth=depth, timeout=timeout,
        threads=threads, rate_per_sec=rate, profile=ScanProfile(profile),
        exclude_paths=[p.strip() for p in exclude.split(",") if p.strip()],
        seed_urls=[s.strip() for s in seeds if s.strip()], proxy=proxy,
        headers={**file_headers, **_parse_kv(headers, ":")},
        cookies={**file_cookies, **_parse_kv(cookies, "=")},
        tags=list(tags), respect_robots=robots, max_duration=max_time,
        use_ct_logs=ct_logs, allow_external=not no_external,
    )

    console.print(f"\n[bold white]▶ Scanning[/] [cyan]{target}[/]  [grey50]({profile})[/]"
                  + (f"  [grey50]config: {cfg_file}[/]" if cfg_file else "") + "\n")
    result = asyncio.run(_run_with_progress(config, quiet))

    _print_summary(result)
    _print_findings(result)
    st = result.stats or {}
    if st.get("requests") and not st.get("responses"):
        console.print("\n[bold yellow]⚠ No HTTP response was received from the target.[/] "
                      "Results only reflect checks that don't need HTTP (e.g. DNS). "
                      "Check the URL, network/proxy, or try --timeout.")

    if output:
        fmt = report_mod.format_for_path(output)
        content, _ = report_mod.render(result, fmt)
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[green]✓[/] {fmt.upper()} report written to [bold]{output}[/]")

    if write_baseline:
        with open(write_baseline, "w", encoding="utf-8") as f:
            json.dump(baseline_mod.make_baseline(result), f, indent=2)
        console.print(f"[green]✓[/] baseline of {len(result.active_findings)} finding(s) written to "
                      f"[bold]{write_baseline}[/]")

    console.print(f"\n[grey70]scan_id:[/] [bold]{result.scan_id}[/]")

    gated = result.active_findings
    if baseline is not None:
        if baseline_mod.host_mismatch(result, baseline):
            console.print("[yellow]⚠ The baseline was written for a different host — nothing will match.[/]")
        gated, known = baseline_mod.split_new(result, baseline)
        console.print(f"[grey70]baseline:[/] {len(known)} known finding(s) ignored, "
                      f"[bold]{len(gated)} new[/]")
    if fail_on:
        threshold = _ORDER.index(fail_on)
        offenders = [f for f in gated if _ORDER.index(f.severity.value) >= threshold]
        if offenders:
            console.print(f"\n[red]✗ Gate failed:[/] {len(offenders)} "
                          f"{'new ' if baseline is not None else ''}finding(s) at or above '{fail_on}':")
            for f in offenders[:10]:
                console.print(f"   [{SEV_COLOR[f.severity.value]}]{f.severity.value:>8}[/]  {f.title}")
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
        t.add_row("Requests", f"{s.get('requests',0)} sent · {s.get('responses',0)} answered "
                  f"({s.get('cache_hits',0)} cached, {s.get('coalesced',0)} shared, "
                  f"{s.get('errors',0)} failed, {s.get('avg_latency_ms',0)}ms avg)")
    if result.tech_stack:
        t.add_row("Tech stack", ", ".join(result.tech_stack))
    if result.module_errors:
        t.add_row("Module errors", "\n".join(
            f"[yellow]{m}[/]×{n}: [grey62]{result.module_error_samples.get(m, '')[:90]}[/]"
            for m, n in result.module_errors.items()))
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
@click.argument("status", type=click.Choice([s.value for s in FindingStatus.user_settable()]))
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
    t.add_column("category"); t.add_column("ext", justify="center", style="grey62")
    t.add_column("on", justify="center")
    t.add_column("checks", style="grey70")
    for m in mods:
        cat_color = "yellow" if m["category"] == "active" else "green"
        src = "" if m.get("source") == "builtin" else f" [magenta]({m['source']})[/]"
        t.add_row(m["name"], m["scope"], f"[{cat_color}]{m['category']}[/]",
                  "↗" if m.get("external") else "",
                  "[green]✓[/]" if MODULES_ENABLED.get(m["name"], True) else "[grey50]✗[/]",
                  m["description"] + src)
    console.print(t)
    console.print("[grey50]↗ = contacts hosts other than the target (skip with --no-external)[/]")
    for err in registry.plugin_errors():
        console.print(f"[yellow]plugin skipped:[/] {err}")
    console.print(f"\n[grey50]{len(mods)} modules · "
                  f"{sum(1 for m in mods if m['category']=='active')} active, "
                  f"{sum(1 for m in mods if m['category']=='passive')} passive[/]")


@cli.command()
@click.argument("scan_id")
@click.argument("server", type=click.Choice(list(fixes_mod.SERVERS)))
@click.option("-o", "--output", default="", help="Write to a file instead of stdout.")
def fixes(scan_id, server, output):
    """Generate paste-ready fixes (nginx/apache/caddy/express/dns) for a scan's findings."""
    result = asyncio.run(db.get_scan(scan_id))
    if result is None:
        console.print("[red]Scan not found.[/]"); sys.exit(1)
    content = fixes_mod.generate(result, server)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[green]✓[/] written to [bold]{output}[/]")
    else:
        click.echo(content)


@cli.command()
@click.argument("scan_id")
@click.option("-o", "--output", default="fsv-badge.svg", show_default=True, help="Where to write the SVG.")
def badge(scan_id, output):
    """Write a dated security-grade badge (SVG) for a scan, for your README."""
    from fsv.core import badge as badge_mod
    result = asyncio.run(db.get_scan(scan_id))
    if result is None:
        console.print("[red]Scan not found.[/]"); sys.exit(1)
    with open(output, "w", encoding="utf-8") as f:
        f.write(badge_mod.render(result))
    console.print(f"[green]✓[/] {output}  —  grade {result.grade}. Add to your README:\n"
                  f"  ![FSV security]({output})\n"
                  "[dim]Re-scan and regenerate it regularly (e.g. in CI): the badge shows the scan date.[/]")


@cli.command()
@click.argument("host")
@click.option("--check", is_flag=True, help="Look for the published proof now and record it if found.")
def verify(host, check):
    """Prove you control HOST (needed for active scans when FSV_REQUIRE_VERIFICATION=1)."""
    from fsv.core import ownership
    host = host.split("://", 1)[-1].split("/", 1)[0].lower()
    secret = asyncio.run(db.get_install_secret())
    info = ownership.instructions(host.split(":")[0], secret)
    if not check:
        console.print(Panel(
            f"[bold]Prove you control[/] [cyan]{host}[/]\n\n"
            f"[bold]Option 1 — DNS[/] (covers {info['dns']['covers']})\n"
            f"  TXT  [green]{info['dns']['name']}[/]  =  [green]\"{info['dns']['value']}\"[/]\n\n"
            f"[bold]Option 2 — HTTP[/] (covers {info['http']['covers']})\n"
            f"  serve [green]{info['http']['url']}[/]\n  containing [green]{info['http']['body']}[/]\n\n"
            f"Then run:  [bold]fsv verify {host} --check[/]",
            title="Ownership verification", border_style="grey35", box=box.ROUNDED))
        return
    method = asyncio.run(ownership.check_proof(host.split(":")[0], secret, netloc=host))
    if not method:
        console.print("[red]✗ No proof found yet.[/] DNS changes can take a few minutes to propagate.")
        sys.exit(1)
    asyncio.run(db.add_verified(
        ownership.verification_domain(host.split(":")[0]) if method == "dns" else host.split(":")[0], method))
    console.print(f"[green]✓ Verified[/] [cyan]{host}[/] via {method.upper()} "
                  f"(valid {ownership.VALID_DAYS} days).")


@cli.command()
def doctor():
    """Check the environment: Python, dependencies, database, DNS, plugins."""
    import importlib, platform, os
    ok = lambda m: console.print(f"[green]✓[/] {m}")
    bad = lambda m: console.print(f"[red]✗[/] {m}")
    warn = lambda m: console.print(f"[yellow]![/] {m}")
    console.print(f"[bold]FSV {__version__}[/] · Python {platform.python_version()} · {platform.system()}")
    (ok if sys.version_info >= (3, 11) else bad)(f"Python ≥ 3.11 (have {platform.python_version()})")
    for mod in ("aiohttp", "fastapi", "aiosqlite", "bs4", "lxml", "dns", "cryptography", "tldextract", "mcp"):
        try:
            importlib.import_module(mod); ok(f"import {mod}")
        except Exception as exc:
            bad(f"import {mod}: {exc}")
    try:
        asyncio.run(db.init_db()); ok(f"database writable: {db._db_path()}")
    except Exception as exc:
        bad(f"database: {exc}")
    from fsv.core import dnsutil
    a = dnsutil.resolve("example.com", "A", 3.0)
    (ok if a.ok else warn)("DNS resolution works" if a.ok else
                           f"DNS lookup of example.com returned '{a.status}' — DNS modules need working DNS")
    from fsv.config import BLOCK_PRIVATE, API_TOKEN
    ok(f"outbound policy: metadata/link-local always blocked; private ranges "
       f"{'BLOCKED (FSV_BLOCK_PRIVATE)' if BLOCK_PRIVATE else 'allowed (set FSV_BLOCK_PRIVATE=1 for shared deployments)'}")
    (ok if API_TOKEN else warn)("dashboard token set" if API_TOKEN else
                                "FSV_TOKEN not set — fine on loopback, required if exposed")
    env_proxy = next((os.environ[k] for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
                      if os.environ.get(k)), "")
    if env_proxy:
        warn("a proxy is configured in the environment — FSV connects directly unless you pass "
             "--proxy env (or proxy = \"env\" in fsv.toml)")
    errs = registry.plugin_errors()
    ok(f"{len(registry.load_registry())} modules loaded")
    for e in errs:
        warn(f"plugin skipped: {e}")


@cli.command()
def web():
    """Launch the web dashboard."""
    from fsv.web.app import run as run_web
    run_web()


@cli.command("mcp-config")
@click.option("--client", type=click.Choice(["claude-code", "claude-desktop", "cursor", "vscode", "json"]),
              default="json", help="Print the snippet for this MCP client.")
def mcp_config(client):
    """Print ready-to-paste MCP configuration for Claude Code, Claude Desktop, Cursor or VS Code."""
    import json as _json
    import shutil
    cmd = shutil.which("fsv-mcp") or "fsv-mcp"
    entry = {"command": cmd}
    if client == "claude-code":
        click.echo(f"claude mcp add fsv -- {cmd}")
        return
    if client == "vscode":
        click.echo("# .vscode/mcp.json")
        click.echo(_json.dumps({"servers": {"fsv": {"type": "stdio", **entry}}}, indent=2))
        return
    where = {"claude-desktop": "# Claude Desktop → Settings → Developer → Edit Config (claude_desktop_config.json)",
             "cursor": "# ~/.cursor/mcp.json"}.get(client)
    if where:
        click.echo(where)
    click.echo(_json.dumps({"mcpServers": {"fsv": entry}}, indent=2))
    if client == "json":
        click.echo("\n# Then ask your assistant:  \"Use the security_review prompt on https://my-site.example\"",
                   err=True)


@cli.command("mcp")
def mcp_cmd():
    """Run the MCP server (stdio)."""
    from fsv.mcp.server import run as run_mcp
    run_mcp()


if __name__ == "__main__":
    cli()
