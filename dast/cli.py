import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import typer

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dast.analyzer import (
    build_auto_target_config,
    discover_and_add_json_endpoints,
    extract_parameters_from_url,
)
from dast.crawler import KatanaCrawler, parse_cookies_string
from dast.config import AuthType, EvidenceStrength, EndpointInfo, ScanProfile, ScanReport, TargetConfig
from dast.scanner import load_templates, run_scan
from dast.utils import setup_logging

console = Console()
app = typer.Typer(rich_markup_mode="rich")


def print_banner():
    console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")


def _print_crawl_report(report) -> None:
    console.print("\n[bold]Crawl Results[/bold]\n")

    if hasattr(report, 'summary'):
        summary = report.summary
        console.print(f"[cyan]Total URLs:[/cyan] {summary.get('total', 0)}")
        console.print(f"[cyan]API Endpoints:[/cyan] {summary.get('api', 0)}")
        console.print(f"[cyan]Auth Endpoints:[/cyan] {summary.get('auth', 0)}")
        console.print(f"[cyan]Admin Endpoints:[/cyan] {summary.get('admin', 0)}")
        console.print(f"[cyan]Page Endpoints:[/cyan] {summary.get('page', 0)}")

        if report.cookies:
            console.print(f"\n[dim]Cookies: {', '.join(report.cookies)}[/dim]")

        if report.endpoints:
            console.print("\n[bold]Sample Endpoints:[/bold]")
            for ep in report.endpoints[:10]:
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                ep_type = ep.get("type", "unknown")
                if ep_type == "api":
                    console.print(f"  [cyan]{method}[/cyan] [{ep_type}] {url}")
                elif ep_type == "auth":
                    console.print(f"  [yellow]{method}[/yellow] [{ep_type}] {url}")
                elif ep_type == "admin":
                    console.print(f"  [red]{method}[/red] [{ep_type}] {url}")
                else:
                    console.print(f"  [green]{method}[/green] [{ep_type}] {url}")
            if len(report.endpoints) > 10:
                console.print(f"  ... and {len(report.endpoints) - 10} more")
        return

    stats = report.statistics
    if isinstance(stats, dict):
        total_requests = stats.get("total_requests", 0)
        unique_urls = stats.get("unique_urls", 0)
        api_endpoints = stats.get("api_endpoints", 0)
        forms_discovered = stats.get("forms_discovered", 0)
        js_endpoints = stats.get("javascript_files", 0)
        interesting = stats.get("interesting_endpoints", 0)
        successful = stats.get("successful_requests", 0)
        failed = stats.get("failed_requests", 0)
    else:
        total_requests = stats.total_requests
        unique_urls = stats.unique_urls
        api_endpoints = stats.api_endpoints
        forms_discovered = stats.forms_discovered
        js_endpoints = getattr(stats, "javascript_files", 0)
        interesting = 0
        successful = getattr(stats, "successful_requests", 0)
        failed = getattr(stats, "failed_requests", 0)

    console.print(f"[cyan]Total Requests:[/cyan] {total_requests}")
    console.print(f"[cyan]Unique URLs:[/cyan] {unique_urls}")
    if successful > 0 or failed > 0:
        console.print(f"[cyan]  Success:[/cyan] {successful} | [cyan]Failed:[/cyan] {failed}")
    console.print(f"[cyan]API Endpoints:[/cyan] {api_endpoints}")
    console.print(f"[cyan]Forms Discovered:[/cyan] {forms_discovered}")
    console.print(f"[cyan]JS Files:[/cyan] {js_endpoints}")
    if interesting > 0:
        console.print(f"[yellow]Interesting Endpoints:[/yellow] {interesting} 🎯")

    if report.auth_data:
        console.print("\n[bold]Authentication:[/bold]")
        auth_type = report.auth_data.get("type", "unknown")
        console.print(f"  Type: {auth_type}")
        if report.auth_data.get("jwt_token"):
            console.print(f"  JWT: [dim]{report.auth_data['jwt_token'][:30]}...[/dim]")

    interesting_endpoints = [
        e for e in report.endpoints
        if isinstance(e, dict) and e.get("interesting")
    ]
    if interesting_endpoints:
        console.print("\n[bold yellow]Interesting Endpoints:[/bold yellow]")
        for ep in interesting_endpoints[:10]:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            hints = ep.get("vulnerability_hints", [])
            hints_str = f" | [red]{', '.join(hints)}[/red]" if hints else ""
            console.print(f"  [{method}] {url}{hints_str}")
        if len(interesting_endpoints) > 10:
            console.print(f"  ... and {len(interesting_endpoints) - 10} more")

    if report.forms:
        console.print(f"\n[bold]Forms ({len(report.forms)}):[/bold]")
        for form in report.forms[:5]:
            action = form.get("action", "unknown")
            method = form.get("method", "GET")
            fields = form.get("fields", form.get("form_fields", []))
            console.print(f"  [{method}] {action}")
            if fields:
                field_names = [f.get("name", "?") for f in fields[:3]]
                console.print(f"    Fields: {', '.join(field_names)}")
        if len(report.forms) > 5:
            console.print(f"  ... and {len(report.forms) - 5} more")


def _print_report(report: ScanReport) -> None:
    console.print("\n[bold]Scan Results[/bold]\n")

    if not report.findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    direct = [f for f in report.findings if f.evidence_strength == EvidenceStrength.DIRECT]
    inference = [f for f in report.findings if f.evidence_strength == EvidenceStrength.INFERENCE]
    heuristic = [f for f in report.findings if f.evidence_strength == EvidenceStrength.HEURISTIC]

    if direct:
        console.print("\n[bold green]Direct Observation[/bold green] [dim](we saw it happen)[/dim]")
        _print_findings_table(direct)

    if inference:
        console.print("\n[bold yellow]Inference[/bold yellow] [dim](strong indirect evidence)[/dim]")
        _print_findings_table(inference)

    if heuristic:
        console.print("\n[bold cyan]Heuristic[/bold cyan] [dim](pattern suggests vulnerability)[/dim]")
        _print_findings_table(heuristic)

    console.print("\n[bold]Detailed Findings:[/bold]\n")
    _print_detailed_findings(report.findings)

    console.print("\n[bold]Summary (by OWASP Top 10 2025):[/bold]")
    owasp_summary = report.get_owasp_summary()
    for category, count in owasp_summary.items():
        if count > 0:
            if any(x in category for x in ["A01", "A05", "A07"]):
                color = "red"
            elif any(x in category for x in ["A02", "A03", "A04", "A06"]):
                color = "yellow"
            else:
                color = "green"
            console.print(f"  {category}: [{color}]{count}[/{color}]")
    console.print(f"\n[dim]Duration: {report.duration_seconds:.1f}s | Templates: {report.templates_executed}[/dim]")


def _print_detailed_findings(findings: list) -> None:
    for i, finding in enumerate(findings, 1):
        owasp_category = finding.owasp_category.value
        if any(x in owasp_category for x in ["A01", "A05", "A07"]):
            category_color = "bold red"
        elif any(x in owasp_category for x in ["A02", "A03", "A04", "A06"]):
            category_color = "yellow"
        else:
            category_color = "green"

        details_text = Text()
        details_text.append(f"#{i} ", style="bold")
        details_text.append(f"[{owasp_category}]", style=category_color)
        details_text.append(f" {finding.vulnerability_type}\n", style="bold")

        details_text.append("URL: ", style="dim")
        details_text.append(f"{finding.url}\n", style="cyan")

        if finding.request_details:
            details_text.append("Request: ", style="dim")
            details_text.append(f"{finding.request_details}\n", style="yellow")

        details_text.append("Message: ", style="dim")
        details_text.append(f"{finding.message}\n")

        if finding.remediation:
            details_text.append("Remediation: ", style="dim")
            details_text.append(f"{finding.remediation}\n", style="green")

        if finding.evidence:
            details_text.append("Evidence: ", style="dim")
            for key, value in finding.evidence.items():
                if key not in ("matcher_evidence",):
                    details_text.append(f"{key}={value} ", style="cyan")

        console.print(Panel(details_text, border_style=category_color))
        console.print()


def _print_findings_table(findings: list) -> None:
    table = Table()
    table.add_column("OWASP Category", width=18)
    table.add_column("Type", width=30)
    table.add_column("Evidence", width=15)
    table.add_column("Details", width=50)

    for finding in findings:
        owasp = finding.owasp_category.value
        if any(x in owasp for x in ["A01", "A05", "A07"]):
            owasp_display = f"[bold red]{owasp}[/bold red]"
        elif any(x in owasp for x in ["A02", "A03", "A04", "A06"]):
            owasp_display = f"[yellow]{owasp}[/yellow]"
        else:
            owasp_display = f"[green]{owasp}[/green]"

        evidence = finding.evidence_strength.value.replace("_", " ").title()
        if evidence == "Direct Observation":
            evidence = "[bold green]Direct[/bold green]"
        elif evidence == "Inference":
            evidence = "[yellow]Inference[/yellow]"
        else:
            evidence = "[cyan]Heuristic[/cyan]"

        details = finding.message[:50]
        if finding.response_details:
            details = f"{details} | {finding.response_details[:30]}"

        table.add_row(owasp_display, finding.vulnerability_type[:30], evidence, details[:50])

    console.print(table)


def _save_results(report: ScanReport, output: str) -> None:
    output_path = Path(output)
    results = {
        "target": report.target,
        "templates_executed": report.templates_executed,
        "duration_seconds": report.duration_seconds,
        "findings": [f.model_dump() for f in report.findings],
        "errors": report.errors,
    }

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"\n[green]Results saved to: {output_path}[/green]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authentication"),
    crawl: bool = typer.Option(False, "--crawl", help="Crawl target first to auto-discover endpoints"),
    generic: bool = typer.Option(True, "--generic/--no-generic", help="Include generic templates"),
    app: str = typer.Option(None, "--app", help="Add app-specific templates (juice-shop, ...)"),
    template: str = typer.Option(None, "-T", "--template", help="Test specific template file"),
    template_dir: str = typer.Option(None, "-t", "--template-dir", help="Override templates directory"),
    output: str = typer.Option(None, "-o", "--output", help="Output JSON file for results"),
    profile: str = typer.Option(None, "--profile", help="Scan profile: passive, standard, thorough, aggressive"),
    checkpoint: str = typer.Option(None, "--checkpoint", help="Save scan progress to file"),
    resume: str = typer.Option(None, "--resume", help="Resume scan from checkpoint file"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
    no_validate: bool = typer.Option(False, "--no-validate", help="Skip target connectivity validation"),
    coverage: bool = typer.Option(False, "--coverage", help="Enable code coverage tracking (requires: pip install coverage)"),
):
    async def _scan():
        cov = None
        if coverage:
            if not HAS_COVERAGE:
                console.print("[red]Error: coverage module not installed[/red]")
                console.print("[dim]Install it: pip install coverage[/dim]")
                raise typer.Exit(1)
            cov = coverage_module.Coverage(source=["dast"], omit=["*/tests/*", "*/test_*.py"])
            cov.start()
            console.print("[cyan]Coverage tracking enabled[/cyan]\n")

        setup_logging(verbose=verbose)

        if not verbose:
            print_banner()

        scan_profile = ScanProfile.STANDARD
        if profile:
            try:
                scan_profile = ScanProfile(profile.lower())
                if scan_profile in (ScanProfile.THOROUGH, ScanProfile.AGGRESSIVE):
                    console.print("[yellow]Warning: Thorough/Aggressive profiles may cause delays.[/yellow]")
            except ValueError:
                console.print(f"[red]Invalid profile: {profile}[/red]")
                console.print("[dim]Valid profiles: passive, standard, thorough, aggressive[/dim]")
                raise typer.Exit(1)

        target_config = TargetConfig(name="Target", base_url=target)

        if bearer:
            target_config.authentication.type = AuthType.BEARER
            target_config.authentication.token = bearer

        endpoint_infos = []

        if crawl:
            console.print(f"[cyan]Phase 1: Crawling {target}[/cyan]")
            console.print("[dim]JS Crawl: enabled[/dim]\n")

            crawl_cookies = {}
            if bearer:
                crawl_cookies['token'] = bearer

            crawler = KatanaCrawler(
                base_url=target,
                max_depth=3,
                js_crawl=True,
                cookies=crawl_cookies,
                filter_static=True,
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Discovering endpoints...[/cyan]", total=None)

                try:
                    report = await crawler.crawl()
                    progress.update(task, completed=True)
                except Exception as e:
                    console.print(f"[red]Crawl failed: {e}[/red]")
                    console.print("[dim]Install Katana: go install github.com/projectdiscovery/katana/cmd/katana@latest[/dim]")
                    raise typer.Exit(1)

            console.print(f"[green]Found {len(report.endpoints)} endpoints[/green]")
            console.print(f"[dim]  API: {report.summary.get('api', 0)} | Auth: {report.summary.get('auth', 0)} | Admin: {report.summary.get('admin', 0)}[/dim]")

            for ep in report.endpoints:
                url = ep.get('full_url', ep.get('url', ''))
                if url:
                    params = extract_parameters_from_url(url, ep.get('method', 'GET'))
                    endpoint_infos.append(EndpointInfo(
                        url=url,
                        method=ep.get('method', 'GET'),
                        path=urlparse(url).path,
                        query_params=params,
                        is_api=ep.get('type') == 'api',
                    ))

            try:
                target_config = report.to_target_config(
                    name="crawled_target",
                    prioritize=True,
                    exclude_static=True,
                )
            except Exception as e:
                console.print(f"[red]Failed to generate target config: {e}[/red]")
                raise typer.Exit(1)

            if not target_config.get_endpoints():
                console.print("[yellow]No scanable endpoints found[/yellow]")
                raise typer.Exit(1)

            try:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("[cyan]Discovering JSON injection points...[/cyan]", total=None)
                    await discover_and_add_json_endpoints(target_config, report.endpoints, crawl_cookies)
                    progress.update(task, completed=True)
            except Exception:
                pass

        console.print(f"[dim]Target: {target_config.base_url}[/dim]")
        console.print(f"[dim]Auth: {target_config.authentication.type or 'none'}[/dim]")
        console.print(f"[dim]Endpoints: {len(target_config.get_endpoints())}[/dim]")
        if profile:
            console.print(f"[dim]Profile: {scan_profile.value}[/dim]")

        # Get project root (cli.py is in dast/, so parent.parent is project root)
        project_root = Path(__file__).parent.parent.resolve()

        # Build list of template directories
        template_paths = []

        if template:
            template_path = Path(template).resolve()
            if not template_path.exists():
                console.print(f"[red]Template file not found: {template}[/red]")
                raise typer.Exit(1)
            template_paths = [template_path]
            console.print(f"[cyan]Testing single template: {template_path.name}[/cyan]\n")
        elif template_dir:
            template_paths = [Path(template_dir).resolve()]
        else:
            if generic:
                generic_path = project_root / "templates" / "generic"
                if generic_path.exists():
                    template_paths.append(generic_path)
            if app:
                app_path = project_root / "templates" / "apps" / app
                if app_path.exists():
                    template_paths.append(app_path)

        if not template_paths:
            console.print("[red]No templates found. Use --generic or --app[/red]")
            raise typer.Exit(1)

        templates = load_templates(template_paths)
        if not verbose:
            console.print(f"[dim]Loaded {len(templates)} templates[/dim]\n")

        if not templates:
            console.print("[red]No templates to execute[/red]")
            raise typer.Exit(1)

        if crawl and endpoint_infos:
            auto_endpoints = build_auto_target_config(
                endpoints=endpoint_infos,
                templates=templates,
                base_url=target,
            )

            for var_name, path in auto_endpoints.items():
                if var_name not in target_config.endpoints.custom:
                    target_config.endpoints.custom[var_name] = path

            if auto_endpoints:
                console.print(f"[dim]Auto-mapped {len(auto_endpoints)} endpoint variables[/dim]")

        if crawl:
            console.print("[cyan]Phase 2: Scanning for vulnerabilities[/cyan]\n")
        elif not verbose:
            console.print("[yellow]Scanning...[/yellow]\n")

        checkpoint_file = resume or checkpoint
        if resume:
            console.print(f"[dim]Resuming from checkpoint: {resume}[/dim]\n")

        report = await run_scan(
            target_config,
            templates,
            validate_target=not no_validate,
            scan_profile=scan_profile,
            checkpoint_file=checkpoint_file,
        )

        _print_report(report)

        if output and report.findings:
            _save_results(report, output)

        # Stop coverage and show report
        if cov is not None:
            cov.stop()
            console.print("\n[bold]Code Coverage Report[/bold]\n")
            cov.report(file=open(1, 'w'), show_missing=True)  # Print to stdout
            console.print("\n[dim]Generate HTML report: coverage html[/dim]")
            console.print("[dim]View report: open htmlcov/index.html[/dim]")

        raise typer.Exit(0 if report.findings else 1)

    asyncio.run(_scan())


@app.command()
def crawl(
    target: str = typer.Argument(..., help="Target URL"),
    output: str = typer.Option(None, "-o", "--output", help="Output YAML file for the crawler report"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum crawl depth"),
    js_crawl: bool = typer.Option(False, "--js-crawl", help="Enable JavaScript crawling"),
    cookies: str = typer.Option(None, "--cookies", help="Authentication cookies"),
    no_filter_static: bool = typer.Option(False, "--no-filter-static", help="Don't filter static files"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _crawl():
        setup_logging(verbose=verbose)

        if not verbose:
            print_banner()

        console.print(f"[dim]Target: {target}[/dim]")
        console.print(f"[dim]Max Depth: {max_depth} | JS Crawl: {js_crawl}[/dim]")
        if no_filter_static:
            console.print("[dim]Filter: none (keeping all files)[/dim]")

        parsed_cookies = {}
        if cookies:
            parsed_cookies = parse_cookies_string(cookies)
            console.print(f"[dim]Cookies: {cookies[:50]}...[/dim]")

        console.print()

        crawler = KatanaCrawler(
            base_url=target,
            max_depth=max_depth,
            js_crawl=js_crawl,
            cookies=parsed_cookies,
            filter_static=not no_filter_static,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Crawling with Katana...[/cyan]", total=None)

            try:
                report = await crawler.crawl()
                progress.update(task, completed=True)
            except Exception as e:
                console.print(f"[red]Error during crawling: {e}[/red]")
                console.print("[dim]Install Katana: go install github.com/projectdiscovery/katana/cmd/katana@latest[/dim]")
                raise typer.Exit(1)

        _print_crawl_report(report)

        if output:
            report.save_yaml(output)
            console.print(f"\n[green]Report saved to: {output}[/green]")

    asyncio.run(_crawl())


@app.command()
def list_templates(
    generic: bool = typer.Option(True, "--generic/--no-generic", help="Include generic templates"),
    app: str = typer.Option(None, "--app", help="Add app-specific templates (juice-shop, ...)"),
    template_dir: str = typer.Option(None, "-t", "--template-dir", help="Override templates directory"),
):
    print_banner()

    # Get project root
    project_root = Path(__file__).parent.parent.resolve()

    # Build list of template directories
    template_paths = []

    if template_dir:
        template_paths = [Path(template_dir).resolve()]
    else:
        if generic:
            generic_path = project_root / "templates" / "generic"
            if generic_path.exists():
                template_paths.append(generic_path)
        if app:
            app_path = project_root / "templates" / "apps" / app
            if app_path.exists():
                template_paths.append(app_path)

    if not template_paths:
        console.print("[red]No templates found. Use --generic or --app[/red]")
        raise typer.Exit(1)

    templates = load_templates(template_paths)

    table = Table(title="Available Templates")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Tags")

    for t in templates:
        tags_str = ", ".join(t.info.tags[:3]) if t.info.tags else ""
        # Handle both SeverityLevel enum and string
        severity_value = t.info.severity.value if hasattr(t.info.severity, 'value') else t.info.severity
        table.add_row(
            t.id,
            t.info.name[:40],
            severity_value,
            tags_str,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(templates)} templates[/dim]")


if __name__ == "__main__":
    app()
