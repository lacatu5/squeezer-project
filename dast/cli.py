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
from dast.crawler import KatanaCrawler
from dast.config import AuthType, EvidenceStrength, EndpointInfo, ScanProfile, ScanReport, TargetConfig
from dast.scanner import load_templates, run_scan
from dast.utils import setup_logging

console = Console()
app = typer.Typer(rich_markup_mode="rich")


def print_banner():
    console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")


def _print_report(report: ScanReport) -> None:
    console.print("\n[bold]Scan Results[/bold]\n")

    if not report.findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    grouped_findings = report.group_similar_findings()
    
    direct = [f for f in grouped_findings if f.evidence_strength == EvidenceStrength.DIRECT]
    inference = [f for f in grouped_findings if f.evidence_strength == EvidenceStrength.INFERENCE]
    heuristic = [f for f in grouped_findings if f.evidence_strength == EvidenceStrength.HEURISTIC]

    total_findings = len(report.findings)
    unique_findings = len(grouped_findings)
    
    if total_findings != unique_findings:
        console.print(f"[dim]Grouped {total_findings} findings into {unique_findings} unique vulnerabilities[/dim]\n")

    if direct:
        console.print("[bold green]Direct Observation[/bold green] [dim](we saw it happen)[/dim]")
        _print_findings_table(direct)

    if inference:
        console.print("\n[bold yellow]Inference[/bold yellow] [dim](strong indirect evidence)[/dim]")
        _print_findings_table(inference)

    if heuristic:
        console.print("\n[bold cyan]Heuristic[/bold cyan] [dim](pattern suggests vulnerability)[/dim]")
        _print_findings_table(heuristic)

    console.print("\n[bold]Detailed Findings:[/bold]\n")
    _print_detailed_findings(grouped_findings)

    console.print("\n[bold]Summary (by OWASP Top 10 2025):[/bold]")
    owasp_summary = report.get_owasp_summary()
    for category, (template_count, vuln_count) in owasp_summary.items():
        if vuln_count > 0:
            if any(x in category for x in ["A01", "A05", "A07"]):
                color = "red"
            elif any(x in category for x in ["A02", "A03", "A04", "A06"]):
                color = "yellow"
            else:
                color = "green"
            console.print(f"  {category}: [{color}]{template_count}:{vuln_count}[/{color}]")
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
        details_text.append(f"{finding.message}")
        if finding.endpoint_count > 1:
            details_text.append(f" [dim]({finding.endpoint_count} endpoints)[/dim]", style="yellow")
        elif finding.payload_count > 1:
            details_text.append(f" [dim]({finding.payload_count} payloads)[/dim]", style="yellow")
        details_text.append("\n")

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
    output: str = typer.Option(None, "-o", "--output", help="Output JSON file for results"),
    profile: str = typer.Option(None, "--profile", help="Scan profile: passive, standard, thorough, aggressive"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _scan():

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
                if bearer:
                    target_config.authentication.type = AuthType.BEARER
                    target_config.authentication.token = bearer
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

        if crawl:
            console.print("[cyan]Phase 2: Scanning for vulnerabilities[/cyan]\n")
        elif not verbose:
            console.print("[yellow]Scanning...[/yellow]\n")

        report = await run_scan(
            target_config,
            templates,
            validate_target=True,
            scan_profile=scan_profile,
        )

        _print_report(report)

        if output and report.findings:
            _save_results(report, output)

        raise typer.Exit(0 if report.findings else 1)

    asyncio.run(_scan())


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
