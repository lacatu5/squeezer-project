import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import typer

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from dast.analyzer import (
    build_auto_target_config,
    discover_and_add_json_endpoints,
    extract_parameters_from_url,
)
from dast.crawler import KatanaCrawler
from dast.config import AuthType, EndpointInfo, ScanProfile, ScanReport, TargetConfig
from dast.report import generate_html_report
from dast.scanner import load_templates, run_scan
from dast.utils import setup_logging

console = Console()
app = typer.Typer(rich_markup_mode="rich")


def print_banner():
    console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")


def _print_report(report: ScanReport) -> None:
    if not report.findings:
        console.print("[green]No vulnerabilities found[/green]")
        return

    grouped = report.group_similar_findings()
    total = len(report.findings)
    unique = len(grouped)

    parts = []
    if report.critical_count:
        parts.append(f"[red]{report.critical_count} critical[/red]")
    if report.high_count:
        parts.append(f"[yellow]{report.high_count} high[/yellow]")
    if report.medium_count:
        parts.append(f"[yellow]{report.medium_count} medium[/yellow]")
    if report.low_count:
        parts.append(f"[green]{report.low_count} low[/green]")

    console.print(f"Found {total} findings ({unique} unique): {', '.join(parts)}")


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

    console.print(f"[green]Results saved to: {output_path}[/green]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authentication"),
    crawl: bool = typer.Option(False, "--crawl", help="Crawl target first to auto-discover endpoints"),
    generic: bool = typer.Option(True, "--generic/--no-generic", help="Include generic templates"),
    app: str = typer.Option(None, "--app", help="Add app-specific templates (juice-shop, ...)"),
    template: str = typer.Option(None, "-T", "--template", help="Test specific template file"),
    output: str = typer.Option(None, "-o", "--output", help="Output JSON file for results"),
    html: str = typer.Option(None, "--html", help="Output HTML report file"),
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
                task = progress.add_task("Crawling...", total=None)

                try:
                    report = await crawler.crawl()
                    progress.update(task, completed=True)
                except Exception as e:
                    console.print(f"[red]Crawl failed: {e}[/red]")
                    console.print("[dim]Install Katana: go install github.com/projectdiscovery/katana/cmd/katana@latest[/dim]")
                    raise typer.Exit(1)

            console.print(f"[cyan]Found {len(report.endpoints)} endpoints[/cyan]")

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
                    task = progress.add_task("Discovering JSON injection points...", total=None)
                    await discover_and_add_json_endpoints(target_config, report.endpoints, crawl_cookies)
                    progress.update(task, completed=True)
            except Exception:
                pass

        project_root = Path(__file__).parent.parent.resolve()
        template_paths = []

        if template:
            template_path = Path(template).resolve()
            if not template_path.exists():
                console.print(f"[red]Template file not found: {template}[/red]")
                raise typer.Exit(1)
            template_paths = [template_path]
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
                if target_config.endpoints.custom and var_name not in target_config.endpoints.custom:
                    if target_config.endpoints.custom is not None:
                        target_config.endpoints.custom[var_name] = path

        report = await run_scan(
            target_config,
            templates,
            validate_target=True,
            scan_profile=scan_profile,
        )

        _print_report(report)

        if output:
            _save_results(report, output)

        if html:
            generate_html_report(report, html)
            console.print(f"[green]HTML report: {html}[/green]")

        raise typer.Exit(0 if report.findings else 1)

    asyncio.run(_scan())


if __name__ == "__main__":
    app()
