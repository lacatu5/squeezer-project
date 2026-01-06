import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from dast.analyzer import (
    build_auto_target_config,
    discover_and_add_json_endpoints,
    extract_parameters_from_url,
)
from dast.crawler import KatanaCrawler
from dast.config import AuthType, EndpointInfo, ScanReport, TargetConfig
from dast.report import generate_html_report
from dast.scaffolder import scaffold_app, get_cached_endpoints, load_app_config
from dast.scanner import load_templates, run_scan
from dast.utils import setup_logging

console = Console()
cli = typer.Typer(rich_markup_mode="rich", no_args_is_help=True)


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


def get_project_root() -> Path:
    return Path(__file__).parent.parent.resolve()


@cli.command("init")
def init_app(
    app_name: str = typer.Argument(..., help="Name for the new app profile"),
    target: str = typer.Argument(..., help="Target URL to crawl"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authenticated crawling"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _init():
        setup_logging(verbose=verbose)
        print_banner()

        console.print(f"[cyan]Initializing app profile: {app_name}[/cyan]")
        console.print(f"[dim]Target: {target}[/dim]\n")

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
            task = progress.add_task("Crawling with Katana...", total=None)

            try:
                report = await crawler.crawl()
                progress.update(task, completed=True)
            except Exception as e:
                console.print(f"[red]Crawl failed: {e}[/red]")
                console.print("[dim]Install Katana: go install github.com/projectdiscovery/katana/cmd/katana@latest[/dim]")
                raise typer.Exit(1)

        console.print(f"[green]Discovered {len(report.endpoints)} endpoints[/green]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scaffolding templates...", total=None)

            result = scaffold_app(
                app_name=app_name,
                target_url=target,
                endpoints=report.endpoints,
                output_dir=get_project_root(),
                bearer_token=bearer,
            )

            progress.update(task, completed=True)

        console.print(f"\n[bold green]✓ App '{app_name}' created![/bold green]")
        console.print(f"[dim]Location: {result['app_dir']}[/dim]\n")

        table = Table(title="Generated Files")
        table.add_column("File", style="cyan")
        table.add_column("Type", style="green")

        table.add_row("app.yaml", "Config + Cached Endpoints")
        for template in result['templates_created']:
            table.add_row(template, "Template Stub")

        console.print(table)

        console.print(f"\n[dim]Endpoints cached: {result['endpoints_discovered']}[/dim]")
        console.print(f"[dim]Templates created: {len(result['templates_created'])}[/dim]")

        console.print("\n[bold]Next steps:[/bold]")
        console.print(f"  1. Edit templates in [cyan]{result['app_dir']}[/cyan]")
        console.print(f"  2. Run: [green]dast scan {target} --app {app_name}[/green]")

    asyncio.run(_init())


@cli.command("scan")
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authentication"),
    crawl: bool = typer.Option(False, "--crawl", help="Force re-crawl (ignores cached endpoints)"),
    generic: bool = typer.Option(True, "--generic/--no-generic", help="Include generic templates"),
    app: str = typer.Option(None, "--app", help="Use app-specific templates"),
    template: str = typer.Option(None, "-T", "--template", help="Test specific template file"),
    output: str = typer.Option(None, "-o", "--output", help="Output JSON file for results"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _scan():
        setup_logging(verbose=verbose)

        if not verbose:
            print_banner()

        target_config = TargetConfig(name="Target", base_url=target)

        if bearer:
            target_config.authentication.type = AuthType.BEARER
            target_config.authentication.token = bearer

        endpoint_infos = []
        project_root = get_project_root()

        cached_endpoints = None
        if app and not crawl:
            cached_endpoints = get_cached_endpoints(app, project_root)
            if cached_endpoints:
                console.print(f"[cyan]Using {len(cached_endpoints)} cached endpoints from '{app}'[/cyan]")

                for ep in cached_endpoints:
                    url = ep.get('url', '')
                    if url:
                        params = extract_parameters_from_url(url, ep.get('method', 'GET'))
                        endpoint_infos.append(EndpointInfo(
                            url=url,
                            method=ep.get('method', 'GET'),
                            path=ep.get('path', urlparse(url).path),
                            query_params=params,
                            is_api='api' in ep.get('tags', []),
                        ))

                target_config.endpoints.custom = {
                    f"endpoint_{i}": ep.get('path', '')
                    for i, ep in enumerate(cached_endpoints)
                }

        if crawl or (not cached_endpoints and not template):
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

        if endpoint_infos:
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
        )

        _print_report(report)

        if output:
            _save_results(report, output)

        html_path = "report.html"
        generate_html_report(report, html_path)
        console.print(f"[green]HTML report: {html_path}[/green]")

        raise typer.Exit(0 if report.findings else 1)

    asyncio.run(_scan())


@cli.command("apps")
def list_apps():
    print_banner()

    project_root = get_project_root()
    apps_dir = project_root / "templates" / "apps"

    if not apps_dir.exists():
        console.print("[yellow]No apps directory found[/yellow]")
        raise typer.Exit(1)

    table = Table(title="Available App Profiles")
    table.add_column("App", style="cyan")
    table.add_column("Target", style="dim")
    table.add_column("Endpoints", style="green")
    table.add_column("Templates", style="yellow")

    for app_dir in sorted(apps_dir.iterdir()):
        if not app_dir.is_dir():
            continue

        config = load_app_config(app_dir.name, project_root)
        templates = list(app_dir.glob("*.yaml"))
        template_count = len([t for t in templates if t.name != "app.yaml"])

        if config:
            endpoint_count = len(config.get('endpoints', []))
            target = config.get('target_url', 'N/A')
        else:
            endpoint_count = 0
            target = "N/A (no app.yaml)"

        table.add_row(
            app_dir.name,
            target[:40] + "..." if len(target) > 40 else target,
            str(endpoint_count) if endpoint_count else "-",
            str(template_count),
        )

    console.print(table)


@cli.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")
        console.print("Usage:")
        console.print("  dast scan <target>           Scan a target URL")
        console.print("  dast init <app> <target>     Create new app profile")
        console.print("  dast apps                    List available app profiles")
        console.print("\nExamples:")
        console.print("  dast scan http://localhost:3000 --crawl --app juice-shop")
        console.print("  dast init my-app http://example.com --bearer TOKEN")
        raise typer.Exit(0)


app = cli

if __name__ == "__main__":
    cli()
