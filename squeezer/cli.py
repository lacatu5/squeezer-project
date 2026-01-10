import asyncio
import json
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from squeezer.config import AuthType, ScanReport, TargetConfig
from squeezer.core.docker import get_docker_manager
from squeezer.crawler import KatanaCrawler
from squeezer.report import generate_html_report
from squeezer.scaffolder import (
    get_cached_endpoints,
    load_app_config,
    scaffold_app,
    sanitize_name,
)
from squeezer.scanner import load_templates, run_scan
from squeezer.utils import setup_logging

console = Console()
cli = typer.Typer(rich_markup_mode="rich", no_args_is_help=True)


def print_banner():
    console.print("\n[bold cyan]Squeezer[/bold cyan] - Template-based DAST Framework\n")


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
    target: str = typer.Argument(None, help="Target URL to crawl (not required with -lab)"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authenticated crawling"),
    lab: str = typer.Option(None, "-lab", "--lab", help="Lab mode (e.g., juice-shop) - starts fresh Docker container"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _init():
        setup_logging(verbose=verbose)
        print_banner()
        project_root = get_project_root()

        effective_target = target
        effective_bearer = bearer

        if lab:
            console.print(f"[cyan]Initializing lab profile: {app_name}[/cyan]")
            console.print(f"[dim]Lab: {lab}[/dim]\n")

            docker_manager = get_docker_manager(project_root)
            lab_result = await docker_manager.start_lab(lab)

            if not lab_result["success"]:
                console.print(f"[red]Failed to start lab: {lab_result.get('error')}[/red]")
                raise typer.Exit(1)

            effective_target = lab_result["url"]
            effective_bearer = None

            console.print(f"[green]Lab started at {effective_target}[/green]")
            console.print(f"[dim]Default user: {lab_result['username']}[/dim]\n")
        elif not effective_target:
            console.print("[red]Target URL required when not using -lab[/red]")
            raise typer.Exit(1)
        else:
            console.print(f"[cyan]Initializing app profile: {app_name}[/cyan]")
            console.print(f"[dim]Target: {effective_target}[/dim]\n")

        crawl_cookies = {}
        if effective_bearer:
            crawl_cookies['token'] = effective_bearer

        crawler = KatanaCrawler(
            base_url=effective_target,
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
                if lab:
                    await docker_manager.stop_lab()
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
                target_url=effective_target,
                endpoints=report.endpoints,
                output_dir=project_root,
                bearer_token=effective_bearer,
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

        if lab:
            console.print("\n[bold]Next steps:[/bold]")
            console.print(f"  1. Edit templates in [cyan]{result['app_dir']}[/cyan]")
            console.print(f"  2. Run: [green]squeezer scan {effective_target} --app {app_name} -lab {lab}[/green]")
            console.print(f"  Or with manual token: [green]squeezer scan {effective_target} --app {app_name} --bearer <token>[/green]")
        else:
            console.print("\n[bold]Next steps:[/bold]")
            console.print(f"  1. Edit templates in [cyan]{result['app_dir']}[/cyan]")
            console.print(f"  2. Run: [green]squeezer scan {effective_target} --app {app_name}[/green]")

    asyncio.run(_init())


@cli.command("scan")
def scan(
    target: str = typer.Argument(None, help="Target URL to scan (not required with -lab)"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authentication"),
    crawl: bool = typer.Option(False, "--crawl", help="Force re-crawl (ignores cached endpoints)"),
    generic: bool = typer.Option(True, "--generic/--no-generic", help="Include generic templates"),
    app: str = typer.Option(None, "--app", help="Use app-specific templates"),
    template: str = typer.Option(None, "-T", "--template", help="Test specific template file"),
    lab: str = typer.Option(None, "-lab", "--lab", help="Lab mode (e.g., juice-shop) - starts fresh Docker container"),
    output: str = typer.Option(None, "-o", "--output", help="Output JSON file for results"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _scan():
        setup_logging(verbose=verbose)

        if not verbose:
            print_banner()

        project_root = get_project_root()
        docker_manager = None
        lab_username = None
        lab_password = None

        effective_target = target
        effective_bearer = bearer

        if lab:
            console.print(f"[cyan]Lab mode: {lab}[/cyan]\n")

            docker_manager = get_docker_manager(project_root)
            lab_result = await docker_manager.start_lab(lab)

            if not lab_result["success"]:
                console.print(f"[red]Failed to start lab: {lab_result.get('error')}[/red]")
                raise typer.Exit(1)

            effective_target = lab_result["url"]
            lab_username = lab_result["username"]
            lab_password = lab_result["password"]

            console.print(f"[green]Lab started at {effective_target}[/green]")
            console.print(f"[dim]Auto-login as: {lab_username}[/dim]\n")
        elif not effective_target:
            console.print("[red]Target URL required when not using -lab[/red]")
            raise typer.Exit(1)

        target_config = TargetConfig(name="Target", base_url=effective_target)

        if effective_bearer:
            target_config.authentication.type = AuthType.BEARER
            target_config.authentication.token = effective_bearer
        elif lab:
            target_config.authentication.type = AuthType.LAB
            target_config.authentication.lab_name = lab
            target_config.authentication.username = lab_username
            target_config.authentication.password = lab_password

        cached_endpoints = None
        effective_app = app

        if app and not crawl:
            cached_endpoints = get_cached_endpoints(app, project_root)

        if not cached_endpoints and not template:
            if not app:
                parsed = urlparse(effective_target)
                effective_app = sanitize_name(parsed.netloc.replace(":", "-"))

            crawl_cookies = {}
            if effective_bearer:
                crawl_cookies['token'] = effective_bearer

            crawler = KatanaCrawler(
                base_url=effective_target,
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
                    if lab and docker_manager:
                        await docker_manager.stop_lab()
                    raise typer.Exit(1)

            console.print(f"[cyan]Found {len(report.endpoints)} endpoints[/cyan]")

            scaffold_app(
                app_name=effective_app,
                target_url=effective_target,
                endpoints=report.endpoints,
                output_dir=project_root,
                bearer_token=effective_bearer,
            )
            console.print(f"[dim]Cached to '{effective_app}'[/dim]")

            cached_endpoints = get_cached_endpoints(effective_app, project_root)

        if cached_endpoints:
            if not app:
                console.print(f"[cyan]Using {len(cached_endpoints)} endpoints from '{effective_app}'[/cyan]")

            if target_config.endpoints.custom is None:
                target_config.endpoints.custom = {}

            for ep in cached_endpoints:
                url = ep.get('url', '')
                if url:
                    target_config.endpoints.custom[url] = url

        if not target_config.get_endpoints() and not template:
            console.print("[yellow]No scanable endpoints found[/yellow]")
            if lab and docker_manager:
                await docker_manager.stop_lab()
            raise typer.Exit(1)

        template_paths = []

        if template:
            template_path = Path(template).resolve()
            if not template_path.exists():
                console.print(f"[red]Template file not found: {template}[/red]")
                if lab and docker_manager:
                    await docker_manager.stop_lab()
                raise typer.Exit(1)
            template_paths = [template_path]
        else:
            if generic:
                generic_path = project_root / "templates" / "generic"
                if generic_path.exists():
                    template_paths.append(generic_path)

            app_path = project_root / "templates" / "apps" / effective_app
            if app_path.exists():
                template_paths.append(app_path)

        if not template_paths:
            console.print("[red]No templates found. Use --generic or --app[/red]")
            if lab and docker_manager:
                await docker_manager.stop_lab()
            raise typer.Exit(1)

        templates = load_templates(template_paths)

        if not templates:
            console.print("[red]No templates to execute[/red]")
            if lab and docker_manager:
                await docker_manager.stop_lab()
            raise typer.Exit(1)

        try:
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
        finally:
            if lab and docker_manager:
                console.print("\n[dim]Stopping lab container...[/dim]")
                await docker_manager.stop_lab()

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
        console.print("\n[bold cyan]Squeezer[/bold cyan] - Template-based DAST Framework\n")
        console.print("Usage:")
        console.print("  squeezer scan <target>           Scan a target URL")
        console.print("  squeezer scan -lab <lab>         Lab mode with clean slate container")
        console.print("  squeezer init <app> <target>     Create new app profile")
        console.print("  squeezer init <app> -lab <lab>   Create app profile in lab mode")
        console.print("  squeezer apps                    List available app profiles")
        console.print("\nExamples:")
        console.print("  squeezer scan http://localhost:3000 --app juice-shop")
        console.print("  squeezer scan -lab juice-shop --app juice-shop")
        console.print("  squeezer init my-app http://example.com --bearer TOKEN")
        console.print("  squeezer init juice-shop -lab juice-shop")
        raise typer.Exit(0)


app = cli

if __name__ == "__main__":
    cli()
