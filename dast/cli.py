"""CLI interface for DAST MVP."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dast.agent_crawler import AgentCrawler
from dast.config import EvidenceStrength, ScanProfile, ScanReport, TargetConfig
from dast.engine import load_templates, run_scan
from dast.utils import setup_logging


console = Console()


def print_banner():
    """Print application banner."""
    console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")


async def scan_command(
    target_url: str,
    config: Optional[str] = None,
    template_dir: Optional[str] = None,
    output: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    token: Optional[str] = None,
    profile: Optional[str] = None,
    verbose: bool = False,
    no_validate: bool = False,
    checkpoint: Optional[str] = None,
    resume: Optional[str] = None,
) -> int:
    """Run vulnerability scan."""
    setup_logging(verbose=verbose)

    if not verbose:
        print_banner()

    # Parse scan profile (defaults to standard for safety)
    scan_profile = ScanProfile.STANDARD
    if profile:
        try:
            scan_profile = ScanProfile(profile.lower())
            if scan_profile in (ScanProfile.THOROUGH, ScanProfile.AGGRESSIVE):
                console.print("[yellow]Warning: Thorough/Aggressive profiles may cause delays.[/yellow]")
        except ValueError:
            console.print(f"[red]Invalid profile: {profile}[/red]")
            console.print("[dim]Valid profiles: passive, standard, thorough, aggressive[/dim]")
            return 1

    # Load or create target configuration
    if config:
        target = TargetConfig.from_yaml(config)
        target.base_url = target_url
    else:
        target = TargetConfig(
            name="Target",
            base_url=target_url,
        )

    # Override credentials from CLI
    if username:
        target.authentication.username = username
    if password:
        target.authentication.password = password
    if token:
        target.authentication.token = token

    console.print(f"[dim]Target: {target.base_url}[/dim]")
    console.print(f"[dim]Auth: {target.authentication.type or 'none'}[/dim]")
    if profile:
        console.print(f"[dim]Profile: {scan_profile.value}[/dim]")

    # Load templates
    template_path = Path(template_dir or "templates/generic")
    if not template_path.exists():
        # Try built-in templates
        template_path = Path(__file__).parent.parent / "templates" / "generic"

    if not template_path.exists():
        console.print("[red]No templates found![/red]")
        return 1

    templates = load_templates(template_path)
    if not verbose:
        console.print(f"[dim]Loaded {len(templates)} templates[/dim]\n")

    if not templates:
        console.print("[red]No templates to execute[/red]")
        return 1

    # Run scan
    if not verbose:
        console.print("[yellow]Scanning...[/yellow]\n")

    # Determine checkpoint file (resume takes precedence over checkpoint)
    checkpoint_file = resume or checkpoint
    if resume:
        console.print(f"[dim]Resuming from checkpoint: {resume}[/dim]\n")

    report = await run_scan(
        target,
        templates,
        validate_target=not no_validate,
        scan_profile=scan_profile,
        checkpoint_file=checkpoint_file,
    )

    # Display results
    _print_report(report)

    # Save results
    if output and report.findings:
        _save_results(report, output)

    return 0 if report.findings else 1


def list_command(template_dir: Optional[str] = None) -> int:
    """List available templates."""
    print_banner()

    template_path = Path(template_dir or "templates")
    if not template_path.exists():
        template_path = Path(__file__).parent.parent / "templates"

    if not template_path.exists():
        console.print("[red]No templates found![/red]")
        return 1

    templates = load_templates(template_path)

    table = Table(title="Available Templates")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Tags")

    for t in templates:
        tags_str = ", ".join(t.info.tags[:3]) if t.info.tags else ""
        table.add_row(
            t.id,
            t.info.name[:40],
            t.info.severity.value,
            tags_str,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(templates)} templates[/dim]")

    return 0


async def crawl_command(
    target_url: str,
    output: Optional[str] = None,
    max_pages: int = 500,
    max_depth: int = 5,
    headless: bool = True,
    extract_javascript: bool = True,
    discover_apis: bool = True,
    analyze_forms: bool = True,
    verbose: bool = False,
) -> int:
    """Run the intelligent agent crawler to discover endpoints."""
    setup_logging(verbose=verbose)

    if not verbose:
        print_banner()

    console.print(f"[dim]Target: {target_url}[/dim]")
    console.print(f"[dim]Max Pages: {max_pages} | Max Depth: {max_depth}[/dim]")
    console.print()

    crawler = AgentCrawler(
        base_url=target_url,
        max_pages=max_pages,
        max_depth=max_depth,
        headless=headless,
        extract_javascript=extract_javascript,
        discover_apis=discover_apis,
        analyze_forms=analyze_forms,
    )

    # Run crawler with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Crawling target...", total=None)

        try:
            report = await crawler.crawl()
            progress.update(task, completed=True)

        except Exception as e:
            console.print(f"[red]Error during crawling: {e}[/red]")
            return 1

    # Display results
    _print_crawl_report(report)

    # Save report if requested
    if output:
        report.save_yaml(output)
        console.print(f"\n[green]Report saved to: {output}[/green]")

    return 0


def _print_crawl_report(report) -> None:
    """Print the crawler report."""
    console.print("\n[bold]Crawl Results[/bold]\n")

    # Statistics
    stats = report.statistics
    if isinstance(stats, dict):
        total_requests = stats.get("total_requests", 0)
        unique_endpoints = stats.get("unique_endpoints", 0)
        api_endpoints = stats.get("api_endpoints", 0)
        forms_discovered = stats.get("forms_discovered", 0)
        js_endpoints = stats.get("js_endpoints_extracted", 0)
        interesting = stats.get("interesting_endpoints", 0)
    else:
        total_requests = stats.total_requests
        unique_endpoints = stats.unique_urls
        api_endpoints = stats.api_endpoints
        forms_discovered = stats.forms_discovered
        js_endpoints = 0
        interesting = 0

    console.print(f"[cyan]Total Requests:[/cyan] {total_requests}")
    console.print(f"[cyan]Unique Endpoints:[/cyan] {unique_endpoints}")
    console.print(f"[cyan]API Endpoints:[/cyan] {api_endpoints}")
    console.print(f"[cyan]Forms Discovered:[/cyan] {forms_discovered}")
    console.print(f"[cyan]JS Endpoints Extracted:[/cyan] {js_endpoints}")
    if interesting > 0:
        console.print(f"[yellow]Interesting Endpoints:[/yellow] {interesting} 🎯")

    # Authentication data
    if report.auth_data:
        console.print("\n[bold]Authentication:[/bold]")
        auth_type = report.auth_data.get("type", "unknown")
        console.print(f"  Type: {auth_type}")
        if report.auth_data.get("jwt_token"):
            console.print(f"  JWT: [dim]{report.auth_data['jwt_token'][:30]}...[/dim]")

    # Interesting endpoints
    interesting_endpoints = [
        e for e in report.endpoints
        if isinstance(e, dict) and e.get("interesting")
    ]
    if interesting_endpoints:
        console.print(f"\n[bold yellow]Interesting Endpoints:[/bold yellow]")
        for ep in interesting_endpoints[:10]:  # Show first 10
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            hints = ep.get("vulnerability_hints", [])
            hints_str = f" | [red]{', '.join(hints)}[/red]" if hints else ""
            console.print(f"  [{method}] {url}{hints_str}")
        if len(interesting_endpoints) > 10:
            console.print(f"  ... and {len(interesting_endpoints) - 10} more")

    # Forms
    if report.forms:
        console.print(f"\n[bold]Forms ({len(report.forms)}):[/bold]")
        for form in report.forms[:5]:  # Show first 5
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
    """Print scan report with evidence-based output."""
    console.print("\n[bold]Scan Results[/bold]\n")

    if not report.findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    direct = [f for f in report.findings if f.evidence_strength == EvidenceStrength.DIRECT]
    inference = [f for f in report.findings if f.evidence_strength == EvidenceStrength.INFERENCE]
    heuristic = [f for f in report.findings if f.evidence_strength == EvidenceStrength.HEURISTIC]

    # Print findings by evidence strength
    if direct:
        console.print("\n[bold green]Direct Observation[/bold green] [dim](we saw it happen)[/dim]")
        _print_findings_table(direct)

    if inference:
        console.print("\n[bold yellow]Inference[/bold yellow] [dim](strong indirect evidence)[/dim]")
        _print_findings_table(inference)

    if heuristic:
        console.print("\n[bold cyan]Heuristic[/bold cyan] [dim](pattern suggests vulnerability)[/dim]")
        _print_findings_table(heuristic)

    # Print detailed findings
    console.print("\n[bold]Detailed Findings:[/bold]\n")
    _print_detailed_findings(report.findings)

    # Summary
    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  Critical: [red]{report.critical_count}[/red]")
    console.print(f"  High: [red]{report.high_count}[/red]")
    console.print(f"  Medium: [yellow]{report.medium_count}[/yellow]")
    console.print(f"  Low: [green]{report.low_count}[/green]")
    console.print(f"\n[dim]Duration: {report.duration_seconds:.1f}s | Templates: {report.templates_executed}[/dim]")


def _print_detailed_findings(findings: list) -> None:
    """Print detailed findings with URLs, evidence, and remediation."""
    for i, finding in enumerate(findings, 1):
        # Severity color
        severity = finding.severity.value.upper()
        if severity == "CRITICAL":
            severity_color = "bold red"
        elif severity == "HIGH":
            severity_color = "red"
        elif severity == "MEDIUM":
            severity_color = "yellow"
        else:
            severity_color = "green"

        # Build details
        details_text = Text()
        details_text.append(f"#{i} ", style="bold")
        details_text.append(f"[{severity}]", style=severity_color)
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

        console.print(Panel(details_text, border_style=severity_color))
        console.print()


def _print_findings_table(findings: list) -> None:
    """Print a table of findings with details."""
    table = Table()
    table.add_column("Severity", width=10)
    table.add_column("Type", width=30)
    table.add_column("Evidence", width=15)
    table.add_column("Details", width=50)

    for finding in findings:
        # Severity with color
        severity = finding.severity.value.upper()
        if severity == "CRITICAL":
            severity = f"[bold red]{severity}[/bold red]"
        elif severity == "HIGH":
            severity = f"[red]{severity}[/red]"
        elif severity == "MEDIUM":
            severity = f"[yellow]{severity}[/yellow]"
        else:
            severity = f"[green]{severity}[/green]"

        # Evidence strength
        evidence = finding.evidence_strength.value.replace("_", " ").title()
        if evidence == "Direct Observation":
            evidence = "[bold green]Direct[/bold green]"
        elif evidence == "Inference":
            evidence = "[yellow]Inference[/yellow]"
        else:
            evidence = "[cyan]Heuristic[/cyan]"

        # Details from evidence
        details = finding.message[:50]
        if finding.response_details:
            details = f"{details} | {finding.response_details[:30]}"

        table.add_row(severity, finding.vulnerability_type[:30], evidence, details[:50])

    console.print(table)


def _save_results(report: ScanReport, output: str) -> None:
    """Save results to JSON file."""
    output_path = Path(output)

    # Convert to dict
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


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="DAST MVP - Template-based DAST Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dast scan http://localhost:3000 --config configs/examples/juice-shop.yaml
  dast scan http://example.com -c configs/myapp.yaml -t templates/generic -o results.json
  dast scan http://localhost:8080 -t templates/generic
  dast scan http://localhost:3000 -t templates/apps/juice-shop  # Business logic

  # Agent Crawler
  dast crawl http://localhost:3000 -o juice-shop-crawled.yaml
  dast crawl http://example.com --max-pages 1000 --max-depth 3

  # List templates
  dast list -t templates/generic
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument("target", help="Target URL (e.g., http://localhost:3000)")
    scan_parser.add_argument("-c", "--config", help="Target configuration file (YAML)")
    scan_parser.add_argument("-t", "--template-dir", help="Templates directory (default: templates/generic)", default="templates/generic")
    scan_parser.add_argument("-o", "--output", help="Output JSON file for results")
    scan_parser.add_argument("-u", "--username", help="Username for authentication")
    scan_parser.add_argument("-p", "--password", help="Password for authentication")
    scan_parser.add_argument("--token", help="Bearer token for authentication")
    scan_parser.add_argument("--profile", help="Scan profile: passive (fast), standard (default), thorough (with delays)", default=None)
    scan_parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")
    scan_parser.add_argument("--no-validate", help="Skip target connectivity validation", action="store_true")
    scan_parser.add_argument("--checkpoint", help="Save scan progress to file for resume capability")
    scan_parser.add_argument("--resume", help="Resume scan from checkpoint file")

    # Crawl command
    crawl_parser = subparsers.add_parser("crawl", help="Run intelligent agent crawler")
    crawl_parser.add_argument("target", help="Target URL (e.g., http://localhost:3000)")
    crawl_parser.add_argument("-o", "--output", help="Output YAML file for the crawler report")
    crawl_parser.add_argument("--max-pages", type=int, default=500, help="Maximum pages to visit (default: 500)")
    crawl_parser.add_argument("--max-depth", type=int, default=5, help="Maximum crawl depth (default: 5)")
    crawl_parser.add_argument("--no-headless", action="store_false", dest="headless", help="Run browser in visible mode")
    crawl_parser.add_argument("--no-js-extract", action="store_false", dest="extract_javascript", help="Don't extract endpoints from JavaScript")
    crawl_parser.add_argument("--no-api-discover", action="store_false", dest="discover_apis", help="Don't discover API endpoints")
    crawl_parser.add_argument("--no-forms", action="store_false", dest="analyze_forms", help="Don't analyze forms")
    crawl_parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")

    # List command
    list_parser = subparsers.add_parser("list", help="List available templates")
    list_parser.add_argument("-t", "--template-dir", help="Templates directory", default="templates/generic")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "scan":
        return asyncio.run(scan_command(
            target_url=args.target,
            config=args.config,
            template_dir=args.template_dir,
            output=args.output,
            username=args.username,
            password=args.password,
            token=args.token,
            profile=args.profile,
            verbose=args.verbose,
            no_validate=args.no_validate,
            checkpoint=getattr(args, 'checkpoint', None),
            resume=getattr(args, 'resume', None),
        ))

    elif args.command == "crawl":
        return asyncio.run(crawl_command(
            target_url=args.target,
            output=args.output,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            headless=args.headless,
            extract_javascript=args.extract_javascript,
            discover_apis=args.discover_apis,
            analyze_forms=args.analyze_forms,
            verbose=args.verbose,
        ))

    elif args.command == "list":
        return list_command(template_dir=args.template_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
