"""CLI interface for DAST MVP."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dast.crawler import KatanaCrawler, parse_cookies_string
from dast.config import EvidenceStrength, ScanProfile, ScanReport, TargetConfig
from dast.scanner import load_templates, run_scan
from dast.utils import setup_logging, logger


console = Console()


# Simple parameter mapping utilities (replaces deleted param_mapper.py)
from urllib.parse import parse_qs
from typing import List, Dict, Any

# Common injectable parameter patterns by vulnerability type
INJECTABLE_PATTERNS = {
    "sqli": [r"id", r"search", r"query", r"q", r"filter", r"find", r"item",
             r"product", r"user", r"category", r"email", r"username", r"name"],
    "xss": [r"name", r"comment", r"message", r"text", r"content", r"input",
            r"desc", r"feedback", r"review", r"callback", r"redirect"],
    "path_traversal": [r"file", r"path", r"folder", r"document", r"image",
                       r"download", r"include", r"template", r"lang", r"filename"],
    "ssrf": [r"url", r"link", r"redirect", r"next", r"dest", r"target",
             r"callback", r"return", r"feed", r"site", r"uri", r"forward"],
    "command": [r"host", r"hostname", r"ip", r"port", r"cmd", r"exec",
                r"command", r"ping", r"traceroute"],
}


def extract_parameters_from_url(url: str, method: str = "GET") -> List[Dict[str, Any]]:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    params = []
    if parsed.query:
        for name, values in parse_qs(parsed.query).items():
            params.append({
                "name": name,
                "value": values[0] if values else "",
                "location": "query",
            })
    return params


def classify_parameter(param_name: str) -> List[str]:
    """Classify a parameter by potential vulnerability types."""
    vuln_types = []
    param_lower = param_name.lower()
    for vuln_type, patterns in INJECTABLE_PATTERNS.items():
        for pattern in patterns:
            if pattern in param_lower:
                vuln_types.append(vuln_type)
                break
    return vuln_types or ["generic"]


def summarize_parameters(endpoint_infos: List[Any]) -> Dict[str, int]:
    """Summarize injectable parameters by vulnerability type."""
    summary = {}
    for ep in endpoint_infos:
        for param in getattr(ep, 'query_params', []):
            if isinstance(param, dict):
                param_name = param.get('name', '')
            else:
                param_name = str(param)
            vuln_types = classify_parameter(param_name)
            for vuln_type in vuln_types:
                summary[vuln_type] = summary.get(vuln_type, 0) + 1
    return summary


def get_injectable_parameters(endpoint_infos: List[Any]) -> Dict[str, List[Dict]]:
    """Get injectable parameters grouped by endpoint path."""
    result = {}
    for ep in endpoint_infos:
        path = getattr(ep, 'path', urlparse(getattr(ep, 'url', '')).path)
        params = getattr(ep, 'query_params', [])
        injectable = []
        for param in params:
            if isinstance(param, dict):
                param_name = param.get('name', '')
            else:
                param_name = str(param)
            vuln_types = classify_parameter(param_name)
            if vuln_types != ["generic"]:
                injectable.append({
                    "name": param_name,
                    "vuln_types": vuln_types,
                })
        if injectable:
            result[path] = injectable
    return result


def build_auto_target_config(
    endpoints: List[Any],
    templates: List[Any],
    base_url: str,
) -> Dict[str, str]:
    """Build auto-mapped endpoint configuration from crawled endpoints."""
    # Simple mapping: find endpoints that match template patterns
    auto_endpoints = {}
    for ep in endpoints:
        path = getattr(ep, 'path', urlparse(getattr(ep, 'url', '')).path)
        method = getattr(ep, 'method', 'GET')
        # Map common paths to template variable names
        if "/rest/user/login" in path or "/api/user/login" in path:
            auto_endpoints["login"] = f"{base_url}{path}"
        elif "/rest/products/search" in path or "/api/products/search" in path:
            auto_endpoints["search"] = f"{base_url}{path}"
        elif "/rest/basket" in path or "/api/basket" in path:
            auto_endpoints["basket"] = f"{base_url}{path}"
        elif "/rest/feedback" in path or "/api/feedback" in path:
            auto_endpoints["feedback"] = f"{base_url}{path}"
    return auto_endpoints


def print_banner():
    """Print application banner."""
    console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")


def add_json_injection_endpoints(
    target: TargetConfig,
    endpoints: list,
) -> None:
    """Add JSON injection endpoints to the target config.

    Analyzes discovered endpoints and adds known JSON injection points
    for common REST API patterns.

    Args:
        target: TargetConfig to modify
        endpoints: List of discovered endpoint dicts
    """
    from dast.utils import logger

    # Extract unique endpoint paths
    paths = set()
    for ep in endpoints:
        path = ep.get('url', '').strip('/')
        if path:
            paths.add(f"/{path}")

    # Known JSON injection endpoints for common APIs
    # Format: endpoint_variable -> (path, json_field_name)
    json_injection_points = {
        "xss_json_post": ("/rest/feedback", "comment"),
        "xss_json_search": ("/rest/products/search", "q"),
        "xss_json_comment": ("/rest/comments", "comment"),
        "command_search": ("/rest/products/search", "q"),
        "sqli_basket": ("/rest/basket/", "quantity"),
        "sqli_products": ("/rest/products/", "quantity"),
    }

    # Add matching endpoints to target config
    added_count = 0
    for var_name, (path, field) in json_injection_points.items():
        # Check if this path exists in discovered endpoints
        for discovered_path in paths:
            if discovered_path.startswith(path.rstrip('/')) or path.startswith(discovered_path.rstrip('/')):
                # Add the JSON injection endpoint
                # Format: /rest/feedback with JSON body {"comment": "PAYLOAD"}
                target._endpoints_custom[var_name] = f"{path}?{field}="
                added_count += 1
                break

    if added_count > 0:
        logger.info(f"Added {added_count} JSON injection endpoints for testing")


async def discover_and_add_json_endpoints(
    target: TargetConfig,
    endpoints: list,
    cookies: Optional[Dict[str, str]] = None,
) -> None:
    """Discover JSON body fields from API endpoints.

    Probes POST endpoints to discover what JSON fields they accept,
    then adds them to the target config for vulnerability testing.

    Args:
        target: TargetConfig to modify
        endpoints: List of discovered endpoint dicts
        cookies: Optional cookies for authentication
    """
    from dast.scanner.json_discovery import quick_discover

    # Build headers
    headers = {}
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers["Cookie"] = cookie_str

    # Get discovered endpoint paths
    endpoint_paths = list(set(ep.get('url', '') for ep in endpoints))

    # Quick discovery based on known API patterns
    json_fields = await quick_discover(target.base_url, endpoint_paths, headers)

    # Initialize custom endpoints if needed
    if not target.endpoints.custom:
        target.endpoints.custom = {}

    # Map discovered JSON fields to template variables
    # Template -> (path_pattern, field_pattern) mappings
    template_mappings = {
        "xss_stored": [
            ("/rest/feedback", "comment"),
            ("/rest/feedbacks", "comment"),
            ("/api/Feedback", "comment"),
            ("/api/Feedbacks", "comment"),
            ("/rest/comments", "comment"),
            ("/api/Comments", "comment"),
        ],
        "xss_reflected": [("/rest/products/search", "q"), ("/api/Products/search", "q")],
        "command_injection": [("/rest/products/search", "q"), ("/api/Products/search", "q")],
        "sqli_post": [("/rest/basket/", "quantity"), ("/rest/products/", "quantity")],
        "path_traversal": [("/rest/file/upload", "file")],
        "ssrf": [("/rest/redirect", "url")],
        "ssti": [("/rest", "input"), ("/api", "input"), ("/rest/", "name"), ("/api/", "name")],
        "xxe": [("/rest", "data"), ("/api", "data"), ("/rest/upload", "file"), ("/api/upload", "file")],
    }

    count = 0
    # Check each discovered endpoint/field against template mappings
    for path, fields in json_fields.items():
        for field in fields:
            # Find matching template
            for template_var, mappings in template_mappings.items():
                for mapping_path, mapping_field in mappings:
                    # Check if this matches the discovered endpoint
                    if path.startswith(mapping_path.rstrip('/')) or mapping_path.startswith(path.rstrip('/')):
                        if field == mapping_field or mapping_field == "*":
                            # Add this endpoint with the template variable name
                            target.endpoints.custom[template_var] = f"JSON:{path}:{field}"
                            count += 1
                            break

    if count > 0:
        from dast.utils import logger
        logger.info(f"Added {count} JSON injection endpoints for testing")
        console.print(f"[dim]  → {count} JSON injection points discovered[/dim]")
    else:
        # Fallback: add common JSON endpoints if discovered
        common_endpoints = {
            "xss_stored": "JSON:/rest/feedback:comment",
            "xss_reflected": "JSON:/rest/products/search:q",
            "command_injection": "JSON:/rest/products/search:q",
        }
        for var, spec in common_endpoints.items():
            # Check if the path exists in discovered endpoints
            path = spec.split(":")[1]
            if any(path in ep.get('url', '') for ep in endpoints):
                target.endpoints.custom[var] = spec
                count += 1

        if count > 0:
            console.print(f"[dim]  → {count} JSON injection endpoints added (fallback)[/dim]")

    # Always add SSTI and XXE endpoints for testing if API endpoints exist
    has_api = any(ep.get('url', '').startswith('/api/') or ep.get('url', '').startswith('/rest/') for ep in endpoints)
    if has_api:
        # Add generic SSTI endpoint
        target.endpoints.custom.setdefault("ssti", "JSON:/rest/products:input")
        # Add generic XXE endpoint
        target.endpoints.custom.setdefault("xxe", "XML:/rest/data")
        count += 2
        console.print(f"[dim]  → Added SSTI and XXE endpoints for testing[/dim]")


async def scan_command(
    target_url: str,
    template_dir: Optional[str] = None,
    output: Optional[str] = None,
    profile: Optional[str] = None,
    verbose: bool = False,
    no_validate: bool = False,
    checkpoint: Optional[str] = None,
    resume: Optional[str] = None,
    crawl: bool = False,
    cookies: Optional[str] = None,
) -> int:
    """Run vulnerability scan.

    If --crawl is specified, runs the Katana crawler first to discover endpoints,
    then automatically tests them for vulnerabilities.

    Crawler defaults: js-crawl enabled, interesting-only enabled, max-depth=3
    """
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

    # Parse cookies
    parsed_cookies = {}
    if cookies:
        parsed_cookies = parse_cookies_string(cookies)

    # Crawler for endpoint discovery
    endpoint_infos = []

    if crawl:
        console.print(f"[cyan]Phase 1: Crawling {target_url}[/cyan]")
        console.print("[dim]JS Crawl: enabled | Interesting-only: enabled | Max Depth: 3[/dim]\n")

        crawler = KatanaCrawler(
            base_url=target_url,
            max_depth=3,
            js_crawl=True,
            cookies=parsed_cookies,
            filter_static=True,
            interesting_only=True,
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
                return 1

        console.print(f"[green]Found {len(report.endpoints)} endpoints[/green]")
        console.print(f"[dim]  API: {report.summary.get('api', 0)} | Auth: {report.summary.get('auth', 0)} | Admin: {report.summary.get('admin', 0)}[/dim]")

        # Build endpoint info for analysis
        from dast.config import EndpointInfo
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

        # Convert to TargetConfig
        try:
            target = report.to_target_config(
                name="crawled_target",
                prioritize=True,
                exclude_static=True,
            )
        except Exception as e:
            console.print(f"[red]Failed to generate target config: {e}[/red]")
            return 1

        if not target.get_endpoints():
            console.print("[yellow]No scanable endpoints found[/yellow]")
            return 1

        # Discover JSON injection points
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Discovering JSON injection points...[/cyan]", total=None)
                await discover_and_add_json_endpoints(target, report.endpoints, parsed_cookies)
                progress.update(task, completed=True)
        except Exception:
            pass  # Continue without JSON endpoints
    else:
        # Simple target config without crawl
        target = TargetConfig(name="Target", base_url=target_url)

    # Set auth from cookies
    if parsed_cookies:
        from dast.config.common import AuthType
        # If cookie has 'token', use as bearer AND add cookies
        if 'token' in parsed_cookies:
            target.authentication.type = AuthType.BEARER
            target.authentication.token = parsed_cookies['token']

        # Build cookie string for ALL cookies (including token if present)
        # This ensures cookies like 'language', 'session', etc. are sent
        cookie_str = "; ".join(f"{k}={v}" for k, v in parsed_cookies.items())
        target.authentication.headers["Cookie"] = cookie_str

    console.print(f"[dim]Target: {target.base_url}[/dim]")
    console.print(f"[dim]Auth: {target.authentication.type or 'none'}[/dim]")
    console.print(f"[dim]Endpoints: {len(target.get_endpoints())}[/dim]")
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

    # Smart endpoint mapping: auto-map crawled endpoints to template variables
    if crawl and endpoint_infos:
        auto_endpoints = build_auto_target_config(
            endpoints=endpoint_infos,
            templates=templates,
            base_url=target_url,
        )

        # Add auto-mapped endpoints to target config
        for var_name, path in auto_endpoints.items():
            if var_name not in target.endpoints.custom:
                target.endpoints.custom[var_name] = path

        if auto_endpoints:
            console.print(f"[dim]Auto-mapped {len(auto_endpoints)} endpoint variables[/dim]")

    # Run scan
    if crawl:
        console.print("[cyan]Phase 2: Scanning for vulnerabilities[/cyan]\n")
    elif not verbose:
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
    max_depth: int = 3,
    js_crawl: bool = False,
    cookies: Optional[str] = None,
    interesting_only: bool = False,
    no_filter_static: bool = False,
    verbose: bool = False,
) -> int:
    """Run the Katana crawler to discover endpoints."""
    setup_logging(verbose=verbose)

    if not verbose:
        print_banner()

    console.print(f"[dim]Target: {target_url}[/dim]")
    console.print(f"[dim]Max Depth: {max_depth} | JS Crawl: {js_crawl}[/dim]")
    if interesting_only:
        console.print("[dim]Filter: interesting only (api, auth, admin)[/dim]")
    if no_filter_static:
        console.print("[dim]Filter: none (keeping all files)[/dim]")

    # Parse cookies from user-provided string
    parsed_cookies = {}
    if cookies:
        parsed_cookies = parse_cookies_string(cookies)
        console.print(f"[dim]Cookies: {cookies[:50]}...[/dim]")

    console.print()

    crawler = KatanaCrawler(
        base_url=target_url,
        max_depth=max_depth,
        js_crawl=js_crawl,
        cookies=parsed_cookies,
        filter_static=not no_filter_static,
        interesting_only=interesting_only,
    )

    # Run crawler with progress indicator
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
            console.print("[dim]Make sure Katana is installed: go install github.com/projectdiscovery/katana/cmd/katana@latest[/dim]")
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

    # Handle both old CrawlerReport and new SimpleCrawlerReport
    if hasattr(report, 'summary'):
        # New SimpleCrawlerReport
        summary = report.summary
        console.print(f"[cyan]Total URLs:[/cyan] {summary.get('total', 0)}")
        console.print(f"[cyan]API Endpoints:[/cyan] {summary.get('api', 0)}")
        console.print(f"[cyan]Auth Endpoints:[/cyan] {summary.get('auth', 0)}")
        console.print(f"[cyan]Admin Endpoints:[/cyan] {summary.get('admin', 0)}")
        console.print(f"[cyan]Page Endpoints:[/cyan] {summary.get('page', 0)}")

        # Show cookies used
        if report.cookies:
            console.print(f"\n[dim]Cookies: {', '.join(report.cookies)}[/dim]")

        # Show sample endpoints
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

    # Old CrawlerReport format
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
        console.print("\n[bold yellow]Interesting Endpoints:[/bold yellow]")
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

    # Summary by OWASP Top 10 2025
    console.print("\n[bold]Summary (by OWASP Top 10 2025):[/bold]")
    owasp_summary = report.get_owasp_summary()
    for category, count in owasp_summary.items():
        if count > 0:
            # Color code based on category priority
            if any(x in category for x in ["A01", "A05", "A07"]):
                color = "red"
            elif any(x in category for x in ["A02", "A03", "A04", "A06"]):
                color = "yellow"
            else:
                color = "green"
            console.print(f"  {category}: [{color}]{count}[/{color}]")
    console.print(f"\n[dim]Duration: {report.duration_seconds:.1f}s | Templates: {report.templates_executed}[/dim]")


def _print_detailed_findings(findings: list) -> None:
    """Print detailed findings with URLs, evidence, and remediation."""
    for i, finding in enumerate(findings, 1):
        # OWASP category color
        owasp_category = finding.owasp_category.value
        if any(x in owasp_category for x in ["A01", "A05", "A07"]):
            category_color = "bold red"
        elif any(x in owasp_category for x in ["A02", "A03", "A04", "A06"]):
            category_color = "yellow"
        else:
            category_color = "green"

        # Build details
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
    """Print a table of findings with details."""
    table = Table()
    table.add_column("OWASP Category", width=18)
    table.add_column("Type", width=30)
    table.add_column("Evidence", width=15)
    table.add_column("Details", width=50)

    for finding in findings:
        # OWASP category with color
        owasp = finding.owasp_category.value
        if any(x in owasp for x in ["A01", "A05", "A07"]):
            owasp_display = f"[bold red]{owasp}[/bold red]"
        elif any(x in owasp for x in ["A02", "A03", "A04", "A06"]):
            owasp_display = f"[yellow]{owasp}[/yellow]"
        else:
            owasp_display = f"[green]{owasp}[/green]"

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

        table.add_row(owasp_display, finding.vulnerability_type[:30], evidence, details[:50])

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
  # Crawl then scan (automatic discovery)
  dast scan http://localhost:3000 --crawl --cookies 'token=eyJ...'

  # Quick scan with cookies (token= becomes Bearer)
  dast scan http://localhost:3000 --cookies 'token=eyJ...'

  # Passive scan (fast, less intrusive)
  dast scan http://localhost:3000 --profile passive

  # Standalone crawl
  dast crawl http://localhost:3000 --cookies 'session=xyz'

  # List templates
  dast list -t templates/generic
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument("target", help="Target URL (e.g., http://localhost:3000)")
    scan_parser.add_argument("-t", "--template-dir", help="Templates directory (default: templates/generic)", default="templates/generic")
    scan_parser.add_argument("-o", "--output", help="Output JSON file for results")
    scan_parser.add_argument("--profile", help="Scan profile: passive (fast), standard (default), thorough (with delays)", default=None)
    scan_parser.add_argument("-v", "--verbose", help="Enable verbose logging", action="store_true")
    scan_parser.add_argument("--no-validate", help="Skip target connectivity validation", action="store_true")
    scan_parser.add_argument("--checkpoint", help="Save scan progress to file for resume capability")
    scan_parser.add_argument("--resume", help="Resume scan from checkpoint file")
    scan_parser.add_argument("--crawl", help="Crawl target first to auto-discover endpoints before scanning", action="store_true")
    scan_parser.add_argument("--cookies", help="Cookies for auth (e.g., 'token=eyJ...' or 'key1=val1; key2=val2'). If 'token' present, sets Bearer.")

    # Crawl command
    crawl_parser = subparsers.add_parser("crawl", help="Run Katana web crawler")
    crawl_parser.add_argument("target", help="Target URL (e.g., http://localhost:3000)")
    crawl_parser.add_argument("-o", "--output", help="Output YAML file for the crawler report")
    crawl_parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    crawl_parser.add_argument("--js-crawl", action="store_true", dest="js_crawl", help="Enable JavaScript crawling (requires Chrome)")
    crawl_parser.add_argument("--cookies", help="Authentication cookies (format: 'key=value; key2=value2' or JSON)")
    crawl_parser.add_argument("--interesting-only", action="store_true", help="Only keep interesting endpoints (api, auth, admin)")
    crawl_parser.add_argument("--no-filter-static", action="store_true", help="Don't filter static files (.js, .css, etc.)")
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
            template_dir=args.template_dir,
            output=args.output,
            profile=args.profile,
            verbose=args.verbose,
            no_validate=args.no_validate,
            checkpoint=getattr(args, 'checkpoint', None),
            resume=getattr(args, 'resume', None),
            crawl=getattr(args, 'crawl', False),
            cookies=getattr(args, 'cookies', None),
        ))

    elif args.command == "crawl":
        return asyncio.run(crawl_command(
            target_url=args.target,
            output=args.output,
            max_depth=args.max_depth,
            js_crawl=args.js_crawl,
            cookies=args.cookies,
            interesting_only=getattr(args, 'interesting_only', False),
            no_filter_static=getattr(args, 'no_filter_static', False),
            verbose=args.verbose,
        ))

    elif args.command == "list":
        return list_command(template_dir=args.template_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
