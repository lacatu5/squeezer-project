"""CLI interface for DAST MVP."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from dast.crawler import KatanaCrawler, parse_cookies_string
from dast.config import AuthType, EvidenceStrength, EndpointInfo, ScanProfile, ScanReport, TargetConfig
from dast.scanner import load_templates, run_scan
from dast.utils import setup_logging, logger

console = Console()
app = typer.Typer(rich_markup_mode="rich")

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
    vuln_types = []
    param_lower = param_name.lower()
    for vuln_type, patterns in INJECTABLE_PATTERNS.items():
        for pattern in patterns:
            if pattern in param_lower:
                vuln_types.append(vuln_type)
                break
    return vuln_types or ["generic"]


def summarize_parameters(endpoint_infos: List[Any]) -> Dict[str, int]:
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
    auto_endpoints = {}
    for ep in endpoints:
        path = getattr(ep, 'path', urlparse(getattr(ep, 'url', '')).path)
        method = getattr(ep, 'method', 'GET')
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
    console.print("\n[bold cyan]DAST MVP[/bold cyan] - Template-based DAST Framework\n")


def add_json_injection_endpoints(
    target: TargetConfig,
    endpoints: list,
) -> None:
    paths = set()
    for ep in endpoints:
        path = ep.get('url', '').strip('/')
        if path:
            paths.add(f"/{path}")

    json_injection_points = {
        "xss_json_post": ("/rest/feedback", "comment"),
        "xss_json_search": ("/rest/products/search", "q"),
        "xss_json_comment": ("/rest/comments", "comment"),
        "command_search": ("/rest/products/search", "q"),
        "sqli_basket": ("/rest/basket/", "quantity"),
        "sqli_products": ("/rest/products/", "quantity"),
    }

    added_count = 0
    for var_name, (path, field) in json_injection_points.items():
        for discovered_path in paths:
            if discovered_path.startswith(path.rstrip('/')) or path.startswith(discovered_path.rstrip('/')):
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
    from dast.scanner.json_discovery import quick_discover

    headers = {}
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers["Cookie"] = cookie_str

    endpoint_paths = list(set(ep.get('url', '') for ep in endpoints))
    json_fields = await quick_discover(target.base_url, endpoint_paths, headers)

    if not target.endpoints.custom:
        target.endpoints.custom = {}

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
    for path, fields in json_fields.items():
        for field in fields:
            for template_var, mappings in template_mappings.items():
                for mapping_path, mapping_field in mappings:
                    if path.startswith(mapping_path.rstrip('/')) or mapping_path.startswith(path.rstrip('/')):
                        if field == mapping_field or mapping_field == "*":
                            target.endpoints.custom[template_var] = f"JSON:{path}:{field}"
                            count += 1
                            break

    if count > 0:
        logger.info(f"Added {count} JSON injection endpoints for testing")
        console.print(f"[dim]  → {count} JSON injection points discovered[/dim]")
    else:
        common_endpoints = {
            "xss_stored": "JSON:/rest/feedback:comment",
            "xss_reflected": "JSON:/rest/products/search:q",
            "command_injection": "JSON:/rest/products/search:q",
        }
        for var, spec in common_endpoints.items():
            path = spec.split(":")[1]
            if any(path in ep.get('url', '') for ep in endpoints):
                target.endpoints.custom[var] = spec
                count += 1

        if count > 0:
            console.print(f"[dim]  → {count} JSON injection endpoints added (fallback)[/dim]")

    has_api = any(ep.get('url', '').startswith('/api/') or ep.get('url', '').startswith('/rest/') for ep in endpoints)
    if has_api:
        target.endpoints.custom.setdefault("ssti", "JSON:/rest/products:input")
        target.endpoints.custom.setdefault("xxe", "XML:/rest/data")
        count += 2
        console.print(f"[dim]  → Added SSTI and XXE endpoints for testing[/dim]")


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
    target: str = typer.Argument(..., help="Target URL (e.g., http://localhost:3000)"),
    bearer: str = typer.Option(None, "-b", "--bearer", help="Bearer token for authentication"),
    crawl: bool = typer.Option(False, "--crawl", help="Crawl target first to auto-discover endpoints"),
    dom_xss: bool = typer.Option(False, "--dom-xss", help="Enable DOM XSS validation with Playwright"),
    template_dir: str = typer.Option("templates/generic", "-t", "--template-dir", help="Templates directory"),
    output: str = typer.Option(None, "-o", "--output", help="Output JSON file for results"),
    profile: str = typer.Option(None, "--profile", help="Scan profile: passive, standard, thorough, aggressive"),
    checkpoint: str = typer.Option(None, "--checkpoint", help="Save scan progress to file"),
    resume: str = typer.Option(None, "--resume", help="Resume scan from checkpoint file"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
    no_validate: bool = typer.Option(False, "--no-validate", help="Skip target connectivity validation"),
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
            console.print("[dim]JS Crawl: enabled | Interesting-only: enabled | Max Depth: 3[/dim]\n")

            crawl_cookies = {}
            if bearer:
                crawl_cookies['token'] = bearer

            crawler = KatanaCrawler(
                base_url=target,
                max_depth=3,
                js_crawl=True,
                cookies=crawl_cookies,
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

        template_path = Path(template_dir or "templates/generic")
        if not template_path.exists():
            template_path = Path(__file__).parent.parent / "templates" / "generic"

        if not template_path.exists():
            console.print("[red]No templates found![/red]")
            raise typer.Exit(1)

        templates = load_templates(template_path)
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

        if dom_xss:
            console.print("[cyan]Phase 3: DOM XSS Validation[/cyan]\n")
            from dast.crawler import DOMXSSValidator
            from urllib.parse import urlparse, parse_qs

            xss_findings = []

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Testing DOM XSS...[/cyan]", total=None)

                try:
                    async with DOMXSSValidator(headless=True, timeout=10000) as validator:
                        for ep in endpoint_infos[:20]:
                            for param_info in ep.query_params[:5]:
                                param_name = param_info.get("name", "") if isinstance(param_info, dict) else str(param_info)
                                if param_name:
                                    try:
                                        findings = await validator.test_url_parameter(
                                            url=ep.url,
                                            param=param_name,
                                        )
                                        for f in findings:
                                            report.add_finding_from_dict({
                                                "vulnerability_type": "DOM XSS",
                                                "url": f.url,
                                                "message": f"XSS payload executed via {f.sink}",
                                                "owasp_category": "A03:2025",
                                                "severity": "High",
                                                "evidence": {
                                                    "payload": f.payload[:100],
                                                    "sink": f.sink,
                                                    "source": f.source,
                                                },
                                            })
                                        xss_findings.extend(findings)
                                    except Exception:
                                        continue
                    progress.update(task, completed=True)
                except Exception as e:
                    console.print(f"[yellow]DOM XSS validation skipped: {e}[/yellow]")
                    console.print("[dim]Install: pip install playwright && playwright install chromium[/dim]")

            if xss_findings:
                console.print(f"[green]DOM XSS: {len(xss_findings)} confirmed[/green]")
            else:
                console.print("[dim]No DOM XSS vulnerabilities found[/dim]")

        _print_report(report)

        if output and report.findings:
            _save_results(report, output)

        raise typer.Exit(0 if report.findings else 1)

    asyncio.run(_scan())


@app.command()
def crawl(
    target: str = typer.Argument(..., help="Target URL"),
    output: str = typer.Option(None, "-o", "--output", help="Output YAML file for the crawler report"),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum crawl depth"),
    js_crawl: bool = typer.Option(False, "--js-crawl", help="Enable JavaScript crawling"),
    cookies: str = typer.Option(None, "--cookies", help="Authentication cookies"),
    interesting_only: bool = typer.Option(False, "--interesting-only", help="Only keep interesting endpoints"),
    no_filter_static: bool = typer.Option(False, "--no-filter-static", help="Don't filter static files"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable verbose logging"),
):
    async def _crawl():
        setup_logging(verbose=verbose)

        if not verbose:
            print_banner()

        console.print(f"[dim]Target: {target}[/dim]")
        console.print(f"[dim]Max Depth: {max_depth} | JS Crawl: {js_crawl}[/dim]")
        if interesting_only:
            console.print("[dim]Filter: interesting only (api, auth, admin)[/dim]")
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
            interesting_only=interesting_only,
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
    template_dir: str = typer.Option("templates", "-t", "--template-dir", help="Templates directory"),
):
    print_banner()

    path = Path(template_dir)
    if not path.exists():
        path = Path(__file__).parent.parent / "templates"

    if not path.exists():
        console.print("[red]No templates found![/red]")
        raise typer.Exit(1)

    templates = load_templates(path)

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


if __name__ == "__main__":
    app()
