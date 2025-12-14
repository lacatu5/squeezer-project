"""
MCP Server for DAST Agent Crawler.

This server exposes the intelligent agent crawler as MCP tools that can be
called from any MCP-compatible client (like Claude Desktop, VS Code, etc.).

Tools provided:
- crawl_target: Crawl a target and discover endpoints
- get_endpoints: Get discovered endpoints
- get_forms: Get discovered forms
- get_auth_data: Get authentication data
- get_statistics: Get crawling statistics
- scan_with_crawled_config: Run a DAST scan using crawled configuration

Usage:
    python -m dast.mcp_server

Or with Claude Desktop, add to claude_desktop_config.json:
{
    "mcpServers": {
        "dast-crawler": {
            "command": "python",
            "args": ["-m", "dast.mcp_server"]
        }
    }
}
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
from pydantic import BaseModel, Field

from dast.agent_crawler import AgentCrawler, DiscoveryMethod, EndpointType
from dast.config import CrawlerReport
from dast.engine import TemplateEngine


# Store for crawler reports (in production, use persistent storage)
_crawler_reports: Dict[str, CrawlerReport] = {}


# ==== Tool Input Schemas ====


class CrawlTargetInput(BaseModel):
    """Input for the crawl_target tool."""

    url: str = Field(description="The base URL to crawl (e.g., http://localhost:3000)")
    max_pages: int = Field(
        default=500,
        description="Maximum number of pages to visit",
    )
    max_depth: int = Field(
        default=5,
        description="Maximum depth to crawl",
    )
    headless: bool = Field(
        default=True,
        description="Run browser in headless mode",
    )
    extract_javascript: bool = Field(
        default=True,
        description="Extract endpoints from JavaScript files",
    )
    discover_apis: bool = Field(
        default=True,
        description="Discover API endpoints",
    )
    analyze_forms: bool = Field(
        default=True,
        description="Analyze forms for input fields",
    )
    save_report: bool = Field(
        default=False,
        description="Save the report to a file",
    )
    report_path: Optional[str] = Field(
        default=None,
        description="Path to save the report (if save_report is True)",
    )


class GetEndpointsInput(BaseModel):
    """Input for the get_endpoints tool."""

    crawl_id: str = Field(
        default="last",
        description="The crawl ID to get endpoints from (use 'last' for most recent)",
    )
    filter_type: Optional[str] = Field(
        default=None,
        description="Filter by endpoint type (api, page, static, auth, admin, etc.)",
    )
    filter_method: Optional[str] = Field(
        default=None,
        description="Filter by HTTP method (GET, POST, etc.)",
    )
    interesting_only: bool = Field(
        default=False,
        description="Only return interesting endpoints",
    )


class GetFormsInput(BaseModel):
    """Input for the get_forms tool."""

    crawl_id: str = Field(
        default="last",
        description="The crawl ID to get forms from (use 'last' for most recent)",
    )


class GetAuthDataInput(BaseModel):
    """Input for the get_auth_data tool."""

    crawl_id: str = Field(
        default="last",
        description="The crawl ID to get auth data from (use 'last' for most recent)",
    )


class GetStatisticsInput(BaseModel):
    """Input for the get_statistics tool."""

    crawl_id: str = Field(
        default="last",
        description="The crawl ID to get statistics from (use 'last' for most recent)",
    )


class ScanInput(BaseModel):
    """Input for the scan_with_crawled_config tool."""

    crawl_id: str = Field(
        default="last",
        description="The crawl ID to use for scanning (use 'last' for most recent)",
    )
    template_dir: str = Field(
        default="templates",
        description="Directory containing scan templates",
    )
    scan_profile: str = Field(
        default="standard",
        description="Scan profile (passive, standard, thorough, aggressive)",
    )


# ==== Helper Functions ====


def get_report(crawl_id: str) -> Optional[CrawlerReport]:
    """Get a crawler report by ID."""
    if crawl_id == "last":
        if not _crawler_reports:
            return None
        return list(_crawler_reports.values())[-1]
    return _crawler_reports.get(crawl_id)


def generate_crawl_id() -> str:
    """Generate a unique crawl ID."""
    return f"crawl_{datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}"


# ==== MCP Server Setup ====


server = Server("dast-crawler")


@server.list_resources()
async def handle_list_resources() -> List[Resource]:
    """List available resources."""
    resources = []

    for crawl_id, report in _crawler_reports.items():
        resources.append(
            Resource(
                uri=f"dast://crawl/{crawl_id}/report",
                name=f"Crawl Report: {crawl_id}",
                description=f"Complete report for {report.target or report.base_url}",
                mimeType="application/json",
            )
        )

    return resources


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("dast://crawl/"):
        path = uri.replace("dast://crawl/", "")
        parts = path.split("/")

        if len(parts) >= 2 and parts[1] == "report":
            crawl_id = parts[0]
            report = get_report(crawl_id)
            if report:
                return json.dumps(report.model_dump(exclude_none=True), indent=2)

    raise ValueError(f"Resource not found: {uri}")


@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available tools."""
    return [
        Tool(
            name="crawl_target",
            description="Crawl a target URL to discover endpoints, forms, and security-relevant data. Uses Playwright for JavaScript-heavy applications and extracts API endpoints from JavaScript files.",
            inputSchema=CrawlTargetInput.model_json_schema(),
        ),
        Tool(
            name="get_endpoints",
            description="Get discovered endpoints from a previous crawl. Can filter by type (api, page, static) or HTTP method.",
            inputSchema=GetEndpointsInput.model_json_schema(),
        ),
        Tool(
            name="get_forms",
            description="Get all discovered HTML forms from a previous crawl, including field names, types, and actions.",
            inputSchema=GetFormsInput.model_json_schema(),
        ),
        Tool(
            name="get_auth_data",
            description="Get authentication data discovered during crawling, including JWT tokens, session cookies, and local storage values.",
            inputSchema=GetAuthDataInput.model_json_schema(),
        ),
        Tool(
            name="get_statistics",
            description="Get crawling statistics including total requests, unique endpoints, forms discovered, and API endpoints found.",
            inputSchema=GetStatisticsInput.model_json_schema(),
        ),
        Tool(
            name="scan_with_crawled_config",
            description="Run a DAST vulnerability scan using the configuration discovered during crawling. Automatically uses discovered endpoints, authentication, and parameters.",
            inputSchema=ScanInput.model_json_schema(),
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls."""

    if name == "crawl_target":
        return await do_crawl_target(arguments)

    elif name == "get_endpoints":
        return await do_get_endpoints(arguments)

    elif name == "get_forms":
        return await do_get_forms(arguments)

    elif name == "get_auth_data":
        return await do_get_auth_data(arguments)

    elif name == "get_statistics":
        return await do_get_statistics(arguments)

    elif name == "scan_with_crawled_config":
        return await do_scan_with_crawled_config(arguments)

    else:
        raise ValueError(f"Unknown tool: {name}")


# ==== Tool Implementations ====


async def do_crawl_target(arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute the crawl_target tool."""
    args = CrawlTargetInput(**arguments)

    crawler = AgentCrawler(
        base_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        headless=args.headless,
        extract_javascript=args.extract_javascript,
        discover_apis=args.discover_apis,
        analyze_forms=args.analyze_forms,
    )

    try:
        report = await crawler.crawl()

        # Store the report
        crawl_id = generate_crawl_id()
        _crawler_reports[crawl_id] = report

        # Save to file if requested
        if args.save_report and args.report_path:
            report.save_yaml(args.report_path)

        # Format summary
        stats = report.statistics
        if isinstance(stats, dict):
            stats_str = json.dumps(stats, indent=2)
        else:
            stats_str = stats.model_dump_json(indent=2)

        summary = f"""Crawling completed successfully!

Crawl ID: {crawl_id}
Target: {report.target or report.base_url}

Endpoints Discovered: {len(report.endpoints)}
Forms Found: {len(report.forms)}
API Endpoints: {stats.get('api_endpoints', 0) if isinstance(stats, dict) else stats.api_endpoints}

Statistics:
{stats_str}

Use this crawl_id with other tools:
- get_endpoints(crawl_id="{crawl_id}")
- get_forms(crawl_id="{crawl_id}")
- get_auth_data(crawl_id="{crawl_id}")
- get_statistics(crawl_id="{crawl_id}")
"""

        return [TextContent(type="text", text=summary)]

    except Exception as e:
        return [TextContent(type="text", text=f"Error crawling target: {e}")]


async def do_get_endpoints(arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute the get_endpoints tool."""
    args = GetEndpointsInput(**arguments)

    report = get_report(args.crawl_id)
    if not report:
        return [TextContent(type="text", text=f"Crawl '{args.crawl_id}' not found. Run crawl_target first.")]

    endpoints = report.endpoints

    # Apply filters
    if args.filter_type:
        endpoints = [
            e for e in endpoints
            if (isinstance(e, dict) and e.get("type") == args.filter_type) or
            (hasattr(e, "endpoint_type") and e.endpoint_type == args.filter_type)
        ]

    if args.filter_method:
        endpoints = [
            e for e in endpoints
            if (isinstance(e, dict) and e.get("method") == args.filter_method.upper()) or
            (hasattr(e, "method") and e.method == args.filter_method.upper())
        ]

    if args.interesting_only:
        endpoints = [
            e for e in endpoints
            if (isinstance(e, dict) and e.get("interesting")) or
            (hasattr(e, "interesting") and e.interesting)
        ]

    # Format output
    output = f"Found {len(endpoints)} endpoints:\n\n"

    for ep in endpoints:
        if isinstance(ep, dict):
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            ep_type = ep.get("type", "unknown")
            status = ep.get("status_code")
            interesting = " 🎯" if ep.get("interesting") else ""
            hints = ep.get("vulnerability_hints", [])
        else:
            url = ep.url
            method = getattr(ep, "method", "GET")
            ep_type = getattr(ep, "endpoint_type", "unknown")
            status = getattr(ep, "status_code", None)
            interesting = " 🎯" if getattr(ep, "interesting", False) else ""
            hints = getattr(ep, "vulnerability_hints", [])

        status_str = f" [{status}]" if status else ""
        hints_str = f" | Hints: {', '.join(hints)}" if hints else ""

        output += f"- [{method}] {url}{status_str} ({ep_type}){interesting}{hints_str}\n"

    return [TextContent(type="text", text=output)]


async def do_get_forms(arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute the get_forms tool."""
    args = GetFormsInput(**arguments)

    report = get_report(args.crawl_id)
    if not report:
        return [TextContent(type="text", text=f"Crawl '{args.crawl_id}' not found. Run crawl_target first.")]

    forms = report.forms

    if not forms:
        return [TextContent(type="text", text="No forms discovered.")]

    output = f"Found {len(forms)} forms:\n\n"

    for i, form in enumerate(forms, 1):
        action = form.get("action", "unknown")
        method = form.get("method", "GET")
        fields = form.get("fields", form.get("form_fields", []))

        output += f"Form {i}: {method} {action}\n"

        if fields:
            output += "  Fields:\n"
            for field in fields:
                if isinstance(field, dict):
                    name = field.get("name", "unknown")
                    field_type = field.get("type", "text")
                    required = " (required)" if field.get("required") else ""
                    output += f"    - {name}: {field_type}{required}\n"

        output += "\n"

    return [TextContent(type="text", text=output)]


async def do_get_auth_data(arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute the get_auth_data tool."""
    args = GetAuthDataInput(**arguments)

    report = get_report(args.crawl_id)
    if not report:
        return [TextContent(type="text", text=f"Crawl '{args.crawl_id}' not found. Run crawl_target first.")]

    auth_data = report.auth_data
    cookies = report.discovered_cookies
    storage = report.storage_data

    output = "Authentication Data:\n\n"

    if auth_data:
        output += "Auth Type: " + auth_data.get("type", "unknown") + "\n"
        if auth_data.get("jwt_token"):
            token = auth_data["jwt_token"]
            # Show first/last parts of token only
            if len(token) > 50:
                token = token[:20] + "..." + token[-20:]
            output += f"JWT Token: {token}\n"
        if auth_data.get("cookie_name"):
            output += f"Cookie Name: {auth_data['cookie_name']}\n"

    if cookies:
        output += f"\nCookies ({len(cookies)}):\n"
        for name, value in cookies.items():
            # Truncate long values
            if len(value) > 50:
                value = value[:30] + "..."
            output += f"  {name}: {value}\n"

    if storage:
        output += f"\nStorage Data ({len(storage)} items):\n"
        for key, value in storage.items():
            # Truncate long values
            value_str = str(value)
            if len(value_str) > 50:
                value_str = value_str[:30] + "..."
            output += f"  {key}: {value_str}\n"

    if not auth_data and not cookies and not storage:
        output += "(No authentication data discovered)\n"

    return [TextContent(type="text", text=output)]


async def do_get_statistics(arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute the get_statistics tool."""
    args = GetStatisticsInput(**arguments)

    report = get_report(args.crawl_id)
    if not report:
        return [TextContent(type="text", text=f"Crawl '{args.crawl_id}' not found. Run crawl_target first.")]

    stats = report.statistics

    if isinstance(stats, dict):
        output = "Crawling Statistics:\n\n"
        for key, value in stats.items():
            output += f"{key}: {value}\n"
    else:
        output = stats.model_dump_json(indent=2)

    return [TextContent(type="text", text=output)]


async def do_scan_with_crawled_config(arguments: Dict[str, Any]) -> List[TextContent]:
    """Execute the scan_with_crawled_config tool."""
    args = ScanInput(**arguments)

    report = get_report(args.crawl_id)
    if not report:
        return [TextContent(type="text", text=f"Crawl '{args.crawl_id}' not found. Run crawl_target first.")]

    target_config = report.to_target_config()

    try:
        engine = TemplateEngine(
            template_dir=args.template_dir,
            scan_profile=args.scan_profile,
        )

        findings = await engine.scan_target(target_config)

        output = f"""Scan completed using crawled configuration!

Target: {target_config.name}
Base URL: {target_config.base_url}
Scan Profile: {args.scan_profile}

Templates Executed: {findings.templates_executed}
Critical Findings: {findings.critical_count}
High Findings: {findings.high_count}
Medium Findings: {findings.medium_count}
Low Findings: {findings.low_count}

"""

        if findings.findings:
            output += "\n=== Findings ===\n\n"
            for finding in findings.findings[:20]:  # Limit to first 20
                output += f"- [{finding.severity.upper()}] {finding.vulnerability_type}\n"
                output += f"  URL: {finding.url}\n"
                output += f"  Evidence: {finding.evidence_strength}\n"
                if finding.message:
                    output += f"  Message: {finding.message}\n"
                output += "\n"

            if len(findings.findings) > 20:
                output += f"... and {len(findings.findings) - 20} more findings\n"

        return [TextContent(type="text", text=output)]

    except Exception as e:
        return [TextContent(type="text", text=f"Error running scan: {e}")]


# ==== Main Entry Point ====


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="dast-crawler",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
