# DAST MCP Server

Intelligent web crawler for DAST (Dynamic Application Security Testing), exposed as an MCP server.

## Features

- **Intelligent Endpoint Discovery**: Uses Playwright to crawl JavaScript-heavy applications
- **API Endpoint Extraction**: Automatically extracts API endpoints from JavaScript files
- **Form Analysis**: Discovers and analyzes HTML forms with field details
- **Authentication Detection**: Extracts JWT tokens, session cookies, and local storage data
- **Vulnerability Hints**: Identifies potential vulnerability indicators in responses
- **MCP Protocol**: Exposes tools via MCP for integration with Claude Desktop and other MCP clients

## Installation

### Using Docker (Recommended)

```bash
# Build and run with docker-compose
docker-compose -f docker-compose.mcp.yml up -d

# Or build manually
docker build -f Dockerfile.mcp -t dast-mcp-server .
docker run -i --name dast-mcp dast-mcp-server
```

### Using Python

```bash
# Install dependencies
pip install -e .

# Run the MCP server
python -m dast.mcp_server
```

## MCP Tools

The server provides the following tools:

### `crawl_target`
Crawl a target URL to discover endpoints, forms, and security-relevant data.

```python
{
    "url": "http://localhost:3000",
    "max_pages": 500,
    "max_depth": 5,
    "headless": true,
    "extract_javascript": true,
    "discover_apis": true,
    "analyze_forms": true,
    "save_report": false,
    "report_path": null
}
```

### `get_endpoints`
Get discovered endpoints from a previous crawl.

```python
{
    "crawl_id": "last",
    "filter_type": null,  # api, page, static, auth, admin, etc.
    "filter_method": null,  # GET, POST, etc.
    "interesting_only": false
}
```

### `get_forms`
Get all discovered HTML forms from a previous crawl.

```python
{
    "crawl_id": "last"
}
```

### `get_auth_data`
Get authentication data discovered during crawling.

```python
{
    "crawl_id": "last"
}
```

### `get_statistics`
Get crawling statistics.

```python
{
    "crawl_id": "last"
}
```

### `scan_with_crawled_config`
Run a DAST vulnerability scan using the discovered configuration.

```python
{
    "crawl_id": "last",
    "template_dir": "templates",
    "scan_profile": "standard"
}
```

## Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dast-crawler": {
      "command": "docker",
      "args": [
        "exec", "-i", "dast-mcp-server",
        "python", "-m", "dast.mcp_server"
      ]
    }
  }
}
```

Or without Docker:

```json
{
  "mcpServers": {
    "dast-crawler": {
      "command": "python",
      "args": ["-m", "dast.mcp_server"],
      "cwd": "/path/to/dast-mvp"
    }
  }
}
```

## CLI Usage

You can also use the crawler directly via CLI:

```bash
# Crawl a target
dast crawl http://localhost:3000 -o juice-shop-crawled.yaml

# With options
dast crawl http://example.com \
    --max-pages 1000 \
    --max-depth 3 \
    --no-headless \
    -o report.yaml

# Run a scan with crawled config
dast scan http://localhost:3000 --config juice-shop-crawled.yaml
```

## Example Workflow

1. **Crawl the target** to discover endpoints
2. **Review discovered data** (endpoints, forms, auth)
3. **Run targeted scans** using the discovered configuration

```python
# Step 1: Crawl
crawl_target("http://localhost:3000")

# Step 2: Get interesting endpoints
get_endpoints(crawl_id="last", interesting_only=true)

# Step 3: Get auth data for authenticated testing
get_auth_data(crawl_id="last")

# Step 4: Run vulnerability scan
scan_with_crawled_config(crawl_id="last", scan_profile="thorough")
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     MCP Server                          │
├─────────────────────────────────────────────────────────┤
│  Tools: crawl_target, get_endpoints, get_forms, etc.   │
├─────────────────────────────────────────────────────────┤
│              Agent Crawler                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Playwright   │  │ JS Analyzer  │  │ Form Extract │  │
│  │ Browser      │  │              │  │              │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────┤
│              Data Collection                            │
│  • Endpoints    • Forms    • Auth Data    • Cookies    │
└─────────────────────────────────────────────────────────┘
```

## Storage

Crawler data is stored in:
- `storage/` - Internal storage for crawler state
- `reports/` - Generated YAML reports (if save_report enabled)

## License

MIT
