# Squeezer - DAST MVP

Squeezer is a minimal, template-based DAST framework. It uses **Katana** for crawling and custom YAML templates for scanning vulnerabilities.

## Getting Started

### 1. Prerequisites

Ensure you have the following installed:

* **Python 3.11+**: [Download](https://www.python.org/downloads/)
* **Docker**: [Download](https://www.docker.com/products/docker-desktop/) (Required for test labs)
* **Katana** (Required for crawling):
* **Go (Universal):** `go install github.com/projectdiscovery/katana/cmd/katana@latest`
* **macOS:** `brew install katana`
* **Windows:** `choco install katana` OR `winget install ProjectDiscovery.Katana`



### 2. Installation

1. **Create and Activate Virtual Environment:**
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

```


2. **Install Dependencies:**
```bash
pip install -e .

```


3. **Verify Installation:**
```bash
squeezer --help

```



### 3. Quick Start

**Option A: Run the Test Lab (Juice Shop)**
Requires Docker. Starts the container and scans it using built-in templates.

```bash
squeezer scan --lab juice-shop --app juice-shop

```

**Option B: Scan a Custom Target**

1. **Initialize (Crawl & Scaffold):**
Crawls the target and creates a workspace in `templates/apps/my-target`.
```bash
squeezer init my-target https://example.com

```


2. **Scan:**
Runs generic and app-specific templates against the target.
```bash
squeezer scan https://example.com --app my-target

```



---

## Command Reference

Squeezer works in two phases: **Initialization** (Discovery) and **Scanning** (Attack).

### 1. `squeezer init`

Crawls the target and scaffolds a new profile.

**Usage:** `squeezer init [OPTIONS] APP_NAME [TARGET]`

* **Arguments:**
* `APP_NAME`: Unique name for the target (creates folder in `templates/apps/`).
* `TARGET`: Target URL (e.g., `https://example.com`).


* **Options:**
* `-b, --bearer`: Bearer token for authenticated crawling.
* `-lab, --lab`: Starts a fresh Docker lab instead of a real URL.
* `-v, --verbose`: Enable detailed logging.



### 2. `squeezer scan`

Executes security templates against the target.

**Usage:** `squeezer scan [OPTIONS] [TARGET]`

* **Options:**
* `--app`: The app profile name (loads cached endpoints/templates).
* `--generic` / `--no-generic`: Run general vulnerability templates (Default: enabled).
* `-T, --template`: Run **only** a specific template file.
* `-b, --bearer`: Override authentication token.
* `-o, --output`: Save results to JSON (e.g., `results.json`).
* `--crawl`: Force a re-crawl, ignoring cached `init` data.



---

## Project Structure

* **`squeezer/`**: Core logic (crawler, scanner, CLI).
* **`templates/generic/`**: General payloads (CORS, IDOR, etc.).
* **`templates/apps/`**: App-specific configuration and templates.
* **`docs/`**: Documentation and design decisions.

## Development

To run tests or verify the package is visible in your environment:

```bash
pip list | grep squeezer

```
