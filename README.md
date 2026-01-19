# Squeezer - DAST MVP

Squeezer is a minimal, template-based DAST (Dynamic Application Security Testing) framework. It uses **Katana** for crawling and custom YAML templates for scanning vulnerabilities.

## 🚀 Getting Started

Follow these steps to set up the environment and run your first scan.

### 1. Prerequisites

Before installing Squeezer, ensure you have the following tools installed on your system:

- **Python 3.11+**: [Download Python](https://www.python.org/downloads/)
- **Docker** (Required for running test labs): [Download Docker Desktop](https://www.docker.com/products/docker-desktop/)
- **Katana** (Required for crawling):
  - **macOS (Homebrew):**
    ```bash
    brew install katana
    ```
  - **Go (Alternative):**
    ```bash
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    ```

### 2. Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/dast-mvp.git
    cd dast-mvp
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    This command installs the project in editable mode along with all required libraries.
    ```bash
    pip install -e .
    ```

### 3. Quick Start

You can verify the installation by checking the help command:

```bash
squeezer --help
```

#### Running a Test Lab (Juice Shop)
The easiest way to test Squeezer is using the built-in lab integration (requires Docker).

1.  **Start and Scan Juice Shop:**
    This command starts a Juice Shop container and scans it using the existing `juice-shop` profile templates.
    
    ```bash
    squeezer scan --lab juice-shop --app juice-shop
    ```

#### Scanning a Custom Target for the First Time
To scan a real application, you typically want to "initialize" it first to crawl and generate a workspace.

1.  **Initialize (Crawl & Scaffold):**
    Crawls the target and creates a new profile in `templates/apps/my-target`.
    
    ```bash
    squeezer init my-target https://example.com
    ```

2.  **Scan:**
    Run the scan using the generic templates and any generated app-specific templates.
    
    ```bash
    squeezer scan https://example.com --app my-target
    ```

## � Command Reference

Squeezer works in two phases: **Initialization** (Discovery) and **Scanning** (Attack).

### 1. `squeezer init`
Initializes a new application profile. This phase performs the crawling and scaffolding.

**Usage:**
```bash
squeezer init [OPTIONS] APP_NAME [TARGET]
```

**Arguments:**
*   `APP_NAME` (Required): A unique name for your target application (e.g., `my-shop`). This creates a folder in `templates/apps/`.
*   `TARGET`: The target URL (e.g., `https://example.com`). Required unless using `--lab`.

**Options:**
*   `-b, --bearer`: Bearer token for authenticated crawling. Useful if parts of the site are behind a login.
*   `-lab, --lab`:  Starts a fresh Docker lab (e.g., `juice-shop`) instead of scanning a real URL.
*   `-v, --verbose`: Enable detailed logging.

### 2. `squeezer scan`
Executes the security testing templates against the target.

**Usage:**
```bash
squeezer scan [OPTIONS] [TARGET]
```

**Options:**
*   `--app`: The name of the app profile (from `init`) to use. Loads cached endpoints and custom templates.
*   `--generic / --no-generic`: Whether to run the general vulnerability templates (Default: enabled).
*   `-T, --template`: Run **only** a specific template file (useful for developing new checks).
*   `-b, --bearer`: Override authentication token for this scan run.
*   `-o, --output`: Save results to a JSON file (e.g., `results.json`).
*   `--crawl`: Force a re-crawl of the target, ignoring the cached endpoints from `init`.

# Project Structure

- **`squeezer/`**: Core logic (crawler, scanner, cli).
- **`templates/generic/`**: General vulnerability payloads (CORS, IDOR, etc.).
- **`templates/apps/`**: App-specific configuration and templates.
- **`docs/`**: Project documentation and design decisions.
- **`report.tex`**: LaTeX template for generating reports.

## 📝 Development

To run tests or contribute, ensure you have the environment set up:

```bash
# Verify installation
pip list | grep squeezer
```
