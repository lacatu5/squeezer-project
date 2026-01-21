# Architecture - Squeezer DAST Framework

## 1. Introduction

This document describes the **system architecture** of **Squeezer**, a minimal template-based Dynamic Application Security Testing (DAST) framework.

---

## 2. System Architecture Overview

```mermaid
flowchart TB
    CLI[CLI Entry Point<br/>typer + rich]
    Orch[Orchestrator<br/>src/dast/cli.py]

    Crawler[Crawler Engine<br/>src/dast/crawler.py]
    Scanner[Scanner Engine<br/>src/dast/scanner.py]
    Reporter[Reporting Module<br/>src/dast/report.py]
    Docker[Docker Manager<br/>src/dast/lab.py]

    Katana[Katana Executor]
    Templates[Templates<br/>YAML]
    Output[HTML/JSON Reports]

    CLI --> Orch
    Orch --> Crawler
    Orch --> Scanner
    Orch --> Reporter
    Orch --> Docker

    Crawler --> Katana
    Scanner --> Templates
    Reporter --> Output

    style CLI fill:#e1f5fe
    style Orch fill:#fff3e0
    style Scanner fill:#f3e5f5
    style Crawler fill:#e8f5e9
    style Reporter fill:#fce4ec
    style Docker fill:#fff9c4
```

---

## 3. Components

### 3.1 CLI Entry Point

| Aspect | Description |
|--------|-------------|
| **Technology** | `typer` + `rich` |
| **Location** | `src/dast/cli.py` |
| **Commands** | `init`, `scan`, `doctor` |

**Responsibilities:**
- Command parsing and validation
- Progress bars and tables
- Configuration loading
- User feedback and error handling

### 3.2 Crawler Engine

| Aspect | Description |
|--------|-------------|
| **Technology** | ProjectDiscovery `katana` |
| **Location** | `src/dast/crawler.py` |
| **Class** | `KatanaCrawler` |

**Responsibilities:**
- Endpoint discovery through web crawling
- JavaScript parsing and XHR extraction
- Form field identification
- Asset discovery (JS, CSS, images)

### 3.3 Scanner Engine

| Aspect | Description |
|--------|-------------|
| **Location** | `src/dast/scanner.py` |
| **Input** | Discovered endpoints + YAML templates |
| **Output** | Vulnerability findings |

**Responsibilities:**
- Template loading from `templates/`
- HTTP request execution
- Response matching (status, regex, DSL)
- Vulnerability classification by severity

### 3.4 Reporting Module

| Aspect | Description |
|--------|-------------|
| **Technology** | `jinja2` |
| **Location** | `src/dast/report.py` |

**Responsibilities:**
- HTML report generation
- JSON export for CI/CD
- Severity aggregation
- OWASP categorization

### 3.5 Docker Manager

| Aspect | Description |
|--------|-------------|
| **Technology** | Docker SDK |
| **Location** | `src/dast/lab.py` |

**Responsibilities:**
- Container lifecycle (start, stop, rm)
- Vulnerable lab deployment (Juice Shop)
- Health checks and port management

---

## 4. Data Flow

```mermaid
flowchart LR
    User[User Command] --> CLI1[CLI Parser]
    CLI1 --> Config[Config Loader]

    Config --> Craw[Crawler Engine]
    Craw --> Endpoints[Discovered Endpoints]

    Endpoints --> Scan[Scanner Engine]
    Scan -.->|reads| Templ[Templates]
    Scan --> Findings[Findings]

    Findings --> Cons[Console Output]
    Findings --> Rep[HTML Report]

    style User fill:#e1f5fe
    style Findings fill:#ffebee
    style Cons fill:#c8e6c9
    style Rep fill:#c8e6c9
```

### Flow Description

| Phase | Description |
|-------|-------------|
| **1. Input** | User executes `squeezer scan` with target URL |
| **2. Config** | CLI loads `app.yaml` configuration |
| **3. Crawl** | Katana discovers endpoints and assets |
| **4. Scan** | Each endpoint is tested against all templates |
| **5. Report** | Findings are displayed and saved |

---

## 5. Template Structure

```mermaid
graph TD
    Root[templates/]
    Generic[generic/]
    Apps[apps/]

    Inj[injection/]
    Auth[authentication/]
    Info[information-disclosure/]
    Red[redirect/]
    Other[other/]

    Juice[juice-shop/]

    Root --> Generic
    Root --> Apps

    Generic --> Inj
    Generic --> Auth
    Generic --> Info
    Generic --> Red
    Generic --> Other

    Apps --> Juice

    style Root fill:#37474f,color:#fff
    style Generic fill:#1976d2,color:#fff
    style Apps fill:#388e3c,color:#fff
```

### Directory Layout

```
templates/
├── generic/                    # Universal vulnerability checks
│   ├── injection/             # SQLi, XSS, Command Injection
│   ├── authentication/        # Auth bypass, weak login
│   ├── information-disclosure/
│   ├── redirect/              # Open redirects
│   └── other/                 # Path traversal, SSRF, XXE
└── apps/                      # Application-specific checks
    └── juice-shop/            # OWASP Juice Shop tests
```

### Template Schema

```yaml
id: unique-identifier
name: Vulnerability Name
severity: critical|high|medium|low|info
category: owasp-category
requests:
  - method: GET|POST|PUT|DELETE|PATCH
    path: /api/target
    headers: {...}
    body: {...}
matches:
  - status: 200
    type: dsl|regex|word
    expression: "..."
```

---

## 6. Deployment Architecture

```mermaid
flowchart TB
    subgraph Dev["Development Machine"]
        Sqz[Squeezer Scanner]
    end

    subgraph Local["Local Lab Mode"]
        Dkr[Docker Container]
        Lab[Target App - Juice Shop]
    end

    subgraph Remote["Remote Target"]
        Web[Web App]
        API[REST API]
        Assets[Static Assets]
    end

    Sqz -.->|optional| Dkr
    Sqz -->|scan| Remote
    Dkr --> Lab

    style Sqz fill:#1976d2,color:#fff
    style Lab fill:#388e3c,color:#fff
    style Web fill:#f57c00,color:#fff
```

### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Remote Scan** | Scan external URL | Production testing, CI/CD |
| **Local Lab** | Docker + vulnerable app | Learning, testing, demo |

---

## 7. File Structure

```
dast-mvp/
├── src/dast/
│   ├── __init__.py
│   ├── cli.py              # Main CLI entry point
│   ├── crawler.py          # KatanaCrawler implementation
│   ├── scanner.py          # Template-based scanner
│   ├── report.py           # HTML/JSON report generation
│   ├── lab.py              # Docker/lifecycle management
│   └── scaffolder.py       # Config generation
├── templates/
│   ├── generic/            # Universal vulnerability templates
│   └── apps/               # Application-specific templates
├── tests/                  # Test suite
├── docs/                   # Documentation
└── pyproject.toml          # Project metadata
```

---

## 8. Related Documentation

- [design-decisions.md](./design-decisions.md) - Design decisions and rationale
- [README.md](../README.md) - Quick start guide
- [prompts.md](./prompts.md) - Development prompts and queries
