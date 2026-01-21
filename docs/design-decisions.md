# Design Decisions - Squeezer DAST Framework

## 1. Introduction

This document captures the **key design decisions** made during the development of **Squeezer**, a minimal template-based Dynamic Application Security Testing (DAST) framework.

For system architecture and component details, see [architecture.md](./architecture.md).

---

## 2. Template-Based Scanning Engine

**Decision:** Segregate vulnerability detection logic from the core codebase using YAML-based templates.

### Rationale

| Benefit | Description |
|---------|-------------|
| **Extensibility** | Users can add new vulnerability checks without modifying Python source code |
| **Maintainability** | Security rules change frequently; config files are easier to update |
| **Clarity** | YAML allows declarative definition of request patterns and matching rules |
| **Community** | Template format enables contributions without programming knowledge |

### Trade-offs

- Limited flexibility compared to code-based checks
- Requires robust YAML validation to prevent injection

---

## 3. Lab Mode & Docker Integration

**Decision:** Integrate Docker management directly into the CLI via `--lab` flag (e.g., `squeezer init --lab juice-shop`).

### Rationale

| Benefit | Description |
|---------|-------------|
| **Ease of Use** | Lowers barrier to entry for testing against vulnerable applications |
| **Automation** | Complete lifecycle (start → scan → teardown) in one command |
| **Isolation** | Clean, reproducible testing environment |

### Trade-offs

- Adds Docker runtime dependency
- Increases initial installation complexity

---

## 4. Crawler: Katana vs Playwright

**Decision:** Use ProjectDiscovery's Katana instead of browser-based solutions like Playwright.

### Rationale

| Factor | Katana | Playwright |
|--------|--------|------------|
| **Complexity** | Low (HTTP-based) | High (browser management) |
| **Performance** | Fast | Slower (browser overhead) |
| **Dependencies** | Lightweight | Heavy (Chromium/Firefox) |
| **JS Support** | XHR/form extraction | Full JavaScript execution |

### Evidence from Development

> Initial prototypes experimented with **Playwright** to handle dynamic content. However, this added excessive complexity to the module (managing browser instances, heavy dependencies). Switching to **Katana** proved to be a more straightforward solution that balanced capability with ease of integration.

### Trade-offs

- Limited JavaScript execution compared to full browser
- May miss client-side rendered content in complex SPAs

---

## 5. Minimalist Core Philosophy

**Decision:** Aggressively remove unused features and complex abstractions.

### Evidence from Git History

| Commit | Removal | Justification |
|--------|---------|---------------|
| `ab2ab42` | `ScanProfile` object | Complex profile replaced with simpler configuration |
| `6c56eae` | MCP Server | Focused on core DAST functionality |
| Multiple | Deprecated templates | Ensured low false positives |

### Rationale

- **Maintainability:** Less code = fewer bugs, easier onboarding
- **Focus:** Core value is scanning, not framework complexity
- **Quality:** Better to have fewer reliable checks than many noisy ones

---

## 6. Dual-Format Reporting

**Decision:** Rich console output + HTML/JSON artifacts.

### Rationale

| Format | Purpose |
|--------|---------|
| **Console** | Immediate feedback during scan (progress bars, tables) |
| **HTML** | Detailed post-scan analysis with grouping and filtering |
| **JSON** | CI/CD pipeline integration and ticketing systems |

---

## 7. Configuration Scaffolding

**Decision:** Implement `init` command for automated configuration generation.

### Rationale

DAST configuration can be complex:
- Authentication tokens and headers
- URL exclusions and scope limits
- Scan depth and concurrency settings

The scaffolder (`squeezer/scaffolder.py`) automates creation of baseline `app.yaml`, encoding best practices and reducing onboarding friction.

---

## 8. Architectural Principles

### 8.1 Separation of Concerns

- Crawling, scanning, and reporting are isolated modules
- Each component has a single, well-defined responsibility

### 8.2 Configuration Over Code

- Vulnerability definitions live in YAML, not Python
- Behavior changes through config, not code modification

### 8.3 Fail-Safe Defaults

- Safe defaults for scan depth, concurrency, and timeout
- Explicit opt-in for aggressive scanning modes

### 8.4 Observability First

- Rich console output by default
- Structured logging for debugging
- Artifacts for audit trails

---

## 9. Technology Choices

| Component | Technology | Justification |
|-----------|------------|---------------|
| CLI Framework | `typer` | Type-safe, auto-generated help, modern Python |
| Terminal Output | `rich` | Beautiful progress bars, tables, syntax highlighting |
| Crawling | `katana` | Fast, Go-based, active development by ProjectDiscovery |
| Templates | `yaml` | Human-readable, widely supported, declarative |
| Reporting | `jinja2` | Flexible HTML generation, Python ecosystem standard |
| Containerization | `docker` | Industry standard, cross-platform |
