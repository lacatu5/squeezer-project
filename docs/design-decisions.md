# Design Decisions Document - Squeezer DAST Framework

## 1. Introduction
This document outlines the key architectural and design decisions made during the development of **Squeezer**, a minimal template-based Dynamic Application Security Testing (DAST) framework. The goal of this project is to provide a lightweight, extensible, and easy-to-use security scanner that integrates seamlessly with modern development workflows.

## 2. Architectural Overview
The system follows a modular architecture composed of four main components:
1.  **CLI Entry Point**: Built with `typer` for a robust command-line interface.
2.  **Crawler Engine**: Responsible for discovering endpoints and assets (referencing "Katana").
3.  **Scanner Engine**: The core logic that matches discovered endpoints with security templates.
4.  **Reporting Module**: Generates human-readable HTML reports and machine-parsable JSON outputs.

## 3. Key Design Decisions

### 3.1. Template-Based Scanning Engine
**Decision:** Segregate vulnerability detection logic from the core codebase using YAML-based templates.
**Rationale:** 
- **Extensibility:** Users can add new vulnerability checks without modifying the Python source code.
- **Maintainability:** Security rules change frequently; keeping them in configuration files (`templates/`) makes updates easier.
- **Clarity:** YAML allows for a declarative definition of request patterns and matching rules (e.g., status codes, response bodies), making it easier to understand what a specific test does.

### 3.2. Lab Mode & Docker Integration
**Decision:** Integrate Docker management directly into the CLI via a `--lab` flag (e.g., `squeezer init --lab juice-shop`).
**Rationale:**
- **Ease of Use:** "Lab Mode" drastically lowers the barrier to entry for users who want to test the scanner against a known vulnerable application like OWASP Juice Shop.
- **Automation:** The scanner can automatically start the target environment, run the scan, and tear it down, providing a complete end-to-end testing lifecycle.
- **Isolation:** Running targets in containers ensures tests are performed in a clean, reproducible environment.

### 3.3. Crawler Abstraction (KatanaCrawler)
**Decision:** Encapsulate the crawling logic within a dedicated `KatanaCrawler` class, utilizing ProjectDiscovery's Katana instead of a browser-based solution like Playwright.
**Rationale:**
- **Simplicity vs. Complexity:** Initial prototypes experimented with **Playwright** to handle dynamic content. However, this added excessive complexity to the module (managing browser instances, heavy dependencies). Switching to **Katana** proved to be a more straightforward solution that balanced capability with ease of integration.
- **Separation of Concerns:** Discovery (finding URLs) and Scanning (attacking URLs) are distinct phases.
- **Enhanced Discovery:** Recent improvements (commits `e4a518c`, `7bd0a9e`) added support for JavaScript crawling, XHR, and form extraction. Processing this complexity in a separate module keeps the main scanner loop clean.

### 3.4. Minimalist Core & Refactoring
**Decision:** Aggressively remove unused features and complex abstractions that provided little immediate value.
**Evidence in History:**
- **Removal of `ScanProfile` (Commit `ab2ab42`):** The initial implementation had a complex "Profile" object that was deemed unnecessary overhead. It was removed in favor of a simpler configuration model.
- **Removal of MCP Server (Commit `6c56eae`):** An initial integration with "Model Context Protocol" was stripped out to focus on the core DAST functionality.
- **Cleanup of Deprecated Templates:** Older or less reliable templates (e.g., certain SSRF or IDOR checks) were removed or refactored to ensure high-fidelity results (low false positives).

### 3.5. Reporting Strategy
**Decision:** Dual-format reporting (Rich Console Output + HTML/JSON Artifacts).
**Rationale:**
- **Immediate Feedback:** Reference to `rich` library for real-time console progress bars and summary tables provides immediate visibility to the user.
- **Comprehensive Artifacts:** The Jinja2-based HTML report allows for detailed post-scan analysis, grouping findings by vulnerability type (OWASP categories) and severity. JSON output supports integration with other tools or CI/CD pipelines.

### 3.6. Scaffolding for New Targets
**Decision:** Implement an `init` command that scaffolds configuration.
**Rationale:** 
- Configuration for DAST tools can be complex (which endpoints to skip, authentication tokens, etc.). The scaffolding tool (`squeezer/scaffolder.py`) automates the creation of a baseline `app.yaml`, making it easier for users to onboard new applications.

## 4. Evolution of the Project
The project has evolved from a broad prototype into a focused tool:
1.  **Prototype Phase:** Initial commits included experimental features (MCP, complex profiles).
2.  **Refactoring Phase:** Significant effort was spent simplified the codebase (mid-project commits), standardizing the template format, and improving code quality.
3.  **Enhancement Phase:** Recent work has focused on specific vulnerability classes (JWT, NoSQL, IDOR) and improving the reliability of the "Lab" environment.
