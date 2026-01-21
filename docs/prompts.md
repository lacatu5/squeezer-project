# Prompts log

**Document purpose:** Some technical challenges and research queries during development.

---

## Format: Problem → Technical Query

Each entry describes a technical problem I encountered and the corresponding research query to explore solutions.

---

## 1. Project Structure & Setup

**Problem:** Designing data models for vulnerability detection with proper OWASP categorization.

**Query:** Create Pydantic models for a DAST tool: `TargetConfig`, `Template`, `Finding`, and `ScanReport`. Add an OWASP Top 10 enum and allow templates to be tagged with an OWASP category.

---

## 2. Template System

**Problem:** Hierarchical template loading from multiple directories with proper separation between generic and app-specific checks.

**Query:** Load YAML templates from disk. Support both app-specific templates under `templates/apps/` and generic templates under `templates/generic/`.

---

## 3. HTTP Execution Engine

**Problem:** Implementing async HTTP requests with proper error handling, timeout management, and resilience against individual template failures.

**Query:** Implement async request execution with `httpx` (method/path/headers/query/json/body/timeouts) and add `{{variable}}` interpolation with defaults. Add helper functions, and make scans resilient to per-template failures (capture errors in the report). Fix any request-building bugs.

---

**Problem:** Discovered bugs in request building logic during testing.

**Query:** My request building is wrong, fix it.

---

## 4. Detection Engine

**Problem:** Building a flexible matching system supporting multiple detection methods (status, word, regex, headers, JSON) with boolean logic.

**Query:** Implement matchers (status/word/regex/header/JSON), AND/OR logic, and `negative: true`. Add regex extractors that persist variables across requests.

---

**Problem:** Validating nested JSON responses with complex path traversal.

**Query:** Add a JSON body matcher that can verify nested paths like `data.user.id` and compare values.

---

**Problem:** Multi-request attack chains requiring data extraction between requests.

**Query:** Add regex extractors that capture values from responses and store them into variables for later requests.

---

## 5. Crawler Integration

**Problem:** Integrating external crawler (Katana) and parsing its output for endpoint discovery.

**Query:** Integrate Katana crawling (subprocess + JSON output). Store discovered endpoints, filter static content, and track basic crawl stats.

---

**Problem:** Discovered query parameters from crawl results were not being parsed for template use.

**Query:** My scanner ignores query parameters from crawl results. Parse the query string and store discovered params so templates can reuse them.


## 6. Variable System

**Problem:** Dynamic variable substitution in URLs, headers, and request bodies.

**Query:** Implement `{{variable}}` interpolation in URLs/headers/body. Also support defaults like `{{user_id | 1}}`.


## 7. Authentication

**Problem:** Supporting multiple authentication methods for different target types.

**Query:** Add authentication support: none, bearer token injection, and a lab mode for Juice Shop (start Docker, wait for readiness, login, retrieve token).

---

**Problem:** Bearer token injection across all requests with template override capability.

**Query:** When `--bearer` is provided, inject `Authorization: Bearer <token>` in every request, unless the template overrides it.

---

**Problem:** Automated lab environment setup with authentication.

**Query:** Implement `--lab juice-shop` that starts a Docker container, waits for readiness, and retrieves a fresh token automatically.


## 8. Template Development

**Problem:** Creating comprehensive vulnerability check templates covering common web app issues.

**Query:** Write a set of YAML templates (generic + app-specific) covering issues like sensitive data exposure, CORS misconfiguration, traversal, JWT "none", IDOR, mass assignment, file upload bypass, LFI, and a small Juice Shop suite.

---

**Problem:** Detecting sensitive data leakage in responses.

**Query:** Write a generic template to detect sensitive data in responses: emails, API keys, passwords, tokens, credit card-like patterns.

---

**Problem:** CORS misconfiguration detection.

**Query:** Write a template that sends an `Origin: https://evil.com` header and checks whether ACAO reflects it.

**Problem:** JWT algorithm confusion testing.

**Query:** Add a JWT test template that attempts a `alg: none` token and checks if privileged access is granted.

---

**Problem:** IDOR vulnerability detection patterns.

**Query:** Create an IDOR template: try accessing resources with different IDs and detect unauthorized access patterns.


**Problem:** LFI via null byte injection.

**Query:** Write a template for null-byte LFI (`%00`) and verify with response evidence.

---

## 9. Reporting

**Problem:** Generating HTML reports with proper grouping and evidence display.

**Query:** Create an HTML report with Jinja2: summary metrics, findings grouped by severity, evidence, and correct timestamps/duration.

---

**Problem:** Report UI improvement for better readability.

**Query:** Improve the report UI: dark theme, cards, severity badges, and readable code blocks.

---


## 10. Reliability & Performance

**Problem:** Template failures were crashing the entire scan.

**Query:** Make the scanner resilient: template failures should not crash the whole scan. Capture errors per-template and include them in the report.

---

**Problem:** Network reliability issues causing false positives.

**Query:** Add retries with exponential backoff using Tenacity. Retry on connection errors/timeouts but not on HTTP 4xx/5xx.

---

**Problem:** Needed concurrency control and rate limiting.

**Query:** Implement a `--parallel` option and a request delay option so scans can be rate-limited.

---

## 11. Code Maintenance

**Problem:** Codebase accumulated unused functions and parameters during iterative development.

**Query:** Refactor the codebase: remove obsolete functions, unused parameters, and deprecated logic (keep behavior stable).


## 12. Logic Bugs

**Problem:** OR condition in matchers was behaving like AND.

**Query:** OR condition is behaving like AND. Find the bug in matcher evaluation and fix it.

---

## 13. Docker & Environment

**Problem:** Docker library errors during container management.

**Query:** Docker currently shows an error with libraries, but docker compose down and compose up --build does not work. Can you help me to understand better the issue?

---

## 14. Background Research

**Problem:** Understanding JWT vulnerability patterns for effective template design.

**Query:** What are common JWT vulnerabilities in web apps?

---

**Problem:** Understanding mass assignment for detection template creation.

**Query:** What is mass assignment and how do frameworks typically become vulnerable?