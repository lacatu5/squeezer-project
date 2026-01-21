# Prompts log

**Document purpose:** Some technical challenges and research queries during development.

---

## Format: Problem → Technical Query

Each entry describes a technical problem I encountered and the corresponding research query to explore solutions.

---

## 1. Project Structure & Setup

**Problem:** Needed to design a clean Python project structure for a CLI-based security tool with YAML template loading.

**Query:** I want to create a DAST scanner in Python using YAML templates (Nuclei-like, web-app focused). Propose a clean project structure and a `pyproject.toml`. Set up a Typer CLI for `squeezer` with `scan` and `init`, using Rich for readable output.

---

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

**Problem:** Matcher classes needed for structured response validation.

**Query:** Create matcher classes: status code matcher, word matcher (body), regex matcher, and header matcher. Return a structured match result with evidence.

---

**Problem:** Needed flexible matcher condition evaluation (sometimes all must match, sometimes any).

**Query:** Add support for matcher conditions: sometimes all matchers must match, sometimes any. Design the config fields and evaluation.

---

**Problem:** Detecting absent patterns (e.g., missing security headers).

**Query:** Add `negative: true` so a matcher passes when the pattern is NOT present. Useful for missing security headers.

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

---

**Problem:** Filtering noise from crawl results (static assets don't need security scanning).

**Query:** Filter static content (js/css/images/fonts) from crawl results using a JSON config file for extensions + ignored paths.

---

## 6. Variable System

**Problem:** Dynamic variable substitution in URLs, headers, and request bodies.

**Query:** Implement `{{variable}}` interpolation in URLs/headers/body. Also support defaults like `{{user_id | 1}}`.

---

**Problem:** Adding randomness for test data generation.

**Query:** Add helper functions inside interpolation: `rand_base(n)` and `rand_int(min,max)`.

---

**Problem:** Variables extracted in request 1 were not available in request 2.

**Query:** Variables extracted in request 1 are not available in request 2. Fix variable scope to persist across a request chain.

---

## 7. Authentication

**Problem:** Supporting multiple authentication methods for different target types.

**Query:** Add authentication support: none, bearer token injection, and a lab mode for Juice Shop (start Docker, wait for readiness, login, retrieve token).

---

**Problem:** Bearer token injection across all requests with template override capability.

**Query:** When `--bearer` is provided, inject `Authorization: Bearer <token>` in every request, unless the template overrides it.

---

**Problem:** Automated lab environment setup with authentication.

**Query:** Implement `--lab juice-shop` that starts a Docker container, waits for readiness, and retrieves a fresh token automatically.

---

**Problem:** Juice Shop login flow automation.

**Query:** Implement automatic login for Juice Shop: POST `/rest/user/login`, parse JSON, extract token, and store it.

---

## 8. Template Development

**Problem:** Creating comprehensive vulnerability check templates covering common web app issues.

**Query:** Write a set of YAML templates (generic + app-specific) covering issues like sensitive data exposure, CORS misconfiguration, traversal, JWT "none", IDOR, mass assignment, file upload bypass, LFI, and a small Juice Shop suite.

---

**Problem:** Detecting sensitive data leakage in responses.

**Query:** Write a generic template to detect sensitive data in responses: emails, API keys, passwords, tokens, credit card-like patterns.

---

**Problem:** CORS misconfiguration detection.

**Query:** Write a template that sends an `Origin: https://evil.com` header and checks whether ACAO reflects it.

---

**Problem:** Path traversal attack detection.

**Query:** Write a traversal template using payloads like `../../../../etc/passwd` and detect known file markers.

---

**Problem:** JWT algorithm confusion testing.

**Query:** Add a JWT test template that attempts a `alg: none` token and checks if privileged access is granted.

---

**Problem:** IDOR vulnerability detection patterns.

**Query:** Create an IDOR template: try accessing resources with different IDs and detect unauthorized access patterns.

---

**Problem:** Mass assignment vulnerability testing.

**Query:** Write a template to test for mass assignment by sending additional JSON fields (e.g., `role=admin`) and checking if they are accepted.

---

**Problem:** Juice Shop-specific business logic vulnerabilities.

**Query:** Add Juice Shop templates for negative quantity and price manipulation at checkout/cart endpoints.

---

**Problem:** File upload bypass techniques.

**Query:** Add a template that uploads a file with a double extension (e.g., `.php.jpg`) or mismatched content-type.

---

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

**Problem:** Reusable components for consistent report rendering.

**Query:** Create reusable macros for severity badges, OWASP tags, and rendering evidence.

---

**Problem:** Deduplicating similar findings across multiple endpoints.

**Query:** Group similar findings across multiple endpoints so the report shows "unique issues" + count.

---

**Problem:** Timestamp tracking was showing incorrect values.

**Query:** Why are my timestamps wrong?

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

---

**Problem:** Cleanup needed for production readiness.

**Query:** Remove unused imports and leftover debug prints. Keep only user-facing CLI output.

---

**Problem:** Git repository tracking generated output files.

**Query:** I accidentally committed generated output / results. Help me remove those from tracking and update `.gitignore`.

---

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

---

**Problem:** OWASP category mapping accuracy.

**Query:** Which OWASP category does "broken access control" map to?

---

**Problem:** Regex pattern for email detection.

**Query:** Give me a solid regex for matching emails in a response body.

---

**Problem:** Reducing false positives in DAST checks.

**Query:** Best practices for writing DAST checks without too many false positives?

---

## 15. Standards & Updates

**Problem:** OWASP categories needed updating to latest version.

**Query:** Update the OWASP categories enum to the latest version and adjust template tags accordingly.

---

**Problem:** Template collection had outdated checks with high false positives.

**Query:** Remove deprecated templates (e.g., SSRF/old injection variants) and keep only templates that have clear evidence and low false positives.

---

**Problem:** Inconsistent template metadata across the collection.

**Query:** Standardize template metadata fields: author, description, references, tags, severity, and OWASP category.

---

**Problem:** CLI usability needed improvement.

**Query:** Improve CLI help text and provide examples for common scans (generic, app profile, bearer auth, lab mode).

---

**Problem:** Finding safe default values for timeouts and concurrency.

**Query:** Pick safe defaults for timeouts and concurrency. Make sure scans don't overwhelm a target.

---

**Problem:** End-to-end validation of the scanner against real target.

**Query:** Run a full scan on Juice Shop with a bearer token and confirm templates execute without crashes. Summarize findings and errors cleanly.
