# AI Prompt Log — Squeezer

**Project:** Squeezer (template-based DAST framework)

**Document purpose:** Provide an auditable record of AI prompts used during development (consolidated prompts + a verbatim prompt history).

---

## 1. Scope and conventions

### 1.1 Scope
This log captures *prompts* (i.e., the inputs given to AI assistants) used to design and implement Squeezer. It is not a complete record of all prompts and their outputs, code changes, or intermediate experiments.

### 1.2 Model usage policy
- **Implementation / development prompts** (code, refactors, features): **z.ai Shippu (GLM-4.6)**
- **Non-development prompts** (definitions, OWASP context, quick explanations): **Gemini 3 Pro**

---

## 2. Prompt catalog

### Consolidated prompts

**Prompt 1:**
> I want to create a DAST scanner in Python using YAML templates (Nuclei-like, web-app focused). Propose a clean project structure and a `pyproject.toml`. Set up a Typer CLI for `squeezer` with `scan` and `init`, using Rich for readable output.

**Prompt 2:**
> Create Pydantic models for a DAST tool: `TargetConfig`, `Template`, `Finding`, and `ScanReport`. Add an OWASP Top 10 enum and allow templates to be tagged with an OWASP category.

**Prompt 3:**
> Load YAML templates from disk. Support both app-specific templates under `templates/apps/` and generic templates under `templates/generic/`.

**Prompt 4:**
> Implement async request execution with `httpx` (method/path/headers/query/json/body/timeouts) and add `{{variable}}` interpolation with defaults. Add a couple of small helper functions, and make scans resilient to per-template failures (capture errors in the report). Fix any request-building bugs.

**Prompt 5:**
> Implement matchers (status/word/regex/header/JSON), AND/OR logic, and `negative: true`. Add regex extractors that persist variables across requests and an `EvidenceStrength` enum.

**Prompt 6:**
> Integrate Katana crawling (subprocess + JSON output). Store discovered endpoints, filter static content, and track basic crawl stats.

**Prompt 7:**
> Add authentication support: none, bearer token injection, and a lab mode for Juice Shop (start Docker, wait for readiness, login, retrieve token).

**Prompt 8:**
> Write a set of YAML templates (generic + app-specific) covering issues like sensitive data exposure, CORS misconfiguration, traversal, JWT “none”, IDOR, mass assignment, file upload bypass, LFI, and a small Juice Shop suite.

**Prompt 9:**
> Create an HTML report with Jinja2: summary metrics, findings grouped by severity, evidence, and correct timestamps/duration.

**Prompt 10:**
> Improve reliability and hygiene (cleanup, `.gitignore`, retries, concurrency/rate limits). Fix query params from crawl results, multi-step variable scope, and OR matcher logic. Update OWASP tags, standardize template metadata, improve CLI help, and validate end-to-end.

---

### Verbatim prompt history

### Prompt 1
> I want to create a DAST scanner in Python. It should use YAML templates similar to Nuclei, but focused on web app vulnerabilities. Propose a clean project structure and a `pyproject.toml`.

### Prompt 2
> Create Pydantic models for a DAST tool: `TargetConfig` (base_url, auth), `Template` (requests + matchers), `Finding` (severity + evidence), and `ScanReport` (metrics + results).

### Prompt 3
> Set up a Typer CLI for `squeezer` with `scan` and `init` commands. Use Rich output (tables, colors) and show a banner.

### Prompt 4
> Add an enum for OWASP Top 10 categories and allow templates to be tagged with an OWASP category.

### Prompt 5
> How do I load YAML templates from a directory in Python? I need both app-specific templates under `templates/apps/` and generic templates under `templates/generic/`.

### Prompt 6
> Implement async request execution with `httpx`. Support method, path, headers, query params, JSON/body, and timeouts.

### Prompt 7
> Implement `{{variable}}` interpolation in URLs/headers/body. Also support defaults like `{{user_id | 1}}`.

### Prompt 8
> Add helper functions inside interpolation: `rand_base(n)` and `rand_int(min,max)`.

### Prompt 9
> Make the scanner resilient: template failures should not crash the whole scan. Capture errors per-template and include them in the report.

### Prompt 10
> my request building is wrong, fix it

### Prompt 11
> Create matcher classes: status code matcher, word matcher (body), regex matcher, and header matcher. Return a structured match result with evidence.

### Prompt 12
> Add support for matcher conditions: sometimes all matchers must match, sometimes any. Design the config fields and evaluation.

### Prompt 13
> Add `negative: true` so a matcher passes when the pattern is NOT present. Useful for missing security headers.

### Prompt 14
> Add a JSON body matcher that can verify nested paths like `data.user.id` and compare values.

### Prompt 15
> Add regex extractors that capture values from responses and store them into variables for later requests.

### Prompt 16
> Add an `EvidenceStrength` enum (direct_observation, inference, heuristic) and include it in match results and findings.

### Prompt 17
> Integrate Katana as a subprocess, parse JSON output, and store discovered endpoints. Enable JavaScript crawling by default.

### Prompt 18
> Filter static content (js/css/images/fonts) from crawl results using a JSON config file for extensions + ignored paths.

### Prompt 19
> Write a function that classifies endpoints into `api`, `page`, `auth`, `admin`, `static` based on URL patterns.

### Prompt 20
> Add keyword-based detection for “interesting endpoints” (admin, debug, backup, config, token, password) driven by config.

### Prompt 21
> Track crawler statistics: totals, unique URLs, status code distribution, API count, interesting endpoints, duration.

### Prompt 22
> Add authentication support: none, bearer token, and lab mode. Store it in a model and make it available to the scanner.

### Prompt 23
> When `--bearer` is provided, inject `Authorization: Bearer <token>` in every request, unless the template overrides it.

### Prompt 24
> Implement `--lab juice-shop` that starts a Docker container, waits for readiness, and retrieves a fresh token automatically.

### Prompt 25
> Implement automatic login for Juice Shop: POST `/rest/user/login`, parse JSON, extract token, and store it.

### Prompt 26
> docker currently shows an error with libraries, but docker compose down and compose up --build does not work. can you help me to understand better the issue?

### Prompt 27
> Write a generic template to detect sensitive data in responses: emails, API keys, passwords, tokens, credit card-like patterns.

### Prompt 28
> Write a template that sends an `Origin: https://evil.com` header and checks whether ACAO reflects it.

### Prompt 29
> Write a traversal template using payloads like `../../../../etc/passwd` and detect known file markers.

### Prompt 30
> Add a JWT test template that attempts a `alg: none` token and checks if privileged access is granted.

### Prompt 31
> Create an IDOR template: try accessing resources with different IDs and detect unauthorized access patterns.

### Prompt 32
> Write a template to test for mass assignment by sending additional JSON fields (e.g., `role=admin`) and checking if they are accepted.

### Prompt 33
> Add Juice Shop templates for negative quantity and price manipulation at checkout/cart endpoints.

### Prompt 34
> Add a template that uploads a file with a double extension (e.g., `.php.jpg`) or mismatched content-type.

### Prompt 35
> Write a template for null-byte LFI (`%00`) and verify with response evidence.

### Prompt 36
> add more templates

### Prompt 37
> Create an HTML report with Jinja2: summary stats, findings grouped by severity, and a detailed section per finding (request/response + evidence).

### Prompt 38
> Improve the report UI: dark theme, cards, severity badges, and readable code blocks.

### Prompt 39
> Create reusable macros for severity badges, OWASP tags, and rendering evidence.

### Prompt 40
> Group similar findings across multiple endpoints so the report shows “unique issues” + count.

### Prompt 41
> Track scan start/end timestamps and duration seconds. Show them in the report.

### Prompt 42
> why are my timestamps wrong?

### Prompt 43
> Refactor the codebase: remove obsolete functions, unused parameters, and deprecated logic (keep behavior stable).

### Prompt 44
> Remove unused imports and leftover debug prints. Keep only user-facing CLI output.

### Prompt 45
> I accidentally committed generated output / results. Help me remove those from tracking and update `.gitignore`.

### Prompt 46
> Add retries with exponential backoff using Tenacity. Retry on connection errors/timeouts but not on HTTP 4xx/5xx.

### Prompt 47
> Implement a `--parallel` option and a request delay option so scans can be rate-limited.

### Prompt 48
> My scanner ignores query parameters from crawl results. Parse the query string and store discovered params so templates can reuse them.

### Prompt 49
> Variables extracted in request 1 are not available in request 2. Fix variable scope to persist across a request chain.

### Prompt 50
> OR condition is behaving like AND. Find the bug in matcher evaluation and fix it.

### Prompt 51
> Update the OWASP categories enum to the latest version and adjust template tags accordingly.

### Prompt 52
> Remove deprecated templates (e.g., SSRF/old injection variants) and keep only templates that have clear evidence and low false positives.

### Prompt 53
> Standardize template metadata fields: author, description, references, tags, severity, and OWASP category.

### Prompt 54
> Improve CLI help text and provide examples for common scans (generic, app profile, bearer auth, lab mode).

### Prompt 55
> Pick safe defaults for timeouts and concurrency. Make sure scans don’t overwhelm a target.

### Prompt 56
> Run a full scan on Juice Shop with a bearer token and confirm templates execute without crashes. Summarize findings and errors cleanly.


## 3. Non-development questions (background and conceptual)

### Prompt 57
> What are common JWT vulnerabilities in web apps?

### Prompt 58
> What is mass assignment and how do frameworks typically become vulnerable?

### Prompt 59
> Which OWASP category does “broken access control” map to?

### Prompt 60
> Give me a solid regex for matching emails in a response body.

### Prompt 61
> Best practices for writing DAST checks without too many false positives?

---

## 4. Maintenance notes

- Keep the consolidated prompts short and close to the recorded wording.
- Keep the verbatim prompt history minimal (only formatting fixes like renumbering/typos).
- If a prompt becomes obsolete, mark it as deprecated rather than deleting it.
- Do not store secrets (tokens, credentials) in prompts, especially in public repos.
