# DAST MVP

Minimal template-based Dynamic Application Security Testing (DAST) framework.

## Features

- **YAML Templates**: Define vulnerability checks in simple YAML
- **Multi-Auth Support**: Form login, Bearer tokens, Basic auth
- **Variable Interpolation**: `{{variable}}`, `{{endpoints.xxx}}`, `{{rand_base(16)}}`
- **Matchers**: Status code, word, regex, JSONPath
- **Extractors**: Pull data from responses for reuse

## Quick Start

```bash
# Install
pip install -e .

# Scan a target
dast scan http://localhost:3000 --config config/juice-shop.yaml

# Run specific templates
dast scan http://localhost:3000 --template templates/

# List templates
dast list
```

## Configuration

```yaml
# config/target.yaml
name: "My App"
base_url: "http://localhost:8080"

authentication:
  type: form  # form, bearer, basic, none
  login:
    url: "/api/login"
    method: POST
    payload:
      username: "{{AUTH_USERNAME}}"
      password: "{{AUTH_PASSWORD}}"
    extract:
      - name: token
        location: body
        selector: "$.token"
    apply:
      headers:
        Authorization: "Bearer {{token}}"
  username: "user@example.com"
  password: "secret"

endpoints:
  api: "/api"
  users: "/api/users"
  products: "/api/products"

variables:
  admin_id: "1"
```

## Template Example

```yaml
# templates/sql-login.yaml
id: sql-login-bypass
info:
  name: SQL Injection in Login
  severity: high
  tags:
    - sqli
    - auth

requests:
  - name: "Test SQL injection in login"
    method: POST
    path: "/api/login"
    headers:
      Content-Type: "application/json"
    body: '{"username": "admin{{rand_int()}}", "password": "' OR 1=1--"}'
    matchers:
      - type: status
        condition: in
        values: [200, 201]
      - type: word
        words: ["token", "session"]
        part: body
        condition: or
```

## Project Structure

```
dast-mvp/
├── dast/
│   ├── __init__.py
│   ├── cli.py           # CLI entry point
│   ├── config.py        # Config loading
│   ├── engine.py        # Template execution engine
│   ├── matchers.py      # Response matchers
│   ├── auth.py          # Authentication handler
│   └── templates/       # Built-in templates
├── config/              # Example configs
├── templates/           # User templates
└── tests/              # Tests
```
