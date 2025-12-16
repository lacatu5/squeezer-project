# Generic Vulnerability Templates

These templates work on **any** web application. They use variable endpoints that are resolved from your config file.

## Structure

```
generic/
├── access-control/        # IDOR, Path Traversal, CSRF, CORS
├── authentication/         # JWT issues, Login Bypass
├── components/            # Vulnerable Dependencies
├── injection/             # SQLi, Command Injection, XSS, XXE, SSTI
├── information-disclosure/ # Info Disclosure
├── misconfiguration/      # Security Headers, Directory Listing
├── other/                 # HPP, Prototype Pollution
└── ssrf/                  # Server-Side Request Forgery
```

## Templates by Category

### access-control/
| File | Description |
|------|-------------|
| `idor.yaml` | Insecure Direct Object Reference |
| `path-traversal.yaml` | Path Traversal |
| `csrf.yaml` | CSRF |
| `cors-misconfiguration.yaml` | CORS Misconfiguration |
| `open-redirect.yaml` | Open Redirect |

### authentication/
| File | Description |
|------|-------------|
| `jwt-claim-escalation.yaml` | JWT Claim Escalation |
| `jwt-none-algorithm.yaml` | JWT None Algorithm |
| `jwt-no-expiration.yaml` | JWT No Expiration |
| `jwt-weak-secret.yaml` | JWT Weak Secret |
| `login-sqli-bypass.yaml` | Login SQLi Bypass |

### components/
| File | Description |
|------|-------------|
| `vulnerable-libs.yaml` | Vulnerable Libraries |
| `dependency-exposure.yaml` | Dependency Exposure |

### injection/
| File | Description |
|------|-------------|
| `sqli-get.yaml` | SQL Injection (GET) |
| `sqli-post-json.yaml` | SQL Injection (POST JSON) |
| `sqli-union.yaml` | SQL Injection (UNION) |
| `command-injection.yaml` | Command Injection |
| `nosql-mongo.yaml` | NoSQL Injection (MongoDB) |
| `ssti.yaml` | Server-Side Template Injection |
| `xss-reflected.yaml` | Reflected XSS |
| `xss-stored.yaml` | Stored XSS |
| `xxe.yaml` | XXE Injection |
| `crlf-injection.yaml` | CRLF Injection |
| `email-header-injection.yaml` | Email Header Injection |

### information-disclosure/
| File | Description |
|------|-------------|
| `info-disclosure.yaml` | Information Disclosure |

### misconfiguration/
| File | Description |
|------|-------------|
| `security-headers.yaml` | Missing Security Headers |
| `server-version.yaml` | Server Version Disclosure |
| `options-method.yaml` | OPTIONS Method Enabled |

### other/
| File | Description |
|------|-------------|
| `hpp.yaml` | HTTP Parameter Pollution |
| `prototype-pollution.yaml` | Prototype Pollution |

### ssrf/
| File | Description |
|------|-------------|
| `ssrf.yaml` | Server-Side Request Forgery |

## How It Works

1. Template uses `{{endpoint_name}}` variable
2. Config maps `endpoint_name: /actual/path`
3. Engine expands template → concrete requests

## Example

**Template** (`injection/sqli-get.yaml`):
```yaml
generic:
  endpoint: "{{sqli}}"
  parameter: "id"
```

**Config** (`myapp.yaml`):
```yaml
endpoints:
  custom:
    sqli: /api/products?id=1&Submit=
```
