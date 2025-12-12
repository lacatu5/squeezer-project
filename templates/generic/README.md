# Generic Vulnerability Templates

These templates work on **any** web application. They use variable endpoints that are resolved from your config file.

## Supported Vulnerability Types

| Category | Templates |
|----------|-----------|
| Injection | `injection/sqli-get.yaml`, `injection/sqli-post.yaml`, `injection/command-injection.yaml` |
| XSS | `xss/reflected.yaml`, `xss/stored.yaml` |
| JWT | `jwt/*.yaml` |
| Other | `ssrf.yaml`, `path-traversal.yaml`, `info-disclosure.yaml` |

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
