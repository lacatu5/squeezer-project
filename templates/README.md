# Squeezer Templates

Generic DAST templates for security testing.

## Template Syntax

### Endpoint Placeholders

Templates use placeholder syntax to match discovered endpoints:

| Placeholder | Description |
|------------|-------------|
| `@api@` | Expands to all API endpoints (paths containing `/api/`) |
| `@api@/1` | Expands to API endpoints with `/1` suffix (ID enumeration) |
| `@api@/users@` | Expands to API endpoints matching "users" (with fuzzy matching) |
| `@api@/cart@/1` | Expands to cart/basket endpoints with ID 1 |
| `@all@` | Expands to all discovered endpoints |

### Fuzzy Matching

The scanner uses fuzzy matching for common endpoint synonyms:

| Pattern | Matches |
|---------|---------|
| `cart` | cart, basket, checkout, order |
| `user` | user, users, User, account, profile |
| `product` | product, products, item, items |
| `register` | users, register, sign-up, signup, create |

### Variable Interpolation

| Syntax | Description |
|--------|-------------|
| `{{rand_int()}}` | Random integer (10000-99999) |
| `{{rand_int(1,100)}}` | Random integer in range |
| `{{uuid()}}` | Random UUID |
| `{{rand_base(10)}}` | Random alphanumeric string |

### Auto-Discovery

Templates can auto-discover common field names:

```yaml
body: '{"email": "test@test.com", "{{autodiscover:privilege}}": "admin"}'
```

This expands to multiple requests, each trying a different field name:
- `role`
- `userType`
- `type`
- `permissions`
- `isAdmin`
- `is_admin`
- `role_id`
- `userRole`
- `role_type`

Available auto-discovery types:

| Type | Fields |
|------|--------|
| `privilege` | role, userType, type, permissions, isAdmin, is_admin, role_id, userRole, role_type |
| `status` | isActive, is_active, status, enabled, verified, active |
| `token` | deluxeToken, token, authToken, apiToken, access_token, session_token |
| `id` | id, userId, user_id, Id, ID |

## Configuration

### Custom Field Patterns

Edit `squeezer/config/autodiscovery.json` to add custom field patterns:

```json
{
  "privilege": ["role", "userType", "type", "permissions", "isAdmin"],
  "status": ["isActive", "is_active", "status", "enabled"],
  "token": ["deluxeToken", "token", "authToken"]
}
```

### Endpoint Synonyms

Edit `squeezer/config/endpoints.json` to add custom endpoint synonyms:

```json
{
  "synonyms": {
    "cart": ["cart", "basket", "checkout", "order"],
    "user": ["user", "users", "User", "account", "profile"]
  }
}
```

## Template Reference

### IDOR (`generic-idor`)

Tests for insecure direct object reference vulnerabilities via sequential ID enumeration.

### Input Validation (`generic-input-validation`)

Tests if endpoints accept empty or null values in required fields.

### Mass Assignment (`generic-mass-assignment`)

Tests for privilege escalation via mass assignment vulnerabilities.

### Business Logic (`generic-business-logic`)

Tests for negative value acceptance in numeric fields (quantity, price).

### CORS Misconfiguration (`generic-cors-misconfig`)

Detects overly permissive CORS policies.

### Rate Limiting (`generic-rate-limit`)

Tests for absence of rate limiting on endpoints.

### SSRF (`generic-ssrf`)

Tests for server-side request forgery vulnerabilities.

## Example Template

```yaml
id: generic-example
info:
  name: Example Template
  description: Tests for a vulnerability
  owasp_category: A01:2025
  severity: high
  tags:
    - generic
    - example

variables:
  test_email: "test{{rand_int()}}@test.local"

requests:
  - name: Test endpoint
    method: POST
    path: "@api@/users@"
    headers:
      Content-Type: application/json
    body: '{"email": "{{test_email}}", "password": "Test1234!", "{{autodiscover:privilege}}": "admin"}'
    matchers:
      - type: status
        condition: in
        status:
          - 200
          - 201
    on_match:
      vulnerability: EXAMPLE_VULN
      message: Example vulnerability found
      remediation: Fix the vulnerability
```
