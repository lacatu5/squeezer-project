# DAST Template Tag Taxonomy

## Categories

### vulnerability-type
The primary weakness type (CWE/OWASP mapping)

- `idor` - Insecure Direct Object Reference
- `sqli` - SQL Injection
- `nosql` - NoSQL Injection
- `xss` - Cross-Site Scripting
- `rce` - Remote Code Execution
- `lfi` - Local File Inclusion
- `path-traversal` - Directory/Path Traversal
- `ssrf` - Server-Side Request Forgery
- `xxe` - XML External Entity
- `csrf` - Cross-Site Request Forgery
- `xxe` - XML External Entity
- `ssti` - Server-Side Template Injection
- `open-redirect` - Open Redirect
- `command-injection` - OS Command Injection

### security-issue
The security problem category

- `access-control` - Authorization failures (includes IDOR)
- `authentication` - Auth bypass, weak auth
- `injection` - Any injection type
- `code-injection` - Code execution via injection
- `input-validation` - Missing or weak validation
- `business-logic` - Flaws in application logic
- `file-upload` - Unsafe file upload
- `misconfiguration` - Server/app misconfig
- `info-disclosure` - Information leakage
- `rate-limit` - Missing rate limiting
- `dos` - Denial of Service

### impact
What an attacker can achieve

- `privilege-escalation` - Gain higher privileges
- `data-exfiltration` - Steal sensitive data
- `authentication-bypass` - Login without credentials
- `payment-bypass` - Avoid payment
- `refund-abuse` - Exploit refund logic
- `price-manipulation` - Modify prices

### scope
Template applicability

- `generic` - Works on any web app
- `app-specific` - tied to specific application
