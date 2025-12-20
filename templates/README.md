# DAST Templates

This directory contains all vulnerability scan templates.

## Structure

```
templates/
├── generic/           # Generic vulnerability patterns (work on any app)
│   ├── injection/     # SQLi, NoSQLi, Command Injection
│   ├── xss/           # Cross-site scripting
│   ├── jwt/           # JWT attacks
│   └── ...
│
└── apps/             # App-specific business logic tests
    ├── juice-shop/   # Juice Shop business logic
    └── <your-app>/   # Add your app here
```

## Adding Templates for Your App

1. Create `templates/apps/<your-app>/`
2. Add business logic templates (IDOR, price manipulation, etc.)
3. Create a config file in `configs/examples/<your-app>.yaml`

## Generic Templates

Use generic templates for common vulnerabilities:
- SQL Injection, XSS, Command Injection, SSRF, etc.
- They work on ANY application - just configure endpoints in your config.
