# App-Specific Templates

These folders contain **business logic** tests specific to each application.

## Why Separate?

Generic vulnerability patterns (SQLi, XSS, etc.) go in `../generic/`.

Only app-specific tests go here:
- Price manipulation
- IDOR (Insecure Direct Object Reference)
- Business logic flaws
- Workflow bypasses

## Adding Your App

1. Create folder: `templates/apps/<your-app>/`
2. Add templates following the naming pattern
3. Reference them in your scan: `-t templates/apps/<your-app>/`

## Example

```
apps/
├── juice-shop/
│   ├── basket-idor.yaml       # IDOR in basket operations
│   ├── price-manipulation.yaml # Business logic flaw
│   └── ...
└── myapp/
    ├── discount-abuse.yaml
    └── ...
```
