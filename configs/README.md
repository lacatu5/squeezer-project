# DAST Configurations

Configuration files for target applications.

## Quick Start

1. Copy `examples/template.yaml` → `<your-app>.yaml`
2. Edit the `endpoints.custom` section to map generic template variables to your app's paths
3. Run: `dast scan <URL> --config configs/<your-app>.yaml -t templates/generic`

## Example

```yaml
# configs/myapp.yaml
name: My Application
base_url: https://myapp.com

endpoints:
  custom:
    sqli: /api/search?q=           # Maps to {{sqli}} in templates
    xss_reflected: /api/search?q=  # Maps to {{xss_reflected}} in templates
```

## Files

- `examples/template.yaml` - Configuration template with all options
- `examples/juice-shop.yaml` - Example configuration for Juice Shop
