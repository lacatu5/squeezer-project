# DAST MVP - External Resources

## Payload Files Included

| File | Description | Count |
|------|-------------|-------|
| `sqli-generic.txt` | SQL injection payloads (boolean, time, union, error-based) | 150+ |
| `command-injection.txt` | Command injection payloads (Unix, Windows, blind) | 100+ |

## How to Download More Payloads

### SecLists (The Gold Standard)
```bash
# Clone the full repository
git clone https://github.com/danielmiessler/SecLists.git

# Or download specific folders
curl -L https://github.com/danielmiessler/SecLists/archive/master.zip | unzip -
```

Key files from SecLists:
- `SecLists/Fuzzing/` - All injection payloads
- `SecLists/Discovery/Web-Content/` - Path fuzzing
- `SecLists/Passwords/` - Password brute force

### Nuclei Templates
```bash
# Clone 6000+ YAML templates
git clone https://github.com/projectdiscovery/nuclei-templates.git

# Key folders:
# - http/vulnerabilities/ - CVEs
# - http/exposures/ - Info leaks
# - http/technologies/ - Tech detection
```

## Python Libraries to Install

```bash
# SQL Injection detection
pip install sqlmap          # Full SQLi testing framework
pip install libinjection     # SQLi/XSS detection (C library)

# Web scanning
pip install httpx           # Async HTTP (already using)
pip install aiohttp         # Alternative async HTTP
pip install rapidfuzz       # Fast fuzzy matching

# Pattern matching
pip install re2             # Faster regex
pip install pyyaml          # YAML parsing (already using)
```

## Useful Python Libraries for DAST

| Library | Purpose | Install |
|---------|---------|---------|
| `libinjection` | SQLi/XSS pattern matching | `pip install libinjection` |
| `sqlmap` | Full SQLi framework | `pip install sqlmap` |
| `httpx` | Async HTTP client | `pip install httpx` |
| `rapidfuzz` | Fuzzy string matching | `pip install rapidfuzz` |
| `beautifulsoup4` | HTML parsing | `pip install beautifulsoup4` |
| `pyyaml` | YAML configs | `pip install pyyaml` |

## Loading Payloads from Files

To use external payload files in templates:

```yaml
generic:
  endpoint: "{{sqli}}"
  method: GET
  parameter: "id"

  # Load from file
  payloads_file: "payloads/sqli-generic.txt"

  # Or inline (current approach)
  payloads:
    - name: "baseline"
      value: "test"
```

## Online Resources

- **SecLists**: https://github.com/danielmiessler/SecLists
- **Nuclei Templates**: https://github.com/projectdiscovery/nuclei-templates
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **OWASP Cheat Sheets**: https://cheatsheetseries.owasp.org/
- **CVE Database**: https://cve.mitre.org/

## Adding libinjection for Better Detection

```bash
# Install
pip install libinjection

# Usage in code
from libinjection import sqli

state = sqli.detect("' OR '1'='1")
# Returns: (True, "sqli", fingerprint_string)
```
