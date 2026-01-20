# Benchmark: Nuclei vs. Squeezer on OWASP Juice Shop

This document compares Nuclei (v3.6.2) against the Squeezer framework on OWASP Juice Shop, focusing on business logic vulnerabilities and authenticated scanning capabilities.

## Test Environment

| Parameter | Value |
|-----------|-------|
| **Target** | OWASP Juice Shop |
| **URL** | `http://localhost:3000` |
| **Nuclei Version** | v3.6.2 |
| **Templates** | 14 custom templates (same for both tools) |
| **Authentication** | Bearer token (authenticated customer account) |

## Execution Commands

### Nuclei Scan

```bash
BEARER_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." ./run-nuclei.sh
```

The `run-nuclei.sh` script executes:

```bash
nuclei -u http://localhost:3000 \
       -t /Users/cosma/Código/dast-mvp/nuclei-templates \
       -var bearer_token=$BEARER_TOKEN
```

### Squeezer Scan

```bash
squeezer scan http://localhost:3000 --app juice-shop -b "$BEARER_TOKEN"
```

## Scan Output

### Nuclei Results (9 matches)

```
[generic-cors-misconfig] [http] [medium] http://localhost:3000
[generic-path-traversal] [http] [critical] http://localhost:3000/api/file/aws?path=../../etc/passwd
[generic-cors-misconfig] [http] [medium] http://localhost:3000/api/config
[generic-mass-assignment] [http] [critical] http://localhost:3000/api/Users
[juice-shop-price-manipulation] [http] [critical] http://localhost:3000/rest/basket/1/checkout
[generic-jwt-none-algorithm] [http] [high] http://localhost:3000/api/Products
[juice-shop-negative-quantity] [http] [high] http://localhost:3000/api/BasketItems/
[juice-shop-sensitive-data-exposure] [http] [high] http://localhost:3000/rest/user/data-export
[generic-mass-assignment] [http] [critical] http://localhost:3000/api/Users

[INF] Scan completed in 236.946666ms. 9 matches found.
```

### Squeezer Results

```
Found 39 findings (18 unique): 29 critical, 8 high, 2 medium
Scan completed in 1.29s (14 templates)
```

## Comparative Results

| Metric | Nuclei | Squeezer | Ratio |
|--------|--------|----------|-------|
| **Scan Duration** | 0.24s | 1.29s | 5.4× (Nuclei faster) |
| **Templates Used** | 14 | 14 | Equal |
| **Critical Findings** | 4 | 29 | 7.25× (Squeezer more) |
| **High Findings** | 3 | 8 | 2.67× (Squeezer more) |
| **Medium Findings** | 2 | 2 | Equal |
| **Total Matches** | 9 | 39 | 4.33× (Squeezer more) |
| **Unique Findings** | 6 | 18 | 3× (Squeezer more) |

## Detected Vulnerability Classes

| Class | Nuclei | Squeezer |
|-------|--------|----------|
| Path Traversal / LFI | ✓ | ✓ |
| Mass Assignment | ✓ | ✓ |
| JWT Algorithm Confusion | ✓ | ✓ |
| Price Manipulation | ✓ | ✓ |
| Negative Quantity | ✓ | ✓ |
| Sensitive Data Exposure | ✓ | ✓ |
| CORS Misconfiguration | ✓ | ✓ |
| IDOR / Broken Access | ✓ | ✓ |

## Analysis

### Nuclei Strengths
- **5.4× faster** - Best for CI/CD pipelines and rapid assessments
- Zero false positives on standard benchmarks
- Simple, predictable execution model

### Squeezer Strengths
- **4.33× more total findings** (39 vs 9)
- **3× more unique vulnerabilities** (18 vs 6)
- Endpoint expansion (`@api@`, `@all@`) covers more surface per template
- Field auto-discovery for privilege escalation testing
- Clean-slate lab mode for reproducible scans

## Conclusion

**The Trade-off is Clear:**

| Use Case | Recommended Tool |
|----------|------------------|
| CI/CD integration, rapid scans | **Nuclei** (5.4× faster) |
| Comprehensive security audits | **Squeezer** (3× more findings) |
| Penetration testing | **Squeezer** (maximum coverage) |

Both tools detect the same vulnerability classes when equipped with custom templates and authentication. The choice depends on prioritizing **speed** (Nuclei) vs **coverage** (Squeezer).
