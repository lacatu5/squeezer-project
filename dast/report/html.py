from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from dast.config import EvidenceStrength, ScanReport


_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)


def _split_filter(value, sep=None, maxsplit=-1):
    if isinstance(value, str):
        return value.split(sep, maxsplit)
    return []


def _truncate_filter(value, length=255, end=''):
    if isinstance(value, str) and len(value) > length:
        return value[:length] + end
    return value


_env.filters['split'] = _split_filter
_env.filters['truncate'] = _truncate_filter


def _severity_chart(severity):
    max_val = max((v for v in severity.values() if v > 0), default=1)
    colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}

    bars = []
    for key, label in [("critical", "Crit"), ("high", "High"), ("medium", "Med"), ("low", "Low")]:
        value = severity.get(key, 0)
        height = max(20, (value / max_val) * 160) if value else 4
        color = colors.get(key, "#64748b")
        bars.append(f'''
            <div class="bar">
                <div class="bar-value" style="color: {color}">{value}</div>
                <div class="bar-fill" style="height: {height}px; background: {color};"></div>
                <div class="bar-label">{label}</div>
            </div>''')
    return "".join(bars)


def _owasp_chart(owasp_data):
    if not owasp_data:
        return '<div style="color: #64748b; text-align: center; padding: 40px;">No OWASP findings</div>'

    max_val = max((d["count"] for d in owasp_data), default=1)

    bars = []
    for item in owasp_data:
        code = item["code"]
        value = item["count"]
        height = max(20, (value / max_val) * 160)
        color = "#dc2626" if code in ["A01", "A05", "A07"] else "#ea580c" if code in ["A02", "A03", "A04", "A06"] else "#ca8a04"
        bars.append(f'''
            <div class="bar">
                <div class="bar-value" style="color: {color}">{value}</div>
                <div class="bar-fill" style="height: {height}px; background: {color};"></div>
                <div class="bar-label">{code}</div>
            </div>''')
    return "".join(bars)


def _evidence_chart(evidence_data):
    total = sum(evidence_data.values()) or 1
    colors = {"direct": "#059669", "inference": "#d97706", "heuristic": "#0891b2"}

    bars = []
    for key, label in [("direct", "Direct"), ("inference", "Inf"), ("heuristic", "Heur")]:
        value = evidence_data.get(key, 0)
        height = max(20, (value / total) * 160) if value else 4
        color = colors.get(key, "#64748b")
        bars.append(f'''
            <div class="bar">
                <div class="bar-value" style="color: {color}">{value}</div>
                <div class="bar-fill" style="height: {height}px; background: {color};"></div>
                <div class="bar-label">{label}</div>
            </div>''')
    return "".join(bars)


_env.globals['severity_chart'] = _severity_chart
_env.globals['owasp_chart'] = _owasp_chart
_env.globals['evidence_chart'] = _evidence_chart


def generate_html_report(report: ScanReport, output_path: str) -> None:
    grouped = report.group_similar_findings()

    severity = {
        "critical": report.critical_count,
        "high": report.high_count,
        "medium": report.medium_count,
        "low": report.low_count,
    }

    owasp = []
    for category, (_, vuln_count) in report.get_owasp_summary().items():
        if vuln_count > 0:
            owasp.append({
                "code": category.split(":")[0],
                "count": vuln_count,
            })

    evidence = {
        "direct": sum(1 for f in grouped if f.evidence_strength == EvidenceStrength.DIRECT),
        "inference": sum(1 for f in grouped if f.evidence_strength == EvidenceStrength.INFERENCE),
        "heuristic": sum(1 for f in grouped if f.evidence_strength == EvidenceStrength.HEURISTIC),
    }

    template = _env.get_template("report.html")
    html = template.render(
        target=report.target,
        duration=report.duration_seconds,
        templates=report.templates_executed,
        total_findings=len(report.findings),
        unique_findings=len(grouped),
        severity=severity,
        owasp=owasp,
        evidence=evidence,
        findings=grouped,
        errors=report.errors,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html, encoding="utf-8")
