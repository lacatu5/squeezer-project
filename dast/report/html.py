from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from dast.config import EvidenceStrength, ScanReport


_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)
_env.filters['split'] = lambda s, sep=None: s.split(sep) if s else []


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

    all_tags = set()
    app_count = 0
    generic_count = 0
    for f in grouped:
        all_tags.update(f.tags)
        if "generic" in f.tags or f.template_id.startswith("generic-"):
            generic_count += 1
        else:
            app_count += 1

    tag_list = sorted(all_tags)

    owasp_codes = sorted(set(f.owasp_category.value.split(":")[0] for f in grouped))

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
        tags=tag_list,
        owasp_codes=owasp_codes,
        app_count=app_count,
        generic_count=generic_count,
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html, encoding="utf-8")
