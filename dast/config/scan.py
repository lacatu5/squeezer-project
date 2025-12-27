from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from dast.config.common import (
    AuthType,
    EvidenceStrength,
    OWASPCategory,
    SeverityLevel,
)
from dast.config.target import AuthConfig, EndpointsConfig, TargetConfig


class Finding(BaseModel):

    template_id: str
    vulnerability_type: str
    severity: SeverityLevel
    owasp_category: OWASPCategory = OWASPCategory.A02_SECURITY_MISCONFIGURATION
    evidence_strength: EvidenceStrength
    url: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    message: str = ""
    remediation: str = ""
    request_details: Optional[str] = None
    response_details: Optional[str] = None
    payload_count: int = 1
    endpoint_count: int = 1


class ParameterInfo(BaseModel):
    """Information about a discovered parameter (query, form, JSON, etc.)."""

    name: str
    type: str = "unknown"
    location: str = "unknown"
    example_values: List[str] = Field(default_factory=list)
    required: bool = False


class EndpointInfo(BaseModel):
    """Detailed information about a discovered endpoint."""

    url: str
    method: str = "GET"
    path: str = ""
    status_code: Optional[int] = None
    content_type: Optional[str] = None

    query_params: List[ParameterInfo] = Field(default_factory=list)
    form_fields: List[ParameterInfo] = Field(default_factory=list)
    json_params: List[ParameterInfo] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)

    forms: List[Dict[str, Any]] = Field(default_factory=list)
    links: List[str] = Field(default_factory=list)
    api_patterns: List[str] = Field(default_factory=list)
    is_api: bool = False
    requires_auth: bool = False

    response_size: int = 0
    has_json: bool = False
    has_html: bool = False
    error_indicators: List[str] = Field(default_factory=list)


class CrawlerStatistics(BaseModel):
    """Statistics collected during crawling."""

    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0

    unique_urls: int = 0
    unique_domains: int = 0

    endpoints_by_method: Dict[str, int] = Field(default_factory=dict)
    endpoints_by_status: Dict[int, int] = Field(default_factory=dict)

    api_endpoints: int = 0
    html_pages: int = 0
    forms_discovered: int = 0
    input_fields_discovered: int = 0

    authentication_detected: List[str] = Field(default_factory=list)


class CrawlerReport(BaseModel):
    """Complete report from crawling a target."""

    target: str = ""
    base_url: str = ""
    timestamp: str = ""

    target_config: Optional[TargetConfig] = None

    endpoints: List[Union[EndpointInfo, Dict[str, Any]]] = Field(default_factory=list)
    statistics: Union[CrawlerStatistics, Dict[str, Any]] = Field(default_factory=dict)

    forms: List[Dict[str, Any]] = Field(default_factory=list)
    auth_data: Dict[str, Any] = Field(default_factory=dict)
    storage_data: Dict[str, Any] = Field(default_factory=dict)
    discovered_cookies: Dict[str, str] = Field(default_factory=dict)

    def get_endpoints_by_method(self, method: str) -> List[Union[EndpointInfo, Dict[str, Any]]]:
        return [
            e for e in self.endpoints
            if (isinstance(e, EndpointInfo) and e.method == method) or
            (isinstance(e, dict) and e.get("method") == method)
        ]

    def get_api_endpoints(self) -> List[Union[EndpointInfo, Dict[str, Any]]]:
        return [
            e for e in self.endpoints
            if (isinstance(e, EndpointInfo) and e.is_api) or
            (isinstance(e, dict) and e.get("type") == "api")
        ]

    def get_forms(self) -> List[Dict[str, Any]]:
        if self.forms:
            return self.forms

        forms = []
        for endpoint in self.endpoints:
            if isinstance(endpoint, EndpointInfo):
                forms.extend(endpoint.forms)
            elif isinstance(endpoint, dict):
                forms.extend(endpoint.get("form_fields", []))
        return forms

    def get_auth_config(self) -> AuthConfig:
        if self.target_config and self.target_config.authentication:
            return self.target_config.authentication

        auth_type = self.auth_data.get("type", "none")
        if auth_type == "jwt":
            return AuthConfig(
                type=AuthType.BEARER,
                token=self.auth_data.get("jwt_token"),
                headers={"Authorization": f"Bearer {self.auth_data.get('jwt_token', '')}"},
            )
        elif auth_type == "session":
            cookie_name = self.auth_data.get("cookie_name", "session")
            return AuthConfig(
                type=AuthType.FORM,
                headers={"Cookie": f"{cookie_name}={self.auth_data.get('jwt_token', '')}"},
            )

        return AuthConfig()

    def to_target_config(self, name: Optional[str] = None) -> TargetConfig:
        if self.target_config:
            return self.target_config

        custom_endpoints = {}
        for endpoint in self.endpoints:
            if isinstance(endpoint, EndpointInfo):
                url = endpoint.url
                path = endpoint.path
            else:
                url = endpoint.get("url", "")
                path = urlparse(url).path

            key = path.strip("/").replace("/", "_").replace("-", "_") or "root"
            original_key = key
            counter = 1
            while key in custom_endpoints:
                key = f"{original_key}_{counter}"
                counter += 1
            custom_endpoints[key] = url

        base = self.base_url or self.target
        parsed = urlparse(base)
        target_name = name or f"agent_crawled_{parsed.netloc}"

        self.target_config = TargetConfig(
            name=target_name,
            base_url=base,
            authentication=self.get_auth_config(),
            endpoints=EndpointsConfig(base="", custom=custom_endpoints),
        )
        return self.target_config

    def save_yaml(self, path: Union[str, Path]) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self.model_dump(exclude_none=True), f, sort_keys=False)

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "CrawlerReport":
        """Load a crawler report from YAML."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)


class ScanReport(BaseModel):
    """Complete scan report."""

    target: str
    templates_executed: int
    findings: List[Finding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0

    def _count_by_severity(self, severity: SeverityLevel) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def critical_count(self) -> int:
        return self._count_by_severity(SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_by_severity(SeverityLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_by_severity(SeverityLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_by_severity(SeverityLevel.LOW)

    def _count_by_owasp(self, category: OWASPCategory) -> int:
        return sum(1 for f in self.findings if f.owasp_category == category)

    @property
    def a01_broken_access_control_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A01_BROKEN_ACCESS_CONTROL)

    @property
    def a02_security_misconfiguration_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A02_SECURITY_MISCONFIGURATION)

    @property
    def a03_software_supply_chain_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A03_SOFTWARE_SUPPLY_CHAIN)

    @property
    def a04_cryptographic_failures_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A04_CRYPTOGRAPHIC_FAILURES)

    @property
    def a05_injection_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A05_INJECTION)

    @property
    def a06_insecure_design_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A06_INSECURE_DESIGN)

    @property
    def a07_authentication_failures_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A07_AUTHENTICATION_FAILURES)

    @property
    def a08_integrity_failures_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A08_INTEGRITY_FAILURES)

    @property
    def a09_logging_failures_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A09_LOGGING_FAILURES)

    @property
    def a10_exception_conditions_count(self) -> int:
        return self._count_by_owasp(OWASPCategory.A10_EXCEPTION_CONDITIONS)

    def get_owasp_summary(self) -> Dict[str, tuple[int, int]]:
        labels = {
            "A01": "Broken Access Control",
            "A02": "Security Misconfiguration",
            "A03": "Software Supply Chain Failures",
            "A04": "Cryptographic Failures",
            "A05": "Injection",
            "A06": "Insecure Design",
            "A07": "Authentication Failures",
            "A08": "Software or Data Integrity Failures",
            "A09": "Security Logging and Alerting Failures",
            "A10": "Mishandling of Exceptional Conditions",
        }
        categories = {
            "A01": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            "A02": OWASPCategory.A02_SECURITY_MISCONFIGURATION,
            "A03": OWASPCategory.A03_SOFTWARE_SUPPLY_CHAIN,
            "A04": OWASPCategory.A04_CRYPTOGRAPHIC_FAILURES,
            "A05": OWASPCategory.A05_INJECTION,
            "A06": OWASPCategory.A06_INSECURE_DESIGN,
            "A07": OWASPCategory.A07_AUTHENTICATION_FAILURES,
            "A08": OWASPCategory.A08_INTEGRITY_FAILURES,
            "A09": OWASPCategory.A09_LOGGING_FAILURES,
            "A10": OWASPCategory.A10_EXCEPTION_CONDITIONS,
        }
        result = {}
        for k, v in categories.items():
            findings = [f for f in self.findings if f.owasp_category == v]
            template_count = len(set(f.template_id for f in findings))
            vuln_count = len(findings)
            result[f"{k}:2025 - {labels[k]}"] = (template_count, vuln_count)
        return result

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_finding_from_dict(self, data: Dict[str, Any]) -> None:
        from dast.core.validators import create_finding_from_dict
        finding = create_finding_from_dict(data)
        self.findings.append(finding)

    def group_similar_findings(self) -> List[Finding]:
        from urllib.parse import urlparse
        
        grouped = {}
        for finding in self.findings:
            parsed = urlparse(finding.url)
            base_path = parsed.path.split('?')[0]
            key = (finding.vulnerability_type, finding.template_id, base_path, finding.evidence_strength)
            
            if key not in grouped:
                grouped[key] = finding
            else:
                grouped[key].payload_count += 1
        
        first_pass = list(grouped.values())
        
        consolidated = {}
        endpoint_data = {}
        
        for finding in first_pass:
            vuln_type = finding.vulnerability_type
            
            if vuln_type.startswith('DEBUG_') or vuln_type.startswith('GENERIC_NOSQLI') or vuln_type == 'GENERIC_SSRF' or vuln_type == 'INSECURE_DIRECT_OBJECT_REFERENCE':
                if vuln_type.startswith('DEBUG_'):
                    group_key = 'DEBUG_ENDPOINTS'
                elif vuln_type == 'GENERIC_NOSQLI':
                    group_key = 'GENERIC_NOSQLI'
                elif vuln_type == 'GENERIC_SSRF':
                    group_key = 'GENERIC_SSRF'
                else:
                    group_key = 'INSECURE_DIRECT_OBJECT_REFERENCE'
                    
                key = (group_key, finding.template_id, finding.evidence_strength)
                
                if key not in consolidated:
                    consolidated[key] = finding
                    if group_key == 'DEBUG_ENDPOINTS':
                        consolidated[key].vulnerability_type = 'DEBUG_ENDPOINTS'
                        consolidated[key].message = 'Debug/Actuator endpoints exposed'
                    endpoint_data[key] = {
                        'paths': [urlparse(finding.url).path],
                        'payloads': finding.payload_count
                    }
                else:
                    endpoint_data[key]['paths'].append(urlparse(finding.url).path)
                    endpoint_data[key]['payloads'] += finding.payload_count
            else:
                unique_key = (finding.vulnerability_type, finding.template_id, urlparse(finding.url).path, finding.evidence_strength)
                consolidated[unique_key] = finding
        
        for key in endpoint_data:
            if key in consolidated:
                data = endpoint_data[key]
                consolidated[key].endpoint_count = len(data['paths'])
                consolidated[key].payload_count = data['payloads']
        
        return list(consolidated.values())

    def add_error(self, error: str) -> None:
        self.errors.append(error)
