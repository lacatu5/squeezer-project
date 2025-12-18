"""Scan result and crawler data models."""

import json
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
    """Vulnerability finding."""

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
    """Complete scan report with checkpoint support for resume capability."""

    target: str
    templates_executed: int
    findings: List[Finding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0

    checkpoint_file: Optional[str] = None
    completed_templates: List[str] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.LOW)

    @property
    def a01_broken_access_control_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A01_BROKEN_ACCESS_CONTROL)

    @property
    def a02_security_misconfiguration_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A02_SECURITY_MISCONFIGURATION)

    @property
    def a03_software_supply_chain_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A03_SOFTWARE_SUPPLY_CHAIN)

    @property
    def a04_cryptographic_failures_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A04_CRYPTOGRAPHIC_FAILURES)

    @property
    def a05_injection_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A05_INJECTION)

    @property
    def a06_insecure_design_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A06_INSECURE_DESIGN)

    @property
    def a07_authentication_failures_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A07_AUTHENTICATION_FAILURES)

    @property
    def a08_integrity_failures_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A08_INTEGRITY_FAILURES)

    @property
    def a09_logging_failures_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A09_LOGGING_FAILURES)

    @property
    def a10_exception_conditions_count(self) -> int:
        return sum(1 for f in self.findings if f.owasp_category == OWASPCategory.A10_EXCEPTION_CONDITIONS)

    def get_owasp_summary(self) -> Dict[str, int]:
        return {
            "A01:2025 - Broken Access Control": self.a01_broken_access_control_count,
            "A02:2025 - Security Misconfiguration": self.a02_security_misconfiguration_count,
            "A03:2025 - Software Supply Chain Failures": self.a03_software_supply_chain_count,
            "A04:2025 - Cryptographic Failures": self.a04_cryptographic_failures_count,
            "A05:2025 - Injection": self.a05_injection_count,
            "A06:2025 - Insecure Design": self.a06_insecure_design_count,
            "A07:2025 - Authentication Failures": self.a07_authentication_failures_count,
            "A08:2025 - Software or Data Integrity Failures": self.a08_integrity_failures_count,
            "A09:2025 - Security Logging and Alerting Failures": self.a09_logging_failures_count,
            "A10:2025 - Mishandling of Exceptional Conditions": self.a10_exception_conditions_count,
        }

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_finding_from_dict(self, data: Dict[str, Any]) -> None:
        from dast.core.validators import create_finding_from_dict
        finding = create_finding_from_dict(data)
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)

    def mark_template_completed(self, template_id: str) -> None:
        """Mark a template as completed and save checkpoint if configured."""
        if template_id not in self.completed_templates:
            self.completed_templates.append(template_id)
        self.save_checkpoint()

    def is_template_completed(self, template_id: str) -> bool:
        """Check if a template has already been completed."""
        return template_id in self.completed_templates

    def save_checkpoint(self) -> None:
        """Save current state to checkpoint file if configured."""
        if not self.checkpoint_file:
            return

        try:
            Path(self.checkpoint_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.checkpoint_file, "w") as f:
                json.dump({
                    "target": self.target,
                    "templates_executed": self.templates_executed,
                    "findings": [f.model_dump() for f in self.findings],
                    "errors": self.errors,
                    "duration_seconds": self.duration_seconds,
                    "completed_templates": self.completed_templates,
                }, f, indent=2)
        except Exception:
            pass

    @classmethod
    def load_checkpoint(cls, checkpoint_file: str) -> Optional["ScanReport"]:
        """Load scan state from checkpoint file."""
        path = Path(checkpoint_file)
        if not path.exists():
            return None

        try:
            with open(path) as f:
                data = json.load(f)

            return cls(
                target=data.get("target", ""),
                templates_executed=data.get("templates_executed", 0),
                findings=[Finding(**f) for f in data.get("findings", [])],
                errors=data.get("errors", []),
                duration_seconds=data.get("duration_seconds", 0.0),
                checkpoint_file=checkpoint_file,
                completed_templates=data.get("completed_templates", []),
            )
        except Exception:
            return None
