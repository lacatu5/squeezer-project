"""Configuration schemas for DAST scanning."""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceStrength(str, Enum):
    """Strength of evidence for a vulnerability finding.

    Reflects how directly the vulnerability was observed, not a statistical confidence.
    """

    DIRECT = "direct_observation"
    """We saw the vulnerability happen - server accepted malicious input."""

    INFERENCE = "inference"
    """Strong indirect evidence - behavior consistent with vulnerability."""

    HEURISTIC = "heuristic"
    """Pattern suggests possible vulnerability - requires manual verification."""


class AuthType(str, Enum):
    """Authentication types."""

    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    FORM = "form"


# ==== Target Configuration ====


class ExtractorConfig(BaseModel):
    """Data extractor configuration."""

    name: str
    location: str = "body"  # body, header
    selector: Optional[str] = None
    regex: Optional[str] = None
    group: int = 1


class LoginConfig(BaseModel):
    """Login configuration for form auth."""

    url: str
    method: str = "POST"
    payload: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    extract: List[ExtractorConfig] = Field(default_factory=list)
    apply: Dict[str, Any] = Field(default_factory=dict)


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: AuthType = AuthType.NONE
    login: Optional[LoginConfig] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class EndpointsConfig(BaseModel):
    """Endpoint mappings."""

    base: str = ""
    custom: Optional[Dict[str, str]] = None

    def get_custom(self) -> Dict[str, str]:
        """Get custom endpoints dict, defaulting to empty dict."""
        return self.custom or {}


class TargetConfig(BaseModel):
    """Target application configuration."""

    name: str
    base_url: str
    authentication: AuthConfig = Field(default_factory=AuthConfig)
    endpoints: EndpointsConfig = Field(default_factory=EndpointsConfig)
    variables: Optional[Dict[str, Any]] = None

    def get_variables(self) -> Dict[str, Any]:
        """Get variables dict, defaulting to empty dict."""
        return self.variables or {}

    def get_endpoints(self) -> Dict[str, str]:
        """Get endpoints dict, defaulting to empty dict."""
        return self.endpoints.get_custom()

    # Scanner settings
    timeout: float = 30.0
    parallel: int = 5

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "TargetConfig":
        """Load configuration from YAML file."""
        import yaml

        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)


# ==== Template Configuration ====


class MatcherConfig(BaseModel):
    """Matcher configuration for response validation."""

    type: str  # status, word, regex, json
    condition: str = "and"  # and, or, equals, contains, etc.
    negative: bool = False

    # Status matcher
    status: Optional[Union[int, List[int]]] = Field(default=None, alias="values")

    # Word matcher
    words: Optional[List[str]] = None
    part: str = "body"  # body, header, all
    case_sensitive: bool = False

    # Regex matcher
    regex: Optional[List[str]] = None

    # JSON matcher
    selector: Optional[str] = None
    value: Optional[Any] = None

    class Config:
        populate_by_name = True


class RequestConfig(BaseModel):
    """HTTP request configuration."""

    name: Optional[str] = None
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    json: Optional[Dict[str, Any]] = None
    cookies: Dict[str, str] = Field(default_factory=dict)

    matchers: List[MatcherConfig] = Field(default_factory=list)
    extractors: List[ExtractorConfig] = Field(default_factory=list)

    # Metadata for findings
    on_match: Optional[Dict[str, Any]] = None


class TemplateInfo(BaseModel):
    """Template metadata."""

    name: str
    author: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class Template(BaseModel):
    """Vulnerability scan template.

    Supports two modes:
    1. Generic mode: Uses 'generic' field with payloads for cross-app testing
    2. Direct mode: Uses 'requests' field for specific test cases
    """

    id: str
    info: TemplateInfo
    variables: Dict[str, Any] = Field(default_factory=dict)
    requests: List[RequestConfig] = Field(default_factory=list)

    # Generic template fields
    generic: Optional["GenericTemplate"] = None

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "Template":
        """Load template from YAML file."""
        import yaml

        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"Empty template: {path}")
        return cls(**data)


class GenericTemplate(BaseModel):
    """Generic template configuration for cross-application vulnerability testing.

    Allows defining payload variations that work across different applications.
    The endpoint and parameters are resolved from the target config.
    """

    # Endpoint variable name (resolved from target config's endpoints.custom)
    endpoint: str

    # HTTP method
    method: str = "GET"

    # Parameter name to inject payloads into
    parameter: Optional[str] = None

    # Request body template for POST requests (supports {{payload}} placeholder)
    body_template: Optional[str] = None

    # Content type for POST requests
    content_type: str = "application/x-www-form-urlencoded"

    # List of payload variations to test
    payloads: List[Union[str, "PayloadConfig"]] = Field(default_factory=list)

    # Headers (beyond auth headers)
    headers: Dict[str, str] = Field(default_factory=dict)

    # Matchers to validate responses
    matchers: List[MatcherConfig] = Field(default_factory=list)


class PayloadConfig(BaseModel):
    """A single payload configuration."""

    name: str
    value: str
    description: Optional[str] = None


# ==== Scan Results ====


class Finding(BaseModel):
    """Vulnerability finding."""

    template_id: str
    vulnerability_type: str
    severity: SeverityLevel
    evidence_strength: EvidenceStrength
    url: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    message: str = ""
    remediation: str = ""
    request_details: Optional[str] = None
    response_details: Optional[str] = None


class ScanReport(BaseModel):
    """Complete scan report."""

    target: str
    templates_executed: int
    findings: List[Finding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0

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

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)
