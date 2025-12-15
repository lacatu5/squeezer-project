"""Template configuration models."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from dast.config.common import DetectionTier, OWASPCategory, SeverityLevel
from dast.config.target import ExtractorConfig


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
    json_body: Optional[Dict[str, Any]] = Field(default=None, alias="json")
    cookies: Dict[str, str] = Field(default_factory=dict)

    matchers: List[MatcherConfig] = Field(default_factory=list)

    # Extractors for data extraction from responses
    extractors: List[ExtractorConfig] = Field(default_factory=list, exclude=True)

    # Metadata for findings
    on_match: Optional[Dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class TemplateInfo(BaseModel):
    """Template metadata."""

    name: str
    author: Optional[str] = None
    severity: Union[SeverityLevel, OWASPCategory, str] = SeverityLevel.MEDIUM
    """Severity level or OWASP Top 10 2025 category.

    Can be:
    - Legacy severity: critical, high, medium, low, info
    - OWASP 2025 category: A01:2025, A02:2025, etc.
    - Full category name: A01_BROKEN_ACCESS_CONTROL, etc.
    """
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    def get_owasp_category(self) -> OWASPCategory:
        """Get the OWASP Top 10 2025 category for this template.

        Maps legacy severity levels and returns the appropriate OWASP category.
        """
        # If already an OWASPCategory, return it
        if isinstance(self.severity, OWASPCategory):
            return self.severity

        # If it's a string, try to parse it
        severity_str = str(self.severity)

        # Check if it's already an OWASP category format (A01:2025, etc.)
        if severity_str.startswith("A0") and ":2025" in severity_str:
            for category in OWASPCategory:
                if category.value == severity_str:
                    return category

        # Map legacy severity strings to OWASP categories based on vulnerability type
        # This is a default mapping; templates should specify owasp_category directly
        if severity_str.lower() in ("critical", "high"):
            # Default critical/high to A05 (Injection) for most exploit-based vulns
            # But check tags for better mapping
            tags_lower = [t.lower() for t in self.tags]
            if any(tag in tags_lower for tag in ["access", "idor", "privilege", "authz"]):
                return OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            if any(tag in tags_lower for tag in ["auth", "jwt", "session", "login"]):
                return OWASPCategory.A07_AUTHENTICATION_FAILURES
            if any(tag in tags_lower for tag in ["crypt", "crypto", "hash"]):
                return OWASPCategory.A04_CRYPTOGRAPHIC_FAILURES
            if any(tag in tags_lower for tag in ["supply", "dependency", "component"]):
                return OWASPCategory.A03_SOFTWARE_SUPPLY_CHAIN
            return OWASPCategory.A05_INJECTION

        elif severity_str.lower() == "medium":
            # Medium severity often maps to misconfiguration or design issues
            tags_lower = [t.lower() for t in self.tags]
            if any(tag in tags_lower for tag in ["config", "header", "misconfig"]):
                return OWASPCategory.A02_SECURITY_MISCONFIGURATION
            if any(tag in tags_lower for tag in ["design", "architecture"]):
                return OWASPCategory.A06_INSECURE_DESIGN
            return OWASPCategory.A02_SECURITY_MISCONFIGURATION

        elif severity_str.lower() == "low":
            # Low severity often maps to error handling or logging
            tags_lower = [t.lower() for t in self.tags]
            if any(tag in tags_lower for tag in ["log", "monitor", "audit"]):
                return OWASPCategory.A09_LOGGING_FAILURES
            return OWASPCategory.A10_EXCEPTION_CONDITIONS

        else:  # info
            return OWASPCategory.A09_LOGGING_FAILURES


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
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"Empty template: {path}")
        return cls(**data)


class DetectionTierConfig(BaseModel):
    """Configuration for a single detection tier.

    Each tier represents a different detection technique with increasing invasiveness.
    """

    tier: Union[DetectionTier, str]
    """The tier level - passive, active, or aggressive."""

    # Detection type for special techniques
    detection_type: Optional[str] = None
    """Type: error_based, boolean_blind, time_blind, union_based."""

    # Baseline payload for diff-based detection (boolean blind)
    baseline_payload: Optional[str] = None
    """Normal payload to compare against (e.g., "test")."""

    # True/false payloads for boolean detection
    true_payload: Optional[str] = None
    """Payload that should make condition TRUE (e.g., "' OR '1'='1")."""

    false_payload: Optional[str] = None
    """Payload that should make condition FALSE (e.g., "' AND '1'='2")."""

    # Time threshold for time-based detection
    threshold_ms: int = 5000
    """Response time threshold in milliseconds for time-based detection."""

    # Matchers for this tier
    matchers: List[MatcherConfig] = Field(default_factory=list)
    """Matchers to validate responses for this tier."""

    def get_tier(self) -> DetectionTier:
        """Get tier as DetectionTier enum."""
        if isinstance(self.tier, str):
            return DetectionTier(self.tier)
        return self.tier

    class Config:
        use_enum_values = True


class GenericTemplate(BaseModel):
    """Generic template configuration for cross-application vulnerability testing.

    Allows defining payload variations that work across different applications.
    The endpoint and parameters are resolved from the target config.

    Supports detection tiers for layered vulnerability scanning.
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

    # Load payloads from external file (one per line, # comments ignored)
    payloads_file: Optional[str] = None

    # Headers (beyond auth headers)
    headers: Dict[str, str] = Field(default_factory=dict)

    # Matchers to validate responses (legacy - use detection_tiers instead)
    matchers: List[MatcherConfig] = Field(default_factory=list)

    # NEW: Detection tiers for layered scanning
    detection_tiers: List[DetectionTierConfig] = Field(default_factory=list)
    """Detection tiers for passive/active/aggressive scanning."""


class PayloadConfig(BaseModel):
    """A single payload configuration."""

    name: str
    value: str
    description: Optional[str] = None
    full_request: Optional[str] = None  # For payloads that need the full request body (e.g., XXE)
