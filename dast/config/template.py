"""Template configuration models."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from dast.config.common import DetectionTier, OWASPCategory, SeverityLevel


class ExtractorConfig(BaseModel):
    """Data extractor configuration for templates."""

    name: str
    location: str = "body"
    selector: Optional[str] = None
    regex: Optional[str] = None
    group: int = 1


class MatcherConfig(BaseModel):
    """Matcher configuration for response validation."""

    type: str  # status, word, regex, json, semantic, dsl, diff, time
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

    # DSL matcher
    dsl: Optional[str] = None
    expression: Optional[str] = None

    # Semantic matcher (uses selector, condition, value)
    expected_type: Optional[str] = None

    # Diff matcher
    base_response: Optional[str] = None
    diff_condition: str = "different"  # different, same, subset

    # Time matcher
    threshold_ms: int = 1000
    threshold_sec: Optional[int] = None
    diff_threshold_ms: Optional[int] = None

    class Config:
        populate_by_name = True
        extra = "allow"  # Allow additional fields for custom matchers


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
    # Global condition for combining all matchers: and/or
    # If set, overrides individual matcher conditions for the overall evaluation
    matchers_condition: str = Field(default="and", description="Global condition for all matchers: and|or")

    # Extractors for data extraction from responses
    extractors: List[ExtractorConfig] = Field(default_factory=list, exclude=True)

    # Metadata for findings
    on_match: Optional[Dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class TemplateInfo(BaseModel):
    """Template metadata."""

    name: str
    author: Optional[str] = None
    severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM
    owasp_category: Optional[Union[OWASPCategory, str]] = None
    """OWASP Top 10 2025 category.

    Can be:
    - Short form: A01:2025, A02:2025, etc.
    - Full enum name: A01_BROKEN_ACCESS_CONTROL, etc.
    - If not specified, derived from tags.
    """
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    def get_owasp_category(self) -> OWASPCategory:
        if self.owasp_category is not None:
            if isinstance(self.owasp_category, OWASPCategory):
                return self.owasp_category
            category_str = str(self.owasp_category).strip()
            if category_str.startswith("A0") and ":2025" in category_str:
                for category in OWASPCategory:
                    if category.value == category_str:
                        return category
            for category in OWASPCategory:
                if category.name == category_str or category.name.replace("_", "") == category_str.replace("_", "").replace(":", "").upper():
                    return category

        tags_lower = [t.lower() for t in self.tags]

        if any(tag in tags_lower for tag in [
            "access", "idor", "privilege", "authz", "authorization",
            "bypass", "escalation", "admin", "race", "directory"
        ]):
            return OWASPCategory.A01_BROKEN_ACCESS_CONTROL

        if any(tag in tags_lower for tag in [
            "sqli", "sql", "injection", "nosql", "mongo", "ldap",
            "xss", "ssti", "template", "xxe", "command", "rce"
        ]):
            return OWASPCategory.A05_INJECTION

        # A07: Authentication Failures
        if any(tag in tags_lower for tag in [
            "auth", "jwt", "session", "login", "credential",
            "password", "token", "csrf", "brute"
        ]):
            return OWASPCategory.A07_AUTHENTICATION_FAILURES

        # A04: Cryptographic Failures
        if any(tag in tags_lower for tag in [
            "crypt", "crypto", "hash", "encryption", "tls", "ssl",
            "certificate", "key", "exposure", "sensitive"
        ]):
            return OWASPCategory.A04_CRYPTOGRAPHIC_FAILURES

        # A02: Security Misconfiguration
        if any(tag in tags_lower for tag in [
            "config", "header", "misconfig", "default", "debug",
            "stack", "disclosure", "info", "version", "fingerprint"
        ]):
            return OWASPCategory.A02_SECURITY_MISCONFIGURATION

        # A08: Integrity Failures
        if any(tag in tags_lower for tag in [
            "integrity", "supply", "dependency", "component", "ssrf",
            "redirect", "open", "pollution", "prototype"
        ]):
            return OWASPCategory.A08_INTEGRITY_FAILURES

        # A06: Insecure Design
        if any(tag in tags_lower for tag in [
            "design", "architecture", "mass", "limit", "rate",
            "hpp", "parameter"
        ]):
            return OWASPCategory.A06_INSECURE_DESIGN

        # A10: Exception Conditions
        if any(tag in tags_lower for tag in [
            "error", "exception", "handling", "debug", "stack"
        ]):
            return OWASPCategory.A10_EXCEPTION_CONDITIONS

        if any(tag in tags_lower for tag in [
            "log", "monitor", "audit", "detection"
        ]):
            return OWASPCategory.A09_LOGGING_FAILURES

        return OWASPCategory.A02_SECURITY_MISCONFIGURATION


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

    # Global condition for combining all matchers in this tier
    matchers_condition: str = Field(default="and", description="Global condition for all matchers: and|or")

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

    headers: Dict[str, str] = Field(default_factory=dict)

    matchers: List[MatcherConfig] = Field(default_factory=list)

    detection_tiers: List[DetectionTierConfig] = Field(default_factory=list)


class PayloadConfig(BaseModel):
    """A single payload configuration."""

    name: str
    value: str
    description: Optional[str] = None
    full_request: Optional[str] = None  # For payloads that need the full request body (e.g., XXE)
