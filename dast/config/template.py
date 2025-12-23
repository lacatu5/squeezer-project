from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from dast.config.common import DetectionTier, OWASPCategory, SeverityLevel


class ExtractorConfig(BaseModel):
    name: str
    location: str = "body"
    selector: Optional[str] = None
    regex: Optional[str] = None
    group: int = 1


class MatcherConfig(BaseModel):
    type: str
    condition: str = "and"
    negative: bool = False

    status: Optional[Union[int, List[int]]] = Field(default=None, alias="values")

    words: Optional[List[str]] = None
    part: str = "body"
    case_sensitive: bool = False

    regex: Optional[List[str]] = None

    selector: Optional[str] = None
    value: Optional[Any] = None

    dsl: Optional[str] = None
    expression: Optional[str] = None

    expected_type: Optional[str] = None

    base_response: Optional[str] = None
    diff_condition: str = "different"

    threshold_ms: int = 1000
    threshold_sec: Optional[int] = None
    diff_threshold_ms: Optional[int] = None

    class Config:
        populate_by_name = True
        extra = "allow"


class RequestConfig(BaseModel):
    name: Optional[str] = None
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    json_body: Optional[Dict[str, Any]] = Field(default=None, alias="json")
    cookies: Dict[str, str] = Field(default_factory=dict)

    matchers: List[MatcherConfig] = Field(default_factory=list)
    matchers_condition: str = Field(default="and", description="Global condition for all matchers: and|or")

    extractors: List[ExtractorConfig] = Field(default_factory=list, exclude=True)

    on_match: Optional[Dict[str, Any]] = None

    model_config = {"populate_by_name": True}


class TemplateInfo(BaseModel):
    name: str
    author: Optional[str] = None
    severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM
    owasp_category: Optional[Union[OWASPCategory, str]] = None
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

        if any(tag in tags_lower for tag in [
            "auth", "jwt", "session", "login", "credential",
            "password", "token", "csrf", "brute"
        ]):
            return OWASPCategory.A07_AUTHENTICATION_FAILURES

        if any(tag in tags_lower for tag in [
            "crypt", "crypto", "hash", "encryption", "tls", "ssl",
            "certificate", "key", "exposure", "sensitive"
        ]):
            return OWASPCategory.A04_CRYPTOGRAPHIC_FAILURES

        if any(tag in tags_lower for tag in [
            "config", "header", "misconfig", "default", "debug",
            "stack", "disclosure", "info", "version", "fingerprint"
        ]):
            return OWASPCategory.A02_SECURITY_MISCONFIGURATION

        if any(tag in tags_lower for tag in [
            "integrity", "supply", "dependency", "component", "ssrf",
            "redirect", "open", "pollution", "prototype"
        ]):
            return OWASPCategory.A08_INTEGRITY_FAILURES

        if any(tag in tags_lower for tag in [
            "design", "architecture", "mass", "limit", "rate",
            "hpp", "parameter"
        ]):
            return OWASPCategory.A06_INSECURE_DESIGN

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
    id: str
    info: TemplateInfo
    variables: Dict[str, Any] = Field(default_factory=dict)
    requests: List[RequestConfig] = Field(default_factory=list)

    generic: Optional["GenericTemplate"] = None

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "Template":
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError(f"Empty template: {path}")
        return cls(**data)


class DetectionTierConfig(BaseModel):
    tier: Union[DetectionTier, str]

    detection_type: Optional[str] = None

    baseline_payload: Optional[str] = None

    true_payload: Optional[str] = None

    false_payload: Optional[str] = None

    threshold_ms: int = 5000

    matchers: List[MatcherConfig] = Field(default_factory=list)

    matchers_condition: str = Field(default="and", description="Global condition for all matchers: and|or")

    def get_tier(self) -> DetectionTier:
        if isinstance(self.tier, str):
            return DetectionTier(self.tier)
        return self.tier

    class Config:
        use_enum_values = True


class GenericTemplate(BaseModel):
    endpoint: str

    method: str = "GET"

    parameter: Optional[str] = None

    body_template: Optional[str] = None

    content_type: str = "application/x-www-form-urlencoded"

    payloads: List[Union[str, "PayloadConfig"]] = Field(default_factory=list)

    payloads_file: Optional[str] = None

    headers: Dict[str, str] = Field(default_factory=dict)

    matchers: List[MatcherConfig] = Field(default_factory=list)

    detection_tiers: List[DetectionTierConfig] = Field(default_factory=list)


class PayloadConfig(BaseModel):
    name: str
    value: str
    description: Optional[str] = None
    full_request: Optional[str] = None
