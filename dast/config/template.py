from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from dast.config.common import DetectionTier, OWASPCategory, SeverityLevel


class ExtractorConfig(BaseModel):
    name: str
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

    base_response: Optional[str] = None
    diff_condition: str = "different"

    threshold_ms: int = 1000

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


class TemplateInfo(BaseModel):
    name: str
    severity: Union[SeverityLevel, str] = SeverityLevel.MEDIUM
    owasp_category: Optional[Union[OWASPCategory, str]] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    def get_owasp_category(self) -> Optional[OWASPCategory]:
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
        return None


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

    content_type: str = "application/x-www-form-urlencoded"

    payloads: List[Union[str, "PayloadConfig"]] = Field(default_factory=list)

    headers: Dict[str, str] = Field(default_factory=dict)

    matchers: List[MatcherConfig] = Field(default_factory=list)

    detection_tiers: List[DetectionTierConfig] = Field(default_factory=list)


class PayloadConfig(BaseModel):
    name: str
    value: str
    description: Optional[str] = None
