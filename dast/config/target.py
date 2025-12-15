"""Target configuration models."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from dast.config.common import AuthType


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

    # Scanner settings
    timeout: float = 30.0
    parallel: int = 5
    request_delay: float = 0.0  # Delay between requests in seconds
    boolean_diff_threshold: float = 0.1  # Threshold for boolean-blind detection (10%)
    time_samples: int = 1  # Number of samples for time-based detection (1-3 recommended)

    def get_variables(self) -> Dict[str, Any]:
        """Get variables dict, defaulting to empty dict."""
        return self.variables or {}

    def get_endpoints(self) -> Dict[str, str]:
        """Get endpoints dict, defaulting to empty dict."""
        return self.endpoints.get_custom()

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "TargetConfig":
        """Load configuration from YAML file."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)
