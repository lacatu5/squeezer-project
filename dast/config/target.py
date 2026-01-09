from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from dast.config.common import AuthType


class AuthConfig(BaseModel):
    type: AuthType = AuthType.NONE
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    lab_name: Optional[str] = None


class EndpointsConfig(BaseModel):
    base: str = ""
    custom: Optional[Dict[str, str]] = None

    def get_custom(self) -> Dict[str, str]:
        return self.custom or {}


class TargetConfig(BaseModel):
    name: str
    base_url: str
    authentication: AuthConfig = Field(default_factory=AuthConfig)
    endpoints: EndpointsConfig = Field(default_factory=EndpointsConfig)
    variables: Optional[Dict[str, Any]] = None
    discovered_params: Optional[Dict[str, List[str]]] = None

    timeout: float = 30.0
    parallel: int = 5
    request_delay: float = 0.0

    def get_variables(self) -> Dict[str, Any]:
        return self.variables or {}

    def get_endpoints(self) -> Dict[str, str]:
        return self.endpoints.get_custom()

    def get_discovered_params(self) -> Dict[str, List[str]]:
        return self.discovered_params or {}

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "TargetConfig":
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)
