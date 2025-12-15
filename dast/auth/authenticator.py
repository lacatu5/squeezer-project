"""Authentication handler for DAST scans."""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx

from dast.config import AuthConfig, AuthType


@dataclass
class AuthContext:
    """Authentication context with session data."""

    authenticated: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    token: Optional[str] = None
    error: Optional[str] = None


class Authenticator:
    """Handles authentication for target applications."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def authenticate(self, config: AuthConfig) -> AuthContext:
        """Perform authentication based on configuration."""
        auth_type = config.type or AuthType.NONE

        if auth_type == AuthType.NONE:
            return AuthContext(authenticated=True)

        elif auth_type == AuthType.BASIC:
            return await self._auth_basic(config)

        elif auth_type == AuthType.BEARER:
            return await self._auth_bearer(config)

        elif auth_type == AuthType.FORM:
            return await self._auth_form(config)

        else:
            return AuthContext(authenticated=False, error=f"Unknown auth type: {auth_type}")

    async def _auth_basic(self, config: AuthConfig) -> AuthContext:
        """HTTP Basic Authentication."""
        username = config.username or ""
        password = config.password or ""

        if not username or not password:
            return AuthContext(authenticated=False, error="Username and password required for Basic auth")

        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

        return AuthContext(
            authenticated=True,
            headers={"Authorization": f"Basic {credentials}"},
        )

    async def _auth_bearer(self, config: AuthConfig) -> AuthContext:
        """Bearer token authentication."""
        token = config.token or ""

        if not token:
            return AuthContext(authenticated=False, error="Token required for Bearer auth")

        return AuthContext(
            authenticated=True,
            headers={"Authorization": f"Bearer {token}"},
        )

    async def _auth_form(self, config: AuthConfig) -> AuthContext:
        """Form-based login with session/token extraction."""
        if not config.login:
            return AuthContext(authenticated=False, error="Login configuration required for form auth")

        client = self._get_client()

        try:
            # Interpolate credentials in payload
            payload = self._interpolate_payload(config.login.payload, config)

            # Determine content type and send accordingly
            headers = dict(config.login.headers)
            content_type = headers.get("Content-Type", "")

            # Perform login request
            if "application/json" in content_type:
                response = await client.request(
                    method=config.login.method,
                    url=config.login.url,
                    json=payload,
                    headers=headers,
                )
            else:
                # Form-encoded or default
                response = await client.request(
                    method=config.login.method,
                    url=config.login.url,
                    data=payload,
                    headers=headers,
                )

            if response.status_code >= 400:
                return AuthContext(
                    authenticated=False,
                    error=f"Login failed: HTTP {response.status_code}",
                )

            # Extract data using configured extractors
            extracted = self._extract_data(response, config.login.extract or [])

            # Build headers from apply config
            headers = {}
            if config.login.apply:
                apply_headers = config.login.apply.get("headers", {})
                for key, value in apply_headers.items():
                    # Replace {{var}} with extracted values
                    value = self._replace_variables(value, extracted)
                    headers[key] = value

            # Add response cookies
            cookies = dict(response.cookies)

            return AuthContext(
                authenticated=True,
                headers=headers,
                cookies=cookies,
                token=extracted.get("token"),
            )

        except httpx.HTTPError as e:
            return AuthContext(authenticated=False, error=f"Login failed: {e}")

    def _interpolate_payload(self, payload: Dict[str, Any], config: AuthConfig) -> Dict[str, Any]:
        """Replace credential placeholders in payload."""
        result = {}
        for key, value in payload.items():
            if isinstance(value, str):
                value = value.replace("{{AUTH_USERNAME}}", config.username or "")
                value = value.replace("{{AUTH_PASSWORD}}", config.password or "")
            result[key] = value
        return result

    def _extract_data(self, response: httpx.Response, extractors: list) -> Dict[str, Any]:
        """Extract data from response using extractors."""
        extracted = {}

        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            return extracted

        for ext in extractors:
            name = ext.name
            location = ext.location
            selector = ext.selector
            regex = ext.regex

            value = None

            if location == "body":
                if selector:
                    # Simple JSONPath-like extraction
                    value = self._extract_json_path(data, selector)
                elif regex:
                    # Regex extraction from text
                    match = re.search(regex, response.text)
                    if match:
                        group = ext.group or 1
                        value = match.group(group)

            if value is not None:
                extracted[name] = value

        return extracted

    def _extract_json_path(self, data: Any, path: str) -> Any:
        """Extract value from JSON using dot notation."""
        if not path:
            return data

        # Remove leading $.
        path = path.lstrip("$.")

        if not path:
            return data

        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if 0 <= idx < len(current) else None
            else:
                return None

            if current is None:
                return None

        return current

    def _replace_variables(self, text: str, variables: Dict[str, Any]) -> str:
        """Replace {{variable}} patterns with values."""
        result = text
        for name, value in variables.items():
            # Try both {{var}} and {var} patterns
            result = result.replace(f"{{{{{name}}}}}", str(value))
            result = result.replace(f"{{{name}}}", str(value))
        return result
