"""Authentication handler for DAST scans."""

from dataclasses import dataclass, field
from typing import Dict, Optional

import httpx

from dast.config import AuthConfig, AuthType


@dataclass
class AuthContext:
    """Authentication context with session data."""

    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    token: Optional[str] = None
    error: Optional[str] = None


class Authenticator:
    """Handles authentication for target applications.

    Supports Bearer token authentication and LAB mode for automated login.
    """

    async def authenticate(self, config: AuthConfig, base_url: Optional[str] = None) -> AuthContext:
        """Perform authentication based on configuration."""
        auth_type = config.type or AuthType.NONE

        if auth_type == AuthType.NONE:
            return AuthContext()

        if auth_type == AuthType.BEARER:
            return self._auth_bearer(config)

        if auth_type == AuthType.LAB:
            if not base_url:
                return AuthContext(error="Base URL required for LAB auth")
            return await self._auth_lab(config, base_url)

        return AuthContext(error=f"Unknown auth type: {auth_type}")

    def _auth_bearer(self, config: AuthConfig) -> AuthContext:
        """Bearer token authentication."""
        token = config.token or ""

        if not token:
            return AuthContext(error="Token required for Bearer auth")

        headers = {"Authorization": f"Bearer {token}"}
        if config.headers:
            headers.update(config.headers)

        cookies = {}
        if "Cookie" in headers:
            cookie_str = headers.pop("Cookie")
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip()

        return AuthContext(
            headers=headers,
            cookies=cookies,
        )

    async def _auth_lab(self, config: AuthConfig, base_url: str) -> AuthContext:
        """LAB mode automated login.

        User is pre-seeded when container starts.
        Just login to get the token.
        """
        username = config.username or ""
        password = config.password or ""

        if not username or not password:
            return AuthContext(error="Username and password required for LAB auth")

        login_url = f"{base_url}/rest/user/login"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    login_url,
                    json={"email": username, "password": password},
                    headers={"Content-Type": "application/json"},
                    timeout=10.0,
                )

                if response.status_code != 200:
                    return AuthContext(
                        error=f"Login failed: HTTP {response.status_code}"
                    )

                data = response.json()
                token = data.get("authentication", {}).get("token")

                if not token:
                    return AuthContext(error="No token in login response")

                headers = {"Authorization": f"Bearer {token}"}
                if config.headers:
                    headers.update(config.headers)

                return AuthContext(
                    headers=headers,
                    cookies={},
                    token=token,
                )
        except Exception as e:
            return AuthContext(error=f"Login request failed: {e}")
