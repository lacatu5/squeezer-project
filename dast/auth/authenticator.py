"""Authentication handler for DAST scans."""

import base64
from dataclasses import dataclass, field
from typing import Dict, Optional

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
    """Handles authentication for target applications.

    Supports Bearer token and Basic auth.
    Token must be obtained externally (manual login -> copy token).
    """

    async def authenticate(self, config: AuthConfig) -> AuthContext:
        """Perform authentication based on configuration."""
        auth_type = config.type or AuthType.NONE

        if auth_type == AuthType.NONE:
            return AuthContext(authenticated=True)

        if auth_type == AuthType.BASIC:
            return self._auth_basic(config)

        if auth_type == AuthType.BEARER:
            return self._auth_bearer(config)

        return AuthContext(authenticated=False, error=f"Unknown auth type: {auth_type}")

    def _auth_basic(self, config: AuthConfig) -> AuthContext:
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

    def _auth_bearer(self, config: AuthConfig) -> AuthContext:
        """Bearer token authentication."""
        token = config.token or ""

        if not token:
            return AuthContext(authenticated=False, error="Token required for Bearer auth")

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
            authenticated=True,
            headers=headers,
            cookies=cookies,
        )
