"""Authentication and session handling for DAST scanning."""

# Import from submodules within this package
from dast.auth.authenticator import AuthContext, Authenticator
from dast.auth.jwt import JWTForge, JWTVulnerabilityScanner, parse_jwt_from_auth_header
from dast.auth.sessions import SessionContext, SessionManager, ResourceIdentifier, create_idor_scanner

__all__ = [
    "AuthContext",
    "Authenticator",
    "JWTForge",
    "JWTVulnerabilityScanner",
    "parse_jwt_from_auth_header",
    "SessionContext",
    "SessionManager",
    "ResourceIdentifier",
    "create_idor_scanner",
]
