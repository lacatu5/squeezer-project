"""Execution context for DAST scanning."""

import random
import re
import string
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from dast.auth.jwt import JWTForge


@dataclass
class ExecutionContext:
    """Execution context for template variables.

    Maintains state across multi-request workflows:
    - variables: Extracted values from previous requests
    - endpoints: Named endpoint URLs
    - responses: History of all responses for comparison
    - request_count: Total requests made in this workflow
    """

    variables: Dict[str, Any] = field(default_factory=dict)
    endpoints: Dict[str, str] = field(default_factory=dict)
    responses: List[httpx.Response] = field(default_factory=list)
    request_count: int = 0

    # Response references for diff matchers (for IDOR detection)
    _named_responses: Dict[str, httpx.Response] = field(default_factory=dict)

    def interpolate(self, text: str) -> str:
        """Replace variable placeholders in text."""
        if not isinstance(text, str):
            return str(text)

        result = text

        # Handle built-in functions
        result = re.sub(r"rand_base\((\d+)\)", lambda m: self._rand_base(m.group(1)), result)
        result = re.sub(r"rand_int\(\)", lambda m: str(random.randint(10000, 99999)), result)
        result = re.sub(r"uuid\(\)", lambda m: str(uuid.uuid4()), result)

        # Handle JWT manipulation functions
        result = self._interpolate_jwt(result)

        # Handle endpoints
        for name, value in self.endpoints.items():
            result = result.replace(f"{{{{endpoints.{name}}}}}", value)

        # Handle variables (process longer keys first to avoid partial replacements)
        for name in sorted(self.variables.keys(), key=len, reverse=True):
            value = self.variables[name]
            # Handle both {{name}} and {{ name }} formats
            result = result.replace(f"{{{{{name}}}}}", str(value))
            result = result.replace(f"{{{{ {name} }}}}", str(value))

        return result

    def _interpolate_jwt(self, text: str) -> str:
        """Handle JWT manipulation functions."""

        # jwt_none(token) - Change algorithm to "none"
        result = re.sub(r"jwt_none\(([^)]+)\)", lambda m: self._jwt_none(m.group(1)), text)

        # jwt_admin(token) - Set role to admin
        result = re.sub(r"jwt_admin\(([^)]+)\)", lambda m: self._jwt_admin(m.group(1)), result)

        # jwt_claim(token, claim, value) - Modify specific claim
        # Note: This handles simple string values
        result = re.sub(
            r'jwt_claim\(([^,]+),\s*([^,]+),\s*([^)]+)\)',
            lambda m: self._jwt_claim(m.group(1), m.group(2), m.group(3)),
            result
        )

        # jwt_no_exp(token) - Remove expiration
        result = re.sub(r"jwt_no_exp\(([^)]+)\)", lambda m: self._jwt_no_exp(m.group(1)), result)

        # jwt_weak_sign(token, secret) - Re-sign with weak secret
        result = re.sub(
            r'jwt_weak_sign\(([^,]+),\s*([^)]+)\)',
            lambda m: self._jwt_weak_sign(m.group(1), m.group(2)),
            result
        )

        return result

    def _jwt_none(self, token_var: str) -> str:
        """Apply jwt_none transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.change_algorithm(token, "none")
        except Exception:
            return token

    def _jwt_admin(self, token_var: str) -> str:
        """Apply jwt_admin transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.set_admin_role(token, "role")
        except Exception:
            return token

    def _jwt_claim(self, token_var: str, claim: str, value: str) -> str:
        """Apply jwt_claim transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        claim = claim.strip().strip('"\'')
        value = value.strip().strip('"\'')
        try:
            return JWTForge.modify_claim(token, claim, value)
        except Exception:
            return token

    def _jwt_no_exp(self, token_var: str) -> str:
        """Apply jwt_no_exp transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        try:
            return JWTForge.remove_expiration(token)
        except Exception:
            return token

    def _jwt_weak_sign(self, token_var: str, secret: str) -> str:
        """Apply jwt_weak_sign transformation to a variable."""
        token = self.variables.get(token_var.strip(), token_var)
        secret = secret.strip().strip('"\'')
        try:
            return JWTForge.sign_with_key(token, secret, "HS256")
        except Exception:
            return token

    def _rand_base(self, length_str: str) -> str:
        length = int(length_str) if length_str else 16
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def set(self, name: str, value: Any) -> None:
        """Set a variable value."""
        self.variables[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        """Get a variable value."""
        return self.variables.get(name, default)

    def save_response(self, name: str, response: httpx.Response) -> None:
        """Save a response by name for later reference (useful for IDOR)."""
        self._named_responses[name] = response

    def get_response(self, name: str) -> Optional[httpx.Response]:
        """Get a previously saved response."""
        return self._named_responses.get(name)

    def get_last_response(self) -> Optional[httpx.Response]:
        """Get the most recent response."""
        return self.responses[-1] if self.responses else None
