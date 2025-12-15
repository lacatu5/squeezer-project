"""Common enumerations used across DAST configuration."""

from enum import Enum


class OWASPCategory(str, Enum):
    """OWASP Top 10 2025 categories for vulnerability classification.

    Maps vulnerabilities to their position in the OWASP Top 10 2025.
    """

    A01_BROKEN_ACCESS_CONTROL = "A01:2025"
    """Broken Access Control - Users can act outside of their intended permissions."""

    A02_SECURITY_MISCONFIGURATION = "A02:2025"
    """Security Misconfiguration - Improperly configured security controls."""

    A03_SOFTWARE_SUPPLY_CHAIN = "A03:2025"
    """Software Supply Chain Failures - Vulnerabilities in dependencies or build processes."""

    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025"
    """Cryptographic Failures - Failures related to cryptography and data protection."""

    A05_INJECTION = "A05:2025"
    """Injection - SQL, NoSQL, OS command, LDAP injection, etc."""

    A06_INSECURE_DESIGN = "A06:2025"
    """Insecure Design - Flaws in architecture or design that allow attacks."""

    A07_AUTHENTICATION_FAILURES = "A07:2025"
    """Authentication Failures - Identity, authentication, and session management issues."""

    A08_INTEGRITY_FAILURES = "A08:2025"
    """Software or Data Integrity Failures - Code or infrastructure integrity issues."""

    A09_LOGGING_FAILURES = "A09:2025"
    """Security Logging and Alerting Failures - Insufficient logging or monitoring."""

    A10_EXCEPTION_CONDITIONS = "A10:2025"
    """Mishandling of Exceptional Conditions - Improper error handling."""

    # Keep legacy mapping for compatibility
    @classmethod
    def from_legacy(cls, legacy_severity: str) -> "OWASPCategory":
        """Map legacy severity levels to OWASP categories for backward compatibility."""
        mapping = {
            "critical": cls.A05_INJECTION,  # Most critical are injection
            "high": cls.A01_BROKEN_ACCESS_CONTROL,  # Access control is high impact
            "medium": cls.A02_SECURITY_MISCONFIGURATION,  # Config issues
            "low": cls.A10_EXCEPTION_CONDITIONS,  # Error handling
            "info": cls.A09_LOGGING_FAILURES,  # Logging
        }
        return mapping.get(legacy_severity.lower(), cls.A02_SECURITY_MISCONFIGURATION)


class SeverityLevel(str, Enum):
    """Legacy severity levels for backward compatibility.

    Deprecated: Use OWASPCategory instead.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanProfile(str, Enum):
    """Scan intensity profiles - controls which detection tiers run."""

    PASSIVE = "passive"
    """Fast, safe techniques only - no observable side effects."""

    STANDARD = "standard"
    """Passive + active techniques - safe for most production systems."""

    THOROUGH = "thorough"
    """All techniques including time-based - may cause delays."""

    AGGRESSIVE = "aggressive"
    """Maximum detection - includes fuzzing and multiple request variations."""


class DetectionTier(str, Enum):
    """Detection tier levels - ordered by invasiveness."""

    PASSIVE = "passive"
    """Error-based, pattern matching - no observable impact."""

    ACTIVE = "active"
    """Boolean-blind, diff-based - sends crafted payloads."""

    AGGRESSIVE = "aggressive"
    """Time-based, heavy delays - may cause temporary slowdown."""


class EvidenceStrength(str, Enum):
    """Strength of evidence for a vulnerability finding.

    Reflects how directly the vulnerability was observed, not a statistical confidence.
    """

    DIRECT = "direct_observation"
    """We saw the vulnerability happen - server accepted malicious input."""

    INFERENCE = "inference"
    """Strong indirect evidence - behavior consistent with vulnerability."""

    HEURISTIC = "heuristic"
    """Pattern suggests possible vulnerability - requires manual verification."""


class AuthType(str, Enum):
    """Authentication types."""

    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    FORM = "form"
