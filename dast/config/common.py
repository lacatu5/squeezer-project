"""Common enumerations used across DAST configuration."""

from enum import Enum


class OWASPCategory(str, Enum):
    """OWASP Top 10 2025 categories for vulnerability classification."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2025"
    A02_SECURITY_MISCONFIGURATION = "A02:2025"
    A03_SOFTWARE_SUPPLY_CHAIN = "A03:2025"
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025"
    A05_INJECTION = "A05:2025"
    A06_INSECURE_DESIGN = "A06:2025"
    A07_AUTHENTICATION_FAILURES = "A07:2025"
    A08_INTEGRITY_FAILURES = "A08:2025"
    A09_LOGGING_FAILURES = "A09:2025"
    A10_EXCEPTION_CONDITIONS = "A10:2025"


class SeverityLevel(str, Enum):
    """Impact level of a vulnerability finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanProfile(str, Enum):
    """Scan intensity profiles - controls which detection tiers run."""

    PASSIVE = "passive"
    STANDARD = "standard"
    THOROUGH = "thorough"
    AGGRESSIVE = "aggressive"


class DetectionTier(str, Enum):
    """Detection tier levels - ordered by invasiveness."""

    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"


class EvidenceStrength(str, Enum):
    """Strength of evidence for a vulnerability finding."""

    DIRECT = "direct_observation"
    INFERENCE = "inference"
    HEURISTIC = "heuristic"


class AuthType(str, Enum):
    """Authentication types."""

    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    FORM = "form"
