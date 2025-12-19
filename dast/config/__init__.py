"""Configuration models for DAST scanning.

This package re-exports all commonly used classes for convenient importing.
"""

# Common enumerations
from dast.config.common import (
    AuthType,
    DetectionTier,
    EvidenceStrength,
    ScanProfile,
    SeverityLevel,
)

# Target configuration
from dast.config.target import (
    AuthConfig,
    EndpointsConfig,
    TargetConfig,
)

# Template configuration
from dast.config.template import (
    DetectionTierConfig,
    ExtractorConfig,
    GenericTemplate,
    MatcherConfig,
    PayloadConfig,
    RequestConfig,
    Template,
    TemplateInfo,
)

# Scan and crawler models
from dast.config.scan import (
    CrawlerReport,
    CrawlerStatistics,
    EndpointInfo,
    Finding,
    ParameterInfo,
    ScanReport,
)

__all__ = [
    # Enums
    "AuthType",
    "DetectionTier",
    "EvidenceStrength",
    "ScanProfile",
    "SeverityLevel",
    # Target
    "AuthConfig",
    "EndpointsConfig",
    "TargetConfig",
    # Template
    "DetectionTierConfig",
    "ExtractorConfig",
    "GenericTemplate",
    "MatcherConfig",
    "PayloadConfig",
    "RequestConfig",
    "Template",
    "TemplateInfo",
    # Scan
    "CrawlerReport",
    "CrawlerStatistics",
    "EndpointInfo",
    "Finding",
    "ParameterInfo",
    "ScanReport",
]
