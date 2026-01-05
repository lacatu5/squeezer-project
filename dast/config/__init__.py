"""Configuration models for DAST scanning.

This package re-exports all commonly used classes for convenient importing.
"""

from dast.config.common import (
    AuthType,
    DetectionTier,
    EvidenceStrength,
    SeverityLevel,
)

from dast.config.target import (
    AuthConfig,
    EndpointsConfig,
    TargetConfig,
)

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

from dast.config.scan import (
    CrawlerReport,
    CrawlerStatistics,
    EndpointInfo,
    Finding,
    ParameterInfo,
    ScanReport,
)

__all__ = [
    "AuthType",
    "DetectionTier",
    "EvidenceStrength",
    "SeverityLevel",
    "AuthConfig",
    "EndpointsConfig",
    "TargetConfig",
    "DetectionTierConfig",
    "ExtractorConfig",
    "GenericTemplate",
    "MatcherConfig",
    "PayloadConfig",
    "RequestConfig",
    "Template",
    "TemplateInfo",
    "CrawlerReport",
    "CrawlerStatistics",
    "EndpointInfo",
    "Finding",
    "ParameterInfo",
    "ScanReport",
]
