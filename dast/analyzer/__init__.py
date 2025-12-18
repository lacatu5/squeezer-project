"""DAST analyzer module.

Provides parameter classification, target building, and endpoint analysis
for the DAST scanner. This module separates business logic from the CLI.
"""

from dast.analyzer.classifier import (
    INJECTABLE_PATTERNS,
    classify_parameter,
    extract_parameters_from_url,
)
from dast.analyzer.target_builder import (
    add_json_injection_endpoints,
    build_auto_target_config,
    discover_and_add_json_endpoints,
)
from dast.analyzer.parameter_analyzer import (
    get_injectable_parameters,
    summarize_parameters,
)

__all__ = [
    # classifier
    "INJECTABLE_PATTERNS",
    "classify_parameter",
    "extract_parameters_from_url",
    # target_builder
    "add_json_injection_endpoints",
    "build_auto_target_config",
    "discover_and_add_json_endpoints",
    # parameter_analyzer
    "get_injectable_parameters",
    "summarize_parameters",
]
