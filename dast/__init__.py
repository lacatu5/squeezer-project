"""DAST MVP - State-aware template-based DAST framework.

A modular vulnerability scanning framework with support for:
- Multi-request workflows with state propagation
- Semantic validation for business logic flaws
"""

__version__ = "0.2.0"

from dast.config import (
    SeverityLevel,
    AuthType,
    ExtractorConfig,
    AuthConfig,
    EndpointsConfig,
    TargetConfig,
    MatcherConfig,
    RequestConfig,
    TemplateInfo,
    Template,
    Finding,
    ScanReport,
)

from dast.scanner import (
    ExecutionContext,
    TemplateEngine,
    load_templates,
    run_scan,
)

from dast.auth import Authenticator, AuthContext

from dast.core.matchers import (
    MatchResult,
    Matcher,
    StatusMatcher,
    WordMatcher,
    RegexMatcher,
    JsonMatcher,
    create_matcher,
    evaluate_matchers,
)

__all__ = [
    "__version__",
    "SeverityLevel",
    "AuthType",
    "ExtractorConfig",
    "AuthConfig",
    "EndpointsConfig",
    "TargetConfig",
    "MatcherConfig",
    "RequestConfig",
    "TemplateInfo",
    "Template",
    "Finding",
    "ScanReport",
    "ExecutionContext",
    "TemplateEngine",
    "load_templates",
    "run_scan",
    "Authenticator",
    "AuthContext",
    "ExtractionResult",
    "MatchResult",
    "Matcher",
    "StatusMatcher",
    "WordMatcher",
    "RegexMatcher",
    "JsonMatcher",
    "create_matcher",
    "evaluate_matchers",
]
