__version__ = "0.2.0"

from squeezer.models import (
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

from squeezer.scanner import (
    ExecutionContext,
    TemplateEngine,
    load_templates,
    run_scan,
)

from squeezer.auth import Authenticator, AuthContext

from squeezer.matchers import (
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
    "MatchResult",
    "Matcher",
    "StatusMatcher",
    "WordMatcher",
    "RegexMatcher",
    "JsonMatcher",
    "create_matcher",
    "evaluate_matchers",
]
