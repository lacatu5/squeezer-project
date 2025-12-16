"""DAST MVP - State-aware template-based DAST framework.

A modular vulnerability scanning framework with support for:
- Multi-request workflows with state propagation
- Semantic validation for business logic flaws
- JWT manipulation testing
"""

__version__ = "0.2.0"

# Core modules
from dast.config import (
    SeverityLevel,
    AuthType,
    ExtractorConfig,
    LoginConfig,
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

# Analysis modules
from dast.extractors import (
    ExtractionResult,
    Extractor,
    RegexExtractor,
    JsonExtractor,
    HeaderExtractor,
    CookieExtractor,
    KataExtractor,
    create_extractor,
    extract_all,
)

from dast.matchers import (
    MatchResult,
    Matcher,
    StatusMatcher,
    WordMatcher,
    RegexMatcher,
    JsonMatcher,
    SemanticMatcher,
    DiffMatcher,
    TimeMatcher,
    create_matcher,
    evaluate_matchers,
)

# Specialized modules
from dast.auth import JWTForge

__all__ = [
    # Version
    "__version__",
    # Config
    "SeverityLevel",
    "AuthType",
    "ExtractorConfig",
    "LoginConfig",
    "AuthConfig",
    "EndpointsConfig",
    "TargetConfig",
    "MatcherConfig",
    "RequestConfig",
    "TemplateInfo",
    "Template",
    "Finding",
    "ScanReport",
    # Engine
    "ExecutionContext",
    "TemplateEngine",
    "load_templates",
    "run_scan",
    # Auth
    "Authenticator",
    "AuthContext",
    # Extractors
    "ExtractionResult",
    "Extractor",
    "RegexExtractor",
    "JsonExtractor",
    "HeaderExtractor",
    "CookieExtractor",
    "KataExtractor",
    "create_extractor",
    "extract_all",
    # Matchers
    "MatchResult",
    "Matcher",
    "StatusMatcher",
    "WordMatcher",
    "RegexMatcher",
    "JsonMatcher",
    "SemanticMatcher",
    "DiffMatcher",
    "TimeMatcher",
    "DSLMatcher",
    "create_matcher",
    "evaluate_matchers",
    # JWT
    "JWTForge",
]
