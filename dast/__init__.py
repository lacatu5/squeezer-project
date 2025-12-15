"""DAST MVP - State-aware template-based DAST framework.

A modular vulnerability scanning framework with support for:
- Multi-request workflows with state propagation
- Semantic validation for business logic flaws
- Dual-context sessions for IDOR detection
- JWT manipulation testing
- Docker-based clean-slate container testing
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
    XPathExtractor,
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
from dast.auth import (
    SessionContext,
    ResourceIdentifier,
    SessionManager,
    create_idor_scanner,
    JWTForge,
    JWTVulnerabilityScanner,
    parse_jwt_from_auth_header,
)

from dast.docker import (
    ContainerInfo,
    ContainerManager,
    ephemeral_container,
    check_docker_requirement,
    get_skip_container_warning,
)

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
    "XPathExtractor",
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
    "create_matcher",
    "evaluate_matchers",
    # Sessions
    "SessionContext",
    "ResourceIdentifier",
    "SessionManager",
    "create_idor_scanner",
    # JWT
    "JWTForge",
    "JWTVulnerabilityScanner",
    "parse_jwt_from_auth_header",
    # Docker
    "ContainerInfo",
    "ContainerManager",
    "ephemeral_container",
    "check_docker_requirement",
    "get_skip_container_warning",
]
