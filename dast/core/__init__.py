"""Core components for DAST scanning.

This module contains fundamental building blocks used across the scanner:
- Matchers: Response pattern matching for vulnerability detection
- Extractors: Dynamic data extraction from HTTP responses
- Validators: Response consistency and confidence scoring
"""

from dast.core.extractors import (
    ExtractionResult,
    Extractor,
    RegexExtractor,
    JsonExtractor,
    HeaderExtractor,
    CookieExtractor,
    KataExtractor,
    create_extractor,
)
from dast.core.matchers import (
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
from dast.core.validators import (
    ConsistencyChecker,
    ConfidenceCalculator,
    compare_responses,
    create_finding_from_dict,
)

__all__ = [
    # Extractors
    "ExtractionResult",
    "Extractor",
    "RegexExtractor",
    "JsonExtractor",
    "HeaderExtractor",
    "CookieExtractor",
    "KataExtractor",
    "create_extractor",
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
    # Validators
    "ConsistencyChecker",
    "ConfidenceCalculator",
    "compare_responses",
    "create_finding_from_dict",
]
