"""Core components for DAST scanning.

This module contains fundamental building blocks used across the scanner:
- Matchers: Response pattern matching for vulnerability detection
- Validators: Response consistency and confidence scoring
"""

from squeezer.core.matchers import (
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
    "MatchResult",
    "Matcher",
    "StatusMatcher",
    "WordMatcher",
    "RegexMatcher",
    "JsonMatcher",
    "create_matcher",
    "evaluate_matchers",
]
