"""Response matchers for vulnerability detection."""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from httpx import Response

from dast.config import MatcherConfig, EvidenceStrength


@dataclass
class MatchResult:
    """Result of a matcher evaluation."""

    matched: bool
    evidence: Dict[str, Any]
    message: str
    evidence_strength: EvidenceStrength = EvidenceStrength.HEURISTIC
    request_details: Optional[str] = None
    response_details: Optional[str] = None


class Matcher:
    """Base matcher class."""

    def __init__(self, config: MatcherConfig):
        self.config = config
        self.condition = config.condition.lower()
        self.negative = config.negative

    def matches(self, response: Response) -> MatchResult:
        """Check if response matches. Override in subclass."""
        raise NotImplementedError

    def _apply_negative(self, result: MatchResult) -> MatchResult:
        """Apply negative flag if set."""
        if self.negative:
            return MatchResult(
                matched=not result.matched,
                evidence=result.evidence,
                message=f"NOT ({result.message})",
            )
        return result


class StatusMatcher(Matcher):
    """Match HTTP status codes."""

    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.statuses: List[int] = []

        # Support both 'status' and 'values' keys
        status_value = config.status or getattr(config, 'values', None)
        if status_value:
            if isinstance(status_value, int):
                self.statuses = [status_value]
            elif isinstance(status_value, list):
                self.statuses = [
                    int(s) if isinstance(s, str) else s
                    for s in status_value
                ]

    def matches(self, response: Response) -> MatchResult:
        status = response.status_code

        if self.condition in ("equals", "in", "and"):
            matched = status in self.statuses
        elif self.condition in ("not_equals", "not_in"):
            matched = status not in self.statuses
        elif self.condition == "gt":
            matched = any(status > s for s in self.statuses)
        elif self.condition == "lt":
            matched = any(status < s for s in self.statuses)
        elif self.condition == "gte":
            matched = any(status >= s for s in self.statuses)
        elif self.condition == "lte":
            matched = any(status <= s for s in self.statuses)
        else:
            matched = status in self.statuses

        # Status matchers provide direct observation
        strength = EvidenceStrength.DIRECT if matched else EvidenceStrength.HEURISTIC

        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"status": status, "expected": self.statuses},
            message=f"Status {status} {'matches' if matched else 'does not match'} {self.statuses}",
            evidence_strength=strength,
        ))


class WordMatcher(Matcher):
    """Match words in response body or headers."""

    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.words = config.words or []
        self.part = config.part
        self.case_sensitive = config.case_sensitive

    def matches(self, response: Response) -> MatchResult:
        # Get the content to search
        if self.part == "header":
            content = str(response.headers)
        elif self.part == "all":
            content = f"{response.headers}\n{response.text}"
        else:  # body
            content = response.text

        if not self.case_sensitive:
            content = content.lower()
            search_words = [w.lower() for w in self.words]
        else:
            search_words = self.words

        # Check for matches
        found_words = []
        for word in search_words:
            if word in content:
                found_words.append(word)

        if self.condition == "and":
            matched = len(found_words) == len(search_words)
        elif self.condition == "or":
            matched = len(found_words) > 0
        else:  # default to AND
            matched = len(found_words) == len(search_words)

        # Word matchers are heuristic (pattern-based)
        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"found": found_words, "content_length": len(content)},
            message=f"Words {found_words} found in {self.part}",
            evidence_strength=EvidenceStrength.HEURISTIC,
        ))


class RegexMatcher(Matcher):
    """Match regex patterns in response."""

    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.patterns = config.regex or []

    def matches(self, response: Response) -> MatchResult:
        content = response.text
        matches = []

        for pattern in self.patterns:
            try:
                if re.search(pattern, content):
                    matches.append(pattern)
            except re.error:
                pass

        matched = len(matches) > 0

        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"matches": matches},
            message=f"Regex patterns matched: {matches}",
            evidence_strength=EvidenceStrength.HEURISTIC,
        ))


class JsonMatcher(Matcher):
    """Match values in JSON response using simple path notation."""

    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.selector = config.selector or ""
        self.value = config.value

    def _extract_value(self, data: Any, path: str) -> Any:
        """Extract value from JSON using dot notation."""
        if not path:
            return data

        # Remove leading $.
        path = path.lstrip("$.")

        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if 0 <= idx < len(current) else None
            else:
                return None

            if current is None:
                return None

        return current

    def matches(self, response: Response) -> MatchResult:
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            return MatchResult(
                matched=False,
                evidence={"error": "Invalid JSON"},
                message="Response is not valid JSON",
            )

        extracted = self._extract_value(data, self.selector)

        if self.condition == "exists":
            matched = extracted is not None
        elif self.condition == "equals":
            matched = extracted == self.value
        elif self.condition == "not_equals":
            matched = extracted != self.value
        elif self.condition == "gt":
            try:
                matched = float(extracted) > float(self.value)
            except (TypeError, ValueError):
                matched = False
        elif self.condition == "lt":
            try:
                matched = float(extracted) < float(self.value)
            except (TypeError, ValueError):
                matched = False
        elif self.condition == "contains":
            matched = self.value in extracted if isinstance(extracted, (list, str)) else False
        else:
            matched = extracted is not None

        # JSON field existence is inference-level evidence
        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"selector": self.selector, "extracted": extracted, "expected": self.value},
            message=f"JSON {self.selector} = {extracted} (expected {self.value})",
            evidence_strength=EvidenceStrength.INFERENCE,
        ))


def create_matcher(config: MatcherConfig, **kwargs) -> Matcher:
    """Create a matcher from configuration."""
    matcher_type = config.type.lower()

    if matcher_type == "status":
        return StatusMatcher(config)
    elif matcher_type == "word":
        return WordMatcher(config)
    elif matcher_type == "regex":
        return RegexMatcher(config)
    elif matcher_type in ("json", "body_json"):
        return JsonMatcher(config)
    else:
        raise ValueError(f"Unknown matcher type: {matcher_type}")


def evaluate_matchers(matchers: List[Matcher], response: Response, condition: str) -> MatchResult:
    """Evaluate multiple matchers against a response.

    Uses hybrid logic for better false positive reduction:
    - Positive matchers (negative=false): Combined with OR if condition='or', AND if condition='and'
    - Negative matchers (negative=true): Always combined with AND (all must pass, i.e., NOT match)

    This allows templates to have multiple alternative positive indicators (OR)
    while ensuring all negative filters apply (AND).
    """
    if not matchers:
        return MatchResult(matched=False, evidence={}, message="No matchers")

    results = []
    positive_results = []
    negative_results = []

    for matcher in matchers:
        result = matcher.matches(response)
        results.append(result)

        # Track positive and negative matchers separately
        if matcher.negative:
            negative_results.append(result)
        else:
            positive_results.append(result)

    # Evaluate positive matchers with the configured condition
    if positive_results:
        if condition == "or":
            positive_matched = any(r.matched for r in positive_results)
        else:
            positive_matched = all(r.matched for r in positive_results)
    else:
        # No positive matchers - require at least one negative to pass
        positive_matched = True

    # Evaluate negative matchers with AND (all must pass, i.e., NOT match)
    # For negative matchers, matched=true means the negative condition was triggered (bad)
    # So we need all negative matchers to have matched=true (meaning they excluded the pattern)
    negative_matched = all(r.matched for r in negative_results) if negative_results else True

    # Overall match: positive must match AND all negatives must pass
    matched = positive_matched and negative_matched

    evidence = {}
    for i, r in enumerate(results):
        evidence[f"matcher_{i}"] = r.evidence

    # Add breakdown to evidence
    evidence["positive_matchers"] = f"{sum(r.matched for r in positive_results)}/{len(positive_results)}" if positive_results else "0/0"
    evidence["negative_matchers"] = f"{sum(r.matched for r in negative_results)}/{len(negative_results)}" if negative_results else "0/0"
    evidence["condition"] = condition

    # Determine evidence strength: use highest from positive matchers that matched
    # Priority: DIRECT > INFERENCE > HEURISTIC
    strength = EvidenceStrength.HEURISTIC
    for r in positive_results:
        if r.matched:
            if r.evidence_strength == EvidenceStrength.DIRECT:
                strength = EvidenceStrength.DIRECT
                break
            elif r.evidence_strength == EvidenceStrength.INFERENCE:
                strength = EvidenceStrength.INFERENCE

    return MatchResult(
        matched=matched,
        evidence=evidence,
        message=f"Combined {condition.upper()}: {sum(r.matched for r in positive_results)}/{len(positive_results)} positive, "
                f"{sum(r.matched for r in negative_results)}/{len(negative_results)} negative passed",
        evidence_strength=strength,
    )
