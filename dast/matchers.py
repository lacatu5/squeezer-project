"""Response matchers for vulnerability detection."""

import json
import re
from dataclasses import dataclass
from decimal import Decimal
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


class SemanticMatcher(Matcher):
    """Validates business logic invariants in JSON responses.

    This matcher enables detection of business logic vulnerabilities by
    validating semantic rules about data (e.g., quantity should be >= 0,
    prices should be positive, totals should match sum of items).

    Supports conditions:
        - lt, lte: Less than, less than or equal
        - gt, gte: Greater than, greater than or equal
        - equals, not_equals: Exact comparison
        - exists, not_exists: Check field presence
        - contains: Check if value is in list/string
        - regex: Match regex pattern
        - negative: Check for negative numbers
        - type: Validate data type
    """

    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.selector = config.selector or ""
        self.value = config.value
        self.expected_type = getattr(config, 'expected_type', None)

    def _extract_value(self, data: Any, path: str) -> Any:
        """Extract value from JSON using dot notation with array support."""
        if not path:
            return data

        path = path.lstrip("$.")

        # Handle bracket notation: items[0].id
        path = re.sub(r'\[(\d+)\]', r'.\1.', path)

        parts = [p for p in path.split('.') if p]
        current = data

        for part in parts:
            if current is None:
                return None
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx] if 0 <= idx < len(current) else None
                except ValueError:
                    return None
            else:
                return None

        return current

    def _to_decimal(self, value: Any) -> Optional[Decimal]:
        """Convert value to Decimal for precise numeric comparison."""
        if value is None:
            return None
        try:
            return Decimal(str(value))
        except (ValueError, TypeError):
            return None

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
        matched = False
        message = ""

        if self.condition == "exists":
            matched = extracted is not None
            message = f"Field {self.selector} exists: {matched}"

        elif self.condition == "not_exists":
            matched = extracted is None
            message = f"Field {self.selector} does not exist: {matched}"

        elif self.condition == "negative":
            # Special case: check if numeric value is negative (vulnerability)
            dec_val = self._to_decimal(extracted)
            matched = dec_val is not None and dec_val < 0
            message = f"Value {extracted} is negative: {matched}"

        elif self.condition == "zero":
            # Check if value is zero (may be vulnerability for ratings)
            dec_val = self._to_decimal(extracted)
            matched = dec_val is not None and dec_val == 0
            message = f"Value {extracted} is zero: {matched}"

        elif self.condition == "type":
            # Validate data type
            expected = self.value or self.expected_type
            if expected == "number":
                matched = isinstance(extracted, (int, float, Decimal)) and not isinstance(extracted, bool)
            elif expected == "string":
                matched = isinstance(extracted, str)
            elif expected == "array":
                matched = isinstance(extracted, list)
            elif expected == "object":
                matched = isinstance(extracted, dict)
            elif expected == "boolean":
                matched = isinstance(extracted, bool)
            else:
                matched = False
            message = f"Value {extracted} is type {expected}: {matched}"

        elif self.condition == "equals":
            matched = extracted == self.value
            message = f"Value {extracted} equals {self.value}: {matched}"

        elif self.condition == "not_equals":
            matched = extracted != self.value
            message = f"Value {extracted} not equals {self.value}: {matched}"

        elif self.condition in ("gt", "gte", "lt", "lte"):
            # Numeric comparisons for business logic validation
            dec_extracted = self._to_decimal(extracted)
            dec_expected = self._to_decimal(self.value)

            if dec_extracted is None or dec_expected is None:
                matched = False
                message = f"Cannot compare {extracted} with {self.value}"
            else:
                if self.condition == "gt":
                    matched = dec_extracted > dec_expected
                elif self.condition == "gte":
                    matched = dec_extracted >= dec_expected
                elif self.condition == "lt":
                    matched = dec_extracted < dec_expected
                elif self.condition == "lte":
                    matched = dec_extracted <= dec_expected
                message = f"Value {extracted} {self.condition} {self.value}: {matched}"

        elif self.condition == "contains":
            matched = self.value in extracted if isinstance(extracted, (list, str, dict)) else False
            message = f"Value {extracted} contains {self.value}: {matched}"

        elif self.condition == "regex":
            if isinstance(extracted, str) and self.value:
                matched = bool(re.search(self.value, extracted))
            else:
                matched = False
            message = f"Value {extracted} matches regex {self.value}: {matched}"

        else:
            matched = extracted is not None
            message = f"Field {self.selector} exists: {matched}"

        # Determine evidence strength based on validation type
        if self.condition in ("negative", "zero", "lt", "gt"):
            # Direct observation of business logic violation
            strength = EvidenceStrength.DIRECT
        elif self.condition in ("equals", "exists", "contains"):
            # Value was observed in response
            strength = EvidenceStrength.INFERENCE
        else:
            strength = EvidenceStrength.HEURISTIC

        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={
                "selector": self.selector,
                "extracted": extracted,
                "expected": self.value,
                "condition": self.condition,
            },
            message=message,
            evidence_strength=strength,
            response_details=f"Validated {self.selector} = {extracted}",
        ))


class DiffMatcher(Matcher):
    """Compare values between multiple responses.

    Useful for IDOR detection - compare victim vs attacker responses
    to detect unauthorized data access.
    """

    def __init__(
        self,
        config: MatcherConfig,
        base_response: Optional[Response] = None,
    ):
        super().__init__(config)
        self.selector = config.selector or ""
        self.base_response = base_response
        self.diff_condition = getattr(config, 'diff_condition', 'different')  # different, same, subset

    def set_base_response(self, response: Response) -> None:
        """Set the base response for comparison."""
        self.base_response = response

    def _extract_value(self, data: Any, path: str) -> Any:
        """Extract value from JSON using dot notation."""
        if not path:
            return data
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
        if self.base_response is None:
            return MatchResult(
                matched=False,
                evidence={"error": "No base response for comparison"},
                message="No base response set for diff matcher",
            )

        try:
            base_data = self.base_response.json()
            response_data = response.json()
        except (json.JSONDecodeError, ValueError):
            return MatchResult(
                matched=False,
                evidence={"error": "Invalid JSON in one or both responses"},
                message="Cannot compare - invalid JSON",
            )

        base_value = self._extract_value(base_data, self.selector)
        current_value = self._extract_value(response_data, self.selector)

        if self.diff_condition == "different":
            matched = base_value != current_value
        elif self.diff_condition == "same":
            matched = base_value == current_value
        elif self.diff_condition == "subset":
            # Check if current_value is a subset of base_value
            matched = isinstance(base_value, dict) and isinstance(current_value, dict)
            if matched:
                for k, v in current_value.items():
                    if base_value.get(k) != v:
                        matched = False
                        break
        else:
            matched = base_value != current_value

        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={
                "base_value": base_value,
                "current_value": current_value,
                "selector": self.selector,
                "condition": self.diff_condition,
            },
            message=f"Values are {self.diff_condition}: base={base_value}, current={current_value}",
        ))


class TimeMatcher(Matcher):
    """Match time-based conditions with baseline comparison support.

    Useful for timing attack detection and response time analysis.
    For accurate time-based detection, use multiple samples and statistical analysis.

    Attributes:
        threshold_ms: Absolute time threshold in milliseconds
        baseline_ms: Baseline response time for comparison (if set)
        diff_threshold_ms: Minimum difference from baseline to trigger match
    """

    def __init__(self, config: MatcherConfig, baseline_response: Optional[Response] = None):
        super().__init__(config)
        self.threshold_ms = getattr(config, 'threshold_ms', 1000)
        self.threshold_sec = getattr(config, 'threshold_sec', None)
        self.diff_threshold_ms = getattr(config, 'diff_threshold_ms', None)

        # Extract baseline from response if provided
        self.baseline_ms = None
        if baseline_response:
            self.baseline_ms = baseline_response.elapsed.total_seconds() * 1000

    def matches(self, response: Response) -> MatchResult:
        # Get elapsed time in milliseconds
        elapsed_ms = response.elapsed.total_seconds() * 1000

        # Use baseline comparison if available (more accurate for network jitter)
        if self.baseline_ms is not None and self.diff_threshold_ms is not None:
            time_diff = elapsed_ms - self.baseline_ms
            matched = time_diff > self.diff_threshold_ms

            return self._apply_negative(MatchResult(
                matched=matched,
                evidence={
                    "elapsed_ms": elapsed_ms,
                    "baseline_ms": self.baseline_ms,
                    "diff_ms": time_diff,
                    "threshold_ms": self.diff_threshold_ms,
                },
                message=f"Response time {elapsed_ms:.0f}ms (baseline: {self.baseline_ms:.0f}ms, diff: {time_diff:.0f}ms)",
                evidence_strength=EvidenceStrength.INFERENCE if matched else EvidenceStrength.HEURISTIC,
            ))

        # Fall back to absolute threshold
        threshold = self.threshold_sec * 1000 if self.threshold_sec else self.threshold_ms

        if self.condition == "gt":
            matched = elapsed_ms > threshold
        elif self.condition == "lt":
            matched = elapsed_ms < threshold
        elif self.condition == "gte":
            matched = elapsed_ms >= threshold
        elif self.condition == "lte":
            matched = elapsed_ms <= threshold
        else:
            # Default: check if response took longer than threshold
            matched = elapsed_ms > threshold

        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={
                "elapsed_ms": elapsed_ms,
                "threshold_ms": threshold,
            },
            message=f"Response time {elapsed_ms:.0f}ms vs threshold {threshold}ms",
            evidence_strength=EvidenceStrength.INFERENCE if matched else EvidenceStrength.HEURISTIC,
        ))


class DSLMatcher(Matcher):
    """DSL expression matcher for dynamic response evaluation.

    Supports simple comparison expressions:
    - compare(response.status,200) - status equals 200
    - compare(response.status,200,">=") - status >= 200
    - compare(response.content_length,100,">=") - content length >= 100
    - compare(response.time,2000) - response time > 2000ms
    - compare(response.time,3000,">") - response time > 3000ms

    Operators: ==, !=, >, >=, <, <=, contains
    """

    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.dsl_expression = getattr(config, 'dsl', None) or getattr(config, 'expression', '')

    def _parse_compare(self, expr: str) -> tuple:
        """Parse a compare() DSL expression.

        Returns: (field, value, operator) or (field, value, '==')
        """
        import re

        # Match: compare(response.<field>, <value>[, <operator>])
        pattern = r'compare\(response\.(\w+),\s*([^,\)]+)(?:,\s*["\']([^"\']+)["\'])?\)'
        match = re.search(pattern, expr)

        if match:
            field = match.group(1)
            value = match.group(2)
            operator = match.group(3) if match.group(3) else '=='
            return field, value, operator

        return None, None, '=='

    def _get_field_value(self, response: Response, field: str):
        """Extract field value from response."""
        if field == 'status':
            return response.status_code
        elif field in ('status_code', 'code'):
            return response.status_code
        elif field == 'content_length':
            return len(response.content)
        elif field == 'length':
            return len(response.content)
        elif field == 'time':
            return response.elapsed.total_seconds() * 1000  # Convert to ms
        elif field == 'size':
            return len(response.content)
        else:
            return None

    def _compare_values(self, actual, expected, operator):
        """Compare two values using the specified operator."""
        try:
            # Try to convert expected to number
            if isinstance(expected, str) and expected.isdigit():
                expected = int(expected)
            elif isinstance(expected, str):
                # Try float
                try:
                    expected = float(expected)
                except ValueError:
                    pass  # Keep as string
        except (ValueError, TypeError):
            pass

        if operator == '==' or operator == 'equals':
            return actual == expected
        elif operator == '!=' or operator == 'not_equals':
            return actual != expected
        elif operator == '>' or operator == 'gt':
            try:
                return float(actual) > float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == '>=' or operator == 'gte':
            try:
                return float(actual) >= float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == '<' or operator == 'lt':
            try:
                return float(actual) < float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == '<=' or operator == 'lte':
            try:
                return float(actual) <= float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == 'contains':
            return str(expected) in str(actual)
        else:
            return actual == expected

    def matches(self, response: Response) -> MatchResult:
        field, value, operator = self._parse_compare(self.dsl_expression)

        if field is None:
            # Invalid DSL expression
            return MatchResult(
                matched=False,
                evidence={"dsl": self.dsl_expression},
                message=f"Invalid DSL expression: {self.dsl_expression}",
            )

        actual = self._get_field_value(response, field)
        matched = self._compare_values(actual, value, operator)

        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={
                "field": field,
                "actual": actual,
                "expected": value,
                "operator": operator,
                "dsl": self.dsl_expression
            },
            message=f"DSL: {field} {operator} {value} (actual: {actual})",
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
    elif matcher_type == "dsl":
        return DSLMatcher(config)
    elif matcher_type == "semantic":
        return SemanticMatcher(config)
    elif matcher_type == "diff":
        return DiffMatcher(config, base_response=kwargs.get("base_response"))
    elif matcher_type == "time":
        return TimeMatcher(config, baseline_response=kwargs.get("base_response"))
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
