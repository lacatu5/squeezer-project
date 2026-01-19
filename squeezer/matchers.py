import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from httpx import Response

from squeezer.models import MatcherConfig


@dataclass
class MatchResult:
    matched: bool
    evidence: Dict[str, Any]
    message: str
    response_details: Optional[str] = None


class Matcher:
    def __init__(self, config: MatcherConfig):
        self.config = config
        self.condition = config.condition.lower()
        self.negative = config.negative

    def matches(self, response: Response) -> MatchResult:
        raise NotImplementedError

    def _apply_negative(self, result: MatchResult) -> MatchResult:
        if self.negative:
            return MatchResult(
                matched=not result.matched,
                evidence=result.evidence,
                message=f"NOT ({result.message})",
            )
        return result


class StatusMatcher(Matcher):
    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.statuses: List[int] = []
        status_value = config.status or getattr(config, 'values', None)
        if status_value:
            if isinstance(status_value, int):
                self.statuses = [status_value]
            elif isinstance(status_value, list):
                self.statuses = [int(s) if isinstance(s, str) else s for s in status_value]

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
        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"status": status, "expected": self.statuses},
            message=f"Status {status} {'matches' if matched else 'does not match'} {self.statuses}",
        ))


class WordMatcher(Matcher):
    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.words = config.words or []
        self.part = config.part
        self.case_sensitive = config.case_sensitive

    def matches(self, response: Response) -> MatchResult:
        if self.part == "header":
            content = str(response.headers)
        elif self.part == "all":
            content = f"{response.headers}\n{response.text}"
        else:
            content = response.text
        if not self.case_sensitive:
            content = content.lower()
            search_words = [w.lower() for w in self.words]
        else:
            search_words = self.words
        found_words = []
        for word in search_words:
            if word in content:
                found_words.append(word)
        if self.condition == "and":
            matched = len(found_words) == len(search_words)
        elif self.condition == "or":
            matched = len(found_words) > 0
        else:
            matched = len(found_words) == len(search_words)
        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"found": found_words, "content_length": len(content)},
            message=f"Words {found_words} found in {self.part}",
        ))


class RegexMatcher(Matcher):
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
        ))


class JsonMatcher(Matcher):
    def __init__(self, config: MatcherConfig):
        super().__init__(config)
        self.selector = config.selector or ""
        self.value = config.value

    def _extract_value(self, data: Any, path: str) -> Any:
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
                if extracted is None or self.value is None:
                    matched = False
                else:
                    matched = float(extracted) > float(self.value)
            except (TypeError, ValueError):
                matched = False
        elif self.condition == "lt":
            try:
                if extracted is None or self.value is None:
                    matched = False
                else:
                    matched = float(extracted) < float(self.value)
            except (TypeError, ValueError):
                matched = False
        elif self.condition == "contains":
            if isinstance(extracted, list):
                matched = any(item == self.value for item in extracted)
            elif isinstance(extracted, str) and self.value is not None:
                matched = str(self.value) in extracted
            else:
                matched = False
        else:
            matched = extracted is not None
        return self._apply_negative(MatchResult(
            matched=matched,
            evidence={"selector": self.selector, "extracted": extracted, "expected": self.value},
            message=f"JSON {self.selector} = {extracted} (expected {self.value})",
        ))


def create_matcher(config: MatcherConfig, **kwargs) -> Matcher:
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
    if not matchers:
        return MatchResult(matched=False, evidence={}, message="No matchers")
    results = []
    positive_results = []
    negative_results = []
    for matcher in matchers:
        result = matcher.matches(response)
        results.append(result)
        if matcher.negative:
            negative_results.append(result)
        else:
            positive_results.append(result)
    if positive_results:
        if condition == "or":
            positive_matched = any(r.matched for r in positive_results)
        else:
            positive_matched = all(r.matched for r in positive_results)
    else:
        positive_matched = True
    negative_matched = all(r.matched for r in negative_results) if negative_results else True
    matched = positive_matched and negative_matched
    evidence = {}
    for i, r in enumerate(results):
        evidence[f"matcher_{i}"] = r.evidence
    evidence["positive_matchers"] = f"{sum(r.matched for r in positive_results)}/{len(positive_results)}" if positive_results else "0/0"
    evidence["negative_matchers"] = f"{sum(r.matched for r in negative_results)}/{len(negative_results)}" if negative_results else "0/0"
    evidence["condition"] = condition
    return MatchResult(
        matched=matched,
        evidence=evidence,
        message=f"Combined {condition.upper()}: {sum(r.matched for r in positive_results)}/{len(positive_results)} positive, "
                f"{sum(r.matched for r in negative_results)}/{len(negative_results)} negative passed",
    )


class ConsistencyChecker:
    @staticmethod
    def are_consistent(responses: List[Response], threshold: float = 0.1) -> bool:
        if not responses:
            return False
        status_codes = {r.status_code for r in responses}
        if len(status_codes) > 1:
            return False
        lengths = [len(r.text) for r in responses]
        avg_length = sum(lengths) / len(lengths)
        if avg_length == 0:
            return True
        for length in lengths:
            variance = abs(length - avg_length) / avg_length
            if variance > threshold:
                return False
        return True
