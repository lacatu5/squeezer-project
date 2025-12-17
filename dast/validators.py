"""Validation logic for retry logic, confidence scoring, and response comparison.

This module implements professional-grade validation patterns inspired by:
- Nuclei (multi-condition matchers)
- SQLMap (response comparison)
- Burp Suite (retry with consistency)
"""

from typing import Any, Dict, List, Optional, Tuple
from httpx import Response

from dast.config.common import EvidenceStrength


class ConsistencyChecker:
    """Check if multiple responses are consistent across retries.

    Consistent responses indicate reliable findings. Inconsistent responses
    may indicate network issues, WAF interference, or false positives.
    """

    @staticmethod
    def are_consistent(
        responses: List[Response],
        threshold: float = 0.1,
    ) -> bool:
        """Check if responses have consistent status codes and similar content length.

        Args:
            responses: List of responses to compare
            threshold: Max allowed variance in content length (10% default)

        Returns:
            True if all responses are consistent
        """
        if not responses:
            return False

        # All must have same status code
        status_codes = {r.status_code for r in responses}
        if len(status_codes) > 1:
            return False

        # Content lengths should be similar (within threshold)
        lengths = [len(r.text) for r in responses]
        avg_length = sum(lengths) / len(lengths)

        if avg_length == 0:
            return True  # All empty responses are consistent

        for length in lengths:
            variance = abs(length - avg_length) / avg_length
            if variance > threshold:
                return False

        return True

    @staticmethod
    def get_similarity_score(response1: Response, response2: Response) -> float:
        """Calculate similarity score between two responses (0-1).

        Returns 1.0 if identical, 0.0 if completely different.
        Uses length-based comparison for speed (faster than text diff).

        Args:
            response1: First response
            response2: Second response

        Returns:
            Similarity score from 0.0 to 1.0
        """
        if response1.status_code != response2.status_code:
            return 0.0

        len1, len2 = len(response1.text), len(response2.text)
        if len1 == 0 and len2 == 0:
            return 1.0

        # Use length-based similarity (fast and effective)
        max_len = max(len1, len2)
        if max_len == 0:
            return 1.0

        length_diff = abs(len1 - len2) / max_len
        return 1.0 - length_diff


class ConfidenceCalculator:
    """Calculate confidence level from matcher results and evidence strength.

    Confidence levels:
    - HIGH: Direct evidence + consistent + multiple matchers
    - MEDIUM: Inference evidence or single matcher with consistency
    - LOW: Heuristic evidence or inconsistent responses
    """

    @staticmethod
    def calculate(
        evidence_strength: EvidenceStrength,
        matcher_count: int,
        passed_matchers: int,
        is_consistent: bool = True,
    ) -> str:
        """Calculate confidence as high/medium/low.

        Scoring:
        - HIGH: DIRECT evidence + consistent + multiple matchers
        - MEDIUM: INFERENCE evidence or single matcher (consistent)
        - LOW: HEURISTIC evidence or inconsistent

        Args:
            evidence_strength: Strength of best matcher
            matcher_count: Total matchers evaluated
            passed_matchers: Matchers that passed
            is_consistent: Response was consistent across retries

        Returns:
            "high", "medium", or "low"
        """
        if not is_consistent:
            return "low"

        # DIRECT evidence (status codes, negative patterns, etc.)
        if evidence_strength == EvidenceStrength.DIRECT:
            if passed_matchers >= 2:
                return "high"
            return "medium"

        # INFERENCE evidence (JSON values, time delays, diffs)
        if evidence_strength == EvidenceStrength.INFERENCE:
            if passed_matchers >= 2 and is_consistent:
                return "medium"
            return "low"

        # HEURISTIC evidence (regex patterns, word matches)
        if evidence_strength == EvidenceStrength.HEURISTIC:
            if passed_matchers >= 3 and is_consistent:
                return "medium"
            return "low"

        return "low"


def compare_responses(
    baseline: Response,
    response_true: Response,
    response_false: Response,
    threshold: float = 0.1,
) -> Dict[str, Any]:
    """Compare responses for boolean-blind detection (SQLMap pattern).

    For boolean-blind SQL injection:
    - TRUE condition payload should differ from baseline
    - FALSE condition payload should also differ (differently)

    Args:
        baseline: Baseline response (normal input)
        response_true: Response with TRUE condition payload (e.g., ' AND '1'='1)
        response_false: Response with FALSE condition payload (e.g., ' AND '1'='2)
        threshold: Difference threshold (default 10%)

    Returns:
        Dict with comparison results including is_vulnerable flag
    """
    checker = ConsistencyChecker()

    # Calculate similarity scores
    true_sim = checker.get_similarity_score(baseline, response_true)
    false_sim = checker.get_similarity_score(baseline, response_false)
    true_false_sim = checker.get_similarity_score(response_true, response_false)

    # Boolean-blind conditions:
    # 1. TRUE response differs from baseline (true_sim < 0.9)
    # 2. FALSE response differs from TRUE response (true_false_sim < 0.9)
    # This indicates the application is responding differently to conditions

    is_vulnerable = (
        true_sim < (1.0 - threshold) and  # TRUE differs from baseline
        true_false_sim < (1.0 - threshold)  # FALSE differs from TRUE
    )

    return {
        "is_vulnerable": is_vulnerable,
        "baseline_true_similarity": round(true_sim, 3),
        "baseline_false_similarity": round(false_sim, 3),
        "true_false_similarity": round(true_false_sim, 3),
        "detection_type": "boolean_blind",
        "evidence": {
            "baseline_length": len(baseline.text),
            "true_length": len(response_true.text),
            "false_length": len(response_false.text),
        },
        "confidence": "high" if is_vulnerable else "low",
    }


def create_finding_from_dict(data: Dict[str, Any]) -> "Finding":
    from dast.config.scan import Finding
    from dast.config.common import OWASPCategory, SeverityLevel, EvidenceStrength

    owasp_str = data.get("owasp_category", "A02:2025")
    if isinstance(owasp_str, str):
        for cat in OWASPCategory:
            if cat.value == owasp_str or cat.name.lower().replace("_", "") in owasp_str.lower().replace(":", "").replace("-", "").replace(" ", ""):
                owasp_category = cat
                break
        else:
            owasp_category = OWASPCategory.A02_SECURITY_MISCONFIGURATION
    else:
        owasp_category = owasp_str

    severity_str = data.get("severity", "Medium")
    if isinstance(severity_str, str):
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity = severity_map.get(severity_str.lower(), SeverityLevel.MEDIUM)
    else:
        severity = severity_str

    return Finding(
        template_id=data.get("template_id", "dom-xss"),
        vulnerability_type=data.get("vulnerability_type", "Unknown"),
        severity=severity,
        owasp_category=owasp_category,
        evidence_strength=EvidenceStrength.DIRECT,
        url=data.get("url", ""),
        evidence=data.get("evidence", {}),
        message=data.get("message", ""),
        remediation=data.get("remediation", ""),
    )
