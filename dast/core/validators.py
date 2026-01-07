"""Validation logic for retry logic, confidence scoring, and response comparison.

This module implements professional-grade validation patterns inspired by:
- Nuclei (multi-condition matchers)
- SQLMap (response comparison)
- Burp Suite (retry with consistency)
"""

from typing import TYPE_CHECKING, List
from httpx import Response

from dast.config.common import EvidenceStrength

if TYPE_CHECKING:
    pass


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
            passed_matchers: Matchers that passed
            is_consistent: Response was consistent across retries

        Returns:
            "high", "medium", or "low"
        """
        if not is_consistent:
            return "low"

        if evidence_strength == EvidenceStrength.DIRECT:
            if passed_matchers >= 2:
                return "high"
            return "medium"

        if evidence_strength == EvidenceStrength.INFERENCE:
            if passed_matchers >= 2 and is_consistent:
                return "medium"
            return "low"

        if evidence_strength == EvidenceStrength.HEURISTIC:
            if passed_matchers >= 3 and is_consistent:
                return "medium"
            return "low"

        return "low"
