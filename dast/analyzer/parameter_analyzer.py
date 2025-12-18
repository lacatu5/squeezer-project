"""Parameter analysis for vulnerability assessment.

Analyzes endpoints to identify injectable parameters and create
summaries for vulnerability targeting.
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from dast.analyzer.classifier import classify_parameter


def summarize_parameters(endpoint_infos: List[Any]) -> Dict[str, int]:
    """Summarize parameters by vulnerability type across all endpoints.

    Args:
        endpoint_infos: List of endpoint objects with query_params attribute

    Returns:
        Dictionary mapping vulnerability types to parameter counts
    """
    summary = {}

    for ep in endpoint_infos:
        params = getattr(ep, "query_params", [])

        for param in params:
            if isinstance(param, dict):
                param_name = param.get("name", "")
            else:
                param_name = str(param)

            vuln_types = classify_parameter(param_name)

            for vuln_type in vuln_types:
                summary[vuln_type] = summary.get(vuln_type, 0) + 1

    return summary


def get_injectable_parameters(endpoint_infos: List[Any]) -> Dict[str, List[Dict]]:
    """Extract injectable parameters grouped by endpoint path.

    Args:
        endpoint_infos: List of endpoint objects

    Returns:
        Dictionary mapping paths to lists of injectable parameters
        with their vulnerability types
    """
    result = {}

    for ep in endpoint_infos:
        path = getattr(ep, "path", urlparse(getattr(ep, "url", "")).path)
        params = getattr(ep, "query_params", [])

        injectable = []

        for param in params:
            if isinstance(param, dict):
                param_name = param.get("name", "")
            else:
                param_name = str(param)

            vuln_types = classify_parameter(param_name)

            if vuln_types != ["generic"]:
                injectable.append({
                    "name": param_name,
                    "vuln_types": vuln_types,
                })

        if injectable:
            result[path] = injectable

    return result
