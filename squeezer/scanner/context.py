"""Execution context for DAST scanning."""

import random
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List

import httpx


@dataclass
class ExecutionContext:
    """Execution context for template variables.

    Maintains state across multi-request workflows:
    - variables: Extracted values from previous requests
    - endpoints: Named endpoint URLs
    - responses: History of all responses for comparison
    """

    variables: Dict[str, Any] = field(default_factory=dict)
    endpoints: Dict[str, str] = field(default_factory=dict)
    responses: List[httpx.Response] = field(default_factory=list)

    _named_responses: Dict[str, httpx.Response] = field(default_factory=dict)

    def interpolate(self, text: str, max_iterations: int = 10) -> str:

        result = text
        prev_result = None

        for _ in range(max_iterations):
            prev_result = result
            result = self._interpolate_once(result)
            if result == prev_result:
                break

        return result

    def _interpolate_once(self, text: str) -> str:
        """Single pass of variable replacement."""
        result = text

        result = re.sub(r"rand_base\((\d+)\)", lambda m: self._rand_base(m.group(1)), result)
        result = re.sub(r"rand_int\((\d+)\,(\d+)\)", lambda m: str(random.randint(int(m.group(1)), int(m.group(2)))), result)
        result = re.sub(r"rand_int\(\)", lambda m: str(random.randint(10000, 99999)), result)
        result = re.sub(r"uuid\(\)", lambda m: str(uuid.uuid4()), result)

        for name, value in self.endpoints.items():
            result = result.replace(f"{{{{endpoints.{name}}}}}", value)

        def replace_with_default(match):
            var_name = match.group(1)
            default_value = match.group(2)
            return str(self.variables.get(var_name, default_value))

        result = re.sub(r'\{\{\s*(\w+)\s*\|\s*([^}]+)\s*\}\}', replace_with_default, result)

        for name in sorted(self.variables.keys(), key=len, reverse=True):
            value = self.variables[name]
            result = result.replace(f"{{{{{name}}}}}", str(value))
            result = result.replace(f"{{{{ {name} }}}}", str(value))

        return result

 
    def save_response(self, name: str, response: httpx.Response) -> None:
        self._named_responses[name] = response
