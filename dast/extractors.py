"""Data extractors for capturing dynamic values from HTTP responses.

Extractors enable multi-request workflows by capturing values from responses
and making them available as variables for subsequent requests.
"""

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

import httpx


class ExtractionResult:
    """Result of an extraction operation."""

    def __init__(self, name: str, value: Any, success: bool = True):
        self.name = name
        self.value = value
        self.success = success

    def __bool__(self) -> bool:
        return self.success and self.value is not None


class Extractor(ABC):
    """Abstract base class for data extractors."""

    def __init__(self, name: str, group: int = 1, internal: bool = False):
        """Initialize the extractor.

        Args:
            name: Variable name to store the extracted value
            group: Regex group number to extract (for regex extractors)
            internal: If True, don't include in findings (metadata only)
        """
        self.name = name
        self.group = group
        self.internal = internal

    @abstractmethod
    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value from HTTP response.

        Args:
            response: The HTTP response to extract from

        Returns:
            ExtractionResult with the extracted value
        """
        pass


class RegexExtractor(Extractor):
    """Extract data using regular expressions."""

    def __init__(
        self,
        name: str,
        regex: str,
        group: int = 1,
        part: str = "body",
        internal: bool = False,
    ):
        """Initialize regex extractor.

        Args:
            name: Variable name to store the extracted value
            regex: Regular expression pattern with capture groups
            group: Which capture group to extract (default: 1)
            part: Response part to search (body, headers, all)
            internal: If True, don't include in findings
        """
        super().__init__(name, group, internal)
        self.regex = regex
        self.part = part.lower()
        self._compiled_regex = re.compile(regex)

    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value using regex pattern."""
        search_text = self._get_search_text(response)
        if search_text is None:
            return ExtractionResult(self.name, None, False)

        match = self._compiled_regex.search(search_text)
        if match:
            try:
                value = match.group(self.group)
                return ExtractionResult(self.name, value, True)
            except IndexError:
                return ExtractionResult(self.name, None, False)

        return ExtractionResult(self.name, None, False)

    def _get_search_text(self, response: httpx.Response) -> Optional[str]:
        """Get the text to search based on part configuration."""
        if self.part == "body":
            return response.text
        elif self.part == "header":
            return str(response.headers)
        elif self.part == "all":
            return f"{response.headers}\n\n{response.text}"
        return response.text


class JsonExtractor(Extractor):
    """Extract data from JSON responses using JSONPath-like selectors."""

    def __init__(
        self,
        name: str,
        selector: str,
        internal: bool = False,
    ):
        """Initialize JSON extractor.

        Args:
            name: Variable name to store the extracted value
            selector: JSONPath selector (e.g., "$.data.id", "$.user.token")
            internal: If True, don't include in findings
        """
        super().__init__(name, internal=internal)
        self.selector = selector

    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value from JSON response using selector."""
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            return ExtractionResult(self.name, None, False)

        value = self._extract_json_path(data, self.selector)
        return ExtractionResult(self.name, value, value is not None)

    def _extract_json_path(self, data: Any, path: str) -> Any:
        """Extract value from JSON using dot notation with array support.

        Supports:
            - "$.user.name" -> data["user"]["name"]
            - "$.data.users.0" -> data["data"]["users"][0]
            - "$.items[0].id" -> data["items"][0]["id"]
        """
        if not path:
            return data

        # Normalize path - remove leading $.
        path = path.lstrip("$.")
        if not path:
            return data

        current = data

        # Handle both dot notation and bracket notation
        parts = self._parse_path(path)

        for part in parts:
            if current is None:
                return None

            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                # Try to use part as index
                try:
                    idx = int(part)
                    if 0 <= idx < len(current):
                        current = current[idx]
                    else:
                        return None
                except ValueError:
                    return None
            else:
                return None

        return current

    def _parse_path(self, path: str) -> List[str]:
        """Parse JSON path into components.

        Handles both:
            - "data.user.token" -> ["data", "user", "token"]
            - "items[0].name" -> ["items", "0", "name"]
        """
        parts = []

        # First, handle bracket notation
        bracket_pattern = r'\[([^\]]+)\]'
        path = re.sub(bracket_pattern, r'.\1.', path)

        # Split by dots and filter empty strings
        for part in path.split('.'):
            if part:
                parts.append(part)

        return parts


class HeaderExtractor(Extractor):
    """Extract data from HTTP response headers."""

    def __init__(
        self,
        name: str,
        header: str,
        regex: Optional[str] = None,
        group: int = 1,
        internal: bool = False,
    ):
        """Initialize header extractor.

        Args:
            name: Variable name to store the extracted value
            header: Header name to extract (case-insensitive)
            regex: Optional regex to filter header value
            group: Regex group number if regex provided
            internal: If True, don't include in findings
        """
        super().__init__(name, group, internal)
        self.header = header.lower()
        self.regex = re.compile(regex) if regex else None

    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value from response headers."""
        # Headers are case-insensitive
        value = None
        for key, val in response.headers.items():
            if key.lower() == self.header:
                value = val
                break

        if value is None:
            return ExtractionResult(self.name, None, False)

        # Apply regex if provided
        if self.regex:
            match = self.regex.search(value)
            if match:
                try:
                    value = match.group(self.group)
                    return ExtractionResult(self.name, value, True)
                except IndexError:
                    return ExtractionResult(self.name, None, False)
            return ExtractionResult(self.name, None, False)

        return ExtractionResult(self.name, value, True)


class CookieExtractor(Extractor):
    """Extract data from HTTP response cookies."""

    def __init__(
        self,
        name: str,
        cookie: str,
        regex: Optional[str] = None,
        group: int = 1,
        internal: bool = False,
    ):
        """Initialize cookie extractor.

        Args:
            name: Variable name to store the extracted value
            cookie: Cookie name to extract
            regex: Optional regex to filter cookie value
            group: Regex group number if regex provided
            internal: If True, don't include in findings
        """
        super().__init__(name, group, internal)
        self.cookie = cookie
        self.regex = re.compile(regex) if regex else None

    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value from response cookies."""
        # Check cookies in response
        value = response.cookies.get(self.cookie)

        if value is None:
            return ExtractionResult(self.name, None, False)

        # Apply regex if provided
        if self.regex:
            match = self.regex.search(value)
            if match:
                try:
                    value = match.group(self.group)
                    return ExtractionResult(self.name, value, True)
                except IndexError:
                    return ExtractionResult(self.name, None, False)
            return ExtractionResult(self.name, None, False)

        return ExtractionResult(self.name, value, True)


class XPathExtractor(Extractor):
    """Extract data from HTML using XPath selectors."""

    def __init__(
        self,
        name: str,
        xpath: str,
        attribute: Optional[str] = None,
        internal: bool = False,
    ):
        """Initialize XPath extractor.

        Args:
            name: Variable name to store the extracted value
            xpath: XPath expression to select element
            attribute: Optional attribute name to extract (default: text content)
            internal: If True, don't include in findings
        """
        super().__init__(name, internal=internal)
        self.xpath = xpath
        self.attribute = attribute
        self._lxml_available = self._check_lxml()

    def _check_lxml(self) -> bool:
        """Check if lxml is available."""
        try:
            from lxml import html as lxml_html
            return True
        except ImportError:
            return False

    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value from HTML using XPath."""
        if not self._lxml_available:
            # Fallback to regex-based extraction
            return self._fallback_extract(response)

        try:
            from lxml import html as lxml_html, etree

            doc = lxml_html.fromstring(response.content)
            elements = doc.xpath(self.xpath)

            if not elements:
                return ExtractionResult(self.name, None, False)

            # Get first matching element
            element = elements[0]

            if self.attribute:
                value = element.get(self.attribute)
            elif isinstance(element, etree._Element):
                value = element.text_content().strip()
            else:
                value = str(element)

            return ExtractionResult(self.name, value, True)

        except Exception:
            return ExtractionResult(self.name, None, False)

    def _fallback_extract(self, response: httpx.Response) -> ExtractionResult:
        """Fallback extraction without lxml (basic regex)."""
        # Simple extraction for common patterns
        if self.attribute:
            pattern = rf'{self.attribute}=["\']([^"\']+)["\']'
            match = re.search(pattern, response.text)
            if match:
                return ExtractionResult(self.name, match.group(1), True)
        return ExtractionResult(self.name, None, False)


class KataExtractor(Extractor):
    """Extract data using KQL (Kotlin Query Language) like syntax.

    This is inspired by Burp Suite's Intruder - useful for extracting
    structured data from semi-structured responses.
    """

    def __init__(
        self,
        name: str,
        prefix: str,
        suffix: str,
        internal: bool = False,
    ):
        """Initialize KATA extractor.

        Args:
            name: Variable name to store the extracted value
            prefix: Text that appears before the desired value
            suffix: Text that appears after the desired value
            internal: If True, don't include in findings
        """
        super().__init__(name, internal=internal)
        self.prefix = re.escape(prefix)
        self.suffix = re.escape(suffix)
        self._pattern = re.compile(f"{self.prefix}(.*?){self.suffix}", re.DOTALL)

    def extract(self, response: httpx.Response) -> ExtractionResult:
        """Extract value between prefix and suffix."""
        match = self._pattern.search(response.text)
        if match:
            value = match.group(1).strip()
            return ExtractionResult(self.name, value, True)
        return ExtractionResult(self.name, None, False)


def create_extractor(config: Dict[str, Any]) -> Extractor:
    """Factory function to create extractor from configuration.

    Args:
        config: Extractor configuration dict with keys:
            - type: Extractor type (regex, json, header, cookie, xpath, kata)
            - name: Variable name
            - [type-specific params]

    Returns:
        Extractor instance

    Raises:
        ValueError: If extractor type is unknown
    """
    extractor_type = config.get("type", "regex").lower()
    name = config.get("name")
    internal = config.get("internal", False)

    if not name:
        raise ValueError("Extractor requires 'name' field")

    if extractor_type == "regex":
        return RegexExtractor(
            name=name,
            regex=config.get("regex", ""),
            group=config.get("group", 1),
            part=config.get("part", "body"),
            internal=internal,
        )

    elif extractor_type == "json":
        return JsonExtractor(
            name=name,
            selector=config.get("selector", ""),
            internal=internal,
        )

    elif extractor_type == "header":
        return HeaderExtractor(
            name=name,
            header=config.get("header", ""),
            regex=config.get("regex"),
            group=config.get("group", 1),
            internal=internal,
        )

    elif extractor_type == "cookie":
        return CookieExtractor(
            name=name,
            cookie=config.get("cookie", ""),
            regex=config.get("regex"),
            group=config.get("group", 1),
            internal=internal,
        )

    elif extractor_type == "xpath":
        return XPathExtractor(
            name=name,
            xpath=config.get("xpath", ""),
            attribute=config.get("attribute"),
            internal=internal,
        )

    elif extractor_type == "kata":
        return KataExtractor(
            name=name,
            prefix=config.get("prefix", ""),
            suffix=config.get("suffix", ""),
            internal=internal,
        )

    else:
        raise ValueError(f"Unknown extractor type: {extractor_type}")


def extract_all(
    response: httpx.Response,
    extractor_configs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Extract all values from response using multiple extractors.

    Args:
        response: HTTP response to extract from
        extractor_configs: List of extractor configuration dicts

    Returns:
        Dictionary mapping extractor names to extracted values
    """
    results = {}

    for config in extractor_configs:
        try:
            extractor = create_extractor(config)
            result = extractor.extract(response)
            if result:
                results[result.name] = result.value
        except Exception:
            # Continue on extraction errors
            continue

    return results
