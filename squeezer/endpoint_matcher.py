from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from squeezer.models import load_endpoint_synonyms


class EndpointMatcher:
    def __init__(self):
        self.synonyms = load_endpoint_synonyms()
        self._build_reverse_map()

    def _build_reverse_map(self):
        self.reverse_map = {}
        for key, values in self.synonyms.items():
            for v in values:
                self.reverse_map[v.lower()] = key

    def match_endpoint(self, endpoint_url: str, pattern: str) -> bool:
        parsed = urlparse(endpoint_url)
        path = parsed.path.lower().strip("/")

        pattern = pattern.lower().strip("@")

        if pattern in path or path.endswith(pattern):
            return True

        pattern_key = self.reverse_map.get(pattern)
        if pattern_key:
            for synonym in self.synonyms.get(pattern_key, []):
                if synonym.lower() in path or path.endswith(synonym.lower()):
                    return True

        return False

    def filter_endpoints(self, endpoints: Dict[str, str], pattern: str) -> List[str]:
        pattern = pattern.lower().strip("@")

        if pattern == "api":
            return [url for url in endpoints.keys() if "/api/" in url.lower() or url.lower().startswith("/api")]

        if "@" not in pattern:
            matching = []
            for url in endpoints.keys():
                parsed = urlparse(url)
                path = parsed.path.lower().strip("/")
                if pattern in path or path.endswith(pattern):
                    matching.append(url)
                else:
                    pattern_key = self.reverse_map.get(pattern)
                    if pattern_key:
                        for synonym in self.synonyms.get(pattern_key, []):
                            if synonym.lower() in path or path.endswith(synonym.lower()):
                                matching.append(url)
                                break
            return matching

        return list(endpoints.keys())

    def expand_with_synonyms(self, pattern: str) -> List[str]:
        pattern = pattern.lower().strip("@")

        if pattern in self.synonyms:
            return self.synonyms[pattern]

        for key, values in self.synonyms.items():
            if pattern in values:
                return values

        return [pattern]

    def match_suffix(self, endpoint_url: str, suffix: str) -> bool:
        parsed = urlparse(endpoint_url)
        path = parsed.path.lower()

        suffix = suffix.lower().strip("@")

        if path.endswith(suffix):
            return True

        suffix_parts = suffix.split("/")
        if len(suffix_parts) > 1:
            first_part = suffix_parts[0]
            remaining = "/".join(suffix_parts[1:])
            first_key = self.reverse_map.get(first_part)
            if first_key:
                for synonym in self.synonyms.get(first_key, []):
                    if path.endswith(f"{synonym.lower()}/{remaining}"):
                        return True

        return False
