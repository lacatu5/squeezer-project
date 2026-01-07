
import logging
import time
from typing import Any
from urllib.parse import urlparse

import httpx


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

    logging.getLogger("httpx").setLevel(logging.WARNING)

    logger.setLevel(level)


logger = logging.getLogger("dast")


class TargetValidator:

    @staticmethod
    async def check_connectivity(
        url: str,
        timeout: float = 10.0
    ) -> dict[str, Any]:
        result = {
            "accessible": False,
            "status_code": None,
            "server": None,
            "error": None,
            "response_time_ms": None
        }

        try:
            start = time.time()

            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(url)

            result["response_time_ms"] = (time.time() - start) * 1000
            result["accessible"] = response.status_code < 500
            result["status_code"] = response.status_code
            result["server"] = response.headers.get("Server", "Unknown")

            if response.status_code >= 400:
                result["error"] = f"HTTP {response.status_code}"

        except httpx.ConnectError as e:
            result["error"] = f"Connection failed: {e}"
        except httpx.TimeoutException:
            result["error"] = "Connection timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    @staticmethod
    def validate_url(url: str) -> tuple[bool, str]:
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False, "URL must include scheme (http/https) and host"
            if parsed.scheme not in ("http", "https"):
                return False, "Only http and https schemes are supported"
            return True, ""
        except Exception as e:
            return False, f"Invalid URL: {e}"


def sanitize_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        if parsed.password:
            safe = parsed._replace(
                netloc=f"{parsed.username}:****@{parsed.hostname}"
            )
            if parsed.port:
                safe = safe._replace(
                    netloc=f"{parsed.username}:****@{parsed.hostname}:{parsed.port}"
                )
            return safe.geturl()
        return url
    except Exception:
        return url
