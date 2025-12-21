"""Utility functions for DAST scanning."""

import asyncio
import logging
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx


# Configure logging
def setup_logging(verbose: bool = False) -> None:
    """Configure logging for DAST scanner.

    Args:
        verbose: Enable debug logging
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Configure our logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )

    # Suppress noisy httpx logging
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Configure module-level logger
    logger.setLevel(level)


logger = logging.getLogger("dast")


class TargetValidator:
    """Validate target accessibility before scanning."""

    @staticmethod
    async def check_connectivity(
        url: str,
        timeout: float = 10.0
    ) -> dict[str, Any]:
        """Check if target is accessible.

        Returns:
            Dict with keys: accessible, status_code, server, error
        """
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
        """Validate URL format.

        Returns:
            (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False, "URL must include scheme (http/https) and host"
            if parsed.scheme not in ("http", "https"):
                return False, "Only http and https schemes are supported"
            return True, ""
        except Exception as e:
            return False, f"Invalid URL: {e}"


async def retry_async(
    func: Callable,
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    on_retry: Optional[Callable] = None,
) -> Any:
    """Retry an async function with exponential backoff.

    Args:
        func: Async function to retry
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries
        backoff: Multiplier for delay after each retry
        on_retry: Optional callback called before each retry

    Returns:
        Result of the function call

    Raises:
        Last exception if all retries fail
    """
    last_error = None
    current_delay = delay

    for attempt in range(max_retries):
        try:
            return await func()
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {current_delay}s...")
                if on_retry:
                    await on_retry(attempt + 1, e)
                await asyncio.sleep(current_delay)
                current_delay *= backoff
            else:
                logger.error(f"All {max_retries} attempts failed: {e}")

    raise last_error


def sanitize_url(url: str) -> str:
    """Sanitize URL for logging (remove credentials)."""
    try:
        parsed = urlparse(url)
        if parsed.password:
            # Remove password from URL
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
