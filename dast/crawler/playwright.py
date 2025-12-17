"""DOM XSS validator using Playwright.

Validates XSS payloads by injecting them and observing JavaScript execution.

Installation:
    playwright install chromium
"""

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
except ImportError:
    raise ImportError(
        "Playwright not installed. Install with:\n"
        "  pip install playwright\n"
        "  playwright install chromium"
    )


class DOMXSSFinding(BaseModel):
    url: str
    payload: str
    sink: str
    source: str
    executed: bool
    evidence: str
    severity: str = "High"


class DOMXSSValidator:
    """DOM XSS validator using Playwright.

    Tests XSS payloads by injecting them and observing JavaScript execution.
    """

    XSS_PAYLOADS = [
        ("<img src=x onerror=alert('XSS')>", "img_onerror"),
        ("\"><script>alert('XSS')</script>", "script_injection"),
        ("javascript:alert('XSS')", "javascript_protocol"),
        ("<svg onload=alert('XSS')>", "svg_onload"),
        ("<iframe src=\"javascript:alert('XSS')\">", "iframe_javascript"),
        ("-alert('XSS')-", "scriptless_injection"),
        ("<body onload=alert('XSS')>", "body_onload"),
    ]

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 10000,
        browser_type: str = "chromium",
    ):
        self.headless = headless
        self.timeout = timeout
        self.browser_type = browser_type
        self._playwright = None
        self._browser = None
        self._context = None

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def initialize(self) -> None:
        self._playwright = await async_playwright().start()
        browser_class = getattr(self._playwright, self.browser_type)
        self._browser = await browser_class.launch(headless=self.headless)
        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
        )

    async def close(self) -> None:
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def test_url_parameter(
        self,
        url: str,
        param: str,
        payloads: Optional[List[str]] = None,
    ) -> List[DOMXSSFinding]:
        if payloads is None:
            payloads = [p[0] for p in self.XSS_PAYLOADS]

        findings = []

        for payload in payloads:
            try:
                finding = await self._test_payload(url, param, payload, "url")
                if finding:
                    findings.append(finding)
            except Exception:
                continue

        return findings

    async def test_form_input(
        self,
        url: str,
        form_data: Dict[str, str],
        field_name: str,
        payloads: Optional[List[str]] = None,
    ) -> List[DOMXSSFinding]:
        if payloads is None:
            payloads = [p[0] for p in self.XSS_PAYLOADS]

        findings = []

        for payload in payloads:
            try:
                finding = await self._test_payload(
                    url,
                    field_name,
                    payload,
                    "form",
                    form_data=form_data
                )
                if finding:
                    findings.append(finding)
            except Exception:
                continue

        return findings

    async def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        injection_type: str,
        form_data: Optional[Dict[str, str]] = None,
    ) -> Optional[DOMXSSFinding]:
        if not self._context:
            await self.initialize()

        page = await self._context.new_page()

        detection_script = """
        () => {
            window.xssDetected = false;
            window.xssSink = null;

            Element.prototype.innerHTML = function(...args) {
                window.xssDetected = true;
                window.xssSink = 'innerHTML';
                return Element.prototype.innerHTML.call(this, ...args);
            };

            const originalAlert = window.alert;
            window.alert = function(...args) {
                window.xssDetected = true;
                window.xssSink = 'alert';
                return originalAlert.apply(this, args);
            };

            window.addEventListener('error', (e) => {
                if (e.message && e.message.includes('XSS')) {
                    window.xssDetected = true;
                    window.xssSink = 'error';
                }
            });

            return true;
        }
        """

        try:
            await page.evaluate(detection_script)

            if injection_type == "url":
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{param}={payload}"
                await page.goto(test_url, timeout=self.timeout, wait_until="networkidle")
            elif injection_type == "form" and form_data:
                form_data[param] = payload
                await page.goto(url, timeout=self.timeout)
                await page.fill(f"[name='{param}']", payload)
                await page.press(f"[name='{param}']", "Enter")

            await asyncio.sleep(0.5)

            detected = await page.evaluate("() => window.xssDetected")
            sink = await page.evaluate("() => window.xssSink")

            if detected:
                return DOMXSSFinding(
                    url=page.url,
                    payload=payload[:200],
                    sink=sink or "unknown",
                    source=param,
                    executed=True,
                    evidence=f"XSS executed via {sink}",
                )

        except Exception:
            pass
        finally:
            await page.close()

        return None


async def validate_dom_xss(
    url: str,
    param: str,
    payloads: Optional[List[str]] = None,
    headless: bool = True,
) -> List[DOMXSSFinding]:
    async with DOMXSSValidator(headless=headless) as validator:
        return await validator.test_url_parameter(url, param, payloads)
