import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from dast.auth import AuthContext, Authenticator
from dast.config import (
    DetectionTier,
    RequestConfig,
    ScanProfile,
    ScanReport,
    TargetConfig,
    Template,
)
from dast.scanner.context import ExecutionContext
from dast.scanner.executor import execute_request
from dast.scanner.expander import (
    build_get_request,
    build_post_request,
    expand_broadcast_template,
    expand_template,
    expand_with_tiers,
)
from dast.utils import TargetValidator, logger, sanitize_url


class TemplateEngine:
    # Tier mapping: which tiers run for each profile
    PROFILE_TIERS = {
        ScanProfile.PASSIVE: [DetectionTier.PASSIVE],
        ScanProfile.STANDARD: [DetectionTier.PASSIVE, DetectionTier.ACTIVE],
        ScanProfile.THOROUGH: [DetectionTier.PASSIVE, DetectionTier.ACTIVE, DetectionTier.AGGRESSIVE],
        ScanProfile.AGGRESSIVE: [DetectionTier.PASSIVE, DetectionTier.ACTIVE, DetectionTier.AGGRESSIVE],
    }

    def __init__(
        self,
        target: TargetConfig,
        validate_target: bool = True,
        scan_profile: ScanProfile = ScanProfile.STANDARD,
    ):
        self.target = target
        self.scan_profile = scan_profile
        self.authenticator = Authenticator()
        self._auth_context: Optional[AuthContext] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._validate_target = validate_target
        self._connectivity_check: Optional[Dict[str, Any]] = None
        self._semaphore = asyncio.Semaphore(max(1, target.parallel))
        self._request_delay = target.request_delay

    async def _acquire_slot(self):
        """Acquire a concurrency slot and apply delay if configured."""
        await self._semaphore.acquire()
        if self._request_delay > 0:
            await asyncio.sleep(self._request_delay)

    def _release_slot(self):
        self._semaphore.release()

    async def initialize(self) -> None:
        is_valid, error = TargetValidator.validate_url(self.target.base_url)
        if not is_valid:
            raise ValueError(f"Invalid target URL: {error}")

        if self._validate_target:
            logger.debug(f"Checking connectivity to {sanitize_url(self.target.base_url)}")
            self._connectivity_check = await TargetValidator.check_connectivity(
                self.target.base_url,
                timeout=min(self.target.timeout, 10.0)
            )

            if not self._connectivity_check["accessible"]:
                logger.warning(
                    f"Target may not be accessible: {self._connectivity_check.get('error', 'Unknown error')}"
                )
            else:
                logger.debug(
                    f"Target accessible: {self._connectivity_check['status_code']} "
                    f"({self._connectivity_check.get('server', 'Unknown server')}) "
                    f"in {self._connectivity_check.get('response_time_ms', 0):.0f}ms"
                )

        if self.target.authentication and self.target.authentication.type != "none":
            logger.debug(f"Authenticating with {self.target.authentication.type.value}")
            try:
                self._auth_context = await self.authenticator.authenticate(
                    self.target.authentication
                )
                logger.debug("Authentication successful")
            except Exception as e:
                logger.error(f"Authentication failed: {e}")
                raise

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.target.base_url,
                timeout=self.target.timeout,
                follow_redirects=True,
            )
        return self._client

    async def execute_template(self, template: Template, report: ScanReport) -> None:
        logger.debug(f"Executing template: {template.id}")

        # Expand generic template if present
        requests_to_execute = self._expand_template(template)

        # Create execution context
        # Include endpoints in variables for direct interpolation {{endpoint_name}}
        variables = self.target.get_variables().copy()
        variables.update(self.target.get_endpoints())

        # Add discovered_params for template use
        discovered_params = self.target.get_discovered_params()
        if discovered_params:
            variables["discovered_params"] = discovered_params

        context = ExecutionContext(
            variables=variables,
            endpoints=self.target.get_endpoints(),
        )
        context.variables.update(template.variables)

        # Execute each request
        for i, request_config in enumerate(requests_to_execute, 1):
            request_name = request_config.name or f"Request {i}"
            logger.debug(f"  Executing: {request_name}")

            try:
                finding = await self._execute_request(request_config, context, template)
                if finding:
                    logger.debug(f"  [+] Finding: {finding.vulnerability_type}")
                    report.add_finding(finding)
            except httpx.TimeoutException:
                logger.warning(f"  [-] Request timeout: {request_name}")
                report.add_error(f"Template {template.id}: Request timeout - {request_name}")
            except httpx.ConnectError as e:
                logger.error(f"  [-] Connection error: {e}")
                report.add_error(f"Template {template.id}: Connection error - {request_name}")
                break  # Stop processing this template on connection errors
            except Exception as e:
                logger.debug(f"  [-] Request failed: {e}")
                report.add_error(f"Template {template.id}: {request_name} - {str(e)}")

    def _load_payloads_from_file(self, file_path: str) -> List[str]:
        project_root = Path(__file__).parent.parent.parent.resolve()
        payloads_dir = project_root / "payloads"

        path = Path(file_path)
        if not path.is_absolute():
            path = (project_root / file_path).resolve()
        else:
            path = path.resolve()
        if not (path.is_relative_to(payloads_dir) or path.is_relative_to(project_root)):
            raise ValueError(
                f"Payload file path validation failed: {file_path} "
                f"(resolved to {path}) is outside allowed directories"
            )

        if not path.exists():
            logger.warning(f"Payload file not found: {file_path}")
            return []

        payloads = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    payloads.append(line)
            logger.debug(f"Loaded {len(payloads)} payloads from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load payload file {file_path}: {e}")

        return payloads

    def _expand_template(self, template: Template) -> List[RequestConfig]:
        return expand_template(
            template=template,
            target=self.target,
            scan_profile=self.scan_profile,
            load_payloads_fn=self._load_payloads_from_file,
            build_get_fn=build_get_request,
            build_post_fn=build_post_request,
            expand_broadcast_fn=lambda t, g, e: expand_broadcast_template(
                t, g, e, self.target, self._load_payloads_from_file,
                build_get_request, build_post_request,
                lambda tmpl, ep, gen: self._expand_with_tiers(tmpl, ep, gen),
            ),
            expand_tiers_fn=lambda t, ep, g: self._expand_with_tiers(t, ep, g),
        )

    def _expand_with_tiers(self, template: Template, endpoint_path: str, generic) -> List[RequestConfig]:
        return expand_with_tiers(
            template=template,
            endpoint_path=endpoint_path,
            generic=generic,
            scan_profile=self.scan_profile,
            profile_tiers_map=self.PROFILE_TIERS,
            build_get_fn=build_get_request,
            build_post_fn=build_post_request,
        )

    async def _execute_request(
        self,
        config: RequestConfig,
        context: ExecutionContext,
        template: Template,
    ):
        await self._acquire_slot()
        try:
            return await execute_request(
                config=config,
                context=context,
                template=template,
                target=self.target,
                auth_context=self._auth_context,
                get_client_fn=self._get_client,
            )
        finally:
            self._release_slot()


def load_templates(template_dirs) -> List[Template]:
    templates = []
    skipped = 0

    if isinstance(template_dirs, (Path, str)):
        dirs_to_scan = [Path(template_dirs)]
    else:
        dirs_to_scan = [Path(d) for d in template_dirs]

    for template_dir in dirs_to_scan:
        if template_dir.is_file():
            yaml_files = [template_dir]
        else:
            yaml_files = list(template_dir.rglob("*.yaml"))

        for yaml_file in yaml_files:
            try:
                template = Template.from_yaml(yaml_file)
                templates.append(template)
                logger.debug(f"Loaded template: {template.id}")
            except Exception as e:
                skipped += 1
                logger.debug(f"Skipping invalid template {yaml_file.name}: {e}")

    logger.debug(f"Loaded {len(templates)} templates ({skipped} skipped)")
    return templates


async def run_scan(
    target: TargetConfig,
    templates: List[Template],
    validate_target: bool = True,
    scan_profile: ScanProfile = ScanProfile.STANDARD,
) -> ScanReport:
    start_time = time.time()
    target_url = sanitize_url(target.base_url)

    logger.info(f"Scanning {target_url} with {len(templates)} templates")
    report = ScanReport(target=target.base_url, templates_executed=len(templates))

    engine = TemplateEngine(target, validate_target=validate_target, scan_profile=scan_profile)

    try:
        await engine.initialize()

        for i, template in enumerate(templates, 1):
            logger.debug(f"[{i}/{len(templates)}] {template.id}")
            try:
                await engine.execute_template(template, report)
            except Exception as e:
                logger.debug(f"Template {template.id} failed: {e}")
                report.add_error(f"Template {template.id} failed: {e}")

    except KeyboardInterrupt:
        logger.warning("Scan interrupted")
        report.add_error("Scan interrupted")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        report.add_error(f"Scan failed: {e}")
    finally:
        await engine.close()

    report.duration_seconds = time.time() - start_time

    return report
