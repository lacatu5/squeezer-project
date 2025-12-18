"""Config merger utilities for combining crawler and user configurations.

The crawler provides TargetConfig via SimpleCrawlerReport.to_target_config().
This module handles merging configs when both user config and crawled config exist.
"""

from dast.config import (
    AuthType,
    EndpointsConfig,
    TargetConfig,
)


def merge_configs(
    base_config: TargetConfig,
    crawled_config: TargetConfig,
    preserve_auth: bool = True,
    preserve_headers: bool = True,
) -> TargetConfig:
    """Merge a crawled config with a user-provided config.

    User config settings take precedence for auth and headers,
    while crawled endpoints are added to existing ones.

    Args:
        base_config: User-provided base TargetConfig
        crawled_config: TargetConfig generated from crawler
        preserve_auth: Keep auth settings from base_config
        preserve_headers: Keep headers from base_config

    Returns:
        Merged TargetConfig

    Raises:
        ValueError: If base_urls don't match between configs
    """
    # Validate that base_urls match
    if base_config.base_url != crawled_config.base_url:
        raise ValueError(
            f"Cannot merge configs with different base URLs: "
            f"{base_config.base_url} != {crawled_config.base_url}"
        )

    # Merge endpoints
    merged_custom = {}

    # Add base endpoints first
    if base_config.endpoints and base_config.endpoints.custom:
        merged_custom.update(base_config.endpoints.custom)

    # Add crawled endpoints (avoid overwriting existing)
    if crawled_config.endpoints and crawled_config.endpoints.custom:
        for key, value in crawled_config.endpoints.custom.items():
            # Add suffix if key already exists
            final_key = key
            counter = 1
            while final_key in merged_custom:
                final_key = f"{key}_{counter}"
                counter += 1
            merged_custom[final_key] = value

    # Determine auth config (base takes precedence)
    auth_config = base_config.authentication
    if not preserve_auth or not auth_config or auth_config.type == AuthType.NONE:
        auth_config = crawled_config.authentication

    # Merge headers
    headers = {}
    if preserve_headers and base_config.authentication:
        headers.update(base_config.authentication.headers)
    headers.update(crawled_config.authentication.headers)

    # Update auth headers
    if auth_config:
        auth_config.headers = headers

    return TargetConfig(
        name=base_config.name,
        base_url=base_config.base_url,
        authentication=auth_config,
        endpoints=EndpointsConfig(
            base=base_config.endpoints.base if base_config.endpoints else "",
            custom=merged_custom,
        ),
        variables=base_config.variables,
        timeout=base_config.timeout,
        parallel=base_config.parallel,
        request_delay=base_config.request_delay,
        boolean_diff_threshold=base_config.boolean_diff_threshold,
        time_samples=base_config.time_samples,
    )
