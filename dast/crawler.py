import asyncio
from typing import List, Set
from urllib.parse import urlparse

from crawlee.crawlers import PlaywrightCrawler, PlaywrightCrawlingContext
from dast.config import TargetConfig, EndpointsConfig, AuthConfig

async def crawl_target(url: str) -> TargetConfig:
    """
    Crawls the target URL using Playwright to discover endpoints.
    Executes JavaScript and extracts unique same-origin URLs.
    Returns a TargetConfig with discovered endpoints.
    """
    discovered_urls: Set[str] = set()
    base_domain = urlparse(url).netloc

    crawler = PlaywrightCrawler(
        # Limit the crawl to avoid infinite loops on huge sites, 
        # though for Juice Shop it should be fine.
        # User didn't specify limits, but a safety net is good.
        max_requests_per_crawl=1000,
        headless=True,
    )

    @crawler.router.default_handler
    async def request_handler(context: PlaywrightCrawlingContext) -> None:
        # Wait for SPA to load
        try:
            await context.page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass  # Continue even if network doesn't settle completely

        current_url = context.request.url
        parsed = urlparse(current_url)
        
        # Ensure same origin (Crawlee usually handles this with enqueue_links strategies, 
        # but let's be explicit in collection)
        if parsed.netloc == base_domain:
            discovered_urls.add(current_url)

        # Enqueue links found on the page
        # specific strategy needed for SPAs with hash routing?
        # We ensure we enqueue same-origin links.
        
        def enable_fragments(req_options):
            req_options['keep_url_fragment'] = True
            return req_options

        await context.enqueue_links(
            strategy="same-domain",
            transform_request_function=enable_fragments,
        )

    await crawler.run([url])

    # Convert discovered URLs to TargetConfig endpoints
    # Map paths to their full URLs. 
    # To handle multiple URLs with same path but different params, 
    # we might need a strategy. For now, we'll maintain uniqueness of full URL.
    # We generate keys based on the path.
    custom_endpoints = {}
    sorted_urls = sorted(list(discovered_urls))
    
    for start_url in sorted_urls:
        parsed = urlparse(start_url)
        path = parsed.path
        fragment = parsed.fragment
        
        # Use fragment if path is root and fragment exists
        if (not path or path == "/") and fragment:
            path = fragment
            
        if not path or path == "/":
            key = "root"
        else:
            # Create a key that is template-friendly
            # e.g. /rest/products/search -> rest_products_search
            key = path.strip("/").replace("/", "_").replace("-", "_")
            
        # If key exists (e.g. same path different query params), append index
        original_key = key
        counter = 1
        while key in custom_endpoints:
            key = f"{original_key}_{counter}"
            counter += 1
            
        custom_endpoints[key] = start_url

    return TargetConfig(
        name=f"crawled_{base_domain}",
        base_url=url,
        authentication=AuthConfig(), # Empty auth for now
        endpoints=EndpointsConfig(
            base="",
            custom=custom_endpoints
        )
    )

if __name__ == "__main__":
    import sys
    import yaml
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            config = asyncio.run(crawl_target(target))
            # Output as YAML matching TargetConfig format
            # We convert Pydantic model to dict
            config_dict = config.model_dump(exclude_unset=True)
            # Adjust endpoints structure if needed, but Pydantic dump should be close
            # TargetConfig matches the YAML structure usually.
            print(yaml.dump(config_dict, sort_keys=False))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python -m dast.crawler <url>", file=sys.stderr)
