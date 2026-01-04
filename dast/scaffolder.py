import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


def sanitize_name(name: str) -> str:
    return re.sub(r'[^a-z0-9_-]', '-', name.lower()).strip('-')


def endpoint_to_template_name(path: str, method: str) -> str:
    clean = path.strip('/').replace('/', '-').replace('{', '').replace('}', '')
    clean = re.sub(r'[^a-z0-9-]', '', clean.lower())
    if not clean:
        clean = 'root'
    return f"{method.lower()}-{clean}"


def classify_endpoint(path: str, method: str) -> list[str]:
    tags = []
    path_lower = path.lower()

    if any(p in path_lower for p in ['/user', '/account', '/profile', '/member']):
        tags.append('user-data')
    if any(p in path_lower for p in ['/admin', '/manage', '/dashboard']):
        tags.append('admin')
    if any(p in path_lower for p in ['/auth', '/login', '/logout', '/register', '/password']):
        tags.append('authentication')
    if any(p in path_lower for p in ['/cart', '/basket', '/order', '/checkout', '/payment']):
        tags.append('commerce')
    if any(p in path_lower for p in ['/upload', '/file', '/image', '/document']):
        tags.append('file-handling')
    if any(p in path_lower for p in ['/search', '/query', '/filter']):
        tags.append('search')
    if any(p in path_lower for p in ['/api/', '/rest/', '/v1/', '/v2/']):
        tags.append('api')

    if re.search(r'/\d+(?:/|$)', path) or re.search(r'/[a-f0-9-]{36}', path):
        tags.append('resource-id')

    if method in ['POST', 'PUT', 'PATCH']:
        tags.append('write-operation')
    if method == 'DELETE':
        tags.append('destructive')

    return tags or ['general']


def generate_idor_template(endpoint: dict, app_name: str) -> dict | None:
    path = endpoint.get('path', '')
    method = endpoint.get('method', 'GET')

    if not any(x in path.lower() for x in ['/api/', '/rest/']):
        return None

    return {
        'id': f"{app_name}-idor-{endpoint_to_template_name(path, method)}",
        'info': {
            'name': f"IDOR: {path}",
            'owasp_category': 'A01:2025',
            'severity': 'high',
            'tags': ['idor', app_name],
        },
        'requests': [
            {
                'path': f"{path}/1",
                'method': 'GET',
                'headers': {'Authorization': '{{bearer_token}}'},
                'matchers': [
                    {'type': 'status', 'status': [200]},
                ],
            },
        ],
    }


def generate_validation_template(endpoint: dict, app_name: str) -> dict | None:
    path = endpoint.get('path', '')
    method = endpoint.get('method', 'POST')

    if method not in ['POST', 'PUT', 'PATCH']:
        return None

    return {
        'id': f"{app_name}-validation-{endpoint_to_template_name(path, method)}",
        'info': {
            'name': f"Validation: {path}",
            'owasp_category': 'A02:2025',
            'severity': 'medium',
            'tags': ['validation', app_name],
        },
        'requests': [
            {
                'path': path,
                'method': method,
                'headers': {
                    'Authorization': '{{bearer_token}}',
                    'Content-Type': 'application/json',
                },
                'body': '{}',
                'matchers': [
                    {'type': 'status', 'status': [200, 201]},
                ],
            },
        ],
    }


def generate_auth_template(endpoint: dict, app_name: str) -> dict | None:
    path = endpoint.get('path', '')
    method = endpoint.get('method', 'GET')

    if not any(x in path.lower() for x in ['/api/', '/rest/']):
        return None

    return {
        'id': f"{app_name}-auth-{endpoint_to_template_name(path, method)}",
        'info': {
            'name': f"Auth: {path}",
            'owasp_category': 'A07:2025',
            'severity': 'high',
            'tags': ['auth', app_name],
        },
        'requests': [
            {
                'path': path,
                'method': method,
                'matchers': [
                    {'type': 'status', 'status': [200]},
                ],
            },
        ],
    }


def scaffold_app(
    app_name: str,
    target_url: str,
    endpoints: list[dict],
    output_dir: Path,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    app_name = sanitize_name(app_name)
    app_dir = output_dir / "templates" / "apps" / app_name
    app_dir.mkdir(parents=True, exist_ok=True)

    api_endpoints = []
    for ep in endpoints:
        url = ep.get('full_url', ep.get('url', ''))
        if not url:
            continue

        parsed = urlparse(url)
        path = parsed.path

        if any(ext in path for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff']):
            continue

        method = ep.get('method', 'GET')
        api_endpoints.append({
            'url': url,
            'path': path,
            'method': method,
            'query': parsed.query,
            'tags': classify_endpoint(path, method),
            'type': ep.get('type', 'unknown'),
        })

    app_config = {
        'name': app_name,
        'target_url': target_url,
        'created_at': datetime.now().isoformat(),
        'endpoints': api_endpoints,
        'auth': {
            'type': 'bearer' if bearer_token else 'none',
        },
    }

    config_path = app_dir / "app.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(app_config, f, default_flow_style=False, sort_keys=False)

    templates_created = []
    seen_paths = set()

    api_only = [ep for ep in api_endpoints if 'api' in ep['tags']]

    for ep in api_only[:10]:
        path = ep['path']
        if path in seen_paths:
            continue
        seen_paths.add(path)

        template = generate_idor_template(ep, app_name)
        if template:
            template_name = f"idor-{endpoint_to_template_name(path, ep['method'])}.yaml"
            template_path = app_dir / template_name
            with open(template_path, 'w') as f:
                yaml.dump(template, f, default_flow_style=False, sort_keys=False)
            templates_created.append(template_name)

    return {
        'app_dir': str(app_dir),
        'config_file': str(config_path),
        'endpoints_discovered': len(api_endpoints),
        'templates_created': templates_created,
    }


def load_app_config(app_name: str, base_dir: Path) -> dict | None:
    app_dir = base_dir / "templates" / "apps" / app_name
    config_path = app_dir / "app.yaml"

    if not config_path.exists():
        return None

    with open(config_path) as f:
        return yaml.safe_load(f)


def get_cached_endpoints(app_name: str, base_dir: Path) -> list[dict] | None:
    config = load_app_config(app_name, base_dir)
    if config and 'endpoints' in config:
        return config['endpoints']
    return None
