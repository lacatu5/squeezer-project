"""Multi-context session manager for IDOR vulnerability detection.

This module enables testing Insecure Direct Object Reference (IDOR)
vulnerabilities by maintaining multiple authenticated sessions and
comparing responses between them.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx


@dataclass
class SessionContext:
    """Authenticated session context.

    Attributes:
        name: Identifier for this session (e.g., "attacker", "victim")
        email: User email for this session
        token: Authentication token
        cookies: Session cookies
        headers: Auth headers
        user_id: Extracted user ID
        basket_id: Extracted basket ID (for e-commerce apps)
    """

    name: str
    email: str
    token: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    user_id: Optional[int] = None
    basket_id: Optional[int] = None
    other_data: Dict[str, Any] = field(default_factory=dict)

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers for requests."""
        headers = self.headers.copy()
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def get_cookies(self) -> Dict[str, str]:
        """Get cookies for requests."""
        return self.cookies.copy()

    def set(self, key: str, value: Any) -> None:
        """Store additional data in this context."""
        self.other_data[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve data from this context."""
        return self.other_data.get(key, default)


@dataclass
class ResourceIdentifier:
    """Represents a resource ID that can be tested for IDOR."""

    resource_type: str  # "basket", "user", "feedback", "order", etc.
    id: int
    owner_context: str  # Name of the session that owns this resource
    endpoint: str  # API endpoint to access this resource


class SessionManager:
    """Manages multiple authenticated sessions for IDOR testing.

    The session manager enables:
    1. Creating multiple authenticated contexts (attacker, victim)
    2. Enumerating resources from victim context
    3. Testing access to victim resources from attacker context
    4. Detecting IDOR vulnerabilities through response comparison
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        """Initialize the session manager.

        Args:
            base_url: Base URL of the target application
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._contexts: Dict[str, SessionContext] = {}

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def create_context(
        self,
        name: str,
        email: str,
        password: str,
        login_path: str = "/rest/user/login",
    ) -> SessionContext:
        """Create an authenticated session context.

        Args:
            name: Context name (e.g., "attacker", "victim")
            email: User email
            password: User password
            login_path: Path to login endpoint

        Returns:
            Authenticated SessionContext

        Raises:
            httpx.HTTPError: If authentication fails
        """
        context = SessionContext(name=name, email=email)

        response = await self.client.post(
            login_path,
            json={"email": email, "password": password},
        )

        if response.status_code in (200, 201):
            data = response.json()
            # Extract common authentication fields
            context.token = data.get("authentication", {}).get("token", "")
            context.user_id = data.get("user", {}).get("id")
            context.basket_id = data.get("bid")

            # Extract any cookies
            if response.cookies:
                context.cookies.update(dict(response.cookies))

        self._contexts[name] = context
        return context

    def get_context(self, name: str) -> Optional[SessionContext]:
        """Get an existing context by name."""
        return self._contexts.get(name)

    def get_attacker_context(self) -> Optional[SessionContext]:
        """Get the attacker context (if created)."""
        return self.get_context("attacker")

    def get_victim_context(self) -> Optional[SessionContext]:
        """Get the victim context (if created)."""
        return self.get_context("victim")

    async def enumerate_resources(
        self,
        context_name: str,
        resource_type: str,
        endpoint: str,
    ) -> List[ResourceIdentifier]:
        """Enumerate resource IDs from a context.

        Args:
            context_name: Name of context to enumerate from
            resource_type: Type of resource ("basket", "user", etc.)
            endpoint: API endpoint to list resources

        Returns:
            List of ResourceIdentifier objects
        """
        context = self.get_context(context_name)
        if not context:
            return []

        resources = []
        response = await self.client.get(
            endpoint,
            headers=context.get_auth_headers(),
            cookies=context.get_cookies(),
        )

        if response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, dict):
                    data = data.get("data", data)

                # Handle array of resources
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "id" in item:
                            resources.append(ResourceIdentifier(
                                resource_type=resource_type,
                                id=item["id"],
                                owner_context=context_name,
                                endpoint=endpoint,
                            ))
            except Exception:
                pass

        return resources

    async def test_idor(
        self,
        attacker_context: str,
        victim_context: str,
        resource: ResourceIdentifier,
    ) -> Tuple[bool, Any, Any]:
        """Test if attacker can access victim's resource (IDOR detection).

        Args:
            attacker_context: Name of attacker context
            victim_context: Name of victim context
            resource: Resource to test access to

        Returns:
            Tuple of (is_vulnerable, attacker_response, victim_response)
        """
        attacker = self.get_context(attacker_context)
        victim = self.get_context(victim_context)

        if not attacker or not victim:
            return False, None, None

        # Get victim's response (expected to succeed)
        victim_response = await self.client.get(
            f"{resource.endpoint}/{resource.id}",
            headers=victim.get_auth_headers(),
            cookies=victim.get_cookies(),
        )

        # Get attacker's response (testing unauthorized access)
        attacker_response = await self.client.get(
            f"{resource.endpoint}/{resource.id}",
            headers=attacker.get_auth_headers(),
            cookies=attacker.get_cookies(),
        )

        # IDOR detected if attacker gets same/similar data as victim
        is_vulnerable = (
            attacker_response.status_code == 200
            and victim_response.status_code == 200
        )

        if is_vulnerable:
            # Additional check: compare response data
            try:
                attacker_data = attacker_response.json()
                victim_data = victim_response.json()

                # Check if responses contain the same resource ID
                if isinstance(attacker_data, dict) and isinstance(victim_data, dict):
                    attacker_id = attacker_data.get("data", attacker_data).get("id")
                    victim_id = victim_data.get("data", victim_data).get("id")

                    if attacker_id == victim_id == resource.id:
                        is_vulnerable = True
                    else:
                        is_vulnerable = False
            except Exception:
                pass

        return is_vulnerable, attacker_response, victim_response

    async def create_dual_contexts(
        self,
        attacker_email: str,
        attacker_password: str,
        victim_email: str,
        victim_password: str,
        login_path: str = "/rest/user/login",
    ) -> Tuple[SessionContext, SessionContext]:
        """Create attacker and victim contexts.

        Args:
            attacker_email: Email for attacker account
            attacker_password: Password for attacker account
            victim_email: Email for victim account
            victim_password: Password for victim account
            login_path: Path to login endpoint

        Returns:
            Tuple of (attacker_context, victim_context)
        """
        attacker = await self.create_context(
            "attacker",
            attacker_email,
            attacker_password,
            login_path,
        )

        victim = await self.create_context(
            "victim",
            victim_email,
            victim_password,
            login_path,
        )

        return attacker, victim

    async def execute_idor_template(
        self,
        requests: List[Dict[str, Any]],
    ) -> List[Tuple[bool, Any, Any]]:
        """Execute a sequence of requests for IDOR testing.

        Args:
            requests: List of request dicts with:
                - context: Which context to use ("attacker", "victim")
                - method: HTTP method
                - path: Request path
                - headers: Additional headers
                - json: Request body

        Returns:
            List of (vulnerable, response) tuples
        """
        results = []

        for request in requests:
            context_name = request.get("context", "attacker")
            context = self.get_context(context_name)

            if not context:
                results.append((False, None))
                continue

            headers = context.get_auth_headers()
            headers.update(request.get("headers", {}))

            response = await self.client.request(
                request.get("method", "GET"),
                request.get("path", "/"),
                headers=headers,
                cookies=context.get_cookies(),
                json=request.get("json"),
            )

            results.append((response.status_code == 200, response))

        return results


async def create_idor_scanner(
    base_url: str,
    attacker_creds: Tuple[str, str],
    victim_creds: Tuple[str, str],
) -> SessionManager:
    """Factory function to create a configured IDOR scanner.

    Args:
        base_url: Base URL of target application
        attacker_creds: Tuple of (email, password) for attacker
        victim_creds: Tuple of (email, password) for victim

    Returns:
        Configured SessionManager with both contexts
    """
    manager = SessionManager(base_url)
    await manager.create_dual_contexts(
        attacker_email=attacker_creds[0],
        attacker_password=attacker_creds[1],
        victim_email=victim_creds[0],
        victim_password=victim_creds[1],
    )
    return manager
