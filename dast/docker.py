"""Docker container management for clean-slate testing.

This module provides ephemeral container lifecycle management to ensure
each scan runs against a fresh instance, preventing state pollution
between test runs (a key requirement from report.tex).
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Optional, List

import httpx


@dataclass
class ContainerInfo:
    """Information about a running container."""

    container_id: str
    image: str
    base_url: str
    port: int
    host_port: int


class ContainerManager:
    """Manages Docker container lifecycle for vulnerability scanning.

    Provides:
        - Provisioning fresh containers from images
        - Waiting for container readiness
        - Cleanup with automatic resource removal
    """

    # Default images
    JUICE_SHOP_IMAGE = "bkimminich/juice-shop:latest"
    BWAPP_IMAGE = "raesene/bwapp:latest"
    DVWA_IMAGE = "vulnerables/web-dvwa:latest"
    DEFAULT_PORT = 3000

    def __init__(
        self,
        image: str = JUICE_SHOP_IMAGE,
        port: int = DEFAULT_PORT,
        host_port: Optional[int] = None,
    ):
        """Initialize the container manager.

        Args:
            image: Docker image name
            port: Container internal port
            host_port: Host port to map (default: random available port)
        """
        self.image = image
        self.port = port
        self.host_port = host_port or 0  # 0 = random port
        self._container_ids: List[str] = []

    async def is_docker_available(self) -> bool:
        """Check if Docker is available on the system."""
        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except FileNotFoundError:
            return False

    async def provision(
        self,
        timeout: int = 60,
        env_vars: Optional[dict] = None,
    ) -> ContainerInfo:
        """Provision a fresh container.

        Args:
            timeout: Seconds to wait for container to be ready
            env_vars: Optional environment variables for the container

        Returns:
            ContainerInfo with connection details

        Raises:
            RuntimeError: If Docker is unavailable
            TimeoutError: If container fails to start within timeout
        """
        if not await self.is_docker_available():
            raise RuntimeError("Docker is not available on this system")

        # Pull image if needed
        await self._pull_image()

        # Run container with random port
        container_id = await self._run_container(env_vars)
        self._container_ids.append(container_id)

        # Get the mapped port
        port_info = await self._get_container_port(container_id)
        if not port_info:
            await self.cleanup(container_id)
            raise RuntimeError("Failed to get container port mapping")

        base_url = f"http://localhost:{port_info}"

        # Wait for container to be ready
        if not await self._wait_for_ready(base_url, timeout):
            await self.cleanup(container_id)
            raise TimeoutError(
                f"Container did not become ready within {timeout} seconds"
            )

        return ContainerInfo(
            container_id=container_id,
            image=self.image,
            base_url=base_url,
            port=self.port,
            host_port=port_info,
        )

    async def _pull_image(self) -> None:
        """Pull the Docker image if not present."""
        # Check if image exists locally
        check_process = await asyncio.create_subprocess_exec(
            "docker",
            "images",
            "-q",
            self.image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await check_process.communicate()

        if not stdout.strip():
            # Image not found, pull it
            pull_process = await asyncio.create_subprocess_exec(
                "docker",
                "pull",
                self.image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await pull_process.communicate()

    async def _run_container(self, env_vars: Optional[dict] = None) -> str:
        """Start a new container."""
        cmd = [
            "docker", "run",
            "-d",
            "-p", f"{self.host_port}:{self.port}",
            "--rm",  # Automatically remove on exit
        ]

        # Add environment variables if provided
        if env_vars:
            for key, value in env_vars.items():
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(self.image)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Failed to start container: {error_msg}")

        return stdout.decode().strip()

    async def _get_container_port(self, container_id: str) -> Optional[int]:
        """Get the mapped host port for a container."""
        process = await asyncio.create_subprocess_exec(
            "docker",
            "port",
            container_id,
            str(self.port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()

        if process.returncode == 0:
            # Output format: "0.0.0.0:32768"
            port_info = stdout.decode().strip()
            if ":" in port_info:
                return int(port_info.split(":")[-1])

        return None

    async def _wait_for_ready(self, base_url: str, timeout: int) -> bool:
        """Wait for the container to accept HTTP requests."""
        start_time = asyncio.get_event_loop().time()

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= timeout:
                return False

            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    response = await client.get(f"{base_url}/")
                    if response.status_code == 200:
                        return True
            except Exception:
                pass

            await asyncio.sleep(1)

    async def cleanup(self, container_id: Optional[str] = None) -> None:
        """Stop and remove a container.

        Args:
            container_id: Container ID to clean up. If None, cleans up all.
        """
        if container_id:
            await self._stop_container(container_id)
            if container_id in self._container_ids:
                self._container_ids.remove(container_id)
        else:
            # Clean up all containers
            for cid in self._container_ids.copy():
                await self._stop_container(cid)
            self._container_ids.clear()

    async def _stop_container(self, container_id: str) -> None:
        """Stop a specific container."""
        process = await asyncio.create_subprocess_exec(
            "docker",
            "stop",
            container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    async def cleanup_all(self) -> None:
        """Clean up all containers created by this manager."""
        await self.cleanup()

    def __del__(self):
        """Cleanup on deletion."""
        # Note: This can't be async, so we can't properly clean up here
        # Users should call cleanup() or use the context manager
        pass


@asynccontextmanager
async def ephemeral_container(
    image: str = ContainerManager.JUICE_SHOP_IMAGE,
    port: int = ContainerManager.DEFAULT_PORT,
    timeout: int = 60,
    env_vars: Optional[dict] = None,
) -> AsyncIterator[ContainerInfo]:
    """Context manager for ephemeral container lifecycle.

    Args:
        image: Docker image name
        port: Container internal port
        timeout: Seconds to wait for readiness
        env_vars: Optional environment variables

    Yields:
        ContainerInfo with connection details

    Example:
        async with ephemeral_container() as container:
            # Scan container.base_url
            pass
        # Container automatically cleaned up
    """
    manager = ContainerManager(image=image, port=port)
    container_info = None

    try:
        container_info = await manager.provision(timeout=timeout, env_vars=env_vars)
        yield container_info
    finally:
        if container_info:
            await manager.cleanup(container_info.container_id)
        else:
            await manager.cleanup_all()


async def check_docker_requirement() -> bool:
    """Check if Docker is available for clean-slate testing.

    Returns:
        True if Docker is available, False otherwise
    """
    manager = ContainerManager()
    return await manager.is_docker_available()


def get_skip_container_warning() -> str:
    """Get warning message for when Docker is unavailable."""
    return (
        "Docker is not available. Running without container provisioning.\n"
        "This may result in state pollution between scans.\n"
        "For clean-slate testing, ensure Docker is installed and running."
    )
