import asyncio
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import yaml
from rich.console import Console

console = Console()


class LabConfig:
    """Lab configuration loaded from YAML."""

    def __init__(self, config: Dict[str, Any]):
        self.name = config.get("name", "")
        self.image = config.get("image", "")
        self.port = config.get("port", 3000)
        self.default_username = config.get("default_username", "")
        self.default_password = config.get("default_password", "")
        self.seed_endpoint = config.get("seed_endpoint", "")
        self.seed_payload = config.get("seed_payload", {})
        self.seed_method = config.get("seed_method", "POST")
        self.healthcheck_path = config.get("healthcheck_path", "/")


def load_lab_config(project_root: Path, lab_name: str) -> Optional[LabConfig]:
    """Load lab config from templates/apps/<lab_name>/lab.yaml"""
    lab_path = project_root / "templates" / "apps" / lab_name / "lab.yaml"

    if not lab_path.exists():
        return None

    with open(lab_path) as f:
        config = yaml.safe_load(f)

    return LabConfig(config)


class DockerManager:
    """Manages Docker containers for clean slate testing."""

    def __init__(self, project_root: Optional[Path] = None):
        self.container_id: Optional[str] = None
        self.container_name: Optional[str] = None
        self.project_root = project_root or Path(__file__).parent.parent.parent

    async def start_lab(self, lab_name: str, port: Optional[int] = None) -> dict:
        """Start a fresh container for the specified lab."""
        lab_config = load_lab_config(self.project_root, lab_name)

        if not lab_config:
            return {
                "success": False,
                "error": f"No lab config found for '{lab_name}'. Create lab.yaml in templates/apps/{lab_name}/",
            }

        target_port = port or lab_config.port

        import uuid
        self.container_name = f"dast-{lab_name}-{uuid.uuid4().hex[:8]}"

        console.print(f"[dim]Starting {lab_name} container...[/dim]")

        proc = await asyncio.create_subprocess_exec(
            "docker",
            "run",
            "-d",
            "--name",
            self.container_name,
            "-p",
            f"{target_port}:{lab_config.port}",
            "--rm",
            lab_config.image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            return {"success": False, "error": error_msg}

        self.container_id = stdout.decode().strip()

        console.print(f"[green]Container started: {self.container_id[:12]}[/green]")

        base_url = f"http://localhost:{target_port}"

        if not await self._wait_for_ready(base_url, lab_config.healthcheck_path):
            await self.stop_lab()
            return {"success": False, "error": "Container did not become ready"}

        if lab_config.seed_endpoint:
            if not await self._seed_user(base_url, lab_config):
                await self.stop_lab()
                return {"success": False, "error": "Failed to seed default user"}

            console.print(f"[dim]Default user seeded: {lab_config.default_username}[/dim]")

        return {
            "success": True,
            "container_id": self.container_id,
            "container_name": self.container_name,
            "url": base_url,
            "username": lab_config.default_username,
            "password": lab_config.default_password,
        }

    async def _wait_for_ready(self, base_url: str, path: str = "/", timeout: int = 30) -> bool:
        """Wait for the container to be ready."""
        url = f"{base_url}{path}"
        async with httpx.AsyncClient() as client:
            for _ in range(timeout * 10):
                try:
                    response = await client.get(url, timeout=1.0)
                    if response.status_code == 200:
                        return True
                except Exception:
                    pass
                await asyncio.sleep(0.1)
        return False

    async def _seed_user(self, base_url: str, lab_config: LabConfig) -> bool:
        """Seed the default user in the application."""
        seed_url = f"{base_url}{lab_config.seed_endpoint}"

        await asyncio.sleep(1)

        payload = lab_config.seed_payload.copy()
        payload["email"] = lab_config.default_username
        payload["password"] = lab_config.default_password

        try:
            async with httpx.AsyncClient() as client:
                if lab_config.seed_method.upper() == "POST":
                    response = await client.post(
                        seed_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10.0,
                    )
                else:
                    response = await client.get(
                        seed_url,
                        params=payload,
                        timeout=10.0,
                    )

                if response.status_code not in (200, 201):
                    console.print(f"[dim]Seed response: {response.status_code} {response.text[:100]}[/dim]")
                return response.status_code in (200, 201)
        except Exception as e:
            console.print(f"[dim]Seed error: {e}[/dim]")
            return False

    async def stop_lab(self) -> bool:
        """Stop and remove the running container."""
        if not self.container_name:
            return True

        console.print(f"[dim]Stopping container {self.container_name}...[/dim]")

        proc = await asyncio.create_subprocess_exec(
            "docker",
            "stop",
            self.container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await proc.communicate()

        self.container_id = None
        self.container_name = None
        return True

    async def restart_lab(self) -> dict:
        """Restart the container for a clean slate."""
        if not self.container_name:
            return {"success": False, "error": "No container running"}

        lab_name = self.container_name.split("-")[1]
        await self.stop_lab()
        await asyncio.sleep(1)
        return await self.start_lab(lab_name)


_docker_manager: Optional[DockerManager] = None


def get_docker_manager(project_root: Optional[Path] = None) -> DockerManager:
    global _docker_manager
    if _docker_manager is None or project_root:
        _docker_manager = DockerManager(project_root)
    return _docker_manager
