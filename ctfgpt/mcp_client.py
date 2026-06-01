"""Thin HTTP client for the official mcp-kali-server.

The Kali VM runs ``kali-server-mcp --ip 127.0.0.1 --port 5000``.
Windows connects via SSH tunnel: ``ssh -L 5000:localhost:5000 kali@KALI_IP``.

This module provides a minimal wrapper — no tool registration,
no middleware, just HTTP calls to the official server.
"""

from __future__ import annotations

from typing import Optional

import httpx
from rich.console import Console

console = Console()


class KaliMCPClient:
    """HTTP client for the mcp-kali-server."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5000,
        timeout: int = 30,
    ) -> None:
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)

    # -- connection check ---------------------------------------------------

    def check_connection(self) -> bool:
        """GET /health — verify server is reachable."""
        try:
            r = self._client.get("/health")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    # -- command execution --------------------------------------------------

    def execute(self, command: str, timeout: Optional[int] = None) -> dict:
        """POST /execute — run a command on Kali.

        Returns
        -------
        dict
            Keys: ``output`` (str), ``error`` (str), ``returncode`` (int).
            On failure returns ``output=''``, ``error=str(exc)``,
            ``returncode=-1``.
        """
        try:
            r = self._client.post(
                "/execute",
                json={"command": command},
                timeout=timeout or self.timeout,
            )
            r.raise_for_status()
            return r.json()
        except httpx.TimeoutException as exc:
            return {"output": "", "error": f"Timeout: {exc}", "returncode": -1}
        except httpx.HTTPError as exc:
            return {"output": "", "error": str(exc), "returncode": -1}

    # -- tool listing -------------------------------------------------------

    def list_tools(self) -> list[str]:
        """GET /tools — list available tools on the Kali server."""
        try:
            r = self._client.get("/tools")
            r.raise_for_status()
            data = r.json()
            # Accept both {"tools": [...]} and bare [...]
            if isinstance(data, list):
                return data
            return data.get("tools", [])
        except httpx.HTTPError:
            return []

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> KaliMCPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------

def get_mcp_client() -> KaliMCPClient:
    """Create a :class:`KaliMCPClient` from the project config."""
    from ctfgpt.config import load_config

    cfg = load_config()
    mcp: dict = cfg.get("mcp", {})
    return KaliMCPClient(
        host=mcp.get("host", "localhost"),
        port=mcp.get("port", 5000),
        timeout=mcp.get("timeout", 30),
    )
