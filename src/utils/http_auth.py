"""Bearer authentication for the Streamable HTTP endpoint.

The endpoint binds 0.0.0.0 and exposes tools that reboot access points, change
radio channels, block clients and rewrite networks, using an account that is a
controller super admin. `UNIFI_MCP_BEARER_TOKEN` existed in the environment for
exactly this and was never read, so anything that could reach the port could
drive the controller.

Enforcement follows the token: set the variable and every request must carry it;
leave it unset and the endpoint is open, which is stated loudly at startup
rather than left to be discovered. A defence that has to be switched on
separately is a defence that stays off.
"""

import hmac
import logging
import os
from typing import Optional

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("unifi-network-mcp")

# Probes and health checks must not need a credential, or a load balancer cannot
# tell a locked door from a dead process.
UNAUTHENTICATED_PATHS = frozenset({"/health"})


def configured_token() -> Optional[str]:
    """The expected bearer token, or None when authentication is not configured."""
    token = os.getenv("UNIFI_MCP_BEARER_TOKEN", "").strip()
    return token or None


class BearerTokenMiddleware:
    """Reject any request that does not present the configured bearer token."""

    def __init__(self, app: ASGIApp, token: str):
        self.app = app
        self._token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        if request.url.path in UNAUTHENTICATED_PATHS:
            await self.app(scope, receive, send)
            return

        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")

        # Compared with compare_digest so a wrong token cannot be recovered by
        # timing how long the rejection takes.
        if scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip(), self._token):
            logger.warning(
                "Rejected unauthenticated %s %s from %s",
                request.method,
                request.url.path,
                request.client.host if request.client else "unknown",
            )
            response = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": "This endpoint requires a bearer token. Send it as 'Authorization: Bearer <token>'.",
                },
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="unifi-network-mcp"'},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
