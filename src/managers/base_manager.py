"""Shared site-scoping base for every UniFi manager.

Before this existed each manager hand-rolled the same dance:

    original_site = self._connection.site
    if target_site != original_site:
        await self._connection.set_site(target_site)
    ...
    finally:
        if target_site != self._connection.site:   # never true after set_site
            await self._connection.set_site(original_site)

That dance was wrong in three separate ways: the restore condition compared the
target against the *already-swapped* current site (so the site leaked into the
next call), `original_site` was bound inside the `try` in some managers (so a
failure before it raised NameError in `finally`), and nothing serialised the
swap against concurrent calls.

The site is now passed down to `ConnectionManager.request()`, which swaps and
restores under a lock. Managers never mutate connection state.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.api import ApiRequest, ApiRequestV2

from ..exceptions import ControllerRefusedError
from .connection_manager import ConnectionManager

logger = logging.getLogger("unifi-network-mcp")


class SiteScopedManager:
    """Base class giving every manager uniform, leak-free site handling."""

    def __init__(self, connection_manager: ConnectionManager):
        self._connection = connection_manager
        self._cache_locks: Dict[str, asyncio.Lock] = {}

    # --- site helpers -----------------------------------------------------

    def _target_site(self, site: Optional[str]) -> str:
        """Resolve `site` (slug or whitelisted display name) to the API slug."""
        return self._connection.resolve_slug(site) or self._connection.site

    def _lock_for(self, cache_key: str) -> asyncio.Lock:
        return self._cache_locks.setdefault(cache_key, asyncio.Lock())

    # --- request helpers --------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        site: Optional[str] = None,
        return_raw: bool = False,
    ) -> Any:
        """Issue a V1 API request scoped to `site`."""
        api_request = ApiRequest(method=method, path=path, data=data) if data is not None else ApiRequest(method=method, path=path)
        return await self._connection.request(api_request, return_raw=return_raw, site=self._target_site(site))

    async def _request_v2(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        site: Optional[str] = None,
        return_raw: bool = False,
    ) -> Any:
        """Issue a V2 API request scoped to `site`."""
        api_request = ApiRequestV2(method=method, path=path, data=data) if data is not None else ApiRequestV2(method=method, path=path)
        return await self._connection.request(api_request, return_raw=return_raw, site=self._target_site(site))

    async def _list(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        site: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Request an endpoint that returns a list, normalising the shapes.

        The controller answers some endpoints with a bare dict instead of a
        single-element list; a few answer with neither. Callers that expect a
        list should never have to care.
        """
        response = await self._request(method, path, data, site=site)
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return [response]
        return []

    async def _one(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        site: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Request an endpoint that logically returns a single object.

        UniFi wraps single objects in a one-element list on most `/stat/*` and
        `/rest/*` paths -- the reason `unifi_get_system_info` used to answer
        `{"success": true, "system_info": {}}`: `/stat/sysinfo` returns
        `list[1]` and the old code only accepted a dict.
        """
        response = await self._request(method, path, data, site=site)
        if isinstance(response, list):
            return response[0] if response else None
        if isinstance(response, dict):
            return response
        return None

    @staticmethod
    def _succeeded(response: Any) -> bool:
        """Interpret a command/update response as success or failure.

        A V1 write answers `{"meta": {"rc": "ok"}, "data": [...]}` when it worked
        and `rc: "error"` with a `msg` when it did not.

        This is a second line of defence, not the primary check, and on the V2
        API it cannot be anything else: `ApiRequestV2.decode` SYNTHESISES
        `meta={"rc": "ok", "msg": ""}` for every body it can parse, raising only
        when the payload carries `errorCode`. So on a V2 endpoint this reads an
        envelope the client library invented, never the controller's verdict,
        and can only answer True. V1 is the mirror image: `ApiRequest.decode`
        raises on `meta.rc == "error"`, so a falsy envelope rarely arrives here
        either.

        On both versions the exception is the real refusal signal, which
        `ConnectionManager.request()` turns into `ControllerRefusedError`
        carrying the controller's own reason. Never read a True from here as
        proof that a write landed: confirm a create by the object the controller
        echoes back, and an update by reading the value again.
        """
        if isinstance(response, dict):
            meta = response.get("meta")
            if isinstance(meta, dict):
                return meta.get("rc") == "ok"
            return True
        if isinstance(response, list):
            return True
        return response is not None

    def _require_ok(self, response: Any, action: str, site: Optional[str] = None) -> Any:
        """Return the response, or raise with the controller's own reason.

        Every write goes through here so a refusal reaches the caller intact.
        A generic "Failed to ..." hides the single fact that would let the
        caller fix the request.
        """
        if self._succeeded(response):
            return response
        meta = (response or {}).get("meta") if isinstance(response, dict) else None
        controller_message = (meta or {}).get("msg") or "no reason given"
        raise ControllerRefusedError(action, controller_message, site=self._target_site(site))
