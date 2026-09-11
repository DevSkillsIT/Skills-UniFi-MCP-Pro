"""Event log and alarm operations on the UniFi Network controller.

Every method takes an explicit `site` and never mutates connection state.

The paths in here are not served by every controller build: UniFi Network
10.5.67 answers 404 for `/stat/event` and `/stat/alarm` on every site. A 404 is
reported as `EndpointNotServedError` rather than folded into an empty list,
because "this controller has no event API" and "this site had no events" are
different answers and a caller that cannot tell them apart will report silence
as calm.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aiounifi.errors import ResponseError

from src.exceptions import UnifiMCPError

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

# The controller refuses a larger page outright.
MAX_EVENT_ROWS = 3000


class EndpointNotServedError(UnifiMCPError):
    """The controller answered 404 for a path the operation depends on.

    Carries the method, path and site so the caller can name the missing
    capability instead of inferring it from an empty result.
    """

    def __init__(self, method: str, path: str, site: str, original_error: str = ""):
        super().__init__(
            error_code="ENDPOINT_NOT_SERVED",
            message=(
                f"This controller does not serve {method.upper()} {path} (HTTP 404). "
                "The result is unknown, not empty."
            ),
            http_status=501,
            details={
                "method": method.upper(),
                "path": path,
                "site": site,
                "controller_status": 404,
                "original_error": original_error,
            },
        )

    @staticmethod
    def matches(error: Exception) -> bool:
        """True when aiounifi reported HTTP 404 for the requested path.

        aiounifi collapses the HTTP status into the exception text, so the
        status is only recoverable as a string. The literal it formats is
        "Call <url> received 404 Not Found"; matching the whole phrase keeps a
        URL that merely contains "404" from being read as a missing endpoint,
        and keeps the 429 that shares this exception type out.
        """
        return isinstance(error, ResponseError) and "received 404" in str(error)


class EventManager(SiteScopedManager):
    """Manages event log and alarm operations on the UniFi Controller."""

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def _rows(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]],
        site: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Read a list endpoint, keeping "unavailable" apart from "empty"."""
        target = self._target_site(site)
        try:
            return await self._list(method, path, data, site=site)
        except Exception as e:
            if EndpointNotServedError.matches(e):
                logger.error(f"{method.upper()} {path} not served by this controller (site={target})")
                raise EndpointNotServedError(method, path, target, str(e)) from e
            logger.error(f"Error reading {path} (site={target}): {e}", exc_info=True)
            return []

    async def get_events(
        self,
        within: int = 24,
        limit: int = 100,
        start: int = 0,
        event_type: Optional[str] = None,
        site: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get events from the controller via POST `/stat/event`.

        Args:
            within: Hours to look back.
            limit: Maximum number of events to return, capped at MAX_EVENT_ROWS.
            start: Offset for pagination.
            event_type: Filter for an event type prefix (e.g. 'EVT_SW_').
            site: Site slug or whitelisted display name.

        Raises:
            EndpointNotServedError: The controller does not serve `/stat/event`.
        """
        # Events are time-sensitive, so the cache is deliberately bypassed.
        payload: Dict[str, Any] = {
            "within": within,
            "_limit": min(limit, MAX_EVENT_ROWS),
            "_start": start,
        }
        if event_type:
            payload["type"] = event_type
        return await self._rows("post", "/stat/event", payload, site)

    async def get_alarms(
        self,
        archived: bool = False,
        limit: int = 100,
        site: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get alarms from the controller via GET `/stat/alarm`.

        Args:
            archived: Include alarms already archived.
            limit: Maximum number of alarms to return.
            site: Site slug or whitelisted display name.

        Raises:
            EndpointNotServedError: The controller does not serve `/stat/alarm`.
        """
        path = "/stat/alarm?archived=true" if archived else "/stat/alarm"
        alarms = await self._rows("get", path, None, site)
        return alarms[:limit]

    def get_event_type_prefixes(self) -> List[Dict[str, str]]:
        """Get the known event type prefixes usable as an event filter."""
        return [
            {"prefix": "EVT_SW_", "description": "Switch events"},
            {"prefix": "EVT_AP_", "description": "Access Point events"},
            {"prefix": "EVT_GW_", "description": "Gateway events"},
            {"prefix": "EVT_LAN_", "description": "LAN events"},
            {
                "prefix": "EVT_WU_",
                "description": "WLAN User events (connect/disconnect)",
            },
            {"prefix": "EVT_WG_", "description": "WLAN Guest events"},
            {"prefix": "EVT_IPS_", "description": "IPS/IDS security events"},
            {"prefix": "EVT_AD_", "description": "Admin events"},
            {"prefix": "EVT_DPI_", "description": "Deep Packet Inspection events"},
        ]

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def _evtmgr(self, payload: Dict[str, Any], site: Optional[str], action: str, subject: str) -> bool:
        """Send a `/cmd/evtmgr` command and report whether it was accepted.

        A refusal by the controller (`rc: "error"`) is a False with the
        controller's own message in the log; a 404 on the command path is a
        different class of failure and is raised, since no amount of retrying
        will make a missing endpoint accept the command.
        """
        target = self._target_site(site)
        try:
            response = await self._request("post", "/cmd/evtmgr", payload, site=site, return_raw=True)
        except Exception as e:
            if EndpointNotServedError.matches(e):
                logger.error(f"POST /cmd/evtmgr not served by this controller (site={target})")
                raise EndpointNotServedError("post", "/cmd/evtmgr", target, str(e)) from e
            logger.error(f"Error on {action} for {subject} (site={target}): {e}")
            return False

        if not self._succeeded(response):
            message = (response or {}).get("meta", {}).get("msg", "unknown error")
            logger.error(f"{action} refused for {subject} on {target}: {message}")
            return False
        logger.info(f"{action} accepted for {subject} on {target}")
        return True

    async def archive_alarm(self, alarm_id: str, site: Optional[str] = None) -> bool:
        """Archive one alarm, marking it resolved."""
        return await self._evtmgr({"cmd": "archive-alarm", "_id": alarm_id}, site, "archive-alarm", alarm_id)

    async def archive_all_alarms(self, site: Optional[str] = None) -> bool:
        """Archive every active alarm on the site."""
        return await self._evtmgr(
            {"cmd": "archive-all-alarms"}, site, "archive-all-alarms", "all active alarms"
        )
