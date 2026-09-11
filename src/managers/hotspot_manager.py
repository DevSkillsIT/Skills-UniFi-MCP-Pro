"""Hotspot voucher operations on the UniFi Network controller.

Vouchers are the guest-portal credentials: they are created and revoked, never
edited -- the controller exposes no update command for them.

Every method takes an explicit `site` and never mutates connection state.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .base_manager import SiteScopedManager

# One definition for every controller path: a 404 carries the same meaning
# whether it comes from an event, an alarm or a voucher endpoint.
from .event_manager import EndpointNotServedError

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_VOUCHERS = "vouchers"


class HotspotManager(SiteScopedManager):
    """Manages hotspot voucher operations on the UniFi Controller."""

    @staticmethod
    def _body(response: Any) -> Any:
        """Take the payload out of a raw envelope, tolerating a bare body.

        An accepted command with an empty payload answers with a list, never
        with None, so the caller can keep None for "not accepted".
        """
        if isinstance(response, dict) and "meta" in response:
            return response.get("data") or []
        return response

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_vouchers(
        self, create_time: Optional[int] = None, site: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List hotspot vouchers for the target site via GET `/stat/voucher`.

        Args:
            create_time: Keep only the vouchers minted in this batch, as
                identified by the controller's creation timestamp.
            site: Site slug or whitelisted display name.

        Raises:
            EndpointNotServedError: The controller does not serve
                `/stat/voucher`, so "no vouchers" would be a guess.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_VOUCHERS}_{target}"

        async with self._lock_for(cache_key):
            # A create_time filter narrows the list, so it must be served from
            # neither the unfiltered cache entry nor written back into it.
            if create_time is None:
                cached: Optional[List[Dict[str, Any]]] = self._connection.get_cached(cache_key)
                if cached is not None:
                    return cached

            try:
                vouchers = await self._list("get", "/stat/voucher", site=site)
            except Exception as e:
                if EndpointNotServedError.matches(e):
                    logger.error(f"GET /stat/voucher not served by this controller (site={target})")
                    raise EndpointNotServedError("get", "/stat/voucher", target, str(e)) from e
                logger.error(f"Error getting vouchers (site={target}): {e}")
                return []

            if create_time is not None:
                return [v for v in vouchers if v.get("create_time") == create_time]

            self._connection._update_cache(cache_key, vouchers)
            return vouchers

    async def get_voucher_details(
        self, voucher_id: str, site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find one voucher by its `_id` on the target site."""
        all_vouchers = await self.get_vouchers(site=site)
        voucher = next((v for v in all_vouchers if v.get("_id") == voucher_id), None)
        if not voucher:
            logger.debug(f"Voucher {voucher_id} not found on site {self._target_site(site)}.")
        return voucher

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def _hotspot_cmd(
        self, payload: Dict[str, Any], site: Optional[str], action: str, subject: str
    ) -> Optional[Any]:
        """Send a `/cmd/hotspot` command and return its payload, or None.

        None means the controller refused or the call failed; the caller must
        not read it as an accepted command with nothing to show. A 404 on the
        command path is raised instead, since the endpoint itself is absent.
        """
        target = self._target_site(site)
        try:
            response = await self._request("post", "/cmd/hotspot", payload, site=site, return_raw=True)
        except Exception as e:
            if EndpointNotServedError.matches(e):
                logger.error(f"POST /cmd/hotspot not served by this controller (site={target})")
                raise EndpointNotServedError("post", "/cmd/hotspot", target, str(e)) from e
            logger.error(f"Error on {action} for {subject} (site={target}): {e}")
            return None

        if not self._succeeded(response):
            message = (response or {}).get("meta", {}).get("msg", "unknown error")
            logger.error(f"{action} refused for {subject} on {target}: {message}")
            return None

        self._connection._invalidate_cache(f"{CACHE_PREFIX_VOUCHERS}_{target}")
        logger.info(f"{action} accepted for {subject} on {target}")
        return self._body(response)

    async def create_voucher(
        self,
        expire_minutes: int,
        count: int = 1,
        quota: int = 1,
        note: Optional[str] = None,
        up_limit_kbps: Optional[int] = None,
        down_limit_kbps: Optional[int] = None,
        bytes_limit_mb: Optional[int] = None,
        site: Optional[str] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """Create one or more hotspot vouchers via `create-voucher`.

        Args:
            expire_minutes: Minutes the voucher stays valid after activation.
            count: How many vouchers to mint.
            quota: 0 for multi-use, 1 for single-use, n for n-times usable.
            note: Note carried by the voucher and shown when it is printed.
            up_limit_kbps: Upload speed cap.
            down_limit_kbps: Download speed cap.
            bytes_limit_mb: Total data transfer cap.
            site: Site slug or whitelisted display name.

        Returns:
            The vouchers the controller minted, or None if it refused.
        """
        payload: Dict[str, Any] = {
            "cmd": "create-voucher",
            "expire": expire_minutes,
            "n": count,
            "quota": quota,
        }
        if note:
            payload["note"] = note
        if up_limit_kbps is not None:
            payload["up"] = up_limit_kbps
        if down_limit_kbps is not None:
            payload["down"] = down_limit_kbps
        if bytes_limit_mb is not None:
            payload["bytes"] = bytes_limit_mb

        subject = f"{count} voucher(s), {expire_minutes} min, quota={quota}"
        body = await self._hotspot_cmd(payload, site, "create-voucher", subject)
        if body is None:
            return None

        created = body if isinstance(body, list) else [body] if isinstance(body, dict) else []
        # The command answers with the batch's creation timestamp rather than
        # the vouchers themselves, so the codes need a second read to surface.
        create_time = created[0].get("create_time") if created else None
        if create_time:
            return await self.get_vouchers(create_time=create_time, site=site)
        return created or await self.get_vouchers(site=site)

    async def revoke_voucher(self, voucher_id: str, site: Optional[str] = None) -> bool:
        """Revoke a voucher by its `_id` via `delete-voucher`."""
        body = await self._hotspot_cmd(
            {"cmd": "delete-voucher", "_id": voucher_id}, site, "delete-voucher", voucher_id
        )
        return body is not None
