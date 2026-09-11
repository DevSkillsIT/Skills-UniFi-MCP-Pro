"""Client operations on the UniFi Network controller.

Every method takes an explicit `site`. Before this, only `get_clients` and
`get_all_clients` did -- so every tool that passed `site=` to `block_client`,
`rename_client`, `authorize_guest`, `set_client_ip_settings` and friends raised
`TypeError` before reaching the controller, and the lookups that did run went
to whatever site the shared connection happened to point at.
"""

import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.client import Client

from ..exceptions import ControllerRefusedError
from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_CLIENTS = "clients"


class ClientManager(SiteScopedManager):
    """Manages client-related operations on the Unifi Controller."""

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_clients(self, active_only: bool = True, site: Optional[str] = None) -> List[Client]:
        """List clients for the target site.

        Args:
            active_only: True lists only clients currently associated
                (`/stat/sta`); False lists every known client including
                offline/historical ones (`/rest/user`). The MCP tool has always
                exposed this switch -- the manager simply never accepted it,
                which is why `unifi_list_clients` was unusable.
            site: Site slug or whitelisted display name.
        """
        if not active_only:
            return await self.get_all_clients(site=site)

        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_CLIENTS}_online_{target}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Client]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                raw = await self._list("get", "/stat/sta", site=site)
                clients = [Client(r) for r in raw]
                self._connection._update_cache(cache_key, clients)
                return clients
            except Exception as e:
                logger.error(f"Error getting online clients (site={target}): {e}")
                return []

    async def get_all_clients(self, site: Optional[str] = None) -> List[Client]:
        """List every known client, including offline/historical ones."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_CLIENTS}_all_{target}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Client]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                raw = await self._list("get", "/rest/user", site=site)
                clients = [Client(r) for r in raw]
                self._connection._update_cache(cache_key, clients)
                return clients
            except Exception as e:
                logger.error(f"Error getting all clients (site={target}): {e}")
                return []

    async def get_client_details(self, client_mac: str, site: Optional[str] = None) -> Optional[Client]:
        """Find one client by MAC, searching online clients then all clients."""
        needle = (client_mac or "").strip().lower()
        if not needle:
            return None
        for getter in (self.get_clients, self.get_all_clients):
            clients = await getter(site=site)
            match = next((c for c in clients if (c.mac or "").lower() == needle), None)
            if match:
                return match
        logger.debug(f"Client {client_mac} not found on site {self._target_site(site)}.")
        return None

    async def get_blocked_clients(self, site: Optional[str] = None) -> List[Client]:
        """List clients currently blocked on the site."""
        all_clients = await self.get_all_clients(site=site)
        return [c for c in all_clients if getattr(c, "blocked", False)]

    async def get_client_by_ip(self, ip_address: str, site: Optional[str] = None) -> Optional[Client]:
        """Find a client by IP, preferring an online match over a stale one."""
        import re

        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address or ""):
            return None

        online = await self.get_clients(site=site)
        match = next((c for c in online if c.ip == ip_address), None)
        if match:
            return match
        all_clients = await self.get_all_clients(site=site)
        return next((c for c in all_clients if c.ip == ip_address), None)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def _stamgr(self, payload: Dict[str, Any], site: Optional[str], action: str, client_mac: str) -> bool:
        """Send a /cmd/stamgr command and report whether it was accepted.

        The response envelope is checked rather than assumed: the previous code
        returned True for any call that did not raise, so a controller refusal
        (`rc: "error"`) was reported to the caller as success.
        """
        try:
            response = await self._request("post", "/cmd/stamgr", payload, site=site, return_raw=True)
            self._require_ok(response, f"{action} client {client_mac}", site)
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error on {action} for client {client_mac}: {e}")
            return False
        logger.info(f"{action} accepted for client {client_mac} on {self._target_site(site)}")
        self._connection._invalidate_cache(CACHE_PREFIX_CLIENTS)
        return True

    async def block_client(self, client_mac: str, site: Optional[str] = None) -> bool:
        """Block a client by MAC address."""
        return await self._stamgr({"mac": client_mac, "cmd": "block-sta"}, site, "block", client_mac)

    async def unblock_client(self, client_mac: str, site: Optional[str] = None) -> bool:
        """Unblock a client by MAC address."""
        return await self._stamgr({"mac": client_mac, "cmd": "unblock-sta"}, site, "unblock", client_mac)

    async def force_reconnect_client(self, client_mac: str, site: Optional[str] = None) -> bool:
        """Force a client to reconnect (kick)."""
        return await self._stamgr({"mac": client_mac, "cmd": "kick-sta"}, site, "kick", client_mac)

    async def authorize_guest(
        self,
        client_mac: str,
        minutes: int,
        up_kbps: Optional[int] = None,
        down_kbps: Optional[int] = None,
        bytes_quota: Optional[int] = None,
        site: Optional[str] = None,
    ) -> bool:
        """Authorize a guest client for a number of minutes."""
        payload: Dict[str, Any] = {"mac": client_mac, "cmd": "authorize-guest", "minutes": minutes}
        if up_kbps is not None:
            payload["up"] = up_kbps
        if down_kbps is not None:
            payload["down"] = down_kbps
        if bytes_quota is not None:
            payload["bytes"] = bytes_quota
        return await self._stamgr(payload, site, "authorize-guest", client_mac)

    async def unauthorize_guest(self, client_mac: str, site: Optional[str] = None) -> bool:
        """Revoke a guest authorization."""
        return await self._stamgr({"mac": client_mac, "cmd": "unauthorize-guest"}, site, "unauthorize-guest", client_mac)

    async def rename_client(self, client_mac: str, name: str, site: Optional[str] = None) -> bool:
        """Rename a client device."""
        try:
            client = await self.get_client_details(client_mac, site=site)
            if not client or "_id" not in client.raw:
                logger.error(f"Cannot rename client {client_mac}: not found on site {self._target_site(site)}.")
                return False
            client_id = client.raw["_id"]

            response = await self._request(
                "put", f"/rest/user/{client_id}", {"name": name, "noted": True}, site=site, return_raw=True
            )
            self._require_ok(response, f"rename client {client_mac}", site)
            logger.info(f"Client {client_mac} renamed to '{name}' on {self._target_site(site)}")
            self._connection._invalidate_cache(CACHE_PREFIX_CLIENTS)
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error renaming client {client_mac} to '{name}': {e}")
            return False

    async def set_client_ip_settings(
        self,
        client_mac: str,
        use_fixedip: Optional[bool] = None,
        fixed_ip: Optional[str] = None,
        local_dns_record_enabled: Optional[bool] = None,
        local_dns_record: Optional[str] = None,
        site: Optional[str] = None,
    ) -> bool:
        """Set a fixed IP and/or a local DNS record for a client.

        Local DNS records require UniFi Network 7.2+.
        """
        try:
            client = await self.get_client_details(client_mac, site=site)
            if not client:
                logger.error(f"Cannot set IP settings for {client_mac}: not found on site {self._target_site(site)}")
                return False

            client_raw = client.raw if hasattr(client, "raw") else client
            client_id = client_raw.get("_id")
            if not client_id:
                logger.error(f"Cannot set IP settings for {client_mac}: missing _id")
                return False

            # A client the controller does not "note" cannot hold IP configuration.
            if not client_raw.get("noted"):
                note_payload: Dict[str, Any] = {"noted": True}
                if not client_raw.get("name") and client_raw.get("hostname"):
                    note_payload["name"] = client_raw["hostname"]
                try:
                    await self._request("put", f"/rest/user/{client_id}", note_payload, site=site)
                except Exception as note_err:
                    logger.warning(f"Could not mark client {client_mac} as known: {note_err}")

            payload: Dict[str, Any] = {}
            if use_fixedip is not None:
                payload["use_fixedip"] = use_fixedip
                if use_fixedip and fixed_ip:
                    payload["fixed_ip"] = fixed_ip
                elif not use_fixedip:
                    payload["fixed_ip"] = ""
            elif fixed_ip is not None:
                payload["use_fixedip"] = True
                payload["fixed_ip"] = fixed_ip

            if local_dns_record_enabled is not None:
                payload["local_dns_record_enabled"] = local_dns_record_enabled
                if local_dns_record_enabled and local_dns_record:
                    payload["local_dns_record"] = local_dns_record
                elif not local_dns_record_enabled:
                    payload["local_dns_record"] = ""
            elif local_dns_record is not None:
                payload["local_dns_record_enabled"] = True
                payload["local_dns_record"] = local_dns_record

            if not payload:
                logger.warning(f"No IP settings provided for {client_mac}")
                return False

            response = await self._request(
                "put", f"/rest/user/{client_id}", payload, site=site, return_raw=True
            )
            self._require_ok(response, f"set IP settings for client {client_mac}", site)
            logger.info(f"IP settings updated for client {client_mac} on {self._target_site(site)}: {payload}")
            self._connection._invalidate_cache(CACHE_PREFIX_CLIENTS)
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error setting IP settings for {client_mac}: {e}")
            return False
