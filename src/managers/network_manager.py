"""Network (LAN/VLAN) and WLAN operations on the UniFi Network controller.

Two problems beyond the site plumbing are addressed here.

`toggle_wlan` read `wlan.enabled` off the value returned by
`get_wlan_details`, which is a plain dict -- an `AttributeError` on every call.

Every write returned True whenever no exception was raised, so a configuration
the controller refused was reported to the caller as applied. Writes now read
the response envelope and report the controller's own message on refusal.

Cache invalidation is keyed on the site the write targeted, not on whichever
site the shared connection happened to be pointing at.
"""

import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.wlan import Wlan

from ..exceptions import ControllerRefusedError
from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_NETWORKS = "networks"
CACHE_PREFIX_WLANS = "wlans"


class NetworkManager(SiteScopedManager):
    """Manages network (LAN/VLAN) and WLAN operations on the Unifi Controller."""

    # ------------------------------------------------------------------
    # Networks
    # ------------------------------------------------------------------

    async def get_networks(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List networks (LAN/VLAN) configured on the target site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_NETWORKS}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                networks = [n for n in await self._list("get", "/rest/networkconf", site=site) if isinstance(n, dict)]
                self._connection._update_cache(cache_key, networks)
                return networks
            except Exception as e:
                logger.error(f"Error getting networks (site={target}): {e}", exc_info=True)
                return []

    async def get_network_details(self, network_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find one network by id on the target site."""
        networks = await self.get_networks(site=site)
        network = next((n for n in networks if n.get("_id") == network_id), None)
        if not network:
            logger.warning(f"Network {network_id} not found on site {self._target_site(site)}.")
        return network

    async def create_network(self, network_data: Dict[str, Any], site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Create a network on the target site."""
        target = self._target_site(site)
        for field in ("name", "purpose"):
            if field not in network_data:
                logger.error(f"Missing required field '{field}' for network creation")
                return None
        try:
            response = await self._request("post", "/rest/networkconf", network_data, site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_NETWORKS}_{target}")

            self._require_ok(response, f"create network '{network_data.get('name')}'", site)

            data = (response or {}).get("data")
            if isinstance(data, list) and data and isinstance(data[0], dict):
                logger.info(f"Network '{network_data.get('name')}' created on site {target}")
                return data[0]
            logger.warning(f"Network creation accepted but returned no object: {data}")
            return None
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error creating network on site {target}: {e}")
            return None

    async def update_network(self, network_id: str, update_data: Dict[str, Any], site: Optional[str] = None) -> bool:
        """Update a network by merging the changes onto its current definition.

        The controller replaces the whole object on PUT, so the current
        definition is fetched and merged; sending only the changed keys would
        clear everything else.
        """
        target = self._target_site(site)
        if not update_data:
            logger.warning(f"No update data provided for network {network_id}.")
            return True

        try:
            existing = await self.get_network_details(network_id, site=site)
            if not existing:
                logger.error(f"Network {network_id} not found for update on site {target}.")
                return False

            merged = {**existing, **update_data}
            response = await self._request(
                "put", f"/rest/networkconf/{network_id}", merged, site=site, return_raw=True
            )
            self._connection._invalidate_cache(f"{CACHE_PREFIX_NETWORKS}_{target}")

            self._require_ok(response, f"update network {network_id}", site)
            logger.info(f"Network {network_id} updated on site {target}.")
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error updating network {network_id}: {e}", exc_info=True)
            return False

    async def delete_network(self, network_id: str, site: Optional[str] = None) -> bool:
        """Delete a network from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request(
                "delete", f"/rest/networkconf/{network_id}", site=site, return_raw=True
            )
            self._connection._invalidate_cache(f"{CACHE_PREFIX_NETWORKS}_{target}")
            self._require_ok(response, f"delete network {network_id}", site)
            logger.info(f"Network {network_id} deleted from site {target}.")
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error deleting network {network_id}: {e}")
            return False

    # ------------------------------------------------------------------
    # WLANs
    # ------------------------------------------------------------------

    async def get_wlans(self, site: Optional[str] = None) -> List[Wlan]:
        """List wireless networks configured on the target site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_WLANS}_{target}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Wlan]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                raw = await self._list("get", "/rest/wlanconf", site=site)
                wlans = [Wlan(w) for w in raw if isinstance(w, dict)]
                self._connection._update_cache(cache_key, wlans)
                return wlans
            except Exception as e:
                logger.error(f"Error getting WLANs (site={target}): {e}")
                return []

    async def get_wlan_details(self, wlan_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find one WLAN by id on the target site, as a plain dict."""
        wlans = await self.get_wlans(site=site)
        wlan = next((w for w in wlans if w.id == wlan_id), None)
        if not wlan:
            logger.warning(f"WLAN {wlan_id} not found on site {self._target_site(site)}.")
            return None
        return wlan.raw if hasattr(wlan, "raw") else None

    async def get_ap_groups(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """AP groups defined on the site.

        Served by the V2 API (`/v2/api/site/<site>/apgroups`); the V1 path
        `/rest/apgroup` answers HTTP 400 on current controllers.
        """
        try:
            response = await self._request_v2("get", "/apgroups", site=site)
            if isinstance(response, list):
                return [g for g in response if isinstance(g, dict)]
            if isinstance(response, dict):
                return [response]
            return []
        except Exception as e:
            logger.error(f"Error getting AP groups (site={self._target_site(site)}): {e}")
            return []

    async def create_wlan(self, wlan_data: Dict[str, Any], site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Create a wireless network on the target site."""
        target = self._target_site(site)
        for field in ("name", "security", "enabled"):
            if field not in wlan_data:
                logger.error(f"Missing required field '{field}' for WLAN creation")
                return None
        if wlan_data.get("security") != "open" and "x_passphrase" not in wlan_data:
            logger.error(f"Security '{wlan_data.get('security')}' requires 'x_passphrase'")
            return None

        payload = dict(wlan_data)
        # The controller refuses a WLAN with no AP group (api.err.ApGroupMissing).
        # Defaulting to the site's own groups keeps the caller from having to know
        # an id that the tool can look up itself.
        if not payload.get("ap_group_ids"):
            groups = await self.get_ap_groups(site=site)
            if groups:
                payload["ap_group_ids"] = [g["_id"] for g in groups if g.get("_id")]
            else:
                logger.warning(f"No AP group found on site {target}; the controller will refuse the WLAN.")

        try:
            response = await self._request("post", "/rest/wlanconf", payload, site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_WLANS}_{target}")
            self._require_ok(response, f"create WLAN '{payload.get('name')}'", site)

            data = (response or {}).get("data")
            if isinstance(data, list) and data and isinstance(data[0], dict):
                logger.info(f"WLAN '{payload.get('name')}' created on site {target}")
                return data[0]
            logger.warning(f"WLAN creation accepted but returned no object: {data}")
            return None
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error creating WLAN on site {target}: {e}")
            return None

    async def update_wlan(self, wlan_id: str, update_data: Dict[str, Any], site: Optional[str] = None) -> bool:
        """Update a WLAN by merging the changes onto its current definition."""
        target = self._target_site(site)
        if not update_data:
            logger.warning(f"No update data provided for WLAN {wlan_id}.")
            return True

        try:
            existing = await self.get_wlan_details(wlan_id, site=site)
            if not existing:
                logger.error(f"WLAN {wlan_id} not found for update on site {target}.")
                return False

            merged = {**existing, **update_data}
            response = await self._request("put", f"/rest/wlanconf/{wlan_id}", merged, site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_WLANS}_{target}")

            self._require_ok(response, f"update WLAN {wlan_id}", site)
            logger.info(f"WLAN {wlan_id} updated on site {target}.")
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error updating WLAN {wlan_id}: {e}", exc_info=True)
            return False

    async def delete_wlan(self, wlan_id: str, site: Optional[str] = None) -> bool:
        """Delete a wireless network from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request("delete", f"/rest/wlanconf/{wlan_id}", site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_WLANS}_{target}")
            self._require_ok(response, f"delete WLAN {wlan_id}", site)
            logger.info(f"WLAN {wlan_id} deleted from site {target}.")
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error deleting WLAN {wlan_id}: {e}")
            return False

    async def toggle_wlan(self, wlan_id: str, site: Optional[str] = None) -> bool:
        """Flip a WLAN between enabled and disabled on the target site."""
        try:
            wlan = await self.get_wlan_details(wlan_id, site=site)
            if not wlan:
                logger.error(f"Cannot toggle WLAN {wlan_id}: not found on site {self._target_site(site)}.")
                return False
            new_state = not wlan.get("enabled", False)
            return await self.update_wlan(wlan_id, {"enabled": new_state}, site=site)
        except Exception as e:
            logger.error(f"Error toggling WLAN {wlan_id}: {e}")
            return False
