"""Traffic route operations on the UniFi Network controller.

Traffic routes are policy-based routing rules that send traffic matching a
domain, IP address, region or device through a specific network such as a VPN.

This manager owns the whole `/trafficroutes` surface -- list, details, create,
update, toggle, delete and the kill switch -- and it is the only one that does.
Two managers caching the same site under the same key while building different
types out of it (model objects on one side, plain dicts on the other) hand
whichever caller arrives second a value it cannot read.

Every method takes an explicit `site` and passes it down to the request layer,
which swaps and restores the controller site under a lock. This manager never
mutates connection state.
"""

import logging
from typing import Any, Dict, List, Optional

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_TRAFFIC_ROUTES = "traffic_routes"


class TrafficRouteManager(SiteScopedManager):
    """Manages traffic route operations on the UniFi Controller."""

    # --- V2 response shapes -----------------------------------------------

    @staticmethod
    def _as_list(response: Any) -> List[Dict[str, Any]]:
        """Normalise a V2 read into a list of objects.

        V2 endpoints answer with a bare list on some controller versions and
        with a `{"meta", "data"}` envelope on others; callers should not have
        to branch on which controller they happen to be talking to.
        """
        if isinstance(response, list):
            return [r for r in response if isinstance(r, dict)]
        if isinstance(response, dict):
            data = response.get("data")
            if isinstance(data, list):
                return [r for r in data if isinstance(r, dict)]
            if isinstance(data, dict):
                return [data]
            if response.get("_id"):
                return [response]
        return []

    @staticmethod
    def _first_object(response: Any) -> Optional[Dict[str, Any]]:
        """Pull the single created object out of a V2 write response."""
        objects = TrafficRouteManager._as_list(response)
        return objects[0] if objects else None

    @staticmethod
    def _refusal(response: Any) -> str:
        """Read the controller's refusal message out of a write response.

        Indexing `meta` blindly is unsafe here: a V2 endpoint may answer with a
        bare list, which has no `get`.
        """
        if isinstance(response, dict):
            meta = response.get("meta")
            if isinstance(meta, dict) and meta.get("msg"):
                return str(meta["msg"])
        return "unknown error"

    def _cache_key(self, site: Optional[str]) -> str:
        """Cache key for the resolved target site.

        The site belongs in the key: a list cached for one site must never be
        served to a caller asking about another.
        """
        return f"{CACHE_PREFIX_TRAFFIC_ROUTES}_{self._target_site(site)}"

    # --- Reads ------------------------------------------------------------

    async def get_traffic_routes(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List every traffic route on the target site.

        Args:
            site: Site slug or whitelisted display name.

        Returns:
            List of traffic route objects as plain dictionaries.
        """
        target = self._target_site(site)
        cache_key = self._cache_key(site)
        async with self._lock_for(cache_key):
            cached: Optional[List[Dict[str, Any]]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._request_v2("get", "/trafficroutes", site=site, return_raw=True)
                routes = self._as_list(response)
                self._connection._update_cache(cache_key, routes)
                return routes
            except Exception as e:
                logger.error(f"Error getting traffic routes (site={target}): {e}", exc_info=True)
                return []

    async def get_traffic_route_details(self, route_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find one traffic route by its `_id` on the target site."""
        try:
            routes = await self.get_traffic_routes(site=site)
            route = next((r for r in routes if r.get("_id") == route_id), None)
            if not route:
                logger.debug(f"Traffic route {route_id} not found on site {self._target_site(site)}.")
            return route
        except Exception as e:
            logger.error(f"Error getting traffic route details for {route_id}: {e}", exc_info=True)
            return None

    # --- Writes -----------------------------------------------------------

    async def create_traffic_route(
        self, route_data: Dict[str, Any], site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a traffic route on the target site.

        Args:
            route_data: Route configuration. `name` and `interface` are required;
                the remaining keys depend on the route type (domain_names,
                ip_addresses, network_ids, enabled, description).
            site: Site slug or whitelisted display name.

        Returns:
            The created route object, carrying its `_id`, or None on failure.
        """
        if not route_data.get("name") or not route_data.get("interface"):
            logger.error("Missing required keys for creating traffic route (name, interface)")
            return None

        target = self._target_site(site)
        try:
            response = await self._request_v2("post", "/trafficroutes", route_data, site=site, return_raw=True)
            if not self._succeeded(response):
                logger.error(
                    f"Traffic route creation refused on {target}: {self._refusal(response)}"
                )
                return None

            created = self._first_object(response)
            if not created or not created.get("_id"):
                logger.error(
                    f"Traffic route creation on {target} returned no identifiable object: {response}"
                )
                return None

            logger.info(f"Created traffic route '{route_data['name']}' ({created['_id']}) on {target}")
            self._connection._invalidate_cache(self._cache_key(site))
            return created
        except Exception as e:
            logger.error(f"Error creating traffic route on {target}: {e}", exc_info=True)
            return None

    async def update_traffic_route(
        self,
        route_id: str,
        updates: Optional[Dict[str, Any]] = None,
        site: Optional[str] = None,
        **field_updates: Any,
    ) -> bool:
        """Update a traffic route, sending the full merged object.

        The V2 endpoint replaces the stored route with the body it is given, so
        the current route is fetched and the changes are merged onto it; sending
        only the changed keys would blank every field left out.

        Args:
            route_id: The `_id` of the route to update.
            updates: Fields to change, as a dictionary.
            site: Site slug or whitelisted display name.
            **field_updates: Fields to change passed individually (`enabled=`,
                `kill_switch=`). A value of None means "leave this field alone",
                which is why None is skipped rather than written.
        """
        merged: Dict[str, Any] = dict(updates or {})
        merged.update({k: v for k, v in field_updates.items() if v is not None})
        if not merged:
            logger.warning(f"No updates provided for traffic route {route_id}.")
            return False

        target = self._target_site(site)
        try:
            current = await self.get_traffic_route_details(route_id, site=site)
            if not current:
                logger.error(f"Traffic route {route_id} not found on {target} for update.")
                return False

            payload: Dict[str, Any] = current.copy()
            payload.update(merged)

            response = await self._request_v2(
                "put", f"/trafficroutes/{route_id}", payload, site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(
                    f"Update refused for traffic route {route_id} on {target}: {self._refusal(response)}"
                )
                return False

            logger.info(f"Updated traffic route {route_id} on {target}: {sorted(merged)}")
            self._connection._invalidate_cache(self._cache_key(site))
            return True
        except Exception as e:
            logger.error(f"Error updating traffic route {route_id}: {e}", exc_info=True)
            return False

    async def toggle_traffic_route(self, route_id: str, site: Optional[str] = None) -> bool:
        """Flip a traffic route's enabled state."""
        current = await self.get_traffic_route_details(route_id, site=site)
        if not current:
            logger.error(f"Traffic route {route_id} not found on {self._target_site(site)} for toggle.")
            return False

        new_state = not current.get("enabled", True)
        return await self.update_traffic_route(route_id, {"enabled": new_state}, site=site)

    async def update_kill_switch(self, route_id: str, enabled: bool, site: Optional[str] = None) -> bool:
        """Set the kill switch for a traffic route.

        The kill switch blocks all traffic matching the route when the route's
        target network (a VPN, typically) becomes unavailable.
        """
        return await self.update_traffic_route(route_id, {"kill_switch": enabled}, site=site)

    async def delete_traffic_route(self, route_id: str, site: Optional[str] = None) -> bool:
        """Delete a traffic route by ID from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request_v2(
                "delete", f"/trafficroutes/{route_id}", site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(
                    f"Delete refused for traffic route {route_id} on {target}: {self._refusal(response)}"
                )
                return False

            logger.info(f"Deleted traffic route {route_id} on {target}")
            self._connection._invalidate_cache(self._cache_key(site))
            return True
        except Exception as e:
            logger.error(f"Error deleting traffic route {route_id}: {e}", exc_info=True)
            return False
