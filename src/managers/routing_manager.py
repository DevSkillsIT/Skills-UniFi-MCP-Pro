"""Static route operations on the UniFi Network controller.

Every public method takes an explicit `site` and passes it down to
`SiteScopedManager._request`, which swaps and restores the controller site
under a lock. The manager never mutates connection state itself.

Writes check the controller's response envelope instead of assuming that "no
exception" means "accepted": a UniFi refusal arrives as `rc: "error"` with a
`msg`, over HTTP 200.
"""

import logging
from typing import Any, Dict, List, Optional

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_ROUTES = "routes"


class RoutingManager(SiteScopedManager):
    """Manages static route operations on the UniFi Controller."""

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_routes(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List user-defined static routes for the target site.

        Args:
            site: Site slug or whitelisted display name.

        Returns:
            List of route objects containing network, nexthop and settings.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_ROUTES}_{target}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Dict[str, Any]]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                routes = await self._list("get", "/rest/routing", site=site)
                self._connection._update_cache(cache_key, routes)
                return routes
            except Exception as e:
                logger.error(f"Error getting routes (site={target}): {e}")
                return []

    async def get_active_routes(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List the device's live routing table, system routes included.

        `/stat/routing` is undocumented and absent on some controller versions,
        so a 404 is downgraded to a debug line and an empty list rather than
        surfaced as a failure.

        Args:
            site: Site slug or whitelisted display name.
        """
        target = self._target_site(site)
        try:
            return await self._list("get", "/stat/routing", site=site)
        except Exception as e:
            if "404" in str(e) or "Not Found" in str(e):
                logger.debug("Active routes endpoint /stat/routing not available on this controller")
            else:
                logger.error(f"Error getting active routes (site={target}): {e}")
            return []

    async def get_route_details(self, route_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find one static route by `_id` on the target site.

        Args:
            route_id: The `_id` of the route.
            site: Site slug or whitelisted display name.

        Returns:
            Route object, or None when no route carries that id.
        """
        try:
            routes = await self.get_routes(site=site)
            route = next((r for r in routes if r.get("_id") == route_id), None)
            if not route:
                logger.debug(f"Route {route_id} not found on site {self._target_site(site)}.")
            return route
        except Exception as e:
            logger.error(f"Error getting route details for {route_id}: {e}")
            return None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def create_route(
        self,
        name: str,
        static_route_network: str,
        static_route_nexthop: str,
        static_route_distance: int = 1,
        enabled: bool = True,
        route_type: str = "nexthop-route",
        site: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a static route via POST /rest/routing.

        Args:
            name: Name/description for the route.
            static_route_network: Destination network in CIDR form.
            static_route_nexthop: Next-hop IP address or interface.
            static_route_distance: Administrative distance.
            enabled: Whether the route starts enabled.
            route_type: Route type accepted by the controller.
            site: Site slug or whitelisted display name.

        Returns:
            The created route object, or None when the controller refused it.
        """
        target = self._target_site(site)
        payload: Dict[str, Any] = {
            "name": name,
            "static-route_network": static_route_network,
            "static-route_nexthop": static_route_nexthop,
            "static-route_distance": static_route_distance,
            "enabled": enabled,
            "type": route_type,
        }
        try:
            response = await self._request("post", "/rest/routing", payload, site=site, return_raw=True)
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Create route '{name}' refused on {target}: {message}")
                return None

            self._connection._invalidate_cache(f"{CACHE_PREFIX_ROUTES}_{target}")
            logger.info(f"Created route '{name}' -> {static_route_network} via {static_route_nexthop} on {target}")
            return self._first_route(response)
        except Exception as e:
            logger.error(f"Error creating route '{name}': {e}")
            return None

    async def update_route(
        self,
        route_id: str,
        name: Optional[str] = None,
        static_route_network: Optional[str] = None,
        static_route_nexthop: Optional[str] = None,
        static_route_distance: Optional[int] = None,
        enabled: Optional[bool] = None,
        site: Optional[str] = None,
    ) -> bool:
        """Update a static route via PUT /rest/routing/{route_id}.

        The controller rejects partial bodies on this endpoint, so the current
        route is fetched and the supplied fields are merged into it.

        Args:
            route_id: The `_id` of the route to update.
            name: Replacement name, when changing it.
            static_route_network: Replacement destination network, when changing it.
            static_route_nexthop: Replacement next-hop, when changing it.
            static_route_distance: Replacement administrative distance, when changing it.
            enabled: Target enabled state, when changing it.
            site: Site slug or whitelisted display name.

        Returns:
            True when the controller accepted the update.
        """
        target = self._target_site(site)
        try:
            current = await self.get_route_details(route_id, site=site)
            if not current:
                logger.error(f"Route {route_id} not found for update on {target}.")
                return False

            payload: Dict[str, Any] = current.copy()
            if name is not None:
                payload["name"] = name
            if static_route_network is not None:
                payload["static-route_network"] = static_route_network
            if static_route_nexthop is not None:
                payload["static-route_nexthop"] = static_route_nexthop
            if static_route_distance is not None:
                payload["static-route_distance"] = static_route_distance
            if enabled is not None:
                payload["enabled"] = enabled

            response = await self._request(
                "put", f"/rest/routing/{route_id}", payload, site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Update refused for route {route_id} on {target}: {message}")
                return False

            self._connection._invalidate_cache(f"{CACHE_PREFIX_ROUTES}_{target}")
            logger.info(f"Updated route {route_id} on {target}")
            return True
        except Exception as e:
            logger.error(f"Error updating route {route_id}: {e}")
            return False

    async def delete_route(self, route_id: str, site: Optional[str] = None) -> bool:
        """Delete a static route via DELETE /rest/routing/{route_id}.

        Args:
            route_id: The `_id` of the route to delete.
            site: Site slug or whitelisted display name.

        Returns:
            True when the controller accepted the deletion.
        """
        target = self._target_site(site)
        try:
            response = await self._request("delete", f"/rest/routing/{route_id}", site=site, return_raw=True)
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Delete refused for route {route_id} on {target}: {message}")
                return False

            self._connection._invalidate_cache(f"{CACHE_PREFIX_ROUTES}_{target}")
            logger.info(f"Deleted route {route_id} on {target}")
            return True
        except Exception as e:
            logger.error(f"Error deleting route {route_id}: {e}")
            return False

    async def enable_route(self, route_id: str, site: Optional[str] = None) -> bool:
        """Enable a static route.

        The controller exposes no dedicated enable endpoint; the enabled flag is
        an ordinary field of the route object, so this is `update_route`.
        """
        return await self.update_route(route_id, enabled=True, site=site)

    async def disable_route(self, route_id: str, site: Optional[str] = None) -> bool:
        """Disable a static route without deleting it."""
        return await self.update_route(route_id, enabled=False, site=site)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _first_route(response: Any) -> Optional[Dict[str, Any]]:
        """Pull the single route object out of a write response.

        A raw envelope carries the object under `data`; a mocked or already
        unwrapped response hands over the list, or the object itself.
        """
        if isinstance(response, dict):
            data = response.get("data")
            if isinstance(data, list):
                return data[0] if data else None
            if isinstance(data, dict):
                return data
            return response or None
        if isinstance(response, list):
            return response[0] if response else None
        return None
