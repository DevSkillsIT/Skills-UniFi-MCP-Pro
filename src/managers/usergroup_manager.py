"""Usergroup Manager for UniFi Network MCP server.

Manages user group operations for bandwidth limits and client categorization.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.api import ApiRequest

from .connection_manager import ConnectionManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_USERGROUPS = "usergroups"


class UsergroupManager:
    """Manages user group operations on the UniFi Controller."""

    def __init__(self, connection_manager: ConnectionManager):
        """Initialize the Usergroup Manager.

        Args:
            connection_manager: The shared ConnectionManager instance.
        """
        self._connection = connection_manager
        self._cache_locks: Dict[str, asyncio.Lock] = {}

    async def get_usergroups(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all user groups for the specified site.

        Uses GET /rest/usergroup endpoint.

        Args:
            site: Target site ID (slug). If None, uses current connection site.

        Returns:
            List of user group objects containing name, bandwidth limits, etc.
        """
        target_site = site or self._connection.site
        cache_key = f"{CACHE_PREFIX_USERGROUPS}_{target_site}"
        lock = self._cache_locks.setdefault(cache_key, asyncio.Lock())

        async with lock:
            cached_data = self._connection.get_cached(cache_key)
            if cached_data is not None:
                return cached_data

            if not await self._connection.ensure_connected():
                return []

            try:
                original_site = self._connection.site
                if target_site != original_site:
                    await self._connection.set_site(target_site)

                api_request = ApiRequest(method="get", path="/rest/usergroup")
                response = await self._connection.request(api_request)

                usergroups = (
                    response
                    if isinstance(response, list)
                    else response.get("data", [])
                    if isinstance(response, dict)
                    else []
                )

                self._connection._update_cache(cache_key, usergroups)
                return usergroups
            except Exception as e:
                logger.error(f"Error getting user groups (site={target_site}): {e}", exc_info=True)
                return []
            finally:
                if target_site != self._connection.site:
                    await self._connection.set_site(original_site)

    async def get_usergroup_details(self, group_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get details for a specific user group by ID.

        Args:
            group_id: The _id of the user group.
            site: Target site ID (slug). If None, uses current connection site.

        Returns:
            User group object or None if not found.
        """
        try:
            all_groups = await self.get_usergroups(site=site)
            group = next((g for g in all_groups if g.get("_id") == group_id), None)
            if not group:
                logger.debug(f"User group {group_id} not found.")
            return group
        except Exception as e:
            logger.error(f"Error getting user group details for {group_id}: {e}", exc_info=True)
            return None

    async def create_usergroup(
        self,
        name: str,
        down_limit_kbps: Optional[int] = None,
        up_limit_kbps: Optional[int] = None,
        site: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a new user group with optional bandwidth limits.

        Uses POST to /rest/usergroup endpoint.

        Args:
            name: Name for the user group.
            down_limit_kbps: Optional download speed limit in Kbps (-1 for unlimited).
            up_limit_kbps: Optional upload speed limit in Kbps (-1 for unlimited).
            site: Target site ID (slug). If None, uses current connection site.

        Returns:
            Created user group object, or None on failure.
        """
        target_site = site or self._connection.site
        try:
            original_site = self._connection.site
            if target_site != original_site:
                await self._connection.set_site(target_site)
            try:
                payload: Dict[str, Any] = {"name": name}

                # -1 means unlimited in UniFi API
                if down_limit_kbps is not None:
                    payload["qos_rate_max_down"] = down_limit_kbps
                if up_limit_kbps is not None:
                    payload["qos_rate_max_up"] = up_limit_kbps

                api_request = ApiRequest(
                    method="post",
                    path="/rest/usergroup",
                    data=payload,
                )
                response = await self._connection.request(api_request)

                logger.info(f"Created user group: {name}")

                # Invalidate cache
                self._connection._invalidate_cache(f"{CACHE_PREFIX_USERGROUPS}_{target_site}")

                # Return the created group
                if isinstance(response, list) and len(response) > 0:
                    return response[0]
                elif isinstance(response, dict):
                    return response.get("data", [response])[0] if response else None

                return None
            finally:
                if target_site != original_site:
                    await self._connection.set_site(original_site)
        except Exception as e:
            logger.error(f"Error creating user group: {e}", exc_info=True)
            return None

    async def update_usergroup(
        self,
        group_id: str,
        name: Optional[str] = None,
        down_limit_kbps: Optional[int] = None,
        up_limit_kbps: Optional[int] = None,
        site: Optional[str] = None,
    ) -> bool:
        """Update an existing user group.

        Uses PUT to /rest/usergroup/{group_id} endpoint.

        Args:
            group_id: The _id of the user group to update.
            name: Optional new name for the group.
            down_limit_kbps: Optional new download limit in Kbps (-1 for unlimited).
            up_limit_kbps: Optional new upload limit in Kbps (-1 for unlimited).
            site: Target site ID (slug). If None, uses current connection site.

        Returns:
            True if successful, False otherwise.
        """
        target_site = site or self._connection.site
        try:
            original_site = self._connection.site
            if target_site != original_site:
                await self._connection.set_site(target_site)
            try:
                # Get current group data first
                current = await self.get_usergroup_details(group_id, site=site)
                if not current:
                    logger.error(f"User group {group_id} not found for update.")
                    return False

                # Build payload with updates
                payload: Dict[str, Any] = {}
                if name is not None:
                    payload["name"] = name
                if down_limit_kbps is not None:
                    payload["qos_rate_max_down"] = down_limit_kbps
                if up_limit_kbps is not None:
                    payload["qos_rate_max_up"] = up_limit_kbps

                if not payload:
                    logger.warning(f"No updates provided for user group {group_id}")
                    return False

                api_request = ApiRequest(
                    method="put",
                    path=f"/rest/usergroup/{group_id}",
                    data=payload,
                )
                await self._connection.request(api_request)

                logger.info(f"Updated user group {group_id}: {payload}")

                # Invalidate cache
                self._connection._invalidate_cache(f"{CACHE_PREFIX_USERGROUPS}_{target_site}")

                return True
            finally:
                if target_site != original_site:
                    await self._connection.set_site(original_site)
        except Exception as e:
            logger.error(f"Error updating user group {group_id}: {e}", exc_info=True)
            return False

    async def delete_usergroup(self, group_id: str, site: Optional[str] = None) -> bool:
        """Delete a user group.

        Uses DELETE to /rest/usergroup/{group_id} endpoint.

        Args:
            group_id: The _id of the user group to delete.
            site: Target site ID (slug). If None, uses current connection site.

        Returns:
            True if successful, False otherwise.
        """
        target_site = site or self._connection.site
        try:
            original_site = self._connection.site
            if target_site != original_site:
                await self._connection.set_site(target_site)
            try:
                api_request = ApiRequest(method="delete", path=f"/rest/usergroup/{group_id}")
                await self._connection.request(api_request)

                logger.info(f"Deleted user group {group_id}")

                # Invalidate cache
                self._connection._invalidate_cache(f"{CACHE_PREFIX_USERGROUPS}_{target_site}")

                return True
            finally:
                if target_site != original_site:
                    await self._connection.set_site(original_site)
        except Exception as e:
            logger.error(f"Error deleting user group {group_id}: {e}", exc_info=True)
            return False
