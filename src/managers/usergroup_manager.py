"""User group (bandwidth profile) operations on the UniFi Network controller.

User groups live on the V1 REST API (`/rest/usergroup`), where `ApiRequest`
raises on `meta.rc == "error"`. A controller refusal therefore arrives as an
exception rather than as a falsy envelope, and `_succeeded()` is the second
line of defence rather than the first.

`/rest/*` endpoints replace the whole object on PUT, so an update sends the
stored group merged with the caller's changes: a payload carrying only `name`
would clear the bandwidth limits it does not mention.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_USERGROUPS = "usergroups"

# Callers describe limits in Kbps; the controller stores them under its own
# field names. Both vocabularies resolve to the field UniFi actually persists,
# so a payload written either way configures the group instead of silently
# adding an attribute the controller ignores.
_FIELD_ALIASES = {
    "down_limit_kbps": "qos_rate_max_down",
    "up_limit_kbps": "qos_rate_max_up",
}

# Identity and ownership fields belong to the controller; echoing a caller's
# copy of them back on a write would let a stale read retarget the request.
_SERVER_OWNED_FIELDS = ("_id", "site_id", "attr_no_delete", "attr_hidden_id")


def _normalise_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Translate limit aliases onto the controller's own field names."""
    return {_FIELD_ALIASES.get(key, key): value for key, value in payload.items()}


def _as_group_list(response: Any) -> List[Dict[str, Any]]:
    """Normalise a usergroup response into a list of group dicts.

    The dict branch covers a whole envelope arriving unwrapped: its `data` is
    the group list, whereas treating the envelope as one group would put
    `meta` into the result.
    """
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        data = response.get("data", [])
        return data if isinstance(data, list) else [data]
    return []


class UsergroupManager(SiteScopedManager):
    """Manages user group operations on the UniFi Controller."""

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_usergroups(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List every user group on the target site.

        Args:
            site: Site slug or whitelisted display name.

        Returns:
            User group objects carrying name and bandwidth limits.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_USERGROUPS}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._request("get", "/rest/usergroup", site=site)
                usergroups = _as_group_list(response)
                self._connection._update_cache(cache_key, usergroups)
                return usergroups
            except Exception as e:
                logger.error(f"Error getting user groups (site={target}): {e}", exc_info=True)
                return []

    async def get_usergroup_details(
        self, group_id: str, site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find one user group by id within the target site's group list."""
        try:
            all_groups = await self.get_usergroups(site=site)
            group = next((g for g in all_groups if g.get("_id") == group_id), None)
            if not group:
                logger.debug(f"User group {group_id} not found on site {self._target_site(site)}.")
            return group
        except Exception as e:
            logger.error(f"Error getting user group details for {group_id}: {e}", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def create_usergroup(
        self, group_data: Dict[str, Any], site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a user group and return the stored object the controller echoes.

        Args:
            group_data: Group fields. `name` is required. Bandwidth limits may
                be given as `down_limit_kbps`/`up_limit_kbps` or under the
                controller's `qos_rate_max_down`/`qos_rate_max_up`; -1 means
                unlimited.
            site: Site slug or whitelisted display name.
        """
        target = self._target_site(site)
        try:
            payload = _normalise_payload(group_data or {})
            if not payload.get("name"):
                logger.error("Missing required field 'name' for user group creation")
                return None

            response = await self._request(
                "post", "/rest/usergroup", payload, site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Create refused for user group '{payload['name']}' on site {target}: {message}")
                return None

            self._connection._invalidate_cache(f"{CACHE_PREFIX_USERGROUPS}_{target}")

            created = _as_group_list(response)
            if created and isinstance(created[0], dict):
                logger.info(f"User group '{payload['name']}' created on site {target}.")
                return created[0]

            logger.error(
                f"User group '{payload['name']}' on site {target}: controller returned no stored object."
            )
            return None
        except Exception as e:
            logger.error(f"Error creating user group on site {target}: {e}", exc_info=True)
            return None

    async def update_usergroup(
        self, group_id: str, update_data: Dict[str, Any], site: Optional[str] = None
    ) -> bool:
        """Update a user group by merging `update_data` over its stored fields.

        Args:
            group_id: The `_id` of the group to update.
            update_data: Fields to change, in either limit vocabulary.
            site: Site slug or whitelisted display name.
        """
        target = self._target_site(site)
        try:
            payload = _normalise_payload(update_data or {})
            if not payload:
                logger.warning(f"No updates provided for user group {group_id}")
                return False

            current = await self.get_usergroup_details(group_id, site=site)
            if not current:
                logger.error(f"User group {group_id} not found for update on site {target}.")
                return False

            merged = {**current, **payload}
            for field in _SERVER_OWNED_FIELDS:
                merged.pop(field, None)

            response = await self._request(
                "put", f"/rest/usergroup/{group_id}", merged, site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Update refused for user group {group_id} on site {target}: {message}")
                return False

            logger.info(f"User group {group_id} updated on site {target}: {sorted(payload)}")
            self._connection._invalidate_cache(f"{CACHE_PREFIX_USERGROUPS}_{target}")
            return True
        except Exception as e:
            logger.error(f"Error updating user group {group_id} on site {target}: {e}", exc_info=True)
            return False

    async def delete_usergroup(self, group_id: str, site: Optional[str] = None) -> bool:
        """Delete a user group from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request(
                "delete", f"/rest/usergroup/{group_id}", site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Delete refused for user group {group_id} on site {target}: {message}")
                return False

            logger.info(f"User group {group_id} deleted on site {target}.")
            self._connection._invalidate_cache(f"{CACHE_PREFIX_USERGROUPS}_{target}")
            return True
        except Exception as e:
            logger.error(f"Error deleting user group {group_id} on site {target}: {e}", exc_info=True)
            return False
