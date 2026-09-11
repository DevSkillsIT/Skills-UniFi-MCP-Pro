"""QoS rule operations on the UniFi Network controller.

QoS lives behind the V2 API (`/v2/api/site/<site>/qos-rules`), which has no
per-rule GET: a single rule is found by filtering the full list. List and
detail therefore share one per-site cache entry.

Verification on V2 is not symmetric with V1. `ApiRequestV2.decode` synthesises
`meta={"rc": "ok"}` for every body it manages to parse and raises only when the
payload carries an `errorCode`. `_succeeded()` on a V2 response consequently
reports the client library's own fabricated envelope, never the controller's
verdict. The exception path is what actually separates an accepted write from a
refused one here, so writes below treat a raised error as the failure signal
and additionally require the controller to echo back the object it claims to
have stored.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_QOS = "qos_rules"


def _as_rule_list(response: Any) -> List[Dict[str, Any]]:
    """Normalise a QoS list response into a list of rule dicts.

    V2 hands back the unwrapped `data` list. The dict branch covers a caller
    (or a mock) that passes the whole envelope through: taking `data` from it
    is right, while treating the envelope itself as a single rule would put
    `meta` into the rule list.
    """
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        data = response.get("data", [])
        return data if isinstance(data, list) else [data]
    return []


class QosManager(SiteScopedManager):
    """Manages QoS (Quality of Service) rules on the Unifi Controller."""

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_qos_rules(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List QoS rules for the target site.

        Args:
            site: Site slug or whitelisted display name.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_QOS}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._request_v2("get", "/qos-rules", site=site)
                rules = _as_rule_list(response)
                self._connection._update_cache(cache_key, rules)
                return rules
            except Exception as e:
                logger.error(f"Error getting QoS rules (site={target}): {e}", exc_info=True)
                return []

    async def get_qos_rule_details(self, rule_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find one QoS rule by id within the target site's rule list."""
        try:
            all_rules = await self.get_qos_rules(site=site)
            rule = next((r for r in all_rules if r.get("_id") == rule_id), None)
            if not rule:
                logger.warning(f"QoS rule {rule_id} not found on site {self._target_site(site)}.")
            return rule
        except Exception as e:
            logger.error(f"Error getting QoS rule details for {rule_id}: {e}", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def update_qos_rule(
        self, rule_id: str, update_data: Dict[str, Any], site: Optional[str] = None
    ) -> bool:
        """Update a QoS rule by merging `update_data` over its stored fields.

        The V2 endpoint replaces the whole object, so a partial PUT would drop
        every field the caller did not mention. The merge base is read from the
        same site the write targets.
        """
        if not update_data:
            logger.warning(f"No update data provided for QoS rule {rule_id}.")
            return True

        target = self._target_site(site)
        try:
            existing_rule = await self.get_qos_rule_details(rule_id, site=site)
            if not existing_rule:
                logger.error(f"QoS rule {rule_id} not found for update on site {target}.")
                return False

            merged_data = {**existing_rule, **update_data}

            response = await self._request_v2(
                "put", f"/qos-rules/{rule_id}", merged_data, site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Update refused for QoS rule {rule_id} on site {target}: {message}")
                return False

            logger.info(f"QoS rule {rule_id} updated on site {target}.")
            self._connection._invalidate_cache(f"{CACHE_PREFIX_QOS}_{target}")
            return True
        except Exception as e:
            logger.error(f"Error updating QoS rule {rule_id} on site {target}: {e}", exc_info=True)
            return False

    async def create_qos_rule(
        self, rule_data: Dict[str, Any], site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a QoS rule and return the stored object the controller echoes.

        Returning None on an unusable response keeps the caller from reporting
        a rule id it never received.
        """
        target = self._target_site(site)
        try:
            required_fields = ["name", "enabled"]
            missing = [f for f in required_fields if f not in rule_data]
            if missing:
                logger.error(f"Missing required field(s) {missing} for QoS rule creation")
                return None

            response = await self._request_v2("post", "/qos-rules", rule_data, site=site, return_raw=True)
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Create refused for QoS rule '{rule_data.get('name')}' on site {target}: {message}")
                return None

            self._connection._invalidate_cache(f"{CACHE_PREFIX_QOS}_{target}")

            created = _as_rule_list(response)
            if created and isinstance(created[0], dict):
                logger.info(f"QoS rule '{rule_data.get('name')}' created on site {target}.")
                return created[0]

            logger.error(
                f"QoS rule '{rule_data.get('name')}' on site {target}: controller returned no stored object."
            )
            return None
        except Exception as e:
            logger.error(f"Error creating QoS rule on site {target}: {e}", exc_info=True)
            return None

    async def delete_qos_rule(self, rule_id: str, site: Optional[str] = None) -> bool:
        """Delete a QoS rule from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request_v2(
                "delete", f"/qos-rules/{rule_id}", site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Delete refused for QoS rule {rule_id} on site {target}: {message}")
                return False

            logger.info(f"QoS rule {rule_id} deleted on site {target}.")
            self._connection._invalidate_cache(f"{CACHE_PREFIX_QOS}_{target}")
            return True
        except Exception as e:
            logger.error(f"Error deleting QoS rule {rule_id} on site {target}: {e}", exc_info=True)
            return False
