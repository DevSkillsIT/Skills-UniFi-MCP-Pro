"""Firewall policy and port forward operations on the UniFi Network controller.

Every method takes an explicit `site` and passes it down to the request layer,
which swaps and restores the controller site under a lock. This manager never
mutates connection state, and every cache key carries the resolved target site
so a value cached for one site is never served to a caller asking about another.

Traffic routes live in `traffic_route_manager.py`, which owns that endpoint
surface alone.
"""

import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.firewall_policy import FirewallPolicy
from aiounifi.models.port_forward import PortForward

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_FIREWALL_POLICIES = "firewall_policies"
CACHE_PREFIX_PORT_FORWARDS = "port_forwards"
CACHE_PREFIX_FIREWALL_ZONES = "firewall_zones"
CACHE_PREFIX_IP_GROUPS = "ip_groups"


class FirewallManager(SiteScopedManager):
    """Manages Firewall Policies and Port Forwards on the Unifi Controller."""

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
        """Pull the single created object out of a write response."""
        objects = FirewallManager._as_list(response)
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

    # --- Firewall policies ------------------------------------------------

    def _policy_cache_key(self, include_predefined: bool, site: Optional[str]) -> str:
        return f"{CACHE_PREFIX_FIREWALL_POLICIES}_{include_predefined}_{self._target_site(site)}"

    def _invalidate_policies(self, site: Optional[str]) -> None:
        """Drop both policy cache variants for one site only.

        `include_predefined` produces two independent lists, and a write
        invalidates both. The target site is spelled out so the other sites'
        entries survive: invalidation matches on key prefix.
        """
        target = self._target_site(site)
        self._connection._invalidate_cache(f"{CACHE_PREFIX_FIREWALL_POLICIES}_True_{target}")
        self._connection._invalidate_cache(f"{CACHE_PREFIX_FIREWALL_POLICIES}_False_{target}")

    async def get_firewall_policies(
        self, include_predefined: bool = False, site: Optional[str] = None
    ) -> List[FirewallPolicy]:
        """List firewall policies for the target site.

        Args:
            include_predefined: Include the controller's predefined policies.
            site: Site slug or whitelisted display name.
        """
        target = self._target_site(site)
        cache_key = self._policy_cache_key(include_predefined, site)
        async with self._lock_for(cache_key):
            cached: Optional[List[FirewallPolicy]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._request_v2("get", "/firewall-policies", site=site, return_raw=True)
                policies = [FirewallPolicy(p) for p in self._as_list(response)]
                if not include_predefined:
                    policies = [p for p in policies if not p.predefined]

                self._connection._update_cache(cache_key, policies)
                return policies
            except Exception as e:
                logger.error(f"Error getting firewall policies (site={target}): {e}", exc_info=True)
                return []

    async def toggle_firewall_policy(self, policy_id: str, site: Optional[str] = None) -> bool:
        """Flip a firewall policy's enabled state."""
        target = self._target_site(site)
        try:
            policies = await self.get_firewall_policies(include_predefined=True, site=site)
            policy: Optional[FirewallPolicy] = next((p for p in policies if p.id == policy_id), None)
            if not policy:
                logger.error(f"Firewall policy {policy_id} not found on {target}.")
                return False

            new_state = not policy.enabled
            response = await self._request_v2(
                "put", f"/firewall-policies/{policy_id}", {"enabled": new_state}, site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(f"Toggle refused for firewall policy {policy_id} on {target}: {self._refusal(response)}")
                return False

            logger.info(
                f"Firewall policy {policy_id} toggled to {'enabled' if new_state else 'disabled'} on {target}"
            )
            self._invalidate_policies(site)
            return True
        except Exception as e:
            logger.error(f"Error toggling firewall policy {policy_id}: {e}", exc_info=True)
            return False

    async def update_firewall_policy(
        self, policy_id: str, updates: Dict[str, Any], site: Optional[str] = None
    ) -> bool:
        """Update fields of a firewall policy.

        The batch endpoint replaces each policy with the object it is given, so
        the current policy is fetched and the changes are merged onto it;
        sending only the changed keys would blank every field left out.
        """
        if not updates:
            logger.warning(f"No updates provided for firewall policy {policy_id}.")
            return False

        target = self._target_site(site)
        try:
            policies = await self.get_firewall_policies(include_predefined=True, site=site)
            policy: Optional[FirewallPolicy] = next((p for p in policies if p.id == policy_id), None)
            if not policy:
                logger.error(f"Firewall policy {policy_id} not found on {target} for update.")
                return False

            if not isinstance(getattr(policy, "raw", None), dict):
                logger.error(f"Firewall policy {policy_id} carries no raw data; update aborted.")
                return False

            policy_data = policy.raw.copy()
            policy_data.update(updates)

            response = await self._request_v2(
                "put", "/firewall-policies/batch", [policy_data], site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(f"Update refused for firewall policy {policy_id} on {target}: {self._refusal(response)}")
                return False

            logger.info(f"Updated firewall policy {policy_id} on {target}: {sorted(updates)}")
            self._invalidate_policies(site)
            return True
        except Exception as e:
            logger.error(f"Error updating firewall policy {policy_id}: {e}", exc_info=True)
            return False

    async def create_firewall_policy(
        self, policy_data: Dict[str, Any], site: Optional[str] = None
    ) -> Optional[FirewallPolicy]:
        """Create a firewall policy on the target site.

        Returns:
            The created FirewallPolicy, or None if the controller refused it.
        """
        policy_name = policy_data.get("name", "Unnamed Policy")
        target = self._target_site(site)
        try:
            response = await self._request_v2("post", "/firewall-policies", policy_data, site=site, return_raw=True)
            if not self._succeeded(response):
                logger.error(f"Creation refused for firewall policy '{policy_name}' on {target}: {self._refusal(response)}")
                return None

            created = self._first_object(response)
            if not created or not created.get("_id"):
                logger.error(f"Firewall policy creation on {target} returned no identifiable object: {response}")
                return None

            logger.info(f"Created firewall policy '{policy_name}' ({created['_id']}) on {target}")
            self._invalidate_policies(site)
            return FirewallPolicy(created)
        except Exception as e:
            logger.error(f"Error creating firewall policy '{policy_name}' on {target}: {e}", exc_info=True)
            return None

    async def delete_firewall_policy(self, policy_id: str, site: Optional[str] = None) -> bool:
        """Delete a firewall policy by ID from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request_v2(
                "delete", f"/firewall-policies/{policy_id}", site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(f"Delete refused for firewall policy {policy_id} on {target}: {self._refusal(response)}")
                return False

            logger.info(f"Deleted firewall policy {policy_id} on {target}")
            self._invalidate_policies(site)
            return True
        except Exception as e:
            logger.error(f"Error deleting firewall policy {policy_id}: {e}", exc_info=True)
            return False

    # --- Port forwards ----------------------------------------------------

    def _port_forward_cache_key(self, site: Optional[str]) -> str:
        return f"{CACHE_PREFIX_PORT_FORWARDS}_{self._target_site(site)}"

    async def get_port_forwards(self, site: Optional[str] = None) -> List[PortForward]:
        """List port forwarding rules for the target site."""
        target = self._target_site(site)
        cache_key = self._port_forward_cache_key(site)
        async with self._lock_for(cache_key):
            cached: Optional[List[PortForward]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                raw = await self._list("get", "/rest/portforward", site=site)
                rules = [PortForward(r) for r in raw]
                self._connection._update_cache(cache_key, rules)
                return rules
            except Exception as e:
                logger.error(f"Error getting port forwards (site={target}): {e}", exc_info=True)
                return []

    async def get_port_forward_by_id(self, rule_id: str, site: Optional[str] = None) -> Optional[PortForward]:
        """Find one port forwarding rule by ID on the target site."""
        try:
            rules = await self.get_port_forwards(site=site)
            return next((rule for rule in rules if rule.id == rule_id), None)
        except Exception as e:
            logger.error(f"Error getting port forward by ID {rule_id}: {e}", exc_info=True)
            return None

    async def update_port_forward(
        self, rule_id: str, updates: Dict[str, Any], site: Optional[str] = None
    ) -> bool:
        """Update fields of a port forwarding rule.

        The endpoint replaces the stored rule with the body it is given, so the
        current rule is fetched and the changes are merged onto it; sending only
        the changed keys would blank every field left out.
        """
        if not updates:
            logger.warning(f"No updates provided for port forward {rule_id}.")
            return False

        target = self._target_site(site)
        try:
            rule = await self.get_port_forward_by_id(rule_id, site=site)
            if not rule:
                logger.error(f"Port forward {rule_id} not found on {target} for update.")
                return False

            if not isinstance(getattr(rule, "raw", None), dict):
                logger.error(f"Port forward {rule_id} carries no raw data; update aborted.")
                return False

            payload = rule.raw.copy()
            payload.update(updates)

            response = await self._request(
                "put", f"/rest/portforward/{rule_id}", payload, site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(f"Update refused for port forward {rule_id} on {target}: {self._refusal(response)}")
                return False

            logger.info(f"Updated port forward {rule_id} on {target}: {sorted(updates)}")
            self._connection._invalidate_cache(self._port_forward_cache_key(site))
            return True
        except Exception as e:
            logger.error(f"Error updating port forward {rule_id}: {e}", exc_info=True)
            return False

    async def toggle_port_forward(self, rule_id: str, site: Optional[str] = None) -> bool:
        """Flip a port forwarding rule's enabled state."""
        rule = await self.get_port_forward_by_id(rule_id, site=site)
        if not rule:
            logger.error(f"Port forward rule {rule_id} not found on {self._target_site(site)}.")
            return False

        new_state = not rule.enabled
        return await self.update_port_forward(rule_id, {"enabled": new_state}, site=site)

    async def create_port_forward(
        self, rule_data: Dict[str, Any], site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a port forwarding rule on the target site.

        Args:
            rule_data: Rule configuration. `name`, `dst_port`, `fwd_port` and
                `fwd_ip` are required.
            site: Site slug or whitelisted display name.

        Returns:
            The created rule object, carrying its `_id`, or None on failure.
        """
        required_keys = {"name", "dst_port", "fwd_port", "fwd_ip"}
        missing = required_keys - rule_data.keys()
        if missing:
            logger.error(f"Missing required keys for creating port forward: {sorted(missing)}")
            return None

        rule_name = rule_data.get("name")
        target = self._target_site(site)
        try:
            response = await self._request("post", "/rest/portforward", rule_data, site=site, return_raw=True)
            if not self._succeeded(response):
                logger.error(f"Creation refused for port forward '{rule_name}' on {target}: {self._refusal(response)}")
                return None

            created = self._first_object(response)
            if not created or not created.get("_id"):
                logger.error(f"Port forward creation on {target} returned no identifiable object: {response}")
                return None

            logger.info(f"Created port forward '{rule_name}' ({created['_id']}) on {target}")
            self._connection._invalidate_cache(self._port_forward_cache_key(site))
            return created
        except Exception as e:
            logger.error(f"Error creating port forward '{rule_name}' on {target}: {e}", exc_info=True)
            return None

    async def delete_port_forward(self, rule_id: str, site: Optional[str] = None) -> bool:
        """Delete a port forwarding rule by ID from the target site."""
        target = self._target_site(site)
        try:
            response = await self._request(
                "delete", f"/rest/portforward/{rule_id}", site=site, return_raw=True
            )
            if not self._succeeded(response):
                logger.error(f"Delete refused for port forward {rule_id} on {target}: {self._refusal(response)}")
                return False

            logger.info(f"Deleted port forward {rule_id} on {target}")
            self._connection._invalidate_cache(self._port_forward_cache_key(site))
            return True
        except Exception as e:
            logger.error(f"Error deleting port forward {rule_id}: {e}", exc_info=True)
            return False

    # --- Firewall building blocks ----------------------------------------

    async def get_firewall_zones(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List firewall zones on the target site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_FIREWALL_ZONES}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._request_v2("get", "/firewall/zones", site=site, return_raw=True)
                zones = self._as_list(response)
                self._connection._update_cache(cache_key, zones)
                return zones
            except Exception as e:
                logger.error(f"Error fetching firewall zones (site={target}): {e}", exc_info=True)
                return []

    async def get_ip_groups(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List IP groups on the target site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_IP_GROUPS}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._request_v2("get", "/ip-groups", site=site, return_raw=True)
                groups = self._as_list(response)
                self._connection._update_cache(cache_key, groups)
                return groups
            except Exception as e:
                logger.error(f"Error fetching ip groups (site={target}): {e}", exc_info=True)
                return []
