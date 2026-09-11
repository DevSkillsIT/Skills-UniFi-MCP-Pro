"""VPN management for UniFi Network MCP server.

VPN configurations are stored in the networkconf API endpoint alongside regular
networks. They're identified by the 'purpose' field (vpn-client, vpn-server,
remote-user-vpn) and/or 'vpn_type' field (wireguard-client, openvpn-server, etc).

Note: UniFi is developing a dedicated VPN API but it's not yet complete.
This implementation uses the networkconf endpoint which is the reliable approach.

Because a VPN config is a networkconf record, every write here targets the same
`/rest/networkconf` paths the NetworkManager uses. The create and delete paths
are therefore guarded by `is_vpn_network`: without that guard the VPN tools
would be a side door for creating or deleting ordinary LANs.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_VPN_CONFIGS = "vpn_configs"
CACHE_PREFIX_NETWORKS = "networks"


def is_vpn_network(network: Dict[str, Any]) -> bool:
    """Check if a network configuration represents a VPN entity.

    Args:
        network: Network configuration dictionary

    Returns:
        True if this is a VPN configuration
    """
    purpose = str(network.get("purpose", "")).lower()
    vpn_type = str(network.get("vpn_type", "")).lower()

    return (
        purpose.startswith("vpn")
        or purpose in {"remote-user-vpn", "vpn-client", "vpn-server"}
        or "vpn" in vpn_type
        or "wireguard" in vpn_type
        or "openvpn" in vpn_type
    )


def classify_vpn_type(purpose: str, vpn_type: str) -> Tuple[bool, bool]:
    """Classify VPN configuration as client or server.

    Args:
        purpose: The purpose field from VPN config
        vpn_type: The vpn_type field from VPN config

    Returns:
        Tuple of (is_client, is_server)
    """
    purpose = str(purpose).lower() if purpose else ""
    vpn_type = str(vpn_type).lower() if vpn_type else ""

    is_client = purpose == "vpn-client" or "client" in vpn_type or vpn_type in {"wireguard-client", "openvpn-client"}

    is_server = (
        purpose in {"vpn-server", "remote-user-vpn"}
        or "server" in vpn_type
        or vpn_type in {"wireguard-server", "openvpn-server"}
    )

    return is_client, is_server


class VpnManager(SiteScopedManager):
    """Manages VPN-related operations on the Unifi Controller.

    VPN configurations are retrieved from the networkconf API and filtered
    based on purpose and vpn_type fields.
    """

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def _get_all_network_configs(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all network configurations from the controller.

        Args:
            site: Site slug or whitelisted display name.

        Returns:
            List of network configuration dictionaries
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_NETWORKS}_{target}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Dict[str, Any]]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                networks = await self._list("get", "/rest/networkconf", site=site)
                self._connection._update_cache(cache_key, networks)
                return networks
            except Exception as e:
                logger.error(f"Error fetching network configurations (site={target}): {e}")
                return []

    async def get_vpn_configs(
        self,
        include_clients: bool = True,
        include_servers: bool = True,
        site: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get VPN configurations from the controller.

        Args:
            include_clients: Whether to include VPN client configurations
            include_servers: Whether to include VPN server configurations
            site: Site slug or whitelisted display name.

        Returns:
            List of VPN configuration dictionaries
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_VPN_CONFIGS}_{target}_{include_clients}_{include_servers}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Dict[str, Any]]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                networks = await self._get_all_network_configs(site=site)
                vpn_configs = []

                for network in networks:
                    if not is_vpn_network(network):
                        continue

                    purpose = network.get("purpose", "")
                    vpn_type = network.get("vpn_type", "")
                    is_client, is_server = classify_vpn_type(purpose, vpn_type)

                    if (include_clients and is_client) or (include_servers and is_server):
                        vpn_configs.append(network)

                logger.debug(f"Found {len(vpn_configs)} VPN configurations on {target}")
                self._connection._update_cache(cache_key, vpn_configs)
                return vpn_configs
            except Exception as e:
                logger.error(f"Error getting VPN configurations (site={target}): {e}")
                return []

    async def get_vpn_clients(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of VPN client configurations for the target site."""
        return await self.get_vpn_configs(include_clients=True, include_servers=False, site=site)

    async def get_vpn_servers(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of VPN server configurations for the target site."""
        return await self.get_vpn_configs(include_clients=False, include_servers=True, site=site)

    async def get_vpn_client_details(self, client_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific VPN client.

        Args:
            client_id: ID of the VPN client to get details for
            site: Site slug or whitelisted display name.

        Returns:
            VPN client details if found, None otherwise
        """
        vpn_clients = await self.get_vpn_clients(site=site)
        client = next((c for c in vpn_clients if c.get("_id") == client_id), None)
        if not client:
            logger.debug(f"VPN client {client_id} not found on {self._target_site(site)}")
        return client

    async def get_vpn_server_details(self, server_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific VPN server.

        Args:
            server_id: ID of the VPN server to get details for
            site: Site slug or whitelisted display name.

        Returns:
            VPN server details if found, None otherwise
        """
        vpn_servers = await self.get_vpn_servers(site=site)
        server = next((s for s in vpn_servers if s.get("_id") == server_id), None)
        if not server:
            logger.debug(f"VPN server {server_id} not found on {self._target_site(site)}")
        return server

    async def get_vpn_config_details(self, config_id: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get one VPN configuration by id, whether it is a client or a server.

        Callers hold a config id taken from `get_vpn_configs`, which unifies both
        kinds; asking them to know which of the two it was before they can read
        it back would make the id useless.

        Args:
            config_id: ID of the VPN configuration to get details for
            site: Site slug or whitelisted display name.

        Returns:
            VPN configuration if found, None otherwise
        """
        configs = await self.get_vpn_configs(site=site)
        config = next((c for c in configs if c.get("_id") == config_id), None)
        if not config:
            logger.debug(f"VPN configuration {config_id} not found on {self._target_site(site)}")
        return config

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def _invalidate(self, target: str) -> None:
        """Drop every cached view a networkconf write can invalidate.

        Invalidation is by bare prefix rather than by enumerated cache key: the
        VPN cache key carries the include_clients/include_servers pair, so a
        hand-written list of suffixes misses combinations and leaves a stale
        view behind.
        """
        self._connection._invalidate_cache(CACHE_PREFIX_NETWORKS)
        self._connection._invalidate_cache(CACHE_PREFIX_VPN_CONFIGS)
        logger.debug(f"Invalidated network and VPN caches after a write on {target}")

    async def create_vpn_config(
        self, config_data: Dict[str, Any], site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a VPN configuration via POST /rest/networkconf.

        Args:
            config_data: The full networkconf body describing the VPN.
            site: Site slug or whitelisted display name.

        Returns:
            The created configuration, or None when the controller refused it
            or the payload does not describe a VPN.
        """
        target = self._target_site(site)
        if not is_vpn_network(config_data):
            logger.error(
                "Refusing to create a network that is not a VPN: "
                "'purpose' must be one of vpn-client, vpn-server, remote-user-vpn, "
                "or 'vpn_type' must name a VPN protocol"
            )
            return None

        name = config_data.get("name", "unnamed")
        try:
            response = await self._request("post", "/rest/networkconf", config_data, site=site, return_raw=True)
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Create VPN configuration '{name}' refused on {target}: {message}")
                return None

            self._invalidate(target)
            logger.info(f"Created VPN configuration '{name}' on {target}")
            return self._first_config(response)
        except Exception as e:
            logger.error(f"Error creating VPN configuration '{name}': {e}")
            return None

    async def update_vpn_config(
        self, config_id: str, update_data: Dict[str, Any], site: Optional[str] = None
    ) -> bool:
        """Update a VPN configuration via PUT /rest/networkconf/{config_id}.

        The endpoint rejects partial bodies, so the stored config is fetched and
        the supplied fields merged into it.

        Args:
            config_id: ID of the VPN configuration to update
            update_data: Fields to merge into the existing configuration
            site: Site slug or whitelisted display name.

        Returns:
            True when the controller accepted the update.
        """
        target = self._target_site(site)
        try:
            networks = await self._get_all_network_configs(site=site)
            existing = next((n for n in networks if n.get("_id") == config_id), None)
            if not existing:
                logger.error(f"VPN configuration {config_id} not found on {target}")
                return False

            merged_data = existing.copy()
            merged_data.update(update_data)

            response = await self._request(
                "put", f"/rest/networkconf/{config_id}", merged_data, site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Update refused for VPN configuration {config_id} on {target}: {message}")
                return False

            self._invalidate(target)
            logger.info(f"Updated VPN configuration {config_id} on {target}")
            return True
        except Exception as e:
            logger.error(f"Error updating VPN configuration {config_id}: {e}")
            return False

    async def delete_vpn_config(self, config_id: str, site: Optional[str] = None) -> bool:
        """Delete a VPN configuration via DELETE /rest/networkconf/{config_id}.

        Args:
            config_id: ID of the VPN configuration to delete
            site: Site slug or whitelisted display name.

        Returns:
            True when the controller accepted the deletion.
        """
        target = self._target_site(site)
        try:
            config = await self.get_vpn_config_details(config_id, site=site)
            if not config:
                logger.error(f"VPN configuration {config_id} not found on {target}")
                return False

            response = await self._request(
                "delete", f"/rest/networkconf/{config_id}", site=site, return_raw=True
            )
            if not self._succeeded(response):
                message = (response or {}).get("meta", {}).get("msg", "unknown error")
                logger.error(f"Delete refused for VPN configuration {config_id} on {target}: {message}")
                return False

            self._invalidate(target)
            logger.info(f"Deleted VPN configuration '{config.get('name', config_id)}' on {target}")
            return True
        except Exception as e:
            logger.error(f"Error deleting VPN configuration {config_id}: {e}")
            return False

    async def set_vpn_config_state(self, config_id: str, enabled: bool, site: Optional[str] = None) -> bool:
        """Set the enabled flag of a VPN configuration, client or server.

        Args:
            config_id: ID of the VPN configuration
            enabled: Target state
            site: Site slug or whitelisted display name.

        Returns:
            True when the controller accepted the change.
        """
        config = await self.get_vpn_config_details(config_id, site=site)
        if not config:
            logger.error(f"VPN configuration {config_id} not found, cannot change its state")
            return False

        result = await self.update_vpn_config(config_id, {"enabled": enabled}, site=site)
        if result:
            state = "enabled" if enabled else "disabled"
            logger.info(f"VPN configuration '{config.get('name', config_id)}' {state}")
        return result

    async def enable_vpn_config(self, config_id: str, site: Optional[str] = None) -> bool:
        """Enable a VPN configuration, client or server."""
        return await self.set_vpn_config_state(config_id, True, site=site)

    async def disable_vpn_config(self, config_id: str, site: Optional[str] = None) -> bool:
        """Disable a VPN configuration without deleting it."""
        return await self.set_vpn_config_state(config_id, False, site=site)

    async def update_vpn_client_state(self, client_id: str, enabled: bool, site: Optional[str] = None) -> bool:
        """Set the enabled state of a VPN client.

        Narrower than `set_vpn_config_state`: an id that belongs to a server is
        rejected rather than acted on.
        """
        client = await self.get_vpn_client_details(client_id, site=site)
        if not client:
            logger.error(f"VPN client {client_id} not found, cannot update state")
            return False

        result = await self.update_vpn_config(client_id, {"enabled": enabled}, site=site)
        if result:
            logger.info(f"VPN client {client.get('name', client_id)} {'enabled' if enabled else 'disabled'}")
        return result

    async def update_vpn_server_state(self, server_id: str, enabled: bool, site: Optional[str] = None) -> bool:
        """Set the enabled state of a VPN server.

        Narrower than `set_vpn_config_state`: an id that belongs to a client is
        rejected rather than acted on.
        """
        server = await self.get_vpn_server_details(server_id, site=site)
        if not server:
            logger.error(f"VPN server {server_id} not found, cannot update state")
            return False

        result = await self.update_vpn_config(server_id, {"enabled": enabled}, site=site)
        if result:
            logger.info(f"VPN server {server.get('name', server_id)} {'enabled' if enabled else 'disabled'}")
        return result

    async def toggle_vpn_config(self, config_id: str, site: Optional[str] = None) -> bool:
        """Flip a VPN configuration's enabled state.

        Args:
            config_id: ID of the VPN configuration to toggle
            site: Site slug or whitelisted display name.

        Returns:
            True when the controller accepted the change.
        """
        config = await self.get_vpn_config_details(config_id, site=site)
        if not config:
            logger.error(f"VPN configuration {config_id} not found on {self._target_site(site)}")
            return False

        return await self.update_vpn_config(config_id, {"enabled": not config.get("enabled", True)}, site=site)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _first_config(response: Any) -> Optional[Dict[str, Any]]:
        """Pull the single config object out of a write response.

        A raw envelope carries the object under `data`; an already unwrapped
        response hands over the list, or the object itself.
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
