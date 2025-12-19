"""
Unifi Network MCP network tools.

This module provides MCP tools to interact with a Unifi Network Controller's network functions,
including managing LAN networks and WLANs.
Supports multi-site operations with optional site parameter.
"""

import json
import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, network_manager, server, system_manager
from src.utils.confirmation import create_preview, should_auto_confirm, update_preview
from src.utils.permissions import parse_permission
from src.validator_registry import UniFiValidatorRegistry
from src.utils.site_context import resolve_site_context, inject_site_metadata
from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_networks",
    description="List all configured networks (LAN, WAN, VLAN-only) on the Unifi Network controller (V1 API based). Supports multi-site with optional site parameter.",
)
async def list_networks(site: Optional[str] = None) -> Dict[str, Any]:
    """Lists all networks configured on the UniFi Network controller for the specified site using the V1 API structure.

    Args:
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Wink", "wink", "grupo-wink" for "Grupo Wink")

    Returns:
        Dict with network list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        networks = await network_manager.get_networks(site=site_slug)

        # Convert Network objects to plain dictionaries
        networks_raw = [n.raw if hasattr(n, "raw") else n for n in networks]

        return inject_site_metadata({
            "success": True,
            "count": len(networks_raw),
            "networks": networks_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing networks: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_network_details",
    description="Get detailed information about a specific network by ID. Supports multi-site with optional site parameter.",
)
async def get_network_details(network_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting network details with multi-site support.

    Args:
        network_id: The _id of the network
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with network details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        network = await network_manager.get_network_details(network_id, site=site_slug)
        if network:
            network_raw = network.raw if hasattr(network, "raw") else network
            return inject_site_metadata({
                "success": True,
                "network": network_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Network with ID {network_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting network details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_network",
    description="Update specific fields of an existing network (LAN/VLAN). Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="networks",
    permission_action="update",
)
async def update_network(network_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for updating network with multi-site support.

    Args:
        network_id: The unique identifier (_id) of the network to update
        update_data: Dictionary of fields to update
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "network", "update"):
        logger.warning(f"Permission denied for updating network ({network_id}).")
        return {"success": False, "error": "Permission denied to update network."}

    if not network_id:
        return {"success": False, "error": "network_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("network_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid network update data for ID {network_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        if not validated_data:
            logger.warning(f"Network update data for ID {network_id} is empty after validation.")
            return {"success": False, "error": "Update data is effectively empty or invalid."}

        # Fetch current state for preview
        current = await network_manager.get_network_details(network_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Network not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="network",
                resource_id=network_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        # Basic cross-field validation
        if "vlan_enabled" in validated_data and validated_data["vlan_enabled"] and "vlan" not in validated_data:
            pass  # Let manager handle fetching existing state for merge
        if "vlan" in validated_data and (int(validated_data["vlan"]) < 1 or int(validated_data["vlan"]) > 4094):
            return {"success": False, "error": "'vlan' must be between 1 and 4094."}

        # Perform the update
        success = await network_manager.update_network(network_id, validated_data, site=site_slug)
        if success:
            # Fetch updated details
            updated = await network_manager.get_network_details(network_id, site=site_slug)
            return inject_site_metadata({
                "success": True,
                "network_id": network_id,
                "updated_fields": list(validated_data.keys()),
                "details": updated,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to update network {network_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating network {network_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_network",
    description="Create a new network (LAN/VLAN) with schema validation. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="networks",
    permission_action="create",
)
async def create_network(network_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for creating network with multi-site support.

    Args:
        network_data: Network configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "network", "create"):
        logger.warning("Permission denied for creating network.")
        return {"success": False, "error": "Permission denied to create network."}

    if not network_data:
        return {"success": False, "error": "network_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the network data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("network_create", network_data)
        if not is_valid:
            logger.warning(f"Invalid network create data: {error_msg}")
            return {"success": False, "error": f"Invalid network data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="network",
                resource_name=validated_data.get("name", "Unknown"),
                resource_data=validated_data,
            )

        # Create the network
        result = await network_manager.create_network(validated_data, site=site_slug)
        if result:
            return inject_site_metadata({
                "success": True,
                "network_id": result.get("_id"),
                "details": result,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to create network",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating network: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
        # Validate the input
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("network", network_data)
        if not is_valid:
            logger.warning(f"Invalid network data: {error_msg}")
            return {"success": False, "error": error_msg}

        # Required fields check
        required_fields = ["name", "purpose"]
        missing_fields = [field for field in required_fields if field not in validated_data]
        if missing_fields:
            error = f"Missing required fields: {', '.join(missing_fields)}"
            logger.warning(error)
            return {"success": False, "error": error}

        # Additional validation for purpose type
        purpose = validated_data.get("purpose")
        # Ensure purpose is one of the allowed values
        allowed_purposes = [
            "corporate",
            "guest",
            "wan",
            "vlan-only",
            "vpn-client",
            "vpn-server",
        ]  # Consider adding "bridge"? Check schema
        if purpose not in allowed_purposes:
            return {
                "success": False,
                "error": f"Invalid 'purpose': {purpose}. Must be one of {allowed_purposes}.",
            }

        # Validation based on purpose
        if purpose != "vlan-only" and not validated_data.get("ip_subnet"):
            return {
                "success": False,
                "error": f"'ip_subnet' is required for network purpose '{purpose}'",
            }

        if purpose == "vlan-only" and not validated_data.get("vlan"):
            return {
                "success": False,
                "error": "'vlan' is required for network purpose 'vlan-only'.",
            }

        # Validation for DHCP
        dhcp_enabled = validated_data.get("dhcp_enabled", True)
        if (
            purpose != "vlan-only"
            and dhcp_enabled
            and (not validated_data.get("dhcp_start") or not validated_data.get("dhcp_stop"))
        ):
            return {
                "success": False,
                "error": "'dhcp_start' and 'dhcp_stop' are required if dhcp_enabled is true (and purpose is not vlan-only).",
            }

        # Validation for VLAN
        vlan_enabled = validated_data.get("vlan_enabled", False)
        vlan_id = validated_data.get("vlan")
        if vlan_enabled and not vlan_id:
            return {
                "success": False,
                "error": "'vlan' is required when vlan_enabled is true",
            }

        if vlan_id is not None and (int(vlan_id) < 1 or int(vlan_id) > 4094):
            return {"success": False, "error": "'vlan' must be between 1 and 4094."}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="network",
                resource_data=validated_data,
                resource_name=validated_data.get("name"),
                warnings=["Creating a network may temporarily disrupt connectivity"],
            )

        logger.info(f"Attempting to create network '{validated_data['name']}' with purpose '{purpose}'")
        try:
            # Use validated data directly
            network_data = validated_data
            network_data.setdefault("enabled", True)

            # Assume manager returns the created dict or None/False
            created_network = await network_manager.create_network(network_data)
            if created_network and created_network.get("_id"):
                new_network_id = created_network.get("_id")
                logger.info(f"Successfully created network '{validated_data['name']}' with ID {new_network_id}")
                return {
                    "success": True,
                    "site": network_manager._connection.site,
                    "message": f"Network '{validated_data['name']}' created successfully.",
                    "network_id": new_network_id,
                    "details": json.loads(json.dumps(created_network, default=str)),
                }
            else:
                error_msg = (
                    created_network.get("error", "Manager returned failure")
                    if isinstance(created_network, dict)
                    else "Manager returned non-dict or failure"
                )
                logger.error(f"Failed to create network '{validated_data['name']}'. Reason: {error_msg}")
                return {
                    "success": False,
                    "error": f"Failed to create network '{validated_data['name']}'. {error_msg}",
                }
        except Exception as e:
            logger.error(
                f"Error creating network '{validated_data.get('name', 'unknown')}': {e}",
                exc_info=True,
            )
            return {"success": False, "error": str(e)}
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    finally:
        if original_site is not None:
            network_manager._connection.site = original_site


@server.tool(
    name="unifi_list_wlans",
    description="List all configured Wireless LANs (WLANs) on the Unifi Network controller.",
)
async def list_wlans() -> Dict[str, Any]:
    """Lists all WLANs (Wireless SSIDs) configured on the UniFi Network controller.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - site (str): The identifier of the UniFi site queried.
        - count (int): The number of WLANs found.
        - wlans (List[Dict]): A list of WLANs, each containing summary info:
            - id (str): The unique identifier (_id) of the WLAN.
            - name (str): The SSID (name) of the WLAN.
            - enabled (bool): Whether the WLAN is currently active.
            - security (str): The security mode (e.g., 'wpapsk', 'open').
            - network_id (str, optional): The ID of the network this WLAN is associated with.
            - usergroup_id (str, optional): The ID of the user group associated with this WLAN.
        - error (str, optional): An error message if the operation failed.

    Example response (success):
    {
        "success": True,
        "site": "default",
        "count": 1,
        "wlans": [
            {
                "id": "60c7d8e9f0a1b2c3d4e5f6a7",
                "name": "MyWiFi",
                "enabled": True,
                "security": "wpapsk",
                "network_id": "60a8b3c4d5e6f7a8b9c0d1e2",
                "usergroup_id": "_default_"
            }
        ]
    }
    """
    if not parse_permission(config.permissions, "wlan", "read"):
        logger.warning("Permission denied for listing WLANs.")
        return {"success": False, "error": "Permission denied to list WLANs."}
    try:
        wlans = await network_manager.get_wlans()
        # Ensure wlans are dictionaries
        wlans_raw = [w.raw if hasattr(w, "raw") else w for w in wlans]
        formatted_wlans = [
            {
                "id": w.get("_id"),
                "name": w.get("name"),
                "enabled": w.get("enabled"),
                "security": w.get("security"),
                "network_id": w.get("networkconf_id"),  # Map internal key
                "usergroup_id": w.get("usergroup_id"),
            }
            for w in wlans_raw
        ]
        return {
            "success": True,
            "site": network_manager._connection.site,
            "count": len(formatted_wlans),
            "wlans": formatted_wlans,
        }
    except Exception as e:
        logger.error(f"Error listing WLANs: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(name="unifi_get_wlan_details", description="Get details for a specific WLAN by ID.")
async def get_wlan_details(wlan_id: str) -> Dict[str, Any]:
    """Gets the detailed configuration of a specific WLAN (SSID) by its ID.

    Args:
        wlan_id (str): The unique identifier (_id) of the WLAN.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - site (str): The identifier of the UniFi site queried.
        - wlan_id (str): The ID of the WLAN requested.
        - details (Dict[str, Any]): A dictionary containing the raw configuration details
          of the WLAN as returned by the UniFi controller.
        - error (str, optional): An error message if the operation failed (e.g., WLAN not found).

    Example response (success):
    {
        "success": True,
        "site": "default",
        "wlan_id": "60c7d8e9f0a1b2c3d4e5f6a7",
        "details": {
            "_id": "60c7d8e9f0a1b2c3d4e5f6a7",
            "name": "MyWiFi",
            "enabled": True,
            "security": "wpapsk",
            "x_passphrase": "secretpassword",
            "hide_ssid": False,
            "networkconf_id": "60a8b3c4d5e6f7a8b9c0d1e2",
            "usergroup_id": "_default_",
            "site_id": "...",
            # ... other fields
        }
    }
    """
    if not parse_permission(config.permissions, "wlan", "read"):
        logger.warning(f"Permission denied for getting WLAN details ({wlan_id}).")
        return {"success": False, "error": "Permission denied to get WLAN details."}
    try:
        if not wlan_id:
            return {"success": False, "error": "wlan_id is required"}
        wlan = await network_manager.get_wlan_details(wlan_id)
        if wlan:
            return {
                "success": True,
                "site": network_manager._connection.site,
                "wlan_id": wlan_id,
                "details": json.loads(json.dumps(wlan, default=str)),
            }
        else:
            return {"success": False, "error": f"WLAN with ID '{wlan_id}' not found."}
    except Exception as e:
        logger.error(f"Error getting WLAN details for {wlan_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_wlan",
    description="Update specific fields of an existing WLAN (SSID). Requires confirmation.",
    permission_category="wlans",
    permission_action="update",
)
async def update_wlan(wlan_id: str, update_data: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Updates specific fields of an existing WLAN (Wireless SSID).

    Allows modifying properties like SSID name, security settings, password,
    enabled state, network association, etc. Only provided fields are updated.
    Requires confirmation.

    Args:
        wlan_id (str): The unique identifier (_id) of the WLAN to update.
        update_data (Dict[str, Any]): Dictionary of fields to update.
            Allowed fields (all optional):
            - name (string): New SSID name.
            - security (string): New security mode ("open", "wpapsk", "wpa2-psk", etc.).
            - x_passphrase (string): New password (required if security is not "open").
            - enabled (boolean): New enabled state.
            - hide_ssid (boolean): New SSID hiding state.
            - guest_policy (boolean): Make this a guest network.
            - usergroup_id (string): New user group ID.
            - networkconf_id (string): New network configuration ID (associates WLAN with network).
            # Add other relevant fields from WLANSchema if needed
        confirm (bool): Must be set to `True` to execute. Defaults to `False`.

    Returns:
        Dict: Success status, ID, updated fields, details, or error message.
        Example (success):
        {
            "success": True,
            "wlan_id": "60c7d8e9f0a1b2c3d4e5f6a7",
            "updated_fields": ["name", "enabled", "x_passphrase"],
            "details": { ... updated WLAN details ... }
        }
    """
    if not parse_permission(config.permissions, "wlan", "update"):
        logger.warning(f"Permission denied for updating WLAN ({wlan_id}).")
        return {"success": False, "error": "Permission denied to update WLAN."}

    if not wlan_id:
        return {"success": False, "error": "wlan_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    # Validate the update data
    is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("wlan_update", update_data)
    if not is_valid:
        logger.warning(f"Invalid WLAN update data for ID {wlan_id}: {error_msg}")
        return {"success": False, "error": f"Invalid update data: {error_msg}"}

    if not validated_data:
        logger.warning(f"WLAN update data for ID {wlan_id} is empty after validation.")
        return {
            "success": False,
            "error": "Update data is effectively empty or invalid.",
        }

    # Fetch current state for preview
    current = await network_manager.get_wlan_details(wlan_id)
    if not current:
        return {"success": False, "error": "WLAN not found"}

    if not confirm and not should_auto_confirm():
        return update_preview(
            resource_type="wlan",
            resource_id=wlan_id,
            resource_name=current.get("name"),
            current_state=current,
            updates=validated_data,
        )

    # Basic cross-field validation for password
    if "security" in validated_data and validated_data["security"] != "open" and "x_passphrase" not in validated_data:
        # Check existing state? Or require passphrase if changing security?
        pass  # Let manager handle merge/API requirements

    updated_fields_list = list(validated_data.keys())
    logger.info(f"Attempting to update WLAN '{wlan_id}' with fields: {', '.join(updated_fields_list)}")
    try:
        # *** Assumption: Need network_manager.update_wlan(wlan_id, validated_data) ***
        # This method needs implementation in NetworkManager.
        success = await network_manager.update_wlan(wlan_id, validated_data)
        error_message_detail = "Manager method update_wlan might not be fully implemented for partial updates."

        if success:
            updated_wlan = await network_manager.get_wlan_details(wlan_id)
            logger.info(f"Successfully updated WLAN ({wlan_id})")
            return {
                "success": True,
                "wlan_id": wlan_id,
                "updated_fields": updated_fields_list,
                "details": json.loads(json.dumps(updated_wlan, default=str)),
            }
        else:
            logger.error(f"Failed to update WLAN ({wlan_id}). {error_message_detail}")
            wlan_after_update = await network_manager.get_wlan_details(wlan_id)
            return {
                "success": False,
                "wlan_id": wlan_id,
                "error": f"Failed to update WLAN ({wlan_id}). Check server logs. {error_message_detail}",
                "details_after_attempt": json.loads(json.dumps(wlan_after_update, default=str)),
            }

    except Exception as e:
        logger.error(f"Error updating WLAN {wlan_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_wlan",
    description=("Create a new Wireless LAN (WLAN/SSID) with schema validation. Requires confirmation."),
    permission_category="wlans",
    permission_action="create",
)
async def create_wlan(wlan_data: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Create a new WLAN (SSID) with comprehensive validation.

    Args:
        wlan_data (Dict[str, Any]): WLAN configuration data
        confirm (bool): Must be set to `True` to execute. Defaults to `False`.

    Required parameters in wlan_data:
    - name (string): Name of the wireless network (SSID)
    - security (string): Security protocol ("open", "wpa-psk", "wpa2-psk", etc.)

    If security is not "open":
    - x_passphrase (string): Password for the wireless network

    Optional parameters in wlan_data:
    - enabled (boolean): Whether the network is enabled (default: true)
    - hide_ssid (boolean): Whether to hide the SSID (default: false)
    - guest_policy (boolean): Whether this is a guest network (default: false)
    - usergroup_id (string): User group ID (default: default group)
    - networkconf_id (string): Network configuration ID to associate with (default: default LAN)

    Example:
    {
        "name": "GuestWiFi",
        "security": "open",
        "enabled": true,
        "guest_policy": true,
        "networkconf_id": "60a8b3c4d5e6f7a8b9c0d1e4" # Associate with guest network
    }

    Returns:
    - success (boolean): Whether the operation succeeded
    - wlan_id (string): ID of the created WLAN if successful
    - details (object): Details of the created WLAN
    - error (string): Error message if unsuccessful
    """
    if not parse_permission(config.permissions, "wlan", "create"):
        logger.warning("Permission denied for creating WLAN.")
        return {"success": False, "error": "Permission denied to create WLAN."}

    # Moved imports
    from src.validator_registry import UniFiValidatorRegistry

    # Validate the input
    is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("wlan", wlan_data)
    if not is_valid:
        logger.warning(f"Invalid WLAN data: {error_msg}")
        return {"success": False, "error": error_msg}

    # Required fields check
    required_fields = ["name", "security"]
    missing_fields = [field for field in required_fields if field not in validated_data]
    if missing_fields:
        error = f"Missing required fields: {', '.join(missing_fields)}"
        logger.warning(error)
        return {"success": False, "error": error}

    # Check passphrase requirement
    if validated_data.get("security") != "open" and not validated_data.get("x_passphrase"):
        return {
            "success": False,
            "error": "'x_passphrase' is required when security is not 'open'",
        }

    if not confirm and not should_auto_confirm():
        return create_preview(
            resource_type="wlan",
            resource_data=validated_data,
            resource_name=validated_data.get("name"),
            warnings=["Creating a WLAN may temporarily affect wireless connectivity"],
        )

    logger.info(f"Attempting to create WLAN '{validated_data['name']}' with security '{validated_data['security']}'")
    try:
        # Pass validated data directly to manager
        wlan_payload = validated_data
        wlan_payload.setdefault("enabled", True)

        created_wlan = await network_manager.create_wlan(wlan_payload)

        if created_wlan and created_wlan.get("_id"):
            new_wlan_id = created_wlan.get("_id")
            logger.info(f"Successfully created WLAN '{validated_data['name']}' with ID {new_wlan_id}")
            return {
                "success": True,
                "site": network_manager._connection.site,
                "message": f"WLAN '{validated_data['name']}' created successfully.",
                "wlan_id": new_wlan_id,
                "details": json.loads(json.dumps(created_wlan, default=str)),
            }
        else:
            error_msg = (
                created_wlan.get("error", "Manager returned failure")
                if isinstance(created_wlan, dict)
                else "Manager returned non-dict or failure"
            )
            logger.error(f"Failed to create WLAN '{validated_data['name']}'. Reason: {error_msg}")
            return {
                "success": False,
                "error": f"Failed to create WLAN '{validated_data['name']}'. {error_msg}",
            }

    except Exception as e:
        logger.error(
            f"Error creating WLAN '{validated_data.get('name', 'unknown')}': {e}",
            exc_info=True,
        )
        return {"success": False, "error": str(e)}
