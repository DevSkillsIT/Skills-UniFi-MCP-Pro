"""
Unifi Network MCP device management tools.

This module provides MCP tools to manage devices in a Unifi Network Controller.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List

print("🔍 [DEBUG] devices.py module loading...")

from src.runtime import config, device_manager, server, system_manager
from src.utils.confirmation import create_preview, preview_response, should_auto_confirm, toggle_preview, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import resolve_site_context, inject_site_metadata
from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_devices",
    description="List devices adopted by the Unifi Network controller. Optimized for token efficiency with summary mode by default.",
)
async def list_devices(
    device_type: str = "all",
    summary: bool = True,
    limit: int = 20,
    site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for listing devices with token-efficient defaults.

    Args:
        device_type: Filter by device type (all, ap, switch, gateway, pdu)
        summary: Return only essential fields (name, type, status, ip) - DEFAULT: True for token efficiency
        limit: Maximum number of devices to return (default: 20, max: 100)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with optimized device list and metadata
    """
    try:
        print("🔍 [DEBUG] list_devices() starting...")
        
        # Enforce reasonable limits
        limit = min(max(1, limit), 100)
        
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        print(f"🔍 [DEBUG] Resolved site: {site_slug}")

        devices = await device_manager.get_devices(site=site_slug)
        print(f"🔍 [DEBUG] Got {len(devices)} devices from controller")

        # Convert Device objects to plain dictionaries
        devices_raw = [d.raw if hasattr(d, "raw") else d for d in devices]

        # Filter by device type
        if device_type != "all":
            prefix_map = {
                "ap": "uap",
                "switch": ("usw", "usk"),
                "gateway": ("ugw", "udm", "uxg"),
                "pdu": "usp",
            }
            prefixes = prefix_map.get(device_type)
            if prefixes:
                devices_raw = [d for d in devices_raw if d.get("type", "").startswith(prefixes)]

        # Apply limit
        devices_raw = devices_raw[:limit]

        # Optimized device data
        if summary:
            devices_optimized = []
            for device in devices_raw:
                device_summary = {
                    "name": device.get("name", "Unknown"),
                    "type": device.get("type", "unknown"),
                    "model": device.get("model", ""),
                    "state": device.get("state", "unknown"),
                    "ip": device.get("ip", "N/A"),
                    "mac": device.get("mac", ""),
                }
                devices_optimized.append(device_summary)
        else:
            devices_optimized = devices_raw

        result = {
            "success": True,
            "devices": devices_optimized,
            "count": len(devices_optimized),
            "filters": {
                "device_type": device_type,
                "summary_mode": summary,
                "limit_applied": limit,
            },
            "token_usage": "optimized" if summary else "high"
        }
        
        print(f"🔍 [DEBUG] Returning {len(devices_optimized)} devices")
        return inject_site_metadata(result, site_id, site_name, site_slug)
        
    except Exception as e:
        logger.error(f"🔍 [DEBUG] Error in list_devices: {e}", exc_info=True)
        return inject_site_metadata({
            "success": False,
            "error": str(e),
            "devices": [],
            "count": 0,
        }, site_id if 'site_id' in locals() else None, 
           site_name if 'site_name' in locals() else None, 
           site_slug if 'site_slug' in locals() else None)


@server.tool(
    name="unifi_get_device_details",
    description="Get detailed information for a specific device by MAC address. Supports multi-site with optional site parameter.",
)
async def get_device_details(
    mac_address: str,
    site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for getting device details with multi-site support.

    Args:
        mac_address: MAC address or device name to search for
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        Dict with device details and metadata including site information

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        device_obj = await device_manager.get_device_details(mac_address, site=site_slug)
        if not device_obj:
            return inject_site_metadata({
                "success": False,
                "error": f"Device not found with MAC address: {mac_address}",
                "device": None,
            }, site_id, site_name, site_slug)

        # Convert Device object to plain dictionary
        device_raw = device_obj.raw if hasattr(device_obj, "raw") else device_obj

        # Format device information
        state_map = {
            0: "offline",
            1: "online",
            2: "pending_adoption",
            4: "managed_by_other/adopting",
            5: "provisioning",
            6: "upgrading",
            11: "error/heartbeat_missed",
        }

        device_state = device_raw.get("state", 0)
        device_status_str = state_map.get(device_state, f"unknown_state ({device_state})")

        device_info = {
            "mac": device_raw.get("mac", ""),
            "name": device_raw.get("name", device_raw.get("model", "Unknown")),
            "model": device_raw.get("model", ""),
            "type": device_raw.get("type", ""),
            "ip": device_raw.get("ip", ""),
            "status": device_status_str,
            "uptime": str(timedelta(seconds=device_raw.get("uptime", 0))) if device_raw.get("uptime") else "N/A",
            "last_seen": (
                datetime.fromtimestamp(device_raw.get("last_seen", 0)).isoformat() if device_raw.get("last_seen") else "N/A"
            ),
            "firmware": device_raw.get("version", ""),
            "adopted": device_raw.get("adopted", False),
            "_id": device_raw.get("_id", ""),
        }

        # Add type-specific details
        if device_raw.get("type", "").startswith("uap"):  # Access Points
            device_info["wifi_clients"] = device_raw.get("num_sta", 0)
            device_info["wifi_bands"] = get_wifi_bands(device_raw)
        elif device_raw.get("type", "").startswith(("usw", "usk")):  # Switches
            device_info["ports_total"] = len(device_raw.get("port_table", []))
            device_info["ports_up"] = len([p for p in device_raw.get("port_table", []) if p.get("up", False)])
        elif device_raw.get("type", "").startswith(("ugw", "udm", "uxg")):  # Gateways
            device_info["wan_ip"] = device_raw.get("wan_ip", "N/A")
            device_info["uptime"] = device_raw.get("uptime", 0)

        result = {
            "success": True,
            "device": device_info,
        }

        return inject_site_metadata(result, site_id, site_name, site_slug)
        
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting device details: {e}", exc_info=True)
        return inject_site_metadata({
            "success": False,
            "error": str(e),
            "device": None,
        }, site_id if 'site_id' in locals() else None, 
           site_name if 'site_name' in locals() else None, 
           site_slug if 'site_slug' in locals() else None)


@server.tool(
    name="unifi_reboot_device",
    description="Reboot a specific device by MAC address. Supports multi-site with optional site parameter.",
    permission_category="devices",
    permission_action="update",
)
async def reboot_device(mac_address: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for rebooting a device with multi-site support.

    Args:
        mac_address: MAC address of the device to reboot
        confirm: If True, skip confirmation prompt (requires admin privileges)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with reboot result and metadata including site information

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Get device details first to verify it exists
        device_obj = await device_manager.get_device_details(mac_address, site=site_slug)
        if not device_obj:
            return inject_site_metadata({
                "success": False,
                "error": f"Device not found with MAC address: {mac_address}",
            }, site_id, site_name, site_slug)

        device_raw = device_obj.raw if hasattr(device_obj, "raw") else device_obj
        device_name = device_raw.get("name", "Unknown Device")

        # Create preview for confirmation
        if not confirm and not should_auto_confirm():
            preview = create_preview(
                action="reboot",
                target=f"device '{device_name}' ({mac_address})",
                site=site_name or site_slug
            )
            return inject_site_metadata({
                "success": False,
                "requires_confirmation": True,
                "preview": preview,
                "message": "Please confirm the device reboot operation"
            }, site_id, site_name, site_slug)

        # Execute reboot
        success = await device_manager.reboot_device(mac_address, site=site_slug)

        result = {
            "success": success,
            "device_name": device_name,
            "mac_address": mac_address,
            "action": "reboot",
        }

        if success:
            result["message"] = f"Device '{device_name}' reboot initiated successfully"
        else:
            result["error"] = f"Failed to reboot device '{device_name}'"

        return inject_site_metadata(result, site_id, site_name, site_slug)
        
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error rebooting device: {e}", exc_info=True)
        return inject_site_metadata({
            "success": False,
            "error": str(e),
        }, site_id if 'site_id' in locals() else None, 
           site_name if 'site_name' in locals() else None, 
           site_slug if 'site_slug' in locals() else None)


@server.tool(
    name="unifi_adopt_device",
    description="Adopt a pending device into the Unifi Network by MAC address. Supports multi-site with optional site parameter.",
    permission_category="devices",
    permission_action="create",
)
async def adopt_device(mac_address: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for adopting a device with multi-site support.

    Args:
        mac_address: MAC address of the device to adopt
        confirm: If True, skip confirmation prompt (requires admin privileges)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with adoption result and metadata including site information

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Create preview for confirmation
        if not confirm and not should_auto_confirm():
            preview = create_preview(
                action="adopt",
                target=f"device with MAC {mac_address}",
                site=site_name or site_slug
            )
            return inject_site_metadata({
                "success": False,
                "requires_confirmation": True,
                "preview": preview,
                "message": "Please confirm the device adoption operation"
            }, site_id, site_name, site_slug)

        # Execute adoption
        success = await device_manager.adopt_device(mac_address, site=site_slug)

        result = {
            "success": success,
            "mac_address": mac_address,
            "action": "adopt",
        }

        if success:
            result["message"] = f"Device with MAC {mac_address} adopted successfully"
        else:
            result["error"] = f"Failed to adopt device with MAC {mac_address}"

        return inject_site_metadata(result, site_id, site_name, site_slug)
        
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error adopting device: {e}", exc_info=True)
        return inject_site_metadata({
            "success": False,
            "error": str(e),
        }, site_id if 'site_id' in locals() else None, 
           site_name if 'site_name' in locals() else None, 
           site_slug if 'site_slug' in locals() else None)
