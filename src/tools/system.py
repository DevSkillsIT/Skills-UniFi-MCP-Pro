"""
Unifi Network MCP system tools.

This module provides MCP tools to interact with a Unifi Network Controller's system functions,
including system information, health checks, and administrative operations.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

print("🔍 [DEBUG] system.py module loading...")

from src.runtime import config, system_manager, server, system_manager as system_mgr
from src.utils.permissions import parse_permission
from src.utils.site_context import resolve_site_context, inject_site_metadata
from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)

print("🔍 [DEBUG] system.py imports completed")

logger = logging.getLogger(__name__)

print("🔍 [DEBUG] system.py logger initialized")


@server.tool(
    name="list_sites",
    description="List all available sites from the UniFi Network controller. Returns site IDs, names, and descriptions.",
)
async def list_sites() -> Dict[str, Any]:
    """
    List all available sites from the UniFi Network controller.
    
    Returns:
        Dict with list of sites and their information
    """
    try:
        logger.info("🔍 [DEBUG] Starting list_sites function...")
        
        # Use the real system manager to get sites from controller
        sites = await system_manager.list_sites()
        
        result = {
            "success": True,
            "sites": sites,
            "count": len(sites),
        }
        logger.info(f"🔍 [DEBUG] Returning {len(sites)} sites from controller")
        return result
        
    except Exception as e:
        logger.error(f"🔍 [DEBUG] Error in list_sites: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "sites": [],
            "count": 0,
        }


@server.tool(
    name="unifi_get_system_info",
    description="Get system information from the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def get_system_info(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting system information with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with system information and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # System info is controller-wide, not site-specific, so no site resolution needed
        info = await system_manager.get_system_info()

        # Convert SystemInfo objects to plain dictionaries
        info_raw = info.raw if hasattr(info, "raw") else info

        # System info is controller-wide, so no site metadata injection
        return {
            "success": True,
            "system_info": info_raw,
        }
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        logger.error(f"Error getting system information: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_health_check",
    description="Get health check status from the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def get_health_check(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting health check with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with health check status and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        health = await system_manager.get_health_check(site=site_slug)

        # Convert HealthCheck objects to plain dictionaries
        health_raw = health.raw if hasattr(health, "raw") else health

        return inject_site_metadata({
            "success": True,
            "health_check": health_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting health check: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_restart_controller",
    description="Restart the Unifi Network controller. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="system",
    permission_action="admin",
)
async def restart_controller(confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for restarting controller with multi-site support.

    Args:
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "system", "admin"):
        logger.warning("Permission denied for restarting controller.")
        return {"success": False, "error": "Permission denied to restart controller."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        if not confirm:
            return inject_site_metadata({
                "success": False,
                "error": "This operation requires confirmation. Set confirm=True to proceed.",
                "warning": "This will restart the Unifi Network controller and may temporarily interrupt service.",
            }, site_id, site_name, site_slug)

        # Restart the controller
        success = await system_manager.restart_controller(site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": "Controller restart initiated successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to restart controller",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error restarting controller: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_system_status",
    description="Get overall system status from the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def get_system_status(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting system status with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with system status and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        status = await system_manager.get_system_status(site=site_slug)

        # Convert SystemStatus objects to plain dictionaries
        status_raw = status.raw if hasattr(status, "raw") else status

        return inject_site_metadata({
            "success": True,
            "system_status": status_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting system status: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
