"""
Unifi Network MCP statistics tools.

This module provides MCP tools to interact with a Unifi Network Controller's statistics functions,
including retrieving system metrics, device statistics, and performance data.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, stats_manager, server, system_manager
from src.utils.permissions import parse_permission
from src.utils.site_context import resolve_site_context, inject_site_metadata
from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_get_system_stats",
    description="Get system statistics for the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def get_system_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting system statistics with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with system statistics and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        stats = await stats_manager.get_system_stats(site=site_slug)

        # Convert Stats objects to plain dictionaries
        stats_raw = stats.raw if hasattr(stats, "raw") else stats

        return inject_site_metadata({
            "success": True,
            "system_stats": stats_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting system statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_device_stats",
    description="Get statistics for a specific device by ID. Supports multi-site with optional site parameter.",
)
async def get_device_stats(device_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting device statistics with multi-site support.

    Args:
        device_id: The _id of the device
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with device statistics and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        stats = await stats_manager.get_device_stats(device_id, site=site_slug)
        if stats:
            stats_raw = stats.raw if hasattr(stats, "raw") else stats
            return inject_site_metadata({
                "success": True,
                "device_stats": stats_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Device statistics for ID {device_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting device statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_network_stats",
    description="Get network statistics for all networks. Supports multi-site with optional site parameter.",
)
async def get_network_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting network statistics with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with network statistics and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        stats = await stats_manager.get_network_stats(site=site_slug)

        # Convert NetworkStats objects to plain dictionaries
        stats_raw = [s.raw if hasattr(s, "raw") else s for s in stats]

        return inject_site_metadata({
            "success": True,
            "count": len(stats_raw),
            "network_stats": stats_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting network statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_client_stats",
    description="Get client statistics for connected clients. Supports multi-site with optional site parameter.",
)
async def get_client_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting client statistics with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with client statistics and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        stats = await stats_manager.get_client_stats(site=site_slug)

        # Convert ClientStats objects to plain dictionaries
        stats_raw = [s.raw if hasattr(s, "raw") else s for s in stats]

        return inject_site_metadata({
            "success": True,
            "count": len(stats_raw),
            "client_stats": stats_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting client statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_ap_stats",
    description="Get access point statistics for all APs. Supports multi-site with optional site parameter.",
)
async def get_ap_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting AP statistics with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with AP statistics and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        stats = await stats_manager.get_ap_stats(site=site_slug)

        # Convert APStats objects to plain dictionaries
        stats_raw = [s.raw if hasattr(s, "raw") else s for s in stats]

        return inject_site_metadata({
            "success": True,
            "count": len(stats_raw),
            "ap_stats": stats_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting AP statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_switch_stats",
    description="Get switch statistics for all switches. Supports multi-site with optional site parameter.",
)
async def get_switch_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting switch statistics with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with switch statistics and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        stats = await stats_manager.get_switch_stats(site=site_slug)

        # Convert SwitchStats objects to plain dictionaries
        stats_raw = [s.raw if hasattr(s, "raw") else s for s in stats]

        return inject_site_metadata({
            "success": True,
            "count": len(stats_raw),
            "switch_stats": stats_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting switch statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
