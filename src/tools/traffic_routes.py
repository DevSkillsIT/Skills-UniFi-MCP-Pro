"""
Unifi Network MCP traffic routes tools.

This module provides MCP tools to interact with a Unifi Network Controller's traffic routes functions,
including managing traffic routing policies and kill switches.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, traffic_route_manager, server, system_manager
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
    name="unifi_list_traffic_routes",
    description="List all traffic routes on the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_traffic_routes(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing traffic routes with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with traffic routes list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        routes = await traffic_route_manager.get_traffic_routes(site=site_slug)

        # Convert TrafficRoute objects to plain dictionaries
        routes_raw = [r.raw if hasattr(r, "raw") else r for r in routes]

        return inject_site_metadata({
            "success": True,
            "count": len(routes_raw),
            "traffic_routes": routes_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing traffic routes: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_traffic_route_details",
    description="Get detailed information about a specific traffic route by ID. Supports multi-site with optional site parameter.",
)
async def get_traffic_route_details(route_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting traffic route details with multi-site support.

    Args:
        route_id: The _id of the traffic route
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with traffic route details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        route = await traffic_route_manager.get_traffic_route_details(route_id, site=site_slug)
        if route:
            route_raw = route.raw if hasattr(route, "raw") else route
            return inject_site_metadata({
                "success": True,
                "traffic_route": route_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Traffic route with ID {route_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting traffic route details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_traffic_route",
    description="Create a new traffic route with validation. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="traffic_route",
    permission_action="create",
)
async def create_traffic_route(route_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for creating traffic route with multi-site support.

    Args:
        route_data: Traffic route configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "traffic_route", "create"):
        logger.warning("Permission denied for creating traffic route.")
        return {"success": False, "error": "Permission denied to create traffic route."}

    if not route_data:
        return {"success": False, "error": "route_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the route data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("traffic_route_create", route_data)
        if not is_valid:
            logger.warning(f"Invalid traffic route create data: {error_msg}")
            return {"success": False, "error": f"Invalid traffic route data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="traffic_route",
                resource_name=validated_data.get("name", f"Route to {validated_data.get('target', 'Unknown')}"),
                resource_data=validated_data,
            )

        # Create the traffic route
        result = await traffic_route_manager.create_traffic_route(validated_data, site=site_slug)
        if result:
            return inject_site_metadata({
                "success": True,
                "route_id": result.get("_id"),
                "details": result,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to create traffic route",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating traffic route: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_traffic_route",
    description="Update a traffic route by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="traffic_route",
    permission_action="update",
)
async def update_traffic_route(route_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for updating traffic route with multi-site support.

    Args:
        route_id: The unique identifier (_id) of the traffic route to update
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
    if not parse_permission(config.permissions, "traffic_route", "update"):
        logger.warning(f"Permission denied for updating traffic route ({route_id}).")
        return {"success": False, "error": "Permission denied to update traffic route."}

    if not route_id:
        return {"success": False, "error": "route_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("traffic_route_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid traffic route update data for ID {route_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        # Fetch current state for preview
        current = await traffic_route_manager.get_traffic_route_details(route_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Traffic route not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="traffic_route",
                resource_id=route_id,
                resource_name=current.get("name", f"Route to {current.get('target', 'Unknown')}"),
                current_state=current,
                updates=validated_data,
            )

        # Perform the update
        success = await traffic_route_manager.update_traffic_route(route_id, validated_data, site=site_slug)
        if success:
            # Fetch updated details
            updated = await traffic_route_manager.get_traffic_route_details(route_id, site=site_slug)
            return inject_site_metadata({
                "success": True,
                "route_id": route_id,
                "updated_fields": list(validated_data.keys()),
                "details": updated,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to update traffic route {route_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating traffic route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_delete_traffic_route",
    description="Delete a traffic route by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="traffic_route",
    permission_action="delete",
)
async def delete_traffic_route(route_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for deleting traffic route with multi-site support.

    Args:
        route_id: The unique identifier (_id) of the traffic route to delete
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "traffic_route", "delete"):
        logger.warning(f"Permission denied for deleting traffic route ({route_id}).")
        return {"success": False, "error": "Permission denied to delete traffic route."}

    if not route_id:
        return {"success": False, "error": "route_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch current state for preview
        current = await traffic_route_manager.get_traffic_route_details(route_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Traffic route not found"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="traffic_route",
                resource_id=route_id,
                resource_name=current.get("name", f"Route to {current.get('target', 'Unknown')}"),
                resource_data=current,
                warnings=["This will permanently delete the traffic route"],
            )

        # Delete the traffic route
        success = await traffic_route_manager.delete_traffic_route(route_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"Traffic route {route_id} deleted successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to delete traffic route {route_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error deleting traffic route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
