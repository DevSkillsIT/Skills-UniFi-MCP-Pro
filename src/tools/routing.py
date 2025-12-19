"""
Unifi Network MCP routing tools.

This module provides MCP tools to interact with a Unifi Network Controller's routing functions,
including managing static routes, routing tables, and gateway configurations.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, routing_manager, server, system_manager
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
    name="unifi_list_static_routes",
    description="List all static routes on the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_static_routes(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing static routes with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with static routes list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        routes = await routing_manager.get_static_routes(site=site_slug)

        # Convert StaticRoute objects to plain dictionaries
        routes_raw = [r.raw if hasattr(r, "raw") else r for r in routes]

        return inject_site_metadata({
            "success": True,
            "count": len(routes_raw),
            "static_routes": routes_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing static routes: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_static_route_details",
    description="Get detailed information about a specific static route by ID. Supports multi-site with optional site parameter.",
)
async def get_static_route_details(route_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting static route details with multi-site support.

    Args:
        route_id: The _id of the static route
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with static route details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        route = await routing_manager.get_static_route_details(route_id, site=site_slug)
        if route:
            route_raw = route.raw if hasattr(route, "raw") else route
            return inject_site_metadata({
                "success": True,
                "static_route": route_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Static route with ID {route_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting static route details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_static_route",
    description="Create a new static route with validation. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="routing",
    permission_action="create",
)
async def create_static_route(route_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for creating static route with multi-site support.

    Args:
        route_data: Static route configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "create"):
        logger.warning("Permission denied for creating static route.")
        return {"success": False, "error": "Permission denied to create static route."}

    if not route_data:
        return {"success": False, "error": "route_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the route data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("static_route_create", route_data)
        if not is_valid:
            logger.warning(f"Invalid static route create data: {error_msg}")
            return {"success": False, "error": f"Invalid static route data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="static_route",
                resource_name=validated_data.get("name", f"Route to {validated_data.get('network', 'Unknown')}"),
                resource_data=validated_data,
            )

        # Create the static route
        result = await routing_manager.create_static_route(validated_data, site=site_slug)
        if result:
            return inject_site_metadata({
                "success": True,
                "route_id": result.get("_id"),
                "details": result,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to create static route",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating static route: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_static_route",
    description="Update a static route by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="routing",
    permission_action="update",
)
async def update_static_route(route_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for updating static route with multi-site support.

    Args:
        route_id: The unique identifier (_id) of the static route to update
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
    if not parse_permission(config.permissions, "routing", "update"):
        logger.warning(f"Permission denied for updating static route ({route_id}).")
        return {"success": False, "error": "Permission denied to update static route."}

    if not route_id:
        return {"success": False, "error": "route_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("static_route_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid static route update data for ID {route_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        # Fetch current state for preview
        current = await routing_manager.get_static_route_details(route_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Static route not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="static_route",
                resource_id=route_id,
                resource_name=current.get("name", f"Route to {current.get('network', 'Unknown')}"),
                current_state=current,
                updates=validated_data,
            )

        # Perform the update
        success = await routing_manager.update_static_route(route_id, validated_data, site=site_slug)
        if success:
            # Fetch updated details
            updated = await routing_manager.get_static_route_details(route_id, site=site_slug)
            return inject_site_metadata({
                "success": True,
                "route_id": route_id,
                "updated_fields": list(validated_data.keys()),
                "details": updated,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to update static route {route_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating static route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_delete_static_route",
    description="Delete a static route by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="routing",
    permission_action="delete",
)
async def delete_static_route(route_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for deleting static route with multi-site support.

    Args:
        route_id: The unique identifier (_id) of the static route to delete
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "delete"):
        logger.warning(f"Permission denied for deleting static route ({route_id}).")
        return {"success": False, "error": "Permission denied to delete static route."}

    if not route_id:
        return {"success": False, "error": "route_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch current state for preview
        current = await routing_manager.get_static_route_details(route_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Static route not found"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="static_route",
                resource_id=route_id,
                resource_name=current.get("name", f"Route to {current.get('network', 'Unknown')}"),
                resource_data=current,
                warnings=["This will permanently delete the static route"],
            )

        # Delete the static route
        success = await routing_manager.delete_static_route(route_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"Static route {route_id} deleted successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to delete static route {route_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error deleting static route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_enable_static_route",
    description="Enable a static route by ID. Supports multi-site with optional site parameter.",
    permission_category="routing",
    permission_action="update",
)
async def enable_static_route(route_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for enabling static route with multi-site support.

    Args:
        route_id: The _id of the static route to enable
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "update"):
        logger.warning(f"Permission denied for enabling static route ({route_id}).")
        return {"success": False, "error": "Permission denied to enable static route."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await routing_manager.enable_static_route(route_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"Static route {route_id} enabled successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to enable static route {route_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error enabling static route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_disable_static_route",
    description="Disable a static route by ID. Supports multi-site with optional site parameter.",
    permission_category="routing",
    permission_action="update",
)
async def disable_static_route(route_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for disabling static route with multi-site support.

    Args:
        route_id: The _id of the static route to disable
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "update"):
        logger.warning(f"Permission denied for disabling static route ({route_id}).")
        return {"success": False, "error": "Permission denied to disable static route."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await routing_manager.disable_static_route(route_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"Static route {route_id} disabled successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to disable static route {route_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error disabling static route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
