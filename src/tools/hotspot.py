"""
Unifi Network MCP hotspot tools.

This module provides MCP tools to interact with a Unifi Network Controller's hotspot functions,
including managing hotspot configurations, vouchers, and guest authentication.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, hotspot_manager, server, system_manager
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
    name="unifi_list_hotspot_configs",
    description="List all hotspot configurations on the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_hotspot_configs(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing hotspot configurations with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with hotspot configurations list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        configs = await hotspot_manager.get_hotspot_configs(site=site_slug)

        # Convert HotspotConfig objects to plain dictionaries
        configs_raw = [c.raw if hasattr(c, "raw") else c for c in configs]

        return inject_site_metadata({
            "success": True,
            "count": len(configs_raw),
            "hotspot_configs": configs_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing hotspot configurations: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_hotspot_config_details",
    description="Get detailed information about a specific hotspot configuration by ID. Supports multi-site with optional site parameter.",
)
async def get_hotspot_config_details(config_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting hotspot configuration details with multi-site support.

    Args:
        config_id: The _id of the hotspot configuration
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with hotspot configuration details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        config = await hotspot_manager.get_hotspot_config_details(config_id, site=site_slug)
        if config:
            config_raw = config.raw if hasattr(config, "raw") else config
            return inject_site_metadata({
                "success": True,
                "hotspot_config": config_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Hotspot configuration with ID {config_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting hotspot configuration details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_hotspot_config",
    description="Create a new hotspot configuration with validation. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="hotspot",
    permission_action="create",
)
async def create_hotspot_config(config_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for creating hotspot configuration with multi-site support.

    Args:
        config_data: Hotspot configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "hotspot", "create"):
        logger.warning("Permission denied for creating hotspot configuration.")
        return {"success": False, "error": "Permission denied to create hotspot configuration."}

    if not config_data:
        return {"success": False, "error": "config_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the configuration data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("hotspot_config_create", config_data)
        if not is_valid:
            logger.warning(f"Invalid hotspot configuration create data: {error_msg}")
            return {"success": False, "error": f"Invalid hotspot configuration data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="hotspot_config",
                resource_name=validated_data.get("name", "Unknown"),
                resource_data=validated_data,
            )

        # Create the hotspot configuration
        result = await hotspot_manager.create_hotspot_config(validated_data, site=site_slug)
        if result:
            return inject_site_metadata({
                "success": True,
                "config_id": result.get("_id"),
                "details": result,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to create hotspot configuration",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating hotspot configuration: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_hotspot_config",
    description="Update a hotspot configuration by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="hotspot",
    permission_action="update",
)
async def update_hotspot_config(config_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for updating hotspot configuration with multi-site support.

    Args:
        config_id: The unique identifier (_id) of the hotspot configuration to update
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
    if not parse_permission(config.permissions, "hotspot", "update"):
        logger.warning(f"Permission denied for updating hotspot configuration ({config_id}).")
        return {"success": False, "error": "Permission denied to update hotspot configuration."}

    if not config_id:
        return {"success": False, "error": "config_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("hotspot_config_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid hotspot configuration update data for ID {config_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        # Fetch current state for preview
        current = await hotspot_manager.get_hotspot_config_details(config_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Hotspot configuration not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="hotspot_config",
                resource_id=config_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        # Perform the update
        success = await hotspot_manager.update_hotspot_config(config_id, validated_data, site=site_slug)
        if success:
            # Fetch updated details
            updated = await hotspot_manager.get_hotspot_config_details(config_id, site=site_slug)
            return inject_site_metadata({
                "success": True,
                "config_id": config_id,
                "updated_fields": list(validated_data.keys()),
                "details": updated,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to update hotspot configuration {config_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating hotspot configuration {config_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
