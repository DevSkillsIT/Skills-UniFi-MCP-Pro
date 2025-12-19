"""
Unifi Network MCP VPN tools.

This module provides MCP tools to interact with a Unifi Network Controller's VPN functions,
including managing VPN configurations, site-to-site VPNs, and client VPNs.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, vpn_manager, server, system_manager
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
    name="unifi_list_vpn_configs",
    description="List all VPN configurations on the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_vpn_configs(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing VPN configurations with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with VPN configurations list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        configs = await vpn_manager.get_vpn_configs(site=site_slug)

        # Convert VPNConfig objects to plain dictionaries
        configs_raw = [c.raw if hasattr(c, "raw") else c for c in configs]

        return inject_site_metadata({
            "success": True,
            "count": len(configs_raw),
            "vpn_configs": configs_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing VPN configurations: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_vpn_config_details",
    description="Get detailed information about a specific VPN configuration by ID. Supports multi-site with optional site parameter.",
)
async def get_vpn_config_details(config_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting VPN configuration details with multi-site support.

    Args:
        config_id: The _id of the VPN configuration
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with VPN configuration details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        config = await vpn_manager.get_vpn_config_details(config_id, site=site_slug)
        if config:
            config_raw = config.raw if hasattr(config, "raw") else config
            return inject_site_metadata({
                "success": True,
                "vpn_config": config_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"VPN configuration with ID {config_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting VPN configuration details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_vpn_config",
    description="Create a new VPN configuration with validation. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="vpn",
    permission_action="create",
)
async def create_vpn_config(config_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for creating VPN configuration with multi-site support.

    Args:
        config_data: VPN configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "vpn", "create"):
        logger.warning("Permission denied for creating VPN configuration.")
        return {"success": False, "error": "Permission denied to create VPN configuration."}

    if not config_data:
        return {"success": False, "error": "config_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the configuration data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("vpn_config_create", config_data)
        if not is_valid:
            logger.warning(f"Invalid VPN configuration create data: {error_msg}")
            return {"success": False, "error": f"Invalid VPN configuration data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="vpn_config",
                resource_name=validated_data.get("name", "Unknown"),
                resource_data=validated_data,
            )

        # Create the VPN configuration
        result = await vpn_manager.create_vpn_config(validated_data, site=site_slug)
        if result:
            return inject_site_metadata({
                "success": True,
                "config_id": result.get("_id"),
                "details": result,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to create VPN configuration",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating VPN configuration: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_vpn_config",
    description="Update a VPN configuration by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="vpn",
    permission_action="update",
)
async def update_vpn_config(config_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for updating VPN configuration with multi-site support.

    Args:
        config_id: The unique identifier (_id) of the VPN configuration to update
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
    if not parse_permission(config.permissions, "vpn", "update"):
        logger.warning(f"Permission denied for updating VPN configuration ({config_id}).")
        return {"success": False, "error": "Permission denied to update VPN configuration."}

    if not config_id:
        return {"success": False, "error": "config_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("vpn_config_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid VPN configuration update data for ID {config_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        # Fetch current state for preview
        current = await vpn_manager.get_vpn_config_details(config_id, site=site_slug)
        if not current:
            return {"success": False, "error": "VPN configuration not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="vpn_config",
                resource_id=config_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        # Perform the update
        success = await vpn_manager.update_vpn_config(config_id, validated_data, site=site_slug)
        if success:
            # Fetch updated details
            updated = await vpn_manager.get_vpn_config_details(config_id, site=site_slug)
            return inject_site_metadata({
                "success": True,
                "config_id": config_id,
                "updated_fields": list(validated_data.keys()),
                "details": updated,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to update VPN configuration {config_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating VPN configuration {config_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_delete_vpn_config",
    description="Delete a VPN configuration by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="vpn",
    permission_action="delete",
)
async def delete_vpn_config(config_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for deleting VPN configuration with multi-site support.

    Args:
        config_id: The unique identifier (_id) of the VPN configuration to delete
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "vpn", "delete"):
        logger.warning(f"Permission denied for deleting VPN configuration ({config_id}).")
        return {"success": False, "error": "Permission denied to delete VPN configuration."}

    if not config_id:
        return {"success": False, "error": "config_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch current state for preview
        current = await vpn_manager.get_vpn_config_details(config_id, site=site_slug)
        if not current:
            return {"success": False, "error": "VPN configuration not found"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="vpn_config",
                resource_id=config_id,
                resource_name=current.get("name"),
                resource_data=current,
                warnings=["This will permanently delete the VPN configuration"],
            )

        # Delete the VPN configuration
        success = await vpn_manager.delete_vpn_config(config_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"VPN configuration {config_id} deleted successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to delete VPN configuration {config_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error deleting VPN configuration {config_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_enable_vpn_config",
    description="Enable a VPN configuration by ID. Supports multi-site with optional site parameter.",
    permission_category="vpn",
    permission_action="update",
)
async def enable_vpn_config(config_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for enabling VPN configuration with multi-site support.

    Args:
        config_id: The _id of the VPN configuration to enable
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "vpn", "update"):
        logger.warning(f"Permission denied for enabling VPN configuration ({config_id}).")
        return {"success": False, "error": "Permission denied to enable VPN configuration."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await vpn_manager.enable_vpn_config(config_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"VPN configuration {config_id} enabled successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to enable VPN configuration {config_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error enabling VPN configuration {config_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_disable_vpn_config",
    description="Disable a VPN configuration by ID. Supports multi-site with optional site parameter.",
    permission_category="vpn",
    permission_action="update",
)
async def disable_vpn_config(config_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for disabling VPN configuration with multi-site support.

    Args:
        config_id: The _id of the VPN configuration to disable
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "vpn", "update"):
        logger.warning(f"Permission denied for disabling VPN configuration ({config_id}).")
        return {"success": False, "error": "Permission denied to disable VPN configuration."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await vpn_manager.disable_vpn_config(config_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"VPN configuration {config_id} disabled successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to disable VPN configuration {config_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error disabling VPN configuration {config_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
