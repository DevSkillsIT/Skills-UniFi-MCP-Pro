"""
Unifi Network MCP user groups tools.

This module provides MCP tools to interact with a Unifi Network Controller's user groups functions,
including managing user group configurations, permissions, and settings.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, usergroup_manager, server, system_manager
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
    name="unifi_list_user_groups",
    description="List all user groups on the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_user_groups(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing user groups with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with user groups list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        groups = await usergroup_manager.get_usergroups(site=site_slug)

        # Convert UserGroup objects to plain dictionaries
        groups_raw = [g.raw if hasattr(g, "raw") else g for g in groups]

        return inject_site_metadata({
            "success": True,
            "count": len(groups_raw),
            "user_groups": groups_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing user groups: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_user_group_details",
    description="Get detailed information about a specific user group by ID. Supports multi-site with optional site parameter.",
)
async def get_user_group_details(group_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting user group details with multi-site support.

    Args:
        group_id: The _id of the user group
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with user group details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        group = await usergroup_manager.get_usergroup_details(group_id, site=site_slug)
        if group:
            group_raw = group.raw if hasattr(group, "raw") else group
            return inject_site_metadata({
                "success": True,
                "user_group": group_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"User group with ID {group_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting user group details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_user_group",
    description="Create a new user group with validation. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="usergroups",
    permission_action="create",
)
async def create_user_group(group_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for creating user group with multi-site support.

    Args:
        group_data: User group configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "usergroups", "create"):
        logger.warning("Permission denied for creating user group.")
        return {"success": False, "error": "Permission denied to create user group."}

    if not group_data:
        return {"success": False, "error": "group_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the group data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("usergroup_create", group_data)
        if not is_valid:
            logger.warning(f"Invalid user group create data: {error_msg}")
            return {"success": False, "error": f"Invalid user group data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="user_group",
                resource_name=validated_data.get("name", "Unknown"),
                resource_data=validated_data,
            )

        # Create the user group
        result = await usergroup_manager.create_usergroup(validated_data, site=site_slug)
        if result:
            return inject_site_metadata({
                "success": True,
                "group_id": result.get("_id"),
                "details": result,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": "Failed to create user group",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating user group: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_user_group",
    description="Update a user group by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="usergroups",
    permission_action="update",
)
async def update_user_group(group_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for updating user group with multi-site support.

    Args:
        group_id: The unique identifier (_id) of the user group to update
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
    if not parse_permission(config.permissions, "usergroups", "update"):
        logger.warning(f"Permission denied for updating user group ({group_id}).")
        return {"success": False, "error": "Permission denied to update user group."}

    if not group_id:
        return {"success": False, "error": "group_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("usergroup_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid user group update data for ID {group_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        # Fetch current state for preview
        current = await usergroup_manager.get_usergroup_details(group_id, site=site_slug)
        if not current:
            return {"success": False, "error": "User group not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="user_group",
                resource_id=group_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        # Perform the update
        success = await usergroup_manager.update_usergroup(group_id, validated_data, site=site_slug)
        if success:
            # Fetch updated details
            updated = await usergroup_manager.get_usergroup_details(group_id, site=site_slug)
            return inject_site_metadata({
                "success": True,
                "group_id": group_id,
                "updated_fields": list(validated_data.keys()),
                "details": updated,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to update user group {group_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating user group {group_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_delete_user_group",
    description="Delete a user group by ID. Supports multi-site with optional site parameter. Requires confirmation.",
    permission_category="usergroups",
    permission_action="delete",
)
async def delete_user_group(group_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for deleting user group with multi-site support.

    Args:
        group_id: The unique identifier (_id) of the user group to delete
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "usergroups", "delete"):
        logger.warning(f"Permission denied for deleting user group ({group_id}).")
        return {"success": False, "error": "Permission denied to delete user group."}

    if not group_id:
        return {"success": False, "error": "group_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch current state for preview
        current = await usergroup_manager.get_usergroup_details(group_id, site=site_slug)
        if not current:
            return {"success": False, "error": "User group not found"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="user_group",
                resource_id=group_id,
                resource_name=current.get("name"),
                resource_data=current,
                warnings=["This will permanently delete the user group"],
            )

        # Delete the user group
        success = await usergroup_manager.delete_usergroup(group_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"User group {group_id} deleted successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to delete user group {group_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error deleting user group {group_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
