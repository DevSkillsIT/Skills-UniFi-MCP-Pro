"""
Unifi Network MCP events tools.

This module provides MCP tools to interact with a Unifi Network Controller's events functions,
including retrieving system events, alerts, and notifications.
Supports multi-site operations with optional site parameter.
"""

import logging
import os
from typing import Any, Dict, Optional, List

from src.runtime import config, event_manager, server, system_manager
from src.utils.permissions import parse_permission
from src.utils.site_context import resolve_site_context, inject_site_metadata
from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_events",
    description="List events from the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_events(limit: int = 100, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing events with multi-site support.

    Args:
        limit: Maximum number of events to return (default: 100)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with events list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        events = await events_manager.get_events(limit=limit, site=site_slug)

        # Convert Event objects to plain dictionaries
        events_raw = [e.raw if hasattr(e, "raw") else e for e in events]

        return inject_site_metadata({
            "success": True,
            "count": len(events_raw),
            "events": events_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing events: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_event_details",
    description="Get detailed information about a specific event by ID. Supports multi-site with optional site parameter.",
)
async def get_event_details(event_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting event details with multi-site support.

    Args:
        event_id: The _id of the event
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with event details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        event = await events_manager.get_event_details(event_id, site=site_slug)
        if event:
            event_raw = event.raw if hasattr(event, "raw") else event
            return inject_site_metadata({
                "success": True,
                "event": event_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Event with ID {event_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting event details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_list_alerts",
    description="List alerts from the Unifi Network controller. Supports multi-site with optional site parameter.",
)
async def list_alerts(limit: int = 100, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing alerts with multi-site support.

    Args:
        limit: Maximum number of alerts to return (default: 100)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with alerts list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        alerts = await events_manager.get_alerts(limit=limit, site=site_slug)

        # Convert Alert objects to plain dictionaries
        alerts_raw = [a.raw if hasattr(a, "raw") else a for a in alerts]

        return inject_site_metadata({
            "success": True,
            "count": len(alerts_raw),
            "alerts": alerts_raw,
        }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing alerts: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_alert_details",
    description="Get detailed information about a specific alert by ID. Supports multi-site with optional site parameter.",
)
async def get_alert_details(alert_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting alert details with multi-site support.

    Args:
        alert_id: The _id of the alert
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with alert details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        alert = await events_manager.get_alert_details(alert_id, site=site_slug)
        if alert:
            alert_raw = alert.raw if hasattr(alert, "raw") else alert
            return inject_site_metadata({
                "success": True,
                "alert": alert_raw,
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Alert with ID {alert_id} not found",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting alert details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_dismiss_alert",
    description="Dismiss an alert by ID. Supports multi-site with optional site parameter.",
    permission_category="events",
    permission_action="update",
)
async def dismiss_alert(alert_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for dismissing alert with multi-site support.

    Args:
        alert_id: The _id of the alert to dismiss
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "events", "update"):
        logger.warning(f"Permission denied for dismissing alert ({alert_id}).")
        return {"success": False, "error": "Permission denied to dismiss alert."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await events_manager.dismiss_alert(alert_id, site=site_slug)
        if success:
            return inject_site_metadata({
                "success": True,
                "message": f"Alert {alert_id} dismissed successfully",
            }, site_id, site_name, site_slug)
        else:
            return inject_site_metadata({
                "success": False,
                "error": f"Failed to dismiss alert {alert_id}",
            }, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error dismissing alert {alert_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
