"""Site context helper for UniFi MCP tools.

Provides standardized site validation, resolution, and metadata injection
for all tools to ensure consistent multi-site behavior.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from .site_resolver import (
    validate_site_parameter,
    resolve_site_identifier,
    validate_site_access,
    map_allowed_sites_to_ids,
)
from ..bootstrap import ALLOWED_SITES

logger = logging.getLogger(__name__)


def _get_allowed_sites() -> Optional[List[str]]:
    """Get list of allowed sites from configuration (UNIFI_SITE/UNIFI_ALLOWED_SITES).

    Returns:
        List of allowed site slugs if whitelist is set, None for ALL-SITES mode.
    """
    if ALLOWED_SITES is None:
        return None  # ALL-SITES mode
    return [s for s in ALLOWED_SITES if s]


async def resolve_site_context(site: Optional[str], system_manager) -> Tuple[str, str, str]:
    """Resolve site parameter to validated site slug and metadata.

    Args:
        site: Optional site name/slug. If None, uses current default site.
        system_manager: SystemManager instance for resolving current site

    Returns:
        Tuple of (site_id, site_name, site_slug) for the resolved site.

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if site is None:
        # Use current connection site as default
        current_site = system_manager._connection.site
        site_info = await resolve_site_identifier(current_site)
        return (site_info["id"], site_info["display_name"], site_info["slug"])

    # Validate site parameter
    site_validated = validate_site_parameter(site)

    # Resolve site identifier
    site_info = await resolve_site_identifier(site_validated)
    site_slug = site_info["slug"]
    site_id = site_info["id"]
    site_name = site_info["display_name"]

    # Validate whitelist access
    allowed_sites_ids = await map_allowed_sites_to_ids(_get_allowed_sites())
    await validate_site_access(site_slug, allowed_sites_ids)

    return (site_id, site_name, site_slug)


def inject_site_metadata(response: Dict[str, Any], site_id: str, site_name: str, site_slug: str) -> Dict[str, Any]:
    """Inject site metadata into tool response.

    Args:
        response: Original tool response
        site_id: Resolved site ID
        site_name: Resolved site name/description
        site_slug: Resolved site slug

    Returns:
        Response with site metadata injected
    """
    if "metadata" not in response:
        response["metadata"] = {}
    
    response["metadata"].update({
        "site_id": site_id,
        "site_name": site_name,
        "site_slug": site_slug,
    })
    
    return response
