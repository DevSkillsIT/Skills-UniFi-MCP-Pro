"""Unifi Network MCP configuration tools.

Registration happens at import time through the `@server.tool` decorator, the
same as every other tool module. The previous version wrapped its tool in a
`register_config_tools()` function that nothing ever called, so the tool was
never registered -- and the body it would have registered returned a hardcoded
placeholder under `success: true`.
"""

import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import server, system_manager
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_get_site_settings",
    description="Configurações gerais do site UniFi Network — código de país, fuso horário, parâmetros de monitoramento de conectividade e demais ajustes de nível de site. Use quando precisar consultar settings globais do site, verificar o fuso horário configurado ou auditar parâmetros de monitoramento. Retorna o objeto de configuração do site indicado no controlador UniFi.",
)
async def get_site_settings(site: Optional[str] = None) -> Dict[str, Any]:
    """Read the site-level settings object.

    Args:
        site: Site slug or display name. Settings are per-site, so the site is
            resolved and reported back in the response metadata.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        settings = await system_manager.get_site_settings(site=site_slug)
        if not settings or not settings.get("sections"):
            return inject_site_metadata(
                {"success": False, "error": "Controller returned no site settings."},
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": True,
                "section_count": settings.get("section_count", 0),
                "settings": settings.get("sections", {}),
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting site settings: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
