"""
Unifi Network MCP statistics tools.

This module provides MCP tools to interact with a Unifi Network Controller's statistics functions,
including retrieving system metrics, device statistics, and performance data.
Supports multi-site operations with optional site parameter.
"""

import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import server, stats_manager, system_manager
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_get_system_stats",
    description="Estatísticas de sistema do controlador UniFi Network — métricas de desempenho, utilização de recursos e indicadores operacionais do hardware, firmware e serviços. Use quando precisar monitorar performance, auditar recursos ou analisar capacidade. Retorna métricas completas de CPU, memória, disco e uptime no controlador UniFi.",
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

        return inject_site_metadata(
            {
                "success": True,
                "system_stats": stats_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting system statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_device_stats",
    description="Estatísticas de dispositivo UniFi Network específico — métricas de desempenho, tráfego e utilização identificadas por ID único de equipamento, access point ou switch. Use quando precisar monitorar device específico, analisar performance ou diagnosticar problemas. Retorna throughput, clientes conectados e métricas operacionais no controlador UniFi.",
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
            return inject_site_metadata(
                {
                    "success": True,
                    "device_stats": stats_raw,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Device statistics for ID {device_id} not found",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting device statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_network_stats",
    description="Estatísticas de redes do controlador UniFi Network — métricas de tráfego, utilização de banda e performance para todas as VLANs, SSIDs e segmentos configurados. Use quando precisar monitorar networks, analisar throughput ou auditar consumo de banda. Retorna lista completa de métricas por rede no controlador UniFi.",
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

        return inject_site_metadata(
            {
                "success": True,
                "count": len(stats_raw),
                "network_stats": stats_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting network statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_client_stats",
    description="Estatísticas de clientes conectados no controlador UniFi Network — métricas de consumo, throughput e performance para todos os dispositivos ativos em redes wireless, wired ou guest. Use quando precisar monitorar clients, analisar consumo ou identificar top users. Retorna lista completa de métricas por cliente no controlador UniFi.",
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

        return inject_site_metadata(
            {
                "success": True,
                "count": len(stats_raw),
                "client_stats": stats_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting client statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_ap_stats",
    description="Estatísticas de access points do controlador UniFi Network — métricas de performance, clientes conectados e utilização de canais para todos os APs wireless gerenciados. Use quando precisar monitorar APs, analisar cobertura ou diagnosticar RF. Retorna lista completa de métricas por access point no controlador UniFi.",
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

        return inject_site_metadata(
            {
                "success": True,
                "count": len(stats_raw),
                "ap_stats": stats_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting AP statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_switch_stats",
    description="Estatísticas de switches do controlador UniFi Network — métricas de performance, throughput de portas e utilização de uplinks para todos os switches gerenciados. Use quando precisar monitorar switches, analisar tráfego de portas ou diagnosticar conectividade. Retorna lista completa de métricas por switch no controlador UniFi.",
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

        return inject_site_metadata(
            {
                "success": True,
                "count": len(stats_raw),
                "switch_stats": stats_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting switch statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
