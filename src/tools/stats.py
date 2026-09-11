"""Unifi Network MCP statistics tools.

Every tool here is site-scoped: the `site` parameter is resolved, validated
against the whitelist, reported back in the response metadata, and carried into
the controller call.
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
    description="Métricas de recursos e capacidade do site UniFi Network — CPU e memória médias e máximas dos equipamentos adotados, contagem de dispositivos por estado, throughput instantâneo e clientes conectados. Use quando precisar monitorar performance, auditar recursos ou analisar capacidade do site. Retorna versão do controlador, saúde por subsistema e métricas agregadas no controlador UniFi.",
)
async def get_system_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """Resource and capacity metrics for the site.

    Args:
        site: Site slug or display name. Defaults to the configured site.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        stats = await stats_manager.get_system_stats(site=site_slug)
        return inject_site_metadata(
            {"success": True, "system_stats": stats},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting system statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_device_stats",
    description="Estatísticas de um equipamento UniFi Network específico — aceita endereço MAC, _id do controlador ou nome do dispositivo como identificador. Use quando precisar monitorar device específico, analisar performance ou diagnosticar problemas. Retorna snapshot atual com CPU, memória, uptime, clientes e portas, mais série horária de tráfego quando o equipamento é um access point no controlador UniFi.",
)
async def get_device_stats(
    device_id: str, duration_hours: int = 24, site: Optional[str] = None
) -> Dict[str, Any]:
    """Statistics for one device.

    Args:
        device_id: MAC address, controller `_id`, or device name. The response
            reports which form matched under `matched_by`.
        duration_hours: Length of the traffic series window.
        site: Site slug or display name.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        stats = await stats_manager.get_device_stats(device_id, duration_hours=duration_hours, site=site_slug)
        if not stats:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": (
                        f"No device matched '{device_id}' on this site. "
                        "Accepted identifiers: MAC address, controller _id, or device name."
                    ),
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {"success": True, "device_stats": stats},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting device statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_network_stats",
    description="Estatísticas por rede do site UniFi Network — quebra real por VLAN e segmento com contagem de clientes com fio, sem fio e visitantes, além de tráfego acumulado por rede. Use quando precisar comparar consumo entre VLANs, auditar distribuição de clientes ou dimensionar segmentos. Retorna uma linha por rede configurada mais um balde explícito para clientes que o controlador não atribuiu a nenhuma rede.",
)
async def get_network_stats(site: Optional[str] = None, include_site_series: bool = False) -> Dict[str, Any]:
    """Per-network breakdown for the site.

    Args:
        site: Site slug or display name.
        include_site_series: Also return the hourly site-wide series. Kept
            separate because it is not a per-network figure and inflates the
            response.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        networks = await stats_manager.get_network_stats(site=site_slug)

        result: Dict[str, Any] = {
            "success": True,
            "count": len(networks),
            "network_stats": networks,
            "traffic_basis": "Per-network byte counters are cumulative since each client associated.",
        }
        if include_site_series:
            result["site_series"] = await stats_manager.get_site_series(site=site_slug)
            result["site_series_attrs"] = (
                "Only wlan_bytes, num_sta, lan-num_sta and wlan-num_sta are served at site level; "
                "the controller drops rx_bytes/tx_bytes from this report."
            )
        return inject_site_metadata(result, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting network statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_client_stats",
    description="Série horária de tráfego de um cliente específico no controlador UniFi Network — consumo de download e upload por hora identificado pelo endereço MAC. Use quando precisar investigar consumo de um dispositivo, montar histórico de uso ou identificar picos. Retorna uma linha por hora da janela solicitada no controlador UniFi.",
)
async def get_client_stats(
    client_mac: str, duration_hours: int = 24, site: Optional[str] = None
) -> Dict[str, Any]:
    """Hourly traffic series for one client.

    Args:
        client_mac: MAC address of the client. Required -- the controller's
            report endpoint has no "all clients" mode.
        duration_hours: Length of the window.
        site: Site slug or display name.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        rows = await stats_manager.get_client_stats(client_mac, duration_hours=duration_hours, site=site_slug)
        return inject_site_metadata(
            {
                "success": True,
                "client_mac": client_mac,
                "count": len(rows),
                "client_stats": rows,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting client statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_ap_stats",
    description="Estatísticas dos access points do site UniFi Network — por AP, com CPU, memória, uptime, clientes conectados, canal, utilização de canal e potência de transmissão por rádio, mais série horária de tráfego. Use quando precisar monitorar APs, analisar cobertura ou diagnosticar RF. Retorna uma linha por access point adotado no controlador UniFi.",
)
async def get_ap_stats(duration_hours: int = 24, site: Optional[str] = None) -> Dict[str, Any]:
    """Per-access-point statistics.

    Args:
        duration_hours: Length of the traffic series window.
        site: Site slug or display name.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        aps = await stats_manager.get_ap_stats(duration_hours=duration_hours, site=site_slug)
        return inject_site_metadata(
            {"success": True, "count": len(aps), "ap_stats": aps},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting AP statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_switch_stats",
    description="Estatísticas dos switches do site UniFi Network — por switch, com CPU, memória, uptime, total de portas, portas ativas, portas com PoE e contadores de tráfego por porta. Use quando precisar monitorar switches, analisar tráfego de portas ou diagnosticar conectividade. Retorna snapshot ao vivo, pois o controlador não serve relatório horário para switches.",
)
async def get_switch_stats(site: Optional[str] = None) -> Dict[str, Any]:
    """Per-switch statistics.

    Args:
        site: Site slug or display name.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        switches = await stats_manager.get_switch_stats(site=site_slug)
        return inject_site_metadata(
            {
                "success": True,
                "count": len(switches),
                "switch_stats": switches,
                "series_availability": "Live snapshot only; the controller serves an hourly report for access points, not switches.",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting switch statistics: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
