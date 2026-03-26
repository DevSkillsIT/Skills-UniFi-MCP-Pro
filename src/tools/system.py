"""
Unifi Network MCP system tools.

This module provides MCP tools to interact with a Unifi Network Controller's system functions,
including system information, health checks, and administrative operations.
Supports multi-site operations with optional site parameter.
"""

import logging
from typing import Any, Dict, Optional

print("🔍 [DEBUG] system.py module loading...")

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import config, server, system_manager
from src.runtime import system_manager as system_mgr
from src.utils.confirmation import should_auto_confirm, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context

print("🔍 [DEBUG] system.py imports completed")

logger = logging.getLogger(__name__)

print("🔍 [DEBUG] system.py logger initialized")


@server.tool(
    name="list_sites",
    description="Sites disponíveis no controlador UniFi Network — identificadores, nomes e descrições de todos os sites gerenciados para operação multi-site. Use quando precisar listar sites, auditar ambientes ou selecionar site de operação. Retorna lista completa de sites com ID, nome e descrição no controlador UniFi.",
)
async def list_sites() -> Dict[str, Any]:
    """
    List all available sites from the UniFi Network controller.

    Returns:
        Dict with list of sites and their information
    """
    try:
        logger.info("🔍 [DEBUG] Starting list_sites function...")

        # Use the real system manager to get sites from controller
        sites = await system_manager.list_sites()

        result = {
            "success": True,
            "sites": sites,
            "count": len(sites),
        }
        logger.info(f"🔍 [DEBUG] Returning {len(sites)} sites from controller")
        return result

    except Exception as e:
        logger.error(f"🔍 [DEBUG] Error in list_sites: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "sites": [],
            "count": 0,
        }


@server.tool(
    name="unifi_get_system_info",
    description="Informações de sistema do controlador UniFi Network — dados de hardware, versão de firmware, modelo e especificações técnicas do equipamento. Use quando precisar consultar versão instalada, verificar modelo do controlador ou auditar configuração de sistema. Retorna detalhes completos do hardware e software no controlador UniFi.",
)
async def get_system_info(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting system information with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with system information and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # System info is controller-wide, not site-specific, so no site resolution needed
        info = await system_manager.get_system_info()

        # Convert SystemInfo objects to plain dictionaries
        info_raw = info.raw if hasattr(info, "raw") else info

        # System info is controller-wide, so no site metadata injection
        return {
            "success": True,
            "system_info": info_raw,
        }
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        logger.error(f"Error getting system information: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_health_check",
    description="Status de saúde do controlador UniFi Network — verificação de componentes, serviços ativos e métricas de desempenho do sistema. Use quando precisar monitorar health do controlador, verificar serviços ou diagnosticar problemas operacionais. Retorna status de todos os subsistemas no controlador UniFi.",
)
async def get_health_check(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting health check with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with health check status and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        health = await system_manager.get_health_check(site=site_slug)

        # Convert HealthCheck objects to plain dictionaries
        health_raw = health.raw if hasattr(health, "raw") else health

        return inject_site_metadata(
            {
                "success": True,
                "health_check": health_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting health check: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_restart_controller",
    description="Reinicialização do controlador UniFi Network com confirmação obrigatória — reboot completo de sistema, serviços e processos gerenciados. Use quando precisar aplicar configurações críticas, resolver problemas de sistema ou executar manutenção programada. Executa restart seguro do controlador UniFi.",
    permission_category="system",
    permission_action="admin",
)
async def restart_controller(confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for restarting controller with multi-site support.

    Args:
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "system", "admin"):
        logger.warning("Permission denied for restarting controller.")
        return {"success": False, "error": "Permission denied to restart controller."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        if not confirm:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": "This operation requires confirmation. Set confirm=True to proceed.",
                    "warning": "This will restart the Unifi Network controller and may temporarily interrupt service.",
                },
                site_id,
                site_name,
                site_slug,
            )

        # Restart the controller
        success = await system_manager.restart_controller(site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": "Controller restart initiated successfully",
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": "Failed to restart controller",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error restarting controller: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_system_status",
    description="Status operacional do controlador UniFi Network — estado atual de sistema, uptime, carga e métricas em tempo real. Use quando precisar monitorar desempenho, verificar disponibilidade ou auditar carga operacional. Retorna status atual com métricas de sistema no controlador UniFi.",
)
async def get_system_status(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting system status with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with system status and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        status = await system_manager.get_system_status(site=site_slug)

        # Convert SystemStatus objects to plain dictionaries
        status_raw = status.raw if hasattr(status, "raw") else status

        return inject_site_metadata(
            {
                "success": True,
                "system_status": status_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting system status: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_snmp_settings",
    description="Configurações SNMP do controlador UniFi Network — parâmetros de monitoramento, community strings e settings do protocolo de gerenciamento. Use quando precisar consultar SNMP configurado, verificar community ou auditar integração de monitoramento. Retorna settings SNMP ativos no controlador UniFi.",
)
async def get_snmp_settings(site: Optional[str] = None) -> Dict[str, Any]:
    """Implementation for getting SNMP settings with multi-site support."""
    logger.info("unifi_get_snmp_settings tool called")
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        settings_list = await system_manager.get_settings("snmp")
        snmp_settings = settings_list[0] if settings_list else {}
        return inject_site_metadata(
            {
                "success": True,
                "snmp_settings": {
                    "enabled": snmp_settings.get("enabled", False),
                    "community": snmp_settings.get("community", ""),
                },
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting SNMP settings: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_snmp_settings",
    description="Atualização de configurações SNMP do controlador UniFi Network com confirmação obrigatória — modificação de community strings, versão do protocolo ou parâmetros de monitoramento. Use quando precisar ajustar SNMP ou modificar integração. Executa update de settings SNMP no controlador UniFi.",
)
async def update_snmp_settings(
    enabled: bool,
    community: Optional[str] = None,
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """Implementation for updating SNMP settings with multi-site support.

    Args:
        enabled: Whether SNMP should be enabled on the site.
        community: SNMP community string (optional, keeps current value if not provided).
        confirm: Must be true to apply changes. When false, returns a preview of proposed changes.
        site: Optional site name/slug. If None, uses current default site.
    """
    logger.info(f"unifi_update_snmp_settings tool called (enabled={enabled}, confirm={confirm})")

    if not parse_permission(config.permissions, "snmp", "update"):
        logger.warning("Permission denied for updating SNMP settings.")
        return {"success": False, "error": "Permission denied to update SNMP settings."}

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_mgr)

        settings_list = await system_manager.get_settings("snmp")
        current = settings_list[0] if settings_list else {}

        updates: Dict[str, Any] = {"enabled": enabled}
        if community is not None:
            updates["community"] = community

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="snmp_settings",
                resource_id=current.get("_id", "snmp"),
                resource_name="SNMP Settings",
                current_state={
                    "enabled": current.get("enabled", False),
                    "community": current.get("community", ""),
                },
                updates=updates,
            )

        payload: Dict[str, Any] = {"enabled": enabled}
        if community is not None:
            payload["community"] = community

        success = await system_manager.update_settings("snmp", payload)
        if success:
            refreshed = await system_manager.get_settings("snmp")
            new_settings = refreshed[0] if refreshed else payload
            return inject_site_metadata(
                {
                    "success": True,
                    "snmp_settings": {
                        "enabled": new_settings.get("enabled", enabled),
                        "community": new_settings.get("community", community or ""),
                    },
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": "Failed to update SNMP settings.",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating SNMP settings: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
