"""Unifi Network MCP system tools.

System information is controller-wide; health, status and settings are
per-site. Each tool below is explicit about which it is, and the per-site ones
carry the resolved site into the controller call instead of relying on whatever
site the shared connection happens to point at.
"""

import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import config, server, system_manager
from src.utils.confirmation import should_auto_confirm, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)


@server.tool(
    name="list_sites",
    description="Sites disponíveis no controlador UniFi Network — identificadores, nomes e descrições de todos os sites que a whitelist permite operar. Use quando precisar listar sites, auditar ambientes ou descobrir o identificador correto para o parâmetro site das demais tools. Retorna o _id real do site, o slug usado nos caminhos da API e o nome legível no controlador UniFi.",
)
async def list_sites() -> Dict[str, Any]:
    """List the sites this server is allowed to operate on.

    The three identifiers are distinct and all three are returned because any
    of them can be passed as `site`: `_id` is the controller's ObjectId, `name`
    is the slug that appears in API paths, and `desc` is the human-readable
    name.
    """
    try:
        sites = await system_manager.list_sites()
        return {
            "success": True,
            "sites": sites,
            "count": len(sites),
            "identifier_note": "_id is the controller ObjectId, name is the API path slug, desc is the display name. Any of the three is accepted as the site parameter.",
        }
    except Exception as e:
        logger.error(f"Error listing sites: {e}", exc_info=True)
        return {"success": False, "error": str(e), "sites": [], "count": 0}


@server.tool(
    name="unifi_get_system_info",
    description="Informações do controlador UniFi Network — versão instalada, build, hostname, uptime, fuso horário e disponibilidade de atualização. Use quando precisar consultar versão, verificar se há update pendente ou auditar a instalação. Retorna os dados de identificação do controlador UniFi, que são globais e não variam por site.",
)
async def get_system_info(site: Optional[str] = None) -> Dict[str, Any]:
    """Controller build and identity.

    Args:
        site: Accepted and validated for consistency with the other tools; the
            underlying endpoint is controller-wide, so the values do not vary
            between sites.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        info = await system_manager.get_system_info(site=site_slug)
        if not info:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": "Controller returned no system information.",
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {"success": True, "system_info": info},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting system info: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_health_check",
    description="Saúde por subsistema do site UniFi Network — estado de wlan, wan, lan, www e vpn, com contagem de equipamentos adotados, desconectados e pendentes e de clientes por tipo. Use quando precisar monitorar a saúde do site, verificar subsistemas ou diagnosticar problemas operacionais. Retorna uma linha por subsistema no controlador UniFi.",
)
async def get_health_check(site: Optional[str] = None) -> Dict[str, Any]:
    """Per-subsystem health for the site.

    Args:
        site: Site slug or display name.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        health = await system_manager.get_health_check(site=site_slug)
        return inject_site_metadata(
            {"success": True, "count": len(health), "health_check": health},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting health check: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_system_status",
    description="Status operacional consolidado do site UniFi Network — versão e uptime do controlador combinados com o estado de cada subsistema, lista explícita dos subsistemas degradados e contagem de equipamentos e clientes. Use quando precisar um veredito rápido de disponibilidade, verificar se algo está degradado ou auditar carga. Retorna o resumo com o campo overall no controlador UniFi.",
)
async def get_system_status(site: Optional[str] = None) -> Dict[str, Any]:
    """Consolidated operational status for the site.

    Args:
        site: Site slug or display name.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        status = await system_manager.get_system_status(site=site_slug)
        return inject_site_metadata(
            {"success": True, "system_status": status},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting system status: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_restart_controller",
    description="Reinicialização do controlador UniFi Network com confirmação obrigatória — reboot completo de sistema, serviços e processos gerenciados, derrubando temporariamente a gestão de todos os sites. Use quando precisar aplicar configurações críticas, resolver problemas de sistema ou executar manutenção programada. Executa restart do controlador UniFi e confirma que o comando foi aceito.",
    permission_category="system",
    permission_action="admin",
)
async def restart_controller(confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """Reboot the controller.

    Args:
        confirm: Must be True to execute.
        site: Resolved and reported, but the reboot affects the whole
            controller, not one site.
    """
    if not parse_permission(config.permissions, "system", "admin"):
        logger.warning("Permission denied for restarting controller.")
        return {"success": False, "error": "Permission denied to restart controller."}

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        if not confirm:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": "This operation requires confirmation. Set confirm=True to proceed.",
                    "warning": "This restarts the entire UniFi Network controller and interrupts management of every site, not just this one.",
                },
                site_id,
                site_name,
                site_slug,
            )

        success = await system_manager.restart_controller(site=site_slug)
        return inject_site_metadata(
            {
                "success": success,
                "message": "Controller restart accepted by the controller."
                if success
                else "Controller refused the restart command.",
            }
            if success
            else {"success": False, "error": "Controller refused the restart command."},
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error restarting controller: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_snmp_settings",
    description="Configurações SNMP do site UniFi Network — estado de habilitação e community string do protocolo de monitoramento. Use quando precisar consultar SNMP configurado, verificar a community ou auditar a integração de monitoramento. Retorna os settings SNMP do site indicado no controlador UniFi.",
)
async def get_snmp_settings(site: Optional[str] = None) -> Dict[str, Any]:
    """Read the SNMP settings of the target site.

    Args:
        site: Site slug or display name. SNMP settings are per-site.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        settings_list = await system_manager.get_settings("snmp", site=site_slug)
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
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting SNMP settings: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_snmp_settings",
    description="Atualização das configurações SNMP do site UniFi Network com confirmação obrigatória — habilita ou desabilita o protocolo e altera a community string de monitoramento. Use quando precisar ajustar SNMP ou modificar a integração de monitoramento. Aplica os settings no site indicado e confirma relendo o valor gravado no controlador UniFi.",
    permission_category="snmp",
    permission_action="update",
)
async def update_snmp_settings(
    enabled: bool,
    community: Optional[str] = None,
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """Write the SNMP settings of the target site.

    Args:
        enabled: Whether SNMP should be enabled on the site.
        community: SNMP community string; the current value is kept when omitted.
        confirm: Must be True to apply; otherwise a preview of the change is returned.
        site: Site slug or display name.
    """
    if not parse_permission(config.permissions, "snmp", "update"):
        logger.warning("Permission denied for updating SNMP settings.")
        return {"success": False, "error": "Permission denied to update SNMP settings."}

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        settings_list = await system_manager.get_settings("snmp", site=site_slug)
        current = settings_list[0] if settings_list else {}

        updates: Dict[str, Any] = {"enabled": enabled}
        if community is not None:
            updates["community"] = community

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="snmp_settings",
                resource_id=current.get("_id", "snmp"),
                resource_name=f"SNMP Settings ({site_name or site_slug})",
                current_state={
                    "enabled": current.get("enabled", False),
                    "community": current.get("community", ""),
                },
                updates=updates,
            )

        success = await system_manager.update_settings("snmp", dict(updates), site=site_slug)
        if not success:
            return inject_site_metadata(
                {"success": False, "error": "Controller refused the SNMP settings update."},
                site_id,
                site_name,
                site_slug,
            )

        # Read back rather than echo the request: the controller is the authority
        # on what was actually stored.
        refreshed = await system_manager.get_settings("snmp", site=site_slug)
        new_settings = refreshed[0] if refreshed else {}
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
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error updating SNMP settings: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
