"""
Unifi Network MCP event and alarm tools.

This module provides MCP tools to read the controller's event log and to
archive alarms. Supports multi-site operations with optional site parameter.
"""

import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.managers.event_manager import EndpointNotServedError
from src.runtime import config, event_manager, server, system_manager
from src.utils.confirmation import preview_response, should_auto_confirm
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_events",
    description="Eventos do controlador UniFi Network — histórico de conexões de clientes, mudanças de estado de equipamentos e ocorrências do sistema dentro da janela informada. Use quando precisar auditar logs, rastrear ações de usuários ou investigar problemas de infraestrutura. Retorna lista cronológica com timestamp, tipo e descrição; filtre por prefixo com event_type (catálogo em unifi_get_event_types).",
)
async def list_events(
    within_hours: int = 24,
    limit: int = 100,
    start: int = 0,
    event_type: Optional[str] = None,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Implementation for listing events with multi-site support.

    Args:
        within_hours: How many hours back to look (default: 24)
        limit: Maximum number of events to return (default: 100, capped at 3000)
        start: Offset for pagination (default: 0)
        event_type: Optional event type prefix filter (e.g. 'EVT_SW_')
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

        events = await event_manager.get_events(
            within=within_hours,
            limit=limit,
            start=start,
            event_type=event_type,
            site=site_slug,
        )

        return inject_site_metadata(
            {
                "success": True,
                "count": len(events),
                "filters": {
                    "within_hours": within_hours,
                    "limit": limit,
                    "start": start,
                    "event_type": event_type,
                },
                "events": events,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Event log unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error listing events: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_list_alarms",
    description="Alarmes do controlador UniFi Network — notificações críticas, avisos de segurança e falhas de conectividade que ainda não foram arquivadas. Use quando precisar monitorar a saúde da rede, identificar equipamentos com falha ou revisar avisos pendentes. Retorna lista com severidade, mensagem e timestamp; include_archived=true acrescenta os alarmes já arquivados no controlador UniFi.",
)
async def list_alarms(
    include_archived: bool = False,
    limit: int = 100,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Implementation for listing alarms with multi-site support.

    Args:
        include_archived: Include alarms already archived (default: False)
        limit: Maximum number of alarms to return (default: 100)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with alarms list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        alarms = await event_manager.get_alarms(
            archived=include_archived,
            limit=limit,
            site=site_slug,
        )

        return inject_site_metadata(
            {
                "success": True,
                "count": len(alarms),
                "include_archived": include_archived,
                "alarms": alarms,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Alarm list unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error listing alarms: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_event_types",
    description="Prefixos de tipo de evento reconhecidos pelo UniFi Network — catálogo das categorias de ocorrência (switch, access point, gateway, IPS, admin) aceitas como filtro. Use antes de filtrar o log, quando precisar descobrir qual prefixo corresponde à categoria desejada. Retorna a lista de prefixos com descrição, prontos para o parâmetro event_type de unifi_list_events.",
)
async def get_event_types() -> Dict[str, Any]:
    """
    Implementation for listing the known event type prefixes.

    Returns:
        Dict with the event type prefixes and how to use them

    Note: The catalogue is static and identical on every site, so this tool
    takes no site parameter.
    """
    try:
        prefixes = event_manager.get_event_type_prefixes()

        return {
            "success": True,
            "count": len(prefixes),
            "event_types": prefixes,
            "usage": "Use the prefix value in the event_type parameter of unifi_list_events",
        }
    except Exception as e:
        logger.error(f"Error getting event types: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_archive_alarm",
    description="Arquivamento de alarme específico do UniFi Network via ID — marca a notificação como resolvida e a retira do painel de alarmes ativos, com confirmação obrigatória. Use quando precisar baixar um aviso já tratado ou limpar alarme resolvido. Executa o comando de arquivamento no controlador UniFi e confirma que o próprio controlador aceitou a operação.",
    permission_category="events",
    permission_action="update",
)
async def archive_alarm(alarm_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for archiving one alarm with multi-site support.

    Args:
        alarm_id: The _id of the alarm to archive
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "event", "update"):
        logger.warning(f"Permission denied for archiving alarm ({alarm_id}).")
        return {"success": False, "error": "Permission denied to archive alarms."}

    if not alarm_id:
        return {"success": False, "error": "alarm_id is required"}

    if not confirm and not should_auto_confirm():
        # The current state is deliberately left empty: reading the alarm back
        # would cost a second call on a path this controller may not serve.
        return preview_response(
            action="archive",
            resource_type="alarm",
            resource_id=alarm_id,
            current_state={},
            proposed_changes={"archived": True},
            warnings=["The alarm leaves the active panel; the underlying event is not deleted."],
        )

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await event_manager.archive_alarm(alarm_id, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Alarm {alarm_id} archived successfully",
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"Failed to archive alarm {alarm_id}",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Alarm archiving unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error archiving alarm {alarm_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_archive_all_alarms",
    description="Arquivamento em lote de todos os alarmes ativos do UniFi Network — marca cada notificação pendente do site como resolvida, com confirmação obrigatória. Use quando precisar zerar o painel depois de tratar uma ocorrência que gerou muitos avisos. Executa o arquivamento em massa no controlador UniFi e confirma que o próprio controlador aceitou a operação.",
    permission_category="events",
    permission_action="update",
)
async def archive_all_alarms(confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for archiving every active alarm with multi-site support.

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
    if not parse_permission(config.permissions, "event", "update"):
        logger.warning("Permission denied for archiving all alarms.")
        return {"success": False, "error": "Permission denied to archive alarms."}

    if not confirm and not should_auto_confirm():
        return preview_response(
            action="archive",
            resource_type="alarm",
            resource_id="all-active-alarms",
            current_state={},
            proposed_changes={"archived": True},
            warnings=["Every active alarm on the site leaves the panel at once."],
        )

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        success = await event_manager.archive_all_alarms(site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": "All active alarms archived successfully",
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": "Failed to archive all alarms",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Alarm archiving unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error archiving all alarms: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
