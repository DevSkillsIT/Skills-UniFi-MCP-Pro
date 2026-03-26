"""
Unifi Network MCP client management tools.

This module provides MCP tools to manage network clients/devices on a Unifi Network Controller.
Supports multi-site operations with optional site parameter.
"""

import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)

# Import the global FastMCP server instance, config, and managers
from src.runtime import client_manager, config, server, system_manager
from src.utils.confirmation import should_auto_confirm, toggle_preview, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_lookup_by_ip",
    description="Clientes e dispositivos conectados no UniFi Network — busca reversa por endereço IP, identificação de equipamentos, hostname e MAC address. Use quando precisar localizar rapidamente um dispositivo, cliente ou aparelho pela rede sem consumir tokens excessivos. Retorna apenas campos essenciais (hostname, nome, MAC) otimizados para consultas ágeis no controlador UniFi.",
)
async def lookup_by_ip(ip_address: str, site: Optional[str] = None) -> Dict[str, Any]:
    """Lookup client by IP address - returns only essential fields to minimize token usage.

    Args:
        ip_address: IPv4 address to search for (e.g. '192.168.1.100').
        site: Optional site name/slug. If None, uses current default site.
    """
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        client_obj = await client_manager.get_client_by_ip(ip_address)
        if client_obj:
            client_raw = client_obj.raw if hasattr(client_obj, "raw") else client_obj
            return inject_site_metadata(
                {
                    "success": True,
                    "ip": ip_address,
                    "hostname": client_raw.get("hostname", ""),
                    "name": client_raw.get("name", ""),
                    "mac": client_raw.get("mac", ""),
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"No client found with IP: {ip_address}",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error looking up client by IP {ip_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_list_clients",
    description="Clientes, dispositivos conectados e equipamentos de rede no UniFi Network — lista completa de aparelhos ativos, estações wireless e dispositivos cabeados registrados no controlador. Use quando precisar visualizar clientes conectados, monitorar dispositivos na rede ou auditar equipamentos. Retorna lista otimizada com campos essenciais (MAC, IP, nome, hostname) para consultas eficientes no UniFi.",
)
async def list_clients(
    active_only: bool = False,
    summary: bool = True,
    limit: int = 50,
    include_details: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Implementation for listing clients with token-efficient defaults.

    Args:
        active_only: If True, only return currently connected clients
        summary: Return only essential fields (mac, ip, name, hostname) - DEFAULT: True for token efficiency
        limit: Maximum number of clients to return (default: 50, max: 200)
        include_details: Include full client details (WARNING: High token usage)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with optimized client list and metadata

    Note: Use summary=True for routine queries, include_details=True only when specific client details are needed.
    """
    try:
        # Enforce reasonable limits
        limit = min(max(1, limit), 200)

        # Warn about high token usage
        if include_details and not summary:
            logger.warning("⚠️ High token usage: include_details=True without summary mode")

        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        clients = await client_manager.get_clients(active_only=active_only, site=site_slug)

        # Convert Client objects to plain dictionaries
        clients_raw = [c.raw if hasattr(c, "raw") else c for c in clients]

        # Apply limit early to save processing
        clients_raw = clients_raw[:limit]

        # Optimized client data based on summary mode
        if summary:
            clients_optimized = []
            for client in clients_raw:
                # Return only essential fields for token efficiency
                client_summary = {
                    "mac": client.get("mac", ""),
                    "ip": client.get("ip", "N/A"),
                    "name": client.get("name", "Unknown"),
                    "hostname": client.get("hostname", ""),
                    "is_wired": client.get("is_wired", False),
                    "oui": client.get("oui", ""),
                }

                # Add minimal connection info
                if client.get("is_wired", False):
                    client_summary["connection_type"] = "wired"
                else:
                    client_summary["connection_type"] = "wireless"
                    client_summary["wifi_ssid"] = client.get("essid", "Unknown")

                clients_optimized.append(client_summary)
        else:
            # Full details (high token usage - user explicitly requested)
            clients_optimized = clients_raw

        result = {
            "success": True,
            "active_only": active_only,
            "count": len(clients_optimized),
            "total_found": len(clients_raw),
            "clients": clients_optimized,
            "filters": {
                "active_only": active_only,
                "summary_mode": summary,
                "limit_applied": limit,
                "include_details": include_details,
            },
            "token_usage": "optimized" if summary else "high",
        }

        # Add warning for large responses
        if len(clients_optimized) > 100 and not summary:
            result["warning"] = (
                f"Large response ({len(clients_optimized)} clients). Consider using summary=True for token efficiency."
            )

        return inject_site_metadata(result, site_id, site_name, site_slug)
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing clients: {e}", exc_info=True)
        return inject_site_metadata(
            {
                "success": False,
                "error": str(e),
                "clients": [],
                "count": 0,
            },
            site_id if "site_id" in locals() else None,
            site_name if "site_name" in locals() else None,
            site_slug if "site_slug" in locals() else None,
        )


@server.tool(
    name="unifi_get_client_details",
    description="Detalhes completos de cliente ou dispositivo específico no UniFi Network — informações técnicas detalhadas de equipamentos, aparelhos e estações conectadas identificadas por MAC address. Use quando precisar dados completos de um cliente, investigar dispositivo específico ou auditar equipamento individual no controlador UniFi. Retorna informações detalhadas incluindo conexão, status e histórico.",
)
async def get_client_details(mac_address: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting client details with multi-site support.

    Args:
        mac_address: MAC address of the client
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with client details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        client = await client_manager.get_client_details(mac_address, site=site_slug)
        if client:
            client_raw = client.raw if hasattr(client, "raw") else client
            return inject_site_metadata(
                {
                    "success": True,
                    "client": client_raw,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client with MAC {mac_address} not found",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting client details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_list_blocked_clients",
    description="Clientes bloqueados e dispositivos banidos no UniFi Network — lista completa de equipamentos, aparelhos e estações com acesso negado à rede pelo controlador. Use quando precisar auditar bloqueios ativos, revisar dispositivos banidos ou gerenciar restrições de acesso no UniFi. Retorna lista de clientes bloqueados com MAC, nome, hostname, IP e timestamp do bloqueio.",
)
async def list_blocked_clients(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing blocked clients with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with blocked client list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        clients = await client_manager.get_blocked_clients(site=site_slug)

        formatted_clients = []
        for c in clients:
            client = c.raw if hasattr(c, "raw") else c
            formatted_clients.append(
                {
                    "mac": client.get("mac"),
                    "name": client.get("name") or client.get("hostname", "Unknown"),
                    "hostname": client.get("hostname", "Unknown"),
                    "ip": client.get("ip", "Unknown"),
                    "connection_type": "Wired" if client.get("is_wired", False) else "Wireless",
                    "blocked_since": client.get("blocked_since", 0),
                    "_id": client.get("_id"),
                }
            )

        return inject_site_metadata(
            {
                "success": True,
                "count": len(formatted_clients),
                "blocked_clients": formatted_clients,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing blocked clients: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_block_client",
    description="Bloqueio de cliente ou dispositivo na rede UniFi Network — nega acesso à rede para equipamentos, aparelhos e estações específicas identificadas por MAC address no controlador. Use quando precisar bloquear dispositivo indesejado, banir equipamento não autorizado ou restringir acesso de cliente específico à rede UniFi. Requer confirmação antes de aplicar o bloqueio permanente.",
    permission_category="clients",
    permission_action="update",
)
async def block_client(mac_address: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for blocking a client with multi-site support.

    Args:
        mac_address: MAC address of the client
        confirm: Whether to confirm the action (shows preview if false)
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Wink", "wink", "grupo-wink" for "Grupo Wink")

    Returns:
        Dict with operation result

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "client", "block"):
        logger.warning(f"Permission denied for blocking client ({mac_address}).")
        return {"success": False, "error": "Permission denied to block clients."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        client_name = client.get("name") or client.get("hostname", "Unknown")
        is_blocked = client.get("blocked", False)

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return toggle_preview(
                resource_type="client",
                resource_id=mac_address,
                resource_name=client_name,
                current_enabled=not is_blocked,  # enabled = not blocked
                additional_info={
                    "ip": client.get("ip"),
                    "hostname": client.get("hostname"),
                    "action": "block",
                },
            )

        success = await client_manager.block_client(mac_address, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Client {mac_address} blocked successfully.",
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"Failed to block client {mac_address}.",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error blocking client {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_unblock_client",
    description="Desbloqueio de cliente ou dispositivo previamente banido no UniFi Network — restaura acesso à rede para equipamentos, aparelhos e estações bloqueadas identificadas por MAC address. Use quando precisar liberar dispositivo bloqueado, restaurar acesso de equipamento banido ou remover restrições de cliente no controlador UniFi. Requer confirmação antes de remover o bloqueio.",
    permission_category="clients",
    permission_action="update",
)
async def unblock_client(mac_address: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for unblocking a client with multi-site support.

    Args:
        mac_address: MAC address of the client
        confirm: Whether to confirm the action (shows preview if false)
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Wink", "wink", "grupo-wink" for "Grupo Wink")

    Returns:
        Dict with operation result

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "client", "unblock"):
        logger.warning(f"Permission denied for unblocking client ({mac_address}).")
        return {"success": False, "error": "Permission denied to unblock clients."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        client_name = client.get("name") or client.get("hostname", "Unknown")
        is_blocked = client.get("blocked", False)

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return toggle_preview(
                resource_type="client",
                resource_id=mac_address,
                resource_name=client_name,
                current_enabled=not is_blocked,  # enabled = not blocked
                additional_info={
                    "ip": client.get("ip"),
                    "hostname": client.get("hostname"),
                    "action": "unblock",
                },
            )

        success = await client_manager.unblock_client(mac_address, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Client {mac_address} unblocked successfully.",
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"Failed to unblock client {mac_address}.",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error unblocking client {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_rename_client",
    description="Renomear cliente ou dispositivo no UniFi Network — altera identificação de equipamentos, aparelhos e estações conectadas no controlador usando MAC address como referência. Use quando precisar organizar nomenclatura de dispositivos, identificar equipamentos de forma amigável ou padronizar nomes de clientes na rede UniFi. Requer confirmação antes de aplicar a alteração de nome.",
)
async def rename_client(
    mac_address: str, name: str, confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Implementation for renaming a client with multi-site support."""
    if not parse_permission(config.permissions, "client", "update"):
        logger.warning(f"Permission denied for renaming client ({mac_address}).")
        return {"success": False, "error": "Permission denied to rename clients."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        current_name = client.get("name") or client.get("hostname", "Unknown")

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="client",
                resource_id=mac_address,
                resource_name=current_name,
                current_state={"name": current_name},
                updates={"name": name},
            )

        success = await client_manager.rename_client(mac_address, name, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Client {mac_address} renamed to '{name}' successfully.",
                    "client_id": mac_address,
                    "new_name": name,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Failed to rename client {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error renaming client {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_force_reconnect_client",
    description="Reconexão forçada de cliente ou dispositivo no UniFi Network — desconecta e força equipamento, aparelho ou estação a reconectar à rede (kick) usando MAC address. Use quando precisar resolver problemas de conexão, forçar renovação DHCP ou liberar sessão travada de dispositivo no controlador UniFi. Requer confirmação antes de desconectar o cliente.",
    permission_category="clients",
    permission_action="update",
)
async def force_reconnect_client(mac_address: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """Implementation for forcing a client to reconnect with multi-site support."""
    if not parse_permission(config.permissions, "client", "reconnect"):
        logger.warning(f"Permission denied for forcing reconnect of client ({mac_address}).")
        return {
            "success": False,
            "error": "Permission denied to force client reconnection.",
        }

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        client_name = client.get("name") or client.get("hostname", "Unknown")

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return {
                "success": False,
                "requires_confirmation": True,
                "action": "force_reconnect",
                "resource_type": "client",
                "resource_id": mac_address,
                "resource_name": client_name,
                "warning": "This will force the client to disconnect and reconnect to the network.",
            }

        success = await client_manager.force_reconnect_client(mac_address, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Client {mac_address} forced to reconnect successfully.",
                    "client_id": mac_address,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Failed to force reconnect client {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error forcing reconnect of client {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_authorize_guest",
    description="Autorização de visitante ou convidado na rede guest do UniFi Network — concede acesso temporário para dispositivos, equipamentos e aparelhos de visitantes identificados por MAC address. Use quando precisar autorizar acesso guest, liberar dispositivo de visitante ou conceder permissão temporária no portal captivo do UniFi. Permite configurar tempo de acesso, cota de dados e limites de velocidade.",
    permission_category="clients",
    permission_action="update",
)
async def authorize_guest(
    mac_address: str,
    minutes: int = 1440,
    up_kbps: Optional[int] = None,
    down_kbps: Optional[int] = None,
    bytes_quota: Optional[int] = None,
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """Implementation for authorizing a guest with multi-site support."""
    if not parse_permission(config.permissions, "client", "authorize"):
        logger.warning(f"Permission denied for authorizing guest ({mac_address}).")
        return {"success": False, "error": "Permission denied to authorize guests."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        client_name = client.get("name") or client.get("hostname", "Unknown")

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            settings = {"minutes": minutes}
            if up_kbps is not None:
                settings["up_kbps"] = up_kbps
            if down_kbps is not None:
                settings["down_kbps"] = down_kbps
            if bytes_quota is not None:
                settings["bytes_quota"] = bytes_quota

            return {
                "success": False,
                "requires_confirmation": True,
                "action": "authorize_guest",
                "resource_type": "client",
                "resource_id": mac_address,
                "resource_name": client_name,
                "preview": {
                    "current": {
                        "ip": client.get("ip"),
                        "hostname": client.get("hostname"),
                    },
                    "proposed": settings,
                },
                "message": f"Will authorize guest '{client_name}' for {minutes} minutes. Set confirm=true to execute.",
            }

        success = await client_manager.authorize_guest(
            mac_address, minutes, up_kbps, down_kbps, bytes_quota, site=site_slug
        )
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Guest {mac_address} authorized successfully for {minutes} minutes.",
                    "client_id": mac_address,
                    "authorized_minutes": minutes,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Failed to authorize guest {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error authorizing guest {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_unauthorize_guest",
    description="Revogação de autorização de visitante ou convidado no UniFi Network — remove acesso guest para dispositivos, equipamentos e aparelhos de visitantes identificados por MAC address. Use quando precisar revogar acesso temporário, encerrar sessão de visitante ou remover permissão de dispositivo guest no portal captivo do controlador UniFi. Requer confirmação antes de revogar autorização.",
    permission_category="clients",
    permission_action="update",
)
async def unauthorize_guest(mac_address: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """Implementation for unauthorizing a guest with multi-site support."""
    if not parse_permission(config.permissions, "client", "authorize"):
        logger.warning(f"Permission denied for unauthorizing guest ({mac_address}).")
        return {"success": False, "error": "Permission denied to unauthorize guests."}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        client_name = client.get("name") or client.get("hostname", "Unknown")

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return {
                "success": False,
                "requires_confirmation": True,
                "action": "unauthorize_guest",
                "resource_type": "client",
                "resource_id": mac_address,
                "resource_name": client_name,
                "preview": {
                    "current": {
                        "ip": client.get("ip"),
                        "hostname": client.get("hostname"),
                    },
                    "action": "Guest authorization will be revoked",
                },
                "message": f"Will revoke guest authorization for '{client_name}'. Set confirm=true to execute.",
            }

        success = await client_manager.unauthorize_guest(mac_address, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Guest {mac_address} unauthorized successfully.",
                    "client_id": mac_address,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Failed to unauthorize guest {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error unauthorizing guest {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_set_client_ip_settings",
    description="Configuração de IP fixo e DNS local para cliente ou dispositivo no UniFi Network — define reserva DHCP estática e registro DNS local para equipamentos, aparelhos e estações identificadas por MAC address. Use quando precisar fixar IP de dispositivo, criar hostname local ou configurar DNS interno no controlador UniFi. Permite configurar IP fixo e registro DNS de forma independente (UniFi Network 7.2+).",
    permission_category="clients",
    permission_action="update",
)
async def set_client_ip_settings(
    mac_address: str,
    use_fixedip: Optional[bool] = None,
    fixed_ip: Optional[str] = None,
    local_dns_record_enabled: Optional[bool] = None,
    local_dns_record: Optional[str] = None,
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """Set fixed IP and/or local DNS record for a client with multi-site support."""
    if not parse_permission(config.permissions, "client", "update"):
        logger.warning(f"Permission denied for setting IP settings ({mac_address}).")
        return {
            "success": False,
            "error": "Permission denied to update client settings.",
        }

    # Validate that at least one setting is provided
    if all(v is None for v in [use_fixedip, fixed_ip, local_dns_record_enabled, local_dns_record]):
        return {
            "success": False,
            "error": "At least one setting must be provided (use_fixedip, fixed_ip, local_dns_record_enabled, or local_dns_record).",
        }

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch client details first
        client_obj = await client_manager.get_client_details(mac_address, site=site_slug)
        if not client_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Client not found with MAC address: {mac_address}",
                },
                site_id,
                site_name,
                site_slug,
            )

        client = client_obj.raw if hasattr(client_obj, "raw") else client_obj
        client_name = client.get("name") or client.get("hostname", "Unknown")

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            # Build current state from the client object
            current_state = {
                "use_fixedip": client.get("use_fixedip", False),
                "fixed_ip": client.get("fixed_ip"),
                "local_dns_record_enabled": client.get("local_dns_record_enabled", False),
                "local_dns_record": client.get("local_dns_record"),
            }

            # Build updates dict with only provided values
            updates = {}
            if use_fixedip is not None:
                updates["use_fixedip"] = use_fixedip
            if fixed_ip is not None:
                updates["fixed_ip"] = fixed_ip
            if local_dns_record_enabled is not None:
                updates["local_dns_record_enabled"] = local_dns_record_enabled
            if local_dns_record is not None:
                updates["local_dns_record"] = local_dns_record

            return update_preview(
                resource_type="client",
                resource_id=mac_address,
                resource_name=client_name,
                current_state=current_state,
                updates=updates,
            )

        success = await client_manager.set_client_ip_settings(
            client_mac=mac_address,
            use_fixedip=use_fixedip,
            fixed_ip=fixed_ip,
            local_dns_record_enabled=local_dns_record_enabled,
            local_dns_record=local_dns_record,
            site=site_slug,
        )
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"IP settings updated for client {mac_address}.",
                    "settings": {
                        k: v
                        for k, v in {
                            "use_fixedip": use_fixedip,
                            "fixed_ip": fixed_ip,
                            "local_dns_record_enabled": local_dns_record_enabled,
                            "local_dns_record": local_dns_record,
                        }.items()
                        if v is not None
                    },
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"Failed to update IP settings for client {mac_address}.",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error setting IP settings for {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
