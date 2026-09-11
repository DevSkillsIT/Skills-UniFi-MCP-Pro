"""
Unifi Network MCP hotspot voucher tools.

This module provides MCP tools to manage the guest-portal vouchers of a Unifi
Network Controller. Supports multi-site operations with optional site parameter.
"""

import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.managers.hotspot_manager import EndpointNotServedError
from src.runtime import config, hotspot_manager, server, system_manager
from src.utils.confirmation import create_preview, preview_response, should_auto_confirm
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)

MAX_VOUCHERS_PER_BATCH = 10000


def _summarize(voucher: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a voucher to the fields that identify and bound it."""
    summary: Dict[str, Any] = {
        "_id": voucher.get("_id"),
        "code": voucher.get("code"),
        "quota": voucher.get("quota", 1),
        "duration_minutes": voucher.get("duration"),
        "used": voucher.get("used", 0),
        "create_time": voucher.get("create_time"),
        "note": voucher.get("note"),
    }
    if voucher.get("qos_rate_max_up"):
        summary["up_limit_kbps"] = voucher.get("qos_rate_max_up")
    if voucher.get("qos_rate_max_down"):
        summary["down_limit_kbps"] = voucher.get("qos_rate_max_down")
    if voucher.get("qos_usage_quota"):
        summary["data_limit_mb"] = voucher.get("qos_usage_quota")
    return summary


@server.tool(
    name="unifi_list_vouchers",
    description="Vouchers de hotspot do UniFi Network — códigos de acesso à rede de convidados com validade, cota de uso, limites de banda e consumo já registrado. Use quando precisar conferir vouchers emitidos, verificar quais já foram usados ou auditar o acesso de visitantes. Retorna a lista de vouchers do site com código, cota, duração e limites no controlador UniFi.",
)
async def list_vouchers(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing hotspot vouchers with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with voucher list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        vouchers = await hotspot_manager.get_vouchers(site=site_slug)
        summarized = [_summarize(v) for v in vouchers]

        return inject_site_metadata(
            {
                "success": True,
                "count": len(summarized),
                "vouchers": summarized,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Voucher list unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error listing vouchers: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_voucher_details",
    description="Detalhes de voucher de hotspot UniFi Network específico — dados completos do código de acesso identificado por ID único. Use quando precisar conferir validade, cota restante ou limites de banda de um voucher antes de entregá-lo ou revogá-lo. Retorna o objeto completo do voucher, com código, nota, cota, uso e data de criação no controlador UniFi.",
)
async def get_voucher_details(voucher_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting voucher details with multi-site support.

    Args:
        voucher_id: The _id of the voucher
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with voucher details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not voucher_id:
        return {"success": False, "error": "voucher_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        voucher = await hotspot_manager.get_voucher_details(voucher_id, site=site_slug)
        if voucher:
            return inject_site_metadata(
                {
                    "success": True,
                    "voucher": voucher,
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"Voucher with ID {voucher_id} not found",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Voucher lookup unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error getting voucher details for {voucher_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_voucher",
    description="Criação de vouchers de hotspot UniFi Network com confirmação — emite um ou vários códigos de acesso à rede de convidados com validade, cota de uso e limites de banda e de tráfego. Use quando precisar liberar acesso temporário a visitantes ou repor códigos do portal captivo. Cria os vouchers no controlador UniFi e retorna os códigos efetivamente emitidos.",
    permission_category="vouchers",
    permission_action="create",
)
async def create_voucher(
    expire_minutes: int = 1440,
    count: int = 1,
    quota: int = 1,
    note: Optional[str] = None,
    up_limit_kbps: Optional[int] = None,
    down_limit_kbps: Optional[int] = None,
    bytes_limit_mb: Optional[int] = None,
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Implementation for creating hotspot vouchers with multi-site support.

    Args:
        expire_minutes: Minutes the voucher stays valid after activation
        count: How many vouchers to mint
        quota: 0 for multi-use, 1 for single-use, n for n-times usable
        note: Note carried by the voucher and shown when it is printed
        up_limit_kbps: Upload speed cap in Kbps
        down_limit_kbps: Download speed cap in Kbps
        bytes_limit_mb: Total data transfer cap in MB
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with the created vouchers and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "voucher", "create"):
        logger.warning("Permission denied for creating vouchers.")
        return {"success": False, "error": "Permission denied to create vouchers."}

    if expire_minutes < 1:
        return {"success": False, "error": "expire_minutes must be at least 1."}
    if count < 1 or count > MAX_VOUCHERS_PER_BATCH:
        return {"success": False, "error": f"count must be between 1 and {MAX_VOUCHERS_PER_BATCH}."}
    if quota < 0:
        return {"success": False, "error": "quota must be 0 (multi-use) or a positive number of uses."}

    if not confirm and not should_auto_confirm():
        resource_data: Dict[str, Any] = {
            "count": count,
            "expire_minutes": expire_minutes,
            "quota": quota,
        }
        if note:
            resource_data["note"] = note
        if up_limit_kbps is not None:
            resource_data["up_limit_kbps"] = up_limit_kbps
        if down_limit_kbps is not None:
            resource_data["down_limit_kbps"] = down_limit_kbps
        if bytes_limit_mb is not None:
            resource_data["bytes_limit_mb"] = bytes_limit_mb
        if site:
            resource_data["site"] = site

        return create_preview(
            resource_type="voucher",
            resource_data=resource_data,
            resource_name=f"{count} voucher(s)",
        )

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        vouchers = await hotspot_manager.create_voucher(
            expire_minutes=expire_minutes,
            count=count,
            quota=quota,
            note=note,
            up_limit_kbps=up_limit_kbps,
            down_limit_kbps=down_limit_kbps,
            bytes_limit_mb=bytes_limit_mb,
            site=site_slug,
        )

        if vouchers is None:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": "The controller did not accept the voucher creation.",
                },
                site_id,
                site_name,
                site_slug,
            )

        return inject_site_metadata(
            {
                "success": True,
                "message": f"Created {len(vouchers)} voucher(s).",
                "count": len(vouchers),
                "vouchers": [_summarize(v) for v in vouchers],
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Voucher creation unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error creating vouchers: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_revoke_voucher",
    description="Revogação de voucher de hotspot UniFi Network via ID — invalida o código de acesso e impede novos usos na rede de convidados, com confirmação obrigatória. Use quando precisar cortar um acesso entregue por engano ou encerrar um código ainda válido. Executa a revogação no controlador UniFi e confirma que o próprio controlador aceitou a operação.",
    permission_category="vouchers",
    permission_action="update",
)
async def revoke_voucher(voucher_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for revoking a hotspot voucher with multi-site support.

    Args:
        voucher_id: The _id of the voucher to revoke
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed

    Note: the permission action is "update" because parse_permission refuses
    every "delete" action outright, which would leave the tool unusable.
    """
    if not parse_permission(config.permissions, "voucher", "update"):
        logger.warning(f"Permission denied for revoking voucher ({voucher_id}).")
        return {"success": False, "error": "Permission denied to revoke vouchers."}

    if not voucher_id:
        return {"success": False, "error": "voucher_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        if not confirm and not should_auto_confirm():
            voucher = await hotspot_manager.get_voucher_details(voucher_id, site=site_slug)
            if not voucher:
                return inject_site_metadata(
                    {
                        "success": False,
                        "error": f"Voucher with ID {voucher_id} not found",
                    },
                    site_id,
                    site_name,
                    site_slug,
                )

            current_state = {
                key: voucher.get(key)
                for key in ("code", "note", "quota", "used")
                if voucher.get(key) is not None
            }
            return preview_response(
                action="revoke",
                resource_type="voucher",
                resource_id=voucher_id,
                resource_name=voucher.get("code"),
                current_state=current_state,
                proposed_changes={"status": "revoked"},
                warnings=["This voucher will no longer be usable."],
            )

        success = await hotspot_manager.revoke_voucher(voucher_id, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Voucher {voucher_id} revoked successfully",
                },
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": False,
                "error": f"Failed to revoke voucher {voucher_id}",
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except EndpointNotServedError as e:
        logger.warning(f"Voucher revocation unavailable on this controller: {e.message}")
        return inject_site_metadata(e.to_dict(), site_id, site_name, site_slug)
    except Exception as e:
        logger.error(f"Error revoking voucher {voucher_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
