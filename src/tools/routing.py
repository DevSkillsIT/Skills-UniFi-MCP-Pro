"""
Unifi Network MCP routing tools.

This module provides MCP tools to interact with a Unifi Network Controller's routing functions,
including managing static routes, routing tables, and gateway configurations.
Supports multi-site operations with optional site parameter.
"""

import logging
from typing import Any, Dict, Optional, Tuple

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import config, routing_manager, server, system_manager
from src.utils.confirmation import create_preview, preview_response, should_auto_confirm, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context
from src.validator_registry import UniFiValidatorRegistry

logger = logging.getLogger(__name__)

# The controller spells a route's fields with a hyphen ("static-route_network"),
# while this tool's own preview labels them "network" and "gateway" -- a caller
# who read the preview sends the friendly spelling back. Accepting both keeps a
# destination or next-hop from being dropped on its way to the manager.
_ROUTE_FIELD_ALIASES: Dict[str, Tuple[str, ...]] = {
    "name": ("name",),
    "static_route_network": ("static-route_network", "static_route_network", "network", "destination"),
    "static_route_nexthop": ("static-route_nexthop", "static_route_nexthop", "nexthop", "gateway"),
    "static_route_distance": ("static-route_distance", "static_route_distance", "distance"),
    "enabled": ("enabled",),
    "route_type": ("type", "route_type"),
}

_ROUTE_REQUIRED = ("name", "static_route_network", "static_route_nexthop")

# The field name the controller stores for each manager keyword. A preview that
# proposes "network" against a route that stores "static-route_network" shows the
# current value as empty for every field being changed.
_ROUTE_API_FIELD = {
    "name": "name",
    "static_route_network": "static-route_network",
    "static_route_nexthop": "static-route_nexthop",
    "static_route_distance": "static-route_distance",
    "enabled": "enabled",
    "route_type": "type",
}


def _route_kwargs(data: Dict[str, Any], for_update: bool = False) -> Dict[str, Any]:
    """Translate a caller's route dict into RoutingManager keyword arguments.

    `for_update` drops "route_type": the update endpoint takes the merged route
    object and the manager exposes no parameter for retyping an existing route.
    """
    kwargs: Dict[str, Any] = {}
    for parameter, aliases in _ROUTE_FIELD_ALIASES.items():
        if for_update and parameter == "route_type":
            continue
        for alias in aliases:
            if alias in data:
                kwargs[parameter] = data[alias]
                break
    return kwargs


def _accepted_route_fields() -> str:
    """Comma-separated list of every field spelling this tool understands."""
    return ", ".join(sorted({alias for aliases in _ROUTE_FIELD_ALIASES.values() for alias in aliases}))


def _validate_optional(
    resource_type: str, data: Dict[str, Any]
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """Validate `data` only when a schema is registered for `resource_type`.

    UniFiValidatorRegistry carries no entry for the routing resource types, and
    an unregistered type answers "no validator found" -- a message that reads as
    invalid input and rejects every create and update whatever the caller sends.
    A missing schema is a gap in the registry, not a verdict on the request.
    """
    if UniFiValidatorRegistry.get_validator(resource_type) is None:
        logger.warning(f"No validator registered for '{resource_type}'; forwarding the request unvalidated.")
        return True, None, data
    is_valid, error_msg, validated = UniFiValidatorRegistry.validate(resource_type, data)
    return is_valid, error_msg, validated or {}


@server.tool(
    name="unifi_list_static_routes",
    description="Rotas estáticas do controlador UniFi Network — tabela de roteamento, destinos de rede e gateways configurados para direcionamento de tráfego. Use quando precisar listar rotas customizadas, auditar roteamento ou verificar configurações de gateway. Retorna lista completa de static routes com destino, gateway e interface no controlador UniFi.",
)
async def list_static_routes(site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for listing static routes with multi-site support.

    Args:
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with static routes list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        routes = await routing_manager.get_routes(site=site_slug)

        # Convert StaticRoute objects to plain dictionaries
        routes_raw = [r.raw if hasattr(r, "raw") else r for r in routes]

        return inject_site_metadata(
            {
                "success": True,
                "count": len(routes_raw),
                "static_routes": routes_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing static routes: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_static_route_details",
    description="Detalhes completos de rota estática UniFi Network específica — informações de destino, gateway, interface e métrica identificados por ID único. Use quando precisar auditar rota específica ou validar configuração de roteamento. Retorna network, next-hop, distância e parâmetros da rota no controlador UniFi.",
)
async def get_static_route_details(route_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting static route details with multi-site support.

    Args:
        route_id: The _id of the static route
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with static route details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        route = await routing_manager.get_route_details(route_id, site=site_slug)
        if route:
            route_raw = route.raw if hasattr(route, "raw") else route
            return inject_site_metadata(
                {
                    "success": True,
                    "static_route": route_raw,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Static route with ID {route_id} not found",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting static route details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_static_route",
    description="Criação de rota estática UniFi Network com validação — novo destino de rede, gateway ou configuração de roteamento com confirmação obrigatória. Use quando precisar adicionar rota personalizada ou configurar direcionamento de tráfego. Cria static route validada no controlador UniFi com suporte multi-site.",
    permission_category="routing",
    permission_action="create",
)
async def create_static_route(
    route_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for creating static route with multi-site support.

    Args:
        route_data: Static route configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "create"):
        logger.warning("Permission denied for creating static route.")
        return {"success": False, "error": "Permission denied to create static route."}

    if not route_data:
        return {"success": False, "error": "route_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the route data
        is_valid, error_msg, validated_data = _validate_optional("static_route_create", route_data)
        if not is_valid:
            logger.warning(f"Invalid static route create data: {error_msg}")
            return {"success": False, "error": f"Invalid static route data: {error_msg}"}

        # Resolved before the preview so a confirmation is never offered for a
        # route the manager cannot build.
        route_kwargs = _route_kwargs(validated_data)
        missing = [field for field in _ROUTE_REQUIRED if field not in route_kwargs]
        if missing:
            return {
                "success": False,
                "error": (
                    f"route_data is missing {', '.join(missing)}. "
                    f"Accepted field names: {_accepted_route_fields()}"
                ),
            }

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="static_route",
                resource_name=route_kwargs["name"],
                resource_data={_ROUTE_API_FIELD[k]: v for k, v in route_kwargs.items()},
            )

        # Create the static route
        result = await routing_manager.create_route(site=site_slug, **route_kwargs)
        if result:
            return inject_site_metadata(
                {
                    "success": True,
                    "route_id": result.get("_id"),
                    "details": result,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": "Failed to create static route",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating static route: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_static_route",
    description="Rotas estáticas do UniFi Network — altera destino, gateway (next-hop), distância e nome de uma rota por ID, e também ativa ou desativa a rota pelo campo enabled em update_data, sem excluí-la. Use quando precisar ajustar, habilitar ou desabilitar uma rota de roteamento. Exige confirmação e retorna os campos alterados lidos do controlador UniFi, com suporte multi-site.",
    permission_category="routing",
    permission_action="update",
)
async def update_static_route(
    route_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for updating static route with multi-site support.

    Args:
        route_id: The unique identifier (_id) of the static route to update
        update_data: Fields to change, keyed by any spelling in _ROUTE_FIELD_ALIASES.
            "enabled" is one of them: the controller stores the on/off state as an
            ordinary field of the route object, so turning a route off is a change
            of that field and not a separate operation.
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "update"):
        logger.warning(f"Permission denied for updating static route ({route_id}).")
        return {"success": False, "error": "Permission denied to update static route."}

    if not route_id:
        return {"success": False, "error": "route_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = _validate_optional("static_route_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid static route update data for ID {route_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        # Resolved before the preview so the proposal is shown in the same field
        # spelling the stored route uses.
        route_kwargs = _route_kwargs(validated_data, for_update=True)
        if not route_kwargs:
            return {
                "success": False,
                "error": (
                    "update_data carries no field this tool can apply. "
                    f"Accepted field names: {_accepted_route_fields()}"
                ),
            }

        # Fetch current state for preview
        current = await routing_manager.get_route_details(route_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Static route not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="static_route",
                resource_id=route_id,
                resource_name=current.get("name", f"Route to {current.get('static-route_network', 'Unknown')}"),
                current_state=current,
                updates={_ROUTE_API_FIELD[k]: v for k, v in route_kwargs.items()},
            )

        # Perform the update
        success = await routing_manager.update_route(route_id, site=site_slug, **route_kwargs)
        if success:
            # Fetch updated details
            updated = await routing_manager.get_route_details(route_id, site=site_slug)
            return inject_site_metadata(
                {
                    "success": True,
                    "route_id": route_id,
                    "updated_fields": sorted(_ROUTE_API_FIELD[k] for k in route_kwargs),
                    "details": updated,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Failed to update static route {route_id}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating static route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_delete_static_route",
    description="Exclusão de rota estática UniFi Network via ID — remoção permanente de destino, gateway ou configuração de roteamento com confirmação obrigatória. Use quando precisar remover rota obsoleta ou limpar configuração de direcionamento. Executa delete permanente de static route no controlador UniFi com suporte multi-site.",
    permission_category="routing",
    permission_action="delete",
)
async def delete_static_route(route_id: str, confirm: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for deleting static route with multi-site support.

    Args:
        route_id: The unique identifier (_id) of the static route to delete
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "routing", "delete"):
        logger.warning(f"Permission denied for deleting static route ({route_id}).")
        return {"success": False, "error": "Permission denied to delete static route."}

    if not route_id:
        return {"success": False, "error": "route_id is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch current state for preview
        current = await routing_manager.get_route_details(route_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Static route not found"}

        if not confirm and not should_auto_confirm():
            return preview_response(
                action="delete",
                resource_type="static_route",
                resource_id=route_id,
                resource_name=current.get("name", f"Route to {current.get('static-route_network', 'Unknown')}"),
                current_state=current,
                proposed_changes={"deleted": True},
                warnings=["This will permanently delete the static route"],
            )

        # Delete the static route
        success = await routing_manager.delete_route(route_id, site=site_slug)
        if success:
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Static route {route_id} deleted successfully",
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Failed to delete static route {route_id}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error deleting static route {route_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
