"""
Unifi Network MCP network tools.

This module provides MCP tools to interact with a Unifi Network Controller's network functions,
including managing LAN networks and WLANs.
Supports multi-site operations with optional site parameter.
"""

import json
import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import config, network_manager, server, system_manager
from src.utils.confirmation import create_preview, should_auto_confirm, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context
from src.utils.write_verification import verify_write
from src.validator_registry import UniFiValidatorRegistry

logger = logging.getLogger(__name__)


def _coerce_vlan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Accept a VLAN id written as a numeric string.

    The controller reports VLAN ids as numbers, and callers frequently send
    them as strings. Coercing here keeps the schema honest about the stored
    type while still accepting the common input.
    """
    vlan = payload.get("vlan")
    if isinstance(vlan, str) and vlan.strip().isdigit():
        return {**payload, "vlan": int(vlan.strip())}
    return payload


@server.tool(
    name="unifi_list_networks",
    description="Redes configuradas no controlador UniFi Network — VLANs, LANs, segmentos corporativos e configurações de rede para isolamento de tráfego, segmentação ou separação de departamentos. Use quando precisar listar networks, auditar VLANs ou revisar segmentação. Retorna lista completa de redes com nome, subnet, VLAN ID e gateway no controlador UniFi.",
)
async def list_networks(site: Optional[str] = None) -> Dict[str, Any]:
    """Lists all networks configured on the UniFi Network controller for the specified site using the V1 API structure.

    Args:
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Acme", "acme", "grupo-acme" for "Grupo Acme")

    Returns:
        Dict with network list and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        networks = await network_manager.get_networks(site=site_slug)

        # Convert Network objects to plain dictionaries
        networks_raw = [n.raw if hasattr(n, "raw") else n for n in networks]

        return inject_site_metadata(
            {
                "success": True,
                "count": len(networks_raw),
                "networks": networks_raw,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing networks: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_network_details",
    description="Detalhes completos de rede UniFi Network específica — informações de VLAN, LAN, subnet e gateway identificados por ID único de segmento ou configuração de rede. Use quando precisar auditar network específica, validar VLAN ou revisar configuração de subnet. Retorna nome, VLAN ID, endereçamento IP e DHCP da rede no controlador UniFi.",
)
async def get_network_details(network_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting network details with multi-site support.

    Args:
        network_id: The _id of the network
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with network details and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        network = await network_manager.get_network_details(network_id, site=site_slug)
        if network:
            network_raw = network.raw if hasattr(network, "raw") else network
            return inject_site_metadata(
                {
                    "success": True,
                    "network": network_raw,
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Network with ID {network_id} not found",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting network details: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_network",
    description="Atualização de rede UniFi Network via ID com confirmação obrigatória — aceita qualquer campo do objeto de rede do controlador: nome, subnet, VLAN, faixa e opções de DHCP, servidores DNS, domínio, IGMP snooping, DHCP guard, mDNS e isolamento de rede. Chame unifi_get_network_details antes para ver os nomes e os valores atuais. Use quando precisar ajustar uma rede, mudar VLAN ou alterar endereçamento. Responde dizendo campo a campo o que o controlador gravou e o que ele ignorou.",
    permission_category="networks",
    permission_action="update",
)
async def update_network(
    network_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for updating network with multi-site support.

    Args:
        network_id: The unique identifier (_id) of the network to update
        update_data: Dictionary of fields to update
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "networks", "update"):
        logger.warning(f"Permission denied for updating network ({network_id}).")
        return {"success": False, "error": "Permission denied to update network."}

    if not network_id:
        return {"success": False, "error": "network_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the update data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("network_update", _coerce_vlan(update_data))
        if not is_valid:
            logger.warning(f"Invalid network update data for ID {network_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}

        if not validated_data:
            logger.warning(f"Network update data for ID {network_id} is empty after validation.")
            return {"success": False, "error": "Update data is effectively empty or invalid."}

        # Fetch current state for preview
        current = await network_manager.get_network_details(network_id, site=site_slug)
        if not current:
            return {"success": False, "error": "Network not found"}

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="network",
                resource_id=network_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        # Basic cross-field validation
        if "vlan_enabled" in validated_data and validated_data["vlan_enabled"] and "vlan" not in validated_data:
            pass  # Let manager handle fetching existing state for merge
        if "vlan" in validated_data and (int(validated_data["vlan"]) < 1 or int(validated_data["vlan"]) > 4094):
            return {"success": False, "error": "'vlan' must be between 1 and 4094."}

        # Perform the update
        success = await network_manager.update_network(network_id, validated_data, site=site_slug)
        if success:
            updated = await network_manager.get_network_details(network_id, site=site_slug)
            return inject_site_metadata(
                {
                    "success": True,
                    "network_id": network_id,
                    "requested_fields": list(validated_data.keys()),
                    **verify_write(validated_data, updated, before=current),
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
                    "error": f"Failed to update network {network_id}",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating network {network_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_network",
    description="Criação de rede UniFi Network com validação — nova VLAN, LAN, segmento corporativo ou configuração de isolamento com confirmação obrigatória. Use quando precisar adicionar network, configurar VLAN ou implementar segmentação. Cria rede validada no controlador UniFi com suporte multi-site e DHCP.",
    permission_category="networks",
    permission_action="create",
)
async def create_network(
    network_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for creating network with multi-site support.

    Args:
        network_data: Network configuration data
        confirm: Must be set to True to execute
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with operation result and site metadata

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "networks", "create"):
        logger.warning("Permission denied for creating network.")
        return {"success": False, "error": "Permission denied to create network."}

    if not network_data:
        return {"success": False, "error": "network_data is required"}

    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Validate the network data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("network", _coerce_vlan(network_data))
        if not is_valid:
            logger.warning(f"Invalid network create data: {error_msg}")
            return {"success": False, "error": f"Invalid network data: {error_msg}"}

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="network",
                resource_name=validated_data.get("name", "Unknown"),
                resource_data=validated_data,
            )

        # Create the network
        result = await network_manager.create_network(validated_data, site=site_slug)
        if result:
            return inject_site_metadata(
                {
                    "success": True,
                    "network_id": result.get("_id"),
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
                    "error": "Failed to create network",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating network: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_list_wlans",
    description="Redes wireless do site UniFi Network — SSIDs, WLANs e configurações de access points para conectividade WiFi, guest network ou redes corporativas sem fio. Use quando precisar listar WLANs, auditar SSIDs ou revisar wireless. Retorna nome, estado, segurança, rede associada e grupo de usuários de cada SSID do site indicado no controlador UniFi.",
)
async def list_wlans(site: Optional[str] = None) -> Dict[str, Any]:
    """List the wireless SSIDs configured on the target site.

    Args:
        site: Site slug or display name. Without it the configured default site
            is used, and the site actually queried is always reported back in
            the response metadata.
    """
    if not parse_permission(config.permissions, "wlans", "read"):
        logger.warning("Permission denied for listing WLANs.")
        return {"success": False, "error": "Permission denied to list WLANs."}
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        wlans = await network_manager.get_wlans(site=site_slug)
        wlans_raw = [w.raw if hasattr(w, "raw") else w for w in wlans]
        formatted_wlans = [
            {
                "id": w.get("_id"),
                "name": w.get("name"),
                "enabled": w.get("enabled"),
                "security": w.get("security"),
                "network_id": w.get("networkconf_id"),
                "usergroup_id": w.get("usergroup_id"),
                "wlan_band": w.get("wlan_band"),
            }
            for w in wlans_raw
        ]
        return inject_site_metadata(
            {
                "success": True,
                "count": len(formatted_wlans),
                "wlans": formatted_wlans,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error listing WLANs: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_wlan_details",
    description="Detalhes completos de uma rede wireless UniFi Network — configuração integral do SSID identificado por ID, incluindo segurança, banda, VLAN associada e políticas. Use quando precisar auditar uma WLAN específica, validar a configuração WiFi ou revisar a autenticação. Retorna a configuração bruta do SSID no site indicado do controlador UniFi.",
)
async def get_wlan_details(wlan_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """Read the full configuration of one SSID.

    Args:
        wlan_id: The WLAN `_id`. IDs are site-scoped, so an ID from one site
            will not resolve on another.
        site: Site slug or display name.
    """
    if not parse_permission(config.permissions, "wlans", "read"):
        logger.warning(f"Permission denied for getting WLAN details ({wlan_id}).")
        return {"success": False, "error": "Permission denied to get WLAN details."}
    if not wlan_id:
        return {"success": False, "error": "wlan_id is required"}
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        wlan = await network_manager.get_wlan_details(wlan_id, site=site_slug)
        if not wlan:
            return inject_site_metadata(
                {"success": False, "error": f"WLAN '{wlan_id}' not found on this site."},
                site_id,
                site_name,
                site_slug,
            )
        return inject_site_metadata(
            {
                "success": True,
                "wlan_id": wlan_id,
                "details": json.loads(json.dumps(wlan, default=str)),
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error getting WLAN details for {wlan_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_update_wlan",
    description="Atualização de rede wireless UniFi Network via ID com confirmação obrigatória — aceita QUALQUER campo do objeto WLAN do controlador, não apenas nome, senha e segurança: taxa mínima de transmissão (minrate_*), filtro de broadcast, isolamento L2, DTIM, assistente de roaming, banda do SSID, PMF, fast roaming, filtro de MAC, agendamento e grupos de AP. Chame unifi_get_wlan_details antes para ver os nomes e os valores atuais de todos os campos. Use quando precisar ajustar qualquer aspecto de uma WLAN. Responde dizendo campo a campo o que o controlador gravou e o que ele ignorou, porque ele aceita nome de campo desconhecido sem reclamar.",
    permission_category="wlans",
    permission_action="update",
)
async def update_wlan(
    wlan_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Update fields of an existing SSID.

    Args:
        wlan_id: The WLAN `_id` on the target site.
        update_data: Fields to change. Any field of the controller's WLAN object
            is accepted, not only the handful the schema names; call
            `unifi_get_wlan_details` to read the current object and take the
            exact field names from it.

            Field families that are settable and frequently needed:

            - Identity and access: `name`, `x_passphrase`, `security`,
              `wpa_mode`, `wpa3_support`, `pmf_mode`, `hide_ssid`, `enabled`
            - Placement: `networkconf_id` (VLAN), `usergroup_id`,
              `ap_group_ids`, `wlan_band` ("2g", "5g", "both")
            - Airtime and density: `minrate_setting_preference`,
              `minrate_ng_enabled`, `minrate_ng_data_rate_kbps`,
              `minrate_na_enabled`, `minrate_na_data_rate_kbps`,
              `bc_filter_enabled`, `mcastenhance_enabled`, `dtim_mode`,
              `dtim_ng`, `dtim_na`
            - Roaming: `fast_roaming_enabled`, `bss_transition`,
              `roaming_assistant_*` (a minimum-RSSI that disconnects clients
              below the threshold)
            - Isolation and filtering: `l2_isolation`, `proxy_arp`,
              `mac_filter_enabled`, `mac_filter_policy`, `mac_filter_list`
            - Scheduling: `schedule_with_duration`

            One dependency is not obvious and the controller does not report it:
            `minrate_*_data_rate_kbps` is clamped to a default unless
            `minrate_setting_preference` is set to "manual" in the same call.

        confirm: Must be True to apply; otherwise a preview is returned.
        site: Site slug or display name. This is a write: passing the wrong
            site changes the wrong network, so it is resolved and reported.

    Returns:
        `applied` names each requested field the controller is now holding and
        `ignored` each one it is not. A field lands in `ignored` when its name is
        misspelled, when it is not settable on this object, or when the
        controller clamped the value -- all three of which it reports as success.
    """
    if not parse_permission(config.permissions, "wlans", "update"):
        logger.warning(f"Permission denied for updating WLAN ({wlan_id}).")
        return {"success": False, "error": "Permission denied to update WLAN."}

    if not wlan_id:
        return {"success": False, "error": "wlan_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("wlan_update", update_data)
        if not is_valid:
            logger.warning(f"Invalid WLAN update data for ID {wlan_id}: {error_msg}")
            return {"success": False, "error": f"Invalid update data: {error_msg}"}
        if not validated_data:
            return {"success": False, "error": "Update data is effectively empty or invalid."}

        current = await network_manager.get_wlan_details(wlan_id, site=site_slug)
        if not current:
            return inject_site_metadata(
                {"success": False, "error": f"WLAN '{wlan_id}' not found on this site."},
                site_id,
                site_name,
                site_slug,
            )

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="wlan",
                resource_id=wlan_id,
                resource_name=f"{current.get('name')} ({site_name or site_slug})",
                current_state=current,
                updates=validated_data,
            )

        updated_fields_list = list(validated_data.keys())
        logger.info(f"Updating WLAN '{wlan_id}' on site {site_slug}: {', '.join(updated_fields_list)}")
        success = await network_manager.update_wlan(wlan_id, validated_data, site=site_slug)

        if not success:
            return inject_site_metadata(
                {
                    "success": False,
                    "wlan_id": wlan_id,
                    "error": f"Controller refused the update of WLAN '{wlan_id}'. See server logs for the controller message.",
                },
                site_id,
                site_name,
                site_slug,
            )

        # Read back rather than echo the request: the controller is the authority
        # on what was actually stored, and it answers rc=ok for a field name it
        # does not recognise.
        updated_wlan = await network_manager.get_wlan_details(wlan_id, site=site_slug)
        verification = verify_write(validated_data, updated_wlan, before=current)
        return inject_site_metadata(
            {
                "success": True,
                "wlan_id": wlan_id,
                "requested_fields": updated_fields_list,
                **verification,
                "details": json.loads(json.dumps(updated_wlan, default=str)),
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error updating WLAN {wlan_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_wlan",
    description="Criação de rede wireless UniFi Network com validação e confirmação obrigatória — novo SSID corporativo, de visitantes ou de dispositivos, com modo de segurança, senha, VLAN associada e grupo de usuários. Use quando precisar adicionar uma WLAN, configurar WiFi novo ou implementar acesso de visitantes. Cria o SSID no site indicado do controlador UniFi.",
    permission_category="wlans",
    permission_action="create",
)
async def create_wlan(
    wlan_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new SSID on the target site.

    Args:
        wlan_data: WLAN configuration. `name` and `security` are required, plus
            `x_passphrase` for any security mode other than `open`.
        confirm: Must be True to apply; otherwise a preview is returned.
        site: Site slug or display name. This is a write: passing the wrong
            site creates the SSID on the wrong network, so it is resolved and
            reported.
    """
    if not parse_permission(config.permissions, "wlans", "create"):
        logger.warning("Permission denied for creating WLAN.")
        return {"success": False, "error": "Permission denied to create WLAN."}

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("wlan", wlan_data)
        if not is_valid:
            logger.warning(f"Invalid WLAN data: {error_msg}")
            return {"success": False, "error": error_msg}

        missing_fields = [f for f in ("name", "security") if f not in validated_data]
        if missing_fields:
            return {"success": False, "error": f"Missing required fields: {', '.join(missing_fields)}"}

        if validated_data.get("security") != "open" and not validated_data.get("x_passphrase"):
            return {
                "success": False,
                "error": "'x_passphrase' is required when security is not 'open'",
            }

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="wlan",
                resource_data=validated_data,
                resource_name=f"{validated_data.get('name')} ({site_name or site_slug})",
                warnings=["Creating a WLAN may temporarily affect wireless connectivity on this site"],
            )

        payload = dict(validated_data)
        payload.setdefault("enabled", True)
        logger.info(f"Creating WLAN '{payload['name']}' on site {site_slug}")
        created_wlan = await network_manager.create_wlan(payload, site=site_slug)

        if not created_wlan or not created_wlan.get("_id"):
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Controller refused the creation of WLAN '{payload['name']}'. See server logs for the controller message.",
                },
                site_id,
                site_name,
                site_slug,
            )

        return inject_site_metadata(
            {
                "success": True,
                "message": f"WLAN '{payload['name']}' created successfully.",
                "wlan_id": created_wlan.get("_id"),
                "details": json.loads(json.dumps(created_wlan, default=str)),
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except Exception as e:
        logger.error(f"Error creating WLAN: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
