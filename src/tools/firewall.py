"""
Firewall policy tools for Unifi Network MCP server.
"""

import json
import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import config, firewall_manager, network_manager, server, system_manager
from src.utils.confirmation import create_preview, should_auto_confirm, toggle_preview, update_preview
from src.utils.permissions import parse_permission  # CORRECTED import name
from src.utils.site_context import inject_site_metadata, resolve_site_context
from src.validator_registry import UniFiValidatorRegistry  # Added

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_firewall_policies",
    description="Políticas de firewall do controlador UniFi Network — regras de segurança, filtros de tráfego e controles de acesso configurados para proteção da rede. Use quando precisar auditar configurações de firewall, revisar permissões de tráfego ou gerenciar proteção de perímetro. Retorna lista de regras ativas com ação, ruleset e índice no controlador UniFi.",
)
async def list_firewall_policies(include_predefined: bool = False, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Lists firewall policies for the current or specified UniFi site.

    Args:
        include_predefined (bool): Whether to include predefined system policies (default: False).
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Acme", "acme", "grupo-acme" for "Grupo Acme")

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - site (str): The identifier of the UniFi site queried.
        - count (int): The number of firewall policies found.
        - policies (List[Dict]): A list of firewall policies, each containing summary info:
            - id (str): The unique identifier (_id) of the policy.
            - name (str): The user-defined name of the policy.
            - enabled (bool): Whether the policy is currently active.
            - action (str): The policy action (e.g., 'accept', 'drop', 'reject').
            - rule_index (int): The order/index of the rule within its ruleset.
            - ruleset (str): The ruleset this policy belongs to (e.g., 'WAN_IN', 'LAN_OUT').
            - description (str): User-provided description of the policy.
        - error (str, optional): An error message if the operation failed.

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed

    Example response (success):
    {
        "success": True,
        "site": "default",
        "count": 1,
        "policies": [
            {
                "id": "60b8a7f1e4b0f4a7f7d6e8c0",
                "name": "Allow Established/Related",
                "enabled": True,
                "action": "accept",
                "rule_index": 2000,
                "ruleset": "WAN_IN",
                "description": "Allow established and related sessions"
            }
        ]
    }
    """
    if not parse_permission(config.permissions, "firewall", "read"):
        logger.warning("Permission denied for listing firewall policies.")
        return {
            "success": False,
            "error": "Permission denied to list firewall policies.",
        }

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        policies = await firewall_manager.get_firewall_policies(
            include_predefined=include_predefined, site=site_slug
        )
        policies_raw = [p.raw if hasattr(p, "raw") else p for p in policies]

        formatted_policies = [
            {
                "id": p.get("_id"),
                "name": p.get("name"),
                "enabled": p.get("enabled"),
                "action": p.get("action"),
                "rule_index": p.get("index", p.get("rule_index")),
                "ruleset": p.get("ruleset"),
                "description": p.get("description", p.get("desc", "")),
            }
            for p in policies_raw
        ]
        return inject_site_metadata(
            {
                "success": True,
                "site": site_slug,
                "count": len(formatted_policies),
                "policies": formatted_policies,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing firewall policies: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_firewall_policy_details",
    description="Configuração detalhada de política de firewall UniFi Network específica — informações completas de regra, filtro ou controle de segurança identificado por ID único. Use quando precisar auditar configuração específica ou validar regra de proteção. Retorna ação, ruleset, protocolo, endereços e parâmetros da política no controlador UniFi.",
)
async def get_firewall_policy_details(policy_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Gets the detailed configuration of a specific firewall policy by its ID.

    Args:
        policy_id (str): The unique identifier (_id) of the firewall policy.
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - policy_id (str): The ID of the policy requested.
        - details (Dict[str, Any]): A dictionary containing the raw configuration details
          of the firewall policy as returned by the UniFi controller.
        - error (str, optional): An error message if the operation failed (e.g., policy not found).

    Example response (success):
    {
        "success": True,
        "policy_id": "60b8a7f1e4b0f4a7f7d6e8c0",
        "details": {
            "_id": "60b8a7f1e4b0f4a7f7d6e8c0",
            "name": "Allow Established/Related",
            "enabled": True,
            "action": "accept",
            "rule_index": 2000,
            "ruleset": "WAN_IN",
            "description": "Allow established and related sessions",
            "protocol_match_excepted": False,
            "logging": False,
            "state_established": True,
            "state_invalid": False,
            "state_new": False,
            "state_related": True,
            "site_id": "...",
            # ... other fields
        }
    }
    """
    if not parse_permission(config.permissions, "firewall", "read"):
        logger.warning(f"Permission denied for getting firewall policy details ({policy_id}).")
        return {
            "success": False,
            "error": "Permission denied to get firewall policy details.",
        }

    try:
        if not policy_id:
            return {"success": False, "error": "policy_id is required"}
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        policies = await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
        policies_raw = [p.raw if hasattr(p, "raw") else p for p in policies]
        policy = next((p for p in policies_raw if p.get("_id") == policy_id), None)
        if not policy:
            return {
                "success": False,
                "error": f"Firewall policy with ID '{policy_id}' not found.",
            }
        return inject_site_metadata(
            {
                "success": True,
                "policy_id": policy_id,
                "details": json.loads(json.dumps(policy, default=str)),
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting firewall policy details for {policy_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_toggle_firewall_policy",
    description="Alternância de estado de política de firewall UniFi Network via ID — ativação ou desativação de regra, filtro ou controle de segurança com confirmação obrigatória. Use quando precisar habilitar proteção temporariamente, desabilitar regra específica ou gerenciar estado de filtros. Executa toggle de política no controlador UniFi alterando enabled/disabled.",
    permission_category="firewall_policies",
    permission_action="update",
)
async def toggle_firewall_policy(
    policy_id: str, confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Enables or disables a specific firewall policy. Requires confirmation.

    Args:
        policy_id (str): The unique identifier (_id) of the firewall policy to toggle.
        confirm (bool): Must be explicitly set to `True` to execute the toggle operation. Defaults to `False`.
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - policy_id (str): The ID of the policy toggled.
        - enabled (bool): The new state of the policy (True if enabled, False if disabled).
        - message (str): A confirmation message indicating the action taken.
        - error (str, optional): An error message if the operation failed.

    Example response (success):
    {
        "success": True,
        "policy_id": "60b8a7f1e4b0f4a7f7d6e8c0",
        "enabled": false,
        "message": "Firewall policy 'Allow Established/Related' (60b8a7f1e4b0f4a7f7d6e8c0) toggled to disabled."
    }
    """
    if not parse_permission(config.permissions, "firewall", "update"):
        logger.warning(f"Permission denied for toggling firewall policy ({policy_id}).")
        return {
            "success": False,
            "error": "Permission denied to toggle firewall policy.",
        }

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
        policies = await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
        policy_obj = next((p for p in policies if p.id == policy_id), None)
        if not policy_obj or not policy_obj.raw:
            return {
                "success": False,
                "error": f"Firewall policy with ID '{policy_id}' not found.",
            }
        policy = policy_obj.raw

        current_state = policy.get("enabled", False)
        policy_name = policy.get("name", policy_id)
        new_state = not current_state

        if not confirm and not should_auto_confirm():
            return toggle_preview(
                resource_type="firewall_policy",
                resource_id=policy_id,
                resource_name=policy_name,
                current_enabled=current_state,
                additional_info={
                    "action": policy.get("action"),
                    "ruleset": policy.get("ruleset"),
                    "index": policy.get("index"),
                },
            )

        logger.info(f"Attempting to toggle firewall policy '{policy_name}' ({policy_id}) to {new_state}")

        success = await firewall_manager.toggle_firewall_policy(policy_id, site=site_slug)

        if success:
            toggled_policy_obj = next(
                (
                    p
                    for p in await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
                    if p.id == policy_id
                ),
                None,
            )
            final_state = toggled_policy_obj.enabled if toggled_policy_obj else new_state

            logger.info(f"Successfully toggled firewall policy '{policy_name}' ({policy_id}) to {final_state}")
            return inject_site_metadata(
                {
                    "success": True,
                    "policy_id": policy_id,
                    "enabled": final_state,
                    "message": f"Firewall policy '{policy_name}' ({policy_id}) toggled successfully to {'enabled' if final_state else 'disabled'}.",
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            logger.error(f"Failed to toggle firewall policy '{policy_name}' ({policy_id}). Manager returned false.")
            policy_after_toggle_obj = next(
                (
                    p
                    for p in await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
                    if p.id == policy_id
                ),
                None,
            )
            state_after = policy_after_toggle_obj.enabled if policy_after_toggle_obj else "unknown"
            return inject_site_metadata(
                {
                    "success": False,
                    "policy_id": policy_id,
                    "state_after_attempt": state_after,
                    "error": f"Failed to toggle firewall policy '{policy_name}' ({policy_id}). Check server logs.",
                },
                site_id,
                site_name,
                site_slug,
            )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error toggling firewall policy {policy_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


async def _resolve_policy_endpoint(endpoint: Dict[str, str], site_slug: Optional[str]) -> Dict[str, Any]:
    """Expand one compact src/dst selector into the controller endpoint structure.

    Args:
        endpoint: Selector with "type" (zone, network, client_mac, ip_group) and "value".
        site_slug: Site the policy is being created on.

    Returns:
        The endpoint dict the V2 firewall-policies endpoint expects.

    Raises:
        ValueError: Unsupported selector type, or a named network absent from the site.
    """
    etype = endpoint["type"].lower()
    value = endpoint["value"].strip()
    base = {
        "match_opposite_ports": False,
        "port_matching_type": "any",
    }
    if etype == "zone":
        return {**base, "matching_target": "zone", "zone_id": value.lower()}
    if etype == "network":
        # Networks are looked up on the same site the policy lands on, so a name
        # never resolves against a like-named network of another site.
        networks = await network_manager.get_networks(site=site_slug)
        net = next(
            (n for n in networks if n.get("_id") == value or n.get("name") == value),
            None,
        )
        if not net:
            raise ValueError(f"Network '{value}' not found")
        return {
            **base,
            "matching_target": "network_id",
            "network_id": net["_id"],
            "zone_id": "lan",  # network selectors still need a zone for the API; default lan
        }
    if etype == "client_mac":
        return {
            **base,
            "matching_target": "client_macs",
            "client_macs": [value.lower()],
            "zone_id": "lan",
        }
    if etype == "ip_group":
        return {
            **base,
            "matching_target": "ip_group_id",
            "ip_group_id": value,
            "zone_id": "lan",
        }
    raise ValueError(f"Unsupported selector type '{etype}'")


async def _expand_simple_policy(policy: Dict[str, Any], site_slug: Optional[str]) -> Dict[str, Any]:
    """Build the controller payload from a validated compact policy.

    Raises:
        ValueError: Propagated from selector expansion.
    """
    return {
        "name": policy["name"],
        "ruleset": policy["ruleset"],
        "action": policy["action"].lower(),
        "index": policy.get("index", 3000),  # the controller needs a position; default late in the ruleset
        "enabled": policy.get("enabled", True),
        "logging": policy.get("log", False),
        "protocol": policy.get("protocol", "all"),
        # inclusive over every state keeps the compact form matching the traffic a
        # user means when they say "block this"
        "connection_state_type": "inclusive",
        "connection_states": ["new", "established", "related", "invalid"],
        "source": await _resolve_policy_endpoint(policy["src"], site_slug),
        "destination": await _resolve_policy_endpoint(policy["dst"], site_slug),
    }


@server.tool(
    name="unifi_create_firewall_policy",
    description="Políticas e regras de firewall no UniFi Network — criação por forma compacta (seletores src/dst de zona, rede, MAC ou grupo de IPs) ou por payload completo da API V2, detectada automaticamente pelo formato enviado. Use quando precisar bloquear, liberar ou filtrar tráfego entre zonas e redes. Retorna preview com confirm=false e a política criada no UniFi com confirm=true.",
    permission_category="firewall_policies",
    permission_action="create",
)
async def create_firewall_policy(
    policy_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Create a firewall policy from either a compact or a controller-shaped definition.

    Two input shapes are accepted in `policy_data`; the shape is detected from the
    keys, never declared by the caller.

    **Compact shape** -- high-level selectors, expanded here into the controller
    structure:
    {
        "name":    "Block Xbox",
        "ruleset": "LAN_OUT",
        "action":  "drop",
        "src": {"type": "client_mac", "value": "4c:3b:df:2c:c8:c6"},
        "dst": {"type": "zone", "value": "wan"},
        "protocol": "all",            # optional, default "all"
        "index": 2010,                # optional, defaults to 3000
        "enabled": True,              # optional, default True
        "log": True                   # optional, default False
    }
    Selector types: "zone", "network" (name or id), "client_mac", "ip_group".
    Connection states and port matching get sane defaults; use the complete shape
    when those need to be controlled.

    **Complete shape** -- the payload the V2 `/firewall-policies` endpoint expects,
    sent through untouched. Refer to UniFi documentation or examine existing policies
    using `unifi_get_firewall_policy_details` for the exact structure.

    **Required** keys in the complete shape:
    - name (string): A descriptive name for the firewall policy.
    - ruleset (string): The target ruleset (e.g., "WAN_IN", "LAN_OUT", "GUEST_LOCAL").
    - action (string): The action to take (must be lowercase: "accept", "drop", "reject").
    - index (integer): The position/priority of the rule within the ruleset (lower numbers execute first).
                       Note: API internally uses 'index', not 'rule_index'.

    **Common Optional** keys in the complete shape:
    - enabled (boolean): Whether the rule is active upon creation (default: True).
    - description (string): A brief description of the rule's purpose.
    - logging (boolean): Enable logging for matched traffic (default: False).
    - protocol (string): Network protocol ("tcp", "udp", "icmp", "all", etc.).
    - connection_states (list[string]): Connection states to match (e.g., ["new", "established", "related"]).
    - source (dict): Source definition (see UniFi structure - often includes `zone_id`, `matching_target`, etc.).
    - destination (dict): Destination definition (see UniFi structure).
    - icmp_typename (string): Specific ICMP type name (if protocol is "icmp").
    - icmp_v6_typename (string): Specific ICMPv6 type name (if protocol is "icmpv6").
    - ... and other fields specific to the UniFi API.

    Example `policy_data` (complete shape, simple block):
    {
        "name": "Block Xbox LAN Out",
        "ruleset": "LAN_OUT",
        "action": "drop",
        "index": 2010,
        "enabled": True,
        "logging": True,
        "description": "Block specific Xbox device from WAN",
        "source": {
            "match_opposite_ports": False,
            "matching_target": "client_macs",
            "port_matching_type": "any",
            "zone_id": "trusted", # Replace with actual source zone ID if needed
            "client_macs": ["4c:3b:df:2c:c8:c6"] # Example MAC
        },
        "destination": {
            "match_opposite_ports": False,
            "matching_target": "zone",
            "port_matching_type": "any",
            "zone_id": "wan" # Target the WAN zone
        },
        "protocol": "all",
        "connection_state_type": "inclusive",
        "connection_states": ["new", "established", "related", "invalid"], # Block all states
        "ip_version": "ipv4" # Or "ipv6" or "both"
    }

    Args:
        policy_data (Dict[str, Any]): The firewall policy configuration, in either shape.
        confirm (bool): Must be explicitly set to `True` to execute the creation. Defaults to `False`,
                        which returns the fully expanded payload as a preview.
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Acme", "acme", "grupo-acme" for "Grupo Acme")

    Returns:
        A dictionary containing:
        - success (boolean): Whether the operation succeeded.
        - message (string): Confirmation message on success.
        - policy_id (string): The ID (_id) of the newly created policy if successful.
        - details (Dict): Full details of the created policy as returned by the controller.
        - error (string): Error message if unsuccessful (includes validation errors or API errors).

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    if not parse_permission(config.permissions, "firewall", "create"):
        logger.warning("Permission denied for creating firewall policy.")
        return {
            "success": False,
            "error": "Permission denied to create firewall policy.",
        }

    if not isinstance(policy_data, dict) or not policy_data:
        return {
            "success": False,
            "error": "policy_data must be a non-empty dictionary.",
        }

    try:
        # Resolved up front because expanding a compact "network" selector has to
        # query the same site the policy will be created on.
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # "src"/"dst" exist only in the compact shape -- the controller shape spells
        # them "source"/"destination". Choosing the schema from that marker keeps a
        # validation error attributable to the shape the caller actually sent,
        # instead of reporting the other shape's missing fields.
        is_compact = "src" in policy_data or "dst" in policy_data

        if is_compact:
            is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate(
                "firewall_policy_simple", policy_data
            )
            if not is_valid or validated_data is None:
                logger.warning(f"Invalid compact firewall policy data: {error_msg}")
                return {"success": False, "error": f"Validation Error: {error_msg}"}

            try:
                policy_data_to_send = await _expand_simple_policy(validated_data, site_slug)
            except ValueError as exc:
                return {"success": False, "error": str(exc)}
        else:
            is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate(
                "firewall_policy_create", policy_data
            )
            if not is_valid or validated_data is None:
                logger.warning(f"Invalid firewall policy data: {error_msg}")
                # Provide the specific validation error back to the caller
                return {"success": False, "error": f"Validation Error: {error_msg}"}

            # Enforce lowercase action (Validator might also handle this depending on schema definition)
            action = validated_data.get("action", "")
            if not isinstance(action, str) or action.lower() not in [
                "accept",
                "drop",
                "reject",
            ]:
                # This check might be redundant if the validator enforces enum values
                error = f"Invalid 'action' after validation: '{action}'. Must be one of 'accept', 'drop', 'reject' (lowercase)."
                logger.warning(error)
                return {"success": False, "error": error}
            validated_data["action"] = action.lower()  # Normalize in the validated data

            # Use the validated and potentially cleaned/defaulted data
            policy_data_to_send = validated_data

        policy_name = policy_data_to_send.get("name", "Unnamed Policy")
        ruleset = policy_data_to_send.get("ruleset", "Unknown Ruleset")

        if not confirm and not should_auto_confirm():
            return create_preview(
                resource_type="firewall_policy",
                resource_data=policy_data_to_send,
                resource_name=policy_name,
            )

        logger.info(f"Attempting to create firewall policy '{policy_name}' in ruleset '{ruleset}'")

        created_policy_obj = await firewall_manager.create_firewall_policy(policy_data_to_send, site=site_slug)

        if created_policy_obj and hasattr(created_policy_obj, "raw"):
            created_policy_details = created_policy_obj.raw
            new_policy_id = created_policy_details.get("_id", "unknown")
            logger.info(f"Successfully created firewall policy '{policy_name}' with ID {new_policy_id}")
            return inject_site_metadata(
                {
                    "success": True,
                    "message": f"Firewall policy '{policy_name}' created successfully.",
                    "policy_id": new_policy_id,
                    "details": json.loads(json.dumps(created_policy_details, default=str)),  # Ensure serialization
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            # The manager method should log specific errors, return a generic failure here.
            logger.error(f"Failed to create firewall policy '{policy_name}'. Manager returned None or invalid object.")
            return {
                "success": False,
                "error": f"Failed to create firewall policy '{policy_name}'. Check manager logs for details (e.g., API errors, invalid data).",
            }

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        # Catch unexpected errors during the tool's execution
        logger.error(
            f"Unexpected error creating firewall policy: {e}",
            exc_info=True,
        )
        return {"success": False, "error": f"An unexpected error occurred: {str(e)}"}


@server.tool(
    name="unifi_update_firewall_policy",
    description="Atualização de política de firewall UniFi Network existente via ID — modificação de campos específicos de regra, filtro ou controle de segurança com confirmação obrigatória. Use quando precisar ajustar proteção, modificar parâmetros de bloqueio ou atualizar permissão de tráfego. Executa update parcial de política no controlador UniFi com suporte multi-site.",
    permission_category="firewall_policies",
    permission_action="update",
)
async def update_firewall_policy(
    policy_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Updates specific fields of an existing firewall policy. Requires confirmation.

    Allows modifying properties like name, action, enabled state, rule index,
    protocol, addresses, ports, etc. Only provided fields are updated.

    Args:
        policy_id (str): The unique identifier (_id) of the firewall policy to update.
        update_data (Dict[str, Any]): A dictionary containing the fields to update.
            Allowed fields (all optional):
            - name (string): New name for the policy.
            - ruleset (string): Move to a different ruleset (e.g., "WAN_IN").
            - action (string): New action ("accept", "drop", "reject").
            - rule_index (integer): New position index.
            - protocol (string): New protocol ("tcp", "udp", "icmp", "all").
            - src_address (string): New source IP/CIDR.
            - dst_address (string): New destination IP/CIDR.
            - src_port (string): New source port/range.
            - dst_port (string): New destination port/range.
            - enabled (boolean): New enabled state.
            - description (string): New description.
            - state_new (boolean): New state matching.
            - state_established (boolean): New state matching.
            - state_related (boolean): New state matching.
            - state_invalid (boolean): New state matching.
            - logging (boolean): New logging state.
        confirm (bool): Must be explicitly set to `True` to execute the update. Defaults to `False`.
        site: Optional site name/slug. If None, uses current default site.
              Accepts fuzzy matching (e.g., "Acme", "acme", "grupo-acme" for "Grupo Acme")

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - policy_id (str): The ID of the policy that was updated.
        - updated_fields (List[str]): Field names that were successfully updated.
        - details (Dict[str, Any]): Full details of the policy after the update.
        - error (str, optional): Error message if the operation failed.

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed

    Example call:
    update_firewall_policy(
        policy_id="60b8a7f1e4b0f4a7f7d6e8c0",
        update_data={
            "name": "Allow Established - Updated",
            "enabled": False,
            "logging": True
        },
        confirm=True
    )

    Example response (success):
    {
        "success": True,
        "policy_id": "60b8a7f1e4b0f4a7f7d6e8c0",
        "updated_fields": ["name", "enabled", "logging"],
        "details": { ... updated policy details ... }
    }
    """
    if not parse_permission(config.permissions, "firewall", "update"):
        logger.warning(f"Permission denied for updating firewall policy ({policy_id}).")
        return {
            "success": False,
            "error": "Permission denied to update firewall policy.",
        }

    if not policy_id:
        return {"success": False, "error": "policy_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("firewall_policy_update", update_data)
    if not is_valid:
        logger.warning(f"Invalid firewall policy update data for ID {policy_id}: {error_msg}")
        return {"success": False, "error": f"Invalid update data: {error_msg}"}

    if not validated_data:
        logger.warning(f"Firewall policy update data for ID {policy_id} is empty after validation.")
        return {
            "success": False,
            "error": "Update data is effectively empty or invalid.",
        }

    updated_fields_list = list(validated_data.keys())

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch current policy state for preview
        policies = await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
        current_policy_obj = next((p for p in policies if p.id == policy_id), None)
        if not current_policy_obj or not current_policy_obj.raw:
            return {
                "success": False,
                "error": f"Firewall policy with ID '{policy_id}' not found.",
            }
        current = current_policy_obj.raw

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="firewall_policy",
                resource_id=policy_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        logger.info(f"Attempting to update firewall policy '{policy_id}' with fields: {', '.join(updated_fields_list)}")

        success = await firewall_manager.update_firewall_policy(policy_id, validated_data, site=site_slug)

        if success:
            updated_policy_obj = next(
                (
                    p
                    for p in await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
                    if p.id == policy_id
                ),
                None,
            )
            updated_details = updated_policy_obj.raw if updated_policy_obj else {}
            logger.info(f"Successfully updated firewall policy ({policy_id})")
            return inject_site_metadata(
                {
                    "success": True,
                    "policy_id": policy_id,
                    "updated_fields": updated_fields_list,
                    "details": json.loads(json.dumps(updated_details, default=str)),
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            logger.error(f"Failed to update firewall policy ({policy_id}). Manager returned false.")
            policy_after_update_obj = next(
                (
                    p
                    for p in await firewall_manager.get_firewall_policies(include_predefined=True, site=site_slug)
                    if p.id == policy_id
                ),
                None,
            )
            details_after_attempt = policy_after_update_obj.raw if policy_after_update_obj else {}
            return inject_site_metadata(
                {
                    "success": False,
                    "policy_id": policy_id,
                    "error": f"Failed to update firewall policy ({policy_id}). Check server logs.",
                    "details_after_attempt": json.loads(json.dumps(details_after_attempt, default=str)),
                },
                site_id,
                site_name,
                site_slug,
            )

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating firewall policy {policy_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_list_firewall_zones",
    description="Zonas de firewall do controlador UniFi Network via API V2 — áreas de segurança, segmentos de rede e perímetros configurados para isolamento e controle de tráfego. Use quando precisar listar zonas disponíveis, identificar segmentos de proteção ou configurar políticas baseadas em zona. Retorna lista completa de zonas definidas no controlador UniFi.",
)
async def list_firewall_zones(site: Optional[str] = None) -> Dict[str, Any]:
    site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
    zones = await firewall_manager.get_firewall_zones(site=site_slug)
    return inject_site_metadata(
        {"success": True, "count": len(zones), "zones": zones},
        site_id,
        site_name,
        site_slug,
    )


@server.tool(
    name="unifi_list_ip_groups",
    description="Grupos de IP do controlador UniFi Network via API V2 — conjuntos de endereços, coleções de hosts e agrupamentos de rede configurados para aplicação em regras de firewall. Use quando precisar listar grupos disponíveis, identificar conjuntos de endereços ou configurar políticas baseadas em grupo. Retorna lista completa de IP groups no controlador UniFi.",
)
async def list_ip_groups(site: Optional[str] = None) -> Dict[str, Any]:
    site_id, site_name, site_slug = await resolve_site_context(site, system_manager)
    groups = await firewall_manager.get_ip_groups(site=site_slug)
    return inject_site_metadata(
        {"success": True, "count": len(groups), "ip_groups": groups},
        site_id,
        site_name,
        site_slug,
    )
