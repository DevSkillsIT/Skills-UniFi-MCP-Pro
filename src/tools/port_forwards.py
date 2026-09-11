"""
Port forward tools for Unifi Network MCP server.
"""

import json
import logging
from typing import Any, Dict, Optional

from src.runtime import config, firewall_manager, server, system_manager
from src.utils.confirmation import create_preview, should_auto_confirm, toggle_preview, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import resolve_site_context
from src.validator_registry import UniFiValidatorRegistry  # Added for validation

logger = logging.getLogger(__name__)

# Ports the controller stores as strings, including ranges like "10000-10010".
# A caller writing a port as a number is writing it the ordinary way, so it is
# coerced here rather than refused with a type error that reads like a typo.
PORT_FIELDS = ("ext_port", "int_port", "dst_port", "fwd_port")


def _coerce_ports(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Render numeric port values as the strings the schema and controller use."""
    coerced = dict(payload)
    for field in PORT_FIELDS:
        value = coerced.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            coerced[field] = str(value)
    return coerced


@server.tool(
    name="unifi_list_port_forwards",
    description="Regras de port forwarding do controlador UniFi Network — redirecionamentos de portas, mapeamentos NAT e exposição de serviços internos para acesso externo via WAN. Use quando precisar listar port forwards, auditar NAT ou revisar exposição de serviços. Retorna lista completa de regras com protocolo, porta externa, IP interno e porta de destino no controlador UniFi.",
)
async def list_port_forwards(site: Optional[str] = None) -> Dict[str, Any]:
    """List all port forwarding rules configured on the UniFi Network controller.

    Args:
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - site (str): The identifier of the UniFi site queried.
        - count (int): The number of port forwarding rules found.
        - port_forwards (List[Dict]): A list of port forward rules, each containing:
            - id (str): The unique identifier of the rule.
            - name (str): The user-defined name of the rule.
            - enabled (bool): Whether the rule is currently active.
            - src_port (str): The destination/external port or range.
            - dst_port (str): The internal port or range to forward to.
            - protocol (str): The network protocol ('tcp', 'udp', 'tcp/udp').
            - dest_ip (str): The internal IP address to forward to.
        - error (str, optional): An error message if the operation failed.

    Example response (success):
    {
        "success": True,
        "site": "default",
        "count": 1,
        "port_forwards": [
            {
                "id": "60f5a9b3e4b0f4a7f7d6e8c1",
                "name": "Web Server",
                "enabled": True,
                "src_port": "80",
                "dst_port": "8080",
                "protocol": "tcp",
                "dest_ip": "192.168.1.100"
            }
        ]
    }
    """
    if not parse_permission(config.permissions, "port_forward", "read"):
        logger.warning("Permission denied for listing port forwards.")
        return {"success": False, "error": "Permission denied to list port forwards."}
    try:
        _site_id, _site_name, site_slug = await resolve_site_context(site, system_manager)

        rules = await firewall_manager.get_port_forwards(site=site_slug)
        rules_raw = [r.raw if hasattr(r, "raw") else r for r in rules]
        port_forward_list = [
            {
                "id": r.get("_id"),
                "name": r.get("name"),
                "enabled": r.get("enabled"),
                "src_port": r.get("dst_port"),  # Note: UniFi uses dst_port for external
                "dst_port": r.get("fwd_port"),  # Note: UniFi uses fwd_port for internal
                "protocol": r.get("proto"),
                "dest_ip": r.get("fwd"),
            }
            for r in rules_raw
        ]
        return {
            "success": True,
            "site": site_slug,
            "count": len(port_forward_list),
            "port_forwards": port_forward_list,
        }
    except Exception as e:
        logger.error(f"Error listing port forwards: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_port_forward",
    description="Detalhes completos de regra de port forwarding UniFi Network específica — informações de redirecionamento de porta, mapeamento NAT e exposição de serviço identificados por ID único. Use quando precisar auditar port forward específico, validar NAT ou revisar configuração de redirecionamento. Retorna protocolo, portas, IP de destino e habilitação da regra no controlador UniFi.",
)
async def get_port_forward(
    port_forward_id: str, site: Optional[str] = None
) -> Dict[str, Any]:
    """Get detailed information about a specific port forwarding rule by its ID.

    Args:
        port_forward_id (str): The unique identifier (_id) of the port forwarding rule.
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - port_forward_id (str): The ID of the rule requested.
        - details (Dict[str, Any]): A dictionary containing the raw configuration details
          of the port forwarding rule as returned by the UniFi controller.
        - error (str, optional): An error message if the operation failed (e.g., rule not found).

    Example response (success):
    {
        "success": True,
        "port_forward_id": "60f5a9b3e4b0f4a7f7d6e8c1",
        "details": {
            "_id": "60f5a9b3e4b0f4a7f7d6e8c1",
            "name": "Web Server",
            "enabled": True,
            "dst_port": "80",
            "fwd_port": "8080",
            "fwd": "192.168.1.100",
            "proto": "tcp",
            "site_id": "...",
            # ... other fields
        }
    }
    """
    if not parse_permission(config.permissions, "port_forward", "read"):
        logger.warning(f"Permission denied for getting port forward ({port_forward_id}).")
        return {
            "success": False,
            "error": "Permission denied to get port forward details.",
        }
    try:
        if not port_forward_id:
            return {"success": False, "error": "port_forward_id is required"}

        _site_id, _site_name, site_slug = await resolve_site_context(site, system_manager)

        rule_obj = await firewall_manager.get_port_forward_by_id(port_forward_id, site=site_slug)
        rule = rule_obj.raw if (rule_obj and hasattr(rule_obj, "raw")) else rule_obj

        if not rule:
            return {
                "success": False,
                "error": f"Port forwarding rule '{port_forward_id}' not found",
            }

        # Return full details, ensure serializable
        return {
            "success": True,
            "port_forward_id": port_forward_id,
            "details": json.loads(json.dumps(rule, default=str)),
        }
    except Exception as e:
        logger.error(f"Error getting port forward {port_forward_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_toggle_port_forward",
    description="Habilitação/desabilitação de regra de port forwarding UniFi Network via ID — alternância de estado de redirecionamento de porta sem remoção permanente. Use quando precisar ativar/desativar port forward temporariamente, pausar NAT ou suspender exposição de serviço. Executa toggle de regra de redirecionamento no controlador UniFi com confirmação obrigatória.",
    permission_category="port_forwards",
    permission_action="update",
)
async def toggle_port_forward(
    port_forward_id: str, confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Enables or disables a specific port forwarding rule. Requires confirmation.

    Args:
        port_forward_id (str): The unique identifier (_id) of the port forwarding rule to toggle.
        confirm (bool): Must be explicitly set to `True` to execute the toggle operation. Defaults to `False`.
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - port_forward_id (str): The ID of the rule that was toggled.
        - enabled (bool): The new state of the rule (True if enabled, False if disabled).
        - message (str): A confirmation message indicating the action taken.
        - error (str, optional): An error message if the operation failed (e.g., permission denied,
          confirmation missing, rule not found, toggle failed).

    Example response (success):
    {
        "success": True,
        "port_forward_id": "60f5a9b3e4b0f4a7f7d6e8c1",
        "enabled": False,
        "message": "Port forward 'Web Server' toggled to disabled."
    }
    """

    if not parse_permission(config.permissions, "port_forward", "update"):
        logger.warning(f"Permission denied for toggling port forward ({port_forward_id}).")
        return {"success": False, "error": "Permission denied to toggle port forward."}

    try:
        if not port_forward_id:
            return {"success": False, "error": "port_forward_id is required"}

        _site_id, _site_name, site_slug = await resolve_site_context(site, system_manager)

        rule_obj = await firewall_manager.get_port_forward_by_id(port_forward_id, site=site_slug)
        rule = rule_obj.raw if (rule_obj and hasattr(rule_obj, "raw")) else rule_obj
        if not rule:
            return {
                "success": False,
                "error": f"Port forwarding rule '{port_forward_id}' not found",
            }

        rule_name = rule.get("name", port_forward_id)
        current_enabled = rule.get("enabled", False)

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return toggle_preview(
                resource_type="port_forward",
                resource_id=port_forward_id,
                resource_name=rule_name,
                current_enabled=current_enabled,
                additional_info={
                    "dst_port": rule.get("dst_port"),
                    "fwd": rule.get("fwd"),
                    "fwd_port": rule.get("fwd_port"),
                },
            )

        new_state = not current_enabled

        logger.info(f"Attempting to toggle port forward '{rule_name}' ({port_forward_id}) to {new_state}")

        # The target state is written explicitly rather than delegating to the
        # manager's own toggle, so the rule lands in the state the preview
        # showed the caller even if something else changed it in between.
        update_payload = {"enabled": new_state}
        success = await firewall_manager.update_port_forward(port_forward_id, update_payload, site=site_slug)

        if success:
            logger.info(f"Successfully toggled port forward '{rule_name}' ({port_forward_id}) to {new_state}")
            return {
                "success": True,
                "port_forward_id": port_forward_id,
                "enabled": new_state,
                "message": f"Port forward '{rule_name}' toggled to {'enabled' if new_state else 'disabled'}.",
            }
        else:
            # Re-fetch to check the state if the update call failed
            rule_after_toggle_obj = await firewall_manager.get_port_forward_by_id(port_forward_id, site=site_slug)
            rule_after_toggle = (
                rule_after_toggle_obj.raw
                if (rule_after_toggle_obj and hasattr(rule_after_toggle_obj, "raw"))
                else rule_after_toggle_obj
            )
            state_after = rule_after_toggle.get("enabled") if rule_after_toggle else "unknown"
            logger.error(
                f"Failed to toggle port forward '{rule_name}' ({port_forward_id}). State after attempt: {state_after}. Manager update returned false."
            )
            return {
                "success": False,
                "error": f"Failed to toggle port forward '{rule_name}'. Check server logs.",
            }

    except Exception as e:
        logger.error(f"Error toggling port forward {port_forward_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


# Create Port Forward
@server.tool(
    name="unifi_create_port_forward",
    description="Port forwarding e NAT no UniFi Network — criação de redirecionamento por forma compacta (ext_port, to_ip) ou por payload completo da API (dst_port, fwd_port, fwd), detectada automaticamente pelo formato enviado. Use quando precisar expor serviço interno na WAN, publicar porta ou mapear NAT. Retorna preview com confirm=false e a regra criada no UniFi com confirm=true.",
    permission_category="port_forwards",
    permission_action="create",
)
async def create_port_forward(
    port_forward_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Create a port forwarding rule from either a compact or a complete definition.

    Two input shapes are accepted in `port_forward_data`; the shape is detected from
    the keys, never declared by the caller.

    **Compact shape** -- external port and destination host, the rest defaulted:
    {
        "name": "Home Web",
        "ext_port": "8443",
        "to_ip": "192.168.1.10",
        "int_port": "443",          # optional (defaults to ext_port)
        "protocol": "tcp",          # optional: "tcp", "udp", "both" (default "both")
        "enabled": True             # optional (default True)
    }

    **Complete shape** -- the fields the controller names:
    - name (string): Name for the port forwarding rule
    - dst_port (string): Destination/external port (e.g., "80", "443", "22" or range "10000-10010")
    - fwd_port (string): Internal port to forward to (e.g., "80", "8080" or range "10000-10010")
    - fwd (string): Internal IP address to forward to. `fwd_ip` is accepted as an alias.

    Optional in the complete shape:
    - protocol (string): Network protocol - "tcp", "udp", or "tcp_udp" (default: "tcp_udp")
    - enabled (boolean): Whether rule is enabled initially (default: true)
    - src_ip (string): Source IP/CIDR to match (default: any)
    - log (boolean): Whether to log rule matches (default: false)

    Example (complete shape):
    {
        "name": "Web Server",
        "dst_port": "80",
        "fwd_port": "8080",
        "fwd": "192.168.1.100",
        "protocol": "tcp",
        "enabled": true
    }

    Args:
        port_forward_data: The rule configuration, in either shape.
        confirm: Must be True to apply; otherwise the expanded payload is returned as a preview.
        site: Optional site name/slug. If None, uses current default site.

    Returns:
    - success (boolean): Whether the operation succeeded
    - message (string): Confirmation message on success
    - port_forward_id (string): ID of the created rule if successful
    - details (object): Additional details about the created rule
    - error (string): Error message if unsuccessful
    """
    if not parse_permission(config.permissions, "port_forward", "create"):
        logger.warning("Permission denied for creating port forward.")
        return {"success": False, "error": "Permission denied to create port forward."}

    # "ext_port"/"to_ip" exist only in the compact shape -- the controller shape
    # spells them "dst_port"/"fwd". Choosing the schema from those markers keeps
    # a validation error attributable to the shape the caller actually sent.
    is_compact = "ext_port" in port_forward_data or "to_ip" in port_forward_data

    if is_compact:
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate(
            "port_forward_simple", _coerce_ports(port_forward_data)
        )
        if not is_valid or validated_data is None:
            logger.warning(f"Invalid compact port forward data: {error_msg}")
            return {"success": False, "error": error_msg or "Validation failed"}

        rule_name = validated_data["name"]
        rule_data: Dict[str, Any] = {
            "name": rule_name,
            "dst_port": str(validated_data["ext_port"]),
            "fwd_port": str(validated_data.get("int_port", validated_data["ext_port"])),
            # The controller reads the destination as `fwd`. Sent as `fwd_ip` it
            # is accepted with rc=ok and dropped, leaving a rule that forwards
            # nowhere.
            "fwd": validated_data["to_ip"],
            # The controller reads `proto`, not `protocol`. A rule sent with
            # `protocol` is accepted with rc=ok and stored with no protocol at
            # all, which forwards nothing and reports success.
            "proto": {
                "tcp": "tcp",
                "udp": "udp",
                "both": "tcp/udp",
                "tcp_udp": "tcp/udp",
            }.get(str(validated_data.get("protocol", "both")).lower(), "tcp/udp"),
            "enabled": validated_data.get("enabled", True),
        }
    else:
        # Validate the input
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("port_forward", _coerce_ports(port_forward_data))
        if not is_valid or validated_data is None:
            logger.warning(f"Invalid port forward data: {error_msg}")
            return {"success": False, "error": error_msg or "Validation failed"}

        # Required fields check
        # `fwd_ip` is the spelling callers and older payloads use; the controller
        # only reads `fwd`, silently discarding the other.
        if "fwd" not in validated_data and validated_data.get("fwd_ip"):
            validated_data["fwd"] = validated_data["fwd_ip"]
        if not validated_data.get("fwd"):
            return {
                "success": False,
                "error": "A forwarding destination is required: pass 'fwd' (or its alias 'fwd_ip').",
            }

        required_fields = ["name", "dst_port", "fwd_port"]
        missing_fields = [field for field in required_fields if field not in validated_data]
        if missing_fields:
            error = f"Missing required fields: {', '.join(missing_fields)}"
            logger.warning(error)
            return {"success": False, "error": error}

        rule_name = validated_data["name"]
        # Prepare data for the manager
        rule_data = {
            "name": rule_name,
            "dst_port": validated_data["dst_port"],
            "fwd_port": validated_data["fwd_port"],
            "fwd": validated_data.get("fwd") or validated_data.get("fwd_ip"),
            "proto": str(validated_data.get("protocol", "tcp_udp")).replace("_", "/"),
            "protocol_match_excepted": False,
            "enabled": validated_data.get("enabled", True),
            "log": validated_data.get("log", False),
        }

        # Handle optional source IP
        if validated_data.get("src_ip"):
            rule_data["src"] = validated_data["src_ip"]

    if not confirm and not should_auto_confirm():
        return create_preview(
            resource_type="port_forward",
            resource_data=rule_data,
            resource_name=rule_name,
        )

    try:
        _site_id, _site_name, site_slug = await resolve_site_context(site, system_manager)

        logger.info(
            f"Attempting to create port forward: {rule_name} "
            f"({rule_data.get('proto')} {rule_data['dst_port']} -> {rule_data.get('fwd')}:{rule_data['fwd_port']})"
        )

        result = await firewall_manager.create_port_forward(rule_data, site=site_slug)

        if result:
            new_rule_id = result if isinstance(result, str) else result.get("_id", "unknown")
            details = result if isinstance(result, dict) else {"id": new_rule_id}
            logger.info(f"Successfully created port forward '{rule_name}' with ID {new_rule_id}")
            return {
                "success": True,
                "message": f"Port forward '{rule_name}' created successfully.",
                "port_forward_id": new_rule_id,
                "details": json.loads(json.dumps(details, default=str)),
            }
        else:
            error_msg = (
                result.get("error", "Manager returned failure")
                if isinstance(result, dict)
                else "Manager returned failure"
            )
            logger.error(f"Failed to create port forward '{rule_name}'. Reason: {error_msg}")
            return {
                "success": False,
                "error": f"Failed to create port forward '{rule_name}'. {error_msg}",
            }

    except Exception as e:
        logger.error(
            f"Error creating port forward '{rule_name}': {e}",
            exc_info=True,
        )
        return {"success": False, "error": str(e)}


# --- NEW UPDATE TOOL ---
@server.tool(
    name="unifi_update_port_forward",
    description="Atualização de regra de port forwarding UniFi Network via ID — modificação de protocolo, portas, IP de destino ou habilitação com confirmação obrigatória. Use quando precisar ajustar port forward, modificar NAT ou alterar redirecionamento. Executa update parcial de regra de port forwarding no controlador UniFi com suporte multi-site.",
    permission_category="port_forwards",
    permission_action="update",
)
async def update_port_forward(
    port_forward_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Updates specific fields of an existing port forwarding rule.

    This tool allows modifying one or more properties of a port forward rule
    identified by its ID. All fields in `update_data` are optional; only provided
    fields will be updated. Requires confirmation.

    Args:
        port_forward_id (str): The unique identifier (_id) of the port forwarding rule to update.
        update_data (Dict[str, Any]): A dictionary containing the fields to update.
            Allowed fields (all optional):
            - name (string): New name for the rule.
            - dst_port (string): New destination/external port or range.
            - fwd_port (string): New internal port or range.
            - fwd (string): New internal IP address. `fwd_ip` is accepted as an alias.
            - protocol (string): New protocol ("tcp", "udp", or "tcp_udp").
            - enabled (boolean): New enabled state (True/False).
            - src_ip (string): New source IP/CIDR match (use empty string "" or null to remove).
            - log (boolean): New logging state (True/False).
        confirm (bool): Must be explicitly set to `True` to execute the update. Defaults to `False`.
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - port_forward_id (str): The ID of the rule that was updated.
        - updated_fields (List[str]): A list of field names that were successfully updated.
        - details (Dict[str, Any]): The full details of the rule after the update.
        - error (str, optional): An error message if the operation failed.

    Example call:
    update_port_forward(
        port_forward_id="60f5a9b3e4b0f4a7f7d6e8c1",
        update_data={
            "name": "Updated Web Server Name",
            "enabled": False,
            "dst_port": "443"
        },
        confirm=True
    )

    Example response (success):
    {
        "success": True,
        "port_forward_id": "60f5a9b3e4b0f4a7f7d6e8c1",
        "updated_fields": ["name", "enabled", "dst_port"],
        "details": { ... updated rule details ... }
    }
    """
    if not parse_permission(config.permissions, "port_forward", "update"):
        logger.warning(f"Permission denied for updating port forward ({port_forward_id}).")
        return {"success": False, "error": "Permission denied to update port forward."}

    if not port_forward_id:
        return {"success": False, "error": "port_forward_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data dictionary cannot be empty"}

    # Validate the update data against the update schema
    is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("port_forward_update", _coerce_ports(update_data))
    if not is_valid:
        logger.warning(f"Invalid port forward update data for ID {port_forward_id}: {error_msg}")
        return {"success": False, "error": f"Invalid update data: {error_msg}"}

    if not validated_data:  # Ensure validation didn't return an empty dict if input was invalid
        logger.warning(f"Port forward update data for ID {port_forward_id} is empty after validation.")
        return {
            "success": False,
            "error": "Update data is effectively empty or invalid.",
        }

    try:
        _site_id, _site_name, site_slug = await resolve_site_context(site, system_manager)

        # Fetch the existing rule first to ensure it exists
        existing_rule_obj = await firewall_manager.get_port_forward_by_id(port_forward_id, site=site_slug)
        existing_rule = existing_rule_obj.raw if (existing_rule_obj and hasattr(existing_rule_obj, "raw")) else None
        if not existing_rule:
            return {
                "success": False,
                "error": f"Port forwarding rule '{port_forward_id}' not found",
            }

        rule_name = existing_rule.get("name", port_forward_id)

        # Return preview when confirm=false
        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="port_forward",
                resource_id=port_forward_id,
                resource_name=rule_name,
                current_state=existing_rule,
                updates=validated_data,
            )

        # Prepare the payload for the manager update function
        # Map schema fields to manager fields if necessary (like protocol)
        update_payload = {}
        updated_fields_list = []
        for key, value in validated_data.items():
            updated_fields_list.append(key)
            if key == "protocol":
                update_payload["proto"] = value.replace("_", "/")
            elif key == "src_ip":
                # Map src_ip to 'src', handle removal if empty string/null
                update_payload["src"] = value if value else None
            # Need to handle 'log' if it's part of the schema/manager
            elif key == "log":
                update_payload["log"] = value
            else:
                update_payload[key] = value

        # Add potentially missing fields required by aiounifi update that aren't directly updatable via schema but needed for context?
        # e.g. _id should be passed in the ID parameter, site_id might be handled by manager
        # We only pass the fields being changed to the manager update function

        logger.info(
            f"Attempting to update port forward '{rule_name}' ({port_forward_id}) with fields: {', '.join(updated_fields_list)}"
        )

        # The manager merges these fields onto the stored rule before sending,
        # because the controller endpoint replaces the whole object.
        success = await firewall_manager.update_port_forward(port_forward_id, update_payload, site=site_slug)

        if success:
            # Fetch the rule again to return the updated state
            updated_rule_obj = await firewall_manager.get_port_forward_by_id(port_forward_id, site=site_slug)
            updated_rule = updated_rule_obj.raw if (updated_rule_obj and hasattr(updated_rule_obj, "raw")) else {}

            logger.info(f"Successfully updated port forward '{rule_name}' ({port_forward_id})")
            return {
                "success": True,
                "port_forward_id": port_forward_id,
                "updated_fields": updated_fields_list,
                "details": json.loads(json.dumps(updated_rule, default=str)),
            }
        else:
            logger.error(f"Failed to update port forward '{rule_name}' ({port_forward_id}). Manager returned false.")
            # Attempt to fetch rule again to see if partial update occurred? Or just report failure.
            rule_after_update_obj = await firewall_manager.get_port_forward_by_id(port_forward_id, site=site_slug)
            rule_after_update = (
                rule_after_update_obj.raw if (rule_after_update_obj and hasattr(rule_after_update_obj, "raw")) else {}
            )
            return {
                "success": False,
                "port_forward_id": port_forward_id,
                "error": f"Failed to update port forward '{rule_name}'. Check server logs.",
                "details_after_attempt": json.loads(
                    json.dumps(rule_after_update, default=str)
                ),  # Provide state after failed attempt
            }

    except Exception as e:
        logger.error(f"Error updating port forward {port_forward_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
