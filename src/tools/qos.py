"""
QoS tools for Unifi Network MCP server.
"""

import json
import logging
from typing import Any, Dict, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.runtime import config, qos_manager, server, system_manager
from src.utils.confirmation import create_preview, should_auto_confirm, toggle_preview, update_preview
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context
from src.validator_registry import UniFiValidatorRegistry

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_list_qos_rules",
    description="Regras de QoS do controlador UniFi Network — políticas de qualidade de serviço, priorização de tráfego e limites de banda configurados para controle de performance, bandwidth e latência. Use quando precisar listar QoS rules, auditar priorização ou revisar bandwidth limits. Retorna lista completa de regras com nome, status, direção e limites no controlador UniFi.",
)
async def list_qos_rules(site: Optional[str] = None) -> Dict[str, Any]:
    """Lists all Quality of Service (QoS) rules configured for a UniFi site.

    Args:
        site (Optional[str]): Site name/slug. If None, uses the default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - site (str): The identifier of the UniFi site queried.
        - count (int): The number of QoS rules found.
        - qos_rules (List[Dict]): A list of QoS rules, each containing summary info:
            - id (str): The unique identifier (_id) of the rule.
            - name (str): The user-defined name of the rule.
            - enabled (bool): Whether the rule is currently active.
            # Add other simple summary fields if available and useful
        - error (str, optional): An error message if the operation failed.

    Example response (success):
    {
        "success": True,
        "site": "default",
        "count": 1,
        "qos_rules": [
            {
                "id": "60d4e5f6a7b8c9d0e1f2a3b4",
                "name": "VoIP Prioritization",
                "enabled": True
            }
        ]
    }
    """
    # Basic permission check (optional for read-only, but good practice)
    if not parse_permission(config.permissions, "qos", "read"):
        logger.warning("Permission denied for listing QoS rules.")
        return {"success": False, "error": "Permission denied to list QoS rules."}
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        qos_rules = await qos_manager.get_qos_rules(site=site_slug)
        rules_raw = [r.raw if hasattr(r, "raw") else r for r in qos_rules]
        formatted_rules = [
            {
                "id": r.get("_id"),
                "name": r.get("name"),
                "enabled": r.get("enabled"),
                # Add other fields as needed for summary
            }
            for r in rules_raw
        ]
        return inject_site_metadata(
            {
                "success": True,
                "site": site_slug,
                "count": len(formatted_rules),
                "qos_rules": formatted_rules,
            },
            site_id,
            site_name,
            site_slug,
        )
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error listing QoS rules: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_get_qos_rule_details",
    description="Detalhes completos de regra de QoS UniFi Network específica — informações de política de qualidade de serviço, priorização de tráfego e limites de banda identificados por ID único. Use quando precisar auditar QoS rule específica, validar priorização ou revisar configuração de bandwidth. Retorna nome, interface, direção, limite e DSCP da QoS rule no controlador UniFi.",
)
async def get_qos_rule_details(rule_id: str, site: Optional[str] = None) -> Dict[str, Any]:
    """Gets the detailed configuration of a specific QoS rule by its ID.

    Args:
        rule_id (str): The unique identifier (_id) of the QoS rule.
        site (Optional[str]): Site name/slug. If None, uses the default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - site (str): The identifier of the UniFi site queried.
        - rule_id (str): The ID of the rule requested.
        - details (Dict[str, Any]): A dictionary containing the raw configuration details
          of the QoS rule as returned by the UniFi controller.
        - error (str, optional): An error message if the operation failed (e.g., rule not found).

    Example response (success):
    {
        "success": True,
        "site": "default",
        "rule_id": "60d4e5f6a7b8c9d0e1f2a3b4",
        "details": {
            "_id": "60d4e5f6a7b8c9d0e1f2a3b4",
            "name": "VoIP Prioritization",
            "enabled": True,
            "interface": "WAN",
            "direction": "upload",
            "bandwidth_limit_kbps": 500,
            "dscp_value": 46,
            "site_id": "...",
            # ... other fields
        }
    }
    """
    if not parse_permission(config.permissions, "qos", "read"):
        logger.warning(f"Permission denied for getting QoS rule details ({rule_id}).")
        return {"success": False, "error": "Permission denied to get QoS rule details."}
    try:
        if not rule_id:
            return {"success": False, "error": "rule_id is required"}

        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        rule = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
        if rule:
            # json round-trip keeps controller values (dates, objects) serializable
            return inject_site_metadata(
                {
                    "success": True,
                    "site": site_slug,
                    "rule_id": rule_id,
                    "details": json.loads(json.dumps(rule, default=str)),
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            return {
                "success": False,
                "error": f"QoS rule with ID '{rule_id}' not found.",
            }
    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting QoS rule {rule_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_toggle_qos_rule_enabled",
    description="Habilitação/desabilitação de regra de QoS UniFi Network via ID — alternância de estado de política de qualidade de serviço sem remoção permanente. Use quando precisar ativar/desativar QoS rule temporariamente, pausar priorização ou suspender limite de banda. Executa toggle de regra de QoS no controlador UniFi com confirmação obrigatória.",
    permission_category="qos_rules",
    permission_action="update",
)
async def toggle_qos_rule_enabled(
    rule_id: str, confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Enables or disables a specific QoS rule. Requires confirmation.

    Args:
        rule_id (str): The unique identifier (_id) of the QoS rule to toggle.
        confirm (bool): Must be explicitly set to `True` to execute the toggle operation. Defaults to `False`.
        site (Optional[str]): Site name/slug. If None, uses the default site.

    Returns:
        A dictionary containing:
        - success (bool): Indicates if the operation was successful.
        - rule_id (str): The ID of the rule toggled.
        - enabled (bool): The new state of the rule (True if enabled, False if disabled).
        - message (str): A confirmation message.
        - error (str, optional): An error message if the operation failed.

    Example response (success):
    {
        "success": True,
        "rule_id": "60d4e5f6a7b8c9d0e1f2a3b4",
        "enabled": false,
        "message": "QoS rule 'VoIP Prioritization' (60d4e5f6a7b8c9d0e1f2a3b4) toggled to disabled."
    }
    """
    if not parse_permission(config.permissions, "qos", "update"):
        logger.warning(f"Permission denied for updating QoS rule state ({rule_id}).")
        return {
            "success": False,
            "error": "Permission denied to update QoS rule state.",
        }

    if not rule_id:
        return {"success": False, "error": "rule_id is required"}

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        # Current state decides the target state, so it is read from the same site the write targets
        rule = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
        if not rule:
            return {
                "success": False,
                "error": f"QoS rule with ID '{rule_id}' not found.",
            }

        if not confirm and not should_auto_confirm():
            return toggle_preview(
                resource_type="qos_rule",
                resource_id=rule_id,
                resource_name=rule.get("name") or rule.get("description"),
                current_enabled=rule.get("enabled", True),
                additional_info={"bandwidth_limit": rule.get("bandwidth_limit_kbps")},
            )

        current_state = rule.get("enabled", False)
        new_state = not current_state
        rule_name = rule.get("name", rule_id)

        logger.info(f"Attempting to toggle QoS rule '{rule_name}' ({rule_id}) to {new_state}")

        update_data = {"enabled": new_state}
        success = await qos_manager.update_qos_rule(rule_id, update_data, site=site_slug)

        if success:
            # Read back so the reported state is the stored one, not the requested one
            rule_after_toggle = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
            final_state = rule_after_toggle.get("enabled", new_state) if rule_after_toggle else new_state

            logger.info(f"Successfully toggled QoS rule '{rule_name}' ({rule_id}) enabled status to {final_state}")
            return inject_site_metadata(
                {
                    "success": True,
                    "rule_id": rule_id,
                    "enabled": final_state,
                    "message": f"QoS rule '{rule_name}' ({rule_id}) toggled to {'enabled' if final_state else 'disabled'}.",
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            logger.error(f"Failed to toggle QoS rule '{rule_name}' ({rule_id}). Manager returned false.")
            rule_after_fail = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
            state_after = rule_after_fail.get("enabled", "unknown") if rule_after_fail else "unknown"
            return inject_site_metadata(
                {
                    "success": False,
                    "rule_id": rule_id,
                    "state_after_attempt": state_after,
                    "error": f"Failed to toggle QoS rule '{rule_name}' ({rule_id}). Check server logs.",
                },
                site_id,
                site_name,
                site_slug,
            )

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error toggling QoS rule {rule_id} state: {e}", exc_info=True)
        return {"success": False, "error": str(e)}



@server.tool(
    name="unifi_update_qos_rule",
    description="Atualização de regra de QoS UniFi Network via ID — modificação de nome, interface, direção, limite de banda ou valor DSCP com confirmação obrigatória. Use quando precisar ajustar QoS rule, modificar priorização ou alterar bandwidth limit. Executa update parcial de regra de QoS no controlador UniFi com suporte multi-site.",
    permission_category="qos_rules",
    permission_action="update",
)
async def update_qos_rule(
    rule_id: str, update_data: Dict[str, Any], confirm: bool = False, site: Optional[str] = None
) -> Dict[str, Any]:
    """Updates specific fields of an existing Quality of Service (QoS) rule.

    Allows modifying properties like name, bandwidth limits, targeting, DSCP values, etc.
    Only provided fields are updated. Requires confirmation.

    Args:
        rule_id (str): The unique identifier (_id) of the QoS rule to update.
        update_data (Dict[str, Any]): Dictionary of fields to update.
            Allowed fields (all optional):
            - name (string): New name for the rule.
            - interface (string): New interface (e.g., 'WAN', 'LAN').
            - direction (string): New direction ('upload', 'download').
            - bandwidth_limit_kbps (integer): New bandwidth limit in Kbps.
            - target_ip_address (string): New target IP address.
            - target_subnet (string): New target subnet (CIDR).
            - dscp_value (integer): New DSCP value (0-63).
            - enabled (boolean): New enabled state.
        confirm (bool): Must be set to `True` to execute. Defaults to `False`.
        site (Optional[str]): Site name/slug. If None, uses the default site.

    Returns:
        Dict: Success status, ID, updated fields, details, or error message.
        Example (success):
        {
            "success": True,
            "rule_id": "60d4e5f6a7b8c9d0e1f2a3b4",
            "updated_fields": ["name", "bandwidth_limit_kbps"],
            "details": { ... updated rule details ... }
        }
    """
    if not parse_permission(config.permissions, "qos", "update"):
        logger.warning(f"Permission denied for updating QoS rule ({rule_id}).")
        return {"success": False, "error": "Permission denied to update QoS rule."}

    if not rule_id:
        return {"success": False, "error": "rule_id is required"}
    if not update_data:
        return {"success": False, "error": "update_data cannot be empty"}

    # Validate the update data
    is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("qos_rule_update", update_data)
    if not is_valid:
        logger.warning(f"Invalid QoS rule update data for ID {rule_id}: {error_msg}")
        return {"success": False, "error": f"Invalid update data: {error_msg}"}

    if not validated_data:
        logger.warning(f"QoS rule update data for ID {rule_id} is empty after validation.")
        return {
            "success": False,
            "error": "Update data is effectively empty or invalid.",
        }

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        current = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
        if not current:
            return {
                "success": False,
                "error": f"QoS rule with ID '{rule_id}' not found.",
            }

        if not confirm and not should_auto_confirm():
            return update_preview(
                resource_type="qos_rule",
                resource_id=rule_id,
                resource_name=current.get("name"),
                current_state=current,
                updates=validated_data,
            )

        updated_fields_list = list(validated_data.keys())
        logger.info(f"Attempting to update QoS rule '{rule_id}' with fields: {', '.join(updated_fields_list)}")

        success = await qos_manager.update_qos_rule(rule_id, validated_data, site=site_slug)

        if success:
            updated_rule = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
            logger.info(f"Successfully updated QoS rule ({rule_id})")
            return inject_site_metadata(
                {
                    "success": True,
                    "rule_id": rule_id,
                    "updated_fields": updated_fields_list,
                    "details": json.loads(json.dumps(updated_rule, default=str)),
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            logger.error(f"Failed to update QoS rule ({rule_id}).")
            rule_after_update = await qos_manager.get_qos_rule_details(rule_id, site=site_slug)
            return inject_site_metadata(
                {
                    "success": False,
                    "rule_id": rule_id,
                    "error": f"Failed to update QoS rule ({rule_id}). Check server logs.",
                    "details_after_attempt": json.loads(json.dumps(rule_after_update, default=str)),
                },
                site_id,
                site_name,
                site_slug,
            )

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error updating QoS rule {rule_id}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


@server.tool(
    name="unifi_create_qos_rule",
    description="Regras de QoS, priorização e limite de banda no UniFi Network — criação por forma compacta (limit_kbps com alvo por IP ou sub-rede) ou por payload completo (bandwidth_limit_kbps), detectada automaticamente pelo formato enviado. Use quando precisar limitar velocidade, priorizar tráfego ou reservar banda. Retorna preview com confirm=false e a regra criada no UniFi com confirm=true.",
    permission_category="qos_rules",
    permission_action="create",
)
async def create_qos_rule(
    qos_data: Dict[str, Any],
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a QoS rule from either a compact or a complete definition.

    Two input shapes are accepted in `qos_data`; the shape is detected from the
    keys, never declared by the caller.

    **Compact shape** -- one bandwidth ceiling and an optional traffic selector:
    {
        "name": "Zoom Upload Limit",
        "interface": "wan",
        "direction": "upload",
        "limit_kbps": 2000,
        "enabled": True,             # optional, default True
        "dscp_value": 46,            # optional
        "target": {                  # optional, omit for every client on the interface
            "type": "ip",          # "ip" | "subnet"
            "value": "192.168.1.50"
        }
    }

    **Complete shape** -- the fields the controller names:
    - name (string): Descriptive name for the QoS rule.
    - interface (string): Network interface (e.g., 'WAN', 'LAN').
    - direction (string): Direction ('upload' or 'download').
    - bandwidth_limit_kbps (integer): Bandwidth limit in Kbps.

    Optional in the complete shape:
    - target_ip_address (string): Specific IP address target.
    - target_subnet (string): Subnet target (CIDR notation).
    - dscp_value (integer): DSCP value (0-63).
    - enabled (boolean): Whether the rule is enabled (default: true).

    Example (complete shape):
    {
        "name": "Zoom Meetings High Priority",
        "interface": "WAN",
        "direction": "upload",
        "bandwidth_limit_kbps": 1000,
        "target_subnet": "192.168.1.0/24",
        "dscp_value": 46,
        "enabled": true
    }

    Args:
        qos_data: The QoS rule configuration, in either shape.
        confirm (bool): Must be set to `True` to execute. Defaults to `False`, which
                        returns the expanded payload as a preview.
        site (Optional[str]): Site name/slug. If None, uses the default site.

    Returns:
    - success (boolean): Whether the operation succeeded.
    - message (string): Confirmation message on success.
    - rule_id (string): ID of the created rule if successful.
    - details (object): Details of the created rule.
    - error (string): Error message if unsuccessful.
    """
    if not parse_permission(config.permissions, "qos", "create"):
        logger.warning("Permission denied for creating QoS rule.")
        return {"success": False, "error": "Permission denied to create QoS rule."}

    # "limit_kbps" exists only in the compact shape -- the controller shape spells it
    # "bandwidth_limit_kbps". Choosing the schema from that marker keeps a validation
    # error attributable to the shape the caller actually sent.
    is_compact = "limit_kbps" in qos_data

    if is_compact:
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("qos_rule_simple", qos_data)
        if not is_valid or validated_data is None:
            logger.warning(f"Invalid compact QoS rule data: {error_msg}")
            return {"success": False, "error": f"Invalid data: {error_msg}"}

        rule_payload: Dict[str, Any] = {
            "name": validated_data["name"],
            "interface": validated_data["interface"],
            "direction": validated_data["direction"],
            "bandwidth_limit_kbps": validated_data["limit_kbps"],
            "enabled": validated_data.get("enabled", True),
        }

        if "dscp_value" in validated_data:
            rule_payload["dscp_value"] = validated_data["dscp_value"]

        target = validated_data.get("target")
        if target:
            t_type = target["type"].lower()
            value = target["value"]
            if t_type == "ip":
                rule_payload["target_ip_address"] = value
            elif t_type == "subnet":
                rule_payload["target_subnet"] = value
            else:
                return {"success": False, "error": f"Unsupported target type '{t_type}'"}
    else:
        # Validate the input data
        is_valid, error_msg, validated_data = UniFiValidatorRegistry.validate("qos_rule", qos_data)
        if not is_valid or validated_data is None:
            logger.warning(f"Invalid QoS rule data: {error_msg}")
            return {"success": False, "error": f"Invalid data: {error_msg}"}

        # Basic required field check (covered by schema, but belt-and-suspenders)
        required = ["name", "interface", "direction", "bandwidth_limit_kbps"]
        if not all(k in validated_data for k in required):
            missing = [k for k in required if k not in validated_data]
            return {"success": False, "error": f"Missing required fields: {missing}"}

        rule_payload = validated_data

    if not confirm and not should_auto_confirm():
        return create_preview(
            resource_type="qos_rule",
            resource_data=rule_payload,
            resource_name=rule_payload.get("name"),
        )

    rule_name = rule_payload["name"]
    logger.info(f"Attempting to create QoS rule '{rule_name}'")
    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        created_rule = await qos_manager.create_qos_rule(rule_payload, site=site_slug)

        # A rule id is only reported when the controller echoed back the stored object
        if created_rule and created_rule.get("_id"):
            new_rule_id = created_rule.get("_id")
            logger.info(f"Successfully created QoS rule '{rule_name}' with ID {new_rule_id}")
            return inject_site_metadata(
                {
                    "success": True,
                    "site": site_slug,
                    "message": f"QoS rule '{rule_name}' created successfully.",
                    "rule_id": new_rule_id,
                    "details": json.loads(json.dumps(created_rule, default=str)),
                },
                site_id,
                site_name,
                site_slug,
            )
        else:
            logger.error(f"Failed to create QoS rule '{rule_name}'.")
            return {
                "success": False,
                "error": f"Failed to create QoS rule '{rule_name}'. Check server logs.",
            }

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error creating QoS rule '{rule_name}': {e}", exc_info=True)
        return {"success": False, "error": str(e)}
