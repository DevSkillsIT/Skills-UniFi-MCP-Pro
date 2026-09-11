"""
Unifi Network MCP device management tools.

This module provides MCP tools to manage devices in a Unifi Network Controller.
Supports multi-site operations with optional site parameter.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from src.exceptions import (
    InvalidSiteParameterError,
    SiteForbiddenError,
    SiteNotFoundError,
)
from src.managers.radio_projection import radio_view, ssid_view
from src.runtime import config, device_manager, server, system_manager
from src.utils.confirmation import action_preview, should_auto_confirm
from src.utils.permissions import parse_permission
from src.utils.site_context import inject_site_metadata, resolve_site_context

logger = logging.getLogger(__name__)

DEVICE_ACTIONS = frozenset({"reboot", "adopt", "rename", "locate", "upgrade", "set_radio"})

# Folding several operations behind one tool must not quietly widen what the
# permission file allows. The decorator gates registration on devices/update;
# an action that is really a create still has to clear devices/create.
DEVICE_ACTION_PERMISSION = {
    "adopt": ("devices", "create"),
}
DEFAULT_DEVICE_PERMISSION = ("devices", "update")

# What the operator is agreeing to when they confirm. Stated per action because
# "are you sure" without a consequence is not a decision.
DEVICE_ACTION_CONSEQUENCES = {
    "reboot": [
        "The device drops off the network while it restarts.",
        "Clients connected through it lose connectivity until it is back.",
    ],
    "adopt": ["The device is provisioned into this site and takes its configuration."],
    "upgrade": [
        "The device downloads and installs firmware, then restarts.",
        "It is unreachable for several minutes and must not lose power.",
    ],
    "set_radio": [
        "The access point re-provisions its radio, briefly dropping wireless clients.",
        "Clients on the affected band reconnect on the new channel.",
    ],
    "rename": ["Only the label changes; the device keeps running."],
    "locate": ["Only the locate LED changes; the device keeps running."],
}

def get_wifi_bands(device_raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Describe the radios an access point is running, configuration and live.

    Delegates to the shared projection so this tool and `unifi_get_ap_stats`
    describe the same radio the same way.
    """
    live_by_name = {
        radio.get("name"): radio
        for radio in (device_raw.get("radio_table_stats") or [])
        if isinstance(radio, dict)
    }
    return [
        radio_view(config, live_by_name.get(config.get("name"), {}))
        for config in (device_raw.get("radio_table") or [])
        if isinstance(config, dict)
    ]


def get_broadcast_ssids(device_raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The SSIDs this access point is broadcasting, per radio."""
    return [ssid_view(v) for v in (device_raw.get("vap_table") or []) if isinstance(v, dict)]


@server.tool(
    name="unifi_list_devices",
    description="Equipamentos de rede UniFi Network adotados pelo controlador — lista completa de access points, switches, gateways e PDUs gerenciados. Use quando precisar visualizar dispositivos de infraestrutura, auditar hardware ou monitorar equipamentos da rede UniFi. Retorna lista otimizada com campos essenciais (nome, tipo, status, IP, modelo) para consultas eficientes no controlador UniFi.",
)
async def list_devices(
    device_type: str = "all", summary: bool = True, limit: int = 20, site: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation for listing devices with token-efficient defaults.

    Args:
        device_type: Filter by device type (all, ap, switch, gateway, pdu)
        summary: Return only essential fields (name, type, status, ip) - DEFAULT: True for token efficiency
        limit: Maximum number of devices to return (default: 20, max: 100)
        site: Optional site name/slug. If None, uses current default site

    Returns:
        Dict with optimized device list and metadata
    """
    try:
        # Enforce reasonable limits
        limit = min(max(1, limit), 100)

        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        devices = await device_manager.get_devices(site=site_slug)

        # Convert Device objects to plain dictionaries
        devices_raw = [d.raw if hasattr(d, "raw") else d for d in devices]

        # Filter by device type
        if device_type != "all":
            prefix_map = {
                "ap": "uap",
                "switch": ("usw", "usk"),
                "gateway": ("ugw", "udm", "uxg"),
                "pdu": "usp",
            }
            prefixes = prefix_map.get(device_type)
            if prefixes:
                devices_raw = [d for d in devices_raw if d.get("type", "").startswith(prefixes)]

        # Apply limit
        devices_raw = devices_raw[:limit]

        # Optimized device data
        if summary:
            devices_optimized = []
            for device in devices_raw:
                device_summary = {
                    "name": device.get("name", "Unknown"),
                    "type": device.get("type", "unknown"),
                    "model": device.get("model", ""),
                    "state": device.get("state", "unknown"),
                    "ip": device.get("ip", "N/A"),
                    "mac": device.get("mac", ""),
                }
                devices_optimized.append(device_summary)
        else:
            devices_optimized = devices_raw

        result = {
            "success": True,
            "devices": devices_optimized,
            "count": len(devices_optimized),
            "filters": {
                "device_type": device_type,
                "summary_mode": summary,
                "limit_applied": limit,
            },
            "token_usage": "optimized" if summary else "high",
        }

        return inject_site_metadata(result, site_id, site_name, site_slug)

    except Exception as e:
        logger.error(f"Error listing devices: {e}", exc_info=True)
        return inject_site_metadata(
            {
                "success": False,
                "error": str(e),
                "devices": [],
                "count": 0,
            },
            site_id if "site_id" in locals() else None,
            site_name if "site_name" in locals() else None,
            site_slug if "site_slug" in locals() else None,
        )


@server.tool(
    name="unifi_get_device_details",
    description="Informações detalhadas de equipamento UniFi Network específico — busca por endereço MAC com dados completos de dispositivo, hardware, firmware e status operacional. Use quando precisar diagnóstico aprofundado de access point, switch, gateway ou aparelho gerenciado. Retorna modelo, IP, uptime, versão e métricas específicas do equipamento no controlador UniFi.",
)
async def get_device_details(mac_address: str, site: Optional[str] = None) -> Dict[str, Any]:
    """
    Implementation for getting device details with multi-site support.

    Args:
        mac_address: MAC address or device name to search for
        site: Optional site name/slug. If None, uses current default site.

    Returns:
        Dict with device details and metadata including site information

    Raises:
        SiteNotFoundError: Site not found in controller
        SiteForbiddenError: Access to site denied by whitelist
        InvalidSiteParameterError: Site parameter validation failed
    """
    try:
        # Resolve site context and get metadata
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        device_obj = await device_manager.get_device_details(mac_address, site=site_slug)
        if not device_obj:
            return inject_site_metadata(
                {
                    "success": False,
                    "error": f"Device not found with MAC address: {mac_address}",
                    "device": None,
                },
                site_id,
                site_name,
                site_slug,
            )

        # Convert Device object to plain dictionary
        device_raw = device_obj.raw if hasattr(device_obj, "raw") else device_obj

        # Format device information
        state_map = {
            0: "offline",
            1: "online",
            2: "pending_adoption",
            4: "managed_by_other/adopting",
            5: "provisioning",
            6: "upgrading",
            11: "error/heartbeat_missed",
        }

        device_state = device_raw.get("state", 0)
        device_status_str = state_map.get(device_state, f"unknown_state ({device_state})")

        device_info = {
            "mac": device_raw.get("mac", ""),
            "name": device_raw.get("name", device_raw.get("model", "Unknown")),
            "model": device_raw.get("model", ""),
            "type": device_raw.get("type", ""),
            "ip": device_raw.get("ip", ""),
            "status": device_status_str,
            "uptime": str(timedelta(seconds=device_raw.get("uptime", 0))) if device_raw.get("uptime") else "N/A",
            "last_seen": (
                datetime.fromtimestamp(device_raw.get("last_seen", 0)).isoformat()
                if device_raw.get("last_seen")
                else "N/A"
            ),
            "firmware": device_raw.get("version", ""),
            "adopted": device_raw.get("adopted", False),
            "_id": device_raw.get("_id", ""),
        }

        # Add type-specific details
        if device_raw.get("type", "").startswith("uap"):  # Access Points
            device_info["wifi_clients"] = device_raw.get("num_sta", 0)
            device_info["wifi_bands"] = get_wifi_bands(device_raw)
            device_info["broadcast_ssids"] = get_broadcast_ssids(device_raw)
        elif device_raw.get("type", "").startswith(("usw", "usk")):  # Switches
            device_info["ports_total"] = len(device_raw.get("port_table", []))
            device_info["ports_up"] = len([p for p in device_raw.get("port_table", []) if p.get("up", False)])
        elif device_raw.get("type", "").startswith(("ugw", "udm", "uxg")):  # Gateways
            device_info["wan_ip"] = device_raw.get("wan_ip", "N/A")
            device_info["uptime"] = device_raw.get("uptime", 0)

        result = {
            "success": True,
            "device": device_info,
        }

        return inject_site_metadata(result, site_id, site_name, site_slug)

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
        logger.warning(f"Site parameter validation error: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Error getting device details: {e}", exc_info=True)
        return inject_site_metadata(
            {
                "success": False,
                "error": str(e),
                "device": None,
            },
            site_id if "site_id" in locals() else None,
            site_name if "site_name" in locals() else None,
            site_slug if "site_slug" in locals() else None,
        )


@server.tool(
    name="unifi_manage_device",
    description="Ações de gerenciamento sobre um equipamento UniFi Network — reiniciar, adotar, renomear, piscar o LED de localização, atualizar firmware e configurar o rádio de um access point com canal, largura de canal e potência de transmissão manuais. Use quando precisar agir sobre um dispositivo específico em vez de apenas consultá-lo. Cada ação exige o endereço MAC do equipamento e a ação desejada; reiniciar, adotar e atualizar firmware exigem confirm=true explícito por serem imediatas e irreversíveis no controlador UniFi.",
    permission_category="devices",
    permission_action="update",
)
async def manage_device(
    mac_address: str,
    action: str,
    name: Optional[str] = None,
    band: Optional[str] = None,
    channel: Optional[Any] = None,
    channel_width: Optional[int] = None,
    tx_power_mode: Optional[str] = None,
    tx_power_dbm: Optional[int] = None,
    enable: bool = True,
    confirm: bool = False,
    site: Optional[str] = None,
) -> Dict[str, Any]:
    """Act on one device.

    Args:
        mac_address: MAC, controller `_id` or name of the device.
        action: One of `reboot`, `adopt`, `rename`, `locate`, `upgrade`,
            `set_radio`.
        name: New device name. Required for `rename`.
        band: Radio to configure: "2.4GHz", "5GHz" or "6GHz". Required for
            `set_radio`.
        channel: Channel number, or "auto" to return the choice to the
            controller. Validated against what the site's regulatory domain
            permits at the chosen width.
        channel_width: 20, 40, 80, 160 or 320 MHz.
        tx_power_mode: auto, low, medium, high, or custom.
        tx_power_dbm: Transmit power, only with `tx_power_mode="custom"`, and
            bounded by what the radio reports it supports.
        enable: For `locate`, whether to start (True) or stop (False) flashing.
        confirm: Required for `reboot`, `adopt` and `upgrade`. Those take effect
            at once and no later call undoes them, so they are never
            auto-confirmed.
        site: Site slug or display name.

    Returns:
        Dict with the outcome and site metadata, or a preview when an action
        that requires confirmation is called without it.
    """
    action_normalised = (action or "").strip().lower()
    if action_normalised not in DEVICE_ACTIONS:
        return {
            "success": False,
            "error": f"Unknown action '{action}'. Use one of: {', '.join(sorted(DEVICE_ACTIONS))}.",
        }

    category, permission = DEVICE_ACTION_PERMISSION.get(action_normalised, DEFAULT_DEVICE_PERMISSION)
    if not parse_permission(config.permissions, category, permission):
        return {
            "success": False,
            "error": f"Permission denied: '{action_normalised}' requires {category}.{permission}.",
        }

    try:
        site_id, site_name, site_slug = await resolve_site_context(site, system_manager)

        device_obj = await device_manager.get_device_details(mac_address, site=site_slug)
        device_label = mac_address
        if device_obj:
            device_raw = device_obj.raw if hasattr(device_obj, "raw") else device_obj
            device_label = f"'{device_raw.get('name') or device_raw.get('model')}' ({mac_address})"
        elif action_normalised != "adopt":
            # A device awaiting adoption is not in the adopted list, so only that
            # action may legitimately name a device this lookup cannot find.
            return inject_site_metadata(
                {"success": False, "error": f"No device matched '{mac_address}' on this site."},
                site_id,
                site_name,
                site_slug,
            )

        if not confirm and not should_auto_confirm(action_normalised):
            return inject_site_metadata(
                action_preview(
                    action=action_normalised,
                    target=f"device {device_label}",
                    site=site_name or site_slug,
                    consequences=DEVICE_ACTION_CONSEQUENCES.get(action_normalised),
                ),
                site_id,
                site_name,
                site_slug,
            )

        if action_normalised == "rename":
            if not name:
                return {"success": False, "error": "rename requires the 'name' parameter."}
            succeeded = await device_manager.rename_device(mac_address, name, site=site_slug)
            result: Dict[str, Any] = {"success": succeeded, "action": "rename", "new_name": name}
        elif action_normalised == "locate":
            succeeded = await device_manager.locate_device(mac_address, enable=enable, site=site_slug)
            result = {"success": succeeded, "action": "locate", "flashing": enable}
        elif action_normalised == "set_radio":
            if not band:
                return {"success": False, "error": "set_radio requires the 'band' parameter (2.4GHz, 5GHz or 6GHz)."}
            outcome = await device_manager.set_radio_config(
                mac_address,
                band=band,
                channel=channel,
                channel_width=channel_width,
                tx_power_mode=tx_power_mode,
                tx_power_dbm=tx_power_dbm,
                site=site_slug,
            )
            result = {"success": True, "action": "set_radio", "band": band, **outcome}
        else:
            runner = {
                "reboot": device_manager.reboot_device,
                "adopt": device_manager.adopt_device,
                "upgrade": device_manager.upgrade_device,
            }[action_normalised]
            succeeded = await runner(mac_address, site=site_slug)
            result = {"success": succeeded, "action": action_normalised}

        result.setdefault("device", device_label)
        if not result.get("success") and "error" not in result:
            result["error"] = f"The controller did not accept {action_normalised} for device {device_label}."
        return inject_site_metadata(result, site_id, site_name, site_slug)

    except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError):
        raise
    except ValueError as e:
        # Raised for an input the radio or the regulatory domain rejects; the
        # message already names the permitted values.
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.error(f"Error running '{action_normalised}' on device {mac_address}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}
