"""One description of a UniFi radio, shared by every tool that reports one.

Two tools answer questions about the same radio -- device details and AP
statistics -- and a projection written twice drifts: the fix lands on one and
the other keeps reporting the old, thinner view.
"""

from typing import Any, Dict, Optional

RADIO_BAND_LABELS = {"ng": "2.4GHz", "na": "5GHz", "6e": "6GHz", "ax": "6GHz"}


def _safe_int(value: Any) -> int:
    """Coerce a controller field to int; several arrive as strings or null."""
    try:
        if value is None:
            return 0
        if isinstance(value, bool):
            return int(value)
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any):
    try:
        return float(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


# A radio adopts a freshly written power on its next provision. Past this many
# seconds since the device last provisioned, a difference is no longer pending.
PROVISION_SETTLE_SECONDS = 600


def _power_status(config: Dict[str, Any], live: Dict[str, Any], provisioned_at: Optional[int]) -> Optional[str]:
    """Explain a configured power the radio is not transmitting at.

    Only meaningful under `custom`: in `auto` the controller picks the power and
    `radio_table.tx_power` holds whatever was last written by hand, which the
    radio is correctly ignoring.

    The distinction that matters is pending versus capped, and the device's own
    `provisioned_at` settles it. Reporting only the live figure makes a setting
    that was applied look like a setting that was ignored -- and reporting only
    the configured figure makes a power the radio refuses look like a power it
    is using.
    """
    if config.get("tx_power_mode") != "custom":
        return None
    configured = _safe_int(config.get("tx_power"))
    actual = _safe_int(live.get("tx_power"))
    if not configured or not actual or configured == actual:
        return None

    settled = None
    if provisioned_at:
        import time

        settled = (time.time() - provisioned_at) > PROVISION_SETTLE_SECONDS

    if settled is True:
        return (
            f"Configured for {configured} dBm and transmitting at {actual} dBm, with the device "
            f"provisioned long enough ago for the setting to have taken. The radio is capping it: "
            f"{configured} dBm will not be reached on this band. `max_txpower` is what the hardware "
            f"supports, not what the regulatory domain permits per band."
        )
    if settled is False:
        return (
            f"Configured for {configured} dBm, transmitting at {actual} dBm. The device provisioned "
            f"recently; the radio may still be adopting the value."
        )
    return (
        f"Configured for {configured} dBm, transmitting at {actual} dBm. Whether the radio is still "
        f"adopting it or capping it cannot be told without the device's provisioning time."
    )


def radio_view(
    config: Dict[str, Any], live: Dict[str, Any], provisioned_at: Optional[int] = None
) -> Dict[str, Any]:
    """Everything the controller knows about one radio, in one object.

    The two tables answer different questions and neither is sufficient:

    - `radio_table` is the intent. The channel here may be the string "auto",
      and `ht` is the width that was asked for.
    - `radio_table_stats` is the outcome. `channel` is where the radio actually
      landed, `bw` is the width actually in use, and `ht` in this table is
      always null -- reading width from it reports no width at all.

    Channel utilisation is split deliberately. `cu_total` alone cannot be acted
    on: 40% caused by this AP's own traffic is a capacity question, while 40%
    caused by somebody else's network is an interference question with a
    different answer. `cu_self_rx + cu_self_tx` is this radio; the remainder is
    everything else on the channel.
    """
    self_rx = _safe_int(live.get("cu_self_rx"))
    self_tx = _safe_int(live.get("cu_self_tx"))
    total = _safe_int(live.get("cu_total"))
    configured_channel = config.get("channel")

    # The controller sets these flags only where it has something to say. An
    # absent flag means "not reported", which is not the same as "unsupported",
    # so an empty result is returned as None rather than as an empty list that
    # reads like a denial.
    standards = []
    if config.get("is_11ax"):
        standards.append("802.11ax (WiFi 6)")
    if config.get("is_11ac"):
        standards.append("802.11ac (WiFi 5)")
    standards = standards or None

    return {
        "interface": config.get("name") or live.get("name"),
        "band": RADIO_BAND_LABELS.get(config.get("radio") or live.get("radio"), config.get("radio")),
        "radio_code": config.get("radio") or live.get("radio"),
        "state": live.get("state"),
        # Channel: what was asked for, and where it actually is.
        "channel": live.get("channel", configured_channel),
        "channel_configured": configured_channel,
        "channel_is_auto": str(configured_channel).lower() == "auto",
        "channel_previous": live.get("last_channel"),
        "extension_channel": live.get("extchannel"),
        # Width: configured, and in use.
        "channel_width_mhz": _safe_int(live.get("bw")) or config.get("ht"),
        "channel_width_configured_mhz": config.get("ht"),
        # Power, intent beside outcome -- the same split as channel and width.
        # A radio can carry a configured power it is not yet transmitting at:
        # the value is stored the moment it is written, while the radio only
        # adopts it once it re-provisions. Reporting the live figure alone makes
        # a setting that was applied look like a setting that was ignored.
        "tx_power_dbm": _safe_int(live.get("tx_power")),
        "tx_power_configured_dbm": _safe_int(config.get("tx_power")) or None,
        "tx_power_mode": config.get("tx_power_mode"),
        "tx_power_min_dbm": config.get("min_txpower"),
        "tx_power_max_dbm": config.get("max_txpower"),
        "tx_power_status": _power_status(config, live, provisioned_at),
        "antenna_gain_dbi": config.get("antenna_gain"),
        # Airtime: whose it is.
        "utilization_total_percent": total,
        "utilization_self_percent": self_rx + self_tx,
        "utilization_self_rx_percent": self_rx,
        "utilization_self_tx_percent": self_tx,
        "utilization_others_percent": max(total - (self_rx + self_tx), 0),
        # Quality.
        "satisfaction_percent": _safe_int(live.get("satisfaction")),
        "tx_retries_percent": _safe_float(live.get("tx_retries_pct")),
        "tx_packets": _safe_int(live.get("tx_packets")),
        "tx_retries": _safe_int(live.get("tx_retries")),
        # Clients.
        "num_clients": _safe_int(live.get("num_sta")),
        "num_clients_guest": _safe_int(live.get("guest-num_sta")),
        "num_clients_user": _safe_int(live.get("user-num_sta")),
        # Capability, which bounds what may be configured.
        "spatial_streams": config.get("nss"),
        "standards": standards,
        "standards_note": None if standards else "The controller reports no standard flags for this radio.",
        "supports_dfs": bool(config.get("has_dfs")),
        "supports_160mhz": bool(config.get("has_ht160")),
        "min_rssi_enabled": bool(config.get("min_rssi_enabled")),
    }


def ssid_view(vap: Dict[str, Any]) -> Dict[str, Any]:
    """One broadcast SSID on one radio of one access point."""
    return {
        "essid": vap.get("essid"),
        "bssid": vap.get("bssid"),
        "radio_interface": vap.get("radio_name"),
        "band": RADIO_BAND_LABELS.get(vap.get("radio"), vap.get("radio")),
        "channel": vap.get("channel"),
        "channel_width_mhz": _safe_int(vap.get("bw")),
        "state": vap.get("state"),
        "up": vap.get("up"),
        "usage": vap.get("usage"),
        "is_guest": vap.get("is_guest"),
        "num_clients": _safe_int(vap.get("num_sta")),
        "avg_client_signal_dbm": _safe_int(vap.get("avg_client_signal")) or None,
        "satisfaction_percent": _safe_int(vap.get("satisfaction")),
        "tx_power_dbm": _safe_int(vap.get("tx_power")),
        "tx_retries": _safe_int(vap.get("tx_retries")),
        "tx_dropped": _safe_int(vap.get("tx_dropped")),
        "rx_errors": _safe_int(vap.get("rx_errors")),
        "mac_filter_rejections": _safe_int(vap.get("mac_filter_rejections")),
        "rx_bytes": _safe_int(vap.get("rx_bytes")),
        "tx_bytes": _safe_int(vap.get("tx_bytes")),
        "wlan_id": vap.get("wlanconf_id"),
    }
