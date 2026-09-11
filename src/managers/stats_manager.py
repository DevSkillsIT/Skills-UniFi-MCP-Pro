"""Statistics retrieval from the UniFi Network controller.

Endpoint choices here are measured, not assumed. Against a UniFi Network
controller (verified 2026-09-10) the report endpoints behave as follows:

    /stat/report/hourly.site   200, but only `wlan_bytes`, `num_sta`,
                               `lan-num_sta`, `wlan-num_sta` and the `wan-*`
                               family survive -- `bytes`/`rx_bytes`/`tx_bytes`
                               are silently dropped from the response.
    /stat/report/hourly.ap     200, returns bytes/rx_bytes/tx_bytes/num_sta
                               per AP. Accepts an optional `mac` filter.
    /stat/report/hourly.user   200, returns rx_bytes/tx_bytes per client.
    /stat/report/hourly.dev    HTTP 500 -- the endpoint does not exist.
    /stat/report/hourly.sta    HTTP 500 -- the endpoint does not exist.

The two 500s are why device and client statistics always came back empty: the
code asked endpoints the controller does not serve, the error was swallowed,
and the tool reported "not found". Neither was a matter of passing the wrong
kind of identifier.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from aiounifi.models.dpi_restriction_app import DPIRestrictionApp
from aiounifi.models.dpi_restriction_group import DPIRestrictionGroup
from aiounifi.models.event import Event

from .base_manager import SiteScopedManager
from .radio_projection import radio_view, ssid_view
from .client_manager import ClientManager
from .connection_manager import ConnectionManager

logger = logging.getLogger("unifi-network-mcp")

# Cache prefixes
CACHE_PREFIX_STATS_NETWORK = "stats_network"
CACHE_PREFIX_STATS_CLIENT = "stats_client"
CACHE_PREFIX_STATS_DEVICE = "stats_device"
CACHE_PREFIX_STATS_DPI = "stats_dpi"
CACHE_PREFIX_STATS_ALERTS = "stats_alerts"
CACHE_PREFIX_STATS_SYSTEM = "stats_system"
CACHE_PREFIX_STATS_AP = "stats_ap"
CACHE_PREFIX_STATS_SWITCH = "stats_switch"

AP_TYPES = ("uap",)
SWITCH_TYPES = ("usw", "usk")
GATEWAY_TYPES = ("ugw", "udm", "uxg")

# Attributes the controller actually honours on /stat/report/hourly.site.
SITE_REPORT_ATTRS = [
    "wlan_bytes",
    "wan-tx_bytes",
    "wan-rx_bytes",
    "num_sta",
    "lan-num_sta",
    "wlan-num_sta",
    "time",
]
AP_REPORT_ATTRS = ["bytes", "rx_bytes", "tx_bytes", "num_sta", "time"]
USER_REPORT_ATTRS = ["rx_bytes", "tx_bytes", "time"]


def _window_ms(duration_hours: int) -> tuple[int, int]:
    """Return (start_ms, end_ms) for a window ending now."""
    end = datetime.now()
    start = end - timedelta(hours=duration_hours)
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)


def _safe_int(value: Any) -> int:
    try:
        if value is None:
            return 0
        if isinstance(value, bool):
            return int(value)
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(str(value))
    except (TypeError, ValueError):
        return None



class StatsManager(SiteScopedManager):
    """Manages statistics retrieval from the Unifi Controller."""

    def __init__(self, connection_manager: ConnectionManager, client_manager: ClientManager):
        super().__init__(connection_manager)
        self._client_manager = client_manager

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    async def _report(
        self,
        scale_and_target: str,
        attrs: List[str],
        duration_hours: int,
        site: Optional[str],
        extra: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """POST a /stat/report/* query and return its rows."""
        start, end = _window_ms(duration_hours)
        payload: Dict[str, Any] = {"attrs": attrs, "start": start, "end": end}
        if extra:
            payload.update(extra)
        try:
            rows = await self._list("post", f"/stat/report/{scale_and_target}", payload, site=site)
            return [r for r in rows if isinstance(r, dict)]
        except Exception as e:
            logger.error(f"Report {scale_and_target} failed (site={self._target_site(site)}): {e}")
            return []

    # ------------------------------------------------------------------
    # Site / network
    # ------------------------------------------------------------------

    async def get_network_stats(self, duration_hours: int = 1, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Per-network breakdown for the site.

        The controller has no per-network report endpoint, so a breakdown has
        to be assembled: the configured networks come from `/rest/networkconf`,
        and live clients from `/stat/sta` are attributed to them. Attribution
        prefers the client's own `network_id`, falls back to matching its VLAN
        tag against the network's `vlan`, and finally to the SSID's
        `networkconf_id`. Clients that match none are reported under an
        explicit "unattributed" bucket rather than being dropped.

        Every returned traffic figure is cumulative since the client
        associated -- that is what the controller exposes per client. The
        site-wide time series is returned separately under `site_series`.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_NETWORK}_{duration_hours}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=120)
            if cached is not None:
                return cached

            try:
                networks = await self._list("get", "/rest/networkconf", site=site)
                wlans = await self._list("get", "/rest/wlanconf", site=site)
                clients = await self._list("get", "/stat/sta", site=site)
            except Exception as e:
                logger.error(f"Error getting network stats (site={target}): {e}", exc_info=True)
                return []

            # SSID -> network id, used when a client carries no network_id.
            ssid_to_network = {
                w.get("name"): w.get("networkconf_id") for w in wlans if w.get("name") and w.get("networkconf_id")
            }
            vlan_to_network = {n.get("vlan"): n.get("_id") for n in networks if n.get("vlan") is not None}

            buckets: Dict[str, Dict[str, Any]] = {}
            for net in networks:
                net_id = net.get("_id")
                if not net_id:
                    continue
                buckets[net_id] = {
                    "network_id": net_id,
                    "name": net.get("name", "unknown"),
                    "purpose": net.get("purpose"),
                    "vlan": net.get("vlan"),
                    "enabled": net.get("enabled", True),
                    "num_clients": 0,
                    "num_wired": 0,
                    "num_wireless": 0,
                    "num_guest": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "total_bytes": 0,
                    "attribution": {},
                }

            unattributed = {
                "network_id": None,
                "name": "(unattributed)",
                "purpose": None,
                "vlan": None,
                "enabled": True,
                "num_clients": 0,
                "num_wired": 0,
                "num_wireless": 0,
                "num_guest": 0,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "total_bytes": 0,
                "attribution": {},
                "note": "Clients the controller did not tie to any configured network.",
            }

            for client in clients:
                net_id = client.get("network_id")
                how = "network_id"
                if not net_id and client.get("vlan") is not None:
                    net_id = vlan_to_network.get(client.get("vlan"))
                    how = "vlan"
                if not net_id and client.get("essid"):
                    net_id = ssid_to_network.get(client.get("essid"))
                    how = "ssid"

                bucket = buckets.get(net_id) if net_id else None
                if bucket is None:
                    bucket = unattributed
                    how = "none"

                rx = _safe_int(client.get("rx_bytes")) + _safe_int(client.get("wired-rx_bytes"))
                tx = _safe_int(client.get("tx_bytes")) + _safe_int(client.get("wired-tx_bytes"))
                bucket["num_clients"] += 1
                bucket["num_wired"] += 1 if client.get("is_wired") else 0
                bucket["num_wireless"] += 0 if client.get("is_wired") else 1
                bucket["num_guest"] += 1 if client.get("is_guest") else 0
                bucket["rx_bytes"] += rx
                bucket["tx_bytes"] += tx
                bucket["total_bytes"] += _safe_int(client.get("bytes")) or (rx + tx)
                bucket["attribution"][how] = bucket["attribution"].get(how, 0) + 1

            result = list(buckets.values())
            if unattributed["num_clients"]:
                result.append(unattributed)

            self._connection._update_cache(cache_key, result, timeout=120)
            return result

    async def get_site_series(self, duration_hours: int = 24, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Hourly site-wide series, using only attributes the controller honours."""
        return await self._report("hourly.site", SITE_REPORT_ATTRS, duration_hours, site)

    # ------------------------------------------------------------------
    # Clients
    # ------------------------------------------------------------------

    async def get_client_stats(
        self, client_mac: str, duration_hours: int = 24, site: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Hourly traffic series for one client, via /stat/report/hourly.user."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_CLIENT}_{client_mac}_{duration_hours}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=300)
            if cached is not None:
                return cached
            rows = await self._report(
                "hourly.user", USER_REPORT_ATTRS, duration_hours, site, {"mac": client_mac.lower()}
            )
            self._connection._update_cache(cache_key, rows, timeout=300)
            return rows

    async def get_top_clients(
        self, duration_hours: int = 24, limit: int = 10, site: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Rank online clients by cumulative usage since association."""
        online_clients = await self._client_manager.get_clients(site=site)
        if not online_clients:
            return []

        clients_raw = [c.raw if hasattr(c, "raw") else c for c in online_clients]
        aggregated: List[Dict[str, Any]] = []
        for client in clients_raw:
            mac = client.get("mac")
            if not mac:
                continue
            rx = _safe_int(client.get("rx_bytes")) + _safe_int(client.get("wired-rx_bytes"))
            tx = _safe_int(client.get("tx_bytes")) + _safe_int(client.get("wired-tx_bytes"))
            aggregated.append(
                {
                    "mac": mac,
                    "name": client.get("name") or client.get("hostname", mac),
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "total_bytes": _safe_int(client.get("bytes")) or (rx + tx),
                }
            )
        return sorted(aggregated, key=lambda x: x["total_bytes"], reverse=True)[:limit]

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    @staticmethod
    def _device_snapshot(device: Dict[str, Any]) -> Dict[str, Any]:
        """Project the fields that actually carry operational meaning."""
        system_stats = device.get("system-stats") or {}
        sys_stats = device.get("sys_stats") or {}
        snapshot = {
            "_id": device.get("_id"),
            "mac": device.get("mac"),
            "name": device.get("name") or device.get("model"),
            "model": device.get("model"),
            "type": device.get("type"),
            "ip": device.get("ip"),
            "state": device.get("state"),
            "adopted": device.get("adopted"),
            "version": device.get("version"),
            "uptime_seconds": _safe_int(device.get("uptime")),
            "cpu_percent": _safe_float(system_stats.get("cpu")),
            "mem_percent": _safe_float(system_stats.get("mem")),
            "mem_total_bytes": _safe_int(sys_stats.get("mem_total")) or None,
            "mem_used_bytes": _safe_int(sys_stats.get("mem_used")) or None,
            "loadavg_1": _safe_float(sys_stats.get("loadavg_1")),
            "num_clients": _safe_int(device.get("num_sta")),
            "rx_bytes": _safe_int(device.get("rx_bytes")),
            "tx_bytes": _safe_int(device.get("tx_bytes")),
            "total_bytes": _safe_int(device.get("bytes")),
        }
        device_type = device.get("type") or ""
        if device_type.startswith(AP_TYPES):
            live_by_name = {
                r.get("name"): r for r in (device.get("radio_table_stats") or []) if isinstance(r, dict)
            }
            snapshot["radios"] = [
                radio_view(
                    config,
                    live_by_name.get(config.get("name"), {}),
                    provisioned_at=device.get("provisioned_at"),
                )
                for config in (device.get("radio_table") or [])
                if isinstance(config, dict)
            ]
            snapshot["ssids"] = [
                ssid_view(v) for v in (device.get("vap_table") or []) if isinstance(v, dict)
            ]
        if device_type.startswith(SWITCH_TYPES):
            ports = device.get("port_table") or []
            snapshot["ports_total"] = len(ports)
            snapshot["ports_up"] = sum(1 for p in ports if p.get("up"))
            snapshot["ports_poe_enabled"] = sum(1 for p in ports if p.get("poe_enable"))
            snapshot["port_details"] = [
                {
                    "port_idx": p.get("port_idx"),
                    "name": p.get("name"),
                    "up": p.get("up"),
                    "speed_mbps": p.get("speed"),
                    "rx_bytes": _safe_int(p.get("rx_bytes")),
                    "tx_bytes": _safe_int(p.get("tx_bytes")),
                    "poe_power_w": _safe_float(p.get("poe_power")),
                }
                for p in ports
            ]
        if device_type.startswith(GATEWAY_TYPES):
            snapshot["wan_ip"] = device.get("wan_ip")
            snapshot["uplink"] = (device.get("uplink") or {}).get("name")
        return snapshot

    async def _devices(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        devices = await self._list("get", "/stat/device", site=site)
        return [d for d in devices if isinstance(d, dict)]

    async def get_device_stats(
        self, device_id: str, duration_hours: int = 24, site: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Statistics for one device, resolved by MAC, _id or name.

        Returns a current snapshot always, plus an hourly traffic series when
        the device is an access point (the only device class the controller
        reports on). `matched_by` says which identifier form was used, so a
        caller never has to guess why a lookup missed.
        """
        needle = (device_id or "").strip().lower()
        if not needle:
            return None

        devices = await self._devices(site=site)
        matched_by = None
        device = None
        for d in devices:
            if (d.get("mac") or "").lower() == needle:
                device, matched_by = d, "mac"
                break
            if (d.get("_id") or "").lower() == needle:
                device, matched_by = d, "_id"
                break
            if (d.get("name") or "").lower() == needle:
                device, matched_by = d, "name"
                break
        if device is None:
            return None

        result: Dict[str, Any] = {
            "matched_by": matched_by,
            "snapshot": self._device_snapshot(device),
            "series": [],
            "series_source": None,
        }
        if (device.get("type") or "").startswith(AP_TYPES) and device.get("mac"):
            rows = await self._report(
                "hourly.ap", AP_REPORT_ATTRS, duration_hours, site, {"mac": device["mac"]}
            )
            result["series"] = rows
            result["series_source"] = "/stat/report/hourly.ap"
        else:
            result["series_source"] = (
                "unavailable: the controller serves an hourly report only for access points"
            )
        return result

    async def get_ap_stats(self, duration_hours: int = 24, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Per-access-point statistics: live snapshot plus hourly traffic."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_AP}_{duration_hours}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=120)
            if cached is not None:
                return cached

            devices = await self._devices(site=site)
            aps = [d for d in devices if (d.get("type") or "").startswith(AP_TYPES)]
            if not aps:
                self._connection._update_cache(cache_key, [], timeout=120)
                return []

            rows = await self._report("hourly.ap", AP_REPORT_ATTRS, duration_hours, site)
            series_by_ap: Dict[str, List[Dict[str, Any]]] = {}
            for row in rows:
                series_by_ap.setdefault((row.get("ap") or "").lower(), []).append(row)

            result = []
            for ap in aps:
                snapshot = self._device_snapshot(ap)
                series = series_by_ap.get((ap.get("mac") or "").lower(), [])
                snapshot["series"] = series
                snapshot["window_rx_bytes"] = sum(_safe_int(r.get("rx_bytes")) for r in series)
                snapshot["window_tx_bytes"] = sum(_safe_int(r.get("tx_bytes")) for r in series)
                snapshot["window_total_bytes"] = sum(_safe_int(r.get("bytes")) for r in series)
                result.append(snapshot)

            self._connection._update_cache(cache_key, result, timeout=120)
            return result

    async def get_switch_stats(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Per-switch statistics: CPU, memory, uptime and per-port counters.

        The controller serves no hourly report for switches, so this is a live
        snapshot only -- stated rather than faked with an empty series.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_SWITCH}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=120)
            if cached is not None:
                return cached
            devices = await self._devices(site=site)
            result = [
                self._device_snapshot(d) for d in devices if (d.get("type") or "").startswith(SWITCH_TYPES)
            ]
            self._connection._update_cache(cache_key, result, timeout=120)
            return result


    async def get_channel_survey(
        self,
        duration_hours: int = 24,
        site: Optional[str] = None,
        min_signal_dbm: int = -80,
        include_empty_channels: bool = False,
    ) -> Dict[str, Any]:
        """What competes for the air on each channel, per band.

        Answers the question a channel change is asked to settle: which channel
        is least occupied by somebody else.

        A raw neighbour count is a misleading answer and the default filter
        exists because of it. One site here detected 142 networks on 5GHz
        channel 161 and not one of them was above -80 dBm; the radio's own
        measured airtime from other sources was 1%. Counting every beacon the
        access point can hear argues for moving off a channel that is in fact
        empty. Only a neighbour loud enough to make this AP defer costs
        anything, so weak ones are counted and then set aside.

        `utilization_others_percent` on the radio itself, in `unifi_get_ap_stats`,
        is the measurement; this survey is the explanation for it. Where the two
        disagree, the measurement wins.

        Args:
            duration_hours: How far back a scan row still counts. A row not seen
                within the window may be a network that no longer exists, and
                counting it argues against a channel that is free.
            site: Site slug or display name.
            min_signal_dbm: Floor for a neighbour to be treated as competing.
                -80 dBm is about where a neighbour starts costing airtime; pass
                a lower value to widen it, or -100 to keep everything.
            include_empty_channels: Also list channels with no competing
                neighbour. Off by default: on a 6GHz band that is 59 channels of
                zeroes, which is most of the response and none of the answer.

        Returns:
            Per band: how many neighbours were heard, how many pass the floor,
            the channels that carry them, and the quietest non-DFS candidates.
        """
        target = self._target_site(site)
        max_age = duration_hours * 3600

        try:
            neighbours = await self._list("post", "/stat/rogueap", {}, site=site)
        except Exception as e:
            logger.error(f"Neighbour scan failed (site={target}): {e}")
            neighbours = []

        country = await self._one("get", "/stat/current-channel", site=site) or {}
        devices = await self._devices(site=site)

        # Keyed by (band, channel): channel numbers repeat across bands -- 161
        # exists on both 5GHz and 6GHz -- so a channel-only key reports a radio
        # as sitting on a band it does not even have.
        own_by_channel: Dict[tuple, List[str]] = {}
        radios_per_band: Dict[str, int] = {}
        for device in devices:
            if not (device.get("type") or "").startswith(AP_TYPES):
                continue
            for live in device.get("radio_table_stats") or []:
                code = live.get("radio")
                radios_per_band[code] = radios_per_band.get(code, 0) + 1
                channel = live.get("channel")
                if channel is not None:
                    own_by_channel.setdefault((code, channel), []).append(
                        f"{device.get('name') or device.get('mac')}/{live.get('name')}"
                    )

        fresh = [
            n
            for n in neighbours
            if isinstance(n, dict) and _safe_int(n.get("age")) <= max_age and n.get("channel") is not None
        ]

        bands: Dict[str, Any] = {}
        for radio_code, label in (("ng", "2.4GHz"), ("na", "5GHz"), ("6e", "6GHz")):
            # A band this site has no radio on cannot be acted on, and reporting
            # it is pure volume.
            if not radios_per_band.get(radio_code):
                continue
            permitted = country.get(f"channels_{radio_code}")
            if not isinstance(permitted, list) or not permitted:
                continue

            dfs = set(country.get(f"channels_{radio_code}_dfs") or [])
            on_band = [n for n in fresh if n.get("band") == radio_code or n.get("radio") == radio_code]
            competing = [n for n in on_band if _safe_int(n.get("signal")) >= min_signal_dbm]

            per_channel = []
            for channel in permitted:
                here = [n for n in competing if n.get("channel") == channel]
                heard = sum(1 for n in on_band if n.get("channel") == channel)
                used_by = own_by_channel.get((radio_code, channel), [])
                if not here and not used_by and not include_empty_channels:
                    continue
                signals = [_safe_int(n.get("signal")) for n in here]
                per_channel.append(
                    {
                        "channel": channel,
                        "competing_neighbours": len(here),
                        "neighbours_heard": heard,
                        "strongest_dbm": max(signals) if signals else None,
                        "loudest_essid": max(here, key=lambda n: _safe_int(n.get("signal"))).get("essid")
                        if here
                        else None,
                        "is_dfs": channel in dfs,
                        "used_by_this_site": used_by,
                    }
                )

            occupied = {c["channel"] for c in per_channel if c["competing_neighbours"]}
            free = [c for c in permitted if c not in occupied and c not in dfs]

            bands[label] = {
                "radio_code": radio_code,
                "radios_on_this_site": radios_per_band.get(radio_code, 0),
                "neighbours_heard": len(on_band),
                "neighbours_competing": len(competing),
                "channels": per_channel,
                "channels_with_no_competitor": free[:12],
                "widths_available": sorted(
                    width
                    for width in (40, 80, 160, 320)
                    if country.get(f"channels_{radio_code}_{width}")
                ),
            }

        return {
            "site": target,
            "regulatory_domain": country.get("name"),
            "window_hours": duration_hours,
            "min_signal_dbm": min_signal_dbm,
            "neighbours_heard_total": len(neighbours),
            "bands": bands,
            "basis": (
                f"Neighbours come from the access points' own scan, kept when seen within "
                f"{duration_hours}h and at or above {min_signal_dbm} dBm. 'neighbours_heard' counts "
                "everything detected; 'competing_neighbours' counts only those loud enough to take "
                "airtime. Channels with neither a competitor nor one of this site's radios are "
                "omitted unless include_empty_channels is set. DFS channels are excluded from "
                "channels_with_no_competitor because radar detection can force a radio off them. "
                "The authoritative figure for interference is utilization_others_percent on the "
                "radio itself, in unifi_get_ap_stats; this survey explains it."
            ),
        }

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    async def get_system_stats(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Resource and capacity metrics for the site.

        Combines the controller build info (`/stat/sysinfo`), the per-subsystem
        health (`/stat/health`) and the resource counters each adopted device
        reports, because the controller exposes no single "system stats"
        endpoint.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_SYSTEM}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=30)
            if cached is not None:
                return cached

            sysinfo = await self._one("get", "/stat/sysinfo", site=site) or {}
            health = await self._list("get", "/stat/health", site=site)
            devices = await self._devices(site=site)

            cpu_values = [v for v in (_safe_float((d.get("system-stats") or {}).get("cpu")) for d in devices) if v is not None]
            mem_values = [v for v in (_safe_float((d.get("system-stats") or {}).get("mem")) for d in devices) if v is not None]

            by_subsystem = {h.get("subsystem"): h for h in health if isinstance(h, dict) and h.get("subsystem")}
            wlan = by_subsystem.get("wlan", {})

            result = {
                "controller": {
                    "version": sysinfo.get("version"),
                    "build": sysinfo.get("build"),
                    "hostname": sysinfo.get("hostname"),
                    "uptime_seconds": _safe_int(sysinfo.get("uptime")) or None,
                    "update_available": sysinfo.get("update_available"),
                    "timezone": sysinfo.get("timezone"),
                },
                "devices": {
                    "adopted": _safe_int(wlan.get("num_adopted")),
                    "disconnected": _safe_int(wlan.get("num_disconnected")),
                    "pending": _safe_int(wlan.get("num_pending")),
                    "disabled": _safe_int(wlan.get("num_disabled")),
                    "reporting_resources": len(cpu_values),
                    "cpu_percent_avg": round(sum(cpu_values) / len(cpu_values), 2) if cpu_values else None,
                    "cpu_percent_max": max(cpu_values) if cpu_values else None,
                    "mem_percent_avg": round(sum(mem_values) / len(mem_values), 2) if mem_values else None,
                    "mem_percent_max": max(mem_values) if mem_values else None,
                },
                "clients": {
                    "total": _safe_int(wlan.get("num_user")),
                    "guest": _safe_int(wlan.get("num_guest")),
                    "iot": _safe_int(wlan.get("num_iot")),
                },
                "throughput": {
                    "rx_bytes_per_sec": _safe_int(wlan.get("rx_bytes-r")),
                    "tx_bytes_per_sec": _safe_int(wlan.get("tx_bytes-r")),
                },
                "subsystems": {
                    name: {"status": h.get("status"), "subsystem": name} for name, h in by_subsystem.items()
                },
            }
            self._connection._update_cache(cache_key, result, timeout=30)
            return result

    # ------------------------------------------------------------------
    # DPI / alerts
    # ------------------------------------------------------------------

    async def get_dpi_stats(self, site: Optional[str] = None) -> Dict[str, List[Any]]:
        """Deep Packet Inspection statistics for the site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_DPI}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=900)
            if cached is not None:
                return cached
            try:
                apps = await self._list("get", "/rest/dpiapp", site=site)
                groups = await self._list("get", "/rest/dpigroup", site=site)
                result: Dict[str, List[Any]] = {
                    "applications": [DPIRestrictionApp(a) if isinstance(a, dict) else a for a in apps],
                    "categories": [DPIRestrictionGroup(g) if isinstance(g, dict) else g for g in groups],
                }
                self._connection._update_cache(cache_key, result, timeout=900)
                return result
            except Exception as e:
                logger.error(f"Error getting DPI stats (site={target}): {e}", exc_info=True)
                return {"applications": [], "categories": []}

    async def get_alerts(self, include_archived: bool = False, site: Optional[str] = None) -> List[Event]:
        """Alerts raised on the site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_STATS_ALERTS}_{include_archived}_{target}"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key, timeout=60)
            if cached is not None:
                return cached
            try:
                raw_alerts = await self._list("get", "/stat/alarm", site=site)
                alerts: List[Event] = []
                for raw in raw_alerts:
                    if not include_archived and raw.get("archived", False):
                        continue
                    try:
                        alerts.append(Event(raw))
                    except Exception:
                        alerts.append(raw)  # type: ignore[arg-type]
                self._connection._update_cache(cache_key, alerts, timeout=60)
                return alerts
            except Exception as e:
                logger.error(f"Error getting alerts (site={target}): {e}", exc_info=True)
                return []
