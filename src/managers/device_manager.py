"""Device operations on the UniFi Network controller.

`reboot_device`, `adopt_device`, `rename_device` and `upgrade_device` now take
a `site`. They did not before, so the tools that passed one raised `TypeError`,
and a call that did land went to whichever site the shared connection was
pointing at -- a reboot aimed at the wrong site.
"""

import logging
from typing import Any, Dict, List, Optional

from aiounifi.models.device import Device

from ..exceptions import ControllerRefusedError
from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_DEVICES = "devices"


class DeviceManager(SiteScopedManager):
    """Manages device-related operations on the Unifi Controller."""

    async def get_devices(self, site: Optional[str] = None) -> List[Device]:
        """List adopted devices for the target site."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_DEVICES}_{target}"
        async with self._lock_for(cache_key):
            cached: Optional[List[Device]] = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                raw = await self._list("get", "/stat/device", site=site)
                devices = [Device(r) for r in raw]
                self._connection._update_cache(cache_key, devices)
                return devices
            except Exception as e:
                logger.error(f"Error getting devices (site={target}): {e}")
                return []

    async def get_device_details(self, device_mac: str, site: Optional[str] = None) -> Optional[Device]:
        """Find one device by MAC, _id or name on the target site.

        The tool documents this parameter as "MAC address or device name", so
        matching only on MAC made a documented input silently fail.
        """
        needle = (device_mac or "").strip().lower()
        if not needle:
            return None
        devices = await self.get_devices(site=site)
        for attr in ("mac", "_id", "name"):
            for device in devices:
                raw = device.raw if hasattr(device, "raw") else device
                if str(raw.get(attr) or "").lower() == needle:
                    return device
        logger.debug(f"Device {device_mac} not found on site {self._target_site(site)}.")
        return None

    async def _devmgr(self, command: str, device_mac: str, site: Optional[str], extra: Optional[Dict[str, Any]] = None) -> bool:
        """Send a /cmd/devmgr command and verify the controller accepted it."""
        payload: Dict[str, Any] = {"mac": device_mac, "cmd": command}
        if extra:
            payload.update(extra)
        try:
            response = await self._request("post", "/cmd/devmgr", payload, site=site, return_raw=True)
            self._require_ok(response, f"{command} device {device_mac}", site)
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error sending {command} to device {device_mac}: {e}")
            return False
        logger.info(f"{command} accepted for device {device_mac} on {self._target_site(site)}")
        self._connection._invalidate_cache(CACHE_PREFIX_DEVICES)
        return True

    async def reboot_device(self, device_mac: str, site: Optional[str] = None) -> bool:
        """Reboot a device by MAC address."""
        return await self._devmgr("restart", device_mac, site)

    async def adopt_device(self, device_mac: str, site: Optional[str] = None) -> bool:
        """Adopt a device by MAC address."""
        return await self._devmgr("adopt", device_mac, site)

    async def upgrade_device(self, device_mac: str, site: Optional[str] = None) -> bool:
        """Start a firmware upgrade for a device by MAC address."""
        return await self._devmgr("upgrade", device_mac, site)

    async def locate_device(self, device_mac: str, enable: bool = True, site: Optional[str] = None) -> bool:
        """Flash (or stop flashing) a device's locate LED."""
        return await self._devmgr("set-locate" if enable else "unset-locate", device_mac, site)

    async def rename_device(self, device_mac: str, name: str, site: Optional[str] = None) -> bool:
        """Rename a device."""
        try:
            device = await self.get_device_details(device_mac, site=site)
            if not device or "_id" not in device.raw:
                logger.error(f"Cannot rename device {device_mac}: not found on site {self._target_site(site)}.")
                return False
            device_id = device.raw["_id"]
            response = await self._request(
                "put", f"/rest/device/{device_id}", {"name": name}, site=site, return_raw=True
            )
            self._require_ok(response, f"rename device {device_mac}", site)
            logger.info(f"Device {device_mac} renamed to '{name}' on {self._target_site(site)}")
            self._connection._invalidate_cache(CACHE_PREFIX_DEVICES)
            return True
        except ControllerRefusedError:
            raise
        except Exception as e:
            logger.error(f"Error renaming device {device_mac} to '{name}': {e}")
            return False

    # --- Radios -----------------------------------------------------------

    # What an operator calls a band, and what the controller calls it.
    RADIO_BANDS = {
        "2.4ghz": "ng",
        "2.4": "ng",
        "ng": "ng",
        "5ghz": "na",
        "5": "na",
        "na": "na",
        "6ghz": "6e",
        "6": "6e",
        "6e": "6e",
    }
    TX_POWER_MODES = ("auto", "low", "medium", "high", "custom")

    async def get_country_channels(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Channels the site's regulatory domain permits, as the controller states them.

        `/stat/current-channel` answers with the country and one list per band and
        channel width (`channels_na_80`, `channels_ng`, and so on). Using it means
        the legal channel set is read from the controller rather than hard-coded
        per country here and going stale.
        """
        try:
            return await self._one("get", "/stat/current-channel", site=site) or {}
        except Exception as e:
            logger.error(f"Error reading permitted channels (site={self._target_site(site)}): {e}")
            return {}

    @staticmethod
    def _permitted_channels(country: Dict[str, Any], radio: str, width: Optional[int]) -> List[int]:
        """The channel list for one band at one width, narrowest match first.

        A wider channel occupies more spectrum, so the controller publishes a
        separate, shorter list per width: 5GHz permits 24 channels at 20MHz but
        only 16 at 160MHz. Validating against the plain band list would accept a
        channel the radio cannot actually centre on at the chosen width.
        """
        if width and width != 20:
            by_width = country.get(f"channels_{radio}_{width}")
            if isinstance(by_width, list) and by_width:
                return [c for c in by_width if isinstance(c, int)]
        plain = country.get(f"channels_{radio}")
        return [c for c in plain if isinstance(c, int)] if isinstance(plain, list) else []

    async def set_radio_config(
        self,
        device_mac: str,
        band: str,
        channel: Optional[Any] = None,
        channel_width: Optional[int] = None,
        tx_power_mode: Optional[str] = None,
        tx_power_dbm: Optional[int] = None,
        site: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Set channel, channel width and transmit power on one radio of an AP.

        Args:
            device_mac: MAC, `_id` or name of the access point.
            band: "2.4GHz", "5GHz" or "6GHz" (the controller's `ng`/`na`/`6e`
                are accepted too).
            channel: A channel number, or "auto" to hand the choice back to the
                controller.
            channel_width: 20, 40, 80, 160 or 320 MHz.
            tx_power_mode: auto, low, medium, high, or custom.
            tx_power_dbm: Required when `tx_power_mode` is "custom", and bounded
                by the radio's own `min_txpower`/`max_txpower`.
            site: Site slug or display name.

        Returns:
            A dict with the radio's state before and after, and the fields that
            changed. Raises ValueError for an input the radio or the regulatory
            domain does not permit, so a rejected setting is refused here rather
            than by the controller after the AP has already been told to
            re-provision.
        """
        radio_code = self.RADIO_BANDS.get(str(band).strip().lower())
        if not radio_code:
            raise ValueError(
                f"Unknown band '{band}'. Use one of: 2.4GHz, 5GHz, 6GHz."
            )

        device = await self.get_device_details(device_mac, site=site)
        if not device:
            raise ValueError(f"No device matched '{device_mac}' on site {self._target_site(site)}.")

        raw = device.raw if hasattr(device, "raw") else device
        if not str(raw.get("type") or "").startswith("uap"):
            raise ValueError(
                f"Device '{raw.get('name') or device_mac}' is a {raw.get('type')}, which has no radios. "
                "Radio settings apply to access points."
            )

        radio_table = [dict(r) for r in (raw.get("radio_table") or []) if isinstance(r, dict)]
        target = next((r for r in radio_table if r.get("radio") == radio_code), None)
        if target is None:
            available = sorted({r.get("radio") for r in radio_table if r.get("radio")})
            raise ValueError(
                f"This access point has no {band} radio. It has: {', '.join(available) or 'none'}."
            )

        before = {
            "channel": target.get("channel"),
            "channel_width_mhz": target.get("ht"),
            "tx_power_mode": target.get("tx_power_mode"),
            "tx_power_dbm": target.get("tx_power"),
        }

        effective_width = channel_width if channel_width is not None else target.get("ht")

        if channel_width is not None:
            if not isinstance(channel_width, int) or channel_width not in (20, 40, 80, 160, 320):
                raise ValueError("channel_width must be one of 20, 40, 80, 160, 320 (MHz).")
            target["ht"] = channel_width

        if channel is not None:
            if isinstance(channel, str) and channel.strip().lower() == "auto":
                target["channel"] = "auto"
            else:
                try:
                    channel_number = int(channel)
                except (TypeError, ValueError):
                    raise ValueError(f"channel must be a number or 'auto', not {channel!r}.") from None
                country = await self.get_country_channels(site=site)
                permitted = self._permitted_channels(country, radio_code, effective_width)
                if permitted and channel_number not in permitted:
                    raise ValueError(
                        f"Channel {channel_number} is not permitted on {band} at "
                        f"{effective_width}MHz in {country.get('name') or 'this regulatory domain'}. "
                        f"Permitted: {permitted}."
                    )
                target["channel"] = channel_number

        if tx_power_mode is not None:
            mode = str(tx_power_mode).strip().lower()
            if mode not in self.TX_POWER_MODES:
                raise ValueError(f"tx_power_mode must be one of: {', '.join(self.TX_POWER_MODES)}.")
            target["tx_power_mode"] = mode
            if mode != "custom":
                target.pop("tx_power", None)

        if tx_power_dbm is not None:
            if target.get("tx_power_mode") != "custom":
                raise ValueError(
                    "tx_power_dbm applies only when tx_power_mode is 'custom'. "
                    "Set tx_power_mode='custom' in the same call."
                )
            low = target.get("min_txpower")
            high = target.get("max_txpower")
            if isinstance(low, int) and isinstance(high, int) and not (low <= tx_power_dbm <= high):
                raise ValueError(
                    f"tx_power_dbm {tx_power_dbm} is outside what this radio supports ({low}-{high} dBm)."
                )
            target["tx_power"] = tx_power_dbm

        after = {
            "channel": target.get("channel"),
            "channel_width_mhz": target.get("ht"),
            "tx_power_mode": target.get("tx_power_mode"),
            "tx_power_dbm": target.get("tx_power"),
        }
        changed = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
        if not changed:
            return {"changed": {}, "before": before, "after": after, "applied": False,
                    "note": "Every requested value already matched; nothing was sent to the controller."}

        device_id = raw.get("_id")
        response = await self._request(
            "put", f"/rest/device/{device_id}", {"radio_table": radio_table}, site=site, return_raw=True
        )
        self._require_ok(response, f"change the {band} radio of '{raw.get('name') or device_mac}'", site)
        self._connection._invalidate_cache(CACHE_PREFIX_DEVICES)
        logger.info(f"Radio {radio_code} of {device_mac} changed on {self._target_site(site)}: {changed}")
        return {"changed": changed, "before": before, "after": after, "applied": True}
