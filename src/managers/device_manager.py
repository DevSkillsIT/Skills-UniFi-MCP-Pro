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
