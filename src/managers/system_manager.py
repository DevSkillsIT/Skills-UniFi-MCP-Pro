"""System, site and admin-user operations on the UniFi Network controller.

Three classes of defect are addressed here beyond the site plumbing.

1. Single-object endpoints. `/stat/sysinfo` answers `list[1]`, not a dict. The
   old `get_system_info` accepted only a dict, so it returned `{}` and the tool
   reported `{"success": true, "system_info": {}}` -- a success that carried
   nothing and could not be told apart from an empty controller.

2. Inverted success detection. `ConnectionManager.request()` returns the `data`
   payload, not the envelope, yet every write checked
   `response.get("meta", {}).get("rc") == "ok"` on that payload. `meta` is never
   present there, so a write that the controller accepted was reported as
   failed. `unifi_restart_controller` would reboot the controller and then tell
   the caller it had failed. Writes now ask for the envelope explicitly.

3. Tools called methods that never existed: `get_health_check`,
   `get_system_status` and `restart_controller` (the implementation is named
   `reboot_controller`). They are provided here.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

import aiohttp
from aiounifi.models.site import Site

from .base_manager import SiteScopedManager

logger = logging.getLogger("unifi-network-mcp")

CACHE_PREFIX_SYSINFO = "system_info"
CACHE_PREFIX_SETTINGS = "settings"
CACHE_PREFIX_SITES = "sites"
CACHE_PREFIX_ADMINS = "admin_users"
CACHE_PREFIX_HEALTH = "health"


class SystemManager(SiteScopedManager):
    """Manages system, site, and user operations on the Unifi Controller."""

    def __init__(self, connection_manager):
        super().__init__(connection_manager)
        self._sites_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Controller information
    # ------------------------------------------------------------------

    async def get_system_info(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Controller build, hostname, uptime and update state."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_SYSINFO}_{target}"
        cached = self._connection.get_cached(cache_key, timeout=15)
        if cached is not None:
            return cached
        try:
            info = await self._one("get", "/stat/sysinfo", site=site) or {}
            self._connection._update_cache(cache_key, info, timeout=15)
            return info
        except Exception as e:
            logger.error(f"Error getting system info (site={target}): {e}")
            return {}

    async def get_health_check(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Per-subsystem health for the site (wlan, wan, lan, www, vpn)."""
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_HEALTH}_{target}"
        cached = self._connection.get_cached(cache_key, timeout=10)
        if cached is not None:
            return cached
        try:
            health = await self._list("get", "/stat/health", site=site)
            self._connection._update_cache(cache_key, health, timeout=10)
            return health
        except Exception as e:
            logger.error(f"Error getting health check (site={target}): {e}")
            return []

    # `get_network_health` is the historical name for the same endpoint; kept so
    # existing callers do not break.
    async def get_network_health(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Alias of `get_health_check`."""
        return await self.get_health_check(site=site)

    async def get_system_status(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Operational status: controller identity plus subsystem roll-up.

        The controller serves no single "status" endpoint -- `/stat/status`
        answers 404 under a site path -- so this composes `/stat/sysinfo` with
        `/stat/health` and states which subsystems are degraded rather than
        returning an opaque blob.
        """
        info = await self.get_system_info(site=site)
        health = await self.get_health_check(site=site)

        subsystems = {
            h.get("subsystem"): h.get("status") for h in health if isinstance(h, dict) and h.get("subsystem")
        }
        degraded = [name for name, status in subsystems.items() if status not in ("ok", None, "unknown")]
        unknown = [name for name, status in subsystems.items() if status == "unknown"]

        wlan = next((h for h in health if h.get("subsystem") == "wlan"), {})
        return {
            "controller": {
                "version": info.get("version"),
                "build": info.get("build"),
                "hostname": info.get("hostname"),
                "uptime_seconds": info.get("uptime"),
                "update_available": info.get("update_available"),
            },
            "site": self._target_site(site),
            "subsystems": subsystems,
            "degraded_subsystems": degraded,
            "unknown_subsystems": unknown,
            "overall": "degraded" if degraded else "ok",
            "devices": {
                "adopted": wlan.get("num_adopted"),
                "disconnected": wlan.get("num_disconnected"),
                "pending": wlan.get("num_pending"),
            },
            "clients": {
                "total": wlan.get("num_user"),
                "guest": wlan.get("num_guest"),
            },
        }

    async def get_controller_status(self) -> Dict[str, Any]:
        """Controller-level status from the unsited `/status` endpoint."""
        try:
            response = await self._connection.request_unsited("/status")
            return response if isinstance(response, dict) else {}
        except Exception as e:
            logger.error(f"Error getting controller status: {e}")
            return {}

    # ------------------------------------------------------------------
    # Controller lifecycle
    # ------------------------------------------------------------------

    async def reboot_controller(self, site: Optional[str] = None) -> bool:
        """Reboot the controller."""
        logger.warning("Initiating controller reboot. This is a potentially disruptive operation.")
        try:
            response = await self._request("post", "/cmd/system", {"cmd": "reboot"}, site=site, return_raw=True)
            success = self._succeeded(response)
            if success:
                logger.info("Controller reboot initiated successfully.")
                self._connection._initialized = False
            else:
                logger.error(f"Controller reboot refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error rebooting controller: {e}")
            return False

    # The tool layer has always called this name; it is the documented verb.
    async def restart_controller(self, site: Optional[str] = None) -> bool:
        """Alias of `reboot_controller`."""
        return await self.reboot_controller(site=site)

    async def upgrade_controller(self, site: Optional[str] = None) -> bool:
        """Upgrade the controller to the latest available version."""
        logger.warning("Initiating controller upgrade. This is a potentially disruptive operation.")
        try:
            response = await self._request("post", "/cmd/system", {"cmd": "upgrade"}, site=site, return_raw=True)
            success = self._succeeded(response)
            if success:
                logger.info("Controller upgrade initiated successfully.")
                self._connection._initialized = False
            else:
                logger.error(f"Controller upgrade refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error upgrading controller: {e}")
            return False

    async def create_backup(self, filename: Optional[str] = None, site: Optional[str] = None) -> Optional[bytes]:
        """Download a configuration backup.

        Goes through the raw-bytes path because aiounifi decodes a response only
        when its content type is JSON; a backup is a binary body and came back
        as an empty dict through the normal request path.
        """
        try:
            data = await self._connection.request_bytes(
                "/cmd/backup", method="post", data={"cmd": "backup"}, site=self._target_site(site)
            )
            if data:
                logger.info("Backup created successfully (%d bytes).", len(data))
            else:
                logger.error("Backup request returned no data.")
            return data
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return None

    async def restore_backup(self, backup_data: bytes, site: Optional[str] = None) -> bool:
        """Restore the controller configuration from a backup file."""
        if not await self._connection.ensure_connected() or not self._connection._aiohttp_session:
            logger.error("Cannot restore backup: Controller not connected.")
            return False

        try:
            form = aiohttp.FormData()
            form.add_field("file", backup_data, filename="backup.unf", content_type="application/octet-stream")

            target = self._target_site(site)
            prefix = "/proxy/network" if self._connection._unifi_os_override else ""
            restore_url = f"{self._connection.url_base}{prefix}/api/s/{target}/cmd/restore"
            logger.info(f"Attempting to restore backup via POST to {restore_url}")

            async with self._connection._aiohttp_session.post(restore_url, data=form) as response:
                if response.status == 200:
                    logger.info("Backup restoration initiated successfully.")
                    self._connection._invalidate_cache()
                    self._connection._initialized = False
                    return True
                response_text = await response.text()
                logger.error(f"Error restoring backup: HTTP {response.status}, Response: {response_text[:200]}")
                return False
        except Exception as e:
            logger.error(f"Exception during backup restore: {e}")
            return False

    async def check_firmware_updates(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Latest firmware version the controller knows about."""
        try:
            return await self._one("get", "/stat/fwupdate/latest-version", site=site) or {}
        except Exception as e:
            logger.error(f"Error checking firmware updates: {e}")
            return {}

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    async def get_settings(self, section: str, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read one settings section for the site.

        Takes `site` because settings are per-site: the SNMP tools resolved a
        site, then read and wrote the settings of whatever site the connection
        was pointing at.
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_SETTINGS}_{section}_{target}"
        cached = self._connection.get_cached(cache_key)
        if cached is not None:
            return cached
        try:
            settings_list = await self._list("get", f"/get/setting/{section}", site=site)
            self._connection._update_cache(cache_key, settings_list)
            return settings_list
        except Exception as e:
            logger.error(f"Error getting {section} settings (site={target}): {e}")
            return []

    async def update_settings(self, section: str, settings_data: Dict[str, Any], site: Optional[str] = None) -> bool:
        """Write one settings section for the site."""
        target = self._target_site(site)
        try:
            current = await self.get_settings(section, site=site)
            settings_id = current[0].get("_id") if current and isinstance(current[0], dict) else None

            payload = dict(settings_data)
            if "_id" not in payload and settings_id:
                payload["_id"] = settings_id
            elif "_id" not in payload:
                logger.warning(
                    f"Updating settings section '{section}' without an _id; the controller may reject it."
                )
            payload.setdefault("key", section)

            response = await self._request("put", f"/set/setting/{section}", payload, site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_SETTINGS}_{section}_{target}")

            success = self._succeeded(response)
            if success:
                logger.info(f"{section} settings updated successfully on site {target}")
            else:
                logger.error(f"{section} settings refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error updating {section} settings: {e}")
            return False

    async def get_site_settings(self, site: Optional[str] = None) -> Dict[str, Any]:
        """Every settings section configured on the site, keyed by section name.

        Reads `/get/setting` with no section. There is no section literally
        named "site": asking for `/get/setting/site` answers HTTP 400, so the
        previous implementation always reported the site as having no settings.
        The unsectioned call returns all of them (country, connectivity, ntp,
        locale, mgmt, snmp and the rest).
        """
        target = self._target_site(site)
        cache_key = f"{CACHE_PREFIX_SETTINGS}_all_{target}"
        cached = self._connection.get_cached(cache_key)
        if cached is not None:
            return cached
        try:
            sections = await self._list("get", "/get/setting", site=site)
            by_key: Dict[str, Any] = {}
            for section in sections:
                if isinstance(section, dict) and section.get("key"):
                    by_key[section["key"]] = section
            result = {"sections": by_key, "section_count": len(by_key), "raw": sections}
            self._connection._update_cache(cache_key, result)
            return result
        except Exception as e:
            logger.error(f"Error getting site settings (site={target}): {e}")
            return {}

    # ------------------------------------------------------------------
    # Sites
    # ------------------------------------------------------------------

    async def get_sites(self) -> List[Site]:
        """Every site the authenticated account can see, as Site models.

        Takes no `site`: the endpoint is controller-level, not site-scoped.
        """
        cached: Optional[List[Site]] = self._connection.get_cached(CACHE_PREFIX_SITES)
        if cached is not None:
            return cached
        try:
            response = await self._connection.request_unsited("/api/self/sites")
            sites_data = response if isinstance(response, list) else []
            sites = [Site(raw) for raw in sites_data]
            self._connection._update_cache(CACHE_PREFIX_SITES, sites)
            return sites
        except Exception as e:
            logger.error(f"Error getting sites: {e}", exc_info=True)
            return []

    async def list_sites(self) -> List[Dict[str, Any]]:
        """Sites the whitelist allows, in the shape the site resolver expects.

        Reads the mapping the connection built at login. That mapping carries
        the real site `_id` alongside the slug, which the API path uses and
        which is NOT the same value -- a site whose display name is
        "Grupo Acme" has slug "grupoacme" and an `_id` of its own.
        Reporting the slug as the `_id`, as the
        previous implementation did, made the two indistinguishable to callers.
        """
        registry = getattr(self._connection, "_sites_by_slug", None)
        if registry:
            return [
                {"_id": entry["_id"], "name": entry["name"], "desc": entry["desc"]}
                for entry in registry.values()
            ]

        # Only reached before the login-time mapping exists.
        sites = await self.get_sites()
        return [
            {"_id": s.raw.get("_id", ""), "name": s.raw.get("name", ""), "desc": s.raw.get("desc") or s.raw.get("name", "")}
            for s in sites
        ]

    async def get_site_details(self, site_identifier: str) -> Optional[Site]:
        """Find one site by `_id`, slug or display name."""
        needle = (site_identifier or "").strip().lower()
        sites = await self.get_sites()
        for s in sites:
            raw = s.raw if hasattr(s, "raw") else {}
            if needle in {
                str(raw.get("_id", "")).lower(),
                str(raw.get("name", "")).lower(),
                str(raw.get("desc", "")).lower(),
            }:
                return s
        logger.warning(f"Site '{site_identifier}' not found.")
        return None

    async def get_current_site(self, site: Optional[str] = None) -> Optional[Site]:
        """The site this connection currently targets, or the one requested."""
        return await self.get_site_details(self._target_site(site))

    async def create_site(self, name: str, description: Optional[str] = None) -> Optional[Site]:
        """Create a site. Controller-level: `site` would be meaningless here."""
        try:
            formatted_name = name.lower().replace(" ", "_").replace("-", "_")
            site_desc = description or name

            sites = await self.get_sites()
            if any((s.raw or {}).get("name") == formatted_name for s in sites):
                logger.error(f"Site with internal name '{formatted_name}' already exists")
                return None

            payload = {"cmd": "add-site", "name": formatted_name, "desc": site_desc}
            response = await self._request("post", "/cmd/sitemgr", payload, return_raw=True)
            self._connection._invalidate_cache(CACHE_PREFIX_SITES)

            if not self._succeeded(response):
                logger.error(f"Site creation refused: {(response or {}).get('meta', {}).get('msg')}")
                return None

            logger.info(f"Site '{site_desc}' (internal: '{formatted_name}') created successfully.")
            await asyncio.sleep(1.5)
            return await self.get_site_details(formatted_name)
        except Exception as e:
            logger.error(f"Error creating site '{name}': {e}", exc_info=True)
            return None

    async def update_site(self, site_id: str, description: str) -> bool:
        """Change a site's description."""
        try:
            site_obj = await self.get_site_details(site_id)
            if not site_obj:
                logger.warning(f"Site '{site_id}' not found.")
                return False
            internal_id = (site_obj.raw or {}).get("_id")
            if not internal_id:
                logger.error(f"Site '{site_id}' has no _id.")
                return False

            payload = {"cmd": "update-site", "site": internal_id, "desc": description}
            response = await self._request("post", "/cmd/sitemgr", payload, return_raw=True)
            self._connection._invalidate_cache(CACHE_PREFIX_SITES)

            success = self._succeeded(response)
            if success:
                logger.info(f"Site {site_id} description updated successfully.")
            else:
                logger.error(f"Site update refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error updating site {site_id}: {e}", exc_info=True)
            return False

    async def delete_site(self, site_id: str) -> bool:
        """Delete a site. Refuses to delete the controller's `default` site."""
        try:
            site_obj = await self.get_site_details(site_id)
            if not site_obj:
                return False
            raw = site_obj.raw or {}
            internal_id = raw.get("_id")
            if not internal_id:
                logger.error(f"Site '{site_id}' has no _id.")
                return False
            if raw.get("name") == "default":
                logger.error("Cannot delete the default site.")
                return False

            response = await self._request(
                "post", "/cmd/sitemgr", {"cmd": "delete-site", "site": internal_id}, return_raw=True
            )
            self._connection._invalidate_cache(CACHE_PREFIX_SITES)

            success = self._succeeded(response)
            if success:
                logger.info(f"Site {site_id} deleted successfully.")
                if self._connection.site == raw.get("name"):
                    logger.warning(
                        f"Deleted the site this connection targets ('{self._connection.site}'); switch to another."
                    )
            else:
                logger.error(f"Site deletion refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error deleting site {site_id}: {e}", exc_info=True)
            return False

    async def switch_site(self, site_identifier: str) -> bool:
        """Change the default site this connection targets.

        Tools scope a single call by passing `site=`; this changes the default
        for calls that pass nothing.
        """
        try:
            site_obj = await self.get_site_details(site_identifier)
            if not site_obj:
                return False
            slug = (site_obj.raw or {}).get("name")
            if not slug:
                logger.error(f"Site '{site_identifier}' has no slug; cannot switch.")
                return False
            await self._connection.set_site(slug)
            return True
        except Exception as e:
            logger.error(f"Error switching to site '{site_identifier}': {e}", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Admin users (controller-level)
    # ------------------------------------------------------------------

    async def get_admin_users(self, site: Optional[str] = None) -> List[Dict[str, Any]]:
        """List controller admin users.

        Requires a super-admin account; a site admin gets HTTP 403 here, which
        is reported rather than flattened into an empty list.
        """
        cache_key = f"{CACHE_PREFIX_ADMINS}_controller"
        async with self._lock_for(cache_key):
            cached = self._connection.get_cached(cache_key)
            if cached is not None:
                return cached
            try:
                response = await self._connection.request_unsited("/api/stat/admin")
                admins = response if isinstance(response, list) else []
                self._connection._update_cache(cache_key, admins)
                return admins
            except Exception as e:
                logger.error(f"Error getting admin users: {e}")
                raise

    async def get_admin_user_details(self, user_identifier: str, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Find one admin user by `_id` or name."""
        admin_users = await self.get_admin_users(site=site)
        user = next(
            (u for u in admin_users if u.get("_id") == user_identifier or u.get("name") == user_identifier),
            None,
        )
        if not user:
            logger.warning(f"Admin user '{user_identifier}' not found.")
        return user

    async def create_admin_user(
        self,
        name: str,
        password: str,
        email: Optional[str] = None,
        is_super: bool = False,
        site_access: Optional[List[str]] = None,
        site: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a controller admin user."""
        try:
            admin_users = await self.get_admin_users(site=site)
            if any(u.get("name") == name for u in admin_users):
                logger.error(f"Admin user with name '{name}' already exists")
                return None

            payload: Dict[str, Any] = {
                "cmd": "create-admin",
                "name": name,
                "x_password": password,
                "email": email or "",
                "is_super": is_super,
            }
            if not is_super and site_access is not None:
                payload["site_access"] = site_access
            elif not is_super:
                logger.warning(f"Creating non-super admin '{name}' without site_access; it will see no sites.")

            response = await self._request("post", "/cmd/sitemgr", payload, site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_ADMINS}_controller")

            if not self._succeeded(response):
                logger.error(f"Admin creation refused: {(response or {}).get('meta', {}).get('msg')}")
                return None

            logger.info(f"Admin user '{name}' created successfully.")
            data = (response or {}).get("data")
            if isinstance(data, list) and data:
                return data[0]
            return {"success": True, "name": name}
        except Exception as e:
            logger.error(f"Error creating admin user '{name}': {e}", exc_info=True)
            return None

    async def update_admin_user(
        self,
        user_id: str,
        name: Optional[str] = None,
        password: Optional[str] = None,
        email: Optional[str] = None,
        is_super: Optional[bool] = None,
        site_access: Optional[List[str]] = None,
        site: Optional[str] = None,
    ) -> bool:
        """Update a controller admin user."""
        try:
            user = await self.get_admin_user_details(user_id, site=site)
            if not user:
                return False
            internal_id = user.get("_id")
            if not internal_id:
                logger.error(f"Admin user '{user_id}' has no _id.")
                return False

            payload: Dict[str, Any] = {"cmd": "update-admin", "admin_id": internal_id}
            if name is not None:
                if name != user.get("name"):
                    admins = await self.get_admin_users(site=site)
                    if any(u.get("name") == name and u.get("_id") != internal_id for u in admins):
                        logger.error(f"Cannot rename admin: username '{name}' already exists.")
                        return False
                payload["name"] = name
            if password is not None:
                payload["x_password"] = password
            if email is not None:
                payload["email"] = email
            if is_super is not None:
                payload["is_super"] = is_super
            if site_access is not None:
                effective_is_super = user.get("is_super", False) if is_super is None else is_super
                if not effective_is_super:
                    payload["site_access"] = site_access
                else:
                    logger.info("Ignoring site_access update for a super admin.")

            if len(payload) <= 2:
                logger.warning(f"No fields provided to update for admin user {user_id}")
                return False

            response = await self._request("post", "/cmd/sitemgr", payload, site=site, return_raw=True)
            self._connection._invalidate_cache(f"{CACHE_PREFIX_ADMINS}_controller")

            success = self._succeeded(response)
            if success:
                logger.info(f"Admin user {user_id} updated successfully.")
            else:
                logger.error(f"Admin update refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error updating admin user {user_id}: {e}", exc_info=True)
            return False

    async def delete_admin_user(self, user_id: str, site: Optional[str] = None) -> bool:
        """Delete a controller admin user."""
        try:
            user = await self.get_admin_user_details(user_id, site=site)
            if not user:
                return False
            internal_id = user.get("_id")
            if not internal_id:
                logger.error(f"Admin user '{user_id}' has no _id.")
                return False
            if user.get("name") == self._connection.username:
                logger.error("Cannot delete the admin user this connection authenticates as.")
                return False

            response = await self._connection.request_unsited(
                f"/api/stat/admin/{internal_id}", method="delete"
            )
            self._connection._invalidate_cache(f"{CACHE_PREFIX_ADMINS}_controller")

            success = self._succeeded(response)
            if success:
                logger.info(f"Admin user {user_id} deleted successfully.")
            else:
                logger.error(f"Admin deletion refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error deleting admin user {user_id}: {e}", exc_info=True)
            return False

    async def invite_admin_user(
        self,
        email: str,
        is_super: bool = False,
        site_access: Optional[List[str]] = None,
        site: Optional[str] = None,
    ) -> bool:
        """Invite an admin user by e-mail."""
        try:
            payload: Dict[str, Any] = {"cmd": "invite-admin", "email": email, "for_super": is_super}
            if site_access:
                logger.warning("site_access is not applied to invitations; set it after the invite is accepted.")

            response = await self._request("post", "/cmd/sitemgr", payload, site=site, return_raw=True)
            success = self._succeeded(response)
            if success:
                logger.info(f"Admin invitation sent successfully to {email}.")
            else:
                logger.error(f"Admin invitation refused: {(response or {}).get('meta', {}).get('msg')}")
            return success
        except Exception as e:
            logger.error(f"Error inviting admin user {email}: {e}", exc_info=True)
            return False

    async def get_current_admin_user(self, site: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """The admin user this connection authenticates as."""
        return await self.get_admin_user_details(self._connection.username, site=site)
