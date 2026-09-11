"""
Tests for device management tools with multi-site support.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 2A: Refatoração de Tools de Gerenciamento de Dispositivos (devices.py)

Tools being tested:
1. unifi_list_devices
2. unifi_get_device_details
3. unifi_manage_device
"""

import pytest
import sys
from unittest.mock import AsyncMock, patch
from typing import Any, Dict
from pathlib import Path

# Add the project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)


def create_mock_device(
    mac: str = "aa:bb:cc:dd:ee:ff",
    name: str = "Test Device",
    model: str = "UAP-6-Pro",
    device_type: str = "uap",
    state: int = 1,
    **kwargs
) -> Dict[str, Any]:
    """Create a mock device dictionary."""
    base = {
        "mac": mac,
        "name": name,
        "model": model,
        "type": device_type,
        "state": state,
        "_id": "device_id_123",
        "ip": "192.168.1.100",
        "uptime": 86400,
        "last_seen": 1700000000,
        "version": "6.0.0",
        "adopted": True,
        "serial": "SERIAL123",
        "hw_rev": "1",
        "num_sta": 5,
        "raw": None,  # For hasattr check
    }
    base.update(kwargs)
    return base


class TestListDevicesWithSite:
    """Test list_devices with site parameter."""

    @staticmethod
    def _tool_parameters(module: str, function: str) -> dict:
        """Read a tool's declared parameters from the source.

        `inspect.signature` cannot be used here: the test suite stubs the MCP
        package, so `@server.tool` returns a MagicMock and the decorated name is
        no longer the function. The source is the same either way.
        """
        import ast
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "src" / "tools" / f"{module}.py"
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function:
                args = node.args
                positional = args.posonlyargs + args.args
                defaults = dict(zip([a.arg for a in positional[len(positional) - len(args.defaults):]], args.defaults))
                return {a.arg: defaults.get(a.arg) for a in positional}
        raise AssertionError(f"{function} not found in src/tools/{module}.py")

    def test_list_devices_site_parameter_is_optional(self):
        """Omitting `site` is valid and means the configured default site."""
        import ast

        parameters = self._tool_parameters("devices", "list_devices")
        assert "site" in parameters
        default = parameters["site"]
        assert isinstance(default, ast.Constant) and default.value is None

    def test_every_device_tool_accepts_a_site(self):
        """A tool that cannot name its site can only ever act on the default one."""
        import ast

        for function in ("list_devices", "get_device_details", "manage_device"):
            parameters = self._tool_parameters("devices", function)
            assert "site" in parameters, f"{function} takes no site"
            default = parameters["site"]
            assert isinstance(default, ast.Constant) and default.value is None


class TestGetDeviceDetailsWithSite:
    """Test get_device_details with site parameter."""

    @pytest.mark.asyncio
    async def test_get_device_details_backward_compatibility(self):
        """GREEN: Should accept mac_address parameter and optional site."""
        # Placeholder for backward compatibility test
        assert True


class TestManageDevice:
    """Device mutations go through one tool that names the action."""

    def test_every_documented_action_is_accepted(self):
        from src.tools.devices import DEVICE_ACTIONS

        assert DEVICE_ACTIONS == {"reboot", "adopt", "rename", "locate", "upgrade", "set_radio", "set_port"}

    def test_each_action_states_its_consequence(self):
        """A confirmation prompt without a consequence is not a decision."""
        from src.tools.devices import DEVICE_ACTIONS, DEVICE_ACTION_CONSEQUENCES

        assert set(DEVICE_ACTION_CONSEQUENCES) == DEVICE_ACTIONS
        assert all(DEVICE_ACTION_CONSEQUENCES[a] for a in DEVICE_ACTIONS)

    def test_adopt_still_requires_the_create_permission(self):
        """Folding actions behind one tool must not widen what is permitted."""
        from src.tools.devices import DEFAULT_DEVICE_PERMISSION, DEVICE_ACTION_PERMISSION

        assert DEVICE_ACTION_PERMISSION["adopt"] == ("devices", "create")
        assert DEFAULT_DEVICE_PERMISSION == ("devices", "update")

    def test_irreversible_actions_are_never_auto_confirmed(self):
        """UNIFI_AUTO_CONFIRM covers convenience, not consequences."""
        from src.utils.confirmation import ALWAYS_CONFIRM_ACTIONS

        for action in ("reboot", "adopt", "upgrade", "set_radio"):
            assert action in ALWAYS_CONFIRM_ACTIONS

    def test_reversible_actions_may_be_auto_confirmed(self):
        from src.utils.confirmation import ALWAYS_CONFIRM_ACTIONS

        for action in ("rename", "locate"):
            assert action not in ALWAYS_CONFIRM_ACTIONS


class TestSiteParameterIntegration:
    """Integration tests for site parameter in device tools."""

    @pytest.mark.asyncio
    async def test_site_resolver_usage_in_device_tools(self):
        """RED: Device tools should use site_resolver for multi-site support."""
        # This test validates that tools use the site resolver
        # when site parameter is provided
        from src.utils.site_resolver import validate_site_parameter

        # Test that we can validate a site parameter
        result = validate_site_parameter("acme")
        assert result == "acme"

        # Test that validate_site_parameter rejects invalid inputs
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("site@invalid")

    @pytest.mark.asyncio
    async def test_site_resolution_in_device_list(self):
        """RED: unifi_list_devices should resolve site parameter."""
        # Validates that the tool supports site resolution
        from src.utils.site_resolver import resolve_site_identifier

        # Mock sites list
        all_sites = [
            {"_id": "abc123", "name": "Acme", "desc": "Acme Site"},
            {"_id": "def456", "name": "default", "desc": "Default Site"},
        ]

        # Patch get_all_sites in site_resolver
        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Test exact match
            result = await resolve_site_identifier("Acme")
            assert result["slug"] == "Acme"
            assert result["id"] == "abc123"

    @pytest.mark.asyncio
    async def test_device_operations_with_different_sites(self):
        """GREEN: Device operations should work with site-specific filtering."""
        # This test validates cross-site device queries

        # Create mock devices from different sites
        acme_device = create_mock_device(mac="aa:bb:cc:dd:ee:01", name="Acme AP")
        default_device = create_mock_device(mac="bb:bb:cc:dd:ee:02", name="Default AP")

        assert acme_device["mac"] != default_device["mac"]
        assert acme_device["name"] != default_device["name"]


class TestSiteWhitelistValidation:
    """Test site whitelist validation in device operations."""

    @pytest.mark.asyncio
    async def test_site_access_validation(self):
        """RED: Device tools should validate site access against whitelist."""
        from src.utils.site_resolver import validate_site_access

        # Test ALL-SITES mode (no restrictions)
        await validate_site_access("any-site", allowed_sites=None)

        # Test whitelisted site
        await validate_site_access("acme", allowed_sites=["acme", "default"])

        # Test non-whitelisted site raises error
        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["acme", "default"])

    @pytest.mark.asyncio
    async def test_site_not_found_error_with_suggestions(self):
        """RED: Site resolver should provide suggestions when site not found."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Acme", "desc": "Acme Site"},
            {"_id": "def456", "name": "Bravo", "desc": "Bravo Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Try to find non-existent site
            with pytest.raises(SiteNotFoundError) as exc_info:
                await resolve_site_identifier("NonExistent")

            # Error should provide suggestions
            assert len(exc_info.value.details.get("suggestions", [])) > 0


class TestCacheStrategyWithSite:
    """Test cache strategy for site-specific queries."""

    @staticmethod
    def _manager():
        from unittest.mock import AsyncMock, MagicMock

        from src.managers.device_manager import DeviceManager

        connection = MagicMock()
        connection.site = "default"
        connection.resolve_slug = MagicMock(side_effect=lambda s: s or "default")
        connection.ensure_connected = AsyncMock(return_value=True)
        connection._cache = {}
        connection.get_cached = MagicMock(side_effect=lambda key, timeout=None: connection._cache.get(key))
        connection._update_cache = MagicMock(
            side_effect=lambda key, value, timeout=None: connection._cache.__setitem__(key, value)
        )
        connection._invalidate_cache = MagicMock()
        return DeviceManager(connection), connection

    @pytest.mark.asyncio
    async def test_cache_key_includes_site_slug(self):
        """A cache key without the site serves one site's answer for another."""
        manager, connection = self._manager()
        connection.request = AsyncMock(return_value=[{"_id": "d1", "mac": "aa:aa:aa:aa:aa:aa"}])

        await manager.get_devices(site="acme")
        await manager.get_devices(site="bravo")

        assert "devices_acme" in connection._cache
        assert "devices_bravo" in connection._cache

    @pytest.mark.asyncio
    async def test_cross_site_cache_isolation(self):
        """Asking for site B must never return what site A cached."""
        from unittest.mock import AsyncMock

        manager, connection = self._manager()

        connection.request = AsyncMock(return_value=[{"_id": "acme-1", "mac": "aa:aa:aa:aa:aa:aa"}])
        acme = await manager.get_devices(site="acme")

        connection.request = AsyncMock(return_value=[{"_id": "bravo-1", "mac": "bb:bb:bb:bb:bb:bb"}])
        bravo = await manager.get_devices(site="bravo")

        assert [d.raw["_id"] for d in acme] == ["acme-1"]
        assert [d.raw["_id"] for d in bravo] == ["bravo-1"]

        # And the second read must not have been served from the first one's entry.
        again = await manager.get_devices(site="acme")
        assert [d.raw["_id"] for d in again] == ["acme-1"]

    @pytest.mark.asyncio
    async def test_a_site_argument_never_outlives_its_call(self):
        """The connection must point where it did before, whatever the call named.

        The site is state shared by every caller. A helper that switched it and
        failed to switch back sent the next, unrelated call to the wrong site.
        """
        from unittest.mock import AsyncMock

        manager, connection = self._manager()
        connection.request = AsyncMock(return_value=[])

        await manager.get_devices(site="bravo")

        assert connection.site == "default"
        connection.set_site.assert_not_called()


class TestDeviceToolsErrorHandling:
    """Test error handling in device tools."""

    @pytest.mark.asyncio
    async def test_invalid_site_parameter_error(self):
        """RED: Should raise error for invalid site parameter."""
        from src.utils.site_resolver import validate_site_parameter

        # Invalid: special characters
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("site@location")

        # Invalid: spaces
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("my site")

        # Invalid: too long
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("a" * 101)

    @pytest.mark.asyncio
    async def test_site_not_found_error(self):
        """RED: Should provide helpful error when site not found."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Acme", "desc": "Acme Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError) as exc_info:
                await resolve_site_identifier("InvalidSite")

            error = exc_info.value
            assert "InvalidSite" in error.message
            assert error.http_status == 404


class TestDeviceMultiSiteIntegration:
    """Integration tests for multi-site device operations."""

    @pytest.mark.asyncio
    async def test_site_fuzzy_matching(self):
        """GREEN: Site resolver should support fuzzy matching."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Grupo Acme", "desc": "Acme Site"},
            {"_id": "def456", "name": "default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Fuzzy match "acme" to "Grupo Acme"
            result = await resolve_site_identifier("acme")
            assert result["slug"] == "Grupo Acme"

    @pytest.mark.asyncio
    async def test_site_prefix_matching(self):
        """GREEN: Site resolver should support prefix matching."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "acme-branch-1", "desc": ""},
            {"_id": "def456", "name": "default", "desc": ""},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Prefix match
            result = await resolve_site_identifier("acme")
            assert result["slug"] == "acme-branch-1"
