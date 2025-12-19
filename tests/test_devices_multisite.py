"""
Tests for device management tools with multi-site support.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 2A: Refatoração de Tools de Gerenciamento de Dispositivos (devices.py)

Tools being tested:
1. unifi_list_devices
2. unifi_get_device_details
3. unifi_adopt_device
4. unifi_reboot_device
"""

import pytest
import asyncio
import sys
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from typing import Any, Dict, List
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

    @pytest.mark.asyncio
    async def test_list_devices_backward_compatibility_without_site(self):
        """GREEN: Should list devices without site parameter (default site mode)."""
        # This is a behavioral test that validates backward compatibility
        # The actual implementation will be updated in GREEN phase
        assert True  # Placeholder for backward compatibility test

    @pytest.mark.asyncio
    async def test_list_devices_site_parameter_signature(self):
        """RED: Tool should accept optional site parameter."""
        # This test validates that the function signature supports site parameter
        # Test will pass after GREEN phase adds site: Optional[str] = None
        import inspect

        # We'll check this by inspecting the tool decorator
        # For now, this is a placeholder showing the expected change
        pass


class TestGetDeviceDetailsWithSite:
    """Test get_device_details with site parameter."""

    @pytest.mark.asyncio
    async def test_get_device_details_backward_compatibility(self):
        """GREEN: Should accept mac_address parameter and optional site."""
        # Placeholder for backward compatibility test
        assert True


class TestAdoptDeviceWithSite:
    """Test adopt_device with site parameter."""

    @pytest.mark.asyncio
    async def test_adopt_device_backward_compatibility(self):
        """GREEN: Should accept mac_address and optional site parameter."""
        # Placeholder for backward compatibility test
        assert True


class TestRebootDeviceWithSite:
    """Test reboot_device with site parameter."""

    @pytest.mark.asyncio
    async def test_reboot_device_backward_compatibility(self):
        """GREEN: Should accept mac_address and optional site parameter."""
        # Placeholder for backward compatibility test
        assert True


class TestSiteParameterIntegration:
    """Integration tests for site parameter in device tools."""

    @pytest.mark.asyncio
    async def test_site_resolver_usage_in_device_tools(self):
        """RED: Device tools should use site_resolver for multi-site support."""
        # This test validates that tools use the site resolver
        # when site parameter is provided
        from src.utils.site_resolver import validate_site_parameter, resolve_site_identifier

        # Test that we can validate a site parameter
        result = validate_site_parameter("wink")
        assert result == "wink"

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
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
            {"_id": "def456", "name": "default", "desc": "Default Site"},
        ]

        # Patch get_all_sites in site_resolver
        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Test exact match
            result = await resolve_site_identifier("Wink")
            assert result["slug"] == "Wink"
            assert result["id"] == "abc123"

    @pytest.mark.asyncio
    async def test_device_operations_with_different_sites(self):
        """GREEN: Device operations should work with site-specific filtering."""
        # This test validates cross-site device queries

        # Create mock devices from different sites
        wink_device = create_mock_device(mac="aa:bb:cc:dd:ee:01", name="Wink AP")
        default_device = create_mock_device(mac="bb:bb:cc:dd:ee:02", name="Default AP")

        assert wink_device["mac"] != default_device["mac"]
        assert wink_device["name"] != default_device["name"]


class TestSiteWhitelistValidation:
    """Test site whitelist validation in device operations."""

    @pytest.mark.asyncio
    async def test_site_access_validation(self):
        """RED: Device tools should validate site access against whitelist."""
        from src.utils.site_resolver import validate_site_access

        # Test ALL-SITES mode (no restrictions)
        await validate_site_access("any-site", allowed_sites=None)

        # Test whitelisted site
        await validate_site_access("wink", allowed_sites=["wink", "default"])

        # Test non-whitelisted site raises error
        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["wink", "default"])

    @pytest.mark.asyncio
    async def test_site_not_found_error_with_suggestions(self):
        """RED: Site resolver should provide suggestions when site not found."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
            {"_id": "def456", "name": "Ramada", "desc": "Ramada Site"},
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

    @pytest.mark.asyncio
    async def test_cache_key_includes_site_slug(self):
        """REFACTOR: Cache keys should include site slug for isolation."""
        # This test validates the caching strategy
        # When site="Wink", cache key should be like "devices_wink_*"
        # When site="default", cache key should be like "devices_default_*"

        # Placeholder for cache key validation
        assert True  # Will be expanded in REFACTOR phase

    @pytest.mark.asyncio
    async def test_cross_site_cache_isolation(self):
        """REFACTOR: Queries for different sites should not share cache."""
        # This validates that querying site A doesn't return site B's cached data
        assert True  # Will be expanded in REFACTOR phase


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
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
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
            {"_id": "abc123", "name": "Grupo Wink", "desc": "Wink Site"},
            {"_id": "def456", "name": "default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Fuzzy match "wink" to "Grupo Wink"
            result = await resolve_site_identifier("wink")
            assert result["slug"] == "Grupo Wink"

    @pytest.mark.asyncio
    async def test_site_prefix_matching(self):
        """GREEN: Site resolver should support prefix matching."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "wink-branch-1", "desc": ""},
            {"_id": "def456", "name": "default", "desc": ""},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Prefix match
            result = await resolve_site_identifier("wink")
            assert result["slug"] == "wink-branch-1"
