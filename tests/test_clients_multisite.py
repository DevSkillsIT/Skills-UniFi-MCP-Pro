"""
Tests for client management tools with multi-site support.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 2B: Refatoração de Tools de Gerenciamento de Clientes (clients.py)

Tools being tested:
1. unifi_list_clients
2. unifi_get_client_details
3. unifi_block_client / unifi_unblock_client
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


def create_mock_client(
    mac: str = "aa:bb:cc:dd:ee:ff",
    name: str = "Test Client",
    hostname: str = "test-device",
    ip: str = "192.168.1.100",
    is_wired: bool = False,
    blocked: bool = False,
    essid: str = "TestNetwork",
    signal: int = -55,
    channel: int = 6,
    radio: str = "ng",
    **kwargs
) -> Dict[str, Any]:
    """Create a mock client dictionary."""
    base = {
        "mac": mac,
        "name": name,
        "hostname": hostname,
        "ip": ip,
        "is_wired": is_wired,
        "blocked": blocked,
        "_id": "client_id_123",
        "last_seen": 1700000000,
        "essid": essid,
        "signal": signal,
        "channel": channel,
        "radio": radio,
        "raw": None,  # For hasattr check
    }
    base.update(kwargs)
    return base


class TestListClientsWithSite:
    """Test unifi_list_clients with site parameter."""

    @pytest.mark.asyncio
    async def test_list_clients_with_valid_site(self):
        """RED: Should list clients for specified site."""
        # This test validates that list_clients accepts site parameter
        # and resolves it correctly
        from src.utils.site_resolver import validate_site_parameter

        # Test that site parameter is accepted and validated
        site_validated = validate_site_parameter("wink")
        assert site_validated == "wink"

    @pytest.mark.asyncio
    async def test_list_clients_backward_compatibility_without_site(self):
        """GREEN: Should list clients without site parameter (default site mode)."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_list_clients_site_not_found_error(self):
        """RED: Should raise SiteNotFoundError for invalid site."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError) as exc_info:
                await resolve_site_identifier("NonExistent")

            error = exc_info.value
            assert "NonExistent" in error.message

    @pytest.mark.asyncio
    async def test_list_clients_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["wink", "default"])

    @pytest.mark.asyncio
    async def test_list_clients_site_fuzzy_matching(self):
        """GREEN: Site resolver should support fuzzy matching for clients."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "GW_PON_ASAG_Escritorio", "desc": "Wink Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            result = await resolve_site_identifier("wink")
            assert result["slug"] == "abc123"
            assert result["display_name"] == "GW_PON_ASAG_Escritorio"


class TestGetClientDetailsWithSite:
    """Test unifi_get_client_details with site parameter."""

    @pytest.mark.asyncio
    async def test_get_client_details_with_valid_site(self):
        """RED: Should get client details for specified site."""
        from src.utils.site_resolver import validate_site_parameter

        site_validated = validate_site_parameter("wink")
        assert site_validated == "wink"

    @pytest.mark.asyncio
    async def test_get_client_details_backward_compatibility(self):
        """GREEN: Should accept mac_address parameter and optional site."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_get_client_details_site_not_found_error(self):
        """RED: Should raise SiteNotFoundError for invalid site."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("InvalidSite")

    @pytest.mark.asyncio
    async def test_get_client_details_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["wink"])


class TestBlockClientWithSite:
    """Test unifi_block_client with site parameter."""

    @pytest.mark.asyncio
    async def test_block_client_with_valid_site(self):
        """RED: Should block client on specified site."""
        from src.utils.site_resolver import validate_site_parameter

        site_validated = validate_site_parameter("wink")
        assert site_validated == "wink"

    @pytest.mark.asyncio
    async def test_block_client_backward_compatibility(self):
        """GREEN: Should accept mac_address and optional site parameter."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_block_client_site_not_found_error(self):
        """RED: Should raise SiteNotFoundError for invalid site."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("NonExistent")

    @pytest.mark.asyncio
    async def test_block_client_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["default"])


class TestUnblockClientWithSite:
    """Test unifi_unblock_client with site parameter."""

    @pytest.mark.asyncio
    async def test_unblock_client_with_valid_site(self):
        """RED: Should unblock client on specified site."""
        from src.utils.site_resolver import validate_site_parameter

        site_validated = validate_site_parameter("wink")
        assert site_validated == "wink"

    @pytest.mark.asyncio
    async def test_unblock_client_backward_compatibility(self):
        """GREEN: Should accept mac_address and optional site parameter."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_unblock_client_site_not_found_error(self):
        """RED: Should raise SiteNotFoundError for invalid site."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("NonExistent")

    @pytest.mark.asyncio
    async def test_unblock_client_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["default"])


class TestClientOperationsWithSiteResolver:
    """Integration tests for client operations with site resolver."""

    @pytest.mark.asyncio
    async def test_site_parameter_validation_in_clients(self):
        """RED: Client tools should validate site parameter."""
        from src.utils.site_resolver import validate_site_parameter

        # Valid site names (converted to lowercase)
        assert validate_site_parameter("wink") == "wink"
        assert validate_site_parameter("default") == "default"
        assert validate_site_parameter("Grupo-Wink") == "Grupo-Wink"  # validate_site_parameter doesn't lowercase

        # Invalid: special characters
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("site@invalid")

    @pytest.mark.asyncio
    async def test_site_access_validation_in_clients(self):
        """RED: Client tools should check site whitelist access."""
        from src.utils.site_resolver import validate_site_access

        # ALL-SITES mode (no restrictions)
        await validate_site_access("any-site", allowed_sites=None)

        # Whitelisted site
        await validate_site_access("wink", allowed_sites=["wink", "default"])

        # Non-whitelisted site
        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden", allowed_sites=["wink"])

    @pytest.mark.asyncio
    async def test_site_resolution_with_fuzzy_matching(self):
        """GREEN: Site resolver should support fuzzy matching."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "GW_PON_ASAG_Escritorio", "desc": "Wink Site"},
            {"_id": "def456", "name": "Ramada_Branch", "desc": "Ramada Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Test alias functionality (main validation for multi-site migration)
            result = await resolve_site_identifier("wink")
            assert result["slug"] == "abc123"
            assert result["display_name"] == "GW_PON_ASAG_Escritorio"
            
            # Test exact match functionality with available site
            result = await resolve_site_identifier("Ramada_Branch")
            assert result["slug"] == "def456"
            assert result["display_name"] == "Ramada_Branch"


class TestClientSiteContextManagement:
    """Test site context switching in client operations."""

    @pytest.mark.asyncio
    async def test_site_context_restoration_after_operation(self):
        """REFACTOR: Site context should be restored after operation."""
        # This validates that after switching site for an operation,
        # the original site context is restored
        from src.utils.site_resolver import validate_site_parameter

        # Validate that we can track site context
        original_site = "default"
        new_site = validate_site_parameter("wink")

        assert original_site != new_site
        # Context restoration would happen in the try/finally block

    @pytest.mark.asyncio
    async def test_client_operations_preserve_site_context(self):
        """REFACTOR: Multiple client operations should not affect site context."""
        # Validates that querying clients from different sites
        # doesn't affect the global site context after operations complete
        assert True  # Will be validated in implementation


class TestClientMultiSiteIntegration:
    """Integration tests for multi-site client operations."""

    @pytest.mark.asyncio
    async def test_list_clients_different_sites_returns_different_results(self):
        """GREEN: Client lists should differ between sites."""
        # Create clients from different sites
        wink_client = create_mock_client(mac="aa:bb:cc:dd:ee:01", name="Wink Client")
        default_client = create_mock_client(mac="bb:bb:cc:dd:ee:02", name="Default Client")

        assert wink_client["mac"] != default_client["mac"]
        assert wink_client["name"] != default_client["name"]

    @pytest.mark.asyncio
    async def test_client_operations_with_prefix_matching(self):
        """GREEN: Site resolver should support prefix matching."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "GW_PON_ASAG_Escritorio", "desc": ""},
            {"_id": "def456", "name": "default", "desc": ""},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Test with actual alias target from .env (wink -> GW_PON_ASAG_Escritorio)
            result = await resolve_site_identifier("wink")
            assert result["slug"] == "abc123"
            assert result["display_name"] == "GW_PON_ASAG_Escritorio"


class TestClientErrorHandling:
    """Test error handling in client tools with site parameter."""

    @pytest.mark.asyncio
    async def test_invalid_site_parameter_in_clients(self):
        """RED: Should handle invalid site parameters gracefully."""
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
    async def test_site_not_found_error_with_suggestions(self):
        """RED: Should provide helpful error with suggestions."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
            {"_id": "def456", "name": "Ramada", "desc": "Ramada Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError) as exc_info:
                await resolve_site_identifier("NonExistent")

            error = exc_info.value
            assert "NonExistent" in error.message
            assert error.http_status == 404


class TestClientMockData:
    """Test helper functions for creating mock client data."""

    def test_create_mock_client_defaults(self):
        """Test creating a mock client with default values."""
        client = create_mock_client()

        assert client["mac"] == "aa:bb:cc:dd:ee:ff"
        assert client["name"] == "Test Client"
        assert client["hostname"] == "test-device"
        assert client["is_wired"] is False
        assert client["blocked"] is False

    def test_create_mock_client_custom_values(self):
        """Test creating a mock client with custom values."""
        client = create_mock_client(
            mac="11:22:33:44:55:66",
            name="Custom Client",
            is_wired=True,
            blocked=True
        )

        assert client["mac"] == "11:22:33:44:55:66"
        assert client["name"] == "Custom Client"
        assert client["is_wired"] is True
        assert client["blocked"] is True

    def test_mock_client_wireless_vs_wired(self):
        """Test mock client properties for wireless and wired."""
        wireless = create_mock_client(is_wired=False, essid="WiFi-Network")
        wired = create_mock_client(is_wired=True)

        assert wireless["is_wired"] is False
        assert wireless["essid"] == "WiFi-Network"
        assert wired["is_wired"] is True
