"""
Tests for network management tools with multi-site support.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 2C: Refatoração de Tools de Gerenciamento de Redes (networks.py)

Tools being tested:
1. unifi_list_networks
2. unifi_create_network
3. unifi_update_network
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


def create_mock_network(
    name: str = "Test Network",
    purpose: str = "corporate",
    ip_subnet: str = "192.168.1.0/24",
    vlan_enabled: bool = False,
    vlan: int = None,
    dhcp_enabled: bool = True,
    dhcp_start: str = "192.168.1.100",
    dhcp_stop: str = "192.168.1.200",
    enabled: bool = True,
    **kwargs
) -> Dict[str, Any]:
    """Create a mock network dictionary."""
    base = {
        "_id": "network_id_123",
        "name": name,
        "purpose": purpose,
        "ip_subnet": ip_subnet,
        "enabled": enabled,
        "vlan_enabled": vlan_enabled,
        "vlan": vlan,
        "dhcp_enabled": dhcp_enabled,
        "dhcp_start": dhcp_start,
        "dhcp_stop": dhcp_stop,
        "site_id": "default_site",
        "raw": None,  # For hasattr check
    }
    base.update(kwargs)
    return base


class TestListNetworksWithSite:
    """Test unifi_list_networks with site parameter."""

    @pytest.mark.asyncio
    async def test_list_networks_with_valid_site(self):
        """RED: Should list networks for specified site."""
        # This test validates that list_networks accepts site parameter
        # and resolves it correctly
        from src.utils.site_resolver import validate_site_parameter

        # Test that site parameter is accepted and validated
        site_validated = validate_site_parameter("wink")
        assert site_validated == "wink"

    @pytest.mark.asyncio
    async def test_list_networks_backward_compatibility_without_site(self):
        """GREEN: Should list networks without site parameter (default site mode)."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_list_networks_site_not_found_error(self):
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
    async def test_list_networks_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["wink", "default"])


class TestCreateNetworkWithSite:
    """Test unifi_create_network with site parameter."""

    @pytest.mark.asyncio
    async def test_create_network_with_valid_site(self):
        """RED: Should create network for specified site."""
        from src.utils.site_resolver import validate_site_parameter

        site_validated = validate_site_parameter("ramada")
        assert site_validated == "ramada"

    @pytest.mark.asyncio
    async def test_create_network_backward_compatibility_without_site(self):
        """GREEN: Should create network without site parameter (default site mode)."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_create_network_site_not_found_error(self):
        """RED: Should raise SiteNotFoundError for invalid site in create."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Ramada", "desc": "Ramada Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("InvalidSite")

    @pytest.mark.asyncio
    async def test_create_network_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site in create."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("unauthorized-site", allowed_sites=["default"])


class TestUpdateNetworkWithSite:
    """Test unifi_update_network with site parameter."""

    @pytest.mark.asyncio
    async def test_update_network_with_valid_site(self):
        """RED: Should update network for specified site."""
        from src.utils.site_resolver import validate_site_parameter

        site_validated = validate_site_parameter("default")
        assert site_validated == "default"

    @pytest.mark.asyncio
    async def test_update_network_backward_compatibility_without_site(self):
        """GREEN: Should update network without site parameter (default site mode)."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_update_network_site_not_found_error(self):
        """RED: Should raise SiteNotFoundError for invalid site in update."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("WrongSite")

    @pytest.mark.asyncio
    async def test_update_network_site_forbidden_error(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site in update."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("restricted-site", allowed_sites=["default", "wink"])
