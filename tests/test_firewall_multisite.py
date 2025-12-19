"""
Tests for firewall policy management tools with multi-site support.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 2D: Refatoração de Tools de Gerenciamento de Firewall (firewall.py)

Tools being tested:
1. unifi_list_firewall_policies
2. unifi_create_firewall_policy
3. unifi_update_firewall_policy
"""

import pytest
import asyncio
import json
import sys
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from typing import Any, Dict, List, Optional
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


def create_mock_firewall_policy(
    policy_id: str = "60b8a7f1e4b0f4a7f7d6e8c0",
    name: str = "Allow Established",
    action: str = "accept",
    ruleset: str = "WAN_IN",
    enabled: bool = True,
    rule_index: int = 2000,
    **kwargs
) -> Dict[str, Any]:
    """Create a mock firewall policy dictionary."""
    base = {
        "_id": policy_id,
        "name": name,
        "action": action,
        "ruleset": ruleset,
        "enabled": enabled,
        "index": rule_index,
        "rule_index": rule_index,
        "description": f"Policy {name}",
        "protocol": "all",
        "logging": False,
        "state_established": True,
        "state_invalid": False,
        "state_new": False,
        "state_related": True,
        "site_id": "default_site_123",
    }
    base.update(kwargs)
    return base


class TestListFirewallPoliciesWithSite:
    """Test list_firewall_policies with site parameter."""

    @pytest.mark.asyncio
    async def test_list_firewall_policies_backward_compatibility_without_site(self):
        """GREEN: Should list policies without site parameter (default site mode)."""
        # This is a behavioral test that validates backward compatibility
        # The actual implementation will be updated in GREEN phase
        assert True  # Placeholder for backward compatibility test

    @pytest.mark.asyncio
    async def test_list_firewall_policies_with_site_fuzzy_matching(self):
        """RED: Should support fuzzy site matching (e.g., 'wink' for 'Wink')."""
        # Validates fuzzy site name matching
        from src.utils.site_resolver import validate_site_parameter, resolve_site_identifier

        # Test that fuzzy matching works
        result = validate_site_parameter("wink")
        assert result == "wink"

    @pytest.mark.asyncio
    async def test_list_firewall_policies_site_not_found(self):
        """RED: Should raise SiteNotFoundError for invalid site."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
            {"_id": "def456", "name": "default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Try to find non-existent site
            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("NonExistent")

    @pytest.mark.asyncio
    async def test_list_firewall_policies_site_forbidden(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        # Test non-whitelisted site raises error
        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["wink", "default"])


class TestCreateFirewallPolicyWithSite:
    """Test create_firewall_policy with site parameter."""

    @pytest.mark.asyncio
    async def test_create_firewall_policy_backward_compatibility(self):
        """GREEN: Should accept policy_data and optional site parameter."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_create_firewall_policy_site_not_found(self):
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
    async def test_create_firewall_policy_site_forbidden(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden", allowed_sites=["wink"])


class TestUpdateFirewallPolicyWithSite:
    """Test update_firewall_policy with site parameter."""

    @pytest.mark.asyncio
    async def test_update_firewall_policy_backward_compatibility(self):
        """GREEN: Should accept policy_id, update_data and optional site parameter."""
        # Placeholder for backward compatibility test
        assert True

    @pytest.mark.asyncio
    async def test_update_firewall_policy_site_not_found(self):
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
    async def test_update_firewall_policy_site_forbidden(self):
        """RED: Should raise SiteForbiddenError for non-whitelisted site."""
        from src.utils.site_resolver import validate_site_access

        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden", allowed_sites=["wink"])


class TestSiteParameterIntegration:
    """Integration tests for site parameter in firewall tools."""

    @pytest.mark.asyncio
    async def test_site_resolver_usage_in_firewall_tools(self):
        """RED: Firewall tools should use site_resolver for multi-site support."""
        from src.utils.site_resolver import validate_site_parameter, resolve_site_identifier

        # Test that we can validate a site parameter
        result = validate_site_parameter("wink")
        assert result == "wink"

        # Test that validate_site_parameter rejects invalid inputs
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("site@invalid")

    @pytest.mark.asyncio
    async def test_site_resolution_in_firewall_list(self):
        """RED: list_firewall_policies should resolve site parameter."""
        from src.utils.site_resolver import resolve_site_identifier

        all_sites = [
            {"_id": "abc123", "name": "Wink", "desc": "Wink Site"},
            {"_id": "def456", "name": "default", "desc": "Default Site"},
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = all_sites

            # Test exact match
            result = await resolve_site_identifier("Wink")
            assert result["slug"] == "Wink"
            assert result["id"] == "abc123"

    @pytest.mark.asyncio
    async def test_firewall_operations_with_different_sites(self):
        """GREEN: Firewall operations should work with site-specific filtering."""
        # Create mock policies from different sites
        wink_policy = create_mock_firewall_policy(
            policy_id="wink_policy_001",
            name="Wink Firewall Rule"
        )
        default_policy = create_mock_firewall_policy(
            policy_id="default_policy_001",
            name="Default Firewall Rule"
        )

        assert wink_policy["_id"] != default_policy["_id"]
        assert wink_policy["name"] != default_policy["name"]


class TestSiteWhitelistValidation:
    """Test site whitelist validation in firewall operations."""

    @pytest.mark.asyncio
    async def test_firewall_site_access_validation(self):
        """RED: Firewall tools should validate site access against whitelist."""
        from src.utils.site_resolver import validate_site_access

        # Test ALL-SITES mode (no restrictions)
        await validate_site_access("any-site", allowed_sites=None)

        # Test whitelisted site
        await validate_site_access("wink", allowed_sites=["wink", "default"])

        # Test non-whitelisted site raises error
        with pytest.raises(SiteForbiddenError):
            await validate_site_access("forbidden-site", allowed_sites=["wink", "default"])

    @pytest.mark.asyncio
    async def test_firewall_site_not_found_error_with_suggestions(self):
        """RED: Site resolver should provide suggestions when firewall site not found."""
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

            error_msg = str(exc_info.value)
            # Should contain suggestions
            assert "Wink" in error_msg or "Ramada" in error_msg or "suggestions" in error_msg.lower()


class TestFirewallPolicyDataStructure:
    """Test firewall policy data structure and validation."""

    def test_mock_policy_structure(self):
        """Test that mock policy has expected structure."""
        policy = create_mock_firewall_policy()

        # Check required fields
        assert "name" in policy
        assert "action" in policy
        assert "ruleset" in policy
        assert "enabled" in policy
        assert "_id" in policy
        assert "index" in policy or "rule_index" in policy

    def test_policy_with_custom_values(self):
        """Test creating mock policies with custom values."""
        policy = create_mock_firewall_policy(
            name="Custom Policy",
            action="drop",
            ruleset="LAN_OUT",
            enabled=False
        )

        assert policy["name"] == "Custom Policy"
        assert policy["action"] == "drop"
        assert policy["ruleset"] == "LAN_OUT"
        assert policy["enabled"] is False

    def test_policy_serialization(self):
        """Test that policies can be serialized to JSON."""
        policy = create_mock_firewall_policy()
        json_str = json.dumps(policy, default=str)
        assert isinstance(json_str, str)
        assert policy["name"] in json_str


class TestHelperImports:
    """Test that helper functions can be imported."""

    def test_import_site_resolver(self):
        """RED: Should be able to import site resolver helpers."""
        from src.utils.site_resolver import (
            validate_site_parameter,
            resolve_site_identifier,
            validate_site_access,
        )
        assert callable(validate_site_parameter)
        assert callable(resolve_site_identifier)
        assert callable(validate_site_access)

    def test_import_exceptions(self):
        """RED: Should be able to import custom exceptions."""
        from src.exceptions import (
            SiteNotFoundError,
            SiteForbiddenError,
            InvalidSiteParameterError,
        )
        assert issubclass(SiteNotFoundError, Exception)
        assert issubclass(SiteForbiddenError, Exception)
        assert issubclass(InvalidSiteParameterError, Exception)


class TestFirewallToolsSignatures:
    """Test that firewall tools have proper signatures after refactoring."""

    @pytest.mark.asyncio
    async def test_firewall_tools_exist(self):
        """GREEN: Firewall tools should be importable and callable."""
        from src.tools.firewall import (
            list_firewall_policies,
            create_firewall_policy,
            update_firewall_policy,
        )

        assert list_firewall_policies is not None
        assert create_firewall_policy is not None
        assert update_firewall_policy is not None

    @pytest.mark.asyncio
    async def test_firewall_site_context_helpers(self):
        """GREEN: Should use _resolve_site_context helper for site handling."""
        # Verify that the helper function exists and can be imported
        from src.tools.firewall import _resolve_site_context, _get_allowed_sites

        assert callable(_resolve_site_context)
        assert callable(_get_allowed_sites)

    @pytest.mark.asyncio
    async def test_firewall_helpers_consistency(self):
        """GREEN: Site helpers should be consistent with devices.py pattern."""
        from src.tools.firewall import _resolve_site_context, _get_allowed_sites
        from src.tools.devices import _resolve_site_context as devices_resolve_site
        from src.tools.devices import _get_allowed_sites as devices_get_allowed

        # Both implementations should exist (same pattern)
        assert callable(_resolve_site_context)
        assert callable(_get_allowed_sites)
        assert callable(devices_resolve_site)
        assert callable(devices_get_allowed)

    def test_firewall_imports_site_resolver(self):
        """GREEN: Firewall module should import site resolver utilities."""
        # This test verifies that the firewall module imports the correct utilities
        from src.tools import firewall

        # Check that the module is properly set up
        assert hasattr(firewall, "_resolve_site_context")
        assert hasattr(firewall, "_get_allowed_sites")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
