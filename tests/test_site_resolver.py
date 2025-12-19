"""
Tests for site resolver with fuzzy matching and semantic search.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 1: Site Resolver + unifi_list_sites (CRÍTICA)
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch
from src.utils.site_resolver import (
    resolve_site_identifier,
    validate_site_access,
    validate_site_parameter,
)
from src.exceptions import (
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
)


# Mock site objects matching aiounifi.models.site.Site structure
def create_mock_site(name: str, _id: str, desc: str = ""):
    """Create a mock Site object as dict."""
    return {
        "name": name,
        "_id": _id,
        "desc": desc,
    }


class TestValidateSiteParameter:
    """Test site parameter validation."""

    def test_valid_site_parameter_lowercase(self):
        """RED: Should accept lowercase alphanumeric."""
        result = validate_site_parameter("default")
        assert result == "default"

    def test_valid_site_parameter_uppercase(self):
        """RED: Should normalize uppercase to lowercase."""
        result = validate_site_parameter("DEFAULT")
        assert result == "default"

    def test_valid_site_parameter_with_hyphen(self):
        """RED: Should accept hyphens."""
        result = validate_site_parameter("groupe-wink")
        assert result == "groupe-wink"

    def test_valid_site_parameter_with_underscore(self):
        """RED: Should accept underscores."""
        result = validate_site_parameter("site_one")
        assert result == "site_one"

    def test_invalid_site_parameter_special_chars(self):
        """RED: Should reject special characters."""
        with pytest.raises(InvalidSiteParameterError) as exc_info:
            validate_site_parameter("site@location")
        assert "Special characters not allowed" in exc_info.value.message

    def test_invalid_site_parameter_spaces(self):
        """RED: Should reject spaces."""
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("my site")

    def test_invalid_site_parameter_too_long(self):
        """RED: Should reject strings > 100 chars."""
        long_string = "a" * 101
        with pytest.raises(InvalidSiteParameterError) as exc_info:
            validate_site_parameter(long_string)
        assert "exceeds maximum length" in exc_info.value.message

    def test_invalid_site_parameter_empty(self):
        """RED: Should reject empty strings."""
        with pytest.raises(InvalidSiteParameterError):
            validate_site_parameter("")

    def test_valid_site_parameter_with_numbers(self):
        """RED: Should accept numbers."""
        result = validate_site_parameter("site123")
        assert result == "site123"

    def test_valid_site_parameter_trimmed(self):
        """RED: Should trim whitespace."""
        result = validate_site_parameter("  default  ")
        assert result == "default"


class TestResolveSiteIdentifier:
    """Test fuzzy matching site resolver."""

    @pytest.mark.asyncio
    async def test_exact_match_by_name(self):
        """RED: Should find exact match by site name."""
        sites = [
            create_mock_site("default", "abc123"),
            create_mock_site("grupowink", "def456", "Grupo Wink"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            result = await resolve_site_identifier("grupowink")

            assert result["slug"] == "grupowink"
            assert result["id"] == "def456"

    @pytest.mark.asyncio
    async def test_case_insensitive_match(self):
        """RED: Should match case-insensitively."""
        sites = [
            create_mock_site("Default", "abc123"),
            create_mock_site("GrupoWink", "def456"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            result = await resolve_site_identifier("GRUPOWINK")

            assert result["slug"] == "GrupoWink"
            assert result["id"] == "def456"

    @pytest.mark.asyncio
    async def test_prefix_match(self):
        """RED: Should match by prefix."""
        sites = [
            create_mock_site("default", "abc123"),
            create_mock_site("ramada", "def456"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            result = await resolve_site_identifier("ram")

            assert result["slug"] == "ramada"

    @pytest.mark.asyncio
    async def test_fuzzy_match_high_score(self):
        """RED: Should fuzzy match with threshold 80%."""
        sites = [
            create_mock_site("grupowink", "def456", "Grupo Wink PMW"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            # "wink" should match "Grupo Wink" with score > 80%
            result = await resolve_site_identifier("wink")

            assert result["slug"] == "grupowink"

    @pytest.mark.asyncio
    async def test_fuzzy_match_description(self):
        """RED: Should also fuzzy match in description."""
        sites = [
            create_mock_site("gw_pmw_escritorio", "xyz789", "Escritório PMW Grupo Wink"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            # "escritorio" should match description
            result = await resolve_site_identifier("escritorio")

            assert result["slug"] == "gw_pmw_escritorio"

    @pytest.mark.asyncio
    async def test_site_not_found_low_score(self):
        """RED: Should raise error for low fuzzy score."""
        sites = [
            create_mock_site("default", "abc123"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            with pytest.raises(SiteNotFoundError) as exc_info:
                await resolve_site_identifier("nonexistent")

            assert exc_info.value.error_code == "SITE_NOT_FOUND"
            assert "nonexistent" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_site_not_found_includes_suggestions(self):
        """RED: Should include suggestions in error."""
        sites = [
            create_mock_site("site1", "id1"),
            create_mock_site("site2", "id2"),
            create_mock_site("site3", "id3"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            with pytest.raises(SiteNotFoundError) as exc_info:
                await resolve_site_identifier("xyz")

            details = exc_info.value.details
            assert "suggestions" in details
            assert len(details["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_empty_sites_list(self):
        """RED: Should handle empty sites list."""
        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = []

            with pytest.raises(SiteNotFoundError):
                await resolve_site_identifier("any")

    @pytest.mark.asyncio
    async def test_whitespace_trimmed(self):
        """RED: Should trim whitespace from input."""
        sites = [
            create_mock_site("default", "abc123"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            result = await resolve_site_identifier("  default  ")

            assert result["slug"] == "default"


class TestValidateSiteAccess:
    """Test site access validation."""

    @pytest.mark.asyncio
    async def test_access_allowed_all_mode(self):
        """RED: Should allow all sites when allowed_sites is None."""
        # Should not raise
        await validate_site_access("anysite", allowed_sites=None)

    @pytest.mark.asyncio
    async def test_access_allowed_in_whitelist(self):
        """RED: Should allow sites in whitelist."""
        # Should not raise
        await validate_site_access(
            "grupowink",
            allowed_sites=["default", "grupowink", "ramada"]
        )

    @pytest.mark.asyncio
    async def test_access_denied_not_in_whitelist(self):
        """RED: Should deny sites not in whitelist."""
        with pytest.raises(SiteForbiddenError) as exc_info:
            await validate_site_access(
                "forbidden",
                allowed_sites=["default", "grupowink"]
            )

        assert exc_info.value.error_code == "SITE_ACCESS_DENIED"
        assert exc_info.value.details["requested_site"] == "forbidden"

    @pytest.mark.asyncio
    async def test_access_case_insensitive(self):
        """RED: Should handle case-insensitive whitelist."""
        # Should not raise
        await validate_site_access(
            "GRUPOWINK",
            allowed_sites=["default", "grupowink"]
        )

    @pytest.mark.asyncio
    async def test_access_denied_empty_whitelist(self):
        """RED: Should deny all with empty whitelist."""
        with pytest.raises(SiteForbiddenError):
            await validate_site_access("default", allowed_sites=[])


class TestResolverIntegration:
    """Integration tests for resolver flow."""

    @pytest.mark.asyncio
    async def test_full_flow_fuzzy_match_allowed(self):
        """RED: Full flow - fuzzy match + access validation."""
        sites = [
            create_mock_site("grupowink", "def456", "Grupo Wink"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            # Resolve fuzzy
            result = await resolve_site_identifier("wink")
            assert result["slug"] == "grupowink"

            # Validate access
            await validate_site_access(
                result["slug"],
                allowed_sites=["grupowink", "default"]
            )

    @pytest.mark.asyncio
    async def test_full_flow_fuzzy_match_denied(self):
        """RED: Full flow - fuzzy match resolved but access denied."""
        sites = [
            create_mock_site("grupowink", "def456", "Grupo Wink"),
        ]

        with patch("src.utils.site_resolver.get_all_sites", new_callable=AsyncMock) as mock:
            mock.return_value = sites

            # Resolve fuzzy
            result = await resolve_site_identifier("wink")
            assert result["slug"] == "grupowink"

            # Access denied
            with pytest.raises(SiteForbiddenError):
                await validate_site_access(
                    result["slug"],
                    allowed_sites=["default"]  # grupowink not in list
                )
