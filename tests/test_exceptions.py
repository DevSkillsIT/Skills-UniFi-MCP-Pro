"""
Tests for exception hierarchy and error handling in UniFi MCP.

Following RED-GREEN-REFACTOR TDD cycle.
Fase 0: Infraestrutura de Exceções (BLOQUEANTE)
"""

import pytest
from src.exceptions import (
    UnifiMCPError,
    SiteNotFoundError,
    SiteForbiddenError,
    InvalidSiteParameterError,
    UnifiAPIUnavailableError,
)


class TestUnifiMCPErrorBase:
    """Test base exception class."""

    def test_base_exception_has_required_attributes(self):
        """RED: Base exception should have required attributes."""
        error = UnifiMCPError(
            error_code="TEST_ERROR",
            message="Test message",
            http_status=500,
            details={"key": "value"}
        )

        assert error.error_code == "TEST_ERROR"
        assert error.message == "Test message"
        assert error.http_status == 500
        assert error.details == {"key": "value"}

    def test_base_exception_to_dict(self):
        """RED: Exception should convert to structured dict."""
        error = UnifiMCPError(
            error_code="TEST_ERROR",
            message="Test message",
            http_status=500,
            details={"key": "value"}
        )

        result = error.to_dict()

        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["error"] == "TEST_ERROR"
        assert result["message"] == "Test message"
        assert result["details"] == {"key": "value"}
        assert result["http_status"] == 500

    def test_base_exception_to_dict_without_details(self):
        """RED: Exception should handle missing details."""
        error = UnifiMCPError(
            error_code="TEST_ERROR",
            message="Test message",
            http_status=500
        )

        result = error.to_dict()

        assert result["details"] == {}


class TestSiteNotFoundError:
    """Test SiteNotFoundError exception."""

    def test_site_not_found_error_attributes(self):
        """RED: SiteNotFoundError should have correct attributes."""
        error = SiteNotFoundError(
            site_name="nonexistent",
            suggestions=["site1", "site2"]
        )

        assert error.error_code == "SITE_NOT_FOUND"
        assert error.http_status == 404
        assert "nonexistent" in error.message

    def test_site_not_found_error_with_suggestions(self):
        """RED: Should include suggestions in details."""
        error = SiteNotFoundError(
            site_name="wink",
            suggestions=["Wink", "Ramada"]
        )

        result = error.to_dict()

        assert result["error"] == "SITE_NOT_FOUND"
        assert result["http_status"] == 404
        assert result["details"]["requested_site"] == "wink"
        assert result["details"]["suggestions"] == ["Wink", "Ramada"]

    def test_site_not_found_error_without_suggestions(self):
        """RED: Should handle missing suggestions."""
        error = SiteNotFoundError(
            site_name="xyz",
            suggestions=[]
        )

        result = error.to_dict()

        assert result["details"]["suggestions"] == []


class TestSiteForbiddenError:
    """Test SiteForbiddenError exception."""

    def test_site_forbidden_error_attributes(self):
        """RED: SiteForbiddenError should have correct attributes."""
        error = SiteForbiddenError(
            site_name="restricted",
            allowed_sites=["site1", "site2"]
        )

        assert error.error_code == "SITE_ACCESS_DENIED"
        assert error.http_status == 403
        assert "restricted" in error.message

    def test_site_forbidden_error_with_allowed_sites(self):
        """RED: Should include allowed sites in details."""
        error = SiteForbiddenError(
            site_name="default",
            allowed_sites=["Wink", "Ramada"]
        )

        result = error.to_dict()

        assert result["error"] == "SITE_ACCESS_DENIED"
        assert result["http_status"] == 403
        assert result["details"]["requested_site"] == "default"
        assert result["details"]["allowed_sites"] == ["Wink", "Ramada"]

    def test_site_forbidden_error_without_allowed_sites(self):
        """RED: Should handle ALL mode."""
        error = SiteForbiddenError(
            site_name="xyz",
            allowed_sites=None
        )

        result = error.to_dict()

        assert result["details"]["allowed_sites"] is None


class TestInvalidSiteParameterError:
    """Test InvalidSiteParameterError exception."""

    def test_invalid_site_parameter_error_attributes(self):
        """RED: InvalidSiteParameterError should have correct attributes."""
        error = InvalidSiteParameterError(
            site_parameter="invalid@site",
            reason="Special characters not allowed"
        )

        assert error.error_code == "INVALID_SITE_PARAMETER"
        assert error.http_status == 400
        assert "invalid@site" in error.message

    def test_invalid_site_parameter_error_with_reason(self):
        """RED: Should include reason in details."""
        error = InvalidSiteParameterError(
            site_parameter="***",
            reason="Only alphanumeric and hyphens allowed"
        )

        result = error.to_dict()

        assert result["error"] == "INVALID_SITE_PARAMETER"
        assert result["http_status"] == 400
        assert result["details"]["provided_value"] == "***"
        assert result["details"]["reason"] == "Only alphanumeric and hyphens allowed"

    def test_invalid_site_parameter_error_without_reason(self):
        """RED: Should handle missing reason."""
        error = InvalidSiteParameterError(
            site_parameter="toolong",
            reason=None
        )

        result = error.to_dict()

        assert result["details"]["reason"] is None


class TestUnifiAPIUnavailableError:
    """Test UnifiAPIUnavailableError exception."""

    def test_unifi_api_unavailable_error_attributes(self):
        """RED: UnifiAPIUnavailableError should have correct attributes."""
        error = UnifiAPIUnavailableError(
            original_error="Connection timeout"
        )

        assert error.error_code == "UNIFI_API_UNAVAILABLE"
        assert error.http_status == 503
        assert "Connection timeout" in error.message

    def test_unifi_api_unavailable_error_with_details(self):
        """RED: Should include original error in details."""
        error = UnifiAPIUnavailableError(
            original_error="DNS resolution failed",
            details={"host": "192.168.1.1", "port": 443}
        )

        result = error.to_dict()

        assert result["error"] == "UNIFI_API_UNAVAILABLE"
        assert result["http_status"] == 503
        assert result["details"]["original_error"] == "DNS resolution failed"
        assert result["details"]["host"] == "192.168.1.1"

    def test_unifi_api_unavailable_error_without_details(self):
        """RED: Should handle missing details."""
        error = UnifiAPIUnavailableError(
            original_error="Service unavailable"
        )

        result = error.to_dict()

        assert result["details"]["original_error"] == "Service unavailable"


class TestExceptionInheritance:
    """Test exception inheritance chain."""

    def test_all_specific_errors_inherit_from_base(self):
        """RED: All specific errors should inherit from UnifiMCPError."""
        errors = [
            SiteNotFoundError("test", []),
            SiteForbiddenError("test", ["allowed"]),
            InvalidSiteParameterError("test", None),
            UnifiAPIUnavailableError("test"),
        ]

        for error in errors:
            assert isinstance(error, UnifiMCPError)
            assert isinstance(error, Exception)

    def test_all_errors_are_catchable_as_parent(self):
        """RED: All specific errors should be catchable as base type."""
        try:
            raise SiteNotFoundError("test", [])
        except UnifiMCPError as e:
            assert isinstance(e, UnifiMCPError)

        try:
            raise SiteForbiddenError("test", [])
        except UnifiMCPError as e:
            assert isinstance(e, UnifiMCPError)


class TestErrorResponseFormat:
    """Test error response format consistency."""

    def test_all_errors_return_consistent_dict_format(self):
        """RED: All error types should return consistent dict format."""
        errors = [
            SiteNotFoundError("test", []),
            SiteForbiddenError("test", []),
            InvalidSiteParameterError("test", None),
            UnifiAPIUnavailableError("test"),
        ]

        for error in errors:
            result = error.to_dict()

            # Check required keys
            assert "success" in result
            assert "error" in result
            assert "message" in result
            assert "http_status" in result
            assert "details" in result

            # Check types
            assert result["success"] is False
            assert isinstance(result["error"], str)
            assert isinstance(result["message"], str)
            assert isinstance(result["http_status"], int)
            assert isinstance(result["details"], dict)
