"""
Exception hierarchy for UniFi MCP multi-site support.

Provides structured error handling with consistent JSON response format.
Fase 0: Infraestrutura de Exceções (BLOQUEANTE)
"""

from typing import Any, Dict, List, Optional


class UnifiMCPError(Exception):
    """
    Base exception class for all UniFi MCP errors.

    All exceptions in the UniFi MCP should inherit from this class
    to ensure consistent error handling and JSON response formatting.
    """

    error_code: str = "UNIFI_MCP_ERROR"
    http_status: int = 500

    def __init__(
        self,
        error_code: str,
        message: str,
        http_status: int,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize UniFi MCP exception.

        Args:
            error_code: Machine-readable error code (e.g., "SITE_NOT_FOUND")
            message: Human-readable error message
            http_status: HTTP status code (400, 403, 404, 500, 503)
            details: Additional error details as dict
        """
        self.error_code = error_code
        self.message = message
        self.http_status = http_status
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to structured JSON response dict.

        Returns:
            Dict with keys: success, error, message, http_status, details
        """
        return {
            "success": False,
            "error": self.error_code,
            "message": self.message,
            "http_status": self.http_status,
            "details": self.details,
        }


class SiteNotFoundError(UnifiMCPError):
    """
    Raised when requested site does not exist in UniFi Controller.

    HTTP Status: 404 Not Found
    Error Code: SITE_NOT_FOUND
    """

    def __init__(
        self,
        site_name: str,
        suggestions: Optional[List[str]] = None
    ):
        """
        Initialize SiteNotFoundError.

        Args:
            site_name: The site name that was not found
            suggestions: List of available site names to suggest to user
        """
        message = (
            f"Site '{site_name}' does not exist on the UniFi Controller. "
            "If you expected it to exist, check the identifier: a site can be named by its _id, "
            "its API slug, or its display name."
        )
        if suggestions:
            message += f" Allowed sites: {', '.join(suggestions)}"

        super().__init__(
            error_code="SITE_NOT_FOUND",
            message=message,
            http_status=404,
            details={
                "requested_site": site_name,
                "suggestions": suggestions or [],
            }
        )


class SiteForbiddenError(UnifiMCPError):
    """
    Raised when user does not have access to the requested site.

    This occurs when:
    - UNIFI_SITE whitelist is configured
    - User attempts to access a site not in the whitelist

    HTTP Status: 403 Forbidden
    Error Code: SITE_ACCESS_DENIED
    """

    def __init__(
        self,
        site_name: str,
        allowed_sites: Optional[List[str]] = None
    ):
        """
        Initialize SiteForbiddenError.

        Args:
            site_name: The site that was denied
            allowed_sites: List of allowed site names (None = ALL mode)
        """
        message = (
            f"Site '{site_name}' is not allowed. It exists on the UniFi Controller but is not "
            "in this server's allowed-sites list (UNIFI_ALLOWED_SITES). "
        )
        if allowed_sites:
            message += f"Allowed sites: {', '.join(allowed_sites)}."
        else:
            message += "No sites are currently allowed."

        super().__init__(
            error_code="SITE_ACCESS_DENIED",
            message=message,
            http_status=403,
            details={
                "requested_site": site_name,
                "allowed_sites": allowed_sites,
            }
        )


class InvalidSiteParameterError(UnifiMCPError):
    """
    Raised when site parameter fails validation.

    Validation rules:
    - Only alphanumeric characters, hyphens, and underscores allowed
    - Maximum 100 characters
    - Must not be empty

    HTTP Status: 400 Bad Request
    Error Code: INVALID_SITE_PARAMETER
    """

    def __init__(
        self,
        site_parameter: str,
        reason: Optional[str] = None
    ):
        """
        Initialize InvalidSiteParameterError.

        Args:
            site_parameter: The invalid parameter value
            reason: Explanation of why the parameter is invalid
        """
        message = f"Invalid site parameter: '{site_parameter}'."
        if reason:
            message += f" {reason}"

        super().__init__(
            error_code="INVALID_SITE_PARAMETER",
            message=message,
            http_status=400,
            details={
                "provided_value": site_parameter,
                "reason": reason,
            }
        )


class UnifiAPIUnavailableError(UnifiMCPError):
    """
    Raised when UniFi Controller API is unavailable.

    This occurs when:
    - Controller is not responding
    - Network connectivity is lost
    - Authentication fails
    - Unexpected API errors occur

    HTTP Status: 503 Service Unavailable
    Error Code: UNIFI_API_UNAVAILABLE
    """

    def __init__(
        self,
        original_error: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize UnifiAPIUnavailableError.

        Args:
            original_error: Original exception message from aiounifi
            details: Additional context (host, port, etc.)
        """
        message = f"UniFi API is unavailable: {original_error}"

        error_details = {"original_error": original_error}
        if details:
            error_details.update(details)

        super().__init__(
            error_code="UNIFI_API_UNAVAILABLE",
            message=message,
            http_status=503,
            details=error_details
        )


class ControllerRefusedError(UnifiMCPError):
    """
    Raised when the UniFi Controller rejects a write.

    The controller states exactly why it refused, in `meta.msg` (for example
    `api.err.InvalidFixedIP`, `api.err.ApGroupMissing`,
    `api.err.UnknownStation`). That message used to be logged and then replaced
    with a generic "Failed to ..." string, so the caller was told something went
    wrong but never what -- and the one piece of information that would fix the
    request was the piece thrown away.

    HTTP Status: 400 Bad Request
    Error Code: CONTROLLER_REFUSED
    """

    # Plain-language readings of the codes this server actually provokes.
    HINTS = {
        "api.err.InvalidFixedIP": (
            "The fixed IP is outside the subnet of the network the client belongs to. "
            "Choose an address inside that network's ip_subnet."
        ),
        "api.err.ApGroupMissing": (
            "The controller requires an AP group on a WLAN. Pass ap_group_ids, or omit it "
            "to have the site's default group applied."
        ),
        "api.err.UnknownStation": (
            "The controller has no active session for this MAC. The command only applies "
            "to a client that is currently associated."
        ),
        "api.err.NoPermission": (
            "The account this server authenticates as is not allowed to write to this site."
        ),
        "api.err.InvalidObject": "The controller rejected the payload as malformed.",
    }

    def __init__(self, action: str, controller_message: str, site: Optional[str] = None):
        """
        Initialize ControllerRefusedError.

        Args:
            action: What was attempted, in the caller's terms.
            controller_message: The controller's own `meta.msg`.
            site: Site the write targeted, when applicable.
        """
        message = f"The UniFi Controller refused to {action}: {controller_message}"
        hint = self.HINTS.get(controller_message)
        if hint:
            message += f" -- {hint}"
        if site:
            message += f" (site: {site})"

        super().__init__(
            error_code="CONTROLLER_REFUSED",
            message=message,
            http_status=400,
            details={
                "action": action,
                "controller_message": controller_message,
                "site": site,
            },
        )
