"""Tests for the QosManager class.

QoS rules live on the V2 API. `ApiRequestV2.decode` synthesises
`meta={"rc": "ok"}` for any body it can parse, so on this manager the
exception path -- not the envelope -- is what separates an accepted write from
a refused one. Both are asserted here.

The manager passes `site=` down to `ConnectionManager.request()` instead of
mutating connection state, so these tests also pin that the target site
reaches `request()` and that caches are keyed per site.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


class TestQosManager:
    """Tests for the QosManager class."""

    @pytest.fixture
    def mock_connection(self):
        """Create a mock ConnectionManager."""
        conn = MagicMock()
        conn.site = "default"
        conn.request = AsyncMock()
        conn.get_cached = MagicMock(return_value=None)
        conn._update_cache = MagicMock()
        conn._invalidate_cache = MagicMock()
        conn.resolve_slug = MagicMock(side_effect=lambda s: s or None)
        return conn

    @pytest.fixture
    def qos_manager(self, mock_connection):
        """Create a QosManager with mocked connection."""
        from src.managers.qos_manager import QosManager

        return QosManager(mock_connection)

    @staticmethod
    def _request_call(mock_connection, index=0):
        """Return (api_request, kwargs) of the Nth call to connection.request."""
        call = mock_connection.request.call_args_list[index]
        return call[0][0], call[1]

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_qos_rules_returns_list(self, qos_manager, mock_connection):
        """A list response is cached and returned as-is."""
        rules = [{"_id": "r1", "name": "VoIP", "enabled": True}]
        mock_connection.request.return_value = rules

        result = await qos_manager.get_qos_rules()

        assert result == rules
        mock_connection._update_cache.assert_called_once_with("qos_rules_default", rules)

    @pytest.mark.asyncio
    async def test_get_qos_rules_uses_v2_path(self, qos_manager, mock_connection):
        """QoS rules are read from the V2 qos-rules endpoint."""
        from aiounifi.models.api import ApiRequestV2

        mock_connection.request.return_value = []

        await qos_manager.get_qos_rules()

        api_request, _ = self._request_call(mock_connection)
        assert isinstance(api_request, ApiRequestV2)
        assert api_request.path == "/qos-rules"
        assert api_request.method == "get"

    @pytest.mark.asyncio
    async def test_get_qos_rules_uses_cache(self, qos_manager, mock_connection):
        """A cached value short-circuits the request."""
        cached = [{"_id": "cached"}]
        mock_connection.get_cached.return_value = cached

        result = await qos_manager.get_qos_rules()

        assert result == cached
        mock_connection.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_qos_rules_unwraps_envelope(self, qos_manager, mock_connection):
        """A full envelope yields its data, never the envelope as a rule."""
        mock_connection.request.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "r1"}]}

        result = await qos_manager.get_qos_rules()

        assert result == [{"_id": "r1"}]

    @pytest.mark.asyncio
    async def test_get_qos_rules_handles_error(self, qos_manager, mock_connection):
        """A transport failure yields an empty list, not an exception."""
        mock_connection.request.side_effect = Exception("Network error")

        assert await qos_manager.get_qos_rules() == []

    @pytest.mark.asyncio
    async def test_get_qos_rules_uses_target_site(self, qos_manager, mock_connection):
        """The requested site is passed to request(), not applied to the connection."""
        mock_connection.request.return_value = []

        await qos_manager.get_qos_rules(site="branch")

        _, kwargs = self._request_call(mock_connection)
        assert kwargs["site"] == "branch"
        mock_connection.set_site.assert_not_called()
        assert mock_connection.site == "default"

    @pytest.mark.asyncio
    async def test_get_qos_rules_cache_key_is_per_site(self, qos_manager, mock_connection):
        """A value cached for one site must never be served for another."""
        mock_connection.request.return_value = []

        await qos_manager.get_qos_rules(site="siteA")
        await qos_manager.get_qos_rules(site="siteB")

        keys = [call[0][0] for call in mock_connection._update_cache.call_args_list]
        assert keys == ["qos_rules_siteA", "qos_rules_siteB"]

    @pytest.mark.asyncio
    async def test_get_qos_rule_details_found(self, qos_manager, mock_connection):
        """A rule is located by id within the site's rule list."""
        mock_connection.request.return_value = [{"_id": "r1"}, {"_id": "r2", "name": "VoIP"}]

        rule = await qos_manager.get_qos_rule_details("r2")

        assert rule["name"] == "VoIP"

    @pytest.mark.asyncio
    async def test_get_qos_rule_details_not_found(self, qos_manager, mock_connection):
        """An unknown id yields None."""
        mock_connection.request.return_value = [{"_id": "r1"}]

        assert await qos_manager.get_qos_rule_details("missing") is None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_update_qos_rule_merges_existing_fields(self, qos_manager, mock_connection):
        """V2 PUT replaces the object, so untouched fields must be resent."""
        mock_connection.request.side_effect = [
            [{"_id": "r1", "name": "VoIP", "enabled": True, "dscp_value": 46}],
            {"meta": {"rc": "ok"}, "data": []},
        ]

        result = await qos_manager.update_qos_rule("r1", {"enabled": False})

        assert result is True
        api_request, _ = self._request_call(mock_connection, 1)
        assert api_request.path == "/qos-rules/r1"
        assert api_request.data["enabled"] is False
        assert api_request.data["dscp_value"] == 46
        assert api_request.data["name"] == "VoIP"

    @pytest.mark.asyncio
    async def test_update_qos_rule_not_found(self, qos_manager, mock_connection):
        """An update against a missing rule fails without writing."""
        mock_connection.request.return_value = []

        assert await qos_manager.update_qos_rule("missing", {"enabled": False}) is False
        assert mock_connection.request.call_count == 1

    @pytest.mark.asyncio
    async def test_update_qos_rule_empty_payload_is_a_noop(self, qos_manager, mock_connection):
        """Nothing to change means nothing to send."""
        assert await qos_manager.update_qos_rule("r1", {}) is True
        mock_connection.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_qos_rule_invalidates_target_site_cache(self, qos_manager, mock_connection):
        """Only the written site's cache entry is dropped."""
        mock_connection.request.side_effect = [
            [{"_id": "r1", "name": "VoIP"}],
            {"meta": {"rc": "ok"}, "data": []},
        ]

        await qos_manager.update_qos_rule("r1", {"enabled": False}, site="branch")

        mock_connection._invalidate_cache.assert_called_once_with("qos_rules_branch")

    @pytest.mark.asyncio
    async def test_update_qos_rule_reports_transport_failure(self, qos_manager, mock_connection):
        """A raised error is the refusal signal on V2 and must not report success."""
        mock_connection.request.side_effect = [
            [{"_id": "r1", "name": "VoIP"}],
            Exception("api.err.InvalidPayload"),
        ]

        assert await qos_manager.update_qos_rule("r1", {"enabled": False}) is False
        mock_connection._invalidate_cache.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_qos_rule_reports_refusal_envelope(self, qos_manager, mock_connection):
        """A V1-shaped refusal envelope is still honoured if one ever arrives."""
        mock_connection.request.side_effect = [
            [{"_id": "r1", "name": "VoIP"}],
            {"meta": {"rc": "error", "msg": "api.err.NoPermission"}},
        ]

        assert await qos_manager.update_qos_rule("r1", {"enabled": False}) is False

    @pytest.mark.asyncio
    async def test_create_qos_rule_returns_stored_object(self, qos_manager, mock_connection):
        """The created rule comes from the controller's echo, not the request."""
        mock_connection.request.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "new1", "name": "VoIP", "enabled": True}],
        }

        created = await qos_manager.create_qos_rule({"name": "VoIP", "enabled": True})

        assert created["_id"] == "new1"
        api_request, _ = self._request_call(mock_connection)
        assert api_request.path == "/qos-rules"
        assert api_request.method == "post"

    @pytest.mark.asyncio
    async def test_create_qos_rule_requires_name_and_enabled(self, qos_manager, mock_connection):
        """A payload missing required fields never reaches the controller."""
        assert await qos_manager.create_qos_rule({"name": "VoIP"}) is None
        mock_connection.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_qos_rule_without_echo_is_a_failure(self, qos_manager, mock_connection):
        """No stored object means no rule id to report."""
        mock_connection.request.return_value = {"meta": {"rc": "ok"}, "data": []}

        assert await qos_manager.create_qos_rule({"name": "VoIP", "enabled": True}) is None

    @pytest.mark.asyncio
    async def test_create_qos_rule_handles_error(self, qos_manager, mock_connection):
        """A raised error yields None rather than a half-reported creation."""
        mock_connection.request.side_effect = Exception("API error")

        assert await qos_manager.create_qos_rule({"name": "VoIP", "enabled": True}) is None

    @pytest.mark.asyncio
    async def test_create_qos_rule_uses_target_site(self, qos_manager, mock_connection):
        """Creation is scoped to the requested site."""
        mock_connection.request.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "new1"}]}

        await qos_manager.create_qos_rule({"name": "VoIP", "enabled": True}, site="branch")

        _, kwargs = self._request_call(mock_connection)
        assert kwargs["site"] == "branch"
        mock_connection._invalidate_cache.assert_called_once_with("qos_rules_branch")

    @pytest.mark.asyncio
    async def test_delete_qos_rule_success(self, qos_manager, mock_connection):
        """Delete hits the V2 rule path for the target site."""
        mock_connection.request.return_value = {"meta": {"rc": "ok"}, "data": []}

        result = await qos_manager.delete_qos_rule("r1", site="branch")

        assert result is True
        api_request, kwargs = self._request_call(mock_connection)
        assert api_request.path == "/qos-rules/r1"
        assert api_request.method == "delete"
        assert kwargs["site"] == "branch"
        mock_connection._invalidate_cache.assert_called_once_with("qos_rules_branch")

    @pytest.mark.asyncio
    async def test_delete_qos_rule_handles_error(self, qos_manager, mock_connection):
        """A raised error is reported as failure and leaves the cache alone."""
        mock_connection.request.side_effect = Exception("API error")

        assert await qos_manager.delete_qos_rule("r1") is False
        mock_connection._invalidate_cache.assert_not_called()

    # ------------------------------------------------------------------
    # Site isolation
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_site_does_not_leak_between_calls(self, qos_manager, mock_connection):
        """A scoped call must not change the site the next call runs against."""
        mock_connection.request.return_value = []

        await qos_manager.get_qos_rules(site="branch")
        await qos_manager.get_qos_rules()

        _, first = self._request_call(mock_connection, 0)
        _, second = self._request_call(mock_connection, 1)
        assert first["site"] == "branch"
        assert second["site"] == "default"
