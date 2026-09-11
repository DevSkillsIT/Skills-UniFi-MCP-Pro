"""Tests for the UsergroupManager class.

This module tests user group (bandwidth profile) operations.

The manager no longer mutates connection state: it passes `site=` down to
`ConnectionManager.request()`, which swaps and restores under its own lock.
These tests therefore assert that the target site reaches `request()` and that
a cache entry for one site is never served for another.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


class TestUsergroupManager:
    """Tests for the UsergroupManager class."""

    @pytest.fixture
    def mock_connection(self):
        """Create a mock ConnectionManager."""
        conn = MagicMock()
        conn.site = "default"
        conn.request = AsyncMock()
        conn.get_cached = MagicMock(return_value=None)
        conn._update_cache = MagicMock()
        conn._invalidate_cache = MagicMock()
        # Real ConnectionManager returns None for a falsy site so the caller
        # falls back to the current default.
        conn.resolve_slug = MagicMock(side_effect=lambda s: s or None)
        return conn

    @pytest.fixture
    def usergroup_manager(self, mock_connection):
        """Create a UsergroupManager with mocked connection."""
        from src.managers.usergroup_manager import UsergroupManager

        return UsergroupManager(mock_connection)

    @staticmethod
    def _request_call(mock_connection, index=0):
        """Return (api_request, kwargs) of the Nth call to connection.request."""
        call = mock_connection.request.call_args_list[index]
        return call[0][0], call[1]

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_usergroups_returns_list(self, usergroup_manager, mock_connection):
        """Test get_usergroups returns a list of user groups."""
        mock_groups = [
            {"_id": "g1", "name": "Default", "qos_rate_max_down": -1},
            {"_id": "g2", "name": "Limited", "qos_rate_max_down": 10000},
        ]
        mock_connection.request.return_value = mock_groups

        groups = await usergroup_manager.get_usergroups()

        assert len(groups) == 2
        assert groups[0]["name"] == "Default"
        mock_connection._update_cache.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_usergroups_uses_cache(self, usergroup_manager, mock_connection):
        """Test get_usergroups returns cached data when available."""
        cached_groups = [{"_id": "cached", "name": "Cached Group"}]
        mock_connection.get_cached.return_value = cached_groups

        groups = await usergroup_manager.get_usergroups()

        assert groups == cached_groups
        mock_connection.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_usergroups_handles_dict_response(self, usergroup_manager, mock_connection):
        """Test get_usergroups unwraps a full envelope instead of treating it as a group."""
        mock_connection.request.return_value = {
            "data": [{"_id": "g1", "name": "Test"}],
            "meta": {"rc": "ok"},
        }

        groups = await usergroup_manager.get_usergroups()

        assert groups == [{"_id": "g1", "name": "Test"}]

    @pytest.mark.asyncio
    async def test_get_usergroups_handles_error(self, usergroup_manager, mock_connection):
        """Test get_usergroups returns empty list on error."""
        mock_connection.request.side_effect = Exception("Network error")

        groups = await usergroup_manager.get_usergroups()

        assert groups == []

    @pytest.mark.asyncio
    async def test_get_usergroups_uses_target_site(self, usergroup_manager, mock_connection):
        """The requested site is passed to request(), not applied to the connection."""
        mock_connection.request.return_value = []

        await usergroup_manager.get_usergroups(site="branch")

        _, kwargs = self._request_call(mock_connection)
        assert kwargs["site"] == "branch"
        mock_connection.set_site.assert_not_called()
        assert mock_connection.site == "default"

    @pytest.mark.asyncio
    async def test_get_usergroups_cache_key_is_per_site(self, usergroup_manager, mock_connection):
        """A value cached for one site must never be served for another."""
        mock_connection.request.return_value = []

        await usergroup_manager.get_usergroups(site="siteA")
        await usergroup_manager.get_usergroups(site="siteB")

        keys = [call[0][0] for call in mock_connection._update_cache.call_args_list]
        assert keys == ["usergroups_siteA", "usergroups_siteB"]

    @pytest.mark.asyncio
    async def test_get_usergroup_details_found(self, usergroup_manager, mock_connection):
        """Test get_usergroup_details returns group when found."""
        mock_groups = [
            {"_id": "g1", "name": "Default"},
            {"_id": "g2", "name": "Limited"},
        ]
        mock_connection.request.return_value = mock_groups

        group = await usergroup_manager.get_usergroup_details("g2")

        assert group is not None
        assert group["name"] == "Limited"

    @pytest.mark.asyncio
    async def test_get_usergroup_details_not_found(self, usergroup_manager, mock_connection):
        """Test get_usergroup_details returns None when not found."""
        mock_connection.request.return_value = [{"_id": "g1"}]

        group = await usergroup_manager.get_usergroup_details("nonexistent")

        assert group is None

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_create_usergroup_basic(self, usergroup_manager, mock_connection):
        """Test create_usergroup with only name."""
        mock_connection.request.return_value = [{"_id": "new1", "name": "New Group"}]

        result = await usergroup_manager.create_usergroup({"name": "New Group"})

        assert result == {"_id": "new1", "name": "New Group"}
        api_request, _ = self._request_call(mock_connection)
        assert api_request.data["name"] == "New Group"
        assert "qos_rate_max_down" not in api_request.data

    @pytest.mark.asyncio
    async def test_create_usergroup_with_limits(self, usergroup_manager, mock_connection):
        """Kbps aliases are stored under the controller's own field names."""
        mock_connection.request.return_value = [{"_id": "new1", "name": "Limited"}]

        await usergroup_manager.create_usergroup(
            {"name": "Limited", "down_limit_kbps": 10000, "up_limit_kbps": 5000}
        )

        api_request, _ = self._request_call(mock_connection)
        assert api_request.data["qos_rate_max_down"] == 10000
        assert api_request.data["qos_rate_max_up"] == 5000
        assert "down_limit_kbps" not in api_request.data

    @pytest.mark.asyncio
    async def test_create_usergroup_accepts_controller_field_names(self, usergroup_manager, mock_connection):
        """A payload already using controller field names passes through unchanged."""
        mock_connection.request.return_value = [{"_id": "new1", "name": "Limited"}]

        await usergroup_manager.create_usergroup({"name": "Limited", "qos_rate_max_down": 2000})

        api_request, _ = self._request_call(mock_connection)
        assert api_request.data["qos_rate_max_down"] == 2000

    @pytest.mark.asyncio
    async def test_create_usergroup_requires_name(self, usergroup_manager, mock_connection):
        """Test create_usergroup refuses a payload without a name."""
        result = await usergroup_manager.create_usergroup({"qos_rate_max_down": 1000})

        assert result is None
        mock_connection.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_usergroup_invalidates_cache(self, usergroup_manager, mock_connection):
        """Test create_usergroup invalidates the cache for the target site."""
        mock_connection.request.return_value = [{"_id": "new1"}]

        await usergroup_manager.create_usergroup({"name": "Test"}, site="branch")

        mock_connection._invalidate_cache.assert_called_once_with("usergroups_branch")

    @pytest.mark.asyncio
    async def test_create_usergroup_handles_error(self, usergroup_manager, mock_connection):
        """Test create_usergroup returns None on error."""
        mock_connection.request.side_effect = Exception("API error")

        result = await usergroup_manager.create_usergroup({"name": "Test"})

        assert result is None

    @pytest.mark.asyncio
    async def test_create_usergroup_reports_controller_refusal(self, usergroup_manager, mock_connection):
        """A refusal envelope is a failure, not a success."""
        mock_connection.request.return_value = {"meta": {"rc": "error", "msg": "api.err.InvalidPayload"}}

        result = await usergroup_manager.create_usergroup({"name": "Test"})

        assert result is None

    @pytest.mark.asyncio
    async def test_update_usergroup_success(self, usergroup_manager, mock_connection):
        """Test update_usergroup with valid parameters."""
        mock_connection.request.side_effect = [
            [{"_id": "g1", "name": "Old Name", "qos_rate_max_up": 999}],  # get_usergroups
            {"meta": {"rc": "ok"}, "data": []},  # update response
        ]

        result = await usergroup_manager.update_usergroup(
            "g1", {"name": "New Name", "down_limit_kbps": 5000}
        )

        assert result is True
        api_request, _ = self._request_call(mock_connection, 1)
        assert api_request.data["name"] == "New Name"
        assert api_request.data["qos_rate_max_down"] == 5000

    @pytest.mark.asyncio
    async def test_update_usergroup_preserves_unmentioned_fields(self, usergroup_manager, mock_connection):
        """PUT replaces the whole object, so untouched fields must be resent."""
        mock_connection.request.side_effect = [
            [{"_id": "g1", "name": "Old", "qos_rate_max_up": 999}],
            {"meta": {"rc": "ok"}, "data": []},
        ]

        await usergroup_manager.update_usergroup("g1", {"name": "New"})

        api_request, _ = self._request_call(mock_connection, 1)
        assert api_request.data["qos_rate_max_up"] == 999
        # Identity fields stay with the controller
        assert "_id" not in api_request.data

    @pytest.mark.asyncio
    async def test_update_usergroup_not_found(self, usergroup_manager, mock_connection):
        """Test update_usergroup returns False when group not found."""
        mock_connection.request.return_value = []  # No groups

        result = await usergroup_manager.update_usergroup("nonexistent", {"name": "Test"})

        assert result is False

    @pytest.mark.asyncio
    async def test_update_usergroup_no_updates(self, usergroup_manager, mock_connection):
        """Test update_usergroup returns False when no updates provided."""
        mock_connection.request.return_value = [{"_id": "g1", "name": "Test"}]

        result = await usergroup_manager.update_usergroup("g1", {})

        assert result is False

    @pytest.mark.asyncio
    async def test_update_usergroup_invalidates_cache(self, usergroup_manager, mock_connection):
        """Test update_usergroup invalidates the cache."""
        mock_connection.request.side_effect = [
            [{"_id": "g1", "name": "Test"}],
            {"meta": {"rc": "ok"}, "data": []},
        ]

        await usergroup_manager.update_usergroup("g1", {"name": "Updated"})

        mock_connection._invalidate_cache.assert_called_once_with("usergroups_default")

    @pytest.mark.asyncio
    async def test_update_usergroup_handles_error(self, usergroup_manager, mock_connection):
        """Test update_usergroup returns False on error."""
        mock_connection.request.side_effect = [
            [{"_id": "g1", "name": "Test"}],  # get_usergroups succeeds
            Exception("API error"),  # update fails
        ]

        result = await usergroup_manager.update_usergroup("g1", {"name": "New"})

        assert result is False

    @pytest.mark.asyncio
    async def test_update_usergroup_reports_controller_refusal(self, usergroup_manager, mock_connection):
        """A refusal envelope on the write is reported as failure."""
        mock_connection.request.side_effect = [
            [{"_id": "g1", "name": "Test"}],
            {"meta": {"rc": "error", "msg": "api.err.NoPermission"}},
        ]

        result = await usergroup_manager.update_usergroup("g1", {"name": "New"})

        assert result is False
        mock_connection._invalidate_cache.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_usergroup_success(self, usergroup_manager, mock_connection):
        """Test delete_usergroup hits the rest endpoint for the target site."""
        mock_connection.request.return_value = {"meta": {"rc": "ok"}, "data": []}

        result = await usergroup_manager.delete_usergroup("g1", site="branch")

        assert result is True
        api_request, kwargs = self._request_call(mock_connection)
        assert api_request.path == "/rest/usergroup/g1"
        assert api_request.method == "delete"
        assert kwargs["site"] == "branch"
        mock_connection._invalidate_cache.assert_called_once_with("usergroups_branch")

    @pytest.mark.asyncio
    async def test_delete_usergroup_reports_controller_refusal(self, usergroup_manager, mock_connection):
        """A refusal envelope on delete is reported as failure."""
        mock_connection.request.return_value = {"meta": {"rc": "error", "msg": "api.err.NoPermission"}}

        result = await usergroup_manager.delete_usergroup("g1")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_usergroup_handles_error(self, usergroup_manager, mock_connection):
        """Test delete_usergroup returns False on error."""
        mock_connection.request.side_effect = Exception("API error")

        result = await usergroup_manager.delete_usergroup("g1")

        assert result is False
