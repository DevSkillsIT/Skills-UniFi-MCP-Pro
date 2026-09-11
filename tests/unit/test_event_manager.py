"""Tests for the EventManager class.

This module tests event and alarm operations.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


class TestEventManager:
    """Tests for the EventManager class."""

    @pytest.fixture
    def mock_connection(self):
        """Create a mock ConnectionManager."""
        conn = MagicMock()
        conn.site = "default"
        conn.request = AsyncMock()
        conn.get_cached = MagicMock(return_value=None)
        conn._update_cache = MagicMock()
        conn._invalidate_cache = MagicMock()
        return conn

    @pytest.fixture
    def event_manager(self, mock_connection):
        """Create an EventManager with mocked connection."""
        from src.managers.event_manager import EventManager

        return EventManager(mock_connection)

    @pytest.mark.asyncio
    async def test_get_events_returns_list(self, event_manager, mock_connection):
        """Test get_events returns a list of events."""
        mock_events = [
            {"_id": "evt1", "msg": "Client connected", "time": 1700000000},
            {"_id": "evt2", "msg": "Client disconnected", "time": 1700000100},
        ]
        mock_connection.request.return_value = mock_events

        events = await event_manager.get_events(within=24, limit=100)

        assert len(events) == 2
        assert events[0]["_id"] == "evt1"
        mock_connection.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_events_with_type_filter(self, event_manager, mock_connection):
        """Test get_events with event type filter."""
        mock_connection.request.return_value = []

        await event_manager.get_events(event_type="EVT_SW_")

        # Verify the payload includes the type filter
        call_args = mock_connection.request.call_args
        api_request = call_args[0][0]
        assert api_request.data["type"] == "EVT_SW_"

    @pytest.mark.asyncio
    async def test_get_events_respects_limit(self, event_manager, mock_connection):
        """Test get_events respects the 3000 API limit."""
        mock_connection.request.return_value = []

        await event_manager.get_events(limit=5000)

        call_args = mock_connection.request.call_args
        api_request = call_args[0][0]
        assert api_request.data["_limit"] == 3000  # Should be capped

    @pytest.mark.asyncio
    async def test_get_events_handles_dict_response(self, event_manager, mock_connection):
        """Test get_events wraps a single object answer in a list.

        ConnectionManager.request already unwraps the {"meta", "data"} envelope,
        so a dict reaching the manager is one event, not an envelope.
        """
        mock_connection.request.return_value = {"_id": "evt1"}

        events = await event_manager.get_events()

        assert len(events) == 1
        assert events[0]["_id"] == "evt1"

    @pytest.mark.asyncio
    async def test_get_events_handles_error(self, event_manager, mock_connection):
        """Test get_events returns empty list on error."""
        mock_connection.request.side_effect = Exception("Network error")

        events = await event_manager.get_events()

        assert events == []

    @pytest.mark.asyncio
    async def test_get_events_reports_missing_endpoint(self, event_manager, mock_connection):
        """Test a 404 on /stat/event is reported, never read as 'no events'."""
        from aiounifi.errors import ResponseError

        from src.managers.event_manager import EndpointNotServedError

        mock_connection.request.side_effect = ResponseError(
            "Call https://host/api/s/default/stat/event received 404 Not Found"
        )

        with pytest.raises(EndpointNotServedError) as excinfo:
            await event_manager.get_events()

        assert excinfo.value.error_code == "ENDPOINT_NOT_SERVED"
        assert excinfo.value.details["path"] == "/stat/event"
        assert excinfo.value.details["controller_status"] == 404

    @pytest.mark.asyncio
    async def test_get_alarms_reports_missing_endpoint(self, event_manager, mock_connection):
        """Test a 404 on /stat/alarm is reported, never read as 'no alarms'."""
        from aiounifi.errors import ResponseError

        from src.managers.event_manager import EndpointNotServedError

        mock_connection.request.side_effect = ResponseError(
            "Call https://host/api/s/default/stat/alarm received 404 Not Found"
        )

        with pytest.raises(EndpointNotServedError):
            await event_manager.get_alarms()

    @pytest.mark.asyncio
    async def test_rate_limit_is_not_a_missing_endpoint(self, event_manager, mock_connection):
        """Test a 429 shares the exception type but is not an absent endpoint."""
        from aiounifi.errors import ResponseError

        mock_connection.request.side_effect = ResponseError("Call https://host received 429: b''")

        events = await event_manager.get_events()

        assert events == []

    @pytest.mark.asyncio
    async def test_get_alarms_returns_list(self, event_manager, mock_connection):
        """Test get_alarms returns a list of alarms."""
        mock_alarms = [
            {"_id": "alm1", "msg": "High CPU usage", "severity": "warning"},
            {"_id": "alm2", "msg": "Device offline", "severity": "critical"},
        ]
        mock_connection.request.return_value = mock_alarms

        alarms = await event_manager.get_alarms()

        assert len(alarms) == 2
        assert alarms[0]["severity"] == "warning"

    @pytest.mark.asyncio
    async def test_get_alarms_archived_parameter(self, event_manager, mock_connection):
        """Test get_alarms uses correct path for archived alarms."""
        mock_connection.request.return_value = []

        await event_manager.get_alarms(archived=True)

        call_args = mock_connection.request.call_args
        api_request = call_args[0][0]
        assert "archived=true" in api_request.path

    @pytest.mark.asyncio
    async def test_get_alarms_limit(self, event_manager, mock_connection):
        """Test get_alarms respects limit parameter."""
        mock_alarms = [{"_id": f"alm{i}"} for i in range(200)]
        mock_connection.request.return_value = mock_alarms

        alarms = await event_manager.get_alarms(limit=50)

        assert len(alarms) == 50

    def test_get_event_type_prefixes(self, event_manager):
        """Test get_event_type_prefixes returns known prefixes."""
        prefixes = event_manager.get_event_type_prefixes()

        assert len(prefixes) > 0
        assert any(p["prefix"] == "EVT_SW_" for p in prefixes)
        assert any(p["prefix"] == "EVT_AP_" for p in prefixes)
        assert all("description" in p for p in prefixes)

    @pytest.mark.asyncio
    async def test_archive_alarm_success(self, event_manager, mock_connection):
        """Test archive_alarm returns True on success."""
        mock_connection.request.return_value = {}

        result = await event_manager.archive_alarm("alarm123")

        assert result is True
        call_args = mock_connection.request.call_args
        api_request = call_args[0][0]
        assert api_request.data["cmd"] == "archive-alarm"
        assert api_request.data["_id"] == "alarm123"

    @pytest.mark.asyncio
    async def test_archive_alarm_failure(self, event_manager, mock_connection):
        """Test archive_alarm returns False on error."""
        mock_connection.request.side_effect = Exception("API error")

        result = await event_manager.archive_alarm("alarm123")

        assert result is False

    @pytest.mark.asyncio
    async def test_archive_alarm_refused_by_controller(self, event_manager, mock_connection):
        """Test a controller refusal is a failure, not a silent success."""
        mock_connection.request.return_value = {
            "meta": {"rc": "error", "msg": "api.err.NoPermission"},
            "data": [],
        }

        result = await event_manager.archive_alarm("alarm123")

        assert result is False
        assert mock_connection.request.call_args.kwargs["return_raw"] is True

    @pytest.mark.asyncio
    async def test_archive_all_alarms_success(self, event_manager, mock_connection):
        """Test archive_all_alarms returns True on success."""
        mock_connection.request.return_value = {}

        result = await event_manager.archive_all_alarms()

        assert result is True
        call_args = mock_connection.request.call_args
        api_request = call_args[0][0]
        assert api_request.data["cmd"] == "archive-all-alarms"

    @pytest.mark.asyncio
    async def test_archive_all_alarms_failure(self, event_manager, mock_connection):
        """Test archive_all_alarms returns False on error."""
        mock_connection.request.side_effect = Exception("API error")

        result = await event_manager.archive_all_alarms()

        assert result is False
