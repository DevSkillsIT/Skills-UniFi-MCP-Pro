"""Tests for the client IP settings functionality.

This module tests the set_client_ip_settings method in ClientManager.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


def _last_write(conn):
    """The ApiRequest of the last non-GET call made on the mocked connection."""
    for call in reversed(conn.request.call_args_list):
        api_request = call[0][0]
        if api_request.method.lower() != "get":
            return api_request
    raise AssertionError("no write request was issued")


class TestClientIPSettings:
    """Tests for client IP settings operations."""

    @pytest.fixture
    def mock_connection(self):
        """Create a mock ConnectionManager.

        Client lookups go through `/rest/user` and `/stat/sta` on
        `connection.request`, scoped by the `site` argument, rather than through
        aiounifi's `controller.clients_all` collection. That collection reads
        whichever site the shared controller object points at, which is why it
        could not be used once every call had to name its own site.
        """
        conn = MagicMock()
        conn.site = "default"
        conn.request = AsyncMock(return_value=[])
        conn.resolve_slug = MagicMock(side_effect=lambda s: s or "default")
        conn.get_cached = MagicMock(return_value=None)
        conn._update_cache = MagicMock()
        conn._invalidate_cache = MagicMock()
        conn.ensure_connected = AsyncMock(return_value=True)
        return conn

    @staticmethod
    def _serve_client(conn, client_raw, write_result=None):
        """Make the mocked connection answer lookups with `client_raw`.

        A lookup is a GET; a write is a PUT that must answer with an envelope so
        the manager can tell an accepted change from a refused one.
        """
        write_envelope = write_result if write_result is not None else {"meta": {"rc": "ok"}, "data": []}

        async def _request(api_request, return_raw=False, site=None):
            if api_request.method.lower() == "get":
                return [client_raw]
            return write_envelope if return_raw else write_envelope.get("data")

        conn.request = AsyncMock(side_effect=_request)
        return conn

    @pytest.fixture
    def client_manager(self, mock_connection):
        """Create a ClientManager with mocked connection."""
        from src.managers.client_manager import ClientManager

        return ClientManager(mock_connection)

    @pytest.fixture
    def mock_client(self):
        """Create a mock client object."""
        client = MagicMock()
        client.mac = "aa:bb:cc:dd:ee:ff"
        client.raw = {
            "_id": "client123",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "noted": True,
        }
        return client

    @pytest.mark.asyncio
    async def test_set_fixed_ip(self, client_manager, mock_connection, mock_client):
        """Test setting a fixed IP address."""
        # Mock get_client_details to return the client
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            use_fixedip=True,
            fixed_ip="192.168.1.100",
        )

        assert result is True
        # Verify the API call
        api_request = _last_write(mock_connection)
        assert api_request.data["use_fixedip"] is True
        assert api_request.data["fixed_ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_set_fixed_ip_only_ip(self, client_manager, mock_connection, mock_client):
        """Test setting fixed IP by only providing the IP address."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            fixed_ip="192.168.1.100",
        )

        assert result is True
        api_request = _last_write(mock_connection)
        # Should auto-enable use_fixedip
        assert api_request.data["use_fixedip"] is True
        assert api_request.data["fixed_ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_disable_fixed_ip(self, client_manager, mock_connection, mock_client):
        """Test disabling fixed IP."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            use_fixedip=False,
        )

        assert result is True
        api_request = _last_write(mock_connection)
        assert api_request.data["use_fixedip"] is False
        assert api_request.data["fixed_ip"] == ""

    @pytest.mark.asyncio
    async def test_set_local_dns_record(self, client_manager, mock_connection, mock_client):
        """Test setting a local DNS record."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            local_dns_record_enabled=True,
            local_dns_record="mydevice.local",
        )

        assert result is True
        api_request = _last_write(mock_connection)
        assert api_request.data["local_dns_record_enabled"] is True
        assert api_request.data["local_dns_record"] == "mydevice.local"

    @pytest.mark.asyncio
    async def test_set_local_dns_only_hostname(self, client_manager, mock_connection, mock_client):
        """Test setting DNS by only providing the hostname."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            local_dns_record="mydevice.local",
        )

        assert result is True
        api_request = _last_write(mock_connection)
        # Should auto-enable local_dns_record_enabled
        assert api_request.data["local_dns_record_enabled"] is True
        assert api_request.data["local_dns_record"] == "mydevice.local"

    @pytest.mark.asyncio
    async def test_disable_local_dns(self, client_manager, mock_connection, mock_client):
        """Test disabling local DNS record."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            local_dns_record_enabled=False,
        )

        assert result is True
        api_request = _last_write(mock_connection)
        assert api_request.data["local_dns_record_enabled"] is False
        assert api_request.data["local_dns_record"] == ""

    @pytest.mark.asyncio
    async def test_set_both_ip_and_dns(self, client_manager, mock_connection, mock_client):
        """Test setting both fixed IP and DNS record."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            use_fixedip=True,
            fixed_ip="192.168.1.100",
            local_dns_record_enabled=True,
            local_dns_record="mydevice.local",
        )

        assert result is True
        api_request = _last_write(mock_connection)
        assert api_request.data["use_fixedip"] is True
        assert api_request.data["fixed_ip"] == "192.168.1.100"
        assert api_request.data["local_dns_record_enabled"] is True
        assert api_request.data["local_dns_record"] == "mydevice.local"

    @pytest.mark.asyncio
    async def test_client_not_found(self, client_manager, mock_connection):
        """Test returns False when client not found."""
        mock_connection.controller.clients_all.values.return_value = []

        result = await client_manager.set_client_ip_settings(
            client_mac="xx:xx:xx:xx:xx:xx",
            fixed_ip="192.168.1.100",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_no_settings_provided(self, client_manager, mock_connection, mock_client):
        """Test returns False when no settings provided."""
        self._serve_client(mock_connection, mock_client.raw)

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_marks_unnoted_client_as_noted(self, client_manager, mock_connection):
        """Test marks unnoted client as noted before setting IP."""
        unnoted_client = MagicMock()
        unnoted_client.mac = "aa:bb:cc:dd:ee:ff"
        unnoted_client.raw = {
            "_id": "client123",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "noted": False,  # Client is not noted
        }
        self._serve_client(mock_connection, unnoted_client.raw)

        await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            fixed_ip="192.168.1.100",
        )

        # A client the controller does not "note" cannot hold IP configuration,
        # so it is marked known before the settings are written.
        writes = [
            call[0][0]
            for call in mock_connection.request.call_args_list
            if call[0][0].method.lower() != "get"
        ]
        assert len(writes) == 2
        assert writes[0].data["noted"] is True
        assert writes[1].data["fixed_ip"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_invalidates_cache(self, client_manager, mock_connection, mock_client):
        """Test invalidates cache after update."""
        self._serve_client(mock_connection, mock_client.raw)

        await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            fixed_ip="192.168.1.100",
        )

        mock_connection._invalidate_cache.assert_called()

    @pytest.mark.asyncio
    async def test_handles_api_error(self, client_manager, mock_connection, mock_client):
        """Test returns False on API error."""
        self._serve_client(mock_connection, mock_client.raw)
        mock_connection.request.side_effect = Exception("API error")

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            fixed_ip="192.168.1.100",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_client_missing_id(self, client_manager, mock_connection):
        """Test returns False when client has no _id."""
        client_without_id = MagicMock()
        client_without_id.mac = "aa:bb:cc:dd:ee:ff"
        client_without_id.raw = {
            "mac": "aa:bb:cc:dd:ee:ff",
            # No _id field
        }
        mock_connection.controller.clients_all.values.return_value = [client_without_id]

        result = await client_manager.set_client_ip_settings(
            client_mac="aa:bb:cc:dd:ee:ff",
            fixed_ip="192.168.1.100",
        )

        assert result is False
