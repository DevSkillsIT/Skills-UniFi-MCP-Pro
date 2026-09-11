"""Radio settings are refused here when the radio or the country cannot honour them.

A rejected channel is not free: the controller re-provisions the access point on
write, dropping every wireless client on the band, so a setting that was never
going to hold should be refused before the AP is told to move. The permitted
channel set comes from the controller's own /stat/current-channel rather than a
table baked in here, which would go stale per country and per firmware.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


AP_RADIO_TABLE = [
    {
        "name": "ra0",
        "radio": "ng",
        "channel": "auto",
        "ht": 20,
        "tx_power_mode": "auto",
        "min_txpower": 6,
        "max_txpower": 26,
    },
    {
        "name": "rai0",
        "radio": "na",
        "channel": "auto",
        "ht": 80,
        "tx_power_mode": "auto",
        "min_txpower": 6,
        "max_txpower": 26,
    },
]

# Brazil, as the controller reports it: channel 165 exists at 20MHz but not at 80.
COUNTRY = {
    "name": "Brazil",
    "channels_ng": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    "channels_na": [36, 40, 44, 48, 149, 153, 157, 161, 165],
    "channels_na_80": [36, 40, 44, 48, 149, 153, 157, 161],
    "channels_na_40": [36, 40, 44, 48, 149, 153, 157, 161],
}


def _device(device_type="uap", radio_table=None):
    device = MagicMock()
    device.raw = {
        "_id": "dev123",
        "mac": "aa:bb:cc:dd:ee:ff",
        "name": "AP-Test",
        "type": device_type,
        "radio_table": [dict(r) for r in (radio_table if radio_table is not None else AP_RADIO_TABLE)],
    }
    return device


@pytest.fixture
def manager():
    from src.managers.device_manager import DeviceManager

    connection = MagicMock()
    connection.site = "default"
    connection.resolve_slug = MagicMock(side_effect=lambda s: s or "default")
    connection.get_cached = MagicMock(return_value=None)
    connection._update_cache = MagicMock()
    connection._invalidate_cache = MagicMock()
    connection.ensure_connected = AsyncMock(return_value=True)
    connection.request = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})

    device_manager = DeviceManager(connection)
    device_manager.get_device_details = AsyncMock(return_value=_device())
    device_manager.get_country_channels = AsyncMock(return_value=COUNTRY)
    return device_manager


class TestRadioValidation:
    @pytest.mark.asyncio
    async def test_rejects_a_device_without_radios(self, manager):
        manager.get_device_details = AsyncMock(return_value=_device(device_type="usw"))
        with pytest.raises(ValueError, match="no radios"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", channel=36)

    @pytest.mark.asyncio
    async def test_rejects_a_band_the_access_point_does_not_have(self, manager):
        with pytest.raises(ValueError, match="no 6GHz radio"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="6GHz", channel=37)

    @pytest.mark.asyncio
    async def test_rejects_an_unknown_band(self, manager):
        with pytest.raises(ValueError, match="Unknown band"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="900MHz", channel=1)

    @pytest.mark.asyncio
    async def test_rejects_a_channel_the_country_forbids(self, manager):
        with pytest.raises(ValueError, match="not permitted"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", channel=64)

    @pytest.mark.asyncio
    async def test_rejects_a_channel_the_width_forbids(self, manager):
        """165 is permitted at 20MHz and absent from the 80MHz list."""
        await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", channel=165, channel_width=20)
        with pytest.raises(ValueError, match="not permitted"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", channel=165, channel_width=80)

    @pytest.mark.asyncio
    async def test_rejects_an_invalid_width(self, manager):
        with pytest.raises(ValueError, match="channel_width"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", channel_width=37)

    @pytest.mark.asyncio
    async def test_rejects_power_outside_the_radio_range(self, manager):
        with pytest.raises(ValueError, match="6-26 dBm"):
            await manager.set_radio_config(
                "aa:bb:cc:dd:ee:ff", band="5GHz", tx_power_mode="custom", tx_power_dbm=40
            )

    @pytest.mark.asyncio
    async def test_rejects_power_without_custom_mode(self, manager):
        with pytest.raises(ValueError, match="custom"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", tx_power_dbm=14)

    @pytest.mark.asyncio
    async def test_rejects_an_unknown_power_mode(self, manager):
        with pytest.raises(ValueError, match="tx_power_mode"):
            await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", tx_power_mode="maximum")


class TestRadioWrite:
    @pytest.mark.asyncio
    async def test_sends_the_whole_radio_table_with_only_the_named_radio_changed(self, manager):
        result = await manager.set_radio_config(
            "aa:bb:cc:dd:ee:ff", band="5GHz", channel=36, channel_width=40
        )

        assert result["applied"] is True
        assert result["changed"]["channel"] == {"from": "auto", "to": 36}
        assert result["changed"]["channel_width_mhz"] == {"from": 80, "to": 40}

        api_request = manager._connection.request.call_args[0][0]
        assert api_request.method.lower() == "put"
        assert api_request.path == "/rest/device/dev123"

        # The controller replaces the whole table, so the untouched radio has to
        # travel with the changed one or its settings are cleared.
        sent = {r["radio"]: r for r in api_request.data["radio_table"]}
        assert set(sent) == {"ng", "na"}
        assert sent["na"]["channel"] == 36
        assert sent["na"]["ht"] == 40
        assert sent["ng"]["channel"] == "auto"
        assert sent["ng"]["ht"] == 20

    @pytest.mark.asyncio
    async def test_sends_nothing_when_every_value_already_matches(self, manager):
        result = await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", channel="auto")

        assert result["applied"] is False
        assert result["changed"] == {}
        manager._connection.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_custom_power_is_written_and_auto_clears_it(self, manager):
        await manager.set_radio_config(
            "aa:bb:cc:dd:ee:ff", band="5GHz", tx_power_mode="custom", tx_power_dbm=14
        )
        sent = {r["radio"]: r for r in manager._connection.request.call_args[0][0].data["radio_table"]}
        assert sent["na"]["tx_power_mode"] == "custom"
        assert sent["na"]["tx_power"] == 14

        manager.get_device_details = AsyncMock(
            return_value=_device(
                radio_table=[
                    {**AP_RADIO_TABLE[0]},
                    {**AP_RADIO_TABLE[1], "tx_power_mode": "custom", "tx_power": 14},
                ]
            )
        )
        await manager.set_radio_config("aa:bb:cc:dd:ee:ff", band="5GHz", tx_power_mode="auto")
        sent = {r["radio"]: r for r in manager._connection.request.call_args[0][0].data["radio_table"]}
        assert sent["na"]["tx_power_mode"] == "auto"
        assert "tx_power" not in sent["na"]
