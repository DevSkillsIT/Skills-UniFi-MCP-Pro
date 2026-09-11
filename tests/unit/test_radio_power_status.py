"""A configured transmit power the radio is not using must say which case it is.

Reporting only the live figure makes a setting that WAS applied look ignored --
which is exactly how a correct configuration got read as "the operator never
changed it". Reporting only the configured figure makes a power the radio
refuses look like a power it is using.

Measured on a U7 Pro: 2.4GHz configured 23 dBm and transmitting 16, 6GHz
configured 24 and transmitting 12, 5GHz configured 24 and transmitting 24 --
with the device provisioned six hours earlier. Nothing was pending; two of the
three radios were capping.
"""

import time


from src.managers.radio_projection import PROVISION_SETTLE_SECONDS, radio_view


def _config(**overrides):
    base = {
        "name": "wifi0",
        "radio": "ng",
        "channel": "auto",
        "ht": 20,
        "tx_power_mode": "custom",
        "tx_power": 23,
        "min_txpower": 6,
        "max_txpower": 23,
        "antenna_gain": 4,
    }
    base.update(overrides)
    return base


def _live(**overrides):
    base = {"name": "wifi0", "radio": "ng", "channel": 6, "bw": 20, "tx_power": 16, "state": "RUN"}
    base.update(overrides)
    return base


SETTLED = int(time.time()) - (PROVISION_SETTLE_SECONDS + 60)
JUST_NOW = int(time.time()) - 5


class TestTxPowerStatus:
    def test_both_figures_are_reported(self):
        """Neither number alone answers 'did my change take'."""
        view = radio_view(_config(), _live(), provisioned_at=SETTLED)
        assert view["tx_power_configured_dbm"] == 23
        assert view["tx_power_dbm"] == 16

    def test_a_settled_difference_is_named_as_a_cap(self):
        view = radio_view(_config(), _live(), provisioned_at=SETTLED)
        assert "capping" in view["tx_power_status"]
        assert "23" in view["tx_power_status"] and "16" in view["tx_power_status"]

    def test_a_fresh_difference_is_named_as_pending(self):
        view = radio_view(_config(), _live(), provisioned_at=JUST_NOW)
        assert "still be adopting" in view["tx_power_status"]

    def test_without_a_provisioning_time_neither_is_claimed(self):
        view = radio_view(_config(), _live(), provisioned_at=None)
        assert "cannot be told" in view["tx_power_status"]

    def test_agreement_says_nothing(self):
        view = radio_view(_config(tx_power=24), _live(tx_power=24), provisioned_at=SETTLED)
        assert view["tx_power_status"] is None

    def test_auto_mode_says_nothing(self):
        """Under auto the controller chooses; the stored value is a leftover."""
        view = radio_view(_config(tx_power_mode="auto", tx_power=20), _live(tx_power=26), provisioned_at=SETTLED)
        assert view["tx_power_status"] is None
        assert view["tx_power_mode"] == "auto"

    def test_max_txpower_is_reported_as_hardware_not_permission(self):
        """The cap the radio applies can sit below the maximum it advertises."""
        view = radio_view(_config(), _live(), provisioned_at=SETTLED)
        assert view["tx_power_max_dbm"] == 23
        assert view["tx_power_dbm"] < view["tx_power_max_dbm"]
        assert "not what the regulatory domain permits" in view["tx_power_status"]


class TestRadioViewJoinsBothTables:
    def test_width_comes_from_config_because_stats_always_reports_null(self):
        view = radio_view(_config(ht=40), _live(ht=None, bw=40), provisioned_at=SETTLED)
        assert view["channel_width_mhz"] == 40
        assert view["channel_width_configured_mhz"] == 40

    def test_channel_reports_intent_beside_outcome(self):
        view = radio_view(_config(channel="auto"), _live(channel=6), provisioned_at=SETTLED)
        assert view["channel"] == 6
        assert view["channel_configured"] == "auto"
        assert view["channel_is_auto"] is True

    def test_airtime_separates_this_radio_from_everyone_else(self):
        view = radio_view(
            _config(), _live(cu_total=36, cu_self_rx=6, cu_self_tx=13), provisioned_at=SETTLED
        )
        assert view["utilization_total_percent"] == 36
        assert view["utilization_self_percent"] == 19
        assert view["utilization_others_percent"] == 17

    def test_others_never_goes_negative(self):
        """Counters are sampled separately and can cross."""
        view = radio_view(_config(), _live(cu_total=5, cu_self_rx=4, cu_self_tx=4), provisioned_at=SETTLED)
        assert view["utilization_others_percent"] == 0
