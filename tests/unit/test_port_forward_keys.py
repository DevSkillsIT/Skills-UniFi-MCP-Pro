"""A port forward must reach the controller under the keys it actually reads.

Measured against a live UniFi controller: a create payload spelling the protocol
`protocol` or the destination `fwd_ip` is answered with HTTP 200 and `rc: "ok"`,
and the value is dropped. The rule is stored with no protocol and no
destination -- it forwards nothing, and the caller is told it worked.

    POST /rest/portforward {"protocol": "tcp", "fwd_ip": "192.168.1.50", ...}
      -> 200 rc=ok, stored: proto=None, fwd=None

    POST /rest/portforward {"proto": "tcp", "fwd": "192.168.1.50", ...}
      -> 200 rc=ok, stored: proto='tcp', fwd='192.168.1.50'

Nothing in the response distinguishes the two, so only a test that inspects the
outgoing payload can hold the line.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def recorded(monkeypatch):
    """Capture what a create would send, without sending it."""
    sent = []

    async def fake_create(rule_data, site=None):
        sent.append({"rule_data": rule_data, "site": site})
        return {"_id": "pf-1", **rule_data}

    from src.runtime import firewall_manager

    monkeypatch.setattr(firewall_manager, "create_port_forward", fake_create)
    return sent


@pytest.fixture
def anywhere(monkeypatch):
    """Resolve any site, so the test is about the payload and nothing else."""
    async def fake_resolve(site, system_manager):
        return ("site-id", "Site", "site-slug")

    import src.tools.port_forwards as module

    monkeypatch.setattr(module, "resolve_site_context", fake_resolve)
    monkeypatch.setattr(module, "parse_permission", lambda *a, **k: True)
    return module


class TestPortForwardPayloadKeys:
    @pytest.mark.asyncio
    async def test_compact_shape_sends_proto_and_fwd(self, anywhere, recorded):
        result = await anywhere.create_port_forward(
            port_forward_data={
                "name": "Probe",
                "ext_port": 18091,
                "int_port": 80,
                "to_ip": "192.168.1.50",
                "protocol": "tcp",
            },
            confirm=True,
        )

        assert result["success"] is True
        payload = recorded[0]["rule_data"]
        assert payload["proto"] == "tcp"
        assert payload["fwd"] == "192.168.1.50"
        assert "protocol" not in payload, "the controller discards 'protocol' silently"
        assert "fwd_ip" not in payload, "the controller discards 'fwd_ip' silently"

    @pytest.mark.asyncio
    async def test_complete_shape_sends_proto_and_fwd(self, anywhere, recorded):
        result = await anywhere.create_port_forward(
            port_forward_data={
                "name": "Probe",
                "dst_port": "18092",
                "fwd_port": "80",
                "fwd": "192.168.1.50",
                "protocol": "udp",
                "enabled": True,
            },
            confirm=True,
        )

        assert result["success"] is True
        payload = recorded[0]["rule_data"]
        assert payload["proto"] == "udp"
        assert payload["fwd"] == "192.168.1.50"
        assert "fwd_ip" not in payload

    @pytest.mark.asyncio
    async def test_fwd_ip_is_accepted_as_an_alias_and_translated(self, anywhere, recorded):
        """Callers spell it `fwd_ip`; the controller only reads `fwd`."""
        result = await anywhere.create_port_forward(
            port_forward_data={
                "name": "Probe",
                "dst_port": "18093",
                "fwd_port": "8080",
                "fwd_ip": "192.168.1.51",
                "protocol": "tcp",
            },
            confirm=True,
        )

        assert result["success"] is True
        payload = recorded[0]["rule_data"]
        assert payload["fwd"] == "192.168.1.51"

    @pytest.mark.asyncio
    async def test_a_rule_without_a_destination_is_refused(self, anywhere, recorded):
        """Better to refuse than to create a rule that forwards nowhere."""
        result = await anywhere.create_port_forward(
            port_forward_data={"name": "Probe", "dst_port": "18094", "fwd_port": "80", "protocol": "tcp"},
            confirm=True,
        )

        assert result["success"] is False
        assert "destination" in result["error"]
        assert recorded == []

    @pytest.mark.asyncio
    async def test_numeric_ports_are_accepted(self, anywhere, recorded):
        """A port written as a number is written the ordinary way."""
        result = await anywhere.create_port_forward(
            port_forward_data={
                "name": "Probe",
                "dst_port": 18095,
                "fwd_port": 80,
                "fwd": "192.168.1.50",
                "protocol": "tcp",
            },
            confirm=True,
        )

        assert result["success"] is True
        assert recorded[0]["rule_data"]["dst_port"] == "18095"


class TestPortForwardReadsBackTheRightKey:
    @pytest.mark.asyncio
    async def test_list_reads_proto_and_fwd(self, anywhere, monkeypatch):
        """Reading under the wrong key reported no protocol for every rule."""
        from src.runtime import firewall_manager

        raw = {
            "_id": "pf-1",
            "name": "Probe",
            "enabled": True,
            "dst_port": "18091",
            "fwd_port": "80",
            "fwd": "192.168.1.50",
            "proto": "tcp",
        }
        monkeypatch.setattr(firewall_manager, "get_port_forwards", AsyncMock(return_value=[MagicMock(raw=raw)]))

        result = await anywhere.list_port_forwards()

        rule = result["port_forwards"][0]
        assert rule["protocol"] == "tcp"
        assert rule["dest_ip"] == "192.168.1.50"
