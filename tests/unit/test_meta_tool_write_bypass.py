"""The meta-tools must not be a way around the host's permission rules.

Every MCP client gates tools by name. When a call goes through `unifi_execute`
or `unifi_batch`, the only name the client sees is the meta-tool's own -- the
tool actually being run is an argument. So a tool the operator declined is
reachable by naming it inside one of these, and an allow-list that reads as
read-only grants everything.

That is not hypothetical here. A settings file in this repository's own backups
carries `unifi_list_clients`, `unifi_get_ap_stats` and `unifi_execute` side by
side: it was plainly meant to grant read-only access, and it granted the whole
server.
"""

import pytest

from src.utils.meta_tools import MUTATING_VERBS, is_mutating_tool, meta_tools_may_write, refuse_mutation


class TestMutationClassifier:
    @pytest.mark.parametrize(
        "tool",
        [
            "unifi_manage_device",
            "unifi_block_client",
            "unifi_unblock_client",
            "unifi_rename_client",
            "unifi_create_network",
            "unifi_update_wlan",
            "unifi_delete_static_route",
            "unifi_set_client_ip_settings",
            "unifi_toggle_firewall_policy",
            "unifi_authorize_guest",
            "unifi_unauthorize_guest",
            "unifi_revoke_voucher",
            "unifi_restart_controller",
            "unifi_archive_alarm",
            "unifi_force_reconnect_client",
            "unifi_update_snmp_settings",
        ],
    )
    def test_writes_are_recognised(self, tool):
        assert is_mutating_tool(tool), f"{tool} would slip through as a read"

    @pytest.mark.parametrize(
        "tool",
        [
            "unifi_list_clients",
            "unifi_list_devices",
            "unifi_get_ap_stats",
            "unifi_get_device_details",
            "unifi_get_client_stats",
            "unifi_list_sites",
            "unifi_get_system_info",
            "unifi_tool_index",
            "unifi_get_network_stats",
            "unifi_list_wlans",
        ],
    )
    def test_reads_are_left_alone(self, tool):
        assert not is_mutating_tool(tool), f"{tool} would be refused though it only reads"

    def test_every_registered_write_tool_is_classified(self):
        """Read the real tool surface rather than trusting the list above.

        A tool added later must be classified by the verbs, not by someone
        remembering to extend a test.
        """
        import ast
        from pathlib import Path

        tools_dir = Path(__file__).resolve().parents[2] / "src" / "tools"
        unclassified = []
        for path in sorted(tools_dir.glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for decorator in node.decorator_list:
                    if not isinstance(decorator, ast.Call):
                        continue
                    keywords = {k.arg: k.value for k in decorator.keywords}
                    name = keywords.get("name")
                    # A tool declaring a permission category is a tool that writes.
                    if "permission_category" not in keywords or not isinstance(name, ast.Constant):
                        continue
                    if not is_mutating_tool(name.value):
                        unclassified.append(f"{path.name}:{name.value}")
        assert not unclassified, (
            "These tools declare a permission category, so they change the controller, "
            f"but the meta-tools would run them as reads: {unclassified}"
        )


class TestRefusal:
    def test_writes_are_refused_by_default(self, monkeypatch):
        monkeypatch.delenv("UNIFI_META_ALLOW_WRITES", raising=False)
        assert meta_tools_may_write() is False

    def test_the_escape_hatch_is_explicit(self, monkeypatch):
        monkeypatch.setenv("UNIFI_META_ALLOW_WRITES", "true")
        assert meta_tools_may_write() is True

    def test_anything_but_an_affirmative_keeps_it_closed(self, monkeypatch):
        for value in ("", "false", "0", "no", "maybe", "TRUE-ish"):
            monkeypatch.setenv("UNIFI_META_ALLOW_WRITES", value)
            assert meta_tools_may_write() is (value.strip().lower() in ("true", "1", "yes"))

    def test_the_refusal_says_what_to_do_instead(self):
        """A refusal that only says no leaves the caller guessing."""
        refusal = refuse_mutation("unifi_manage_device", "unifi_execute")
        assert refusal["success"] is False
        assert "unifi_manage_device" in refusal["hint"]
        assert "directly" in refusal["error"]
        assert "UNIFI_META_ALLOW_WRITES" in refusal["error"]

    def test_the_verb_list_is_not_empty(self):
        """Guard the guard: an empty list would classify every tool as a read."""
        assert len(MUTATING_VERBS) >= 10
