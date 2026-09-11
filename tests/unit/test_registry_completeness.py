"""Every key the tools pass to a registry must be registered there.

Two registries drifted apart in this codebase and neither drift was loud: a tool
asked `UniFiValidatorRegistry.validate()` for a resource type nobody had
registered, and `validate()` answers an unregistered key with a *failure*, not
with "nothing to check". The tool then refused its own input and never reached
the manager -- `unifi_create_qos_rule`, `unifi_update_qos_rule`,
`unifi_create_user_group`, `unifi_update_user_group` and `unifi_create_network`
were all dead this way, with an error message that blamed the input.

These tests read the call sites out of the syntax tree so a new tool cannot
introduce the same silence.
"""

import ast
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "tools"


def _validator_keys_used() -> set[tuple[str, str]]:
    """(module, key) for every literal key passed to a `validate()` call."""
    used: set[tuple[str, str]] = set()
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "validate"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                used.add((path.name, node.args[0].value))
    return used


class TestValidatorRegistryCompleteness:
    """The validator registry must cover every key the tools ask for."""

    @pytest.fixture
    def registered(self) -> set[str]:
        from src.validator_registry import UniFiValidatorRegistry

        return set(UniFiValidatorRegistry._validators)

    def test_every_key_used_by_a_tool_is_registered(self, registered: set[str]):
        missing = sorted((module, key) for module, key in _validator_keys_used() if key not in registered)
        assert not missing, (
            "Tools validate against resource types that are not registered, so they "
            f"always fail before reaching the manager: {missing}"
        )

    def test_the_scan_finds_call_sites(self):
        """Guard the guard: an empty scan would make the test above vacuous."""
        assert len(_validator_keys_used()) >= 10

    def test_unregistered_key_fails_rather_than_passing_through(self):
        """State the behaviour the tests above depend on."""
        from src.validator_registry import UniFiValidatorRegistry

        is_valid, error, data = UniFiValidatorRegistry.validate("no_such_resource_type", {"a": 1})
        assert is_valid is False
        assert data is None
        assert "no_such_resource_type" in (error or "")
