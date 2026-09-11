"""Every tool must be able to name the site it acts on.

This is the invariant the whole multi-site surface rests on. A tool that does
not declare `site` cannot be pointed anywhere: it silently acts on the default
site, and the caller is not told. That is how a read reported one site's data
under another site's name, and how a write would have landed on the wrong
network.

Declared parameters are read from the source rather than from the imported
tool, because the suite stubs the MCP package and `@server.tool` therefore
returns a mock rather than the function.
"""

import ast
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "tools"

# Tools that legitimately take no site, each for a stated reason. Anything not
# on this list and missing `site` is a defect, not an omission.
SITE_EXEMPT = {
    # Lists the sites themselves; asking it to pick one is circular.
    "unifi_list_sites",
    # Returns a fixed catalogue of event-type prefixes. The list is the same on
    # every site and is never read from the controller, so there is nothing for
    # a site to select.
    "unifi_get_event_types",
}

TOOL_DECORATORS = {"tool", "permissioned_tool", "_original_tool"}


def _registered_tools():
    """(module, tool name, function node) for every `@server.tool` in src/tools."""
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                attr = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if attr not in TOOL_DECORATORS:
                    continue
                name = next(
                    (
                        kw.value.value
                        for kw in decorator.keywords
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant)
                    ),
                    None,
                )
                if name:
                    yield path.stem, name, node


def _parameters(node):
    args = node.args
    positional = args.posonlyargs + args.args
    with_defaults = positional[len(positional) - len(args.defaults):]
    defaults = dict(zip([a.arg for a in with_defaults], args.defaults))
    return {a.arg: defaults.get(a.arg) for a in positional}


ALL_TOOLS = list(_registered_tools())


def test_the_scan_finds_the_tools():
    """Guard the guard: an empty scan would make every test below vacuous."""
    assert len(ALL_TOOLS) >= 70


@pytest.mark.parametrize("module,name,node", ALL_TOOLS, ids=[t[1] for t in ALL_TOOLS])
def test_tool_declares_a_site(module, name, node):
    if name in SITE_EXEMPT:
        pytest.skip(f"{name} is exempt by design")
    parameters = _parameters(node)
    assert "site" in parameters, f"{name} (src/tools/{module}.py) cannot name a site"


@pytest.mark.parametrize("module,name,node", ALL_TOOLS, ids=[t[1] for t in ALL_TOOLS])
def test_site_is_optional(module, name, node):
    """`site` defaults to None so an existing caller that omits it still works."""
    if name in SITE_EXEMPT:
        pytest.skip(f"{name} is exempt by design")
    default = _parameters(node)["site"]
    assert isinstance(default, ast.Constant) and default.value is None, (
        f"{name} must default site to None, not {ast.dump(default) if default else 'nothing'}"
    )


def test_exemptions_still_exist():
    """An exemption for a tool that no longer exists hides a real gap later."""
    registered = {name for _, name, _ in ALL_TOOLS}
    stale = SITE_EXEMPT - registered
    assert not stale, f"Exempted tools that are no longer registered: {sorted(stale)}"
