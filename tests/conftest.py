"""Pytest configuration for unifi-network-mcp tests."""

import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def mock_runtime_dependencies():
    """Stub only the MCP server layer, never the configuration layer.

    `omegaconf` used to be replaced with a MagicMock and then deleted from
    `sys.modules` on teardown. Any module imported while the mock was installed
    kept a reference to it, so a later real `OmegaConf` call raised
    `ConfigTypeError: isinstance() arg 2 must be a type`. The failure surfaced
    only when two test modules ran together, which made it look like a defect in
    whichever module happened to import a tool first.

    The real configuration loader works under test -- it reads
    `src/config/config.yaml` -- so there is nothing to gain by faking it.
    """
    import sys

    mock_mcp = MagicMock()
    mock_fastmcp = MagicMock()
    mock_mcp.server.fastmcp.FastMCP = MagicMock
    saved = {name: sys.modules.get(name) for name in ("mcp", "mcp.server", "mcp.server.fastmcp")}

    sys.modules["mcp"] = mock_mcp
    sys.modules["mcp.server"] = MagicMock()
    sys.modules["mcp.server.fastmcp"] = mock_fastmcp

    yield

    for name, module in saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module
