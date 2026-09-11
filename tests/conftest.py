"""Pytest configuration for unifi-network-mcp tests."""

import sys
from pathlib import Path
import pytest

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def mock_runtime_dependencies():
    """No longer stubs anything, and is kept so existing tests still request it.

    Both stubs this fixture used to install did more harm than the isolation
    they bought.

    `omegaconf` was replaced with a MagicMock and then deleted from
    `sys.modules` on teardown, so anything imported while the mock was in place
    kept a reference to it and a later real `OmegaConf` call raised
    `ConfigTypeError`. The failure only showed when two test modules ran
    together, which made it look like a defect in whichever module imported a
    tool first.

    `mcp` was replaced too, which made `server.tool` a MagicMock -- and since
    that decorator returns the function it wraps, every tool in `src/tools`
    became a MagicMock rather than a coroutine. A test could then neither call a
    tool nor read its signature, which is why so many of them were written as
    `assert True`.

    Both the real configuration loader and the real FastMCP server work under
    test: the loader reads `src/config/config.yaml`, and constructing a server
    opens no socket.
    """
    yield
