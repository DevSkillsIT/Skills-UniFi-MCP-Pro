"""Pytest configuration for unifi-network-mcp tests."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock
import pytest

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def mock_runtime_dependencies():
    """Mock MCP runtime dependencies before importing tools."""
    import sys
    from unittest.mock import MagicMock, AsyncMock

    # Create mock for mcp module
    mock_mcp = MagicMock()
    mock_fastmcp = MagicMock()
    mock_mcp.server.fastmcp.FastMCP = MagicMock
    sys.modules['mcp'] = mock_mcp
    sys.modules['mcp.server'] = MagicMock()
    sys.modules['mcp.server.fastmcp'] = mock_fastmcp

    # Mock OmegaConf
    mock_omegaconf = MagicMock()
    sys.modules['omegaconf'] = mock_omegaconf

    yield

    # Cleanup
    if 'mcp' in sys.modules:
        del sys.modules['mcp']
    if 'omegaconf' in sys.modules:
        del sys.modules['omegaconf']
