#!/usr/bin/env python3
"""Generate static tool manifest at build time.

This script imports all tool modules in eager mode to extract their metadata
and writes a static JSON manifest. This allows lazy loading to provide full
tool schemas without runtime imports.

Usage:
    python scripts/generate_tool_manifest.py

Output:
    src/tools_manifest.json - Static tool metadata with FULL schemas for all tools
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Add src to path so we can import modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Force eager mode for manifest generation
os.environ["UNIFI_TOOL_REGISTRATION_MODE"] = "eager"

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def generate_manifest() -> dict[str, Any]:
    """Generate tool manifest by forcing eager tool registration.

    This ensures all tools are properly registered through their decorators,
    providing full schemas with parameter information for LLMs.

    Returns:
        Dictionary with tool metadata for all tools
    """
    logger.info("🔨 Generating tool manifest with full schemas...")

    # Import the tool registry first
    from src.tool_index import TOOL_REGISTRY

    # CRITICAL: Import main.py to trigger the server.tool monkey-patch
    # This ensures @server.tool decorators call register_tool()
    logger.info("   Setting up permissioned tool decorator...")
    import src.main  # noqa: F401 -- imported for the side effect of patching server.tool

    # Force eager loading of all tools to populate TOOL_REGISTRY
    # We need to import the tool loader to trigger all tool registrations
    logger.info("   Loading all tools in eager mode to extract schemas...")

    try:
        # Import the auto loader which will trigger all tool registrations
        from src.utils.tool_loader import auto_load_tools

        # Load all tools - this will trigger all @server.tool decorators
        # which in turn call register_tool() to populate TOOL_REGISTRY
        auto_load_tools()

        # The meta-tools are registered by register_meta_tools(), not by a
        # decorator under src/tools, so loading the tool modules alone leaves
        # them out. A manifest without them under-reports the surface, and in
        # lazy mode unifi_tool_index reads the manifest -- so the tools a client
        # needs in order to reach every other tool would be the ones missing.
        from src.jobs import get_job_status, start_async_tool
        from src.runtime import server
        from src.tool_index import register_tool, tool_index_handler
        from src.utils.meta_tools import register_load_tools, register_meta_tools

        original_decorator = getattr(server, "_original_tool", server.tool)
        register_meta_tools(
            server=server,
            tool_decorator=original_decorator,
            tool_index_handler=tool_index_handler,
            start_async_tool=start_async_tool,
            get_job_status=get_job_status,
            register_tool=register_tool,
        )
        try:
            from src.utils.lazy_tool_loader import setup_lazy_loading

            register_load_tools(
                server=server,
                tool_decorator=original_decorator,
                lazy_loader=setup_lazy_loading(server, original_decorator),
                register_tool=register_tool,
            )
        except Exception as exc:
            logger.warning("   unifi_load_tools not added to the manifest: %s", exc)

        logger.info(f"   ✅ Loaded {len(TOOL_REGISTRY)} tools into registry")

    except Exception as e:
        logger.error(f"   ❌ Failed to load tools: {e}")
        import traceback
        traceback.print_exc()

        # Fallback to minimal manifest if tool loading fails
        logger.warning("   Falling back to minimal manifest from TOOL_MODULE_MAP")
        from src.utils.lazy_tool_loader import TOOL_MODULE_MAP

        tools = []
        for tool_name in sorted(TOOL_MODULE_MAP.keys()):
            tools.append({
                "name": tool_name,
                "description": f"UniFi tool: {tool_name}",
                "schema": {
                    "input": {"type": "object", "properties": {}},
                },
            })

        return {
            "tools": tools,
            "count": len(tools),
            "generated_by": "scripts/generate_tool_manifest.py",
            "note": "Fallback manifest with minimal schemas due to loading error.",
            "error": str(e),
        }

    # Build manifest from registry with full schemas
    tools = []
    for tool_name in sorted(TOOL_REGISTRY.keys()):
        meta = TOOL_REGISTRY[tool_name]

        tool_data = {
            "name": meta.name,
            "description": meta.description,
            "schema": {
                "input": meta.input_schema,
            },
        }

        # Include output schema if available
        if meta.output_schema:
            tool_data["schema"]["output"] = meta.output_schema

        tools.append(tool_data)

    # `module_map` is what `lazy_tool_loader._load_module_map_from_manifest()`
    # reads when the tools directory is not on disk, as in a packaged install.
    # The generator never wrote the key, so that fallback silently produced an
    # empty map and no tool could be loaded on demand.
    from src.utils.lazy_tool_loader import _build_tool_module_map

    module_map = _build_tool_module_map()
    # Meta-tools live in src/utils/meta_tools.py rather than in a tool module.
    for meta_name in ("unifi_tool_index", "unifi_execute", "unifi_batch", "unifi_batch_status", "unifi_load_tools"):
        if any(t["name"] == meta_name for t in tools):
            module_map.setdefault(meta_name, "src.utils.meta_tools")
    missing = sorted(t["name"] for t in tools if t["name"] not in module_map)
    if missing:
        logger.warning("   Tools absent from the module map: %s", missing)

    manifest = {
        "tools": tools,
        "count": len(tools),
        "module_map": module_map,
        "generated_by": "scripts/generate_tool_manifest.py",
        "note": "Auto-generated with full schemas from tool decorators. Do not edit manually.",
    }

    logger.info(f"   ✅ Generated manifest with {len(tools)} tools and full schemas")

    # Log a sample tool to verify schemas are complete
    if tools:
        sample_tool = tools[0]
        logger.info(f"   📋 Sample tool: {sample_tool['name']}")
        logger.info(f"      Properties: {list(sample_tool['schema']['input'].get('properties', {}).keys())}")

    return manifest


def main():
    """Generate and write tool manifest."""
    try:
        # Generate manifest
        manifest = generate_manifest()

        # Write to src/tools_manifest.json
        output_path = project_root / "src" / "tools_manifest.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        logger.info(f"   📝 Wrote manifest to {output_path}")
        logger.info("   🎉 Tool manifest generation complete!")

        return 0

    except Exception as e:
        logger.error(f"   ❌ Failed to generate manifest: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
