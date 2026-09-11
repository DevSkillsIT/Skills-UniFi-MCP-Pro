"""Meta-tools registration helper.

Provides a unified way to register meta-tools (tool_index, execute, batch, job_status)
that work in both MCP server mode and dev console mode.
"""

import json
import logging
from typing import TYPE_CHECKING, Any, Callable, List, Optional

if TYPE_CHECKING:
    from src.utils.lazy_tool_loader import LazyToolLoader

logger = logging.getLogger("unifi-network-mcp")

# Import site resolver for display name → slug resolution
from src.utils.site_resolver import resolve_site_identifier
from src.exceptions import InvalidSiteParameterError, SiteForbiddenError, SiteNotFoundError


async def resolve_site_for_call(site: Optional[str]) -> Optional[str]:
    """Resolve a site argument to the slug the tools expect.

    Delegates to the same resolver the tools use, so `unifi_execute` and a
    direct tool call fail identically. The previous implementation kept its own
    whitelist logic and its own message ("not allowed"), while the direct path
    said "not found in UniFi Controller" for the very same input -- which sent
    the reader to investigate the controller instead of the whitelist.
    """
    if site is None:
        return None
    resolved = await resolve_site_identifier(site)
    return resolved["slug"]


def tool_accepts_site(server, tool_name: str) -> bool:
    """Whether `tool_name` declares a `site` parameter.

    FastMCP validates arguments with a model that ignores unknown keys, so a
    `site` handed to a tool that does not declare one is dropped without a
    word and the call silently runs against the default site. Checking the
    declared schema lets the caller be told instead.
    """
    try:
        tool = server._tool_manager.get_tool(tool_name)
    except Exception:
        return False
    if tool is None:
        return False
    properties = (tool.parameters or {}).get("properties") or {}
    return "site" in properties


def unwrap_tool_result(result: Any) -> Any:
    """Turn what `server.call_tool` returns back into a plain value.

    `call_tool` answers in one of two shapes depending on whether the tool
    declares a return type:

      - `list[ContentBlock]`                    -- no structured output
      - `(list[ContentBlock], structured_dict)` -- structured output, where a
        non-model return value sits under the key "result"

    Returning either shape straight out of a tool made FastMCP serialise an
    already-serialised payload, so every `unifi_execute` and every
    `unifi_batch_status` response carried the same data twice -- once as a JSON
    string inside a text block and once as the structured object -- doubling
    the token cost of every call that went through them.

    The structured half is preferred when present because it is already a
    Python object; the text blocks are only decoded as a fallback.
    """
    if isinstance(result, tuple) and len(result) == 2:
        _blocks, structured = result
        if isinstance(structured, dict):
            if set(structured.keys()) == {"result"}:
                return structured["result"]
            return structured
        return _decode_blocks(_blocks)

    if isinstance(result, list):
        return _decode_blocks(result)

    return result


def _decode_blocks(blocks: Any) -> Any:
    """Decode a list of content blocks into plain Python values."""
    if not isinstance(blocks, (list, tuple)):
        return blocks
    decoded = []
    for block in blocks:
        text = getattr(block, "text", None)
        if text is None:
            decoded.append(block)
            continue
        try:
            decoded.append(json.loads(text))
        except (TypeError, ValueError):
            decoded.append(text)
    if len(decoded) == 1:
        return decoded[0]
    return decoded


def register_meta_tools(
    server,
    tool_decorator: Callable,
    tool_index_handler: Callable,
    start_async_tool: Callable,
    get_job_status: Callable,
    register_tool: Callable,
) -> None:
    """Register meta-tools with the MCP server.

    Tools registered:
    - unifi_tool_index: Discover available tools
    - unifi_execute: Execute a single tool (returns result directly)
    - unifi_batch: Execute multiple tools in parallel (returns job IDs)
    - unifi_batch_status: Check batch job progress

    Args:
        server: FastMCP server instance (for call_tool access)
        tool_decorator: The decorator function to register tools (@server.tool)
        tool_index_handler: Handler function for tool_index
        start_async_tool: Function to start async jobs
        get_job_status: Function to get job status
        register_tool: Function to register in tool index
    """

    # =========================================================================
    # DISCOVERY: unifi_tool_index
    # =========================================================================
    @tool_decorator(
        name="unifi_tool_index",
        description="""List every UniFi tool currently registered on this server, with its full schema.

CALL THIS FIRST to discover the right tool for your task. The response carries
the exact count under "count" -- how many tools are registered depends on the
server's enabled_categories and permissions configuration, so read it rather
than assuming a number.

Tools are grouped by category: clients, devices, networks, stats, system,
firewall, port forwards, QoS, VPN, routing, traffic routes, hotspot vouchers,
user groups and events.

After finding the right tool, use unifi_execute to run it.""",
    )
    async def _tool_index_wrapper() -> dict:
        return await tool_index_handler(None)

    register_tool(
        name="unifi_tool_index",
        description="CALL FIRST - List the UniFi tools registered on this server with their schemas; the response reports the exact count.",
        input_schema={"type": "object", "properties": {}},
        output_schema={
            "type": "object",
            "properties": {
                "tools": {"type": "array", "description": "Available tools with schemas"},
                "count": {"type": "integer"},
            },
        },
    )

    # =========================================================================
    # SINGLE EXECUTION: unifi_execute
    # =========================================================================
    @tool_decorator(
        name="unifi_execute",
        description="""Execute a UniFi tool discovered via unifi_tool_index.

WORKFLOW: Call unifi_tool_index first to find the right tool, then execute it here.

PARAMETERS:
- tool: Tool name from unifi_tool_index
- arguments: Tool parameters (see tool schema from unifi_tool_index)
- site: Optional site name/slug for multi-site support (accepts fuzzy matching)

MULTI-SITE SUPPORT:
If 'site' parameter is provided, it will be automatically injected into the tool's arguments.
The site resolver will:
1. Validate the site parameter (alphanumeric + hyphen/underscore only)
2. Resolve friendly names to site slugs (e.g., "acme" → "grupo-acme")
3. Validate access against UNIFI_SITE whitelist (if configured)
4. Execute the tool in the context of the specified site
5. Restore the original site context after execution

For bulk/parallel operations, use unifi_batch instead.""",
    )
    async def execute_handler(tool: str, arguments: dict = None, site: str = None) -> dict:
        """Execute a UniFi tool synchronously with optional site context.

        Args:
            tool: Tool name from unifi_tool_index
            arguments: Tool parameters (defaults to {})
            site: Optional site name/slug for multi-site support

        Returns:
            Tool execution result or error dict
        """
        if arguments is None:
            arguments = {}

        if site is not None:
            if not tool_accepts_site(server, tool):
                # Injecting it anyway would be dropped by argument validation and
                # the call would quietly run against the default site.
                return {
                    "success": False,
                    "error": (
                        f"Tool '{tool}' does not accept a 'site' parameter, so the site you passed "
                        f"cannot be honoured. Check the tool's schema via unifi_tool_index."
                    ),
                    "requested_site": site,
                }
            try:
                slug = await resolve_site_for_call(site)
                arguments = {**arguments, "site": slug}
                logger.info(f"unifi_execute: site '{site}' resolved to slug '{slug}'")
            except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
                return e.to_dict()

        try:
            result = await server.call_tool(tool, arguments)
            return unwrap_tool_result(result)
        except Exception as e:
            logger.error(f"Error executing tool '{tool}': {e}", exc_info=True)
            return {"success": False, "error": f"Failed to execute tool '{tool}': {e}"}

    register_tool(
        name="unifi_execute",
        description="Execute a tool discovered via unifi_tool_index. Supports optional site parameter for multi-site operations.",
        input_schema={
            "type": "object",
            "required": ["tool"],
            "properties": {
                "tool": {"type": "string", "description": "Tool name from unifi_tool_index"},
                "arguments": {"type": "object", "description": "Tool parameters from schema"},
                "site": {
                    "type": "string",
                    "description": "Optional site name/slug for multi-site support. Accepts fuzzy matching (e.g., 'acme', 'Grupo Acme')."
                },
            },
        },
        output_schema={"type": "object", "description": "Tool result"},
    )

    # =========================================================================
    # BATCH EXECUTION: unifi_batch
    # =========================================================================
    @tool_decorator(
        name="unifi_batch",
        description="""Execute multiple UniFi tools in parallel with optional multi-site support.

WORKFLOW: Call unifi_tool_index first to discover tools, then batch execute them here.

Returns job IDs for each operation. Use unifi_batch_status to check progress and get results.

PARAMETERS:
- operations: Array of {tool, arguments, site?} objects where tool names come from unifi_tool_index
- site: Optional global site parameter that applies to all operations (overridden by per-operation site)

MULTI-SITE SUPPORT:
- Global site: Applies to all operations unless overridden
- Per-operation site: Each operation can specify its own site parameter
- Priority: Per-operation site > Global site > Default site

USE FOR: Bulk operations, parallel execution, long-running tasks, multi-site batch queries.
FOR SINGLE OPERATIONS: Use unifi_execute instead (returns result directly).""",
    )
    async def batch_handler(operations: List[dict], site: str = None) -> dict:
        """Execute multiple operations in parallel with optional site context.

        Args:
            operations: Array of {tool, arguments, site?} objects
            site: Optional global site parameter (applies to all operations unless overridden)

        Returns:
            Dictionary with jobs array and optional errors
        """
        if not operations:
            return {"error": "No operations specified", "jobs": []}

        jobs = []
        errors = []

        for i, op in enumerate(operations):
            tool = op.get("tool")
            arguments = op.get("arguments", {})
            op_site = op.get("site")  # Per-operation site parameter

            if not tool:
                errors.append({"index": i, "error": "Missing 'tool' field"})
                continue

            # Determine effective site parameter (priority: per-operation > global)
            effective_site = op_site if op_site is not None else site

            if effective_site is not None:
                if not tool_accepts_site(server, tool):
                    errors.append(
                        {
                            "index": i,
                            "tool": tool,
                            "error": f"Tool '{tool}' does not accept a 'site' parameter; the requested site cannot be honoured.",
                            "requested_site": effective_site,
                        }
                    )
                    continue
                try:
                    slug = await resolve_site_for_call(effective_site)
                    arguments = {**arguments, "site": slug}
                    logger.info(f"Batch operation {i} ({tool}): site '{effective_site}' resolved to slug '{slug}'")
                except (SiteNotFoundError, SiteForbiddenError, InvalidSiteParameterError) as e:
                    errors.append({"index": i, "tool": tool, **e.to_dict()})
                    continue

            try:
                # Create a closure that captures the current tool and arguments
                async def _make_executor(t, a):
                    async def _execute():
                        return unwrap_tool_result(await server.call_tool(t, a))

                    return _execute

                executor = await _make_executor(tool, arguments)
                job_result = await start_async_tool(executor, {})

                jobs.append(
                    {
                        "index": i,
                        "tool": tool,
                        "jobId": job_result.get("jobId"),
                    }
                )
            except Exception as e:
                logger.error(f"Error starting batch operation {i} ({tool}): {e}", exc_info=True)
                errors.append({"index": i, "tool": tool, "error": str(e)})

        return {
            "jobs": jobs,
            "errors": errors if errors else None,
            "message": f"Started {len(jobs)} operation(s). Use unifi_batch_status to check progress.",
        }

    register_tool(
        name="unifi_batch",
        description="Execute multiple tools in parallel with multi-site support. Returns job IDs for status checking.",
        input_schema={
            "type": "object",
            "required": ["operations"],
            "properties": {
                "operations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["tool"],
                        "properties": {
                            "tool": {"type": "string", "description": "Tool name from unifi_tool_index"},
                            "arguments": {"type": "object", "description": "Tool parameters"},
                            "site": {
                                "type": "string",
                                "description": "Optional per-operation site (overrides global site)",
                            },
                        },
                    },
                    "description": "Array of {tool, arguments, site?} objects",
                },
                "site": {
                    "type": "string",
                    "description": "Optional global site parameter (applies to all operations unless overridden)",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "jobs": {"type": "array", "description": "Started jobs with IDs"},
                "errors": {"type": "array", "description": "Any errors"},
            },
        },
    )

    # =========================================================================
    # BATCH STATUS: unifi_batch_status
    # =========================================================================
    @tool_decorator(
        name="unifi_batch_status",
        description="""Check status of operations started with unifi_batch.

Returns: status ("running", "done", "error"), result (if done), error (if failed).

Can check multiple jobs at once by passing an array of job IDs.""",
    )
    async def batch_status_handler(jobId: str = None, jobIds: List[str] = None) -> dict:
        """Check status of one or more jobs."""
        # Handle single job ID
        if jobId and not jobIds:
            try:
                status = await get_job_status(jobId)
                return status
            except Exception as e:
                logger.error(f"Error getting job status for '{jobId}': {e}", exc_info=True)
                return {"status": "error", "error": str(e)}

        # Handle multiple job IDs
        if jobIds:
            results = []
            for jid in jobIds:
                try:
                    status = await get_job_status(jid)
                    results.append({"jobId": jid, **status})
                except Exception as e:
                    results.append({"jobId": jid, "status": "error", "error": str(e)})
            return {"jobs": results}

        return {"error": "Provide jobId or jobIds parameter"}

    register_tool(
        name="unifi_batch_status",
        description="Check status of batch operations. Returns status, result (if done), or error.",
        input_schema={
            "type": "object",
            "properties": {
                "jobId": {"type": "string", "description": "Single job ID to check"},
                "jobIds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple job IDs to check",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["running", "done", "error", "unknown"]},
                "result": {"description": "Result (if done)"},
                "error": {"type": "string", "description": "Error message (if failed)"},
                "jobs": {"type": "array", "description": "Status of multiple jobs"},
            },
        },
    )

    logger.info("Registered meta-tools: unifi_tool_index, unifi_execute, unifi_batch, unifi_batch_status")


def register_load_tools(
    server,
    tool_decorator: Callable,
    lazy_loader: "LazyToolLoader",
    register_tool: Callable,
) -> None:
    """Register unifi_load_tools for dynamic tool loading (capable clients only).

    This enables direct tool access for MCP clients that support tool_list_changed notifications.
    Most users should use unifi_execute instead - it works with all clients.
    """
    from mcp.server.fastmcp import Context

    from src.utils.lazy_tool_loader import TOOL_MODULE_MAP

    @tool_decorator(
        name="unifi_load_tools",
        description="""Load tools for direct MCP access (advanced).

Most users should use unifi_execute instead - it works with all clients.

This tool is for MCP clients that support tool_list_changed notifications.
After loading, the client is notified to refresh its tool list.

EXAMPLE: {"tools": ["unifi_list_clients", "unifi_list_devices"]}""",
    )
    async def load_tools_handler(tools: List[str], ctx: Context) -> dict:
        """Load specific tools and notify the client."""
        if not tools:
            return {"error": "No tools specified", "loaded": [], "errors": []}

        loaded = []
        errors = []

        for tool_name in tools:
            if tool_name not in TOOL_MODULE_MAP:
                errors.append({"tool": tool_name, "error": "Unknown tool"})
                continue

            try:
                success = await lazy_loader.load_tool(tool_name)
                if success:
                    loaded.append(tool_name)
                else:
                    errors.append({"tool": tool_name, "error": "Failed to load"})
            except Exception as e:
                logger.error(f"Error loading tool '{tool_name}': {e}", exc_info=True)
                errors.append({"tool": tool_name, "error": str(e)})

        if loaded:
            try:
                await ctx.session.send_tool_list_changed()
                logger.info(f"Sent tool_list_changed notification after loading: {loaded}")
            except Exception as e:
                logger.warning(f"Failed to send tool_list_changed notification: {e}")

        return {
            "loaded": loaded,
            "errors": errors if errors else None,
            "message": f"Loaded {len(loaded)} tool(s). Client should refresh tool list.",
        }

    register_tool(
        name="unifi_load_tools",
        description="Load tools for direct MCP access (advanced). Most users should use unifi_execute.",
        input_schema={
            "type": "object",
            "required": ["tools"],
            "properties": {
                "tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tool names to load",
                },
            },
        },
        output_schema={
            "type": "object",
            "properties": {
                "loaded": {"type": "array", "description": "Successfully loaded tools"},
                "errors": {"type": "array", "description": "Any errors"},
                "message": {"type": "string"},
            },
        },
    )

    logger.info("Registered unifi_load_tools meta-tool for dynamic tool loading")
