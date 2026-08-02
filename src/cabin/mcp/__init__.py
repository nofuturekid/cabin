"""cabin's Model Context Protocol server (spec 0013).

A fourth front door onto the same domain services the UI, the REST API and
ACME use -- see :mod:`cabin.mcp.server` for the endpoint and its tools, and
:mod:`cabin.mcp.auth` for how a cabin API token gets a caller through it.
"""

from cabin.mcp.server import (
    MCP_PATH,
    McpServer,
    create_mcp_app,
    endpoint_url,
    is_enabled,
)

__all__ = [
    "MCP_PATH",
    "McpServer",
    "create_mcp_app",
    "endpoint_url",
    "is_enabled",
]
