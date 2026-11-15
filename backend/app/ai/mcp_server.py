"""
Stdio MCP server exposing ai/tools.py to the Claude CLI during `investigate`.

Started by the CLI itself, once per investigation session, from the config
that ClaudeCLIProvider.investigate() writes:

    python -m app.ai.mcp_server

Scope comes from the environment that config sets — VULNSCAN_WORKSPACE_ID,
VULNSCAN_JOB_ID, VULNSCAN_TRAIL — never from the model.

Hand-rolled rather than built on the `mcp` SDK: the stdio transport is
newline-delimited JSON-RPC 2.0 and this server needs four methods, while the
SDK pins starlette/pydantic/uvicorn versions that would have to agree with
FastAPI's and forces a rebuild of all four backend images. It is synchronous
on purpose — there is no event loop here for a blocking DB call to freeze.

stdout is the protocol channel. Anything else that reaches it — a stray
print() in an imported module, a log handler — corrupts the stream and the CLI
drops the server, so stdout is rebound to stderr before anything is imported.
"""
import json
import logging
import os
import sys

_PROTOCOL_OUT = sys.stdout
sys.stdout = sys.stderr
logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

from app.ai.tools import TOOLS, ToolScope, call_tool  # noqa: E402

_SERVER_INFO = {"name": "vulnscan", "version": "1"}
_MAX_RESULT_CHARS = 30_000


def _send(msg: dict) -> None:
    _PROTOCOL_OUT.write(json.dumps(msg) + "\n")
    _PROTOCOL_OUT.flush()


def _reply(mid, result: dict) -> None:
    _send({"jsonrpc": "2.0", "id": mid, "result": result})


def _error(mid, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})


def main() -> None:
    scope = ToolScope(
        workspace_id=int(os.environ["VULNSCAN_WORKSPACE_ID"]),
        job_id=int(os.environ["VULNSCAN_JOB_ID"]),
    )
    trail = os.environ.get("VULNSCAN_TRAIL") or None

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _error(None, -32700, "parse error")
            continue
        mid, method = msg.get("id"), msg.get("method")
        params = msg.get("params") or {}

        if method == "initialize":
            # Answer with the client's own protocol version: this server uses
            # nothing that differs between the versions the CLI speaks.
            _reply(mid, {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": _SERVER_INFO,
            })
        elif method == "tools/list":
            _reply(mid, {"tools": [
                {"name": name, "description": desc, "inputSchema": schema}
                for name, (_fn, desc, schema) in TOOLS.items()
            ]})
        elif method == "tools/call":
            result = call_tool(scope, params.get("name", ""), params.get("arguments") or {}, trail)
            text = json.dumps(result, default=str)
            if len(text) > _MAX_RESULT_CHARS:
                text = text[:_MAX_RESULT_CHARS] + ' …[truncated]'
            _reply(mid, {"content": [{"type": "text", "text": text}],
                         "isError": "error" in result})
        elif method == "ping":
            _reply(mid, {})
        elif mid is None:
            pass  # a notification, e.g. notifications/initialized: no reply
        else:
            _error(mid, -32601, f"method not found: {method}")


if __name__ == "__main__":
    main()
