"""
Smoke-test stub only — not the real MCP server.

Reads newline-delimited JSON-RPC requests from stdin, replies with a
trivial "ok" result for anything it gets. Use this to confirm the
extension's spawn -> stdin/stdout -> parse loop actually works before
the real Python MCP server (mcp SDK, tools, security layer) exists.
"""
import json
import sys


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"ok": True, "echoed_method": req.get("method")},
        }
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()