"""The MCP server as a client really meets it: a subprocess over stdio, JSON-RPC end to end."""
import json
import os
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def test_mcp_server_over_stdio(tmp_path):
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "fsv.mcp.server"],
        env={**os.environ, "FSV_DB": str(tmp_path / "mcp.db"), "FSV_NO_PLUGINS": "1"})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "fsv"

            tools = {t.name for t in (await session.list_tools()).tools}
            assert {"fsv_scan", "fsv_quick_check", "fsv_fixes", "fsv_triage", "fsv_verify_ownership"} <= tools

            prompts = {p.name for p in (await session.list_prompts()).prompts}
            assert "security_review" in prompts
            text = (await session.get_prompt("security_review", {"target": "https://example.com"})).messages[0]
            assert "authorized" in text.content.text and "https://example.com" in text.content.text

            mods = json.loads((await session.call_tool("fsv_list_modules", {})).content[0].text)
            assert {"debug_mode", "supply_chain", "takeover"} <= {m["name"] for m in mods["modules"]}

            # refuses without explicit authorization — and says why
            res = await session.call_tool("fsv_scan", {"target": "https://example.com", "authorized": False})
            assert "authoriz" in res.content[0].text.lower()
