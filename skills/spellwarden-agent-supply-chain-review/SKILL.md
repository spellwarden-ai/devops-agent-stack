---
name: spellwarden-agent-supply-chain-review
description: Review the safety of this agent's own skills, instruction files and MCP servers with Spellwarden. Use when asked whether the agent's skills or tools are safe, and on the weekly supply chain review.
license: Apache-2.0
metadata:
  version: 1.0.0
---

# Agent supply chain review

Use Spellwarden's read-only tools. Make no AWS calls.

1. Call `list_agent_space_connections` and note this Agent Space's connection, its status and its last sync.
2. Call `list_skills` and `list_mcp_servers` for the connected organisation. Note anything quarantined or switched off, and any server that allows all tools.
3. Call `list_findings` with status `open` and severity `critical`, then `high`. Note findings that are new since the last report.
4. Report new or changed findings, quarantined or switched-off skills, servers that allow all tools, and items that were not scanned. Name each item and give its severity or trust score.

Keep the report short. If a tool answers with an error, say which tool and stop. Do not guess.
