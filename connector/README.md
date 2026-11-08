# Spellwarden

Spellwarden checks the skills and MCP servers your agents load and reports findings, trust scores and alerts. This connector gives the agent Spellwarden's read-only tools.

## Sign in (default)

Choose Sign in. Spellwarden asks you which organisation the Agent Space may see and whether the connection is read only or read and write. Choose read only and the organisation the Agent Space should see. The connection then acts as you in that one organisation only, and the agent is told so when it connects and in the answer of `list_organisations`. You can revoke the connection at any time under Connected apps in the Spellwarden dashboard. A connection lasts 365 days.

## Or use an API key

In the Spellwarden dashboard, open Settings, API keys, and create a key with read access. Paste it as the Spellwarden API key (read access).

## Tools to allow

Allow the read-only tools: `list_organisations`, `get_organisation`, `list_skills`, `get_skill`, `list_findings`, `get_trust_score`, `list_policy_packs`, `list_registry_entries`, `get_runtime_inventory`, `get_eval_run`, `get_migration_report`, `list_mcp_servers` and `list_agent_space_connections`. Do not allow tools that start scans, add servers or start evaluations.

## Guard

To let Spellwarden read the skills, instructions and servers this Agent Space loads, deploy the stack at https://github.com/spellwarden-ai/devops-agent-stack.
