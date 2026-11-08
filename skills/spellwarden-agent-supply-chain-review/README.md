# spellwarden-agent-supply-chain-review

A skill for AWS DevOps Agent that reviews the safety of the agent's own skills, instruction files and MCP servers with Spellwarden's read-only tools. It needs Spellwarden's tools in the Agent Space (the `ConnectSpellwardenTools` option of the stack, or the Spellwarden connector from the console) and makes no AWS calls.

Use it by asking whether the agent's skills or tools are safe, or on a weekly schedule with the `WeeklyReview` option.
