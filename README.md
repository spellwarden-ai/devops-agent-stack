# Spellwarden for AWS DevOps Agent

An open source CloudFormation stack that connects one AWS DevOps Agent Agent Space to [Spellwarden](https://spellwarden.ai). It is the only artifact customers run: `template/spellwarden-devops-agent.yaml`. All logic runs in Spellwarden's backend, which assumes a role this stack creates. The stack holds only IAM, one Secrets Manager secret, one small registration function and DevOps Agent resources.

What it does:

- **Guard.** Spellwarden reads the skills, `AGENTS.md` files, custom agents, the `directives` memory store and the MCP server associations of the Agent Space every hour, scans them with the same engine and rules as everything else, and shows them in the Spellwarden dashboard.
- **Deliver.** With `AllowInstall`, you can install vetted catalog skills into the Agent Space and accept upgrades with one click.
- **Tool.** The stack registers Spellwarden's MCP server in the Agent Space with 13 read-only tools. With `WeeklyReview` it also adds a weekly supply chain review.

## Connect an Agent Space

In the dashboard, open Settings, AWS DevOps Agent, Connect an Agent Space, and choose the Region and the options. Then:

1. Download the template. The dashboard serves the exact file this repository tags, `template/spellwarden-devops-agent.yaml`.
2. Open CloudFormation in the Agent Space's account and Region, choose Create stack, With new resources, Upload a template file, and pick the file.
3. Enter the stack name and the parameters the dashboard shows (the external ID and the setup code among them), acknowledge that the stack creates IAM resources with custom names, and create it.

The setup code is single use and valid for one hour: do not share it. Or deploy with the `aws cloudformation create-stack --template-body` command the dashboard shows, run where the downloaded file is.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `AgentSpaceId` | required | The Agent Space in this Region that Spellwarden may read |
| `ExternalId` | from the link | Set by Spellwarden for this connection |
| `SetupCode` | from the link | Single use, valid for one hour |
| `AllowSwitchOff` | `false` | Spellwarden may set a failing skill to `INACTIVE` |
| `AllowInstall` | `false` | Spellwarden may install, update and remove the catalog skills it installed |
| `ReadMemories` | `false` | Spellwarden also reads the memory stores other than `directives` |
| `ConnectSpellwardenTools` | `true` | Register Spellwarden's MCP server and allow its read-only tools |
| `WeeklyReview` | `false` | Add the review skill, a custom agent and a weekly trigger. Each run is agent time on your bill: about USD 2.50 for five minutes |

One stack per Agent Space, in the Agent Space's Region. Several stacks can live side by side in one account.

## Permissions

The role `SpellwardenDevOpsAgent-<AgentSpaceId>` trusts only Spellwarden's role `arn:aws:iam::359360911388:role/spellwarden-devops-agent`, and only with the external ID.

| Policy | When | Actions | On |
|---|---|---|---|
| `Read` | always | `aidevops:GetAgentSpace`, `ListAssets`, `GetAsset`, `GetAssetContent`, `ListAssetFiles`, `GetAssetFile`, `ListAssociations` | this Agent Space |
| `Read` | always | `aidevops:ListServices`, `GetService`, `ListAssetTypes` | `*` (the service names no resource type) |
| `SwitchOff` | `AllowSwitchOff` | `aidevops:UpdateAsset` | this Agent Space |
| `Install` | `AllowInstall` | `aidevops:CreateAsset`, `UpdateAsset`, `DeleteAsset` | this Agent Space |

IAM cannot limit `UpdateAsset` to the status field, or `DeleteAsset` to the assets Spellwarden created. Spellwarden's backend enforces both: it sends only the status field, and it changes only skills it installed.

IAM also cannot limit reads to some kinds of asset. AWS authorises `ListAssets`, `GetAsset`, `GetAssetContent`, `ListAssetFiles` and `GetAssetFile` only on the whole Agent Space and offers no condition key for the asset type (the [service authorization reference for `aidevops`](https://docs.aws.amazon.com/service-authorization/latest/reference/list_devops-agent.html)). So the `Read` policy lets the role read every asset of this Agent Space, memory stores included, whatever `ReadMemories` says. What Spellwarden reads, below, is enforced by Spellwarden's backend, and a test there pins it.

You can check it yourself: every call the role makes is in your CloudTrail, with a session name that starts with `dag-`.

## What Spellwarden never reads

Attachments, test profiles, feedback, chats, journals and investigations. Memory stores other than `directives` are read only with `ReadMemories`. Spellwarden's backend keeps to this; the role's permissions alone would allow more (see Permissions). If an Agent Space holds material Spellwarden must not be able to read at all, do not connect that Agent Space.

## Costs

The stack itself costs about USD 0.40 a month: AWS bills its one Secrets Manager secret. The registration function runs only when the stack is created, updated or deleted. Idle Agent Spaces, skills and registrations cost nothing. A weekly review run is agent time (USD 0.0083 a second).

## Remove it

Disconnect in the dashboard, or delete the stack. Deleting the stack removes the role, the secret and the DevOps Agent registrations and tells Spellwarden. Either order works. Spellwarden keeps the scan history until the organisation deletes it.

## Checks

Every push runs `cfn-lint` against CloudFormation's resource schemas, the tests in `tests/` (the role's policies, the registration function, and the skill and agent the template carries, which must equal `skills/` and `custom-agent/`) and Spellwarden's scanner on `skills/`. Locally: `python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt && .venv/bin/cfn-lint template/spellwarden-devops-agent.yaml && .venv/bin/python -m pytest -q tests`.

## Security

Report a problem to security@spellwarden.ai. See `SECURITY.md`.
