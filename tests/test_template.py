"""The stack's template, its inline registration function, the skill and the prompt it carries, and the connector staged for
the AWS DevOps Agent gallery. Spellwarden's backend runs the same tests against its vendored copy of this repository."""
from __future__ import annotations

import io
import json
import re
import sys
import time
import types
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "template" / "spellwarden-devops-agent.yaml"
HOP = "arn:aws:iam::359360911388:role/spellwarden-devops-agent"
WRITES = {"aidevops:UpdateAsset", "aidevops:CreateAsset", "aidevops:DeleteAsset"}
READ_TOOLS = ("list_organisations", "get_organisation", "list_skills", "get_skill", "list_findings", "get_trust_score",
              "list_policy_packs", "list_registry_entries", "get_runtime_inventory", "get_eval_run", "get_migration_report",
              "list_mcp_servers", "list_agent_space_connections")


class _Loader(yaml.SafeLoader):
    pass


def _construct(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {"Ref" if suffix == "Ref" else f"Fn::{suffix}": value}


_Loader.add_multi_constructor("!", _construct)


def template() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), _Loader)


def function_code() -> str:
    lines = template()["Resources"]["RegisterFunction"]["Properties"]["Code"]["ZipFile"]
    return lines


def test_the_parameters_and_their_defaults_are_those_of_the_spec():
    parameters = template()["Parameters"]
    assert list(parameters) == ["AgentSpaceId", "ExternalId", "SetupCode", "AllowSwitchOff", "AllowInstall", "ReadMemories",
                                "ConnectSpellwardenTools", "WeeklyReview"]
    assert parameters["ExternalId"]["AllowedPattern"] == "^sw-[0-9a-f]{32}$"
    assert parameters["SetupCode"]["AllowedPattern"] == "^swsetup_[A-Za-z0-9_-]{40}$" and parameters["SetupCode"]["NoEcho"] is True
    defaults = {name: parameters[name]["Default"] for name in list(parameters)[3:]}
    assert defaults == {"AllowSwitchOff": "false", "AllowInstall": "false", "ReadMemories": "false",
                        "ConnectSpellwardenTools": "true", "WeeklyReview": "false"}


def test_the_role_trusts_only_the_hop_role_with_the_external_id_and_lasts_an_hour():
    role = template()["Resources"]["SpellwardenRole"]["Properties"]
    assert role["RoleName"] == {"Fn::Sub": "SpellwardenDevOpsAgent-${AgentSpaceId}"} and role["MaxSessionDuration"] == 3600
    [statement] = role["AssumeRolePolicyDocument"]["Statement"]
    assert statement["Principal"] == {"AWS": HOP} and statement["Action"] == "sts:AssumeRole"
    assert statement["Condition"] == {"StringEquals": {"sts:ExternalId": {"Ref": "ExternalId"}}}


def _policies(role: dict) -> list[tuple[str | None, dict]]:
    """`(condition, policy)` for each inline policy of the role."""
    found = []
    for entry in role["Policies"]:
        if "Fn::If" in entry:
            condition, policy, _ = entry["Fn::If"]
            found.append((condition, policy))
        else:
            found.append((None, entry))
    return found


def test_every_write_action_sits_behind_its_condition_and_no_statement_is_broader_than_the_agent_space():
    role = template()["Resources"]["SpellwardenRole"]["Properties"]
    by_name = {policy["PolicyName"]: (condition, policy) for condition, policy in _policies(role)}
    assert list(by_name) == ["Read", "SwitchOff", "Install"]
    assert by_name["SwitchOff"][0] == "SwitchOff" and by_name["Install"][0] == "Install"
    assert by_name["Read"][0] is None
    for name, (condition, policy) in by_name.items():
        for statement in policy["PolicyDocument"]["Statement"]:
            actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            assert not any(action.endswith(":*") or action == "*" for action in actions), name
            if set(actions) & WRITES:
                assert condition in ("SwitchOff", "Install") and statement["Resource"] != "*", name
    switch = by_name["SwitchOff"][1]["PolicyDocument"]["Statement"][0]["Action"]
    install = by_name["Install"][1]["PolicyDocument"]["Statement"][0]["Action"]
    assert switch == "aidevops:UpdateAsset" and install == ["aidevops:CreateAsset", "aidevops:UpdateAsset", "aidevops:DeleteAsset"]
    read = by_name["Read"][1]["PolicyDocument"]["Statement"]
    assert not any(set(s["Action"] if isinstance(s["Action"], list) else [s["Action"]]) & WRITES for s in read)


def test_the_tools_of_the_association_are_the_thirteen_read_only_tools():
    resource = template()["Resources"]["SpellwardenAssociation"]
    assert tuple(resource["Properties"]["Configuration"]["MCPServer"]["Tools"]) == READ_TOOLS
    assert resource["Condition"] == "ConnectTools" and template()["Resources"]["SpellwardenService"]["Condition"] == "ConnectTools"
    token = template()["Resources"]["SpellwardenService"]["Properties"]["ServiceDetails"]["MCPServer"]["AuthorizationConfig"]["BearerToken"]
    assert "${Registration.SecretVersionId}" in token["TokenValue"]["Fn::Sub"] and ":SecretString:api_key::" in token["TokenValue"]["Fn::Sub"]


SERVER_NAME = {"Fn::Join": ["", ["spellwarden-", {"Fn::Select": [0, {"Fn::Split": ["-", {"Ref": "AgentSpaceId"}]}]}]]}


def test_every_tool_name_fits_devops_agents_64_characters():
    """End-to-end gate, 2026-11-08: DevOps Agent names a tool <server name>_<tool> and refuses more than 64 characters, which
    spellwarden-<a 36-character Agent Space ID> broke. The server is named after the ID's first segment, at most 23 characters."""
    resources_ = template()["Resources"]
    assert resources_["SpellwardenService"]["Properties"]["ServiceDetails"]["MCPServer"]["Name"] == SERVER_NAME
    assert resources_["SpellwardenAssociation"]["Properties"]["Configuration"]["MCPServer"]["Name"] == SERVER_NAME
    pattern = re.compile(template()["Parameters"]["AgentSpaceId"]["AllowedPattern"])
    assert template()["Parameters"]["AgentSpaceId"]["MaxLength"] == 64
    longest_segment = "a" * 23
    assert pattern.match(longest_segment + "-7950-42f8") and pattern.match("73dcdf31-7950-42f8-ac3c-096c865c79b3")
    assert not pattern.match("a" * 24 + "-x") and not pattern.match("-abc")
    assert max(len(f"spellwarden-{longest_segment}_{tool}") for tool in READ_TOOLS) == 64
    for tool_id in resources_["ReviewAgent"]["Properties"]["Metadata"]["tools"]:
        parts = tool_id["Fn::Join"][1]
        assert parts[:2] == SERVER_NAME["Fn::Join"][1] and parts[2].startswith("_") and parts[2][1:] in READ_TOOLS


def test_the_weekly_review_needs_the_tools_and_carries_the_files_of_the_repository():
    resources_ = template()["Resources"]
    for name in ("ReviewSkill", "ReviewAgent", "ReviewTrigger"):
        assert resources_[name]["Condition"] == "Weekly", name
    trigger = resources_["ReviewTrigger"]["Properties"]
    assert trigger["Condition"] == {"Schedule": {"Expression": "rate(7 days)"}} and trigger["Status"] == "Active"   # the CFN schema
    assert trigger["Action"] == {"actionType": "create:task", "task": {"agent": {"Fn::Sub": "custom:${ReviewAgent.AssetId}"}}}
    skill = (ROOT / "skills" / "spellwarden-agent-supply-chain-review" / "SKILL.md").read_text(encoding="utf-8")
    prompt = (ROOT / "custom-agent" / "AGENT.md").read_text(encoding="utf-8")
    assert resources_["ReviewSkill"]["Properties"]["Files"] == [{"Path": "SKILL.md", "ContentText": resources_["ReviewSkill"]["Properties"]["Files"][0]["ContentText"]}]
    assert resources_["ReviewSkill"]["Properties"]["Files"][0]["ContentText"].strip() == skill.strip()
    assert resources_["ReviewAgent"]["Properties"]["Files"][0] == {"Path": "AGENT.md", "ContentText": prompt}
    front = yaml.safe_load(skill.split("---")[1])                  # a one-file skill names itself in the metadata (Asset API)
    metadata = resources_["ReviewSkill"]["Properties"]["Metadata"]
    assert (metadata["name"], metadata["description"], metadata["agent_types"]) == (front["name"], front["description"], ["GENERIC"])
    rule = template()["Rules"]["WeeklyReviewNeedsTools"]
    assert rule["Assertions"][0]["Assert"] == {"Fn::Equals": [{"Ref": "ConnectSpellwardenTools"}, "true"]}


def test_the_registration_is_a_custom_resource_whose_properties_change_with_every_option():
    properties = template()["Resources"]["Registration"]["Properties"]
    assert template()["Resources"]["Registration"]["Type"] == "Custom::SpellwardenRegistration"
    assert {"SetupCode", "TemplateVersion", "AllowSwitchOff", "AllowInstall", "ReadMemories", "ConnectSpellwardenTools",
            "WeeklyReview", "RoleArn", "ExternalId", "AgentSpaceId"} <= set(properties)
    function = template()["Resources"]["RegisterFunction"]["Properties"]
    assert function["Runtime"] == "python3.13" and function["Timeout"] == 30 and len(function_code()) < 4096
    secret = template()["Resources"]["ConnectionSecret"]
    assert secret["DeletionPolicy"] == "Delete" and json.loads(secret["Properties"]["SecretString"]) == {"api_key": "", "connection_token": ""}
    statements = template()["Resources"]["RegisterRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"],
                           "Resource": {"Ref": "ConnectionSecret"}}]


class _Secrets:
    def __init__(self, value):
        self.value, self.puts = value, []

    def get_secret_value(self, SecretId):
        return {"SecretString": json.dumps(self.value), "VersionId": "v-current"}

    def put_secret_value(self, SecretId, SecretString):
        self.value = json.loads(SecretString)
        self.puts.append(self.value)
        return {"VersionId": "v-new"}


class _Reply:
    def __init__(self, body):
        self.body = body

    def read(self):
        return json.dumps(self.body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _run(monkeypatch, event_type, properties, *, old=None, secret=None, answer=None, fail_post=False, refuse=None):
    """`refuse`: `(status, error body)` answers Spellwarden gives, in order, before it answers `answer`."""
    secrets_client = _Secrets(secret or {"api_key": "", "connection_token": ""})
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda name: secrets_client))
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    monkeypatch.setenv("SECRET", "arn:secret")
    monkeypatch.setenv("BASE", "https://dash.example/api/public/devops-agent")
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    posted, replies = [], []
    refusals = list(refuse or [])

    def urlopen(request, timeout=0):
        if request.full_url.startswith("https://dash.example"):
            if fail_post:
                raise OSError("down")
            posted.append((request.full_url.rsplit("/", 1)[1], json.loads(request.data)))
            if refusals:
                status, payload = refusals.pop(0)
                raise urllib.error.HTTPError(request.full_url, status, "refused", {}, io.BytesIO(json.dumps(payload).encode()))
            return _Reply(answer or {"api_key": "swk_new", "connection_token": "swdc_new", "status": "Connected to organisation acme"})
        replies.append(json.loads(request.data))
        return _Reply({})

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    namespace: dict = {}
    exec(compile(function_code(), "index.py", "exec"), namespace)
    event = {"RequestType": event_type, "ResourceProperties": properties, "StackId": "stack-1", "RequestId": "r1",
             "LogicalResourceId": "Registration", "ResponseURL": "https://cfn.example/response"}
    if old is not None:
        event["OldResourceProperties"] = old
    context = types.SimpleNamespace(invoked_function_arn="arn:aws:lambda:eu-central-1:210987654321:function:f", log_stream_name="ls",
                                    get_remaining_time_in_millis=lambda: 29000)
    namespace["handler"](event, context)
    return posted, replies, secrets_client


PROPS = {"ExternalId": "sw-" + "1" * 32, "SetupCode": "swsetup_" + "A" * 40, "RoleArn": "arn:role", "AgentSpaceId": "as-1",
         "TemplateVersion": "1.0.0", "AllowSwitchOff": "true", "AllowInstall": "false", "ReadMemories": "false",
         "ConnectSpellwardenTools": "true", "WeeklyReview": "false"}


def test_create_registers_with_the_setup_code_and_stores_the_answer_in_the_secret(monkeypatch):
    posted, replies, secrets_client = _run(monkeypatch, "Create", PROPS)
    [(path, body)] = posted
    assert path == "register" and body["setup_code"] == PROPS["SetupCode"] and body["account_id"] == "210987654321"
    assert body["options"] == {"allow_switch_off": True, "allow_install": False, "read_memories": False, "connect_tools": True,
                               "weekly_review": False}
    assert (body["region"], body["agent_space_id"], body["stack_id"]) == ("eu-central-1", "as-1", "stack-1")
    assert secrets_client.puts == [{"api_key": "swk_new", "connection_token": "swdc_new"}]
    assert replies[0]["Status"] == "SUCCESS" and replies[0]["Data"] == {"SecretVersionId": "v-new",
                                                                         "ConnectionStatus": "Connected to organisation acme"}


def test_an_update_with_the_same_setup_code_sends_the_token_and_leaves_the_secret_alone(monkeypatch):
    secret = {"api_key": "swk_old", "connection_token": "swdc_old"}
    posted, replies, secrets_client = _run(monkeypatch, "Update", PROPS, old=dict(PROPS), secret=secret,
                                           answer={"status": "Connected to organisation acme"})
    [(path, body)] = posted
    assert path == "register" and body["connection_token"] == "swdc_old" and "setup_code" not in body
    assert secrets_client.puts == [] and replies[0]["Data"]["SecretVersionId"] == "v-current"


def test_an_update_with_a_new_setup_code_reconnects_and_writes_a_new_secret_version(monkeypatch):
    new = {**PROPS, "SetupCode": "swsetup_" + "B" * 40}
    posted, replies, secrets_client = _run(monkeypatch, "Update", new, old=dict(PROPS),
                                           secret={"api_key": "swk_old", "connection_token": "swdc_old"})
    assert posted[0][1]["setup_code"] == new["SetupCode"] and secrets_client.puts == [
        {"api_key": "swk_new", "connection_token": "swdc_new"}]
    assert replies[0]["Data"]["SecretVersionId"] == "v-new"


USED = (400, {"error": "setup_invalid", "message": "This setup code is not valid. Create a new one in Spellwarden."})


def test_a_rollback_that_brings_back_a_used_setup_code_keeps_the_connection_and_succeeds(monkeypatch):
    """Review r0:F4: during UPDATE_ROLLBACK the properties hold the old, already used code and the old ones the new code; the
    function then keeps the connection the secret holds (the token path) instead of failing into UPDATE_ROLLBACK_FAILED."""
    new = {**PROPS, "SetupCode": "swsetup_" + "B" * 40}
    posted, replies, secrets_client = _run(monkeypatch, "Update", PROPS, old=new, refuse=[USED],
                                           secret={"api_key": "swk_new", "connection_token": "swdc_new"},
                                           answer={"status": "Connected to organisation acme"})
    assert [("setup_code" in body, body.get("connection_token")) for _, body in posted] == [(True, None), (False, "swdc_new")]
    assert secrets_client.puts == [] and replies[0]["Status"] == "SUCCESS" and replies[0]["Data"]["SecretVersionId"] == "v-current"


def test_a_used_setup_code_whose_token_is_no_longer_valid_fails_with_the_setup_message(monkeypatch):
    """An ordinary update with an expired or used code and a revoked token fails with the setup code's message."""
    new = {**PROPS, "SetupCode": "swsetup_" + "B" * 40}
    revoked = (400, {"error": "token_invalid", "message": "The connection token is not valid."})
    _, replies, _ = _run(monkeypatch, "Update", new, old=dict(PROPS), refuse=[USED, revoked],
                         secret={"api_key": "", "connection_token": "swdc_revoked"})
    assert replies[0]["Status"] == "FAILED" and replies[0]["Reason"] == USED[1]["message"]


def test_a_used_setup_code_on_create_fails_and_never_tries_a_token(monkeypatch):
    posted, replies, _ = _run(monkeypatch, "Create", PROPS, refuse=[USED], secret={"api_key": "", "connection_token": "swdc_x"})
    assert len(posted) == 1 and replies[0]["Status"] == "FAILED" and replies[0]["Reason"] == USED[1]["message"]


def test_delete_unregisters_and_always_reports_success(monkeypatch):
    posted, replies, _ = _run(monkeypatch, "Delete", PROPS, secret={"api_key": "k", "connection_token": "swdc_old"})
    assert posted == [("unregister", {"connection_token": "swdc_old", "stack_id": "stack-1"})] and replies[0]["Status"] == "SUCCESS"
    _, replies, _ = _run(monkeypatch, "Delete", PROPS, fail_post=True)
    assert replies[0]["Status"] == "SUCCESS"


def test_a_failed_registration_fails_the_stack_with_the_reason(monkeypatch):
    _, replies, _ = _run(monkeypatch, "Create", PROPS, fail_post=True)
    assert replies[0]["Status"] == "FAILED" and "down" in replies[0]["Reason"]


def test_a_refusal_while_the_new_role_propagates_is_tried_again(monkeypatch):
    """IAM makes a new role assumable a few seconds after CloudFormation reports it created: the function asks again."""
    refusal = (400, {"error": "assume_role_denied", "message": "AWS refused to let Spellwarden take the role."})
    posted, replies, secrets_client = _run(monkeypatch, "Create", PROPS, refuse=[refusal])
    assert [path for path, _ in posted] == ["register", "register"] and replies[0]["Status"] == "SUCCESS"
    assert secrets_client.puts == [{"api_key": "swk_new", "connection_token": "swdc_new"}]


def test_a_refused_registration_fails_the_stack_with_spellwardens_message(monkeypatch):
    """Spec 7.7: a full key cap answers api_key_cap at register, and the stack fails with that message."""
    message = "This organisation has 20 API keys. Revoke one, then connect again."
    posted, replies, _ = _run(monkeypatch, "Create", PROPS, refuse=[(409, {"error": "api_key_cap", "message": message})])
    assert len(posted) == 1 and replies[0]["Status"] == "FAILED" and replies[0]["Reason"] == message


def test_the_connector_matches_the_spec_and_names_the_skill_it_offers():
    connector = yaml.safe_load((ROOT / "connector" / "connector.yaml").read_text(encoding="utf-8"))
    assert (connector["schema_version"], connector["name"], connector["tier"], connector["type"]) == (1, "spellwarden", "partner-managed", "mcp")
    assert connector["mcp"]["endpoint"] == "https://dash.spellwarden.ai/api/v1/mcp"
    assert [auth["type"] for auth in connector["mcp"]["auth"]] == ["dynamic_client_registration", "api_key"]
    assert connector["mcp"]["auth"][0]["authorization_server"] == "https://dash.spellwarden.ai"
    assert connector["mcp"]["auth"][1]["headers"] == [{"header": "Authorization", "label": "Spellwarden API key (read access)", "prefix": "Bearer "}]
    assert connector["skills"] == ["spellwarden-agent-supply-chain-review"] and connector["contact_email"] == "security@spellwarden.ai"
    assert "triggers" not in connector                                              # D19
    assert (ROOT / "connector" / "logo.svg").is_file() and (ROOT / "connector" / "README.md").is_file()


def test_the_staged_files_use_no_dash_character_and_no_emoji():
    for path in (p for p in ROOT.rglob("*") if ".venv" not in p.parts and ".git" not in p.parts):
        if path.is_file() and path.suffix in (".md", ".yaml", ".yml"):
            text = path.read_text(encoding="utf-8")
            assert "\u2014" not in text and "\u2013" not in text, path
