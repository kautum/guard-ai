import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    d9 = f.read()
with open("policies/taint.cedar") as f:
    taint = f.read()
with open("policies/rt1_exfil.cedar") as f:
    rt1 = f.read()

policies = d9 + "\n" + taint + "\n" + rt1

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "custdb"}}, "attrs": {"resource_class": "InternalLowSens", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "cred1"}}, "attrs": {"resource_class": "Credential", "sensitivity": "CRITICAL", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
]

def make_context(**overrides):
    base = {
        "action_provenance": "trusted",
        "untrusted_influence": False,
        "recipient_is_authorized": True,
        "high_impact": False,
        "authority_status": "present",
        "scope_is_strict_subset": True,
        "applicable_transform_recipe": "",
        "intent_alignment": "original_user_task",
        "is_irreversible": False,
        "resource_sensitivity": "LOW",
        "sink_class": "InternalUserControlled",
        "approval_present_for_this_action": False,
        "rate_exceeds_ceiling": False,
        "snapshot_consistent": True,
        "delegation_depth": 0,
        "authority_requirement": "implicit_sufficient",
        "sandbox_unavailable": False
    }
    base.update(overrides)
    return base

def run(name, resource_id, action, context):
    request = {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": action},
        "resource": {"type": "Resource", "id": resource_id},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

# Case 1: send customer DB to unauthorized party, no authority -> DENY(none) exfil
run("exfil_no_authority", "custdb", "Send", make_context(
    resource_sensitivity="HIGH",
    recipient_is_authorized=False,
    authority_status="absent",
    authority_requirement="explicit_required"
))

# Case 2: credential to unauthorized party -> DENY(none), hard forbid regardless
run("credential_exfil", "cred1", "Send", make_context(
    resource_sensitivity="CRITICAL",
    recipient_is_authorized=False,
    authority_status="present",
    authority_requirement="explicit_required",
    approval_present_for_this_action=True
))

# Case 3: reply to customer with their own data (authorized) -> ALLOW
run("authorized_reply", "custdb", "Send", make_context(
    resource_sensitivity="HIGH",
    recipient_is_authorized=True
))

# Case 4: read external/public data -> ALLOW (legitimate, taint-stamped elsewhere)
run("read_external_data", "custdb", "Read", make_context())