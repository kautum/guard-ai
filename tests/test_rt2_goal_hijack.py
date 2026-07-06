import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    d9 = f.read()
with open("policies/taint.cedar") as f:
    taint = f.read()
with open("policies/rt2_goal_hijack.cedar") as f:
    rt2 = f.read()

policies = d9 + "\n" + taint + "\n" + rt2

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "inbox"}}, "attrs": {"resource_class": "InternalLowSens", "sensitivity": "LOW", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
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
                "authority_requirement": "implicit_sufficient",
        "sandbox_unavailable": False,
        "source_attestation_verified": False,
        "integrity_hash_match": False
    }
    base.update(overrides)
    return base

def run(name, action, context):
    request = {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": action},
        "resource": {"type": "Resource", "id": "inbox"},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

# Case 1: prompt injection shifts goal, agent proposes Send -> DENY(none) goal_hijack
run("goal_hijack", "Send", make_context(
    intent_alignment="shifted",
    untrusted_influence=True
))

# Case 2: ambiguous intent -> DENY(escalate)
run("intent_ambiguous", "Execute", make_context(
    intent_alignment="ambiguous"
))

# Case 3: legitimate action, aligned with original task, authority present -> ALLOW
run("legit_action", "Send", make_context(
    intent_alignment="original_user_task",
    authority_status="present"
))

# Case 4: read hostile content for abuse triage, not serving injected goal -> ALLOW
run("abuse_triage_read", "Read", make_context(
    intent_alignment="ambiguous",
    untrusted_influence=True
))