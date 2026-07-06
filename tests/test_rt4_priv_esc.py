import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    d9 = f.read()
with open("policies/taint.cedar") as f:
    taint = f.read()
with open("policies/rt4_priv_esc.cedar") as f:
    rt4 = f.read()

policies = d9 + "\n" + taint + "\n" + rt4

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "subagent1"}}, "attrs": {"resource_class": "InternalLowSens", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
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

def run(name, context):
    request = {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "Delegate"},
        "resource": {"type": "Resource", "id": "subagent1"},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

# Case 1: delegated scope equals parent scope (not strict subset) -> DENY(none)
run("privesc_equal_scope", make_context(
    scope_is_strict_subset=False,
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))

# Case 2: delegation depth exceeds ceiling -> DENY(none) cascade_depth
run("cascade_depth_exceeded", make_context(
    scope_is_strict_subset=True,
    delegation_depth=5
))

# Case 3: narrower scope, authority present, depth ok -> ALLOW
run("legit_delegation", make_context(
    scope_is_strict_subset=True,
    authority_status="present",
    delegation_depth=1
))

# Case 4 (NEW — regression test for off-by-one bug found in audit):
# delegation depth EXACTLY at the ceiling (3) must be DENIED, not allowed.
run("cascade_depth_at_ceiling_boundary", make_context(
    scope_is_strict_subset=True,
    authority_status="present",
    delegation_depth=3
))

# Case 5 (NEW): delegation depth one below ceiling (2) must be ALLOWED.
run("cascade_depth_just_below_ceiling", make_context(
    scope_is_strict_subset=True,
    authority_status="present",
    delegation_depth=2
))
