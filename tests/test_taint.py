import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    d9 = f.read()
with open("policies/taint.cedar") as f:
    taint = f.read()

policies = d9 + "\n" + taint

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "doc1"}}, "attrs": {"resource_class": "Credential", "sensitivity": "CRITICAL", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
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
        "action": {"type": "Action", "id": "Send"},
        "resource": {"type": "Resource", "id": "doc1"},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

# Case 1: lethal trifecta -> DENY(none)
run("lethal_trifecta_fires", make_context(
    untrusted_influence=True,
    resource_sensitivity="CRITICAL",
    recipient_is_authorized=False,
    authority_requirement="explicit_required",
    authority_status="absent"
))

# Case 2: same untrusted influence, but recipient IS authorized -> should NOT trip trifecta
run("authorized_recipient_safe", make_context(
    untrusted_influence=True,
    resource_sensitivity="CRITICAL",
    recipient_is_authorized=True,
    authority_requirement="explicit_required",
    authority_status="present",
    approval_present_for_this_action=True
))

# Case 3: untrusted influence but LOW sensitivity -> should NOT trip trifecta
run("low_sensitivity_safe", make_context(
    untrusted_influence=True,
    resource_sensitivity="LOW",
    recipient_is_authorized=False,
    authority_requirement="implicit_sufficient"
))