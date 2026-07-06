import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    policies = f.read()

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "doc1"}}, "attrs": {"resource_class": "PublicData", "sensitivity": "LOW", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
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
        "action": {"type": "Action", "id": "Read"},
        "resource": {"type": "Resource", "id": "doc1"},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | reasons: {result.diagnostics.reasons}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

# Case 1: implicit_sufficient, no untrusted influence -> ALLOW
run("implicit_ok", make_context())

# Case 2: absent authority, explicit_required -> DENY(none)
run("absent_denies", make_context(authority_requirement="explicit_required", authority_status="absent"))

# Case 3: revoked authority -> DENY(escalate)
run("revoked_escalates", make_context(authority_requirement="explicit_required", authority_status="revoked"))

# Case 4: present, per_instance, no approval -> DENY(escalate)
run("per_instance_unapproved", make_context(authority_requirement="explicit_required_per_instance", authority_status="present", approval_present_for_this_action=False))

# Case 5: present, per_instance, approved -> ALLOW
run("per_instance_approved", make_context(authority_requirement="explicit_required_per_instance", authority_status="present", approval_present_for_this_action=True, is_irreversible=True))

# Case 6: partial with recipe -> DENY(transform)
run("partial_with_recipe", make_context(authority_requirement="explicit_required", authority_status="partial", applicable_transform_recipe="downscope_action"))

# Case 7: conflicting -> DENY(escalate)
run("conflicting", make_context(authority_requirement="explicit_required", authority_status="conflicting"))
# Case 8 (NEW for BUG C6): implicit_sufficient + conflicting authority -> ALLOW
run("implicit_conflicting_allow", make_context(authority_requirement="implicit_sufficient", authority_status="conflicting"))

# Case 9 (NEW for BUG C6): implicit_sufficient + partial authority -> ALLOW
run("implicit_partial_allow", make_context(authority_requirement="implicit_sufficient", authority_status="partial"))
