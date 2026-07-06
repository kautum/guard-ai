import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    d9 = f.read()
with open("policies/taint.cedar") as f:
    taint = f.read()
with open("policies/rt5_supply_chain.cedar") as f:
    rt5 = f.read()

policies = d9 + "\n" + taint + "\n" + rt5

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "dep1"}}, "attrs": {"resource_class": "Dependency", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
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
        "sandbox_unavailable": False,
        "source_attestation_verified": True,
        "integrity_hash_match": True
    }
    base.update(overrides)
    return base

def run(name, context):
    request = {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "Install"},
        "resource": {"type": "Resource", "id": "dep1"},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

run("unverified_source", make_context(
    source_attestation_verified=False,
    integrity_hash_match=True,
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))

run("integrity_mismatch", make_context(
    source_attestation_verified=True,
    integrity_hash_match=False,
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))

run("both_broken", make_context(
    source_attestation_verified=False,
    integrity_hash_match=False,
    resource_sensitivity="HIGH"
))

run("legit_install", make_context(
    source_attestation_verified=True,
    integrity_hash_match=True,
    authority_status="present",
    approval_present_for_this_action=True,
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))