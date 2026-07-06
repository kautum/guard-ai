import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

with open("policies/d9_core.cedar") as f:
    d9 = f.read()
with open("policies/taint.cedar") as f:
    taint = f.read()
with open("policies/rt3_memory_poison.cedar") as f:
    rt3 = f.read()

policies = d9 + "\n" + taint + "\n" + rt3

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "instr1"}}, "attrs": {"resource_class": "InstructionMemory", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "fact1"}}, "attrs": {"resource_class": "FactMemory", "sensitivity": "MEDIUM", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "scratch1"}}, "attrs": {"resource_class": "EphemeralMemory", "sensitivity": "LOW", "owner": "alice", "origin_boundary": "internal"}, "parents": []}
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

def run(name, resource_id, context):
    request = {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "MemoryWrite"},
        "resource": {"type": "Resource", "id": resource_id},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    print(f"{name}: {result.decision.value}  | annotations: {result.diagnostics.id_annotations_by_reason}  | errors: {result.diagnostics.errors}")

# Case 1: untrusted content written to InstructionMemory -> DENY(none) mempoison
run("mempoison_untrusted", "instr1", make_context(
    action_provenance="untrusted",
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))

# Case 2: validated (sanitized) content to GoalMemory -> still DENY(none), validated NOT enough
run("mempoison_validated", "instr1", make_context(
    action_provenance="validated",
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))

# Case 3: trusted write to InstructionMemory, authority present, approved -> ALLOW
run("legit_instruction_write", "instr1", make_context(
    action_provenance="trusted",
    authority_status="present",
    approval_present_for_this_action=True,
    resource_sensitivity="HIGH",
    authority_requirement="explicit_required"
))

# Case 4: untrusted write to FactMemory -> transform
run("fact_untrusted_transform", "fact1", make_context(
    action_provenance="untrusted",
    resource_sensitivity="MEDIUM"
))

# Case 5: trusted write to FactMemory -> ALLOW
run("fact_trusted_allow", "fact1", make_context(
    action_provenance="trusted",
    authority_status="present",
    resource_sensitivity="MEDIUM"
))

# Case 6: any write to EphemeralMemory (scratch) -> ALLOW
run("ephemeral_scratch", "scratch1", make_context(
    action_provenance="untrusted"
))