import json
import glob
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

policy_files = [
    "policies/d9_core.cedar",
    "policies/taint.cedar",
    "policies/rt1_exfil.cedar",
    "policies/rt2_goal_hijack.cedar",
    "policies/rt3_memory_poison.cedar",
    "policies/rt4_priv_esc.cedar",
    "policies/rt5_supply_chain.cedar",
]

policies = "\n".join(open(f).read() for f in policy_files)

entities = [
    {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"is_human": True, "trust_tier": 1}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "custdb"}}, "attrs": {"resource_class": "InternalLowSens", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "cred1"}}, "attrs": {"resource_class": "Credential", "sensitivity": "CRITICAL", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "inbox"}}, "attrs": {"resource_class": "InternalLowSens", "sensitivity": "LOW", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "instr1"}}, "attrs": {"resource_class": "InstructionMemory", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "fact1"}}, "attrs": {"resource_class": "FactMemory", "sensitivity": "MEDIUM", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "scratch1"}}, "attrs": {"resource_class": "EphemeralMemory", "sensitivity": "LOW", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "subagent1"}}, "attrs": {"resource_class": "InternalLowSens", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
    {"uid": {"__entity": {"type": "Resource", "id": "dep1"}}, "attrs": {"resource_class": "Dependency", "sensitivity": "HIGH", "owner": "alice", "origin_boundary": "internal"}, "parents": []},
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
        "integrity_hash_match": True,
    }
    base.update(overrides)
    return base

def run(name, resource_id, action, context, expected):
    request = {
        "principal": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": action},
        "resource": {"type": "Resource", "id": resource_id},
        "context": context
    }
    result = is_authorized(request, policies, entities, schema=schema)
    status = "PASS" if result.decision.value.lower() == expected.lower() else "FAIL"
    print(f"[{status}] {name}: {result.decision.value} (expected {expected}) | annotations: {result.diagnostics.id_annotations_by_reason} | errors: {result.diagnostics.errors}")
    return status == "PASS"

results = []

# TAINT-4 lethal trifecta
results.append(run("lethal_trifecta_fires", "custdb", "Send", make_context(
    untrusted_influence=True, resource_sensitivity="HIGH", recipient_is_authorized=False,
    authority_status="absent", authority_requirement="explicit_required"), "deny"))
results.append(run("authorized_recipient_safe", "custdb", "Send", make_context(recipient_is_authorized=True), "allow"))
results.append(run("low_sensitivity_safe", "custdb", "Send", make_context(), "allow"))

# RT1
results.append(run("exfil_no_authority", "custdb", "Send", make_context(
    resource_sensitivity="HIGH", recipient_is_authorized=False, authority_status="absent",
    authority_requirement="explicit_required"), "deny"))
results.append(run("credential_exfil", "cred1", "Send", make_context(
    resource_sensitivity="CRITICAL", recipient_is_authorized=False, authority_status="present",
    authority_requirement="explicit_required", approval_present_for_this_action=True), "deny"))
results.append(run("authorized_reply", "custdb", "Send", make_context(
    resource_sensitivity="HIGH", recipient_is_authorized=True), "allow"))
results.append(run("read_external_data", "custdb", "Read", make_context(), "allow"))

# RT2
results.append(run("goal_hijack", "inbox", "Send", make_context(
    intent_alignment="shifted", untrusted_influence=True), "deny"))
results.append(run("intent_ambiguous", "inbox", "Execute", make_context(
    intent_alignment="ambiguous"), "deny"))
results.append(run("legit_action", "inbox", "Send", make_context(
    intent_alignment="original_user_task", authority_status="present"), "allow"))
results.append(run("abuse_triage_read", "inbox", "Read", make_context(
    intent_alignment="ambiguous", untrusted_influence=True), "allow"))

# RT3
results.append(run("mempoison_untrusted", "instr1", "MemoryWrite", make_context(
    action_provenance="untrusted", resource_sensitivity="HIGH", authority_requirement="explicit_required"), "deny"))
results.append(run("mempoison_validated", "instr1", "MemoryWrite", make_context(
    action_provenance="validated", resource_sensitivity="HIGH", authority_requirement="explicit_required"), "deny"))
results.append(run("legit_instruction_write", "instr1", "MemoryWrite", make_context(
    action_provenance="trusted", authority_status="present", approval_present_for_this_action=True,
    resource_sensitivity="HIGH", authority_requirement="explicit_required"), "allow"))
results.append(run("fact_untrusted_transform", "fact1", "MemoryWrite", make_context(
    action_provenance="untrusted", resource_sensitivity="MEDIUM"), "deny"))
results.append(run("fact_trusted_allow", "fact1", "MemoryWrite", make_context(
    action_provenance="trusted", authority_status="present", resource_sensitivity="MEDIUM"), "allow"))
results.append(run("ephemeral_scratch", "scratch1", "MemoryWrite", make_context(
    action_provenance="untrusted"), "allow"))

# RT4
results.append(run("privesc_equal_scope", "subagent1", "Delegate", make_context(
    scope_is_strict_subset=False, resource_sensitivity="HIGH", authority_requirement="explicit_required"), "deny"))
results.append(run("cascade_depth_exceeded", "subagent1", "Delegate", make_context(
    scope_is_strict_subset=True, delegation_depth=5), "deny"))
results.append(run("legit_delegation", "subagent1", "Delegate", make_context(
    scope_is_strict_subset=True, authority_status="present", delegation_depth=1), "allow"))

# RT5
results.append(run("unverified_source", "dep1", "Install", make_context(
    source_attestation_verified=False, integrity_hash_match=True, resource_sensitivity="HIGH",
    authority_requirement="explicit_required"), "deny"))
results.append(run("integrity_mismatch", "dep1", "Install", make_context(
    source_attestation_verified=True, integrity_hash_match=False, resource_sensitivity="HIGH",
    authority_requirement="explicit_required"), "deny"))
results.append(run("both_broken", "dep1", "Install", make_context(
    source_attestation_verified=False, integrity_hash_match=False, resource_sensitivity="HIGH"), "deny"))
results.append(run("legit_install", "dep1", "Install", make_context(
    source_attestation_verified=True, integrity_hash_match=True, authority_status="present",
    approval_present_for_this_action=True, resource_sensitivity="HIGH",
    authority_requirement="explicit_required"), "allow"))

print(f"\n{sum(results)}/{len(results)} PASSED")