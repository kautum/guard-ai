import json
from cedarpy import is_authorized

with open("schema/guardai.cedarschema.json") as f:
    schema = json.load(f)

policies = """
permit(
  principal,
  action == Action::"Read",
  resource
) when {
  resource.sensitivity == "LOW"
};
"""

entities = [
    {
        "uid": {"__entity": {"type": "User", "id": "alice"}},
        "attrs": {"is_human": True, "trust_tier": 1},
        "parents": []
    },
    {
        "uid": {"__entity": {"type": "Resource", "id": "doc1"}},
        "attrs": {
            "resource_class": "PublicData",
            "sensitivity": "LOW",
            "owner": "alice",
            "origin_boundary": "internal"
        },
        "parents": []
    }
]

request = {
    "principal": {"type": "User", "id": "alice"},
    "action": {"type": "Action", "id": "Read"},
    "resource": {"type": "Resource", "id": "doc1"},
    "context": {
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
}

result = is_authorized(request, policies, entities, schema=schema)
print("Decision:", result.decision)
print("Diagnostics errors:", result.diagnostics.errors)