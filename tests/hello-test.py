from cedarpy import is_authorized, Decision

policies = """
permit(
  principal,
  action == Action::"ReadFile",
  resource
) when {
  resource.sensitivity == "public"
};
"""

entities = [
    {
        "uid": {"__entity": {"type": "Resource", "id": "doc1"}},
        "attrs": {"sensitivity": "public"},
        "parents": []
    }
]

request = {
    "principal": 'User::"alice"',
    "action": 'Action::"ReadFile"',
    "resource": 'Resource::"doc1"',
    "context": {}
}

result = is_authorized(request, policies, entities)

print("Decision:", result.decision)
print("Allowed:", result.allowed)
print("Diagnostics:", result.diagnostics)

# Test 2: same resource, but a sensitivity that has no matching permit rule
entities2 = [
    {
        "uid": {"__entity": {"type": "Resource", "id": "doc2"}},
        "attrs": {"sensitivity": "credential_secret"},
        "parents": []
    }
]

request2 = {
    "principal": 'User::"alice"',
    "action": 'Action::"ReadFile"',
    "resource": 'Resource::"doc2"',
    "context": {}
}

result2 = is_authorized(request2, policies, entities2)

print("\nDecision 2:", result2.decision)
print("Allowed 2:", result2.allowed)