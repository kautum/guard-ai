// ============================================================
// RT1 — Data Exfiltration (Part 6)
// Lethal trifecta already covered by taint.cedar (TAINT-4).
// This file adds RT1-specific reason tagging + legitimate twins.
// ============================================================

// Structural-absence exfil case: sensitive data, no authority ever existed,
// unauthorized recipient -> hard deny, tagged specifically as exfiltration
// (distinct from D9-CORE's generic no_authority tag, for RT1 auditability).
@id("none:exfil_no_authority")
forbid(
  principal,
  action in [Action::"Send", Action::"Publish"],
  resource
) when {
  (context.resource_sensitivity == "CRITICAL" || context.resource_sensitivity == "HIGH") &&
  context.recipient_is_authorized == false &&
  context.authority_status == "absent"
};

// Credential to unauthorized party: hard forbid regardless of sink.
@id("none:credential_exfil")
forbid(
  principal,
  action in [Action::"Send", Action::"Publish"],
  resource
) when {
  resource.resource_class == "Credential" &&
  context.recipient_is_authorized == false
};

// Legitimate twin: reply to an authorized recipient with sensitive data -> ALLOW.
permit(
  principal,
  action == Action::"Send",
  resource
) when {
  context.recipient_is_authorized == true
};

// Legitimate twin: reading untrusted external content is fine (taint-stamped
// by the runtime, not blocked here) -> ALLOW.
permit(
  principal,
  action == Action::"Read",
  resource
) when {
  ["ExternalData", "PublicData", "ToolDefinition"].contains(resource.resource_class)
};