// ============================================================
// RT4 — Privilege Escalation / Delegation (Part 6)
// Load-bearing field: context.scope_is_strict_subset (identical to P-1, 1.1)
// VF minimum break: node 3 — strict subset, not equal
// DEPTH_CEILING hardcoded to 3 as stopgap — not yet in schema (7.5 Config
// Constants Registry). Flag for Arvinth/Kautum to add as a proper context
// field or schema-level constant.
// ============================================================

@id("none:privesc")
forbid(
  principal,
  action == Action::"Delegate",
  resource
) when {
  context.scope_is_strict_subset == false
};

@id("none:cascade_depth")
forbid(
  principal,
  action == Action::"Delegate",
  resource
) when {
  context.delegation_depth > 3
};

permit(
  principal,
  action == Action::"Delegate",
  resource
) when {
  context.scope_is_strict_subset == true &&
  context.authority_status == "present" &&
  context.delegation_depth <= 3
};