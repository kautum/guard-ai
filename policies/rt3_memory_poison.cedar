// ============================================================
// RT3 — Memory Poisoning (Part 6)
// Load-bearing fields: resource.resource_class (write target) + context.action_provenance
// VF minimum break: node 4 (target is FactMemory/EphemeralMemory instead of
// InstructionMemory/GoalMemory) OR node 5 (write source is provenance-trusted)
// resource_class is a String attribute, not an entity — use .contains()/string
// equality, never Cedar's "in" hierarchy operator.
// ============================================================

// Writing untrusted OR merely-validated content into behavior-shaping memory
// is a hard deny. Validated proves shape, never intent (Part 5) — sanitizers
// cannot launder attacker-influenced content into instruction/goal memory.
@id("none:mempoison")
forbid(
  principal,
  action == Action::"MemoryWrite",
  resource
) when {
  ["InstructionMemory", "GoalMemory"].contains(resource.resource_class) &&
  (context.action_provenance == "untrusted" || context.action_provenance == "validated")
};

// Legitimate twin: trusted-provenance write to instruction/goal memory,
// authority present, fresh per-instance approval (PI tier, 1.8) -> ALLOW.
permit(
  principal,
  action == Action::"MemoryWrite",
  resource
) when {
  ["InstructionMemory", "GoalMemory"].contains(resource.resource_class) &&
  context.action_provenance == "trusted" &&
  context.authority_status == "present" &&
  context.approval_present_for_this_action == true
};

// Untrusted write to FactMemory -> transform (strip untrusted content, mark provenance).
@id("transform:strip_untrusted_mark_provenance")
forbid(
  principal,
  action == Action::"MemoryWrite",
  resource
) when {
  resource.resource_class == "FactMemory" &&
  context.action_provenance == "untrusted"
};

// Legitimate twin: trusted or validated write to FactMemory, authority present -> ALLOW.
permit(
  principal,
  action == Action::"MemoryWrite",
  resource
) when {
  resource.resource_class == "FactMemory" &&
  (context.action_provenance == "trusted" || context.action_provenance == "validated") &&
  context.authority_status == "present"
};

// EphemeralMemory is scratch space -> always ALLOW.
permit(
  principal,
  action == Action::"MemoryWrite",
  resource
) when {
  resource.resource_class == "EphemeralMemory"
};