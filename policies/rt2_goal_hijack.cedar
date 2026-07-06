// ============================================================
// RT2 — Command Execution / Goal Hijack (Part 6)
// Load-bearing field: context.intent_alignment
// VF minimum break: node 3 — proposed_action.intent_alignment == original_user_task
// ============================================================

@id("none:goal_hijack")
forbid(
  principal,
  action in [Action::"Execute", Action::"Install", Action::"Delegate",
             Action::"Send", Action::"Publish"],
  resource
) when {
  context.intent_alignment == "shifted" &&
  context.untrusted_influence == true
};

@id("escalate:intent_ambiguous")
forbid(
  principal,
  action in [Action::"Execute", Action::"Install", Action::"Delegate",
             Action::"Send", Action::"Publish"],
  resource
) when {
  context.intent_alignment == "ambiguous"
};

// Legitimate twin: same action, aligned with original task, authority present -> ALLOW.
permit(
  principal,
  action in [Action::"Execute", Action::"Install", Action::"Delegate",
             Action::"Send", Action::"Publish"],
  resource
) when {
  context.intent_alignment == "original_user_task" &&
  context.authority_status == "present"
};

// Legitimate twin: reading/summarizing hostile content is fine as long as the
// action does not serve the injected goal (abuse triage) -> ALLOW.
permit(
  principal,
  action in [Action::"Read"],
  resource
) when {
  context.intent_alignment != "shifted"
};