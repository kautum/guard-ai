// ============================================================
// D9-CORE — the authority_status switch (spec Part 3.1)
// Single source of truth for authority_status -> decision.
// @id encodes "remediation:reason" so the Python wrapper can
// read it via diagnostics.id_annotations_by_reason.
// ============================================================

permit(
  principal,
  action,
  resource
) when {
  context.authority_requirement == "implicit_sufficient" &&
  !(context.untrusted_influence && context.high_impact)
};

permit(
  principal,
  action,
  resource
) when {
  (context.authority_requirement == "explicit_required" ||
   context.authority_requirement == "explicit_required_per_instance") &&
  context.authority_status == "present" &&
  !(context.authority_requirement == "explicit_required_per_instance" && !context.approval_present_for_this_action) &&
  !(context.is_irreversible && !context.approval_present_for_this_action)
};

@id("escalate:per_instance_approval_missing")
forbid(
  principal,
  action,
  resource
) when {
  context.authority_status == "present" &&
  context.authority_requirement == "explicit_required_per_instance" &&
  !context.approval_present_for_this_action
};

@id("escalate:irreversible_unapproved")
forbid(
  principal,
  action,
  resource
) when {
  context.authority_status == "present" &&
  context.is_irreversible &&
  !context.approval_present_for_this_action
};

@id("none:no_authority")
forbid(
  principal,
  action,
  resource
) when {
  context.authority_status == "absent" &&
  (context.authority_requirement == "explicit_required" ||
   context.authority_requirement == "explicit_required_per_instance")
};

@id("escalate:authority_lapsed")
forbid(
  principal,
  action,
  resource
) when {
  (context.authority_status == "revoked" || context.authority_status == "expired") &&
  (context.authority_requirement == "explicit_required" ||
   context.authority_requirement == "explicit_required_per_instance")
};

@id("transform:partial_authority_transformable")
forbid(
  principal,
  action,
  resource
) when {
  context.authority_status == "partial" &&
  context.applicable_transform_recipe != "" &&
  (context.authority_requirement == "explicit_required" ||
   context.authority_requirement == "explicit_required_per_instance")
};

@id("escalate:partial_authority_no_recipe")
forbid(
  principal,
  action,
  resource
) when {
  context.authority_status == "partial" &&
  context.applicable_transform_recipe == "" &&
  (context.authority_requirement == "explicit_required" ||
   context.authority_requirement == "explicit_required_per_instance")
};

@id("escalate:conflicting_authority")
forbid(
  principal,
  action,
  resource
) when {
  context.authority_status == "conflicting" &&
  (context.authority_requirement == "explicit_required" ||
   context.authority_requirement == "explicit_required_per_instance")
};