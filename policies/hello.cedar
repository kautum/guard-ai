permit(
  principal,
  action == Action::"ReadFile",
  resource
) when {
  resource.sensitivity == "public"
};