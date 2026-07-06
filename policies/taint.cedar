// ============================================================
// TAINT-4 — Lethal Trifecta (Part 5)
// If untrusted influence touches a high-sensitivity resource
// AND the recipient isn't authorized to receive it -> hard deny.
// TAINT-1/2/3 (provenance assignment/propagation/declassification)
// are runtime computations, not Cedar rules — they produce the
// untrusted_influence/resource_sensitivity/recipient_is_authorized
// values Cedar reads here.
// ============================================================

@id("none:lethal_trifecta")
forbid(
  principal,
  action,
  resource
) when {
  context.untrusted_influence == true &&
  (context.resource_sensitivity == "CRITICAL" || context.resource_sensitivity == "HIGH") &&
  context.recipient_is_authorized == false
};