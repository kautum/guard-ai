// ============================================================
// RT5 — Supply Chain Compromise (Part 6)
// SPEC DEVIATION FLAG: Part 6.5 specifies source_attestation and
// integrity_hash as STRUCTURED records (registry_url, signature, timestamp,
// verified/match derived fields) specifically because flat booleans here are
// trivially spoofed at generation time. Schema does not yet model these as
// records — using flat booleans as an interim stopgap, same as
// DEPTH_CEILING in RT4. Needs schema fix (proper SourceAttestation /
// IntegrityHash record types) before production build. Flag for
// Arvinth/Kautum sign-off.
//
// Load-bearing fields (stopgap): context.source_attestation_verified,
// context.integrity_hash_match
// VF minimum break: nodes 2 AND 3 simultaneously — a single-node break
// (verified source without integrity evidence) does NOT prevent the harm chain.
// ============================================================

@id("none:supply_chain_integrity")
forbid(
  principal,
  action == Action::"Install",
  resource
) when {
  resource.resource_class == "Dependency" &&
  !(context.source_attestation_verified && context.integrity_hash_match)
};

// Legitimate twin: verified attestation, matching integrity hash, authority
// present, fresh per-instance approval (Install is IRREVERSIBLEEFFECTS, PI
// tier, 1.8) -> ALLOW.
permit(
  principal,
  action == Action::"Install",
  resource
) when {
  resource.resource_class == "Dependency" &&
  context.source_attestation_verified &&
  context.integrity_hash_match &&
  context.authority_status == "present" &&
  context.approval_present_for_this_action == true
};