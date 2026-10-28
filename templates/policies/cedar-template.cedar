// =============================================================================
// Cedar policy template: JIT access to production databases (Zero Trust)
// NIST SP 800-207 tenets: 3 (per-session), 4 (dynamic policy), 6 (dynamic authN/authZ)
//
// Schema: cedar-schema.cedarschema (declares every attribute used here)
// Test:   cedar authorize --schema cedar-schema.cedarschema --policies cedar-template.cedar \
//           --entities <entities.json> --principal ... --action ... --resource ... --context ...
// =============================================================================

// Forbid rules always win over permit rules in Cedar.

// Deny: revoked devices, compromised credentials, and explicitly denied resources
@id("deny-revoked-device")
forbid (principal, action, resource)
when { principal.device.revoked };

@id("deny-compromised-credentials")
forbid (principal, action, resource)
when { context.compromisedCredentials };

@id("deny-user-deny-list")
forbid (principal, action, resource)
when { principal.denyList.contains(resource.name) };

// Permit: engineers in the on-call group, inside their shift, with fresh phishing-resistant MFA,
// a compliant device, acceptable risk, and an approved network or country.
@id("permit-oncall-prod-db")
permit (principal, action == ZeroTrust::Action::"connect", resource)
when {
  principal.role == "engineer" &&
  principal.groups.contains("on-call") &&
  principal.onCallStart <= context.now &&
  context.now <= principal.onCallEnd &&
  principal.mfaVerified &&
  (principal.mfaMethod == "fido2" || principal.mfaMethod == "push") &&
  context.now - principal.mfaTime <= 3600 &&
  principal.device.managed &&
  principal.device.encrypted &&
  principal.device.edrRunning &&
  principal.device.postureScore >= 70 &&
  principal.riskScore <= 70 &&
  resource.environment == "production" &&
  (context.network == "corporate" || ["US", "CA", "GB", "DE"].contains(context.country))
};
