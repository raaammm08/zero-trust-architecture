// =============================================================================
// AWS Cedar Policy Template: Zero Trust Access Control
// =============================================================================
// This template implements Zero Trust principles per NIST SP 800-207 using
// Cedar's entity-based, typed policy model.
// 
// Usage:
// 1. Define your entity schema in schema.json
// 2. Customize policies for your resources/actions
// 3. Create entities.json with your runtime data
// 4. Test with `cedar authorize`
// 5. Deploy to Verified Permissions or Cedar-enabled service
// =============================================================================

// -----------------------------------------------------------------------------
// Entity Type Definitions (matching schema.json)
// -----------------------------------------------------------------------------

// entity User {
//   uid: String,
//   email: String,
//   groups: Set<String>,
//   roles: Set<String>,
//   clearance: ClearanceLevel,
//   mfaVerified: Boolean,
//   mfaMethod: MfaMethod,
//   device: Device,
//   onCallSchedule: OnCallSchedule?,
//   suspended: Boolean,
//   locked: Boolean,
//   residency: String,
//   denyList: Set<String>
// }

// entity Device {
//   uid: String,
//   managed: Boolean,
//   encrypted: Boolean,
//   os: String,
//   osVersion: String,
//   firewallEnabled: Boolean,
//   autoUpdates: Boolean,
//   edr: String,
//   edrStatus: String,
//   edrLastScan: Long,
//   postureScore: Long,
//   certificateRequired: Boolean,
//   certificateValid: Boolean,
//   certificateExpiry: Long,
//   revoked: Boolean
// }

// entity Resource {
//   uid: String,
//   type: ResourceType,
//   classification: ClearanceLevel,
//   environment: Environment,
//   region: String,
//   tags: Set<String>,
//   active: Boolean,
//   owner: String
// }

// entity Context {
//   currentTime: Long,
//   requestId: String,
//   sourceIp: String,
//   network: String,
//   networkType: String,
//   country: String,
//   timezone: String,
//   userRiskScore: Long,
//   signinRisk: RiskLevel,
//   deviceRiskScore: Long,
//   compromisedCredentials: Boolean,
//   managerApproval: Boolean,
//   approvalExpiry: Long
// }

// entity OnCallSchedule {
//   start: Long,
//   end: Long
// }

// -----------------------------------------------------------------------------
// Enum Definitions
// -----------------------------------------------------------------------------

enum ClearanceLevel {
  PUBLIC,
  INTERNAL,
  CONFIDENTIAL,
  RESTRICTED,
  TOP_SECRET
}

enum MfaMethod {
  FIDO2,
  PASSKEY,
  CERTIFICATE,
  PUSH,
  TOTP,
  SMS,
  NONE
}

enum ResourceType {
  DATABASE,
  API,
  KUBERNETES,
  STORAGE,
  SAAS,
  LEGACY_APP
}

enum Environment {
  DEVELOPMENT,
  STAGING,
  PRODUCTION,
  DISASTER_RECOVERY
}

enum RiskLevel {
  LOW,
  MEDIUM,
  HIGH,
  CRITICAL
}

enum Action {
  READ,
  WRITE,
  DELETE,
  ADMIN,
  ASSUME_ROLE
}

// -----------------------------------------------------------------------------
// Helper Functions (Cedar doesn't have functions, use inline logic)
// -----------------------------------------------------------------------------

// Clearance dominance: user_clearance >= resource_classification
// clearance_rank(PUBLIC) = 0
// clearance_rank(INTERNAL) = 1
// clearance_rank(CONFIDENTIAL) = 2
// clearance_rank(RESTRICTED) = 3
// clearance_rank(TOP_SECRET) = 4

// -----------------------------------------------------------------------------
// Main Policies
// -----------------------------------------------------------------------------

// =============================================================================
// PERMIT: Standard user access to resources
// =============================================================================
permit (
  principal: User,
  action: Action,
  resource: Resource
) when {
  // Identity verified (Tenet 3, 6)
  principal.authenticated == true &&
  principal.mfaVerified == true &&
  principal.suspended == false &&
  principal.locked == false &&
  
  // Phishing-resistant MFA for sensitive resources (Tenet 6)
  (principal.mfaMethod == MfaMethod::FIDO2 ||
   principal.mfaMethod == MfaMethod::PASSKEY ||
   principal.mfaMethod == MfaMethod::CERTIFICATE ||
   !(resource.classification == ClearanceLevel::RESTRICTED ||
     resource.classification == ClearanceLevel::TOP_SECRET ||
     action == Action::DELETE ||
     action == Action::ADMIN) ||
   principal.mfaMethod == MfaMethod::FIDO2) &&
  
  // Device compliant (Tenet 1, 2, 5)
  principal.device.managed == true &&
  principal.device.encrypted == true &&
  principal.device.firewallEnabled == true &&
  principal.device.autoUpdates == true &&
  principal.device.edrStatus == "healthy" &&
  principal.device.postureScore >= 70 &&
  (principal.device.certificateRequired == false ||
   (principal.device.certificateValid == true &&
    principal.device.certificateExpiry > context.currentTime)) &&
  principal.device.revoked == false &&
  
  // OS version compliant
  (principal.device.os == "macos" && principal.device.osVersion >= "13.0" ||
   principal.device.os == "windows" && principal.device.osVersion >= "11.0" ||
   principal.device.os == "linux" && principal.device.osVersion >= "5.15" ||
   principal.device.os == "ios" && principal.device.osVersion >= "16.0" ||
   principal.device.os == "android" && principal.device.osVersion >= "13.0") &&
  
  // EDR recent scan (within 24 hours)
  principal.device.edrLastScan > context.currentTime - 86400 &&
  
  // Context authorization (Tenet 4)
  // Time-based: business hours for sensitive actions
  !(action == Action::DELETE || action == Action::ADMIN ||
    resource.classification == ClearanceLevel::RESTRICTED ||
    resource.classification == ClearanceLevel::TOP_SECRET ||
    resource.environment == Environment::PRODUCTION && action in [Action::WRITE, Action::DELETE, Action::ADMIN]) ||
  (context.currentTime.hour() >= 6 && context.currentTime.hour() <= 22) &&
  
  // Location/network: approved, not high-risk
  (context.network in ["corporate", "vpc"] ||
   context.country in ["US", "CA", "GB", "DE", "JP", "AU"]) &&
  context.networkType not in ["tor", "vpn", "proxy", "hosting"] &&
  
  // Risk-based: acceptable scores
  context.userRiskScore <= 70 &&
  context.signinRisk in [RiskLevel::LOW, RiskLevel::MEDIUM] &&
  context.deviceRiskScore <= 60 &&
  
  // Role-based access control
  (action == Action::READ && principal.hasRole("reader") ||
   action == Action::WRITE && principal.hasRole("writer") ||
   action == Action::DELETE && principal.hasRole("admin") ||
   action == Action::ADMIN && principal.hasRole("admin")) &&
  
  // ABAC: Attribute-based conditions
  // On-call required for production writes
  !(resource.environment == Environment::PRODUCTION &&
    action in [Action::WRITE, Action::DELETE, Action::ADMIN]) ||
  (principal.onCallSchedule?.start <= context.currentTime &&
   principal.onCallSchedule?.end >= context.currentTime) &&
  
  // Manager approval for finance data
  !("finance" in resource.tags) ||
  (context.managerApproval == true &&
   context.approvalExpiry > context.currentTime) &&
  
  // Data residency
  !(resource.region == "eu") ||
  principal.residency == "eu" &&
  
  // Resource permits (Tenet 1, 4)
  resource.active == true &&
  // Clearance dominates classification
  clearance_rank(principal.clearance) >= clearance_rank(resource.classification) &&
  
  // No explicit deny
  context.compromisedCredentials == false &&
  !(resource.uid in principal.denyList) &&
  context.country not in ["KP", "IR", "SY", "CU", "RU"] &&
  
  // Session valid (Tenet 3)
  // (Session validation would be in context or separate entity)
  true
};

// =============================================================================
// PERMIT: On-call engineer elevated access
// =============================================================================
permit (
  principal: User,
  action: Action,
  resource: Resource
) when {
  principal.hasRole("on-call-engineer") &&
  principal.onCallSchedule?.start <= context.currentTime &&
  principal.onCallSchedule?.end >= context.currentTime &&
  principal.mfaVerified == true &&
  principal.mfaMethod in [MfaMethod::FIDO2, MfaMethod::PASSKEY, MfaMethod::CERTIFICATE] &&
  resource.environment == Environment::PRODUCTION &&
  action in [Action::READ, Action::WRITE] &&
  principal.device.postureScore >= 85 &&
  context.userRiskScore <= 50
};

// =============================================================================
// PERMIT: Break-glass / emergency access
// =============================================================================
permit (
  principal: User,
  action: Action,
  resource: Resource
) when {
  principal.hasRole("break-glass") &&
  context.managerApproval == true &&
  context.approvalExpiry > context.currentTime &&
  principal.mfaVerified == true &&
  // Break-glass requires FIDO2
  principal.mfaMethod == MfaMethod::FIDO2 &&
  // Audit obligation enforced by caller
  true
};

// =============================================================================
// PERMIT: Service-to-service (workload identity)
// =============================================================================
permit (
  principal: Workload,
  action: Action,
  resource: Resource
) when {
  principal.spiffeId != "" &&
  principal.trustDomain == "company.internal" &&
  principal.certificateExpiry > context.currentTime &&
  // Workload-specific policy: allow based on SPIFFE ID pattern
  principal.spiffeId.matches("spiffe://company.internal/ns/production/sa/*") &&
  action == Action::READ &&
  resource.type == ResourceType::DATABASE
};

// =============================================================================
// FORBID: Explicit denials (take precedence over permit)
// =============================================================================

// Compromised credentials - immediate block
forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  context.compromisedCredentials == true
};

// Revoked/compromised device
forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  principal.device.revoked == true
};

// Sanctioned countries
forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  context.country in ["KP", "IR", "SY", "CU", "RU"]
};

// User explicitly denied for resource
forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  resource.uid in principal.denyList
};

// High-risk sign-in without step-up
forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  context.signinRisk == RiskLevel::HIGH &&
  action in [Action::WRITE, Action::DELETE, Action::ADMIN]
};

// Production delete without on-call + manager approval
forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  resource.environment == Environment::PRODUCTION &&
  action == Action::DELETE &&
  !(principal.hasRole("on-call-engineer") &&
    principal.onCallSchedule?.start <= context.currentTime &&
    principal.onCallSchedule?.end >= context.currentTime &&
    context.managerApproval == true)
};

// =============================================================================
// Role Definitions (for hasRole() extension)
// =============================================================================

// These would be implemented as Cedar extensions or computed attributes
// Example entity attributes that enable hasRole():
// principal.roles contains "db_reader" -> hasRole("reader") for DATABASE
// principal.roles contains "db_writer" -> hasRole("writer") for DATABASE
// principal.roles contains "db_admin" -> hasRole("admin") for DATABASE

// =============================================================================
// Context Extensions (for use in policies)
// =============================================================================

// context.currentTime.hour() - extract hour from timestamp
// context.currentTime - Unix timestamp in seconds
// clearance_rank(ClearanceLevel) - custom extension for comparison

// =============================================================================
// END OF TEMPLATE
// =============================================================================