package authz

# =============================================================================
# OPA/Rego Policy Template: Zero Trust Access Control
# =============================================================================
# This template implements Zero Trust principles per NIST SP 800-207:
# - Tenet 3: Per-session access (short-lived, re-evaluated)
# - Tenet 4: Dynamic policy (context-aware)
# - Tenet 6: Dynamic authentication/authorization
#
# Usage:
# 1. Customize the `input` schema for your environment
# 2. Replace placeholder rules with your business logic
# 3. Add test cases in `_test.rego` file
# 4. Deploy via OPA/Gatekeeper/Envoy/Istio
# =============================================================================

default allow = false

# -----------------------------------------------------------------------------
# Main Decision Rules
# -----------------------------------------------------------------------------

# Allow access if all conditions met
allow if {
	# 1. Identity verified
	identity_verified
	
	# 2. Device compliant
	device_compliant
	
	# 3. Context authorizes action
	context_authorizes
	
	# 4. Resource permits access
	resource_permits
	
	# 5. Session valid (recent auth)
	session_valid
	
	# 6. No explicit deny
	not explicit_deny
}

# Every reason that applies is reported; allow requires none of them
deny contains msg if {
	some reason in deny_reasons
	msg := sprintf("Access denied: %v", [reason])
}

# -----------------------------------------------------------------------------
# Identity Verification (Tenet 3, 6)
# -----------------------------------------------------------------------------

identity_verified if {
	input.user != {}
	input.user.authenticated == true
	input.user.mfa_verified == true
	
	# Phishing-resistant MFA required for sensitive resources
	mfa_satisfies_resource
	
	# User not suspended/locked
	not input.user.suspended
	not input.user.locked
}

phishing_resistant_mfa if {
	# FIDO2/WebAuthn, passkeys, or certificate-based
	input.user.mfa_method in {"fido2", "passkey", "certificate"}
}

# Sensitive resources additionally require FIDO2 specifically
mfa_satisfies_resource if {
	not requires_fido2
	phishing_resistant_mfa
}

mfa_satisfies_resource if {
	requires_fido2
	input.user.mfa_method == "fido2"
}

requires_fido2 if {
	input.resource.classification in {"restricted", "top_secret"}
}

requires_fido2 if {
	input.action in {"delete", "admin"}
}

# -----------------------------------------------------------------------------
# Device Compliance (Tenet 1, 2, 5)
# -----------------------------------------------------------------------------

device_compliant if {
	input.device != {}
	
	# Device is managed by MDM
	input.device.managed == true
	
	# Disk encryption enabled
	input.device.encrypted == true
	
	# OS version meets minimum
	os_version_compliant
	
	# EDR/AV running and healthy
	edr_healthy
	
	# Firewall enabled
	input.device.firewall_enabled == true
	
	# Auto-updates enabled
	input.device.auto_updates == true
	
	# Posture score above threshold
	input.device.posture_score >= 70
	
	# Device certificate valid (if applicable)
	certificate_valid
}

os_version_compliant if {
	min_version := minimum_os_version[input.device.os]
	semver.compare(input.device.os_version, min_version) >= 0
}

minimum_os_version := {
	"macos": "13.0.0",
	"windows": "11.0.0",
	"linux": "5.15.0",
	"ios": "16.0.0",
	"android": "13.0.0"
}

edr_healthy if {
	input.device.edr != ""
	input.device.edr_status == "healthy"
	input.device.edr_last_scan > time.now_ns() - 86400000000000  # 24 hours
}

certificate_valid if {
	not input.device.certificate_required
}

certificate_valid if {
	input.device.certificate_valid == true
	input.device.certificate_expiry > time.now_ns()
}

# -----------------------------------------------------------------------------
# Context Authorization (Tenet 4)
# -----------------------------------------------------------------------------

context_authorizes if {
	# Time-based restrictions
	time_authorized
	
	# Location/network restrictions
	location_authorized
	
	# Risk-based (adaptive)
	risk_acceptable
	
	# Role/permission check
	role_authorized
}

time_authorized if {
	not sensitive_action
}

time_authorized if {
	business_hours
}

business_hours if {
	hour := time.clock(time.now_ns())[0]
	hour >= 6
	hour <= 22
	# Could add timezone awareness: input.context.timezone
}

sensitive_action if {
	input.action in {"delete", "admin"}
}

sensitive_action if {
	input.resource.classification in {"restricted", "top_secret"}
}

location_authorized if {
	# Allow from corporate networks
	input.context.network in {"corporate", "vpc"}

	# Allow from approved countries
	approved_country

	# Deny from high-risk (TOR, VPN, proxy)
	not high_risk_network
}

approved_country if {
	input.context.country in ["US", "CA", "GB", "DE", "JP", "AU"]
	# Customize for your organization
}

high_risk_network if {
	input.context.network_type in ["tor", "vpn", "proxy", "hosting"]
	# Could integrate with threat intel feeds
}

risk_acceptable if {
	# User risk score
	input.context.user_risk_score <= 70
	
	# Sign-in risk
	input.context.signin_risk in ["low", "medium"]
	
	# Device risk
	input.context.device_risk_score <= 60
}

role_authorized if {
	# RBAC: user has required role for resource/action
	required_role := role_requirements[input.resource.type][input.action]
	input.user.roles[_] == required_role
	
	# ABAC: attribute-based conditions
	abac_conditions_met
}

role_requirements := {
	"database": {
		"read": "db_reader",
		"write": "db_writer",
		"admin": "db_admin"
	},
	"api": {
		"read": "api_user",
		"write": "api_developer",
		"admin": "api_admin"
	},
	"kubernetes": {
		"read": "k8s_viewer",
		"write": "k8s_developer",
		"admin": "k8s_admin"
	},
	"storage": {
		"read": "storage_reader",
		"write": "storage_writer",
		"admin": "storage_admin"
	}
}

# Each condition is "not applicable, or satisfied"
abac_conditions_met if {
	on_call_ok
	finance_ok
	residency_ok
}

on_call_ok if {
	not production_write
}

on_call_ok if {
	on_call
}

finance_ok if {
	not finance_data
}

finance_ok if {
	manager_approved
}

residency_ok if {
	not eu_data
}

residency_ok if {
	eu_resident
}

production_write if {
	input.resource.environment == "production"
	input.action in ["write", "delete", "admin"]
}

on_call if {
	input.user.on_call == true
	input.user.on_call_end > time.now_ns() / 1000000000
}

finance_data if {
	input.resource.tags[_] == "finance"
}

manager_approved if {
	input.context.manager_approval == true
	input.context.approval_expiry > time.now_ns() / 1000000000
}

eu_data if {
	input.resource.region == "eu"
}

eu_resident if {
	input.user.residency == "eu"
}

# -----------------------------------------------------------------------------
# Resource Permissions (Tenet 1, 4)
# -----------------------------------------------------------------------------

resource_permits if {
	# Resource exists and is active
	input.resource.active == true
	
	# Classification allows access level
	classification_permits
	
	# Resource-specific policies
	resource_policy_allows
}

classification_permits if {
	# Clearance dominates classification
	user_clearance := clearance_level[input.user.clearance]
	resource_classification := clearance_level[input.resource.classification]
	user_clearance >= resource_classification
}

clearance_level := {
	"public": 0,
	"internal": 1,
	"confidential": 2,
	"restricted": 3,
	"top_secret": 4
}

resource_policy_allows if {
	# Resource-specific allow rule, if one is populated for this resource and action
	object.get(object.get(resource_allow_rules, input.resource.id, {}), input.action, false) == true
}

resource_policy_allows if {
	# No resource-specific rule exists; role-based checks decide
	object.get(resource_allow_rules, input.resource.id, null) == null
}

# Resource-specific allow rules (populated from external data)
resource_allow_rules := {}  # Populated via OPA Bundle/REST

# -----------------------------------------------------------------------------
# Session Validation (Tenet 3)
# -----------------------------------------------------------------------------

session_valid if {
	# Session not expired
	input.session.expires_at > time.now_ns() / 1000000000
	
	# Session not revoked
	not input.session.revoked
	
	# Re-authentication within bounds for sensitive actions
	reauth_within_bounds
}

reauth_within_bounds if {
	not requires_reauth
}

reauth_within_bounds if {
	input.session.last_auth < time.now_ns() / 1000000000 - 300  # 5 min
}

requires_reauth if {
	input.action in {"delete", "admin", "privileged"}
}

requires_reauth if {
	input.resource.classification in {"restricted", "top_secret"}
}

# -----------------------------------------------------------------------------
# Explicit Deny Rules (Tenet 4, 6)
# -----------------------------------------------------------------------------

explicit_deny if {
	# Compromised credentials
	input.context.compromised_credentials == true
}

explicit_deny if {
	# Device revoked/compromised
	input.device.revoked == true
}

explicit_deny if {
	# User explicitly denied (break-glass, legal hold)
	input.user.deny_list[_] == input.resource.id
}

explicit_deny if {
	# Geographic sanction
	sanctioned_country
}

sanctioned_country if {
	input.context.country in ["KP", "IR", "SY", "CU", "RU"]
	# Update per OFAC/regulatory requirements
}

deny_reasons contains "Explicit deny" if {
	explicit_deny
}

deny_reasons contains "MFA not phishing-resistant" if {
	not mfa_satisfies_resource
}

deny_reasons contains "Device non-compliant" if {
	not device_compliant
}

deny_reasons contains "Outside business hours" if {
	not time_authorized
}

deny_reasons contains "High-risk network" if {
	not location_authorized
}

deny_reasons contains "Risk score too high" if {
	not risk_acceptable
}

deny_reasons contains "Insufficient role/permissions" if {
	not role_authorized
}

deny_reasons contains "Classification mismatch" if {
	not classification_permits
}

deny_reasons contains "Session expired or revoked" if {
	not session_valid
}

deny_reasons contains "Sanctioned country" if {
	sanctioned_country
}

# -----------------------------------------------------------------------------
# Obligations (Additional requirements on allow)
# -----------------------------------------------------------------------------

obligations contains obligation if {
	allow
	
	# Log all access
	obligation := {"type": "audit_log", "level": "info"}
}

obligations contains obligation if {
	allow
	sensitive_action
	
	# Enhanced logging for sensitive actions
	obligation := {"type": "audit_log", "level": "detailed", "include": ["input", "decision"]}
}

obligations contains obligation if {
	allow
	input.context.user_risk_score > 50
	
	# Step-up authentication for medium risk
	obligation := {"type": "step_up_auth", "method": "push"}
}

# -----------------------------------------------------------------------------
# External Data (Loaded via OPA Bundle or REST)
# -----------------------------------------------------------------------------

# These would be populated from external sources:
# - user_roles: mapping user -> roles
# - device_inventory: device_id -> posture
# - threat_intel: IP -> reputation
# - resource_catalog: resource_id -> metadata
# - on_call_schedule: user -> on_call_window

# Example external data structure:
# {
#   "user_roles": { "user-123": ["engineer", "on-call"] },
#   "device_inventory": { "device-456": {"posture_score": 95, "managed": true} },
#   "threat_intel": { "1.2.3.4": "malicious" },
#   "resource_catalog": { "prod-db-01": {"classification": "confidential", "environment": "production"} }
# }

# =============================================================================
# END OF TEMPLATE
# =============================================================================