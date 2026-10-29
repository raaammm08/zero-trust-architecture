package jit.db

# =============================================================================
# JIT database access policy (production DBs)
# NIST SP 800-207 tenets: 3 (per-session), 4 (dynamic policy), 6 (dynamic authN/authZ)
# Tenet 5 (posture) via device checks; tenet 7 via obligations (audit logging).
# =============================================================================

default allow := false

# Allow only when every helper holds and nothing is denied
allow if {
	count(deny) == 0
	identity_verified
	device_compliant
	location_authorized
	time_authorized
	on_call
	risk_acceptable
}

# Explicit, auditable deny reasons (tenet 4)
deny contains "MFA missing, stale, or not phishing-resistant" if {
	not identity_verified
}

deny contains "Device not managed, encrypted, or EDR not running" if {
	not device_compliant
}

deny contains "Location not corporate network or approved country" if {
	not location_authorized
}

deny contains "Outside on-call shift window" if {
	not time_authorized
}

deny contains "User is not an engineer in the on-call group" if {
	not on_call
}

deny contains "Risk score above threshold" if {
	not risk_acceptable
}

# -----------------------------------------------------------------------------
# Helper rules
# -----------------------------------------------------------------------------

# MFA verified within the last hour, using a phishing-resistant method (tenet 6)
identity_verified if {
	input.user.mfa_verified == true
	input.user.mfa_method in {"fido2", "push"}
	input.context.now - input.user.mfa_time <= 3600
}

device_compliant if {
	input.device.managed == true
	input.device.encrypted == true
	input.device.edr_running == true
}

location_authorized if {
	input.context.network == "corporate"
}

location_authorized if {
	input.context.country in approved_countries
}

approved_countries := {"US", "CA", "GB", "DE"}

time_authorized if {
	input.context.now >= input.user.on_call_start
	input.context.now <= input.user.on_call_end
}

on_call if {
	input.user.role == "engineer"
	some group in input.user.groups
	group == "on-call"
}

risk_acceptable if {
	input.user.risk_score <= 70
	input.device.risk_score <= 60
}

# Obligations: every decision is logged with full context (tenet 7)
obligations := [{
	"type": "audit_log",
	"fields": ["user.id", "device.id", "resource", "context.now", "context.network", "context.country", "decision"],
}]
