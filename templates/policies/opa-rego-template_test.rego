package authz_test

import data.authz

# Fixed clock for repeatable tests: 2027-01-15 08:00:00 UTC (inside business hours).
now_s := 1800000000

now_ns := now_s * 1000000000

base_input := {
	"action": "read",
	"user": {
		"authenticated": true,
		"mfa_verified": true,
		"mfa_method": "fido2",
		"roles": ["db_reader"],
		"clearance": "confidential",
	},
	"device": {
		"managed": true,
		"encrypted": true,
		"os": "macos",
		"os_version": "14.0.0",
		"edr": "example-edr",
		"edr_status": "healthy",
		"edr_last_scan": now_ns - 3600000000000,
		"firewall_enabled": true,
		"auto_updates": true,
		"posture_score": 90,
		"certificate_required": false,
	},
	"context": {
		"network": "corporate",
		"network_type": "direct",
		"country": "US",
		"user_risk_score": 10,
		"signin_risk": "low",
		"device_risk_score": 10,
	},
	"resource": {
		"id": "db-1",
		"type": "database",
		"classification": "confidential",
		"environment": "staging",
		"region": "us",
		"active": true,
		"tags": [],
	},
	"session": {
		"expires_at": now_s + 3600,
		"revoked": false,
		"last_auth": now_s - 60,
	},
}

# Admin action by a db_admin who re-authenticated 60 seconds ago.
admin_input := object.union(base_input, {
	"action": "admin",
	"user": object.union(base_input.user, {"roles": ["db_admin"]}),
})

test_compliant_request_allowed if {
	authz.allow with input as base_input with time.now_ns as now_ns
}

test_compliant_request_has_no_deny_reasons if {
	count(authz.deny) == 0 with input as base_input with time.now_ns as now_ns
}

test_push_mfa_denied if {
	req := object.union(base_input, {"user": object.union(base_input.user, {"mfa_method": "push"})})
	not authz.allow with input as req with time.now_ns as now_ns
	"Access denied: MFA not phishing-resistant" in authz.deny with input as req with time.now_ns as now_ns
}

test_unmanaged_device_denied if {
	req := object.union(base_input, {"device": object.union(base_input.device, {"managed": false})})
	not authz.allow with input as req with time.now_ns as now_ns
	"Access denied: Device non-compliant" in authz.deny with input as req with time.now_ns as now_ns
}

test_missing_role_denied if {
	req := object.union(base_input, {"user": object.union(base_input.user, {"roles": ["api_user"]})})
	not authz.allow with input as req with time.now_ns as now_ns
}

test_clearance_below_classification_denied if {
	req := object.union(base_input, {"user": object.union(base_input.user, {"clearance": "internal"})})
	not authz.allow with input as req with time.now_ns as now_ns
	"Access denied: Classification mismatch" in authz.deny with input as req with time.now_ns as now_ns
}

test_sanctioned_country_denied if {
	req := object.union(base_input, {"context": object.union(base_input.context, {"country": "KP"})})
	not authz.allow with input as req with time.now_ns as now_ns
	"Access denied: Sanctioned country" in authz.deny with input as req with time.now_ns as now_ns
}

test_compromised_credentials_denied if {
	req := object.union(base_input, {"context": object.union(base_input.context, {"compromised_credentials": true})})
	not authz.allow with input as req with time.now_ns as now_ns
	"Access denied: Explicit deny" in authz.deny with input as req with time.now_ns as now_ns
}

test_expired_session_denied if {
	req := object.union(base_input, {"session": object.union(base_input.session, {"expires_at": now_s - 1})})
	not authz.allow with input as req with time.now_ns as now_ns
	"Access denied: Session expired or revoked" in authz.deny with input as req with time.now_ns as now_ns
}

test_admin_with_recent_reauth_allowed if {
	authz.allow with input as admin_input with time.now_ns as now_ns
}

test_admin_with_stale_auth_denied if {
	req := object.union(admin_input, {"session": object.union(admin_input.session, {"last_auth": now_s - 3600})})
	not authz.allow with input as req with time.now_ns as now_ns
}

test_admin_outside_business_hours_denied if {
	# 02:00 UTC on the same day
	not authz.allow with input as admin_input with time.now_ns as now_ns - ((6 * 3600) * 1000000000)
}

test_production_write_requires_on_call if {
	req := object.union(base_input, {
		"action": "write",
		"user": object.union(base_input.user, {"roles": ["db_writer"]}),
		"resource": object.union(base_input.resource, {"environment": "production"}),
	})
	not authz.allow with input as req with time.now_ns as now_ns
}

test_production_write_allowed_while_on_call if {
	req := object.union(base_input, {
		"action": "write",
		"user": object.union(base_input.user, {
			"roles": ["db_writer"],
			"on_call": true,
			"on_call_end": now_s + 3600,
		}),
		"resource": object.union(base_input.resource, {"environment": "production"}),
	})
	authz.allow with input as req with time.now_ns as now_ns
}

test_allowed_request_gets_audit_obligation if {
	{"type": "audit_log", "level": "info"} in authz.obligations with input as base_input with time.now_ns as now_ns
}
