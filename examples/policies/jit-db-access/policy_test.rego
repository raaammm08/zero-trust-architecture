package jit.db_test

import data.jit.db

# Fixed clock: unix seconds
now := 1793448000

base_user := {
	"id": "u1",
	"role": "engineer",
	"groups": ["on-call"],
	"mfa_verified": true,
	"mfa_method": "fido2",
	"mfa_time": now - 600,
	"on_call_start": now - 3600,
	"on_call_end": now + 3600,
	"risk_score": 20,
}

base_device := {
	"id": "d1",
	"managed": true,
	"encrypted": true,
	"edr_running": true,
	"risk_score": 10,
}

base_context := {"now": now, "network": "corporate", "country": "US"}

# Positive: on-call engineer, compliant device
test_oncall_compliant_allowed if {
	db.allow with input as {"user": base_user, "device": base_device, "context": base_context}
}

# Negative: off-call engineer
test_offcall_denied if {
	not db.allow with input as {"user": object.union(base_user, {"on_call_end": now - 60}), "device": base_device, "context": base_context}
}

# Negative: non-engineer in on-call group
test_nonengineer_denied if {
	not db.allow with input as {"user": object.union(base_user, {"role": "analyst"}), "device": base_device, "context": base_context}
}

# Negative: non-compliant device (EDR off)
test_noncompliant_device_denied if {
	not db.allow with input as {"user": base_user, "device": object.union(base_device, {"edr_running": false}), "context": base_context}
}

# Negative: missing MFA
test_missing_mfa_denied if {
	not db.allow with input as {"user": object.union(base_user, {"mfa_verified": false}), "device": base_device, "context": base_context}
}

# Negative: high user risk score
test_high_risk_denied if {
	not db.allow with input as {"user": object.union(base_user, {"risk_score": 75}), "device": base_device, "context": base_context}
}
