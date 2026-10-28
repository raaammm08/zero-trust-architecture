# Policy Languages Reference

Comparison and best practices for Zero Trust policy languages: OPA/Rego, AWS Cedar, Alpha, and vendor-specific.

---

## OPA / Rego

### Overview
- **Use Case**: Kubernetes admission, service mesh, API gateways, microservices
- **Model**: Datalog-based, declarative, set-oriented
- **Ecosystem**: OPA, Gatekeeper, Kubewarden, Envoy, Istio, Kong, Traefik
- **Testing**: Built-in `opa test`, Rego Playground

### Syntax Basics

OPA 1.x (Rego v1): every rule body needs `if`, and partial sets use `contains`. The v0 form `allow { ... }` no longer parses.

```rego
package authz

# Allow if user has role and resource matches
allow if {
  input.user.roles[_] == "engineer"
  input.resource.environment == "production"
  input.action == "read"
  on_call(input.user)
  mfa_verified(input.user)
}

# Helper rules
on_call(user) if {
  now := time.now_ns() / 1000000000
  user.on_call_start <= now
  user.on_call_end >= now
}

mfa_verified(user) if {
  user.mfa_methods[_] == "push"
  user.last_mfa <= time.now_ns() / 1000000000 - 3600  # within 1 hour
}

# Deny with reason
deny contains msg if {
  not allow
  msg := sprintf("Access denied: user=%v action=%v resource=%v", [input.user.id, input.action, input.resource.id])
}
```

### Data Model (Input Document)
```json
{
  "user": {
    "id": "user-123",
    "email": "engineer@company.com",
    "roles": ["engineer", "on-call"],
    "groups": ["engineering", "platform"],
    "mfa_methods": ["push", "totp"],
    "last_mfa": 1699900000,
    "on_call_start": 1699872000,
    "on_call_end": 1699958400,
    "device": {
      "id": "device-456",
      "managed": true,
      "encrypted": true,
      "os": "macos",
      "os_version": "14.2",
      "edr": "crowdstrike",
      "posture_score": 95
    }
  },
  "action": "read",
  "resource": {
    "id": "prod-db-01",
    "type": "database",
    "environment": "production",
    "classification": "confidential",
    "owner": "platform-team"
  },
  "context": {
    "time": "2024-01-15T14:30:00Z",
    "ip": "10.0.1.50",
    "location": "office",
    "network": "corporate"
  }
}
```

### Best Practices
1. **Use `default allow = false`** — explicit allow
2. **Separate policy from data** — use external data (Bundles, REST)
3. **Write tests first** — `opa test -v`
4. **Use partial evaluation** — for compile-time optimization
5. **Version policies** — GitOps, signed bundles
6. **Avoid recursion** — use comprehension instead
7. **Document with comments** — `# METADATA` annotations

### Testing
```rego
# test_authz.rego
package authz

test_allow_engineer_on_call {
  allow with input as {"user": {"roles": ["engineer"], "on_call_start": 1000, "on_call_end": 2000, "mfa_methods": ["push"], "last_mfa": 1500}, "action": "read", "resource": {"environment": "production"}, "context": {"time": "2024-01-15T14:30:00Z"}}
}

test_deny_off_call {
  not allow with input as {"user": {"roles": ["engineer"], "on_call_start": 1000, "on_call_end": 2000, "mfa_methods": ["push"], "last_mfa": 1500}, "action": "read", "resource": {"environment": "production"}, "context": {"time": "2024-01-15T22:30:00Z"}}
}

test_deny_no_mfa {
  not allow with input as {"user": {"roles": ["engineer"], "on_call_start": 1000, "on_call_end": 2000, "mfa_methods": [], "last_mfa": 0}, "action": "read", "resource": {"environment": "production"}, "context": {"time": "2024-01-15T14:30:00Z"}}
}
```

### Deployment Patterns
- **Sidecar**: OPA container per pod (Istio, Envoy)
- **DaemonSet**: One OPA per node (Kube-mgmt)
- **Centralized**: OPA server + bundle API (high availability)
- **Gatekeeper**: Admission controller (validating/mutating)

---

## AWS Cedar

### Overview
- **Use Case**: Application-level authorization, Verified Permissions, fine-grained access
- **Model**: Policy-as-code, entity-based, typed, decidable
- **Ecosystem**: Verified Permissions, Cedar CLI, Cedar Playground
- **Testing**: `cedar validate`, `cedar authorize`, unit tests

### Syntax Basics
```cedar
// Entity types (schema)
entity User {
  id: String,
  email: String,
  groups: Set<String>,
  roles: Set<String>,
  mfaVerified: Boolean,
  device: Device,
  onCallSchedule: OnCallSchedule?
}

entity Device {
  id: String,
  managed: Boolean,
  encrypted: Boolean,
  os: String,
  postureScore: Long
}

entity Resource {
  id: String,
  type: String,
  environment: String,
  classification: String,
  owner: String
}

entity OnCallSchedule {
  start: Long,  // Unix timestamp
  end: Long
}

// Policies
permit (
  principal: User,
  action: Action,
  resource: Resource
) when {
  principal.hasRole("engineer") &&
  principal.mfaVerified == true &&
  principal.device.managed == true &&
  principal.device.encrypted == true &&
  resource.environment == "production" &&
  action == Action::"read" &&
  principal.onCallSchedule?.start <= context.currentTime &&
  principal.onCallSchedule?.end >= context.currentTime
};

forbid (
  principal: User,
  action: Action,
  resource: Resource
) when {
  action == Action::"delete" &&
  resource.environment == "production" &&
  !principal.hasRole("dba")
};

// Role definition
permit (
  principal: User,
  action: Action::"assumeRole",
  resource: Role
) when {
  principal.groups.contains("engineers") &&
  resource.name == "on-call-engineer"
};
```

### Context (Request Context)
```json
{
  "currentTime": 1705331400,
  "requestId": "req-abc123",
  "sourceIp": "10.0.1.50"
}
```

### Schema Definition (JSON)
```json
{
  "entityTypes": {
    "User": {
      "shape": {
        "type": "Record",
        "attributes": {
          "id": {"type": "String"},
          "email": {"type": "String"},
          "groups": {"type": "Set", "elementType": {"type": "String"}},
          "roles": {"type": "Set", "elementType": {"type": "String"}},
          "mfaVerified": {"type": "Boolean"},
          "device": {"type": "Entity", "entityType": "Device"},
          "onCallSchedule": {"type": "Optional", "elementType": {"type": "Entity", "entityType": "OnCallSchedule"}}
        }
      }
    },
    "Device": {
      "shape": {
        "type": "Record",
        "attributes": {
          "id": {"type": "String"},
          "managed": {"type": "Boolean"},
          "encrypted": {"type": "Boolean"},
          "os": {"type": "String"},
          "postureScore": {"type": "Long"}
        }
      }
    }
  },
  "actions": {
    "read": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}},
    "write": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}},
    "delete": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}},
    "assumeRole": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Role"]}}
  }
}
```

### Best Practices
1. **Define schema first** — enables validation, autocomplete
2. **Use `permit` for allow, `forbid` for deny** — explicit precedence
3. **Leverage `when` conditions** — context-aware decisions
4. **Use entity references** — not string matching
5. **Test with `cedar authorize`** — CLI for local testing
6. **Version policies** — store in Git, deploy via Verified Permissions

### Testing
```bash
# Validate policy syntax
cedar validate --schema schema.json --policies policies.cedar

# Test authorization
cedar authorize --schema schema.json --policies policies.cedar --entities entities.json --request request.json

# Entities example (entities.json)
{
  "User::\"user-123\"": {
    "attrs": {
      "id": "user-123",
      "email": "engineer@company.com",
      "groups": ["engineers"],
      "roles": ["engineer"],
      "mfaVerified": true,
      "device": {"__entity": {"type": "Device", "id": "device-456"}}
    }
  },
  "Device::\"device-456\"": {
    "attrs": {
      "id": "device-456",
      "managed": true,
      "encrypted": true,
      "os": "macos",
      "postureScore": 95
    }
  }
}
```

---

## Alpha (Google Zanzibar-inspired)

### Overview
- **Use Case**: Relationship-based access control (ReBAC), Google-scale
- **Model**: Tuple-based (subject, relation, object), graph traversal
- **Ecosystem**: Authzed/SpiceDB, Ory Keto, OpenFGA, Topaz
- **Testing**: Built-in test frameworks per implementation

### Schema (DSL)
```alpha
definition user {
  relation member: group
  relation owner: resource
  relation viewer: resource
  relation editor: resource
}

definition group {
  relation member: user
  relation admin: user
}

definition resource {
  relation viewer: user | group#member
  relation editor: user | group#member
  relation owner: user
  permission view = viewer + editor + owner
  permission edit = editor + owner
  permission delete = owner
}
```

### Tuples (Data)
```
user:alice  member  group:engineers
user:bob    member  group:engineers
group:engineers  member  group:on-call
resource:prod-db  viewer  group:engineers
resource:prod-db  editor  group:on-call
resource:prod-db  owner   user:alice
```

### Check Request
```bash
# Check if Alice can view prod-db
spicedb check user:alice view resource:prod-db
# → true (via group:engineers → viewer)

# Check if Bob can edit prod-db
spicedb check user:bob edit resource:prod-db
# → true (via group:engineers → group:on-call → editor)

# Check if Bob can delete prod-db
spicedb check user:bob delete resource:prod-db
# → false (not owner)
```

### Best Practices
1. **Model relationships, not roles** — more flexible
2. **Use caveats for context** — time, location, MFA (if supported)
3. **Denormalize carefully** — materialized views for performance
4. **Use consistency modes** — fully consistent vs best effort
5. **Audit tuple changes** — relationship changes = policy changes

---

## Vendor-Specific Policy Languages

### Cloudflare Access Policies
```yaml
# YAML for Terraform/Config
decision: allow
include:
  - email_domain: company.com
  - group: engineers@company.com
  - device_posture:
      - managed-device
      - disk-encryption
require:
  - mfa: true
  - device_posture: managed-device
```

### Zscaler ZPA Policies
```json
{
  "policyType": "CLIENT_FORWARDING",
  "name": "Engineer Access",
  "conditions": [
    {"lhs": "user.groups", "rhs": "engineers", "op": "IN"},
    {"lhs": "device.posture", "rhs": "healthy", "op": "EQ"},
    {"lhs": "auth.mfa", "rhs": "true", "op": "EQ"}
  ],
  "action": "ALLOW"
}
```

### Okta Fine-Grained AuthZ (FGA)
```rego
# Similar to OPA but with Okta-specific built-ins
package okta.fga

allow(user, action, resource) {
  okta.user.groups[user] == "engineers"
  okta.device.trustLevel[user] == "HIGH"
  okta.auth.mfaVerified[user] == true
  resource.environment == "production"
  action == "read"
}
```

---

## Language Selection Guide

| Requirement | Recommended Language |
|-------------|---------------------|
| Kubernetes admission / Service mesh | **OPA/Rego** |
| Application-level fine-grained authZ | **AWS Cedar** |
| Relationship-based (Google Drive style) | **Alpha/SpiceDB** |
| Cloudflare ecosystem | **Cloudflare Access** |
| Zscaler ecosystem | **ZPA Policies** |
| Okta ecosystem | **Okta FGA** |
| Microsoft ecosystem | **Conditional Access + Verified Permissions** |
| Multi-cloud portable | **OPA/Rego** or **Cedar** |

---

## Policy Testing Strategy (All Languages)

### Required Test Cases per Policy
1. **Happy path** — authorized user, compliant device, valid context
2. **Wrong role** — user lacks required role/group
3. **Non-compliant device** — unmanaged, unencrypted, outdated OS
4. **Missing MFA** — no MFA or expired MFA
5. **Wrong time** — outside allowed hours
6. **Wrong resource** — dev vs prod, wrong classification
7. **Elevated action** — read vs write vs delete
8. **Edge case** — boundary times, leap seconds, clock skew

### Test Organization
```
tests/
├── policies/
│   ├── engineer-production-read.rego
│   ├── engineer-production-read_test.rego
│   ├── admin-production-delete.cedar
│   └── admin-production-delete_test.cedar
├── fixtures/
│   ├── user-engineer-oncall.json
│   ├── user-engineer-offcall.json
│   ├── user-contractor.json
│   ├── device-compliant.json
│   └── device-noncompliant.json
└── test-runner.sh  # Runs all tests, outputs JUnit/XML
```

### CI/CD Integration
```yaml
# .github/workflows/policy-test.yml
name: Policy Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test OPA policies
        run: opa test -v policies/ tests/
      - name: Test Cedar policies
        run: |
          cedar validate --schema schema.json --policies policies/
          cedar authorize --schema schema.json --policies policies/ --entities entities.json --request tests/request.json
```