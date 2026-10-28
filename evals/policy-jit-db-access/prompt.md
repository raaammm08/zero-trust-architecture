Write an OPA/Rego policy for just-in-time (JIT) database access with the following requirements:
- Only engineers in the "on-call" group can access production databases
- Access only allowed during their on-call shift (defined in user.on_call_start/end timestamps)
- MFA must be verified within the last hour (push or FIDO2)
- Device must be managed, encrypted, and have EDR running
- Access must be from corporate network or approved country (US, CA, GB, DE)
- All access must be logged with full context
- Deny access if user risk score > 70 or device risk score > 60
- Include test cases for: on-call engineer with compliant device, off-call engineer, non-engineer, non-compliant device, missing MFA, high risk score

Use the OPA/Rego template from the skill as a starting point.