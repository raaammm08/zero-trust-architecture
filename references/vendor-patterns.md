# Vendor-Specific Zero Trust Patterns

Platform-specific implementation guidance for major ZT vendors. Use alongside architecture patterns.

---

## Cloudflare Zero Trust (Cloudflare One)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Access** | ZTNA (PEP) | Identity-aware proxy, short-lived certs, device posture |
| **Gateway** | SWG + DNS + CASB | DNS filtering, HTTP policies, RBI, DLP |
| **Browser Isolation** | RBI (PEP) | Remote browser, data loss prevention |
| **CASB** | SaaS Security | API-based, shadow IT discovery |
| **DLP** | Data Protection | Exact match, regex, ML classifiers |
| **Magic WAN** | Network Connectivity | Any-to-any, replaces MPLS |
| **Zero Trust Dashboard** | Visibility | Analytics, logs, alerts |

### Architecture Pattern
```
User → Cloudflare Access (IdP + Device Posture) → Application
     → Cloudflare Gateway (SWG/DNS/CASB) → Internet/SaaS
     → Magic WAN / Cloudflare Network Interconnect → On-prem/Cloud
```

### Policy Configuration (Terraform)
```hcl
resource "cloudflare_access_application" "app" {
  zone_id = var.zone_id
  name    = "internal-app"
  domain  = "app.example.com"
  session_duration = "24h"
}

resource "cloudflare_access_policy" "engineers" {
  zone_id = var.zone_id
  application_id = cloudflare_access_application.app.id
  name = "Engineers with MFA + Device"
  decision = "allow"
  include {
    group = ["engineers@company.com"]
    device_posture = ["managed-device", "disk-encryption"]
  }
  require = ["mfa"]
}
```

### Device Posture Checks
- `managed-device` (MDM enrolled)
- `disk-encryption` (FileVault/BitLocker)
- `firewall` (enabled)
- `auto-updates` (enabled)
- `os-version` (minimum version)
- Custom: CrowdStrike, SentinelOne, Jamf, Intune, Kandji

### Integration Points
- IdP: OIDC/SAML (Okta, Entra ID, Google, Ping, Keycloak)
- MDM: Jamf, Intune, Kandji, Mosyle, Addigy, VMware Workspace ONE
- EDR: CrowdStrike, SentinelOne, Microsoft Defender, Carbon Black
- SIEM: Splunk, Datadog, Sumo Logic, Elastic, Panther

---

## Zscaler (ZIA + ZPA + ZDX)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **ZIA** | SSE (SWG, CASB, DLP, FWaaS) | Inline inspection, SSL/TLS, sandboxing |
| **ZPA** | ZTNA (PEP) | App segmentation, app connectors, micro-tenancy |
| **ZDX** | DEM (Visibility) | User experience scoring, hop-by-hop visibility |
| **ZIA Posture** | Device Trust | Partner integrations, posture profiles |
| **ZPA Browser Access** | Clientless ZTNA | No client for web apps |

### Architecture Pattern
```
User → ZPA Client Connector → ZPA Private Service Edge → Application
     → ZIA (forward proxy) → Internet/SaaS
     → ZDX → Visibility/Analytics
```

### ZPA Policy (API/Config)
```json
{
  "name": "Engineer Access to Production",
  "action": "ALLOW",
  "conditions": [
    {"attribute": "user.groups", "operator": "IN", "values": ["engineers"]},
    {"attribute": "device.posture", "operator": "EQUALS", "values": ["healthy"]},
    {"attribute": "auth.mfa", "operator": "EQUALS", "values": ["true"]},
    {"attribute": "time.window", "operator": "BETWEEN", "values": ["09:00", "18:00"]}
  ],
  "appSegment": "production-api",
  "serverGroups": ["prod-app-servers"]
}
```

### App Connector Deployment
```bash
# Kubernetes (Helm)
helm install zpa-connector zscaler/zpa-connector \
  --set provisioningKey="<key>" \
  --set replicaCount=3 \
  --set resources.limits.cpu=500m \
  --set resources.limits.memory=512Mi
```

### Integration Points
- IdP: SAML/OIDC (Okta, Entra ID, AD FS, Ping, CyberArk)
- MDM: Jamf, Intune, VMware, MobileIron, Ivanti
- EDR: CrowdStrike, SentinelOne, Defender, Trend Micro, Carbon Black
- SIEM: Splunk, QRadar, Sentinel, Elastic, Chronicle, Datadog
- ITSM: ServiceNow, Jira, Zendesk

---

## Okta (Identity + Access Gateway + ASA)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Workforce Identity Cloud** | IdP (PE) | Universal Directory, MFA, Lifecycle, Governance |
| **Access Gateway** | PEP (on-prem apps) | Reverse proxy, header-based auth, Kerberos |
| **ASA (Adaptive Scale Architecture)** | Risk Engine | Behavioral analytics, risk-based auth |
| **Device Trust** | Device Posture | Okta Verify, partner integrations |
| **Fine-Grained AuthZ** | Policy (PE) | Centralized policy, external PDP |

### Architecture Pattern
```
User → Okta (AuthN + Risk) → Access Gateway / App Proxy → Application
     → Device Trust (Okta Verify + Partner) → Posture Check
     → Fine-Grained AuthZ → Dynamic Policy Decision
```

### Policy (Okta Expression Language)
```javascript
// Risk-based authentication policy
if (user.groups.contains("engineers") && 
    device.trustLevel == "HIGH" && 
    context.authContext.mfaAuthenticated &&
    context.request.ip.reputation != "HIGH_RISK") {
  return ALLOW;
} else if (user.groups.contains("engineers") && 
           context.authContext.mfaAuthenticated) {
  return CHALLENGE("PUSH");
} else {
  return DENY;
}
```

### Fine-Grained Authorization (FGA)
```rego
# Okta FGA uses Rego-like syntax
package okta.fga

allow(user, action, resource) {
  has_role(user, "engineer", resource)
  action == "read"
  resource.environment == "production"
  time.now() >= resource.on_call_start
  time.now() <= resource.on_call_end
  mfa_verified(user)
}
```

### Integration Points
- Directories: AD, LDAP, HR systems (Workday, BambooHR)
- MDM: Jamf, Intune, VMware, Kandji, Mosyle
- EDR: CrowdStrike, SentinelOne, Defender, Jamf Protect
- SIEM: Splunk, Sentinel, Datadog, Panther, Sumo Logic
- ITSM: ServiceNow, Jira, Okta Workflows

---

## Microsoft Entra ID (Azure AD) + Global Secure Access

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Entra ID P1/P2** | IdP + Risk | Conditional Access, Identity Protection, PIM |
| **Global Secure Access** | ZTNA + SWG | Entra Private Access, Internet Access |
| **Conditional Access** | Policy (PE) | Signal-based, session controls, CA policies |
| **Entra ID Governance** | IGA | Access reviews, entitlement management, Lifecycle |
| **Entra Workload ID** | Workload Identity | Federated credentials, managed identities |

### Architecture Pattern
```
User → Entra ID (AuthN + Conditional Access) → Global Secure Access → Resource
     → Device Compliance (Intune) → Posture
     → PIM → JIT Privileged Access
     → Workload Identity → Service-to-Service
```

### Conditional Access Policy (Graph API)
```json
{
  "displayName": "Engineers - Production Access",
  "state": "enabled",
  "conditions": {
    "users": {"includeGroups": ["engineers-group-id"]},
    "applications": {"includeApplications": ["production-app-id"]},
    "platforms": {"includePlatforms": ["all"]},
    "locations": {"includeLocations": ["all"], "excludeLocations": ["trusted-ips"]},
    "clientApps": {"includeClientApps": ["browser", "mobileApps"]},
    "filterForDevices": "device.deviceTrustType -eq 'compliant'",
    "signInRiskLevels": ["low", "medium"],
    "userRiskLevels": ["low", "medium"]
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "compliantDevice", "passwordChange"]
  },
  "sessionControls": {
    "signInFrequency": {"value": 4, "type": "hours", "isEnabled": true},
    "persistentBrowser": {"mode": "never", "isEnabled": true},
    "cloudAppSecurity": {"type": "monitorOnly", "isEnabled": true}
  }
}
```

### Workload Identity (AKS Example)
```yaml
# Azure Workload Identity
apiVersion: v1
kind: ServiceAccount
metadata:
  name: workload-identity-sa
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: workload-identity-sa
      containers:
      - name: app
        env:
        - name: AZURE_CLIENT_ID
          value: "<managed-identity-client-id>"
        - name: AZURE_TENANT_ID
          value: "<tenant-id>"
        - name: AZURE_AUTHORITY_HOST
          value: "https://login.microsoftonline.com"
```

### Integration Points
- On-prem AD: Entra Connect Sync / Cloud Sync
- Endpoint: Intune (compliance, config, apps)
- EDR: Defender for Endpoint, CrowdStrike, SentinelOne (via API)
- SIEM: Sentinel, Splunk, Elastic, Datadog
- Cloud: AWS IAM Roles Anywhere, GCP Workload Identity Federation

---

## AWS (Verified Access + IAM + IAM Roles Anywhere)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Verified Access** | ZTNA (PEP) | Application endpoints, trust providers, access logs |
| **IAM** | Policy (PE) | Policies, conditions, tags, boundaries, Access Analyzer |
| **IAM Roles Anywhere** | Workload Identity | X.509 certs for on-prem/hybrid workloads |
| **Verified Permissions** | Fine-Grained AuthZ | Cedar policies, schema-based, decisions API |
| **Network Firewall** | Network Segmentation | Stateful, Suricata, TLS inspection |
| **Security Lake** | Visibility | Centralized logs, OCSF, Athena/QuickSight |

### Architecture Pattern
```
User/Workload → Verified Access Endpoint → Trust Provider (OIDC/SAML) → Application
            → IAM Roles Anywhere (hybrid) → AWS Resources
            → Verified Permissions (Cedar) → Fine-Grained Decisions
```

### Verified Access Policy (Cedar)
```cedar
permit (
  principal == User::"engineer-*",
  action == Action::"read",
  resource == Resource::"production-db"
) when {
  principal.hasMFA == true &&
  principal.device.compliant == true &&
  context.time >= "09:00" &&
  context.time <= "18:00"
};

forbid (
  principal,
  action == Action::"delete",
  resource == Resource::"production-*"
) unless {
  principal.hasRole("dba") &&
  principal.justification != ""
};
```

### Verified Access Trust Provider (OIDC)
```hcl
resource "aws_verifiedaccess_trust_provider" "okta" {
  trust_provider_type = "user"
  user_trust_provider_type = "oidc"
  oidc_options {
    issuer        = "https://company.okta.com"
    authorization_endpoint = "https://company.okta.com/oauth2/v1/authorize"
    token_endpoint       = "https://company.okta.com/oauth2/v1/token"
    user_info_endpoint   = "https://company.okta.com/oauth2/v1/userinfo"
    client_id            = var.okta_client_id
    client_secret        = var.okta_client_secret
    scope                = "openid profile email groups"
  }
  policy_reference_name = "okta-trust"
}
```

### Integration Points
- IdP: OIDC/SAML (Okta, Entra ID, Ping, Keycloak, Auth0)
- MDM: Jamf, Intune (via trust provider device attributes)
- SIEM: Security Lake → Athena/OpenSearch/Splunk/Datadog
- On-prem: IAM Roles Anywhere + Private CA

---

## Google Cloud (IAP + BeyondCorp Enterprise + Identity-Aware Proxy)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Identity-Aware Proxy (IAP)** | ZTNA (PEP) | TCP/HTTP, JWT validation, context-aware |
| **BeyondCorp Enterprise** | ZTNA + DLP + CASB | Device trust, data protection, threat prevention |
| **Identity Platform** | IdP | OIDC/SAML, MFA, risk-based auth |
| **Service Mesh (Anthos/Traffic Director)** | Service-to-Service | mTLS, AuthZ, observability |
| **Binary Authorization** | Supply Chain | Attestations, policy enforcement |
| **Confidential Computing** | Data Protection | TEE, encrypted memory |

### Architecture Pattern
```
User → IAP (Identity + Context) → App Engine / GKE / Compute / On-prem
     → BeyondCorp Enterprise (Device + Data + Threat)
     → Service Mesh (mTLS + AuthZ between services)
```

### IAP Policy (IAM Conditions)
```yaml
# IAM Condition for IAP
title: "Engineers with compliant device during business hours"
description: "Allow engineers to access internal apps with device compliance"
expression: |
  request.auth.principal.email.endsWith("@company.com") &&
  "groups/engineers" in request.auth.principal.groups &&
  request.auth.context.device.trust_level == "COMPLIANT" &&
  request.time.getHours() >= 9 &&
  request.time.getHours() <= 18
```

### BeyondCorp Device Policy
```json
{
  "name": "engineer-device-policy",
  "description": "Engineer device requirements",
  "deviceTrustRequirements": {
    "osConstraints": [
      {"osType": "MACOS", "minimumVersion": "14.0"},
      {"osType": "WINDOWS", "minimumVersion": "11.0"}
    ],
    "requireScreenLock": true,
    "requireDiskEncryption": true,
    "requireCorpManaged": true,
    "allowedDeviceManagement": ["GOOGLE_ENDPOINT_MANAGEMENT", "JAMF", "INTUNE"]
  },
  "accessLevels": ["engineer-access"]
}
```

### Integration Points
- IdP: OIDC/SAML (Okta, Entra ID, Ping, Keycloak, Auth0)
- MDM: Google Endpoint Management, Jamf, Intune, VMware
- EDR: CrowdStrike, SentinelOne, Defender, Carbon Black
- SIEM: Chronicle, Splunk, Datadog, Elastic, Panther
- On-prem: Cloud Interconnect + IAP for on-prem apps

---

## Palo Alto Networks (Prisma Access + Prisma Cloud + Cortex)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Prisma Access** | SSE (ZTNA, SWG, CASB, DLP, FWaaS) | Global PoPs, unified policy |
| **Prisma Cloud** | CNAPP | Code-to-cloud, runtime, compliance |
| **Cortex XDR/XSOAR** | Visibility + Automation | UEBA, SOAR, ASM |
| **IoT/OT Security** | Device | Agentless, behavioral profiling |
| **Strata Cloud Manager** | Management | Single pane, policy as code |

### Architecture Pattern
```
User → Prisma Access (ZTNA/SWG) → Internet/SaaS/Private Apps
     → Prisma Cloud (Workload Protection) → Cloud Workloads
     → Cortex XDR (Endpoint/Network/Cloud) → Detection/Response
```

### Prisma Access Policy (API)
```json
{
  "name": "Engineer-ZTNA-Policy",
  "rule_type": "ztna",
  "action": "allow",
  "source_user": ["engineers"],
  "source_device": {
    "posture_profile": "managed-compliant",
    "os": ["macos", "windows"]
  },
  "destination": ["app:production-api"],
  "schedule": "business-hours",
  "authentication_profile": "saml-okta",
  "ssl_decryption": "decrypt-known-cert"
}
```

### Integration Points
- IdP: SAML/OIDC (Okta, Entra ID, AD FS, Ping, CyberArk)
- MDM: Jamf, Intune, VMware, MobileIron, Ivanti
- EDR: Cortex XDR, CrowdStrike, SentinelOne, Defender
- SIEM: Cortex XSOAR, Splunk, Sentinel, QRadar, Elastic
- Cloud: AWS, Azure, GCP, OCI, Alibaba

---

## Netskope (SSE Platform)

### Components
| Component | ZT Function | Key Features |
|-----------|-------------|--------------|
| **Netskope Private Access (NPA)** | ZTNA | App connectors, publisher, client |
| **Netskope Cloud Exchange** | Integration | SIEM, ITSM, Identity, EDR |
| **Advanced DLP** | Data | ML classifiers, OCR, fingerprinting |
| **Cloud Firewall** | Network | L3/L4, IPS, TLS inspection |
| **UEBA** | Visibility | Behavioral analytics, risk scoring |

### Architecture Pattern
```
User → NPA Client → NPA Publisher → Private Application
     → Netskope SWG/CASB/DLP → Internet/SaaS
     → Cloud Exchange → SIEM/ITSM/Identity/EDR
```

### Integration Points
- IdP: SAML/OIDC (Okta, Entra ID, AD FS, Ping, Keycloak, CyberArk)
- MDM: Jamf, Intune, VMware, Kandji, Mosyle, Addigy
- EDR: CrowdStrike, SentinelOne, Defender, Carbon Black, Trend
- SIEM: Splunk, Sentinel, Elastic, Datadog, Panther, Sumo Logic
- ITSM: ServiceNow, Jira, Zendesk

---

## Vendor Selection Matrix

| Requirement | Cloudflare | Zscaler | Okta | Microsoft | AWS | Google | Palo Alto | Netskope |
|-------------|------------|---------|------|-----------|-----|--------|-----------|----------|
| **Best for Cloud-Native** | ✅ | | | | ✅ | ✅ | | |
| **Best for Hybrid/Legacy** | | ✅ | | ✅ | ✅ | | ✅ | ✅ |
| **Best for Identity-First** | | | ✅ | ✅ | | | | |
| **Best for Network-Heavy** | ✅ | ✅ | | | | | ✅ | ✅ |
| **Best for Data Protection** | ✅ | ✅ | | ✅ | | ✅ | ✅ | ✅ |
| **Best for OT/IoT** | | | | | | | ✅ | |
| **Best for Compliance** | | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Cost Model** | Per user | Per user/bandwidth | Per user | Per user | Per request/GB | Per user/GB | Per user/bandwidth | Per user |

---

## Multi-Vendor Strategy

Common combinations:
- **Identity + ZTNA**: Okta + Cloudflare/Zscaler/Netskope
- **Microsoft shops**: Entra ID + Global Secure Access + Defender + Sentinel
- **AWS shops**: Verified Access + IAM + Security Lake + GuardDuty
- **Google shops**: IAP + BeyondCorp + Chronicle + Anthos
- **Network-centric**: Palo Alto Prisma Access + Cortex + Prisma Cloud

Avoid: Running multiple ZTNA proxies for same traffic (double encryption, latency, complexity)