# Zero Trust Architecture Patterns

Reference architectures organized by organization profile. Each pattern maps to NIST 800-207 deployment models and CISA ZTMM stages.

---

## Pattern 1: Cloud-Native Startup (50-500 people)

**Profile**: Born in cloud, SaaS-first, modern stack, high velocity
**Target Maturity**: Advanced (12-18 months)
**NIST Model**: Cloud-Native / Identity-Aware Proxy + Service Mesh

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Identity Provider                       │
│  (Okta / Entra ID / Google Workspace + MFA + JIT)           │
└──────────────┬──────────────────────────────────────────────┘
               │
        ┌──────▼──────┐     ┌─────────────────────────────┐
        │  Cloud IAP  │     │      Service Mesh           │
        │ (AWS VA /   │────▶│  (Istio / Linkerd /         │
        │  Azure AD   │     │   Consul Connect)           │
        │  App Proxy) │     │  mTLS + AuthZ per service   │
        └─────────────┘     └─────────────────────────────┘
               │                      │
        ┌──────▼──────┐     ┌────────▼────────┐
        │   SaaS Apps │     │  Kubernetes     │
        │ (GitHub,    │     │  Workloads      │
        │  Slack,     │     │  (microservices,│
        │  Atlassian) │     │   databases)    │
        └─────────────┘     └─────────────────┘
```

### Key Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Identity | Cloud IdP + SCIM | Fast provisioning, native MFA |
| Network | Cloud IAP + Service Mesh | No VPN, identity-based access |
| Device | MDM + posture checks | Fleet management, compliance |
| Data | Cloud KMS + DLP | Managed encryption, classification |
| Visibility | Cloud logging + SIEM | Native integration, cost-effective |

### Migration Phases

1. **Phase 1 (0-3 mo)**: IdP + MFA + SSO + MDM + Central logging
2. **Phase 2 (3-6 mo)**: Cloud IAP for all apps + Service mesh pilot
3. **Phase 3 (6-12 mo)**: Full service mesh + Policy-as-code + UEBA
4. **Phase 4 (12-18 mo)**: Risk-based auth + Automated response + cATO

---

## Pattern 2: Enterprise Hybrid (1,000-10,000 people)

**Profile**: Mixed cloud/on-prem, legacy apps, regulated industry, complex compliance
**Target Maturity**: Advanced → Optimal (18-36 months)
**NIST Model**: Enclave-Based + Device Agent/Gateway + Resource Portal

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Identity Fabric                               │
│  (Entra ID / Okta + AD Connect + PAM + JIT + Workload Identity) │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼───────┐ ┌──────▼──────┐ ┌──────▼──────────┐
│  On-Premises  │ │   Cloud     │ │   Edge/Remote   │
│  Data Center  │ │  (Multi)    │ │   Workers       │
│               │ │             │ │                 │
│ ┌───────────┐ │ │ ┌─────────┐ │ │ ┌────────────┐  │
│ │ SDP/Gateway│ │ │ │ Cloud  │ │ │ │ ZTNA Client │  │
│ │ (Zscaler/  │ │ │ │ IAP    │ │ │ │ + Device   │  │
│ │  Palo Alto)│ │ │ │ + Mesh │ │ │ │ Posture    │  │
│ └─────┬─────┘ │ │ └────┬────┘ │ │ └──────┬─────┘  │
│       │       │ │      │       │ │        │        │
│ ┌─────▼─────┐ │ │ ┌────▼────┐ │ │ ┌──────▼─────┐  │
│ │ Micro-Seg │ │ │ │ Workload│ │ │ │  Internet  │  │
│ │ (Illumio/ │ │ │ │ Identity│ │ │ │  / SaaS    │  │
│ │  Guardicore)│ │ │ │ (SPIFFE)│ │ │ │  via SSE  │  │
│ └───────────┘ │ │ └─────────┘ │ │ └────────────┘  │
└───────────────┘ └─────────────┘ └─────────────────┘
```

### Key Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Identity | Hybrid IdP (AD + Cloud) + PAM | Legacy AD integration, privileged access |
| Network | SDP + Micro-segmentation | Legacy app support, east-west control |
| Device | Unified endpoint management | Corporate + BYOD + IoT/OT |
| Data | Classification + DLP + IRM | Compliance, IP protection |
| Visibility | Enterprise SIEM + SOAR | Scale, correlation, automation |

### Migration Phases

1. **Phase 1 (0-6 mo)**: IdP consolidation + MFA + PAM + Device inventory + SIEM
2. **Phase 2 (6-12 mo)**: ZTNA for remote + SDP for DC + Micro-seg pilot + API gateway
3. **Phase 3 (12-24 mo)**: Full micro-seg + Service mesh (cloud) + Workload identity + DLP
4. **Phase 4 (24-36 mo)**: Risk-based auth + Confidential computing + Autonomous response

---

## Pattern 3: Regulated / Government (FedRAMP, CMMC, HIPAA)

**Profile**: High compliance, audit-heavy, classified data, long procurement cycles
**Target Maturity**: Optimal (continuous)
**NIST Model**: All models, evidence-driven, continuous monitoring

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Continuous Authority to Operate (cATO)              │
│  (Automated Evidence Collection + Continuous Monitoring)         │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼───────┐ ┌──────▼──────┐ ┌──────▼──────────┐
│  Classified   │ │  CUI /      │ │  Public /       │
│  Enclave      │ │  Controlled │ │  Unclassified   │
│               │ │  Unclass.   │ │                 │
│ • Air-gapped  │ │ • NIST 800- │ │ • Standard ZT   │
│ • Hardware    │ │   171       │ │ • Cloud-native  │
│   roots of    │ │ • CMMC L2/3 │ │ • FedRAMP auth  │
│   trust       │ │ • Encrypted │ │                 │
└───────────────┘ └─────────────┘ └─────────────────┘
```

### Key Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Identity | PIV/CAC + Derived credentials | Federal mandate, hardware-backed |
| Network | Cross-domain solutions (CDS) | Multi-level security (MLS) |
| Device | Hardware-attested, TPM 2.0+ | Supply chain, FIPS 140-3 |
| Data | Label-based (CAPCO, CUI) | Mandatory access control (MAC) |
| Visibility | Continuous monitoring (CDM) | FISMA, OMB M-22-09 |

### Compliance Mapping

| Framework | Key Controls | ZT Mapping |
|-----------|--------------|------------|
| FedRAMP High | AC-2, AC-3, AC-17, SC-7, SC-8, SI-4 | All 7 tenets |
| CMMC 2.0 L3 | IA.L2-3.5.2, AC.L2-3.1.1, SC.L2-3.13.11 | Tenets 2,3,4,6 |
| HIPAA | §164.312(a)(1), (e)(1), (e)(2) | Tenets 1,2,5,7 |
| NIST 800-53 Rev 5 | AC, IA, SC, SI families | Complete coverage |

---

## Pattern 4: OT / Industrial (Manufacturing, Energy, Utilities)

**Profile**: OT/IT convergence, safety-critical, legacy protocols, long lifecycles
**Target Maturity**: Initial → Advanced (extended timeline)
**NIST Model**: Enclave-Based + Purdue Model Integration

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    IT/OT Identity Bridge                         │
│  (Separate IdPs with trust federation, no direct IT→OT access)   │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼───────┐ ┌──────▼──────┐ ┌──────▼──────────┐
│   Level 4/5   │ │  Level 3    │ │  Level 0-2      │
│  Enterprise   │ │  Operations │ │  Control/Field  │
│               │ │             │ │                 │
│ • Standard ZT │ │ • SDP/OT    │ │ • Protocol-aware│
│ • Cloud apps  │ │   Firewall  │ │   segmentation  │
│               │ │ • Historian │ │ • Unidirectional│
│               │ │   Isolation │ │   Gateways      │
└───────────────┘ └─────────────┘ └─────────────────┘
```

### Key Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Identity | Separate OT IdP + Federation | Safety, no IT credential reuse in OT |
| Network | Purdue Model + Unidirectional Gateways | Physics safety, deterministic latency |
| Device | Passive monitoring + allowlisting | No agents on PLCs/RTUs |
| Data | Historian segmentation | Data integrity, regulatory retention |
| Visibility | OT-specific anomaly detection | Process-aware, not just network |

### Special Considerations

- **Safety first**: Availability > Confidentiality > Integrity (vs IT CIA triad)
- **No active scanning** on OT networks
- **Vendor remote access**: JIT, recorded, time-boxed, dual-control
- **Legacy protocol support**: Modbus, DNP3, OPC-UA with deep packet inspection

---

## Pattern 5: Multi-Cloud / Cloud-Agnostic

**Profile**: Workloads across AWS, Azure, GCP, avoiding vendor lock-in
**Target Maturity**: Advanced
**NIST Model**: Service Mesh + Cloud-Native (federated)

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              Federated Identity & Policy                         │
│  (SPIFFE/SPIRE + OPA/Gatekeeper + Cross-Cloud Mesh)              │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
┌───────▼───────┐ ┌──────▼──────┐ ┌──────▼──────────┐
│     AWS       │ │    Azure    │ │      GCP        │
│               │ │             │ │                 │
│ • Verified    │ │ • App       │ │ • Identity-Aware│
│   Access      │ │   Proxy     │ │   Proxy         │
│ • IAM Roles   │ │ • Managed   │ │ • Workload      │
│   Anywhere    │ │   Identity  │ │   Identity      │
│ • EKS +       │ │ • AKS +     │ │ • GKE +         │
│   Istio       │ │   Istio     │ │   Istio         │
└───────────────┘ └─────────────┘ └─────────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
              ┌──────────▼──────────┐
              │  Cross-Cloud Mesh   │
              │  (Istio Multi-Cluster│
              │   / Consul / Cilium) │
              └─────────────────────┘
```

### Key Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Identity | SPIFFE/SPIRE (workload) + OIDC federation | Portable, cloud-agnostic |
| Network | Service mesh (Istio/Cilium) + Cloud IAP | Consistent policy, mTLS everywhere |
| Policy | OPA/Gatekeeper + Cedar | Portable policy language |
| Data | Cloud KMS + External key management | Key portability, sovereignty |
| Visibility | OpenTelemetry + Unified SIEM | Vendor-neutral telemetry |

---

## Pattern Selection Guide

| If your org... | Start with Pattern |
|----------------|-------------------|
| Cloud-only, <500 people, modern stack | Pattern 1 |
| Hybrid, 1000+, legacy apps, regulated | Pattern 2 |
| Federal/Defense/High compliance | Pattern 3 |
| Manufacturing/Energy/Utilities | Pattern 4 |
| Multi-cloud, avoiding lock-in | Pattern 5 |
| Not sure | Pattern 2 (most common baseline) |

---

## Customization Checklist

For any pattern, customize:
- [ ] Identity provider(s) and federation strategy
- [ ] Device management (corporate, BYOD, IoT/OT)
- [ ] Network segmentation granularity (app, namespace, workload)
- [ ] Data classification schema and encryption strategy
- [ ] Threat model and risk appetite
- [ ] Compliance frameworks and evidence requirements
- [ ] Team structure and skill gaps
- [ ] Budget and timeline constraints
- [ ] Vendor preferences and existing investments