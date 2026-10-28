# Zero Trust Gap Analysis Report

**Organization**: [Name]
**Assessment Date**: [YYYY-MM-DD]
**Assessor**: [Name]
**Framework**: [CISA ZTMM / NIST 800-207 / Custom]
**Scope**: [Systems, environments, pillars assessed]

---

## 1. Executive Summary

### 1.1 Overall Maturity Score
| Pillar | Current Stage | Target Stage | Gap |
|--------|---------------|--------------|-----|
| Identity | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |
| Device | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |
| Network | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |
| Application/Workload | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |
| Data | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |
| Visibility & Analytics | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |
| Automation & Orchestration | [Traditional/Initial/Advanced/Optimal] | [Target] | [Stages] |

**Overall**: [Current Average] → [Target Average]

### 1.2 Top 5 Critical Gaps
| Rank | Gap ID | Pillar | Description | Risk | Effort |
|------|--------|--------|-------------|------|--------|
| 1 | GAP-001 | Identity | No phishing-resistant MFA for admins | Critical | Medium |
| 2 | GAP-002 | Network | Flat network, VPN-only remote access | Critical | High |
| 3 | GAP-003 | Device | No authoritative device inventory | High | High |
| 4 | GAP-004 | Application | No service mesh, workloads lack mTLS | High | Medium |
| 5 | GAP-005 | Data | No classification, DLP limited to email | High | Medium |

### 1.3 Recommended Investment Priority
1. **Identity** (Foundation) — Enables all other pillars
2. **Network** (Risk Reduction) — Eliminates lateral movement
3. **Device** (Context) — Required for dynamic policy
4. **Application** (Modernization) — Protects crown jewels
5. **Data** (Compliance) — Regulatory requirement
6. **Visibility/Automation** (Scale) — Operational maturity

---

## 2. Detailed Pillar Assessments

### 2.1 Identity
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| MFA Coverage | [e.g., SMS for 60%] | [Phishing-resistant 100%] | [Stages] | [Config screenshots] |
| MFA Methods | [SMS, Push] | [FIDO2, Passkey, Cert] | [Stages] | [Policy doc] |
| Single Sign-On | [Partial, 5 apps] | [All apps, SAML/OIDC] | [Stages] | [App catalog] |
| Identity Governance | [Annual manual] | [Quarterly automated] | [Stages] | [Process doc] |
| Privileged Access (PAM) | [Shared accounts] | [JIT, session recording] | [Stages] | [PAM config] |
| Workload Identity | [Static keys] | [SPIFFE/Cloud-native] | [Stages] | [Architecture] |
| Conditional Access | [None/Static] | [Risk-based, device-aware] | [Stages] | [CA policies] |
| Identity Threat Detection | [None] | [ITDR, UEBA] | [Stages] | [Tool config] |

**Key Findings**: [Narrative summary]

---

### 2.2 Device
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| Device Inventory | [Spreadsheet, 60%] | [Automated, 100%] | [Stages] | [CMDB report] |
| MDM/UEM Coverage | [Corporate only] | [Corporate + BYOD + IoT] | [Stages] | [MDM console] |
| Posture Assessment | [None/Annual] | [Real-time, continuous] | [Stages] | [EDR config] |
| Compliance Policies | [Basic] | [Granular, risk-based] | [Stages] | [Policy export] |
| Automated Remediation | [Manual] | [Quarantine/wipe <5 min] | [Stages] | [Playbook] |
| Certificate Management | [Manual/None] | [Automated, short-lived] | [Stages] | [PKI/CA config] |
| IoT/OT Visibility | [None] | [Passive profiling] | [Stages] | [Network taps] |

**Key Findings**: [Narrative summary]

---

### 2.3 Network
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| Remote Access | [VPN] | [ZTNA, no VPN] | [Stages] | [VPN/ZTNA config] |
| Network Segmentation | [VLANs, flat] | [Micro-segmentation] | [Stages] | [Firewall rules] |
| Encryption | [TLS 1.2, some] | [mTLS everywhere, TLS 1.3] | [Stages] | [Cert scan] |
| Software-Defined Perimeter | [None] | [SDP for all apps] | [Stages] | [Architecture] |
| DNS Security | [Standard] | [DNSSEC, DoH, filtering] | [Stages] | [DNS config] |
| East-West Visibility | [NetFlow only] | [Full packet/flow + TLS inspection] | [Stages] | [Sensor deployment] |
| Zero Trust Network Access | [None] | [Identity-based, per-session] | [Stages] | [ZTNA config] |

**Key Findings**: [Narrative summary]

---

### 2.4 Application / Workload
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| Service Mesh | [None] | [Istio/Cilium, mTLS STRICT] | [Stages] | [Mesh config] |
| API Security | [Basic GW] | [Schema validation, rate limit, AuthZ] | [Stages] | [GW config] |
| Container Security | [Image scan] | [Admission + Runtime + SBOM] | [Stages] | [Pipeline config] |
| Workload Identity | [None] | [SPIFFE, short-lived certs] | [Stages] | [SPIRE config] |
| Policy-as-Code | [Manual] | [OPA/Gatekeeper, GitOps] | [Stages] | [Repo + pipeline] |
| Immutable Infrastructure | [Some] | [All, no SSH, GitOps] | [Stages] | [Deploy process] |
| Confidential Computing | [None] | [TEE for sensitive workloads] | [Stages] | [Instance types] |

**Key Findings**: [Narrative summary]

---

### 2.5 Data
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| Data Classification | [None/Manual] | [Automated ML, 4-tier] | [Stages] | [Classifier config] |
| Encryption at Rest | [Partial, AWS KMS] | [CMK everywhere, key rotation] | [Stages] | [KMS policies] |
| Encryption in Transit | [TLS 1.2] | [mTLS + TLS 1.3 everywhere] | [Stages] | [Cert scan] |
| DLP | [Email only] | [Endpoint, Network, Cloud, SaaS] | [Stages] | [DLP policies] |
| Information Rights Mgmt | [None] | [Labels, permissions follow data] | [Stages] | [IRM config] |
| Data Access Governance | [ACLs] | [Catalog, lineage, automated reviews] | [Stages] | [Catalog tool] |
| Data Loss Prevention | [Basic] | [ML-based, fingerprinting, OCR] | [Stages] | [DLP rules] |

**Key Findings**: [Narrative summary]

---

### 2.6 Visibility & Analytics
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| Centralized Logging | [Partial, 60%] | [100% sources, OCSF] | [Stages] | [SIEM sources] |
| UEBA | [None] | [ML models, <5% FP] | [Stages] | [UEBA config] |
| SOAR | [Manual] | [Top 20 playbooks auto] | [Stages] | [Playbook list] |
| Threat Intelligence | [Feed only] | [Integrated, scored, auto-block] | [Stages] | [TIP config] |
| Cross-Pillar Correlation | [None] | [Identity+Device+Network+App] | [Stages] | [Detection rules] |
| MITRE ATT&CK Coverage | [Unknown] | [Mapped, measured] | [Stages] | [Coverage report] |
| Continuous Monitoring | [Periodic scans] | [Real-time, cATO ready] | [Stages] | [Monitoring config] |

**Key Findings**: [Narrative summary]

---

### 2.7 Automation & Orchestration
**Current Stage**: [Traditional/Initial/Advanced/Optimal]

| Capability | Current State | Target State | Gap | Evidence |
|------------|---------------|--------------|-----|----------|
| Infrastructure as Code | [Partial] | [100% GitOps, policy-as-code] | [Stages] | [Repo structure] |
| Policy Testing in CI/CD | [None] | [All policies tested, gates] | [Stages] | [Pipeline config] |
| Cross-Pillar Orchestration | [None] | [Identity→Device→Network auto] | [Stages] | [Orchestration tool] |
| Adaptive Policy | [Static] | [Context-aware, real-time] | [Stages] | [Policy engine] |
| ChatOps Integration | [None] | [Slack/Teams for approvals] | [Stages] | [Bot config] |
| Self-Healing | [None] | [Auto-remediate common issues] | [Stages] | [Runbooks] |
| Digital Twin / Simulation | [None] | [Policy what-if, blast radius] | [Stages] | [Tool eval] |

**Key Findings**: [Narrative summary]

---

## 3. Risk-Weighted Gap Prioritization

| Gap ID | Pillar | Description | Likelihood | Impact | Risk Score | Effort | Priority |
|--------|--------|-------------|------------|--------|------------|--------|----------|
| GAP-001 | Identity | No phishing-resistant MFA | High | Critical | 25 | Medium | P0 |
| GAP-002 | Network | Flat network, VPN only | High | Critical | 25 | High | P0 |
| GAP-003 | Device | No authoritative inventory | High | High | 20 | High | P1 |
| GAP-004 | App | No service mesh | Medium | High | 15 | Medium | P1 |
| GAP-005 | Data | No classification | Medium | High | 15 | Medium | P1 |
| GAP-006 | Vis | No UEBA | Medium | High | 15 | High | P2 |
| GAP-007 | Auto | No policy-as-code | Low | High | 10 | Medium | P2 |
| ... | ... | ... | ... | ... | ... | ... | ... |

**Risk Score** = Likelihood (1-5) × Impact (1-5)

---

## 4. Remediation Roadmap

### Quick Wins (0-3 months)
| Gap ID | Action | Owner | Cost | Success Metric |
|--------|--------|-------|------|----------------|
| GAP-001 | Enable FIDO2 for all admins | Identity | $50K | 100% admins FIDO2 |
| GAP-003 | Deploy MDM + inventory scan | Endpoint | $100K | 95% devices enrolled |
| GAP-005 | Deploy data classification scanner | Data | $75K | 80% data classified |

### Foundation (3-12 months)
| Gap ID | Action | Owner | Cost | Success Metric |
|--------|--------|-------|------|----------------|
| GAP-001 | Full FIDO2 rollout (all users) | Identity | $200K | 90% users FIDO2 |
| GAP-002 | ZTNA pilot → full deployment | Network | $500K | VPN <5% usage |
| GAP-003 | Real-time posture + auto-remediation | Endpoint | $300K | <5 min quarantine |
| GAP-004 | Service mesh pilot (critical apps) | Platform | $200K | 50% workloads meshed |

### Advanced (12-24 months)
| Gap ID | Action | Owner | Cost | Success Metric |
|--------|--------|-------|------|----------------|
| GAP-002 | Full micro-segmentation | Network | $800K | Zero implicit trust |
| GAP-004 | Full service mesh + workload identity | Platform | $500K | 100% mTLS + SPIFFE |
| GAP-005 | Enterprise DLP + IRM | Data | $600K | 0 critical leaks |
| GAP-006 | UEBA + SOAR (20 playbooks) | SecOps | $700K | 80% auto-response |

### Optimal (24+ months)
| Gap ID | Action | Owner | Cost | Success Metric |
|--------|--------|-------|------|----------------|
| All | Passwordless (passkeys) | Identity | $300K | 0 passwords |
| All | Autonomous response | SecOps | $500K | MTTR <30 sec |
| App | Confidential computing | Platform | $400K | 100% sensitive in TEE |
| Auto | Policy simulation / what-if | SecEng | $200K | 0 policy regressions |

---

## 5. Compliance Mapping

| Framework | Current Coverage | Target Coverage | Gaps |
|-----------|------------------|-----------------|------|
| NIST 800-53 Rev 5 | 45% | 90% | AC-2, AC-3, SC-7, SI-4 |
| CISA ZTMM | Initial (avg) | Advanced (avg) | All pillars |
| FedRAMP Moderate | 30% | 100% | 125 controls |
| ISO 27001:2022 | 55% | 95% | Annex A.8, A.9, A.12 |
| SOC 2 Type II | 60% | 100% | CC6.1, CC6.2, CC6.7 |

---

## 6. Investment Summary

| Category | Year 1 | Year 2 | Year 3 | Total |
|----------|--------|--------|--------|-------|
| Identity | $500K | $400K | $300K | $1.2M |
| Device | $400K | $300K | $250K | $950K |
| Network | $800K | $600K | $500K | $1.9M |
| Application | $400K | $500K | $400K | $1.3M |
| Data | $600K | $400K | $350K | $1.35M |
| Visibility | $700K | $500K | $450K | $1.65M |
| Automation | $300K | $400K | $300K | $1.0M |
| Personnel | $3.5M | $3.5M | $2.5M | $9.5M |
| **Total** | **$7.2M** | **$6.6M** | **$5.05M** | **$18.85M** |

---

## 7. Appendices

### 7.1 Assessment Methodology
- [Interview list]
- [Document review list]
- [Tool scans performed]
- [Scoring rubric]

### 7.2 Evidence Catalog
| Evidence ID | Description | Location | Pillar |
|-------------|-------------|----------|--------|
| EV-001 | IdP MFA configuration | [Link] | Identity |
| EV-002 | Firewall rule export | [Link] | Network |
| ... | ... | ... | ... |

### 7.3 Stakeholder Sign-Off
| Role | Name | Signature | Date |
|------|------|-----------|------|
| CISO | | | |
| CIO | | | |
| Compliance Officer | | | |
| Platform Lead | | | |

---

*Classification: Confidential. Review annually or after significant change.*