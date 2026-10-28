# Threat Modeling with Zero Trust Reference

Integration of STRIDE, PASTA, MITRE ATT&CK with Zero Trust Architecture principles.

---

## Methodology: STRIDE + Zero Trust

Apply STRIDE per trust zone, then map ZT mitigations.

### STRIDE Categories with ZT Mitigations

| Threat | Traditional Mitigation | **Zero Trust Mitigation** |
|--------|------------------------|---------------------------|
| **Spoofing** | Network segmentation, VLANs | **Continuous verification (Tenet 3,6)**: mTLS, short-lived certs, workload identity (SPIFFE), device attestation, behavioral auth |
| **Tampering** | Integrity checks, WAF | **Dynamic policy (Tenet 4)**: Policy-as-code, signed artifacts (Sigstore), immutable infra, runtime protection (eBPF), confidential computing |
| **Repudiation** | Audit logs, SIEM | **Monitoring & measurement (Tenet 5,7)**: Immutable audit trails, cryptographic logging, continuous monitoring, UEBA |
| **Information Disclosure** | Encryption, DLP | **Secure communication (Tenet 2)**: mTLS everywhere, data-centric encryption (follows data), classification-based policy, IRM |
| **Denial of Service** | Rate limiting, WAF | **Assume breach (Tenet 7)**: Auto-scaling, circuit breakers, graceful degradation, chaos engineering |
| **Elevation of Privilege** | RBAC, least privilege | **Least privilege + dynamic (Tenet 3,4)**: JIT/JEA, context-aware policy, continuous authorization, workload identity |

---

## Trust Zone Modeling

Define trust zones based on NIST 800-207 logical components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet / Untrusted                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Policy Enforcement Point  │
                    │  (ZTNA / IAP / Gateway)    │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼───────┐    ┌───────▼───────┐    ┌───────▼───────┐
│  Identity     │    │   Device      │    │   Network     │
│  Zone         │    │   Zone        │    │   Zone        │
│               │    │               │    │               │
│ • IdP         │    │ • MDM/EDR     │    │ • Micro-seg   │
│ • PAM         │    │ • Posture     │    │ • mTLS        │
│ • JIT         │    │ • Certificates│    │ • SDP         │
└───────────────┘    └───────────────┘    └───────────────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Policy Engine  │
                    │  (Decisions)    │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼───────┐    ┌───────▼───────┐    ┌───────▼───────┐
│  Application  │    │    Data       │    │  Visibility   │
│  Zone         │    │   Zone        │    │   Zone        │
│               │    │               │    │               │
│ • Service Mesh│    │ • Classification│  │ • SIEM/UEBA   │
│ • API Gateway │    │ • DLP/IRM     │    │ • SOAR        │
│ • Runtime     │    │ • Encryption  │    │ • Threat Intel│
└───────────────┘    └───────────────┘    └───────────────┘
```

---

## Attack Surface Analysis per Zone

### Identity Zone
| Asset | Threats | ZT Controls |
|-------|---------|-------------|
| IdP | Credential stuffing, token theft, admin compromise | Phishing-resistant MFA, conditional access, PIM, token binding |
| PAM | Credential theft, session hijack | JIT, session recording, dual-control, automatic rotation |
| Service Accounts | Key compromise, overprivilege | Workload identity (SPIFFE), short-lived tokens, no static keys |

### Device Zone
| Asset | Threats | ZT Controls |
|-------|---------|-------------|
| Endpoints | Malware, rootkits, data exfil | EDR/XDR, posture checks, device certificates, auto-remediation |
| Mobile/BYOD | Data leakage, unmanaged apps | MAM, containerization, selective wipe, app tunneling |
| IoT/OT | Botnets, lateral movement | Passive profiling, micro-segmentation, unidirectional gateways |

### Network Zone
| Asset | Threats | ZT Controls |
|-------|---------|-------------|
| Network Fabric | Lateral movement, reconnaissance | Micro-segmentation, encryption, zero-trust network access |
| DNS | Tunneling, hijacking | DNSSEC, DoH/DoT, DNS filtering, analytics |
| Remote Access | VPN exploits, credential reuse | ZTNA (no VPN), device posture, continuous verification |

### Application Zone
| Asset | Threats | ZT Controls |
|-------|---------|-------------|
| APIs | Injection, broken auth, excessive data | Schema validation, mTLS, rate limiting, fine-grained AuthZ |
| Containers | Escape, supply chain, misconfig | Admission control, runtime security, signed images, SBOM |
| Serverless | Event injection, privilege escalation | Least privilege roles, VPC, runtime protection |

### Data Zone
| Asset | Threats | ZT Controls |
|-------|---------|-------------|
| Databases | SQL injection, excessive access, exfil | Dynamic masking, row-level security, encryption, DLP |
| Object Storage | Public buckets, unauthorized access | Bucket policies, encryption, access logging, MAC |
| SaaS Data | Shadow IT, over-sharing | CASB, DLP, data classification, sharing controls |

### Visibility Zone
| Asset | Threats | ZT Controls |
|-------|---------|-------------|
| SIEM | Log tampering, blind spots | Immutable logs, cryptographic verification, coverage metrics |
| UEBA | Model poisoning, false negatives | Continuous training, adversarial testing, explainable AI |
| Threat Intel | Stale feeds, false positives | Automated validation, scoring, integration with policy |

---

## MITRE ATT&CK Mapping to ZT Tenets

| ATT&CK Tactic | Technique Examples | ZT Tenet(s) | ZT Controls |
|---------------|-------------------|-------------|-------------|
| **Reconnaissance** | Active Scanning, Phishing for Information | 2, 5 | Egress filtering, threat intel feeds, deny-by-default exposure |
| **Resource Development** | Acquire Infrastructure, Compromise Accounts | 5, 6 | Threat intel, identity monitoring, credential rotation |
| **Initial Access** | Phishing, Valid Accounts, Exploit Public-Facing App | 2, 3, 6 | Phishing-resistant MFA, ZTNA (no public apps), device posture |
| **Execution** | Command/Script, Container, User Execution | 4, 5 | Policy-as-code, runtime protection, application allowlisting |
| **Persistence** | Account Manipulation, Scheduled Task, Web Shell | 3, 4, 7 | JIT access, immutable infra, continuous monitoring |
| **Privilege Escalation** | Exploitation, Access Token Manipulation, Sudo | 3, 4, 6 | Least privilege, dynamic policy, continuous verification |
| **Defense Evasion** | Impair Defenses, Rootkit, Process Injection | 5, 7 | EDR/XDR, runtime security, integrity monitoring |
| **Credential Access** | OS Credential Dumping, Network Sniffing, MFA Interception | 2, 3, 6 | mTLS, short-lived creds, phishing-resistant MFA, token binding |
| **Discovery** | Network Scan, Permission Groups, Cloud Instance Metadata | 1, 4 | Micro-segmentation, dynamic policy, metadata service protection |
| **Lateral Movement** | Remote Services, Pass the Hash, SSH Hijacking | 1, 2, 3, 4 | Micro-segmentation, mTLS, workload identity, no implicit trust |
| **Collection** | Data from Local System, Email, Cloud Storage | 1, 5 | Data classification, DLP, encryption, access logging |
| **Command & Control** | App Layer Protocol, Encrypted Channel, Proxy | 2, 5, 7 | TLS inspection, DNS filtering, egress controls, UEBA |
| **Exfiltration** | Exfil over C2, Web Service, Cloud Storage | 1, 2, 5 | Data-centric policy, DLP, egress inspection, classification |
| **Impact** | Ransomware, Data Destruction, Service Stop | 4, 5, 7 | Immutable backups, automated response, chaos engineering |

---

## Threat Modeling Process (Zero Trust Edition)

### Step 1: System Decomposition
1. Identify all resources (Tenet 1)
2. Map trust zones and data flows
3. Identify Policy Engine, Administrator, Enforcement Points
4. Document identity providers, device management, network segments

### Step 2: Threat Enumeration
1. Apply STRIDE per trust zone
2. Map ATT&CK techniques to each zone
3. Consider insider threat (assume breach)
4. Consider supply chain (dependencies, CI/CD)

### Step 3: ZT Control Mapping
For each threat, identify which ZT tenet(s) mitigate:
- **Prevent**: Tenets 2, 3, 4, 6 (verify, least privilege, dynamic policy)
- **Detect**: Tenets 5, 7 (monitor, collect, analyze)
- **Respond**: Tenet 7 (automated orchestration)
- **Recover**: Tenet 5 (integrity measurement, posture)

### Step 4: Gap Analysis
| Threat | Current Controls | ZT Tenet | Gap | Residual Risk |
|--------|-----------------|----------|-----|---------------|
| Phishing → Credential Theft | MFA (SMS) | 6 | Phishing-resistant MFA missing | High |
| Lateral Movement | VLANs | 1,2 | Micro-segmentation not deployed | Critical |
| Data Exfil | DLP (email only) | 1,5 | No cloud/storage DLP | High |

### Step 5: Risk Prioritization
```
Risk = Likelihood × Impact × (1 - Control_Effectiveness)

Control_Effectiveness:
  0.9 = Optimal ZT control (automated, continuous)
  0.7 = Advanced ZT control (mostly automated)
  0.5 = Initial ZT control (partial, manual)
  0.2 = Traditional control (perimeter-based)
  0.0 = No control
```

### Step 6: Mitigation Roadmap
Prioritize by:
1. **Critical gaps** in Identity/Device (foundational)
2. **High-risk** lateral movement paths
3. **Compliance-driven** data protection
4. **Visibility** gaps for detection

---

## Example: Microservices Platform Threat Model

### System
- Kubernetes (EKS/GKE/AKS)
- Service mesh (Istio)
- External API Gateway
- PostgreSQL + Redis
- CI/CD (GitHub Actions/GitLab)

### Threat Model Summary

| # | Threat | STRIDE | Zone | ATT&CK | ZT Tenet | Current | Target | Gap |
|---|--------|--------|------|--------|----------|---------|--------|-----|
| 1 | Pod compromise → lateral movement | EoP | App | T1021, T1550 | 1,2,3,4 | Namespace isolation | mTLS + AuthZ per service | Critical |
| 2 | Stolen service account token | CredAccess | Identity | T1528 | 3,6 | Long-lived tokens | SPIFFE/SPIRE, 1hr TTL | High |
| 3 | Container image supply chain | Tampering | App | T1195 | 4,5 | Basic scanning | Sigstore + SLSA L3 | Medium |
| 4 | Database credential leak | InfoDisc | Data | T1555 | 1,2,5 | Env vars | Vault + dynamic creds | High |
| 5 | Admin credential phishing | Spoofing | Identity | T1566 | 6 | MFA (push) | FIDO2 + Conditional Access | Critical |
| 6 | Unencrypted service traffic | InfoDisc | Network | T1040 | 2 | Plaintext | mTLS (Istio STRICT) | High |

### Mitigation Roadmap
1. **Week 1-2**: Enable Istio STRICT mTLS, deploy SPIRE
2. **Week 3-4**: Vault dynamic secrets, remove env vars
3. **Month 2**: FIDO2 rollout, conditional access policies
4. **Month 3**: SLSA L3 supply chain, admission policies
5. **Ongoing**: UEBA tuning, automated response playbooks

---

## Threat Model Template

```markdown
# Threat Model: [System Name]

## System Overview
- **Scope**: [What's in/out of scope]
- **Architecture**: [Reference diagram]
- **Trust Zones**: [List with boundaries]
- **Data Classifications**: [Types handled]

## Threat Enumeration

| ID | Threat | STRIDE | Zone | ATT&CK | Likelihood | Impact | Current Controls | ZT Tenet | Gap | Residual Risk |
|----|--------|--------|------|--------|------------|--------|------------------|----------|-----|---------------|
| TM-001 | ... | ... | ... | ... | High/Med/Low | High/Med/Low | ... | ... | ... | Critical/High/Med/Low |

## ZT Control Coverage Matrix

| Tenet | Controls Implemented | Coverage % | Gaps |
|-------|---------------------|------------|------|
| 1. All resources | ... | 80% | IoT devices not inventoried |
| 2. Secure comms | mTLS (internal), TLS (external) | 90% | Legacy app no mTLS |
| 3. Per-session | JIT for admin, not for users | 60% | User sessions long-lived |
| 4. Dynamic policy | OPA for K8s, not for SaaS | 70% | SaaS apps static RBAC |
| 5. Monitor posture | EDR, K8s audit | 85% | Device posture not in policy |
| 6. Dynamic authZ | Conditional Access, OPA | 75% | No continuous re-auth |
| 7. Collect/improve | SIEM, basic UEBA | 60% | No automated response |

## Prioritized Mitigations

| Priority | Mitigation | Tenet | Effort | Owner | Target Date |
|----------|------------|-------|--------|-------|-------------|
| 1 | Deploy FIDO2 + Conditional Access | 6 | Medium | IAM | 2024-Q2 |
| 2 | Istio STRICT mTLS + AuthZ policies | 2,4 | High | Platform | 2024-Q2 |
| 3 | SPIRE for workload identity | 3,6 | Medium | Platform | 2024-Q3 |
| 4 | Vault dynamic database credentials | 1,2 | Medium | Security | 2024-Q3 |

## Assumptions & Dependencies
- [List assumptions]
- [External dependencies]

## Review Schedule
- **Next Review**: [Date]
- **Trigger Events**: Architecture change, incident, new compliance req
```

---

## Tools & Automation

### Threat Modeling Tools
- **Microsoft Threat Modeling Tool** (STRIDE, DFD)
- **OWASP Threat Dragon** (Open source, STRIDE/LINDDUN)
- **IriusRisk** (Commercial, standards mapping)
- **Custom**: Mermaid + Markdown + CI/CD

### ZT-Specific Automation
```python
# scripts/generate-threats.py
# Input: Architecture components (YAML)
# Output: Threat model (Markdown) with STRIDE per zone + ZT mitigations

# scripts/map-attack-to-zt.py
# Input: ATT&CK techniques observed/relevant
# Output: ZT tenet coverage matrix + gap analysis
```

---

## Key References

- NIST SP 800-207 Section 3.3 (Threat Modeling)
- MITRE ATT&CK: https://attack.mitre.org/
- STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- PASTA: https://www.verisgroup.com/pasta-threat-modeling/
- Google BeyondCorp Threat Model: https://cloud.google.com/beyondcorp/docs/threat-model