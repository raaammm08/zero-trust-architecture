Map Zero Trust Architecture controls to FedRAMP High baseline. The organization has implemented the following ZT capabilities:

IDENTITY:
- Okta with FIDO2 MFA for all users
- CyberArk PAM for all privileged access (JIT, session recording)
- SPIRE for workload identity (K8s, VMs)
- Automated quarterly access reviews

DEVICE:
- Jamf/Intune 100% coverage with compliance policies
- Real-time posture via CrowdStrike integration
- Device certificates for mTLS
- Automated remediation (quarantine <5 min)

NETWORK:
- Cloudflare Zero Trust (ZTNA, SWG, CASB, DLP)
- Service mesh (Istio) with mTLS STRICT mode
- Micro-segmentation via Istio AuthorizationPolicy
- DNS filtering via Cloudflare Gateway

APPLICATION/WORKLOAD:
- OPA Gatekeeper for admission control
- Falco for runtime security
- Sigstore for image signing (SLSA L2)
- GitOps with ArgoCD + policy gates

DATA:
- Automated classification (ML + regex)
- CMK for all encryption (Cloud KMS + AWS KMS)
- Cloudflare DLP + IRM for data in motion
- Data catalog with lineage

VISIBILITY & ANALYTICS:
- Splunk with 100% log coverage (OCSF)
- UEBA with <5% false positive rate
- SOAR with 15 automated playbooks
- MITRE ATT&CK coverage >85%

AUTOMATION & ORCHESTRATION:
- Policy-as-code (OPA/Cedar) via GitOps
- Automated policy testing in CI/CD
- cATO pipeline with continuous evidence
- Policy simulation for what-if analysis

Produce:
1. Control matrix mapping NIST 800-207 tenets → NIST 800-53 Rev 5 → FedRAMP High controls
2. Evidence checklist for FedRAMP 3PAO assessment
3. Gap analysis for any missing FedRAMP controls
4. Continuous monitoring dashboard specifications
5. cATO package outline