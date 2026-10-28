Assess the Zero Trust maturity of a mid-size enterprise (1,500 employees) with the following current state:

IDENTITY:
- MFA deployed via push notifications for all users (no FIDO2)
- Okta as primary IdP with AD sync
- PAM solution for domain admins only (not cloud/service accounts)
- Manual quarterly access reviews
- No workload identity (static keys in CI/CD)

DEVICE:
- Jamf for Mac, Intune for Windows (80% coverage)
- Basic compliance checks (OS version, encryption)
- No EDR integration with access policy
- No device certificates
- BYOD not supported

NETWORK:
- VPN for remote access (Cisco AnyConnect)
- Flat network with VLANs only (no micro-segmentation)
- TLS 1.2 at edge, no mTLS internally
- Standard DNS (no DoH/DoT, no filtering)

APPLICATION/WORKLOAD:
- Kubernetes (EKS) with no service mesh
- API gateway (AWS API GW) with basic auth
- Container scanning in CI/CD (Trivy)
- No admission control, no runtime protection

DATA:
- No classification schema
- Encryption at rest (AWS KMS default)
- DLP only for email (M365)
- No IRM, no data catalog

VISIBILITY & ANALYTICS:
- Splunk for logs (60% coverage)
- Basic dashboards, no UEBA
- Manual incident response
- No threat intelligence integration

AUTOMATION & ORCHESTRATION:
- Terraform for infrastructure
- Manual policy changes via console
- No policy-as-code
- No SOAR

Produce:
1. CISA ZTMM maturity scorecard with current stage per sub-capability
2. Overall pillar scores (Traditional/Initial/Advanced/Optimal)
3. Top 5 critical gaps with risk ratings
4. Prioritized remediation roadmap (Quick wins, Foundation, Advanced)
5. Investment summary for Year 1-3
6. Success metrics (KPIs) with baselines and targets