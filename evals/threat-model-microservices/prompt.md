Create a threat model for a Kubernetes-based microservices platform using Zero Trust principles. The platform runs on EKS with:
- 50+ microservices communicating via gRPC
- External API gateway (AWS API GW) for north-south traffic
- RDS PostgreSQL and ElastiCache Redis for data
- GitHub Actions for CI/CD
- ArgoCD for GitOps deployment
- CloudWatch for logging, no SIEM yet

Apply STRIDE per trust zone and map to MITRE ATT&CK. Identify how each NIST 800-207 tenet mitigates threats. Produce:
1. System decomposition with trust zones
2. STRIDE analysis per zone (Internet, Edge, Identity, Platform, Data)
3. Attack trees for: production data access, cluster admin compromise
4. MITRE ATT&CK mapping to ZT tenets
5. Gap analysis of current controls vs ZT mitigations
6. Prioritized mitigations with effort/risk ratings
7. Test cases to validate mitigations