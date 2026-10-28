---
name: zero-trust-architecture
description: Comprehensive Zero Trust Architecture skill for designing, implementing, and governing Zero Trust systems. Use this skill whenever the user mentions Zero Trust, ZTNA, micro-segmentation, identity-centric security, SASE/SSE, continuous verification, least privilege access, or any NIST 800-207 / CISA Zero Trust Maturity Model concepts. Trigger on: "zero trust", "ZTNA", "micro-segmentation", "identity-centric", "continuous verification", "least privilege", "SASE", "SSE", "NIST 800-207", "CISA ZTMM", "OPA policies", "Cedar policies", "Zscaler", "Cloudflare Zero Trust", "Okta", "Palo Alto Prisma", "Netskope", "architecture design", "policy creation", "compliance mapping", "gap analysis", "threat modeling", "ZT assessment".
---

# Zero Trust Architecture Skill

This skill provides end-to-end Zero Trust Architecture capabilities: architecture design, policy authoring, implementation guidance, assessment/audit, threat modeling, and compliance mapping — all aligned with NIST SP 800-207 and CISA Zero Trust Maturity Model.

## Core Principles (NIST 800-207)

All outputs must reflect these seven tenets:
1. **All data sources and computing services are resources**
2. **All communication is secured regardless of network location**
3. **Access to individual enterprise resources is granted on a per-session basis**
4. **Access to resources is determined by dynamic policy**
5. **The enterprise monitors and measures the integrity and security posture of all owned and associated assets**
6. **All resource authentication and authorization are dynamic and strictly enforced before access is allowed**
7. **The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture**

## CISA Zero Trust Maturity Model Pillars

Reference `references/cisa-ztmm.md` for detailed maturity stages (Traditional → Initial → Advanced → Optimal) across:
- **Identity** (ICAM, MFA, risk-based auth, continuous auth)
- **Device** (inventory, compliance, posture, BYOD)
- **Network** (micro-segmentation, encrypted traffic, SDP)
- **Application/Workload** (API security, container security, CI/CD integration)
- **Data** (classification, DLP, encryption, rights management)
- **Visibility & Analytics** (logging, UEBA, SOAR integration)
- **Automation & Orchestration** (policy as code, automated remediation)

---

## Workflow Selection

Determine the user's primary intent and follow the corresponding workflow. Multiple workflows can be combined.

### 1. Architecture Design (`design`)

**When**: User wants to design a new ZT architecture, create reference architectures, or define target state.

**Steps**:
1. Gather requirements: org size, cloud/on-prem/hybrid, existing identity provider, compliance needs, threat model
2. Select reference architecture pattern from `references/architecture-patterns.md`
3. Define trust zones and micro-segmentation strategy
4. Design identity fabric (IdP, PAM, JIT access, service accounts)
5. Design device trust (MDM/EDR integration, posture checks)
6. Design network segmentation (SDP, overlay networks, DNS-based controls)
7. Define data flow controls (classification, DLP, encryption)
8. Produce architecture diagram (Mermaid) + decision log

**Outputs**: Architecture document (Markdown), Mermaid diagrams, component inventory, migration phasing plan

### 2. Policy Creation (`policy`)

**When**: User needs to write, review, or test access policies.

**Steps**:
1. Identify policy language target: OPA/Rego, AWS Cedar, Cloudflare Gateway, Zscaler, custom
2. Define policy intent in natural language (who, what, when, where, why, how)
3. Map to policy template from `templates/policies/`
4. Generate policy code with comments
5. Create test cases (positive/negative) in `tests/policy-tests/`
6. Validate syntax and logic

**Outputs**: Policy files (`.rego`, `.cedar`, `.yaml`), test cases, decision logs

### 3. Implementation Guidance (`implement`)

**When**: User needs step-by-step deployment for a specific platform or component.

**Steps**:
1. Identify target platform from `references/vendor-patterns.md`
2. Map architecture design to platform capabilities
3. Generate phased implementation plan with prerequisites
4. Provide configuration snippets (Terraform, CLI, API)
5. Define validation tests for each phase
6. Create rollback procedures

**Outputs**: Implementation runbook, Terraform/CLI configs, validation checklists

### 4. Assessment/Audit (`assess`)

**When**: User wants to evaluate current ZT posture, run gap analysis, or prepare for audit.

**Steps**:
1. Select assessment framework: NIST 800-207, CISA ZTMM, custom
2. Run discovery questions (interactive or from uploaded docs)
3. Score each pillar against maturity model
4. Identify gaps with risk ratings
5. Prioritize remediation by risk/effort
6. Generate executive summary + technical findings

**Outputs**: Assessment report (Markdown/PDF), maturity heatmap, remediation roadmap, evidence checklist

### 5. Threat Modeling (`threat-model`)

**When**: User wants to apply ZT principles to threat modeling or attack surface analysis.

**Steps**:
1. Choose methodology: STRIDE, PASTA, MITRE ATT&CK + ZT mitigations
2. Define system boundaries and trust zones
3. Identify assets, actors, data flows
4. Apply ZT mitigations per tenet (verify explicitly, least privilege, assume breach)
5. Map threats to ZT controls
6. Prioritize by likelihood × impact

**Outputs**: Threat model document, attack trees, mitigation mapping, residual risk register

### 6. Compliance Mapping (`compliance`)

**When**: User needs to map ZT controls to regulatory frameworks.

**Steps**:
1. Identify target frameworks (FedRAMP, CMMC, ISO 27001, SOC 2, HIPAA, PCI-DSS)
2. Map NIST 800-207 tenets to framework controls
3. Identify overlapping and unique requirements
4. Generate control implementation matrix
5. Define evidence artifacts for each control
6. Create continuous monitoring queries

**Outputs**: Compliance matrix (CSV/Excel), evidence collection guide, monitoring dashboard specs

---

## Reference Files

Always check these references before producing outputs:

| File | Purpose |
|------|---------|
| `references/nist-800-207.md` | Core tenets, logical components, deployment models |
| `references/cisa-ztmm.md` | Maturity stages, pillar definitions, assessment criteria |
| `references/architecture-patterns.md` | Reference architectures by org size/cloud model |
| `references/vendor-patterns.md` | Platform-specific patterns (Cloudflare, Zscaler, Okta, AWS, Azure, GCP, Palo Alto, Netskope) |
| `references/policy-languages.md` | OPA/Rego, Cedar, Alpha syntax and best practices |
| `references/threat-modeling.md` | STRIDE/PASTA/MITRE integration with ZT |

---

## Templates

Use templates from `templates/` for consistent outputs:

| Template | Use Case |
|----------|----------|
| `templates/architecture/design-doc.md` | Architecture design document |
| `templates/architecture/migration-plan.md` | Phased migration plan |
| `templates/policies/opa-rego-template.rego` | OPA/Rego policy boilerplate |
| `templates/policies/cedar-template.cedar` | AWS Cedar policy boilerplate |
| `templates/assessment/gap-analysis.md` | Gap analysis report |
| `templates/assessment/maturity-scorecard.xlsx` | Maturity scoring spreadsheet |
| `templates/threat-model/threat-model.md` | Threat model document |
| `templates/compliance/control-matrix.xlsx` | Compliance control mapping |

---

## Scripts

Use scripts from `scripts/` for deterministic tasks:

| Script | Purpose |
|--------|---------|
| `scripts/validate-rego.py` | Validate OPA/Rego syntax and run tests |
| `scripts/validate-cedar.py` | Validate Cedar policy syntax |
| `scripts/generate-mermaid.py` | Generate architecture diagrams from component list |
| `scripts/score-maturity.py` | Calculate ZTMM scores from assessment answers |
| `scripts/map-compliance.py` | Map NIST tenets to framework controls |

---

Setup: `pip install -r requirements.txt` (PyYAML, needed by `score-maturity.py` and `map-compliance.py`). `validate-rego.py` needs OPA 1.x on PATH (`brew install opa`). `validate-cedar.py` needs the `cedar` CLI.

Rego must use OPA v1 syntax: `allow if { ... }`, `deny contains msg if { ... }`, `default allow := false`. Templates in `templates/policies/` are v1 and pass `opa check`.

## Output Formats

**Architecture Design**: Markdown document + Mermaid diagrams + component inventory (JSON)
**Policy Creation**: Policy files (`.rego`, `.cedar`, `.yaml`) + test cases (JSON) + decision log (Markdown)
**Implementation**: Runbook (Markdown) + IaC configs (Terraform/HCL, CLI) + validation checklist
**Assessment**: Report (Markdown) + heatmap (Mermaid) + roadmap (Markdown) + evidence checklist (CSV)
**Threat Model**: Document (Markdown) + attack trees (Mermaid) + mitigation mapping (CSV) + risk register (Excel)
**Compliance**: Control matrix (Excel/CSV) + evidence guide (Markdown) + monitoring specs (JSON)

---

## Interaction Patterns

### Architecture Design
```
User: "Design a Zero Trust architecture for a 500-person fintech startup on AWS"
→ Clarify: compliance needs, existing IdP, data sensitivity, team structure
→ Select pattern: cloud-native, identity-centric, micro-segmented
→ Produce: design doc, diagrams, migration phases
```

### Policy Creation
```
User: "Write an OPA policy: only allow engineers to access production DB during on-call hours with MFA"
→ Generate: Rego policy with time-based + MFA + role conditions
→ Create: test cases for on-call/off-call, MFA present/absent, engineer/non-engineer
```

### Assessment
```
User: "Assess our current Zero Trust maturity against CISA ZTMM"
→ Run: interactive discovery across 7 pillars
→ Score: Traditional/Initial/Advanced/Optimal per pillar
→ Produce: heatmap, gap analysis, prioritized roadmap
```

### Threat Modeling
```
User: "Threat model our new microservices platform with Zero Trust"
→ Apply: STRIDE + ZT mitigations per tenet
→ Map: threats → ZT controls (verify explicitly, least privilege, assume breach)
→ Produce: threat model, residual risk register
```

### Compliance
```
User: "Map our ZT controls to FedRAMP High"
→ Cross-reference: NIST 800-207 tenets → NIST 800-53 controls → FedRAMP baselines
→ Produce: control matrix, evidence artifacts, continuous monitoring queries
```

---

## Quality Gates

Before delivering any output, verify:
- [ ] All seven NIST 800-207 tenets addressed where applicable
- [ ] CISA ZTMM maturity stage explicitly stated for each pillar
- [ ] Policies include positive AND negative test cases
- [ ] Architecture diagrams render valid Mermaid
- [ ] Compliance mappings cite specific control IDs
- [ ] Implementation steps include validation criteria
- [ ] Threat models include ZT-specific mitigations (not just generic)
- [ ] Outputs reference source standards (NIST, CISA, vendor docs)

---

## Example Prompts That Should Trigger This Skill

- "Design a Zero Trust architecture for our migration to Google Cloud"
- "Write an OPA policy for just-in-time database access"
- "Assess our Zero Trust maturity against CISA ZTMM"
- "Create a threat model for our Kubernetes platform using Zero Trust principles"
- "Map our Zero Trust controls to FedRAMP Moderate"
- "Implement micro-segmentation with Cloudflare Zero Trust"
- "Design identity-centric perimeter for hybrid workforce"
- "Review our Zscaler ZIA/ZPA configuration for ZT alignment"
- "Generate a Zero Trust migration roadmap from VPN-based access"
- "Create Cedar policies for AWS resource access with condition keys"

---

## Notes for the Model

- **Default to NIST 800-207** as the authoritative reference unless user specifies otherwise
- **Always cite pillar maturity stages** when doing assessments (Traditional/Initial/Advanced/Optimal)
- **Prefer policy-as-code** (OPA/Rego, Cedar) over vendor-specific UI configs for portability
- **Include test cases** with every policy (run them with `opa test`, not just a syntax check) — this is non-negotiable for ZT
- **Assume breach** in all threat models — design for lateral movement containment
- **Reference the logical components** from NIST 800-207: Policy Engine, Policy Administrator, Policy Enforcement Point
- **Distinguish between ZTNA (access) and ZT (architecture)** — ZTNA is a subset
- **Vendor-neutral first**, then platform-specific implementation guidance