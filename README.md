# Zero Trust Architecture Skill

A Claude Code skill and a set of command-line tools for:

- designing Zero Trust architectures,
- writing and testing access policies (OPA/Rego and AWS Cedar),
- scoring your Zero Trust maturity (CISA ZTMM v2),
- mapping controls to compliance frameworks (NIST SP 800-53, FedRAMP High, and more),
- building threat models (STRIDE, MITRE ATT&CK).

It is aligned with **NIST SP 800-207** (the default reference) and the **CISA Zero Trust Maturity Model v2**.

**Pick your starting point:**

| If you are... | Start here |
|---------------|-----------|
| New to Zero Trust, or new to the command line | [Part 1: Concepts](#part-1-concepts), then [Part 2: Setup](#part-2-setup-step-by-step), then [Part 4: Your first 15 minutes](#part-4-your-first-15-minutes) |
| Comfortable with a terminal, new to this skill | [Part 2: Setup](#part-2-setup-step-by-step), then [Part 5: Command reference](#part-5-command-reference-every-script-every-flag) |
| An experienced engineer or security architect | [Part 5: Command reference](#part-5-command-reference-every-script-every-flag), [Part 6: Input files](#part-6-input-file-reference), [Part 8: Extending](#part-8-extending-the-skill) |
| Stuck on an error | [Part 9: Troubleshooting](#part-9-troubleshooting) |

---

## Table of contents

- [Part 1: Concepts](#part-1-concepts)
- [Part 2: Setup, step by step](#part-2-setup-step-by-step)
- [Part 3: Two ways to use the skill](#part-3-two-ways-to-use-the-skill)
- [Part 4: Your first 15 minutes](#part-4-your-first-15-minutes)
- [Part 5: Command reference (every script, every flag)](#part-5-command-reference-every-script-every-flag)
- [Part 6: Input file reference](#part-6-input-file-reference)
- [Part 7: Worked scenarios](#part-7-worked-scenarios)
- [Part 8: Extending the skill](#part-8-extending-the-skill)
- [Part 9: Troubleshooting](#part-9-troubleshooting)
- [Part 10: Verifying the skill works](#part-10-verifying-the-skill-works)
- [Part 11: Repository layout](#part-11-repository-layout)
- [Part 12: Limitations and gotchas](#part-12-limitations-and-gotchas)
- [Glossary](#glossary)

---

## Part 1: Concepts

### What is Zero Trust?

Traditional security trusted anything inside the corporate network. Zero Trust assumes breach: no user, device, or service is trusted because of where it sits. Every access request is checked (verified, authorized, logged) before it is allowed, and the check is repeated over time.

NIST SP 800-207 defines seven tenets. The skill uses them as its checklist:

1. All data sources and computing services are resources.
2. All communication is secured regardless of network location.
3. Access to each resource is granted per session.
4. Access is decided by dynamic policy.
5. The enterprise monitors the security posture of all its assets.
6. Authentication and authorization are dynamic and strictly enforced before access.
7. The enterprise collects as much information as possible and uses it to improve security.

### What is CISA ZTMM?

The CISA Zero Trust Maturity Model rates your organization in seven **pillars**:

| Pillar | What it covers |
|--------|----------------|
| Identity | Who the user is: MFA, privileged access, workload identity |
| Device | Whether the device is managed and healthy |
| Network | Segmentation, encryption, remote access |
| Application/Workload | APIs, containers, service mesh, CI/CD |
| Data | Classification, encryption, data loss prevention |
| Visibility & Analytics | Logging, behaviour analytics, response automation |
| Automation & Orchestration | Policy as code, automated compliance |

Each pillar has five **sub-capabilities** (35 in total). Each one is scored at one of four **stages**:

| Stage | Meaning in brief |
|-------|------------------|
| Traditional | Perimeter-based, mostly manual, static credentials |
| Initial | Some Zero Trust controls in place, not yet consistent |
| Advanced | Consistent, automated controls across the pillar |
| Optimal | Continuous, adaptive, and fully automated |

A pillar's stage is its **weakest** sub-capability. One Traditional item keeps the whole pillar at Traditional.

### What is a policy, and what are OPA/Rego and Cedar?

A **policy** is a rule that says who may do what, under which conditions. Policy-as-code means writing those rules in a language that a computer can run and test.

- **OPA (Open Policy Agent)** with its language **Rego** is widely used in Kubernetes and cloud systems.
- **Cedar** is AWS's policy language, used in Amazon Verified Permissions and other AWS services.

Both can be tested automatically. This skill includes validators and test cases for each.

### What is a compliance mapping?

Frameworks such as FedRAMP High and SOC 2 list required controls (for example, "AC-2: Account Management"). A **mapping** shows which Zero Trust capability satisfies which control. The skill produces the mapping, a list of evidence an assessor will ask for, and a continuous-monitoring plan.

### What is a threat model?

A structured list of how a system could be attacked, and what stops each attack. The skill uses **STRIDE** (six threat categories) per trust zone, and maps attacker behaviour to **MITRE ATT&CK** techniques (`T1078`, `T1552`, and so on).

### What does the skill produce?

| Workflow | You get |
|----------|---------|
| Architecture design | A design document, Mermaid diagrams, a component inventory, a migration plan, a risk register |
| Policy creation | Policy files and test cases that pass or fail |
| Implementation | A runbook with configuration steps and checks |
| Assessment | A maturity scorecard, a gap analysis, a roadmap, KPI targets |
| Threat modeling | A threat model, attack trees, a mapping to ZT tenets, validation tests |
| Compliance mapping | A control matrix, an evidence checklist, a monitoring spec, a cATO outline |

---

## Part 2: Setup, step by step

You need three things: **Python**, **Git**, and (for policy work) **OPA** and **Cedar**. Pick your operating system below.

### 2.1 Check what you already have

Open a terminal and run:

```bash
python3 --version   # needs 3.9 or newer
git --version
```

If `python3` is missing or older than 3.9, install Python from [python.org](https://www.python.org/downloads/) or your package manager.

### 2.2 Install on macOS

macOS is the platform the skill was built and tested on. These commands use [Homebrew](https://brew.sh). If you do not have Homebrew, install it first using the command on its website.

```bash
brew install python git
brew install opa                 # needed for Rego validation and `opa test`
brew install rust                # needed to build the Cedar CLI
cargo install cedar-policy-cli   # Cedar CLI; takes several minutes the first time
```

### 2.3 Install on Linux (Debian or Ubuntu)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl
```

For OPA, follow the official instructions at [openpolicyagent.org/docs](https://www.openpolicyagent.org/docs/latest/#running-opa) for your architecture, and put the `opa` binary on your PATH.

For Rust and Cedar:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # accept the defaults
source "$HOME/.cargo/env"
cargo install cedar-policy-cli
```

### 2.4 Install on Windows

Use **WSL2** (Windows Subsystem for Linux) and follow section 2.3 inside the Ubuntu shell. The scripts are Python and the policy tools are command-line programs, so they run most reliably in a Linux environment.

### 2.5 Install the skill

Clone the repository into your Claude skills folder:

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/raaammm08/zero-trust-architecture.git ~/.claude/skills/zero-trust-architecture
```

Install the Python dependency (PyYAML):

```bash
cd ~/.claude/skills/zero-trust-architecture
python3 -m pip install -r requirements.txt
```

If pip reports `externally-managed-environment` (common on newer Linux systems), use a virtual environment:

```bash
python3 -m venv ~/.venvs/zt
source ~/.venvs/zt/bin/activate
python3 -m pip install -r requirements.txt
```

Activate that environment (`source ~/.venvs/zt/bin/activate`) in any terminal before running the scripts.

### 2.6 Confirm the setup

Run this from any folder:

```bash
python3 -c "import yaml; print('PyYAML OK')"          # expect: PyYAML OK
opa version | head -1                                 # expect: Version: 1.x.x
cedar --version || ~/.cargo/bin/cedar --version       # expect: cedar-policy-cli 4.x.x
ls ~/.claude/skills/zero-trust-architecture/SKILL.md  # expect: the path, no error
```

If `cedar` is not on your PATH, the validator still finds it at `~/.cargo/bin/cedar`. The `opa` and `cedar` checks are needed only for policy work. The architecture, assessment, and compliance tools need only Python and PyYAML.

### 2.7 Versions tested

| Tool | Version |
|------|---------|
| Python | 3.9 (macOS system Python) |
| PyYAML | 6.0 |
| OPA | 1.21.4 |
| cedar-policy-cli | 4.14.0 |
| Mermaid parser (for diagram checks) | 11 |

Newer versions should work. OPA 0.x (the old Rego syntax) does not work with the templates. Use OPA 1.x.

---

## Part 3: Two ways to use the skill

### Way A: Inside Claude Code (no programming needed)

Open Claude Code in the project folder where you want the output, and describe your goal in plain English. Claude loads the skill when your request matches its topics. You can also call it by name:

```
/zero-trust-architecture design a Zero Trust architecture for a 200-person fintech on AWS
```

Good requests, one per workflow:

| Workflow | Example request |
|----------|-----------------|
| Design | "Design a Zero Trust architecture for our migration to Google Cloud. 500 staff, Okta and EKS." |
| Policy | "Write an OPA policy so only on-call engineers can reach production databases, with MFA within the last hour." |
| Implementation | "Implement micro-segmentation with Cloudflare Zero Trust, step by step, with validation after each phase." |
| Assessment | "Assess our Zero Trust maturity against CISA ZTMM. Here are our current controls: [describe them]." |
| Threat model | "Threat model our Kubernetes platform using STRIDE per trust zone, mapped to MITRE ATT&CK." |
| Compliance | "Map our Zero Trust controls to FedRAMP High. Produce a control matrix and an evidence checklist." |

The more specific your inputs, the more specific the output. Give Claude:

- the platforms you use (identity provider, cloud, Kubernetes, and so on),
- the size of the organization,
- the compliance target,
- what is already in place, and what is missing.

Claude usually writes the deliverables into your project folder. To be sure of the file name and location, ask for it explicitly: "save the control matrix as control_matrix.csv".

### Way B: From the terminal (repeatable, scriptable)

Run the scripts directly, as described in [Part 5](#part-5-command-reference-every-script-every-flag). This is the right choice when you want:

- the same result every time (the scripts are deterministic),
- to put checks in a CI pipeline,
- to produce files for an auditor without a language model in the loop.

The scripts do the checking and calculating. The model is needed only for the narrative documents (design text, gap descriptions, roadmaps).

---

## Part 4: Your first 15 minutes

This walkthrough takes you from a fresh install to a finished result in about 15 minutes. Each command has an expected output.

### Step 1: Go to the skill folder

```bash
cd ~/.claude/skills/zero-trust-architecture
```

### Step 2: Score the sample maturity assessment

```bash
python3 scripts/score-maturity.py examples/sample-assessment.yaml
```

You will see a JSON dump, then a summary like this:

```
==================================================
MATURITY ASSESSMENT SUMMARY
==================================================
Overall: Traditional (1.0/4.0)
  Identity: Traditional (1.60)
  Device: Traditional (1.40)
  ...
```

What this means: the sample organization is at Traditional overall. The number in brackets is the pillar's average score, where 1 = Traditional, 2 = Initial, 3 = Advanced, 4 = Optimal.

Now write the same result to a readable report:

```bash
python3 scripts/score-maturity.py examples/sample-assessment.yaml -o my-scorecard.md --format markdown
open my-scorecard.md        # macOS; use xdg-open on Linux
```

The Markdown report has an executive summary, a pillar table, every sub-capability, and a prioritized list of actions.

### Step 3: Draw an architecture

```bash
python3 scripts/generate-mermaid.py examples/architecture-example.yaml -o my-architecture.mmd
```

Open `my-architecture.mmd` in any Mermaid viewer. Paste its contents into [mermaid.live](https://mermaid.live) to see the picture. Each trust zone becomes a coloured box, and each component is a node inside its zone.

### Step 4: Map controls to FedRAMP High

```bash
python3 scripts/map-compliance.py --framework fedramp_high --format csv -o control_matrix.csv
head -3 control_matrix.csv
```

Expected output (abbreviated):

```
ZT Tenet,Tenet Number,ZT Implementation,NIST 800-53,FedRAMP High
All data sources and computing services are resources,1,"Automated asset discovery, ...",CM-8; CM-9; PM-5; RA-5; SA-12,...
```

Open `control_matrix.csv` in Excel or Numbers. Each row is one of the seven tenets, with the controls that implement it.

### Step 5: Run a policy test

```bash
opa test -v examples/policies/jit-db-access
```

The output ends with:

```
PASS: 6/6
```

Six tests check the just-in-time database policy. An on-call engineer is allowed. An off-call engineer, a non-engineer, a non-compliant device, missing MFA, and a high risk score are each denied.

### Step 6: Validate a Cedar policy

```bash
python3 scripts/validate-cedar.py templates/policies
```

The output ends with:

```
Valid: True
Policies checked: 1
Tests run: 13 (passed 13, failed 0)
```

If this fails, see [Part 9](#part-9-troubleshooting), "Cedar CLI not found".

### Step 7: Check everything at once

Run the checks in [Part 10](#part-10-verifying-the-skill-works). If none fail, the skill works on your machine.

You have now run each kind of tool the skill contains. The rest of this page explains each one in full.

---

## Part 5: Command reference (every script, every flag)

All commands assume you are in the skill folder (`cd ~/.claude/skills/zero-trust-architecture`) and that `python3` is the Python you installed. Every script accepts `-h` (or `--help`), which prints its options.

Conventions:

- `-o FILE` (or `--output FILE`) writes to a file. Without it, most scripts print to the terminal.
- Exit code `0` means success. Any other value means something failed. The script prints the reason.

### 5.1 `generate-mermaid.py`: architecture diagrams

Turns an architecture YAML file (zones and components) into a Mermaid diagram.

```
python3 scripts/generate-mermaid.py INPUT [--type {architecture,dataflow,matrix}] [--details] [-o OUTPUT]
```

| Argument | Required | Meaning |
|----------|----------|---------|
| `INPUT` | yes | Your architecture YAML file. See [6.1](#61-architecture-yaml). |
| `--type architecture` | default | One subgraph per trust zone, with components and connections. |
| `--type dataflow` | no | A diagram of the connections between components, in data-flow style. |
| `--type matrix` | no | A matrix view of how the zones connect. |
| `--details` | no | Adds component details (descriptions) to the diagram. |
| `-o OUTPUT` | no | File to write. Without it, the diagram prints to the terminal. |

Examples:

```bash
# Print the architecture diagram to the terminal
python3 scripts/generate-mermaid.py examples/architecture-example.yaml

# Save all three diagram types
python3 scripts/generate-mermaid.py examples/architecture-example.yaml --type architecture --details -o arch.mmd
python3 scripts/generate-mermaid.py examples/architecture-example.yaml --type dataflow -o flow.mmd
python3 scripts/generate-mermaid.py examples/architecture-example.yaml --type matrix -o matrix.mmd
```

Output format: the file starts with `graph TB` for the architecture diagram, or `graph LR` for the data-flow diagram. Every label is quoted, so commas, parentheses, and brackets in your text are safe.

Viewing the result:

- **GitHub, GitLab, and many wikis** render a fenced code block tagged `mermaid` directly.
- **mermaid.live** renders any `.mmd` contents you paste into it.
- **VS Code**: install a Mermaid preview extension.

Write one diagram per `.mmd` file. Two `graph` blocks in one file are invalid.

### 5.2 `map-compliance.py`: control mapping and evidence

Maps the seven NIST 800-207 tenets to controls in several frameworks, and produces evidence checklists.

```
python3 scripts/map-compliance.py [--framework FW] [--format FMT] [-o OUTPUT]
python3 scripts/map-compliance.py --evidence-checklist FW [-o OUTPUT]
python3 scripts/map-compliance.py --tenet N
```

| Option | Values | Default | Meaning |
|--------|--------|---------|---------|
| `--framework` | `nist_800_53`, `fedramp_high`, `cmmc_20_l3`, `iso_27001_2022`, `soc2`, `hipaa`, `pci_dss_40`, `all` | `all` | Which framework's controls to include. Choosing `fedramp_high` also includes its NIST 800-53 base column. |
| `--format` | `csv`, `json`, `yaml`, `markdown` | `csv` | Output format. `yaml` needs PyYAML (installed in setup). |
| `-o`, `--output` | any file name | `control-matrix.<format>` | Where to write the matrix. |
| `--evidence-checklist` | same framework values | none | Produces an evidence checklist instead of a matrix. |
| `--tenet` | `1` to `7` | none | Prints one tenet's mapping as JSON to the terminal. |

Examples:

```bash
# Control matrix, all frameworks, default name (control-matrix.csv)
python3 scripts/map-compliance.py

# FedRAMP High as JSON
python3 scripts/map-compliance.py --framework fedramp_high --format json -o fedramp.json

# SOC 2 as a Markdown table
python3 scripts/map-compliance.py --framework soc2 --format markdown -o soc2.md

# Evidence checklist for FedRAMP High: one row per (control, evidence item)
python3 scripts/map-compliance.py --evidence-checklist fedramp_high -o evidence.csv

# Tenet 3 in detail
python3 scripts/map-compliance.py --tenet 3
```

Reading the output:

- **Control matrix (csv):** one row per tenet. The framework columns list the controls, separated by semicolons.
- **Evidence checklist (csv):** one row per (control, evidence item) pair, with empty `collected`, `location`, and `notes` columns for you to fill in.
- **`--tenet`:** `zt_implementation` says what to build, and `evidence_required` says what an assessor will ask to see.

The control mappings are built into the script. Check them against the current NIST and FedRAMP baselines before you rely on them in an assessment.

### 5.3 `score-maturity.py`: CISA ZTMM scoring

Calculates Zero Trust maturity from your answers.

```
python3 scripts/score-maturity.py ASSESSMENT [-o OUTPUT] [--format {json,yaml,markdown}]
```

| Argument | Meaning |
|----------|---------|
| `ASSESSMENT` | Your assessment YAML. See [6.2](#62-assessment-yaml). |
| `-o`, `--output` | File to write. Without it, JSON prints to the terminal. |
| `--format json` | Default. Machine-readable results: pillar scores, sub-capability stages, recommendations. |
| `--format yaml` | The same results as YAML. |
| `--format markdown` | A report for people: summary, pillar table, sub-capability table, prioritized recommendations. |

Examples:

```bash
python3 scripts/score-maturity.py my-assessment.yaml -o scorecard.json
python3 scripts/score-maturity.py my-assessment.yaml -o scorecard.md --format markdown
```

What the numbers mean:

- **Overall stage:** the average of the seven pillar stages, rounded.
- **Pillar stage:** the lowest of that pillar's five sub-capabilities (weakest link).
- **Pillar score (for example `1.60`):** the average of its five sub-capabilities, on a 1-to-4 scale. Use it to compare pillars that share a stage.
- **Recommendations:** the weakest sub-capability in each pillar, with the next stage as the target.

Messages you may see:

- `Error: Unknown maturity stage 'xyz'`: the stage must be `traditional`, `initial`, `advanced`, or `optimal`. Check the spelling.
- `WARNING: no answer for <pillar> / <sub-capability>; scored Traditional`: a sub-capability is missing from your file. Add it, or accept the Traditional default on purpose.

### 5.4 `validate-rego.py`: OPA/Rego policy checks

Checks every `.rego` file in a folder: syntax, the safe-default and deny-rule conventions, and whether a test file exists.

```
python3 scripts/validate-rego.py POLICY_DIR [-o OUTPUT] [--strict]
```

| Argument | Meaning |
|----------|---------|
| `POLICY_DIR` | A folder containing `.rego` files. It is searched recursively. |
| `-o`, `--output` | Writes a JSON report with the errors, warnings, and test counts. |
| `--strict` | Treats warnings as errors. The script exits 1 if there are any warnings. Use it in CI. |

Checks performed:

| Check | Severity |
|-------|----------|
| Rego syntax (OPA parser) | error |
| `default allow = false` (or `default allow := false`) present | warning |
| Explicit deny rules (`deny contains ...` or `deny[...]`) present | warning |
| A matching `*_test.rego` file exists | warning |

Examples:

```bash
python3 scripts/validate-rego.py examples/policies/jit-db-access -o rego-report.json
python3 scripts/validate-rego.py examples/policies/jit-db-access --strict   # exits 1 on any warning
```

The JIT example prints two advisory warnings: no session validation, and no data classification check. They are real gaps in that example policy, not errors. Add those checks if your environment needs them. Because of them, the example itself exits 1 under `--strict`.

Requires OPA on your PATH. If it is missing, the validator reports `opa not found`.

### 5.5 `validate-cedar.py`: Cedar policy checks and test cases

Checks Cedar policies against a schema, runs authorization test cases, and reports pattern gaps.

```
python3 scripts/validate-cedar.py POLICY_DIR [-o OUTPUT] [--strict]
```

| Argument | Meaning |
|----------|---------|
| `POLICY_DIR` | A folder containing `.cedar` policies, a schema, and test files. |
| `-o`, `--output` | Writes a JSON report with each test result. |
| `--strict` | Treats warnings as errors. |

What the validator looks for in `POLICY_DIR`:

- **Policies:** every `*.cedar` file.
- **Schema:** the first `*.cedarschema` file, or else a `*schema*.json` file. Without a schema, policies get a syntax-only check and the validator prints a warning.
- **Tests:** every `*tests*.json` file. It needs an `entities` key (the entity data file, relative to the test file) and a `cases` list (see [6.3](#63-cedar-test-cases)).

Each test case has an expected decision, `ALLOW` or `DENY`. A case passes only when Cedar's decision matches.

Example:

```bash
python3 scripts/validate-cedar.py templates/policies -o cedar-report.json
```

Exit code `0` means every policy parsed and every case matched. Exit code `1` means something failed. The report lists which cases failed and what Cedar decided.

Requires the Cedar CLI (`cargo install cedar-policy-cli`). The validator also looks in `~/.cargo/bin/` if `cedar` is not on your PATH.

### 5.6 `opa test`: running Rego unit tests

This is the OPA command, not a skill script. Use it to run the test files.

```bash
opa test -v examples/policies/jit-db-access          # verbose: one line per test
opa test examples/policies/jit-db-access             # summary only
opa check templates/policies/opa-rego-template.rego  # syntax check only
```

`-v` shows each test as `PASS` or `FAIL`. A failing test prints the inputs and the value it got.

### 5.7 Quick reference

| Script | Purpose | Main input | Main output |
|--------|---------|------------|-------------|
| `generate-mermaid.py` | Architecture diagrams | Architecture YAML | `.mmd` file |
| `map-compliance.py` | Control mapping, evidence | Built-in data | CSV, JSON, YAML, or Markdown |
| `score-maturity.py` | ZTMM scoring | Assessment YAML | JSON, YAML, or Markdown |
| `validate-rego.py` | Rego checks | Folder of `.rego` | Terminal or JSON report |
| `validate-cedar.py` | Cedar checks and tests | Folder of `.cedar`, schema, tests | Terminal or JSON report |

---

## Part 6: Input file reference

### 6.1 Architecture YAML

Used by `generate-mermaid.py`. Start from `examples/architecture-example.yaml`.

```yaml
zones:
  - id: identity                 # short unique name, used as the subgraph id
    name: Identity Fabric        # accepted, but the diagram title comes from `type` (see below)
    type: identity               # one of the zone types listed below
    components: [okta, pam]      # component ids that belong to this zone
    trust_assumptions: "High trust, continuously monitored"
    boundary_controls: "FIDO2 MFA, conditional access, JIT"

components:
  - id: okta
    name: Okta                   # the text shown on the diagram
    zone: identity               # must match a zone id AND be listed in that zone's components
    type: identity               # controls the node shape (see below)
    description: "SSO and FIDO2"
    connections: [mdm]           # ids of components this one talks to
```

Allowed zone `type` values. Each sets the diagram title and colour:

| `type` | Diagram title |
|--------|---------------|
| `internet` | Internet / Untrusted |
| `edge` | Edge / ZTNA |
| `identity` | Identity Fabric |
| `device` | Device Trust |
| `network` | Network Segmentation |
| `platform` | Platform / Workloads |
| `application` | Applications |
| `data` | Data Protection |
| `visibility` | Visibility & Analytics |

Component `type` values set the node shape:

| `type` | Shape | Typical use |
|--------|-------|-------------|
| `gateway`, `proxy`, `pep` | Double-bordered box | Policy enforcement points, gateways |
| `database`, `store` | Cylinder | RDS, S3, databases |
| `identity`, `idp`, `pam` | Circle | Identity providers, privileged access |
| anything else | Plain box | Services, devices, users |

Rules and gotchas (these are verified behaviours of the generator):

- A component must appear in **both** its zone's `components` list **and** have `zone:` set to that zone. If it appears in only one place, it is left out of the diagram without an error.
- A `connections` entry that names an unknown component is **not** reported. It produces an arrow to an empty node, so check your ids.
- Zone titles come from the zone `type`. Your `name` is accepted but not shown.
- Zone `type` and component `zone` values must be one of the listed zone types. Other values stop the run with an error.

### 6.2 Assessment YAML

Used by `score-maturity.py`. Start from `examples/sample-assessment.yaml`.

```yaml
metadata:
  organization: "Example Corp"
  date: "2026-01-15"
  assessor: "Security Team"
  framework: "CISA ZTMM v2"

Identity:                        # pillar names must match exactly
  Authentication: "initial"      # sub-capability names must match exactly
  Identity Lifecycle: "initial"
  Privileged Access: "initial"
  Workload Identity: "traditional"
  Identity Threat Detection: "traditional"
# ...then Device, Network, Application/Workload, Data, Visibility & Analytics, Automation & Orchestration
```

Exact pillar names (case-sensitive):

- `Identity`
- `Device`
- `Network`
- `Application/Workload`
- `Data`
- `Visibility & Analytics`
- `Automation & Orchestration`

Exact sub-capability names per pillar:

| Pillar | Sub-capabilities |
|--------|------------------|
| Identity | Authentication; Identity Lifecycle; Privileged Access; Workload Identity; Identity Threat Detection |
| Device | Device Inventory; Device Posture; Device Authentication; BYOD / Personal Devices; IoT / OT Devices |
| Network | Network Segmentation; Encryption; Remote Access; DNS Security; Software-Defined Networking |
| Application/Workload | API Security; Container / Workload Security; Service Mesh; CI/CD Security; Application Identity |
| Data | Data Classification; Encryption; Data Loss Prevention; Access Governance; Data Monitoring |
| Visibility & Analytics | Logging & Telemetry; User/Entity Behavior Analytics; Security Orchestration (SOAR); Threat Intelligence; Cross-Pillar Correlation |
| Automation & Orchestration | Policy as Code; Infrastructure as Code; Adaptive/Contextual Policy; Automated Compliance; ChatOps / Collaboration |

Allowed stage values (case-insensitive): `traditional`, `initial`, `advanced`, `optimal`.

How to fill it in honestly:

1. For each sub-capability, read the stage definitions in `references/cisa-ztmm.md`.
2. Choose the **highest stage you can prove**, not the one you intend to reach.
3. Leave nothing out. A missing sub-capability is scored Traditional, with a warning.

### 6.3 Cedar test cases

Used by `validate-cedar.py`. Lives in a `*tests*.json` file, for example `templates/policies/tests/cedar-tests.json`.

```json
{
  "entities": "entities.json",
  "cases": [
    {
      "name": "on-call engineer, compliant device",
      "principal": "ZeroTrust::User::\"alice\"",
      "action": "ZeroTrust::Action::\"connect\"",
      "resource": "ZeroTrust::Database::\"prod-db-1\"",
      "context": {"now": 1793448000, "network": "corporate", "country": "US", "compromisedCredentials": false},
      "expect": "ALLOW"
    }
  ]
}
```

- `entities` is the file of entity data (users, devices, resources), relative to the test file. Its structure is shown in `templates/policies/tests/entities.json`.
- `context` must contain every attribute the schema declares for the action. A missing one is a parse error, not a `DENY`.
- `expect` is `ALLOW` or `DENY`.
- Every `principal`, `resource`, and device referenced must exist in the entity file.

### 6.4 Rego test files

A Rego test is a rule whose name starts with `test_`. It uses `with input as` to supply data, and then asserts the result. See `examples/policies/jit-db-access/policy_test.rego` for six complete examples, covering both allow and deny paths.

---

## Part 7: Worked scenarios

Each scenario is a complete task from start to finish. Commands assume the skill folder is your current directory.

### Scenario 1: Assess your organization's maturity

**Goal:** a maturity scorecard and a prioritized list of what to fix.

1. Copy the sample:
   ```bash
   cp examples/sample-assessment.yaml my-assessment.yaml
   ```
2. Open `my-assessment.yaml` in a text editor. For each of the 35 sub-capabilities, set the stage using the rules in [6.2](#62-assessment-yaml). Set `metadata` to your organization's details.
3. Score it:
   ```bash
   python3 scripts/score-maturity.py my-assessment.yaml -o my-scorecard.md --format markdown
   python3 scripts/score-maturity.py my-assessment.yaml -o my-scorecard.json --format json
   ```
4. Open `my-scorecard.md`. Read the "Recommendations" table first. It lists the weakest item in each pillar, in priority order.
5. Ask Claude Code for the narrative: "Using my-scorecard.md, write a gap analysis and a 3-phase remediation roadmap with owners and effort estimates."

Checking your work: if a pillar shows Traditional, look for the single sub-capability at Traditional in that pillar. That item is the one pulling the pillar down.

### Scenario 2: Write and test an access policy (OPA/Rego)

**Goal:** a policy that allows production database access only for on-call engineers with fresh MFA, and tests that prove it.

1. Look at the working example:
   ```bash
   cat examples/policies/jit-db-access/policy.rego
   ```
2. Copy it into your own folder and change the rules to match your requirements:
   ```bash
   mkdir -p my-policies
   cp examples/policies/jit-db-access/policy.rego my-policies/
   ```
3. Write a test for each rule you care about. Copy `policy_test.rego` and add a `test_...` rule for each new case. Each test sets the input with `with input as {...}` and asserts with `allow` or `not allow`.
4. Run the tests:
   ```bash
   opa test -v my-policies
   ```
   A failure prints the failing test's name, so you can see exactly what was checked.
5. Check the policy for missing conventions:
   ```bash
   python3 scripts/validate-rego.py my-policies
   ```

Rego syntax reminder (OPA 1.x):

- Rules use `if`: `allow if { ... }`
- Sets of reasons use `contains`: `deny contains "msg" if { ... }`
- The default is `default allow := false`

### Scenario 3: Write and test an access policy (Cedar)

**Goal:** the same kind of rule, in Cedar, with test cases that check each decision.

1. Look at the template and its schema:
   ```bash
   cat templates/policies/cedar-template.cedar
   cat templates/policies/cedar-schema.cedarschema
   ```
   The schema declares every entity attribute the policy reads. If the policy uses an attribute the schema does not declare, validation fails.
2. Add a test case. Open `templates/policies/tests/cedar-tests.json` and add an object to `cases`. This example uses `carol`, who is in the on-call group but has the `analyst` role, so the policy should deny her:
   ```json
   {
     "name": "analyst in on-call group (should be denied)",
     "principal": "ZeroTrust::User::\"carol\"",
     "action": "ZeroTrust::Action::\"connect\"",
     "resource": "ZeroTrust::Database::\"prod-db-1\"",
     "context": {"now": 1793448000, "network": "corporate", "country": "US", "compromisedCredentials": false},
     "expect": "DENY"
   }
   ```
   The user must exist in `templates/policies/tests/entities.json`. `carol` already does.
3. Run the validator:
   ```bash
   python3 scripts/validate-cedar.py templates/policies -o cedar-report.json
   ```
   A case whose decision does not match its `expect` is listed as a failure, with the decision Cedar actually gave.

Tip: a `DENY` is not always a bug. Before you change the policy, check whether the case should be denied in the first place.

### Scenario 4: Map controls and collect evidence for an assessor

**Goal:** a control matrix and an evidence checklist for a FedRAMP High assessment.

1. Produce the matrix and the checklist:
   ```bash
   python3 scripts/map-compliance.py --framework fedramp_high --format csv -o control_matrix.csv
   python3 scripts/map-compliance.py --evidence-checklist fedramp_high -o evidence_checklist.csv
   ```
2. Open `evidence_checklist.csv` and fill in the `collected`, `location`, and `notes` columns as you gather artifacts. Each row is one control and one piece of evidence.
3. Ask Claude Code for the narrative documents: "Using control_matrix.csv, write a gap analysis for FedRAMP High. For each cloud service in our boundary, state whether it is FedRAMP authorized and whether FIPS 140-3 validation applies."

Important: the gap analysis must check **vendor authorization status** (is each SaaS in your boundary FedRAMP authorized at the required level?) and **FIPS 140-3 validation** of cryptographic modules. The scripts do not check these. Verify them against the FedRAMP Marketplace and the vendor documentation.

### Scenario 5: Draw your architecture

**Goal:** a diagram you can share.

1. Write a YAML file describing your zones and components, following [6.1](#61-architecture-yaml). Start from the example:
   ```bash
   cp examples/architecture-example.yaml my-architecture.yaml
   ```
2. Edit it: one zone per trust boundary, one component per system, and the `connections` for each component.
3. Generate the diagrams:
   ```bash
   python3 scripts/generate-mermaid.py my-architecture.yaml --type architecture --details -o architecture.mmd
   python3 scripts/generate-mermaid.py my-architecture.yaml --type dataflow -o dataflow.mmd
   ```
4. Check the result at [mermaid.live](https://mermaid.live). If a component is missing, check the gotchas in [6.1](#61-architecture-yaml). It must be in its zone's `components` list and have a matching `zone:` value.

### Scenario 6: Threat model a system

**Goal:** a threat model with STRIDE per zone and an ATT&CK mapping.

1. Start from the template: `templates/threat-model/threat-model.md`.
2. In Claude Code, describe your system and ask for the threat model using the template. For example: "Threat model our EKS platform (50 services over gRPC, API Gateway, RDS, GitHub Actions, ArgoCD) using STRIDE per trust zone. Map each threat to MITRE ATT&CK and to the NIST 800-207 tenets. Include validation tests for each mitigation."
3. Check that the output includes the trust zones, STRIDE table, attack trees, ATT&CK mapping, gaps, prioritized mitigations, and tests. The skill's `references/threat-modeling.md` describes each of these.
4. Review: every mitigation should name a test that proves it works.

### Scenario 7: Design an architecture for a new company

**Goal:** a complete design package.

Ask Claude Code, with details:

> Design a Zero Trust architecture for a 200-person fintech, cloud-native on AWS. Identity: Okta. Compute: EKS. Data: RDS PostgreSQL and S3. Compliance: SOC 2 Type II within 6 months. Today: VPN for remote access, no micro-segmentation. Produce the design document, Mermaid diagrams, a component inventory, a 0-to-6-month migration plan, a risk assessment, and CISA ZTMM target stages per pillar.

The evaluation case `evals/design-fintech-startup/` contains this request and a list of what a complete answer must include. Use that list as a checklist.

---

## Part 8: Extending the skill

### 8.1 Adding a Rego policy

1. Create a folder under `examples/policies/` or in your own project.
2. Add `policy.rego` and `policy_test.rego` (same package, `test_` rules).
3. Run `opa test -v <folder>` until it passes, then `python3 scripts/validate-rego.py <folder>`.

### 8.2 Adding a Cedar policy

1. Add any new attributes to `templates/policies/cedar-schema.cedarschema` first.
2. Add the `.cedar` policy in the same folder.
3. Add cases to a `*tests*.json` file, and their entities to the entity file it references.
4. Run `python3 scripts/validate-cedar.py <folder>` until every case matches.

### 8.3 Changing the maturity criteria

The sub-capability names and their criteria live in `scripts/score-maturity.py` (`SUBCAPABILITIES` and `STAGE_CRITERIA`). If you rename one, update every assessment file that uses it.

### 8.4 Changing the control mappings

The control mappings live in `scripts/map-compliance.py` (`_load_default_mappings`). Each entry lists the controls for one tenet and framework. After editing, run `python3 scripts/map-compliance.py --framework all -o check.csv` and review the result.

### 8.5 Adding an evaluation case

Each case lives in `evals/<case-name>/` with three files:

- `prompt.md`: the request given to the skill.
- `case.yaml`: the expected output files and success criteria.
- `graders/assertions.txt`: one checkable statement per line.

Write each assertion so that a script or a person can check it against the output files.

### 8.6 Contributing

1. Make your change on a branch.
2. Run the checks in [Part 10](#part-10-verifying-the-skill-works).
3. Open a pull request. Describe what changed and which checks you ran.

---

## Part 9: Troubleshooting

Find your error message in the table, then follow the fix.

| You see | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'yaml'` | PyYAML is not installed, or is installed for a different Python | `python3 -m pip install -r requirements.txt`, then run the scripts with the same `python3` |
| `externally-managed-environment` when installing | Newer Linux systems block system-wide pip | Use a virtual environment (section 2.5) |
| `opa: command not found` or `opa not found` | OPA is not installed or not on PATH | Install OPA (section 2.2 or 2.3), then run `opa version` |
| `Cedar CLI not found. Install with: cargo install cedar-policy-cli` | Cedar is not installed | Install Rust, then `cargo install cedar-policy-cli` |
| `rego_parse_error: 'if' keyword is required before rule body` | Rego written in the old v0 syntax | Use `allow if { ... }` (see Scenario 2) |
| `Error: Unknown maturity stage 'xyz'` | A stage value is misspelled | Use `traditional`, `initial`, `advanced`, or `optimal` |
| `WARNING: no answer for X / Y; scored Traditional` | A sub-capability is missing from your assessment | Add the missing line |
| A component is missing from the diagram | It is not in its zone's `components` list, or its `zone:` value is wrong | Check [6.1](#61-architecture-yaml) |
| `zsh: command not found: timeout` (macOS) | macOS has no `timeout` command by default | Run the command without `timeout`, or install `coreutils` |
| `dyld: Library not loaded: ... libsimdjson` when running `node` | A Homebrew library was updated out of step | `brew reinstall simdjson` |
| Cedar `invalid token` or `unexpected token` | Cedar syntax error, such as `?.` optional chaining, or schema declarations inside a policy file | Cedar has no optional chaining: guard the attribute with `has` first. Keep schema declarations in the `.cedarschema` file |
| Cedar `failed to parse request ... expected the record to have an attribute` | A test case's `context` is missing a field the schema requires | Add the missing field to every case's `context` |
| A test case shows `expected DENY, got ALLOW` (or the reverse) | Either the expectation is wrong or the policy is | Decide which is correct for your requirement, then fix whichever is wrong |
| `No schema found` warning from `validate-cedar.py` | No `*.cedarschema` (or `*schema*.json`) file in the folder | Add a schema for full validation, or accept the syntax-only check |

If your error is not listed, run the command with `-h`, check the spelling of every option, and read the lines marked `FAIL` or `ERROR`. They name the file and the problem.

---

## Part 10: Verifying the skill works

Run these checks to confirm the skill works on your machine. All commands run from the skill folder.

### 10.1 Quick check (about one minute)

```bash
# 1. Scripts run and produce files
python3 scripts/score-maturity.py examples/sample-assessment.yaml -o check-score.md --format markdown && echo "scorer OK"
python3 scripts/map-compliance.py --framework fedramp_high -o check-map.csv && echo "mapper OK"
python3 scripts/generate-mermaid.py examples/architecture-example.yaml -o check.mmd && echo "diagram OK"

# 2. Policy tests pass
opa test examples/policies/jit-db-access && echo "rego tests OK"

# 3. Cedar cases pass
python3 scripts/validate-cedar.py templates/policies && echo "cedar tests OK"
```

Each script line should end with `OK`. The `opa` and `cedar` lines end with `PASS: 6/6` and `Tests run: 13 (passed 13, failed 0)` when they succeed. The files written by the first three lines (`check-score.md`, `check-map.csv`, `check.mmd`) are created in the skill folder, so you can delete them afterwards. If a line does not succeed, the troubleshooting table in Part 9 covers the usual causes.

### 10.2 Full check

- Every `-h` option works: `python3 scripts/<name>.py -h`.
- Each `--format` value produces a file: `csv`, `json`, `yaml`, and `markdown` for `map-compliance.py`, and `json`, `yaml`, and `markdown` for `score-maturity.py`.
- Each `--framework` value runs: `nist_800_53`, `fedramp_high`, `cmmc_20_l3`, `iso_27001_2022`, `soc2`, `hipaa`, `pci_dss_40`, `all`.
- `--tenet` values 1 to 7 each return JSON with a `tenet_number`.
- Bad input fails as expected: an unknown stage, a malformed YAML file, an out-of-range tenet (`--tenet 9`), a broken Rego file, and a Cedar policy with a typo each exit with a non-zero code.

### 10.3 What "working" means

| Area | Working means |
|------|---------------|
| Scripts | Each command exits 0 for valid input and non-zero for invalid input, and writes a file in the format you asked for |
| Rego | `opa test` reports every test PASS |
| Cedar | `validate-cedar.py` reports every case matching its expectation |
| Diagrams | Each `.mmd` file parses in a Mermaid viewer |
| Claude Code | Asking a Zero Trust question in a new session loads the skill and produces documents |

The last row is the one these checks cannot confirm for you. Start a new Claude Code session and ask a Zero Trust question to see whether the skill loads.

---

## Part 11: Repository layout

```
zero-trust-architecture/
├── SKILL.md                      Entry point Claude reads: workflows, rules, quality gates
├── README.md                     This file
├── requirements.txt              Python dependency (PyYAML)
├── references/                   Background material the skill cites
│   ├── nist-800-207.md           The seven tenets, logical components, deployment models
│   ├── cisa-ztmm.md              Maturity stages and criteria for each pillar
│   ├── architecture-patterns.md  Reference architectures by organization type
│   ├── vendor-patterns.md        Platform-specific patterns (Cloudflare, Zscaler, Okta, AWS, ...)
│   ├── policy-languages.md       OPA/Rego and Cedar syntax and practice
│   └── threat-modeling.md        STRIDE, PASTA, and the ATT&CK-to-tenet table
├── templates/                    Starting points for deliverables
│   ├── architecture/             Design document and migration plan
│   ├── assessment/               Gap analysis and maturity scorecard
│   ├── compliance/               Control matrix (spreadsheet)
│   ├── policies/                 Rego template, Cedar template, Cedar schema, Cedar tests
│   └── threat-model/             Threat model document
├── scripts/                      Deterministic tools (see Part 5)
│   ├── generate-mermaid.py
│   ├── map-compliance.py
│   ├── score-maturity.py
│   ├── validate-rego.py
│   └── validate-cedar.py
├── examples/                     Sample inputs and a complete, tested policy
│   ├── architecture-example.yaml
│   ├── sample-assessment.yaml
│   └── policies/jit-db-access/   policy.rego + policy_test.rego (6 tests)
└── evals/                        Five evaluation cases: prompt, expected outputs, assertions
    ├── design-fintech-startup/
    ├── assess-cisa-ztmm/
    ├── compliance-fedramp/
    ├── policy-jit-db-access/
    └── threat-model-microservices/
```

What each part is for:

- **`SKILL.md`** is what Claude reads when the skill loads. Its paths are relative to the skill folder.
- **`references/`** holds the knowledge. Claude checks it before producing output.
- **`templates/`** holds starting documents. Copy them into your project and edit the copy.
- **`scripts/`** holds the tools that give repeatable answers.
- **`examples/`** holds working inputs you can run straight away.
- **`evals/`** holds the test cases the skill was checked against. Each one lists the files a complete answer must contain.

---

## Part 12: Limitations and gotchas

Read these before relying on the output.

**Scope limits**

- The scripts check structure, syntax, and arithmetic. They do not check whether your controls actually work. An assessor still needs evidence.
- The control mappings are built in. Confirm them against current NIST SP 800-53 Rev 5 and FedRAMP baselines before submitting anything.
- Vendor FedRAMP authorization status and FIPS 140-3 validation are **not** checked by any script. Verify them yourself for every cloud service in your boundary.
- The narrative documents (design text, roadmaps, gap descriptions) are written by the language model from your input. Review them with a qualified person before use.

**Tool limits**

- Mermaid diagrams are checked for valid syntax with the Mermaid parser. They are not checked visually. Look at your diagram in a viewer before you publish it.
- The Cedar validator needs a schema for full type-checking. Without one it only checks syntax.
- `validate-rego.py` warns when a folder has no test file. The starter template `templates/policies/opa-rego-template.rego` has no test file, because its input shape depends on your system. Write tests for your own input before you deploy.
- The diagram title comes from the zone type, so a custom zone name is not shown. See [6.1](#61-architecture-yaml).

**Known gotchas**

- `generate-mermaid.py` does not report unknown `connections` targets. Check your component ids.
- A component left out of its zone's list silently disappears from the diagram.
- `score-maturity.py` scores a missing sub-capability as Traditional, with a warning. Read the warnings.
- Rego files must use OPA 1.x syntax. The old `allow { ... }` form fails to parse.
- Cedar has no optional chaining (`?.`). Guard optional attributes with `has`.

---

## Glossary

| Term | Meaning |
|------|---------|
| **ATT&CK** | MITRE's knowledge base of attacker techniques, numbered like `T1078` |
| **cATO** | Continuous Authority to Operate: an authorization kept current by automated evidence |
| **CISA ZTMM** | CISA's Zero Trust Maturity Model v2 |
| **Cedar** | AWS's policy language for authorization decisions |
| **FedRAMP High** | US government cloud security baseline for high-impact data |
| **FIDO2 / passkey** | Phishing-resistant authentication using hardware keys or device-bound credentials |
| **FIPS 140-3** | US standard for validated cryptographic modules |
| **JIT access** | Just-in-time: privileges granted for a short time, when needed |
| **mTLS** | Mutual TLS: both sides of a connection prove their identity |
| **NIST SP 800-207** | NIST's Zero Trust Architecture standard |
| **NIST SP 800-53 Rev 5** | NIST's catalogue of security controls (for example, `AC-2`) |
| **OPA / Rego** | Open Policy Agent, and its policy language |
| **PDP / PEP** | Policy Decision Point (decides) and Policy Enforcement Point (enforces) |
| **SOC 2 Type II** | An audit report on controls operating over a period of time |
| **STRIDE** | Six threat categories: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege |
| **Tenet** | One of the seven NIST 800-207 principles |
| **Trust zone** | A group of systems that share one level of trust |
| **ZTNA** | Zero Trust Network Access: per-application access instead of network-wide VPN access |
