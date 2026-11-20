# Zero Trust Architecture Skill

[![CI](https://github.com/raaammm08/zero-trust-architecture/actions/workflows/ci.yml/badge.svg)](https://github.com/raaammm08/zero-trust-architecture/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/raaammm08/zero-trust-architecture)](https://github.com/raaammm08/zero-trust-architecture/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Code plugin](https://img.shields.io/badge/Claude_Code-plugin-d97757)](#install)

**A free, open-source CISA ZTMM maturity assessment tool and NIST SP 800-207 Zero Trust architecture toolkit.** Score your CISA Zero Trust Maturity Model v2 assessment, map controls to FedRAMP High and NIST 800-53, generate architecture diagrams, and test OPA/Rego and AWS Cedar access policies. No paid platform required.

![Animated terminal demo: score-maturity.py prints the CISA ZTMM scorecard](docs/images/score-maturity-demo-animated.svg)

**Watch the 35-second demo with narration:** [zero-trust-demo.mp4](https://github.com/raaammm08/zero-trust-architecture/releases/download/v1.0.0/zero-trust-demo.mp4)

> **Limitations at a glance:** the scripts check structure, syntax, and arithmetic. They do not verify that your controls work, do not check vendor FedRAMP status or FIPS 140-3 validation, and cannot replace an assessor. Read the [full list](docs/guide.md#part-12-limitations-and-gotchas) before you rely on any output.

**Built for** security architects, GRC and compliance teams, and platform engineers who need a ZTMM score, tested access policies, and a control map, without a 40-page spreadsheet.

## Install

**As a Claude Code plugin (recommended).** Inside Claude Code:

```text
/plugin marketplace add raaammm08/zero-trust-architecture
/plugin install zero-trust-architecture@zero-trust-architecture
```

**Or clone it** into your skills folder. Do this as well if you want to run the scripts from a terminal:

```bash
git clone https://github.com/raaammm08/zero-trust-architecture.git ~/.claude/skills/zero-trust-architecture
python3 -m pip install -r ~/.claude/skills/zero-trust-architecture/requirements.txt
```

Python 3.9+ and PyYAML are all you need for scoring, mapping, and diagrams. Policy testing also needs [OPA 1.x](https://www.openpolicyagent.org/docs/latest/#running-opa) and the [Cedar CLI](https://github.com/cedar-policy/cedar). Platform-specific setup (macOS, Linux, WSL) is in the [guide](docs/guide.md#part-2-setup-step-by-step).

## Quick start (2 minutes)

From the cloned folder:

```bash
cd ~/.claude/skills/zero-trust-architecture

# Score a CISA ZTMM v2 assessment (edit the YAML to score your own organization)
python3 scripts/score-maturity.py examples/sample-assessment.yaml --format markdown -o scorecard.md

# Map Zero Trust tenets to FedRAMP High controls, plus an evidence checklist
python3 scripts/map-compliance.py --framework fedramp_high --format markdown
python3 scripts/map-compliance.py --evidence-checklist fedramp_high

# Draw the architecture as a Mermaid diagram
python3 scripts/generate-mermaid.py examples/architecture-example.yaml -o architecture.mmd

# Test access policies
opa test examples/policies/jit-db-access
python3 scripts/validate-cedar.py templates/policies
```

Or ask Claude Code in plain English, in the folder where you want the output:

| Workflow | Example request |
|----------|-----------------|
| Design | "Design a Zero Trust architecture for our migration to Google Cloud. 500 staff, Okta and EKS." |
| Policy | "Write an OPA policy so only on-call engineers can reach production databases, with MFA within the last hour." |
| Implementation | "Implement micro-segmentation with Cloudflare Zero Trust, step by step, with validation after each phase." |
| Assessment | "Assess our Zero Trust maturity against CISA ZTMM. Here are our current controls: [describe them]." |
| Threat model | "Threat model our Kubernetes platform using STRIDE per trust zone, mapped to MITRE ATT&CK." |
| Compliance | "Map our Zero Trust controls to FedRAMP High. Produce a control matrix and an evidence checklist." |

## What's included

| Part | What it does |
|------|--------------|
| `score-maturity.py` | Scores all 7 CISA ZTMM v2 pillars with weakest-link stages; JSON, YAML, or Markdown output |
| `map-compliance.py` | Control matrix and evidence checklists for NIST 800-53, FedRAMP High, CMMC 2.0, ISO 27001:2022, SOC 2, HIPAA, PCI DSS 4.0 |
| `generate-mermaid.py` | Architecture, data-flow, and access-matrix diagrams from a YAML description |
| `validate-rego.py`, `validate-cedar.py` | Syntax checks, Zero Trust convention checks, and test runs for OPA/Rego and Cedar policies |
| Policy templates | An OPA v1 Rego template with 15 tests, a Cedar template with schema and 13 test cases, and a just-in-time database access policy with 6 tests |
| Document templates | Design doc, migration plan, gap analysis, threat model, maturity scorecard and control matrix spreadsheets |
| References | NIST SP 800-207, CISA ZTMM v2, architecture and vendor patterns, policy languages, threat modeling |
| Evals | Five evaluation cases with expected outputs and graded assertions |

## Documentation

The **[full guide](docs/guide.md)** covers everything:

- [Concepts](docs/guide.md#part-1-concepts): Zero Trust, ZTMM, policies, compliance mappings, and threat models, explained from scratch
- [Command reference](docs/guide.md#part-5-command-reference-every-script-every-flag): every script and flag
- [Input file reference](docs/guide.md#part-6-input-file-reference): architecture and assessment YAML, Cedar and Rego tests
- [Worked scenarios](docs/guide.md#part-7-worked-scenarios): seven end-to-end walkthroughs
- [Extending the skill](docs/guide.md#part-8-extending-the-skill): add policies, maturity criteria, mappings, evals
- [Troubleshooting](docs/guide.md#part-9-troubleshooting) and [limitations](docs/guide.md#part-12-limitations-and-gotchas)

## Contributing

Contributions are welcome, especially vendor patterns, new framework mappings, and policy examples with tests. Read [CONTRIBUTING.md](CONTRIBUTING.md), then pick an issue labelled [good first issue](https://github.com/raaammm08/zero-trust-architecture/labels/good%20first%20issue). Ask questions in [Discussions](https://github.com/raaammm08/zero-trust-architecture/discussions). Report security issues as described in [SECURITY.md](SECURITY.md).

If this saved you time, a star helps other people find it.

## License

[MIT](LICENSE). Changes are recorded in the [changelog](CHANGELOG.md).
