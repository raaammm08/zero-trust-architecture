# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-30

First public release.

### Added
- Skill entry point (`SKILL.md`) covering six workflows: architecture design, policy creation, implementation, assessment, threat modeling, and compliance mapping.
- Reference material on NIST SP 800-207, CISA ZTMM v2, architecture patterns, vendor patterns, policy languages, and threat modeling.
- `score-maturity.py`: CISA ZTMM scoring with weakest-link pillar stages, JSON/YAML/Markdown output, and clean errors for bad input.
- `map-compliance.py`: control matrix and evidence checklists for NIST 800-53, FedRAMP High, CMMC, ISO 27001, SOC 2, HIPAA, and PCI DSS, plus per-tenet mappings.
- `generate-mermaid.py`: architecture, data-flow, and matrix diagrams with quoted labels; output parses with the Mermaid 11 parser.
- `validate-rego.py`: OPA/Rego syntax and convention checks, with `--strict` mode.
- `validate-cedar.py`: Cedar schema validation and authorization test cases, reading ALLOW/DENY decisions from the Cedar CLI.
- Rego template in OPA v1 syntax, and a Cedar template with schema and 13 test cases.
- A tested just-in-time database access policy with six `opa test` cases (`examples/policies/jit-db-access`).
- Five evaluation cases with expected outputs and assertions.
- Full README with setup for macOS, Linux, and WSL, command reference, worked scenarios, troubleshooting, and known limitations.
- MIT license.

### Fixed during pre-release testing
- Mapper no longer requires PyYAML unless YAML output is requested.
- Mapper CSV columns are named `ZT Tenet`, `NIST 800-53`, and `FedRAMP High`.
- Maturity JSON export no longer crashes or writes truncated files; stages print by name; ties are reported as ties.
- Unknown maturity stage names are an error instead of silently scoring Traditional.
- Rego template converted from OPA v0 to v1 syntax and checked with `opa check`.
- Cedar template rewritten: removed unsupported optional chaining and moved schema declarations to a separate schema file.
- Cedar validator reads ALLOW/DENY decisions correctly (exit 0 and 2 are both valid).
- Mermaid labels are quoted; generated diagrams parse.
- Rego validator recognizes `deny contains` rules.
