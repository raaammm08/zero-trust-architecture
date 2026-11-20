# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.1.0] - 2026-11-20

### Added
- Claude Code plugin and marketplace manifests (`.claude-plugin/`). Install with `/plugin marketplace add raaammm08/zero-trust-architecture`, then `/plugin install zero-trust-architecture@zero-trust-architecture`.
- 15 `opa test` cases for the Rego template (`templates/policies/opa-rego-template_test.rego`), with a fixed clock so results do not depend on the time of day.
- pytest suite (`tests/`) covering every script, format, framework, and tenet option, and the bad-input cases in the guide.
- GitHub Actions CI: tests on Python 3.9, 3.11, and 3.13, Rego format, strict check, and unit tests, Cedar cases, and plugin manifest validation.
- Release workflow that publishes a GitHub release from a version tag, using the matching changelog section.
- Issue forms, pull request template, Dependabot, CODEOWNERS, security policy, and code of conduct.

### Changed
- The README is now a short overview. The full manual moved to `docs/guide.md`.
- `SKILL.md` resolves paths against the skill's base directory, so it works for both plugin and manual installs.
- Rego files formatted with `opa fmt`.

### Fixed
- Rego template: the 5-minute re-authentication check for sensitive actions was inverted. It allowed sessions last authenticated more than 5 minutes ago and denied fresh ones. It now requires authentication within the past 5 minutes.
- `map-compliance.py`: the default output file now uses `.md` for Markdown (was `.markdown`), and the evidence checklist default file uses the extension of the chosen `--format` (was always `.csv`).

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
