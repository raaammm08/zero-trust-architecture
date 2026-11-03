# Contributing

Thanks for helping improve the Zero Trust Architecture skill. Useful contributions include:

- **Vendor patterns:** add or correct platform guidance in `references/vendor-patterns.md`.
- **Policy templates and tests:** add Rego or Cedar examples with positive and negative test cases.
- **Assessment content:** fix or clarify CISA ZTMM capability descriptions in `references/cisa-ztmm.md`.
- **Bugs:** open an issue with the command you ran, the input file, and the full error output.

## Before you open a pull request

1. Run the scripts on the sample inputs and confirm they still work:
   ```bash
   python3 scripts/score-maturity.py examples/sample-assessment.yaml
   opa test examples/policies/jit-db-access
   ```
2. If you add a policy, add tests for both an allowed and a denied case.
3. If you change a reference file, cite the source standard (NIST SP 800-207, CISA ZTMM v2, or the vendor documentation) in the change description.

## Scope

This project is vendor-neutral first, with platform-specific guidance layered on top. It does not verify that a control works in a live environment and does not replace an assessor. Please keep claims in documentation to what the tools actually check.

## Questions

Use GitHub Discussions for design questions and ideas. Use Issues for bugs and concrete change requests.
