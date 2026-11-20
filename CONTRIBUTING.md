# Contributing

Thanks for helping improve the Zero Trust Architecture skill. Useful contributions include:

- **Vendor patterns:** add or correct platform guidance in `references/vendor-patterns.md`.
- **Policy templates and tests:** add Rego or Cedar examples with positive and negative test cases.
- **Assessment content:** fix or clarify CISA ZTMM capability descriptions in `references/cisa-ztmm.md`.
- **Bugs:** open an issue with the command you ran, the input file, and the full error output.

## Before you open a pull request

1. Run the test suite. It covers every script, the Rego templates, and the Cedar cases:
   ```bash
   python3 -m pip install -r requirements-dev.txt
   python3 -m pytest
   opa test templates/policies/*.rego examples/policies
   opa fmt --list --fail templates/policies/*.rego examples/policies
   ```
   Tests that need `opa` or `cedar` are skipped when the tool is not installed. CI runs all of them on every pull request.
2. If you add a policy, add tests for both an allowed and a denied case.
3. If you change a reference file, cite the source standard (NIST SP 800-207, CISA ZTMM v2, or the vendor documentation) in the change description.
4. Add a line to `CHANGELOG.md` under `Unreleased`.

New here? Issues labelled [good first issue](https://github.com/raaammm08/zero-trust-architecture/labels/good%20first%20issue) are small and self-contained.

## Releasing (maintainer)

1. Rename the `Unreleased` section of `CHANGELOG.md` to the new version and date, and set the same version in `.claude-plugin/plugin.json`.
2. Merge to `main`, then tag and push: `git tag v1.2.0 && git push origin v1.2.0`.
3. The release workflow checks that the tag matches `plugin.json` and publishes a GitHub release with the changelog section as notes.

## Scope

This project is vendor-neutral first, with platform-specific guidance layered on top. It does not verify that a control works in a live environment and does not replace an assessor. Please keep claims in documentation to what the tools actually check.

## Questions

Use GitHub Discussions for design questions and ideas. Use Issues for bugs and concrete change requests.

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
