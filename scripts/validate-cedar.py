#!/usr/bin/env python3
"""
Cedar Policy Validator for the Zero Trust Architecture Skill

Checks Cedar policies against a schema (cedar validate, or check-parse when no
schema exists), runs authorization test cases, and reports Zero Trust pattern gaps.

Requires the Cedar CLI: cargo install cedar-policy-cli

Test case file (any *tests*.json under the policy directory):
    {
      "entities": "entities.json",          # path relative to this file
      "cases": [
        {"name": "...", "principal": "ZeroTrust::User::\"alice\"",
         "action": "ZeroTrust::Action::\"connect\"",
         "resource": "ZeroTrust::Database::\"prod-db-1\"",
         "context": {...}, "expect": "ALLOW" | "DENY"}
      ]
    }
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

def _find_cedar() -> str:
    """Use cedar from PATH, or the default `cargo install` location."""
    import shutil
    found = shutil.which("cedar") or str(Path.home() / ".cargo" / "bin" / "cedar")
    return found

CEDAR = _find_cedar()
INSTALL_HINT = "Cedar CLI not found. Install with: cargo install cedar-policy-cli"


class CedarValidator:
    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.results: Dict[str, Dict[str, Any]] = {}

    def _run(self, args: List[str]) -> Optional[subprocess.CompletedProcess]:
        """Run the Cedar CLI. Returns None (and records an error) if it is not installed."""
        try:
            return subprocess.run([CEDAR] + args, capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            self.errors.append(INSTALL_HINT)
        except subprocess.TimeoutExpired:
            self.errors.append(f"cedar {args[0]} timed out")
        return None

    def schema_args(self, schema: Optional[Path]) -> List[str]:
        if schema is None:
            return []
        fmt = "json" if schema.suffix == ".json" else "cedar"
        return ["--schema", str(schema), "--schema-format", fmt]

    def check_syntax(self, schema: Optional[Path], policy_file: Path) -> bool:
        """Parse one policy file; validate it against the schema when one exists."""
        if schema is None:
            proc = self._run(["check-parse", "--policies", str(policy_file)])
        else:
            proc = self._run(["validate", *self.schema_args(schema), "--policies", str(policy_file)])
        if proc is None:
            return False
        if proc.returncode != 0:
            self.errors.append(f"{policy_file}: {proc.stderr.strip() or proc.stdout.strip()}")
            return False
        return True

    def run_case(self, schema: Optional[Path], policy_file: Path, entities: Path,
                 case: Dict[str, Any], context_file: Path) -> Dict[str, Any]:
        """Run one authorization case. The decision is read from stdout (ALLOW or DENY)."""
        context_file.write_text(json.dumps(case["context"]))
        args = ["authorize", *self.schema_args(schema),
                "--policies", str(policy_file), "--entities", str(entities),
                "--principal", case["principal"], "--action", case["action"],
                "--resource", case["resource"], "--context", str(context_file)]
        proc = self._run(args)
        if proc is None:
            return {"passed": False, "error": self.errors[-1]}
        decision = proc.stdout.strip()
        if proc.returncode not in (0, 2) or decision not in ("ALLOW", "DENY"):
            return {"passed": False, "error": proc.stderr.strip() or f"no decision (exit {proc.returncode})"}
        return {"passed": decision == case["expect"], "decision": decision, "expected": case["expect"]}

    def check_zt_patterns(self, text: str) -> List[str]:
        """Warn about Zero Trust policy elements missing from the combined Cedar text."""
        checks = [
            ("permit", "permit (" in text or "permit(" in text, "No permit rules"),
            ("forbid", "forbid (" in text or "forbid(" in text, "No forbid rules (explicit deny)"),
            ("MFA", "mfaVerified" in text or "mfa" in text.lower(), "No MFA verification check"),
            ("device", "device" in text.lower(), "No device compliance check"),
            ("classification", "classification" in text.lower() or "clearance" in text.lower(),
             "No data classification or clearance check"),
            ("time", "now" in text or "currentTime" in text or "onCall" in text,
             "No time-based restriction"),
            ("risk", "risk" in text.lower(), "No risk-based decision"),
        ]
        return [f"{msg}" for _, ok, msg in checks if not ok]

    def validate_directory(self) -> Dict[str, Any]:
        policy_files = sorted(self.policy_dir.rglob("*.cedar"))
        schema_files = sorted(self.policy_dir.rglob("*.cedarschema")) + sorted(self.policy_dir.rglob("*schema*.json"))
        test_files = sorted(p for p in self.policy_dir.rglob("*tests*.json"))

        if not policy_files:
            self.errors.append(f"No .cedar policy files found in {self.policy_dir}")
            return self._result(policy_files)

        schema = schema_files[0] if schema_files else None
        if schema is None:
            self.warnings.append("No schema found (*.cedarschema or *schema*.json); syntax checked without schema validation")

        for policy_file in policy_files:
            if not self.check_syntax(schema, policy_file):
                return self._result(policy_files)

        combined = "\n".join(p.read_text() for p in policy_files + schema_files[:1])
        self.warnings.extend(self.check_zt_patterns(combined))

        for test_file in test_files:
            spec = json.loads(test_file.read_text())
            entities = (test_file.parent / spec["entities"]).resolve()
            # authorize takes one policy file, so policies are combined into a temp file
            with tempfile.TemporaryDirectory() as tmp:
                combined_policies = Path(tmp) / "policies.cedar"
                combined_policies.write_text("\n".join(p.read_text() for p in policy_files))
                context_file = Path(tmp) / "context.json"
                for case in spec["cases"]:
                    key = f"{test_file.name}::{case['name']}"
                    result = self.run_case(schema, combined_policies, entities, case, context_file)
                    self.results[key] = result
                    if not result.get("passed"):
                        detail = result.get("error") or f"expected {result['expected']}, got {result['decision']}"
                        self.errors.append(f"Test failed: {key}: {detail}")

        return self._result(policy_files)

    def _result(self, policy_files: List[Path]) -> Dict[str, Any]:
        passed = sum(1 for r in self.results.values() if r.get("passed"))
        return {
            "valid": len(self.errors) == 0,
            "errors": self.errors,
            "warnings": self.warnings,
            "test_results": self.results,
            "summary": {
                "policies_checked": len(policy_files),
                "tests_run": len(self.results),
                "tests_passed": passed,
                "tests_failed": len(self.results) - passed,
            },
        }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate Cedar Zero Trust policies")
    parser.add_argument("policy_dir", help="Directory containing .cedar policies, an optional schema, and test files")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    args = parser.parse_args()

    validator = CedarValidator(args.policy_dir)
    result = validator.validate_directory()

    if args.strict and validator.warnings:
        result["valid"] = False
        result["errors"].extend([f"STRICT: {w}" for w in validator.warnings])

    print("\n" + "=" * 50)
    print("CEDAR VALIDATION SUMMARY")
    print("=" * 50)
    print(f"Valid: {result['valid']}")
    print(f"Policies checked: {result['summary']['policies_checked']}")
    print(f"Tests run: {result['summary']['tests_run']} "
          f"(passed {result['summary']['tests_passed']}, failed {result['summary']['tests_failed']})")

    if result["errors"]:
        print("\nERRORS:")
        for err in result["errors"]:
            print(f"  x {err}")
    if result["warnings"]:
        print("\nWARNINGS:")
        for warn in result["warnings"]:
            print(f"  ! {warn}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nResults written to {args.output}")

    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
