#!/usr/bin/env python3
"""
OPA/Rego Policy Validator for Zero Trust Architecture Skill

Validates OPA/Rego syntax, runs tests, and checks for common Zero Trust policy patterns.
"""

import subprocess
import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

class RegoValidator:
    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self.errors = []
        self.warnings = []
        self.results = {}

    def validate_syntax(self, file_path: Path) -> bool:
        """Validate Rego syntax using `opa parse`."""
        try:
            result = subprocess.run(
                ["opa", "parse", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                self.errors.append(f"Syntax error in {file_path}: {result.stderr}")
                return False
            return True
        except FileNotFoundError:
            self.errors.append("OPA not installed. Install with: brew install opa")
            return False
        except subprocess.TimeoutExpired:
            self.errors.append(f"Timeout parsing {file_path}")
            return False

    def run_tests(self, policy_file: Path, test_file: Path) -> Dict[str, Any]:
        """Run OPA tests using `opa test`."""
        try:
            result = subprocess.run(
                ["opa", "test", "-v", str(policy_file), str(test_file)],
                capture_output=True,
                text=True,
                timeout=60
            )
            return {
                "passed": result.returncode == 0,
                "output": result.stdout,
                "errors": result.stderr,
                "policy": str(policy_file),
                "test": str(test_file)
            }
        except FileNotFoundError:
            return {"passed": False, "error": "OPA not installed"}
        except subprocess.TimeoutExpired:
            return {"passed": False, "error": "Test timeout"}

    def check_zt_patterns(self, file_path: Path) -> List[str]:
        """Check for Zero Trust policy patterns and best practices."""
        warnings = []
        content = file_path.read_text()

        # Check for default deny
        if "default allow = false" not in content and "default allow := false" not in content:
            warnings.append(f"{file_path}: Missing 'default allow = false' (explicit deny by default)")

        # Check for explicit deny rules
        if "deny[" not in content and "deny{" not in content:
            warnings.append(f"{file_path}: No explicit deny rules found")

        # Check for MFA verification
        if "mfa_verified" not in content and "mfaVerified" not in content:
            warnings.append(f"{file_path}: No MFA verification check")

        # Check for device posture
        if "device_compliant" not in content and "deviceCompliant" not in content and "posture" not in content.lower():
            warnings.append(f"{file_path}: No device posture/compliance check")

        # Check for session validation
        if "session_valid" not in content and "sessionValid" not in content:
            warnings.append(f"{file_path}: No session validation")

        # Check for classification/clearance check
        if "classification" not in content.lower() and "clearance" not in content.lower():
            warnings.append(f"{file_path}: No data classification/clearance check")

        # Check for time-based restrictions
        if "time_authorized" not in content and "business_hours" not in content and "time.window" not in content:
            warnings.append(f"{file_path}: No time-based access restrictions")

        # Check for location/network checks
        if "location_authorized" not in content and "network" not in content.lower():
            warnings.append(f"{file_path}: No network/location context check")

        # Check for risk-based decisions
        if "risk" not in content.lower():
            warnings.append(f"{file_path}: No risk-based decision logic")

        # Check for obligations
        if "obligations" not in content:
            warnings.append(f"{file_path}: No obligations (audit logging, step-up auth)")

        # Check for test file existence
        test_file = file_path.with_name(file_path.stem + "_test.rego")
        if not test_file.exists():
            warnings.append(f"{file_path}: No test file found ({test_file.name})")

        return warnings

    def validate_directory(self) -> Dict[str, Any]:
        """Validate all .rego files in the policy directory."""
        policy_files = list(self.policy_dir.rglob("*.rego"))
        test_files = [f for f in policy_files if f.name.endswith("_test.rego")]
        policy_files = [f for f in policy_files if not f.name.endswith("_test.rego")]

        if not policy_files:
            self.errors.append(f"No .rego policy files found in {self.policy_dir}")

        for policy_file in policy_files:
            print(f"Validating {policy_file}...")

            # Syntax check
            if not self.validate_syntax(policy_file):
                continue

            # Pattern checks
            pattern_warnings = self.check_zt_patterns(policy_file)
            self.warnings.extend(pattern_warnings)

            # Find and run tests
            test_file = policy_file.with_name(policy_file.stem + "_test.rego")
            if test_file.exists():
                print(f"  Running tests from {test_file}...")
                test_result = self.run_tests(policy_file, test_file)
                self.results[str(policy_file)] = test_result
                if not test_result.get("passed", False):
                    self.errors.append(f"Tests failed for {policy_file}: {test_result.get('errors', test_result.get('output', ''))}")
            else:
                self.warnings.append(f"No test file for {policy_file}")

        return {
            "valid": len(self.errors) == 0,
            "errors": self.errors,
            "warnings": self.warnings,
            "test_results": self.results,
            "summary": {
                "policies_checked": len(policy_files),
                "tests_run": len([r for r in self.results.values() if r.get("passed")]),
                "tests_failed": len([r for r in self.results.values() if not r.get("passed", True)])
            }
        }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate OPA/Rego Zero Trust policies")
    parser.add_argument("policy_dir", help="Directory containing .rego policy files")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    args = parser.parse_args()

    validator = RegoValidator(args.policy_dir)
    result = validator.validate_directory()

    if args.strict and validator.warnings:
        result["valid"] = False
        result["errors"].extend([f"STRICT: {w}" for w in validator.warnings])

    print("\n" + "="*50)
    print("VALIDATION SUMMARY")
    print("="*50)
    print(f"Valid: {result['valid']}")
    print(f"Policies checked: {result['summary']['policies_checked']}")
    print(f"Tests passed: {result['summary']['tests_run']}")
    print(f"Tests failed: {result['summary']['tests_failed']}")
    print(f"Errors: {len(result['errors'])}")
    print(f"Warnings: {len(result['warnings'])}")

    if result["errors"]:
        print("\nERRORS:")
        for err in result["errors"]:
            print(f"  ✗ {err}")

    if result["warnings"]:
        print("\nWARNINGS:")
        for warn in result["warnings"]:
            print(f"  ⚠ {warn}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nResults written to {args.output}")

    sys.exit(0 if result["valid"] else 1)

if __name__ == "__main__":
    main()