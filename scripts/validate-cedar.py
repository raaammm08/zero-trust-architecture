#!/usr/bin/env python3
"""
AWS Cedar Policy Validator for Zero Trust Architecture Skill

Validates Cedar syntax, runs authorization tests, and checks for ZT patterns.
"""

import subprocess
import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any

class CedarValidator:
    def __init__(self, policy_dir: str):
        self.policy_dir = Path(policy_dir)
        self.errors = []
        self.warnings = []
        self.results = {}

    def validate_syntax(self, schema_file: Path, policy_files: List[Path]) -> bool:
        """Validate Cedar syntax using `cedar validate`."""
        try:
            cmd = ["cedar", "validate", "--schema", str(schema_file)]
            for pf in policy_files:
                cmd.extend(["--policies", str(pf)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                self.errors.append(f"Syntax validation failed: {result.stderr}")
                return False
            return True
        except FileNotFoundError:
            self.errors.append("Cedar CLI not installed. Install from: https://github.com/cedar-policy/cedar")
            return False
        except subprocess.TimeoutExpired:
            self.errors.append("Syntax validation timeout")
            return False

    def run_authorization_test(self, schema_file: Path, policy_files: List[Path], 
                               entities_file: Path, request_file: Path) -> Dict[str, Any]:
        """Run authorization test using `cedar authorize`."""
        try:
            cmd = ["cedar", "authorize", "--schema", str(schema_file)]
            for pf in policy_files:
                cmd.extend(["--policies", str(pf)])
            cmd.extend(["--entities", str(entities_file), "--request", str(request_file)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "passed": result.returncode == 0,
                "output": result.stdout.strip(),
                "errors": result.stderr,
                "request": str(request_file)
            }
        except FileNotFoundError:
            return {"passed": False, "error": "Cedar CLI not installed"}
        except subprocess.TimeoutExpired:
            return {"passed": False, "error": "Authorization test timeout"}

    def check_zt_patterns(self, policy_files: List[Path]) -> List[str]:
        """Check for Zero Trust policy patterns in Cedar policies."""
        warnings = []
        
        for policy_file in policy_files:
            content = policy_file.read_text()
            
            # Check for permit rules
            if "permit (" not in content:
                warnings.append(f"{policy_file}: No permit rules found")
            
            # Check for forbid rules
            if "forbid (" not in content:
                warnings.append(f"{policy_file}: No forbid rules found (explicit deny)")
            
            # Check for MFA verification
            if "mfaVerified" not in content and "mfa_verified" not in content:
                warnings.append(f"{policy_file}: No MFA verification check")
            
            # Check for device compliance
            if "device" not in content.lower() or ("managed" not in content and "posture" not in content.lower()):
                warnings.append(f"{policy_file}: No device compliance/posture check")
            
            # Check for classification/clearance
            if "classification" not in content.lower() and "clearance" not in content.lower():
                warnings.append(f"{policy_file}: No data classification/clearance check")
            
            # Check for context-aware conditions (when clause)
            if "when {" not in content:
                warnings.append(f"{policy_file}: No context-aware conditions (when clauses)")
            
            # Check for time-based restrictions
            if "currentTime" not in content and "time" not in content.lower():
                warnings.append(f"{policy_file}: No time-based access restrictions")
            
            # Check for risk-based decisions
            if "risk" not in content.lower() and "RiskLevel" not in content:
                warnings.append(f"{policy_file}: No risk-based decision logic")
            
            # Check for entity types
            if "entity User" not in content and "entity Workload" not in content:
                warnings.append(f"{policy_file}: No User/Workload entity types defined")
            
            # Check for break-glass/emergency access
            if "break-glass" not in content.lower() and "emergency" not in content.lower():
                warnings.append(f"{policy_file}: No break-glass/emergency access policy")

        return warnings

    def validate_directory(self) -> Dict[str, Any]:
        """Validate all Cedar files in the policy directory."""
        schema_files = list(self.policy_dir.rglob("*schema*.json"))
        policy_files = list(self.policy_dir.rglob("*.cedar"))
        entities_files = list(self.policy_dir.rglob("*entities*.json"))
        request_files = list(self.policy_dir.rglob("*request*.json"))
        
        if not schema_files:
            self.warnings.append(f"No schema.json found in {self.policy_dir}; schema validation skipped")
        
        if not policy_files:
            self.errors.append(f"No .cedar policy files found in {self.policy_dir}")

        schema_file = schema_files[0] if schema_files else None
        
        if schema_file and policy_files:
            print(f"Validating syntax with schema {schema_file}...")
            if not self.validate_syntax(schema_file, policy_files):
                return self._result()
        
        # Pattern checks
        pattern_warnings = self.check_zt_patterns(policy_files)
        self.warnings.extend(pattern_warnings)
        
        # Run authorization tests if test files exist
        if entities_files and request_files:
            for request_file in request_files:
                print(f"Running authorization test: {request_file}...")
                test_result = self.run_authorization_test(
                    schema_file, policy_files, entities_files[0], request_file
                )
                self.results[str(request_file)] = test_result
                if not test_result.get("passed", False):
                    self.errors.append(f"Auth test failed for {request_file}: {test_result.get('errors', test_result.get('output', ''))}")
        
        return self._result()

    def _result(self) -> Dict[str, Any]:
        return {
            "valid": len(self.errors) == 0,
            "errors": self.errors,
            "warnings": self.warnings,
            "test_results": self.results,
            "summary": {
                "policies_checked": len(list(self.policy_dir.rglob("*.cedar"))),
                "tests_run": len([r for r in self.results.values() if r.get("passed")]),
                "tests_failed": len([r for r in self.results.values() if not r.get("passed", True)])
            }
        }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate AWS Cedar Zero Trust policies")
    parser.add_argument("policy_dir", help="Directory containing Cedar policy files")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    args = parser.parse_args()

    validator = CedarValidator(args.policy_dir)
    result = validator.validate_directory()

    if args.strict and validator.warnings:
        result["valid"] = False
        result["errors"].extend([f"STRICT: {w}" for w in validator.warnings])

    print("\n" + "="*50)
    print("CEDAR VALIDATION SUMMARY")
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