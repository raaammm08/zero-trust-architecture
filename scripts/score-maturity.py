#!/usr/bin/env python3
"""
Zero Trust Maturity Scorer

Calculates CISA ZTMM maturity scores from assessment answers.
"""

import json
import yaml
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class MaturityStage(Enum):
    TRADITIONAL = 1
    INITIAL = 2
    ADVANCED = 3
    OPTIMAL = 4

    @classmethod
    def from_string(cls, value: str) -> 'MaturityStage':
        mapping = {
            "traditional": cls.TRADITIONAL,
            "initial": cls.INITIAL,
            "advanced": cls.ADVANCED,
            "optimal": cls.OPTIMAL,
            "t": cls.TRADITIONAL,
            "i": cls.INITIAL,
            "a": cls.ADVANCED,
            "o": cls.OPTIMAL,
        }
        key = str(value).strip().lower()
        if key not in mapping:
            # A typo must not silently score as Traditional
            raise ValueError(f"Unknown maturity stage {value!r}; use traditional, initial, advanced, or optimal")
        return mapping[key]

    def to_string(self) -> str:
        return self.name.capitalize()

def _plain(value: Any) -> Any:
    """Convert MaturityStage values to their names so results serialize to JSON and print cleanly."""
    if isinstance(value, MaturityStage):
        return value.to_string()
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value

@dataclass
class SubCapability:
    id: str
    name: str
    pillar: str
    stage: MaturityStage
    evidence: str = ""
    notes: str = ""

@dataclass
class PillarScore:
    name: str
    stage: MaturityStage
    sub_capabilities: List[SubCapability]
    score: float  # 1.0 - 4.0

class MaturityScorer:
    PILLARS = [
        "Identity",
        "Device",
        "Network",
        "Application/Workload",
        "Data",
        "Visibility & Analytics",
        "Automation & Orchestration"
    ]

    SUBCAPABILITIES = {
        "Identity": [
            "Authentication",
            "Identity Lifecycle",
            "Privileged Access",
            "Workload Identity",
            "Identity Threat Detection"
        ],
        "Device": [
            "Device Inventory",
            "Device Posture",
            "Device Authentication",
            "BYOD / Personal Devices",
            "IoT / OT Devices"
        ],
        "Network": [
            "Network Segmentation",
            "Encryption",
            "Remote Access",
            "DNS Security",
            "Software-Defined Networking"
        ],
        "Application/Workload": [
            "API Security",
            "Container / Workload Security",
            "Service Mesh",
            "CI/CD Security",
            "Application Identity"
        ],
        "Data": [
            "Data Classification",
            "Encryption",
            "Data Loss Prevention",
            "Access Governance",
            "Data Monitoring"
        ],
        "Visibility & Analytics": [
            "Logging & Telemetry",
            "User/Entity Behavior Analytics",
            "Security Orchestration (SOAR)",
            "Threat Intelligence",
            "Cross-Pillar Correlation"
        ],
        "Automation & Orchestration": [
            "Policy as Code",
            "Infrastructure as Code",
            "Adaptive/Contextual Policy",
            "Automated Compliance",
            "ChatOps / Collaboration"
        ]
    }

    STAGE_CRITERIA = {
        "Identity": {
            "Authentication": {
                MaturityStage.TRADITIONAL: "Static passwords, periodic rotation, no MFA or SMS only",
                MaturityStage.INITIAL: "MFA for all users (any method), SSO deployed for some apps",
                MaturityStage.ADVANCED: "Risk-based adaptive auth, continuous auth, JIT/JEA for privileged",
                MaturityStage.OPTIMAL: "Passwordless (FIDO2/passkeys), decentralized identity, predictive risk"
            },
            "Identity Lifecycle": {
                MaturityStage.TRADITIONAL: "Manual provisioning/deprovisioning, annual access reviews",
                MaturityStage.INITIAL: "HR-driven lifecycle, basic PAM, quarterly reviews",
                MaturityStage.ADVANCED: "Automated lifecycle, PAM with session recording, automated reviews",
                MaturityStage.OPTIMAL: "Real-time governance, AI-driven certification, DID/VC for partners"
            },
            "Privileged Access": {
                MaturityStage.TRADITIONAL: "Shared accounts, static credentials, no session logging",
                MaturityStage.INITIAL: "PAM for admins, basic session logging, some JIT",
                MaturityStage.ADVANCED: "JIT/JEA, zero standing privilege, workflow approvals, full audit",
                MaturityStage.OPTIMAL: "Ephemeral credentials, dual-control, autonomous privilege management"
            },
            "Workload Identity": {
                MaturityStage.TRADITIONAL: "Static keys/secrets in code, long-lived credentials",
                MaturityStage.INITIAL: "Basic service accounts, some rotation, cloud IAM roles",
                MaturityStage.ADVANCED: "SPIFFE/SPIRE, cloud-native WIF, short-lived tokens, mTLS",
                MaturityStage.OPTIMAL: "Universal workload identity, cross-cloud federation, confidential"
            },
            "Identity Threat Detection": {
                MaturityStage.TRADITIONAL: "None, basic failed login alerts only",
                MaturityStage.INITIAL: "Basic anomaly detection, some UEBA for identity",
                MaturityStage.ADVANCED: "ITDR, UEBA for identity, anomaly detection, automated response",
                MaturityStage.OPTIMAL: "Predictive identity risk, autonomous response, deception"
            }
        },
        # ... (similar for other pillars - abbreviated for brevity)
    }

    def __init__(self):
        self.pillar_scores: Dict[str, PillarScore] = {}

    def load_assessment(self, file_path: Path) -> Dict[str, Any]:
        """Load assessment from YAML or JSON."""
        with open(file_path) as f:
            if file_path.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(f)
            else:
                return json.load(f)

    def score_pillar(self, pillar: str, subcapability_scores: Dict[str, str]) -> PillarScore:
        """Score a pillar based on sub-capability stages (weakest link)."""
        subcapabilities = []
        min_stage = MaturityStage.OPTIMAL
        
        for subcap_name in self.SUBCAPABILITIES.get(pillar, []):
            if subcap_name not in subcapability_scores:
                # Unanswered sub-capabilities default to Traditional, but say so
                print(f"WARNING: no answer for {pillar} / {subcap_name}; scored Traditional", file=sys.stderr)
            stage_str = subcapability_scores.get(subcap_name, "traditional")
            stage = MaturityStage.from_string(stage_str)
            
            subcap = SubCapability(
                id=f"{pillar.lower().replace('/', '_')}_{subcap_name.lower().replace(' ', '_')}",
                name=subcap_name,
                pillar=pillar,
                stage=stage
            )
            subcapabilities.append(subcap)
            
            if stage.value < min_stage.value:
                min_stage = stage
        
        # Pillar score = lowest sub-capability (weakest link)
        pillar_stage = min_stage
        # Also calculate numeric average for reporting
        avg_score = sum(s.stage.value for s in subcapabilities) / len(subcapabilities)
        
        return PillarScore(
            name=pillar,
            stage=pillar_stage,
            sub_capabilities=subcapabilities,
            score=avg_score
        )

    def calculate_overall(self, pillar_scores: Dict[str, PillarScore]) -> Dict[str, Any]:
        """Calculate overall maturity metrics."""
        stages = [ps.stage.value for ps in pillar_scores.values()]
        avg_numeric = sum(stages) / len(stages)
        
        # Determine overall stage (average rounded)
        if avg_numeric >= 3.5:
            overall_stage = MaturityStage.OPTIMAL
        elif avg_numeric >= 2.5:
            overall_stage = MaturityStage.ADVANCED
        elif avg_numeric >= 1.5:
            overall_stage = MaturityStage.INITIAL
        else:
            overall_stage = MaturityStage.TRADITIONAL
        
        lowest_pillar = min(pillar_scores.items(), key=lambda x: x[1].stage.value)
        highest_pillar = max(pillar_scores.items(), key=lambda x: x[1].stage.value)
        # When every pillar sits at the same stage there is no meaningful highest pillar
        all_tied = len({ps.stage for ps in pillar_scores.values()}) == 1
        highest = {"name": "None (all pillars tied)", "stage": lowest_pillar[1].stage.to_string()} if all_tied \
            else {"name": highest_pillar[0], "stage": highest_pillar[1].stage.to_string()}

        return {
            "average_numeric": round(avg_numeric, 2),
            "overall_stage": overall_stage.to_string(),
            "lowest_pillar": {"name": lowest_pillar[0], "stage": lowest_pillar[1].stage.to_string()},
            "highest_pillar": highest,
            "pillar_count": len(pillar_scores),
            "stage_distribution": {
                stage.to_string(): sum(1 for ps in pillar_scores.values() if ps.stage == stage)
                for stage in MaturityStage
            }
        }

    def run_assessment(self, assessment_file: Path) -> Dict[str, Any]:
        """Run full maturity assessment."""
        data = self.load_assessment(assessment_file)
        
        # Score each pillar
        for pillar in self.PILLARS:
            subcap_scores = data.get(pillar, {})
            self.pillar_scores[pillar] = self.score_pillar(pillar, subcap_scores)
        
        overall = self.calculate_overall(self.pillar_scores)
        
        return {
            "assessment_metadata": data.get("metadata", {}),
            "pillar_scores": {k: _plain(asdict(v)) for k, v in self.pillar_scores.items()},
            "overall": overall,
            "recommendations": self.generate_recommendations()
        }

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on scores."""
        recommendations = []
        
        # Sort pillars by score (lowest first)
        sorted_pillars = sorted(
            self.pillar_scores.items(),
            key=lambda x: x[1].score
        )
        
        for i, (pillar_name, pillar_score) in enumerate(sorted_pillars):
            priority = "P0" if i == 0 else "P1" if i < 3 else "P2"
            
            # Find lowest sub-capability
            lowest_subcap = min(pillar_score.sub_capabilities, key=lambda s: s.stage.value)
            
            recommendations.append({
                "priority": priority,
                "pillar": pillar_name,
                "focus_area": lowest_subcap.name,
                "current_stage": lowest_subcap.stage.to_string(),
                "target_stage": MaturityStage(min(lowest_subcap.stage.value + 1, 4)).to_string(),
                "rationale": f"Lowest scoring sub-capability in {pillar_name} pillar",
                "suggested_actions": self.get_suggested_actions(pillar_name, lowest_subcap.name)
            })
        
        return recommendations

    def get_suggested_actions(self, pillar: str, subcapability: str) -> List[str]:
        """Get suggested actions for a sub-capability."""
        actions = {
            "Identity": {
                "Authentication": [
                    "Deploy phishing-resistant MFA (FIDO2/passkeys) for all users",
                    "Implement risk-based conditional access policies",
                    "Enable continuous authentication for sensitive resources"
                ],
                "Identity Lifecycle": [
                    "Automate provisioning/deprovisioning via HR integration",
                    "Implement quarterly automated access reviews",
                    "Deploy PAM for all privileged access"
                ],
                "Privileged Access": [
                    "Implement JIT/JEA for all admin access",
                    "Eliminate standing privileges",
                    "Enable session recording and dual-control"
                ],
                "Workload Identity": [
                    "Deploy SPIFFE/SPIRE for workload identity",
                    "Migrate to cloud-native workload identity (AWS IAM Roles Anywhere, GCP WIF)",
                    "Eliminate static secrets from CI/CD"
                ],
                "Identity Threat Detection": [
                    "Deploy ITDR solution",
                    "Integrate identity UEBA with SIEM",
                    "Implement automated response for identity threats"
                ]
            },
            "Device": {
                "Device Inventory": [
                    "Deploy automated discovery for all endpoints",
                    "Integrate MDM/UEM with CMDB",
                    "Implement IoT/OT passive profiling"
                ],
                "Device Posture": [
                    "Integrate EDR/XDR with policy engine",
                    "Implement real-time posture assessment",
                    "Deploy automated remediation (quarantine/wipe)"
                ]
            }
        }
        
        return actions.get(pillar, {}).get(subcapability, [
            f"Assess current {subcapability} capabilities",
            f"Define target state for {subcapability}",
            f"Create implementation plan for {subcapability}"
        ])

    def export_report(self, results: Dict[str, Any], output_path: Path, format: str = "json"):
        """Export assessment report."""
        if format == "json":
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
        elif format == "yaml":
            with open(output_path, "w") as f:
                yaml.dump(results, f, default_flow_style=False)
        elif format == "markdown":
            self._export_markdown(results, output_path)

    def _export_markdown(self, results: Dict[str, Any], output_path: Path):
        """Export as Markdown report."""
        lines = [
            "# Zero Trust Maturity Assessment Report",
            "",
            f"**Date**: {results.get('assessment_metadata', {}).get('date', 'N/A')}",
            f"**Assessor**: {results.get('assessment_metadata', {}).get('assessor', 'N/A')}",
            f"**Framework**: CISA ZTMM v2 (Zero Trust Maturity Model), NIST SP 800-207",
            "",
            "## Executive Summary",
            "",
            f"**Overall Maturity**: {results['overall']['overall_stage']}",
            f"**Average Score**: {results['overall']['average_numeric']}/4.0",
            f"**Lowest Pillar**: {results['overall']['lowest_pillar']['name']} ({results['overall']['lowest_pillar']['stage']})",
            f"**Highest Pillar**: {results['overall']['highest_pillar']['name']} ({results['overall']['highest_pillar']['stage']})",
            "",
            "## Pillar Scores",
            "",
            "| Pillar | Stage | Score |",
            "|--------|-------|-------|"
        ]
        
        for pillar_name, pillar_data in results["pillar_scores"].items():
            lines.append(f"| {pillar_name} | {pillar_data['stage']} | {pillar_data['score']:.2f} |")
        
        lines.extend([
            "",
            "## Sub-Capability Details",
            ""
        ])
        
        for pillar_name, pillar_data in results["pillar_scores"].items():
            lines.append(f"### {pillar_name}")
            lines.append("")
            lines.append("| Sub-Capability | Stage |")
            lines.append("|----------------|-------|")
            for subcap in pillar_data["sub_capabilities"]:
                lines.append(f"| {subcap['name']} | {subcap['stage']} |")
            lines.append("")
        
        lines.extend([
            "## Recommendations",
            "",
            "| Priority | Pillar | Focus Area | Current | Target | Rationale |",
            "|----------|--------|------------|---------|--------|-----------|"
        ])
        
        for rec in results["recommendations"]:
            lines.append(
                f"| {rec['priority']} | {rec['pillar']} | {rec['focus_area']} | "
                f"{rec['current_stage']} | {rec['target_stage']} | {rec['rationale']} |"
            )
        
        lines.append("")
        lines.append("## Suggested Actions")
        for rec in results["recommendations"]:
            lines.append(f"### {rec['priority']}: {rec['pillar']} - {rec['focus_area']}")
            for action in rec["suggested_actions"]:
                lines.append(f"- {action}")
            lines.append("")
        
        with open(output_path, "w") as f:
            f.write("\n".join(lines))

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Calculate Zero Trust Maturity Model scores")
    parser.add_argument("assessment_file", help="YAML/JSON file with assessment answers")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--format", choices=["json", "yaml", "markdown"], default="json")
    args = parser.parse_args()

    scorer = MaturityScorer()
    try:
        results = scorer.run_assessment(Path(args.assessment_file))
    except ValueError as e:
        # Bad stage names are user input errors, so report them without a traceback
        raise SystemExit(f"Error: {e}")

    if args.output:
        scorer.export_report(results, Path(args.output), args.format)
        print(f"Report written to {args.output}")
    else:
        print(json.dumps(results, indent=2))

    # Print summary
    print("\n" + "="*50)
    print("MATURITY ASSESSMENT SUMMARY")
    print("="*50)
    print(f"Overall: {results['overall']['overall_stage']} ({results['overall']['average_numeric']}/4.0)")
    for pillar, score in results["pillar_scores"].items():
        print(f"  {pillar}: {score['stage']} ({score['score']:.2f})")

if __name__ == "__main__":
    main()