#!/usr/bin/env python3
"""
Zero Trust Compliance Mapper

Maps NIST 800-207 Zero Trust tenets to various compliance frameworks.
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

FRAMEWORK_LABELS = {
    "nist_800_53": "NIST 800-53",
    "fedramp_high": "FedRAMP High",
    "cmmc_20_l3": "CMMC 2.0 L3",
    "iso_27001_2022": "ISO 27001:2022",
    "soc2": "SOC 2",
    "hipaa": "HIPAA",
    "pci_dss_40": "PCI DSS 4.0",
}

@dataclass
class ControlMapping:
    zt_tenet: str
    tenet_number: int
    nist_800_53: List[str]
    fedramp_high: List[str]
    cmmc_20_l3: List[str]
    iso_27001_2022: List[str]
    soc2: List[str]
    hipaa: List[str]
    pci_dss_40: List[str]
    zt_implementation: str
    evidence_required: List[str]

class ComplianceMapper:
    def __init__(self):
        self.mappings = self._load_default_mappings()

    def _load_default_mappings(self) -> List[ControlMapping]:
        """Load default ZT-to-compliance mappings."""
        return [
            ControlMapping(
                zt_tenet="All data sources and computing services are resources",
                tenet_number=1,
                nist_800_53=["CM-8", "CM-9", "PM-5", "RA-5", "SA-12"],
                fedramp_high=["CM-8", "CM-9", "PM-5", "RA-5", "SA-12"],
                cmmc_20_l3=["CM.L2-3.4.9", "CM.L2-3.4.10", "RA.L2-3.11.1"],
                iso_27001_2022=["A.5.9", "A.8.1.1", "A.8.1.2", "A.12.6.1"],
                soc2=["CC6.1", "CC6.2", "CC6.7"],
                hipaa=["§164.308(a)(1)", "§164.308(a)(3)", "§164.310(a)(1)"],
                pci_dss_40=["Req 2.2", "Req 2.3", "Req 2.4", "Req 11.5"],
                zt_implementation="Automated asset discovery, CMDB with classification tags, continuous inventory reconciliation, vulnerability scanning",
                evidence_required=[
                    "CMDB export with classification",
                    "Discovery scan results",
                    "Reconciliation reports",
                    "Vulnerability scan reports",
                    "Asset criticality ratings"
                ]
            ),
            ControlMapping(
                zt_tenet="All communication is secured regardless of network location",
                tenet_number=2,
                nist_800_53=["SC-7", "SC-8", "SC-13", "SC-23", "SC-12", "SC-17"],
                fedramp_high=["SC-7", "SC-8", "SC-13", "SC-23"],
                cmmc_20_l3=["SC.L2-3.13.11", "SC.L2-3.13.12", "SC.L2-3.13.13"],
                iso_27001_2022=["A.8.2.1", "A.13.1.1", "A.13.2.1", "A.10.1.1"],
                soc2=["CC6.1", "CC6.7", "CC6.8"],
                hipaa=["§164.312(e)(1)", "§164.312(e)(2)", "§164.312(c)(1)"],
                pci_dss_40=["Req 2.3", "Req 4.1", "Req 4.2"],
                zt_implementation="mTLS everywhere (service mesh), TLS 1.3, ZTNA for remote access, certificate automation, deny-by-default network",
                evidence_required=[
                    "Network diagrams with encryption zones",
                    "mTLS configuration and verification",
                    "Certificate inventory and rotation logs",
                    "TLS scan results (all endpoints)",
                    "ZTNA configuration and access logs"
                ]
            ),
            ControlMapping(
                zt_tenet="Access to individual enterprise resources is granted on a per-session basis",
                tenet_number=3,
                nist_800_53=["AC-2", "AC-3", "AC-12", "AC-17", "AC-14", "IA-8"],
                fedramp_high=["AC-2", "AC-3", "AC-12", "AC-17"],
                cmmc_20_l3=["AC.L2-3.1.1", "AC.L2-3.1.2", "IA.L2-3.5.2"],
                iso_27001_2022=["A.9.2.1", "A.9.2.2", "A.9.4.2", "A.9.4.3"],
                soc2=["CC6.1", "CC6.2", "CC6.3"],
                hipaa=["§164.312(a)(1)", "§164.312(a)(2)", "§164.312(d)"],
                pci_dss_40=["Req 7.1", "Req 8.1", "Req 8.2", "Req 8.3"],
                zt_implementation="Dynamic PDP/PEP, short-lived sessions, immediate revocation, continuous evaluation, JIT access",
                evidence_required=[
                    "Policy engine configuration",
                    "Session TTL and revocation tests",
                    "JIT access workflow and logs",
                    "Continuous evaluation architecture",
                    "Break-glass procedures"
                ]
            ),
            ControlMapping(
                zt_tenet="Access to resources is determined by dynamic policy",
                tenet_number=4,
                nist_800_53=["AC-2", "AC-3", "AC-4", "AC-16", "SC-7", "SC-16", "SI-10"],
                fedramp_high=["AC-2", "AC-3", "AC-4", "AC-16", "SC-7"],
                cmmc_20_l3=["AC.L2-3.1.1", "AC.L2-3.1.3", "SC.L2-3.13.11"],
                iso_27001_2022=["A.9.1.2", "A.9.2.3", "A.9.4.1", "A.13.1.1"],
                soc2=["CC6.1", "CC6.3", "CC6.7"],
                hipaa=["§164.312(a)(1)", "§164.312(a)(2)", "§164.312(c)(1)"],
                pci_dss_40=["Req 7.1", "Req 7.2", "Req 8.1"],
                zt_implementation="OPA/Cedar policy-as-code, ABAC with real-time attributes (risk, posture, threat), GitOps deployment, policy testing",
                evidence_required=[
                    "Policy definitions (Rego/Cedar)",
                    "Attribute sources and freshness",
                    "Decision logs with context",
                    "Policy test results (CI/CD)",
                    "GitOps deployment pipeline"
                ]
            ),
            ControlMapping(
                zt_tenet="The enterprise monitors and measures the integrity and security posture of all owned and associated assets",
                tenet_number=5,
                nist_800_53=["SI-4", "SI-7", "CM-11", "RA-5", "CA-7", "CM-8", "PE-6", "PE-20"],
                fedramp_high=["SI-4", "SI-7", "CM-11", "RA-5", "CA-7"],
                cmmc_20_l3=["SI.L2-3.14.1", "SI.L2-3.14.2", "RA.L2-3.11.1"],
                iso_27001_2022=["A.12.4.1", "A.12.6.1", "A.12.5.1", "A.16.1.1"],
                soc2=["CC7.1", "CC7.2", "CC7.3", "CC7.4"],
                hipaa=["§164.308(a)(5)", "§164.312(b)", "§164.312(c)(1)"],
                pci_dss_40=["Req 10.1", "Req 10.2", "Req 10.5", "Req 11.5"],
                zt_implementation="EDR/XDR, CSPM, network sensors, UEBA, SOAR, continuous monitoring dashboard, cATO pipeline",
                evidence_required=[
                    "Monitoring coverage report (all 7 pillars)",
                    "UEBA model metrics and tuning",
                    "SOAR playbook inventory and execution logs",
                    "MTTD/MTTR metrics",
                    "cATO continuous monitoring package"
                ]
            ),
            ControlMapping(
                zt_tenet="All resource authentication and authorization are dynamic and strictly enforced before access is allowed",
                tenet_number=6,
                nist_800_53=["IA-2", "IA-3", "IA-4", "IA-5", "IA-8", "IA-11", "AC-2", "AC-3"],
                fedramp_high=["IA-2", "IA-3", "IA-4", "IA-5", "IA-8"],
                cmmc_20_l3=["IA.L2-3.5.1", "IA.L2-3.5.2", "IA.L2-3.5.3", "IA.L2-3.5.4"],
                iso_27001_2022=["A.9.3.1", "A.9.4.2", "A.9.4.3", "A.9.2.1"],
                soc2=["CC6.1", "CC6.2", "CC6.4"],
                hipaa=["§164.312(a)(1)", "§164.312(d)"],
                pci_dss_40=["Req 8.1", "Req 8.2", "Req 8.3", "Req 8.4", "Req 8.5"],
                zt_implementation="Phishing-resistant MFA (FIDO2), device certificates, workload identity (SPIFFE), conditional access, token binding",
                evidence_required=[
                    "MFA enrollment reports (FIDO2 %)",
                    "Device certificate inventory",
                    "Workload identity deployment (SPIRE)",
                    "Conditional access policies",
                    "Authentication logs with context"
                ]
            ),
            ControlMapping(
                zt_tenet="The enterprise collects information about the current state of assets, network infrastructure, and communications and uses it to improve its security posture",
                tenet_number=7,
                nist_800_53=["AU-2", "AU-3", "AU-6", "AU-12", "AU-14", "IR-4", "IR-5", "IR-6", "PM-14", "CA-7"],
                fedramp_high=["AU-2", "AU-3", "AU-6", "AU-12", "AU-14", "IR-4", "IR-5", "IR-6", "PM-14"],
                cmmc_20_l3=["AU.L2-3.3.1", "AU.L2-3.3.2", "IR.L2-3.6.1", "IR.L2-3.6.2"],
                iso_27001_2022=["A.12.4.1", "A.12.4.3", "A.16.1.5", "A.16.1.6"],
                soc2=["CC7.2", "CC7.3", "CC7.4", "CC7.5"],
                hipaa=["§164.308(a)(5)", "§164.312(b)", "§164.308(a)(6)"],
                pci_dss_40=["Req 10.1", "Req 10.2", "Req 10.5", "Req 11.4"],
                zt_implementation="Immutable centralized logging (OCSF), cryptographic log integrity, automated compliance evidence, red team/purple team, chaos engineering",
                evidence_required=[
                    "Log source coverage matrix",
                    "Log integrity verification",
                    "Automated compliance evidence samples",
                    "Red team / purple team results",
                    "Chaos engineering experiment logs"
                ]
            )
        ]

    def get_mapping(self, tenet_number: int) -> Optional[ControlMapping]:
        """Get mapping for a specific tenet."""
        for mapping in self.mappings:
            if mapping.tenet_number == tenet_number:
                return mapping
        return None

    def get_frameworks_for_control(self, framework: str) -> List[Dict[str, Any]]:
        """Get all control mappings for a specific framework."""
        results = []
        for mapping in self.mappings:
            controls = getattr(mapping, framework.lower().replace("-", "_"), [])
            for control in controls:
                results.append({
                    "zt_tenet": mapping.zt_tenet,
                    "tenet_number": mapping.tenet_number,
                    "framework_control": control,
                    "zt_implementation": mapping.zt_implementation,
                    "evidence_required": mapping.evidence_required
                })
        return results

    def generate_control_matrix(self, frameworks: List[str] = None) -> List[Dict[str, Any]]:
        """Generate control matrix for specified frameworks."""
        if frameworks is None:
            frameworks = ["nist_800_53", "fedramp_high", "cmmc_20_l3", "iso_27001_2022", "soc2", "hipaa", "pci_dss_40"]
        # FedRAMP High is built on NIST 800-53, so always show the base control column beside it
        if "fedramp_high" in frameworks and "nist_800_53" not in frameworks:
            frameworks = ["nist_800_53"] + frameworks

        matrix = []
        for mapping in self.mappings:
            row = {
                "ZT Tenet": mapping.zt_tenet,
                "Tenet Number": mapping.tenet_number,
                "ZT Implementation": mapping.zt_implementation
            }
            for fw in frameworks:
                controls = getattr(mapping, fw.lower().replace("-", "_"), [])
                row[FRAMEWORK_LABELS.get(fw, fw)] = "; ".join(controls)
            matrix.append(row)
        return matrix

    def export_matrix(self, output_path: Path, format: str = "csv", frameworks: List[str] = None):
        """Export control matrix."""
        matrix = self.generate_control_matrix(frameworks)
        
        if format == "csv":
            if not matrix:
                return
            fieldnames = list(matrix[0].keys())
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(matrix)
        elif format == "json":
            with open(output_path, "w") as f:
                json.dump(matrix, f, indent=2)
        elif format == "yaml":
            try:
                import yaml
            except ImportError:
                raise SystemExit("YAML output needs PyYAML: pip install -r requirements.txt")
            with open(output_path, "w") as f:
                yaml.dump(matrix, f, default_flow_style=False)
        elif format == "markdown":
            self._export_markdown(matrix, output_path)

    def _export_markdown(self, matrix: List[Dict[str, Any]], output_path: Path):
        """Export as Markdown table."""
        if not matrix:
            return
        
        headers = list(matrix[0].keys())
        
        with open(output_path, "w") as f:
            f.write("# Zero Trust to Compliance Control Matrix\n\n")
            f.write("| " + " | ".join(headers) + " |\n")
            f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
            
            for row in matrix:
                # Truncate long cells for readability
                cells = []
                for h in headers:
                    val = str(row.get(h, ""))
                    if len(val) > 80:
                        val = val[:77] + "..."
                    cells.append(val)
                f.write("| " + " | ".join(cells) + " |\n")

    def generate_evidence_checklist(self, framework: str) -> List[Dict[str, Any]]:
        """Generate evidence collection checklist for a framework."""
        checklist = []
        for mapping in self.mappings:
            controls = getattr(mapping, framework.lower().replace("-", "_"), [])
            for control in controls:
                for evidence in mapping.evidence_required:
                    checklist.append({
                        "framework": framework,
                        "control": control,
                        "zt_tenet": mapping.zt_tenet,
                        "tenet_number": mapping.tenet_number,
                        "evidence": evidence,
                        "collected": False,
                        "location": "",
                        "notes": ""
                    })
        return checklist

    def export_evidence_checklist(self, framework: str, output_path: Path, format: str = "csv"):
        """Export evidence checklist."""
        checklist = self.generate_evidence_checklist(framework)
        
        if format == "csv":
            fieldnames = ["framework", "control", "zt_tenet", "tenet_number", "evidence", "collected", "location", "notes"]
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(checklist)
        elif format == "json":
            with open(output_path, "w") as f:
                json.dump(checklist, f, indent=2)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Map Zero Trust tenets to compliance frameworks")
    parser.add_argument("--framework", choices=["nist_800_53", "fedramp_high", "cmmc_20_l3", "iso_27001_2022", "soc2", "hipaa", "pci_dss_40", "all"],
                        default="all", help="Target framework")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--format", choices=["csv", "json", "yaml", "markdown"], default="csv")
    parser.add_argument("--evidence-checklist", help="Generate evidence checklist for framework")
    parser.add_argument("--tenet", type=int, choices=range(1, 8), help="Show mapping for specific tenet")
    args = parser.parse_args()

    mapper = ComplianceMapper()

    if args.tenet:
        mapping = mapper.get_mapping(args.tenet)
        if mapping:
            print(json.dumps(asdict(mapping), indent=2))
        else:
            print(f"Tenet {args.tenet} not found")
        return

    if args.evidence_checklist:
        if not args.output:
            args.output = f"evidence-checklist-{args.evidence_checklist}.csv"
        mapper.export_evidence_checklist(args.evidence_checklist, Path(args.output), args.format)
        print(f"Evidence checklist written to {args.output}")
        return

    frameworks = None if args.framework == "all" else [args.framework]
    if not args.output:
        args.output = f"control-matrix.{args.format}"

    mapper.export_matrix(Path(args.output), args.format, frameworks)
    print(f"Control matrix written to {args.output}")

if __name__ == "__main__":
    main()