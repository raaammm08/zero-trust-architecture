"""Smoke tests for the command-line scripts.

These cover the checks in docs/guide.md, Part 10: each script runs on the
sample inputs, every format and framework option writes a file, and bad input
exits with a non-zero code. Tests that need `opa` or `cedar` are skipped when
the tool is not installed.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SAMPLE_ASSESSMENT = ROOT / "examples" / "sample-assessment.yaml"
SAMPLE_ARCHITECTURE = ROOT / "examples" / "architecture-example.yaml"
FRAMEWORKS = ["nist_800_53", "fedramp_high", "cmmc_20_l3", "iso_27001_2022", "soc2", "hipaa", "pci_dss_40", "all"]


def run(script, *args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *map(str, args)],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def cedar_available():
    return shutil.which("cedar") or (Path.home() / ".cargo" / "bin" / "cedar").exists()


@pytest.mark.parametrize("script", sorted(p.name for p in SCRIPTS.glob("*.py")))
def test_help(script):
    result = run(script, "-h")
    assert result.returncode == 0, result.stderr
    assert "usage" in result.stdout.lower()


# --- score-maturity.py -------------------------------------------------------

@pytest.mark.parametrize("fmt", ["json", "yaml", "markdown"])
def test_score_formats(tmp_path, fmt):
    out = tmp_path / f"score.{fmt}"
    result = run("score-maturity.py", SAMPLE_ASSESSMENT, "-o", out, "--format", fmt)
    assert result.returncode == 0, result.stderr
    assert out.stat().st_size > 0


def test_score_json_has_every_pillar(tmp_path):
    out = tmp_path / "score.json"
    assert run("score-maturity.py", SAMPLE_ASSESSMENT, "-o", out).returncode == 0
    text = out.read_text()
    json.loads(text)
    for pillar in ["Identity", "Device", "Network", "Application/Workload", "Data",
                   "Visibility & Analytics", "Automation & Orchestration"]:
        assert pillar in text


def test_score_rejects_unknown_stage(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(SAMPLE_ASSESSMENT.read_text().replace('Authentication: "initial"', 'Authentication: "excellent"', 1))
    assert run("score-maturity.py", bad).returncode != 0


def test_score_rejects_malformed_yaml(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("Identity: [unclosed\n")
    assert run("score-maturity.py", bad).returncode != 0


# --- map-compliance.py -------------------------------------------------------

@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_map_frameworks(tmp_path, framework):
    out = tmp_path / "matrix.csv"
    result = run("map-compliance.py", "--framework", framework, "-o", out)
    assert result.returncode == 0, result.stderr
    assert out.stat().st_size > 0


@pytest.mark.parametrize("fmt,ext", [("csv", "csv"), ("json", "json"), ("yaml", "yaml"), ("markdown", "md")])
def test_map_default_output_name(tmp_path, fmt, ext):
    result = run("map-compliance.py", "--framework", "fedramp_high", "--format", fmt, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / f"control-matrix.{ext}").stat().st_size > 0


def test_map_evidence_checklist(tmp_path):
    result = run("map-compliance.py", "--evidence-checklist", "fedramp_high", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "evidence-checklist-fedramp_high.csv").stat().st_size > 0


@pytest.mark.parametrize("tenet", range(1, 8))
def test_map_tenet(tenet):
    result = run("map-compliance.py", "--tenet", tenet)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["tenet_number"] == tenet


def test_map_rejects_out_of_range_tenet():
    assert run("map-compliance.py", "--tenet", 9).returncode != 0


# --- generate-mermaid.py -----------------------------------------------------

@pytest.mark.parametrize("kind", ["architecture", "dataflow", "matrix"])
def test_mermaid_types(tmp_path, kind):
    out = tmp_path / f"{kind}.mmd"
    result = run("generate-mermaid.py", SAMPLE_ARCHITECTURE, "--type", kind, "-o", out)
    assert result.returncode == 0, result.stderr
    assert out.read_text().strip()


# --- validate-rego.py --------------------------------------------------------

@pytest.mark.skipif(not shutil.which("opa"), reason="opa not installed")
@pytest.mark.parametrize("policy_dir", ["templates/policies", "examples/policies/jit-db-access"])
def test_rego_valid(policy_dir):
    result = run("validate-rego.py", ROOT / policy_dir)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not shutil.which("opa"), reason="opa not installed")
def test_rego_rejects_broken_policy(tmp_path):
    (tmp_path / "broken.rego").write_text("package broken\n\nallow if {\n")
    assert run("validate-rego.py", tmp_path).returncode != 0


# --- validate-cedar.py -------------------------------------------------------

@pytest.mark.skipif(not cedar_available(), reason="cedar not installed")
def test_cedar_template_cases_pass():
    result = run("validate-cedar.py", ROOT / "templates" / "policies")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "failed 0" in result.stdout


@pytest.mark.skipif(not cedar_available(), reason="cedar not installed")
def test_cedar_rejects_typo(tmp_path):
    for name in ["cedar-template.cedar", "cedar-schema.cedarschema"]:
        shutil.copy(ROOT / "templates" / "policies" / name, tmp_path / name)
    policy = tmp_path / "cedar-template.cedar"
    policy.write_text(policy.read_text().replace("\npermit (", "\npermt (", 1))
    assert run("validate-cedar.py", tmp_path).returncode != 0
