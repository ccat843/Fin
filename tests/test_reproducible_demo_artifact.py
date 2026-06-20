import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / "artifacts" / "reproducible_demo"


def test_reproducible_demo_artifact_regenerates_all_intermediate_outputs():
    subprocess.run(
        [sys.executable, "scripts/generate_demo_artifacts.py"],
        cwd=ROOT,
        env={"PYTHONPATH": "src"},
        check=True,
    )

    expected = [
        "01_original_source.sol",
        "02_contract_ir.json",
        "03_execution_paths.json",
        "04_solver_decisions.json",
        "05_invariant_violations.json",
        "06_minimized_counterexample.json",
        "07_escalation_analysis.json",
        "08_final_audit_report.md",
        "README.md",
    ]
    for name in expected:
        assert (ARTIFACT_DIR / name).read_text(encoding="utf-8").strip()

    ir = json.loads((ARTIFACT_DIR / "02_contract_ir.json").read_text(encoding="utf-8"))
    counterexamples = json.loads((ARTIFACT_DIR / "06_minimized_counterexample.json").read_text(encoding="utf-8"))
    report = (ARTIFACT_DIR / "08_final_audit_report.md").read_text(encoding="utf-8")

    vulnerable_ir = next(contract for contract in ir if contract["id"] == "VulnerableVault")

    assert vulnerable_ir["transitions"][0]["name"] == "drain"
    assert counterexamples[0]["state_snapshot"] == {"balance": -5}
    assert "User → audit_repository → final report" in (ARTIFACT_DIR / "README.md").read_text(encoding="utf-8")
    assert "## Escalation Chains" in report
