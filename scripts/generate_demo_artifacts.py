"""Generate a reproducible, human-readable auditor-skill demonstration artifact."""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any

from contract_verifier.auditor import audit_repository
from contract_verifier.ir.schema import ExprKind, Expression

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "artifacts" / "reproducible_demo"
DEMO_SOURCE = "tests/fixtures/VulnerableVault.sol"


def normalize(value: Any) -> Any:
    if isinstance(value, Expression):
        return {
            "kind": value.kind.value,
            "value": value.value,
            "args": [normalize(arg) for arg in value.args],
        }
    if isinstance(value, ExprKind):
        return value.value
    if is_dataclass(value):
        return {field.name: normalize(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [normalize(item) for item in sorted(value, key=repr)]
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(value[key]) for key in sorted(value)}
    return value


def write_text(name: str, content: str) -> None:
    (OUT_DIR / name).write_text(content, encoding="utf-8")


def write_json(name: str, value: Any) -> None:
    write_text(name, json.dumps(normalize(value), indent=2, sort_keys=True) + "\n")


def expr_text(expr: Expression) -> str:
    if expr.kind == ExprKind.LITERAL:
        return repr(expr.value)
    if expr.kind in {ExprKind.SYMBOL, ExprKind.READ, ExprKind.CALLER}:
        return str(expr.value) if expr.value is not None else expr.kind.value
    if expr.kind == ExprKind.NOT:
        return f"not ({expr_text(expr.args[0])})"
    if len(expr.args) == 2:
        operators = {
            ExprKind.EQ: "==",
            ExprKind.NEQ: "!=",
            ExprKind.LT: "<",
            ExprKind.LTE: "<=",
            ExprKind.GT: ">",
            ExprKind.GTE: ">=",
            ExprKind.ADD: "+",
            ExprKind.SUB: "-",
            ExprKind.MUL: "*",
            ExprKind.DIV: "/",
        }
        return (
            f"({expr_text(expr.args[0])} "
            f"{operators.get(expr.kind, expr.kind.value)} "
            f"{expr_text(expr.args[1])})"
        )
    return repr(normalize(expr))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    run = audit_repository(ROOT)

    write_text("01_original_source.sol", (ROOT / DEMO_SOURCE).read_text(encoding="utf-8"))
    write_json("02_contract_ir.json", run.contracts)
    write_json(
        "03_execution_paths.json",
        {path: artifact["states"] for path, artifact in run.artifacts.items() if isinstance(artifact, dict)},
    )
    write_json(
        "04_solver_decisions.json",
        {
            path: [
                {
                    "path": state.transition_ids,
                    "branch_history": state.branch_history,
                    "solver_status": state.metadata.get("solver_status"),
                    "solver_proof": state.metadata.get("solver_proof"),
                    "path_conditions": [expr_text(expr) for expr in state.path_conditions],
                }
                for state in artifact["states"]
            ]
            for path, artifact in run.artifacts.items()
            if isinstance(artifact, dict)
        },
    )
    write_json(
        "05_invariant_violations.json",
        {path: artifact["violations"] for path, artifact in run.artifacts.items() if isinstance(artifact, dict)},
    )
    write_json("06_minimized_counterexample.json", [finding.counterexample for finding in run.findings])
    write_json("07_escalation_analysis.json", [finding.escalation.to_dict() for finding in run.findings])
    write_text("08_final_audit_report.md", run.to_markdown())

    index = """# Reproducible Auditor Skill Demonstration

This directory contains a committed, human-readable snapshot of the auditor
workflow. It is intended for demos, review, and regression checks.

## Regenerate

From the repository root, run:

```bash
PYTHONPATH=src python scripts/generate_demo_artifacts.py
```

The generator calls `audit_repository` on the repository root and rewrites this
directory with deterministic outputs.

## End-to-end flow

```text
User → audit_repository → final report
```

## Artifact map

1. `01_original_source.sol` — representative Solidity source discovered by
   `audit_repository`.
2. `02_contract_ir.json` — generated `ContractIR` for every discovered
   Solidity/Anchor contract.
3. `03_execution_paths.json` — symbolic execution paths explored for each
   lowered contract.
4. `04_solver_decisions.json` — path feasibility and solver decisions.
5. `05_invariant_violations.json` — invariant violations detected.
6. `06_minimized_counterexample.json` — minimized counterexamples for failed
   invariants.
7. `07_escalation_analysis.json` — exploit escalation analysis.
8. `08_final_audit_report.md` — aggregate final audit report.

## Expected headline result

The current demo audits the repository examples and fixtures, finds the
`VulnerableVault` negative-balance path, minimizes it to the `drain` transition
with `balance = -5`, and reports critical asset-loss impact.
"""
    write_text("README.md", index)


if __name__ == "__main__":
    main()
