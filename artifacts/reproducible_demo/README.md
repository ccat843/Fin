# Reproducible Auditor Skill Demonstration

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
5. `05_invariant_violations.json` — invariant violations and hypothesis-backed
   confirmation failures detected.
6. `06_minimized_counterexample.json` — minimized counterexamples for confirmed
   exploits.
7. `07_escalation_analysis.json` — exploit escalation analysis.
8. `08_final_audit_report.md` — aggregate final audit report including
   hypotheses, confirmed exploits, failed hypotheses, potential risks, and
   remediation.

## Expected headline result

The current demo audits the repository examples and fixtures, generates an
`unchecked_value_mutation` hypothesis for `VulnerableVault.drain`, validates it
with symbolic execution, minimizes the confirmed exploit to the `drain`
transition with `balance = -5`, and reports critical asset-loss impact.
