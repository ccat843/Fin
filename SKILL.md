---
name: contract-verifier
description: Use this skill when an auditor or developer asks an AI agent to audit Solidity or Anchor smart-contract repositories, explain findings, generate remediation guidance, compare before/after patches, or produce reproducible verification artifacts with the local contract_verifier package.
---

# Contract Verifier

Use this skill to run the repository's security-first auditor interface for
Solidity and Anchor smart-contract vulnerability discovery demos.

## Core commands

Run Python from the skill/repository root with `PYTHONPATH=src` unless the
package has already been installed into the active environment.

```python
from contract_verifier.auditor import (
    audit_contract,
    audit_repository,
    explain_finding,
    generate_remediation,
    compare_before_after_patch,
)
```

## Standard workflow

1. For a repository audit, call `audit_repository(path)`.
2. Read `run.to_markdown()` for hypotheses, confirmed exploits, failed hypotheses, potential risks, and remediation.
3. Inspect `run.hypotheses`, `run.hypothesis_validations`, and `run.findings` for structured results.
4. Use `explain_finding(finding)` when the user needs auditor-readable prose.
5. Use `generate_remediation(finding)` when the user asks how to fix a failed invariant.
6. Use `compare_before_after_patch(before, after)` to summarize whether a patch resolved findings.

## Reproducible demo

To regenerate the bundled demo artifacts, run:

```bash
PYTHONPATH=src python scripts/generate_demo_artifacts.py
```

The output is written to `artifacts/reproducible_demo` and demonstrates:

```text
User → audit_repository → final report
```

## Guardrails

- Treat this as a hybrid discovery scaffold, not a production-grade audit engine.
- Report the documented limitations when presenting results: Solidity support is
  subset-based, Anchor lowering is a shell, and the bundled solver is conservative.
- Do not claim unsupported paths are proven safe when the solver reports `unknown`.
