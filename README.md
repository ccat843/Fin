# Contract Verifier Skill

A deterministic, auditor-facing smart-contract verification scaffold for Solidity
and Anchor repositories. The project lowers supported contract syntax into a
unified `ContractIR`, explores paths with a symbolic executor, checks invariants
with a deterministic constraint solver, minimizes counterexamples, evaluates
exploit escalation, and emits auditor-readable reports.

This repository is intentionally small and reproducible: no external SMT solver,
LLM provider, blockchain node, or compiler is required for the bundled demo and
test suite.

## What is implemented today

- **Auditor skill commands** in `contract_verifier.auditor`:
  - `audit_contract`
  - `audit_repository`
  - `explain_finding`
  - `generate_remediation`
  - `compare_before_after_patch`
- **Repository audit workflow** that discovers Solidity files and Anchor-looking
  Rust files, lowers each supported contract, runs the existing verification
  pipeline, and aggregates findings into a final report.
- **Solidity frontend subset** for contract declarations, state variables,
  functions, `require(...)` guards, `msg.sender`, and simple assignments or
  arithmetic updates.
- **Anchor frontend placeholder** that identifies Anchor/Rust sources and lowers
  them into a Solana `ContractIR` shell. Detailed Anchor account/instruction
  lowering is not implemented yet.
- **Deterministic symbolic execution and constraint solving** for the IR subset
  covered by the tests and demo.
- **Counterexample minimization**, **escalation analysis**, and structured
  **audit report rendering**.
- **Reproducible demo artifacts** in `artifacts/reproducible_demo` showing the
  full path from `User → audit_repository → final report`.

## Repository layout

```text
src/contract_verifier/
  auditor/       Auditor-facing command interface and report aggregation
  frontends/     Solidity subset frontend and Anchor placeholder frontend
  ir/            Chain-neutral dataclass schema for ContractIR
  symbolic/      Symbolic execution, invariant evaluation, counterexamples
  solver/        Deterministic baseline constraint solver
  escalation/    Exploit escalation analysis for confirmed counterexamples
  reporting/     Structured audit report dataclass and markdown renderer
  ai/            Candidate-property generation boundary placeholder

examples/        Example Solidity and Anchor contracts
tests/           Unit and end-to-end tests
artifacts/       Committed reproducible demonstration outputs
scripts/         Demo artifact generator
```

## Quick start

### 1. Create an environment

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

The project itself has no runtime dependencies beyond Python 3.11+. The `dev`
extra installs `pytest`.

### 2. Run the tests

```bash
pytest -q
```

### 3. Run an auditor-facing repository audit

```bash
PYTHONPATH=src python - <<'PY'
from contract_verifier.auditor import audit_repository

run = audit_repository('.')
print(run.to_markdown())
PY
```

### 4. Regenerate the end-to-end demo artifacts

```bash
PYTHONPATH=src python scripts/generate_demo_artifacts.py
```

This rewrites the files in `artifacts/reproducible_demo`:

1. original Solidity source
2. generated ContractIR for discovered contracts
3. execution paths explored
4. solver decisions
5. invariant violations
6. minimized counterexamples
7. escalation analysis
8. final audit report

## Auditor command examples

### Audit a single contract

```python
from pathlib import Path
from contract_verifier.auditor import audit_contract

source = Path('tests/fixtures/VulnerableVault.sol').read_text()
run = audit_contract(source, file_name='VulnerableVault.sol')
print(run.to_markdown())
```

### Audit a repository

```python
from contract_verifier.auditor import audit_repository

run = audit_repository('.')
for finding in run.findings:
    print(finding.explanation)
```

### Explain a finding and generate remediation

```python
from contract_verifier.auditor import audit_contract, explain_finding, generate_remediation

run = audit_contract(source, file_name='VulnerableVault.sol')
finding = run.findings[0]
print(explain_finding(finding))
print(generate_remediation(finding)['why_it_works'])
```

### Compare before and after a patch

```python
from contract_verifier.auditor import compare_before_after_patch

comparison = compare_before_after_patch('before.sol', 'after.sol')
print(comparison['summary'])
```

## Current verification model

The verifier uses deterministic local components only:

1. Frontends lower source text into `ContractIR`.
2. The auditor interface adds default asset non-negativity obligations for
   recognized numeric asset-like resources such as `balance`.
3. Symbolic execution explores transition paths and records guards, effects,
   path conditions, and terminal states.
4. The baseline solver checks simple boolean, equality, inequality, and affine
   range constraints. Unsupported symbolic shapes are reported as `unknown`
   rather than guessed.
5. Invariant violations are minimized into compact counterexamples.
6. Escalation analysis ranks impact and builds a compact exploit-chain graph.
7. Reports convert technical results into auditor-readable markdown.

## Limitations

This is a scaffold and demonstration harness, not a production-grade smart
contract auditor yet.

- Solidity parsing covers a deterministic subset, not the full Solidity grammar.
- Anchor parsing currently creates a Solana IR shell; detailed account,
  constraint, CPI, and instruction lowering remains future work.
- The bundled solver is intentionally conservative and not a full SMT backend.
- The AI property generator is a boundary placeholder and returns no obligations
  by default.
- Default obligations and initial storage are heuristics designed for the demo
  and tests; real audits should supply explicit project-specific invariants.

## Development workflow

```bash
# Regenerate demo artifacts
PYTHONPATH=src python scripts/generate_demo_artifacts.py

# Run the full test suite
pytest -q
```

When changing the auditor interface or verification flow, update both
`docs/design.md` and the reproducible demo artifacts so the committed docs match
the current behavior.
