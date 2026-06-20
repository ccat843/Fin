# Contract Verifier Design

This document describes the current implementation in this repository. It is not
an aspirational architecture document: sections below distinguish implemented
behavior from known limitations.

## Purpose

The project provides an auditor-facing interface for deterministic smart-contract
verification demos. Auditors call high-level commands such as
`audit_repository`, receive an aggregate report, and can inspect intermediate
artifacts when they need to understand how a finding was produced.

The core design goal is separation of responsibilities:

- frontends lower source into a shared IR;
- symbolic execution and solver layers make verification decisions;
- counterexample, escalation, and reporting layers make results easier to audit;
- the auditor interface orchestrates those pieces without adding verification
  internals.

## Auditor skill interface

The public command surface lives in `contract_verifier.auditor`.

| Command | Purpose |
| --- | --- |
| `audit_contract(source, file_name=...)` | Audit one Solidity or Anchor/Rust source string and return an `AuditRun`. |
| `audit_repository(path)` | Discover supported contracts under a repository, lower each contract, run verification, and aggregate findings. |
| `explain_finding(finding)` | Convert a technical finding into auditor-readable prose. |
| `generate_remediation(finding)` | Propose a remediation and explain why it removes the counterexample. |
| `compare_before_after_patch(before, after)` | Audit two files or repositories and summarize resolved/new/unchanged findings. |

`AuditRun` contains the command name, lowered contracts, findings, final
`AuditReport`, and per-contract artifacts such as states and violations.


## Skill packaging and installation

The repository is also packaged as an AI-agent skill by including a root
`SKILL.md`. Agent runtimes that support local skill folders can install the repo
under their skills directory, for example `$CODEX_HOME/skills/contract-verifier`,
and then install the Python package in editable mode with `python -m pip install
-e '.[dev]'`.

The skill file intentionally stays concise. It tells agents to call the public
`contract_verifier.auditor` commands and to disclose current limitations when
presenting audit results. The root `README.md` contains human-oriented setup and
installation details.

## Repository workflow

`audit_repository` currently performs this deterministic workflow:

1. Walk the repository in sorted order.
2. Ignore generated/cache directories such as `.git`, `.pytest_cache`,
   `__pycache__`, `node_modules`, `target`, and `artifacts`.
3. Discover `*.sol` files and Rust `*.rs` files that look like Anchor programs
   by containing `#[program]` or `anchor_lang`.
4. Lower each source through the Solidity or Anchor frontend.
5. Add default asset non-negativity obligations for recognized numeric,
   asset-like resources such as `balance`.
6. Run symbolic execution with deterministic initial storage heuristics.
7. Evaluate obligations and collect invariant violations.
8. Minimize each violation into a counterexample.
9. Run escalation analysis for each counterexample.
10. Aggregate all findings into a final `AuditReport`.

## Unified IR schema

The shared `ContractIR` model is chain-neutral. It contains:

- **Resources**: state variables, accounts, balances, storage slots, or other
  mutable assets.
- **Principals**: owners, callers, admins, signers, programs, or other actors.
- **Transitions**: contract functions or program instructions.
- **Guards**: `require` checks, permission checks, signer checks, or account
  constraints after they are lowered by a frontend.
- **Effects**: assignments, increments, decrements, transfers, creates, or
  closes.
- **Obligations**: invariants supplied by a frontend, user, AI candidate
  generator, or the auditor interface.

IR validation is structural. It rejects malformed references, but it does not
classify vulnerabilities.

## Implemented modules

| Module | Current behavior |
| --- | --- |
| `auditor` | Exposes auditor commands, repository discovery, orchestration, explanations, remediations, patch comparison, and report aggregation. |
| `frontends.solidity` | Lowers a small Solidity subset: contract declarations, state variables, functions, `require(...)`, `msg.sender`, simple expressions, and assignment/decrement/increment effects. |
| `frontends.anchor` | Returns a Solana `ContractIR` shell for Anchor/Rust sources; detailed Anchor lowering is not implemented yet. |
| `ir` | Defines dataclasses for resources, principals, transitions, guards, effects, obligations, expressions, and structural validation. |
| `symbolic` | Explores transition paths, applies effects to path-local state, evaluates invariants, and minimizes counterexamples. |
| `solver` | Provides a deterministic conservative solver for simple boolean contradictions and symbol/literal equality, inequality, and range constraints. |
| `escalation` | Converts minimized counterexamples into impact ratings and compact exploit-chain graph data. |
| `reporting` | Builds stable dictionaries and markdown audit reports. |
| `ai` | Defines the candidate-property generation boundary; the default generator returns no obligations. |

## Execution flow for one finding

1. Solidity source such as `VulnerableVault.sol` is lowered into `ContractIR`.
2. The auditor interface adds a default `balance_non_negative` obligation for
   the numeric asset-like `balance` resource.
3. Symbolic execution explores the `drain` transition.
4. The path satisfying `msg.sender != owner` applies `balance = balance - 15`
   to the deterministic initial balance of `10`.
5. The terminal state has `balance = -5`, violating `balance >= 0`.
6. Counterexample minimization reduces the finding to the `drain` trace and the
   `{'balance': -5}` state snapshot.
7. Escalation analysis classifies asset loss as critical.
8. Reporting emits the final auditor-readable finding and remediation.

## Reproducible demo

The demo generator is `scripts/generate_demo_artifacts.py`. It calls
`audit_repository` on the repository root and writes human-readable artifacts to
`artifacts/reproducible_demo`.

The committed demo demonstrates:

```text
User → audit_repository → final report
```

The artifact directory includes original source, lowered IR, explored paths,
solver decisions, invariant violations, minimized counterexample, escalation
analysis, and final audit report.

## Current limitations

- Solidity support is a regular-expression-based subset and is not a full AST
  parser.
- Anchor support is discovery plus a Solana IR shell only.
- The solver is conservative and intentionally returns `unknown` for unsupported
  symbolic shapes.
- The auditor interface's default obligations and initial storage values are
  demo heuristics, not a substitute for user-provided audit invariants.
- AI-generated properties are not integrated into the default audit commands.
- Reports are markdown/dictionary renderings; there is no SARIF, JSON schema, or
  web UI output yet.

## Recommended next steps

1. Replace the Solidity subset parser with a real AST-based frontend.
2. Implement Anchor account, instruction, constraint, and CPI lowering.
3. Add an optional SMT backend behind the existing solver protocol.
4. Allow callers to provide explicit invariants and initial-state assumptions to
   `audit_contract` and `audit_repository`.
5. Add machine-readable report exports in addition to markdown.
