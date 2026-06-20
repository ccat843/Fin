# AI Security & Formal Verification Skill Design

## Unified IR schema

The IR is the only input accepted by verification modules. Solidity and
Rust/Anchor frontends must lower source code into the same contract model:

- **Resources**: EVM state variables, balances, storage slots, Solana accounts,
  token accounts, PDA-owned data, and lamports.
- **Principals**: callers, owners, admins, programs, signers, authorities, and
  external contracts/programs.
- **Transitions**: Solidity functions or Anchor instructions.
- **Guards**: permission checks, signer checks, ownership checks, require/assert
  predicates, Anchor constraints, and account relationship checks.
- **Effects**: writes, arithmetic updates, transfers, account create/close
  operations, and cross-contract/program-visible mutations.
- **Obligations**: invariants from source assertions, user input, frontend rules,
  and AI-generated candidate properties.

Expressions are deliberately small and deterministic so symbolic execution and
constraint solving can own every correctness decision.

## Module architecture

1. `frontends`: parse Solidity and Rust/Anchor, classify semantics, and lower to
   IR. Frontends may use AI for semantic classification, but not verification.
2. `ir`: defines schemas and structural validation. Validation rejects malformed
   references only; it does not classify vulnerabilities.
3. `ai`: proposes candidate obligations from IR and source context. These are
   untrusted until solver-backed verification succeeds or fails.
4. `symbolic`: explores feasible transition paths with symbolic inputs, state,
   principals, and resources. It records path constraints and effects.
5. `solver`: checks path feasibility, obligation violations, and counterexample
   models with an SMT/constraint backend.
6. `escalation`: starts from confirmed findings and recursively explores feasible
   dependent paths to test privilege escalation, guard bypass, global-state
   impact, and transition unlocking.
7. `reporting`: emits structured audit reports with executive summary, threat
   model, invariants, PASS/FAIL properties, counterexamples, escalation chains,
   and remediation suggestions.

Each module has an interface boundary so parser, solver, LLM provider, symbolic
execution strategy, or report renderer can be replaced independently.

## Execution flow

1. Select frontend by source type: Solidity maps to the EVM model; Rust/Anchor
   maps to the Solana model.
2. Parse and lower source code into `ContractIR`.
3. Validate IR structure.
4. Generate candidate obligations through the AI property generator only after IR
   exists.
5. Merge obligations from frontend, user, and AI sources.
6. Symbolically execute transitions, collecting constraints for each path.
7. Ask the solver whether each path is feasible.
8. For feasible paths, check whether obligations can be violated.
9. For every failed property, emit a concrete counterexample model. For every
   rejected path or property violation attempt, emit an infeasibility proof note.
10. Run escalation analysis on confirmed low/medium findings using only symbolic
    execution and solver results.
11. Generate a structured report.

## Current scaffold status

Implemented now:

- Python package layout for all mandatory modules.
- Unified IR dataclasses and structural validation.
- Frontend interfaces plus placeholder Solidity and Anchor frontends.
- Symbolic execution, solver, AI property, escalation, and report boundaries.
- Smoke tests for IR validation, frontend dispatch shape, symbolic path shape,
  and structured report shape.

Missing by design in this iteration:

- Real Solidity AST parsing.
- Real Rust/Anchor AST parsing.
- SMT backend integration.
- Full symbolic state model.
- AI provider integration for invariant proposals.
- Feasible escalation recursion.
- Full counterexample-producing audit runs.

Next recommended step: implement minimal real parser lowering for one Solidity
contract and one Anchor instruction, then add solver-backed tests for a simple
access-control counterexample.
