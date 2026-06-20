"""Counterexample minimization and trace reduction.

This module is intentionally separate from symbolic execution and invariant
detection. It transforms raw invariant violations into compact, deterministic
counterexample artifacts without changing how paths are explored or detected.
"""

from __future__ import annotations

from dataclasses import dataclass

from contract_verifier.ir.schema import ExprKind, Expression
from contract_verifier.solver.solver import ConstraintSolver, SimpleConstraintSolver, SolverResult
from contract_verifier.symbolic.invariants import InvariantViolation


@dataclass(frozen=True)
class MinimizedCounterexample:
    obligation_id: str
    attack_trace: tuple[str, ...]
    input_constraints: tuple[Expression, ...]
    state_snapshot: dict[str, object]
    solver_result: SolverResult


class CounterexampleMinimizer:
    """Produces exploit-ready counterexamples from raw invariant violations."""

    def __init__(self, solver: ConstraintSolver | None = None) -> None:
        self.solver = solver or SimpleConstraintSolver()

    def minimize(self, violation: InvariantViolation) -> MinimizedCounterexample:
        state = violation.counterexample
        violating_predicate = self._substitute_state_reads(violation.predicate, state.storage)
        violation_condition = Expression(kind=ExprKind.NOT, args=(violating_predicate,))
        minimized_constraints = self._minimize_constraints(
            state.path_conditions,
            violation_condition,
        )
        solver_result = self.solver.check((*minimized_constraints, violation_condition))
        return MinimizedCounterexample(
            obligation_id=violation.obligation_id,
            attack_trace=self._minimize_trace(state.transition_ids),
            input_constraints=minimized_constraints,
            state_snapshot=self._state_snapshot(violation.predicate, state.storage),
            solver_result=solver_result,
        )

    def _minimize_constraints(
        self,
        constraints: tuple[Expression, ...],
        violation_condition: Expression,
    ) -> tuple[Expression, ...]:
        minimized = list(constraints)
        index = 0
        while index < len(minimized):
            candidate = tuple(minimized[:index] + minimized[index + 1 :])
            result = self.solver.check((*candidate, violation_condition))
            if result.status == "sat":
                minimized = list(candidate)
            else:
                index += 1
        return tuple(minimized)

    def _minimize_trace(self, transition_ids: tuple[str, ...]) -> tuple[str, ...]:
        minimized: list[str] = []
        for transition_id in transition_ids:
            if transition_id not in minimized:
                minimized.append(transition_id)
        return tuple(minimized)

    def _state_snapshot(self, predicate: Expression, storage: dict[str, object]) -> dict[str, object]:
        resource_ids = self._read_resource_ids(predicate)
        return {resource_id: storage[resource_id] for resource_id in sorted(resource_ids) if resource_id in storage}

    def _substitute_state_reads(self, expr: Expression, storage: dict[str, object]) -> Expression:
        if expr.kind == ExprKind.READ and str(expr.value) in storage:
            return Expression(kind=ExprKind.LITERAL, value=storage[str(expr.value)])
        if not expr.args:
            return expr
        return Expression(
            kind=expr.kind,
            value=expr.value,
            args=tuple(self._substitute_state_reads(arg, storage) for arg in expr.args),
        )

    def _read_resource_ids(self, expr: Expression) -> set[str]:
        resource_ids: set[str] = set()
        if expr.kind == ExprKind.READ:
            resource_ids.add(str(expr.value))
        for arg in expr.args:
            resource_ids.update(self._read_resource_ids(arg))
        return resource_ids
