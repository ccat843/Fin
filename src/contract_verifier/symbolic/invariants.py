"""Deterministic invariant evaluation for terminal execution states."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

from contract_verifier.ir.schema import ExprKind, Expression, Obligation
from contract_verifier.solver.solver import ConstraintSolver, SolverResult
from contract_verifier.symbolic.context import ExecutionState

EvaluationStatus = Literal["violated", "satisfied", "unknown"]
ExpressionEvaluator = Callable[[Expression, ExecutionState], object]


@dataclass(frozen=True)
class InvariantViolation:
    obligation_id: str
    obligation_description: str
    predicate: Expression
    counterexample: ExecutionState
    solver_result: SolverResult
    detection: Literal["immediate", "solver"]


@dataclass(frozen=True)
class InvariantEvaluation:
    obligation_id: str
    status: EvaluationStatus
    solver_result: SolverResult | None = None
    violation: InvariantViolation | None = None


class InvariantEvaluator:
    """Evaluates IR obligations against execution states without AI assistance."""

    def __init__(self, solver: ConstraintSolver, evaluate_expression: ExpressionEvaluator) -> None:
        self.solver = solver
        self.evaluate_expression = evaluate_expression

    def evaluate_state(
        self, state: ExecutionState, obligations: tuple[Obligation, ...]
    ) -> tuple[InvariantEvaluation, ...]:
        return tuple(self._evaluate_obligation(state, obligation) for obligation in obligations)

    def violations_for_state(
        self, state: ExecutionState, obligations: tuple[Obligation, ...]
    ) -> tuple[InvariantViolation, ...]:
        return tuple(
            evaluation.violation
            for evaluation in self.evaluate_state(state, obligations)
            if evaluation.violation is not None
        )

    def _evaluate_obligation(self, state: ExecutionState, obligation: Obligation) -> InvariantEvaluation:
        evaluated_predicate = self.evaluate_expression(obligation.predicate, state)
        if evaluated_predicate is False:
            solver_result = SolverResult(
                status="sat",
                model=dict(state.metadata),
                proof="obligation evaluated to false in concrete execution state",
            )
            violation = self._violation(state, obligation, solver_result, detection="immediate")
            return InvariantEvaluation(
                obligation_id=obligation.id,
                status="violated",
                solver_result=solver_result,
                violation=violation,
            )
        if evaluated_predicate is True:
            return InvariantEvaluation(obligation_id=obligation.id, status="satisfied")

        violation_condition = Expression(
            kind=ExprKind.NOT,
            args=(self._as_expression(evaluated_predicate),),
        )
        solver_result = self.solver.check((*state.path_conditions, violation_condition))
        if solver_result.status == "sat":
            violation = self._violation(state, obligation, solver_result, detection="solver")
            return InvariantEvaluation(
                obligation_id=obligation.id,
                status="violated",
                solver_result=solver_result,
                violation=violation,
            )
        if solver_result.status == "unsat":
            return InvariantEvaluation(
                obligation_id=obligation.id,
                status="satisfied",
                solver_result=solver_result,
            )
        return InvariantEvaluation(
            obligation_id=obligation.id,
            status="unknown",
            solver_result=solver_result,
        )

    def _violation(
        self,
        state: ExecutionState,
        obligation: Obligation,
        solver_result: SolverResult,
        *,
        detection: Literal["immediate", "solver"],
    ) -> InvariantViolation:
        return InvariantViolation(
            obligation_id=obligation.id,
            obligation_description=obligation.description,
            predicate=obligation.predicate,
            counterexample=state,
            solver_result=solver_result,
            detection=detection,
        )

    def _as_expression(self, value: object) -> Expression:
        if isinstance(value, Expression):
            return value
        return Expression(kind=ExprKind.LITERAL, value=value)
