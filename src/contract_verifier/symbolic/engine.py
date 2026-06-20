"""Deterministic symbolic execution engine.

The executor evaluates IR guards, forks execution states for symbolic/unknown
branches, and applies IR effects to cloned path-local state. It never uses an LLM
for execution or correctness decisions.
"""

from __future__ import annotations

from dataclasses import dataclass

from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Guard, Obligation, Transition
from contract_verifier.solver.solver import ConstraintSolver, SimpleConstraintSolver, SolverResult
from contract_verifier.symbolic.context import BranchValue, ExecutionContext, ExecutionState
from contract_verifier.symbolic.invariants import InvariantEvaluator, InvariantViolation


@dataclass(frozen=True)
class PathState:
    """Backward-compatible view of an execution state."""

    transition_ids: tuple[str, ...]
    constraints: tuple[Expression, ...]
    effects_applied: tuple[str, ...] = ()
    invariant_violations: tuple[str, ...] = ()
    storage: dict[str, object] | None = None
    branch_history: tuple[str, ...] = ()
    reverted: bool = False
    metadata: dict[str, str] | None = None

    @classmethod
    def from_execution_state(cls, state: ExecutionState) -> "PathState":
        return cls(
            transition_ids=state.transition_ids,
            constraints=state.constraints,
            effects_applied=state.effects_applied,
            invariant_violations=state.invariant_violations,
            storage=dict(state.storage),
            branch_history=state.branch_history,
            reverted=state.reverted,
            metadata=dict(state.metadata),
        )


class SymbolicExecutionEngine:
    def __init__(self, solver: ConstraintSolver | None = None) -> None:
        self.solver = solver or SimpleConstraintSolver()
        self.invariant_evaluator = InvariantEvaluator(self.solver, self._eval_expr)

    def explore(
        self,
        ir: ContractIR,
        context: ExecutionContext | None = None,
        initial_storage: dict[str, object] | None = None,
    ) -> tuple[ExecutionState, ...]:
        ir.validate()
        base_context = context or ExecutionContext(chain=ir.chain, caller="caller")
        base_storage = {
            resource.id: self._initial_value(resource.id, initial_storage)
            for resource in ir.resources
        }
        states: list[ExecutionState] = []
        for transition in ir.transitions:
            entry_state = ExecutionState(
                context=base_context,
                storage=dict(base_storage),
                transition_ids=(transition.id,),
            )
            states.extend(self.execute_transition(transition, entry_state, ir.obligations))
        return tuple(states)

    def explore_paths(
        self,
        ir: ContractIR,
        context: ExecutionContext | None = None,
        initial_storage: dict[str, object] | None = None,
    ) -> tuple[PathState, ...]:
        return tuple(
            PathState.from_execution_state(state)
            for state in self.explore(ir, context=context, initial_storage=initial_storage)
        )

    def execute_transition(
        self,
        transition: Transition,
        initial_state: ExecutionState,
        obligations: tuple[Obligation, ...] = (),
    ) -> tuple[ExecutionState, ...]:
        feasible_initial = self._filter_feasible(initial_state)
        if feasible_initial is None:
            return ()
        active_states = (feasible_initial,)
        terminal_states: list[ExecutionState] = []

        for guard in transition.guards:
            next_active: list[ExecutionState] = []
            for state in active_states:
                true_state, false_state = self._branch_guard(state, guard)
                if true_state is not None:
                    feasible_true = self._filter_feasible(true_state)
                    if feasible_true is not None:
                        next_active.append(feasible_true)
                if false_state is not None:
                    feasible_false = self._filter_feasible(false_state)
                    if feasible_false is not None:
                        terminal_states.append(self._check_obligations(feasible_false, obligations))
            active_states = tuple(next_active)

        for state in active_states:
            mutated_state = self._apply_effects(state, transition.effects)
            terminal_states.append(self._check_obligations(mutated_state, obligations))

        return tuple(terminal_states)

    def evaluate_obligations(
        self, ir: ContractIR, states: tuple[ExecutionState, ...]
    ) -> tuple[InvariantViolation, ...]:
        violations: list[InvariantViolation] = []
        for state in states:
            violations.extend(self.invariant_evaluator.violations_for_state(state, ir.obligations))
        return tuple(violations)

    def _check_obligations(
        self, state: ExecutionState, obligations: tuple[Obligation, ...]
    ) -> ExecutionState:
        if not obligations:
            return state
        violations = self.invariant_evaluator.violations_for_state(state, obligations)
        if not violations:
            return state
        metadata = dict(state.metadata)
        metadata["invariant_status"] = "violated"
        metadata["invariant_violations"] = ",".join(violation.obligation_id for violation in violations)
        return state.clone(metadata=metadata).with_invariant_violations(
            tuple(violation.obligation_id for violation in violations)
        )

    def _filter_feasible(self, state: ExecutionState) -> ExecutionState | None:
        result = self.solver.check(state.path_conditions)
        if result.status == "unsat":
            return None
        return self._record_solver_result(state, result)

    def _record_solver_result(self, state: ExecutionState, result: SolverResult) -> ExecutionState:
        metadata = dict(state.metadata)
        metadata["solver_status"] = result.status
        if result.proof is not None:
            metadata["solver_proof"] = result.proof
        return state.clone(metadata=metadata)

    def _branch_guard(
        self, state: ExecutionState, guard: Guard
    ) -> tuple[ExecutionState | None, ExecutionState | None]:
        result = self._truth_value(self._eval_expr(guard.predicate, state))
        true_constraint = guard.predicate
        false_constraint = Expression(kind=ExprKind.NOT, args=(guard.predicate,))

        if result == "true":
            return state.with_constraint(true_constraint, f"{guard.id}:true"), None
        if result == "false":
            return None, state.with_constraint(false_constraint, f"{guard.id}:false").clone(reverted=True)
        return (
            state.with_constraint(true_constraint, f"{guard.id}:true"),
            state.with_constraint(false_constraint, f"{guard.id}:false").clone(reverted=True),
        )

    def _apply_effects(self, state: ExecutionState, effects: tuple[Effect, ...]) -> ExecutionState:
        next_state = state
        for effect in effects:
            current = next_state.storage.get(effect.resource_id)
            value = self._effect_value(effect, current, next_state)
            next_state = next_state.with_effect(effect.id, effect.resource_id, value)
        return next_state

    def _effect_value(self, effect: Effect, current: object, state: ExecutionState) -> object:
        value = self._eval_expr(effect.value, state) if effect.value is not None else None
        if effect.operation == "assign":
            return value
        if effect.operation == "increment":
            return self._eval_expr(
                Expression(
                    kind=ExprKind.ADD,
                    args=(self._as_expr(current), self._as_expr(value)),
                ),
                state,
            )
        if effect.operation == "decrement":
            return self._eval_expr(
                Expression(
                    kind=ExprKind.SUB,
                    args=(self._as_expr(current), self._as_expr(value)),
                ),
                state,
            )
        if effect.operation == "transfer":
            return {"from": effect.resource_id, "to": value, "previous": current}
        if effect.operation == "create":
            return value if value is not None else {"created": True}
        if effect.operation == "close":
            return None
        raise ValueError(f"Unsupported effect operation {effect.operation}")

    def _eval_expr(self, expr: Expression | None, state: ExecutionState) -> object:
        if expr is None:
            return None
        if expr.kind == ExprKind.LITERAL:
            return expr.value
        if expr.kind == ExprKind.SYMBOL:
            return state.context.inputs.get(str(expr.value), expr)
        if expr.kind == ExprKind.READ:
            return state.storage.get(str(expr.value), expr)
        if expr.kind == ExprKind.CALLER:
            return state.context.caller
        if expr.kind == ExprKind.ACCOUNT:
            return state.context.accounts.get(str(expr.value), expr)
        if expr.kind == ExprKind.NOT:
            value = self._eval_expr(expr.args[0], state)
            truth = self._truth_value(value)
            if truth == "true":
                return False
            if truth == "false":
                return True
            return Expression(kind=ExprKind.NOT, args=(self._as_expr(value),))
        if expr.kind in {ExprKind.AND, ExprKind.OR}:
            return self._eval_boolean_op(expr, state)
        if expr.kind in {ExprKind.EQ, ExprKind.NEQ, ExprKind.LT, ExprKind.LTE, ExprKind.GT, ExprKind.GTE}:
            return self._eval_comparison(expr, state)
        if expr.kind in {ExprKind.ADD, ExprKind.SUB, ExprKind.MUL, ExprKind.DIV}:
            return self._eval_arithmetic(expr, state)
        raise ValueError(f"Unsupported expression kind {expr.kind}")

    def _eval_boolean_op(self, expr: Expression, state: ExecutionState) -> object:
        left = self._eval_expr(expr.args[0], state)
        right = self._eval_expr(expr.args[1], state)
        left_truth = self._truth_value(left)
        right_truth = self._truth_value(right)
        if expr.kind == ExprKind.AND:
            if left_truth == "false" or right_truth == "false":
                return False
            if left_truth == "true" and right_truth == "true":
                return True
        if expr.kind == ExprKind.OR:
            if left_truth == "true" or right_truth == "true":
                return True
            if left_truth == "false" and right_truth == "false":
                return False
        return Expression(kind=expr.kind, args=(self._as_expr(left), self._as_expr(right)))

    def _eval_comparison(self, expr: Expression, state: ExecutionState) -> object:
        left = self._eval_expr(expr.args[0], state)
        right = self._eval_expr(expr.args[1], state)
        if self._is_concrete(left) and self._is_concrete(right):
            if expr.kind == ExprKind.EQ:
                return left == right
            if expr.kind == ExprKind.NEQ:
                return left != right
            if expr.kind == ExprKind.LT:
                return left < right
            if expr.kind == ExprKind.LTE:
                return left <= right
            if expr.kind == ExprKind.GT:
                return left > right
            if expr.kind == ExprKind.GTE:
                return left >= right
        return Expression(kind=expr.kind, args=(self._as_expr(left), self._as_expr(right)))

    def _eval_arithmetic(self, expr: Expression, state: ExecutionState) -> object:
        left = self._eval_expr(expr.args[0], state)
        right = self._eval_expr(expr.args[1], state)
        if isinstance(left, int) and isinstance(right, int):
            if expr.kind == ExprKind.ADD:
                return left + right
            if expr.kind == ExprKind.SUB:
                return left - right
            if expr.kind == ExprKind.MUL:
                return left * right
            if expr.kind == ExprKind.DIV:
                if right == 0:
                    return Expression(kind=expr.kind, args=(self._as_expr(left), self._as_expr(right)))
                return left // right
        return Expression(kind=expr.kind, args=(self._as_expr(left), self._as_expr(right)))

    def _truth_value(self, value: object) -> BranchValue:
        if value is True:
            return "true"
        if value is False:
            return "false"
        return "unknown"

    def _as_expr(self, value: object) -> Expression:
        if isinstance(value, Expression):
            return value
        return Expression(kind=ExprKind.LITERAL, value=value)

    def _is_concrete(self, value: object) -> bool:
        return not isinstance(value, Expression)

    def _initial_value(self, resource_id: str, initial_storage: dict[str, object] | None) -> object:
        if initial_storage and resource_id in initial_storage:
            return initial_storage[resource_id]
        return Expression(kind=ExprKind.SYMBOL, value=f"state.{resource_id}")
