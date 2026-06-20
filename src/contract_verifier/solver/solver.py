"""Deterministic constraint solver boundary and baseline implementation.

Production implementations may use SMT backends, but must return deterministic
results containing either a model/counterexample or an infeasibility proof note.
The bundled solver is intentionally small: it is a conservative, reproducible
feasibility checker for the IR expression subset used by the symbolic executor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from contract_verifier.ir.schema import ExprKind, Expression


@dataclass(frozen=True)
class SolverResult:
    status: Literal["sat", "unsat", "unknown"]
    model: dict[str, object] = field(default_factory=dict)
    proof: str | None = None


class ConstraintSolver(Protocol):
    def check(self, constraints: tuple[Expression, ...]) -> SolverResult:
        """Return whether a conjunction of path constraints is feasible."""


@dataclass
class _SymbolBounds:
    lower: int | None = None
    lower_inclusive: bool = True
    upper: int | None = None
    upper_inclusive: bool = True
    equal: object | None = None
    not_equal: set[object] = field(default_factory=set)


class SimpleConstraintSolver:
    """Conservative deterministic solver for simple symbolic path conditions.

    It proves UNSAT for direct boolean contradictions and simple symbol-vs-literal
    equality/inequality/range conflicts, including simple affine forms such as
    ``amount + 1 <= 10`` when only one side is symbolic. Anything outside
    that subset returns UNKNOWN unless a concrete falsehood is present; this keeps
    execution conservative and reproducible without pretending to be a full SMT
    solver.
    """

    def check(self, constraints: tuple[Expression, ...]) -> SolverResult:
        seen: set[str] = set()
        negated: set[str] = set()
        bounds: dict[str, _SymbolBounds] = {}
        unsupported_constraints: list[Expression] = []

        for constraint in constraints:
            concrete = self._eval_concrete(constraint)
            if concrete is False:
                return SolverResult(status="unsat", proof="path contains concrete false constraint")
            if concrete is True:
                continue

            if constraint.kind == ExprKind.NOT and len(constraint.args) == 1:
                inner = constraint.args[0]
                inner_key = repr(inner)
                if inner_key in seen:
                    return SolverResult(status="unsat", proof="path contains p and not(p)")
                negated.add(inner_key)
                unsat_proof = self._record_negated_constraint(inner, bounds)
                if unsat_proof is None and self._parse_symbol_literal_comparison(inner) is None:
                    unsupported_constraints.append(constraint)
            else:
                constraint_key = repr(constraint)
                if constraint_key in negated:
                    return SolverResult(status="unsat", proof="path contains p and not(p)")
                seen.add(constraint_key)
                unsat_proof = self._record_positive_constraint(constraint, bounds)
                if unsat_proof is None and self._parse_symbol_literal_comparison(constraint) is None:
                    unsupported_constraints.append(constraint)

            if unsat_proof is not None:
                return SolverResult(status="unsat", proof=unsat_proof)

        if unsupported_constraints:
            return SolverResult(
                status="unknown",
                model=self._model_from_bounds(bounds),
                proof="unsupported symbolic constraint shape",
            )
        return SolverResult(status="sat", model=self._model_from_bounds(bounds))

    def _record_positive_constraint(
        self, expr: Expression, bounds: dict[str, _SymbolBounds]
    ) -> str | None:
        parsed = self._parse_symbol_literal_comparison(expr)
        if parsed is None:
            return None
        symbol, operator, literal = parsed
        return self._apply_bound(bounds.setdefault(symbol, _SymbolBounds()), operator, literal)

    def _record_negated_constraint(
        self, expr: Expression, bounds: dict[str, _SymbolBounds]
    ) -> str | None:
        parsed = self._parse_symbol_literal_comparison(expr)
        if parsed is None:
            return None
        symbol, operator, literal = parsed
        inverse = {
            ExprKind.EQ: ExprKind.NEQ,
            ExprKind.NEQ: ExprKind.EQ,
            ExprKind.GT: ExprKind.LTE,
            ExprKind.GTE: ExprKind.LT,
            ExprKind.LT: ExprKind.GTE,
            ExprKind.LTE: ExprKind.GT,
        }[operator]
        return self._apply_bound(bounds.setdefault(symbol, _SymbolBounds()), inverse, literal)

    def _apply_bound(self, bound: _SymbolBounds, operator: ExprKind, literal: object) -> str | None:
        if operator == ExprKind.EQ:
            if bound.equal is not None and bound.equal != literal:
                return "symbol has conflicting equality constraints"
            if literal in bound.not_equal:
                return "symbol equality conflicts with not-equal constraint"
            bound.equal = literal
        elif operator == ExprKind.NEQ:
            if bound.equal == literal:
                return "symbol not-equal conflicts with equality constraint"
            bound.not_equal.add(literal)
        elif isinstance(literal, int):
            if operator == ExprKind.GT:
                self._tighten_lower(bound, literal, inclusive=False)
            elif operator == ExprKind.GTE:
                self._tighten_lower(bound, literal, inclusive=True)
            elif operator == ExprKind.LT:
                self._tighten_upper(bound, literal, inclusive=False)
            elif operator == ExprKind.LTE:
                self._tighten_upper(bound, literal, inclusive=True)
        return self._bound_conflict(bound)

    def _tighten_lower(self, bound: _SymbolBounds, value: int, *, inclusive: bool) -> None:
        if bound.lower is None or value > bound.lower:
            bound.lower = value
            bound.lower_inclusive = inclusive
        elif value == bound.lower:
            bound.lower_inclusive = bound.lower_inclusive and inclusive

    def _tighten_upper(self, bound: _SymbolBounds, value: int, *, inclusive: bool) -> None:
        if bound.upper is None or value < bound.upper:
            bound.upper = value
            bound.upper_inclusive = inclusive
        elif value == bound.upper:
            bound.upper_inclusive = bound.upper_inclusive and inclusive

    def _bound_conflict(self, bound: _SymbolBounds) -> str | None:
        if isinstance(bound.equal, int):
            if bound.lower is not None:
                if bound.equal < bound.lower or (bound.equal == bound.lower and not bound.lower_inclusive):
                    return "symbol equality is below lower bound"
            if bound.upper is not None:
                if bound.equal > bound.upper or (bound.equal == bound.upper and not bound.upper_inclusive):
                    return "symbol equality is above upper bound"
        if bound.lower is not None and bound.upper is not None:
            if bound.lower > bound.upper:
                return "symbol lower bound exceeds upper bound"
            if bound.lower == bound.upper and (not bound.lower_inclusive or not bound.upper_inclusive):
                return "symbol bounds exclude the only possible value"
        return None

    def _parse_symbol_literal_comparison(
        self, expr: Expression
    ) -> tuple[str, ExprKind, object] | None:
        if expr.kind not in {ExprKind.EQ, ExprKind.NEQ, ExprKind.LT, ExprKind.LTE, ExprKind.GT, ExprKind.GTE}:
            return None
        left, right = expr.args
        left_affine = self._parse_affine_symbol(left)
        right_affine = self._parse_affine_symbol(right)
        if left_affine is not None and right.kind == ExprKind.LITERAL:
            symbol, offset = left_affine
            literal = self._subtract_numeric(right.value, offset)
            if literal is not None:
                return symbol, expr.kind, literal
        if right_affine is not None and left.kind == ExprKind.LITERAL:
            flipped = {
                ExprKind.EQ: ExprKind.EQ,
                ExprKind.NEQ: ExprKind.NEQ,
                ExprKind.LT: ExprKind.GT,
                ExprKind.LTE: ExprKind.GTE,
                ExprKind.GT: ExprKind.LT,
                ExprKind.GTE: ExprKind.LTE,
            }[expr.kind]
            symbol, offset = right_affine
            literal = self._subtract_numeric(left.value, offset)
            if literal is not None:
                return symbol, flipped, literal
        return None

    def _parse_affine_symbol(self, expr: Expression) -> tuple[str, int] | None:
        if expr.kind == ExprKind.SYMBOL:
            return str(expr.value), 0
        if expr.kind not in {ExprKind.ADD, ExprKind.SUB} or len(expr.args) != 2:
            return None
        left, right = expr.args
        left_affine = self._parse_affine_symbol(left)
        right_affine = self._parse_affine_symbol(right)
        if left_affine is not None and right.kind == ExprKind.LITERAL and isinstance(right.value, int):
            symbol, offset = left_affine
            if expr.kind == ExprKind.ADD:
                return symbol, offset + right.value
            return symbol, offset - right.value
        if expr.kind == ExprKind.ADD and left.kind == ExprKind.LITERAL and isinstance(left.value, int):
            if right_affine is None:
                return None
            symbol, offset = right_affine
            return symbol, offset + left.value
        return None

    def _subtract_numeric(self, value: object, offset: int) -> object | None:
        if isinstance(value, int):
            return value - offset
        if offset == 0:
            return value
        return None

    def _eval_concrete(self, expr: Expression) -> bool | None:
        if expr.kind == ExprKind.LITERAL and isinstance(expr.value, bool):
            return expr.value
        if expr.kind == ExprKind.NOT and len(expr.args) == 1:
            inner = self._eval_concrete(expr.args[0])
            if inner is not None:
                return not inner
        if len(expr.args) != 2:
            return None
        left, right = expr.args
        if left.kind != ExprKind.LITERAL or right.kind != ExprKind.LITERAL:
            return None
        if expr.kind == ExprKind.EQ:
            return left.value == right.value
        if expr.kind == ExprKind.NEQ:
            return left.value != right.value
        if expr.kind == ExprKind.LT:
            return left.value < right.value
        if expr.kind == ExprKind.LTE:
            return left.value <= right.value
        if expr.kind == ExprKind.GT:
            return left.value > right.value
        if expr.kind == ExprKind.GTE:
            return left.value >= right.value
        return None

    def _model_from_bounds(self, bounds: dict[str, _SymbolBounds]) -> dict[str, object]:
        model: dict[str, object] = {}
        for symbol in sorted(bounds):
            bound = bounds[symbol]
            if bound.equal is not None:
                model[symbol] = bound.equal
            elif bound.lower is not None:
                model[symbol] = bound.lower if bound.lower_inclusive else bound.lower + 1
            elif bound.upper is not None:
                model[symbol] = bound.upper if bound.upper_inclusive else bound.upper - 1
        return model
