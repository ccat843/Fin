"""Unified execution context and symbolic state model.

This module contains deterministic execution data structures only. It does not
call AI services and does not decide whether a security property is correct.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal

from contract_verifier.ir.schema import ChainModel, Expression

BranchValue = Literal["true", "false", "unknown"]


@dataclass(frozen=True)
class ExecutionContext:
    """Chain-neutral transaction/instruction context.

    EVM callers and Solana signers/authorities are represented through the same
    principal fields so guard evaluation can be shared across chains.
    """

    chain: ChainModel
    caller: str
    program_id: str | None = None
    signers: frozenset[str] = frozenset()
    accounts: dict[str, object] = field(default_factory=dict)
    inputs: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionState:
    """A single symbolic execution path with isolated mutable contract state."""

    context: ExecutionContext
    storage: dict[str, object]
    transition_ids: tuple[str, ...] = ()
    constraints: tuple[Expression, ...] = ()
    effects_applied: tuple[str, ...] = ()
    invariant_violations: tuple[str, ...] = ()
    branch_history: tuple[str, ...] = ()
    reverted: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def path_conditions(self) -> tuple[Expression, ...]:
        return self.constraints

    def clone(self, **changes: object) -> "ExecutionState":
        base_changes = {
            "storage": dict(self.storage),
            "metadata": dict(self.metadata),
        }
        base_changes.update(changes)
        return replace(self, **base_changes)

    def with_constraint(self, constraint: Expression, branch_label: str) -> "ExecutionState":
        return self.clone(
            constraints=(*self.constraints, constraint),
            branch_history=(*self.branch_history, branch_label),
        )

    def with_effect(self, effect_id: str, resource_id: str, value: object) -> "ExecutionState":
        next_storage = dict(self.storage)
        next_storage[resource_id] = value
        return self.clone(
            storage=next_storage,
            effects_applied=(*self.effects_applied, effect_id),
        )

    def with_invariant_violations(self, obligation_ids: tuple[str, ...]) -> "ExecutionState":
        return self.clone(invariant_violations=(*self.invariant_violations, *obligation_ids))
