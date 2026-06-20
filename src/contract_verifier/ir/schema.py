"""Unified Intermediate Representation schema.

The IR is chain-neutral: Solidity/EVM and Rust/Anchor/Solana frontends must lower
contract-specific syntax into resources, principals, transitions, guards, effects,
and obligations before any verification starts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

ChainModel = Literal["evm", "solana"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class ExprKind(str, Enum):
    """Small, deterministic expression language used by guards/effects."""

    SYMBOL = "symbol"
    LITERAL = "literal"
    READ = "read"
    CALLER = "caller"
    ACCOUNT = "account"
    NOT = "not"
    AND = "and"
    OR = "or"
    EQ = "eq"
    NEQ = "neq"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"


@dataclass(frozen=True)
class SourceSpan:
    file: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class Expression:
    kind: ExprKind
    value: Any | None = None
    args: tuple["Expression", ...] = ()


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    chain: ChainModel
    source: SourceSpan | None = None


@dataclass(frozen=True)
class Resource:
    id: str
    kind: Literal["state_variable", "account", "balance", "storage_slot"]
    type_name: str
    owner: str | None = None
    mutable: bool = True
    source: SourceSpan | None = None


@dataclass(frozen=True)
class Guard:
    id: str
    predicate: Expression
    description: str
    source: SourceSpan | None = None


@dataclass(frozen=True)
class Effect:
    id: str
    resource_id: str
    operation: Literal["assign", "increment", "decrement", "transfer", "create", "close"]
    value: Expression | None = None
    source: SourceSpan | None = None


@dataclass(frozen=True)
class Obligation:
    id: str
    predicate: Expression
    description: str
    origin: Literal["frontend", "ai_generated", "user"]
    severity_on_failure: Severity = "medium"
    source: SourceSpan | None = None


@dataclass(frozen=True)
class Transition:
    id: str
    name: str
    chain: ChainModel
    inputs: tuple[Resource, ...] = ()
    guards: tuple[Guard, ...] = ()
    effects: tuple[Effect, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    source: SourceSpan | None = None


@dataclass(frozen=True)
class ContractIR:
    id: str
    chain: ChainModel
    resources: tuple[Resource, ...] = ()
    principals: tuple[Principal, ...] = ()
    transitions: tuple[Transition, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        """Reject malformed IR before symbolic execution.

        This is intentionally structural only. Security conclusions must be made
        by the symbolic executor and solver layers, not by schema validation.
        """
        resource_ids = {resource.id for resource in self.resources}
        for transition in self.transitions:
            for effect in transition.effects:
                if effect.resource_id not in resource_ids:
                    raise ValueError(
                        f"Transition {transition.id} effect {effect.id} references "
                        f"unknown resource {effect.resource_id}"
                    )
