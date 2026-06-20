"""Deterministic exploit escalation analysis.

The escalation engine consumes minimized counterexamples and builds a compact
exploit-chain graph. It may re-run symbolic execution when a ContractIR is
provided, but it does not modify symbolic execution, invariant evaluation, the
solver, reporting, or AI modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from contract_verifier.ir.schema import ChainModel, ContractIR, Expression, Severity
from contract_verifier.solver.solver import ConstraintSolver, SimpleConstraintSolver, SolverResult
from contract_verifier.symbolic.context import ExecutionContext
from contract_verifier.symbolic.counterexamples import MinimizedCounterexample
from contract_verifier.symbolic.engine import SymbolicExecutionEngine

SEVERITY_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class EscalationChain:
    initial_finding_id: str
    final_severity: Severity
    feasible_steps: tuple[str, ...]
    stop_reason: str


@dataclass(frozen=True)
class EscalationVariant:
    id: str
    caller: str
    accounts: dict[str, object] = field(default_factory=dict)
    preconditions: tuple[Expression, ...] = ()
    solver_result: SolverResult | None = None
    feasible: bool = False


@dataclass(frozen=True)
class ExploitGraphNode:
    id: str
    label: str
    state_snapshot: dict[str, object]
    severity: Severity
    feasible: bool


@dataclass(frozen=True)
class ExploitGraphEdge:
    source: str
    target: str
    transition: str
    severity_before: Severity
    severity_after: Severity
    feasible: bool


@dataclass(frozen=True)
class ExploitChainGraph:
    nodes: tuple[ExploitGraphNode, ...]
    edges: tuple[ExploitGraphEdge, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "nodes": [
                {
                    "id": node.id,
                    "label": node.label,
                    "severity": node.severity,
                    "feasible": node.feasible,
                    "state_snapshot": dict(sorted(node.state_snapshot.items())),
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "transition": edge.transition,
                    "severity_before": edge.severity_before,
                    "severity_after": edge.severity_after,
                    "feasible": edge.feasible,
                }
                for edge in self.edges
            ],
        }


@dataclass(frozen=True)
class EscalationResult:
    counterexample: MinimizedCounterexample
    escalation_graph: ExploitChainGraph
    max_severity: Severity
    max_severity_path: tuple[str, ...]
    variants: tuple[EscalationVariant, ...]
    impact: dict[str, Severity]
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "obligation_id": self.counterexample.obligation_id,
            "max_severity": self.max_severity,
            "max_severity_path": list(self.max_severity_path),
            "impact": dict(sorted(self.impact.items())),
            "variants": [
                {
                    "id": variant.id,
                    "caller": variant.caller,
                    "feasible": variant.feasible,
                    "solver_status": variant.solver_result.status if variant.solver_result else None,
                    "solver_proof": variant.solver_result.proof if variant.solver_result else None,
                    "accounts": dict(sorted(variant.accounts.items())),
                }
                for variant in sorted(self.variants, key=lambda item: item.id)
            ],
            "graph": self.escalation_graph.to_dict(),
            "explanation": self.explanation,
        }


class EscalationEngine:
    """Analyzes whether an isolated counterexample can escalate impact."""

    def __init__(
        self,
        *,
        ir: ContractIR | None = None,
        solver: ConstraintSolver | None = None,
        symbolic_engine: SymbolicExecutionEngine | None = None,
    ) -> None:
        self.ir = ir
        self.solver = solver or SimpleConstraintSolver()
        self.symbolic_engine = symbolic_engine or SymbolicExecutionEngine(solver=self.solver)

    def analyze(self, counterexample: MinimizedCounterexample) -> EscalationResult:
        impact = self._impact(counterexample)
        variants = self._evaluate_variants(counterexample)
        graph = self._build_graph(counterexample, impact, variants)
        max_severity = self._max_severity((*impact.values(), *(node.severity for node in graph.nodes)))
        max_path = self._max_path(graph, max_severity)
        return EscalationResult(
            counterexample=counterexample,
            escalation_graph=graph,
            max_severity=max_severity,
            max_severity_path=max_path,
            variants=variants,
            impact=impact,
            explanation=self._explanation(counterexample, variants, max_severity),
        )

    def _impact(self, counterexample: MinimizedCounterexample) -> dict[str, Severity]:
        return {
            "privilege_escalation": self._privilege_escalation(counterexample),
            "asset_loss": self._asset_loss(counterexample),
            "state_corruption": self._state_corruption(counterexample),
            "control_flow": self._control_flow(counterexample),
        }

    def _evaluate_variants(self, counterexample: MinimizedCounterexample) -> tuple[EscalationVariant, ...]:
        generated = self._generate_variants(counterexample)
        return tuple(self._evaluate_variant(counterexample, variant) for variant in generated)

    def _generate_variants(self, counterexample: MinimizedCounterexample) -> tuple[EscalationVariant, ...]:
        chain = self.ir.chain if self.ir is not None else "evm"
        variants = [
            EscalationVariant(
                id="attacker-caller",
                caller="attacker",
                preconditions=counterexample.input_constraints,
            ),
            EscalationVariant(
                id="privileged-caller",
                caller="admin",
                preconditions=counterexample.input_constraints,
            ),
        ]
        if chain == "solana":
            variants.append(
                EscalationVariant(
                    id="solana-attacker-account-setup",
                    caller="attacker_program",
                    accounts={"authority": "attacker", "owner": "victim", "writable": True},
                    preconditions=counterexample.input_constraints,
                )
            )
        return tuple(variants)

    def _evaluate_variant(
        self, counterexample: MinimizedCounterexample, variant: EscalationVariant
    ) -> EscalationVariant:
        solver_result = self.solver.check(variant.preconditions)
        if solver_result.status == "unsat":
            return self._replace_variant(variant, solver_result=solver_result, feasible=False)
        if self.ir is None:
            return self._replace_variant(
                variant,
                solver_result=solver_result,
                feasible=solver_result.status in {"sat", "unknown"},
            )
        context = ExecutionContext(
            chain=self.ir.chain,
            caller=variant.caller,
            accounts=variant.accounts,
        )
        states = self.symbolic_engine.explore(
            self.ir,
            context=context,
            initial_storage=dict(counterexample.state_snapshot),
        )
        return self._replace_variant(
            variant,
            solver_result=solver_result,
            feasible=bool(states) and solver_result.status in {"sat", "unknown"},
        )

    def _build_graph(
        self,
        counterexample: MinimizedCounterexample,
        impact: dict[str, Severity],
        variants: tuple[EscalationVariant, ...],
    ) -> ExploitChainGraph:
        feasible = any(variant.feasible for variant in variants)
        max_impact = self._max_severity(tuple(impact.values()))
        nodes = [
            ExploitGraphNode(
                id="state:initial",
                label="counterexample entry",
                state_snapshot={},
                severity="low" if feasible else "info",
                feasible=feasible,
            )
        ]
        edges: list[ExploitGraphEdge] = []
        previous = nodes[0]
        trace = counterexample.attack_trace or ("counterexample",)
        for index, transition in enumerate(trace, start=1):
            severity = self._progress_severity(index, len(trace), max_impact, feasible)
            node = ExploitGraphNode(
                id=f"state:{index}",
                label=f"after {transition}",
                state_snapshot=dict(counterexample.state_snapshot) if index == len(trace) else {},
                severity=severity,
                feasible=feasible,
            )
            nodes.append(node)
            edges.append(
                ExploitGraphEdge(
                    source=previous.id,
                    target=node.id,
                    transition=transition,
                    severity_before=previous.severity,
                    severity_after=node.severity,
                    feasible=feasible,
                )
            )
            previous = node
        return ExploitChainGraph(nodes=tuple(nodes), edges=tuple(edges))

    def _privilege_escalation(self, counterexample: MinimizedCounterexample) -> Severity:
        text = self._counterexample_text(counterexample)
        if any(marker in text for marker in ("owner", "admin", "authority", "privilege", "signer")):
            return "high"
        return "low"

    def _asset_loss(self, counterexample: MinimizedCounterexample) -> Severity:
        text = self._counterexample_text(counterexample)
        asset_named = any(marker in text for marker in ("balance", "token", "asset", "lamport", "vault"))
        negative_numeric = any(
            isinstance(value, int) and value < 0 for value in counterexample.state_snapshot.values()
        )
        if negative_numeric and asset_named:
            return "critical"
        if asset_named:
            return "high"
        return "low"

    def _state_corruption(self, counterexample: MinimizedCounterexample) -> Severity:
        if counterexample.state_snapshot:
            return "medium"
        return "low"

    def _control_flow(self, counterexample: MinimizedCounterexample) -> Severity:
        text = self._counterexample_text(counterexample)
        if any(marker in text for marker in ("upgrade", "execute", "delegate", "call", "cpi")):
            return "high"
        if counterexample.attack_trace:
            return "medium"
        return "low"

    def _progress_severity(
        self, index: int, total: int, max_impact: Severity, feasible: bool
    ) -> Severity:
        if not feasible:
            return "info"
        if index == total:
            return max_impact
        return "medium" if self._severity_rank(max_impact) >= self._severity_rank("medium") else max_impact

    def _max_path(self, graph: ExploitChainGraph, max_severity: Severity) -> tuple[str, ...]:
        path: list[str] = []
        for node in graph.nodes:
            path.append(node.id)
            if node.severity == max_severity:
                break
        return tuple(path)

    def _explanation(
        self,
        counterexample: MinimizedCounterexample,
        variants: tuple[EscalationVariant, ...],
        max_severity: Severity,
    ) -> str:
        feasible_variants = tuple(variant.id for variant in variants if variant.feasible)
        infeasible_variants = tuple(
            f"{variant.id}:{variant.solver_result.status if variant.solver_result else 'not-run'}"
            for variant in variants
            if not variant.feasible
        )
        if feasible_variants:
            return (
                f"Escalation is feasible for {counterexample.obligation_id}; "
                f"feasible variants={feasible_variants}; "
                f"infeasible variants={infeasible_variants}; "
                f"max severity={max_severity}."
            )
        return (
            f"Escalation is not feasible for {counterexample.obligation_id}; "
            f"variant statuses={infeasible_variants}; "
            "all generated caller/account/precondition variants were UNSAT or reached no symbolic states."
        )

    def _counterexample_text(self, counterexample: MinimizedCounterexample) -> str:
        parts = [counterexample.obligation_id, *counterexample.attack_trace, *counterexample.state_snapshot]
        return " ".join(str(part).lower() for part in parts)

    def _max_severity(self, severities: tuple[Severity, ...]) -> Severity:
        return max(severities or ("info",), key=self._severity_rank)

    def _severity_rank(self, severity: Severity) -> int:
        return SEVERITY_ORDER.index(severity)

    def _replace_variant(
        self,
        variant: EscalationVariant,
        *,
        solver_result: SolverResult,
        feasible: bool,
    ) -> EscalationVariant:
        return EscalationVariant(
            id=variant.id,
            caller=variant.caller,
            accounts=dict(variant.accounts),
            preconditions=variant.preconditions,
            solver_result=solver_result,
            feasible=feasible,
        )
