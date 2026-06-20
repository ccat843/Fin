from contract_verifier.escalation.engine import EscalationEngine
from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Resource, Transition
from contract_verifier.solver.solver import SolverResult
from contract_verifier.symbolic.counterexamples import MinimizedCounterexample


def literal(value):
    return Expression(kind=ExprKind.LITERAL, value=value)


def symbol(name):
    return Expression(kind=ExprKind.SYMBOL, value=name)


def minimized_counterexample(**overrides):
    base = {
        "obligation_id": "non_negative_balance",
        "attack_trace": ("withdraw",),
        "input_constraints": (),
        "state_snapshot": {"balance": -5},
        "solver_result": SolverResult(status="sat"),
    }
    base.update(overrides)
    return MinimizedCounterexample(**base)


def test_escalation_graph_reports_asset_loss_and_max_path():
    counterexample = minimized_counterexample()

    result = EscalationEngine().analyze(counterexample)

    assert result.max_severity == "critical"
    assert result.impact["asset_loss"] == "critical"
    assert result.escalation_graph.nodes[-1].state_snapshot == {"balance": -5}
    assert result.escalation_graph.edges[0].transition == "withdraw"
    assert result.max_severity_path == ("state:initial", "state:1")
    assert "Escalation is feasible" in result.explanation
    assert result.to_dict()["variants"][0]["id"] == "attacker-caller"
    assert result.to_dict()["graph"]["nodes"][-1]["state_snapshot"] == {"balance": -5}


def test_escalation_generates_solana_account_variant_and_reruns_symbolic_execution():
    ir = ContractIR(
        id="solana_vault",
        chain="solana",
        resources=(Resource(id="balance", kind="account", type_name="i64"),),
        transitions=(
            Transition(
                id="withdraw",
                name="withdraw",
                chain="solana",
                effects=(Effect(id="dec", resource_id="balance", operation="decrement", value=literal(1)),),
            ),
        ),
    )
    counterexample = minimized_counterexample(
        obligation_id="authority_balance_invariant",
        attack_trace=("withdraw",),
        state_snapshot={"balance": -1},
    )

    result = EscalationEngine(ir=ir).analyze(counterexample)

    assert any(variant.id == "solana-attacker-account-setup" for variant in result.variants)
    assert any(variant.feasible for variant in result.variants)
    assert result.impact["privilege_escalation"] == "high"
    assert result.escalation_graph.edges[0].feasible is True


def test_unsat_preconditions_make_escalation_infeasible():
    counterexample = minimized_counterexample(
        input_constraints=(
            Expression(kind=ExprKind.GT, args=(symbol("amount"), literal(0))),
            Expression(kind=ExprKind.LTE, args=(symbol("amount"), literal(0))),
        )
    )

    result = EscalationEngine().analyze(counterexample)

    assert all(not variant.feasible for variant in result.variants)
    assert result.escalation_graph.nodes[0].severity == "info"
    assert all(not edge.feasible for edge in result.escalation_graph.edges)
    assert "not feasible" in result.explanation
