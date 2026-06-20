from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Obligation, Resource, Transition
from contract_verifier.symbolic.engine import SymbolicExecutionEngine


def literal(value):
    return Expression(kind=ExprKind.LITERAL, value=value)


def read(resource_id):
    return Expression(kind=ExprKind.READ, value=resource_id)


def symbol(name):
    return Expression(kind=ExprKind.SYMBOL, value=name)


def obligation(obligation_id, predicate):
    return Obligation(
        id=obligation_id,
        predicate=predicate,
        description=f"{obligation_id} invariant",
        origin="user",
        severity_on_failure="high",
    )


def test_invariant_violation_is_detected_immediately():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="int256"),),
        obligations=(
            obligation(
                "non_negative_balance",
                Expression(kind=ExprKind.GTE, args=(read("balance"), literal(0))),
            ),
        ),
        transitions=(
            Transition(
                id="withdraw",
                name="withdraw",
                chain="evm",
                effects=(Effect(id="dec", resource_id="balance", operation="decrement", value=literal(15)),),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(ir, initial_storage={"balance": 10})

    assert len(states) == 1
    assert states[0].storage["balance"] == -5
    assert states[0].invariant_violations == ("non_negative_balance",)
    assert states[0].metadata["invariant_status"] == "violated"


def test_non_violation_paths_are_ignored():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="int256"),),
        obligations=(
            obligation(
                "non_negative_balance",
                Expression(kind=ExprKind.GTE, args=(read("balance"), literal(0))),
            ),
        ),
        transitions=(
            Transition(
                id="deposit",
                name="deposit",
                chain="evm",
                effects=(Effect(id="inc", resource_id="balance", operation="increment", value=literal(5)),),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(ir, initial_storage={"balance": 10})
    deferred_violations = SymbolicExecutionEngine().evaluate_obligations(ir, states)

    assert len(states) == 1
    assert states[0].storage["balance"] == 15
    assert states[0].invariant_violations == ()
    assert deferred_violations == ()


def test_counterexample_state_is_captured_correctly_for_deferred_evaluation():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="int256"),),
        obligations=(
            obligation(
                "non_negative_balance",
                Expression(kind=ExprKind.GTE, args=(read("balance"), literal(0))),
            ),
        ),
        transitions=(
            Transition(
                id="withdraw",
                name="withdraw",
                chain="evm",
                effects=(Effect(id="dec", resource_id="balance", operation="decrement", value=literal(15)),),
            ),
        ),
    )

    engine = SymbolicExecutionEngine()
    states = engine.explore(ir, initial_storage={"balance": 10})
    violations = engine.evaluate_obligations(ir, states)

    assert len(violations) == 1
    assert violations[0].obligation_id == "non_negative_balance"
    assert violations[0].counterexample.storage == {"balance": -5}
    assert violations[0].counterexample.transition_ids == ("withdraw",)
    assert violations[0].detection == "immediate"


def test_solver_backed_invariant_violation_is_detected_from_path_conditions():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="int256"),),
        obligations=(
            obligation(
                "amount_must_not_be_positive",
                Expression(kind=ExprKind.LTE, args=(symbol("amount"), literal(0))),
            ),
        ),
        transitions=(
            Transition(
                id="noop",
                name="noop",
                chain="evm",
            ),
        ),
    )

    state = SymbolicExecutionEngine().explore(ir, initial_storage={"balance": 10})[0]
    violations = SymbolicExecutionEngine().evaluate_obligations(ir, (state,))

    assert len(violations) == 1
    assert violations[0].detection == "solver"
    assert violations[0].counterexample.storage == {"balance": 10}
