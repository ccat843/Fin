from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Obligation, Resource, Transition
from contract_verifier.symbolic.counterexamples import CounterexampleMinimizer
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


def test_minimized_counterexample_contains_attack_trace_constraints_and_snapshot():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(
            Resource(id="balance", kind="state_variable", type_name="int256"),
            Resource(id="owner", kind="state_variable", type_name="address"),
        ),
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
    states = engine.explore(ir, initial_storage={"balance": 10, "owner": "alice"})
    violation = engine.evaluate_obligations(ir, states)[0]

    minimized = CounterexampleMinimizer().minimize(violation)

    assert minimized.obligation_id == "non_negative_balance"
    assert minimized.attack_trace == ("withdraw",)
    assert minimized.input_constraints == ()
    assert minimized.state_snapshot == {"balance": -5}
    assert minimized.solver_result.status == "sat"


def test_minimizer_prunes_irrelevant_path_conditions_while_preserving_sat():
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
    engine = SymbolicExecutionEngine()
    state = engine.explore(ir, initial_storage={"balance": 10})[0].clone(
        constraints=(
            Expression(kind=ExprKind.GT, args=(symbol("amount"), literal(0))),
            Expression(kind=ExprKind.GT, args=(symbol("limit"), literal(10))),
        ),
        transition_ids=("prepare", "prepare", "noop"),
    )
    violation = engine.evaluate_obligations(ir, (state,))[0]

    minimized = CounterexampleMinimizer().minimize(violation)

    assert minimized.attack_trace == ("prepare", "noop")
    assert minimized.input_constraints == ()
    assert minimized.solver_result.status == "sat"


def test_minimizer_removes_constraints_redundant_for_violation_consistency():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="int256"),),
        obligations=(obligation("amount_is_not_five", Expression(kind=ExprKind.NEQ, args=(symbol("amount"), literal(5)))),),
        transitions=(Transition(id="noop", name="noop", chain="evm"),),
    )
    engine = SymbolicExecutionEngine()
    state = engine.explore(ir, initial_storage={"balance": 10})[0].clone(
        constraints=(
            Expression(kind=ExprKind.GTE, args=(symbol("amount"), literal(5))),
            Expression(kind=ExprKind.LTE, args=(symbol("amount"), literal(5))),
            Expression(kind=ExprKind.GT, args=(symbol("limit"), literal(10))),
        )
    )
    violation = engine.evaluate_obligations(ir, (state,))[0]

    minimized = CounterexampleMinimizer().minimize(violation)

    assert minimized.input_constraints == ()
    assert minimized.solver_result.status == "sat"
