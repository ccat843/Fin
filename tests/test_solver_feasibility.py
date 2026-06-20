from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Guard, Resource, Transition
from contract_verifier.solver.solver import SolverResult
from contract_verifier.symbolic.engine import SymbolicExecutionEngine


def literal(value):
    return Expression(kind=ExprKind.LITERAL, value=value)


def symbol(name):
    return Expression(kind=ExprKind.SYMBOL, value=name)


def test_unsat_guard_path_is_pruned_immediately():
    amount_positive = Expression(kind=ExprKind.GT, args=(symbol("amount"), literal(0)))
    amount_non_positive = Expression(kind=ExprKind.LTE, args=(symbol("amount"), literal(0)))
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="uint256"),),
        transitions=(
            Transition(
                id="withdraw",
                name="withdraw",
                chain="evm",
                guards=(
                    Guard(id="positive", predicate=amount_positive, description="amount > 0"),
                    Guard(id="non_positive", predicate=amount_non_positive, description="amount <= 0"),
                ),
                effects=(Effect(id="dec", resource_id="balance", operation="decrement", value=symbol("amount")),),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(ir, initial_storage={"balance": 10})

    assert all(state.branch_history != ("positive:true", "non_positive:true") for state in states)
    assert all(state.effects_applied == () for state in states)
    assert {state.branch_history for state in states} == {
        ("positive:false",),
        ("positive:true", "non_positive:false"),
    }


class UnknownSolver:
    def check(self, constraints):
        return SolverResult(status="unknown", proof="deliberate test uncertainty")


def test_unknown_solver_result_is_conservatively_kept():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="uint256"),),
        transitions=(
            Transition(
                id="deposit",
                name="deposit",
                chain="evm",
                guards=(
                    Guard(
                        id="maybe_positive",
                        predicate=Expression(kind=ExprKind.GT, args=(symbol("amount"), literal(0))),
                        description="amount > 0",
                    ),
                ),
                effects=(Effect(id="inc", resource_id="balance", operation="increment", value=symbol("amount")),),
            ),
        ),
    )

    states = SymbolicExecutionEngine(solver=UnknownSolver()).explore(ir, initial_storage={"balance": 10})

    assert len(states) == 2
    assert {state.metadata["solver_status"] for state in states} == {"unknown"}
    assert {state.branch_history for state in states} == {("maybe_positive:true",), ("maybe_positive:false",)}


def test_pluggable_solver_can_prune_all_paths():
    class UnsatSolver:
        def check(self, constraints):
            return SolverResult(status="unsat", proof="forced unsat")

    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="uint256"),),
        transitions=(
            Transition(
                id="deposit",
                name="deposit",
                chain="evm",
                guards=(
                    Guard(
                        id="maybe_positive",
                        predicate=Expression(kind=ExprKind.GT, args=(symbol("amount"), literal(0))),
                        description="amount > 0",
                    ),
                ),
                effects=(Effect(id="inc", resource_id="balance", operation="increment", value=symbol("amount")),),
            ),
        ),
    )

    assert SymbolicExecutionEngine(solver=UnsatSolver()).explore(ir, initial_storage={"balance": 10}) == ()
