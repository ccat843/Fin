from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Guard, Obligation, Resource, Transition
from contract_verifier.symbolic.context import ExecutionContext
from contract_verifier.symbolic.engine import SymbolicExecutionEngine


def literal(value):
    return Expression(kind=ExprKind.LITERAL, value=value)


def read(resource_id):
    return Expression(kind=ExprKind.READ, value=resource_id)


def symbol(name):
    return Expression(kind=ExprKind.SYMBOL, value=name)


def test_true_guard_applies_effect_to_cloned_state():
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
                    Guard(
                        id="owner_only",
                        predicate=Expression(
                            kind=ExprKind.EQ,
                            args=(Expression(kind=ExprKind.CALLER), literal("alice")),
                        ),
                        description="caller is owner",
                    ),
                ),
                effects=(
                    Effect(id="dec", resource_id="balance", operation="decrement", value=symbol("amount")),
                ),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(
        ir,
        context=ExecutionContext(chain="evm", caller="alice", inputs={"amount": 3}),
        initial_storage={"balance": 10},
    )

    assert len(states) == 1
    assert states[0].reverted is False
    assert states[0].storage["balance"] == 7
    assert states[0].effects_applied == ("dec",)
    assert states[0].branch_history == ("owner_only:true",)


def test_false_guard_reverts_without_applying_effects():
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
                    Guard(
                        id="owner_only",
                        predicate=Expression(
                            kind=ExprKind.EQ,
                            args=(Expression(kind=ExprKind.CALLER), literal("alice")),
                        ),
                        description="caller is owner",
                    ),
                ),
                effects=(
                    Effect(id="dec", resource_id="balance", operation="decrement", value=symbol("amount")),
                ),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(
        ir,
        context=ExecutionContext(chain="evm", caller="bob", inputs={"amount": 3}),
        initial_storage={"balance": 10},
    )

    assert len(states) == 1
    assert states[0].reverted is True
    assert states[0].storage["balance"] == 10
    assert states[0].effects_applied == ()
    assert states[0].branch_history == ("owner_only:false",)
    assert states[0].constraints[0].kind == ExprKind.NOT


def test_unknown_guard_forks_true_and_false_paths():
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
                    Guard(
                        id="positive_amount",
                        predicate=Expression(kind=ExprKind.GT, args=(symbol("amount"), literal(0))),
                        description="amount is positive",
                    ),
                ),
                effects=(
                    Effect(id="dec", resource_id="balance", operation="decrement", value=symbol("amount")),
                ),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(ir, initial_storage={"balance": 10})

    assert len(states) == 2
    true_state = next(state for state in states if state.branch_history == ("positive_amount:true",))
    false_state = next(state for state in states if state.branch_history == ("positive_amount:false",))
    assert true_state.reverted is False
    assert true_state.effects_applied == ("dec",)
    assert isinstance(true_state.storage["balance"], Expression)
    assert false_state.reverted is True
    assert false_state.effects_applied == ()
    assert false_state.storage["balance"] == 10


def test_explore_paths_exposes_backward_compatible_path_view():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="uint256"),),
        transitions=(
            Transition(
                id="deposit",
                name="deposit",
                chain="evm",
                effects=(Effect(id="inc", resource_id="balance", operation="increment", value=literal(5)),),
            ),
        ),
    )

    paths = SymbolicExecutionEngine().explore_paths(ir, initial_storage={"balance": 10})

    assert len(paths) == 1
    assert paths[0].transition_ids == ("deposit",)
    assert paths[0].effects_applied == ("inc",)
    assert paths[0].storage == {"balance": 15}


def test_solana_account_guard_uses_unified_execution_context():
    vault_owner = Expression(kind=ExprKind.ACCOUNT, value="vault.owner")
    signer = Expression(kind=ExprKind.ACCOUNT, value="owner.key")
    ir = ContractIR(
        id="anchor_vault",
        chain="solana",
        resources=(Resource(id="vault.balance", kind="account", type_name="u64"),),
        transitions=(
            Transition(
                id="withdraw",
                name="withdraw",
                chain="solana",
                guards=(
                    Guard(
                        id="owner_matches",
                        predicate=Expression(kind=ExprKind.EQ, args=(vault_owner, signer)),
                        description="owner signer matches vault owner",
                    ),
                ),
                effects=(
                    Effect(
                        id="assign_balance",
                        resource_id="vault.balance",
                        operation="assign",
                        value=literal(0),
                    ),
                ),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(
        ir,
        context=ExecutionContext(
            chain="solana",
            caller="owner_program",
            program_id="vault_program",
            signers=frozenset({"alice"}),
            accounts={"vault.owner": "alice", "owner.key": "alice"},
        ),
        initial_storage={"vault.balance": 50},
    )

    assert len(states) == 1
    assert states[0].reverted is False
    assert states[0].storage["vault.balance"] == 0
    assert states[0].branch_history == ("owner_matches:true",)


def test_reverted_paths_do_not_report_invariant_violations():
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(Resource(id="balance", kind="state_variable", type_name="int256"),),
        obligations=(
            Obligation(
                id="must_be_zero",
                predicate=Expression(kind=ExprKind.EQ, args=(read("balance"), literal(0))),
                description="balance must be zero",
                origin="user",
            ),
        ),
        transitions=(
            Transition(
                id="withdraw",
                name="withdraw",
                chain="evm",
                guards=(
                    Guard(
                        id="owner_only",
                        predicate=Expression(
                            kind=ExprKind.EQ,
                            args=(Expression(kind=ExprKind.CALLER), literal("alice")),
                        ),
                        description="caller is owner",
                    ),
                ),
                effects=(Effect(id="dec", resource_id="balance", operation="decrement", value=literal(1)),),
            ),
        ),
    )

    states = SymbolicExecutionEngine().explore(
        ir,
        context=ExecutionContext(chain="evm", caller="bob"),
        initial_storage={"balance": 10},
    )

    assert len(states) == 1
    assert states[0].reverted is True
    assert states[0].invariant_violations == ()
