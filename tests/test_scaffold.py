import pytest

from contract_verifier.frontends.anchor import AnchorFrontend
from contract_verifier.frontends.solidity import SolidityFrontend
from contract_verifier.ir.schema import ContractIR, Effect, ExprKind, Expression, Resource, Transition
from contract_verifier.reporting.report import ReportGenerator
from contract_verifier.symbolic.engine import SymbolicExecutionEngine


def test_frontends_return_chain_specific_ir():
    assert SolidityFrontend().parse("contract C {}", file_name="C.sol").chain == "evm"
    assert AnchorFrontend().parse("pub mod c {}", file_name="lib.rs").chain == "solana"


def test_ir_validation_rejects_unknown_effect_resource():
    ir = ContractIR(
        id="bad",
        chain="evm",
        transitions=(
            Transition(
                id="t1",
                name="write",
                chain="evm",
                effects=(Effect(id="e1", resource_id="missing", operation="assign"),),
            ),
        ),
    )

    with pytest.raises(ValueError, match="unknown resource"):
        ir.validate()


def test_symbolic_engine_emits_deterministic_transition_path():
    resource = Resource(id="balance", kind="state_variable", type_name="uint256")
    ir = ContractIR(
        id="vault",
        chain="evm",
        resources=(resource,),
        transitions=(
            Transition(
                id="deposit",
                name="deposit",
                chain="evm",
                effects=(
                    Effect(
                        id="increase_balance",
                        resource_id="balance",
                        operation="increment",
                        value=Expression(kind=ExprKind.SYMBOL, value="amount"),
                    ),
                ),
            ),
        ),
    )

    paths = SymbolicExecutionEngine().explore(ir)

    assert len(paths) == 1
    assert paths[0].transition_ids == ("deposit",)
    assert paths[0].effects_applied == ("increase_balance",)


def test_report_generator_outputs_structured_sections():
    report = ReportGenerator().empty().to_dict()

    assert set(report) == {
        "executive_summary",
        "threat_model",
        "invariants",
        "verified_properties",
        "counterexamples",
        "escalation_chains",
        "remediation",
    }
