from pathlib import Path

from contract_verifier.escalation.engine import EscalationEngine
from contract_verifier.frontends.solidity import SolidityFrontend
from contract_verifier.ir.schema import ContractIR, ExprKind, Expression, Obligation
from contract_verifier.reporting.report import AuditReport
from contract_verifier.symbolic.context import ExecutionContext
from contract_verifier.symbolic.counterexamples import CounterexampleMinimizer
from contract_verifier.symbolic.engine import SymbolicExecutionEngine


SAMPLE_CONTRACT = Path(__file__).parent / "fixtures" / "VulnerableVault.sol"


def literal(value):
    return Expression(kind=ExprKind.LITERAL, value=value)


def read(resource_id):
    return Expression(kind=ExprKind.READ, value=resource_id)


def test_solidity_source_to_final_report_pipeline():
    source = SAMPLE_CONTRACT.read_text()
    parsed = SolidityFrontend().parse(source, file_name=str(SAMPLE_CONTRACT))
    non_negative_balance = Obligation(
        id="non_negative_balance",
        predicate=Expression(kind=ExprKind.GTE, args=(read("balance"), literal(0))),
        description="vault balance must never become negative",
        origin="user",
        severity_on_failure="high",
    )
    ir = ContractIR(
        id=parsed.id,
        chain=parsed.chain,
        resources=parsed.resources,
        principals=parsed.principals,
        transitions=parsed.transitions,
        obligations=(non_negative_balance,),
        metadata=parsed.metadata,
    )

    engine = SymbolicExecutionEngine()
    states = engine.explore(
        ir,
        context=ExecutionContext(chain="evm", caller="attacker"),
        initial_storage={"owner": "alice", "balance": 10},
    )
    violations = engine.evaluate_obligations(ir, states)
    counterexample = CounterexampleMinimizer().minimize(violations[0])
    escalation = EscalationEngine(ir=ir).analyze(counterexample)
    report = AuditReport(
        executive_summary="1 failed invariant found in VulnerableVault.",
        threat_model={"principals": ["owner", "attacker"], "assets": ["balance"], "trust_boundaries": ["msg.sender"]},
        invariants=[{"id": non_negative_balance.id, "status": "fail", "severity": "high"}],
        verified_properties=[],
        counterexamples=[
            {
                "id": counterexample.obligation_id,
                "attack_trace": list(counterexample.attack_trace),
                "state_snapshot": counterexample.state_snapshot,
                "solver_status": counterexample.solver_result.status,
            }
        ],
        escalation_chains=[escalation.to_dict()],
        remediation=[{"id": "access_control", "recommendation": "Restrict drain() or remove the negative-balance update."}],
    )

    data = report.to_dict()
    markdown = report.to_markdown()

    assert parsed.id == "VulnerableVault"
    assert [resource.id for resource in parsed.resources] == ["owner", "balance"]
    assert parsed.transitions[0].guards[0].predicate.kind == ExprKind.NEQ
    assert parsed.transitions[0].effects[0].operation == "decrement"
    assert states[0].storage["balance"] == -5
    assert violations[0].obligation_id == "non_negative_balance"
    assert counterexample.attack_trace == ("drain",)
    assert counterexample.state_snapshot == {"balance": -5}
    assert escalation.max_severity == "critical"
    assert data["counterexamples"][0]["state_snapshot"] == {"balance": -5}
    assert "## Counterexamples" in markdown
    assert "non_negative_balance" in markdown
