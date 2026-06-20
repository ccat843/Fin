"""Auditor-facing skill commands.

This module is intentionally a thin interface layer. It orchestrates existing
frontends, symbolic execution, counterexample minimization, escalation analysis,
and reporting without adding new verification logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal

from contract_verifier.escalation.engine import EscalationEngine, EscalationResult
from contract_verifier.frontends.anchor import AnchorFrontend
from contract_verifier.frontends.solidity import SolidityFrontend
from contract_verifier.ir.schema import ContractIR, ExprKind, Expression, Obligation, Resource, Severity
from contract_verifier.reporting.report import AuditReport
from contract_verifier.symbolic.context import ExecutionContext
from contract_verifier.symbolic.counterexamples import CounterexampleMinimizer, MinimizedCounterexample
from contract_verifier.symbolic.engine import SymbolicExecutionEngine
from contract_verifier.symbolic.invariants import InvariantViolation
from contract_verifier.vulnerability.patterns import (
    HypothesisValidation,
    VulnerabilityHypothesis,
    VulnerabilityPatternEngine,
)

CommandName = Literal[
    "audit_contract",
    "audit_repository",
    "explain_finding",
    "generate_remediation",
    "compare_before_after_patch",
]


@dataclass(frozen=True)
class AuditFinding:
    """Auditor-readable wrapper around a verified invariant violation."""

    id: str
    contract_id: str
    source_file: str
    severity: Severity
    invariant: Obligation
    violation: InvariantViolation
    counterexample: MinimizedCounterexample
    escalation: EscalationResult
    explanation: str
    remediation: dict[str, str]
    hypothesis: VulnerabilityHypothesis | None = None

    def to_report_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "contract": self.contract_id,
            "source_file": self.source_file,
            "severity": self.severity,
            "invariant": self.invariant.description,
            "explanation": self.explanation,
            "attack_trace": list(self.counterexample.attack_trace),
            "state_snapshot": dict(self.counterexample.state_snapshot),
            "solver_status": self.counterexample.solver_result.status,
            "hypothesis_id": self.hypothesis.id if self.hypothesis else None,
        }


@dataclass(frozen=True)
class AuditRun:
    """Result returned by auditor skill commands."""

    command: CommandName
    contracts: tuple[ContractIR, ...]
    findings: tuple[AuditFinding, ...]
    report: AuditReport
    artifacts: dict[str, object] = field(default_factory=dict)
    hypotheses: tuple[VulnerabilityHypothesis, ...] = ()
    hypothesis_validations: tuple[HypothesisValidation, ...] = ()

    def to_markdown(self) -> str:
        return self.report.to_markdown()


class AuditorSkill:
    """Public command surface for auditors.

    The methods map directly to the skill commands requested by users and return
    structured data plus final markdown through ``AuditReport``.
    """

    def __init__(self) -> None:
        self.solidity_frontend = SolidityFrontend()
        self.anchor_frontend = AnchorFrontend()
        self.symbolic_engine = SymbolicExecutionEngine()
        self.counterexample_minimizer = CounterexampleMinimizer()
        self.vulnerability_engine = VulnerabilityPatternEngine(symbolic_engine=self.symbolic_engine)

    @property
    def commands(self) -> tuple[CommandName, ...]:
        return (
            "audit_contract",
            "audit_repository",
            "explain_finding",
            "generate_remediation",
            "compare_before_after_patch",
        )

    def audit_contract(self, source: str, *, file_name: str) -> AuditRun:
        ir = self._lower_contract(source, file_name=file_name)
        findings, artifacts = self._run_contract_pipeline(ir)
        report = self._build_report((ir,), findings, artifacts["hypotheses"], artifacts["hypothesis_validations"])
        return AuditRun(
            command="audit_contract",
            contracts=(ir,),
            findings=findings,
            report=report,
            artifacts={file_name: artifacts},
            hypotheses=artifacts["hypotheses"],
            hypothesis_validations=artifacts["hypothesis_validations"],
        )

    def audit_repository(self, repository: str | Path) -> AuditRun:
        root = Path(repository)
        contracts = tuple(self._discover_contracts(root))
        findings: list[AuditFinding] = []
        hypotheses: list[VulnerabilityHypothesis] = []
        validations: list[HypothesisValidation] = []
        artifacts: dict[str, object] = {}
        for source_path in contracts:
            source = source_path.read_text(encoding="utf-8")
            ir = self._lower_contract(source, file_name=str(source_path.relative_to(root)))
            contract_findings, contract_artifacts = self._run_contract_pipeline(ir)
            findings.extend(contract_findings)
            hypotheses.extend(contract_artifacts["hypotheses"])
            validations.extend(contract_artifacts["hypothesis_validations"])
            artifacts[str(source_path.relative_to(root))] = contract_artifacts
        lowered = tuple(item["ir"] for item in artifacts.values() if isinstance(item, dict) and "ir" in item)
        report = self._build_report(lowered, tuple(findings), tuple(hypotheses), tuple(validations))
        return AuditRun(
            command="audit_repository",
            contracts=lowered,
            findings=tuple(findings),
            report=report,
            artifacts=artifacts,
            hypotheses=tuple(hypotheses),
            hypothesis_validations=tuple(validations),
        )

    def explain_finding(self, finding: AuditFinding) -> str:
        trace = " → ".join(finding.counterexample.attack_trace) or "the violating transition"
        snapshot = ", ".join(
            f"{key}={value}" for key, value in sorted(finding.counterexample.state_snapshot.items())
        ) or "no minimized state values"
        return (
            f"{finding.contract_id} violates '{finding.invariant.description}' in {finding.source_file}. "
            f"The feasible path is {trace}, which leaves {snapshot}. "
            f"The issue is rated {finding.severity} after escalation analysis."
        )

    def generate_remediation(self, finding: AuditFinding) -> dict[str, str]:
        resources = ", ".join(sorted(finding.counterexample.state_snapshot)) or "the affected state"
        trace = " → ".join(finding.counterexample.attack_trace) or "the vulnerable path"
        return {
            "id": f"fix_{finding.id}",
            "recommendation": (
                f"Add authorization and precondition checks around {trace} so {resources} cannot reach the "
                "violating value."
            ),
            "why_it_works": (
                f"The failed invariant is '{finding.invariant.description}'. Guarding the path and rejecting "
                "state updates that would falsify the invariant removes the minimized counterexample from the "
                "feasible state space."
            ),
        }

    def compare_before_after_patch(self, before: str | Path, after: str | Path) -> dict[str, object]:
        before_run = (
            self.audit_repository(before)
            if Path(before).is_dir()
            else self.audit_contract(Path(before).read_text(), file_name=str(before))
        )
        after_run = (
            self.audit_repository(after)
            if Path(after).is_dir()
            else self.audit_contract(Path(after).read_text(), file_name=str(after))
        )
        before_ids = {finding.id for finding in before_run.findings}
        after_ids = {finding.id for finding in after_run.findings}
        return {
            "before_findings": len(before_ids),
            "after_findings": len(after_ids),
            "resolved_findings": sorted(before_ids - after_ids),
            "new_findings": sorted(after_ids - before_ids),
            "unchanged_findings": sorted(before_ids & after_ids),
            "summary": f"Findings changed from {len(before_ids)} before to {len(after_ids)} after the patch.",
        }

    def _discover_contracts(self, root: Path) -> Iterable[Path]:
        ignored = {".git", ".pytest_cache", "__pycache__", "node_modules", "target", "artifacts"}
        for path in sorted(root.rglob("*")):
            if not path.is_file() or any(part in ignored for part in path.parts):
                continue
            if path.suffix == ".sol" or (path.suffix == ".rs" and self._looks_like_anchor(path)):
                yield path

    def _looks_like_anchor(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return False
        return "#[program]" in text or "anchor_lang" in text

    def _lower_contract(self, source: str, *, file_name: str) -> ContractIR:
        if file_name.endswith(".sol"):
            parsed = self.solidity_frontend.parse(source, file_name=file_name)
        elif file_name.endswith(".rs"):
            parsed = self.anchor_frontend.parse(source, file_name=file_name)
        else:
            raise ValueError(f"Unsupported contract source type: {file_name}")
        obligations = self._default_obligations(parsed)
        return ContractIR(
            id=parsed.id,
            chain=parsed.chain,
            resources=parsed.resources,
            principals=parsed.principals,
            transitions=parsed.transitions,
            obligations=obligations,
            metadata=parsed.metadata,
        )

    def _run_contract_pipeline(self, ir: ContractIR) -> tuple[tuple[AuditFinding, ...], dict[str, object]]:
        initial_storage = self._initial_storage(ir)
        states = self.symbolic_engine.explore(
            ir,
            context=ExecutionContext(chain=ir.chain, caller="attacker"),
            initial_storage=initial_storage,
        )
        violations = self.symbolic_engine.evaluate_obligations(ir, states)
        hypotheses = self.vulnerability_engine.discover(ir)
        validations = self.vulnerability_engine.validate(ir, hypotheses, initial_storage=initial_storage)
        findings = self._merge_findings(ir, violations, validations)
        return findings, {
            "ir": ir,
            "states": states,
            "violations": violations,
            "hypotheses": hypotheses,
            "hypothesis_validations": validations,
            "initial_storage": initial_storage,
        }

    def _merge_findings(
        self,
        ir: ContractIR,
        violations: tuple[InvariantViolation, ...],
        validations: tuple[HypothesisValidation, ...],
    ) -> tuple[AuditFinding, ...]:
        findings: list[AuditFinding] = [self._finding(ir, violation) for violation in violations]
        existing = {finding.id for finding in findings}
        existing_traces = {finding.counterexample.attack_trace for finding in findings}
        for validation in validations:
            if validation.status != "confirmed" or validation.violation is None:
                continue
            finding = self._finding(ir, validation.violation, hypothesis=validation.hypothesis)
            if finding.id in existing or finding.counterexample.attack_trace in existing_traces:
                continue
            findings.append(finding)
            existing.add(finding.id)
            existing_traces.add(finding.counterexample.attack_trace)
        return tuple(findings)

    def _finding(
        self,
        ir: ContractIR,
        violation: InvariantViolation,
        *,
        hypothesis: VulnerabilityHypothesis | None = None,
    ) -> AuditFinding:
        counterexample = self.counterexample_minimizer.minimize(violation)
        escalation = EscalationEngine(ir=ir).analyze(counterexample)
        invariant = self._obligation_by_id(ir, violation.obligation_id)
        severity = escalation.max_severity
        draft = AuditFinding(
            id=f"{ir.id}:{violation.obligation_id}",
            contract_id=ir.id,
            source_file=ir.metadata.get("source_file", ir.id),
            severity=severity,
            invariant=invariant,
            violation=violation,
            counterexample=counterexample,
            escalation=escalation,
            explanation="",
            remediation={},
            hypothesis=hypothesis,
        )
        remediation = self.generate_remediation(draft)
        return AuditFinding(
            id=draft.id,
            contract_id=draft.contract_id,
            source_file=draft.source_file,
            severity=draft.severity,
            invariant=draft.invariant,
            violation=draft.violation,
            counterexample=draft.counterexample,
            escalation=draft.escalation,
            explanation=self.explain_finding(draft),
            remediation=remediation,
            hypothesis=draft.hypothesis,
        )

    def _default_obligations(self, ir: ContractIR) -> tuple[Obligation, ...]:
        obligations: list[Obligation] = []
        for resource in ir.resources:
            if self._is_non_negative_asset(resource):
                obligations.append(
                    Obligation(
                        id=f"{resource.id}_non_negative",
                        predicate=Expression(
                            kind=ExprKind.GTE,
                            args=(
                                Expression(kind=ExprKind.READ, value=resource.id),
                                Expression(kind=ExprKind.LITERAL, value=0),
                            ),
                        ),
                        description=f"{resource.id} must never become negative",
                        origin="frontend",
                        severity_on_failure="high",
                        source=resource.source,
                    )
                )
        return tuple(obligations)

    def _is_non_negative_asset(self, resource: Resource) -> bool:
        name = resource.id.lower()
        type_name = resource.type_name.lower()
        return any(marker in name for marker in ("balance", "amount", "asset", "token", "lamport")) and (
            type_name.startswith("int") or type_name.startswith("uint") or type_name in {"u64", "i64"}
        )

    def _initial_storage(self, ir: ContractIR) -> dict[str, object]:
        storage: dict[str, object] = {}
        for resource in ir.resources:
            if resource.type_name == "address":
                storage[resource.id] = "alice"
            elif self._is_non_negative_asset(resource):
                storage[resource.id] = 10
        return storage

    def _obligation_by_id(self, ir: ContractIR, obligation_id: str) -> Obligation:
        for obligation in ir.obligations:
            if obligation.id == obligation_id:
                return obligation
        if obligation_id.startswith("hypothesis_"):
            resource_id = obligation_id.removeprefix("hypothesis_").removesuffix("_non_negative")
            return Obligation(
                id=obligation_id,
                predicate=Expression(
                    kind=ExprKind.GTE,
                    args=(Expression(kind=ExprKind.READ, value=resource_id), Expression(kind=ExprKind.LITERAL, value=0)),
                ),
                description=f"{resource_id} should remain non-negative under vulnerability hypothesis",
                origin="hypothesis",
                severity_on_failure="high",
            )
        raise KeyError(obligation_id)

    def _build_report(
        self,
        contracts: tuple[ContractIR, ...],
        findings: tuple[AuditFinding, ...],
        hypotheses: tuple[VulnerabilityHypothesis, ...] = (),
        validations: tuple[HypothesisValidation, ...] = (),
    ) -> AuditReport:
        return AuditReport(
            executive_summary=self._executive_summary(contracts, findings),
            threat_model={
                "contracts": [contract.id for contract in contracts],
                "principals": ["contract owner", "external caller", "attacker"],
                "assets": sorted({resource.id for contract in contracts for resource in contract.resources}),
                "trust_boundaries": ["msg.sender", "Anchor account constraints"],
            },
            invariants=[
                {
                    "id": obligation.id,
                    "contract": contract.id,
                    "description": obligation.description,
                    "status": (
                        "fail"
                        if any(
                            finding.invariant.id == obligation.id and finding.contract_id == contract.id
                            for finding in findings
                        )
                        else "pass"
                    ),
                    "severity": obligation.severity_on_failure,
                }
                for contract in contracts
                for obligation in contract.obligations
            ],
            vulnerability_hypotheses=[hypothesis.to_dict() for hypothesis in hypotheses],
            confirmed_exploits=[validation.to_dict() for validation in validations if validation.status == "confirmed"],
            failed_hypotheses=[validation.to_dict() for validation in validations if validation.status == "failed"],
            potential_risks=[validation.to_dict() for validation in validations if validation.status == "potential"],
            verified_properties=[],
            counterexamples=[finding.to_report_record() for finding in findings],
            escalation_chains=[finding.escalation.to_dict() for finding in findings],
            remediation=[finding.remediation for finding in findings],
        )

    def _executive_summary(self, contracts: tuple[ContractIR, ...], findings: tuple[AuditFinding, ...]) -> str:
        if not contracts:
            return "No supported Solidity or Anchor contracts were discovered."
        if not findings:
            return f"Audited {len(contracts)} contract(s); no confirmed exploits were found."
        highest = max(
            (finding.severity for finding in findings),
            key=("info", "low", "medium", "high", "critical").index,
        )
        return (
            f"Audited {len(contracts)} contract(s) and found {len(findings)} confirmed exploit(s); "
            f"highest severity is {highest}."
        )


_DEFAULT_SKILL = AuditorSkill()


def audit_contract(source: str, *, file_name: str) -> AuditRun:
    return _DEFAULT_SKILL.audit_contract(source, file_name=file_name)


def audit_repository(repository: str | Path) -> AuditRun:
    return _DEFAULT_SKILL.audit_repository(repository)


def explain_finding(finding: AuditFinding) -> str:
    return _DEFAULT_SKILL.explain_finding(finding)


def generate_remediation(finding: AuditFinding) -> dict[str, str]:
    return _DEFAULT_SKILL.generate_remediation(finding)


def compare_before_after_patch(before: str | Path, after: str | Path) -> dict[str, object]:
    return _DEFAULT_SKILL.compare_before_after_patch(before, after)
