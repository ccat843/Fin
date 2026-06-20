from pathlib import Path

from contract_verifier.auditor import (
    AuditorSkill,
    audit_contract,
    audit_repository,
    compare_before_after_patch,
    explain_finding,
    generate_remediation,
)


VULNERABLE = """pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    int256 public balance;

    function drain() public {
        require(msg.sender != owner, "only non-owner can trigger the vulnerable path");
        balance = balance - 15;
    }
}
"""

PATCHED = """pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    int256 public balance;

    function drain() public {
        require(msg.sender != owner, "only non-owner can trigger the vulnerable path");
        require(balance >= 15, "insufficient balance");
        balance = balance - 15;
    }
}
"""

ANCHOR = """use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;
    pub fn initialize(_ctx: Context<Initialize>) -> Result<()> { Ok(()) }
}

#[derive(Accounts)]
pub struct Initialize {}
"""


def test_auditor_skill_exposes_required_commands():
    assert AuditorSkill().commands == (
        "audit_contract",
        "audit_repository",
        "explain_finding",
        "generate_remediation",
        "compare_before_after_patch",
    )


def test_audit_repository_discovers_lowers_verifies_and_aggregates(tmp_path: Path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "VulnerableVault.sol").write_text(VULNERABLE, encoding="utf-8")
    (tmp_path / "programs").mkdir()
    (tmp_path / "programs" / "vault.rs").write_text(ANCHOR, encoding="utf-8")

    run = audit_repository(tmp_path)

    assert run.command == "audit_repository"
    assert {contract.chain for contract in run.contracts} == {"evm", "solana"}
    assert {contract.metadata["frontend"] for contract in run.contracts} == {"solidity", "anchor"}
    assert len(run.findings) == 1
    assert run.findings[0].counterexample.state_snapshot == {"balance": -5}
    assert "Audited 2 contract(s)" in run.to_markdown()


def test_explain_finding_and_generate_remediation_are_auditor_readable():
    run = audit_contract(VULNERABLE, file_name="VulnerableVault.sol")
    finding = run.findings[0]

    explanation = explain_finding(finding)
    remediation = generate_remediation(finding)

    assert "violates 'balance must never become negative'" in explanation
    assert "feasible path is drain" in explanation
    assert "recommendation" in remediation
    assert "why_it_works" in remediation
    assert "removes the minimized counterexample" in remediation["why_it_works"]


def test_compare_before_after_patch_reports_resolved_findings(tmp_path: Path):
    before = tmp_path / "before.sol"
    after = tmp_path / "after.sol"
    before.write_text(VULNERABLE, encoding="utf-8")
    after.write_text(PATCHED, encoding="utf-8")

    comparison = compare_before_after_patch(before, after)

    assert comparison["before_findings"] == 1
    assert comparison["after_findings"] == 0
    assert comparison["resolved_findings"] == ["VulnerableVault:balance_non_negative"]
